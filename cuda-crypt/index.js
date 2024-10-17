const {
	SEED_SIZE,
	SIG_SIZE,
	UINT32_SIZE,
	PUB_KEY_SIZE,
	PRIV_KEY_SIZE,
	GpuElems,
	cudaCrypt,
} = require("./wrapper");

const PACKET_SIZE = 512
const STREAMER_META_SIZE = 40
const STREAMER_PACKET_SIZE = PACKET_SIZE + STREAMER_META_SIZE

function init() {
	return cudaCrypt.ed25519_init();
}

function setVerbose(verbose) {
	cudaCrypt.ed25519_set_verbose(verbose);
}

function createKeyPair() {
	const seed = Buffer.alloc(SEED_SIZE);
	const publicKey = Buffer.alloc(PUB_KEY_SIZE);   // ed25519 public key is 32 bytes
	const privateKey = Buffer.alloc(PRIV_KEY_SIZE);  // ed25519 private key is 64 bytes

	let success = cudaCrypt.ed25519_create_seed(seed);
	if(success != 0)
		throw `unable to create seed`;

	cudaCrypt.ed25519_create_keypair(publicKey, privateKey, seed);

	return {publicKey, privateKey}
}

function sign(message, publicKey, privateKey) {
	const signature = Buffer.alloc(64);
	cudaCrypt.ed25519_sign(signature, message, message.length, publicKey, privateKey);
	return signature;
}

function verify(signature, message, publicKey) {
	return cudaCrypt.ed25519_verify(signature, message, message.length, publicKey);
}

function signMany(dataBuffer, messageLens) {
	count = messageLens.length;

	const publicKeyOffsets = Array.from({length: count}, () => 0); // Offsets for public keys
    const privateKeyOffsets = Array.from({length: count}, () => 0); // Offsets for private keys
    const messageStartOffsets = Array.from({length: count}, () => 0); // Offsets for messages

	let baseOffset = 0
    for (let i = 0; i < count; i++) {
		privateKeyOffsets[i] = baseOffset
		publicKeyOffsets[i] = baseOffset + PRIV_KEY_SIZE
		messageStartOffsets[i] = baseOffset + PUB_KEY_SIZE + PRIV_KEY_SIZE

		baseOffset += STREAMER_PACKET_SIZE
    }

	// Convert arrays to buffers (pointers)
    const messageLensBuffer = Buffer.from(new Uint32Array(messageLens).buffer);
    const publicKeyOffsetsBuffer = Buffer.from(new Uint32Array(publicKeyOffsets).buffer);
    const privateKeyOffsetsBuffer = Buffer.from(new Uint32Array(privateKeyOffsets).buffer);
    const messageStartOffsetsBuffer = Buffer.from(new Uint32Array(messageStartOffsets).buffer);

    // Create an instance of GpuElemsPtr
    const gpuElem = new GpuElems({
        num: count,          // Number of elements (3 in this case)
        elems: dataBuffer, // Pass the messages buffer
    });

	const signaturesBuffer = Buffer.alloc(count * SIG_SIZE)
    cudaCrypt.ed25519_sign_many(
		gpuElem.ref(),                 // GpuElemsPtr (messages)
        1,                         // num_elems
        STREAMER_PACKET_SIZE,      // message_size
        count,                     // total_packets
        count,                     // total_signatures
        messageLensBuffer,         // message lengths
        publicKeyOffsetsBuffer,    // public key offsets
        privateKeyOffsetsBuffer,   // private key offsets
        messageStartOffsetsBuffer, // message start offsets
        signaturesBuffer,          // output signatures buffer
        1                          // use_non_default_stream (set to 0 for now)
    );

    return signaturesBuffer
}

function verifyMany(dataBuffer, messageLens) {
	count = messageLens.length;

    const signatureOffsets = Array.from({length: count}, () => 0); // Offsets for private keys
	const publicKeyOffsets = Array.from({length: count}, () => 0); // Offsets for public keys
    const messageStartOffsets = Array.from({length: count}, () => 0); // Offsets for messages

	let baseOffset = 0
    for (let i = 0; i < count; i++) {
		signatureOffsets[i] = baseOffset
		publicKeyOffsets[i] = baseOffset + SIG_SIZE
		messageStartOffsets[i] = baseOffset + SIG_SIZE + PUB_KEY_SIZE

		baseOffset += STREAMER_PACKET_SIZE
    }

	// Convert arrays to buffers (pointers)
    const messageLensBuffer = Buffer.from(new Uint32Array(messageLens).buffer);
    const publicKeyOffsetsBuffer = Buffer.from(new Uint32Array(publicKeyOffsets).buffer);
    const signatureOffsetsBuffer = Buffer.from(new Uint32Array(signatureOffsets).buffer);
    const messageStartOffsetsBuffer = Buffer.from(new Uint32Array(messageStartOffsets).buffer);

    // Create an instance of GpuElemsPtr
    const gpuElem = new GpuElems({
        num: count,          // Number of elements (3 in this case)
        elems: dataBuffer, // Pass the messages buffer
    });

	const outBuffer = Buffer.alloc(count)
    cudaCrypt.ed25519_verify_many(
		gpuElem.ref(),                 // GpuElemsPtr (messages)
        1,                         // num_elems
        STREAMER_PACKET_SIZE,      // message_size
        count,                     // total_packets
        count,                     // total_signatures
        messageLensBuffer,         // message lengths
        publicKeyOffsetsBuffer,    // public key offsets
        signatureOffsetsBuffer,   // private key offsets
        messageStartOffsetsBuffer, // message start offsets
        outBuffer,          // output signatures buffer
        1                          // use_non_default_stream (set to 0 for now)
    );

    return outBuffer
}

module.exports = {
	STREAMER_PACKET_SIZE,
	SIG_SIZE,
	PRIV_KEY_SIZE,
	PUB_KEY_SIZE,
	init,
	setVerbose,
	createKeyPair,
	sign,
	verify,
	signMany,
	verifyMany,
	cudaCrypt,
}