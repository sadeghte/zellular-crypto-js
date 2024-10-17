const cc = require('./cuda-crypt')

const LOG = (...args) => process.env.VERBOSE == "1" && console.log(...args);

function getTime() {
	return Date.now() / 1000;
}

function format(num, n) {
	return `${num.toFixed(n)}`
}

async function main() {
	const argv = process.argv.slice(2)

    // cc.setVerbose(true);
	cc.init();
	process.env.VERBOSE = "1";

    const count = parseInt(argv[0]);
    if (count <= 0)
        throw `count should be > 0! ${count}`

	// Create messages, privateKeys, publicKeys
	console.log("preparing data...");
	const rawData = Array.from({length: count}, () => ({
		message: Buffer.from(new TextEncoder().encode("abcd1234")),
		...cc.createKeyPair(),
	}))

	// Pack data to pass it to the GPU to sign messages
	const gpuPacketSize = cc.STREAMER_PACKET_SIZE
    const signingDataBuffer = Buffer.alloc(count * gpuPacketSize);
	for (let i = 0; i < count; i++) {
		let baseOffset = i*gpuPacketSize

		rawData[i].privateKey.copy(signingDataBuffer, baseOffset)
		rawData[i].publicKey.copy(signingDataBuffer, baseOffset + cc.PRIV_KEY_SIZE)
		rawData[i].message.copy(signingDataBuffer, baseOffset + cc.PUB_KEY_SIZE + cc.PRIV_KEY_SIZE); 
    }
    const messageLens = Array.from({length: count}, () => 8);

	// Call GPU sign method
	let signT0 = getTime()
	const signatures = cc.signMany(signingDataBuffer, messageLens);
	let signT1 = getTime()

	console.log(`\n  sign: time: ${format(signT1-signT0, 2)},     sign/sec: ${format(count/(signT1-signT0), 2)}`)

	// Pack data to pass to the GPU to verify signatures
	const verifingDataBuffer = Buffer.alloc(count * gpuPacketSize);
	for (let i = 0; i < count; i++) {
		let baseOffset = i*gpuPacketSize

		signatures.copy(verifingDataBuffer, baseOffset, i*cc.SIG_SIZE, (i+1)*cc.SIG_SIZE)
		rawData[i].publicKey.copy(verifingDataBuffer, baseOffset + cc.SIG_SIZE)
		rawData[i].message.copy(verifingDataBuffer, baseOffset + cc.SIG_SIZE + cc.PUB_KEY_SIZE); 
    }
	// Call GPU verify method
	let verifT0 = getTime()
	const verified = cc.verifyMany(verifingDataBuffer, messageLens);
	let verifT1 = getTime()
	console.log(`verify: time: ${format(verifT1-verifT0, 2)}, verifies/sec: ${format(count/(verifT1-verifT0), 2)}`)
}

main()
	.catch(e => {
		console.log(e)
	})
	.finally(() => {
		process.exit(0)
	})
