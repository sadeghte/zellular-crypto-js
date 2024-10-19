const cc = require('./cuda-crypt')

const LOG = (...args) => process.env.VERBOSE == "1" && console.log(...args);

function getTime() {
	return Date.now() / 1000;
}

function format(num, n) {
	return `${num.toFixed(n)}`
}

function isPrime(num) {
    if (num <= 1) return false; // Numbers less than or equal to 1 are not prime
    if (num <= 3) return true;  // 2 and 3 are prime numbers

    // Check for even numbers greater than 2
    if (num % 2 === 0) return false;

    // Check for odd factors from 3 to the square root of num
    for (let i = 3; i * i <= num; i += 2) {
        if (num % i === 0) return false;
    }
    return true;
}

async function main() {
	const argv = process.argv.slice(2)

    // cc.setVerbose(true);
	cc.init();
	process.env.VERBOSE = "1";

    const count = parseInt(argv[0]);
    if (isNaN(count) || count <= 0)
        throw `signature count should be > 0! ${count}`

	// Create messages, privateKeys, publicKeys
	console.log(`preparing ${count} data...`);
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

	// checking signatures
	for(let i=0; i<count; i++) {
		const tSign = cc.sign(rawData[i].message, rawData[i].publicKey, rawData[i].privateKey);
		const verified = cc.verify(tSign, rawData[i].message, rawData[i].publicKey);
		if(!verified)
			throw `Invalid signature (verification failed)`
		if(!signatures.slice(i*cc.SIG_SIZE, (i+1)*cc.SIG_SIZE).equals(tSign))
			throw `Invalid signature (wrong value)`
	}
	console.log(`\n  sign: time: ${format(signT1-signT0, 2)},     sign/sec: ${format(count/(signT1-signT0), 2)}`)

	// corrupt some signatures to check false positive verification.
	for(let i=0; i<count; i++) {
		if(isPrime(i)) {
			const t = signatures[i*cc.SIG_SIZE];
			signatures[i*cc.SIG_SIZE] = t === 0 ? 1 : 0
		}
	}

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

	// checking verify responses
	for(let i=0; i<count; i++) {
		const expected = !isPrime(i);
		if(verified[i] != expected)
			throw `verification failed.`
	}
	console.log(`verify: time: ${format(verifT1-verifT0, 2)}, verifies/sec: ${format(count/(verifT1-verifT0), 2)}`)
}

main()
	.catch(e => {
		console.log(e)
	})
	.finally(() => {
		process.exit(0)
	})
