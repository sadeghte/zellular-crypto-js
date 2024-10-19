const cc = require("./cuda-crypt")

// Example usage

// Create keypair
const {publicKey, privateKey} = cc.createKeyPair()
console.log('Public Key:', publicKey.toString('hex'));
console.log('Private Key:', privateKey.toString('hex'));

// Sign a message
const message = Buffer.from('Hello, Zellular!');

// Sign the message
signature = cc.sign(message, publicKey, privateKey);
console.log('Signature:', signature.toString('hex'));

// Verify the signature
const isValid = cc.verify(signature, message, publicKey);
console.log(isValid === 1 ? 'Signature is valid!' : 'Signature is invalid.');
