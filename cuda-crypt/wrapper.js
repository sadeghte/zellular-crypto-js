const ffi = require('ffi-napi');
const ref = require('ref-napi');
const StructType = require('ref-struct-napi');

const SHA512_SIZE = 64;
const SIG_SIZE = 64;
const PUB_KEY_SIZE = 32;
const PRIV_KEY_SIZE = 64;
const SCALAR_SIZE = 32;
const SEED_SIZE = 32;
const UINT32_SIZE = 4;

const uint8Ptr = ref.refType(ref.types.uint8);
const uint32Ptr = ref.refType(ref.types.uint32);
const GpuElems = StructType({
	elems: uint8Ptr,		
	num: ref.types.uint32
});
const GpuElemsPtr = ref.refType(GpuElems);

const cudaCrypt = ffi.Library('./cuda-crypt/libcuda-crypt.so', {
	'ed25519_init': ['bool', []],  // init
	'ed25519_set_verbose': ['void', ['bool']],  // Set verbosity
	'ed25519_create_seed': ['int', ['pointer']], // Create seed (if supported by your build)
	'ed25519_create_keypair': ['void', ['pointer', 'pointer', 'pointer']],  // public key, private key, seed
	'ed25519_sign': ['void', ['pointer', 'pointer', 'size_t', 'pointer', 'pointer']],  // signature, message, message_len, public_key, private_key
	'ed25519_sign_many': [
		'void', 
		[
			GpuElemsPtr,       // const gpu_Elems* elems
			ref.types.uint32,  // uint32_t num_elems
			ref.types.uint32,  // uint32_t message_size
			ref.types.uint32,  // uint32_t total_packets
			ref.types.uint32,  // uint32_t total_signatures
			uint32Ptr,         // const uint32_t* message_lens
			uint32Ptr,         // const uint32_t* public_key_offsets
			uint32Ptr,         // const uint32_t* private_key_offsets
			uint32Ptr,         // const uint32_t* message_start_offsets
			uint8Ptr,          // uint8_t* signatures_out
			ref.types.uint8    // uint8_t use_non_default_stream
		]
	],
	'ed25519_verify': ['int', ['pointer', 'pointer', 'uint32', 'pointer']],  // signature, message, message_len, public_key
	'ed25519_verify_many': [
		'void', 
		[
			GpuElemsPtr,		// const gpu_Elems* elems
			ref.types.uint32,	// num_elems
			ref.types.uint32,	// message_size
			ref.types.uint32,	// total_packets
			ref.types.uint32,	// total_signatures
			uint32Ptr,			// message_lens (array of uint32_t)
			uint32Ptr,			// public_key_offsets (array of uint32_t)
			uint32Ptr,			// private_key_offsets (array of uint32_t)
			uint32Ptr,			// message_start_offsets (array of uint32_t)
			uint32Ptr,			// out (output buffer for verification results)
			ref.types.uint8		// use_non_default_stream
		]
	],
});

module.exports = {
	SHA512_SIZE,
	SIG_SIZE,
	PUB_KEY_SIZE,
	PRIV_KEY_SIZE,
	SCALAR_SIZE,
	SEED_SIZE,
	UINT32_SIZE,

	GpuElems,

	cudaCrypt,
}