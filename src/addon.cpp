#include <napi.h>
#include <stdint.h>
#include <random>
#include <iostream>
#include <iomanip> 
#include "ed25519.h"


Napi::Value Ed25519Init(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    bool success = ed25519_init();
    return Napi::Boolean::New(env, success);
}

Napi::Value Ed25519SetVerbose(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBoolean()) {
        Napi::TypeError::New(env, "Boolean expected").ThrowAsJavaScriptException();
        return env.Null();
    }

    bool verbose = info[0].As<Napi::Boolean>().Value();

    // Set the verbose mode (You need to implement this function in your C library)
    ed25519_set_verbose(verbose);

    return env.Null();
}

Napi::Value Ed25519CreateSeed(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // Check the number of arguments
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Seed buffer expected").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Check that the first argument is a Buffer
    if (!info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Seed buffer expected").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Get the seed buffer from the first argument
    unsigned char* seedBuffer = info[0].As<Napi::Buffer<unsigned char>>().Data();

    // Call the ed25519_create_seed function from the C library
    int result = ed25519_create_seed(seedBuffer);

    // Return the result code
    return Napi::Number::New(env, result); // Return the integer result code
}

Napi::Value Ed25519CreateKeypair(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "Expected 3 arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    unsigned char* public_key = info[0].As<Napi::Buffer<unsigned char>>().Data();
    unsigned char* private_key = info[1].As<Napi::Buffer<unsigned char>>().Data();
    const unsigned char* seed = info[2].As<Napi::Buffer<unsigned char>>().Data();

    ed25519_create_keypair(public_key, private_key, seed);
    return env.Null();
}

Napi::Value Ed25519Sign(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 5) {
        Napi::TypeError::New(env, "Expected 5 arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    unsigned char* signature = info[0].As<Napi::Buffer<unsigned char>>().Data();
    const unsigned char* message = info[1].As<Napi::Buffer<unsigned char>>().Data();
    size_t message_len = info[2].As<Napi::Number>().Uint32Value();
    const unsigned char* public_key = info[3].As<Napi::Buffer<unsigned char>>().Data();
    const unsigned char* private_key = info[4].As<Napi::Buffer<unsigned char>>().Data();

    ed25519_sign(signature, message, message_len, public_key, private_key);
    return env.Null();
}

Napi::Value Ed25519Verify(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4) {
        Napi::TypeError::New(env, "Expected 4 arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    const unsigned char* signature = info[0].As<Napi::Buffer<unsigned char>>().Data();
    const unsigned char* message = info[1].As<Napi::Buffer<unsigned char>>().Data();
    size_t message_len = info[2].As<Napi::Number>().Uint32Value();
    const unsigned char* public_key = info[3].As<Napi::Buffer<unsigned char>>().Data();

    int result = ed25519_verify(signature, message, message_len, public_key);
    return Napi::Boolean::New(env, result == 1);
}

gpu_Elems* getGpuElems(const Napi::CallbackInfo& info, uint32_t count) {
	Napi::Env env = info.Env();

    // Step 1: Get the array of gpuElem objects from JS (as Buffer)
    Napi::Array gpuElemArray = info[0].As<Napi::Array>();


    gpu_Elems* gpuElems = new gpu_Elems[3];

	for(int i=0; i<count; i++) {
		// Step 2: Retrieve the first gpuElem struct
		Napi::Object gpuElemObject = gpuElemArray.Get((uint32_t)0).As<Napi::Object>();

		// Step 4: Create the gpu_Elems struct and populate it
		gpuElems[i].num = gpuElemObject.Get("num").As<Napi::Number>().Uint32Value();
		gpuElems[i].elems = gpuElemObject.Get("elems").As<Napi::Buffer<uint8_t>>().Data();
	}

	return gpuElems;
}

Napi::Value Ed25519SignMany(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	
	// Validate arguments, extract parameters, and call the C function
	uint32_t num_elems = info[1].As<Napi::Number>().Uint32Value();
    gpu_Elems* elems = getGpuElems(info, num_elems);
	uint32_t message_size = info[2].As<Napi::Number>().Uint32Value();
	uint32_t total_packets = info[3].As<Napi::Number>().Uint32Value();
	uint32_t total_signatures = info[4].As<Napi::Number>().Uint32Value();
	uint32_t* message_lens = reinterpret_cast<uint32_t*>(info[5].As<Napi::Buffer<uint32_t>>().Data());
	uint32_t* public_key_offsets = reinterpret_cast<uint32_t*>(info[6].As<Napi::Buffer<uint32_t>>().Data());
	uint32_t* private_key_offsets = reinterpret_cast<uint32_t*>(info[7].As<Napi::Buffer<uint32_t>>().Data());
	uint32_t* message_start_offsets = reinterpret_cast<uint32_t*>(info[8].As<Napi::Buffer<uint32_t>>().Data());
	uint8_t* signatures_out = reinterpret_cast<uint8_t*>(info[9].As<Napi::Buffer<uint8_t>>().Data());
	uint8_t use_non_default_stream = info[10].As<Napi::Number>().Uint32Value();

	ed25519_sign_many(elems, num_elems, message_size, total_packets, total_signatures, message_lens, public_key_offsets, private_key_offsets, message_start_offsets, signatures_out, use_non_default_stream);

	return env.Null();
}

Napi::Value Ed25519VerifyMany(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	// Validate arguments, extract parameters, and call the C function
	uint32_t num_elems = info[1].As<Napi::Number>().Uint32Value();
	gpu_Elems* elems = getGpuElems(info, num_elems);
	uint32_t message_size = info[2].As<Napi::Number>().Uint32Value();
	uint32_t total_packets = info[3].As<Napi::Number>().Uint32Value();
	uint32_t total_signatures = info[4].As<Napi::Number>().Uint32Value();
	uint32_t* message_lens = reinterpret_cast<uint32_t*>(info[5].As<Napi::Buffer<uint32_t>>().Data());
	uint32_t* public_key_offsets = reinterpret_cast<uint32_t*>(info[6].As<Napi::Buffer<uint32_t>>().Data());
	uint32_t* private_key_offsets = reinterpret_cast<uint32_t*>(info[7].As<Napi::Buffer<uint32_t>>().Data());
	uint32_t* message_start_offsets = reinterpret_cast<uint32_t*>(info[8].As<Napi::Buffer<uint32_t>>().Data());
	uint8_t* out = reinterpret_cast<uint8_t*>(info[9].As<Napi::Buffer<uint8_t>>().Data());
	uint8_t use_non_default_stream = info[10].As<Napi::Number>().Uint32Value();

	ed25519_verify_many(elems, num_elems, message_size, total_packets, total_signatures, message_lens, public_key_offsets, private_key_offsets, message_start_offsets, out, use_non_default_stream);

	return env.Null();
}

Napi::Value Ed25519License(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    const char* license = ed25519_license();
    return Napi::String::New(env, license);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "ed25519_init"), Napi::Function::New(env, Ed25519Init));
    exports.Set(Napi::String::New(env, "ed25519_set_verbose"), Napi::Function::New(env, Ed25519SetVerbose));
    exports.Set(Napi::String::New(env, "ed25519_create_seed"), Napi::Function::New(env, Ed25519CreateSeed));
    exports.Set(Napi::String::New(env, "ed25519_create_keypair"), Napi::Function::New(env, Ed25519CreateKeypair));
    exports.Set(Napi::String::New(env, "ed25519_sign"), Napi::Function::New(env, Ed25519Sign));
    exports.Set(Napi::String::New(env, "ed25519_verify"), Napi::Function::New(env, Ed25519Verify));
	exports.Set(Napi::String::New(env, "ed25519_sign_many"), Napi::Function::New(env, Ed25519SignMany));
	exports.Set(Napi::String::New(env, "ed25519_verify_many"), Napi::Function::New(env, Ed25519VerifyMany));
    exports.Set(Napi::String::New(env, "ed25519_license"), Napi::Function::New(env, Ed25519License));
    return exports;
}

NODE_API_MODULE(addon, Init)
