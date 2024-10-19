{
  "targets": [
    {
      "target_name": "addon",
      "sources": [ "src/addon.cpp" ],
      "libraries": [ "<(module_root_dir)/cuda-crypt/libcuda-crypt.so" ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ]
    }
  ]
}
