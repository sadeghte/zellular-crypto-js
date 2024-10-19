SOLANA_PERF_LIBS_REPO=https://github.com/sadeghte/solana-perf-libs.git
BUILD_DIR=solana-perf-libs
MODULE_DIR=cuda-crypt
ABSOLUTE_MODULE_DIR=$(shell realpath $(MODULE_DIR))

.PHONY: all clone build build-addon clean

all: clone build build-addon

clone:
	@if [ ! -d "$(BUILD_DIR)" ]; then \
		git clone $(SOLANA_PERF_LIBS_REPO); \
	fi

build: clone
	@export PATH=/usr/local/cuda/bin:$$PATH && \
	cd $(BUILD_DIR) && \
	make -e -j$$(nproc) && \
	make DESTDIR=$(ABSOLUTE_MODULE_DIR) install

build-addon:
	node-gyp configure build

clean:
	node-gyp clean
	rm -rf build
	rm -rf $(BUILD_DIR)
