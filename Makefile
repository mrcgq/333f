
# =========================================================================
# v3 Project Makefile (Ultimate Edition)
# Purpose: Automate compilation of all v3 components
# =========================================================================

CC = gcc
CLANG = clang
CFLAGS_COMMON = -O3 -flto -Wall -Wextra -fPIC -fno-plt -fno-omit-frame-pointer

SRC_DIR = src
BPF_DIR = bpf
BUILD_DIR = build

LIBS_MAX = -luring -lsodium -lpthread -lbpf
LIBS_WSS = -lssl -lcrypto -lpthread
LIBS_XDP_LOADER = -lbpf -lelf -lz
LIBS_BENCHMARK = -lsodium -lm
LIBS_TURBO = -luring -lpthread

SRCS_MAX = $(SRC_DIR)/v3_ultimate_optimized.c \
           $(SRC_DIR)/v3_fec_simd.c \
           $(SRC_DIR)/v3_pacing_adaptive.c \
           $(SRC_DIR)/v3_antidetect_mtu.c \
           $(SRC_DIR)/v3_cpu_dispatch.c \
           $(SRC_DIR)/v3_health.c

SRCS_TURBO = $(SRC_DIR)/v3_turbo.c \
             $(SRC_DIR)/v3_cpu_dispatch.c

SRCS_TURBO_PORTABLE = $(SRC_DIR)/v3_turbo_portable.c

SRCS_BENCHMARK = $(SRC_DIR)/v3_benchmark.c \
                 $(SRC_DIR)/v3_fec_simd.c \
                 $(SRC_DIR)/v3_cpu_dispatch.c

.PHONY: all clean dirs help detect tools full release \
        v3_server_max v3_server_lite v3_server_wss v3_xdp \
        v3_server_generic v3_server_sse42 v3_server_avx2 v3_server_avx512 \
        v3_server_native v3_server_aarch64 \
        v3_server_turbo v3_server_turbo_portable \
        v3_xdp_loader v3_benchmark \
        debug analyze format-check install uninstall

all: dirs v3_server_max

dirs:
	@mkdir -p $(BUILD_DIR)

v3_server_max: dirs $(SRCS_MAX)
	@echo "Building v3 Server Max (v5 Enterprise)..."
	$(CC) $(CFLAGS_COMMON) -march=x86-64 \
		$(SRCS_MAX) \
		-o $(BUILD_DIR)/v3_server_max \
		$(LIBS_MAX)

v3_server_lite: dirs $(SRC_DIR)/v3_portable.c
	@echo "Building v3 Server Lite (v6 Portable)..."
	musl-gcc -O3 -static -s \
		$(SRC_DIR)/v3_portable.c \
		-o $(BUILD_DIR)/v3_server_lite \
		-lpthread

v3_server_wss: dirs $(SRC_DIR)/v3_ws_server.c
	@echo "Building v3 Server WSS (v7 Rescue)..."
	$(CC) -O3 \
		$(SRC_DIR)/v3_ws_server.c \
		-o $(BUILD_DIR)/v3_server_wss \
		$(LIBS_WSS)

v3_server_turbo: dirs $(SRCS_TURBO)
	@echo "Building v3 Server Turbo (v8 Brutal)..."
	$(CC) $(CFLAGS_COMMON) -march=x86-64 \
		$(SRCS_TURBO) \
		-o $(BUILD_DIR)/v3_server_turbo \
		$(LIBS_TURBO)

v3_server_turbo_portable: dirs $(SRCS_TURBO_PORTABLE)
	@echo "Building v3 Server Turbo-Portable (v9 Static)..."
	musl-gcc -O3 -static -s \
		$(SRCS_TURBO_PORTABLE) \
		-o $(BUILD_DIR)/v3_server_turbo_portable \
		-lpthread

v3_xdp: dirs $(BPF_DIR)/v3_xdp.c $(BPF_DIR)/v3_common.h
	@echo "Building XDP BPF Object..."
	$(CLANG) -O2 -target bpf \
		-I/usr/include/x86_64-linux-gnu \
		-I/usr/include \
		-c $(BPF_DIR)/v3_xdp.c \
		-o $(BUILD_DIR)/v3_xdp.o

v3_server_generic: dirs $(SRCS_MAX)
	@echo "Building Generic (x86-64-v1)..."
	$(CC) $(CFLAGS_COMMON) -march=x86-64 \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)

v3_server_sse42: dirs $(SRCS_MAX)
	@echo "Building SSE4.2 (x86-64-v2)..."
	$(CC) $(CFLAGS_COMMON) -march=x86-64-v2 \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)

v3_server_avx2: dirs $(SRCS_MAX)
	@echo "Building AVX2 (x86-64-v3)..."
	$(CC) $(CFLAGS_COMMON) -march=x86-64-v3 \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)

v3_server_avx512: dirs $(SRCS_MAX)
	@echo "Building AVX-512 (x86-64-v4)..."
	$(CC) $(CFLAGS_COMMON) -march=x86-64-v4 \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)

v3_server_native: dirs $(SRCS_MAX)
	@echo "Building Native (current CPU)..."
	$(CC) $(CFLAGS_COMMON) -march=native \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)

v3_server_aarch64: dirs $(SRCS_MAX)
	@echo "Building ARM64..."
	$(CC) $(CFLAGS_COMMON) -march=armv8-a+crypto \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)

v3_xdp_loader: dirs $(SRC_DIR)/v3_xdp_loader.c
	@echo "Building XDP Loader..."
	$(CC) -O2 -Wall \
		$(SRC_DIR)/v3_xdp_loader.c \
		-o $(BUILD_DIR)/v3_xdp_loader \
		$(LIBS_XDP_LOADER)

v3_benchmark: dirs $(SRCS_BENCHMARK)
	@echo "Building Benchmark Tool..."
	$(CC) -O3 -march=native -Wall \
		-DHAVE_SODIUM \
		$(SRCS_BENCHMARK) \
		-o $(BUILD_DIR)/v3_benchmark \
		$(LIBS_BENCHMARK)

tools: dirs v3_xdp_loader v3_benchmark

full: dirs v3_server_max v3_server_lite v3_server_wss \
      v3_server_turbo v3_server_turbo_portable \
      v3_xdp tools

release: dirs v3_server_generic v3_server_avx2 v3_server_avx512 \
         v3_server_lite v3_server_wss \
         v3_server_turbo v3_server_turbo_portable \
         v3_xdp

detect:
	@echo "CPU Capabilities Check:"
	@grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs
	@grep "flags" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | tr ' ' '\n' | grep -E "sse|avx|neon" | sort -u | tr '\n' ' '

benchmark: v3_benchmark
	@$(BUILD_DIR)/v3_benchmark

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "Usage: make [target]"
	@echo "Targets: full, release, detect, clean, etc."

debug: dirs $(SRCS_MAX)
	$(CC) -O0 -g -Wall -Wextra -DDEBUG \
		$(SRCS_MAX) -o $(BUILD_DIR)/v3_server_debug $(LIBS_MAX)

analyze: $(SRCS_MAX)
	@for src in $(SRCS_MAX); do \
		$(CC) -fsyntax-only -Wall -Wextra -pedantic $$src; \
	done

format-check:
	@find $(SRC_DIR) -name "*.c" -o -name "*.h" | xargs clang-format --dry-run --Werror 2>/dev/null

install: v3_server_max
	install -m 755 $(BUILD_DIR)/v3_server_max /usr/local/bin/v3_server

uninstall:
	rm -f /usr/local/bin/v3_server
	
	
	
	
	
	
