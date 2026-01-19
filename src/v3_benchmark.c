
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <getopt.h>

#include "v3_cpu_dispatch.h"
#include "v3_fec_simd.h"

#ifdef HAVE_SODIUM
#include <sodium.h>
#define HAS_CRYPTO 1
#endif

// =========================================================
// 配置
// =========================================================
#define DEFAULT_ITERATIONS      10000
#define DEFAULT_DATA_SIZE       14000   // 10 x 1400 bytes
#define DEFAULT_DATA_SHARDS     10
#define DEFAULT_PARITY_SHARDS   4
#define WARMUP_ITERATIONS       100

// =========================================================
// 工具函数
// =========================================================

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

static double calculate_stddev(double *samples, int count, double mean) {
    double sum_sq = 0;
    for (int i = 0; i < count; i++) {
        double diff = samples[i] - mean;
        sum_sq += diff * diff;
    }
    return sqrt(sum_sq / count);
}

// =========================================================
// FEC 基准测试
// =========================================================

typedef struct {
    double throughput_mbps;
    double latency_us;
    double latency_stddev;
    int    iterations;
    size_t data_size;
} bench_result_t;

static bench_result_t benchmark_fec_encode(fec_type_t type, 
                                            int data_shards,
                                            int parity_shards,
                                            size_t data_size,
                                            int iterations) {
    bench_result_t result = {0};
    
    // 创建 FEC 引擎
    fec_engine_t *engine = fec_create(type, data_shards, parity_shards);
    if (!engine) {
        fprintf(stderr, "[ERROR] Failed to create FEC engine\n");
        return result;
    }
    
    // 分配缓冲区
    uint8_t *data = aligned_alloc(64, data_size);
    uint8_t out_shards[FEC_MAX_TOTAL_SHARDS][FEC_SHARD_SIZE];
    size_t out_lens[FEC_MAX_TOTAL_SHARDS];
    uint32_t group_id;
    
    if (!data) {
        fec_destroy(engine);
        return result;
    }
    
    fill_random(data, data_size);
    
    // 预热
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        fec_encode(engine, data, data_size, out_shards, out_lens, &group_id);
    }
    
    // 收集延迟样本
    double *latencies = malloc(iterations * sizeof(double));
    if (!latencies) {
        free(data);
        fec_destroy(engine);
        return result;
    }
    
    // 正式测试
    uint64_t start_ns = get_time_ns();
    
    for (int i = 0; i < iterations; i++) {
        uint64_t iter_start = get_time_ns();
        fec_encode(engine, data, data_size, out_shards, out_lens, &group_id);
        uint64_t iter_end = get_time_ns();
        
        latencies[i] = (iter_end - iter_start) / 1000.0;  // µs
    }
    
    uint64_t end_ns = get_time_ns();
    
    // 计算结果
    double elapsed_sec = (end_ns - start_ns) / 1e9;
    double total_bytes = (double)data_size * iterations;
    
    result.throughput_mbps = (total_bytes / elapsed_sec) / (1024 * 1024);
    result.iterations = iterations;
    result.data_size = data_size;
    
    // 计算延迟统计
    double sum_latency = 0;
    for (int i = 0; i < iterations; i++) {
        sum_latency += latencies[i];
    }
    result.latency_us = sum_latency / iterations;
    result.latency_stddev = calculate_stddev(latencies, iterations, result.latency_us);
    
    // 清理
    free(latencies);
    free(data);
    fec_destroy(engine);
    
    return result;
}

static bench_result_t benchmark_fec_decode(fec_type_t type,
                                            int data_shards,
                                            int parity_shards,
                                            size_t data_size,
                                            int iterations) {
    bench_result_t result = {0};
    
    // 创建 FEC 引擎
    fec_engine_t *encoder = fec_create(type, data_shards, parity_shards);
    fec_engine_t *decoder = fec_create(type, data_shards, parity_shards);
    
    if (!encoder || !decoder) {
        if (encoder) fec_destroy(encoder);
        if (decoder) fec_destroy(decoder);
        return result;
    }
    
    // 分配缓冲区
    uint8_t *data = aligned_alloc(64, data_size);
    uint8_t out_shards[FEC_MAX_TOTAL_SHARDS][FEC_SHARD_SIZE];
    size_t out_lens[FEC_MAX_TOTAL_SHARDS];
    uint8_t recovered[FEC_SHARD_SIZE * FEC_MAX_DATA_SHARDS];
    size_t recovered_len;
    uint32_t group_id;
    
    if (!data) {
        fec_destroy(encoder);
        fec_destroy(decoder);
        return result;
    }
    
    fill_random(data, data_size);
    
    // 编码一次获取分片
    int num_shards = fec_encode(encoder, data, data_size, out_shards, out_lens, &group_id);
    
    // 收集延迟样本
    double *latencies = malloc(iterations * sizeof(double));
    if (!latencies) {
        free(data);
        fec_destroy(encoder);
        fec_destroy(decoder);
        return result;
    }
    
    // 正式测试（模拟丢失第一个数据分片）
    uint64_t start_ns = get_time_ns();
    
    for (int i = 0; i < iterations; i++) {
        uint64_t iter_start = get_time_ns();
        
        // 重新创建解码器（模拟新的组）
        // 跳过 shard 0，模拟丢失
        for (int s = 1; s < num_shards; s++) {
            fec_decode(decoder, group_id + i, s, out_shards[s], out_lens[s],
                      recovered, &recovered_len);
        }
        
        uint64_t iter_end = get_time_ns();
        latencies[i] = (iter_end - iter_start) / 1000.0;
    }
    
    uint64_t end_ns = get_time_ns();
    
    // 计算结果
    double elapsed_sec = (end_ns - start_ns) / 1e9;
    double total_bytes = (double)data_size * iterations;
    
    result.throughput_mbps = (total_bytes / elapsed_sec) / (1024 * 1024);
    result.iterations = iterations;
    result.data_size = data_size;
    
    double sum_latency = 0;
    for (int i = 0; i < iterations; i++) {
        sum_latency += latencies[i];
    }
    result.latency_us = sum_latency / iterations;
    result.latency_stddev = calculate_stddev(latencies, iterations, result.latency_us);
    
    // 清理
    free(latencies);
    free(data);
    fec_destroy(encoder);
    fec_destroy(decoder);
    
    return result;
}

// =========================================================
// 加密基准测试
// =========================================================

#ifdef HAS_CRYPTO
static bench_result_t benchmark_crypto(size_t data_size, int iterations) {
    bench_result_t result = {0};
    
    uint8_t *plaintext = aligned_alloc(64, data_size);
    uint8_t *ciphertext = aligned_alloc(64, data_size + crypto_aead_chacha20poly1305_ietf_ABYTES);
    uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    unsigned long long ciphertext_len;
    
    if (!plaintext || !ciphertext) {
        if (plaintext) free(plaintext);
        if (ciphertext) free(ciphertext);
        return result;
    }
    
    fill_random(plaintext, data_size);
    randombytes_buf(key, sizeof(key));
    randombytes_buf(nonce, sizeof(nonce));
    
    // 预热
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext, &ciphertext_len,
            plaintext, data_size,
            NULL, 0,
            NULL, nonce, key);
    }
    
    // 收集延迟
    double *latencies = malloc(iterations * sizeof(double));
    if (!latencies) {
        free(plaintext);
        free(ciphertext);
        return result;
    }
    
    uint64_t start_ns = get_time_ns();
    
    for (int i = 0; i < iterations; i++) {
        uint64_t iter_start = get_time_ns();
        
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext, &ciphertext_len,
            plaintext, data_size,
            NULL, 0,
            NULL, nonce, key);
        
        uint64_t iter_end = get_time_ns();
        latencies[i] = (iter_end - iter_start) / 1000.0;
        
        // 递增 nonce
        nonce[0]++;
    }
    
    uint64_t end_ns = get_time_ns();
    
    double elapsed_sec = (end_ns - start_ns) / 1e9;
    double total_bytes = (double)data_size * iterations;
    
    result.throughput_mbps = (total_bytes / elapsed_sec) / (1024 * 1024);
    result.iterations = iterations;
    result.data_size = data_size;
    
    double sum_latency = 0;
    for (int i = 0; i < iterations; i++) {
        sum_latency += latencies[i];
    }
    result.latency_us = sum_latency / iterations;
    result.latency_stddev = calculate_stddev(latencies, iterations, result.latency_us);
    
    free(latencies);
    free(plaintext);
    free(ciphertext);
    
    return result;
}
#endif

// =========================================================
// 报告输出
// =========================================================

static void print_result(const char *name, const bench_result_t *result) {
    printf("║  %-20s │ %10.2f │ %8.2f │ %8.2f │ %8d ║\n",
           name,
           result->throughput_mbps,
           result->latency_us,
           result->latency_stddev,
           result->iterations);
}

static void print_report_header(void) {
    printf("╔══════════════════════════════════════════════════════════════════════╗\n");
    printf("║                         Benchmark Results                            ║\n");
    printf("╠══════════════════════╤════════════╤══════════╤══════════╤════════════╣\n");
    printf("║  Test                │  Throughput│  Latency │  Std Dev │ Iterations ║\n");
    printf("║                      │    (MB/s)  │   (µs)   │   (µs)   │            ║\n");
    printf("╠══════════════════════╪════════════╪══════════╪══════════╪════════════╣\n");
}

static void print_report_footer(void) {
    printf("╚══════════════════════╧════════════╧══════════╧══════════╧════════════╝\n");
}

static void print_section(const char *name) {
    printf("╠══════════════════════╧════════════╧══════════╧══════════╧════════════╣\n");
    printf("║  %-68s ║\n", name);
    printf("╠══════════════════════╤════════════╤══════════╤══════════╤════════════╣\n");
}

// =========================================================
// 主程序
// =========================================================

static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -i, --iterations=N    Number of iterations (default: %d)\n", DEFAULT_ITERATIONS);
    printf("  -s, --size=BYTES      Data size per iteration (default: %d)\n", DEFAULT_DATA_SIZE);
    printf("  -d, --data-shards=N   FEC data shards (default: %d)\n", DEFAULT_DATA_SHARDS);
    printf("  -p, --parity-shards=N FEC parity shards (default: %d)\n", DEFAULT_PARITY_SHARDS);
    printf("  -a, --all             Run all benchmarks\n");
    printf("  -f, --fec             Run FEC benchmarks only\n");
    printf("  -c, --crypto          Run crypto benchmarks only\n");
    printf("  -h, --help            Show this help\n");
}

int main(int argc, char **argv) {
    int iterations = DEFAULT_ITERATIONS;
    size_t data_size = DEFAULT_DATA_SIZE;
    int data_shards = DEFAULT_DATA_SHARDS;
    int parity_shards = DEFAULT_PARITY_SHARDS;
    bool run_fec = true;
    bool run_crypto = true;
    
    static struct option long_opts[] = {
        {"iterations",    required_argument, 0, 'i'},
        {"size",          required_argument, 0, 's'},
        {"data-shards",   required_argument, 0, 'd'},
        {"parity-shards", required_argument, 0, 'p'},
        {"all",           no_argument,       0, 'a'},
        {"fec",           no_argument,       0, 'f'},
        {"crypto",        no_argument,       0, 'c'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:s:d:p:afch", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'i':
                iterations = atoi(optarg);
                break;
            case 's':
                data_size = atoi(optarg);
                break;
            case 'd':
                data_shards = atoi(optarg);
                break;
            case 'p':
                parity_shards = atoi(optarg);
                break;
            case 'a':
                run_fec = true;
                run_crypto = true;
                break;
            case 'f':
                run_fec = true;
                run_crypto = false;
                break;
            case 'c':
                run_fec = false;
                run_crypto = true;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
        }
    }
    
    // 初始化
    srand(time(NULL));
    cpu_detect();
    
#ifdef HAS_CRYPTO
    if (sodium_init() < 0) {
        fprintf(stderr, "[ERROR] Failed to initialize libsodium\n");
        return 1;
    }
#endif
    
    // 打印系统信息
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║                      v3 Benchmark Tool                                ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");
    
    cpu_print_info();
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║                      Test Configuration                               ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Iterations:      %-10d                                          ║\n", iterations);
    printf("║  Data Size:       %-10zu bytes                                    ║\n", data_size);
    printf("║  FEC Config:      %d data + %d parity shards                           ║\n", 
           data_shards, parity_shards);
    printf("║  SIMD Available:  %-10s                                          ║\n", 
           fec_simd_available() ? "Yes" : "No");
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");
    
    printf("Running benchmarks... (this may take a while)\n\n");
    
    // 运行测试
    print_report_header();
    
    if (run_fec) {
        // FEC 编码测试
        print_section("FEC Encode");
        
        // XOR 模式
        bench_result_t xor_encode = benchmark_fec_encode(
            FEC_TYPE_XOR, 4, 1, data_size, iterations);
        print_result("XOR (4:1)", &xor_encode);
        
        // RS Simple
        bench_result_t rs_simple = benchmark_fec_encode(
            FEC_TYPE_RS_SIMPLE, data_shards, parity_shards, data_size, iterations);
        print_result("RS (Simple)", &rs_simple);
        
        // RS SIMD
        bench_result_t rs_simd = benchmark_fec_encode(
            FEC_TYPE_RS_SIMD, data_shards, parity_shards, data_size, iterations);
        print_result("RS (SIMD)", &rs_simd);
        
        // RS Auto
        bench_result_t rs_auto = benchmark_fec_encode(
            FEC_TYPE_AUTO, data_shards, parity_shards, data_size, iterations);
        print_result("RS (Auto)", &rs_auto);
        
        // FEC 解码测试
        print_section("FEC Decode (1 shard lost)");
        
        bench_result_t decode_simd = benchmark_fec_decode(
            FEC_TYPE_RS_SIMD, data_shards, parity_shards, data_size, iterations / 10);
        print_result("RS Decode (SIMD)", &decode_simd);
    }
    
#ifdef HAS_CRYPTO
    if (run_crypto) {
        print_section("Crypto (ChaCha20-Poly1305)");
        
        // 不同大小的加密测试
        size_t sizes[] = {64, 256, 1024, 1400, 4096};
        const char *names[] = {"64 bytes", "256 bytes", "1024 bytes", "1400 bytes", "4096 bytes"};
        
        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
            bench_result_t crypto_result = benchmark_crypto(sizes[i], iterations);
            print_result(names[i], &crypto_result);
        }
    }
#else
    if (run_crypto) {
        print_section("Crypto (Not Available)");
        printf("║  (Compile with -DHAVE_SODIUM and link -lsodium for crypto tests)     ║\n");
    }
#endif
    
    print_report_footer();
    
    // 打印性能对比
    if (run_fec) {
        printf("\n");
        printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
        printf("║                      Performance Summary                              ║\n");
        printf("╠═══════════════════════════════════════════════════════════════════════╣\n");
        
        bench_result_t simple = benchmark_fec_encode(
            FEC_TYPE_RS_SIMPLE, data_shards, parity_shards, data_size, 1000);
        bench_result_t simd = benchmark_fec_encode(
            FEC_TYPE_RS_SIMD, data_shards, parity_shards, data_size, 1000);
        
        double speedup = simd.throughput_mbps / simple.throughput_mbps;
        
        printf("║  SIMD Speedup:    %.2fx vs Simple implementation                      ║\n", 
               speedup);
        printf("║  CPU Level:       %-50s  ║\n", cpu_level_name(cpu_get_level()));
        printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
    }
    
    printf("\nBenchmark complete.\n\n");
    
    return 0;
}



