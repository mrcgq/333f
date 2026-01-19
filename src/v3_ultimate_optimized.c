
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <liburing.h>
#include <sodium.h>
#include <getopt.h>

// 引入模块头文件
#include "v3_fec_simd.h"
#include "v3_pacing_adaptive.h"
#include "v3_antidetect_mtu.h"
#include "v3_cpu_dispatch.h"
#include "v3_health.h"

// =========================================================
// 配置常量
// =========================================================
#define V3_PORT             51820
#define QUEUE_DEPTH         4096
#define BUF_SIZE            2048
#define MAX_CONNS           32768
#define MAGIC_WINDOW_SEC    60          // Magic 有效窗口（秒）
#define MAGIC_TOLERANCE     1           // 允许前后各 1 个窗口

// =========================================================
// 全局配置结构
// =========================================================
typedef struct {
    bool        fec_enabled;
    fec_type_t  fec_type;
    uint8_t     fec_data_shards;
    uint8_t     fec_parity_shards;
    
    bool        pacing_enabled;
    uint64_t    pacing_rate;
    uint64_t    pacing_initial_bps;
    uint64_t    pacing_min_bps;
    uint64_t    pacing_max_bps;
    
    ad_profile_t ad_profile;
    uint16_t     mtu;
    
    uint16_t    port;
    const char *bind_addr;
    
    bool        verbose;
    bool        benchmark;

    // 健康检查配置
    bool        health_enabled;
    int         health_port;
    int         health_interval;
} config_t;

static config_t g_config = {
    .fec_enabled = false,
    .fec_type = FEC_TYPE_AUTO,
    .fec_data_shards = 5,
    .fec_parity_shards = 2,
    .pacing_enabled = false,
    .pacing_initial_bps = 100 * 1000 * 1000,
    .pacing_min_bps = 1 * 1000 * 1000,
    .pacing_max_bps = 1000 * 1000 * 1000,
    .ad_profile = AD_PROFILE_NONE,
    .mtu = 1500,
    .port = 51820,
    .bind_addr = "0.0.0.0",
    .verbose = false,
    .benchmark = false,
    .health_enabled = true,
    .health_port = 8080,
    .health_interval = 60,
};

// =========================================================
// 全局状态
// =========================================================
static fec_engine_t *g_fec = NULL;
static pacing_adaptive_t g_pacing;
static ad_mtu_ctx_t g_antidetect;
static v3_health_ctx_t g_health_ctx;
static struct io_uring g_ring;
static volatile sig_atomic_t g_running = 1;
static uint8_t g_master_key[32];

// =========================================================
// 协议定义
// =========================================================
typedef struct __attribute__((packed)) {
    uint32_t magic_derived; 
    uint8_t  nonce[12];     
    uint8_t  enc_block[16]; 
    uint8_t  tag[16];
    uint16_t early_len;     
    uint16_t pad;
} v3_header_t;

#define V3_HEADER_SIZE sizeof(v3_header_t)

// I/O 上下文
typedef struct {
    int fd;
    struct sockaddr_in addr;
    struct iovec iov;
    struct msghdr msg;
    uint8_t buf[BUF_SIZE];
    enum { OP_READ, OP_WRITE } op;
} io_context_t;

static io_context_t g_io_ctx_pool[MAX_CONNS];

// =========================================================
// [修复] Magic 派生与验证（安全实现）
// =========================================================

/**
 * @brief 派生 Magic 值
 * 
 * 使用 Master Key + 时间窗口生成 4 字节 Magic
 * 时间窗口为 60 秒，确保客户端和服务端在同一窗口内生成相同 Magic
 * 
 * @param window 时间窗口（通常是 time(NULL) / MAGIC_WINDOW_SEC）
 * @return 4 字节 Magic 值
 */
static uint32_t derive_magic(uint64_t window) {
    // 构造输入：Key (32 bytes) + Window (8 bytes)
    uint8_t input[40];
    memcpy(input, g_master_key, 32);
    
    // 小端序写入窗口值
    input[32] = (window >> 0)  & 0xFF;
    input[33] = (window >> 8)  & 0xFF;
    input[34] = (window >> 16) & 0xFF;
    input[35] = (window >> 24) & 0xFF;
    input[36] = (window >> 32) & 0xFF;
    input[37] = (window >> 40) & 0xFF;
    input[38] = (window >> 48) & 0xFF;
    input[39] = (window >> 56) & 0xFF;
    
    // 使用 BLAKE2b 生成 Hash
    uint8_t hash[32];
    if (crypto_generichash(hash, sizeof(hash), input, sizeof(input), NULL, 0) != 0) {
        // 如果 Hash 失败，返回 0（会被验证拒绝）
        return 0;
    }
    
    // 取前 4 字节作为 Magic
    uint32_t magic;
    memcpy(&magic, hash, 4);
    
    return magic;
}

/**
 * @brief 获取当前时间窗口的 Magic
 */
static uint32_t get_current_magic(void) {
    time_t now = time(NULL);
    uint64_t window = now / MAGIC_WINDOW_SEC;
    return derive_magic(window);
}

/**
 * @brief 验证 Magic 值
 * 
 * 允许当前窗口 ± MAGIC_TOLERANCE 个窗口的误差
 * 这样可以容忍客户端和服务端的时间差
 * 
 * @param received 收到的 Magic 值
 * @return true 如果 Magic 有效
 */
static bool verify_magic(uint32_t received) {
    time_t now = time(NULL);
    uint64_t current_window = now / MAGIC_WINDOW_SEC;
    
    // 检查当前窗口
    if (received == derive_magic(current_window)) {
        return true;
    }
    
    // 检查前后窗口（容忍时间差）
    for (int offset = 1; offset <= MAGIC_TOLERANCE; offset++) {
        if (received == derive_magic(current_window - offset)) {
            return true;
        }
        if (received == derive_magic(current_window + offset)) {
            return true;
        }
    }
    
    return false;
}

/**
 * @brief 获取有效的 Magic 值列表（用于 XDP）
 * 
 * @param magics 输出数组，至少 3 个元素
 */
static void get_valid_magics(uint32_t magics[3]) {
    time_t now = time(NULL);
    uint64_t current_window = now / MAGIC_WINDOW_SEC;
    
    magics[0] = derive_magic(current_window - 1);   // 前一个窗口
    magics[1] = derive_magic(current_window);       // 当前窗口
    magics[2] = derive_magic(current_window + 1);   // 下一个窗口
}

// =========================================================
// 健康检查打印线程
// =========================================================
static void* health_print_thread(void *arg) {
    int interval = *(int*)arg;
    
    while (g_running) {
        sleep(interval);
        if (!g_running) break;
        
        v3_health_t health;
        v3_health_snapshot(&g_health_ctx, &health);
        v3_health_print(&health);
    }
    
    return NULL;
}

// =========================================================
// 模块初始化
// =========================================================
static void init_modules(void) {
    // 1. CPU 检测
    cpu_detect();
    if (g_config.verbose) {
        cpu_print_info();
    }

    // 2. libsodium 初始化
    if (sodium_init() < 0) {
        fprintf(stderr, "[FATAL] libsodium initialization failed\n");
        exit(1);
    }
    
    // 3. 生成 Master Key（实际生产应从配置文件读取）
    randombytes_buf(g_master_key, sizeof(g_master_key));
    
    if (g_config.verbose) {
        printf("[Crypto] Master key generated\n");
        printf("[Crypto] Current magic: 0x%08X\n", get_current_magic());
    }

    // 4. FEC 引擎
    if (g_config.fec_enabled) {
        g_fec = fec_create(g_config.fec_type, 
                           g_config.fec_data_shards, 
                           g_config.fec_parity_shards);
        if (g_config.verbose) {
            printf("[FEC] Engine initialized (Type: %d, %d:%d)\n",
                   g_config.fec_type,
                   g_config.fec_data_shards,
                   g_config.fec_parity_shards);
        }
    }
    
    // 5. Pacing
    if (g_config.pacing_enabled) {
        pacing_adaptive_init(&g_pacing, g_config.pacing_initial_bps);
        pacing_adaptive_set_range(&g_pacing, 
                                   g_config.pacing_min_bps, 
                                   g_config.pacing_max_bps);
        pacing_adaptive_enable_jitter(&g_pacing, 50000);
        
        if (g_config.verbose) {
            printf("[Pacing] Enabled (Initial: %lu Mbps)\n", 
                   g_config.pacing_initial_bps / 1000000);
        }
    }
    
    // 6. Anti-Detect
    if (g_config.ad_profile != AD_PROFILE_NONE) {
        ad_mtu_init(&g_antidetect, g_config.ad_profile, g_config.mtu);
        
        if (g_config.verbose) {
            const char* profile_names[] = {
                "None", "HTTPS", "Video", "VoIP", "Gaming"
            };
            printf("[AntiDetect] Profile: %s, MTU: %d\n",
                   profile_names[g_config.ad_profile],
                   g_config.mtu);
        }
    }

    // 7. 健康检查
    v3_health_init(&g_health_ctx);
    v3_health_set_modules(&g_health_ctx, 
                           false,  // XDP 状态后续更新
                           g_config.fec_enabled, 
                           g_config.pacing_enabled, 
                           g_config.ad_profile != AD_PROFILE_NONE);

    if (g_config.health_enabled) {
        if (v3_health_start_server(&g_health_ctx, g_config.health_port) == 0) {
            if (g_config.verbose) {
                printf("[Health] HTTP API listening on http://127.0.0.1:%d/\n", 
                       g_config.health_port);
            }
        } else {
            fprintf(stderr, "[WARN] Failed to start health server on port %d\n",
                    g_config.health_port);
        }
    }
}

// =========================================================
// I/O 操作
// =========================================================
static void prepare_recv(struct io_uring *ring, int fd, io_context_t *ctx) {
    ctx->fd = fd;
    ctx->op = OP_READ;
    ctx->iov.iov_base = ctx->buf;
    ctx->iov.iov_len = BUF_SIZE;
    ctx->msg.msg_name = &ctx->addr;
    ctx->msg.msg_namelen = sizeof(ctx->addr);
    ctx->msg.msg_iov = &ctx->iov;
    ctx->msg.msg_iovlen = 1;
    ctx->msg.msg_control = NULL;
    ctx->msg.msg_controllen = 0;
    ctx->msg.msg_flags = 0;
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    while (!sqe) {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }
    
    io_uring_prep_recvmsg(sqe, fd, &ctx->msg, 0);
    io_uring_sqe_set_data(sqe, ctx);
}

static void submit_recv(io_context_t *ctx) {
    prepare_recv(&g_ring, ctx->fd, ctx);
}

// =========================================================
// 包处理逻辑
// =========================================================
static void handle_packet(io_context_t *ctx, int len) {
    // 记录接收流量
    v3_health_record_rx(&g_health_ctx, len);

    // 检查最小长度
    if (len < (int)V3_HEADER_SIZE) {
        v3_health_record_drop(&g_health_ctx, 2);  // 包太短
        submit_recv(ctx);
        return;
    }
    
    v3_header_t *hdr = (v3_header_t*)ctx->buf;
    
    // =========================================================
    // [修复] 使用安全的 Magic 验证
    // =========================================================
    if (!verify_magic(hdr->magic_derived)) {
        v3_health_record_drop(&g_health_ctx, 1);  // Magic 无效
        
        if (g_config.verbose) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ctx->addr.sin_addr, client_ip, sizeof(client_ip));
            printf("[DROP] Invalid magic 0x%08X from %s:%d\n",
                   hdr->magic_derived, client_ip, ntohs(ctx->addr.sin_port));
        }
        
        submit_recv(ctx);
        return;
    }
    
    // 构造 AAD (Additional Authenticated Data)
    uint8_t aad[8];
    memcpy(aad + 0, &hdr->early_len, 2);
    memcpy(aad + 2, &hdr->pad, 2);
    memcpy(aad + 4, &hdr->magic_derived, 4);
    
    // 组合密文 + Tag
    uint8_t combined[32];
    memcpy(combined, hdr->enc_block, 16);
    memcpy(combined + 16, hdr->tag, 16);
    
    // 解密元数据块
    uint8_t plaintext[16];
    unsigned long long decrypted_len;
    
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &decrypted_len, 
            NULL,                           // nsec (unused)
            combined, 32,                   // 密文 + tag
            aad, sizeof(aad),               // AAD
            hdr->nonce,                     // nonce
            g_master_key) != 0) {
        
        v3_health_record_drop(&g_health_ctx, 1);  // 解密失败
        submit_recv(ctx);
        return;
    }

    // 解析元数据
    uint64_t session_token;
    uint16_t intent_id, stream_id, flags;
    
    memcpy(&session_token, plaintext, 8);
    memcpy(&intent_id, plaintext + 8, 2);
    memcpy(&stream_id, plaintext + 10, 2);
    memcpy(&flags, plaintext + 12, 2);
    
    // 计算 payload 长度
    int payload_len = len - (int)V3_HEADER_SIZE;
    
    if (g_config.verbose) {
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ctx->addr.sin_addr, client_ip, sizeof(client_ip));
        printf("[RECV] Session: 0x%lX, Intent: %d, Stream: %d, Payload: %d bytes from %s\n",
               session_token, intent_id, stream_id, payload_len, client_ip);
    }
    
    // Pacing 反馈
    if (g_config.pacing_enabled && payload_len > 0) {
        pacing_adaptive_ack(&g_pacing, len);
    }
    
    // TODO: 实际转发逻辑
    // 这里应该根据 intent_id 查找目标，转发 payload
    // 目前仅作为演示，记录统计后回收
    
    // 继续接收下一个包
    submit_recv(ctx);
}

// =========================================================
// 信号处理
// =========================================================
static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n[INFO] Received signal, shutting down...\n");
}

// =========================================================
// 命令行解析
// =========================================================
static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  --port=PORT           Listen port (default: 51820)\n");
    printf("  --fec                 Enable FEC (auto mode)\n");
    printf("  --fec-shards=D:P      FEC data:parity shards (default: 5:2)\n");
    printf("  --pacing=MBPS         Enable pacing with initial rate\n");
    printf("  --profile=TYPE        Anti-detect profile (https|video|voip|gaming)\n");
    printf("  --health              Enable health HTTP API\n");
    printf("  --health-port=PORT    Health API port (default: 8080)\n");
    printf("  --health-interval=SEC Stats print interval (default: 60)\n");
    printf("  --verbose, -v         Verbose output\n");
    printf("  --benchmark           Run FEC benchmark and exit\n");
    printf("  --help, -h            Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --fec --pacing=100 --profile=https\n", prog);
    printf("  %s --port=443 --health --verbose\n", prog);
}

static void parse_args(int argc, char **argv) {
    static struct option long_opts[] = {
        {"fec",             optional_argument, 0, 'f'},
        {"fec-shards",      required_argument, 0, 'F'},
        {"pacing",          required_argument, 0, 'P'},
        {"profile",         required_argument, 0, 'A'},
        {"port",            required_argument, 0, 'p'},
        {"health",          optional_argument, 0, 'H'},
        {"health-port",     required_argument, 0, 1001},
        {"health-interval", required_argument, 0, 1002},
        {"verbose",         no_argument,       0, 'v'},
        {"benchmark",       no_argument,       0, 'B'},
        {"help",            no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "f::F:P:A:p:H::vBh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'f':
                g_config.fec_enabled = true;
                g_config.fec_type = FEC_TYPE_AUTO;
                break;
                
            case 'F':
                if (sscanf(optarg, "%hhu:%hhu", 
                           &g_config.fec_data_shards, 
                           &g_config.fec_parity_shards) == 2) {
                    g_config.fec_enabled = true;
                } else {
                    fprintf(stderr, "Invalid FEC shards format. Use D:P (e.g., 5:2)\n");
                    exit(1);
                }
                break;
                
            case 'P':
                g_config.pacing_enabled = true;
                g_config.pacing_initial_bps = atoll(optarg) * 1000000ULL;
                break;
                
            case 'A':
                if (strcmp(optarg, "https") == 0) {
                    g_config.ad_profile = AD_PROFILE_HTTPS;
                } else if (strcmp(optarg, "video") == 0) {
                    g_config.ad_profile = AD_PROFILE_VIDEO;
                } else if (strcmp(optarg, "voip") == 0) {
                    g_config.ad_profile = AD_PROFILE_VOIP;
                } else if (strcmp(optarg, "gaming") == 0) {
                    g_config.ad_profile = AD_PROFILE_GAMING;
                } else {
                    fprintf(stderr, "Unknown profile: %s\n", optarg);
                    fprintf(stderr, "Available: https, video, voip, gaming\n");
                    exit(1);
                }
                break;
                
            case 'p':
                g_config.port = atoi(optarg);
                if (g_config.port == 0 || g_config.port > 65535) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    exit(1);
                }
                break;
                
            case 'H':
                g_config.health_enabled = true;
                if (optarg) {
                    g_config.health_port = atoi(optarg);
                }
                break;
                
            case 1001:
                g_config.health_port = atoi(optarg);
                break;
                
            case 1002:
                g_config.health_interval = atoi(optarg);
                break;
                
            case 'v':
                g_config.verbose = true;
                break;
                
            case 'B':
                g_config.benchmark = true;
                break;
                
            case 'h':
                usage(argv[0]);
                exit(0);
                
            default:
                usage(argv[0]);
                exit(1);
        }
    }
}

// =========================================================
// 基准测试
// =========================================================
static void run_benchmark(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    v3 FEC Benchmark                           ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    cpu_print_info();
    
    if (!g_config.fec_enabled) {
        g_fec = fec_create(FEC_TYPE_AUTO, 10, 4);
    }
    
    if (g_fec) {
        printf("[Benchmark] Running FEC encode test...\n");
        
        double throughput = fec_benchmark(fec_get_type(g_fec), 1400 * 10, 10000);
        
        printf("[Result] Throughput: %.2f MB/s\n", throughput);
        printf("[Result] FEC Type: %d\n", fec_get_type(g_fec));
        
        fec_destroy(g_fec);
    }
    
    printf("\nBenchmark complete.\n");
}

// =========================================================
// 主程序
// =========================================================
int main(int argc, char **argv) {
    parse_args(argc, argv);
    
    // 打印横幅
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║               v3 Ultimate Server (Enterprise)                 ║\n");
    printf("║         io_uring + SIMD FEC + Adaptive Pacing                 ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    // 初始化模块
    init_modules();
    
    // 基准测试模式
    if (g_config.benchmark) {
        run_benchmark();
        return 0;
    }
    
    // 信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    // 启动健康打印线程
    pthread_t health_tid = 0;
    if (g_config.health_interval > 0) {
        pthread_create(&health_tid, NULL, health_print_thread, &g_config.health_interval);
    }
    
    // 创建 UDP socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    
    // Socket 选项
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
    
    // 增大缓冲区
    int bufsize = 4 * 1024 * 1024;  // 4MB
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    
    // 绑定
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(g_config.port),
        .sin_addr.s_addr = INADDR_ANY
    };
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return 1;
    }
    
    // 初始化 io_uring
    struct io_uring_params params = {0};
    
    // 如果是 root，启用 SQPOLL 模式
    if (geteuid() == 0) {
        params.flags |= IORING_SETUP_SQPOLL;
        params.sq_thread_idle = 2000;  // 2 秒空闲后休眠
    }
    
    if (io_uring_queue_init_params(QUEUE_DEPTH, &g_ring, &params) < 0) {
        perror("io_uring_queue_init");
        close(fd);
        return 1;
    }
    
    printf("[INFO] v3 Server listening on 0.0.0.0:%d\n", g_config.port);
    printf("[INFO] Health API: http://127.0.0.1:%d/\n", g_config.health_port);
    printf("[INFO] Press Ctrl+C to stop\n\n");
    
    // 预提交所有接收请求
    for (int i = 0; i < MAX_CONNS; i++) {
        prepare_recv(&g_ring, fd, &g_io_ctx_pool[i]);
    }
    io_uring_submit(&g_ring);
    
    // 主循环
    struct io_uring_cqe *cqe;
    
    while (g_running) {
        int ret = io_uring_wait_cqe(&g_ring, &cqe);
        
        if (ret < 0) {
            if (ret == -EINTR) continue;
            perror("io_uring_wait_cqe");
            break;
        }
        
        io_context_t *ctx = (io_context_t *)io_uring_cqe_get_data(cqe);
        
        if (cqe->res > 0 && ctx->op == OP_READ) {
            handle_packet(ctx, cqe->res);
        } else {
            // 错误或空包，重新提交接收
            submit_recv(ctx);
        }
        
        io_uring_cqe_seen(&g_ring, cqe);
    }
    
    // 清理
    printf("[INFO] Cleaning up...\n");
    
    v3_health_stop_server();
    
    if (health_tid) {
        pthread_cancel(health_tid);
        pthread_join(health_tid, NULL);
    }
    
    io_uring_queue_exit(&g_ring);
    close(fd);
    
    if (g_fec) {
        fec_destroy(g_fec);
    }
    
    printf("[INFO] Shutdown complete.\n");
    return 0;
}



