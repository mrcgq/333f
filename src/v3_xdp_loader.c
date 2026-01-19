
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// 如果有 libsodium，用于 Magic 派生
#ifdef HAVE_SODIUM
#include <sodium.h>
#endif

// =========================================================
// 常量定义（必须与 v3_common.h 一致）
// =========================================================
#define V3_PORT             51820
#define MAGIC_WINDOW_SEC    60
#define MAGIC_UPDATE_SEC    30      // Magic 更新间隔

// 统计计数器索引
enum stats_key {
    STAT_PASSED = 0,
    STAT_DROPPED_BLACKLIST,
    STAT_DROPPED_RATELIMIT,
    STAT_DROPPED_INVALID_MAGIC,
    STAT_DROPPED_TOO_SHORT,
    STAT_DROPPED_NOT_UDP,
    STAT_TOTAL_PROCESSED,
    STAT_MAX
};

// =========================================================
// 全局状态
// =========================================================
static struct bpf_object *g_obj = NULL;
static int g_prog_fd = -1;
static int g_ifindex = 0;
static char g_ifname[IF_NAMESIZE] = {0};
static __u32 g_xdp_flags = 0;
static volatile sig_atomic_t g_running = 1;

// Map 文件描述符
static int g_map_valid_magics = -1;
static int g_map_stats = -1;
static int g_map_latency = -1;
static int g_map_blacklist = -1;
static int g_map_rate_limit = -1;
static int g_map_conn_cache = -1;

// Master Key（实际应从配置文件读取）
static uint8_t g_master_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

// =========================================================
// Magic 派生
// =========================================================
static uint32_t derive_magic(uint64_t window) {
    uint8_t input[40];
    memcpy(input, g_master_key, 32);
    
    // 小端序写入窗口值
    for (int i = 0; i < 8; i++) {
        input[32 + i] = (window >> (i * 8)) & 0xFF;
    }
    
#ifdef HAVE_SODIUM
    uint8_t hash[32];
    crypto_generichash(hash, sizeof(hash), input, sizeof(input), NULL, 0);
    uint32_t magic;
    memcpy(&magic, hash, 4);
    return magic;
#else
    // 简单的非加密 Hash（仅用于演示）
    uint32_t hash = 0x811c9dc5;  // FNV-1a offset
    for (size_t i = 0; i < sizeof(input); i++) {
        hash ^= input[i];
        hash *= 0x01000193;  // FNV-1a prime
    }
    return hash;
#endif
}

static void get_valid_magics(uint32_t magics[8]) {
    time_t now = time(NULL);
    uint64_t current_window = now / MAGIC_WINDOW_SEC;
    
    // 扩展时间窗口覆盖，支持更大时钟偏差
    for (int i = 0; i < 8; i++) {
        magics[i] = derive_magic(current_window - 3 + i);  // -3 到 +4
    }
}

// =========================================================
// XDP 操作
// =========================================================

static int xdp_load(const char *obj_path, const char *ifname, __u32 flags) {
    int err;
    
    // 获取接口索引
    g_ifindex = if_nametoindex(ifname);
    if (g_ifindex == 0) {
        fprintf(stderr, "[ERROR] Interface '%s' not found\n", ifname);
        return -1;
    }
    strncpy(g_ifname, ifname, IF_NAMESIZE - 1);
    g_xdp_flags = flags;
    
    printf("[INFO] Loading XDP program from '%s'\n", obj_path);
    printf("[INFO] Target interface: %s (index %d)\n", ifname, g_ifindex);
    
    // 打开 BPF 对象文件
    g_obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(g_obj)) {
        fprintf(stderr, "[ERROR] Failed to open BPF object: %s\n", obj_path);
        g_obj = NULL;
        return -1;
    }
    
    // 加载 BPF 程序
    err = bpf_object__load(g_obj);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to load BPF object: %d\n", err);
        bpf_object__close(g_obj);
        g_obj = NULL;
        return -1;
    }
    
    // 查找程序
    struct bpf_program *prog = bpf_object__find_program_by_name(g_obj, "v3_filter");
    if (!prog) {
        fprintf(stderr, "[ERROR] Failed to find program 'v3_filter'\n");
        bpf_object__close(g_obj);
        g_obj = NULL;
        return -1;
    }
    
    g_prog_fd = bpf_program__fd(prog);
    
    // 获取 Map 文件描述符
    g_map_valid_magics = bpf_object__find_map_fd_by_name(g_obj, "valid_magics");
    g_map_stats = bpf_object__find_map_fd_by_name(g_obj, "stats");
    g_map_latency = bpf_object__find_map_fd_by_name(g_obj, "latency_histogram");
    g_map_blacklist = bpf_object__find_map_fd_by_name(g_obj, "blacklist");
    g_map_rate_limit = bpf_object__find_map_fd_by_name(g_obj, "rate_limit");
    g_map_conn_cache = bpf_object__find_map_fd_by_name(g_obj, "conn_cache");
    
    if (g_map_valid_magics < 0) {
        fprintf(stderr, "[WARN] Map 'valid_magics' not found\n");
    }
    if (g_map_stats < 0) {
        fprintf(stderr, "[WARN] Map 'stats' not found\n");
    }
    
    // 尝试附加 XDP 程序
    printf("[INFO] Attaching XDP program...\n");
    
    // 首先尝试用户指定的模式
    LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts);
    
    err = bpf_xdp_attach(g_ifindex, g_prog_fd, flags, &attach_opts);
    
    if (err < 0) {
        const char *mode_name = "Unknown";
        if (flags & XDP_FLAGS_DRV_MODE) mode_name = "Native";
        else if (flags & XDP_FLAGS_SKB_MODE) mode_name = "Generic";
        else if (flags & XDP_FLAGS_HW_MODE) mode_name = "Offload";
        
        fprintf(stderr, "[WARN] %s mode failed (err=%d), trying fallback...\n", 
                mode_name, err);
        
        // 回退到 Generic 模式
        if (!(flags & XDP_FLAGS_SKB_MODE)) {
            g_xdp_flags = XDP_FLAGS_SKB_MODE;
            err = bpf_xdp_attach(g_ifindex, g_prog_fd, g_xdp_flags, &attach_opts);
        }
        
        if (err < 0) {
            fprintf(stderr, "[ERROR] Failed to attach XDP program: %d\n", err);
            bpf_object__close(g_obj);
            g_obj = NULL;
            return -1;
        }
    }
    
    // 确定实际使用的模式
    const char *mode = "Unknown";
    if (g_xdp_flags & XDP_FLAGS_HW_MODE) mode = "Offload (Hardware)";
    else if (g_xdp_flags & XDP_FLAGS_DRV_MODE) mode = "Native (Driver)";
    else if (g_xdp_flags & XDP_FLAGS_SKB_MODE) mode = "Generic (SKB)";
    
    printf("[OK] XDP program attached successfully\n");
    printf("[INFO] Mode: %s\n", mode);
    
    return 0;
}

static void xdp_unload(void) {
    if (g_ifindex > 0) {
        printf("[INFO] Detaching XDP program from %s...\n", g_ifname);
        
        LIBBPF_OPTS(bpf_xdp_attach_opts, detach_opts);
        bpf_xdp_detach(g_ifindex, g_xdp_flags, &detach_opts);
        
        g_ifindex = 0;
    }
    
    if (g_obj) {
        bpf_object__close(g_obj);
        g_obj = NULL;
    }
    
    printf("[OK] XDP program detached\n");
}

// =========================================================
// Magic 表更新
// =========================================================
static int xdp_update_magics(void) {
    if (g_map_valid_magics < 0) {
        return -1;
    }
    

	uint32_t magics[8];
    get_valid_magics(magics);

    for (uint32_t i = 0; i < 8; i++) {
        if (bpf_map_update_elem(g_map_valid_magics, &i, &magics[i], BPF_ANY) != 0) {
            fprintf(stderr, "[ERROR] Failed to update magic[%u]\n", i);
            return -1;
        }
    }
    
    return 0;
}

// =========================================================
// 统计信息读取
// =========================================================
typedef struct {
    uint64_t passed;
    uint64_t dropped_blacklist;
    uint64_t dropped_ratelimit;
    uint64_t dropped_invalid_magic;
    uint64_t dropped_too_short;
    uint64_t dropped_not_udp;
    uint64_t total_processed;
    uint64_t latency_buckets[4];
} xdp_stats_t;

static int xdp_get_stats(xdp_stats_t *stats) {
    memset(stats, 0, sizeof(*stats));
    
    if (g_map_stats < 0) {
        return -1;
    }
    
    // 读取统计（PERCPU_ARRAY 需要聚合所有 CPU 的值）
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) {
        return -1;
    }
    
    uint64_t *values = calloc(num_cpus, sizeof(uint64_t));
    if (!values) {
        return -1;
    }
    
    uint64_t *stat_ptrs[] = {
        &stats->passed,
        &stats->dropped_blacklist,
        &stats->dropped_ratelimit,
        &stats->dropped_invalid_magic,
        &stats->dropped_too_short,
        &stats->dropped_not_udp,
        &stats->total_processed,
    };
    
    for (uint32_t key = 0; key < STAT_MAX; key++) {
        if (bpf_map_lookup_elem(g_map_stats, &key, values) == 0) {
            for (int cpu = 0; cpu < num_cpus; cpu++) {
                if (key < sizeof(stat_ptrs) / sizeof(stat_ptrs[0])) {
                    *stat_ptrs[key] += values[cpu];
                }
            }
        }
    }
    
    // 读取延迟直方图
    if (g_map_latency >= 0) {
        for (uint32_t bucket = 0; bucket < 4; bucket++) {
            memset(values, 0, num_cpus * sizeof(uint64_t));
            if (bpf_map_lookup_elem(g_map_latency, &bucket, values) == 0) {
                for (int cpu = 0; cpu < num_cpus; cpu++) {
                    stats->latency_buckets[bucket] += values[cpu];
                }
            }
        }
    }
    
    free(values);
    return 0;
}

static void xdp_print_stats(const xdp_stats_t *stats) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    XDP Statistics                             ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Processed:     %-20lu                    ║\n", stats->total_processed);
    printf("║  Passed:              %-20lu                    ║\n", stats->passed);
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Dropped (Blacklist): %-20lu                    ║\n", stats->dropped_blacklist);
    printf("║  Dropped (Ratelimit): %-20lu                    ║\n", stats->dropped_ratelimit);
    printf("║  Dropped (Bad Magic): %-20lu                    ║\n", stats->dropped_invalid_magic);
    printf("║  Dropped (Too Short): %-20lu                    ║\n", stats->dropped_too_short);
    printf("║  Non-UDP (Passed):    %-20lu                    ║\n", stats->dropped_not_udp);
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Latency Histogram:                                           ║\n");
    printf("║    < 1µs:             %-20lu                    ║\n", stats->latency_buckets[0]);
    printf("║    1-10µs:            %-20lu                    ║\n", stats->latency_buckets[1]);
    printf("║    10-100µs:          %-20lu                    ║\n", stats->latency_buckets[2]);
    printf("║    > 100µs:           %-20lu                    ║\n", stats->latency_buckets[3]);
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

// =========================================================
// 信号处理
// =========================================================
static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n[INFO] Received signal, stopping...\n");
}

// =========================================================
// 主程序
// =========================================================
static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -i, --interface=IFACE   Network interface (required)\n");
    printf("  -o, --object=FILE       BPF object file (default: v3_xdp.o)\n");
    printf("  -m, --mode=MODE         XDP mode: native, generic, offload (default: native)\n");
    printf("  -s, --stats-interval=N  Stats print interval in seconds (default: 5)\n");
    printf("  -u, --unload            Unload existing XDP program and exit\n");
    printf("  -h, --help              Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -i eth0                    # Load with native mode\n", prog);
    printf("  %s -i eth0 -m generic         # Load with generic mode\n", prog);
    printf("  %s -i eth0 -u                 # Unload XDP program\n", prog);
}

int main(int argc, char **argv) {
    const char *ifname = NULL;
    const char *obj_path = "v3_xdp.o";
    const char *mode_str = "native";
    int stats_interval = 5;
    bool unload_only = false;
    
    static struct option long_opts[] = {
        {"interface",      required_argument, 0, 'i'},
        {"object",         required_argument, 0, 'o'},
        {"mode",           required_argument, 0, 'm'},
        {"stats-interval", required_argument, 0, 's'},
        {"unload",         no_argument,       0, 'u'},
        {"help",           no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:m:s:uh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'i':
                ifname = optarg;
                break;
            case 'o':
                obj_path = optarg;
                break;
            case 'm':
                mode_str = optarg;
                break;
            case 's':
                stats_interval = atoi(optarg);
                break;
            case 'u':
                unload_only = true;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
        }
    }
    
    if (!ifname) {
        fprintf(stderr, "[ERROR] Interface name is required (-i)\n");
        usage(argv[0]);
        return 1;
    }
    
    // 确定 XDP 模式
    __u32 xdp_flags = 0;
    if (strcmp(mode_str, "native") == 0) {
        xdp_flags = XDP_FLAGS_DRV_MODE;
    } else if (strcmp(mode_str, "generic") == 0 || strcmp(mode_str, "skb") == 0) {
        xdp_flags = XDP_FLAGS_SKB_MODE;
    } else if (strcmp(mode_str, "offload") == 0 || strcmp(mode_str, "hw") == 0) {
        xdp_flags = XDP_FLAGS_HW_MODE;
    } else {
        fprintf(stderr, "[ERROR] Unknown mode: %s\n", mode_str);
        return 1;
    }
    
    // 仅卸载模式
    if (unload_only) {
        int ifidx = if_nametoindex(ifname);
        if (ifidx == 0) {
            fprintf(stderr, "[ERROR] Interface '%s' not found\n", ifname);
            return 1;
        }
        
        printf("[INFO] Unloading XDP from %s...\n", ifname);
        
        LIBBPF_OPTS(bpf_xdp_attach_opts, detach_opts);
        
        // 尝试所有模式的卸载
        bpf_xdp_detach(ifidx, XDP_FLAGS_DRV_MODE, &detach_opts);
        bpf_xdp_detach(ifidx, XDP_FLAGS_SKB_MODE, &detach_opts);
        bpf_xdp_detach(ifidx, XDP_FLAGS_HW_MODE, &detach_opts);
        bpf_xdp_detach(ifidx, 0, &detach_opts);
        
        printf("[OK] XDP program unloaded\n");
        return 0;
    }
    
    // 打印横幅
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    v3 XDP Loader                              ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    // 信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 加载 XDP 程序
    if (xdp_load(obj_path, ifname, xdp_flags) != 0) {
        return 1;
    }
    
    // 初始更新 Magic 表
    if (xdp_update_magics() == 0) {
        uint32_t magics[3];
        get_valid_magics(magics);
        printf("[INFO] Magic table updated: 8 slots, current=0x%08X\n", magics[3]);
    }
    
    printf("[INFO] Running... (Ctrl+C to stop)\n");
    printf("[INFO] Stats interval: %d seconds\n\n", stats_interval);
    
    // 主循环
    time_t last_magic_update = time(NULL);
    time_t last_stats_print = time(NULL);
    
    while (g_running) {
        sleep(1);
        
        time_t now = time(NULL);
        
        // 定时更新 Magic
        if (now - last_magic_update >= MAGIC_UPDATE_SEC) {
            if (xdp_update_magics() == 0) {
                printf("[INFO] Magic table refreshed at %ld\n", now);
            }
            last_magic_update = now;
        }
        
        // 定时打印统计
        if (now - last_stats_print >= stats_interval) {
            xdp_stats_t stats;
            if (xdp_get_stats(&stats) == 0) {
                xdp_print_stats(&stats);
            }
            last_stats_print = now;
        }
    }
    
    // 清理
    xdp_unload();
    
    return 0;
}



