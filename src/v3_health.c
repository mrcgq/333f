
#define _GNU_SOURCE
#include "v3_health.h"
#include "v3_cpu_dispatch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

// =========================================================
// 版本信息
// =========================================================
#ifndef V3_VERSION
#define V3_VERSION "1.0.0"
#endif

#ifndef V3_BUILD_TIME
#define V3_BUILD_TIME __DATE__ " " __TIME__
#endif

// =========================================================
// 辅助函数
// =========================================================

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline uint64_t get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec;
}

// 读取 CPU 使用率
static void read_cpu_stats(uint64_t *total, uint64_t *idle) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) {
        *total = 0;
        *idle = 0;
        return;
    }
    
    char line[256];
    if (fgets(line, sizeof(line), f)) {
        uint64_t user, nice, system, idle_val, iowait, irq, softirq, steal;
        sscanf(line, "cpu %lu %lu %lu %lu %lu %lu %lu %lu",
               &user, &nice, &system, &idle_val, &iowait, &irq, &softirq, &steal);
        
        *idle = idle_val + iowait;
        *total = user + nice + system + idle_val + iowait + irq + softirq + steal;
    }
    
    fclose(f);
}

// 读取内存使用
static void read_memory_stats(float *mb, float *percent) {
    // 读取进程内存
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        *mb = 0;
        *percent = 0;
        return;
    }
    
    char line[256];
    uint64_t vm_rss = 0;
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%lu", &vm_rss);
            break;
        }
    }
    fclose(f);
    
    *mb = vm_rss / 1024.0f;
    
    // 读取系统总内存
    f = fopen("/proc/meminfo", "r");
    if (!f) {
        *percent = 0;
        return;
    }
    
    uint64_t mem_total = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            sscanf(line + 9, "%lu", &mem_total);
            break;
        }
    }
    fclose(f);
    
    if (mem_total > 0) {
        *percent = (vm_rss * 100.0f) / mem_total;
    } else {
        *percent = 0;
    }
}

// 检查 XDP 是否激活
static bool check_xdp_active(void) {
    // 检查是否有 XDP 程序附加到任何接口
    FILE *f = popen("ip link show 2>/dev/null | grep -c 'xdp' || echo 0", "r");
    if (!f) return false;
    
    int count = 0;
    fscanf(f, "%d", &count);
    pclose(f);
    
    return count > 0;
}

// 计算 P99 延迟
static uint64_t calculate_p99(uint64_t *samples, int count) {
    if (count == 0) return 0;
    
    // 复制并排序
    uint64_t sorted[1000];
    int n = (count > 1000) ? 1000 : count;
    memcpy(sorted, samples, n * sizeof(uint64_t));
    
    // 简单冒泡排序（样本数小，可以接受）
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (sorted[j] > sorted[j + 1]) {
                uint64_t t = sorted[j];
                sorted[j] = sorted[j + 1];
                sorted[j + 1] = t;
            }
        }
    }
    
    int p99_idx = (n * 99) / 100;
    return sorted[p99_idx];
}

// =========================================================
// API 实现
// =========================================================

void v3_health_init(v3_health_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->start_time_ns = get_time_ns();
    ctx->last_sample_time_ns = ctx->start_time_ns;
}

void v3_health_record_rx(v3_health_ctx_t *ctx, size_t bytes) {
    __sync_fetch_and_add(&ctx->packets_rx, 1);
    __sync_fetch_and_add(&ctx->bytes_rx, bytes);
}

void v3_health_record_tx(v3_health_ctx_t *ctx, size_t bytes) {
    __sync_fetch_and_add(&ctx->packets_tx, 1);
    __sync_fetch_and_add(&ctx->bytes_tx, bytes);
}

void v3_health_record_drop(v3_health_ctx_t *ctx, int reason) {
    __sync_fetch_and_add(&ctx->packets_dropped, 1);
    if (reason == 1) {
        __sync_fetch_and_add(&ctx->packets_invalid, 1);
    }
}

void v3_health_record_fec(v3_health_ctx_t *ctx, bool recovered) {
    __sync_fetch_and_add(&ctx->fec_groups, 1);
    if (recovered) {
        __sync_fetch_and_add(&ctx->fec_recoveries, 1);
    } else {
        __sync_fetch_and_add(&ctx->fec_failures, 1);
    }
}

void v3_health_record_latency(v3_health_ctx_t *ctx, uint64_t latency_us) {
    __sync_fetch_and_add(&ctx->latency_sum_us, latency_us);
    __sync_fetch_and_add(&ctx->latency_count, 1);
    
    // 存入环形缓冲
    int idx = __sync_fetch_and_add(&ctx->latency_idx, 1) % 1000;
    ctx->latency_samples[idx] = latency_us;
}

void v3_health_record_connection(v3_health_ctx_t *ctx, bool connected) {
    if (connected) {
        __sync_fetch_and_add(&ctx->connections_active, 1);
        __sync_fetch_and_add(&ctx->connections_total, 1);
    } else {
        __sync_fetch_and_sub(&ctx->connections_active, 1);
    }
}

void v3_health_set_modules(v3_health_ctx_t *ctx, 
                            bool xdp, bool fec, 
                            bool pacing, bool antidetect) {
    ctx->xdp_active = xdp;
    ctx->fec_enabled = fec;
    ctx->pacing_enabled = pacing;
    ctx->antidetect_enabled = antidetect;
}

void v3_health_snapshot(v3_health_ctx_t *ctx, v3_health_t *health) {
    memset(health, 0, sizeof(*health));
    
    uint64_t now_ns = get_time_ns();
    
    // 基础信息
    health->uptime_sec = (now_ns - ctx->start_time_ns) / 1000000000ULL;
    health->start_time = get_time_sec() - health->uptime_sec;
    
    // 流量统计
    health->packets_rx = ctx->packets_rx;
    health->packets_tx = ctx->packets_tx;
    health->bytes_rx = ctx->bytes_rx;
    health->bytes_tx = ctx->bytes_tx;
    health->packets_dropped = ctx->packets_dropped;
    health->packets_invalid = ctx->packets_invalid;
    
    // 计算速率
    uint64_t elapsed_ns = now_ns - ctx->last_sample_time_ns;
    if (elapsed_ns > 0) {
        uint64_t packets_delta = ctx->packets_rx - ctx->last_packets_rx;
        uint64_t bytes_delta = ctx->bytes_rx - ctx->last_bytes_rx;
        
        health->packets_per_sec = (packets_delta * 1000000000ULL) / elapsed_ns;
        health->bytes_per_sec = (bytes_delta * 1000000000ULL) / elapsed_ns;
        
        // 更新采样点
        ctx->last_sample_time_ns = now_ns;
        ctx->last_packets_rx = ctx->packets_rx;
        ctx->last_bytes_rx = ctx->bytes_rx;
    }
    
    // FEC 统计
    health->fec_groups_total = ctx->fec_groups;
    health->fec_recoveries = ctx->fec_recoveries;
    health->fec_failures = ctx->fec_failures;
    if (ctx->fec_groups > 0) {
        health->fec_recovery_rate = (float)ctx->fec_recoveries / ctx->fec_groups * 100.0f;
    }
    
    // 连接统计
    health->connections_active = ctx->connections_active;
    health->connections_total = ctx->connections_total;
    
    // 延迟统计
    if (ctx->latency_count > 0) {
        health->latency_avg_us = ctx->latency_sum_us / ctx->latency_count;
        int sample_count = (ctx->latency_count > 1000) ? 1000 : ctx->latency_count;
        health->latency_p99_us = calculate_p99(ctx->latency_samples, sample_count);
    }
    
    // CPU 使用率
    uint64_t cpu_total, cpu_idle;
    read_cpu_stats(&cpu_total, &cpu_idle);
    
    if (ctx->last_cpu_total > 0) {
        uint64_t total_delta = cpu_total - ctx->last_cpu_total;
        uint64_t idle_delta = cpu_idle - ctx->last_cpu_idle;
        
        if (total_delta > 0) {
            health->cpu_usage = 100.0f * (1.0f - (float)idle_delta / total_delta);
        }
    }
    ctx->last_cpu_total = cpu_total;
    ctx->last_cpu_idle = cpu_idle;
    
    // 内存使用
    read_memory_stats(&health->memory_mb, &health->memory_percent);
    
    // 模块状态
    health->xdp_active = ctx->xdp_active || check_xdp_active();
    health->fec_enabled = ctx->fec_enabled;
    health->pacing_enabled = ctx->pacing_enabled;
    health->antidetect_enabled = ctx->antidetect_enabled;
    
    // CPU 信息
    cpu_detect();
    strncpy(health->cpu_level, cpu_level_name(cpu_get_level()), sizeof(health->cpu_level) - 1);
    
    // 版本信息
    strncpy(health->version, V3_VERSION, sizeof(health->version) - 1);
    strncpy(health->build_time, V3_BUILD_TIME, sizeof(health->build_time) - 1);
}

void v3_health_print(const v3_health_t *health) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    v3 Server Health Status                    ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    // 基础信息
    int days = health->uptime_sec / 86400;
    int hours = (health->uptime_sec % 86400) / 3600;
    int mins = (health->uptime_sec % 3600) / 60;
    int secs = health->uptime_sec % 60;
    
    printf("║  Uptime:        %d days, %02d:%02d:%02d                            ║\n",
           days, hours, mins, secs);
    printf("║  Version:       %-20s                        ║\n", health->version);
    printf("║  CPU Level:     %-20s                        ║\n", health->cpu_level);
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Traffic Statistics                                           ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    // 流量统计
    double rx_mb = health->bytes_rx / (1024.0 * 1024.0);
    double tx_mb = health->bytes_tx / (1024.0 * 1024.0);
    double throughput_mbps = (health->bytes_per_sec * 8.0) / (1024.0 * 1024.0);
    
    printf("║  Packets RX:    %-15lu  TX: %-15lu     ║\n", 
           health->packets_rx, health->packets_tx);
    printf("║  Bytes RX:      %-10.2f MB   TX: %-10.2f MB          ║\n", 
           rx_mb, tx_mb);
    printf("║  Throughput:    %-10.2f Mbps                              ║\n", 
           throughput_mbps);
    printf("║  Packets/sec:   %-15lu                              ║\n", 
           health->packets_per_sec);
    printf("║  Dropped:       %-10lu  Invalid: %-10lu            ║\n",
           health->packets_dropped, health->packets_invalid);
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  FEC Statistics                                               ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    printf("║  Groups:        %-15lu                              ║\n", 
           health->fec_groups_total);
    printf("║  Recoveries:    %-10lu  Failures: %-10lu          ║\n",
           health->fec_recoveries, health->fec_failures);
    printf("║  Recovery Rate: %-6.2f%%                                       ║\n",
           health->fec_recovery_rate);
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Performance                                                  ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    printf("║  Latency Avg:   %-10lu µs                                 ║\n",
           health->latency_avg_us);
    printf("║  Latency P99:   %-10lu µs                                 ║\n",
           health->latency_p99_us);
    printf("║  Connections:   %-10u active / %-10u total          ║\n",
           health->connections_active, health->connections_total);
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  System Resources                                             ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    printf("║  CPU Usage:     %-6.2f%%                                       ║\n",
           health->cpu_usage);
    printf("║  Memory:        %-10.2f MB (%.2f%%)                        ║\n",
           health->memory_mb, health->memory_percent);
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Modules                                                      ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    printf("║  XDP:           %-5s  FEC:         %-5s                    ║\n",
           health->xdp_active ? "ON" : "OFF",
           health->fec_enabled ? "ON" : "OFF");
    printf("║  Pacing:        %-5s  Anti-Detect: %-5s                    ║\n",
           health->pacing_enabled ? "ON" : "OFF",
           health->antidetect_enabled ? "ON" : "OFF");
    
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

int v3_health_to_json(const v3_health_t *health, char *buf, size_t buflen) {
    return snprintf(buf, buflen,
        "{\n"
        "  \"uptime_sec\": %lu,\n"
        "  \"version\": \"%s\",\n"
        "  \"cpu_level\": \"%s\",\n"
        "  \"traffic\": {\n"
        "    \"packets_rx\": %lu,\n"
        "    \"packets_tx\": %lu,\n"
        "    \"bytes_rx\": %lu,\n"
        "    \"bytes_tx\": %lu,\n"
        "    \"packets_per_sec\": %lu,\n"
        "    \"bytes_per_sec\": %lu,\n"
        "    \"dropped\": %lu,\n"
        "    \"invalid\": %lu\n"
        "  },\n"
        "  \"fec\": {\n"
        "    \"groups\": %lu,\n"
        "    \"recoveries\": %lu,\n"
        "    \"failures\": %lu,\n"
        "    \"recovery_rate\": %.2f\n"
        "  },\n"
        "  \"performance\": {\n"
        "    \"latency_avg_us\": %lu,\n"
        "    \"latency_p99_us\": %lu,\n"
        "    \"connections_active\": %u,\n"
        "    \"connections_total\": %u\n"
        "  },\n"
        "  \"system\": {\n"
        "    \"cpu_usage\": %.2f,\n"
        "    \"memory_mb\": %.2f,\n"
        "    \"memory_percent\": %.2f\n"
        "  },\n"
        "  \"modules\": {\n"
        "    \"xdp\": %s,\n"
        "    \"fec\": %s,\n"
        "    \"pacing\": %s,\n"
        "    \"antidetect\": %s\n"
        "  }\n"
        "}\n",
        health->uptime_sec,
        health->version,
        health->cpu_level,
        health->packets_rx, health->packets_tx,
        health->bytes_rx, health->bytes_tx,
        health->packets_per_sec, health->bytes_per_sec,
        health->packets_dropped, health->packets_invalid,
        health->fec_groups_total, health->fec_recoveries,
        health->fec_failures, health->fec_recovery_rate,
        health->latency_avg_us, health->latency_p99_us,
        health->connections_active, health->connections_total,
        health->cpu_usage, health->memory_mb, health->memory_percent,
        health->xdp_active ? "true" : "false",
        health->fec_enabled ? "true" : "false",
        health->pacing_enabled ? "true" : "false",
        health->antidetect_enabled ? "true" : "false"
    );
}

// =========================================================
// HTTP 健康检查服务器
// =========================================================

static volatile int g_health_server_running = 0;
static int g_health_server_fd = -1;
static pthread_t g_health_server_thread;
static v3_health_ctx_t *g_health_ctx = NULL;

static void* health_server_thread(void *arg) {
    int port = *(int*)arg;
    free(arg);
    
    g_health_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_health_server_fd < 0) {
        perror("health server socket");
        return NULL;
    }
    
    int opt = 1;
    setsockopt(g_health_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr("127.0.0.1")  // 只监听本地
    };
    
    if (bind(g_health_server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("health server bind");
        close(g_health_server_fd);
        return NULL;
    }
    
    listen(g_health_server_fd, 5);
    
    // 设置非阻塞
    int flags = fcntl(g_health_server_fd, F_GETFL, 0);
    fcntl(g_health_server_fd, F_SETFL, flags | O_NONBLOCK);
    
    printf("[Health] Server listening on 127.0.0.1:%d\n", port);
    
    while (g_health_server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(g_health_server_fd, 
                               (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100000);  // 100ms
                continue;
            }
            break;
        }
        
        // 读取 HTTP 请求（简化处理）
        char request[1024];
        recv(client_fd, request, sizeof(request), 0);
        
        // 生成响应
        v3_health_t health;
        v3_health_snapshot(g_health_ctx, &health);
        
        char json[4096];
        int json_len = v3_health_to_json(&health, json, sizeof(json));
        
        char response[8192];
        int resp_len = snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
            "%s",
            json_len, json);
        
        send(client_fd, response, resp_len, 0);
        close(client_fd);
    }
    
    close(g_health_server_fd);
    g_health_server_fd = -1;
    
    return NULL;
}

int v3_health_start_server(v3_health_ctx_t *ctx, int port) {
    if (g_health_server_running) {
        return -1;  // 已经在运行
    }
    
    g_health_ctx = ctx;
    g_health_server_running = 1;
    
    int *port_arg = malloc(sizeof(int));
    *port_arg = port;
    
    if (pthread_create(&g_health_server_thread, NULL, 
                       health_server_thread, port_arg) != 0) {
        free(port_arg);
        g_health_server_running = 0;
        return -1;
    }
    
    return 0;
}

void v3_health_stop_server(void) {
    if (!g_health_server_running) return;
    
    g_health_server_running = 0;
    
    if (g_health_server_fd >= 0) {
        shutdown(g_health_server_fd, SHUT_RDWR);
    }
    
    pthread_join(g_health_server_thread, NULL);
}


