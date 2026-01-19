
#ifndef V3_HEALTH_H
#define V3_HEALTH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// =========================================================
// 健康检查数据结构
// =========================================================

typedef struct {
    // 基础信息
    uint64_t    uptime_sec;         // 运行时间（秒）
    uint64_t    start_time;         // 启动时间戳
    
    // 流量统计
    uint64_t    packets_rx;         // 接收数据包总数
    uint64_t    packets_tx;         // 发送数据包总数
    uint64_t    packets_per_sec;    // 每秒数据包数（最近统计）
    uint64_t    bytes_rx;           // 接收字节总数
    uint64_t    bytes_tx;           // 发送字节总数
    uint64_t    bytes_per_sec;      // 每秒字节数（吞吐量）
    
    // 错误统计
    uint64_t    packets_dropped;    // 丢弃的数据包
    uint64_t    packets_invalid;    // 无效数据包（解密失败等）
    uint64_t    packets_ratelimit;  // 被限速的数据包
    
    // FEC 统计
    uint64_t    fec_groups_total;   // FEC 组总数
    uint64_t    fec_recoveries;     // FEC 成功恢复次数
    uint64_t    fec_failures;       // FEC 恢复失败次数
    float       fec_recovery_rate;  // 恢复率
    
    // 连接统计
    uint32_t    connections_active; // 活跃连接数
    uint32_t    connections_total;  // 历史连接总数
    
    // 系统资源
    float       cpu_usage;          // CPU 使用率 (0-100)
    float       memory_mb;          // 内存使用 (MB)
    float       memory_percent;     // 内存使用率 (0-100)
    
    // 模块状态
    bool        xdp_active;         // XDP 是否激活
    bool        fec_enabled;        // FEC 是否启用
    bool        pacing_enabled;     // Pacing 是否启用
    bool        antidetect_enabled; // 反检测是否启用
    
    // 性能指标
    uint64_t    latency_avg_us;     // 平均延迟（微秒）
    uint64_t    latency_p99_us;     // P99 延迟（微秒）
    uint64_t    io_uring_sqe_used;  // io_uring SQE 使用量
    uint64_t    io_uring_cqe_pending; // io_uring CQE 待处理
    
    // CPU 信息
    char        cpu_level[32];      // CPU 优化级别
    char        cpu_name[64];       // CPU 型号
    
    // 版本信息
    char        version[32];        // 程序版本
    char        build_time[32];     // 编译时间
} v3_health_t;

// =========================================================
// 健康检查上下文（内部状态）
// =========================================================

typedef struct {
    // 启动时间
    uint64_t    start_time_ns;
    
    // 累计统计
    uint64_t    packets_rx;
    uint64_t    packets_tx;
    uint64_t    bytes_rx;
    uint64_t    bytes_tx;
    uint64_t    packets_dropped;
    uint64_t    packets_invalid;
    
    // FEC 统计
    uint64_t    fec_groups;
    uint64_t    fec_recoveries;
    uint64_t    fec_failures;
    
    // 连接统计
    uint32_t    connections_active;
    uint32_t    connections_total;
    
    // 延迟追踪
    uint64_t    latency_sum_us;
    uint64_t    latency_count;
    uint64_t    latency_samples[1000];  // 环形缓冲
    int         latency_idx;
    
    // 速率计算
    uint64_t    last_sample_time_ns;
    uint64_t    last_packets_rx;
    uint64_t    last_bytes_rx;
    uint64_t    packets_per_sec;
    uint64_t    bytes_per_sec;
    
    // CPU 统计（上一次采样）
    uint64_t    last_cpu_total;
    uint64_t    last_cpu_idle;
    
    // 模块状态
    bool        xdp_active;
    bool        fec_enabled;
    bool        pacing_enabled;
    bool        antidetect_enabled;
} v3_health_ctx_t;

// =========================================================
// API 函数
// =========================================================

/**
 * @brief 初始化健康检查模块
 * @param ctx 健康检查上下文
 */
void v3_health_init(v3_health_ctx_t *ctx);

/**
 * @brief 记录接收数据包
 * @param ctx 上下文
 * @param bytes 数据包大小
 */
void v3_health_record_rx(v3_health_ctx_t *ctx, size_t bytes);

/**
 * @brief 记录发送数据包
 * @param ctx 上下文
 * @param bytes 数据包大小
 */
void v3_health_record_tx(v3_health_ctx_t *ctx, size_t bytes);

/**
 * @brief 记录丢弃的数据包
 * @param ctx 上下文
 * @param reason 丢弃原因 (0=限速, 1=无效, 2=其他)
 */
void v3_health_record_drop(v3_health_ctx_t *ctx, int reason);

/**
 * @brief 记录 FEC 操作
 * @param ctx 上下文
 * @param recovered 是否成功恢复
 */
void v3_health_record_fec(v3_health_ctx_t *ctx, bool recovered);

/**
 * @brief 记录延迟样本
 * @param ctx 上下文
 * @param latency_us 延迟（微秒）
 */
void v3_health_record_latency(v3_health_ctx_t *ctx, uint64_t latency_us);

/**
 * @brief 记录连接状态
 * @param ctx 上下文
 * @param connected true=新连接, false=断开
 */
void v3_health_record_connection(v3_health_ctx_t *ctx, bool connected);

/**
 * @brief 设置模块状态
 * @param ctx 上下文
 * @param xdp XDP 是否激活
 * @param fec FEC 是否启用
 * @param pacing Pacing 是否启用
 * @param antidetect 反检测是否启用
 */
void v3_health_set_modules(v3_health_ctx_t *ctx, 
                            bool xdp, bool fec, 
                            bool pacing, bool antidetect);

/**
 * @brief 获取健康快照
 * @param ctx 上下文
 * @param health 输出的健康数据
 */
void v3_health_snapshot(v3_health_ctx_t *ctx, v3_health_t *health);

/**
 * @brief 打印健康信息到控制台
 * @param health 健康数据
 */
void v3_health_print(const v3_health_t *health);

/**
 * @brief 生成 JSON 格式的健康信息
 * @param health 健康数据
 * @param buf 输出缓冲区
 * @param buflen 缓冲区大小
 * @return 写入的字节数
 */
int v3_health_to_json(const v3_health_t *health, char *buf, size_t buflen);

/**
 * @brief 启动 HTTP 健康检查服务
 * @param ctx 上下文
 * @param port 监听端口
 * @return 0=成功, -1=失败
 */
int v3_health_start_server(v3_health_ctx_t *ctx, int port);

/**
 * @brief 停止健康检查服务
 */
void v3_health_stop_server(void);

#endif // V3_HEALTH_H

