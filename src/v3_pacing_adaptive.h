

#ifndef V3_PACING_ADAPTIVE_H
#define V3_PACING_ADAPTIVE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    uint64_t    target_bps;
    uint64_t    max_bps;
    uint64_t    min_bps;
    
    double      tokens;
    double      tokens_per_ns;
    uint64_t    last_refill_ns;
    
    uint64_t    rtt_us;
    uint64_t    rtt_min_us;
    uint64_t    rtt_max_us;
    double      rtt_var;
    
    uint64_t    bw_estimate_bps;
    uint64_t    bytes_in_flight;
    uint64_t    last_bw_update_ns;
    
    enum {
        PACING_SLOW_START,
        PACING_CONGESTION_AVOIDANCE,
        PACING_RECOVERY,
    } state;
    
    uint64_t    cwnd;
    uint64_t    ssthresh;
    
    uint64_t    last_loss_ns;
    uint32_t    loss_count;
    
    bool        jitter_enabled;
    uint32_t    jitter_range_ns;
    uint64_t    rng_state;
    
    uint64_t    total_bytes;
    uint64_t    total_packets;
    uint64_t    throttled_count;
    uint64_t    burst_count;
} pacing_adaptive_t;

void pacing_adaptive_init(pacing_adaptive_t *ctx, uint64_t initial_bps);

void pacing_adaptive_set_range(pacing_adaptive_t *ctx, 
                                uint64_t min_bps, uint64_t max_bps);

void pacing_adaptive_enable_jitter(pacing_adaptive_t *ctx, uint32_t range_ns);

void pacing_adaptive_update_rtt(pacing_adaptive_t *ctx, uint64_t rtt_us);

void pacing_adaptive_report_loss(pacing_adaptive_t *ctx);

uint64_t pacing_adaptive_acquire(pacing_adaptive_t *ctx, size_t bytes);

void pacing_adaptive_commit(pacing_adaptive_t *ctx, size_t bytes);

void pacing_adaptive_ack(pacing_adaptive_t *ctx, size_t bytes);

uint64_t pacing_adaptive_get_bw(pacing_adaptive_t *ctx);

bool pacing_adaptive_allow_burst(pacing_adaptive_t *ctx, size_t bytes);

#endif


