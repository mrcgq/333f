

#include "v3_pacing_adaptive.h"
#include <string.h>
#include <time.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline uint64_t xorshift64(pacing_adaptive_t *ctx) {
    uint64_t x = ctx->rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    ctx->rng_state = x;
    return x;
}

void pacing_adaptive_init(pacing_adaptive_t *ctx, uint64_t initial_bps) {
    memset(ctx, 0, sizeof(*ctx));
    
    ctx->target_bps = initial_bps;
    ctx->max_bps = initial_bps * 2;
    ctx->min_bps = initial_bps / 10;
    
    ctx->tokens = 65536;
    ctx->tokens_per_ns = (double)initial_bps / 8.0 / 1e9;
    ctx->last_refill_ns = get_time_ns();
    
    ctx->rtt_us = 100000;
    ctx->rtt_min_us = UINT64_MAX;
    
    ctx->state = PACING_SLOW_START;
    ctx->cwnd = 10 * 1400;
    ctx->ssthresh = UINT64_MAX;
    
    ctx->rng_state = get_time_ns() ^ 0xDEADBEEF;
}

void pacing_adaptive_set_range(pacing_adaptive_t *ctx, 
                                uint64_t min_bps, uint64_t max_bps) {
    ctx->min_bps = min_bps;
    ctx->max_bps = max_bps;
}

void pacing_adaptive_enable_jitter(pacing_adaptive_t *ctx, uint32_t range_ns) {
    ctx->jitter_enabled = true;
    ctx->jitter_range_ns = range_ns;
}

void pacing_adaptive_update_rtt(pacing_adaptive_t *ctx, uint64_t rtt_us) {
    if (ctx->rtt_us == 0) {
        ctx->rtt_us = rtt_us;
        ctx->rtt_var = rtt_us / 2.0;
    } else {
        double diff = (double)rtt_us - ctx->rtt_us;
        ctx->rtt_var = ctx->rtt_var * 0.75 + (diff > 0 ? diff : -diff) * 0.25;
        ctx->rtt_us = ctx->rtt_us * 0.875 + rtt_us * 0.125;
    }
    
    if (rtt_us < ctx->rtt_min_us) ctx->rtt_min_us = rtt_us;
    if (rtt_us > ctx->rtt_max_us) ctx->rtt_max_us = rtt_us;
    
    if (ctx->bytes_in_flight > 0 && rtt_us > 0) {
        uint64_t bw = ctx->bytes_in_flight * 8 * 1000000 / rtt_us;
        
        if (ctx->bw_estimate_bps == 0) {
            ctx->bw_estimate_bps = bw;
        } else {
            ctx->bw_estimate_bps = ctx->bw_estimate_bps * 0.9 + bw * 0.1;
        }
        
        ctx->target_bps = MIN(ctx->bw_estimate_bps, ctx->max_bps);
        ctx->target_bps = MAX(ctx->target_bps, ctx->min_bps);
        ctx->tokens_per_ns = (double)ctx->target_bps / 8.0 / 1e9;
    }
}

void pacing_adaptive_report_loss(pacing_adaptive_t *ctx) {
    uint64_t now = get_time_ns();
    ctx->loss_count++;
    
    if (now - ctx->last_loss_ns < ctx->rtt_us * 1000) {
        return;
    }
    ctx->last_loss_ns = now;
    
    switch (ctx->state) {
    case PACING_SLOW_START:
        ctx->ssthresh = ctx->cwnd / 2;
        ctx->cwnd = ctx->ssthresh;
        ctx->state = PACING_RECOVERY;
        break;
        
    case PACING_CONGESTION_AVOIDANCE:
        ctx->ssthresh = ctx->cwnd / 2;
        ctx->cwnd = ctx->ssthresh;
        ctx->state = PACING_RECOVERY;
        break;
        
    case PACING_RECOVERY:
        break;
    }
    
    ctx->target_bps = ctx->target_bps * 7 / 10;
    if (ctx->target_bps < ctx->min_bps) {
        ctx->target_bps = ctx->min_bps;
    }
    ctx->tokens_per_ns = (double)ctx->target_bps / 8.0 / 1e9;
}

static void refill_tokens(pacing_adaptive_t *ctx, uint64_t now_ns) {
    uint64_t elapsed = now_ns - ctx->last_refill_ns;
    double new_tokens = elapsed * ctx->tokens_per_ns;
    
    double max_burst = ctx->target_bps / 8.0 * ctx->rtt_us / 1e6;
    if (max_burst < 65536) max_burst = 65536;
    
    ctx->tokens += new_tokens;
    if (ctx->tokens > max_burst) {
        ctx->tokens = max_burst;
    }
    
    ctx->last_refill_ns = now_ns;
}

uint64_t pacing_adaptive_acquire(pacing_adaptive_t *ctx, size_t bytes) {
    uint64_t now_ns = get_time_ns();
    refill_tokens(ctx, now_ns);
    
    if (ctx->bytes_in_flight + bytes > ctx->cwnd) {
        uint64_t wait = ctx->rtt_us * 1000 / 4;
        ctx->throttled_count++;
        return wait;
    }
    
    if (ctx->tokens >= (double)bytes) {
        return 0;
    }
    
    double deficit = (double)bytes - ctx->tokens;
    uint64_t wait_ns = (uint64_t)(deficit / ctx->tokens_per_ns);
    
    if (wait_ns < 10000) wait_ns = 10000;
    
    if (ctx->jitter_enabled && ctx->jitter_range_ns > 0) {
        wait_ns += xorshift64(ctx) % ctx->jitter_range_ns;
    }
    
    ctx->throttled_count++;
    return wait_ns;
}

void pacing_adaptive_commit(pacing_adaptive_t *ctx, size_t bytes) {
    ctx->tokens -= (double)bytes;
    if (ctx->tokens < 0) ctx->tokens = 0;
    
    ctx->bytes_in_flight += bytes;
    ctx->total_bytes += bytes;
    ctx->total_packets++;
}

void pacing_adaptive_ack(pacing_adaptive_t *ctx, size_t bytes) {
    if (bytes > ctx->bytes_in_flight) {
        ctx->bytes_in_flight = 0;
    } else {
        ctx->bytes_in_flight -= bytes;
    }
    
    switch (ctx->state) {
    case PACING_SLOW_START:
        ctx->cwnd += bytes;
        if (ctx->cwnd >= ctx->ssthresh) {
            ctx->state = PACING_CONGESTION_AVOIDANCE;
        }
        break;
        
    case PACING_CONGESTION_AVOIDANCE:
        ctx->cwnd += 1400 * bytes / ctx->cwnd;
        break;
        
    case PACING_RECOVERY:
        if (ctx->bytes_in_flight < ctx->cwnd / 2) {
            ctx->state = PACING_CONGESTION_AVOIDANCE;
        }
        break;
    }
}

uint64_t pacing_adaptive_get_bw(pacing_adaptive_t *ctx) {
    return ctx->bw_estimate_bps;
}

bool pacing_adaptive_allow_burst(pacing_adaptive_t *ctx, size_t bytes) {
    if (ctx->state == PACING_SLOW_START) {
        return ctx->bytes_in_flight + bytes <= ctx->cwnd;
    }
    
    return bytes <= 2 * 1400 && ctx->tokens >= bytes;
}




