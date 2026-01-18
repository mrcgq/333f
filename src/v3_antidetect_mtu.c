	  

#include "v3_antidetect_mtu.h"
#include <string.h>
#include <time.h>

typedef struct {
    uint16_t size_min;
    uint16_t size_max;
    uint32_t interval_us;
    uint32_t interval_var_us;
    uint8_t  burst_prob;
    uint8_t  burst_size;
    uint8_t  idle_prob;
    uint32_t idle_duration_us;
} profile_params_t;

static const profile_params_t g_profiles[] = {
    [AD_PROFILE_NONE] = {
        .size_min = 0, .size_max = 0,
        .interval_us = 0, .interval_var_us = 0,
    },
    [AD_PROFILE_HTTPS] = {
        .size_min = 100, .size_max = 1200,
        .interval_us = 5000, .interval_var_us = 20000,
        .burst_prob = 30, .burst_size = 5,
        .idle_prob = 10, .idle_duration_us = 100000,
    },
    [AD_PROFILE_VIDEO] = {
        .size_min = 1000, .size_max = 1400,
        .interval_us = 10000, .interval_var_us = 5000,
        .burst_prob = 5, .burst_size = 3,
        .idle_prob = 2, .idle_duration_us = 500000,
    },
    [AD_PROFILE_VOIP] = {
        .size_min = 60, .size_max = 200,
        .interval_us = 20000, .interval_var_us = 2000,
        .burst_prob = 1, .burst_size = 2,
        .idle_prob = 0, .idle_duration_us = 0,
    },
    [AD_PROFILE_GAMING] = {
        .size_min = 40, .size_max = 300,
        .interval_us = 16000, .interval_var_us = 8000,
        .burst_prob = 20, .burst_size = 4,
        .idle_prob = 5, .idle_duration_us = 200000,
    },
};

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline uint64_t xoroshiro128plus(ad_mtu_ctx_t *ctx) {
    uint64_t s0 = ctx->rng_state;
    uint64_t s1 = ctx->rng_state ^ 0x9E3779B97F4A7C15ULL;
    uint64_t result = s0 + s1;
    s1 ^= s0;
    ctx->rng_state = ((s0 << 24) | (s0 >> 40)) ^ s1 ^ (s1 << 16);
    return result;
}
#define xorshift64 xoroshiro128plus

static inline uint32_t random_range(ad_mtu_ctx_t *ctx, uint32_t min, uint32_t max) {
    if (min >= max) return min;
    return min + (xorshift64(ctx) % (max - min + 1));
}

void ad_mtu_init(ad_mtu_ctx_t *ctx, ad_profile_t profile, uint16_t mtu) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->profile = profile;
    ctx->rng_state = get_time_ns() ^ 0xCAFEBABE12345678ULL;
    ad_mtu_set_mtu(ctx, mtu);
    
    const profile_params_t *p = &g_profiles[profile];
    ctx->typical_size_min = p->size_min;
    ctx->typical_size_max = p->size_max;
    ctx->typical_interval_us = p->interval_us;
    ctx->interval_variance_us = p->interval_var_us;
}

void ad_mtu_set_mtu(ad_mtu_ctx_t *ctx, uint16_t mtu) {
    ctx->mtu = mtu;
    
    uint16_t overhead = 20 + 8 + 52 + 2 + 20;
    
    if (mtu > overhead) {
        ctx->mss = mtu - overhead;
    } else {
        ctx->mss = 1200;
    }
    
    ctx->min_padding = 0;
    ctx->max_padding = 100;
    
    if (ctx->max_padding > ctx->mss / 10) {
        ctx->max_padding = ctx->mss / 10;
    }
}

size_t ad_mtu_max_payload(ad_mtu_ctx_t *ctx) {
    return ctx->mss - ctx->max_padding - 2;
}

bool ad_mtu_would_fragment(ad_mtu_ctx_t *ctx, size_t len) {
    return len > ctx->mss;
}

uint64_t ad_mtu_process_outbound(ad_mtu_ctx_t *ctx,
                                  uint8_t *buf, size_t *len, size_t max_len) {
    if (ctx->profile == AD_PROFILE_NONE) {
        return 0;
    }
    
    uint64_t now_ns = get_time_ns();
    uint64_t delay_ns = 0;
    size_t original_len = *len;
    
    ctx->packets_processed++;
    
    const profile_params_t *p = &g_profiles[ctx->profile];

    switch (ctx->state) {
    case AD_STATE_IDLE:
        if (now_ns >= ctx->idle_until_ns) {
            ctx->state = AD_STATE_NORMAL;
        } else {
            return ctx->idle_until_ns - now_ns;
        }
        break;
        
    case AD_STATE_BURST:
        ctx->burst_remaining--;
        if (ctx->burst_remaining <= 0) {
            ctx->state = AD_STATE_NORMAL;
        }
        delay_ns = random_range(ctx, 100000, 500000);
        break;
        
    case AD_STATE_NORMAL:
    default:
        if (random_range(ctx, 0, 100) < p->burst_prob) {
            ctx->state = AD_STATE_BURST;
            ctx->burst_remaining = p->burst_size;
        }
        else if (random_range(ctx, 0, 100) < p->idle_prob) {
            ctx->state = AD_STATE_IDLE;
            ctx->idle_until_ns = now_ns + p->idle_duration_us * 1000ULL;
        }
        break;
    }
    
    size_t available_space = max_len - original_len;
    size_t max_safe_padding = ctx->mss - original_len;
    
    if (max_safe_padding < 2) {
        ctx->fragments_avoided++;
        goto calc_delay;
    }
    
    size_t max_pad = ctx->max_padding;
    if (max_pad > max_safe_padding - 2) {
        max_pad = max_safe_padding - 2;
    }
    if (max_pad > available_space - 2) {
        max_pad = available_space - 2;
    }
    
    size_t target_size;
    
    if (original_len >= ctx->typical_size_min && 
        original_len <= ctx->typical_size_max &&
        random_range(ctx, 0, 100) < 40) {
        target_size = original_len;
    } else {
        target_size = random_range(ctx, ctx->typical_size_min, ctx->typical_size_max);
        
        if (target_size < original_len + 2) {
            target_size = original_len + 2;
        }
        
        if (target_size > original_len + max_pad + 2) {
            target_size = original_len + max_pad + 2;
        }
    }
    
    if (target_size > original_len + 2) {
        size_t padding_len = target_size - original_len - 2;
        
        for (size_t i = 0; i < padding_len; i += 8) {
            uint64_t r = xorshift64(ctx);
            size_t copy = (padding_len - i > 8) ? 8 : (padding_len - i);
            memcpy(buf + original_len + i, &r, copy);
        }
        
        buf[original_len + padding_len] = (original_len >> 8) & 0xFF;
        buf[original_len + padding_len + 1] = original_len & 0xFF;
        
        *len = target_size;
        ctx->padding_bytes += padding_len;
    }
    
calc_delay:
    if (ctx->state != AD_STATE_BURST) {
        uint32_t base = p->interval_us;
        uint32_t var = p->interval_var_us;
        
        uint64_t since_last = (now_ns - ctx->last_send_ns) / 1000;
        
        if (since_last < base - var / 2) {
            delay_ns = (base - since_last) * 1000;
            delay_ns += random_range(ctx, 0, var) * 1000;
        } else {
            delay_ns = random_range(ctx, 0, var / 2) * 1000;
        }
    }
    
    ctx->last_send_ns = now_ns + delay_ns;
    return delay_ns;
}

size_t ad_mtu_process_inbound(ad_mtu_ctx_t *ctx,
                               uint8_t *buf, size_t len) {
    if (ctx->profile == AD_PROFILE_NONE || len < 2) {
        return len;
    }
    
    size_t original_len = (buf[len - 2] << 8) | buf[len - 1];
    
    if (original_len > 0 && original_len <= len - 2) {
        return original_len;
    }
    
    return len;
}



