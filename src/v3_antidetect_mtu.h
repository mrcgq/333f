

#ifndef V3_ANTIDETECT_MTU_H
#define V3_ANTIDETECT_MTU_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    AD_PROFILE_NONE = 0,
    AD_PROFILE_HTTPS,
    AD_PROFILE_VIDEO,
    AD_PROFILE_VOIP,
    AD_PROFILE_GAMING,
} ad_profile_t;

typedef struct {
    ad_profile_t profile;
    
    uint16_t    mtu;
    uint16_t    mss;
    uint16_t    min_padding;
    uint16_t    max_padding;
    
    uint16_t    typical_size_min;
    uint16_t    typical_size_max;
    uint32_t    typical_interval_us;
    uint32_t    interval_variance_us;
    
    enum {
        AD_STATE_NORMAL,
        AD_STATE_BURST,
        AD_STATE_IDLE,
    } state;
    int         burst_remaining;
    uint64_t    idle_until_ns;
    uint64_t    last_send_ns;
    
    uint64_t    rng_state;
    
    uint64_t    packets_processed;
    uint64_t    padding_bytes;
    uint64_t    fragments_avoided;
} ad_mtu_ctx_t;

void ad_mtu_init(ad_mtu_ctx_t *ctx, ad_profile_t profile, uint16_t mtu);

void ad_mtu_set_mtu(ad_mtu_ctx_t *ctx, uint16_t mtu);

uint64_t ad_mtu_process_outbound(ad_mtu_ctx_t *ctx,
                                  uint8_t *buf, size_t *len, size_t max_len);

size_t ad_mtu_process_inbound(ad_mtu_ctx_t *ctx,
                               uint8_t *buf, size_t len);

size_t ad_mtu_max_payload(ad_mtu_ctx_t *ctx);

bool ad_mtu_would_fragment(ad_mtu_ctx_t *ctx, size_t len);

#endif






