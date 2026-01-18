
#ifndef V3_COMMON_H
#define V3_COMMON_H

#include <linux/types.h>

#define V3_PORT         51820
#define V3_HEADER_SIZE  52
#define V3_MAGIC_SLOTS  8

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

struct v3_header {
    __u32 magic_derived;
    __u8  nonce[12];
    __u8  enc_block[16];
    __u8  tag[16];
    __u16 early_len;
    __u16 pad;
} __attribute__((packed));

struct blacklist_entry {
    __u64 fail_count;
    __u64 last_fail_ns;
};

struct rate_entry {
    __u64 window_start_ns;
    __u64 packet_count;
};

struct conn_cache_entry {
    __u64 last_seen_ns;
    __u32 magic;
};

#endif

