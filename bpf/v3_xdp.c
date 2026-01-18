
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "v3_common.h"

#define BLACKLIST_THRESHOLD   100
#define RATE_LIMIT_PPS        10000
#define RATE_WINDOW_NS        1000000000ULL
#define DECAY_INTERVAL_NS     60000000000ULL

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} valid_magics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4); 
    __type(key, __u32);
    __type(value, __u64);
} latency_histogram SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct blacklist_entry);
} blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct rate_entry);
} rate_limit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, __u64);
    __type(value, struct conn_cache_entry);
} conn_cache SEC(".maps");

static __always_inline void stats_increment(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

static __always_inline void record_latency(__u64 elapsed_ns) {
    __u32 bucket;
    if (elapsed_ns < 1000) bucket = 0;
    else if (elapsed_ns < 10000) bucket = 1;
    else if (elapsed_ns < 100000) bucket = 2;
    else bucket = 3;

    __u64 *count = bpf_map_lookup_elem(&latency_histogram, &bucket);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

SEC("xdp")
int v3_filter(struct xdp_md *ctx) {
    __u64 start_ns = bpf_ktime_get_ns();
    
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    int action = XDP_PASS;
    __u32 stat_key = STAT_TOTAL_PROCESSED;
    
    stats_increment(STAT_TOTAL_PROCESSED);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP)) {
        action = XDP_PASS;
        goto out;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        action = XDP_PASS;
        goto out;
    }
    
    if (ip->protocol != IPPROTO_UDP) {
        stats_increment(STAT_DROPPED_NOT_UDP);
        action = XDP_PASS;
        goto out;
    }
    __u32 src_ip = ip->saddr;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end || udp->dest != bpf_htons(V3_PORT)) {
        action = XDP_PASS;
        goto out;
    }

    __u64 now_ns = start_ns;
    struct blacklist_entry *bl_entry = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (bl_entry) {
        __u64 decay_periods = (now_ns - bl_entry->last_fail_ns) / DECAY_INTERVAL_NS;

		if (decay_periods > 0) {
        __u64 shift = decay_periods > 8 ? 8 : decay_periods;
            bl_entry->fail_count >>= shift;
            bl_entry->last_fail_ns = now_ns;
        }
        if (bl_entry->fail_count >= BLACKLIST_THRESHOLD) {
            stats_increment(STAT_DROPPED_BLACKLIST);
            action = XDP_DROP;
            goto out;
        }
    }

    struct rate_entry *rl_entry = bpf_map_lookup_elem(&rate_limit, &src_ip);
    if (!rl_entry) {
        struct rate_entry new_rl = {.window_start_ns = now_ns, .packet_count = 1};
        bpf_map_update_elem(&rate_limit, &src_ip, &new_rl, BPF_NOEXIST);
    } else {
        if (now_ns - rl_entry->window_start_ns < RATE_WINDOW_NS) {
            if (rl_entry->packet_count >= RATE_LIMIT_PPS) {
                stats_increment(STAT_DROPPED_RATELIMIT);
                action = XDP_DROP;
                goto out;
            }
            __sync_fetch_and_add(&rl_entry->packet_count, 1);
        } else {
            rl_entry->window_start_ns = now_ns;
            rl_entry->packet_count = 1;
        }
    }

    void *payload = (void *)(udp + 1);
    if (payload + sizeof(struct v3_header) > data_end) {
        stats_increment(STAT_DROPPED_TOO_SHORT);
        action = XDP_DROP;
        goto out;
    }

    __u32 received_magic = ((struct v3_header *)payload)->magic_derived;
	__u64 conn_key = ((__u64)src_ip << 32) | ((__u32)bpf_ntohs(udp->source) << 16) | bpf_ntohs(udp->dest);

    struct conn_cache_entry *cache = bpf_map_lookup_elem(&conn_cache, &conn_key);
    if (cache && cache->magic == received_magic) {
        cache->last_seen_ns = now_ns;
        stats_increment(STAT_PASSED);
        action = XDP_PASS;
        goto out;
    }

    int magic_valid = 0;
	#pragma unroll
    for (__u32 i = 0; i < 8; i++) {
        __u32 *valid = bpf_map_lookup_elem(&valid_magics, &i);
        if (valid && *valid == received_magic) {
            magic_valid = 1;
            break;
        }
    }

    if (!magic_valid) {
        if (bl_entry) {
            __sync_fetch_and_add(&bl_entry->fail_count, 1);
            bl_entry->last_fail_ns = now_ns;
        } else {
            struct blacklist_entry new_bl = {.fail_count = 1, .last_fail_ns = now_ns};
            bpf_map_update_elem(&blacklist, &src_ip, &new_bl, BPF_NOEXIST);
        }
        stats_increment(STAT_DROPPED_INVALID_MAGIC);
        action = XDP_DROP;
        goto out;
    }

    struct conn_cache_entry new_cache = {.last_seen_ns = now_ns, .magic = received_magic};
    bpf_map_update_elem(&conn_cache, &conn_key, &new_cache, BPF_ANY);
    stats_increment(STAT_PASSED);
    action = XDP_PASS;

out:
    record_latency(bpf_ktime_get_ns() - start_ns);
    return action;
}

char _license[] SEC("license") = "GPL";
