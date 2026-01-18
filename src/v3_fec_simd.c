
#define _GNU_SOURCE
#include "v3_fec_simd.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#ifdef __x86_64__
#include <cpuid.h>
#include <immintrin.h>
#define HAVE_AVX2 1
#define HAVE_AVX512 1
#endif

#ifdef __aarch64__
#include <arm_neon.h>
#define HAVE_NEON 1
#endif

static uint8_t gf_exp[512];
static uint8_t gf_log[256];

static uint8_t gf_mul_low[256][16] __attribute__((aligned(64)));
static uint8_t gf_mul_high[256][16] __attribute__((aligned(64)));

static int gf_initialized = 0;

static void gf_init(void) {
    if (gf_initialized) return;
    
    int x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = x;
        gf_log[x] = i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11d;
    }
    for (int i = 255; i < 512; i++) {
        gf_exp[i] = gf_exp[i - 255];
    }
    gf_log[0] = 0;
    
    for (int c = 0; c < 256; c++) {
        for (int i = 0; i < 16; i++) {
            if (c == 0 || i == 0) {
                gf_mul_low[c][i] = 0;
            } else {
                gf_mul_low[c][i] = gf_exp[gf_log[c] + gf_log[i]];
            }
            
            int val_high = i << 4;
            if (c == 0 || val_high == 0) {
                gf_mul_high[c][i] = 0;
            } else {
                gf_mul_high[c][i] = gf_exp[gf_log[c] + gf_log[val_high]];
            }
        }
    }
    
    gf_initialized = 1;
}

static inline uint8_t gf_mul_scalar(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return gf_exp[gf_log[a] + gf_log[b]];
}

#ifdef __x86_64__
static inline uint64_t xgetbv(uint32_t index) {
    uint32_t eax, edx;
    __asm__ __volatile__(
        "xgetbv"
        : "=a"(eax), "=d"(edx)
        : "c"(index)
    );
    return ((uint64_t)edx << 32) | eax;
}

#include "v3_cpu_dispatch.h"

static inline bool cpu_has_avx512(void) {
    return cpu_has_feature(CPU_FEATURE_AVX512F) && cpu_has_feature(CPU_FEATURE_AVX512BW);
}

static inline bool cpu_has_avx2(void) {
    return cpu_has_feature(CPU_FEATURE_AVX2);
}

static inline bool cpu_has_ssse3(void) {
    return cpu_has_feature(CPU_FEATURE_SSSE3);
}

#endif

bool fec_simd_available(void) {
#ifdef __x86_64__
    return cpu_has_avx2() || cpu_has_avx512();
#elif defined(HAVE_NEON)
    return true;
#else
    return false;
#endif
}

static void gf_mul_add_region_simple(uint8_t *dst, const uint8_t *src, uint8_t coef, size_t len) {
    if (coef == 0) return;
    if (coef == 1) {
        for (size_t i = 0; i < len; i++) dst[i] ^= src[i];
    } else {
        for (size_t i = 0; i < len; i++) {
            dst[i] ^= gf_mul_low[coef][src[i] & 0x0F] ^ gf_mul_high[coef][src[i] >> 4];
        }
    }
}

#ifdef HAVE_AVX2

__attribute__((target("ssse3")))
static void gf_mul_add_region_ssse3(uint8_t *dst, const uint8_t *src, uint8_t coef, size_t len) {
    if (coef == 0) return;
    if (coef == 1) {
        size_t i = 0;
        for (; i + 16 <= len; i += 16) {
            __m128i d = _mm_loadu_si128((__m128i*)(dst + i));
            __m128i s = _mm_loadu_si128((__m128i*)(src + i));
            _mm_storeu_si128((__m128i*)(dst + i), _mm_xor_si128(d, s));
        }
        for (; i < len; i++) dst[i] ^= src[i];
        return;
    }

    __m128i tbl_lo = _mm_loadu_si128((__m128i*)gf_mul_low[coef]);
    __m128i tbl_hi = _mm_loadu_si128((__m128i*)gf_mul_high[coef]);
    __m128i mask_0f = _mm_set1_epi8(0x0F);

    size_t i = 0;
    for (; i + 16 <= len; i += 16) {
        __m128i v = _mm_loadu_si128((__m128i*)(src + i));
        __m128i d = _mm_loadu_si128((__m128i*)(dst + i));

        __m128i v_lo = _mm_and_si128(v, mask_0f);
        __m128i v_hi = _mm_and_si128(_mm_srli_epi64(v, 4), mask_0f);

        __m128i r_lo = _mm_shuffle_epi8(tbl_lo, v_lo);
        __m128i r_hi = _mm_shuffle_epi8(tbl_hi, v_hi);

        __m128i res = _mm_xor_si128(r_lo, r_hi);
        _mm_storeu_si128((__m128i*)(dst + i), _mm_xor_si128(d, res));
    }

    for (; i < len; i++) {
        dst[i] ^= gf_mul_low[coef][src[i] & 0x0F] ^ gf_mul_high[coef][src[i] >> 4];
    }
}

__attribute__((target("avx2")))
static void gf_mul_add_region_avx2(uint8_t *dst, const uint8_t *src, uint8_t coef, size_t len) {
    if (coef == 0) return;
    if (coef == 1) {
        size_t i = 0;
        for (; i + 32 <= len; i += 32) {
            __m256i d = _mm256_loadu_si256((__m256i*)(dst + i));
            __m256i s = _mm256_loadu_si256((__m256i*)(src + i));
            _mm256_storeu_si256((__m256i*)(dst + i), _mm256_xor_si256(d, s));
        }
        for (; i < len; i++) dst[i] ^= src[i];
        return;
    }

    __m128i tbl_lo_128 = _mm_loadu_si128((__m128i*)gf_mul_low[coef]);
    __m128i tbl_hi_128 = _mm_loadu_si128((__m128i*)gf_mul_high[coef]);
    __m256i tbl_lo = _mm256_broadcastsi128_si256(tbl_lo_128);
    __m256i tbl_hi = _mm256_broadcastsi128_si256(tbl_hi_128);
    __m256i mask_0f = _mm256_set1_epi8(0x0F);

    size_t i = 0;
    for (; i + 32 <= len; i += 32) {
        __m256i v = _mm256_loadu_si256((__m256i*)(src + i));
        __m256i d = _mm256_loadu_si256((__m256i*)(dst + i));

        __m256i v_lo = _mm256_and_si256(v, mask_0f);
        __m256i v_hi = _mm256_and_si256(_mm256_srli_epi64(v, 4), mask_0f);

        __m256i r_lo = _mm256_shuffle_epi8(tbl_lo, v_lo);
        __m256i r_hi = _mm256_shuffle_epi8(tbl_hi, v_hi);

        __m256i res = _mm256_xor_si256(r_lo, r_hi);
        
        _mm256_storeu_si256((__m256i*)(dst + i), _mm256_xor_si256(d, res));
    }

    for (; i < len; i++) {
        dst[i] ^= gf_mul_low[coef][src[i] & 0x0F] ^ gf_mul_high[coef][src[i] >> 4];
    }
}

#endif

#ifdef HAVE_AVX512

__attribute__((target("avx512f,avx512bw")))
static void gf_mul_add_region_avx512(uint8_t *dst, const uint8_t *src, uint8_t coef, size_t len) {
    if (coef == 0) return;
    if (coef == 1) {
        size_t i = 0;
        for (; i + 64 <= len; i += 64) {
            __m512i d = _mm512_loadu_si512((__m512i*)(dst + i));
            __m512i s = _mm512_loadu_si512((__m512i*)(src + i));
            _mm512_storeu_si512((__m512i*)(dst + i), _mm512_xor_si512(d, s));
        }
        for (; i + 32 <= len; i += 32) {
            __m256i d = _mm256_loadu_si256((__m256i*)(dst + i));
            __m256i s = _mm256_loadu_si256((__m256i*)(src + i));
            _mm256_storeu_si256((__m256i*)(dst + i), _mm256_xor_si256(d, s));
        }
        for (; i < len; i++) dst[i] ^= src[i];
        return;
    }

    __m128i tbl_lo_128 = _mm_loadu_si128((__m128i*)gf_mul_low[coef]);
    __m128i tbl_hi_128 = _mm_loadu_si128((__m128i*)gf_mul_high[coef]);
    __m512i tbl_lo = _mm512_broadcast_i32x4(tbl_lo_128);
    __m512i tbl_hi = _mm512_broadcast_i32x4(tbl_hi_128);
    __m512i mask_0f = _mm512_set1_epi8(0x0F);

    size_t i = 0;
    for (; i + 64 <= len; i += 64) {
        __m512i v = _mm512_loadu_si512((__m512i*)(src + i));
        __m512i d = _mm512_loadu_si512((__m512i*)(dst + i));

        __m512i v_lo = _mm512_and_si512(v, mask_0f);
        __m512i v_hi = _mm512_and_si512(_mm512_srli_epi64(v, 4), mask_0f);

        __m512i r_lo = _mm512_shuffle_epi8(tbl_lo, v_lo);
        __m512i r_hi = _mm512_shuffle_epi8(tbl_hi, v_hi);

        __m512i res = _mm512_xor_si512(r_lo, r_hi);
        
        _mm512_storeu_si512((__m512i*)(dst + i), _mm512_xor_si512(d, res));
    }

    if (i + 32 <= len) {
        __m128i tbl_lo_128_2 = _mm_loadu_si128((__m128i*)gf_mul_low[coef]);
        __m128i tbl_hi_128_2 = _mm_loadu_si128((__m128i*)gf_mul_high[coef]);
        __m256i tbl_lo_256 = _mm256_broadcastsi128_si256(tbl_lo_128_2);
        __m256i tbl_hi_256 = _mm256_broadcastsi128_si256(tbl_hi_128_2);
        __m256i mask_0f_256 = _mm256_set1_epi8(0x0F);
        
        for (; i + 32 <= len; i += 32) {
            __m256i v = _mm256_loadu_si256((__m256i*)(src + i));
            __m256i d = _mm256_loadu_si256((__m256i*)(dst + i));

            __m256i v_lo = _mm256_and_si256(v, mask_0f_256);
            __m256i v_hi = _mm256_and_si256(_mm256_srli_epi64(v, 4), mask_0f_256);

            __m256i r_lo = _mm256_shuffle_epi8(tbl_lo_256, v_lo);
            __m256i r_hi = _mm256_shuffle_epi8(tbl_hi_256, v_hi);

            __m256i res = _mm256_xor_si256(r_lo, r_hi);
            _mm256_storeu_si256((__m256i*)(dst + i), _mm256_xor_si256(d, res));
        }
    }

    for (; i < len; i++) {
        dst[i] ^= gf_mul_low[coef][src[i] & 0x0F] ^ gf_mul_high[coef][src[i] >> 4];
    }
}

#endif

#ifdef HAVE_NEON
static void gf_mul_add_region_neon(uint8_t *dst, const uint8_t *src, uint8_t coef, size_t len) {
    if (coef == 0) return;
    if (coef == 1) {
        size_t i = 0;
        for (; i + 16 <= len; i += 16) {
            uint8x16_t d = vld1q_u8(dst + i);
            uint8x16_t s = vld1q_u8(src + i);
            vst1q_u8(dst + i, veorq_u8(d, s));
        }
        for (; i < len; i++) dst[i] ^= src[i];
        return;
    }

    uint8x16_t tbl_lo = vld1q_u8(gf_mul_low[coef]);
    uint8x16_t tbl_hi = vld1q_u8(gf_mul_high[coef]);
    uint8x16_t mask_0f = vdupq_n_u8(0x0F);

    size_t i = 0;
    for (; i + 16 <= len; i += 16) {
        uint8x16_t v = vld1q_u8(src + i);
        uint8x16_t d = vld1q_u8(dst + i);

        uint8x16_t v_lo = vandq_u8(v, mask_0f);
        uint8x16_t v_hi = vandq_u8(vshrq_n_u8(v, 4), mask_0f);

        uint8x16_t r_lo = vqtbl1q_u8(tbl_lo, v_lo);
        uint8x16_t r_hi = vqtbl1q_u8(tbl_hi, v_hi);

        uint8x16_t res = veorq_u8(r_lo, r_hi);
        vst1q_u8(dst + i, veorq_u8(d, res));
    }

    for (; i < len; i++) {
        dst[i] ^= gf_mul_low[coef][src[i] & 0x0F] ^ gf_mul_high[coef][src[i] >> 4];
    }
}
#endif

typedef void (*gf_mul_add_func_t)(uint8_t*, const uint8_t*, uint8_t, size_t);

static gf_mul_add_func_t get_best_mul_add_func(fec_type_t type) {
    if (type != FEC_TYPE_RS_SIMD) {
        return gf_mul_add_region_simple;
    }

#ifdef __x86_64__
    if (cpu_has_avx512()) {
        return gf_mul_add_region_avx512;
    }
    if (cpu_has_avx2()) {
        return gf_mul_add_region_avx2;
    }
    if (cpu_has_ssse3()) {
        return gf_mul_add_region_ssse3;
    }
    return gf_mul_add_region_simple;
#elif defined(HAVE_NEON)
    return gf_mul_add_region_neon;
#else
    return gf_mul_add_region_simple;
#endif
}

const char* fec_get_simd_level(void) {
#ifdef __x86_64__
    if (cpu_has_avx512()) return "AVX-512";
    if (cpu_has_avx2()) return "AVX2";
    if (cpu_has_ssse3()) return "SSSE3";
    return "Scalar";
#elif defined(HAVE_NEON)
    return "NEON";
#else
    return "Scalar";
#endif
}

typedef struct {
    uint32_t next_group_id;
    uint8_t  group_size;
    
    struct {
        uint32_t group_id;
        uint8_t  shards[FEC_XOR_GROUP_SIZE + 1][FEC_SHARD_SIZE];
        bool     present[FEC_XOR_GROUP_SIZE + 1];
        size_t   shard_len;
        uint64_t create_time;
    } decode_cache[32];
    int cache_count;
} xor_fec_t;

static int xor_encode(xor_fec_t *ctx,
                      const uint8_t *data, size_t len,
                      uint8_t out[][FEC_SHARD_SIZE],
                      size_t out_lens[],
                      uint32_t *group_id) {
    uint8_t gs = ctx->group_size;
    *group_id = ctx->next_group_id++;
    
    size_t shard_size = (len + gs - 1) / gs;
    if (shard_size > FEC_SHARD_SIZE - 8) shard_size = FEC_SHARD_SIZE - 8;
    
    for (int i = 0; i < gs; i++) {
        out[i][0] = (*group_id >> 24) & 0xFF;
        out[i][1] = (*group_id >> 16) & 0xFF;
        out[i][2] = (*group_id >> 8) & 0xFF;
        out[i][3] = *group_id & 0xFF;
        out[i][4] = i;
        out[i][5] = gs;
        out[i][6] = (shard_size >> 8) & 0xFF;
        out[i][7] = shard_size & 0xFF;
        
        size_t offset = i * shard_size;
        size_t copy_len = (offset + shard_size <= len) ? shard_size : 
                          (offset < len ? len - offset : 0);
        if (copy_len > 0) memcpy(out[i] + 8, data + offset, copy_len);
        if (copy_len < shard_size) memset(out[i] + 8 + copy_len, 0, shard_size - copy_len);
        out_lens[i] = shard_size + 8;
    }
    
    out[gs][0] = (*group_id >> 24) & 0xFF;
    out[gs][1] = (*group_id >> 16) & 0xFF;
    out[gs][2] = (*group_id >> 8) & 0xFF;
    out[gs][3] = *group_id & 0xFF;
    out[gs][4] = gs;
    out[gs][5] = gs;
    out[gs][6] = (shard_size >> 8) & 0xFF;
    out[gs][7] = shard_size & 0xFF;
    
    memset(out[gs] + 8, 0, shard_size);
    
    uint64_t *parity_ptr = (uint64_t*)(out[gs] + 8);
    for (int i = 0; i < gs; i++) {
        uint64_t *data_ptr = (uint64_t*)(out[i] + 8);
        for (size_t j = 0; j < shard_size / 8; j++) {
            parity_ptr[j] ^= data_ptr[j];
        }
        for (size_t j = (shard_size / 8) * 8; j < shard_size; j++) {
            out[gs][8 + j] ^= out[i][8 + j];
        }
    }
    out_lens[gs] = shard_size + 8;
    
    return gs + 1;
}

static int xor_decode(xor_fec_t *ctx, uint32_t group_id, uint8_t shard_idx,
                      const uint8_t *data, size_t len,
                      uint8_t *out_data, size_t *out_len) {
    if (len < 8) return -1;
    uint8_t gs = data[5];
    size_t shard_size = (data[6] << 8) | data[7];
    
    int cache_idx = -1;
    for (int i = 0; i < ctx->cache_count; i++) {
        if (ctx->decode_cache[i].group_id == group_id) {
            cache_idx = i;
            break;
        }
    }
    
    if (cache_idx < 0) {
        if (ctx->cache_count >= 32) {
            memmove(&ctx->decode_cache[0], &ctx->decode_cache[1], 31 * sizeof(ctx->decode_cache[0]));
            ctx->cache_count = 31;
        }
        cache_idx = ctx->cache_count++;
        memset(&ctx->decode_cache[cache_idx], 0, sizeof(ctx->decode_cache[0]));
        ctx->decode_cache[cache_idx].group_id = group_id;
        ctx->decode_cache[cache_idx].shard_len = shard_size;
    }
    
    if (shard_idx <= gs) {
        memcpy(ctx->decode_cache[cache_idx].shards[shard_idx], data + 8, shard_size);
        ctx->decode_cache[cache_idx].present[shard_idx] = true;
    }
    
    int present_count = 0;
    int missing_idx = -1;
    for (int i = 0; i <= gs; i++) {
        if (ctx->decode_cache[cache_idx].present[i]) present_count++;
        else missing_idx = i;
    }
    
    if (present_count < gs) return 0;
    
    if (present_count == gs && missing_idx >= 0 && missing_idx < gs) {
        memset(ctx->decode_cache[cache_idx].shards[missing_idx], 0, shard_size);
        uint64_t *target = (uint64_t*)ctx->decode_cache[cache_idx].shards[missing_idx];
        for (int i = 0; i <= gs; i++) {
            if (i != missing_idx && ctx->decode_cache[cache_idx].present[i]) {
                uint64_t *src = (uint64_t*)ctx->decode_cache[cache_idx].shards[i];
                for (size_t j = 0; j < shard_size / 8; j++) target[j] ^= src[j];
                for (size_t j = (shard_size / 8) * 8; j < shard_size; j++) {
                    ctx->decode_cache[cache_idx].shards[missing_idx][j] ^= 
                        ctx->decode_cache[cache_idx].shards[i][j];
                }
            }
        }
        ctx->decode_cache[cache_idx].present[missing_idx] = true;
    }
    
    *out_len = 0;
    for (int i = 0; i < gs; i++) {
        memcpy(out_data + *out_len, ctx->decode_cache[cache_idx].shards[i], shard_size);
        *out_len += shard_size;
    }
    
    ctx->decode_cache[cache_idx].group_id = 0;
    return 1;
}

static void rs_encode_dispatch(fec_type_t type,
                               const uint8_t *data[], int data_count,
                               uint8_t *parity[], int parity_count,
                               int shard_size) {
    
    uint8_t matrix[FEC_MAX_PARITY_SHARDS][FEC_MAX_DATA_SHARDS];
    for (int p = 0; p < parity_count; p++) {
        uint8_t x = data_count + p + 1;
        matrix[p][0] = 1;
        for (int j = 1; j < data_count; j++) {
            matrix[p][j] = gf_mul_scalar(matrix[p][j-1], x);
        }
    }
    
    gf_mul_add_func_t mul_add_func = get_best_mul_add_func(type);

    for (int p = 0; p < parity_count; p++) {
        memset(parity[p], 0, shard_size);
        for (int d = 0; d < data_count; d++) {
            mul_add_func(parity[p], data[d], matrix[p][d], shard_size);
        }
    }
}

static int rs_decode_common(fec_type_t type,
                            uint8_t shards[][FEC_SHARD_SIZE],
                            bool *present,
                            int data_count,
                            int total_count,
                            int shard_size) {
    
    int available = 0;
    for (int i = 0; i < total_count; i++) if (present[i]) available++;
    if (available < data_count) return -1;
    
    gf_mul_add_func_t mul_add_func = get_best_mul_add_func(type);

    uint8_t matrix[FEC_MAX_DATA_SHARDS][FEC_MAX_DATA_SHARDS];
    uint8_t *shard_ptrs[FEC_MAX_DATA_SHARDS];
    
    int idx = 0;
    for (int i = 0; i < total_count && idx < data_count; i++) {
        if (present[i]) {
            if (i < data_count) {
                memset(matrix[idx], 0, data_count);
                matrix[idx][i] = 1;
            } else {
                int p = i - data_count;
                uint8_t x = data_count + p + 1;
                matrix[idx][0] = 1;
                for (int j = 1; j < data_count; j++) {
                    matrix[idx][j] = gf_mul_scalar(matrix[idx][j-1], x);
                }
            }
            shard_ptrs[idx] = shards[i];
            idx++;
        }
    }
    
    uint8_t inv[FEC_MAX_DATA_SHARDS][FEC_MAX_DATA_SHARDS];
    memset(inv, 0, sizeof(inv));
    for (int i = 0; i < data_count; i++) inv[i][i] = 1;
    
    for (int col = 0; col < data_count; col++) {
        int pivot = -1;
        for (int row = col; row < data_count; row++) {
            if (matrix[row][col] != 0) {
                pivot = row;
                break;
            }
        }
        if (pivot < 0) return -1;
        
        if (pivot != col) {
            for (int j = 0; j < data_count; j++) {
                uint8_t t = matrix[col][j]; matrix[col][j] = matrix[pivot][j]; matrix[pivot][j] = t;
                t = inv[col][j]; inv[col][j] = inv[pivot][j]; inv[pivot][j] = t;
            }
            uint8_t *t = shard_ptrs[col]; shard_ptrs[col] = shard_ptrs[pivot]; shard_ptrs[pivot] = t;
        }
        
        uint8_t scale = gf_exp[255 - gf_log[matrix[col][col]]];
        for (int j = 0; j < data_count; j++) {
            matrix[col][j] = gf_mul_scalar(matrix[col][j], scale);
            inv[col][j] = gf_mul_scalar(inv[col][j], scale);
        }
        
        for (int row = 0; row < data_count; row++) {
            if (row != col && matrix[row][col] != 0) {
                uint8_t factor = matrix[row][col];
                for (int j = 0; j < data_count; j++) {
                    matrix[row][j] ^= gf_mul_scalar(matrix[col][j], factor);
                    inv[row][j] ^= gf_mul_scalar(inv[col][j], factor);
                }
            }
        }
    }
    
    for (int i = 0; i < data_count; i++) {
        if (!present[i]) {
            memset(shards[i], 0, shard_size);
            for (int j = 0; j < data_count; j++) {
                mul_add_func(shards[i], shard_ptrs[j], inv[i][j], shard_size);
            }
            present[i] = true;
        }
    }
    
    return 0;
}

struct fec_engine_s {
    fec_type_t type;
    uint8_t    data_shards;
    uint8_t    parity_shards;
    float      loss_rate;
    uint32_t   next_group_id;
    
    union {
        xor_fec_t xor_ctx;
        struct {
            struct {
                uint32_t group_id;
                uint8_t  shards[FEC_MAX_TOTAL_SHARDS][FEC_SHARD_SIZE];
                bool     present[FEC_MAX_TOTAL_SHARDS];
                size_t   shard_size;
                uint8_t  data_count;
                uint8_t  parity_count;           
			} cache[FEC_DECODE_CACHE_SIZE];
            int cache_count;
        } rs_ctx;
    };
};

fec_engine_t* fec_create(fec_type_t type, uint8_t data_shards, uint8_t parity_shards) {
    fec_engine_t *e = calloc(1, sizeof(fec_engine_t));
    if (!e) return NULL;
    
    if (type == FEC_TYPE_AUTO) {
        if (fec_simd_available()) type = FEC_TYPE_RS_SIMD;
        else if (data_shards <= 4 && parity_shards == 1) type = FEC_TYPE_XOR;
        else type = FEC_TYPE_RS_SIMPLE;
    }
    
    e->type = type;
    e->data_shards = data_shards > 0 ? data_shards : 5;
    e->parity_shards = parity_shards > 0 ? parity_shards : 2;
    
    if (type == FEC_TYPE_XOR) {
        e->xor_ctx.group_size = e->data_shards;
    }
    
    gf_init();
    return e;
}

void fec_destroy(fec_engine_t *e) {
    if (e) free(e);
}

int fec_encode(fec_engine_t *e,
               const uint8_t *data, size_t len,
               uint8_t out_shards[][FEC_SHARD_SIZE],
               size_t out_lens[],
               uint32_t *group_id) {
    
    if (e->type == FEC_TYPE_XOR) {
        return xor_encode(&e->xor_ctx, data, len, out_shards, out_lens, group_id);
    }
    
    *group_id = e->next_group_id++;
    uint8_t ds = e->data_shards;
    uint8_t ps = e->parity_shards;
    
    size_t shard_size = (len + ds - 1) / ds;
    if (shard_size > FEC_SHARD_SIZE - 8) shard_size = FEC_SHARD_SIZE - 8;
    
    if (shard_size % 64 != 0) shard_size = (shard_size + 63) & ~63;
    if (shard_size > FEC_SHARD_SIZE - 8) shard_size = ((FEC_SHARD_SIZE - 8) & ~63);

    const uint8_t *data_ptrs[FEC_MAX_DATA_SHARDS];
    uint8_t data_buf[FEC_MAX_DATA_SHARDS][FEC_SHARD_SIZE] __attribute__((aligned(64)));
    memset(data_buf, 0, sizeof(data_buf));
    
    size_t offset = 0;
    for (int i = 0; i < ds; i++) {
        size_t copy = (len > offset) ? (len - offset) : 0;
        if (copy > shard_size) copy = shard_size;
        if (copy > 0) memcpy(data_buf[i], data + offset, copy);
        data_ptrs[i] = data_buf[i];
        offset += copy;
    }
    
    uint8_t *parity_ptrs[FEC_MAX_PARITY_SHARDS];
    uint8_t parity_buf[FEC_MAX_PARITY_SHARDS][FEC_SHARD_SIZE] __attribute__((aligned(64)));
    for (int i = 0; i < ps; i++) parity_ptrs[i] = parity_buf[i];

    rs_encode_dispatch(e->type, data_ptrs, ds, parity_ptrs, ps, shard_size);
    
    int total = ds + ps;
    
    for (int i = 0; i < ds; i++) {
        out_shards[i][0] = (*group_id >> 24) & 0xFF;
        out_shards[i][1] = (*group_id >> 16) & 0xFF;
        out_shards[i][2] = (*group_id >> 8) & 0xFF;
        out_shards[i][3] = *group_id & 0xFF;
        out_shards[i][4] = i;
        out_shards[i][5] = ds;
        out_shards[i][6] = ps;
        out_shards[i][7] = (shard_size >> 4) & 0xFF;
        memcpy(out_shards[i] + 8, data_buf[i], shard_size);
        out_lens[i] = shard_size + 8;
    }
    
    for (int i = 0; i < ps; i++) {
        int idx = ds + i;
        out_shards[idx][0] = (*group_id >> 24) & 0xFF;
        out_shards[idx][1] = (*group_id >> 16) & 0xFF;
        out_shards[idx][2] = (*group_id >> 8) & 0xFF;
        out_shards[idx][3] = *group_id & 0xFF;
        out_shards[idx][4] = idx;
        out_shards[idx][5] = ds;
        out_shards[idx][6] = ps;
        out_shards[idx][7] = (shard_size >> 4) & 0xFF;
        memcpy(out_shards[idx] + 8, parity_buf[i], shard_size);
        out_lens[idx] = shard_size + 8;
    }
    
    return total;
}

int fec_decode(fec_engine_t *e,
               uint32_t group_id,
               uint8_t shard_idx,
               const uint8_t *shard_data, size_t shard_len,
               uint8_t *out_data, size_t *out_len) {
    
    if (shard_len < 8) return -1;
    
    if (e->type == FEC_TYPE_XOR) {
        return xor_decode(&e->xor_ctx, group_id, shard_idx, 
                          shard_data, shard_len, out_data, out_len);
    }
    
    uint8_t ds = shard_data[5];
    uint8_t ps = shard_data[6];
    size_t shard_size = shard_data[7] << 4;
    int total = ds + ps;
    
    int cache_idx = -1;
    for (int i = 0; i < e->rs_ctx.cache_count; i++) {
        if (e->rs_ctx.cache[i].group_id == group_id) {
            cache_idx = i;
            break;
        }
    }
    
    if (cache_idx < 0) {

		if (e->rs_ctx.cache_count >= FEC_DECODE_CACHE_SIZE) {
    memmove(&e->rs_ctx.cache[0], &e->rs_ctx.cache[1], (FEC_DECODE_CACHE_SIZE - 1) * sizeof(e->rs_ctx.cache[0]));
    e->rs_ctx.cache_count = FEC_DECODE_CACHE_SIZE - 1;
}
        cache_idx = e->rs_ctx.cache_count++;
        memset(&e->rs_ctx.cache[cache_idx], 0, sizeof(e->rs_ctx.cache[0]));
        e->rs_ctx.cache[cache_idx].group_id = group_id;
        e->rs_ctx.cache[cache_idx].shard_size = shard_size;
        e->rs_ctx.cache[cache_idx].data_count = ds;
        e->rs_ctx.cache[cache_idx].parity_count = ps;
    }
    
    if (shard_idx < total) {
        memcpy(e->rs_ctx.cache[cache_idx].shards[shard_idx], shard_data + 8, shard_size);
        e->rs_ctx.cache[cache_idx].present[shard_idx] = true;
    }
    
    int present_count = 0;
    for (int i = 0; i < total; i++) {
        if (e->rs_ctx.cache[cache_idx].present[i]) present_count++;
    }
    
    if (present_count < ds) return 0;
    
    if (rs_decode_common(e->type,
                         e->rs_ctx.cache[cache_idx].shards,
                         e->rs_ctx.cache[cache_idx].present,
                         ds, total, shard_size) < 0) {
        return -1;
    }
    
    *out_len = 0;
    for (int i = 0; i < ds; i++) {
        memcpy(out_data + *out_len, e->rs_ctx.cache[cache_idx].shards[i], shard_size);
        *out_len += shard_size;
    }
    
    e->rs_ctx.cache[cache_idx].group_id = 0;
    return 1;
}

void fec_set_loss_rate(fec_engine_t *e, float loss_rate) {
    e->loss_rate = loss_rate;
    if (e->type == FEC_TYPE_XOR) return;
    
    if (loss_rate < 0.05f) e->parity_shards = 2;
    else if (loss_rate < 0.10f) e->parity_shards = 3;
    else if (loss_rate < 0.20f) e->parity_shards = 4;
    else if (loss_rate < 0.30f) e->parity_shards = 6;
    else e->parity_shards = e->data_shards;
}

fec_type_t fec_get_type(fec_engine_t *e) {
    return e->type;
}

double fec_benchmark(fec_type_t type, size_t data_size, int iterations) {
    fec_engine_t *e = fec_create(type, 10, 4);
    if (!e) return -1;
    
    uint8_t *data = malloc(data_size);
    uint8_t shards[FEC_MAX_TOTAL_SHARDS][FEC_SHARD_SIZE];
    size_t lens[FEC_MAX_TOTAL_SHARDS];
    uint32_t gid;
    
    for (size_t i = 0; i < data_size; i++) data[i] = rand() & 0xFF;
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < iterations; i++) {
        fec_encode(e, data, data_size, shards, lens, &gid);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput = (data_size * iterations) / elapsed / (1024 * 1024);
    
    free(data);
    fec_destroy(e);
    return throughput;
}

void fec_print_info(void) {
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    FEC Module Information                     ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  SIMD Level:    %-20s                        ║\n", fec_get_simd_level());
    printf("║  SIMD Available: %-5s                                        ║\n", 
           fec_simd_available() ? "YES" : "NO");
    
#ifdef __x86_64__
    printf("║  Capabilities:                                                ║\n");
    printf("║    SSSE3:   %-5s                                             ║\n", 
           cpu_has_ssse3() ? "YES" : "NO");
    printf("║    AVX2:    %-5s                                             ║\n", 
           cpu_has_avx2() ? "YES" : "NO");
    printf("║    AVX-512: %-5s                                             ║\n", 
           cpu_has_avx512() ? "YES" : "NO");
#endif
    
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
}







