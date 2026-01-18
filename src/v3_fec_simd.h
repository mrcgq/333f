
#ifndef V3_FEC_SIMD_H
#define V3_FEC_SIMD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    FEC_TYPE_NONE = 0,
    FEC_TYPE_XOR,
    FEC_TYPE_RS_SIMPLE,
    FEC_TYPE_RS_SIMD,
    FEC_TYPE_AUTO,
} fec_type_t;

#define FEC_MAX_DATA_SHARDS     20
#define FEC_MAX_PARITY_SHARDS   10
#define FEC_MAX_TOTAL_SHARDS    30
#define FEC_SHARD_SIZE          1400
#define FEC_DECODE_CACHE_SIZE   128
#define FEC_XOR_GROUP_SIZE      4

typedef struct fec_engine_s fec_engine_t;

fec_engine_t* fec_create(fec_type_t type, uint8_t data_shards, uint8_t parity_shards);

void fec_destroy(fec_engine_t *engine);

int fec_encode(fec_engine_t *engine,
               const uint8_t *data, size_t len,
               uint8_t out_shards[][FEC_SHARD_SIZE],
               size_t out_lens[],
               uint32_t *group_id);

int fec_decode(fec_engine_t *engine,
               uint32_t group_id,
               uint8_t shard_idx,
               const uint8_t *shard_data, size_t shard_len,
               uint8_t *out_data, size_t *out_len);

void fec_set_loss_rate(fec_engine_t *engine, float loss_rate);

fec_type_t fec_get_type(fec_engine_t *engine);

bool fec_simd_available(void);

const char* fec_get_simd_level(void);

void fec_print_info(void);

double fec_benchmark(fec_type_t type, size_t data_size, int iterations);

#endif



