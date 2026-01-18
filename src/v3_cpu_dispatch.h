
#ifndef V3_CPU_DISPATCH_H
#define V3_CPU_DISPATCH_H

#include <stdint.h>
#include <stdbool.h>

// =========================================================
// CPU Feature Flags
// =========================================================
typedef enum {
    CPU_FEATURE_SSE2      = (1 << 0),
    CPU_FEATURE_SSE3      = (1 << 1),
    CPU_FEATURE_SSSE3     = (1 << 2),
    CPU_FEATURE_SSE41     = (1 << 3),
    CPU_FEATURE_SSE42     = (1 << 4),
    CPU_FEATURE_AVX       = (1 << 5),
    CPU_FEATURE_AVX2      = (1 << 6),
    CPU_FEATURE_AVX512F   = (1 << 7),
    CPU_FEATURE_AVX512BW  = (1 << 8),
    CPU_FEATURE_NEON      = (1 << 9),
    CPU_FEATURE_SVE       = (1 << 10),
} cpu_feature_t;

// =========================================================
// CPU Levels (For optimization selection)
// =========================================================
typedef enum {
    CPU_LEVEL_GENERIC = 0,      // Scalar C
    CPU_LEVEL_SSE42,            // x86-64-v2
    CPU_LEVEL_AVX2,             // x86-64-v3
    CPU_LEVEL_AVX512,           // x86-64-v4
    CPU_LEVEL_NEON,             // ARM64
    CPU_LEVEL_SVE,              // ARM64 SVE
    CPU_LEVEL_MAX
} cpu_level_t;

// =========================================================
// API
// =========================================================

void cpu_detect(void);

uint32_t cpu_get_features(void);

bool cpu_has_feature(cpu_feature_t feature);

cpu_level_t cpu_get_level(void);

const char* cpu_get_name(void);

const char* cpu_level_name(cpu_level_t level);

void cpu_print_info(void);

#endif // V3_CPU_DISPATCH_H


