/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Benchmarking API
 *
 * This header provides the benchmarking harness for measuring performance
 * of PQCP cryptographic operations and protocols.
 *
 * Stability: stable analysis API for the 1.0.x line. `PQCP_METRIC` field
 * ordering is part of the public benchmark contract.
 */

#ifndef PQCP_ZEPHYR_BENCH_H
#define PQCP_ZEPHYR_BENCH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Benchmark Types
 */

/**
 * @brief Benchmark operation identifiers emitted in primitive/protocol results.
 */
typedef enum {
    PQCP_BENCH_MLKEM_KEYPAIR     = 0x0100, /**< ML-KEM key generation. */
    PQCP_BENCH_MLKEM_ENCAPS      = 0x0101, /**< ML-KEM encapsulation. */
    PQCP_BENCH_MLKEM_DECAPS      = 0x0102, /**< ML-KEM decapsulation. */

    PQCP_BENCH_MLDSA_KEYPAIR     = 0x0200, /**< ML-DSA key generation. */
    PQCP_BENCH_MLDSA_SIGN        = 0x0201, /**< ML-DSA signing. */
    PQCP_BENCH_MLDSA_VERIFY      = 0x0202, /**< ML-DSA verification. */
    PQCP_BENCH_MLDSA_SIGN_STREAM = 0x0203, /**< ML-DSA streaming signing. */

    PQCP_BENCH_TLS_HANDSHAKE     = 0x0300, /**< TLS handshake benchmark. */
    PQCP_BENCH_DTLS_HANDSHAKE    = 0x0301, /**< DTLS handshake benchmark. */

    PQCP_BENCH_RNG_ENTROPY       = 0x0400, /**< Entropy-source benchmark. */
    PQCP_BENCH_RNG_DRBG          = 0x0401, /**< DRBG benchmark. */
} pqcp_bench_op_t;

/**
 * @brief Primitive benchmark result record.
 */
typedef struct pqcp_bench_result {
    pqcp_bench_op_t op;     /**< Operation identifier. */

    uint16_t level;         /**< Security level, e.g. 512, 768, or 1024. */

    uint32_t iterations;    /**< Number of measured iterations. */

    uint64_t total_time;    /**< Total measured time in the selected unit. */
    uint64_t min_time;      /**< Minimum per-iteration time. */
    uint64_t max_time;      /**< Maximum per-iteration time. */
    uint64_t avg_time;      /**< Average time in the selected unit. */
    uint64_t avg_cycles;    /**< Average timing in raw hardware cycles. */
    uint64_t avg_us;        /**< Average timing converted to microseconds. */

    uint32_t stack_used;    /**< Peak stack usage in bytes. */
    uint32_t heap_used;     /**< Peak heap usage in bytes, if measured. */

    uint32_t text_size;     /**< .text section size from build artifacts. */
    uint32_t data_size;     /**< .data section size from build artifacts. */
    uint32_t bss_size;      /**< .bss section size from build artifacts. */

    uint8_t  time_unit;     /**< Time unit selector: 0 cycles, 1 microseconds. */
    uint8_t  backend;       /**< Backend selector: 0 C, 1 native assembly. */
} pqcp_bench_result_t;

/**
 * @brief Protocol benchmark result record.
 */
typedef struct pqcp_bench_protocol_result {
    pqcp_bench_result_t base; /**< Embedded primitive-style result header. */

    uint32_t handshake_time_ms;   /**< Handshake latency in milliseconds. */
    uint16_t sig_level;           /**< Signature/authentication security level. */
    uint32_t client_bytes;        /**< Approximate client-to-server payload. */
    uint32_t server_bytes;        /**< Approximate server-to-client payload. */
    uint32_t transcript_bytes;    /**< Total bytes exchanged. */
    uint16_t fragments;           /**< Number of network fragments. */
    uint8_t  cpu_percent;         /**< CPU utilization during handshake. */
    uint32_t peak_ram_bytes;      /**< Peak RAM usage. */
    uint32_t stack_bytes;         /**< Peak stack usage, if measurable. */
    uint32_t heap_bytes;          /**< Peak heap usage, if measurable. */
    uint32_t working_set_bytes;   /**< Static working set used by the flow. */
    uint64_t auth_time_us;        /**< ML-DSA auth stage time. */
    uint64_t key_exchange_time_us;/**< ML-KEM key exchange stage time. */
    uint64_t provider_overhead_us;/**< Handshake time outside PQCP primitives. */
    uint32_t certificate_bytes;   /**< ML-DSA public key + signature footprint. */
    uint32_t key_exchange_bytes;  /**< ML-KEM public key + ciphertext footprint. */
    uint32_t transport_overhead_bytes; /**< Transcript bytes outside PQ payloads. */
    uint32_t rtos_isr_count;      /**< Timer ISR expiries observed during the run. */
    uint32_t rtos_yield_count;    /**< Background load thread yields. */
    uint32_t rtos_jitter_p50_us;  /**< Background load wake-up jitter p50. */
    uint32_t rtos_jitter_p90_us;  /**< Background load wake-up jitter p90. */
    uint32_t rtos_jitter_p99_us;  /**< Background load wake-up jitter p99. */

    uint32_t p50_latency;         /**< Handshake latency p50 in milliseconds. */
    uint32_t p90_latency;         /**< Handshake latency p90 in milliseconds. */
    uint32_t p99_latency;         /**< Handshake latency p99 in milliseconds. */
} pqcp_bench_protocol_result_t;

/*
 * Benchmark Configuration
 */

/**
 * @brief Benchmark execution configuration.
 */
typedef struct pqcp_bench_config {
    uint32_t iterations;     /**< Number of measured iterations. */
    uint32_t warmup;         /**< Warmup iterations before measurement. */
    uint8_t  use_cycles;     /**< Use cycle counter instead of wall time. */
    uint8_t  measure_stack;  /**< Capture stack usage when supported. */
    uint8_t  verbose;        /**< Print per-operation progress. */
} pqcp_bench_config_t;

/* Default configuration */
#define PQCP_BENCH_CONFIG_DEFAULT { \
    .iterations = 100, \
    .warmup = 10, \
    .use_cycles = 1, \
    .measure_stack = 1, \
    .verbose = 0 \
}

/*
 * Benchmark Functions
 */

/**
 * @brief Initialize the benchmark harness.
 *
 * Sets up timing infrastructure (cycle counter or timer).
 *
 * @return 0 on success, negative error code on failure.
 */
int pqcp_bench_init(void);

/**
 * @brief Run ML-KEM benchmarks.
 *
 * @param level   Security level (512, 768, or 1024).
 * @param config  Benchmark configuration (NULL for defaults).
 * @param results Array of 3 results (keypair, encaps, decaps).
 *
 * @return 0 on success, negative error code on failure.
 */
int pqcp_bench_mlkem(uint16_t level,
                     const pqcp_bench_config_t *config,
                     pqcp_bench_result_t results[3]);

/**
 * @brief Run ML-DSA benchmarks.
 *
 * @param level   Security level (44, 65, or 87).
 * @param msg_len Message length for sign/verify.
 * @param config  Benchmark configuration (NULL for defaults).
 * @param results Array of 3 results (keypair, sign, verify).
 *
 * @return 0 on success, negative error code on failure.
 */
int pqcp_bench_mldsa(uint16_t level,
                     size_t msg_len,
                     const pqcp_bench_config_t *config,
                     pqcp_bench_result_t results[3]);

/**
 * @brief Run RNG benchmarks.
 *
 * @param block_size Size of random blocks to generate.
 * @param config     Benchmark configuration.
 * @param result     Output result.
 *
 * @return 0 on success, negative error code on failure.
 */
int pqcp_bench_rng(size_t block_size,
                   const pqcp_bench_config_t *config,
                   pqcp_bench_result_t *result);

/**
 * @brief Run all primitive benchmarks and print results.
 *
 * This is a convenience function that runs ML-KEM and ML-DSA
 * benchmarks for all enabled security levels and prints
 * the results in a parseable format.
 *
 * @param config  Benchmark configuration (NULL for defaults).
 */
void pqcp_bench_run_all(const pqcp_bench_config_t *config);

/**
 * @brief Print a benchmark result in log format.
 *
 * Outputs a line like:
 * PRIM,MLKEM768,MLKEM_KEYPAIR,cycles=12345,us=67,stack=2048,text=4096,bss=256,backend=C
 *
 * The operation field is the stable token returned by pqcp_bench_op_name(),
 * such as MLKEM_KEYPAIR, MLKEM_ENCAPS, MLKEM_DECAPS, MLDSA_KEYPAIR,
 * MLDSA_SIGN, or MLDSA_VERIFY.
 *
 * @note The `PRIM,...` line is a stable parser contract for
 *       `scripts/parse_logs.py`. Add new comma-separated fields only after the
 *       existing fields, and update parser tests in the same change.
 *
 * @param result The benchmark result to print.
 */
void pqcp_bench_print_result(const pqcp_bench_result_t *result);

/**
 * @brief Print a protocol benchmark result.
 *
 * Outputs both PQCP_METRIC format and legacy TLS format:
 * PQCP_METRIC,protocol,handshake,MLKEM,768,time,150,ms
 * TLS,MLKEM768,handshake_ms=150,cpu_pct=45,peak_kib=32,...
 *
 * @note `PQCP_METRIC` lines use the fixed eight-field format documented below.
 *       New metric names are allowed, but field order and units are consumed by
 *       release tooling and must remain compatible.
 *
 * @param result The protocol benchmark result to print.
 */
void pqcp_bench_print_protocol_result(const pqcp_bench_protocol_result_t *result);

/**
 * @brief Run TLS handshake benchmark.
 *
 * Performs simulated TLS 1.3 handshakes using actual PQCP cryptographic
 * operations. Measures real primitive costs without requiring network
 * connectivity.
 *
 * @param kem_level   KEM security level (512, 768, or 1024).
 * @param sig_level   Signature security level (44, 65, or 87).
 * @param iterations  Number of handshakes to perform.
 * @param result      Output protocol benchmark result.
 *
 * @return 0 on success, negative error code on failure.
 */
int pqcp_bench_tls_handshake(uint16_t kem_level,
                              uint16_t sig_level,
                              uint32_t iterations,
                              pqcp_bench_protocol_result_t *result);

/**
 * @brief Run all protocol benchmarks.
 *
 * Runs TLS handshake benchmarks for all enabled algorithm combinations
 * and prints results in both PQCP_METRIC and legacy formats.
 */
void pqcp_bench_run_protocol_all(void);

/*
 * Structured Metrics Logging
 *
 * Use these macros to emit machine-parseable metrics that can be
 * collected by scripts/parse_logs.py.
 *
 * Format: PQCP_METRIC,<component>,<operation>,<algo>,<level>,<metric>,<value>,<unit>
 *
 * Components: primitive, driver, protocol, rtos, entropy
 * Operations: keygen, encaps, decaps, sign, verify, handshake, etc.
 */

/* Log a single metric value */
#define PQCP_LOG_METRIC(component, op, algo, level, metric, value, unit) \
    printk("PQCP_METRIC,%s,%s,%s,%d,%s,%llu,%s\n", \
           (component), (op), (algo), (level), (metric), \
           (unsigned long long)(value), (unit))

/* Convenience macros for common metric types */
#define PQCP_LOG_CYCLES(component, op, algo, level, cycles) \
    PQCP_LOG_METRIC(component, op, algo, level, "cycles", cycles, "cyc")

#define PQCP_LOG_TIME_US(component, op, algo, level, us) \
    PQCP_LOG_METRIC(component, op, algo, level, "time", us, "us")

#define PQCP_LOG_TIME_MS(component, op, algo, level, ms) \
    PQCP_LOG_METRIC(component, op, algo, level, "time", ms, "ms")

#define PQCP_LOG_STACK(component, op, algo, level, bytes) \
    PQCP_LOG_METRIC(component, op, algo, level, "stack", bytes, "B")

#define PQCP_LOG_SIZE(component, op, algo, level, name, bytes) \
    PQCP_LOG_METRIC(component, op, algo, level, name, bytes, "B")

/* Log status (pass/fail) */
#define PQCP_LOG_STATUS(component, op, algo, level, status) \
    printk("PQCP_METRIC,%s,%s,%s,%d,status,%s,\n", \
           (component), (op), (algo), (level), (status) ? "PASS" : "FAIL")

/*
 * Low-level timing utilities
 */

/**
 * @brief Start timing measurement.
 *
 * @return Start timestamp (hardware cycles).
 */
uint64_t pqcp_bench_start_timing(void);

/**
 * @brief End timing measurement.
 *
 * @param start Start timestamp from pqcp_bench_start_timing().
 * @return Elapsed hardware cycles.
 */
uint64_t pqcp_bench_end_timing(uint64_t start);

/**
 * @brief Convert elapsed hardware cycles to microseconds.
 *
 * @param cycles Elapsed hardware cycles.
 *
 * @return Equivalent duration in microseconds.
 */
uint64_t pqcp_bench_cycles_to_us(uint64_t cycles);

/**
 * @brief Get stack high water mark.
 *
 * Uses Zephyr's stack sentinel/analysis features if available.
 *
 * @return Stack usage in bytes, or 0 if not measurable.
 */
uint32_t pqcp_bench_get_stack_usage(void);

/**
 * @brief Get operation name string.
 *
 * @param op Operation ID.
 * @return Human-readable name like "MLKEM_KEYPAIR".
 */
const char *pqcp_bench_op_name(pqcp_bench_op_t op);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_BENCH_H */
