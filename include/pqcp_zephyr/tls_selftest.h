/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - TLS Self-Test Helpers
 *
 * Shared self-test and protocol benchmarking helpers for exercising the
 * PQCP TLS/PSA integration path without requiring live networking.
 *
 * Stability: stable validation API for the 1.0.x line. This is not a general
 * production TLS session API.
 */

#ifndef PQCP_ZEPHYR_TLS_SELFTEST_H_
#define PQCP_ZEPHYR_TLS_SELFTEST_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Shared TLS self-test configuration.
 *
 * `kem_level` and `sig_level` must match levels compiled into the current
 * image. `initialize_rng` and `initialize_psa` allow callers to exercise the
 * harness either as a self-contained smoke test or inside a larger benchmark
 * flow where setup already happened earlier.
 *
 * This API is intended for offline self-test, benchmark, and CI coverage
 * flows. It is not a replacement for a production TLS session manager.
 */
typedef struct pqcp_tls_selftest_config {
    uint16_t kem_level;     /**< ML-KEM parameter set, e.g. 768. */
    uint16_t sig_level;     /**< ML-DSA parameter set, e.g. 65. */
    bool initialize_rng;    /**< Initialize the PQCP RNG path before testing. */
    bool initialize_psa;    /**< Initialize PSA Crypto before testing. */
    bool emit_metrics;      /**< Emit stable PQCP_METRIC records on success. */
} pqcp_tls_selftest_config_t;

/**
 * @brief Structured report produced by the TLS self-test harness.
 *
 * Timing fields are reported in microseconds. Byte counters capture the
 * synthetic client/server payload sizes and derived transcript size used by
 * the offline TLS benchmark path. `provider_overhead_us` is the residual
 * handshake time after subtracting the direct ML-KEM and ML-DSA stage costs,
 * which makes it easier to separate primitive cost from the surrounding
 * framework state machine when analyzing protocol metrics.
 *
 * `certificate_bytes`, `key_exchange_bytes`, and
 * `transport_overhead_bytes` provide a lightweight handshake size
 * decomposition without changing the stable PQCP_METRIC wire format.
 * Memory fields reflect best-effort working set and stack observations
 * available in the current build.
 *
 * The report structure is shared by the TLS sample, protocol benchmark sample,
 * and ztest coverage so those paths stay aligned on metric names and meaning.
 *
 * The current implementation uses module-static cryptographic work buffers.
 * Serialize calls to `pqcp_tls_selftest_run()` if multiple threads could
 * exercise the harness at the same time.
 */
typedef struct pqcp_tls_selftest_report {
    uint16_t kem_level;                 /**< ML-KEM parameter set used. */
    uint16_t sig_level;                 /**< ML-DSA parameter set used. */

    uint64_t kem_keygen_us;             /**< ML-KEM key generation time. */
    uint64_t kem_encaps_us;             /**< ML-KEM encapsulation time. */
    uint64_t kem_decaps_us;             /**< ML-KEM decapsulation time. */
    uint64_t sig_keygen_us;             /**< ML-DSA key generation time. */
    uint64_t sig_sign_us;               /**< ML-DSA signing time. */
    uint64_t sig_verify_us;             /**< ML-DSA verification time. */

    uint64_t auth_us;                   /**< Authentication-stage duration. */
    uint64_t key_exchange_us;           /**< Key-exchange-stage duration. */
    uint64_t handshake_us;              /**< Synthetic handshake duration. */
    uint64_t provider_overhead_us;      /**< Residual provider overhead. */

    uint32_t client_bytes;              /**< Synthetic client flight bytes. */
    uint32_t server_bytes;              /**< Synthetic server flight bytes. */
    uint32_t transcript_bytes;          /**< Transcript bytes accounted. */
    uint32_t certificate_bytes;         /**< Certificate payload bytes. */
    uint32_t key_exchange_bytes;        /**< Key exchange payload bytes. */
    uint32_t transport_overhead_bytes;  /**< Framing/transport overhead. */
    uint16_t packets;                   /**< Synthetic packet count. */

    uint32_t working_set_bytes;         /**< Estimated working set size. */
    uint32_t stack_bytes;               /**< Observed stack usage, if known. */
    uint32_t heap_bytes;                /**< Observed heap usage, if known. */
    bool psa_ready;                     /**< Whether PSA Crypto was ready. */
} pqcp_tls_selftest_report_t;

/** @brief Default TLS self-test configuration: ML-KEM-768 plus ML-DSA-65. */
#define PQCP_TLS_SELFTEST_CONFIG_DEFAULT { \
    .kem_level = 768, \
    .sig_level = 65, \
    .initialize_rng = true, \
    .initialize_psa = false, \
    .emit_metrics = true, \
}

/**
 * @brief Initialize PSA crypto for TLS self-tests.
 *
 * When PSA support is not compiled in, the function returns -ENOTSUP.
 *
 * @param ready Optional pointer that receives whether PSA was initialized.
 *
 * @return 0 on success, negative errno-style code on failure.
 *
 * @note Intended for both test/benchmark harnesses and production-oriented
 *       integrations that want to probe PSA availability before calling the
 *       shared TLS self-test flow.
 */
int pqcp_tls_selftest_init_psa(bool *ready);

/**
 * @brief Run the shared PQCP TLS self-test flow.
 *
 * This performs the same PQC-heavy operations used by the TLS sample's
 * self-test mode: ML-DSA key generation/sign/verify and ML-KEM
 * key generation/encaps/decaps, plus transcript and payload accounting.
 *
 * Callers typically use this in one of two ways:
 *
 * - TLS sample self-test mode, with `initialize_rng=true`,
 *   `initialize_psa=true`, and `emit_metrics=true`
 * - Protocol benchmark/sample mode, with setup handled externally and
 *   `emit_metrics` controlled by the benchmark harness
 *
 * @param config Benchmark/self-test configuration. NULL uses defaults.
 * @param report Output report filled on success.
 *
 * @retval 0 Self-test flow completed successfully.
 * @retval -EINVAL Invalid pointers or unsupported algorithm levels.
 * @retval -ENOTSUP PSA initialization was requested in a build without PSA.
 * @retval Other negative errno-style codes propagated from RNG or PSA setup.
 * @retval -EIO One of the underlying PQCP operations failed or produced
 *         mismatched shared secrets.
 *
 * @note Intended for both reusable test/benchmark harnesses and sample code
 *       paths that want a shared offline TLS/PSA/PQCP validation flow. This
 *       function is not reentrant because the implementation uses shared
 *       module-static work buffers.
 */
int pqcp_tls_selftest_run(const pqcp_tls_selftest_config_t *config,
                          pqcp_tls_selftest_report_t *report);

/**
 * @brief Emit structured metrics for a completed TLS self-test run.
 *
 * Metric emission preserves the stable eight-field `PQCP_METRIC` wire format
 * used across the module. The harness only adds new metric names and does not
 * alter the field layout.
 *
 * @param report Completed report to log.
 *
 * @note Intended for test/benchmark harnesses and sample code paths that emit
 *       structured metrics for later parsing.
 */
void pqcp_tls_selftest_log_metrics(const pqcp_tls_selftest_report_t *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_TLS_SELFTEST_H_ */
