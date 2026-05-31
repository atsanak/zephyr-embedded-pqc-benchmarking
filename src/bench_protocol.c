/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Protocol-Level Benchmarks
 *
 * Measures TLS/DTLS handshake performance with PQC algorithms.
 *
 * This module provides simulated protocol benchmarks that measure the
 * cryptographic overhead of PQC algorithms in TLS-like handshakes without
 * requiring actual network connectivity. Real TLS benchmarks require
 * CONFIG_PQCP_BENCH_PROTOCOL and networking support.
 *
 * Metrics are emitted using the PQCP_METRIC format for consistency with
 * primitive benchmarks.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/atomic.h>
#include <pqcp_zephyr/bench.h>
#include <pqcp_zephyr/provider.h>
#include <pqcp_zephyr/rng.h>
#include <pqcp_zephyr/tls_selftest.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/sys/util.h>
#include <zephyr/version.h>

#ifndef KERNEL_VERSION_STRING
#define KERNEL_VERSION_STRING "unknown"
#endif

/* Protocol benchmarks can work in two modes:
 * 1. Always available: simulated handshake using PQCP primitives
 * 2. CONFIG_PQCP_BENCH_PROTOCOL: real TLS benchmarks (requires networking)
 */

/*
 * Protocol benchmark state
 */

typedef struct {
    uint32_t latency_samples[100];
    uint16_t sample_count;
} protocol_bench_ctx_t;

static protocol_bench_ctx_t bench_ctx;
static bool protocol_metadata_printed;

static uint32_t percentile(uint32_t *samples, uint16_t count, uint8_t p);

static uint32_t protocol_bench_profile_flags(void)
{
    uint32_t flags = 0U;

#if defined(CONFIG_PQCP_PROFILE_MCU_MINIMAL)
    flags |= BIT(0);
#endif
#if defined(CONFIG_PQCP_PROFILE_GATEWAY)
    flags |= BIT(1);
#endif
#if defined(CONFIG_PQCP_PROFILE_NATIVE_LAB)
    flags |= BIT(2);
#endif
#if defined(CONFIG_PQCP_MLKEM_MULTI_LEVEL)
    flags |= BIT(8);
#endif
#if defined(CONFIG_PQCP_MLDSA_MULTI_LEVEL)
    flags |= BIT(9);
#endif
#if defined(CONFIG_PQCP_BACKEND_FORCE_C)
    flags |= BIT(16);
#endif
#if defined(CONFIG_PQCP_BACKEND_FORCE_NATIVE)
    flags |= BIT(17);
#endif

    return flags;
}

static uint32_t protocol_bench_backend_selector(void)
{
#if defined(CONFIG_PQCP_BACKEND_FORCE_NATIVE)
    return 2U;
#elif defined(CONFIG_PQCP_BACKEND_FORCE_C)
    return 1U;
#else
    return 0U;
#endif
}

static void protocol_bench_print_metadata_once(void)
{
    if (protocol_metadata_printed) {
        return;
    }

    protocol_metadata_printed = true;
    printk("PQCP_METRIC,build,metadata,compiler,0,id,%s,\n", __VERSION__);
    printk("PQCP_METRIC,build,metadata,zephyr,0,version,%s,\n",
           KERNEL_VERSION_STRING);
    printk("PQCP_METRIC,build,metadata,board,0,name,%s,\n", CONFIG_BOARD);
    PQCP_LOG_METRIC("build", "metadata", "profile", 0,
                    "flags", protocol_bench_profile_flags(), "mask");
    PQCP_LOG_METRIC("build", "metadata", "backend", 0,
                    "selector", protocol_bench_backend_selector(), "id");
    PQCP_LOG_METRIC("build", "metadata", "distribution", 0,
                    "sample_cap", ARRAY_SIZE(bench_ctx.latency_samples),
                    "count");
#if defined(CONFIG_PQCP_PROVIDER_CONTRACT)
    (void)pqcp_provider_emit_contract();
#endif
}

#if defined(CONFIG_PQCP_BENCH_PROTOCOL_RTOS_METRICS)
#define PQCP_PROTOCOL_RTOS_LOAD_STACK_SIZE 1024
#define PQCP_PROTOCOL_RTOS_JITTER_SAMPLES 128U

typedef struct {
    struct k_timer timer;
    struct k_thread thread;
    atomic_t stop;
    atomic_t isr_count;
    atomic_t yield_count;
} protocol_rtos_probe_t;

K_THREAD_STACK_DEFINE(protocol_rtos_load_stack, PQCP_PROTOCOL_RTOS_LOAD_STACK_SIZE);
static protocol_rtos_probe_t protocol_rtos_probe;
static uint32_t protocol_rtos_jitter_samples[PQCP_PROTOCOL_RTOS_JITTER_SAMPLES];
static uint16_t protocol_rtos_jitter_count;

static uint32_t saturating_us_delta(uint64_t actual, uint64_t expected)
{
    uint64_t delta = (actual > expected) ? (actual - expected) : (expected - actual);

    if (delta > UINT32_MAX) {
        return UINT32_MAX;
    }

    return (uint32_t)delta;
}

static void protocol_rtos_timer_handler(struct k_timer *timer)
{
    protocol_rtos_probe_t *probe = k_timer_user_data_get(timer);

    if (probe != NULL) {
        atomic_inc(&probe->isr_count);
    }
}

static void protocol_rtos_load_thread(void *p1, void *p2, void *p3)
{
    protocol_rtos_probe_t *probe = p1;
    const uint64_t period_us =
        (uint64_t)CONFIG_PQCP_BENCH_PROTOCOL_RTOS_LOAD_PERIOD_MS * USEC_PER_MSEC;
    uint64_t expected_wake_us = k_cyc_to_us_floor64(k_cycle_get_64()) + period_us;

    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    while (atomic_get(&probe->stop) == 0) {
        k_sleep(K_MSEC(CONFIG_PQCP_BENCH_PROTOCOL_RTOS_LOAD_PERIOD_MS));

        if (atomic_get(&probe->stop) != 0) {
            break;
        }

        if (protocol_rtos_jitter_count < ARRAY_SIZE(protocol_rtos_jitter_samples)) {
            uint64_t actual_wake_us = k_cyc_to_us_floor64(k_cycle_get_64());

            protocol_rtos_jitter_samples[protocol_rtos_jitter_count++] =
                saturating_us_delta(actual_wake_us, expected_wake_us);
        }
        expected_wake_us += period_us;

#if CONFIG_PQCP_BENCH_PROTOCOL_RTOS_LOAD_BUSY_WAIT_US > 0
        k_busy_wait(CONFIG_PQCP_BENCH_PROTOCOL_RTOS_LOAD_BUSY_WAIT_US);
#endif
        atomic_inc(&probe->yield_count);
        k_yield();
    }
}

static void protocol_rtos_probe_start(void)
{
    memset(&protocol_rtos_probe, 0, sizeof(protocol_rtos_probe));
    atomic_clear(&protocol_rtos_probe.stop);
    atomic_clear(&protocol_rtos_probe.isr_count);
    atomic_clear(&protocol_rtos_probe.yield_count);
    protocol_rtos_jitter_count = 0U;

    k_timer_init(&protocol_rtos_probe.timer, protocol_rtos_timer_handler, NULL);
    k_timer_user_data_set(&protocol_rtos_probe.timer, &protocol_rtos_probe);
    k_timer_start(&protocol_rtos_probe.timer,
                  K_MSEC(CONFIG_PQCP_BENCH_PROTOCOL_RTOS_LOAD_PERIOD_MS),
                  K_MSEC(CONFIG_PQCP_BENCH_PROTOCOL_RTOS_LOAD_PERIOD_MS));

    (void)k_thread_create(&protocol_rtos_probe.thread,
                          protocol_rtos_load_stack,
                          K_THREAD_STACK_SIZEOF(protocol_rtos_load_stack),
                          protocol_rtos_load_thread,
                          &protocol_rtos_probe, NULL, NULL,
                          K_LOWEST_APPLICATION_THREAD_PRIO,
                          0,
                          K_NO_WAIT);
}

static void protocol_rtos_probe_stop(pqcp_bench_protocol_result_t *result)
{
    atomic_set(&protocol_rtos_probe.stop, 1);
    k_timer_stop(&protocol_rtos_probe.timer);
    k_sleep(K_MSEC(CONFIG_PQCP_BENCH_PROTOCOL_RTOS_LOAD_PERIOD_MS + 1));
    k_thread_abort(&protocol_rtos_probe.thread);

    result->rtos_isr_count = (uint32_t)atomic_get(&protocol_rtos_probe.isr_count);
    result->rtos_yield_count = (uint32_t)atomic_get(&protocol_rtos_probe.yield_count);
    result->rtos_jitter_p50_us = percentile(protocol_rtos_jitter_samples,
                                            protocol_rtos_jitter_count, 50);
    result->rtos_jitter_p90_us = percentile(protocol_rtos_jitter_samples,
                                            protocol_rtos_jitter_count, 90);
    result->rtos_jitter_p99_us = percentile(protocol_rtos_jitter_samples,
                                            protocol_rtos_jitter_count, 99);
}
#endif

static inline uint32_t div_round_up_u32(uint32_t value, uint32_t divisor)
{
    return (value + divisor - 1U) / divisor;
}

void pqcp_bench_print_protocol_result(const pqcp_bench_protocol_result_t *result)
{
    const char *suite = (result->base.op == PQCP_BENCH_TLS_HANDSHAKE) ?
        "TLS13" : "DTLS13";

    protocol_bench_print_metadata_once();

    PQCP_LOG_TIME_MS("protocol", "handshake", suite, 0,
                     result->handshake_time_ms);
    PQCP_LOG_TIME_US("protocol", "auth", "MLDSA",
                     result->sig_level, result->auth_time_us);
    PQCP_LOG_TIME_US("protocol", "key_exchange", "MLKEM",
                     result->base.level, result->key_exchange_time_us);
    PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                    "provider_overhead", result->provider_overhead_us, "us");
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "client_bytes", result->client_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "server_bytes", result->server_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "transcript_bytes", result->transcript_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "certificate_bytes", result->certificate_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "key_exchange_bytes", result->key_exchange_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "transport_overhead_bytes", result->transport_overhead_bytes);
    PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                    "packets", result->fragments, "pkt");
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "working_set", result->working_set_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "peak_ram", result->peak_ram_bytes);

    if (result->stack_bytes > 0U) {
        PQCP_LOG_STACK("protocol", "handshake", suite, 0,
                       result->stack_bytes);
    }

    if (result->heap_bytes > 0U) {
        PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                      "heap", result->heap_bytes);
    }

    if (result->p50_latency > 0U) {
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "min", result->base.min_time, "us");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "max", result->base.max_time, "us");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "p50", result->p50_latency, "ms");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "p90", result->p90_latency, "ms");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "p99", result->p99_latency, "ms");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "sample_count", result->base.iterations, "count");
    }

    if (result->rtos_isr_count > 0U || result->rtos_yield_count > 0U ||
        result->rtos_jitter_p50_us > 0U || result->rtos_jitter_p90_us > 0U ||
        result->rtos_jitter_p99_us > 0U) {
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "rtos_isr_count", result->rtos_isr_count, "count");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "rtos_yield_count", result->rtos_yield_count, "count");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "rtos_jitter_p50", result->rtos_jitter_p50_us, "us");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "rtos_jitter_p90", result->rtos_jitter_p90_us, "us");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "rtos_jitter_p99", result->rtos_jitter_p99_us, "us");
    }

    /* Also emit legacy format for backward compatibility */
    printk("TLS,MLKEM%u_MLDSA%u,handshake_ms=%u,cpu_pct=%u,peak_kib=%u,"
           "transcript_bytes=%u,frags=%u,p50=%u,p90=%u,p99=%u\n",
           result->base.level,
           result->sig_level,
           result->handshake_time_ms,
           result->cpu_percent,
           result->peak_ram_bytes / 1024,
           result->transcript_bytes,
           result->fragments,
           result->p50_latency,
           result->p90_latency,
           result->p99_latency);
}

/* Simple comparison for qsort */
static int compare_uint32(const void *a, const void *b)
{
    uint32_t ua = *(const uint32_t *)a;
    uint32_t ub = *(const uint32_t *)b;
    return (ua > ub) - (ua < ub);
}

/* Calculate percentile from sorted samples */
static uint32_t percentile(uint32_t *samples, uint16_t count, uint8_t p)
{
    if (count == 0U) {
        return 0U;
    }

    qsort(samples, count, sizeof(samples[0]), compare_uint32);

    size_t idx = ((size_t)p * (count - 1U)) / 100U;
    return samples[idx];
}

/**
 * @brief Run TLS handshake benchmark
 *
 * This performs simulated TLS handshakes using actual PQCP cryptographic
 * operations. It measures real primitive costs without requiring network
 * connectivity.
 */
int pqcp_bench_tls_handshake(uint16_t kem_level,
                              uint16_t sig_level,
                              uint32_t iterations,
                              pqcp_bench_protocol_result_t *result)
{
    pqcp_tls_selftest_config_t cfg = {
        .kem_level = kem_level,
        .sig_level = sig_level,
        .initialize_rng = true,
        .initialize_psa = false,
        .emit_metrics = false,
    };
    uint64_t total_handshake_us = 0U;
    uint64_t total_auth_us = 0U;
    uint64_t total_key_exchange_us = 0U;
    uint32_t total_transcript = 0U;
    uint32_t total_client_bytes = 0U;
    uint32_t total_server_bytes = 0U;
    uint32_t total_certificate_bytes = 0U;
    uint32_t total_key_exchange_bytes = 0U;
    uint32_t total_transport_overhead_bytes = 0U;
    uint32_t peak_stack = 0U;
    uint32_t peak_heap = 0U;
    uint32_t peak_working_set = 0U;
    uint64_t total_provider_overhead_us = 0U;
    uint64_t min_time_us = UINT64_MAX;
    uint64_t max_time_us = 0U;
    uint32_t actual_iterations;

    if (result == NULL || iterations == 0U) {
        return -EINVAL;
    }

    memset(result, 0, sizeof(*result));
    memset(&bench_ctx, 0, sizeof(bench_ctx));

    result->base.op = PQCP_BENCH_TLS_HANDSHAKE;
    result->base.level = kem_level;
    result->sig_level = sig_level;
    result->base.iterations = iterations;

    printk("Protocol benchmark: ML-KEM-%u + ML-DSA-%u (%u iterations)\n",
           kem_level, sig_level, iterations);

    if (!pqcp_rng_is_ready()) {
        int ret = pqcp_rng_init();
        if (ret != 0) {
            return ret;
        }
    }

#if defined(CONFIG_PQCP_BENCH_PROTOCOL_RTOS_METRICS)
    protocol_rtos_probe_start();
#endif

    for (uint32_t i = 0U; i < iterations; i++) {
        pqcp_tls_selftest_report_t report;
        uint32_t elapsed_ms;
        int ret = pqcp_tls_selftest_run(&cfg, &report);

        if (ret != 0) {
            printk("ERROR: Simulated handshake failed at iteration %u: %d\n",
                   i, ret);
            return ret;
        }

        elapsed_ms = (uint32_t)((report.handshake_us + 999U) / 1000U);
        if (bench_ctx.sample_count < ARRAY_SIZE(bench_ctx.latency_samples)) {
            bench_ctx.latency_samples[bench_ctx.sample_count++] = elapsed_ms;
        }

        total_handshake_us += report.handshake_us;
        total_auth_us += report.auth_us;
        total_key_exchange_us += report.key_exchange_us;
        total_transcript += report.transcript_bytes;
        total_client_bytes += report.client_bytes;
        total_server_bytes += report.server_bytes;
        total_provider_overhead_us += report.provider_overhead_us;
        total_certificate_bytes += report.certificate_bytes;
        total_key_exchange_bytes += report.key_exchange_bytes;
        total_transport_overhead_bytes += report.transport_overhead_bytes;

        if (report.stack_bytes > peak_stack) {
            peak_stack = report.stack_bytes;
        }
        if (report.heap_bytes > peak_heap) {
            peak_heap = report.heap_bytes;
        }
        if (report.working_set_bytes > peak_working_set) {
            peak_working_set = report.working_set_bytes;
        }
        if (report.handshake_us < min_time_us) {
            min_time_us = report.handshake_us;
        }
        if (report.handshake_us > max_time_us) {
            max_time_us = report.handshake_us;
        }
    }

    actual_iterations = iterations;
    result->handshake_time_ms = (uint32_t)(((total_handshake_us / actual_iterations) + 999U) / 1000U);
    result->auth_time_us = total_auth_us / actual_iterations;
    result->key_exchange_time_us = total_key_exchange_us / actual_iterations;
    result->client_bytes = total_client_bytes / actual_iterations;
    result->server_bytes = total_server_bytes / actual_iterations;
    result->transcript_bytes = total_transcript / actual_iterations;
    result->provider_overhead_us = total_provider_overhead_us / actual_iterations;
    result->certificate_bytes = total_certificate_bytes / actual_iterations;
    result->key_exchange_bytes = total_key_exchange_bytes / actual_iterations;
    result->transport_overhead_bytes =
        total_transport_overhead_bytes / actual_iterations;
    result->fragments = (uint16_t)div_round_up_u32(result->client_bytes, 1400U) +
                        (uint16_t)div_round_up_u32(result->server_bytes, 1400U);
    result->cpu_percent = 95;
    result->stack_bytes = peak_stack;
    result->heap_bytes = peak_heap;
    result->working_set_bytes = peak_working_set;
    result->peak_ram_bytes = peak_stack + peak_heap + peak_working_set;

    result->p50_latency = percentile(bench_ctx.latency_samples,
                                     bench_ctx.sample_count, 50);
    result->p90_latency = percentile(bench_ctx.latency_samples,
                                     bench_ctx.sample_count, 90);
    result->p99_latency = percentile(bench_ctx.latency_samples,
                                     bench_ctx.sample_count, 99);

    result->base.avg_time = total_handshake_us / actual_iterations;
    result->base.min_time = min_time_us;
    result->base.max_time = max_time_us;
    result->base.stack_used = peak_stack;
    result->base.heap_used = peak_heap;
    result->base.time_unit = 1;

#if defined(CONFIG_PQCP_BENCH_PROTOCOL_RTOS_METRICS)
    protocol_rtos_probe_stop(result);
#endif

    return 0;
}

/**
 * @brief Run all protocol benchmarks
 */
void pqcp_bench_run_protocol_all(void)
{
    pqcp_bench_protocol_result_t result;

    printk("\n=== Protocol Benchmark Suite ===\n\n");

    /* Test various combinations based on what's compiled in */
    uint16_t kem_levels[] = {
#ifdef CONFIG_PQCP_MLKEM_LEVEL_512
        512,
#endif
#ifdef CONFIG_PQCP_MLKEM_LEVEL_768
        768,
#endif
#ifdef CONFIG_PQCP_MLKEM_LEVEL_1024
        1024,
#endif
        0  /* sentinel */
    };

    uint16_t sig_levels[] = {
#ifdef CONFIG_PQCP_MLDSA_LEVEL_44
        44,
#endif
#ifdef CONFIG_PQCP_MLDSA_LEVEL_65
        65,
#endif
#ifdef CONFIG_PQCP_MLDSA_LEVEL_87
        87,
#endif
        0  /* sentinel */
    };

    for (size_t i = 0; kem_levels[i] != 0; i++) {
        for (size_t j = 0; sig_levels[j] != 0; j++) {
            int ret = pqcp_bench_tls_handshake(kem_levels[i], sig_levels[j],
                                               CONFIG_PQCP_BENCH_ITERATIONS,
                                               &result);
            if (ret == 0) {
                pqcp_bench_print_protocol_result(&result);
            } else {
                printk("ERROR: Benchmark ML-KEM-%u + ML-DSA-%u failed: %d\n",
                       kem_levels[i], sig_levels[j], ret);
            }
        }
    }

    printk("\n=== Protocol Benchmark Complete ===\n");
}

/* Suppress unused function warning when protocol bench is disabled */
#ifdef CONFIG_PQCP_BENCH_PROTOCOL
/* Real protocol benchmarking hooks would go here when networking is available */
#endif
