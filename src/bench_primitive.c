/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Primitive-Level Benchmarks
 *
 * Measures performance of ML-KEM and ML-DSA operations.
 */
#include <pqcp_zephyr/rng.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/bench.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/provider.h>

#include <stdlib.h>
#include <string.h>
#include <zephyr/sys/util.h>
#include <zephyr/version.h>

#ifdef CONFIG_PQCP_BENCH

#ifndef KERNEL_VERSION_STRING
#define KERNEL_VERSION_STRING "unknown"
#endif

#ifndef CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES
#define CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES 128
#endif

/*
 * Timing infrastructure
 */

/*
 * Use Zephyr's public Arm Cortex-M DWT helpers when the helper header is
 * exported by the current tree. This mirrors Zephyr's own Arm timing code
 * include style (`<cortex_m/dwt.h>`) instead of depending on private paths.
 */
#if defined(CONFIG_CPU_CORTEX_M_HAS_DWT) && defined(CONFIG_PQCP_BENCH_CYCLE_COUNTER)
#if defined(__has_include) && !defined(__CPPCHECK__)
#if __has_include(<cortex_m/dwt.h>)
#include <cortex_m/dwt.h>
#define USE_DWT_CYCLES 1
#endif
#endif
#endif

#ifndef USE_DWT_CYCLES
#define USE_DWT_CYCLES 0
#endif

static bool bench_initialized = false;
static bool bench_metadata_printed;

typedef struct {
    bool valid;
    pqcp_bench_op_t op;
    uint16_t level;
    uint32_t sample_count;
    uint64_t min_cycles;
    uint64_t median_cycles;
    uint64_t p90_cycles;
    uint64_t p99_cycles;
    uint64_t max_cycles;
    uint64_t mad_cycles;
} pqcp_bench_distribution_t;

static pqcp_bench_distribution_t bench_distribution_cache[24];

static int compare_u64(const void *a, const void *b)
{
    uint64_t lhs = *(const uint64_t *)a;
    uint64_t rhs = *(const uint64_t *)b;

    if (lhs < rhs) {
        return -1;
    }
    if (lhs > rhs) {
        return 1;
    }
    return 0;
}

static uint64_t percentile_sorted_u64(const uint64_t *samples,
                                      uint32_t count, uint8_t percentile)
{
    uint32_t idx;

    if (count == 0U) {
        return 0U;
    }

    idx = ((uint32_t)percentile * (count - 1U)) / 100U;
    return samples[idx];
}

static uint64_t median_absolute_deviation(const uint64_t *samples,
                                          uint32_t count,
                                          uint64_t median)
{
    static uint64_t deviations[CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES];

    if (count == 0U || count > ARRAY_SIZE(deviations)) {
        return 0U;
    }

    for (uint32_t i = 0U; i < count; ++i) {
        deviations[i] = samples[i] > median ? samples[i] - median
                                            : median - samples[i];
    }

    qsort(deviations, count, sizeof(deviations[0]), compare_u64);
    return percentile_sorted_u64(deviations, count, 50);
}

static void pqcp_bench_store_distribution(pqcp_bench_op_t op,
                                          uint16_t level,
                                          uint64_t *samples,
                                          uint32_t count)
{
    pqcp_bench_distribution_t stats = { 0 };
    pqcp_bench_distribution_t *slot = NULL;

    if (count == 0U) {
        return;
    }

    if (count > CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES) {
        count = CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES;
    }

    qsort(samples, count, sizeof(samples[0]), compare_u64);

    stats.valid = true;
    stats.op = op;
    stats.level = level;
    stats.sample_count = count;
    stats.min_cycles = samples[0];
    stats.median_cycles = percentile_sorted_u64(samples, count, 50);
    stats.p90_cycles = percentile_sorted_u64(samples, count, 90);
    stats.p99_cycles = percentile_sorted_u64(samples, count, 99);
    stats.max_cycles = samples[count - 1U];
    stats.mad_cycles = median_absolute_deviation(samples, count,
                                                 stats.median_cycles);

    for (size_t i = 0U; i < ARRAY_SIZE(bench_distribution_cache); ++i) {
        if (bench_distribution_cache[i].valid &&
            bench_distribution_cache[i].op == op &&
            bench_distribution_cache[i].level == level) {
            slot = &bench_distribution_cache[i];
            break;
        }
        if (slot == NULL && !bench_distribution_cache[i].valid) {
            slot = &bench_distribution_cache[i];
        }
    }

    if (slot != NULL) {
        *slot = stats;
    }
}

static const pqcp_bench_distribution_t *
pqcp_bench_find_distribution(pqcp_bench_op_t op, uint16_t level)
{
    for (size_t i = 0U; i < ARRAY_SIZE(bench_distribution_cache); ++i) {
        if (bench_distribution_cache[i].valid &&
            bench_distribution_cache[i].op == op &&
            bench_distribution_cache[i].level == level) {
            return &bench_distribution_cache[i];
        }
    }

    return NULL;
}

static const char *pqcp_bench_metric_component(pqcp_bench_op_t op)
{
    if (op >= PQCP_BENCH_MLKEM_KEYPAIR && op <= PQCP_BENCH_MLKEM_DECAPS) {
        return "MLKEM";
    }
    if (op >= PQCP_BENCH_MLDSA_KEYPAIR && op <= PQCP_BENCH_MLDSA_VERIFY) {
        return "MLDSA";
    }
    return "RNG";
}

static const char *pqcp_bench_metric_operation(pqcp_bench_op_t op)
{
    switch (op) {
    case PQCP_BENCH_MLKEM_KEYPAIR:
    case PQCP_BENCH_MLDSA_KEYPAIR:
        return "keygen";
    case PQCP_BENCH_MLKEM_ENCAPS:
        return "encaps";
    case PQCP_BENCH_MLKEM_DECAPS:
        return "decaps";
    case PQCP_BENCH_MLDSA_SIGN:
        return "sign";
    case PQCP_BENCH_MLDSA_VERIFY:
        return "verify";
    case PQCP_BENCH_RNG_ENTROPY:
        return "entropy";
    default:
        return "unknown";
    }
}

static uint32_t pqcp_bench_profile_flags(void)
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

static uint32_t pqcp_bench_backend_selector(void)
{
#if defined(CONFIG_PQCP_BACKEND_FORCE_NATIVE)
    return 2U;
#elif defined(CONFIG_PQCP_BACKEND_FORCE_C)
    return 1U;
#else
    return 0U;
#endif
}

static void pqcp_bench_print_metadata_once(void)
{
    if (bench_metadata_printed) {
        return;
    }

    bench_metadata_printed = true;
    printk("PQCP_METRIC,build,metadata,compiler,0,id,%s,\n", __VERSION__);
    printk("PQCP_METRIC,build,metadata,zephyr,0,version,%s,\n",
           KERNEL_VERSION_STRING);
    printk("PQCP_METRIC,build,metadata,board,0,name,%s,\n", CONFIG_BOARD);
    PQCP_LOG_METRIC("build", "metadata", "profile", 0,
                    "flags", pqcp_bench_profile_flags(), "mask");
    PQCP_LOG_METRIC("build", "metadata", "backend", 0,
                    "selector", pqcp_bench_backend_selector(), "id");
    PQCP_LOG_METRIC("build", "metadata", "distribution", 0,
                    "sample_cap", CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES,
                    "count");
#if defined(CONFIG_PQCP_PROVIDER_CONTRACT)
    (void)pqcp_provider_emit_contract();
#endif
}

int pqcp_bench_init(void)
{
    if (bench_initialized) {
        return 0;
    }

#if USE_DWT_CYCLES
    z_arm_dwt_init();
    z_arm_dwt_init_cycle_counter();
#endif

    bench_initialized = true;
    return 0;
}

uint64_t pqcp_bench_start_timing(void)
{
#if USE_DWT_CYCLES
    return z_arm_dwt_get_cycles();
#else
    return k_cycle_get_32();
#endif
}

uint64_t pqcp_bench_end_timing(uint64_t start)
{
#if USE_DWT_CYCLES
    uint32_t end = z_arm_dwt_get_cycles();
    return (uint64_t)(end - (uint32_t)start);
#else
    uint32_t end = k_cycle_get_32();
    return (uint64_t)(end - (uint32_t)start);
#endif
}

uint64_t pqcp_bench_cycles_to_us(uint64_t cycles)
{
    return (cycles * 1000000ULL) / CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC;
}

uint32_t pqcp_bench_get_stack_usage(void)
{
#if defined(CONFIG_THREAD_STACK_INFO) && defined(CONFIG_INIT_STACKS)
    struct k_thread *thread = k_current_get();
    size_t unused = 0;

    int ret = k_thread_stack_space_get(thread, &unused);
    if (ret == 0) {
        /* Return used = total - unused */
        return (uint32_t)(thread->stack_info.size - unused);
    }
#endif
    return 0;
}

const char *pqcp_bench_op_name(pqcp_bench_op_t op)
{
    switch (op) {
    case PQCP_BENCH_MLKEM_KEYPAIR: return "MLKEM_KEYPAIR";
    case PQCP_BENCH_MLKEM_ENCAPS:  return "MLKEM_ENCAPS";
    case PQCP_BENCH_MLKEM_DECAPS:  return "MLKEM_DECAPS";
    case PQCP_BENCH_MLDSA_KEYPAIR: return "MLDSA_KEYPAIR";
    case PQCP_BENCH_MLDSA_SIGN:    return "MLDSA_SIGN";
    case PQCP_BENCH_MLDSA_VERIFY:  return "MLDSA_VERIFY";
    case PQCP_BENCH_RNG_ENTROPY:   return "RNG_ENTROPY";
    default: return "UNKNOWN";
    }
}

void pqcp_bench_print_result(const pqcp_bench_result_t *result)
{
    const char *unit = (result->time_unit == 0) ? "cycles" : "us";
    const char *backend = (result->backend == 0) ? "C" : "native";
    const char *algorithm = pqcp_bench_metric_component(result->op);
    const char *operation = pqcp_bench_metric_operation(result->op);
    const pqcp_bench_distribution_t *distribution =
        pqcp_bench_find_distribution(result->op, result->level);

    pqcp_bench_print_metadata_once();

    printk("PRIM,%s%u,%s,%s=%llu,us=%llu,stack=%u,text=%u,bss=%u,backend=%s\n",
           algorithm,
           result->level,
           pqcp_bench_op_name(result->op),
           unit,
           result->avg_time,
           result->avg_us,
           result->stack_used,
           result->text_size,
           result->bss_size,
           backend);

    if (result->avg_cycles > 0U) {
        PQCP_LOG_CYCLES("primitive", operation, algorithm, result->level,
                        result->avg_cycles);
    }
    if (result->avg_us > 0U) {
        PQCP_LOG_TIME_US("primitive", operation, algorithm, result->level,
                         result->avg_us);
    }
    if (result->stack_used > 0U) {
        PQCP_LOG_STACK("primitive", "total", algorithm, result->level,
                       result->stack_used);
    }
    if (distribution != NULL) {
        PQCP_LOG_METRIC("primitive", operation, algorithm, result->level,
                        "cycles_min", distribution->min_cycles, "cyc");
        PQCP_LOG_METRIC("primitive", operation, algorithm, result->level,
                        "cycles_median", distribution->median_cycles, "cyc");
        PQCP_LOG_METRIC("primitive", operation, algorithm, result->level,
                        "cycles_p90", distribution->p90_cycles, "cyc");
        PQCP_LOG_METRIC("primitive", operation, algorithm, result->level,
                        "cycles_p99", distribution->p99_cycles, "cyc");
        PQCP_LOG_METRIC("primitive", operation, algorithm, result->level,
                        "cycles_max", distribution->max_cycles, "cyc");
        PQCP_LOG_METRIC("primitive", operation, algorithm, result->level,
                        "cycles_mad", distribution->mad_cycles, "cyc");
        PQCP_LOG_METRIC("primitive", operation, algorithm, result->level,
                        "sample_count", distribution->sample_count, "count");
    }
}

/*
 * ML-KEM Benchmarks
 */

int pqcp_bench_mlkem(uint16_t level,
                     const pqcp_bench_config_t *config,
                     pqcp_bench_result_t results[3])
{
    pqcp_bench_config_t cfg;

    if (config == NULL) {
        cfg = (pqcp_bench_config_t)PQCP_BENCH_CONFIG_DEFAULT;
    } else {
        cfg = *config;
    }

    pqcp_mlkem_level_t mlkem_level;
    switch (level) {
    case 512:  mlkem_level = PQCP_MLKEM_512;  break;
    case 768:  mlkem_level = PQCP_MLKEM_768;  break;
    case 1024: mlkem_level = PQCP_MLKEM_1024; break;
    default: return -1;
    }

    /* Allocate buffers */
    static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
    static uint8_t ss1[PQCP_MLKEM_SS_SIZE];
    static uint8_t ss2[PQCP_MLKEM_SS_SIZE];

    uint64_t cycles_totals[3] = {0, 0, 0};
    uint64_t min_cycles[3] = {UINT64_MAX, UINT64_MAX, UINT64_MAX};
    uint64_t max_cycles[3] = {0, 0, 0};
    static uint64_t samples[3][CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES];
    uint32_t sample_counts[3] = {0, 0, 0};

    /* Initialize benchmark infrastructure */
    pqcp_bench_init();

    if (cfg.verbose) {
        printk("Benchmarking ML-KEM-%u (%u iterations, %u warmup)\n",
               level, cfg.iterations, cfg.warmup);
    }

    /* Warmup */
    for (uint32_t i = 0; i < cfg.warmup; i++) {
        pqcp_mlkem_keypair(mlkem_level, pk, sk);
        pqcp_mlkem_encapsulate(mlkem_level, pk, ct, ss1);
        pqcp_mlkem_decapsulate(mlkem_level, ct, sk, ss2);
    }

    /* Benchmark keygen */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mlkem_keypair(mlkem_level, pk, sk);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[0] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[0]) min_cycles[0] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[0]) max_cycles[0] = elapsed_cycles;
        if (sample_counts[0] < ARRAY_SIZE(samples[0])) {
            samples[0][sample_counts[0]++] = elapsed_cycles;
        }
    }

    /* Benchmark encapsulation */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mlkem_encapsulate(mlkem_level, pk, ct, ss1);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[1] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[1]) min_cycles[1] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[1]) max_cycles[1] = elapsed_cycles;
        if (sample_counts[1] < ARRAY_SIZE(samples[1])) {
            samples[1][sample_counts[1]++] = elapsed_cycles;
        }
    }

    /* Benchmark decapsulation */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mlkem_decapsulate(mlkem_level, ct, sk, ss2);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[2] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[2]) min_cycles[2] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[2]) max_cycles[2] = elapsed_cycles;
        if (sample_counts[2] < ARRAY_SIZE(samples[2])) {
            samples[2][sample_counts[2]++] = elapsed_cycles;
        }
    }

    /* Fill results */
    static const pqcp_bench_op_t ops[3] = {
        PQCP_BENCH_MLKEM_KEYPAIR,
        PQCP_BENCH_MLKEM_ENCAPS,
        PQCP_BENCH_MLKEM_DECAPS
    };

    for (int i = 0; i < 3; i++) {
        uint64_t avg_cycles = cycles_totals[i] / cfg.iterations;
        uint64_t avg_us = pqcp_bench_cycles_to_us(avg_cycles);

        pqcp_bench_store_distribution(ops[i], level, samples[i],
                                      sample_counts[i]);

        results[i].op = ops[i];
        results[i].level = level;
        results[i].iterations = cfg.iterations;
        results[i].total_time = cfg.use_cycles ? cycles_totals[i]
                                               : pqcp_bench_cycles_to_us(cycles_totals[i]);
        results[i].min_time = cfg.use_cycles ? min_cycles[i]
                                             : pqcp_bench_cycles_to_us(min_cycles[i]);
        results[i].max_time = cfg.use_cycles ? max_cycles[i]
                                             : pqcp_bench_cycles_to_us(max_cycles[i]);
        results[i].avg_time = cfg.use_cycles ? avg_cycles : avg_us;
        results[i].avg_cycles = avg_cycles;
        results[i].avg_us = avg_us;
        results[i].stack_used = 0;
        if (cfg.measure_stack) {
            results[i].stack_used = pqcp_bench_get_stack_usage();
        }
        results[i].heap_used = 0;
        results[i].text_size = 0;  /* Filled by scripts */
        results[i].data_size = 0;
        results[i].bss_size = 0;
        results[i].time_unit = cfg.use_cycles ? 0 : 1;
#ifdef CONFIG_PQCP_BACKEND_FORCE_NATIVE
        results[i].backend = 1;
#else
        results[i].backend = 0;
#endif
    }

    return 0;
}

/*
 * ML-DSA Benchmarks
 */

int pqcp_bench_mldsa(uint16_t level,
                     size_t msg_len,
                     const pqcp_bench_config_t *config,
                     pqcp_bench_result_t results[3])
{
    pqcp_bench_config_t cfg;

    if (config == NULL) {
        cfg = (pqcp_bench_config_t)PQCP_BENCH_CONFIG_DEFAULT;
    } else {
        cfg = *config;
    }

    pqcp_mldsa_level_t mldsa_level;
    switch (level) {
    case 44: mldsa_level = PQCP_MLDSA_44; break;
    case 65: mldsa_level = PQCP_MLDSA_65; break;
    case 87: mldsa_level = PQCP_MLDSA_87; break;
    default: return -1;
    }

    /* Allocate buffers */
    static uint8_t pk[PQCP_MLDSA_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLDSA_SK_SIZE_MAX];
    static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    static uint8_t msg[256];  /* Max message size for benchmark */

    if (msg_len > sizeof(msg)) {
        msg_len = sizeof(msg);
    }

    /* Initialize message with pattern */
    for (size_t i = 0; i < msg_len; i++) {
        msg[i] = (uint8_t)(i & 0xFF);
    }

    uint64_t cycles_totals[3] = {0, 0, 0};
    uint64_t min_cycles[3] = {UINT64_MAX, UINT64_MAX, UINT64_MAX};
    uint64_t max_cycles[3] = {0, 0, 0};
    static uint64_t samples[3][CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES];
    uint32_t sample_counts[3] = {0, 0, 0};

    pqcp_bench_init();

    if (cfg.verbose) {
        printk("Benchmarking ML-DSA-%u (%u iterations, msg_len=%zu)\n",
               level, cfg.iterations, msg_len);
    }

    /* Warmup */
    for (uint32_t i = 0; i < cfg.warmup; i++) {
        pqcp_mldsa_keypair(mldsa_level, pk, sk);
        pqcp_mldsa_sign(mldsa_level, sk, msg, msg_len, NULL, 0, sig);
        pqcp_mldsa_verify(mldsa_level, pk, msg, msg_len, NULL, 0, sig);
    }

    /* Generate key for sign/verify benchmarks */
    pqcp_mldsa_keypair(mldsa_level, pk, sk);

    /* Benchmark keygen */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mldsa_keypair(mldsa_level, pk, sk);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[0] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[0]) min_cycles[0] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[0]) max_cycles[0] = elapsed_cycles;
        if (sample_counts[0] < ARRAY_SIZE(samples[0])) {
            samples[0][sample_counts[0]++] = elapsed_cycles;
        }
    }

    /* Benchmark signing */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mldsa_sign(mldsa_level, sk, msg, msg_len, NULL, 0, sig);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[1] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[1]) min_cycles[1] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[1]) max_cycles[1] = elapsed_cycles;
        if (sample_counts[1] < ARRAY_SIZE(samples[1])) {
            samples[1][sample_counts[1]++] = elapsed_cycles;
        }
    }

    /* Benchmark verification */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mldsa_verify(mldsa_level, pk, msg, msg_len, NULL, 0, sig);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[2] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[2]) min_cycles[2] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[2]) max_cycles[2] = elapsed_cycles;
        if (sample_counts[2] < ARRAY_SIZE(samples[2])) {
            samples[2][sample_counts[2]++] = elapsed_cycles;
        }
    }

    /* Fill results */
    static const pqcp_bench_op_t ops[3] = {
        PQCP_BENCH_MLDSA_KEYPAIR,
        PQCP_BENCH_MLDSA_SIGN,
        PQCP_BENCH_MLDSA_VERIFY
    };

    for (int i = 0; i < 3; i++) {
        uint64_t avg_cycles = cycles_totals[i] / cfg.iterations;
        uint64_t avg_us = pqcp_bench_cycles_to_us(avg_cycles);

        pqcp_bench_store_distribution(ops[i], level, samples[i],
                                      sample_counts[i]);

        results[i].op = ops[i];
        results[i].level = level;
        results[i].iterations = cfg.iterations;
        results[i].total_time = cfg.use_cycles ? cycles_totals[i]
                                               : pqcp_bench_cycles_to_us(cycles_totals[i]);
        results[i].min_time = cfg.use_cycles ? min_cycles[i]
                                             : pqcp_bench_cycles_to_us(min_cycles[i]);
        results[i].max_time = cfg.use_cycles ? max_cycles[i]
                                             : pqcp_bench_cycles_to_us(max_cycles[i]);
        results[i].avg_time = cfg.use_cycles ? avg_cycles : avg_us;
        results[i].avg_cycles = avg_cycles;
        results[i].avg_us = avg_us;
        results[i].stack_used = 0;
        if (cfg.measure_stack) {
            results[i].stack_used = pqcp_bench_get_stack_usage();
        }
        results[i].heap_used = 0;
        results[i].text_size = 0;
        results[i].data_size = 0;
        results[i].bss_size = 0;
        results[i].time_unit = cfg.use_cycles ? 0 : 1;
#ifdef CONFIG_PQCP_BACKEND_FORCE_NATIVE
        results[i].backend = 1;
#else
        results[i].backend = 0;
#endif
    }

    return 0;
}

/*
 * RNG Benchmarks
 */

int pqcp_bench_rng(size_t block_size,
                   const pqcp_bench_config_t *config,
                   pqcp_bench_result_t *result)
{
    pqcp_bench_config_t cfg;

    if (config == NULL) {
        cfg = (pqcp_bench_config_t)PQCP_BENCH_CONFIG_DEFAULT;
    } else {
        cfg = *config;
    }

    static uint8_t buffer[256];
    if (block_size > sizeof(buffer)) {
        block_size = sizeof(buffer);
    }

    pqcp_bench_init();

    uint64_t total_cycles = 0;
    uint64_t min_cycles = UINT64_MAX;
    uint64_t max_cycles = 0;
    static uint64_t samples[CONFIG_PQCP_BENCH_DISTRIBUTION_SAMPLES];
    uint32_t sample_count = 0;

    /* Warmup */
    for (uint32_t i = 0; i < cfg.warmup; i++) {
        pqcp_rng_get_bytes(buffer, block_size);
    }

    /* Benchmark */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_rng_get_bytes(buffer, block_size);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        total_cycles += elapsed_cycles;
        if (elapsed_cycles < min_cycles) min_cycles = elapsed_cycles;
        if (elapsed_cycles > max_cycles) max_cycles = elapsed_cycles;
        if (sample_count < ARRAY_SIZE(samples)) {
            samples[sample_count++] = elapsed_cycles;
        }
    }

    pqcp_bench_store_distribution(PQCP_BENCH_RNG_ENTROPY,
                                  (uint16_t)block_size,
                                  samples, sample_count);

    result->avg_cycles = total_cycles / cfg.iterations;
    result->avg_us = pqcp_bench_cycles_to_us(result->avg_cycles);
    result->op = PQCP_BENCH_RNG_ENTROPY;
    result->level = (uint16_t)block_size;
    result->iterations = cfg.iterations;
    result->total_time = cfg.use_cycles ? total_cycles
                                        : pqcp_bench_cycles_to_us(total_cycles);
    result->min_time = cfg.use_cycles ? min_cycles
                                      : pqcp_bench_cycles_to_us(min_cycles);
    result->max_time = cfg.use_cycles ? max_cycles
                                      : pqcp_bench_cycles_to_us(max_cycles);
    result->avg_time = cfg.use_cycles ? result->avg_cycles : result->avg_us;
    result->stack_used = 0;
    result->heap_used = 0;
    result->text_size = 0;
    result->data_size = 0;
    result->bss_size = 0;
    result->time_unit = cfg.use_cycles ? 0 : 1;
    result->backend = 0;

    return 0;
}

/*
 * Run all benchmarks
 */

void pqcp_bench_run_all(const pqcp_bench_config_t *config)
{
    pqcp_bench_result_t results[3];

    printk("\n=== PQCP Benchmark Suite ===\n\n");

#ifdef CONFIG_PQCP_MLKEM_LEVEL_512
    printk("--- ML-KEM-512 ---\n");
    pqcp_bench_mlkem(512, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif

#ifdef CONFIG_PQCP_MLKEM_LEVEL_768
    printk("\n--- ML-KEM-768 ---\n");
    pqcp_bench_mlkem(768, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif

#ifdef CONFIG_PQCP_MLKEM_LEVEL_1024
    printk("\n--- ML-KEM-1024 ---\n");
    pqcp_bench_mlkem(1024, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif

#ifdef CONFIG_PQCP_MLDSA_LEVEL_44
    printk("\n--- ML-DSA-44 ---\n");
    pqcp_bench_mldsa(44, 64, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif

#ifdef CONFIG_PQCP_MLDSA_LEVEL_65
    printk("\n--- ML-DSA-65 ---\n");
    pqcp_bench_mldsa(65, 64, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif

#ifdef CONFIG_PQCP_MLDSA_LEVEL_87
    printk("\n--- ML-DSA-87 ---\n");
    pqcp_bench_mldsa(87, 64, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif

    printk("\n--- RNG ---\n");
    pqcp_bench_result_t rng_result;
    pqcp_bench_rng(32, config, &rng_result);
    pqcp_bench_print_result(&rng_result);

    printk("\n=== Benchmark Complete ===\n");
}

#endif /* CONFIG_PQCP_BENCH */
