/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Basic KEM Sample
 *
 * Demonstrates ML-KEM key encapsulation mechanism using the PQCP module.
 * Runs keygen, encapsulation, and decapsulation operations and prints
 * timing results.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>
#include <pqcp_zephyr/bench.h>

#include <string.h>

/* Verify shared secrets match */
static bool verify_ss(const uint8_t *ss1, const uint8_t *ss2)
{
    return memcmp(ss1, ss2, PQCP_MLKEM_SS_SIZE) == 0;
}

static pqcp_mlkem_level_t sample_mlkem_level(void)
{
#if defined(CONFIG_PQCP_MLKEM_MULTI_LEVEL)
    return PQCP_MLKEM_768;
#elif defined(CONFIG_PQCP_MLKEM_LEVEL_512) && \
      !defined(CONFIG_PQCP_MLKEM_LEVEL_768) && \
      !defined(CONFIG_PQCP_MLKEM_LEVEL_1024)
    return PQCP_MLKEM_512;
#elif defined(CONFIG_PQCP_MLKEM_LEVEL_1024) && \
      !defined(CONFIG_PQCP_MLKEM_LEVEL_512) && \
      !defined(CONFIG_PQCP_MLKEM_LEVEL_768)
    return PQCP_MLKEM_1024;
#else
    return PQCP_MLKEM_768;
#endif
}

/* Print hex bytes */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printk("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) {
        printk("%02x", data[i]);
    }
    if (len > 16) {
        printk("...");
    }
    printk("\n");
}

int main(void)
{
    uint64_t keygen_us;
    uint64_t encaps_us;
    uint64_t decaps_us;

    printk("\n");
    printk("========================================\n");
    printk("  PQCP Basic ML-KEM Sample\n");
    printk("========================================\n\n");

    /* Initialize RNG */
    int ret = pqcp_rng_init();
    if (ret != 0) {
        printk("ERROR: Failed to initialize RNG: %d\n", ret);
        return -1;
    }
    printk("RNG initialized successfully\n");

    pqcp_mlkem_level_t level = sample_mlkem_level();

    printk("\nUsing %s\n", pqcp_mlkem_level_name(level));
    printk("  Public key size: %zu bytes\n", pqcp_mlkem_pk_size(level));
    printk("  Secret key size: %zu bytes\n", pqcp_mlkem_sk_size(level));
    printk("  Ciphertext size: %zu bytes\n", pqcp_mlkem_ct_size(level));
    printk("  Shared secret:   %d bytes\n\n", PQCP_MLKEM_SS_SIZE);

    /* Allocate buffers */
    static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
    static uint8_t ss_enc[PQCP_MLKEM_SS_SIZE];
    static uint8_t ss_dec[PQCP_MLKEM_SS_SIZE];

    /* Initialize benchmark timing */
    pqcp_bench_init();

    /* Key Generation */
    printk("--- Key Generation ---\n");
    uint64_t start = pqcp_bench_start_timing();

    ret = pqcp_mlkem_keypair(level, pk, sk);

    uint64_t keygen_time = pqcp_bench_end_timing(start);
    keygen_us = pqcp_bench_cycles_to_us(keygen_time);

    if (ret != PQCP_MLKEM_SUCCESS) {
        printk("ERROR: Key generation failed: %d\n", ret);
        return -1;
    }

    printk("Key generation completed\n");
    print_hex("Public key", pk, pqcp_mlkem_pk_size(level));
    printk("Time: %llu cycles (%llu us)\n\n", keygen_time, keygen_us);

    /* Encapsulation */
    printk("--- Encapsulation ---\n");
    start = pqcp_bench_start_timing();

    ret = pqcp_mlkem_encapsulate(level, pk, ct, ss_enc);

    uint64_t encaps_time = pqcp_bench_end_timing(start);
    encaps_us = pqcp_bench_cycles_to_us(encaps_time);

    if (ret != PQCP_MLKEM_SUCCESS) {
        printk("ERROR: Encapsulation failed: %d\n", ret);
        return -1;
    }

    printk("Encapsulation completed\n");
    print_hex("Ciphertext", ct, pqcp_mlkem_ct_size(level));
    print_hex("Shared secret (encap)", ss_enc, PQCP_MLKEM_SS_SIZE);
    printk("Time: %llu cycles (%llu us)\n\n", encaps_time, encaps_us);

    /* Decapsulation */
    printk("--- Decapsulation ---\n");
    start = pqcp_bench_start_timing();

    ret = pqcp_mlkem_decapsulate(level, ct, sk, ss_dec);

    uint64_t decaps_time = pqcp_bench_end_timing(start);
    decaps_us = pqcp_bench_cycles_to_us(decaps_time);

    if (ret != PQCP_MLKEM_SUCCESS) {
        printk("ERROR: Decapsulation failed: %d\n", ret);
        return -1;
    }

    printk("Decapsulation completed\n");
    print_hex("Shared secret (decap)", ss_dec, PQCP_MLKEM_SS_SIZE);
    printk("Time: %llu cycles (%llu us)\n\n", decaps_time, decaps_us);

    /* Verify */
    printk("--- Verification ---\n");
    if (verify_ss(ss_enc, ss_dec)) {
        printk("SUCCESS: Shared secrets match!\n");
    } else {
        printk("FAILURE: Shared secrets do not match!\n");
        return -1;
    }

    /* Summary */
    printk("\n--- Summary ---\n");
    printk("Algorithm: %s\n", pqcp_mlkem_level_name(level));
    printk("KeyGen:    %llu cycles\n", keygen_time);
    printk("           %llu us\n", keygen_us);
    printk("Encaps:    %llu cycles\n", encaps_time);
    printk("           %llu us\n", encaps_us);
    printk("Decaps:    %llu cycles\n", decaps_time);
    printk("           %llu us\n", decaps_us);
    printk("Total:     %llu cycles\n", keygen_time + encaps_time + decaps_time);
    printk("           %llu us\n", keygen_us + encaps_us + decaps_us);

    /* Stack usage */
    uint32_t stack = pqcp_bench_get_stack_usage();
    if (stack > 0) {
        printk("Stack:     %u bytes\n", stack);
    }

    /* Emit structured metrics for parsing */
    printk("\n--- Structured Metrics ---\n");
    PQCP_LOG_CYCLES("primitive", "keygen", "MLKEM", level, keygen_time);
    PQCP_LOG_TIME_US("primitive", "keygen", "MLKEM", level, keygen_us);
    PQCP_LOG_CYCLES("primitive", "encaps", "MLKEM", level, encaps_time);
    PQCP_LOG_TIME_US("primitive", "encaps", "MLKEM", level, encaps_us);
    PQCP_LOG_CYCLES("primitive", "decaps", "MLKEM", level, decaps_time);
    PQCP_LOG_TIME_US("primitive", "decaps", "MLKEM", level, decaps_us);

    if (stack > 0) {
        PQCP_LOG_STACK("primitive", "total", "MLKEM", level, stack);
    }

    PQCP_LOG_SIZE("primitive", "keygen", "MLKEM", level, "pk_size", pqcp_mlkem_pk_size(level));
    PQCP_LOG_SIZE("primitive", "keygen", "MLKEM", level, "sk_size", pqcp_mlkem_sk_size(level));
    PQCP_LOG_SIZE("primitive", "encaps", "MLKEM", level, "ct_size", pqcp_mlkem_ct_size(level));
    PQCP_LOG_SIZE("primitive", "encaps", "MLKEM", level, "ss_size", PQCP_MLKEM_SS_SIZE);

    PQCP_LOG_STATUS("primitive", "complete", "MLKEM", level, 1);

    printk("\n========================================\n");
    printk("  Sample completed successfully!\n");
    printk("========================================\n");

    return 0;
}
