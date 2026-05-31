/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP KAT Deterministic Sample
 *
 * Demonstrates Known Answer Test (KAT) mode using deterministic RNG.
 * This is for testing and ACVP validation only - NOT for production!
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>
#include <pqcp_zephyr/bench.h>

#include <string.h>

/*
 * Known test vectors
 * In a real implementation, these would come from NIST ACVP vectors
 */

/* Test seed for ML-KEM (d || z, 64 bytes) */
static const uint8_t mlkem_seed[64] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
};

/* Test seed for ML-DSA (xi, 32 bytes) */
static const uint8_t mldsa_seed[32] = {
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
    0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
    0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0
};

/* Encapsulation randomness */
static const uint8_t mlkem_coins[32] = {
    0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
    0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0
};

/* Test message for signing */
static const uint8_t test_message[] = "KAT test message for ML-DSA";

/* Counters */
static int tests_passed = 0;
static int tests_failed = 0;

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printk("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printk("%02x", data[i]);
    }
    if (len > 32) {
        printk("...");
    }
    printk("\n");
}

static void test_mlkem_kat(void)
{
    printk("\n--- ML-KEM KAT Test ---\n");

    pqcp_mlkem_level_t level = PQCP_MLKEM_768;

    static uint8_t pk1[PQCP_MLKEM_PK_SIZE_MAX];
    static uint8_t sk1[PQCP_MLKEM_SK_SIZE_MAX];
    static uint8_t pk2[PQCP_MLKEM_PK_SIZE_MAX];
    static uint8_t sk2[PQCP_MLKEM_SK_SIZE_MAX];
    static uint8_t ct1[PQCP_MLKEM_CT_SIZE_MAX];
    static uint8_t ct2[PQCP_MLKEM_CT_SIZE_MAX];
    static uint8_t ss1[PQCP_MLKEM_SS_SIZE];
    static uint8_t ss2[PQCP_MLKEM_SS_SIZE];
    static uint8_t ss3[PQCP_MLKEM_SS_SIZE];

    /* Generate keypair twice with same seed - should be identical */
    int ret1 = pqcp_mlkem_keypair_deterministic(level, mlkem_seed, pk1, sk1);
    int ret2 = pqcp_mlkem_keypair_deterministic(level, mlkem_seed, pk2, sk2);

    if (ret1 != PQCP_MLKEM_SUCCESS || ret2 != PQCP_MLKEM_SUCCESS) {
        printk("FAIL: Deterministic keygen failed (ret1=%d, ret2=%d)\n", ret1, ret2);
        tests_failed++;
        return;
    }

    /* Compare keys */
    if (memcmp(pk1, pk2, pqcp_mlkem_pk_size(level)) == 0 &&
        memcmp(sk1, sk2, pqcp_mlkem_sk_size(level)) == 0) {
        printk("PASS: Deterministic keygen produces identical keys\n");
        tests_passed++;
    } else {
        printk("FAIL: Deterministic keygen produced different keys\n");
        tests_failed++;
    }

    print_hex("Public key (first 32 bytes)", pk1, 32);

    /* Encapsulate twice with same coins */
    ret1 = pqcp_mlkem_encapsulate_deterministic(level, pk1, mlkem_coins, ct1, ss1);
    ret2 = pqcp_mlkem_encapsulate_deterministic(level, pk1, mlkem_coins, ct2, ss2);

    if (ret1 != PQCP_MLKEM_SUCCESS || ret2 != PQCP_MLKEM_SUCCESS) {
        printk("FAIL: Deterministic encaps failed\n");
        tests_failed++;
        return;
    }

    if (memcmp(ct1, ct2, pqcp_mlkem_ct_size(level)) == 0 &&
        memcmp(ss1, ss2, PQCP_MLKEM_SS_SIZE) == 0) {
        printk("PASS: Deterministic encaps produces identical outputs\n");
        tests_passed++;
    } else {
        printk("FAIL: Deterministic encaps produced different outputs\n");
        tests_failed++;
    }

    print_hex("Ciphertext (first 32 bytes)", ct1, 32);
    print_hex("Shared secret", ss1, PQCP_MLKEM_SS_SIZE);

    /* Decapsulate and verify shared secret matches */
    int ret3 = pqcp_mlkem_decapsulate(level, ct1, sk1, ss3);

    if (ret3 != PQCP_MLKEM_SUCCESS) {
        printk("FAIL: Decapsulation failed\n");
        tests_failed++;
        return;
    }

    if (memcmp(ss1, ss3, PQCP_MLKEM_SS_SIZE) == 0) {
        printk("PASS: Decapsulated shared secret matches encapsulated\n");
        tests_passed++;
    } else {
        printk("FAIL: Shared secrets don't match\n");
        tests_failed++;
    }
}

static void test_mldsa_kat(void)
{
    printk("\n--- ML-DSA KAT Test ---\n");

    pqcp_mldsa_level_t level = PQCP_MLDSA_65;

    static uint8_t pk1[PQCP_MLDSA_PK_SIZE_MAX];
    static uint8_t sk1[PQCP_MLDSA_SK_SIZE_MAX];
    static uint8_t pk2[PQCP_MLDSA_PK_SIZE_MAX];
    static uint8_t sk2[PQCP_MLDSA_SK_SIZE_MAX];
    static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];

    /* Generate keypair twice with same seed */
    int ret1 = pqcp_mldsa_keypair_deterministic(level, mldsa_seed, pk1, sk1);
    int ret2 = pqcp_mldsa_keypair_deterministic(level, mldsa_seed, pk2, sk2);

    if (ret1 != PQCP_MLDSA_SUCCESS || ret2 != PQCP_MLDSA_SUCCESS) {
        printk("FAIL: Deterministic keygen failed (ret1=%d, ret2=%d)\n", ret1, ret2);
        tests_failed++;
        return;
    }

    if (memcmp(pk1, pk2, pqcp_mldsa_pk_size(level)) == 0 &&
        memcmp(sk1, sk2, pqcp_mldsa_sk_size(level)) == 0) {
        printk("PASS: Deterministic keygen produces identical keys\n");
        tests_passed++;
    } else {
        printk("FAIL: Deterministic keygen produced different keys\n");
        tests_failed++;
    }

    print_hex("Public key (first 32 bytes)", pk1, 32);

    /* Re-seed RNG for signing (ML-DSA sign needs randomness) */
    uint8_t sign_seed[64];
    memcpy(sign_seed, mldsa_seed, 32);
    memset(sign_seed + 32, 0x55, 32);  /* Different padding for sign */
    pqcp_rng_deterministic_seed(sign_seed, 64);

    /* Sign message */
    int ret = pqcp_mldsa_sign(level, sk1,
                              test_message, sizeof(test_message) - 1,
                              NULL, 0, sig);

    /* Reset RNG after signing */
    pqcp_rng_deterministic_reset();

    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("FAIL: Signing failed (ret=%d)\n", ret);
        tests_failed++;
        return;
    }

    print_hex("Signature (first 32 bytes)", sig, 32);

    /* Verify signature */
    ret = pqcp_mldsa_verify(level, pk1,
                            test_message, sizeof(test_message) - 1,
                            NULL, 0, sig);

    if (ret == PQCP_MLDSA_SUCCESS) {
        printk("PASS: Signature verified successfully\n");
        tests_passed++;
    } else {
        printk("FAIL: Signature verification failed\n");
        tests_failed++;
    }

    /* Verify with wrong key fails */
    pk1[0] ^= 0x01;  /* Corrupt public key */
    ret = pqcp_mldsa_verify(level, pk1,
                            test_message, sizeof(test_message) - 1,
                            NULL, 0, sig);

    if (ret == PQCP_MLDSA_ERR_VERIFY) {
        printk("PASS: Corrupted key correctly rejected\n");
        tests_passed++;
    } else {
        printk("FAIL: Corrupted key not rejected (ret=%d)\n", ret);
        tests_failed++;
    }
}

int main(void)
{
    printk("\n");
    printk("========================================\n");
    printk("  PQCP KAT Deterministic Test\n");
    printk("========================================\n");
    printk("\nWARNING: This uses deterministic RNG!\n");
    printk("         NOT FOR PRODUCTION USE!\n");

    /* Initialize deterministic RNG */
    int ret = pqcp_rng_init();
    if (ret != 0) {
        printk("ERROR: Failed to initialize RNG: %d\n", ret);
        return -1;
    }

    /* Run tests */
    test_mlkem_kat();
    test_mldsa_kat();

    /* Summary */
    printk("\n========================================\n");
    printk("  Test Results\n");
    printk("========================================\n");
    printk("Passed: %d\n", tests_passed);
    printk("Failed: %d\n", tests_failed);
    printk("Total:  %d\n", tests_passed + tests_failed);

    if (tests_failed == 0) {
        printk("\nAll KAT tests PASSED!\n");
    } else {
        printk("\nSome tests FAILED!\n");
    }

    /* Emit structured metrics for parsing */
    printk("\n--- Structured Metrics ---\n");
    PQCP_LOG_STATUS("kat", "mlkem_det_keygen", "MLKEM", 768, tests_failed == 0);
    PQCP_LOG_STATUS("kat", "mlkem_det_encaps", "MLKEM", 768, tests_failed == 0);
    PQCP_LOG_STATUS("kat", "mldsa_det_keygen", "MLDSA", 65, tests_failed == 0);
    PQCP_LOG_STATUS("kat", "mldsa_sign_verify", "MLDSA", 65, tests_failed == 0);
    PQCP_LOG_METRIC("kat", "summary", "ALL", 0, "passed", tests_passed, "");
    PQCP_LOG_METRIC("kat", "summary", "ALL", 0, "failed", tests_failed, "");

    printk("========================================\n");

    return tests_failed > 0 ? -1 : 0;
}
