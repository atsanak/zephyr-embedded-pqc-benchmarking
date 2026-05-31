/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP TLS mbedTLS PSA Sample
 *
 * Demonstrates TLS with post-quantum cryptography using mbedTLS and PSA.
 * Note: Full PQC TLS requires mbedTLS PQC support which is still evolving.
 * This sample demonstrates the PSA driver integration and basic TLS.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/tls_selftest.h>

/* Placeholder for actual TLS handshake */
static void demo_tls_usage(void)
{
    printk("\n--- TLS Integration Notes ---\n");
    printk("\n");
    printk("To use PQC in TLS with mbedTLS:\n");
    printk("\n");
    printk("1. mbedTLS ML-KEM support is in development (see issue #9803)\n");
    printk("2. Hybrid key exchange (X25519 + ML-KEM) expected in future\n");
    printk("3. ML-DSA certificates need X.509 PQC OID support\n");
    printk("\n");
    printk("Current integration path:\n");
    printk("  - Use PQCP PSA drivers for ML-DSA signing\n");
    printk("  - Use PQCP for out-of-band key encapsulation\n");
    printk("  - Wait for mbedTLS TLS 1.3 PQC groups\n");
    printk("\n");
    printk("Key sizes for TLS planning:\n");
    printk("  ML-KEM-768:  pk=%zu ct=%zu ss=%d\n",
           pqcp_mlkem_pk_size(PQCP_MLKEM_768),
           pqcp_mlkem_ct_size(PQCP_MLKEM_768),
           PQCP_MLKEM_SS_SIZE);
    printk("  ML-DSA-65:   pk=%zu sig=%zu\n",
           pqcp_mldsa_pk_size(PQCP_MLDSA_65),
           pqcp_mldsa_sig_size(PQCP_MLDSA_65));
    printk("\n");
    printk("Estimated TLS 1.3 handshake overhead:\n");
    printk("  Hybrid (X25519+ML-KEM-768):  +1184 pk +1088 ct = ~2.3KB extra\n");
    printk("  ML-DSA-65 cert:              +1952 pk +3293 sig = ~5.2KB extra\n");
    printk("  Total extra for PQC:         ~7-10KB per handshake\n");
}

int main(void)
{
    pqcp_tls_selftest_config_t cfg = {
        .kem_level = 768,
        .sig_level = 65,
        .initialize_rng = true,
        .initialize_psa = true,
        .emit_metrics = true,
    };
    pqcp_tls_selftest_report_t report;
    bool psa_ready = false;
    int ret;

    printk("\n");
    printk("========================================\n");
    printk("  PQCP TLS mbedTLS PSA Sample\n");
    printk("========================================\n\n");

    printk("Initializing shared TLS self-test path...\n");

    ret = pqcp_tls_selftest_init_psa(&psa_ready);
    if (ret == 0) {
        printk("PSA Crypto initialized successfully\n");
        cfg.initialize_psa = false;
    } else {
        printk("WARNING: PSA init failed, continuing with PQCP-only flow\n");
        cfg.initialize_psa = false;
    }

    ret = pqcp_tls_selftest_run(&cfg, &report);
    if (ret != 0) {
        printk("\nERROR: PQCP TLS self-test failed: %d\n", ret);
        return -1;
    }
    report.psa_ready = psa_ready;

    printk("\n--- Shared TLS Self-Test Report ---\n");
    printk("ML-KEM-%u keygen:   %llu us\n",
           report.kem_level, report.kem_keygen_us);
    printk("ML-KEM-%u encaps:   %llu us\n",
           report.kem_level, report.kem_encaps_us);
    printk("ML-KEM-%u decaps:   %llu us\n",
           report.kem_level, report.kem_decaps_us);
    printk("ML-DSA-%u keygen:   %llu us\n",
           report.sig_level, report.sig_keygen_us);
    printk("ML-DSA-%u sign:     %llu us\n",
           report.sig_level, report.sig_sign_us);
    printk("ML-DSA-%u verify:   %llu us\n",
           report.sig_level, report.sig_verify_us);
    printk("Auth stage:         %llu us\n", report.auth_us);
    printk("Key exchange stage: %llu us\n", report.key_exchange_us);
    printk("Handshake total:    %llu us\n", report.handshake_us);
    printk("Client payload:     %u bytes\n", report.client_bytes);
    printk("Server payload:     %u bytes\n", report.server_bytes);
    printk("Transcript total:   %u bytes\n", report.transcript_bytes);
    printk("Packets (approx):   %u\n", report.packets);
    if (report.stack_bytes > 0U) {
        printk("Stack usage:        %u bytes\n", report.stack_bytes);
    }
    printk("Working set:        %u bytes\n", report.working_set_bytes);
    printk("PSA active:         %s\n", psa_ready ? "yes" : "no");

    /* Show TLS integration notes */
    demo_tls_usage();

    printk("========================================\n");
    printk("  Sample completed successfully!\n");
    printk("========================================\n");

    return 0;
}
