/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Streaming Hash ML-DSA Sample
 *
 * Demonstrates streaming signing of large messages using Hash-ML-DSA style API.
 * This is useful for constrained devices that cannot fit entire messages in RAM.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>
#include <pqcp_zephyr/bench.h>

#include <string.h>

/* Streaming context - use PQCP_MLDSA_STREAM_CTX_SIZE for proper sizing */
static uint8_t stream_ctx_buffer[PQCP_MLDSA_STREAM_CTX_SIZE];

/* Simulated large message - sent in chunks */
#define TOTAL_MESSAGE_SIZE 4096
#define CHUNK_SIZE 128

/* Generate pseudo-random message chunk */
static void generate_chunk(uint8_t *buf, size_t offset, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        /* Simple deterministic pattern for verification */
        buf[i] = (uint8_t)((offset + i) * 7 + 13);
    }
}

int main(void)
{
    printk("\n");
    printk("========================================\n");
    printk("  PQCP Streaming Hash ML-DSA Sample\n");
    printk("========================================\n\n");

    /* Initialize RNG */
    int ret = pqcp_rng_init();
    if (ret != 0) {
        printk("ERROR: Failed to initialize RNG: %d\n", ret);
        return -1;
    }

    pqcp_mldsa_level_t level = PQCP_MLDSA_65;

    printk("Using %s with streaming API\n", pqcp_mldsa_level_name(level));
    printk("Message size: %d bytes\n", TOTAL_MESSAGE_SIZE);
    printk("Chunk size:   %d bytes\n", CHUNK_SIZE);
    printk("Chunks:       %d\n\n", TOTAL_MESSAGE_SIZE / CHUNK_SIZE);

    /* Allocate key buffers */
    static uint8_t pk[PQCP_MLDSA_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLDSA_SK_SIZE_MAX];
    static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    static uint8_t chunk[CHUNK_SIZE];

    /* Generate keypair */
    printk("--- Generating Keypair ---\n");
    ret = pqcp_mldsa_keypair(level, pk, sk);
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("ERROR: Key generation failed: %d\n", ret);
        return -1;
    }
    printk("Keypair generated successfully\n\n");

    /* Context string for domain separation */
    const uint8_t ctx[] = "streaming-example";

    /*
     * STREAMING SIGN
     */
    printk("--- Streaming Sign ---\n");

    pqcp_mldsa_stream_ctx_t *sign_ctx = (pqcp_mldsa_stream_ctx_t *)stream_ctx_buffer;

    /* Initialize signing context */
    uint32_t start = k_uptime_get_32();

    ret = pqcp_mldsa_sign_stream_init(sign_ctx, level, sk, ctx, sizeof(ctx) - 1);
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("ERROR: Sign stream init failed: %d\n", ret);
        return -1;
    }
    printk("Sign context initialized\n");

    /* Feed message in chunks */
    size_t offset = 0;
    int chunk_num = 0;

    while (offset < TOTAL_MESSAGE_SIZE) {
        size_t remaining = TOTAL_MESSAGE_SIZE - offset;
        size_t this_chunk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;

        /* Generate this chunk of the message */
        generate_chunk(chunk, offset, this_chunk);

        /* Update hash with chunk */
        ret = pqcp_mldsa_sign_stream_update(sign_ctx, chunk, this_chunk);
        if (ret != PQCP_MLDSA_SUCCESS) {
            printk("ERROR: Sign stream update failed at chunk %d: %d\n", chunk_num, ret);
            return -1;
        }

        offset += this_chunk;
        chunk_num++;

        /* Print progress every 8 chunks */
        if (chunk_num % 8 == 0) {
            printk("  Processed %d/%d bytes (%d chunks)\n",
                   (int)offset, TOTAL_MESSAGE_SIZE, chunk_num);
        }
    }

    printk("All %d chunks processed\n", chunk_num);

    /* Finalize and get signature */
    ret = pqcp_mldsa_sign_stream_final(sign_ctx, sig);
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("ERROR: Sign stream final failed: %d\n", ret);
        return -1;
    }

    uint32_t sign_time = k_uptime_get_32() - start;

    printk("Signature generated successfully!\n");
    printk("Time: %u ms\n\n", sign_time);

    /* Print signature snippet */
    printk("Signature (first 32 bytes): ");
    for (int i = 0; i < 32; i++) {
        printk("%02x", sig[i]);
    }
    printk("...\n\n");

    /*
     * STREAMING VERIFY
     */
    printk("--- Streaming Verify ---\n");

    pqcp_mldsa_stream_ctx_t *verify_ctx = (pqcp_mldsa_stream_ctx_t *)stream_ctx_buffer;

    /* Initialize verification context */
    start = k_uptime_get_32();

    ret = pqcp_mldsa_verify_stream_init(verify_ctx, level, pk, sig, ctx, sizeof(ctx) - 1);
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("ERROR: Verify stream init failed: %d\n", ret);
        return -1;
    }
    printk("Verify context initialized\n");

    /* Feed same message chunks */
    offset = 0;
    chunk_num = 0;

    while (offset < TOTAL_MESSAGE_SIZE) {
        size_t remaining = TOTAL_MESSAGE_SIZE - offset;
        size_t this_chunk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;

        /* Regenerate this chunk (same as during signing) */
        generate_chunk(chunk, offset, this_chunk);

        ret = pqcp_mldsa_verify_stream_update(verify_ctx, chunk, this_chunk);
        if (ret != PQCP_MLDSA_SUCCESS) {
            printk("ERROR: Verify stream update failed at chunk %d: %d\n", chunk_num, ret);
            return -1;
        }

        offset += this_chunk;
        chunk_num++;
    }

    printk("All %d chunks processed\n", chunk_num);

    /* Finalize verification */
    ret = pqcp_mldsa_verify_stream_final(verify_ctx);

    uint32_t verify_time = k_uptime_get_32() - start;

    if (ret == PQCP_MLDSA_SUCCESS) {
        printk("Signature verification: VALID\n");
    } else if (ret == PQCP_MLDSA_ERR_VERIFY) {
        printk("Signature verification: INVALID\n");
        return -1;
    } else {
        printk("ERROR: Verification failed: %d\n", ret);
        return -1;
    }

    printk("Time: %u ms\n\n", verify_time);

    /*
     * TEST: Verify with corrupted message should fail
     */
    printk("--- Negative Test (corrupted message) ---\n");

    ret = pqcp_mldsa_verify_stream_init(verify_ctx, level, pk, sig, ctx, sizeof(ctx) - 1);
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("ERROR: Verify stream init failed\n");
        return -1;
    }

    offset = 0;
    while (offset < TOTAL_MESSAGE_SIZE) {
        size_t remaining = TOTAL_MESSAGE_SIZE - offset;
        size_t this_chunk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;

        generate_chunk(chunk, offset, this_chunk);

        /* Corrupt one byte in the middle of the message */
        if (offset == TOTAL_MESSAGE_SIZE / 2) {
            chunk[0] ^= 0x01;
        }

        pqcp_mldsa_verify_stream_update(verify_ctx, chunk, this_chunk);
        offset += this_chunk;
    }

    ret = pqcp_mldsa_verify_stream_final(verify_ctx);

    if (ret == PQCP_MLDSA_ERR_VERIFY) {
        printk("PASS: Corrupted message correctly rejected!\n");
    } else {
        printk("FAIL: Corrupted message not rejected (ret=%d)\n", ret);
        return -1;
    }

    /* Summary */
    printk("\n========================================\n");
    printk("  Summary\n");
    printk("========================================\n");
    printk("Algorithm:    %s\n", pqcp_mldsa_level_name(level));
    printk("Message size: %d bytes\n", TOTAL_MESSAGE_SIZE);
    printk("Chunk size:   %d bytes\n", CHUNK_SIZE);
    printk("Sign time:    %u ms\n", sign_time);
    printk("Verify time:  %u ms\n", verify_time);
    printk("\nStreaming API allows signing messages larger than RAM!\n");

    /* Emit structured metrics for parsing */
    printk("\n--- Structured Metrics ---\n");
    PQCP_LOG_TIME_MS("primitive", "sign_stream", "MLDSA", level, sign_time);
    PQCP_LOG_TIME_MS("primitive", "verify_stream", "MLDSA", level, verify_time);
    PQCP_LOG_SIZE("primitive", "sign_stream", "MLDSA", level, "msg_size", TOTAL_MESSAGE_SIZE);
    PQCP_LOG_SIZE("primitive", "sign_stream", "MLDSA", level, "chunk_size", CHUNK_SIZE);
    PQCP_LOG_SIZE("primitive", "sign_stream", "MLDSA", level, "sig_size", pqcp_mldsa_sig_size(level));
    PQCP_LOG_STATUS("primitive", "stream_complete", "MLDSA", level, 1);

    printk("========================================\n");

    return 0;
}
