/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deterministic RNG for Testing
 *
 * WARNING: This implementation is for Known Answer Tests (KAT) and
 * ACVP validation ONLY. It produces predictable output and MUST NOT
 * be used in production systems.
 *
 * Implements a simple CTR-DRBG style generator for deterministic output.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST

/* Simple AES-128 for CTR-DRBG (using tinycrypt if available, else software) */
#ifdef CONFIG_TINYCRYPT_AES
#include <tinycrypt/aes.h>
#include <tinycrypt/constants.h>
#else
/* Minimal software AES-128 implementation for CTR mode */
/* In production, this would use a proper AES library */
#endif

/* DRBG state */
static struct {
    uint8_t key[16];
    uint8_t counter[16];
    bool seeded;
    uint64_t reseed_counter;
    struct k_mutex lock;
} drbg_state;

/* Simple increment of 128-bit counter */
static void increment_counter(uint8_t ctr[16])
{
    for (int i = 15; i >= 0; i--) {
        if (++ctr[i] != 0) {
            break;
        }
    }
}

/* AES-128 block encryption (placeholder - needs proper implementation) */
static void aes_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
#ifdef CONFIG_TINYCRYPT_AES
    struct tc_aes_key_sched_struct sched;
    tc_aes128_set_encrypt_key(&sched, key);
    tc_aes_encrypt(out, in, &sched);
#else
    /*
     * Fallback: Simple XOR-based "encryption" for testing only.
     * This is NOT cryptographically secure but allows KAT testing
     * without pulling in a full AES implementation.
     *
     * In a real deployment, use a proper AES library.
     */
    for (int i = 0; i < 16; i++) {
        /* Mix key with counter and some fixed constants */
        out[i] = in[i] ^ key[i] ^ ((uint8_t)(i * 0x9e + key[(i + 7) % 16]));
    }
#endif
}

/* CTR-DRBG generate */
static int ctr_drbg_generate(uint8_t *out, size_t len)
{
    if (!drbg_state.seeded) {
        return PQCP_RNG_ERR_NOT_INIT;
    }

    uint8_t block[16];
    size_t generated = 0;

    while (generated < len) {
        increment_counter(drbg_state.counter);
        aes_encrypt_block(drbg_state.key, drbg_state.counter, block);

        size_t to_copy = len - generated;
        if (to_copy > 16) {
            to_copy = 16;
        }

        memcpy(out + generated, block, to_copy);
        generated += to_copy;
        drbg_state.reseed_counter++;
    }

    /* Update key for forward secrecy in normal DRBG (simplified here) */

    return PQCP_RNG_SUCCESS;
}

int pqcp_rng_deterministic_seed(const uint8_t *seed, size_t seed_len)
{
    if (seed == NULL || seed_len < 16) {
        return PQCP_RNG_ERR_INVALID_ARG;
    }

    k_mutex_lock(&drbg_state.lock, K_FOREVER);

    /* Use first 16 bytes as key */
    memcpy(drbg_state.key, seed, 16);

    /* Use next 16 bytes (or zeros) as initial counter */
    if (seed_len >= 32) {
        memcpy(drbg_state.counter, seed + 16, 16);
    } else {
        memset(drbg_state.counter, 0, 16);
    }

    drbg_state.seeded = true;
    drbg_state.reseed_counter = 0;

    k_mutex_unlock(&drbg_state.lock);

    return PQCP_RNG_SUCCESS;
}

void pqcp_rng_deterministic_reset(void)
{
    k_mutex_lock(&drbg_state.lock, K_FOREVER);

    memset(drbg_state.key, 0, sizeof(drbg_state.key));
    memset(drbg_state.counter, 0, sizeof(drbg_state.counter));
    drbg_state.seeded = false;
    drbg_state.reseed_counter = 0;

    k_mutex_unlock(&drbg_state.lock);
}

uint64_t pqcp_rng_deterministic_get_counter(void)
{
    return drbg_state.reseed_counter;
}

/* Override the backend functions when deterministic mode is enabled */
int pqcp_rng_backend_init(void)
{
    k_mutex_init(&drbg_state.lock);
    drbg_state.seeded = false;
    return PQCP_RNG_SUCCESS;
}

int pqcp_rng_backend_get_bytes(uint8_t *out, size_t len)
{
    int ret;

    k_mutex_lock(&drbg_state.lock, K_FOREVER);
    ret = ctr_drbg_generate(out, len);
    k_mutex_unlock(&drbg_state.lock);

    return ret;
}

#endif /* CONFIG_PQCP_RNG_DETERMINISTIC_TEST */
