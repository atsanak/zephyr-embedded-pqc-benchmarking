/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - RNG Abstraction
 *
 * This header provides the random number generator abstraction for PQCP.
 * It supports multiple RNG backends configurable via Kconfig.
 *
 * Stability: stable production API for the 1.0.x line.
 */

#ifndef PQCP_ZEPHYR_RNG_H
#define PQCP_ZEPHYR_RNG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RNG error codes */
#define PQCP_RNG_SUCCESS            0
#define PQCP_RNG_ERR_NOT_INIT       -1
#define PQCP_RNG_ERR_ENTROPY        -2
#define PQCP_RNG_ERR_INVALID_ARG    -3
#define PQCP_RNG_ERR_UNSUPPORTED    -4

/**
 * @brief RNG interface structure for custom implementations.
 *
 * Applications using CONFIG_PQCP_RNG_CUSTOM must implement this interface
 * and register it before using any PQCP cryptographic operations.
 */
typedef struct pqcp_rng_iface {
    /**
     * @brief Generate random bytes.
     *
     * @param ctx      User context pointer (passed during registration).
     * @param out      Output buffer for random bytes.
     * @param len      Number of bytes to generate.
     *
     * @return 0 on success, negative error code on failure.
     */
    int (*get_bytes)(void *ctx, uint8_t *out, size_t len);

    /**
     * @brief Optional: Seed the RNG (for deterministic mode).
     *
     * @param ctx      User context pointer.
     * @param seed     Seed data.
     * @param seed_len Length of seed.
     *
     * @return 0 on success, negative error code on failure.
     */
    int (*seed)(void *ctx, const uint8_t *seed, size_t seed_len);

    /**
     * @brief Optional: Reset the RNG state.
     *
     * @param ctx User context pointer.
     */
    void (*reset)(void *ctx);

    /** User context pointer passed to callbacks */
    void *ctx;
} pqcp_rng_iface_t;

/**
 * @brief Register a custom RNG implementation.
 *
 * Must be called before any PQCP cryptographic operations when using
 * CONFIG_PQCP_RNG_CUSTOM. The interface must remain valid for the
 * lifetime of the application.
 *
 * @param iface Pointer to RNG interface (must not be NULL).
 *
 * @return PQCP_RNG_SUCCESS on success.
 */
int pqcp_rng_register(const pqcp_rng_iface_t *iface);

/**
 * @brief Get random bytes from the configured RNG.
 *
 * This is the main RNG function used internally by PQCP.
 * For CSPRNG mode, it uses sys_csrand_get() or PSA RNG.
 * For custom mode, it uses the registered interface.
 *
 * @param out Buffer to receive random bytes.
 * @param len Number of bytes to generate.
 *
 * @return PQCP_RNG_SUCCESS on success, negative error code on failure.
 */
int pqcp_rng_get_bytes(uint8_t *out, size_t len);

/**
 * @brief Initialize the RNG subsystem.
 *
 * Called automatically during module init, but can be called explicitly
 * if early initialization is needed.
 *
 * @return PQCP_RNG_SUCCESS on success.
 */
int pqcp_rng_init(void);

/**
 * @brief Check if the RNG is ready to use.
 *
 * @return true if RNG is initialized and ready, false otherwise.
 */
int pqcp_rng_is_ready(void);

/*
 * Deterministic RNG for testing (CONFIG_PQCP_RNG_DETERMINISTIC_TEST only)
 *
 * WARNING: These functions produce predictable output and MUST NOT be
 * used in production. They exist solely for Known Answer Tests (KAT)
 * and ACVP validation.
 */

#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST

/**
 * @brief Seed the deterministic RNG.
 *
 * Seeds the internal CTR-DRBG with the given seed value.
 * Subsequent calls to pqcp_rng_get_bytes() will produce
 * deterministic output based on this seed.
 *
 * @param seed     Seed value.
 * @param seed_len Length of seed (minimum 32 bytes recommended).
 *
 * @return PQCP_RNG_SUCCESS on success.
 */
int pqcp_rng_deterministic_seed(const uint8_t *seed, size_t seed_len);

/**
 * @brief Reset the deterministic RNG to unseeded state.
 *
 * After calling this, pqcp_rng_get_bytes() will fail until
 * a new seed is provided.
 */
void pqcp_rng_deterministic_reset(void);

/**
 * @brief Get the current counter value (for debugging).
 *
 * @return Current internal counter value.
 */
uint64_t pqcp_rng_deterministic_get_counter(void);

#endif /* CONFIG_PQCP_RNG_DETERMINISTIC_TEST */

/*
 * Internal callback type used by mlkem-native and mldsa-native.
 * This matches their expected randombytes() signature.
 */
typedef int (*pqcp_randombytes_fn)(uint8_t *out, size_t len);

/**
 * @brief Get the randombytes function pointer for native libraries.
 *
 * Returns a function pointer that can be passed to mlkem-native
 * and mldsa-native for their RNG needs.
 *
 * @return Function pointer to randombytes implementation.
 */
pqcp_randombytes_fn pqcp_rng_get_randombytes(void);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RNG_H */
