/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - ML-KEM Zephyr Wrapper
 *
 * Wraps mlkem-native for Zephyr RTOS integration.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/* Check if we have the real mlkem-native */
#if defined(PQCP_MLKEM_MULTILEVEL_BUILD)
#define HAVE_MLKEM_NATIVE 1
#include "mlkem_native_all.h"
#elif __has_include("mlkem_native.h")
#define HAVE_MLKEM_NATIVE 1
#include "mlkem_native.h"
#elif __has_include("mlkem/mlkem_native.h")
#define HAVE_MLKEM_NATIVE 1
#include "mlkem/mlkem_native.h"
#else
#error "mlkem-native headers not found. Run ext/setup_libs.py first."
#endif

/* Validate the requested level matches the compiled level */
static inline int validate_level(pqcp_mlkem_level_t level)
{
#if defined(PQCP_MLKEM_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLKEM_512:
        return IS_ENABLED(CONFIG_PQCP_MLKEM_LEVEL_512) ? 0 : -1;
    case PQCP_MLKEM_768:
        return IS_ENABLED(CONFIG_PQCP_MLKEM_LEVEL_768) ? 0 : -1;
    case PQCP_MLKEM_1024:
        return IS_ENABLED(CONFIG_PQCP_MLKEM_LEVEL_1024) ? 0 : -1;
    default:
        return -1;
    }
#else
/*
 * Determine the compile-time configured level from MLK_CONFIG_PARAMETER_SET
 * or fall back to the legacy MLKEM_K definition.
 */
#if defined(MLK_CONFIG_PARAMETER_SET)
#define PQCP_MLKEM_COMPILED_LEVEL MLK_CONFIG_PARAMETER_SET
#elif defined(MLKEM_K)
/* Map MLKEM_K (2,3,4) to parameter set (512,768,1024) */
#if MLKEM_K == 2
#define PQCP_MLKEM_COMPILED_LEVEL 512
#elif MLKEM_K == 3
#define PQCP_MLKEM_COMPILED_LEVEL 768
#elif MLKEM_K == 4
#define PQCP_MLKEM_COMPILED_LEVEL 1024
#else
#error "Invalid MLKEM_K value"
#endif
#else
/* Default to ML-KEM-768 */
#define PQCP_MLKEM_COMPILED_LEVEL 768
#endif
    switch (level) {
    case PQCP_MLKEM_512:
        return (PQCP_MLKEM_COMPILED_LEVEL == 512) ? 0 : -1;
    case PQCP_MLKEM_768:
        return (PQCP_MLKEM_COMPILED_LEVEL == 768) ? 0 : -1;
    case PQCP_MLKEM_1024:
        return (PQCP_MLKEM_COMPILED_LEVEL == 1024) ? 0 : -1;
    default:
        return -1;
    }
#endif
}

size_t pqcp_mlkem_pk_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return MLKEM512_PUBLICKEYBYTES;
    case PQCP_MLKEM_768:  return MLKEM768_PUBLICKEYBYTES;
    case PQCP_MLKEM_1024: return MLKEM1024_PUBLICKEYBYTES;
    default: return 0;
    }
}

size_t pqcp_mlkem_sk_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return MLKEM512_SECRETKEYBYTES;
    case PQCP_MLKEM_768:  return MLKEM768_SECRETKEYBYTES;
    case PQCP_MLKEM_1024: return MLKEM1024_SECRETKEYBYTES;
    default: return 0;
    }
}

size_t pqcp_mlkem_ct_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return MLKEM512_CIPHERTEXTBYTES;
    case PQCP_MLKEM_768:  return MLKEM768_CIPHERTEXTBYTES;
    case PQCP_MLKEM_1024: return MLKEM1024_CIPHERTEXTBYTES;
    default: return 0;
    }
}

const char *pqcp_mlkem_level_name(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return "ML-KEM-512";
    case PQCP_MLKEM_768:  return "ML-KEM-768";
    case PQCP_MLKEM_1024: return "ML-KEM-1024";
    default: return "Unknown";
    }
}

#if HAVE_MLKEM_NATIVE

/* Real implementation using mlkem-native */

int pqcp_mlkem_keypair(pqcp_mlkem_level_t level, uint8_t *pk, uint8_t *sk)
{
    if (pk == NULL || sk == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    if (validate_level(level) != 0) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    if (!pqcp_rng_is_ready()) {
        return PQCP_MLKEM_ERR_RNG;
    }

    int ret;

#if defined(PQCP_MLKEM_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLKEM_512:
        ret = mlkem512_keypair(pk, sk);
        break;
    case PQCP_MLKEM_768:
        ret = mlkem768_keypair(pk, sk);
        break;
    case PQCP_MLKEM_1024:
        ret = mlkem1024_keypair(pk, sk);
        break;
    default:
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
#else
    /* mlkem-native uses namespaced API: crypto_kem_keypair is a macro
     * that expands to the correct function name based on config */
    ret = crypto_kem_keypair(pk, sk);
#endif

    return (ret == 0) ? PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}

int pqcp_mlkem_encapsulate(pqcp_mlkem_level_t level, const uint8_t *pk,
                           uint8_t *ct, uint8_t *ss)
{
    if (pk == NULL || ct == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    if (validate_level(level) != 0) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    if (!pqcp_rng_is_ready()) {
        return PQCP_MLKEM_ERR_RNG;
    }

    int ret;

#if defined(PQCP_MLKEM_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLKEM_512:
        ret = mlkem512_enc(ct, ss, pk);
        break;
    case PQCP_MLKEM_768:
        ret = mlkem768_enc(ct, ss, pk);
        break;
    case PQCP_MLKEM_1024:
        ret = mlkem1024_enc(ct, ss, pk);
        break;
    default:
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
#else
    ret = crypto_kem_enc(ct, ss, pk);
#endif

    return (ret == 0) ? PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}

int pqcp_mlkem_decapsulate(pqcp_mlkem_level_t level, const uint8_t *ct,
                           const uint8_t *sk, uint8_t *ss)
{
    if (ct == NULL || sk == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    if (validate_level(level) != 0) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    int ret;

#if defined(PQCP_MLKEM_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLKEM_512:
        ret = mlkem512_dec(ss, ct, sk);
        break;
    case PQCP_MLKEM_768:
        ret = mlkem768_dec(ss, ct, sk);
        break;
    case PQCP_MLKEM_1024:
        ret = mlkem1024_dec(ss, ct, sk);
        break;
    default:
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
#else
    ret = crypto_kem_dec(ss, ct, sk);
#endif

    /* ML-KEM uses implicit rejection - always returns success */
    return (ret == 0) ? PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}

#endif /* HAVE_MLKEM_NATIVE */

/* Deterministic functions - only when test mode enabled */
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST

int pqcp_mlkem_keypair_deterministic(pqcp_mlkem_level_t level,
                                     const uint8_t seed[64],
                                     uint8_t *pk, uint8_t *sk)
{
    if (seed == NULL || pk == NULL || sk == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    /* Seed the deterministic RNG */
    int ret = pqcp_rng_deterministic_seed(seed, 64);
    if (ret != 0) {
        return PQCP_MLKEM_ERR_RNG;
    }

    /* Generate keypair using deterministic RNG */
    ret = pqcp_mlkem_keypair(level, pk, sk);

    /* Reset RNG after use */
    pqcp_rng_deterministic_reset();

    return ret;
}

int pqcp_mlkem_encapsulate_deterministic(pqcp_mlkem_level_t level,
                                         const uint8_t *pk,
                                         const uint8_t coins[32],
                                         uint8_t *ct, uint8_t *ss)
{
    if (pk == NULL || coins == NULL || ct == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    /* Use coins as RNG seed */
    uint8_t seed[64];
    memcpy(seed, coins, 32);
    memset(seed + 32, 0, 32);

    int ret = pqcp_rng_deterministic_seed(seed, 64);
    if (ret != 0) {
        return PQCP_MLKEM_ERR_RNG;
    }

    ret = pqcp_mlkem_encapsulate(level, pk, ct, ss);

    pqcp_rng_deterministic_reset();

    return ret;
}

#else

int pqcp_mlkem_keypair_deterministic(pqcp_mlkem_level_t level,
                                     const uint8_t seed[64],
                                     uint8_t *pk, uint8_t *sk)
{
    (void)level;
    (void)seed;
    (void)pk;
    (void)sk;
    return PQCP_MLKEM_ERR_UNSUPPORTED;
}

int pqcp_mlkem_encapsulate_deterministic(pqcp_mlkem_level_t level,
                                         const uint8_t *pk,
                                         const uint8_t coins[32],
                                         uint8_t *ct, uint8_t *ss)
{
    (void)level;
    (void)pk;
    (void)coins;
    (void)ct;
    (void)ss;
    return PQCP_MLKEM_ERR_UNSUPPORTED;
}

#endif /* CONFIG_PQCP_RNG_DETERMINISTIC_TEST */
