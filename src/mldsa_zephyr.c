/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - ML-DSA Zephyr Wrapper
 *
 * Wraps mldsa-native for Zephyr RTOS integration.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/* Check if we have the real mldsa-native */
#if defined(PQCP_MLDSA_MULTILEVEL_BUILD)
#define HAVE_MLDSA_NATIVE 1
#include "mldsa_native_all.h"
#elif __has_include("mldsa_native.h")
#define HAVE_MLDSA_NATIVE 1
#include "mldsa_native.h"
#elif __has_include("mldsa/mldsa_native.h")
#define HAVE_MLDSA_NATIVE 1
#include "mldsa/mldsa_native.h"
#else
#error "mldsa-native headers not found. Run ext/setup_libs.py first."
#endif

/* Validate the requested level matches the compiled level */
static inline int validate_level(pqcp_mldsa_level_t level)
{
#if defined(PQCP_MLDSA_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLDSA_44:
        return IS_ENABLED(CONFIG_PQCP_MLDSA_LEVEL_44) ? 0 : -1;
    case PQCP_MLDSA_65:
        return IS_ENABLED(CONFIG_PQCP_MLDSA_LEVEL_65) ? 0 : -1;
    case PQCP_MLDSA_87:
        return IS_ENABLED(CONFIG_PQCP_MLDSA_LEVEL_87) ? 0 : -1;
    default:
        return -1;
    }
#else
/*
 * Determine the compile-time configured level from MLD_CONFIG_PARAMETER_SET
 * or fall back to the legacy MLDSA_MODE definition.
 */
#if defined(MLD_CONFIG_PARAMETER_SET)
#define PQCP_MLDSA_COMPILED_LEVEL MLD_CONFIG_PARAMETER_SET
#elif defined(MLDSA_MODE)
/* Map MLDSA_MODE (2,3,5) to parameter set (44,65,87) */
#if MLDSA_MODE == 2
#define PQCP_MLDSA_COMPILED_LEVEL 44
#elif MLDSA_MODE == 3
#define PQCP_MLDSA_COMPILED_LEVEL 65
#elif MLDSA_MODE == 5
#define PQCP_MLDSA_COMPILED_LEVEL 87
#else
#error "Invalid MLDSA_MODE value"
#endif
#else
/* Default to ML-DSA-65 */
#define PQCP_MLDSA_COMPILED_LEVEL 65
#endif
    switch (level) {
    case PQCP_MLDSA_44:
        return (PQCP_MLDSA_COMPILED_LEVEL == 44) ? 0 : -1;
    case PQCP_MLDSA_65:
        return (PQCP_MLDSA_COMPILED_LEVEL == 65) ? 0 : -1;
    case PQCP_MLDSA_87:
        return (PQCP_MLDSA_COMPILED_LEVEL == 87) ? 0 : -1;
    default:
        return -1;
    }
#endif
}

size_t pqcp_mldsa_pk_size(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44: return MLDSA44_PUBLICKEYBYTES;
    case PQCP_MLDSA_65: return MLDSA65_PUBLICKEYBYTES;
    case PQCP_MLDSA_87: return MLDSA87_PUBLICKEYBYTES;
    default: return 0;
    }
}

size_t pqcp_mldsa_sk_size(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44: return MLDSA44_SECRETKEYBYTES;
    case PQCP_MLDSA_65: return MLDSA65_SECRETKEYBYTES;
    case PQCP_MLDSA_87: return MLDSA87_SECRETKEYBYTES;
    default: return 0;
    }
}

size_t pqcp_mldsa_sig_size(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44: return MLDSA44_BYTES;
    case PQCP_MLDSA_65: return MLDSA65_BYTES;
    case PQCP_MLDSA_87: return MLDSA87_BYTES;
    default: return 0;
    }
}

const char *pqcp_mldsa_level_name(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44: return "ML-DSA-44";
    case PQCP_MLDSA_65: return "ML-DSA-65";
    case PQCP_MLDSA_87: return "ML-DSA-87";
    default: return "Unknown";
    }
}

#if HAVE_MLDSA_NATIVE

/* Real implementation using mldsa-native */

int pqcp_mldsa_keypair(pqcp_mldsa_level_t level, uint8_t *pk, uint8_t *sk)
{
    if (pk == NULL || sk == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (validate_level(level) != 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (!pqcp_rng_is_ready()) {
        return PQCP_MLDSA_ERR_RNG;
    }

    int ret;

#if defined(PQCP_MLDSA_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLDSA_44:
        ret = mldsa44_keypair(pk, sk);
        break;
    case PQCP_MLDSA_65:
        ret = mldsa65_keypair(pk, sk);
        break;
    case PQCP_MLDSA_87:
        ret = mldsa87_keypair(pk, sk);
        break;
    default:
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
#else
    /* mldsa-native uses namespaced API: crypto_sign_keypair is a macro
     * that expands to the correct function name based on config */
    ret = crypto_sign_keypair(pk, sk);
#endif

    return (ret == 0) ? PQCP_MLDSA_SUCCESS : PQCP_MLDSA_ERR_INTERNAL;
}

int pqcp_mldsa_sign(pqcp_mldsa_level_t level, const uint8_t *sk,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *ctx, size_t ctx_len,
                    uint8_t *sig)
{
    if (sk == NULL || sig == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (msg == NULL && msg_len > 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (ctx_len > PQCP_MLDSA_CONTEXT_MAX) {
        return PQCP_MLDSA_ERR_CONTEXT_LEN;
    }

    if (validate_level(level) != 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    size_t sig_len = 0;

    int ret;

#if defined(PQCP_MLDSA_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLDSA_44:
        ret = mldsa44_signature(sig, &sig_len, msg, msg_len, ctx, ctx_len, sk);
        break;
    case PQCP_MLDSA_65:
        ret = mldsa65_signature(sig, &sig_len, msg, msg_len, ctx, ctx_len, sk);
        break;
    case PQCP_MLDSA_87:
        ret = mldsa87_signature(sig, &sig_len, msg, msg_len, ctx, ctx_len, sk);
        break;
    default:
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
#else
    /* mldsa-native signing function: crypto_sign_signature */
    ret = crypto_sign_signature(sig, &sig_len, msg, msg_len, ctx, ctx_len, sk);
#endif

    return (ret == 0) ? PQCP_MLDSA_SUCCESS : PQCP_MLDSA_ERR_INTERNAL;
}

int pqcp_mldsa_verify(pqcp_mldsa_level_t level, const uint8_t *pk,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *ctx, size_t ctx_len,
                      const uint8_t *sig)
{
    if (pk == NULL || sig == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (msg == NULL && msg_len > 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (ctx_len > PQCP_MLDSA_CONTEXT_MAX) {
        return PQCP_MLDSA_ERR_CONTEXT_LEN;
    }

    if (validate_level(level) != 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    size_t sig_len = pqcp_mldsa_sig_size(level);
    if (sig_len == 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    int ret;

#if defined(PQCP_MLDSA_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLDSA_44:
        ret = mldsa44_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk);
        break;
    case PQCP_MLDSA_65:
        ret = mldsa65_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk);
        break;
    case PQCP_MLDSA_87:
        ret = mldsa87_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk);
        break;
    default:
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
#else
    ret = crypto_sign_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk);
#endif

    if (ret == 0) {
        return PQCP_MLDSA_SUCCESS;
    } else {
        return PQCP_MLDSA_ERR_VERIFY;
    }
}

#endif /* HAVE_MLDSA_NATIVE */

/* Hash-based signing (placeholder) */
int pqcp_mldsa_sign_hash(pqcp_mldsa_level_t level, const uint8_t *sk,
                         const uint8_t *hash, size_t hash_len,
                         const uint8_t *hash_oid, size_t oid_len,
                         const uint8_t *ctx, size_t ctx_len,
                         uint8_t *sig)
{
    /* For now, treat hash as a message */
    (void)hash_oid;
    (void)oid_len;

    return pqcp_mldsa_sign(level, sk, hash, hash_len, ctx, ctx_len, sig);
}

int pqcp_mldsa_verify_hash(pqcp_mldsa_level_t level, const uint8_t *pk,
                           const uint8_t *hash, size_t hash_len,
                           const uint8_t *hash_oid, size_t oid_len,
                           const uint8_t *ctx, size_t ctx_len,
                           const uint8_t *sig)
{
    (void)hash_oid;
    (void)oid_len;

    return pqcp_mldsa_verify(level, pk, hash, hash_len, ctx, ctx_len, sig);
}

/* Deterministic functions */
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST

int pqcp_mldsa_keypair_deterministic(pqcp_mldsa_level_t level,
                                     const uint8_t seed[32],
                                     uint8_t *pk, uint8_t *sk)
{
    if (seed == NULL || pk == NULL || sk == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    /* Expand seed to 64 bytes for DRBG */
    uint8_t expanded_seed[64];
    memcpy(expanded_seed, seed, 32);
    memset(expanded_seed + 32, 0, 32);

    int ret = pqcp_rng_deterministic_seed(expanded_seed, 64);
    if (ret != 0) {
        return PQCP_MLDSA_ERR_RNG;
    }

    ret = pqcp_mldsa_keypair(level, pk, sk);

    pqcp_rng_deterministic_reset();

    return ret;
}

#else

int pqcp_mldsa_keypair_deterministic(pqcp_mldsa_level_t level,
                                     const uint8_t seed[32],
                                     uint8_t *pk, uint8_t *sk)
{
    (void)level;
    (void)seed;
    (void)pk;
    (void)sk;
    return PQCP_MLDSA_ERR_UNSUPPORTED;
}

#endif /* CONFIG_PQCP_RNG_DETERMINISTIC_TEST */
