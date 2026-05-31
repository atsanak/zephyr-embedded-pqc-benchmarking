/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - ML-DSA API
 *
 * This header provides the Zephyr-facing API for ML-DSA (FIPS-204)
 * operations using mldsa-native as the underlying implementation.
 *
 * Stability: stable production API for the 1.0.x line.
 */

#ifndef PQCP_ZEPHYR_MLDSA_H
#define PQCP_ZEPHYR_MLDSA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ML-DSA Security Levels (FIPS-204)
 *
 * ML-DSA-44: NIST Level 2 (equivalent to SHA-256/AES-128)
 * ML-DSA-65: NIST Level 3 (equivalent to AES-192) - Recommended default
 * ML-DSA-87: NIST Level 5 (equivalent to AES-256)
 */

/**
 * @brief ML-DSA security parameter set selector.
 *
 * Values match the FIPS 204 parameter-set suffixes. Pass one of these values
 * to the ML-DSA size helpers and key generation, signing, or verification
 * entry points.
 */
typedef enum {
    PQCP_MLDSA_44 = 44,   /**< ML-DSA-44, NIST security level 2. */
    PQCP_MLDSA_65 = 65,   /**< ML-DSA-65, NIST security level 3. */
    PQCP_MLDSA_87 = 87    /**< ML-DSA-87, NIST security level 5. */
} pqcp_mldsa_level_t;

/* Key and signature sizes per security level */
#define PQCP_MLDSA_44_PK_SIZE       1312
#define PQCP_MLDSA_44_SK_SIZE       2560
#define PQCP_MLDSA_44_SIG_SIZE      2420

#define PQCP_MLDSA_65_PK_SIZE       1952
#define PQCP_MLDSA_65_SK_SIZE       4032
#define PQCP_MLDSA_65_SIG_SIZE      3309

#define PQCP_MLDSA_87_PK_SIZE       2592
#define PQCP_MLDSA_87_SK_SIZE       4896
#define PQCP_MLDSA_87_SIG_SIZE      4627

/* Maximum sizes (for static allocation) */
#define PQCP_MLDSA_PK_SIZE_MAX      PQCP_MLDSA_87_PK_SIZE
#define PQCP_MLDSA_SK_SIZE_MAX      PQCP_MLDSA_87_SK_SIZE
#define PQCP_MLDSA_SIG_SIZE_MAX     PQCP_MLDSA_87_SIG_SIZE

/* Context string maximum length */
#define PQCP_MLDSA_CONTEXT_MAX      255

/* Error codes */
#define PQCP_MLDSA_SUCCESS          0
#define PQCP_MLDSA_ERR_INVALID_ARG  -1
#define PQCP_MLDSA_ERR_RNG          -2
#define PQCP_MLDSA_ERR_VERIFY       -3
#define PQCP_MLDSA_ERR_UNSUPPORTED  -4
#define PQCP_MLDSA_ERR_INTERNAL     -5
#define PQCP_MLDSA_ERR_CONTEXT_LEN  -6

/**
 * @brief Get the public key size for a given security level.
 *
 * @param level The ML-DSA security level.
 * @return Size of the public key in bytes, or 0 if invalid.
 */
size_t pqcp_mldsa_pk_size(pqcp_mldsa_level_t level);

/**
 * @brief Get the secret key size for a given security level.
 *
 * @param level The ML-DSA security level.
 * @return Size of the secret key in bytes, or 0 if invalid.
 */
size_t pqcp_mldsa_sk_size(pqcp_mldsa_level_t level);

/**
 * @brief Get the signature size for a given security level.
 *
 * @param level The ML-DSA security level.
 * @return Size of the signature in bytes, or 0 if invalid.
 */
size_t pqcp_mldsa_sig_size(pqcp_mldsa_level_t level);

/**
 * @brief Generate an ML-DSA keypair.
 *
 * Generates a fresh ML-DSA keypair using the configured RNG backend. The
 * caller owns both output buffers and is responsible for clearing the secret
 * key when it is no longer needed.
 *
 * @param level  Security level (PQCP_MLDSA_44, 65, or 87).
 * @param pk     Output buffer for public key (must be pqcp_mldsa_pk_size(level) bytes).
 * @param sk     Output buffer for secret key (must be pqcp_mldsa_sk_size(level) bytes).
 *
 * @retval PQCP_MLDSA_SUCCESS Keypair generated successfully.
 * @retval PQCP_MLDSA_ERR_INVALID_ARG Invalid level or NULL output buffer.
 * @retval PQCP_MLDSA_ERR_RNG The configured RNG path is not ready.
 * @retval PQCP_MLDSA_ERR_INTERNAL The backend reported a generation failure.
 */
int pqcp_mldsa_keypair(pqcp_mldsa_level_t level, uint8_t *pk, uint8_t *sk);

/**
 * @brief Sign a message using ML-DSA (pure mode).
 *
 * Signs a message using the pure ML-DSA API. The current native backend uses
 * the FIPS 204 signing interface and writes a fixed-size signature for
 * @p level into caller-owned @p sig.
 *
 * @param level    Security level.
 * @param sk       Secret key (pqcp_mldsa_sk_size(level) bytes).
 * @param msg      Message to sign.
 * @param msg_len  Length of message in bytes.
 * @param ctx      Optional context string (NULL for empty).
 * @param ctx_len  Length of context string (0-255).
 * @param sig      Output signature buffer (pqcp_mldsa_sig_size(level) bytes).
 *
 * @retval PQCP_MLDSA_SUCCESS Signature generated successfully.
 * @retval PQCP_MLDSA_ERR_INVALID_ARG Invalid level, NULL key/signature buffer,
 *         or NULL message with non-zero @p msg_len.
 * @retval PQCP_MLDSA_ERR_CONTEXT_LEN @p ctx_len exceeds
 *         @ref PQCP_MLDSA_CONTEXT_MAX.
 * @retval PQCP_MLDSA_ERR_INTERNAL The backend reported a signing failure.
 *
 * @note @p ctx may be NULL only when @p ctx_len is zero. The function does not
 *       retain pointers after returning.
 */
int pqcp_mldsa_sign(pqcp_mldsa_level_t level, const uint8_t *sk,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *ctx, size_t ctx_len,
                    uint8_t *sig);

/**
 * @brief Verify an ML-DSA signature (pure mode).
 *
 * Verifies a fixed-size ML-DSA signature on a message.
 *
 * @param level    Security level.
 * @param pk       Public key (pqcp_mldsa_pk_size(level) bytes).
 * @param msg      Message that was signed.
 * @param msg_len  Length of message in bytes.
 * @param ctx      Context string used during signing (NULL for empty).
 * @param ctx_len  Length of context string (0-255).
 * @param sig      Signature to verify (pqcp_mldsa_sig_size(level) bytes).
 *
 * @retval PQCP_MLDSA_SUCCESS Signature is valid.
 * @retval PQCP_MLDSA_ERR_VERIFY Signature verification failed cleanly.
 * @retval PQCP_MLDSA_ERR_INVALID_ARG Invalid level, NULL key/signature buffer,
 *         or NULL message with non-zero @p msg_len.
 * @retval PQCP_MLDSA_ERR_CONTEXT_LEN @p ctx_len exceeds
 *         @ref PQCP_MLDSA_CONTEXT_MAX.
 */
int pqcp_mldsa_verify(pqcp_mldsa_level_t level, const uint8_t *pk,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *ctx, size_t ctx_len,
                      const uint8_t *sig);

/**
 * @brief Sign a pre-hashed message (HashML-DSA).
 *
 * Compatibility helper for signing caller-supplied digest bytes.
 *
 * The current implementation treats @p hash as the message input to the pure
 * ML-DSA signing path and ignores @p hash_oid / @p oid_len. It is useful for
 * applications that already pre-hash large messages and want a stable wrapper,
 * but it should not be interpreted as a separate certified HashML-DSA mode.
 *
 * @param level      Security level.
 * @param sk         Secret key.
 * @param hash       Pre-computed hash of the message.
 * @param hash_len   Length of hash in bytes.
 * @param hash_oid   OID of the hash algorithm used (DER encoded).
 * @param oid_len    Length of OID.
 * @param ctx        Optional context string.
 * @param ctx_len    Length of context string.
 * @param sig        Output signature buffer.
 *
 * @retval PQCP_MLDSA_SUCCESS Signature generated successfully.
 * @retval PQCP_MLDSA_ERR_INVALID_ARG Invalid arguments.
 * @retval PQCP_MLDSA_ERR_CONTEXT_LEN Context length exceeds 255 bytes.
 * @retval PQCP_MLDSA_ERR_INTERNAL The backend reported a signing failure.
 */
int pqcp_mldsa_sign_hash(pqcp_mldsa_level_t level, const uint8_t *sk,
                         const uint8_t *hash, size_t hash_len,
                         const uint8_t *hash_oid, size_t oid_len,
                         const uint8_t *ctx, size_t ctx_len,
                         uint8_t *sig);

/**
 * @brief Verify a signature over caller-supplied digest bytes.
 *
 * The current implementation mirrors @ref pqcp_mldsa_sign_hash by treating
 * @p hash as the message input to the pure ML-DSA verification path and
 * ignoring @p hash_oid / @p oid_len.
 *
 * @param level      Security level.
 * @param pk         Public key.
 * @param hash       Pre-computed hash of the message.
 * @param hash_len   Length of hash in bytes.
 * @param hash_oid   OID of the hash algorithm used.
 * @param oid_len    Length of OID.
 * @param ctx        Context string used during signing.
 * @param ctx_len    Length of context string.
 * @param sig        Signature to verify.
 *
 * @retval PQCP_MLDSA_SUCCESS Signature is valid.
 * @retval PQCP_MLDSA_ERR_VERIFY Signature verification failed cleanly.
 * @retval PQCP_MLDSA_ERR_INVALID_ARG Invalid arguments.
 * @retval PQCP_MLDSA_ERR_CONTEXT_LEN Context length exceeds 255 bytes.
 */
int pqcp_mldsa_verify_hash(pqcp_mldsa_level_t level, const uint8_t *pk,
                           const uint8_t *hash, size_t hash_len,
                           const uint8_t *hash_oid, size_t oid_len,
                           const uint8_t *ctx, size_t ctx_len,
                           const uint8_t *sig);

/*
 * Streaming API for large messages
 *
 * These functions allow signing/verifying messages larger than available
 * RAM by processing the message in chunks. Only available when
 * CONFIG_PQCP_MLDSA_STREAMING is enabled.
 */

/**
 * @brief Opaque streaming context.
 *
 * Allocate storage with at least @ref PQCP_MLDSA_STREAM_CTX_SIZE bytes and
 * pass it as a `pqcp_mldsa_stream_ctx_t *`. The implementation owns the
 * contents only until finalization returns; callers still own and should clear
 * the backing storage if it held secret-key material.
 */
typedef struct pqcp_mldsa_stream_ctx pqcp_mldsa_stream_ctx_t;

/** @brief Minimum backing storage size for a streaming context. */
#define PQCP_MLDSA_STREAM_CTX_SIZE \
    (PQCP_MLDSA_SK_SIZE_MAX + PQCP_MLDSA_SIG_SIZE_MAX + \
     PQCP_MLDSA_CONTEXT_MAX + 600)

/**
 * @brief Initialize streaming signing context.
 *
 * @param ctx        Pointer to context structure to initialize.
 * @param level      Security level.
 * @param sk         Secret key.
 * @param context    Optional application context string.
 * @param ctx_len    Length of context string.
 *
 * @retval PQCP_MLDSA_SUCCESS Context initialized successfully.
 * @retval Negative error code on invalid arguments or unsupported levels.
 */
int pqcp_mldsa_sign_stream_init(pqcp_mldsa_stream_ctx_t *ctx,
                                pqcp_mldsa_level_t level,
                                const uint8_t *sk,
                                const uint8_t *context, size_t ctx_len);

/**
 * @brief Update streaming signing with message chunk.
 *
 * @param ctx        Initialized streaming context.
 * @param data       Message chunk to process.
 * @param len        Length of chunk.
 *
 * @retval PQCP_MLDSA_SUCCESS Chunk accepted successfully.
 * @retval Negative error code if @p ctx or @p data is invalid.
 */
int pqcp_mldsa_sign_stream_update(pqcp_mldsa_stream_ctx_t *ctx,
                                  const uint8_t *data, size_t len);

/**
 * @brief Finalize streaming signing and produce signature.
 *
 * @param ctx        Streaming context.
 * @param sig        Output signature buffer.
 *
 * @retval PQCP_MLDSA_SUCCESS Signature generated successfully.
 * @retval Negative error code if the context or output buffer is invalid.
 */
int pqcp_mldsa_sign_stream_final(pqcp_mldsa_stream_ctx_t *ctx, uint8_t *sig);

/**
 * @brief Initialize streaming verification context.
 *
 * @param ctx        Pointer to context structure to initialize.
 * @param level      Security level.
 * @param pk         Public key.
 * @param sig        Signature to verify.
 * @param context    Optional application context string.
 * @param ctx_len    Length of context string.
 *
 * @retval PQCP_MLDSA_SUCCESS Context initialized successfully.
 * @retval Negative error code on invalid arguments or unsupported levels.
 */
int pqcp_mldsa_verify_stream_init(pqcp_mldsa_stream_ctx_t *ctx,
                                  pqcp_mldsa_level_t level,
                                  const uint8_t *pk,
                                  const uint8_t *sig,
                                  const uint8_t *context, size_t ctx_len);

/**
 * @brief Update streaming verification with message chunk.
 *
 * @param ctx        Initialized streaming context.
 * @param data       Message chunk to process.
 * @param len        Length of chunk.
 *
 * @retval PQCP_MLDSA_SUCCESS Chunk accepted successfully.
 * @retval Negative error code if @p ctx or @p data is invalid.
 */
int pqcp_mldsa_verify_stream_update(pqcp_mldsa_stream_ctx_t *ctx,
                                    const uint8_t *data, size_t len);

/**
 * @brief Finalize streaming verification.
 *
 * @param ctx        Streaming context.
 *
 * @retval PQCP_MLDSA_SUCCESS Signature is valid.
 * @retval PQCP_MLDSA_ERR_VERIFY Signature verification failed cleanly.
 * @retval Negative error code if the context is invalid.
 */
int pqcp_mldsa_verify_stream_final(pqcp_mldsa_stream_ctx_t *ctx);

/**
 * @brief Deterministic keypair generation for KAT/testing.
 *
 * WARNING: Only available with CONFIG_PQCP_RNG_DETERMINISTIC_TEST.
 * Do not use in production!
 *
 * @param level  Security level.
 * @param seed   Deterministic seed (32 bytes: xi per FIPS-204).
 * @param pk     Output public key buffer.
 * @param sk     Output secret key buffer.
 *
 * @retval PQCP_MLDSA_SUCCESS Keypair generated successfully.
 * @retval PQCP_MLDSA_ERR_INVALID_ARG Invalid level or NULL buffer.
 * @retval PQCP_MLDSA_ERR_RNG Deterministic RNG seeding failed.
 *
 * @note Test/KAT only. Production key generation must use
 *       @ref pqcp_mldsa_keypair with the configured production RNG.
 */
int pqcp_mldsa_keypair_deterministic(pqcp_mldsa_level_t level,
                                     const uint8_t seed[32],
                                     uint8_t *pk, uint8_t *sk);

/**
 * @brief Get string name for a security level.
 *
 * @param level The ML-DSA security level.
 * @return String name like "ML-DSA-65", or "Unknown" if invalid.
 */
const char *pqcp_mldsa_level_name(pqcp_mldsa_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_MLDSA_H */
