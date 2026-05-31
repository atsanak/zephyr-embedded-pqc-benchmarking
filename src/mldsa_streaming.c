/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - ML-DSA Streaming API
 *
 * Implements streaming signing/verification for large messages.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/*
 * Streaming context structure
 *
 * Uses a SHAKE-256 based hash to accumulate the message, then
 * signs/verifies the final hash. This matches the HashML-DSA approach.
 */

/* Internal hash state - would use SHAKE256 from FIPS-202 */
#define STREAMING_HASH_SIZE 64
#define STREAMING_BUFFER_SIZE 136  /* SHAKE256 rate */

struct pqcp_mldsa_stream_ctx {
    /* Security level */
    pqcp_mldsa_level_t level;

    /* Key material */
    uint8_t key[PQCP_MLDSA_SK_SIZE_MAX];  /* sk for sign, pk for verify */
    size_t key_len;

    /* Signature (for verification) */
    uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    size_t sig_len;

    /* Context string */
    uint8_t context[PQCP_MLDSA_CONTEXT_MAX];
    size_t context_len;

    /* Hash accumulator state */
    uint8_t hash_state[200];  /* Keccak state */
    uint8_t buffer[STREAMING_BUFFER_SIZE];
    size_t buffer_pos;
    size_t total_len;

    /* Operation mode: 0 = sign, 1 = verify */
    uint8_t mode;

    /* Initialized flag */
    uint8_t initialized;
};

/* Simple placeholder hash accumulator */
/* In production, this would use proper SHAKE256 */
static void hash_init(struct pqcp_mldsa_stream_ctx *ctx)
{
    memset(ctx->hash_state, 0, sizeof(ctx->hash_state));
    ctx->buffer_pos = 0;
    ctx->total_len = 0;
}

static void hash_update(struct pqcp_mldsa_stream_ctx *ctx,
                        const uint8_t *data, size_t len)
{
    /* Accumulate into buffer, "absorb" when full */
    size_t pos = 0;
    const size_t absorb_len = MIN(STREAMING_BUFFER_SIZE, sizeof(ctx->hash_state));

    while (pos < len) {
        size_t to_copy = len - pos;
        size_t space = STREAMING_BUFFER_SIZE - ctx->buffer_pos;

        if (to_copy > space) {
            to_copy = space;
        }

        memcpy(ctx->buffer + ctx->buffer_pos, data + pos, to_copy);
        ctx->buffer_pos += to_copy;
        pos += to_copy;

        if (ctx->buffer_pos == STREAMING_BUFFER_SIZE) {
            /* "Absorb" - XOR into state (simplified) */
            for (size_t i = 0; i < absorb_len; i++) {
                ctx->hash_state[i] ^= ctx->buffer[i];
            }
            ctx->buffer_pos = 0;
        }
    }

    ctx->total_len += len;
}

static void hash_final(struct pqcp_mldsa_stream_ctx *ctx,
                       uint8_t *out, size_t out_len)
{
    /* Pad and finalize (simplified SHAKE256 padding) */
    const size_t absorb_len = MIN(STREAMING_BUFFER_SIZE, sizeof(ctx->hash_state));

    ctx->buffer[ctx->buffer_pos++] = 0x1F;  /* SHAKE256 domain separator */

    while (ctx->buffer_pos < STREAMING_BUFFER_SIZE - 1) {
        ctx->buffer[ctx->buffer_pos++] = 0x00;
    }
    ctx->buffer[ctx->buffer_pos] = 0x80;

    /* Final absorb */
    for (size_t i = 0; i < absorb_len; i++) {
        ctx->hash_state[i] ^= ctx->buffer[i];
    }

    /* "Squeeze" - output hash (simplified) */
    size_t copied = 0;
    while (copied < out_len) {
        size_t to_copy = out_len - copied;
        if (to_copy > STREAMING_BUFFER_SIZE) {
            to_copy = STREAMING_BUFFER_SIZE;
        }

        memcpy(out + copied, ctx->hash_state, to_copy);
        copied += to_copy;

        /* Would permute state here for more output */
    }
}

int pqcp_mldsa_sign_stream_init(pqcp_mldsa_stream_ctx_t *ctx,
                                pqcp_mldsa_level_t level,
                                const uint8_t *sk,
                                const uint8_t *context, size_t ctx_len)
{
    struct pqcp_mldsa_stream_ctx *sctx = (struct pqcp_mldsa_stream_ctx *)ctx;

    if (sctx == NULL || sk == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (ctx_len > PQCP_MLDSA_CONTEXT_MAX) {
        return PQCP_MLDSA_ERR_CONTEXT_LEN;
    }

    size_t sk_len = pqcp_mldsa_sk_size(level);
    if (sk_len == 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    memset(sctx, 0, sizeof(*sctx));
    sctx->level = level;
    memcpy(sctx->key, sk, sk_len);
    sctx->key_len = sk_len;

    if (context != NULL && ctx_len > 0) {
        memcpy(sctx->context, context, ctx_len);
        sctx->context_len = ctx_len;
    }

    sctx->mode = 0;  /* Sign mode */
    hash_init(sctx);

    /* Include domain separator and context in hash */
    const uint8_t header[2] = { 0x01, (uint8_t)ctx_len };  /* Pure ML-DSA */
    hash_update(sctx, header, 2);
    if (ctx_len > 0) {
        hash_update(sctx, sctx->context, ctx_len);
    }

    sctx->initialized = 1;

    return PQCP_MLDSA_SUCCESS;
}

int pqcp_mldsa_sign_stream_update(pqcp_mldsa_stream_ctx_t *ctx,
                                  const uint8_t *data, size_t len)
{
    struct pqcp_mldsa_stream_ctx *sctx = (struct pqcp_mldsa_stream_ctx *)ctx;

    if (sctx == NULL || !sctx->initialized || sctx->mode != 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (data == NULL && len > 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (len > 0) {
        hash_update(sctx, data, len);
    }

    return PQCP_MLDSA_SUCCESS;
}

int pqcp_mldsa_sign_stream_final(pqcp_mldsa_stream_ctx_t *ctx, uint8_t *sig)
{
    struct pqcp_mldsa_stream_ctx *sctx = (struct pqcp_mldsa_stream_ctx *)ctx;

    if (sctx == NULL || !sctx->initialized || sctx->mode != 0 || sig == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    /* Finalize hash */
    uint8_t hash[STREAMING_HASH_SIZE];
    hash_final(sctx, hash, sizeof(hash));

    /* Sign the hash using HashML-DSA */
    int ret = pqcp_mldsa_sign_hash(sctx->level, sctx->key,
                                   hash, sizeof(hash),
                                   NULL, 0,  /* No OID for internal use */
                                   NULL, 0,  /* Context already included in hash */
                                   sig);

    /* Clear sensitive state */
    memset(sctx, 0, sizeof(*sctx));

    return ret;
}

int pqcp_mldsa_verify_stream_init(pqcp_mldsa_stream_ctx_t *ctx,
                                  pqcp_mldsa_level_t level,
                                  const uint8_t *pk,
                                  const uint8_t *sig,
                                  const uint8_t *context, size_t ctx_len)
{
    struct pqcp_mldsa_stream_ctx *sctx = (struct pqcp_mldsa_stream_ctx *)ctx;

    if (sctx == NULL || pk == NULL || sig == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (ctx_len > PQCP_MLDSA_CONTEXT_MAX) {
        return PQCP_MLDSA_ERR_CONTEXT_LEN;
    }

    size_t pk_len = pqcp_mldsa_pk_size(level);
    size_t sig_len = pqcp_mldsa_sig_size(level);

    if (pk_len == 0 || sig_len == 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    memset(sctx, 0, sizeof(*sctx));
    sctx->level = level;
    memcpy(sctx->key, pk, pk_len);
    sctx->key_len = pk_len;
    memcpy(sctx->sig, sig, sig_len);
    sctx->sig_len = sig_len;

    if (context != NULL && ctx_len > 0) {
        memcpy(sctx->context, context, ctx_len);
        sctx->context_len = ctx_len;
    }

    sctx->mode = 1;  /* Verify mode */
    hash_init(sctx);

    /* Include domain separator and context */
    const uint8_t header[2] = { 0x01, (uint8_t)ctx_len };
    hash_update(sctx, header, 2);
    if (ctx_len > 0) {
        hash_update(sctx, sctx->context, ctx_len);
    }

    sctx->initialized = 1;

    return PQCP_MLDSA_SUCCESS;
}

int pqcp_mldsa_verify_stream_update(pqcp_mldsa_stream_ctx_t *ctx,
                                    const uint8_t *data, size_t len)
{
    struct pqcp_mldsa_stream_ctx *sctx = (struct pqcp_mldsa_stream_ctx *)ctx;

    if (sctx == NULL || !sctx->initialized || sctx->mode != 1) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (data == NULL && len > 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    if (len > 0) {
        hash_update(sctx, data, len);
    }

    return PQCP_MLDSA_SUCCESS;
}

int pqcp_mldsa_verify_stream_final(pqcp_mldsa_stream_ctx_t *ctx)
{
    struct pqcp_mldsa_stream_ctx *sctx = (struct pqcp_mldsa_stream_ctx *)ctx;

    if (sctx == NULL || !sctx->initialized || sctx->mode != 1) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    /* Finalize hash */
    uint8_t hash[STREAMING_HASH_SIZE];
    hash_final(sctx, hash, sizeof(hash));

    /* Verify the hash */
    int ret = pqcp_mldsa_verify_hash(sctx->level, sctx->key,
                                     hash, sizeof(hash),
                                     NULL, 0,
                                     NULL, 0,
                                     sctx->sig);

    /* Clear state */
    memset(sctx, 0, sizeof(*sctx));

    return ret;
}
