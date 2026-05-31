/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP ACVP known-answer tests for all FIPS 203 / FIPS 204 parameter sets.
 */

#include <zephyr/ztest.h>

#include <pqcp_zephyr/acvp_cmd.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/mlkem.h>

#include <stdbool.h>
#include <string.h>

#include "kat_vectors.h"
#include "mlkem_native_all.h"
#ifdef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_SECRETKEYBYTES
#endif
#ifdef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#endif
#ifdef CRYPTO_BYTES
#undef CRYPTO_BYTES
#endif
#include "mldsa_native_all.h"

#define MLDSA_KAT_MESSAGE_BYTES_MAX 8192U

static void decode_hex_exact(const char *hex, uint8_t *out, size_t expected_len)
{
    size_t out_len = 0U;

    zassert_equal(
        pqcp_acvp_hex_to_bytes(hex, out, &out_len, expected_len),
        0,
        "hex decode failed"
    );
    zassert_equal(out_len, expected_len, "unexpected decoded length");
}

static size_t decode_hex_variable(const char *hex, uint8_t *out, size_t capacity)
{
    size_t out_len = 0U;

    zassert_not_null(hex);
    zassert_not_null(out);
    zassert_true((strlen(hex) / 2U) <= capacity, "hex input exceeds capacity");
    zassert_equal(
        pqcp_acvp_hex_to_bytes(hex, out, &out_len, capacity),
        0,
        "hex decode failed"
    );

    return out_len;
}

static void build_mldsa_external_preamble(const uint8_t *context, size_t context_len,
                                          uint8_t *preamble, size_t *preamble_len)
{
    zassert_not_null(preamble);
    zassert_not_null(preamble_len);
    zassert_true(context_len <= UINT8_MAX, "context too large for external preamble");

    preamble[0] = 0U;
    preamble[1] = (uint8_t)context_len;
    if ((context != NULL) && (context_len > 0U)) {
        memcpy(&preamble[2], context, context_len);
    }
    *preamble_len = context_len + 2U;
}

static int mlkem_keypair_derand_for_level(pqcp_mlkem_level_t level,
                                          uint8_t *pk, uint8_t *sk,
                                          const uint8_t coins[64])
{
    switch (level) {
    case PQCP_MLKEM_512:
        return mlkem512_keypair_derand(pk, sk, coins);
    case PQCP_MLKEM_768:
        return mlkem768_keypair_derand(pk, sk, coins);
    case PQCP_MLKEM_1024:
        return mlkem1024_keypair_derand(pk, sk, coins);
    default:
        return -1;
    }
}

static int mlkem_encaps_derand_for_level(pqcp_mlkem_level_t level,
                                         uint8_t *ct, uint8_t *ss,
                                         const uint8_t *pk,
                                         const uint8_t coins[32])
{
    switch (level) {
    case PQCP_MLKEM_512:
        return mlkem512_enc_derand(ct, ss, pk, coins);
    case PQCP_MLKEM_768:
        return mlkem768_enc_derand(ct, ss, pk, coins);
    case PQCP_MLKEM_1024:
        return mlkem1024_enc_derand(ct, ss, pk, coins);
    default:
        return -1;
    }
}

static int mldsa_signature_internal_for_level(pqcp_mldsa_level_t level,
                                              uint8_t *sig, size_t *sig_len,
                                              const uint8_t *msg, size_t msg_len,
                                              const uint8_t *pre, size_t pre_len,
                                              const uint8_t rnd[32],
                                              const uint8_t *sk)
{
    switch (level) {
    case PQCP_MLDSA_44:
        return mldsa44_signature_internal(sig, sig_len, msg, msg_len,
                                          pre, pre_len, rnd, sk, 0);
    case PQCP_MLDSA_65:
        return mldsa65_signature_internal(sig, sig_len, msg, msg_len,
                                          pre, pre_len, rnd, sk, 0);
    case PQCP_MLDSA_87:
        return mldsa87_signature_internal(sig, sig_len, msg, msg_len,
                                          pre, pre_len, rnd, sk, 0);
    default:
        return -1;
    }
}

static void run_mlkem_keygen_kat(pqcp_mlkem_level_t level,
                                 const char *seed_d_hex,
                                 const char *seed_z_hex,
                                 const char *expected_pk_hex,
                                 const char *expected_sk_hex)
{
    uint8_t keypair_coins[64];
    uint8_t expected_pk[PQCP_MLKEM_PK_SIZE_MAX];
    uint8_t expected_sk[PQCP_MLKEM_SK_SIZE_MAX];
    uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    size_t pk_len = pqcp_mlkem_pk_size(level);
    size_t sk_len = pqcp_mlkem_sk_size(level);

    zassert_true(pk_len > 0U, "invalid ML-KEM level");
    zassert_true(sk_len > 0U, "invalid ML-KEM level");

    decode_hex_exact(seed_d_hex, keypair_coins, PQCP_MLKEM_SS_SIZE);
    decode_hex_exact(seed_z_hex, keypair_coins + PQCP_MLKEM_SS_SIZE, PQCP_MLKEM_SS_SIZE);
    decode_hex_exact(expected_pk_hex, expected_pk, pk_len);
    decode_hex_exact(expected_sk_hex, expected_sk, sk_len);

    zassert_equal(mlkem_keypair_derand_for_level(level, pk, sk, keypair_coins), 0);
    zassert_mem_equal(pk, expected_pk, pk_len, "ML-KEM public key KAT mismatch");
    zassert_mem_equal(sk, expected_sk, sk_len, "ML-KEM secret key KAT mismatch");
}

static void run_mlkem_encaps_kat(pqcp_mlkem_level_t level,
                                 const char *pk_hex,
                                 const char *sk_hex,
                                 const char *coins_hex,
                                 const char *expected_ct_hex,
                                 const char *expected_ss_hex)
{
    uint8_t coins[32];
    uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    uint8_t expected_ct[PQCP_MLKEM_CT_SIZE_MAX];
    uint8_t expected_ss[PQCP_MLKEM_SS_SIZE];
    uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
    uint8_t ss[PQCP_MLKEM_SS_SIZE];
    uint8_t recovered_ss[PQCP_MLKEM_SS_SIZE];
    size_t pk_len = pqcp_mlkem_pk_size(level);
    size_t sk_len = pqcp_mlkem_sk_size(level);
    size_t ct_len = pqcp_mlkem_ct_size(level);

    zassert_true(pk_len > 0U && sk_len > 0U && ct_len > 0U, "invalid ML-KEM level");

    decode_hex_exact(pk_hex, pk, pk_len);
    decode_hex_exact(sk_hex, sk, sk_len);
    decode_hex_exact(coins_hex, coins, sizeof(coins));
    decode_hex_exact(expected_ct_hex, expected_ct, ct_len);
    decode_hex_exact(expected_ss_hex, expected_ss, sizeof(expected_ss));

    zassert_equal(mlkem_encaps_derand_for_level(level, ct, ss, pk, coins), 0);
    zassert_mem_equal(ct, expected_ct, ct_len, "ML-KEM ciphertext KAT mismatch");
    zassert_mem_equal(ss, expected_ss, sizeof(ss), "ML-KEM shared secret KAT mismatch");

    zassert_equal(pqcp_mlkem_decapsulate(level, ct, sk, recovered_ss), PQCP_MLKEM_SUCCESS);
    zassert_mem_equal(recovered_ss, expected_ss, sizeof(recovered_ss),
                      "ML-KEM decapsulation mismatch");
}

static void run_mldsa_sign_kat(pqcp_mldsa_level_t level,
                               const char *message_hex,
                               const char *context_hex,
                               const char *sk_hex,
                               const char *expected_sig_hex)
{
    uint8_t message[MLDSA_KAT_MESSAGE_BYTES_MAX];
    uint8_t context[PQCP_MLDSA_CONTEXT_MAX];
    uint8_t preamble[PQCP_MLDSA_CONTEXT_MAX + 2U];
    uint8_t sk[PQCP_MLDSA_SK_SIZE_MAX];
    uint8_t expected_sig[PQCP_MLDSA_SIG_SIZE_MAX];
    uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    uint8_t deterministic_rnd[32] = { 0U };
    size_t message_len = decode_hex_variable(message_hex, message, sizeof(message));
    size_t context_len = decode_hex_variable(context_hex, context, sizeof(context));
    size_t sk_len = pqcp_mldsa_sk_size(level);
    size_t expected_sig_len = pqcp_mldsa_sig_size(level);
    size_t preamble_len = 0U;
    size_t sig_len = 0U;

    zassert_true(sk_len > 0U, "invalid ML-DSA level");
    zassert_true(expected_sig_len > 0U, "invalid ML-DSA signature length");

    decode_hex_exact(sk_hex, sk, sk_len);
    decode_hex_exact(expected_sig_hex, expected_sig, expected_sig_len);
    build_mldsa_external_preamble(context, context_len, preamble, &preamble_len);

    zassert_equal(
        mldsa_signature_internal_for_level(level, sig, &sig_len, message, message_len,
                                           preamble, preamble_len,
                                           deterministic_rnd, sk),
        0
    );
    zassert_equal(sig_len, expected_sig_len, "unexpected ML-DSA signature length");
    zassert_mem_equal(sig, expected_sig, expected_sig_len, "ML-DSA signature KAT mismatch");
}

static void run_mldsa_verify_kat(pqcp_mldsa_level_t level,
                                 const char *pk_hex,
                                 const char *message_hex,
                                 const char *context_hex,
                                 const char *sig_hex,
                                 bool expect_pass)
{
    uint8_t pk[PQCP_MLDSA_PK_SIZE_MAX];
    uint8_t message[MLDSA_KAT_MESSAGE_BYTES_MAX];
    uint8_t context[PQCP_MLDSA_CONTEXT_MAX];
    uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    size_t pk_len = pqcp_mldsa_pk_size(level);
    size_t sig_len = pqcp_mldsa_sig_size(level);
    size_t message_len = decode_hex_variable(message_hex, message, sizeof(message));
    size_t context_len = decode_hex_variable(context_hex, context, sizeof(context));
    int verify_status;

    zassert_true(pk_len > 0U && sig_len > 0U, "invalid ML-DSA level");
    decode_hex_exact(pk_hex, pk, pk_len);
    decode_hex_exact(sig_hex, sig, sig_len);

    verify_status = pqcp_mldsa_verify(level, pk, message, message_len,
                                      context, context_len, sig);
    if (expect_pass) {
        zassert_equal(verify_status, PQCP_MLDSA_SUCCESS, "ML-DSA verify KAT mismatch");
    } else {
        zassert_equal(verify_status, PQCP_MLDSA_ERR_VERIFY,
                      "ML-DSA invalid-vector rejection mismatch");
    }
}

#define DEFINE_MLKEM_KEYGEN_TEST(level_num)                                   \
    ZTEST(pqcp_acvp_kat, test_mlkem_##level_num##_keygen)                     \
    {                                                                         \
        run_mlkem_keygen_kat(PQCP_MLKEM_##level_num,                          \
                             MLKEM##level_num##_KEYGEN_D_HEX,                 \
                             MLKEM##level_num##_KEYGEN_Z_HEX,                 \
                             MLKEM##level_num##_KEYGEN_PK_HEX,                \
                             MLKEM##level_num##_KEYGEN_SK_HEX);               \
    }

#define DEFINE_MLKEM_ENCAPS_TEST(level_num)                                   \
    ZTEST(pqcp_acvp_kat, test_mlkem_##level_num##_encaps)                     \
    {                                                                         \
        run_mlkem_encaps_kat(PQCP_MLKEM_##level_num,                          \
                             MLKEM##level_num##_ENCAPS_PK_HEX,                \
                             MLKEM##level_num##_ENCAPS_SK_HEX,                \
                             MLKEM##level_num##_ENCAPS_MESSAGE_HEX,           \
                             MLKEM##level_num##_ENCAPS_CT_HEX,                \
                             MLKEM##level_num##_ENCAPS_SS_HEX);               \
    }

#define DEFINE_MLDSA_SIGN_TEST(level_num)                                     \
    ZTEST(pqcp_acvp_kat, test_mldsa_##level_num##_sign)                       \
    {                                                                         \
        run_mldsa_sign_kat(PQCP_MLDSA_##level_num,                            \
                           MLDSA##level_num##_SIGN_MESSAGE_HEX,               \
                           MLDSA##level_num##_SIGN_CONTEXT_HEX,               \
                           MLDSA##level_num##_SIGN_SK_HEX,                    \
                           MLDSA##level_num##_SIGN_SIG_HEX);                  \
    }

#define DEFINE_MLDSA_VERIFY_TEST(level_num)                                   \
    ZTEST(pqcp_acvp_kat, test_mldsa_##level_num##_verify)                     \
    {                                                                         \
        run_mldsa_verify_kat(PQCP_MLDSA_##level_num,                          \
                             MLDSA##level_num##_VERIFY_PK_HEX,                \
                             MLDSA##level_num##_VERIFY_MESSAGE_HEX,           \
                             MLDSA##level_num##_VERIFY_CONTEXT_HEX,           \
                             MLDSA##level_num##_VERIFY_SIG_HEX,               \
                             (MLDSA##level_num##_VERIFY_EXPECT_PASS != 0));   \
    }

DEFINE_MLKEM_KEYGEN_TEST(512)
DEFINE_MLKEM_ENCAPS_TEST(512)
DEFINE_MLKEM_KEYGEN_TEST(768)

#if !defined(CONFIG_PQCP_KAT_SMOKE_ONLY)
DEFINE_MLKEM_ENCAPS_TEST(768)
DEFINE_MLKEM_KEYGEN_TEST(1024)
DEFINE_MLKEM_ENCAPS_TEST(1024)
#endif

DEFINE_MLDSA_SIGN_TEST(44)
DEFINE_MLDSA_VERIFY_TEST(44)
DEFINE_MLDSA_SIGN_TEST(65)

#if !defined(CONFIG_PQCP_KAT_SMOKE_ONLY)
DEFINE_MLDSA_VERIFY_TEST(65)
DEFINE_MLDSA_SIGN_TEST(87)
DEFINE_MLDSA_VERIFY_TEST(87)
#endif

ZTEST_SUITE(pqcp_acvp_kat, NULL, NULL, NULL, NULL, NULL);
