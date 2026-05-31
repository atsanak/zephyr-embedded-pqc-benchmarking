/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Primitive Tests
 *
 * Zephyr ztest suite for ML-KEM and ML-DSA operations.
 */

#include <zephyr/ztest.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/* Static buffers for tests */
static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
static uint8_t ss1[PQCP_MLKEM_SS_SIZE];
static uint8_t ss2[PQCP_MLKEM_SS_SIZE];

static uint8_t sig_pk[PQCP_MLDSA_PK_SIZE_MAX];
static uint8_t sig_sk[PQCP_MLDSA_SK_SIZE_MAX];
static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];

static const uint8_t test_msg[] = "Test message for signature";

/*
 * ML-KEM Tests
 */

ZTEST(pqcp_primitive, test_mlkem_size_functions)
{
    /* Test size functions return expected values */
    zassert_equal(pqcp_mlkem_pk_size(PQCP_MLKEM_512), PQCP_MLKEM_512_PK_SIZE);
    zassert_equal(pqcp_mlkem_sk_size(PQCP_MLKEM_512), PQCP_MLKEM_512_SK_SIZE);
    zassert_equal(pqcp_mlkem_ct_size(PQCP_MLKEM_512), PQCP_MLKEM_512_CT_SIZE);

    zassert_equal(pqcp_mlkem_pk_size(PQCP_MLKEM_768), PQCP_MLKEM_768_PK_SIZE);
    zassert_equal(pqcp_mlkem_sk_size(PQCP_MLKEM_768), PQCP_MLKEM_768_SK_SIZE);
    zassert_equal(pqcp_mlkem_ct_size(PQCP_MLKEM_768), PQCP_MLKEM_768_CT_SIZE);

    zassert_equal(pqcp_mlkem_pk_size(PQCP_MLKEM_1024), PQCP_MLKEM_1024_PK_SIZE);
    zassert_equal(pqcp_mlkem_sk_size(PQCP_MLKEM_1024), PQCP_MLKEM_1024_SK_SIZE);
    zassert_equal(pqcp_mlkem_ct_size(PQCP_MLKEM_1024), PQCP_MLKEM_1024_CT_SIZE);

    /* Invalid level returns 0 */
    zassert_equal(pqcp_mlkem_pk_size(0), 0);
    zassert_equal(pqcp_mlkem_sk_size(999), 0);
}

ZTEST(pqcp_primitive, test_mlkem_level_names)
{
    zassert_str_equal(pqcp_mlkem_level_name(PQCP_MLKEM_512), "ML-KEM-512");
    zassert_str_equal(pqcp_mlkem_level_name(PQCP_MLKEM_768), "ML-KEM-768");
    zassert_str_equal(pqcp_mlkem_level_name(PQCP_MLKEM_1024), "ML-KEM-1024");
    zassert_str_equal(pqcp_mlkem_level_name(0), "Unknown");
}

ZTEST(pqcp_primitive, test_mlkem_keypair_null_args)
{
    int ret = pqcp_mlkem_keypair(PQCP_MLKEM_768, NULL, sk);
    zassert_equal(ret, PQCP_MLKEM_ERR_INVALID_ARG);

    ret = pqcp_mlkem_keypair(PQCP_MLKEM_768, pk, NULL);
    zassert_equal(ret, PQCP_MLKEM_ERR_INVALID_ARG);
}

ZTEST(pqcp_primitive, test_mlkem_keypair_success)
{
    int ret = pqcp_mlkem_keypair(PQCP_MLKEM_768, pk, sk);
    zassert_equal(ret, PQCP_MLKEM_SUCCESS, "Keypair generation failed: %d", ret);

    /* Keys should not be all zeros */
    bool pk_nonzero = false;
    for (size_t i = 0; i < pqcp_mlkem_pk_size(PQCP_MLKEM_768); i++) {
        if (pk[i] != 0) {
            pk_nonzero = true;
            break;
        }
    }
    zassert_true(pk_nonzero, "Public key is all zeros");
}

ZTEST(pqcp_primitive, test_mlkem_encaps_decaps)
{
    /* Generate keypair */
    int ret = pqcp_mlkem_keypair(PQCP_MLKEM_768, pk, sk);
    zassert_equal(ret, PQCP_MLKEM_SUCCESS);

    /* Encapsulate */
    ret = pqcp_mlkem_encapsulate(PQCP_MLKEM_768, pk, ct, ss1);
    zassert_equal(ret, PQCP_MLKEM_SUCCESS, "Encapsulation failed: %d", ret);

    /* Decapsulate */
    ret = pqcp_mlkem_decapsulate(PQCP_MLKEM_768, ct, sk, ss2);
    zassert_equal(ret, PQCP_MLKEM_SUCCESS, "Decapsulation failed: %d", ret);

    /* Shared secrets must match */
    zassert_mem_equal(ss1, ss2, PQCP_MLKEM_SS_SIZE,
                      "Shared secrets don't match");
}

ZTEST(pqcp_primitive, test_mlkem_encaps_null_args)
{
    int ret = pqcp_mlkem_encapsulate(PQCP_MLKEM_768, NULL, ct, ss1);
    zassert_equal(ret, PQCP_MLKEM_ERR_INVALID_ARG);

    ret = pqcp_mlkem_encapsulate(PQCP_MLKEM_768, pk, NULL, ss1);
    zassert_equal(ret, PQCP_MLKEM_ERR_INVALID_ARG);

    ret = pqcp_mlkem_encapsulate(PQCP_MLKEM_768, pk, ct, NULL);
    zassert_equal(ret, PQCP_MLKEM_ERR_INVALID_ARG);
}

/*
 * ML-DSA Tests
 */

ZTEST(pqcp_primitive, test_mldsa_size_functions)
{
    zassert_equal(pqcp_mldsa_pk_size(PQCP_MLDSA_44), PQCP_MLDSA_44_PK_SIZE);
    zassert_equal(pqcp_mldsa_sk_size(PQCP_MLDSA_44), PQCP_MLDSA_44_SK_SIZE);
    zassert_equal(pqcp_mldsa_sig_size(PQCP_MLDSA_44), PQCP_MLDSA_44_SIG_SIZE);

    zassert_equal(pqcp_mldsa_pk_size(PQCP_MLDSA_65), PQCP_MLDSA_65_PK_SIZE);
    zassert_equal(pqcp_mldsa_sk_size(PQCP_MLDSA_65), PQCP_MLDSA_65_SK_SIZE);
    zassert_equal(pqcp_mldsa_sig_size(PQCP_MLDSA_65), PQCP_MLDSA_65_SIG_SIZE);

    zassert_equal(pqcp_mldsa_pk_size(PQCP_MLDSA_87), PQCP_MLDSA_87_PK_SIZE);

    /* Invalid returns 0 */
    zassert_equal(pqcp_mldsa_pk_size(0), 0);
}

ZTEST(pqcp_primitive, test_mldsa_level_names)
{
    zassert_str_equal(pqcp_mldsa_level_name(PQCP_MLDSA_44), "ML-DSA-44");
    zassert_str_equal(pqcp_mldsa_level_name(PQCP_MLDSA_65), "ML-DSA-65");
    zassert_str_equal(pqcp_mldsa_level_name(PQCP_MLDSA_87), "ML-DSA-87");
}

ZTEST(pqcp_primitive, test_mldsa_keypair_success)
{
    int ret = pqcp_mldsa_keypair(PQCP_MLDSA_65, sig_pk, sig_sk);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS, "Keypair generation failed: %d", ret);
}

ZTEST(pqcp_primitive, test_mldsa_sign_verify)
{
    /* Generate keypair */
    int ret = pqcp_mldsa_keypair(PQCP_MLDSA_65, sig_pk, sig_sk);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);

    /* Sign */
    ret = pqcp_mldsa_sign(PQCP_MLDSA_65, sig_sk,
                          test_msg, sizeof(test_msg) - 1,
                          NULL, 0, sig);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS, "Signing failed: %d", ret);

    /* Verify */
    ret = pqcp_mldsa_verify(PQCP_MLDSA_65, sig_pk,
                            test_msg, sizeof(test_msg) - 1,
                            NULL, 0, sig);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS, "Verification failed: %d", ret);
}

ZTEST(pqcp_primitive, test_mldsa_verify_modified_message)
{
    /* Generate keypair and sign */
    int ret = pqcp_mldsa_keypair(PQCP_MLDSA_65, sig_pk, sig_sk);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);

    ret = pqcp_mldsa_sign(PQCP_MLDSA_65, sig_sk,
                          test_msg, sizeof(test_msg) - 1,
                          NULL, 0, sig);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);

    /* Modify message */
    uint8_t modified_msg[sizeof(test_msg)];
    memcpy(modified_msg, test_msg, sizeof(test_msg));
    modified_msg[0] ^= 0x01;

    /* Verification should fail */
    ret = pqcp_mldsa_verify(PQCP_MLDSA_65, sig_pk,
                            modified_msg, sizeof(modified_msg) - 1,
                            NULL, 0, sig);
    zassert_equal(ret, PQCP_MLDSA_ERR_VERIFY,
                  "Modified message should not verify");
}

ZTEST(pqcp_primitive, test_mldsa_context_string)
{
    const uint8_t ctx[] = "test-context";

    /* Generate keypair */
    int ret = pqcp_mldsa_keypair(PQCP_MLDSA_65, sig_pk, sig_sk);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);

    /* Sign with context */
    ret = pqcp_mldsa_sign(PQCP_MLDSA_65, sig_sk,
                          test_msg, sizeof(test_msg) - 1,
                          ctx, sizeof(ctx) - 1, sig);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);

    /* Verify with same context should succeed */
    ret = pqcp_mldsa_verify(PQCP_MLDSA_65, sig_pk,
                            test_msg, sizeof(test_msg) - 1,
                            ctx, sizeof(ctx) - 1, sig);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);

    /* Verify with different context should fail */
    const uint8_t wrong_ctx[] = "wrong-context";
    ret = pqcp_mldsa_verify(PQCP_MLDSA_65, sig_pk,
                            test_msg, sizeof(test_msg) - 1,
                            wrong_ctx, sizeof(wrong_ctx) - 1, sig);
    zassert_equal(ret, PQCP_MLDSA_ERR_VERIFY,
                  "Wrong context should not verify");
}

ZTEST(pqcp_primitive, test_mldsa_context_too_long)
{
    /* Context > 255 bytes should fail */
    uint8_t long_ctx[300];
    memset(long_ctx, 'X', sizeof(long_ctx));

    int ret = pqcp_mldsa_sign(PQCP_MLDSA_65, sig_sk,
                              test_msg, sizeof(test_msg) - 1,
                              long_ctx, sizeof(long_ctx), sig);
    zassert_equal(ret, PQCP_MLDSA_ERR_CONTEXT_LEN,
                  "Should reject context > 255 bytes");
}

/*
 * PSA Driver Tests (conditionally compiled)
 */

#ifdef CONFIG_PQCP_PSA_DRIVER_MLKEM

#include <psa/crypto.h>

/* Declare PSA driver functions */
extern psa_status_t pqcp_psa_mlkem_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length);

extern psa_status_t pqcp_psa_mlkem_encapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length,
    uint8_t *shared_secret, size_t shared_secret_size, size_t *shared_secret_length);

extern psa_status_t pqcp_psa_mlkem_decapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *shared_secret, size_t shared_secret_size, size_t *shared_secret_length);

/* Provisional PSA algorithm IDs */
#ifndef PSA_ALG_ML_KEM_768
#define PSA_ALG_ML_KEM_768     ((psa_algorithm_t)0x06000E01)
#endif
#ifndef PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY
#define PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY   ((psa_key_type_t)0x4002)
#endif
#ifndef PSA_KEY_TYPE_ML_KEM_KEY_PAIR
#define PSA_KEY_TYPE_ML_KEM_KEY_PAIR     ((psa_key_type_t)0x7002)
#endif

static uint8_t psa_key_buffer[PQCP_MLKEM_PK_SIZE_MAX + PQCP_MLKEM_SK_SIZE_MAX];
static uint8_t psa_ct[PQCP_MLKEM_CT_SIZE_MAX];
static uint8_t psa_ss1[PQCP_MLKEM_SS_SIZE];
static uint8_t psa_ss2[PQCP_MLKEM_SS_SIZE];

ZTEST(pqcp_primitive, test_psa_mlkem_keygen)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t key_length;

    psa_set_key_algorithm(&attributes, PSA_ALG_ML_KEM_768);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);

    psa_status_t status = pqcp_psa_mlkem_generate_key(
        &attributes, psa_key_buffer, sizeof(psa_key_buffer), &key_length);

    zassert_equal(status, PSA_SUCCESS, "PSA ML-KEM keygen failed: %d", status);

    size_t expected = pqcp_mlkem_pk_size(PQCP_MLKEM_768) +
                      pqcp_mlkem_sk_size(PQCP_MLKEM_768);
    zassert_equal(key_length, expected, "Key length mismatch");
}

ZTEST(pqcp_primitive, test_psa_mlkem_encaps_decaps)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t key_length, ct_length, ss_length;

    psa_set_key_algorithm(&attributes, PSA_ALG_ML_KEM_768);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);

    /* Generate keypair */
    psa_status_t status = pqcp_psa_mlkem_generate_key(
        &attributes, psa_key_buffer, sizeof(psa_key_buffer), &key_length);
    zassert_equal(status, PSA_SUCCESS);

    /* Encapsulate using public key */
    status = pqcp_psa_mlkem_encapsulate(
        &attributes, psa_key_buffer, key_length, PSA_ALG_ML_KEM_768,
        psa_ct, sizeof(psa_ct), &ct_length,
        psa_ss1, sizeof(psa_ss1), &ss_length);
    zassert_equal(status, PSA_SUCCESS, "PSA encaps failed: %d", status);
    zassert_equal(ct_length, pqcp_mlkem_ct_size(PQCP_MLKEM_768));
    zassert_equal(ss_length, PQCP_MLKEM_SS_SIZE);

    /* Decapsulate */
    status = pqcp_psa_mlkem_decapsulate(
        &attributes, psa_key_buffer, key_length, PSA_ALG_ML_KEM_768,
        psa_ct, ct_length,
        psa_ss2, sizeof(psa_ss2), &ss_length);
    zassert_equal(status, PSA_SUCCESS, "PSA decaps failed: %d", status);

    /* Shared secrets must match */
    zassert_mem_equal(psa_ss1, psa_ss2, PQCP_MLKEM_SS_SIZE,
                      "PSA shared secrets don't match");
}

ZTEST(pqcp_primitive, test_psa_mlkem_keygen_wrong_key_type)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t key_length = 0U;

    psa_set_key_algorithm(&attributes, PSA_ALG_ML_KEM_768);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY);

    psa_status_t status = pqcp_psa_mlkem_generate_key(
        &attributes, psa_key_buffer, sizeof(psa_key_buffer), &key_length);

    zassert_equal(status, PSA_ERROR_NOT_SUPPORTED,
                  "Public-key generation should be rejected");
}

ZTEST(pqcp_primitive, test_psa_mlkem_encaps_rejects_bad_inputs)
{
    psa_key_attributes_t keypair_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t public_attrs = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t short_ct[32];
    size_t key_length = 0U;
    size_t ct_length = 0U;
    size_t ss_length = 0U;

    psa_set_key_algorithm(&keypair_attrs, PSA_ALG_ML_KEM_768);
    psa_set_key_type(&keypair_attrs, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);
    psa_set_key_algorithm(&public_attrs, PSA_ALG_ML_KEM_768);
    psa_set_key_type(&public_attrs, PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY);

    psa_status_t status = pqcp_psa_mlkem_generate_key(
        &keypair_attrs, psa_key_buffer, sizeof(psa_key_buffer), &key_length);
    zassert_equal(status, PSA_SUCCESS);

    status = pqcp_psa_mlkem_encapsulate(
        &public_attrs, psa_key_buffer, key_length, PSA_ALG_ML_KEM_768,
        short_ct, sizeof(short_ct), &ct_length,
        psa_ss1, sizeof(psa_ss1), &ss_length);
    zassert_equal(status, PSA_ERROR_BUFFER_TOO_SMALL,
                  "Short ciphertext buffer should be rejected");

    status = pqcp_psa_mlkem_encapsulate(
        &keypair_attrs, NULL, key_length, PSA_ALG_ML_KEM_768,
        psa_ct, sizeof(psa_ct), &ct_length,
        psa_ss1, sizeof(psa_ss1), &ss_length);
    zassert_equal(status, PSA_ERROR_INVALID_ARGUMENT,
                  "NULL public-key buffer should be rejected");
}

ZTEST(pqcp_primitive, test_psa_mlkem_decaps_wrong_key_type)
{
    psa_key_attributes_t keypair_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t public_attrs = PSA_KEY_ATTRIBUTES_INIT;
    size_t key_length = 0U;
    size_t ct_length = 0U;
    size_t ss_length = 0U;

    psa_set_key_algorithm(&keypair_attrs, PSA_ALG_ML_KEM_768);
    psa_set_key_type(&keypair_attrs, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);
    psa_set_key_algorithm(&public_attrs, PSA_ALG_ML_KEM_768);
    psa_set_key_type(&public_attrs, PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY);

    psa_status_t status = pqcp_psa_mlkem_generate_key(
        &keypair_attrs, psa_key_buffer, sizeof(psa_key_buffer), &key_length);
    zassert_equal(status, PSA_SUCCESS);

    status = pqcp_psa_mlkem_encapsulate(
        &public_attrs, psa_key_buffer, key_length, PSA_ALG_ML_KEM_768,
        psa_ct, sizeof(psa_ct), &ct_length,
        psa_ss1, sizeof(psa_ss1), &ss_length);
    zassert_equal(status, PSA_SUCCESS);

    status = pqcp_psa_mlkem_decapsulate(
        &public_attrs, psa_key_buffer, key_length, PSA_ALG_ML_KEM_768,
        psa_ct, ct_length, psa_ss2, sizeof(psa_ss2), &ss_length);
    zassert_equal(status, PSA_ERROR_NOT_SUPPORTED,
                  "Public-key decapsulation should be rejected");
}

#endif /* CONFIG_PQCP_PSA_DRIVER_MLKEM */

#ifdef CONFIG_PQCP_PSA_DRIVER_MLDSA

#include <psa/crypto.h>

/* Declare PSA driver functions */
extern psa_status_t pqcp_psa_mldsa_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length);

extern psa_status_t pqcp_psa_mldsa_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length);

extern psa_status_t pqcp_psa_mldsa_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *signature, size_t signature_length);

/* Provisional PSA algorithm IDs */
#ifndef PSA_ALG_ML_DSA_65
#define PSA_ALG_ML_DSA_65     ((psa_algorithm_t)0x06000F01)
#endif
#ifndef PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY
#define PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY   ((psa_key_type_t)0x4003)
#endif
#ifndef PSA_KEY_TYPE_ML_DSA_KEY_PAIR
#define PSA_KEY_TYPE_ML_DSA_KEY_PAIR     ((psa_key_type_t)0x7003)
#endif

static uint8_t psa_sig_key_buffer[PQCP_MLDSA_PK_SIZE_MAX + PQCP_MLDSA_SK_SIZE_MAX];
static uint8_t psa_signature[PQCP_MLDSA_SIG_SIZE_MAX];
static const uint8_t psa_test_msg[] = "PSA test message for ML-DSA";

ZTEST(pqcp_primitive, test_psa_mldsa_keygen)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t key_length;

    psa_set_key_algorithm(&attributes, PSA_ALG_ML_DSA_65);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);

    psa_status_t status = pqcp_psa_mldsa_generate_key(
        &attributes, psa_sig_key_buffer, sizeof(psa_sig_key_buffer), &key_length);

    zassert_equal(status, PSA_SUCCESS, "PSA ML-DSA keygen failed: %d", status);

    size_t expected = pqcp_mldsa_pk_size(PQCP_MLDSA_65) +
                      pqcp_mldsa_sk_size(PQCP_MLDSA_65);
    zassert_equal(key_length, expected, "Key length mismatch");
}

ZTEST(pqcp_primitive, test_psa_mldsa_sign_verify)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t key_length, sig_length;

    psa_set_key_algorithm(&attributes, PSA_ALG_ML_DSA_65);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);

    /* Generate keypair */
    psa_status_t status = pqcp_psa_mldsa_generate_key(
        &attributes, psa_sig_key_buffer, sizeof(psa_sig_key_buffer), &key_length);
    zassert_equal(status, PSA_SUCCESS);

    /* Sign */
    status = pqcp_psa_mldsa_sign_message(
        &attributes, psa_sig_key_buffer, key_length, PSA_ALG_ML_DSA_65,
        psa_test_msg, sizeof(psa_test_msg) - 1,
        psa_signature, sizeof(psa_signature), &sig_length);
    zassert_equal(status, PSA_SUCCESS, "PSA sign failed: %d", status);
    zassert_equal(sig_length, pqcp_mldsa_sig_size(PQCP_MLDSA_65));

    /* Verify */
    status = pqcp_psa_mldsa_verify_message(
        &attributes, psa_sig_key_buffer, key_length, PSA_ALG_ML_DSA_65,
        psa_test_msg, sizeof(psa_test_msg) - 1,
        psa_signature, sig_length);
    zassert_equal(status, PSA_SUCCESS, "PSA verify failed: %d", status);
}

ZTEST(pqcp_primitive, test_psa_mldsa_verify_bad_sig)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t key_length, sig_length;

    psa_set_key_algorithm(&attributes, PSA_ALG_ML_DSA_65);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);

    /* Generate and sign */
    psa_status_t status = pqcp_psa_mldsa_generate_key(
        &attributes, psa_sig_key_buffer, sizeof(psa_sig_key_buffer), &key_length);
    zassert_equal(status, PSA_SUCCESS);

    status = pqcp_psa_mldsa_sign_message(
        &attributes, psa_sig_key_buffer, key_length, PSA_ALG_ML_DSA_65,
        psa_test_msg, sizeof(psa_test_msg) - 1,
        psa_signature, sizeof(psa_signature), &sig_length);
    zassert_equal(status, PSA_SUCCESS);

    /* Corrupt signature */
    psa_signature[0] ^= 0xFF;

    /* Verify should fail */
    status = pqcp_psa_mldsa_verify_message(
        &attributes, psa_sig_key_buffer, key_length, PSA_ALG_ML_DSA_65,
        psa_test_msg, sizeof(psa_test_msg) - 1,
        psa_signature, sig_length);
    zassert_equal(status, PSA_ERROR_INVALID_SIGNATURE,
                  "Bad signature should fail verification");
}

ZTEST(pqcp_primitive, test_psa_mldsa_keygen_wrong_key_type)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t key_length = 0U;

    psa_set_key_algorithm(&attributes, PSA_ALG_ML_DSA_65);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);

    psa_status_t status = pqcp_psa_mldsa_generate_key(
        &attributes, psa_sig_key_buffer, sizeof(psa_sig_key_buffer), &key_length);

    zassert_equal(status, PSA_ERROR_NOT_SUPPORTED,
                  "Public-key generation should be rejected");
}

ZTEST(pqcp_primitive, test_psa_mldsa_sign_rejects_bad_inputs)
{
    psa_key_attributes_t keypair_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t public_attrs = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t short_signature[64];
    size_t key_length = 0U;
    size_t sig_length = 0U;

    psa_set_key_algorithm(&keypair_attrs, PSA_ALG_ML_DSA_65);
    psa_set_key_type(&keypair_attrs, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);
    psa_set_key_algorithm(&public_attrs, PSA_ALG_ML_DSA_65);
    psa_set_key_type(&public_attrs, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);

    psa_status_t status = pqcp_psa_mldsa_generate_key(
        &keypair_attrs, psa_sig_key_buffer, sizeof(psa_sig_key_buffer), &key_length);
    zassert_equal(status, PSA_SUCCESS);

    status = pqcp_psa_mldsa_sign_message(
        &keypair_attrs, psa_sig_key_buffer, key_length, PSA_ALG_ML_DSA_65,
        psa_test_msg, sizeof(psa_test_msg) - 1,
        short_signature, sizeof(short_signature), &sig_length);
    zassert_equal(status, PSA_ERROR_BUFFER_TOO_SMALL,
                  "Short signature buffer should be rejected");

    status = pqcp_psa_mldsa_sign_message(
        &public_attrs, psa_sig_key_buffer, key_length, PSA_ALG_ML_DSA_65,
        psa_test_msg, sizeof(psa_test_msg) - 1,
        psa_signature, sizeof(psa_signature), &sig_length);
    zassert_equal(status, PSA_ERROR_NOT_SUPPORTED,
                  "Signing with a public-key attribute should be rejected");

    status = pqcp_psa_mldsa_sign_message(
        &keypair_attrs, NULL, key_length, PSA_ALG_ML_DSA_65,
        psa_test_msg, sizeof(psa_test_msg) - 1,
        psa_signature, sizeof(psa_signature), &sig_length);
    zassert_equal(status, PSA_ERROR_INVALID_ARGUMENT,
                  "NULL key buffer should be rejected");
}

#endif /* CONFIG_PQCP_PSA_DRIVER_MLDSA */

/*
 * Test Suite Setup
 */

static void *pqcp_primitive_setup(void)
{
    /* Initialize RNG before tests */
    int ret = pqcp_rng_init();
    zassert_equal(ret, 0, "RNG init failed");

#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    /* Seed deterministic RNG for boards without hardware entropy */
    static const uint8_t test_seed[48] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    };
    ret = pqcp_rng_deterministic_seed(test_seed, sizeof(test_seed));
    zassert_equal(ret, 0, "Deterministic RNG seed failed");
#endif

#if defined(CONFIG_PQCP_PSA_DRIVER_MLKEM) || defined(CONFIG_PQCP_PSA_DRIVER_MLDSA)
    /* Initialize PSA Crypto for PSA driver tests */
    psa_status_t status = psa_crypto_init();
    zassert_equal(status, PSA_SUCCESS, "PSA crypto init failed: %d", status);
#endif

    return NULL;
}

ZTEST_SUITE(pqcp_primitive, NULL, pqcp_primitive_setup, NULL, NULL, NULL);
