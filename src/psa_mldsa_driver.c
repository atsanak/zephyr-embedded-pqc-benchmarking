/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - PSA ML-DSA Driver Shim
 *
 * PSA Crypto driver for ML-DSA (FIPS-204) operations.
 * Based on TF-PSA-Crypto issue #633 design.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C
#include <psa/crypto.h>
#include <psa/crypto_types.h>
#include <psa/crypto_values.h>
#endif

#include <string.h>

/*
 * PSA Algorithm and Key Type Definitions for ML-DSA
 *
 * These should eventually come from psa/crypto_values.h when
 * ML-DSA support is standardized. For now, we define provisional values.
 */

#ifndef PSA_ALG_ML_DSA_44
/* ML-DSA algorithm identifiers (provisional) */
#define PSA_ALG_ML_DSA_44     ((psa_algorithm_t)0x06000F00)
#define PSA_ALG_ML_DSA_65     ((psa_algorithm_t)0x06000F01)
#define PSA_ALG_ML_DSA_87     ((psa_algorithm_t)0x06000F02)

/* ML-DSA key types (provisional) */
#define PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY   ((psa_key_type_t)0x4003)
#define PSA_KEY_TYPE_ML_DSA_KEY_PAIR     ((psa_key_type_t)0x7003)
#endif

#ifdef CONFIG_PQCP_PSA_DRIVER_MLDSA

/*
 * Helper functions
 */

static pqcp_mldsa_level_t psa_alg_to_mldsa_level(psa_algorithm_t alg)
{
    switch (alg) {
    case PSA_ALG_ML_DSA_44: return PQCP_MLDSA_44;
    case PSA_ALG_ML_DSA_65: return PQCP_MLDSA_65;
    case PSA_ALG_ML_DSA_87: return PQCP_MLDSA_87;
    default: return 0;
    }
}

static size_t mldsa_level_to_pk_bits(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44: return PQCP_MLDSA_44_PK_SIZE * 8;
    case PQCP_MLDSA_65: return PQCP_MLDSA_65_PK_SIZE * 8;
    case PQCP_MLDSA_87: return PQCP_MLDSA_87_PK_SIZE * 8;
    default: return 0;
    }
}

static bool mldsa_key_type_is_public(psa_key_type_t type)
{
    return type == PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY;
}

static bool mldsa_key_type_is_key_pair(psa_key_type_t type)
{
    return type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR;
}

static bool mldsa_key_type_is_supported(psa_key_type_t type)
{
    return mldsa_key_type_is_public(type) || mldsa_key_type_is_key_pair(type);
}

static psa_status_t mldsa_validate_attributes(
    const psa_key_attributes_t *attributes,
    psa_key_type_t *type,
    pqcp_mldsa_level_t *level)
{
    pqcp_mldsa_level_t resolved_level;

    if ((attributes == NULL) || (type == NULL) || (level == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *type = psa_get_key_type(attributes);
    resolved_level = psa_alg_to_mldsa_level(psa_get_key_algorithm(attributes));

    if (resolved_level == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (!mldsa_key_type_is_supported(*type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *level = resolved_level;

    return PSA_SUCCESS;
}

static psa_status_t mldsa_map_operation_status(int ret)
{
    switch (ret) {
    case PQCP_MLDSA_SUCCESS:
        return PSA_SUCCESS;
    case PQCP_MLDSA_ERR_VERIFY:
        return PSA_ERROR_INVALID_SIGNATURE;
    case PQCP_MLDSA_ERR_INVALID_ARG:
    case PQCP_MLDSA_ERR_CONTEXT_LEN:
        return PSA_ERROR_INVALID_ARGUMENT;
    case PQCP_MLDSA_ERR_UNSUPPORTED:
        return PSA_ERROR_NOT_SUPPORTED;
    case PQCP_MLDSA_ERR_RNG:
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    default:
        return PSA_ERROR_HARDWARE_FAILURE;
    }
}

#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C

/*
 * PSA Driver Entry Points
 *
 * These functions implement the PSA driver interface for ML-DSA.
 * They would be registered with the PSA driver wrapper.
 */

/**
 * @brief Generate an ML-DSA keypair
 */
psa_status_t pqcp_psa_mldsa_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length)
{
    psa_key_type_t type;
    pqcp_mldsa_level_t level;
    psa_status_t status = mldsa_validate_attributes(attributes, &type, &level);

    if (status != PSA_SUCCESS) {
        return status;
    }

    if (!mldsa_key_type_is_key_pair(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if ((key_buffer == NULL) || (key_buffer_length == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t pk_size = pqcp_mldsa_pk_size(level);
    size_t sk_size = pqcp_mldsa_sk_size(level);
    size_t total_size = pk_size + sk_size;

    if (key_buffer_size < total_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Generate keypair: key_buffer = [pk || sk] */
    uint8_t *pk = key_buffer;
    uint8_t *sk = key_buffer + pk_size;

    status = mldsa_map_operation_status(pqcp_mldsa_keypair(level, pk, sk));
    if (status != PSA_SUCCESS) {
        return status;
    }

    *key_buffer_length = total_size;

    return PSA_SUCCESS;
}

/**
 * @brief Import an ML-DSA key
 */
psa_status_t pqcp_psa_mldsa_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits)
{
    psa_key_type_t type;
    pqcp_mldsa_level_t level;
    psa_status_t status = mldsa_validate_attributes(attributes, &type, &level);

    if (status != PSA_SUCCESS) {
        return status;
    }

    if ((data == NULL) || (key_buffer == NULL) ||
        (key_buffer_length == NULL) || (bits == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t pk_size = pqcp_mldsa_pk_size(level);
    size_t sk_size = pqcp_mldsa_sk_size(level);

    if (mldsa_key_type_is_public(type)) {
        if (data_length != pk_size) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (key_buffer_size < pk_size) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        memcpy(key_buffer, data, pk_size);
        *key_buffer_length = pk_size;
        *bits = mldsa_level_to_pk_bits(level);

    } else if (mldsa_key_type_is_key_pair(type)) {
        size_t total_size = pk_size + sk_size;

        if (data_length != total_size) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (key_buffer_size < total_size) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        memcpy(key_buffer, data, total_size);
        *key_buffer_length = total_size;
        *bits = mldsa_level_to_pk_bits(level);

    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

/**
 * @brief Export an ML-DSA public key
 */
psa_status_t pqcp_psa_mldsa_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length)
{
    psa_key_type_t type;
    pqcp_mldsa_level_t level;
    psa_status_t status = mldsa_validate_attributes(attributes, &type, &level);

    if (status != PSA_SUCCESS) {
        return status;
    }

    if ((key_buffer == NULL) || (data == NULL) || (data_length == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t pk_size = pqcp_mldsa_pk_size(level);

    if (data_size < pk_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mldsa_key_type_is_public(type)) {
        /* Key is already public */
        if (key_buffer_size < pk_size) {
            return PSA_ERROR_CORRUPTION_DETECTED;
        }
        memcpy(data, key_buffer, pk_size);

    } else if (mldsa_key_type_is_key_pair(type)) {
        /* Extract public key from keypair [pk || sk] */
        if (key_buffer_size < pk_size) {
            return PSA_ERROR_CORRUPTION_DETECTED;
        }
        memcpy(data, key_buffer, pk_size);

    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *data_length = pk_size;

    return PSA_SUCCESS;
}

/**
 * @brief Sign a message with ML-DSA
 */
psa_status_t pqcp_psa_mldsa_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    psa_key_type_t type;
    pqcp_mldsa_level_t level = psa_alg_to_mldsa_level(alg);

    if ((attributes == NULL) || (key_buffer == NULL) || (signature == NULL) ||
        (signature_length == NULL) || ((input == NULL) && (input_length != 0U))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    type = psa_get_key_type(attributes);
    if (!mldsa_key_type_is_key_pair(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (level == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    size_t pk_size = pqcp_mldsa_pk_size(level);
    size_t sig_size = pqcp_mldsa_sig_size(level);

    if (signature_size < sig_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Key buffer is [pk || sk], extract sk */
    if (key_buffer_size < pk_size + pqcp_mldsa_sk_size(level)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const uint8_t *sk = key_buffer + pk_size;

    psa_status_t status = mldsa_map_operation_status(
        pqcp_mldsa_sign(level, sk, input, input_length, NULL, 0, signature));
    if (status != PSA_SUCCESS) {
        return status;
    }

    *signature_length = sig_size;

    return PSA_SUCCESS;
}

/**
 * @brief Verify an ML-DSA signature
 */
psa_status_t pqcp_psa_mldsa_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *signature,
    size_t signature_length)
{
    psa_key_type_t type;
    pqcp_mldsa_level_t level = psa_alg_to_mldsa_level(alg);

    if ((attributes == NULL) || (key_buffer == NULL) || (signature == NULL) ||
        ((input == NULL) && (input_length != 0U))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    type = psa_get_key_type(attributes);
    if (!mldsa_key_type_is_supported(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (level == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    size_t pk_size = pqcp_mldsa_pk_size(level);
    size_t sig_size = pqcp_mldsa_sig_size(level);

    if (signature_length != sig_size) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    /* Key buffer contains public key (or pk at start of keypair) */
    if (key_buffer_size < pk_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const uint8_t *pk = key_buffer;

    return mldsa_map_operation_status(
        pqcp_mldsa_verify(level, pk, input, input_length, NULL, 0, signature));
}

/**
 * @brief Sign a hash with ML-DSA (HashML-DSA)
 */
psa_status_t pqcp_psa_mldsa_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    psa_key_type_t type;
    pqcp_mldsa_level_t level = psa_alg_to_mldsa_level(alg);

    if ((attributes == NULL) || (key_buffer == NULL) || (signature == NULL) ||
        (signature_length == NULL) || ((hash == NULL) && (hash_length != 0U))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    type = psa_get_key_type(attributes);
    if (!mldsa_key_type_is_key_pair(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (level == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    size_t pk_size = pqcp_mldsa_pk_size(level);
    size_t sig_size = pqcp_mldsa_sig_size(level);

    if (signature_size < sig_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (key_buffer_size < pk_size + pqcp_mldsa_sk_size(level)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const uint8_t *sk = key_buffer + pk_size;

    psa_status_t status = mldsa_map_operation_status(
        pqcp_mldsa_sign_hash(level, sk, hash, hash_length,
                             NULL, 0, NULL, 0, signature));
    if (status != PSA_SUCCESS) {
        return status;
    }

    *signature_length = sig_size;

    return PSA_SUCCESS;
}

/**
 * @brief Verify a hash signature with ML-DSA
 */
psa_status_t pqcp_psa_mldsa_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length)
{
    psa_key_type_t type;
    pqcp_mldsa_level_t level = psa_alg_to_mldsa_level(alg);

    if ((attributes == NULL) || (key_buffer == NULL) || (signature == NULL) ||
        ((hash == NULL) && (hash_length != 0U))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    type = psa_get_key_type(attributes);
    if (!mldsa_key_type_is_supported(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (level == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    size_t pk_size = pqcp_mldsa_pk_size(level);
    size_t sig_size = pqcp_mldsa_sig_size(level);

    if (signature_length != sig_size) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (key_buffer_size < pk_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const uint8_t *pk = key_buffer;

    return mldsa_map_operation_status(
        pqcp_mldsa_verify_hash(level, pk, hash, hash_length,
                               NULL, 0, NULL, 0, signature));
}

#endif /* CONFIG_MBEDTLS_PSA_CRYPTO_C */

#endif /* CONFIG_PQCP_PSA_DRIVER_MLDSA */
