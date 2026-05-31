/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - PSA ML-KEM Driver Shim
 *
 * PSA Crypto driver for ML-KEM (FIPS-203) operations.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C
#include <psa/crypto.h>
#include <psa/crypto_types.h>
#include <psa/crypto_values.h>
#endif

#include <string.h>

/*
 * PSA Algorithm and Key Type Definitions for ML-KEM
 *
 * These should eventually come from psa/crypto_values.h when
 * ML-KEM support is standardized. For now, we define provisional values.
 */

#ifndef PSA_ALG_ML_KEM_512
/* ML-KEM algorithm identifiers (provisional) */
#define PSA_ALG_ML_KEM_512     ((psa_algorithm_t)0x06000E00)
#define PSA_ALG_ML_KEM_768     ((psa_algorithm_t)0x06000E01)
#define PSA_ALG_ML_KEM_1024    ((psa_algorithm_t)0x06000E02)

/* ML-KEM key types (provisional) */
#define PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY   ((psa_key_type_t)0x4002)
#define PSA_KEY_TYPE_ML_KEM_KEY_PAIR     ((psa_key_type_t)0x7002)
#endif

#ifdef CONFIG_PQCP_PSA_DRIVER_MLKEM

/*
 * Helper functions
 */

static pqcp_mlkem_level_t psa_alg_to_mlkem_level(psa_algorithm_t alg)
{
    switch (alg) {
    case PSA_ALG_ML_KEM_512:  return PQCP_MLKEM_512;
    case PSA_ALG_ML_KEM_768:  return PQCP_MLKEM_768;
    case PSA_ALG_ML_KEM_1024: return PQCP_MLKEM_1024;
    default: return 0;
    }
}

static size_t mlkem_level_to_pk_bits(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return PQCP_MLKEM_512_PK_SIZE * 8;
    case PQCP_MLKEM_768:  return PQCP_MLKEM_768_PK_SIZE * 8;
    case PQCP_MLKEM_1024: return PQCP_MLKEM_1024_PK_SIZE * 8;
    default: return 0;
    }
}

static bool mlkem_key_type_is_public(psa_key_type_t type)
{
    return type == PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY;
}

static bool mlkem_key_type_is_key_pair(psa_key_type_t type)
{
    return type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR;
}

static bool mlkem_key_type_is_supported(psa_key_type_t type)
{
    return mlkem_key_type_is_public(type) || mlkem_key_type_is_key_pair(type);
}

static psa_status_t mlkem_validate_attributes(
    const psa_key_attributes_t *attributes,
    psa_key_type_t *type,
    pqcp_mlkem_level_t *level)
{
    pqcp_mlkem_level_t resolved_level;

    if ((attributes == NULL) || (type == NULL) || (level == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *type = psa_get_key_type(attributes);
    resolved_level = psa_alg_to_mlkem_level(psa_get_key_algorithm(attributes));

    if (resolved_level == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (!mlkem_key_type_is_supported(*type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *level = resolved_level;

    return PSA_SUCCESS;
}

static psa_status_t mlkem_map_operation_status(int ret)
{
    switch (ret) {
    case PQCP_MLKEM_SUCCESS:
        return PSA_SUCCESS;
    case PQCP_MLKEM_ERR_INVALID_ARG:
        return PSA_ERROR_INVALID_ARGUMENT;
    case PQCP_MLKEM_ERR_UNSUPPORTED:
        return PSA_ERROR_NOT_SUPPORTED;
    case PQCP_MLKEM_ERR_RNG:
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    default:
        return PSA_ERROR_HARDWARE_FAILURE;
    }
}

#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C

/*
 * PSA Driver Entry Points for ML-KEM
 */

/**
 * @brief Generate an ML-KEM keypair
 */
psa_status_t pqcp_psa_mlkem_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length)
{
    psa_key_type_t type;
    pqcp_mlkem_level_t level;
    psa_status_t status = mlkem_validate_attributes(attributes, &type, &level);

    if (status != PSA_SUCCESS) {
        return status;
    }

    if (!mlkem_key_type_is_key_pair(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if ((key_buffer == NULL) || (key_buffer_length == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t pk_size = pqcp_mlkem_pk_size(level);
    size_t sk_size = pqcp_mlkem_sk_size(level);
    size_t total_size = pk_size + sk_size;

    if (key_buffer_size < total_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Generate keypair: key_buffer = [pk || sk] */
    uint8_t *pk = key_buffer;
    uint8_t *sk = key_buffer + pk_size;

    status = mlkem_map_operation_status(pqcp_mlkem_keypair(level, pk, sk));
    if (status != PSA_SUCCESS) {
        return status;
    }

    *key_buffer_length = total_size;

    return PSA_SUCCESS;
}

/**
 * @brief Import an ML-KEM key
 */
psa_status_t pqcp_psa_mlkem_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits)
{
    psa_key_type_t type;
    pqcp_mlkem_level_t level;
    psa_status_t status = mlkem_validate_attributes(attributes, &type, &level);

    if (status != PSA_SUCCESS) {
        return status;
    }

    if ((data == NULL) || (key_buffer == NULL) ||
        (key_buffer_length == NULL) || (bits == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t pk_size = pqcp_mlkem_pk_size(level);
    size_t sk_size = pqcp_mlkem_sk_size(level);

    if (mlkem_key_type_is_public(type)) {
        if (data_length != pk_size) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (key_buffer_size < pk_size) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        memcpy(key_buffer, data, pk_size);
        *key_buffer_length = pk_size;
        *bits = mlkem_level_to_pk_bits(level);

    } else if (mlkem_key_type_is_key_pair(type)) {
        size_t total_size = pk_size + sk_size;

        if (data_length != total_size) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (key_buffer_size < total_size) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        memcpy(key_buffer, data, total_size);
        *key_buffer_length = total_size;
        *bits = mlkem_level_to_pk_bits(level);

    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

/**
 * @brief Export an ML-KEM public key
 */
psa_status_t pqcp_psa_mlkem_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length)
{
    psa_key_type_t type;
    pqcp_mlkem_level_t level;
    psa_status_t status = mlkem_validate_attributes(attributes, &type, &level);

    if (status != PSA_SUCCESS) {
        return status;
    }

    if ((key_buffer == NULL) || (data == NULL) || (data_length == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t pk_size = pqcp_mlkem_pk_size(level);

    if (data_size < pk_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (mlkem_key_type_is_public(type)) {
        if (key_buffer_size < pk_size) {
            return PSA_ERROR_CORRUPTION_DETECTED;
        }
        memcpy(data, key_buffer, pk_size);

    } else if (mlkem_key_type_is_key_pair(type)) {
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
 * @brief Encapsulate using ML-KEM
 *
 * Note: PSA doesn't have a standard KEM API yet, so this uses
 * a provisional interface that may change.
 */
psa_status_t pqcp_psa_mlkem_encapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,      /* Public key */
    size_t key_buffer_size,
    psa_algorithm_t alg,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length)
{
    psa_key_type_t type;
    pqcp_mlkem_level_t level = psa_alg_to_mlkem_level(alg);

    if ((attributes == NULL) || (ciphertext == NULL) ||
        (ciphertext_length == NULL) || (shared_secret == NULL) ||
        (shared_secret_length == NULL) || (key_buffer == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    type = psa_get_key_type(attributes);
    if (!mlkem_key_type_is_supported(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (!mlkem_key_type_is_public(type) && !mlkem_key_type_is_key_pair(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (level == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    size_t pk_size = pqcp_mlkem_pk_size(level);
    size_t ct_size = pqcp_mlkem_ct_size(level);

    if (key_buffer_size < pk_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ciphertext_size < ct_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (shared_secret_size < PQCP_MLKEM_SS_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_status_t status = mlkem_map_operation_status(
        pqcp_mlkem_encapsulate(level, key_buffer, ciphertext, shared_secret));
    if (status != PSA_SUCCESS) {
        return status;
    }

    *ciphertext_length = ct_size;
    *shared_secret_length = PQCP_MLKEM_SS_SIZE;

    return PSA_SUCCESS;
}

/**
 * @brief Decapsulate using ML-KEM
 */
psa_status_t pqcp_psa_mlkem_decapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,      /* Key pair [pk || sk] */
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length)
{
    psa_key_type_t type;
    pqcp_mlkem_level_t level = psa_alg_to_mlkem_level(alg);

    if ((attributes == NULL) || (key_buffer == NULL) || (ciphertext == NULL) ||
        (shared_secret == NULL) || (shared_secret_length == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    type = psa_get_key_type(attributes);
    if (!mlkem_key_type_is_key_pair(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (level == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    size_t pk_size = pqcp_mlkem_pk_size(level);
    size_t sk_size = pqcp_mlkem_sk_size(level);
    size_t ct_size = pqcp_mlkem_ct_size(level);

    if (key_buffer_size < pk_size + sk_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ciphertext_length != ct_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (shared_secret_size < PQCP_MLKEM_SS_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Extract secret key from keypair */
    const uint8_t *sk = key_buffer + pk_size;

    psa_status_t status = mlkem_map_operation_status(
        pqcp_mlkem_decapsulate(level, ciphertext, sk, shared_secret));
    if (status != PSA_SUCCESS) {
        /*
         * Note: ML-KEM uses implicit rejection, so successful decapsulation still
         * yields a shared secret for invalid ciphertexts. Any error that surfaces
         * here reflects argument/support/internal failures in the local wrapper.
         */
        return status;
    }

    *shared_secret_length = PQCP_MLKEM_SS_SIZE;

    return PSA_SUCCESS;
}

#endif /* CONFIG_MBEDTLS_PSA_CRYPTO_C */

#endif /* CONFIG_PQCP_PSA_DRIVER_MLKEM */
