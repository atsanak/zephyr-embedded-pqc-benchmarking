/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - PSA Crypto RNG Backend
 *
 * Uses PSA Crypto's psa_generate_random() for random number generation.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/rng.h>

#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C
#include <psa/crypto.h>
#endif

int pqcp_rng_backend_init(void)
{
#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return PQCP_RNG_ERR_ENTROPY;
    }
    return PQCP_RNG_SUCCESS;
#else
    return PQCP_RNG_ERR_UNSUPPORTED;
#endif
}

int pqcp_rng_backend_get_bytes(uint8_t *out, size_t len)
{
#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C
    psa_status_t status = psa_generate_random(out, len);

    if (status == PSA_SUCCESS) {
        return PQCP_RNG_SUCCESS;
    } else if (status == PSA_ERROR_INVALID_ARGUMENT) {
        return PQCP_RNG_ERR_INVALID_ARG;
    } else {
        return PQCP_RNG_ERR_ENTROPY;
    }
#else
    (void)out;
    (void)len;
    return PQCP_RNG_ERR_UNSUPPORTED;
#endif
}
