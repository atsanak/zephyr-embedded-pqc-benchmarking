/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Zephyr Entropy RNG Backend
 *
 * Uses Zephyr's sys_csrand_get() for cryptographically secure random bytes.
 * This is the recommended backend for production use.
 */

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/*
 * IMPORTANT: sys_csrand_get() is the ONLY Zephyr API safe for cryptographic
 * use. DO NOT use sys_rand_get() or sys_rand32_get() for crypto - they may
 * use weak PRNGs like xoshiro128++.
 *
 * sys_csrand_get() is backed by:
 * - Hardware TRNG on supported SoCs (STM32 RNG, nRF RNG, MCUX RNGA, etc.)
 * - CTR-DRBG seeded from entropy driver
 * - Requires CONFIG_ENTROPY_GENERATOR=y
 */

int pqcp_rng_backend_init(void)
{
#ifdef CONFIG_ENTROPY_GENERATOR
    /* sys_csrand_get initialization is handled by Zephyr */
    return PQCP_RNG_SUCCESS;
#else
    /* No entropy source available */
    return PQCP_RNG_ERR_UNSUPPORTED;
#endif
}

int pqcp_rng_backend_get_bytes(uint8_t *out, size_t len)
{
#ifdef CONFIG_ENTROPY_GENERATOR
    /*
     * sys_csrand_get() returns:
     *  0 on success
     * -EINVAL if buffer is NULL
     * -EIO if entropy source fails
     */
    int ret = sys_csrand_get(out, len);

    if (ret == 0) {
        return PQCP_RNG_SUCCESS;
    } else if (ret == -EINVAL) {
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
