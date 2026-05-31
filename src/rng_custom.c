/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Custom RNG Backend
 *
 * Allows application-provided RNG implementation.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/rng.h>

/*
 * For custom RNG, initialization is handled by the application
 * calling pqcp_rng_register() with their implementation.
 */

int pqcp_rng_backend_init(void)
{
    /* Custom RNG requires explicit registration */
    return PQCP_RNG_SUCCESS;
}

int pqcp_rng_backend_get_bytes(uint8_t *out, size_t len)
{
    /* This should not be called - custom iface handles it in rng_common.c */
    (void)out;
    (void)len;
    return PQCP_RNG_ERR_NOT_INIT;
}
