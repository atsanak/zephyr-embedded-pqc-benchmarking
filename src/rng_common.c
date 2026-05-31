/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - RNG Common Interface
 *
 * Provides the common RNG abstraction used by ML-KEM and ML-DSA wrappers.
 */
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/* Global RNG state */
static struct {
    const pqcp_rng_iface_t *custom_iface;
    bool initialized;
    struct k_mutex lock;
} rng_state;

/* Forward declaration of backend-specific functions */
extern int pqcp_rng_backend_init(void);
extern int pqcp_rng_backend_get_bytes(uint8_t *out, size_t len);

int pqcp_rng_init(void)
{
    if (rng_state.initialized) {
        return PQCP_RNG_SUCCESS;
    }

    k_mutex_init(&rng_state.lock);

    int ret = pqcp_rng_backend_init();
    if (ret == 0) {
        rng_state.initialized = true;
    }

    return ret;
}

int pqcp_rng_is_ready(void)
{
    return rng_state.initialized;
}

int pqcp_rng_register(const pqcp_rng_iface_t *iface)
{
    if (iface == NULL || iface->get_bytes == NULL) {
        return PQCP_RNG_ERR_INVALID_ARG;
    }

    k_mutex_lock(&rng_state.lock, K_FOREVER);
    rng_state.custom_iface = iface;
    rng_state.initialized = true;
    k_mutex_unlock(&rng_state.lock);

    return PQCP_RNG_SUCCESS;
}

int pqcp_rng_get_bytes(uint8_t *out, size_t len)
{
    if (out == NULL) {
        return PQCP_RNG_ERR_INVALID_ARG;
    }

    if (len == 0) {
        return PQCP_RNG_SUCCESS;
    }

    if (!rng_state.initialized) {
        return PQCP_RNG_ERR_NOT_INIT;
    }

#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    /* Deterministic mode uses backend directly, bypassing custom interface */
    return pqcp_rng_backend_get_bytes(out, len);
#elif defined(CONFIG_PQCP_RNG_CUSTOM)
    if (rng_state.custom_iface != NULL) {
        return rng_state.custom_iface->get_bytes(
            rng_state.custom_iface->ctx, out, len);
    }
    return PQCP_RNG_ERR_NOT_INIT;
#else
    return pqcp_rng_backend_get_bytes(out, len);
#endif
}

/*
 * randombytes callback for mlkem-native and mldsa-native.
 *
 * Both libraries expect a function with this exact signature to be
 * provided externally. They call it via their internal wrappers
 * (mlk_randombytes / mld_randombytes).
 */
int randombytes(uint8_t *out, size_t len)
{
    return pqcp_rng_get_bytes(out, len);
}

/* Legacy callback wrapper */
static int pqcp_randombytes_callback(uint8_t *out, size_t len)
{
    return pqcp_rng_get_bytes(out, len);
}

pqcp_randombytes_fn pqcp_rng_get_randombytes(void)
{
    return pqcp_randombytes_callback;
}

/* Module initialization */
static int pqcp_rng_sys_init(void)
{
    return pqcp_rng_init();
}

SYS_INIT(pqcp_rng_sys_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
