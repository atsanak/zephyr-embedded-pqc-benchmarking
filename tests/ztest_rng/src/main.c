/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP RNG Tests
 *
 * Zephyr ztest suite for RNG operations.
 */

#include <zephyr/ztest.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/*
 * Basic RNG Tests
 */

ZTEST(pqcp_rng, test_rng_init)
{
    int ret = pqcp_rng_init();
    zassert_equal(ret, PQCP_RNG_SUCCESS, "RNG init failed: %d", ret);

    zassert_true(pqcp_rng_is_ready(), "RNG should be ready after init");
}

ZTEST(pqcp_rng, test_rng_get_bytes_null)
{
    int ret = pqcp_rng_get_bytes(NULL, 32);
    zassert_equal(ret, PQCP_RNG_ERR_INVALID_ARG,
                  "Should reject NULL buffer");
}

ZTEST(pqcp_rng, test_rng_get_bytes_zero_len)
{
    uint8_t buf[1];
    int ret = pqcp_rng_get_bytes(buf, 0);
    zassert_equal(ret, PQCP_RNG_SUCCESS, "Zero length should succeed");
}

ZTEST(pqcp_rng, test_rng_get_bytes_success)
{
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));

    int ret = pqcp_rng_get_bytes(buf, sizeof(buf));
    zassert_equal(ret, PQCP_RNG_SUCCESS, "RNG get_bytes failed: %d", ret);

    /* Buffer should not be all zeros */
    bool has_nonzero = false;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) {
            has_nonzero = true;
            break;
        }
    }
    zassert_true(has_nonzero, "Random bytes are all zeros");
}

ZTEST(pqcp_rng, test_rng_different_calls)
{
    uint8_t buf1[32];
    uint8_t buf2[32];

    int ret = pqcp_rng_get_bytes(buf1, sizeof(buf1));
    zassert_equal(ret, PQCP_RNG_SUCCESS);

    ret = pqcp_rng_get_bytes(buf2, sizeof(buf2));
    zassert_equal(ret, PQCP_RNG_SUCCESS);

    /* Two calls should produce different output */
    zassert_true(memcmp(buf1, buf2, sizeof(buf1)) != 0,
                 "Two RNG calls produced identical output");
}

ZTEST(pqcp_rng, test_rng_large_buffer)
{
    static uint8_t large_buf[1024];

    int ret = pqcp_rng_get_bytes(large_buf, sizeof(large_buf));
    zassert_equal(ret, PQCP_RNG_SUCCESS, "Large buffer RNG failed: %d", ret);
}

ZTEST(pqcp_rng, test_rng_multiple_small_calls)
{
    /* Multiple small calls should all succeed */
    for (int i = 0; i < 100; i++) {
        uint8_t buf[8];
        int ret = pqcp_rng_get_bytes(buf, sizeof(buf));
        zassert_equal(ret, PQCP_RNG_SUCCESS,
                      "RNG call %d failed: %d", i, ret);
    }
}

ZTEST(pqcp_rng, test_rng_callback_available)
{
    /* Test that randombytes callback is available */
    pqcp_randombytes_fn fn = pqcp_rng_get_randombytes();
    zassert_not_null(fn, "randombytes callback is NULL");

    /* Call it */
    uint8_t buf[16];
    int ret = fn(buf, sizeof(buf));
    zassert_equal(ret, PQCP_RNG_SUCCESS, "Callback failed: %d", ret);
}

/*
 * Test Suite
 */

static void *pqcp_rng_setup(void)
{
    return NULL;
}

ZTEST_SUITE(pqcp_rng, NULL, pqcp_rng_setup, NULL, NULL, NULL);
