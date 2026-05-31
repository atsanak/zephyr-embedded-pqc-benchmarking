/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP ACVP command library tests
 */

#include <zephyr/ztest.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/acvp_cmd.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/mlkem.h>

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#define TEST_BUFFER_SIZE 16384

static uint8_t work_buffer[TEST_BUFFER_SIZE];
static uint8_t response_buffer[TEST_BUFFER_SIZE];
static char line_buffer[TEST_BUFFER_SIZE * 2];
static char hex_buffer[TEST_BUFFER_SIZE * 2];
static char response_line[TEST_BUFFER_SIZE * 2];

static int run_command(const char *fmt, struct pqcp_acvp_response *resp, ...)
{
    va_list args;
    int written;
    int ret;

    pqcp_acvp_response_init(resp, response_buffer, sizeof(response_buffer));

    va_start(args, resp);
    written = vsnprintk(line_buffer, sizeof(line_buffer), fmt, args);
    va_end(args);

    zassert_true(written >= 0 && written < (int)sizeof(line_buffer),
                 "command buffer overflow");

    ret = pqcp_acvp_validate_command_line(line_buffer, strlen(line_buffer));
    if (ret != 0) {
        resp->result = (ret == -ENOSPC) ?
            PQCP_ACVP_ERR_BUFFER_TOO_SMALL : PQCP_ACVP_ERR_INVALID_CMD;
        return ret;
    }

    return pqcp_acvp_process_command(line_buffer, work_buffer,
                                     sizeof(work_buffer), resp);
}

static void bytes_to_hex(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    zassert_true(out_size >= (len * 2U) + 1U, "hex buffer too small");
    pqcp_acvp_bytes_to_hex(data, len, out);
}

static void assert_response_line(const struct pqcp_acvp_response *resp,
                                 const char *expected)
{
    zassert_equal(pqcp_acvp_format_response_line(resp, response_line,
                                                 sizeof(response_line)),
                  0);
    zassert_equal(strcmp(response_line, expected), 0,
                  "unexpected response line: %s", response_line);
}

static void assert_response_prefix(const struct pqcp_acvp_response *resp,
                                   const char *expected_prefix)
{
    zassert_equal(pqcp_acvp_format_response_line(resp, response_line,
                                                 sizeof(response_line)),
                  0);
    zassert_not_null(strstr(response_line, expected_prefix),
                     "response line %s missing prefix %s",
                     response_line, expected_prefix);
}

ZTEST(pqcp_acvp_serial, test_mlkem_roundtrip_commands)
{
    struct pqcp_acvp_response resp;
    size_t pk_size = pqcp_mlkem_pk_size(PQCP_MLKEM_768);
    size_t sk_size = pqcp_mlkem_sk_size(PQCP_MLKEM_768);
    size_t ct_size = pqcp_mlkem_ct_size(PQCP_MLKEM_768);
    uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    uint8_t shared_secret[PQCP_MLKEM_SS_SIZE];

    zassert_equal(
        run_command("SEED:DRBG:0:%s", &resp,
                    "000102030405060708090a0b0c0d0e0f"
                    "101112131415161718191a1b1c1d1e1f"
                    "202122232425262728292a2b2c2d2e2f"),
        0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    assert_response_line(&resp, "RESULT:OK");

    zassert_equal(run_command("KEYGEN:MLKEM:768:", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, pk_size + sk_size);
    assert_response_prefix(&resp, "RESULT:");
    memcpy(pk, resp.data, pk_size);
    memcpy(sk, resp.data + pk_size, sk_size);

    bytes_to_hex(pk, pk_size, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("ENCAPS:MLKEM:768:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, ct_size + PQCP_MLKEM_SS_SIZE);
    assert_response_prefix(&resp, "RESULT:");
    memcpy(shared_secret, resp.data + ct_size, sizeof(shared_secret));

    memcpy(work_buffer, resp.data, ct_size);
    memcpy(work_buffer + ct_size, sk, sk_size);
    bytes_to_hex(work_buffer, ct_size + sk_size, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("DECAPS:MLKEM:768:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, PQCP_MLKEM_SS_SIZE);
    assert_response_prefix(&resp, "RESULT:");
    zassert_mem_equal(resp.data, shared_secret, PQCP_MLKEM_SS_SIZE);
}

ZTEST(pqcp_acvp_serial, test_mldsa_roundtrip_and_invalid_signature)
{
    struct pqcp_acvp_response resp;
    static const uint8_t message[] = "acvp-message";
    size_t pk_size = pqcp_mldsa_pk_size(PQCP_MLDSA_65);
    size_t sk_size = pqcp_mldsa_sk_size(PQCP_MLDSA_65);
    size_t sig_size = pqcp_mldsa_sig_size(PQCP_MLDSA_65);
    uint8_t pk[PQCP_MLDSA_PK_SIZE_MAX];
    uint8_t sk[PQCP_MLDSA_SK_SIZE_MAX];

    zassert_equal(
        run_command("SEED:DRBG:0:%s", &resp,
                    "f0e0d0c0b0a090807060504030201000"
                    "00112233445566778899aabbccddeeff"
                    "0102030405060708090a0b0c0d0e0f10"),
        0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    assert_response_line(&resp, "RESULT:OK");

    zassert_equal(run_command("KEYGEN:MLDSA:65:", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, pk_size + sk_size);
    assert_response_prefix(&resp, "RESULT:");
    memcpy(pk, resp.data, pk_size);
    memcpy(sk, resp.data + pk_size, sk_size);

    memcpy(work_buffer, sk, sk_size);
    memcpy(work_buffer + sk_size, message, sizeof(message) - 1U);
    bytes_to_hex(work_buffer, sk_size + sizeof(message) - 1U,
                 hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("SIGN:MLDSA:65:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, sig_size);
    assert_response_prefix(&resp, "RESULT:");

    memcpy(work_buffer, pk, pk_size);
    memcpy(work_buffer + pk_size, message, sizeof(message) - 1U);
    memcpy(work_buffer + pk_size + sizeof(message) - 1U, resp.data, sig_size);
    bytes_to_hex(work_buffer, pk_size + sig_size + sizeof(message) - 1U,
                 hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("VERIFY:MLDSA:65:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, 0U);
    assert_response_line(&resp, "RESULT:OK");

    work_buffer[pk_size + sizeof(message) - 1U + sig_size - 1U] ^= 0x01U;
    bytes_to_hex(work_buffer, pk_size + sig_size + sizeof(message) - 1U,
                 hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("VERIFY:MLDSA:65:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_VERIFY_INVALID);
    assert_response_line(&resp, "RESULT:INVALID");
}

ZTEST(pqcp_acvp_serial, test_rejects_malformed_commands)
{
    struct pqcp_acvp_response resp;

    zassert_equal(run_command("KEYGEN:MLKEM", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_MISSING_ARGS);
    assert_response_line(&resp, "ERROR:MISSING_ARGS");

    zassert_equal(run_command("KEYGEN:MLKEM:not-a-level:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_LEVEL);
    assert_response_line(&resp, "ERROR:INVALID_LEVEL");

    zassert_equal(run_command("KEYGEN:UNKNOWN:768:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_ALG);
    assert_response_line(&resp, "ERROR:INVALID_ALG");

    zassert_equal(run_command("KEYGEN:MLKEM:768:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    zassert_equal(run_command("FOO:MLKEM:768:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    zassert_equal(run_command("HELP:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    zassert_equal(run_command("SELFTEST:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    zassert_equal(run_command("VERIFY:MLDSA:65:00:11", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");
}

ZTEST(pqcp_acvp_serial, test_rejects_invalid_hex_and_wrong_sizes)
{
    struct pqcp_acvp_response resp;
    size_t kem_pk_size = pqcp_mlkem_pk_size(PQCP_MLKEM_768);
    size_t ct_size = pqcp_mlkem_ct_size(PQCP_MLKEM_768);
    size_t kem_sk_size = pqcp_mlkem_sk_size(PQCP_MLKEM_768);
    size_t sig_sk_size = pqcp_mldsa_sk_size(PQCP_MLDSA_65);
    size_t sig_pk_size = pqcp_mldsa_pk_size(PQCP_MLDSA_65);
    size_t sig_size = pqcp_mldsa_sig_size(PQCP_MLDSA_65);
    size_t oversize_encaps_len = kem_pk_size + 1U;
    size_t oversize_decaps_len = ct_size + kem_sk_size + 1U;
    size_t oversize_sign_len = sig_sk_size + PQCP_ACVP_MAX_MESSAGE_BYTES + 1U;
    size_t oversize_verify_len = sig_pk_size + sig_size + PQCP_ACVP_MAX_MESSAGE_BYTES + 1U;

    zassert_equal(run_command("SEED:DRBG:0:abc", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_HEX);
    assert_response_line(&resp, "ERROR:INVALID_HEX");

    zassert_equal(run_command("ENCAPS:MLKEM:768:zz", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_HEX);
    assert_response_line(&resp, "ERROR:INVALID_HEX");

    zassert_equal(run_command("ENCAPS:MLKEM:999:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_LEVEL);
    assert_response_line(&resp, "ERROR:INVALID_LEVEL");

    zassert_equal(run_command("DECAPS:MLKEM:768:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");

    memset(work_buffer, 0x11, oversize_encaps_len);
    bytes_to_hex(work_buffer, oversize_encaps_len, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("ENCAPS:MLKEM:768:%s", &resp, hex_buffer), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");

    memset(work_buffer, 0x22, oversize_decaps_len);
    bytes_to_hex(work_buffer, oversize_decaps_len, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("DECAPS:MLKEM:768:%s", &resp, hex_buffer), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");

    zassert_equal(run_command("VERIFY:MLDSA:65:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");

    memset(work_buffer, 0x5a, oversize_sign_len);
    bytes_to_hex(work_buffer, oversize_sign_len, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("SIGN:MLDSA:65:%s", &resp, hex_buffer), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");

    memset(work_buffer, 0xa5, oversize_verify_len);
    bytes_to_hex(work_buffer, oversize_verify_len, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("VERIFY:MLDSA:65:%s", &resp, hex_buffer), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");
}

ZTEST(pqcp_acvp_serial, test_mlkem_negative_paths_recover_cleanly)
{
    struct pqcp_acvp_response resp;
    size_t pk_size = pqcp_mlkem_pk_size(PQCP_MLKEM_768);
    size_t sk_size = pqcp_mlkem_sk_size(PQCP_MLKEM_768);
    size_t ct_size = pqcp_mlkem_ct_size(PQCP_MLKEM_768);
    uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    uint8_t ciphertext[PQCP_MLKEM_CT_SIZE_MAX];
    uint8_t shared_secret[PQCP_MLKEM_SS_SIZE];

    zassert_equal(
        run_command("SEED:DRBG:0:%s", &resp,
                    "000102030405060708090a0b0c0d0e0f"
                    "101112131415161718191a1b1c1d1e1f"
                    "202122232425262728292a2b2c2d2e2f"),
        0);
    zassert_equal(resp.result, PQCP_ACVP_OK);

    zassert_equal(run_command("KEYGEN:MLKEM:768:", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    memcpy(pk, resp.data, pk_size);
    memcpy(sk, resp.data + pk_size, sk_size);

    bytes_to_hex(pk, pk_size - 1U, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("ENCAPS:MLKEM:768:%s", &resp, hex_buffer), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");

    memcpy(work_buffer, pk, pk_size);
    work_buffer[pk_size] = 0x5aU;
    bytes_to_hex(work_buffer, pk_size + 1U, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("ENCAPS:MLKEM:768:%s", &resp, hex_buffer), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");

    bytes_to_hex(pk, pk_size, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("ENCAPS:MLKEM:768:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    memcpy(ciphertext, resp.data, ct_size);
    memcpy(shared_secret, resp.data + ct_size, PQCP_MLKEM_SS_SIZE);

    memcpy(work_buffer, ciphertext, ct_size);
    memcpy(work_buffer + ct_size, sk, sk_size - 1U);
    bytes_to_hex(work_buffer, ct_size + sk_size - 1U, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("DECAPS:MLKEM:768:%s", &resp, hex_buffer), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");

    memcpy(work_buffer, ciphertext, ct_size);
    memcpy(work_buffer + ct_size, sk, sk_size);
    work_buffer[ct_size + sk_size] = 0xa5U;
    bytes_to_hex(work_buffer, ct_size + sk_size + 1U, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("DECAPS:MLKEM:768:%s", &resp, hex_buffer), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");

    memcpy(work_buffer, ciphertext, ct_size);
    memcpy(work_buffer + ct_size, sk, sk_size);
    bytes_to_hex(work_buffer, ct_size + sk_size, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("DECAPS:MLKEM:768:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_mem_equal(resp.data, shared_secret, PQCP_MLKEM_SS_SIZE);
}

ZTEST(pqcp_acvp_serial, test_serial_line_garbage_rejected_and_recovered)
{
    struct pqcp_acvp_response resp;

    zassert_equal(run_command("%s", &resp, "\x1b[31mKEYGEN:MLKEM:768:"), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    zassert_equal(run_command("KEYGEN:MLKEM:768:", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    assert_response_prefix(&resp, "RESULT:");
}

ZTEST(pqcp_acvp_serial, test_readline_timeout)
{
    static const char *partial = "KEYGEN:MLKEM:768:";
    static const char *slow_drip_prefix = "KEY";
    static const char *slow_drip_suffix = "GEN:";
    static const char *complete = "KEYGEN:MLKEM:768:\n";
    struct pqcp_acvp_serial_line_state state;
    struct pqcp_acvp_response resp;
    size_t line_len = 0U;
    char serial_line[64];

    pqcp_acvp_serial_line_reset(&state);
    serial_line[0] = '\0';

    for (size_t i = 0U; i < strlen(partial); ++i) {
        zassert_equal(
            pqcp_acvp_serial_line_consume_char(&state, partial[i],
                                               serial_line, sizeof(serial_line),
                                               &line_len),
            0);
    }

    zassert_equal(
        pqcp_acvp_serial_line_timeout(&state, serial_line, sizeof(serial_line)),
        -ETIMEDOUT);
    zassert_equal(strcmp(pqcp_acvp_result_str(PQCP_ACVP_ERR_LINE_TIMEOUT),
                         "TIMEOUT"),
                  0);
    zassert_equal(serial_line[0], '\0');
    zassert_false(state.active);
    zassert_false(state.overflow);
    zassert_equal(state.len, 0U);

    for (size_t i = 0U; i < strlen(slow_drip_prefix); ++i) {
        zassert_equal(
            pqcp_acvp_serial_line_consume_char(&state, slow_drip_prefix[i],
                                               serial_line, sizeof(serial_line),
                                               &line_len),
            0);
    }

    k_sleep(K_MSEC(CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS + 20));

    zassert_equal(
        pqcp_acvp_serial_line_consume_char(&state, slow_drip_suffix[0],
                                           serial_line, sizeof(serial_line),
                                           &line_len),
        -ETIMEDOUT);
    zassert_equal(serial_line[0], '\0');
    zassert_false(state.active);
    zassert_false(state.overflow);
    zassert_equal(state.len, 0U);

    pqcp_acvp_response_init(&resp, response_buffer, sizeof(response_buffer));
    resp.result = PQCP_ACVP_ERR_LINE_TIMEOUT;
    resp.data_len = 0U;
    assert_response_line(&resp, "ERROR:TIMEOUT");

    for (size_t i = 0U; i < strlen(complete) - 1U; ++i) {
        zassert_equal(
            pqcp_acvp_serial_line_consume_char(&state, complete[i],
                                               serial_line, sizeof(serial_line),
                                               &line_len),
            0);
    }

    zassert_equal(
        pqcp_acvp_serial_line_consume_char(&state, '\n',
                                           serial_line, sizeof(serial_line),
                                           &line_len),
        1);
    zassert_equal(strcmp(serial_line, partial), 0);
    zassert_equal(line_len, strlen(partial));

    zassert_equal(run_command("KEYGEN:MLKEM:768:", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    assert_response_prefix(&resp, "RESULT:");
}

ZTEST(pqcp_acvp_serial, test_hex_decoder_rejects_oversize_payload)
{
    size_t out_len = 0U;
    uint8_t small_buffer[4];

    zassert_equal(
        pqcp_acvp_hex_to_bytes("001122334455", small_buffer, &out_len,
                               sizeof(small_buffer)),
        -ENOSPC);
}

ZTEST(pqcp_acvp_serial, test_hex_decoder_accepts_mixed_case_without_libc_parse)
{
    static const uint8_t expected[] = {
        0x00U, 0x1aU, 0x2bU, 0x3cU, 0x4dU, 0x5eU, 0x6fU,
        0x7aU, 0x8bU, 0x9cU, 0xadU, 0xbeU, 0xcfU, 0xd0U,
        0xe1U, 0xf2U,
    };
    size_t out_len = 0U;

    memset(work_buffer, 0, sizeof(expected));
    zassert_equal(
        pqcp_acvp_hex_to_bytes("001A2b3C4d5E6f7A8b9CadBEcFd0E1f2",
                               work_buffer, &out_len, sizeof(work_buffer)),
        0);
    zassert_equal(out_len, sizeof(expected));
    zassert_mem_equal(work_buffer, expected, sizeof(expected));
}

ZTEST(pqcp_acvp_serial, test_hex_decoder_rejects_invalid_nibbles_without_partial_success)
{
    size_t out_len = 1234U;

    zassert_equal(pqcp_acvp_hex_to_bytes("001x", work_buffer, &out_len,
                                         sizeof(work_buffer)),
                  -EINVAL);
    zassert_equal(out_len, 1234U);

    zassert_equal(pqcp_acvp_hex_to_bytes("abc", work_buffer, &out_len,
                                         sizeof(work_buffer)),
                  -EINVAL);
    zassert_equal(out_len, 1234U);
}

ZTEST(pqcp_acvp_serial, test_wrong_size_payload_rejected_before_decode_write)
{
    struct pqcp_acvp_response resp;

    memset(work_buffer, 0xa5, 16U);
    zassert_equal(run_command("ENCAPS:MLKEM:768:001122", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    for (size_t i = 0U; i < 16U; ++i) {
        zassert_equal(work_buffer[i], 0xa5,
                      "wrong-size preflight should not decode byte %zu", i);
    }
    assert_response_line(&resp, "ERROR:WRONG_SIZE");
}

ZTEST(pqcp_acvp_serial, test_help_and_selftest_commands)
{
    struct pqcp_acvp_response resp;

    zassert_equal(run_command("HELP::", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, 0U);
    assert_response_line(&resp, "RESULT:OK");

    zassert_equal(run_command("SELFTEST::", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, 0U);
    assert_response_line(&resp, "RESULT:OK");
}

ZTEST(pqcp_acvp_serial, test_result_strings_are_stable)
{
    static const struct {
        enum pqcp_acvp_result result;
        const char *expected;
    } cases[] = {
        { PQCP_ACVP_OK, "OK" },
        { PQCP_ACVP_ERR_INVALID_HEX, "INVALID_HEX" },
        { PQCP_ACVP_ERR_INVALID_LEVEL, "INVALID_LEVEL" },
        { PQCP_ACVP_ERR_INVALID_ALG, "INVALID_ALG" },
        { PQCP_ACVP_ERR_INVALID_CMD, "INVALID_CMD" },
        { PQCP_ACVP_ERR_MISSING_ARGS, "MISSING_ARGS" },
        { PQCP_ACVP_ERR_WRONG_SIZE, "WRONG_SIZE" },
        { PQCP_ACVP_ERR_KEYGEN, "KEYGEN_FAILED" },
        { PQCP_ACVP_ERR_ENCAPS, "ENCAPS_FAILED" },
        { PQCP_ACVP_ERR_DECAPS, "DECAPS_FAILED" },
        { PQCP_ACVP_ERR_SIGN, "SIGN_FAILED" },
        { PQCP_ACVP_ERR_VERIFY, "VERIFY_FAILED" },
        { PQCP_ACVP_ERR_SEED, "SEED_FAILED" },
        { PQCP_ACVP_ERR_NOT_ENABLED, "NOT_ENABLED" },
        { PQCP_ACVP_ERR_BUFFER_TOO_SMALL, "BUFFER_TOO_SMALL" },
        { PQCP_ACVP_ERR_TIMEOUT, "TIMEOUT" },
        { PQCP_ACVP_VERIFY_INVALID, "INVALID" },
    };

    for (size_t i = 0U; i < ARRAY_SIZE(cases); ++i) {
        const char *result_str = pqcp_acvp_result_str(cases[i].result);

        zassert_not_null(result_str);
        zassert_equal(strcmp(result_str, cases[i].expected), 0,
                      "unexpected string for ACVP result %d",
                      (int)cases[i].result);
    }

    zassert_equal(strcmp(pqcp_acvp_result_str((enum pqcp_acvp_result)999),
                         "UNKNOWN"),
                  0);
}

ZTEST(pqcp_acvp_serial, test_response_formatter_serializes_public_wire_forms)
{
    struct pqcp_acvp_response resp;
    static uint8_t payload[] = { 0x00U, 0xabU, 0x7fU };

    pqcp_acvp_response_init(&resp, payload, sizeof(payload));

    resp.result = PQCP_ACVP_OK;
    resp.data_len = 0U;
    assert_response_line(&resp, "RESULT:OK");

    resp.result = PQCP_ACVP_VERIFY_INVALID;
    resp.data_len = 0U;
    assert_response_line(&resp, "RESULT:INVALID");

    resp.result = PQCP_ACVP_ERR_INVALID_CMD;
    resp.data_len = 0U;
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    resp.result = PQCP_ACVP_OK;
    resp.data = payload;
    resp.data_len = sizeof(payload);
    assert_response_line(&resp, "RESULT:00ab7f");
}

ZTEST(pqcp_acvp_serial, test_response_formatter_rejects_tiny_buffer)
{
    struct pqcp_acvp_response resp;
    char tiny_buffer[4];
    char exact_error_buffer[sizeof("ERROR:INVALID_CMD") - 1U];
    char exact_ok_buffer[sizeof("RESULT:OK") - 1U];
    char exact_payload_buffer[sizeof("RESULT:00") - 1U];
    uint8_t payload[] = { 0x00U };

    pqcp_acvp_response_init(&resp, response_buffer, sizeof(response_buffer));
    resp.result = PQCP_ACVP_ERR_INVALID_CMD;

    zassert_equal(
        pqcp_acvp_format_response_line(&resp, tiny_buffer, sizeof(tiny_buffer)),
        -ENOSPC);
    zassert_equal(
        pqcp_acvp_format_response_line(&resp, exact_error_buffer,
                                       sizeof(exact_error_buffer)),
        -ENOSPC);

    resp.result = PQCP_ACVP_OK;
    resp.data_len = 0U;
    zassert_equal(
        pqcp_acvp_format_response_line(&resp, exact_ok_buffer,
                                       sizeof(exact_ok_buffer)),
        -ENOSPC);

    resp.data = payload;
    resp.data_len = sizeof(payload);
    zassert_equal(
        pqcp_acvp_format_response_line(&resp, exact_payload_buffer,
                                       sizeof(exact_payload_buffer)),
        -ENOSPC);
}

ZTEST(pqcp_acvp_serial, test_response_formatter_accepts_exact_plus_nul_capacity)
{
    struct pqcp_acvp_response resp;
    char error_buffer[sizeof("ERROR:INVALID_CMD")];
    char invalid_buffer[sizeof("RESULT:INVALID")];
    char ok_buffer[sizeof("RESULT:OK")];
    char payload_buffer[sizeof("RESULT:00ff")];
    uint8_t payload[] = { 0x00U, 0xffU };

    pqcp_acvp_response_init(&resp, response_buffer, sizeof(response_buffer));
    resp.result = PQCP_ACVP_ERR_INVALID_CMD;
    zassert_equal(pqcp_acvp_format_response_line(&resp, error_buffer,
                                                 sizeof(error_buffer)),
                  0);
    zassert_equal(strcmp(error_buffer, "ERROR:INVALID_CMD"), 0);

    resp.result = PQCP_ACVP_VERIFY_INVALID;
    zassert_equal(pqcp_acvp_format_response_line(&resp, invalid_buffer,
                                                 sizeof(invalid_buffer)),
                  0);
    zassert_equal(strcmp(invalid_buffer, "RESULT:INVALID"), 0);

    resp.result = PQCP_ACVP_OK;
    resp.data_len = 0U;
    zassert_equal(pqcp_acvp_format_response_line(&resp, ok_buffer,
                                                 sizeof(ok_buffer)),
                  0);
    zassert_equal(strcmp(ok_buffer, "RESULT:OK"), 0);

    resp.data = payload;
    resp.data_len = sizeof(payload);
    zassert_equal(pqcp_acvp_format_response_line(&resp, payload_buffer,
                                                 sizeof(payload_buffer)),
                  0);
    zassert_equal(strcmp(payload_buffer, "RESULT:00ff"), 0);
}

ZTEST(pqcp_acvp_serial, test_response_formatter_rejects_size_wraparound)
{
    struct pqcp_acvp_response resp;
    uint8_t payload[] = { 0x00U };

    pqcp_acvp_response_init(&resp, response_buffer, sizeof(response_buffer));
    resp.result = PQCP_ACVP_OK;
    resp.data = payload;
    resp.data_len = (SIZE_MAX / 2U) + 1U;

    zassert_equal(pqcp_acvp_format_response_line(&resp, response_line,
                                                 sizeof(response_line)),
                  -ENOSPC);
}

ZTEST(pqcp_acvp_serial, test_hex_codec_roundtrips_all_byte_values)
{
    uint8_t input[256];
    uint8_t output[256];
    size_t output_len = 0U;

    for (size_t i = 0U; i < ARRAY_SIZE(input); ++i) {
        input[i] = (uint8_t)i;
    }

    pqcp_acvp_bytes_to_hex(input, sizeof(input), hex_buffer);
    zassert_equal(strlen(hex_buffer), sizeof(input) * 2U);
    zassert_equal(pqcp_acvp_hex_to_bytes(hex_buffer, output, &output_len,
                                         sizeof(output)),
                  0);
    zassert_equal(output_len, sizeof(input));
    zassert_mem_equal(output, input, sizeof(input));
}

/*
 * Stress-oriented parser coverage is compiled only when overlay-fuzz.conf
 * enables CONFIG_PQCP_FUZZ_TESTS for this test image.
 */
#if defined(CONFIG_PQCP_FUZZ_TESTS)
static uint32_t fuzz_state = 0x8f23d91bU;

static uint32_t fuzz_next(void)
{
    fuzz_state = (1103515245U * fuzz_state) + 12345U;
    return fuzz_state;
}

ZTEST(pqcp_acvp_serial, test_stress_randomized_command_parsing)
{
    static const char *seed_hex =
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f";
    struct pqcp_acvp_response resp;
    int ret;

    for (size_t i = 0U; i < 64U; ++i) {
        switch (fuzz_next() % 8U) {
        case 0U:
            ret = run_command("HELP::", &resp);
            zassert_equal(ret, 0);
            break;
        case 1U:
            ret = run_command("SELFTEST::", &resp);
            zassert_equal(ret, 0);
            break;
        case 2U:
            ret = run_command("SEED:DRBG:0:%s", &resp, seed_hex);
            zassert_equal(ret, 0);
            break;
        case 3U:
            ret = run_command("KEYGEN:MLKEM:768:", &resp);
            zassert_equal(ret, 0);
            break;
        case 4U:
            ret = run_command("KEYGEN:MLDSA:65:", &resp);
            zassert_equal(ret, 0);
            break;
        case 5U:
            ret = run_command("VERIFY:MLDSA:65:xyz", &resp);
            zassert_true(ret < 0);
            break;
        case 6U:
            ret = run_command("ENCAPS:MLKEM:%u:00", &resp,
                              500U + (fuzz_next() % 700U));
            zassert_true(ret < 0);
            break;
        default:
            ret = run_command("NOPE:MLKEM:768:00:extra", &resp);
            zassert_true(ret < 0);
            break;
        }

        zassert_equal(pqcp_acvp_format_response_line(&resp, response_line,
                                                     sizeof(response_line)),
                      0);
        zassert_true(strncmp(response_line, "RESULT:", 7) == 0 ||
                     strncmp(response_line, "ERROR:", 6) == 0,
                     "unexpected response format: %s", response_line);
    }
}
#endif

static void *pqcp_acvp_setup(void)
{
    return NULL;
}

ZTEST_SUITE(pqcp_acvp_serial, NULL, pqcp_acvp_setup, NULL, NULL, NULL);
