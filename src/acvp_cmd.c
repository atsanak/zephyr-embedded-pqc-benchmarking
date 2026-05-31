/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP ACVP Command Library Implementation
 */

#include <pqcp_zephyr/acvp_cmd.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <zephyr/kernel.h>

#include <string.h>
#include <stdbool.h>
#include <limits.h>

#ifndef CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS
#define CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS 2000
#endif

static struct k_timer acvp_serial_line_timer;
static bool acvp_serial_line_timer_initialized;
static bool acvp_serial_line_timer_armed;

static const uint8_t acvp_hex_decode_table[256] = {
    ['0'] = 1U, ['1'] = 2U, ['2'] = 3U, ['3'] = 4U,
    ['4'] = 5U, ['5'] = 6U, ['6'] = 7U, ['7'] = 8U,
    ['8'] = 9U, ['9'] = 10U,
    ['a'] = 11U, ['b'] = 12U, ['c'] = 13U,
    ['d'] = 14U, ['e'] = 15U, ['f'] = 16U,
    ['A'] = 11U, ['B'] = 12U, ['C'] = 13U,
    ['D'] = 14U, ['E'] = 15U, ['F'] = 16U,
};

static bool acvp_serial_line_has_partial(
    const struct pqcp_acvp_serial_line_state *state)
{
    return state != NULL &&
           (state->active || state->overflow || state->len > 0U);
}

static void acvp_serial_line_timer_ensure(void)
{
    if (!acvp_serial_line_timer_initialized) {
        k_timer_init(&acvp_serial_line_timer, NULL, NULL);
        acvp_serial_line_timer_initialized = true;
    }
}

static void acvp_serial_line_timer_stop(void)
{
    if (acvp_serial_line_timer_initialized && acvp_serial_line_timer_armed) {
        k_timer_stop(&acvp_serial_line_timer);
    }
    acvp_serial_line_timer_armed = false;
}

static void acvp_serial_line_timer_start_once(void)
{
    acvp_serial_line_timer_ensure();
    if (!acvp_serial_line_timer_armed) {
        k_timer_start(&acvp_serial_line_timer,
                      K_MSEC(CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS),
                      K_NO_WAIT);
        acvp_serial_line_timer_armed = true;
    }
}

static bool acvp_serial_line_timer_expired(void)
{
    if (!acvp_serial_line_timer_initialized || !acvp_serial_line_timer_armed) {
        return false;
    }

    if (k_timer_status_get(&acvp_serial_line_timer) == 0U) {
        return false;
    }

    acvp_serial_line_timer_stop();
    return true;
}

static int acvp_hex_nibble(unsigned char c)
{
    uint8_t encoded = acvp_hex_decode_table[c];

    return encoded == 0U ? -1 : (int)encoded - 1;
}

static int acvp_hex_measure(const char *hex, size_t *hex_len, size_t *byte_len)
{
    size_t len = 0U;

    if (hex_len == NULL || byte_len == NULL) {
        return -EINVAL;
    }

    if (hex == NULL) {
        *hex_len = 0U;
        *byte_len = 0U;
        return 0;
    }

    while (hex[len] != '\0') {
        if (acvp_hex_nibble((unsigned char)hex[len]) < 0) {
            return -EINVAL;
        }
        len++;
    }

    if ((len & 1U) != 0U) {
        return -EINVAL;
    }

    *hex_len = len;
    *byte_len = len / 2U;
    return 0;
}

static void acvp_hex_decode_known_len(const char *hex, uint8_t *out,
                                      size_t byte_len)
{
    for (size_t i = 0U; i < byte_len; i++) {
        int hi = acvp_hex_nibble((unsigned char)hex[i * 2U]);
        int lo = acvp_hex_nibble((unsigned char)hex[i * 2U + 1U]);

        out[i] = (uint8_t)(((uint8_t)hi << 4) | (uint8_t)lo);
    }
}

static int acvp_decode_payload_checked(const char *hex,
                                       uint8_t *out, size_t out_cap,
                                       size_t byte_len)
{
    if (byte_len > out_cap) {
        return -ENOSPC;
    }
    if (byte_len > 0U && out == NULL) {
        return -EINVAL;
    }

    acvp_hex_decode_known_len(hex, out, byte_len);
    return 0;
}

const char *pqcp_acvp_result_str(enum pqcp_acvp_result result)
{
    switch (result) {
    case PQCP_ACVP_OK:               return "OK";
    case PQCP_ACVP_ERR_INVALID_HEX:  return "INVALID_HEX";
    case PQCP_ACVP_ERR_INVALID_LEVEL: return "INVALID_LEVEL";
    case PQCP_ACVP_ERR_INVALID_ALG:  return "INVALID_ALG";
    case PQCP_ACVP_ERR_INVALID_CMD:  return "INVALID_CMD";
    case PQCP_ACVP_ERR_MISSING_ARGS: return "MISSING_ARGS";
    case PQCP_ACVP_ERR_WRONG_SIZE:   return "WRONG_SIZE";
    case PQCP_ACVP_ERR_KEYGEN:       return "KEYGEN_FAILED";
    case PQCP_ACVP_ERR_ENCAPS:       return "ENCAPS_FAILED";
    case PQCP_ACVP_ERR_DECAPS:       return "DECAPS_FAILED";
    case PQCP_ACVP_ERR_SIGN:         return "SIGN_FAILED";
    case PQCP_ACVP_ERR_VERIFY:       return "VERIFY_FAILED";
    case PQCP_ACVP_ERR_SEED:         return "SEED_FAILED";
    case PQCP_ACVP_ERR_NOT_ENABLED:  return "NOT_ENABLED";
    case PQCP_ACVP_ERR_BUFFER_TOO_SMALL: return "BUFFER_TOO_SMALL";
    case PQCP_ACVP_ERR_TIMEOUT:      return "TIMEOUT";
    case PQCP_ACVP_VERIFY_INVALID:   return "INVALID";
    default: return "UNKNOWN";
    }
}

void pqcp_acvp_response_init(struct pqcp_acvp_response *resp,
                             uint8_t *buffer, size_t buffer_size)
{
    resp->result = PQCP_ACVP_OK;
    resp->data = buffer;
    resp->data_len = 0;
    resp->data_cap = buffer_size;
}

int pqcp_acvp_format_response_line(const struct pqcp_acvp_response *resp,
                                   char *out, size_t out_size)
{
    size_t line_len;

    if (resp == NULL || out == NULL || out_size == 0U) {
        return -EINVAL;
    }

    if (resp->result != PQCP_ACVP_OK &&
        resp->result != PQCP_ACVP_VERIFY_INVALID) {
        const char *prefix = "ERROR:";
        const char *suffix = pqcp_acvp_result_str(resp->result);
        const size_t prefix_len = sizeof("ERROR:") - 1U;
        const size_t suffix_len = strlen(suffix);

        line_len = prefix_len + suffix_len;
        if (line_len >= out_size) {
            return -ENOSPC;
        }

        memcpy(out, prefix, prefix_len);
        memcpy(out + prefix_len, suffix, suffix_len);
        out[line_len] = '\0';
        return 0;
    }

    if (resp->result == PQCP_ACVP_VERIFY_INVALID) {
        line_len = sizeof("RESULT:INVALID") - 1U;
        if (line_len >= out_size) {
            return -ENOSPC;
        }

        memcpy(out, "RESULT:INVALID", sizeof("RESULT:INVALID"));
        return 0;
    }

    if (resp->data_len == 0U) {
        line_len = sizeof("RESULT:OK") - 1U;
        if (line_len >= out_size) {
            return -ENOSPC;
        }

        memcpy(out, "RESULT:OK", sizeof("RESULT:OK"));
        return 0;
    }

    if (resp->data_len > (SIZE_MAX - sizeof("RESULT:")) / 2U) {
        return -ENOSPC;
    }

    if (resp->data == NULL || out_size < (sizeof("RESULT:") - 1U) +
                                       (resp->data_len * 2U) + 1U) {
        return -ENOSPC;
    }

    memcpy(out, "RESULT:", sizeof("RESULT:") - 1U);
    pqcp_acvp_bytes_to_hex(resp->data, resp->data_len, out + sizeof("RESULT:") - 1U);
    return 0;
}

int pqcp_acvp_hex_to_bytes(const char *hex, uint8_t *out,
                           size_t *out_len, size_t max_len)
{
    size_t hex_len;
    size_t byte_len;
    int ret;

    if (out_len == NULL) {
        return -EINVAL;
    }

    ret = acvp_hex_measure(hex, &hex_len, &byte_len);
    if (ret != 0) {
        return ret;
    }

    ret = acvp_decode_payload_checked(hex, out, max_len, byte_len);
    if (ret != 0) {
        return ret;
    }

    (void)hex_len;
    *out_len = byte_len;
    return 0;
}

void pqcp_acvp_bytes_to_hex(const uint8_t *data, size_t len, char *out)
{
    static const char hex_chars[] = "0123456789abcdef";

    for (size_t i = 0; i < len; i++) {
        out[i*2] = hex_chars[(data[i] >> 4) & 0xF];
        out[i*2+1] = hex_chars[data[i] & 0xF];
    }
    out[len * 2] = '\0';
}

/* Helper to convert level int to enum */
static pqcp_mlkem_level_t get_mlkem_level(int level)
{
    switch (level) {
    case 512:  return PQCP_MLKEM_512;
    case 768:  return PQCP_MLKEM_768;
    case 1024: return PQCP_MLKEM_1024;
    default:   return (pqcp_mlkem_level_t)-1;
    }
}

static pqcp_mldsa_level_t get_mldsa_level(int level)
{
    switch (level) {
    case 44: return PQCP_MLDSA_44;
    case 65: return PQCP_MLDSA_65;
    case 87: return PQCP_MLDSA_87;
    default: return (pqcp_mldsa_level_t)-1;
    }
}

static size_t split_fields(char *line, char **fields, size_t max_fields,
                           bool *too_many_fields)
{
    size_t count = 0U;
    char *cursor = line;

    *too_many_fields = false;

    while (count < max_fields) {
        char *sep;

        fields[count++] = cursor;
        sep = strchr(cursor, ':');
        if (sep == NULL) {
            return count;
        }

        *sep = '\0';
        cursor = sep + 1;
    }

    if (strchr(cursor, ':') != NULL || cursor[0] != '\0') {
        *too_many_fields = true;
    }

    return count;
}

static int parse_level_token(const char *level_str, int *level)
{
    int parsed = 0;

    if (level_str == NULL || level_str[0] == '\0' || level == NULL) {
        return -EINVAL;
    }

    for (size_t i = 0U; level_str[i] != '\0'; i++) {
        unsigned char ch = (unsigned char)level_str[i];

        if (ch < '0' || ch > '9') {
            return -EINVAL;
        }
        if (parsed > (INT_MAX - (int)(ch - '0')) / 10) {
            return -EINVAL;
        }
        parsed = (parsed * 10) + (int)(ch - '0');
    }

    if (parsed <= 0) {
        return -EINVAL;
    }

    *level = parsed;
    return 0;
}

static int validate_exact_payload_len(size_t payload_len,
                                      size_t expected_len,
                                      size_t max_len)
{
    if (payload_len > max_len) {
        return -EMSGSIZE;
    }

    if (payload_len != expected_len) {
        return -EINVAL;
    }

    return 0;
}

static int validate_mlkem_encaps_payload_len(pqcp_mlkem_level_t level,
                                             size_t payload_len)
{
    return validate_exact_payload_len(
        payload_len,
        pqcp_mlkem_pk_size(level),
        PQCP_ACVP_MLKEM_ENCAPS_REQUEST_BYTES_MAX
    );
}

static int validate_mlkem_decaps_payload_len(pqcp_mlkem_level_t level,
                                             size_t payload_len,
                                             size_t *ct_size,
                                             size_t *sk_size)
{
    *ct_size = pqcp_mlkem_ct_size(level);
    *sk_size = pqcp_mlkem_sk_size(level);
    return validate_exact_payload_len(
        payload_len,
        *ct_size + *sk_size,
        PQCP_ACVP_MLKEM_DECAPS_REQUEST_BYTES_MAX
    );
}

static int validate_mldsa_sign_payload_len(pqcp_mldsa_level_t level,
                                           size_t payload_len,
                                           size_t *msg_len)
{
    size_t sk_size = pqcp_mldsa_sk_size(level);

    if (payload_len < sk_size) {
        return -EINVAL;
    }

    *msg_len = payload_len - sk_size;
    if (*msg_len > PQCP_ACVP_MAX_MESSAGE_BYTES) {
        return -EMSGSIZE;
    }

    return 0;
}

static int validate_mldsa_verify_payload_len(pqcp_mldsa_level_t level,
                                             size_t payload_len,
                                             size_t *msg_len)
{
    size_t pk_size = pqcp_mldsa_pk_size(level);
    size_t sig_size = pqcp_mldsa_sig_size(level);

    if (payload_len < pk_size + sig_size) {
        return -EINVAL;
    }

    *msg_len = payload_len - pk_size - sig_size;
    if (*msg_len > PQCP_ACVP_MAX_MESSAGE_BYTES) {
        return -EMSGSIZE;
    }

    return 0;
}

int pqcp_acvp_validate_command_line(const char *line, size_t line_len)
{
    if (line == NULL) {
        return -EINVAL;
    }

    if (line_len == 0U) {
        return 0;
    }

    if (line_len >= PQCP_ACVP_COMMAND_LINE_CHARS_MAX) {
        return -ENOSPC;
    }

    for (size_t i = 0; i < line_len; i++) {
        char ch = line[i];

        if (ch == '\0') {
            return -EINVAL;
        }

        if ((ch >= '0' && ch <= '9') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z') ||
            ch == ':' || ch == '-') {
            continue;
        }

        return -EINVAL;
    }

    return 0;
}

void pqcp_acvp_serial_line_reset(struct pqcp_acvp_serial_line_state *state)
{
    if (state == NULL) {
        return;
    }

    acvp_serial_line_timer_stop();
    state->len = 0U;
    state->active = false;
    state->overflow = false;
}

int pqcp_acvp_serial_line_consume_char(struct pqcp_acvp_serial_line_state *state,
                                       char ch,
                                       char *line, size_t line_size,
                                       size_t *line_len)
{
    if (state == NULL || line == NULL || line_len == NULL || line_size == 0U) {
        return -EINVAL;
    }

    if (acvp_serial_line_has_partial(state) &&
        acvp_serial_line_timer_expired()) {
        line[0] = '\0';
        *line_len = 0U;
        pqcp_acvp_serial_line_reset(state);
        return -ETIMEDOUT;
    }

    if (ch == '\r' || ch == '\n') {
        int ret = 1;

        if (state->overflow) {
            ret = -ENOSPC;
        }

        line[state->len < line_size ? state->len : line_size - 1U] = '\0';
        *line_len = state->len;
        pqcp_acvp_serial_line_reset(state);
        return ret;
    }

    if (ch == '\b' || ch == 0x7f) {
        if (state->len > 0U && !state->overflow) {
            state->len--;
            line[state->len] = '\0';
        }
        if (acvp_serial_line_has_partial(state)) {
            acvp_serial_line_timer_start_once();
        }
        return 0;
    }

    state->active = true;

    if (!state->overflow) {
        if (state->len < line_size - 1U) {
            line[state->len++] = ch;
            line[state->len] = '\0';
            acvp_serial_line_timer_start_once();
            return 0;
        }

        state->overflow = true;
    }

    acvp_serial_line_timer_start_once();
    return 0;
}

int pqcp_acvp_serial_line_timeout(struct pqcp_acvp_serial_line_state *state,
                                  char *line, size_t line_size)
{
    if (state == NULL || line == NULL || line_size == 0U) {
        return -EINVAL;
    }

    if (!state->active && !state->overflow && state->len == 0U) {
        return 0;
    }

    line[0] = '\0';
    pqcp_acvp_serial_line_reset(state);
    return -ETIMEDOUT;
}

int pqcp_acvp_cmd_seed(const uint8_t *seed, size_t seed_len,
                       struct pqcp_acvp_response *resp)
{
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    int ret = pqcp_rng_deterministic_seed(seed, seed_len);
    if (ret == 0) {
        resp->result = PQCP_ACVP_OK;
        resp->data_len = 0;
        return 0;
    } else {
        resp->result = PQCP_ACVP_ERR_SEED;
        return -EIO;
    }
#else
    (void)seed;
    (void)seed_len;
    resp->result = PQCP_ACVP_ERR_NOT_ENABLED;
    return -ENOTSUP;
#endif
}

int pqcp_acvp_cmd_mlkem_keygen(int level, struct pqcp_acvp_response *resp)
{
    pqcp_mlkem_level_t mlkem_level = get_mlkem_level(level);
    if ((int)mlkem_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }

    size_t pk_size = pqcp_mlkem_pk_size(mlkem_level);
    size_t sk_size = pqcp_mlkem_sk_size(mlkem_level);

    if (pk_size + sk_size > resp->data_cap) {
        resp->result = PQCP_ACVP_ERR_BUFFER_TOO_SMALL;
        return -ENOSPC;
    }

    uint8_t *pk = resp->data;
    uint8_t *sk = resp->data + pk_size;

    int ret = pqcp_mlkem_keypair(mlkem_level, pk, sk);
    if (ret != PQCP_MLKEM_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_KEYGEN;
        return -EIO;
    }

    resp->result = PQCP_ACVP_OK;
    resp->data_len = pk_size + sk_size;
    return 0;
}

int pqcp_acvp_cmd_mlkem_encaps(int level, const uint8_t *pk, size_t pk_len,
                               struct pqcp_acvp_response *resp)
{
    pqcp_mlkem_level_t mlkem_level = get_mlkem_level(level);
    if ((int)mlkem_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }

    if (validate_mlkem_encaps_payload_len(mlkem_level, pk_len) != 0) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }

    size_t ct_size = pqcp_mlkem_ct_size(mlkem_level);

    if (ct_size + PQCP_MLKEM_SS_SIZE > resp->data_cap) {
        resp->result = PQCP_ACVP_ERR_BUFFER_TOO_SMALL;
        return -ENOSPC;
    }

    uint8_t *ct = resp->data;
    uint8_t *ss = resp->data + ct_size;

    int ret = pqcp_mlkem_encapsulate(mlkem_level, pk, ct, ss);
    if (ret != PQCP_MLKEM_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_ENCAPS;
        return -EIO;
    }

    resp->result = PQCP_ACVP_OK;
    resp->data_len = ct_size + PQCP_MLKEM_SS_SIZE;
    return 0;
}

int pqcp_acvp_cmd_mlkem_decaps(int level,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t *sk, size_t sk_len,
                               struct pqcp_acvp_response *resp)
{
    pqcp_mlkem_level_t mlkem_level = get_mlkem_level(level);
    if ((int)mlkem_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }

    if (ct_len != pqcp_mlkem_ct_size(mlkem_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }

    if (sk_len != pqcp_mlkem_sk_size(mlkem_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }

    if (PQCP_MLKEM_SS_SIZE > resp->data_cap) {
        resp->result = PQCP_ACVP_ERR_BUFFER_TOO_SMALL;
        return -ENOSPC;
    }

    int ret = pqcp_mlkem_decapsulate(mlkem_level, ct, sk, resp->data);
    if (ret != PQCP_MLKEM_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_DECAPS;
        return -EIO;
    }

    resp->result = PQCP_ACVP_OK;
    resp->data_len = PQCP_MLKEM_SS_SIZE;
    return 0;
}

int pqcp_acvp_cmd_mldsa_keygen(int level, struct pqcp_acvp_response *resp)
{
    pqcp_mldsa_level_t mldsa_level = get_mldsa_level(level);
    if ((int)mldsa_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }

    size_t pk_size = pqcp_mldsa_pk_size(mldsa_level);
    size_t sk_size = pqcp_mldsa_sk_size(mldsa_level);

    if (pk_size + sk_size > resp->data_cap) {
        resp->result = PQCP_ACVP_ERR_BUFFER_TOO_SMALL;
        return -ENOSPC;
    }

    uint8_t *pk = resp->data;
    uint8_t *sk = resp->data + pk_size;

    int ret = pqcp_mldsa_keypair(mldsa_level, pk, sk);
    if (ret != PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_KEYGEN;
        return -EIO;
    }

    resp->result = PQCP_ACVP_OK;
    resp->data_len = pk_size + sk_size;
    return 0;
}

int pqcp_acvp_cmd_mldsa_sign(int level,
                             const uint8_t *sk, size_t sk_len,
                             const uint8_t *msg, size_t msg_len,
                             struct pqcp_acvp_response *resp)
{
    pqcp_mldsa_level_t mldsa_level = get_mldsa_level(level);
    if ((int)mldsa_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }

    if (sk_len != pqcp_mldsa_sk_size(mldsa_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }

    size_t sig_size = pqcp_mldsa_sig_size(mldsa_level);

    if (sig_size > resp->data_cap) {
        resp->result = PQCP_ACVP_ERR_BUFFER_TOO_SMALL;
        return -ENOSPC;
    }

    int ret = pqcp_mldsa_sign(mldsa_level, sk, msg, msg_len, NULL, 0, resp->data);
    if (ret != PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_SIGN;
        return -EIO;
    }

    resp->result = PQCP_ACVP_OK;
    resp->data_len = sig_size;
    return 0;
}

int pqcp_acvp_cmd_mldsa_verify(int level,
                               const uint8_t *pk, size_t pk_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len,
                               struct pqcp_acvp_response *resp)
{
    pqcp_mldsa_level_t mldsa_level = get_mldsa_level(level);
    if ((int)mldsa_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }

    if (pk_len != pqcp_mldsa_pk_size(mldsa_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }

    if (sig_len != pqcp_mldsa_sig_size(mldsa_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }

    resp->data_len = 0;

    int ret = pqcp_mldsa_verify(mldsa_level, pk, msg, msg_len, NULL, 0, sig);

    if (ret == PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_OK;
        return 0;
    } else if (ret == PQCP_MLDSA_ERR_VERIFY) {
        resp->result = PQCP_ACVP_VERIFY_INVALID;
        return 0;  /* Not an error, just invalid signature */
    } else {
        resp->result = PQCP_ACVP_ERR_VERIFY;
        return -EIO;
    }
}

int pqcp_acvp_cmd_selftest(struct pqcp_acvp_response *resp)
{
    /* Use local buffers for selftest */
    static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
    static uint8_t ss1[PQCP_MLKEM_SS_SIZE], ss2[PQCP_MLKEM_SS_SIZE];

#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    /* Seed for reproducibility */
    static const uint8_t selftest_seed[48] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30
    };
    pqcp_rng_deterministic_seed(selftest_seed, sizeof(selftest_seed));
#endif

    /* ML-KEM test */
    pqcp_mlkem_level_t kem_level = PQCP_MLKEM_768;

    int ret = pqcp_mlkem_keypair(kem_level, pk, sk);
    if (ret != PQCP_MLKEM_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_KEYGEN;
        return -EIO;
    }

    ret = pqcp_mlkem_encapsulate(kem_level, pk, ct, ss1);
    if (ret != PQCP_MLKEM_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_ENCAPS;
        return -EIO;
    }

    ret = pqcp_mlkem_decapsulate(kem_level, ct, sk, ss2);
    if (ret != PQCP_MLKEM_SUCCESS || memcmp(ss1, ss2, PQCP_MLKEM_SS_SIZE) != 0) {
        resp->result = PQCP_ACVP_ERR_DECAPS;
        return -EIO;
    }

    /* ML-DSA test - use larger buffers */
    static uint8_t dsa_pk[PQCP_MLDSA_PK_SIZE_MAX];
    static uint8_t dsa_sk[PQCP_MLDSA_SK_SIZE_MAX];
    static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    static const uint8_t msg[] = "selftest";

#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    pqcp_rng_deterministic_seed(selftest_seed, sizeof(selftest_seed));
#endif

    pqcp_mldsa_level_t dsa_level = PQCP_MLDSA_65;

    ret = pqcp_mldsa_keypair(dsa_level, dsa_pk, dsa_sk);
    if (ret != PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_KEYGEN;
        return -EIO;
    }

#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    pqcp_rng_deterministic_seed(selftest_seed, sizeof(selftest_seed));
#endif

    ret = pqcp_mldsa_sign(dsa_level, dsa_sk, msg, sizeof(msg)-1, NULL, 0, sig);
    if (ret != PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_SIGN;
        return -EIO;
    }

    ret = pqcp_mldsa_verify(dsa_level, dsa_pk, msg, sizeof(msg)-1, NULL, 0, sig);
    if (ret != PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_VERIFY;
        return -EIO;
    }

    resp->result = PQCP_ACVP_OK;
    resp->data_len = 0;
    return 0;
}

int pqcp_acvp_process_command(char *line,
                              uint8_t *work_buf, size_t work_buf_size,
                              struct pqcp_acvp_response *resp)
{
    char *fields[4] = { 0 };
    const char *cmd;
    const char *alg;
    const char *level_str;
    const char *data;
    bool too_many_fields;
    bool cmd_requires_data;
    size_t field_count;
    int level = 0;

    if (line == NULL || resp == NULL) {
        return -EINVAL;
    }

    field_count = split_fields(line, fields, 4U, &too_many_fields);
    cmd = (field_count > 0U) ? fields[0] : NULL;
    alg = (field_count > 1U) ? fields[1] : NULL;
    level_str = (field_count > 2U) ? fields[2] : NULL;
    data = (field_count > 3U) ? fields[3] : NULL;

    if (too_many_fields || cmd == NULL || cmd[0] == '\0') {
        resp->result = PQCP_ACVP_ERR_INVALID_CMD;
        return -EINVAL;
    }

    /* HELP command */
    if (strcmp(cmd, "HELP") == 0) {
        bool exact_help = (field_count == 1U) ||
            (field_count == 3U &&
             alg != NULL && alg[0] == '\0' &&
             level_str != NULL && level_str[0] == '\0');

        if (!exact_help) {
            resp->result = PQCP_ACVP_ERR_INVALID_CMD;
            return -EINVAL;
        }
        resp->result = PQCP_ACVP_OK;
        resp->data_len = 0;
        return 0;
    }

    /* SELFTEST command */
    if (strcmp(cmd, "SELFTEST") == 0) {
        bool exact_selftest = (field_count == 1U) ||
            (field_count == 3U &&
             alg != NULL && alg[0] == '\0' &&
             level_str != NULL && level_str[0] == '\0');

        if (!exact_selftest) {
            resp->result = PQCP_ACVP_ERR_INVALID_CMD;
            return -EINVAL;
        }
        return pqcp_acvp_cmd_selftest(resp);
    }

    /* SEED command */
    if (strcmp(cmd, "SEED") == 0) {
        size_t seed_len;
        size_t seed_hex_len;
        int ret;

        if (alg == NULL || strcmp(alg, "DRBG") != 0) {
            resp->result = PQCP_ACVP_ERR_INVALID_ALG;
            return -EINVAL;
        }
        if (level_str == NULL || strcmp(level_str, "0") != 0) {
            resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
            return -EINVAL;
        }
        if (data == NULL || data[0] == '\0') {
            resp->result = PQCP_ACVP_ERR_MISSING_ARGS;
            return -EINVAL;
        }

        ret = acvp_hex_measure(data, &seed_hex_len, &seed_len);
        if (ret != 0) {
            resp->result = PQCP_ACVP_ERR_INVALID_HEX;
            return ret;
        }
        ret = acvp_decode_payload_checked(data, work_buf, work_buf_size, seed_len);
        if (ret != 0) {
            resp->result = (ret == -ENOSPC) ?
                PQCP_ACVP_ERR_BUFFER_TOO_SMALL : PQCP_ACVP_ERR_INVALID_HEX;
            return ret;
        }
        (void)seed_hex_len;
        return pqcp_acvp_cmd_seed(work_buf, seed_len, resp);
    }

    /* Commands that require ALG and LEVEL */
    if (alg == NULL || alg[0] == '\0' ||
        level_str == NULL || level_str[0] == '\0') {
        resp->result = PQCP_ACVP_ERR_MISSING_ARGS;
        return -EINVAL;
    }

    if (parse_level_token(level_str, &level) != 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }

    /* KEYGEN command */
    if (strcmp(cmd, "KEYGEN") == 0) {
        if (data != NULL && data[0] != '\0') {
            resp->result = PQCP_ACVP_ERR_INVALID_CMD;
            return -EINVAL;
        }
        if (strcmp(alg, "MLKEM") == 0) {
            return pqcp_acvp_cmd_mlkem_keygen(level, resp);
        } else if (strcmp(alg, "MLDSA") == 0) {
            return pqcp_acvp_cmd_mldsa_keygen(level, resp);
        } else {
            resp->result = PQCP_ACVP_ERR_INVALID_ALG;
            return -EINVAL;
        }
    }

    cmd_requires_data = (strcmp(cmd, "ENCAPS") == 0) ||
                        (strcmp(cmd, "DECAPS") == 0) ||
                        (strcmp(cmd, "SIGN") == 0) ||
                        (strcmp(cmd, "VERIFY") == 0);
    if (!cmd_requires_data) {
        resp->result = PQCP_ACVP_ERR_INVALID_CMD;
        return -EINVAL;
    }

    /* Commands that require DATA */
    if (data == NULL || data[0] == '\0') {
        resp->result = PQCP_ACVP_ERR_MISSING_ARGS;
        return -EINVAL;
    }

    size_t data_hex_len = 0U;
    size_t data_len = 0U;
    int ret = acvp_hex_measure(data, &data_hex_len, &data_len);
    if (ret != 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_HEX;
        return ret;
    }

    /* ML-KEM commands */
    if (strcmp(alg, "MLKEM") == 0) {
        if (strcmp(cmd, "ENCAPS") == 0) {
            pqcp_mlkem_level_t mlkem_level = get_mlkem_level(level);
            if ((int)mlkem_level < 0) {
                resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
                return -EINVAL;
            }
            if (validate_mlkem_encaps_payload_len(mlkem_level, data_len) != 0) {
                resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
                return -EINVAL;
            }
            ret = acvp_decode_payload_checked(data, work_buf, work_buf_size, data_len);
            if (ret != 0) {
                resp->result = (ret == -ENOSPC) ?
                    PQCP_ACVP_ERR_BUFFER_TOO_SMALL : PQCP_ACVP_ERR_INVALID_HEX;
                return ret;
            }
            return pqcp_acvp_cmd_mlkem_encaps(level, work_buf, data_len, resp);
        } else if (strcmp(cmd, "DECAPS") == 0) {
            pqcp_mlkem_level_t mlkem_level = get_mlkem_level(level);
            if ((int)mlkem_level < 0) {
                resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
                return -EINVAL;
            }
            size_t ct_size;
            size_t sk_size;
            if (validate_mlkem_decaps_payload_len(mlkem_level, data_len,
                                                  &ct_size, &sk_size) != 0) {
                resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
                return -EINVAL;
            }
            ret = acvp_decode_payload_checked(data, work_buf, work_buf_size, data_len);
            if (ret != 0) {
                resp->result = (ret == -ENOSPC) ?
                    PQCP_ACVP_ERR_BUFFER_TOO_SMALL : PQCP_ACVP_ERR_INVALID_HEX;
                return ret;
            }
            return pqcp_acvp_cmd_mlkem_decaps(level,
                                              work_buf, ct_size,
                                              work_buf + ct_size, sk_size,
                                              resp);
        }
    }

    /* ML-DSA commands */
    if (strcmp(alg, "MLDSA") == 0) {
        if (strcmp(cmd, "SIGN") == 0) {
            pqcp_mldsa_level_t mldsa_level = get_mldsa_level(level);
            size_t sk_size;
            size_t msg_len;

            if ((int)mldsa_level < 0) {
                resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
                return -EINVAL;
            }

            sk_size = pqcp_mldsa_sk_size(mldsa_level);
            if (validate_mldsa_sign_payload_len(mldsa_level, data_len, &msg_len) != 0) {
                resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
                return -EINVAL;
            }
            ret = acvp_decode_payload_checked(data, work_buf, work_buf_size, data_len);
            if (ret != 0) {
                resp->result = (ret == -ENOSPC) ?
                    PQCP_ACVP_ERR_BUFFER_TOO_SMALL : PQCP_ACVP_ERR_INVALID_HEX;
                return ret;
            }
            return pqcp_acvp_cmd_mldsa_sign(level,
                                            work_buf, sk_size,
                                            work_buf + sk_size, msg_len,
                                            resp);
        } else if (strcmp(cmd, "VERIFY") == 0) {
            pqcp_mldsa_level_t mldsa_level = get_mldsa_level(level);
            size_t pk_size;
            size_t sig_size;
            size_t msg_len;

            if ((int)mldsa_level < 0) {
                resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
                return -EINVAL;
            }

            pk_size = pqcp_mldsa_pk_size(mldsa_level);
            sig_size = pqcp_mldsa_sig_size(mldsa_level);
            if (validate_mldsa_verify_payload_len(mldsa_level, data_len, &msg_len) != 0) {
                resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
                return -EINVAL;
            }
            ret = acvp_decode_payload_checked(data, work_buf, work_buf_size, data_len);
            if (ret != 0) {
                resp->result = (ret == -ENOSPC) ?
                    PQCP_ACVP_ERR_BUFFER_TOO_SMALL : PQCP_ACVP_ERR_INVALID_HEX;
                return ret;
            }
            return pqcp_acvp_cmd_mldsa_verify(level,
                                              work_buf, pk_size,
                                              work_buf + pk_size, msg_len,
                                              work_buf + pk_size + msg_len, sig_size,
                                              resp);
        }
    }

    (void)data_hex_len;
    resp->result = PQCP_ACVP_ERR_INVALID_CMD;
    return -EINVAL;
}
