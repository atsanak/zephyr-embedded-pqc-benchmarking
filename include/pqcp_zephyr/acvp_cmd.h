/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP ACVP Command Library
 *
 * Reusable command handlers for ACVP testing. These can be used
 * by the serial ACVP sample or programmatically by tests.
 *
 * Stability: stable validation API for the 1.0.x line. The ACVP wire
 * grammar is stable, but this header is not a production transport API.
 */

#ifndef PQCP_ZEPHYR_ACVP_CMD_H_
#define PQCP_ZEPHYR_ACVP_CMD_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup pqcp_acvp_cmd PQCP ACVP Command Library
 * @{
 */

/**
 * @brief ACVP command result codes.
 *
 * These values are shared by the lab/test-oriented ACVP command helpers, the
 * serial ACVP sample, and the ztest coverage that validates the stable
 * `RESULT:*` / `ERROR:*` wire protocol. They are not intended to replace a
 * production network protocol status model.
 */
enum pqcp_acvp_result {
    PQCP_ACVP_OK = 0,              /**< Success */
    PQCP_ACVP_ERR_INVALID_HEX,     /**< Invalid hex input */
    PQCP_ACVP_ERR_INVALID_LEVEL,   /**< Invalid algorithm level */
    PQCP_ACVP_ERR_INVALID_ALG,     /**< Unknown algorithm */
    PQCP_ACVP_ERR_INVALID_CMD,     /**< Unknown command */
    PQCP_ACVP_ERR_MISSING_ARGS,    /**< Missing arguments */
    PQCP_ACVP_ERR_WRONG_SIZE,      /**< Wrong input data size */
    PQCP_ACVP_ERR_KEYGEN,          /**< Key generation failed */
    PQCP_ACVP_ERR_ENCAPS,          /**< Encapsulation failed */
    PQCP_ACVP_ERR_DECAPS,          /**< Decapsulation failed */
    PQCP_ACVP_ERR_SIGN,            /**< Signing failed */
    PQCP_ACVP_ERR_VERIFY,          /**< Verification failed (not invalid signature) */
    PQCP_ACVP_ERR_SEED,            /**< RNG seeding failed */
    PQCP_ACVP_ERR_NOT_ENABLED,     /**< Feature not enabled in build */
    PQCP_ACVP_ERR_BUFFER_TOO_SMALL,/**< Output buffer too small */
    PQCP_ACVP_ERR_TIMEOUT,         /**< Serial frame timed out before newline */
    PQCP_ACVP_VERIFY_INVALID,      /**< Signature is invalid (not an error) */
};

/** @brief Backward-compatible alias for the serial line timeout result. */
#define PQCP_ACVP_ERR_LINE_TIMEOUT PQCP_ACVP_ERR_TIMEOUT

/**
 * @brief ACVP response structure.
 *
 * Holds the result of an ACVP command execution together with caller-owned
 * payload storage used by the lab/test harnesses.
 */
struct pqcp_acvp_response {
    enum pqcp_acvp_result result;  /**< Result code */
    uint8_t *data;                 /**< Output data buffer (caller-provided) */
    size_t data_len;               /**< Length of output data */
    size_t data_cap;               /**< Capacity of output buffer */
};

/**
 * @brief Maximum message payload accepted by the serial ACVP sign/verify helpers.
 *
 * The ACVP serial harness is intentionally a lab-oriented command interface, not
 * a streaming transport. Keeping a bounded message payload makes malformed host
 * traffic easier to reject predictably and prevents accidental "benchmark" runs
 * from turning the harness into an unbounded message tunnel.
 */
#define PQCP_ACVP_MAX_MESSAGE_BYTES 1024U

/**
 * @brief Maximum ML-KEM ACVP request/response sizes accepted by the lab harness.
 *
 * These bounds intentionally mirror the fixed-size ML-KEM request and response
 * shapes used by the serial ACVP helpers. Keeping them explicit in the public
 * header lets the reusable command library, serial sample, and ztests share the
 * same limits for keypair, encapsulation, and decapsulation handling.
 */
#define PQCP_ACVP_MLKEM_KEYGEN_RESPONSE_BYTES_MAX \
    (PQCP_MLKEM_PK_SIZE_MAX + PQCP_MLKEM_SK_SIZE_MAX)
/** @brief Maximum decoded ML-KEM encapsulation request size. */
#define PQCP_ACVP_MLKEM_ENCAPS_REQUEST_BYTES_MAX \
    PQCP_MLKEM_PK_SIZE_MAX
/** @brief Maximum decoded ML-KEM encapsulation response size. */
#define PQCP_ACVP_MLKEM_ENCAPS_RESPONSE_BYTES_MAX \
    (PQCP_MLKEM_CT_SIZE_MAX + PQCP_MLKEM_SS_SIZE)
/** @brief Maximum decoded ML-KEM decapsulation request size. */
#define PQCP_ACVP_MLKEM_DECAPS_REQUEST_BYTES_MAX \
    (PQCP_MLKEM_CT_SIZE_MAX + PQCP_MLKEM_SK_SIZE_MAX)
/** @brief Maximum decoded ML-KEM decapsulation response size. */
#define PQCP_ACVP_MLKEM_DECAPS_RESPONSE_BYTES_MAX \
    PQCP_MLKEM_SS_SIZE

/**
 * @brief Maximum ML-DSA ACVP request/response sizes accepted by the lab harness.
 */
#define PQCP_ACVP_MLDSA_KEYGEN_RESPONSE_BYTES_MAX \
    (PQCP_MLDSA_PK_SIZE_MAX + PQCP_MLDSA_SK_SIZE_MAX)
/** @brief Maximum decoded ML-DSA signing request size. */
#define PQCP_ACVP_MLDSA_SIGN_REQUEST_BYTES_MAX \
    (PQCP_MLDSA_SK_SIZE_MAX + PQCP_ACVP_MAX_MESSAGE_BYTES)
/** @brief Maximum decoded ML-DSA signing response size. */
#define PQCP_ACVP_MLDSA_SIGN_RESPONSE_BYTES_MAX \
    PQCP_MLDSA_SIG_SIZE_MAX
/** @brief Maximum decoded ML-DSA verification request size. */
#define PQCP_ACVP_MLDSA_VERIFY_REQUEST_BYTES_MAX \
    (PQCP_MLDSA_PK_SIZE_MAX + PQCP_MLDSA_SIG_SIZE_MAX + \
     PQCP_ACVP_MAX_MESSAGE_BYTES)

/**
 * @brief Maximum decoded input and encoded response payloads for the serial harness.
 */
#define PQCP_ACVP_INPUT_BYTES_MAX \
    PQCP_ACVP_MLDSA_VERIFY_REQUEST_BYTES_MAX
/** @brief Maximum decoded ACVP command response payload size. */
#define PQCP_ACVP_RESPONSE_BYTES_MAX \
    PQCP_ACVP_MLDSA_KEYGEN_RESPONSE_BYTES_MAX
/** @brief Maximum raw ACVP command line length, excluding CR/LF. */
#define PQCP_ACVP_COMMAND_LINE_CHARS_MAX \
    ((PQCP_ACVP_INPUT_BYTES_MAX * 2U) + 64U)

/**
 * @brief Incremental serial line state for the lab-oriented ACVP sample.
 *
 * This state machine keeps UART framing behavior shared between the serial
 * sample, the host-side timeout scenarios, and ztest coverage. It is not a
 * general-purpose production transport API.
 *
 * Callers own both this state object and the line buffer passed to
 * @ref pqcp_acvp_serial_line_consume_char. Reset the state before first use
 * and after any transport-level disconnect.
 */
struct pqcp_acvp_serial_line_state {
    size_t len;       /**< Current buffered line length */
    bool active;      /**< True after the first non-newline character arrives */
    bool overflow;    /**< True after the frame exceeds the configured buffer */
};

/**
 * @brief Convert a response/result code to its stable wire-format token.
 *
 * This helper is shared by the serial sample and ztests to guarantee that the
 * documented machine-readable `ERROR:<code>` and `RESULT:INVALID` spellings
 * stay stable over time.
 *
 * @param result Result code to stringify.
 *
 * @return Non-NULL pointer to a static string. Unknown enum values map to
 *         `"UNKNOWN"`.
 *
 * @note Intended for test/lab harnesses and host-visible diagnostics.
 */
const char *pqcp_acvp_result_str(enum pqcp_acvp_result result);

/**
 * @brief Format a command response into the serial ACVP wire format.
 *
 * The formatter preserves the stable host-visible response grammar used by
 * the serial sample:
 *
 * - `RESULT:OK`
 * - `RESULT:INVALID`
 * - `RESULT:<hex payload>`
 * - `ERROR:<error_code>`
 *
 * @param resp Parsed command response.
 * @param out Destination buffer for the formatted line.
 * @param out_size Capacity of @p out in bytes.
 *
 * @retval 0 Response formatted successfully.
 * @retval -EINVAL Invalid arguments were provided.
 * @retval -ENOSPC @p out is too small for the formatted line.
 *
 * @note Intended for test/lab harnesses and both the serial sample and ztest
 *       coverage. The public wire grammar must remain stable.
 */
int pqcp_acvp_format_response_line(const struct pqcp_acvp_response *resp,
                                   char *out, size_t out_size);

/**
 * @brief Initialize a response object around caller-owned storage.
 *
 * @param resp Response structure to initialize.
 * @param buffer Payload buffer used for command outputs.
 * @param buffer_size Capacity of @p buffer in bytes.
 *
 * @note Intended for test/lab harnesses and reusable host-driven validation
 *       flows. Callers retain ownership of @p buffer.
 */
void pqcp_acvp_response_init(struct pqcp_acvp_response *resp,
                             uint8_t *buffer, size_t buffer_size);

/**
 * @brief Seed the deterministic RNG used by ACVP/KAT-style flows.
 *
 * @param seed Seed bytes.
 * @param seed_len Length of @p seed in bytes.
 * @param resp Response structure updated with the wire-visible result code.
 *
 * @retval 0 Seed accepted successfully.
 * @retval Negative errno-style code on failure. The corresponding
 *         `resp->result` value remains machine-readable for wire formatting.
 *
 * @note Test/lab only. Production-oriented profiles must not enable the
 *       deterministic RNG path by default.
 */
int pqcp_acvp_cmd_seed(const uint8_t *seed, size_t seed_len,
                       struct pqcp_acvp_response *resp);

/**
 * @brief Generate an ML-KEM keypair for ACVP/KAT handling.
 *
 * @param level ML-KEM level (512, 768, or 1024).
 * @param resp Response structure that receives `pk || sk` on success.
 *
 * @retval 0 Keypair generated successfully.
 * @retval Negative errno-style code on failure.
 *
 * @note Intended for test/lab harnesses and host-driven validation flows.
 */
int pqcp_acvp_cmd_mlkem_keygen(int level, struct pqcp_acvp_response *resp);

/**
 * @brief Encapsulate with ML-KEM for ACVP/KAT handling.
 *
 * @param level ML-KEM level.
 * @param pk Public key bytes.
 * @param pk_len Length of @p pk.
 * @param resp Response structure that receives `ct || ss` on success.
 *
 * @retval 0 Encapsulation completed successfully.
 * @retval Negative errno-style code on failure.
 *
 * @note Intended for test/lab harnesses and host-driven validation flows.
 */
int pqcp_acvp_cmd_mlkem_encaps(int level, const uint8_t *pk, size_t pk_len,
                               struct pqcp_acvp_response *resp);

/**
 * @brief Decapsulate with ML-KEM for ACVP/KAT handling.
 *
 * @param level ML-KEM level.
 * @param ct Ciphertext bytes.
 * @param ct_len Length of @p ct.
 * @param sk Secret key bytes.
 * @param sk_len Length of @p sk.
 * @param resp Response structure that receives `ss` on success.
 *
 * @retval 0 Decapsulation completed successfully.
 * @retval Negative errno-style code on failure.
 *
 * @note Intended for test/lab harnesses and host-driven validation flows.
 */
int pqcp_acvp_cmd_mlkem_decaps(int level,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t *sk, size_t sk_len,
                               struct pqcp_acvp_response *resp);

/**
 * @brief Generate an ML-DSA keypair for ACVP/KAT handling.
 *
 * @param level ML-DSA level (44, 65, or 87).
 * @param resp Response structure that receives `pk || sk` on success.
 *
 * @retval 0 Keypair generated successfully.
 * @retval Negative errno-style code on failure.
 *
 * @note Intended for test/lab harnesses and host-driven validation flows.
 */
int pqcp_acvp_cmd_mldsa_keygen(int level, struct pqcp_acvp_response *resp);

/**
 * @brief Sign a message with ML-DSA for ACVP/KAT handling.
 *
 * @param level ML-DSA level.
 * @param sk Secret key bytes.
 * @param sk_len Length of @p sk.
 * @param msg Message bytes to sign.
 * @param msg_len Length of @p msg.
 * @param resp Response structure that receives the signature on success.
 *
 * @retval 0 Signature generated successfully.
 * @retval Negative errno-style code on failure.
 *
 * @note Intended for test/lab harnesses and host-driven validation flows.
 */
int pqcp_acvp_cmd_mldsa_sign(int level,
                             const uint8_t *sk, size_t sk_len,
                             const uint8_t *msg, size_t msg_len,
                             struct pqcp_acvp_response *resp);

/**
 * @brief Verify an ML-DSA signature for ACVP/KAT handling.
 *
 * @param level ML-DSA level.
 * @param pk Public key bytes.
 * @param pk_len Length of @p pk.
 * @param msg Message bytes.
 * @param msg_len Length of @p msg.
 * @param sig Signature bytes.
 * @param sig_len Length of @p sig.
 * @param resp Response structure updated to `PQCP_ACVP_OK` for a valid
 *             signature or `PQCP_ACVP_VERIFY_INVALID` for a clean invalid
 *             signature result.
 *
 * @retval 0 Verification completed successfully. Check `resp->result` to
 *         distinguish valid from invalid signatures.
 * @retval Negative errno-style code on parsing or library failures.
 *
 * @note Intended for test/lab harnesses and host-driven validation flows.
 */
int pqcp_acvp_cmd_mldsa_verify(int level,
                               const uint8_t *pk, size_t pk_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len,
                               struct pqcp_acvp_response *resp);

/**
 * @brief Run the ACVP command-library self-test.
 *
 * Runs basic correctness tests for ML-KEM and ML-DSA through the same command
 * helper layer used by the sample and ztests.
 *
 * @param resp Response structure updated with the self-test result.
 *
 * @retval 0 Self-test completed successfully.
 * @retval Negative errno-style code on failure.
 *
 * @note Intended for test/lab harnesses.
 */
int pqcp_acvp_cmd_selftest(struct pqcp_acvp_response *resp);

/**
 * @brief Hex encoding/decoding utilities
 */

/**
 * @brief Convert a hex string to bytes.
 *
 * @param hex Null-terminated hex string.
 * @param out Destination buffer.
 * @param out_len Pointer that receives the decoded length.
 * @param max_len Capacity of @p out in bytes.
 *
 * @retval 0 Conversion succeeded.
 * @retval -EINVAL The input string was malformed.
 * @retval -ENOSPC @p out was too small for the decoded payload.
 *
 * @note Shared utility for both test/lab command handling and host-visible
 *       sample flows.
 */
int pqcp_acvp_hex_to_bytes(const char *hex, uint8_t *out,
                           size_t *out_len, size_t max_len);

/**
 * @brief Convert bytes to a lowercase hex string.
 *
 * @param data Input data.
 * @param len Length of @p data.
 * @param out Output buffer. Must be at least `len * 2 + 1` bytes.
 *
 * @note Shared utility for both test/lab command handling and host-visible
 *       sample flows.
 */
void pqcp_acvp_bytes_to_hex(const uint8_t *data, size_t len, char *out);

/**
 * @brief Validate a raw ACVP serial command line before parsing.
 *
 * This helper is intended for serial-facing transports that need to reject
 * line noise or truncated/oversize frames before handing them to the command
 * parser. It keeps the transport-layer framing rules shared between the serial
 * sample and ztests without changing the stable ACVP wire format.
 *
 * Accepted lines are bounded to @ref PQCP_ACVP_COMMAND_LINE_CHARS_MAX and may
 * only contain ASCII letters, digits, `-`, and `:` separators. Empty lines are
 * allowed so callers can continue to ignore blank serial reads.
 *
 * @param line Raw command line bytes without trailing CR/LF.
 * @param line_len Number of bytes in @p line.
 *
 * @retval 0 The line is safe to pass to @ref pqcp_acvp_process_command.
 * @retval -EINVAL The line contains unexpected serial garbage or framing
 *         characters.
 * @retval -ENOSPC The line exceeds the supported serial command length.
 */
int pqcp_acvp_validate_command_line(const char *line, size_t line_len);

/**
 * @brief Reset the shared serial line state.
 *
 * @param state Line state object to reset.
 */
void pqcp_acvp_serial_line_reset(struct pqcp_acvp_serial_line_state *state);

/**
 * @brief Feed one character into the shared serial line state machine.
 *
 * Supported editing/framing behavior mirrors the serial ACVP sample:
 *
 * - `\r` or `\n` completes the current frame
 * - backspace / DEL removes the most recent buffered character
 * - oversize frames continue consuming bytes until newline, then return
 *   `-ENOSPC`
 * - timeout handling is explicit: transports call
 *   @ref pqcp_acvp_serial_line_timeout when their per-frame timer expires
 *
 * @param state Shared serial line state.
 * @param ch Input character.
 * @param line Destination buffer for the assembled line.
 * @param line_size Capacity of @p line.
 * @param line_len Receives the completed line length on success.
 *
 * @retval 0 Frame is still in progress.
 * @retval 1 A full line is ready in @p line.
 * @retval -EINVAL Invalid arguments were provided.
 * @retval -ENOSPC The frame exceeded @p line_size before newline.
 *
 * @note Intended for the lab/test ACVP serial harness and ztest coverage.
 */
int pqcp_acvp_serial_line_consume_char(struct pqcp_acvp_serial_line_state *state,
                                       char ch,
                                       char *line, size_t line_size,
                                       size_t *line_len);

/**
 * @brief Drop the current partial serial frame after a transport timeout.
 *
 * @param state Shared serial line state.
 * @param line Destination buffer used for the current frame.
 * @param line_size Capacity of @p line.
 *
 * @retval 0 No partial frame was active.
 * @retval -EINVAL Invalid arguments were provided.
 * @retval -ETIMEDOUT A partial frame was discarded and the caller should emit
 *         `ERROR:TIMEOUT`.
 *
 * @note Intended for the lab/test ACVP serial harness and ztest coverage. The
 *       helper clears @p line before returning `-ETIMEDOUT` so the next
 *       command can start from an idle receiver state.
 */
int pqcp_acvp_serial_line_timeout(struct pqcp_acvp_serial_line_state *state,
                                  char *line, size_t line_size);

/**
 * @brief Parse and execute one ACVP command line.
 *
 * Parses a line in the format `CMD:ALG:LEVEL:HEX_DATA`, updates @p resp with a
 * stable machine-readable result, and returns a conventional errno-style code
 * for callers that want both transport and local-status handling.
 *
 * Supported commands are:
 *
 * - `SEED:DRBG:0:<hexseed>`
 * - `KEYGEN:MLKEM:<512|768|1024>:`
 * - `ENCAPS:MLKEM:<level>:<pk_hex>`
 * - `DECAPS:MLKEM:<level>:<ct_hex><sk_hex>`
 * - `KEYGEN:MLDSA:<44|65|87>:`
 * - `SIGN:MLDSA:<level>:<sk_hex><msg_hex>`
 * - `VERIFY:MLDSA:<level>:<pk_hex><msg_hex><sig_hex>`
 * - `SELFTEST::`
 * - `HELP::`
 *
 * @param line Command line buffer. It will be modified in-place during token
 *             parsing.
 * @param work_buf Scratch buffer used for hex decoding and concatenated inputs.
 * @param work_buf_size Capacity of @p work_buf in bytes.
 * @param resp Response structure updated with the result and any payload.
 *
 * @retval 0 Command completed successfully. Check `resp->result` for
 *         `PQCP_ACVP_VERIFY_INVALID` versus `PQCP_ACVP_OK` when verifying
 *         signatures.
 * @retval Negative errno-style code on parse or execution failures.
 *
 * @note Intended for test/lab harnesses such as the serial sample and the
 *       ztest command-coverage suite.
 */
int pqcp_acvp_process_command(char *line,
                              uint8_t *work_buf, size_t work_buf_size,
                              struct pqcp_acvp_response *resp);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_ACVP_CMD_H_ */
