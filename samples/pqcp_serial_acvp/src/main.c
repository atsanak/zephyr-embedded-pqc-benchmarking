/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Serial ACVP Sample
 *
 * UART/Serial interface for running ACVP test vectors.
 * Accepts commands via serial and returns results for ACVP validation.
 *
 * Protocol:
 *   Input:  CMD:ALG:LEVEL:HEX_DATA
 *   Output: RESULT:HEX_DATA or ERROR:CODE
 *
 * Commands:
 *   SEED:DRBG:0:hexseed - Seed deterministic RNG
 *   KEYGEN:MLKEM:768:   - Generate ML-KEM keypair
 *   ENCAPS:MLKEM:768:pk - Encapsulate to public key
 *   DECAPS:MLKEM:768:ctsk - Decapsulate ciphertext with secret key
 *   KEYGEN:MLDSA:65:    - Generate ML-DSA keypair
 *   SIGN:MLDSA:65:skmsg - Sign message with secret key
 *   VERIFY:MLDSA:65:pkmsgsig - Verify signature
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/console/console.h>
#include <pqcp_zephyr/acvp_cmd.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

#define MAX_RESPONSE_DATA_LEN PQCP_ACVP_RESPONSE_BYTES_MAX
#define MAX_INPUT_DATA_LEN    PQCP_ACVP_INPUT_BYTES_MAX
#define MAX_LINE_LEN         PQCP_ACVP_COMMAND_LINE_CHARS_MAX
#define CONSOLE_RX_THREAD_STACK_SIZE 1024
#define CONSOLE_RX_THREAD_PRIORITY 5

/* Working buffer for hex decoding */
static uint8_t work_buffer[MAX_INPUT_DATA_LEN];

/* Response buffer for output data */
static uint8_t response_buffer[MAX_RESPONSE_DATA_LEN];

/* Hex output buffer (2x data + null) */
static char response_line[(MAX_RESPONSE_DATA_LEN * 2U) + 64U];

/* Line input buffer */
static char line_buffer[MAX_LINE_LEN];

K_MSGQ_DEFINE(console_rx_msgq, sizeof(char), MAX_LINE_LEN, 4);
K_THREAD_STACK_DEFINE(console_rx_thread_stack, CONSOLE_RX_THREAD_STACK_SIZE);
static struct k_thread console_rx_thread_data;

static void console_rx_thread(void *arg1, void *arg2, void *arg3)
{
    ARG_UNUSED(arg1);
    ARG_UNUSED(arg2);
    ARG_UNUSED(arg3);

    while (1) {
        char ch = console_getchar();

        (void)k_msgq_put(&console_rx_msgq, &ch, K_FOREVER);
    }
}

static int uart_readline(char *line, size_t line_size, size_t *line_len)
{
    struct pqcp_acvp_serial_line_state state;
    char ch;
    int ret;

    pqcp_acvp_serial_line_reset(&state);
    *line_len = 0U;
    line[0] = '\0';

    while (1) {
        k_timeout_t timeout = (state.active || state.overflow) ?
            K_MSEC(CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS) : K_FOREVER;

        ret = k_msgq_get(&console_rx_msgq, &ch, timeout);
        if (ret == -EAGAIN) {
            ret = pqcp_acvp_serial_line_timeout(&state, line, line_size);
            if (ret == -ETIMEDOUT) {
                return ret;
            }
            continue;
        } else if (ret != 0) {
            return ret;
        }

        ret = pqcp_acvp_serial_line_consume_char(&state, ch, line, line_size,
                                                 line_len);
        if (ret != 0) {
            return ret;
        }
    }
}

/* Print help text */
static void print_help(void)
{
    printk("Commands:\n");
    printk("  SEED:DRBG:0:<hexseed>     - Seed deterministic RNG\n");
    printk("  KEYGEN:MLKEM:<512|768|1024>: - Generate ML-KEM keypair\n");
    printk("  ENCAPS:MLKEM:<level>:<pk>    - Encapsulate with public key\n");
    printk("  DECAPS:MLKEM:<level>:<ct||sk> - Decapsulate ciphertext\n");
    printk("  KEYGEN:MLDSA:<44|65|87>:  - Generate ML-DSA keypair\n");
    printk("  SIGN:MLDSA:<level>:<sk||msg> - Sign message\n");
    printk("  VERIFY:MLDSA:<level>:<pk||msg||sig> - Verify signature\n");
    printk("  SELFTEST::                - Run internal self-test\n");
    printk("RESULT:OK\n");
}

static bool is_help_command(const char *line)
{
    return strcmp(line, "HELP") == 0 || strcmp(line, "HELP::") == 0;
}

/* Process and respond to a command */
static void process_and_respond(char *line)
{
    size_t line_len = strlen(line);
    int ret;

    while (line_len > 0U &&
           (line[line_len - 1U] == '\r' || line[line_len - 1U] == '\n')) {
        line[--line_len] = '\0';
    }

    if (line_len == 0U) {
        return;
    }

    ret = pqcp_acvp_validate_command_line(line, line_len);
    if (ret != 0) {
        enum pqcp_acvp_result error_result =
            (ret == -ENOSPC) ? PQCP_ACVP_ERR_BUFFER_TOO_SMALL :
                               PQCP_ACVP_ERR_INVALID_CMD;

        printk("ERROR:%s\n", pqcp_acvp_result_str(error_result));
        return;
    }

    /* Special case: HELP command */
    if (is_help_command(line)) {
        print_help();
        return;
    }

    /* Initialize response */
    struct pqcp_acvp_response resp;
    pqcp_acvp_response_init(&resp, response_buffer, sizeof(response_buffer));

    /* Process the command */
    pqcp_acvp_process_command(line, work_buffer, sizeof(work_buffer), &resp);

    if (pqcp_acvp_format_response_line(&resp, response_line,
                                       sizeof(response_line)) != 0) {
        printk("ERROR:%s\n",
               pqcp_acvp_result_str(PQCP_ACVP_ERR_BUFFER_TOO_SMALL));
        return;
    }

    printk("%s\n", response_line);
}

int main(void)
{
    int ret;

    printk("\n");
    printk("PQCP Serial ACVP Interface\n");
    printk("==========================\n");
    printk("Ready for commands. Format: CMD:ALG:LEVEL:HEX_DATA\n");
    printk("Commands: SEED, KEYGEN, ENCAPS, DECAPS, SIGN, VERIFY, SELFTEST, HELP\n");
    printk("\n");

    /* Initialize RNG */
    pqcp_rng_init();

    console_init();
    k_thread_create(&console_rx_thread_data, console_rx_thread_stack,
                    K_THREAD_STACK_SIZEOF(console_rx_thread_stack),
                    console_rx_thread,
                    NULL, NULL, NULL,
                    CONSOLE_RX_THREAD_PRIORITY, 0, K_NO_WAIT);

    while (1) {
        size_t line_len = 0U;

        printk("> ");

        ret = uart_readline(line_buffer, sizeof(line_buffer), &line_len);
        if (ret == -ENOSPC) {
            printk("ERROR:%s\n",
                   pqcp_acvp_result_str(PQCP_ACVP_ERR_BUFFER_TOO_SMALL));
            continue;
        }

        if (ret == -ETIMEDOUT) {
            printk("ERROR:%s\n",
                   pqcp_acvp_result_str(PQCP_ACVP_ERR_TIMEOUT));
            continue;
        }

        if (ret != 1) {
            continue;
        }

        if (line_len > 0U) {
            process_and_respond(line_buffer);
        }
    }

    return 0;
}
