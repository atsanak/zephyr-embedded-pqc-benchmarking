/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Protocol Benchmark Sample
 */

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/bench.h>

int main(void)
{
    printk("\n");
    printk("========================================\n");
    printk("  PQCP Protocol Benchmark Sample\n");
    printk("========================================\n\n");
    printk("Running protocol self-test benchmarks with %d iterations per suite\n",
           CONFIG_PQCP_BENCH_ITERATIONS);

    pqcp_bench_run_protocol_all();

    printk("\n========================================\n");
    printk("  Protocol benchmark completed!\n");
    printk("========================================\n");

    return 0;
}
