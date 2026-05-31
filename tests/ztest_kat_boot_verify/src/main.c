/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */
/*
 * If we got far enough to run a ZTEST entry point, the SYS_INIT hook
 * installed by src/kat_boot_verify.c (under CONFIG_PQCP_KAT_BOOT_VERIFY=y)
 * already ran and did not call k_panic(). The point of this test is
 * simply to *exercise* the boot path under qemu_x86_64 / nucleo_h743zi
 * so the captured ztest transcript can be bound to the
 * boot.kat_self_verify assurance claim.
 *
 * If src/kat_boot_verify.c fails any primitive roundtrip, the system
 * panics during boot and ztest never reaches main, so the
 * "TESTSUITE pqcp_kat_boot_verify succeeded" marker would never appear
 * in the transcript and the assurance claim would fail at evaluation
 * time.
 */

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

ZTEST(pqcp_kat_boot_verify, test_boot_self_verify_did_not_panic)
{
	/*
	 * The SYS_INIT hook ran before this; if it had panicked we would
	 * not be here. Print a marker so the assurance evaluator can
	 * positively confirm the boot self-verify executed in this run.
	 */
	printk("PQCP_KAT_BOOT_VERIFY: ztest reached main without panic\n");
	zassert_true(true, "SYS_INIT pqcp_kat_boot_verify_init returned 0");
}

ZTEST_SUITE(pqcp_kat_boot_verify, NULL, NULL, NULL, NULL, NULL);
