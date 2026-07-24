/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Instruction-count constant-time evidence for ML-KEM decapsulation.
 *
 * This test brackets each ML-KEM-768 decapsulation between two no-inline
 * marker functions, pqcp_ct_region_begin() and pqcp_ct_region_end(), whose
 * guest addresses the runner resolves from the ELF symbol table. Under the
 * pqcp_ct_insn TCG plugin (see tools/tcg_ct_plugin and
 * scripts/run_ct_instruction_checks.py) the plugin emits the exact number
 * of guest instructions executed inside every bracketed region.
 *
 * The test itself only exercises the workload deterministically: it runs N
 * decapsulations against a valid ciphertext (regions 0..N-1) and N against a
 * corrupted ciphertext (regions N..2N-1). The instruction-count equality
 * assertion lives in the runner, which reads the plugin outfile. Run without
 * the plugin this is a plain decapsulation smoke test.
 *
 * This is stronger evidence than wall-clock cycles but still NOT a formal
 * constant-time proof: data-dependent memory addressing and
 * microarchitectural effects are out of scope, and the project does not
 * claim ML-KEM is constant-time.
 */

#include <stdint.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

#define CT_INSTR_ITERATIONS 8U

static uint8_t public_key[PQCP_MLKEM_768_PK_SIZE];
static uint8_t secret_key[PQCP_MLKEM_768_SK_SIZE];
static uint8_t valid_ct[PQCP_MLKEM_768_CT_SIZE];
static uint8_t corrupt_ct[PQCP_MLKEM_768_CT_SIZE];
static uint8_t shared_secret[PQCP_MLKEM_SS_SIZE];

/*
 * Marker call sites for the TCG plugin. The volatile asm barrier keeps the
 * call from being optimized away or merged and prevents the surrounding
 * code from being reordered across the region boundary. The tag is for human
 * reading of disassembly only; the plugin keys on the instruction address.
 */
__attribute__((noinline)) void pqcp_ct_region_begin(uint32_t tag)
{
	__asm__ volatile("" : : "r"(tag) : "memory");
}

__attribute__((noinline)) void pqcp_ct_region_end(uint32_t tag)
{
	__asm__ volatile("" : : "r"(tag) : "memory");
}

static void seed_rng(void)
{
	static const uint8_t seed[32] = {
		0x50, 0x51, 0x43, 0x50, 0x2d, 0x43, 0x54, 0x2d,
		0x49, 0x4e, 0x53, 0x4e, 0x2d, 0x54, 0x45, 0x53,
		0x54, 0x2d, 0x53, 0x45, 0x45, 0x44, 0x2d, 0x30,
		0x30, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
	};

	zassert_equal(pqcp_rng_deterministic_seed(seed, sizeof(seed)),
		      PQCP_RNG_SUCCESS);
}

ZTEST(pqcp_ct_instr, test_decap_instruction_count_regions)
{
	seed_rng();

	zassert_equal(pqcp_mlkem_keypair(PQCP_MLKEM_768, public_key,
					 secret_key),
		      PQCP_MLKEM_SUCCESS);
	zassert_equal(pqcp_mlkem_encapsulate(PQCP_MLKEM_768, public_key,
					     valid_ct, shared_secret),
		      PQCP_MLKEM_SUCCESS);

	/* A corrupted ciphertext exercises the implicit-rejection path. */
	memcpy(corrupt_ct, valid_ct, sizeof(corrupt_ct));
	corrupt_ct[0] ^= 0xFFU;
	corrupt_ct[sizeof(corrupt_ct) / 2U] ^= 0xA5U;
	corrupt_ct[sizeof(corrupt_ct) - 1U] ^= 0x5AU;

	for (uint32_t i = 0U; i < CT_INSTR_ITERATIONS; ++i) {
		pqcp_ct_region_begin(0U);
		(void)pqcp_mlkem_decapsulate(PQCP_MLKEM_768, valid_ct,
					     secret_key, shared_secret);
		pqcp_ct_region_end(0U);
	}

	for (uint32_t i = 0U; i < CT_INSTR_ITERATIONS; ++i) {
		pqcp_ct_region_begin(1U);
		(void)pqcp_mlkem_decapsulate(PQCP_MLKEM_768, corrupt_ct,
					     secret_key, shared_secret);
		pqcp_ct_region_end(1U);
	}

	printk("PQCP_CT_INSTR alg=MLKEM-768 iterations=%u regions=%u\n",
	       CT_INSTR_ITERATIONS, 2U * CT_INSTR_ITERATIONS);
}

ZTEST_SUITE(pqcp_ct_instr, NULL, NULL, NULL, NULL, NULL);
