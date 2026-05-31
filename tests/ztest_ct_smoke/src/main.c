/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */
/*
 * Constant-time runtime smoke for ML-KEM decapsulation.
 *
 * THIS IS EXPLICITLY A SMOKE TEST, NOT A PROOF.
 *
 * What it does:
 *   - Generates ML-KEM-512/768/1024 keypairs with the deterministic test
 *     RNG so the run is reproducible.
 *   - Encapsulates against the public key to obtain a valid ciphertext +
 *     shared secret.
 *   - Constructs a deliberately invalid ciphertext by flipping the most
 *     significant byte of the valid one.
 *   - Runs decapsulation N times against the valid ciphertext and N
 *     times against the invalid one, measuring k_cycle_get_64() deltas.
 *   - Computes the absolute difference between the two median cycle
 *     counts and asserts it falls under a documented loose bound.
 *
 * What it does NOT prove:
 *   - It is not a formal constant-time proof. A real attacker has
 *     access to far better measurement infrastructure than k_cycle_get
 *     on a simulated CPU.
 *   - On qemu_x86_64 the cycle counter is itself coarse, so a "pass"
 *     here does not extend to physical hardware.
 *   - It does not exercise data-dependent memory access patterns,
 *     cache footprint, or microarchitectural side channels.
 *
 * What it does prove (and why it is still worth shipping):
 *   - That the public ML-KEM decapsulation API has a *first-order*
 *     timing profile that does not visibly bifurcate on validity, which
 *     is exactly the failure mode introduced when a maintainer
 *     accidentally short-circuits decapsulation on an invalid CT.
 *   - That the captured ztest transcript records a measurable variance
 *     number that the assurance ledger can bind to the
 *     security.ct_smoke claim, so a regression is named directly
 *     instead of disappearing into "decap still works".
 *
 * docs/assurance-model.md and docs/publications.md state the same
 * caveats verbatim.
 */

#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

#define CT_SMOKE_ITERATIONS 32U
/* Loose bound: under 50% relative variance between valid and invalid
 * decap medians. Anything larger is symptomatic of an obvious
 * data-dependent branch on the result. We intentionally do NOT set a
 * tight bound here — that would be more honest if we had access to
 * cycle-accurate hardware, but on a simulator a tight bound just
 * generates noise.
 */
#define CT_SMOKE_RELATIVE_BOUND_PERCENT 50U

static const uint8_t ct_smoke_seed[48] = {
	0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
	0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
	0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
	0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
	0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,
};

static uint8_t kem_pk[PQCP_MLKEM_PK_SIZE_MAX];
static uint8_t kem_sk[PQCP_MLKEM_SK_SIZE_MAX];
static uint8_t kem_ct_valid[PQCP_MLKEM_CT_SIZE_MAX];
static uint8_t kem_ct_invalid[PQCP_MLKEM_CT_SIZE_MAX];
static uint8_t kem_ss_throwaway[PQCP_MLKEM_SS_SIZE];

static int compare_uint64(const void *a, const void *b)
{
	uint64_t lhs = *(const uint64_t *)a;
	uint64_t rhs = *(const uint64_t *)b;
	if (lhs < rhs) {
		return -1;
	}
	if (lhs > rhs) {
		return 1;
	}
	return 0;
}

static uint64_t median_u64(uint64_t *samples, size_t n)
{
	qsort(samples, n, sizeof(uint64_t), compare_uint64);
	return samples[n / 2U];
}

static uint64_t mean_u64(const uint64_t *samples, size_t n)
{
	uint64_t total = 0U;

	for (size_t i = 0U; i < n; ++i) {
		total += samples[i];
	}

	return n > 0U ? total / n : 0U;
}

static uint64_t sample_variance_u64(const uint64_t *samples,
				    size_t n,
				    uint64_t mean)
{
	uint64_t total = 0U;

	if (n < 2U) {
		return 0U;
	}

	for (size_t i = 0U; i < n; ++i) {
		uint64_t delta = samples[i] > mean ? samples[i] - mean
						   : mean - samples[i];

		if (delta > 0xffffffffULL) {
			delta = 0xffffffffULL;
		}
		total += delta * delta;
	}

	return total / (n - 1U);
}

static uint64_t welch_t2_x1000(const uint64_t *valid_samples,
			       const uint64_t *invalid_samples,
			       size_t n,
			       uint64_t *mean_valid,
			       uint64_t *mean_invalid)
{
	uint64_t variance_valid;
	uint64_t variance_invalid;
	uint64_t denominator;
	uint64_t delta;

	*mean_valid = mean_u64(valid_samples, n);
	*mean_invalid = mean_u64(invalid_samples, n);
	variance_valid = sample_variance_u64(valid_samples, n, *mean_valid);
	variance_invalid = sample_variance_u64(invalid_samples, n, *mean_invalid);
	denominator = (variance_valid / n) + (variance_invalid / n);
	delta = *mean_valid > *mean_invalid ? *mean_valid - *mean_invalid
					    : *mean_invalid - *mean_valid;

	if (denominator == 0U) {
		return delta == 0U ? 0U : UINT64_MAX;
	}

	return (delta * delta * 1000U) / denominator;
}

static void run_mlkem_decap_ct_smoke(pqcp_mlkem_level_t level, const char *name)
{
	zassert_equal(pqcp_rng_init(), 0);
	zassert_equal(pqcp_rng_deterministic_seed(ct_smoke_seed,
						  sizeof(ct_smoke_seed)),
		      0);

	zassert_equal(pqcp_mlkem_keypair(level, kem_pk, kem_sk),
		      PQCP_MLKEM_SUCCESS);

	zassert_equal(pqcp_mlkem_encapsulate(level, kem_pk,
					     kem_ct_valid,
					     kem_ss_throwaway),
		      PQCP_MLKEM_SUCCESS);

	memcpy(kem_ct_invalid, kem_ct_valid,
	       pqcp_mlkem_ct_size(level));
	kem_ct_invalid[0] ^= 0xFFU;

	uint64_t valid_samples[CT_SMOKE_ITERATIONS];
	uint64_t invalid_samples[CT_SMOKE_ITERATIONS];

	for (size_t i = 0; i < CT_SMOKE_ITERATIONS; ++i) {
		uint64_t t0 = k_cycle_get_64();
		(void)pqcp_mlkem_decapsulate(level, kem_ct_valid,
					     kem_sk, kem_ss_throwaway);
		valid_samples[i] = k_cycle_get_64() - t0;
		if (IS_ENABLED(CONFIG_PQCP_CT_SAMPLE_TRANSCRIPT)) {
			printk("PQCP_CT_SAMPLE alg=%s class=valid idx=%u cycles=%llu\n",
			       name,
			       (unsigned int)i,
			       (unsigned long long)valid_samples[i]);
		}
	}
	for (size_t i = 0; i < CT_SMOKE_ITERATIONS; ++i) {
		uint64_t t0 = k_cycle_get_64();
		(void)pqcp_mlkem_decapsulate(level, kem_ct_invalid,
					     kem_sk, kem_ss_throwaway);
		invalid_samples[i] = k_cycle_get_64() - t0;
		if (IS_ENABLED(CONFIG_PQCP_CT_SAMPLE_TRANSCRIPT)) {
			printk("PQCP_CT_SAMPLE alg=%s class=invalid idx=%u cycles=%llu\n",
			       name,
			       (unsigned int)i,
			       (unsigned long long)invalid_samples[i]);
		}
	}

	uint64_t median_valid = median_u64(valid_samples, CT_SMOKE_ITERATIONS);
	uint64_t median_invalid = median_u64(invalid_samples,
					     CT_SMOKE_ITERATIONS);
	uint64_t mean_valid;
	uint64_t mean_invalid;
	uint64_t t2_x1000 = welch_t2_x1000(valid_samples, invalid_samples,
					   CT_SMOKE_ITERATIONS,
					   &mean_valid, &mean_invalid);

	uint64_t hi = median_valid > median_invalid ? median_valid
						    : median_invalid;
	uint64_t lo = median_valid < median_invalid ? median_valid
						    : median_invalid;
	uint64_t delta = hi - lo;
	uint64_t relative_pct = lo > 0U ? (delta * 100U) / lo : 0U;

	/*
	 * Marker line consumed by the assurance evaluator. Format is
	 * stable: PQCP_CT_SMOKE alg=<NAME> iters=<N> median_valid=<C>
	 *         median_invalid=<C> delta=<C> relative_pct=<P>
	 *         bound_pct=<B>
	 */
	printk("PQCP_CT_SMOKE alg=%s iters=%u "
	       "median_valid=%llu median_invalid=%llu delta=%llu "
	       "relative_pct=%llu bound_pct=%u\n",
	       name,
	       (unsigned int)CT_SMOKE_ITERATIONS,
	       (unsigned long long)median_valid,
	       (unsigned long long)median_invalid,
	       (unsigned long long)delta,
	       (unsigned long long)relative_pct,
	       (unsigned int)CT_SMOKE_RELATIVE_BOUND_PERCENT);

	/*
	 * Additive transcript marker for offline replay. This Welch-style
	 * statistic is intentionally not asserted in the ztest because QEMU's
	 * timer granularity can collapse variance to zero. The release tooling
	 * uses it as named evidence that the distribution was captured.
	 */
	printk("PQCP_CT_TTEST alg=%s iters=%u "
	       "mean_valid=%llu mean_invalid=%llu t2_x1000=%llu\n",
	       name,
	       (unsigned int)CT_SMOKE_ITERATIONS,
	       (unsigned long long)mean_valid,
	       (unsigned long long)mean_invalid,
	       (unsigned long long)t2_x1000);

	zassert_true(relative_pct <= CT_SMOKE_RELATIVE_BOUND_PERCENT,
		     "%s decap median timing variance %llu%% > smoke bound %u%%",
		     name,
		     (unsigned long long)relative_pct,
		     (unsigned int)CT_SMOKE_RELATIVE_BOUND_PERCENT);
}

ZTEST(pqcp_ct_smoke, test_mlkem_decap_timing_profile_does_not_bifurcate)
{
	run_mlkem_decap_ct_smoke(PQCP_MLKEM_512, "MLKEM-512");
	run_mlkem_decap_ct_smoke(PQCP_MLKEM_768, "MLKEM-768");
	run_mlkem_decap_ct_smoke(PQCP_MLKEM_1024, "MLKEM-1024");
}

ZTEST_SUITE(pqcp_ct_smoke, NULL, NULL, NULL, NULL, NULL);
