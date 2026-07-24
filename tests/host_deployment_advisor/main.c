/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Fast host-side regression checks for the allocation-free advisor core.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <pqcp_zephyr/deployment_advisor.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define CHECK(expression)                                                       \
	do {                                                                     \
		if (!(expression)) {                                               \
			fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__,    \
				__LINE__, #expression);                              \
			return 1;                                                    \
		}                                                                \
	} while (0)

static const struct pqcp_deployment_scenario scenario = {
	.scenario_id = "m7_device_onboarding",
	.operation = PQCP_DEPLOYMENT_OPERATION_ONBOARDING,
	.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
	.minimum_security_level = 3U,
	.latency_budget_us = 10000U,
	.ram_budget_bytes = 65536U,
	.stack_budget_bytes = 16384U,
	.heap_budget_bytes = 8192U,
	.flash_budget_bytes = 262144U,
	.energy_budget_uj = 2500U,
	.preference = PQCP_DEPLOYMENT_PREFERENCE_BALANCED,
	.required_evidence_level = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT,
	.require_native_provider = true,
	.require_hardware_evidence = true,
};

static const struct pqcp_deployment_candidate candidates[] = {
	{
		.candidate_id = "hybrid768_65_m7",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
				  PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING,
		.security_level = 3U,
		.mlkem_level = 768U,
		.mldsa_level = 65U,
		.latency_us = 7600U,
		.cycles = 3040000U,
		.ram_bytes = 43000U,
		.stack_bytes = 9200U,
		.heap_bytes = 3800U,
		.flash_bytes = 210000U,
		.energy_uj = 1800U,
		.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
	{
		.candidate_id = "hybrid768_65_needs_hw",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
				  PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING,
		.security_level = 3U,
		.mlkem_level = 768U,
		.mldsa_level = 65U,
		.latency_us = 6800U,
		.cycles = 2720000U,
		.ram_bytes = 39000U,
		.stack_bytes = 8500U,
		.heap_bytes = 3400U,
		.flash_bytes = 205000U,
		.energy_uj = 1700U,
		.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK &
				 ~PQCP_DEPLOYMENT_EVIDENCE_HARDWARE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
	{
		.candidate_id = "hybrid1024_87_over_budget",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
				  PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING,
		.security_level = 5U,
		.mlkem_level = 1024U,
		.mldsa_level = 87U,
		.latency_us = 13000U,
		.cycles = 5200000U,
		.ram_bytes = 61000U,
		.stack_bytes = 14000U,
		.heap_bytes = 6000U,
		.flash_bytes = 300000U,
		.energy_uj = 2700U,
		.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
};

static int same_result(
	const struct pqcp_deployment_candidate_result *left,
	const struct pqcp_deployment_candidate_result *right)
{
	return left->candidate_index == right->candidate_index &&
	       left->rank == right->rank &&
	       strcmp(left->candidate_id, right->candidate_id) == 0 &&
	       left->status == right->status &&
	       left->blocker_mask == right->blocker_mask &&
	       left->gap_mask == right->gap_mask &&
	       left->score == right->score &&
	       left->confidence == right->confidence &&
	       left->feasible == right->feasible &&
	       left->evidence_ready == right->evidence_ready;
}

int main(void)
{
	struct pqcp_deployment_candidate_result first[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_candidate_result replay[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_gap_plan_entry gaps[PQCP_DEPLOYMENT_MAX_GAPS];
	struct pqcp_deployment_report first_report;
	struct pqcp_deployment_report replay_report;
	struct pqcp_deployment_scenario invalid = scenario;
	size_t gap_count = 0U;
	int ret;

	ret = pqcp_deployment_advise(
		&scenario, candidates, ARRAY_SIZE(candidates), first,
		&first_report);
	CHECK(ret == 0);
	CHECK(first_report.candidate_count == 3U);
	CHECK(first_report.feasible_count == 2U);
	CHECK(first_report.accepted_count == 1U);
	CHECK(first_report.conditional_count == 1U);
	CHECK(first_report.rejected_count == 1U);
	CHECK(first_report.recommendation_ready);
	CHECK(strcmp(
		      first[first_report.top_result_index].candidate_id,
		      "hybrid768_65_m7") == 0);
	CHECK(first[0].rank == 1U);
	CHECK(first[0].status == PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED);
	CHECK(first[1].status ==
	      PQCP_DEPLOYMENT_RECOMMENDATION_CONDITIONAL);
	CHECK((first[1].gap_mask & PQCP_DEPLOYMENT_GAP_HARDWARE) != 0U);
	CHECK(first[2].status == PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED);
	CHECK((first[2].blocker_mask & PQCP_DEPLOYMENT_BLOCKER_LATENCY) !=
	      0U);
	CHECK((first[2].blocker_mask & PQCP_DEPLOYMENT_BLOCKER_FLASH) != 0U);

	ret = pqcp_deployment_plan_gaps(
		&scenario, candidates, first, ARRAY_SIZE(candidates), gaps,
		ARRAY_SIZE(gaps), &gap_count);
	CHECK(ret == 0);
	CHECK(gap_count == 1U);
	CHECK(gaps[0].gap == PQCP_DEPLOYMENT_GAP_HARDWARE);
	CHECK(strcmp(gaps[0].expected_artifact,
		     "hardware_benchmark_transcript") == 0);

	ret = pqcp_deployment_advise(
		&scenario, candidates, ARRAY_SIZE(candidates), replay,
		&replay_report);
	CHECK(ret == 0);
	for (size_t i = 0U; i < ARRAY_SIZE(candidates); ++i) {
		CHECK(same_result(&first[i], &replay[i]));
	}
	CHECK(first_report.top_result_index == replay_report.top_result_index);

	invalid.scenario_id = "invalid id with spaces";
	CHECK(pqcp_deployment_scenario_validate(&invalid) == -EINVAL);
	CHECK(pqcp_deployment_advise(
		      &scenario, candidates,
		      PQCP_DEPLOYMENT_MAX_CANDIDATES + 1U, first,
		      &first_report) == -E2BIG);

	printf("deployment advisor host checks: PASS "
	       "(accepted=1 conditional=1 rejected=1 gaps=1)\n");
	return 0;
}
