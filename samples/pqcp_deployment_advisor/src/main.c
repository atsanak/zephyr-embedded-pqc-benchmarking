/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Minimal allocation-free deployment-advisor demonstration.
 */

#include <errno.h>
#include <stdint.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/deployment_advisor.h>

#define REVIEW_EVIDENCE PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK

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
		.evidence_mask = REVIEW_EVIDENCE,
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
		.evidence_mask = REVIEW_EVIDENCE &
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
		.evidence_mask = REVIEW_EVIDENCE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
};

int main(void)
{
	struct pqcp_deployment_candidate_result results[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_gap_plan_entry gaps[PQCP_DEPLOYMENT_MAX_GAPS];
	struct pqcp_deployment_report report;
	size_t gap_count = 0U;
	int ret;

	ret = pqcp_deployment_advise(&scenario, candidates,
				     ARRAY_SIZE(candidates), results, &report);
	if (ret != 0) {
		printk("deployment advisor failed: %d\n", ret);
		return ret;
	}

	(void)pqcp_deployment_scenario_emit(&scenario);
	for (size_t i = 0U; i < ARRAY_SIZE(candidates); ++i) {
		(void)pqcp_deployment_candidate_result_emit(
			&scenario, &candidates[i], &results[i]);
	}

	ret = pqcp_deployment_plan_gaps(
		&scenario, candidates, results, ARRAY_SIZE(candidates), gaps,
		ARRAY_SIZE(gaps), &gap_count);
	if (ret != 0 && ret != -ENOSPC) {
		printk("gap planning failed: %d\n", ret);
		return ret;
	}
	for (size_t i = 0U; i < gap_count; ++i) {
		(void)pqcp_deployment_gap_plan_entry_emit(&gaps[i]);
	}

	return pqcp_deployment_report_emit(&report, results);
}
