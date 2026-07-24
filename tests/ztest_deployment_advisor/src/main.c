/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free deployment advisor tests.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_advisor.h>

#define ALL_EVIDENCE PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK

static struct pqcp_deployment_scenario base_scenario(void)
{
	return (struct pqcp_deployment_scenario) {
		.scenario_id = "gateway_kem",
		.operation = PQCP_DEPLOYMENT_OPERATION_KEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.minimum_security_level = 3U,
		.latency_budget_us = 5000U,
		.ram_budget_bytes = 32768U,
		.stack_budget_bytes = 8192U,
		.heap_budget_bytes = 4096U,
		.flash_budget_bytes = 196608U,
		.energy_budget_uj = 1000U,
		.preference = PQCP_DEPLOYMENT_PREFERENCE_BALANCED,
		.required_evidence_level = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT,
		.require_native_provider = true,
		.require_hardware_evidence = true,
	};
}

static struct pqcp_deployment_candidate base_candidate(void)
{
	return (struct pqcp_deployment_candidate) {
		.candidate_id = "mlkem768_m7",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM |
				  PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING |
				  PQCP_DEPLOYMENT_OPERATION_MASK_RECONNECT |
				  PQCP_DEPLOYMENT_OPERATION_MASK_TELEMETRY,
		.security_level = 3U,
		.mlkem_level = 768U,
		.mldsa_level = 0U,
		.latency_us = 1000U,
		.cycles = 400000U,
		.ram_bytes = 8192U,
		.stack_bytes = 2048U,
		.heap_bytes = 1024U,
		.flash_bytes = 49152U,
		.energy_uj = 250U,
		.evidence_mask = ALL_EVIDENCE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	};
}

static struct pqcp_deployment_candidate mldsa_candidate(void)
{
	struct pqcp_deployment_candidate candidate = base_candidate();

	candidate.candidate_id = "mldsa65_m7";
	candidate.kind = PQCP_DEPLOYMENT_CANDIDATE_MLDSA;
	candidate.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_SIGNATURE |
				   PQCP_DEPLOYMENT_OPERATION_MASK_FIRMWARE_UPDATE;
	candidate.mlkem_level = 0U;
	candidate.mldsa_level = 65U;
	return candidate;
}

static struct pqcp_deployment_candidate hybrid_candidate(void)
{
	struct pqcp_deployment_candidate candidate = base_candidate();

	candidate.candidate_id = "hybrid768_65_m7";
	candidate.kind = PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE;
	candidate.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
				   PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING;
	candidate.mldsa_level = 65U;
	candidate.latency_us = 3000U;
	candidate.ram_bytes = 20000U;
	candidate.flash_bytes = 120000U;
	return candidate;
}

static struct pqcp_deployment_candidate_result evaluate(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate)
{
	struct pqcp_deployment_candidate_result result;

	zassert_equal(pqcp_deployment_candidate_evaluate(
			      scenario, candidate, 0U, &result),
		      0);
	return result;
}

ZTEST(pqcp_deployment_advisor, test_string_tokens_and_required_evidence)
{
	zassert_true(strcmp(pqcp_deployment_operation_str(
				    PQCP_DEPLOYMENT_OPERATION_HYBRID_TLS),
			    "hybrid_tls") == 0);
	zassert_true(strcmp(pqcp_deployment_target_class_str(
				    PQCP_DEPLOYMENT_TARGET_CORTEX_M7),
			    "cortex_m7") == 0);
	zassert_true(strcmp(pqcp_deployment_candidate_kind_str(
				    PQCP_DEPLOYMENT_CANDIDATE_MLKEM),
			    "mlkem") == 0);
	zassert_true(strcmp(pqcp_deployment_preference_str(
				    PQCP_DEPLOYMENT_PREFERENCE_COMPACT_ARTIFACTS),
			    "compact_artifacts") == 0);
	zassert_true(strcmp(pqcp_deployment_evidence_level_str(
				    PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT),
			    "product") == 0);
	zassert_true(strcmp(pqcp_deployment_recommendation_status_str(
				    PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED),
			    "ACCEPTED") == 0);
	zassert_true(strcmp(pqcp_deployment_gap_str(
				    PQCP_DEPLOYMENT_GAP_HARDWARE),
			    "hardware") == 0);
	zassert_true(strcmp(pqcp_deployment_gap_str(0x80000000U),
			    "unknown") == 0);
	zassert_true(strcmp(pqcp_deployment_operation_str(
				    (enum pqcp_deployment_operation)99),
			    "unknown") == 0);

	zassert_true((pqcp_deployment_required_evidence_mask(
			      PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE) &
		      PQCP_DEPLOYMENT_EVIDENCE_KAT) != 0U);
	zassert_true((pqcp_deployment_required_evidence_mask(
			      PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PAPER) &
		      PQCP_DEPLOYMENT_EVIDENCE_BASELINE) != 0U);
	zassert_true((pqcp_deployment_required_evidence_mask(
			      PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT) &
		      PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE) != 0U);
	zassert_equal(pqcp_deployment_required_evidence_mask(
			      (enum pqcp_deployment_evidence_level)99),
		      0U);
}

ZTEST(pqcp_deployment_advisor, test_scenario_validation)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	char long_id[PQCP_DEPLOYMENT_ID_MAX_CHARS + 1U];

	memset(long_id, 'a', sizeof(long_id));
	long_id[sizeof(long_id) - 1U] = '\0';

	zassert_equal(pqcp_deployment_scenario_validate(&scenario), 0);
	zassert_equal(pqcp_deployment_scenario_validate(NULL), -EINVAL);

	scenario.scenario_id = "bad id";
	zassert_equal(pqcp_deployment_scenario_validate(&scenario), -EINVAL);
	scenario.scenario_id = long_id;
	zassert_equal(pqcp_deployment_scenario_validate(&scenario), -EINVAL);
	scenario = base_scenario();
	scenario.minimum_security_level = 0U;
	zassert_equal(pqcp_deployment_scenario_validate(&scenario), -EINVAL);
	scenario.minimum_security_level = 6U;
	zassert_equal(pqcp_deployment_scenario_validate(&scenario), -EINVAL);
	scenario = base_scenario();
	scenario.operation = (enum pqcp_deployment_operation)99;
	zassert_equal(pqcp_deployment_scenario_validate(&scenario), -EINVAL);
	scenario = base_scenario();
	scenario.target_class = (enum pqcp_deployment_target_class)99;
	zassert_equal(pqcp_deployment_scenario_validate(&scenario), -EINVAL);
	scenario = base_scenario();
	scenario.preference = (enum pqcp_deployment_preference)99;
	zassert_equal(pqcp_deployment_scenario_validate(&scenario), -EINVAL);
	scenario = base_scenario();
	scenario.required_evidence_level =
		(enum pqcp_deployment_evidence_level)99;
	zassert_equal(pqcp_deployment_scenario_validate(&scenario), -EINVAL);
}

ZTEST(pqcp_deployment_advisor, test_candidate_validation)
{
	struct pqcp_deployment_candidate candidate = base_candidate();

	zassert_equal(pqcp_deployment_candidate_validate(&candidate), 0);
	zassert_equal(pqcp_deployment_candidate_validate(NULL), -EINVAL);

	candidate.candidate_id = "bad/id";
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), -EINVAL);
	candidate = base_candidate();
	candidate.target_class = PQCP_DEPLOYMENT_TARGET_ANY;
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), -EINVAL);
	candidate = base_candidate();
	candidate.operation_mask = 0U;
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), -EINVAL);
	candidate.operation_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), -EINVAL);
	candidate = base_candidate();
	candidate.evidence_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), -EINVAL);
	candidate = base_candidate();
	candidate.mlkem_level = 999U;
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), -EINVAL);
	candidate = base_candidate();
	candidate.mldsa_level = 65U;
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), -EINVAL);

	candidate = mldsa_candidate();
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), 0);
	candidate.mlkem_level = 768U;
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), -EINVAL);
	candidate = mldsa_candidate();
	candidate.mldsa_level = 999U;
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), -EINVAL);

	candidate = hybrid_candidate();
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), 0);
	candidate.mldsa_level = 0U;
	zassert_equal(pqcp_deployment_candidate_validate(&candidate), -EINVAL);
}

ZTEST(pqcp_deployment_advisor, test_complete_candidate_is_accepted)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidate = base_candidate();
	struct pqcp_deployment_candidate_result result =
		evaluate(&scenario, &candidate);

	zassert_equal(result.status,
		      PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED);
	zassert_true(result.feasible);
	zassert_true(result.evidence_ready);
	zassert_equal(result.blocker_mask, 0U);
	zassert_equal(result.gap_mask, 0U);
	zassert_true(result.score > 0U);
	zassert_true(result.confidence > 80U);
}

ZTEST(pqcp_deployment_advisor, test_operation_security_target_and_policy_blockers)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidate = mldsa_candidate();
	struct pqcp_deployment_candidate_result result =
		evaluate(&scenario, &candidate);

	zassert_true((result.blocker_mask &
		      PQCP_DEPLOYMENT_BLOCKER_OPERATION) != 0U);
	zassert_equal(result.status,
		      PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED);

	candidate = base_candidate();
	candidate.security_level = 1U;
	result = evaluate(&scenario, &candidate);
	zassert_true((result.blocker_mask &
		      PQCP_DEPLOYMENT_BLOCKER_SECURITY_LEVEL) != 0U);

	candidate = base_candidate();
	candidate.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M4;
	result = evaluate(&scenario, &candidate);
	zassert_true((result.blocker_mask &
		      PQCP_DEPLOYMENT_BLOCKER_TARGET_CLASS) != 0U);

	candidate = base_candidate();
	candidate.policy_allowed = false;
	result = evaluate(&scenario, &candidate);
	zassert_true((result.blocker_mask &
		      PQCP_DEPLOYMENT_BLOCKER_POLICY) != 0U);

	candidate = base_candidate();
	candidate.native_provider = false;
	result = evaluate(&scenario, &candidate);
	zassert_true((result.blocker_mask &
		      PQCP_DEPLOYMENT_BLOCKER_PROVIDER) != 0U);
}

ZTEST(pqcp_deployment_advisor, test_all_numeric_budget_blockers)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidate = base_candidate();
	struct pqcp_deployment_candidate_result result;

	candidate.latency_us = scenario.latency_budget_us + 1U;
	result = evaluate(&scenario, &candidate);
	zassert_true((result.blocker_mask & PQCP_DEPLOYMENT_BLOCKER_LATENCY) != 0U);
	candidate = base_candidate();
	candidate.ram_bytes = scenario.ram_budget_bytes + 1U;
	result = evaluate(&scenario, &candidate);
	zassert_true((result.blocker_mask & PQCP_DEPLOYMENT_BLOCKER_RAM) != 0U);
	candidate = base_candidate();
	candidate.stack_bytes = scenario.stack_budget_bytes + 1U;
	result = evaluate(&scenario, &candidate);
	zassert_true((result.blocker_mask & PQCP_DEPLOYMENT_BLOCKER_STACK) != 0U);
	candidate = base_candidate();
	candidate.heap_bytes = scenario.heap_budget_bytes + 1U;
	result = evaluate(&scenario, &candidate);
	zassert_true((result.blocker_mask & PQCP_DEPLOYMENT_BLOCKER_HEAP) != 0U);
	candidate = base_candidate();
	candidate.flash_bytes = scenario.flash_budget_bytes + 1U;
	result = evaluate(&scenario, &candidate);
	zassert_true((result.blocker_mask & PQCP_DEPLOYMENT_BLOCKER_FLASH) != 0U);
	candidate = base_candidate();
	candidate.energy_uj = scenario.energy_budget_uj + 1U;
	result = evaluate(&scenario, &candidate);
	zassert_true((result.blocker_mask & PQCP_DEPLOYMENT_BLOCKER_ENERGY) != 0U);
}

ZTEST(pqcp_deployment_advisor, test_missing_metrics_create_conditional_gaps)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidate = base_candidate();
	struct pqcp_deployment_candidate_result result;

	candidate.latency_us = 0U;
	candidate.ram_bytes = 0U;
	candidate.stack_bytes = 0U;
	candidate.heap_bytes = 0U;
	candidate.flash_bytes = 0U;
	candidate.energy_uj = 0U;
	result = evaluate(&scenario, &candidate);

	zassert_equal(result.blocker_mask, 0U);
	zassert_equal(result.status,
		      PQCP_DEPLOYMENT_RECOMMENDATION_CONDITIONAL);
	zassert_true((result.gap_mask & PQCP_DEPLOYMENT_GAP_LATENCY) != 0U);
	zassert_true((result.gap_mask & PQCP_DEPLOYMENT_GAP_RAM) != 0U);
	zassert_true((result.gap_mask & PQCP_DEPLOYMENT_GAP_STACK) != 0U);
	zassert_true((result.gap_mask & PQCP_DEPLOYMENT_GAP_HEAP) != 0U);
	zassert_true((result.gap_mask & PQCP_DEPLOYMENT_GAP_FLASH) != 0U);
	zassert_true((result.gap_mask & PQCP_DEPLOYMENT_GAP_ENERGY) != 0U);
}

ZTEST(pqcp_deployment_advisor, test_evidence_levels_and_environment_gaps)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidate = base_candidate();
	struct pqcp_deployment_candidate_result result;

	scenario.required_evidence_level =
		PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE;
	scenario.require_hardware_evidence = false;
	candidate.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KAT |
				  PQCP_DEPLOYMENT_EVIDENCE_POLICY |
				  PQCP_DEPLOYMENT_EVIDENCE_PROVIDER;
	candidate.independent_evidence = false;
	result = evaluate(&scenario, &candidate);
	zassert_equal(result.status,
		      PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED);

	scenario.required_evidence_level = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PAPER;
	candidate.evidence_mask = pqcp_deployment_required_evidence_mask(
		PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PAPER);
	result = evaluate(&scenario, &candidate);
	zassert_true((result.gap_mask & PQCP_DEPLOYMENT_GAP_SIMULATION) != 0U);
	zassert_true((result.gap_mask & PQCP_DEPLOYMENT_GAP_INDEPENDENT) != 0U);

	candidate.evidence_mask |= PQCP_DEPLOYMENT_EVIDENCE_SIMULATION;
	candidate.independent_evidence = true;
	result = evaluate(&scenario, &candidate);
	zassert_equal(result.status,
		      PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED);

	scenario.required_evidence_level =
		PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT;
	candidate.evidence_mask = pqcp_deployment_required_evidence_mask(
		PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT);
	result = evaluate(&scenario, &candidate);
	zassert_true((result.gap_mask & PQCP_DEPLOYMENT_GAP_HARDWARE) != 0U);
}

ZTEST(pqcp_deployment_advisor, test_advise_ranks_and_summarizes)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidates[] = {
		base_candidate(),
		base_candidate(),
		mldsa_candidate(),
	};
	struct pqcp_deployment_candidate_result results[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_report report;

	candidates[0].candidate_id = "mlkem768_slow";
	candidates[0].latency_us = 3500U;
	candidates[1].candidate_id = "mlkem768_fast";
	candidates[1].latency_us = 500U;

	zassert_equal(pqcp_deployment_advise(
			      &scenario, candidates, ARRAY_SIZE(candidates),
			      results, &report),
		      0);
	zassert_equal(report.candidate_count, ARRAY_SIZE(candidates));
	zassert_equal(report.feasible_count, 2U);
	zassert_equal(report.accepted_count, 2U);
	zassert_equal(report.rejected_count, 1U);
	zassert_true(report.recommendation_ready);
	zassert_equal(results[1].rank, 1U);
	zassert_equal(report.top_result_index, 1U);
}

ZTEST(pqcp_deployment_advisor, test_tie_break_is_stable_by_identifier)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidates[] = {
		base_candidate(),
		base_candidate(),
	};
	struct pqcp_deployment_candidate_result results[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_report report;

	candidates[0].candidate_id = "z_candidate";
	candidates[1].candidate_id = "a_candidate";
	zassert_equal(pqcp_deployment_advise(
			      &scenario, candidates, ARRAY_SIZE(candidates),
			      results, &report),
		      0);
	zassert_equal(results[1].rank, 1U);
	zassert_equal(results[0].rank, 2U);
}

ZTEST(pqcp_deployment_advisor, test_preference_changes_ranking)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidates[] = {
		base_candidate(),
		base_candidate(),
	};
	struct pqcp_deployment_candidate_result results[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_report report;

	candidates[0].candidate_id = "compact";
	candidates[0].latency_us = 3500U;
	candidates[0].ram_bytes = 2048U;
	candidates[0].stack_bytes = 512U;
	candidates[0].heap_bytes = 256U;
	candidates[0].flash_bytes = 12000U;
	candidates[1].candidate_id = "fast";
	candidates[1].latency_us = 500U;
	candidates[1].ram_bytes = 25000U;
	candidates[1].stack_bytes = 7000U;
	candidates[1].heap_bytes = 3500U;
	candidates[1].flash_bytes = 160000U;

	scenario.preference = PQCP_DEPLOYMENT_PREFERENCE_COMPACT_ARTIFACTS;
	zassert_equal(pqcp_deployment_advise(
			      &scenario, candidates, ARRAY_SIZE(candidates),
			      results, &report),
		      0);
	zassert_equal(results[0].rank, 1U);

	scenario.preference = PQCP_DEPLOYMENT_PREFERENCE_LOW_LATENCY;
	zassert_equal(pqcp_deployment_advise(
			      &scenario, candidates, ARRAY_SIZE(candidates),
			      results, &report),
		      0);
	zassert_equal(results[1].rank, 1U);
}

ZTEST(pqcp_deployment_advisor, test_gap_plan_is_prioritized_and_bounded)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidate = base_candidate();
	struct pqcp_deployment_candidate_result result;
	struct pqcp_deployment_report report;
	struct pqcp_deployment_gap_plan_entry entries[PQCP_DEPLOYMENT_MAX_GAPS];
	size_t entry_count = 0U;

	candidate.latency_us = 0U;
	candidate.evidence_mask &= ~PQCP_DEPLOYMENT_EVIDENCE_KAT;
	zassert_equal(pqcp_deployment_advise(
			      &scenario, &candidate, 1U, &result, &report),
		      0);
	zassert_equal(pqcp_deployment_plan_gaps(
			      &scenario, &candidate, &result, 1U, entries,
			      ARRAY_SIZE(entries), &entry_count),
		      0);
	zassert_true(entry_count >= 2U);
	zassert_equal(entries[0].priority, 1U);
	zassert_equal(entries[0].candidate_index, 0U);
	zassert_equal(entries[0].gap, PQCP_DEPLOYMENT_GAP_LATENCY);
	zassert_equal(entries[0].acceptance_max, scenario.latency_budget_us);
	zassert_true(strcmp(entries[0].expected_artifact,
			    "benchmark_latency_transcript") == 0);
	zassert_true(strcmp(entries[0].claim_token,
			    "claim.performance_latency_budget") == 0);

	zassert_equal(pqcp_deployment_plan_gaps(
			      &scenario, &candidate, &result, 1U, entries,
			      1U, &entry_count),
		      -ENOSPC);
	zassert_equal(entry_count, 1U);
}

ZTEST(pqcp_deployment_advisor, test_invalid_candidate_is_retained_as_rejected)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidate = base_candidate();
	struct pqcp_deployment_candidate_result result;
	struct pqcp_deployment_report report;

	candidate.mlkem_level = 999U;
	zassert_equal(pqcp_deployment_advise(
			      &scenario, &candidate, 1U, &result, &report),
		      0);
	zassert_true((result.blocker_mask &
		      PQCP_DEPLOYMENT_BLOCKER_INVALID_FACTS) != 0U);
	zassert_equal(result.status,
		      PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED);
	zassert_equal(report.rejected_count, 1U);
	zassert_equal(report.top_result_index, UINT32_MAX);
}

ZTEST(pqcp_deployment_advisor, test_emitters_validate_and_emit)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidate = base_candidate();
	struct pqcp_deployment_candidate_result result;
	struct pqcp_deployment_report report;
	struct pqcp_deployment_gap_plan_entry entry = {
		.priority = 1U,
		.candidate_index = 0U,
		.candidate_id = "mlkem768_m7",
		.gap = PQCP_DEPLOYMENT_GAP_HARDWARE,
		.maturity = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT,
		.acceptance_max = 0U,
		.expected_artifact = "hardware_benchmark_transcript",
		.claim_token = "claim.deployment_physical_target",
	};

	zassert_equal(pqcp_deployment_advise(
			      &scenario, &candidate, 1U, &result, &report),
		      0);
	zassert_equal(pqcp_deployment_scenario_emit(&scenario), 0);
	zassert_equal(pqcp_deployment_candidate_result_emit(
			      &scenario, &candidate, &result),
		      0);
	zassert_equal(pqcp_deployment_report_emit(&report, &result), 0);
	zassert_equal(pqcp_deployment_gap_plan_entry_emit(&entry), 0);

	entry.expected_artifact = "wrong";
	zassert_equal(pqcp_deployment_gap_plan_entry_emit(&entry), -EBADMSG);
	entry.expected_artifact = "hardware_benchmark_transcript";
	entry.gap = PQCP_DEPLOYMENT_GAP_HARDWARE |
		    PQCP_DEPLOYMENT_GAP_BASELINE;
	zassert_equal(pqcp_deployment_gap_plan_entry_emit(&entry), -EINVAL);
	result.candidate_id = "different";
	zassert_equal(pqcp_deployment_candidate_result_emit(
			      &scenario, &candidate, &result),
		      -EINVAL);
}

ZTEST(pqcp_deployment_advisor, test_invalid_arguments_and_limits)
{
	struct pqcp_deployment_scenario scenario = base_scenario();
	struct pqcp_deployment_candidate candidates[
		PQCP_DEPLOYMENT_MAX_CANDIDATES + 1U];
	struct pqcp_deployment_candidate_result results[
		PQCP_DEPLOYMENT_MAX_CANDIDATES + 1U];
	struct pqcp_deployment_report report;
	struct pqcp_deployment_gap_plan_entry entry;
	size_t entry_count;

	for (size_t i = 0U; i < ARRAY_SIZE(candidates); ++i) {
		candidates[i] = base_candidate();
	}

	zassert_equal(pqcp_deployment_candidate_evaluate(
			      NULL, &candidates[0], 0U, &results[0]),
		      -EINVAL);
	zassert_equal(pqcp_deployment_candidate_evaluate(
			      &scenario, NULL, 0U, &results[0]),
		      -EINVAL);
	zassert_equal(pqcp_deployment_advise(
			      &scenario, candidates, 0U, results, &report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_advise(
			      &scenario, candidates, ARRAY_SIZE(candidates),
			      results, &report),
		      -E2BIG);
	zassert_equal(pqcp_deployment_plan_gaps(
			      &scenario, candidates, results, 1U, &entry, 0U,
			      &entry_count),
		      -EINVAL);
	zassert_equal(pqcp_deployment_scenario_emit(NULL), -EINVAL);
	zassert_equal(pqcp_deployment_report_emit(NULL, results), -EINVAL);
	zassert_equal(pqcp_deployment_gap_plan_entry_emit(NULL), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_advisor, NULL, NULL, NULL, NULL, NULL);
