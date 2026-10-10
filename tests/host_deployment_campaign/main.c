/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Synthetic observations exercise the C pipeline, not hardware performance.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <pqcp_zephyr/deployment_campaign.h>

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "check failed at line %d: %s\n", \
			__LINE__, #condition); \
		return 1; \
	} \
} while (0)

static struct pqcp_deployment_campaign_config config(void)
{
	return (struct pqcp_deployment_campaign_config) {
		.campaign_id = "synthetic_kem_campaign",
		.candidate_template = {
			.candidate_id = "mlkem768_sim",
			.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
			.target_class = PQCP_DEPLOYMENT_TARGET_QEMU,
			.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM,
			.security_level = 3U,
			.mlkem_level = 768U,
			.policy_allowed = true,
			.native_provider = true,
			.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KAT |
				PQCP_DEPLOYMENT_EVIDENCE_POLICY |
				PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
				PQCP_DEPLOYMENT_EVIDENCE_SIMULATION,
		},
		.projection = PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90,
		.min_samples = 5U,
	};
}

static struct pqcp_deployment_campaign_observation observation(uint64_t latency)
{
	return (struct pqcp_deployment_campaign_observation) {
		.passed = true, .latency_us = latency, .cycles = latency * 100U,
		.ram_bytes = 24000U, .stack_bytes = 6000U, .heap_bytes = 1000U,
		.flash_bytes = 80000U,
	};
}

static int campaign_checks(void)
{
	struct pqcp_deployment_campaign_config cfg = config();
	struct pqcp_deployment_campaign_observation storage[5];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary, replay;
	const uint64_t latencies[] = {104U, 100U, 103U, 101U, 102U};
	struct pqcp_deployment_scenario scenario = {
		.scenario_id = "synthetic_simulation",
		.operation = PQCP_DEPLOYMENT_OPERATION_KEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_QEMU,
		.minimum_security_level = 3U,
		.latency_budget_us = 105U, .ram_budget_bytes = 30000U,
		.preference = PQCP_DEPLOYMENT_PREFERENCE_BALANCED,
		.required_evidence_level = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE,
		.require_native_provider = true,
	};
	struct pqcp_deployment_candidate_result result;
	struct pqcp_deployment_report report;

	CHECK(pqcp_deployment_campaign_init(&state, &cfg, storage, 5U) == 0);
	CHECK(pqcp_deployment_campaign_summarize(&state, &summary) == 0);
	CHECK(summary.quality_mask & PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_EMPTY);
	CHECK(!summary.projected_candidate_valid);
	for (size_t i = 0U; i < 5U; ++i) {
		struct pqcp_deployment_campaign_observation obs = observation(latencies[i]);
		CHECK(pqcp_deployment_campaign_add(&state, &obs) == 0);
	}
	CHECK(pqcp_deployment_campaign_summarize(&state, &summary) == 0);
	CHECK(summary.quality_mask == 0U);
	CHECK(summary.latency.min == 100U && summary.latency.max == 104U);
	CHECK(summary.latency.mean == 102U && summary.latency.median == 102U);
	CHECK(summary.latency.p90 == 103U && summary.latency.p99 == 103U);
	CHECK(summary.latency.mad == 1U && summary.latency.cv_bps == 138U);
	CHECK(summary.energy.count == 0U); /* No synthetic energy claim. */
	CHECK(summary.projected_candidate_valid);
	CHECK(summary.projected_candidate.latency_us == 103U);
	CHECK(summary.projected_candidate.ram_bytes == 24000U);
	CHECK(pqcp_deployment_campaign_summarize(&state, &replay) == 0);
	CHECK(memcmp(&summary, &replay, sizeof(summary)) == 0);
	CHECK(pqcp_deployment_campaign_summary_emit(&summary) == 0);
	CHECK(pqcp_deployment_advise(&scenario, &summary.projected_candidate,
				    1U, &result, &report) == 0);
	CHECK(report.recommendation_ready);
	CHECK(pqcp_deployment_report_emit(&report, &result) == 0);
	scenario.latency_budget_us = 102U;
	CHECK(pqcp_deployment_advise(&scenario, &summary.projected_candidate,
				    1U, &result, &report) == 0);
	CHECK(!report.recommendation_ready);
	CHECK(result.blocker_mask & PQCP_DEPLOYMENT_BLOCKER_LATENCY);

	/* Failed observations cannot inherit quality credit from the template. */
	cfg.candidate_template.evidence_mask |= PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE;
	CHECK(pqcp_deployment_campaign_init(&state, &cfg, storage, 5U) == 0);
	for (size_t i = 0U; i < 5U; ++i) {
		struct pqcp_deployment_campaign_observation obs = observation(100U);
		obs.passed = i != 0U;
		CHECK(pqcp_deployment_campaign_add(&state, &obs) == 0);
	}
	CHECK(pqcp_deployment_campaign_summarize(&state, &summary) == 0);
	CHECK(summary.failed_count == 1U && summary.successful_count == 4U);
	CHECK(summary.quality_mask & PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_FAILED_OBSERVATION);
	CHECK(summary.quality_mask & PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_INSUFFICIENT);
	CHECK(!(summary.projected_candidate.evidence_mask &
		PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE));
	CHECK(pqcp_deployment_campaign_summary_emit(&summary) == -ENODATA);

	CHECK(pqcp_deployment_campaign_init(&state, &cfg, storage, 5U) == 0);
	for (size_t i = 0U; i < 5U; ++i) {
		struct pqcp_deployment_campaign_observation obs = observation(i == 4U ? 10000U : 100U);
		if (i == 3U) {
			obs.ram_bytes = 30000U;
		}
		CHECK(pqcp_deployment_campaign_add(&state, &obs) == 0);
	}
	CHECK(pqcp_deployment_campaign_summarize(&state, &summary) == 0);
	CHECK(summary.quality_mask & PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_HIGH_VARIANCE);
	CHECK(summary.quality_mask & PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_OUTLIERS);
	CHECK(summary.quality_mask & PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_STATIC_DRIFT);
	CHECK(summary.projected_candidate.ram_bytes == 30000U);

	CHECK(pqcp_deployment_campaign_init(&state, &cfg, storage, 5U) == 0);
	for (size_t i = 0U; i < 5U; ++i) {
		struct pqcp_deployment_campaign_observation obs = observation(0U);
		obs.ram_bytes = obs.stack_bytes = obs.heap_bytes = obs.flash_bytes = 0U;
		CHECK(pqcp_deployment_campaign_add(&state, &obs) == 0);
	}
	CHECK(pqcp_deployment_campaign_summarize(&state, &summary) == 0);
	CHECK(summary.quality_mask & PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_PERFORMANCE);
	CHECK(summary.quality_mask & PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_RESOURCE);
	CHECK(!summary.projected_candidate_valid);
	CHECK(!(summary.projected_candidate.evidence_mask &
		(PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		 PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE |
		 PQCP_DEPLOYMENT_EVIDENCE_RESOURCE)));
	return 0;
}

static int boundary_checks(void)
{
	struct pqcp_deployment_campaign_config cfg = config();
	struct pqcp_deployment_campaign_observation storage[5];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary;
	struct pqcp_deployment_campaign_observation obs = observation(100U);

	CHECK(pqcp_deployment_campaign_init(NULL, &cfg, storage, 5U) == -EINVAL);
	CHECK(pqcp_deployment_campaign_init(&state, &cfg, storage, 0U) == -EINVAL);
	CHECK(pqcp_deployment_campaign_init(&state, &cfg, storage, 65U) == -EINVAL);
	cfg.campaign_id = "unsafe marker\n";
	CHECK(pqcp_deployment_campaign_init(&state, &cfg, storage, 5U) == -EINVAL);
	cfg = config();
	CHECK(pqcp_deployment_campaign_init(&state, &cfg, storage, 5U) == 0);
	obs.latency_us = UINT64_MAX;
	CHECK(pqcp_deployment_campaign_add(&state, &obs) == -EINVAL);
	obs = observation(100U);
	for (size_t i = 0U; i < 5U; ++i) {
		CHECK(pqcp_deployment_campaign_add(&state, &obs) == 0);
	}
	CHECK(pqcp_deployment_campaign_add(&state, &obs) == -EINVAL);
	state.observation_count = 6U;
	CHECK(pqcp_deployment_campaign_summarize(&state, &summary) == -EINVAL);
	state.observation_count = 5U;
	state.failed_count = 6U;
	CHECK(pqcp_deployment_campaign_summarize(&state, &summary) == -EINVAL);
	CHECK(pqcp_deployment_campaign_add(&state, &obs) == -EINVAL);
	state.failed_count = 0U;
	state.observation_count = 0U;
	state.observation_capacity = 65U;
	CHECK(pqcp_deployment_campaign_add(&state, &obs) == -EINVAL);
	CHECK(pqcp_deployment_campaign_summarize(&state, &summary) == -EINVAL);
	CHECK(pqcp_deployment_campaign_summary_emit(NULL) == -EINVAL);
	return 0;
}

int main(void)
{
	if (campaign_checks() != 0 || boundary_checks() != 0) {
		return 1;
	}
	puts("synthetic campaign/advisor integration and boundary checks: PASS");
	return 0;
}
