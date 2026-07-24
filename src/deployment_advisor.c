/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free on-device PQC deployment advisor.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/deployment_advisor.h>

struct score_weights {
	uint32_t security;
	uint32_t latency;
	uint32_t footprint;
	uint32_t evidence;
};

struct gap_metadata {
	uint32_t gap;
	const char *name;
	const char *expected_artifact;
	const char *claim_token;
};

static const struct gap_metadata gap_metadata[] = {
	{ PQCP_DEPLOYMENT_GAP_LATENCY, "latency",
	  "benchmark_latency_transcript",
	  "claim.performance_latency_budget" },
	{ PQCP_DEPLOYMENT_GAP_RAM, "ram",
	  "resource_ram_report",
	  "claim.resource_ram_budget" },
	{ PQCP_DEPLOYMENT_GAP_STACK, "stack",
	  "resource_stack_report",
	  "claim.resource_stack_budget" },
	{ PQCP_DEPLOYMENT_GAP_HEAP, "heap",
	  "resource_heap_report",
	  "claim.resource_heap_budget" },
	{ PQCP_DEPLOYMENT_GAP_FLASH, "flash",
	  "resource_flash_report",
	  "claim.resource_flash_budget" },
	{ PQCP_DEPLOYMENT_GAP_ENERGY, "energy",
	  "hardware_energy_report",
	  "claim.performance_energy_budget" },
	{ PQCP_DEPLOYMENT_GAP_KAT, "kat",
	  "kat_transcript",
	  "claim.correctness_known_answer" },
	{ PQCP_DEPLOYMENT_GAP_ACVP, "acvp",
	  "acvp_transcript",
	  "claim.interface_acvp_behavior" },
	{ PQCP_DEPLOYMENT_GAP_CT_SMOKE, "ct_smoke",
	  "ct_smoke_transcript",
	  "claim.security_timing_regression" },
	{ PQCP_DEPLOYMENT_GAP_REPRODUCIBILITY, "reproducibility",
	  "reproducibility_report",
	  "claim.measurement_reproducibility" },
	{ PQCP_DEPLOYMENT_GAP_BASELINE, "baseline",
	  "baseline_comparison_report",
	  "claim.performance_comparison" },
	{ PQCP_DEPLOYMENT_GAP_HARDWARE, "hardware",
	  "hardware_benchmark_transcript",
	  "claim.deployment_physical_target" },
	{ PQCP_DEPLOYMENT_GAP_SIMULATION, "simulation",
	  "qemu_benchmark_transcript",
	  "claim.deployment_simulation_regression" },
	{ PQCP_DEPLOYMENT_GAP_POLICY, "policy",
	  "firmware_policy_marker",
	  "claim.policy_profile_acceptance" },
	{ PQCP_DEPLOYMENT_GAP_PROVIDER, "provider",
	  "provider_contract_marker",
	  "claim.provider_native_binding" },
	{ PQCP_DEPLOYMENT_GAP_TRANSCRIPT, "transcript",
	  "evidence_transcript_manifest",
	  "claim.evidence_hash_binding" },
	{ PQCP_DEPLOYMENT_GAP_INDEPENDENT, "independent",
	  "independent_framework_comparison",
	  "claim.evidence_independent_baseline" },
};

static bool has_text(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool id_is_valid(const char *value)
{
	size_t length;

	if (!has_text(value)) {
		return false;
	}

	length = strlen(value);
	if (length >= PQCP_DEPLOYMENT_ID_MAX_CHARS) {
		return false;
	}

	for (size_t i = 0U; i < length; ++i) {
		char c = value[i];

		if ((c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') ||
		    c == '_' || c == '-' || c == '.') {
			continue;
		}
		return false;
	}

	return true;
}

static bool operation_valid(enum pqcp_deployment_operation value)
{
	return value >= PQCP_DEPLOYMENT_OPERATION_KEM &&
	       value <= PQCP_DEPLOYMENT_OPERATION_TELEMETRY_SESSION;
}

static bool target_valid(enum pqcp_deployment_target_class value)
{
	return value >= PQCP_DEPLOYMENT_TARGET_ANY &&
	       value <= PQCP_DEPLOYMENT_TARGET_GATEWAY;
}

static bool candidate_target_valid(enum pqcp_deployment_target_class value)
{
	return target_valid(value) && value != PQCP_DEPLOYMENT_TARGET_ANY;
}

static bool candidate_kind_valid(enum pqcp_deployment_candidate_kind value)
{
	return value >= PQCP_DEPLOYMENT_CANDIDATE_MLKEM &&
	       value <= PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE;
}

static bool preference_valid(enum pqcp_deployment_preference value)
{
	return value >= PQCP_DEPLOYMENT_PREFERENCE_BALANCED &&
	       value <= PQCP_DEPLOYMENT_PREFERENCE_LOW_LATENCY;
}

static bool evidence_level_valid(enum pqcp_deployment_evidence_level value)
{
	return value >= PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE &&
	       value <= PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PARTNER_DEMO;
}

static bool recommendation_status_valid(
	enum pqcp_deployment_recommendation_status value)
{
	return value >= PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED &&
	       value <= PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED;
}

static bool mlkem_level_valid(uint32_t level)
{
	return level == 512U || level == 768U || level == 1024U;
}

static bool mldsa_level_valid(uint32_t level)
{
	return level == 44U || level == 65U || level == 87U;
}

static bool security_level_valid(uint32_t level)
{
	return level >= 1U && level <= 5U;
}

static bool is_single_bit(uint32_t value)
{
	return value != 0U && (value & (value - 1U)) == 0U;
}

static uint32_t bit_count(uint32_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		count += value & 1U;
		value >>= 1;
	}

	return count;
}

const char *pqcp_deployment_operation_str(enum pqcp_deployment_operation value)
{
	switch (value) {
	case PQCP_DEPLOYMENT_OPERATION_KEM:
		return "kem";
	case PQCP_DEPLOYMENT_OPERATION_SIGNATURE:
		return "signature";
	case PQCP_DEPLOYMENT_OPERATION_HYBRID_TLS:
		return "hybrid_tls";
	case PQCP_DEPLOYMENT_OPERATION_ONBOARDING:
		return "onboarding";
	case PQCP_DEPLOYMENT_OPERATION_RECONNECT:
		return "reconnect";
	case PQCP_DEPLOYMENT_OPERATION_FIRMWARE_UPDATE:
		return "firmware_update";
	case PQCP_DEPLOYMENT_OPERATION_TELEMETRY_SESSION:
		return "telemetry_session";
	default:
		return "unknown";
	}
}

const char *pqcp_deployment_target_class_str(
	enum pqcp_deployment_target_class value)
{
	switch (value) {
	case PQCP_DEPLOYMENT_TARGET_ANY:
		return "any";
	case PQCP_DEPLOYMENT_TARGET_QEMU:
		return "qemu";
	case PQCP_DEPLOYMENT_TARGET_NATIVE_SIM:
		return "native_sim";
	case PQCP_DEPLOYMENT_TARGET_CORTEX_M0:
		return "cortex_m0";
	case PQCP_DEPLOYMENT_TARGET_CORTEX_M4:
		return "cortex_m4";
	case PQCP_DEPLOYMENT_TARGET_CORTEX_M7:
		return "cortex_m7";
	case PQCP_DEPLOYMENT_TARGET_RISCV_MCU:
		return "riscv_mcu";
	case PQCP_DEPLOYMENT_TARGET_GATEWAY:
		return "gateway";
	default:
		return "unknown";
	}
}

const char *pqcp_deployment_candidate_kind_str(
	enum pqcp_deployment_candidate_kind value)
{
	switch (value) {
	case PQCP_DEPLOYMENT_CANDIDATE_MLKEM:
		return "mlkem";
	case PQCP_DEPLOYMENT_CANDIDATE_MLDSA:
		return "mldsa";
	case PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE:
		return "hybrid_suite";
	default:
		return "unknown";
	}
}

const char *pqcp_deployment_preference_str(
	enum pqcp_deployment_preference value)
{
	switch (value) {
	case PQCP_DEPLOYMENT_PREFERENCE_BALANCED:
		return "balanced";
	case PQCP_DEPLOYMENT_PREFERENCE_CONSERVATIVE_SECURITY:
		return "conservative_security";
	case PQCP_DEPLOYMENT_PREFERENCE_COMPACT_ARTIFACTS:
		return "compact_artifacts";
	case PQCP_DEPLOYMENT_PREFERENCE_LOW_LATENCY:
		return "low_latency";
	default:
		return "unknown";
	}
}

const char *pqcp_deployment_evidence_level_str(
	enum pqcp_deployment_evidence_level value)
{
	switch (value) {
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE:
		return "prototype";
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PAPER:
		return "paper";
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT:
		return "product";
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PARTNER_DEMO:
		return "partner_demo";
	default:
		return "unknown";
	}
}

const char *pqcp_deployment_recommendation_status_str(
	enum pqcp_deployment_recommendation_status value)
{
	switch (value) {
	case PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED:
		return "REJECTED";
	case PQCP_DEPLOYMENT_RECOMMENDATION_CONDITIONAL:
		return "CONDITIONAL";
	case PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED:
		return "ACCEPTED";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_deployment_gap_str(uint32_t gap)
{
	for (size_t i = 0U; i < ARRAY_SIZE(gap_metadata); ++i) {
		if (gap_metadata[i].gap == gap) {
			return gap_metadata[i].name;
		}
	}

	return "unknown";
}

uint32_t pqcp_deployment_required_evidence_mask(
	enum pqcp_deployment_evidence_level level)
{
	switch (level) {
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE:
		return PQCP_DEPLOYMENT_EVIDENCE_KAT |
		       PQCP_DEPLOYMENT_EVIDENCE_POLICY |
		       PQCP_DEPLOYMENT_EVIDENCE_PROVIDER;
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PAPER:
		return PQCP_DEPLOYMENT_EVIDENCE_KAT |
		       PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		       PQCP_DEPLOYMENT_EVIDENCE_BASELINE |
		       PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
		       PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
		       PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT:
		return PQCP_DEPLOYMENT_EVIDENCE_KAT |
		       PQCP_DEPLOYMENT_EVIDENCE_ACVP |
		       PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE |
		       PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		       PQCP_DEPLOYMENT_EVIDENCE_POLICY |
		       PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
		       PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
		       PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
		       PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PARTNER_DEMO:
		return PQCP_DEPLOYMENT_EVIDENCE_KAT |
		       PQCP_DEPLOYMENT_EVIDENCE_ACVP |
		       PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		       PQCP_DEPLOYMENT_EVIDENCE_POLICY |
		       PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
		       PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
		       PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
		       PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
	default:
		return 0U;
	}
}

int pqcp_deployment_scenario_validate(
	const struct pqcp_deployment_scenario *scenario)
{
	if (scenario == NULL || !id_is_valid(scenario->scenario_id) ||
	    !operation_valid(scenario->operation) ||
	    !target_valid(scenario->target_class) ||
	    !security_level_valid(scenario->minimum_security_level) ||
	    !preference_valid(scenario->preference) ||
	    !evidence_level_valid(scenario->required_evidence_level)) {
		return -EINVAL;
	}

	return 0;
}

int pqcp_deployment_candidate_validate(
	const struct pqcp_deployment_candidate *candidate)
{
	if (candidate == NULL || !id_is_valid(candidate->candidate_id) ||
	    !candidate_kind_valid(candidate->kind) ||
	    !candidate_target_valid(candidate->target_class) ||
	    candidate->operation_mask == 0U ||
	    (candidate->operation_mask &
	     ~PQCP_DEPLOYMENT_OPERATION_MASK_KNOWN) != 0U ||
	    !security_level_valid(candidate->security_level) ||
	    (candidate->evidence_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK) != 0U) {
		return -EINVAL;
	}

	switch (candidate->kind) {
	case PQCP_DEPLOYMENT_CANDIDATE_MLKEM:
		if (!mlkem_level_valid(candidate->mlkem_level) ||
		    candidate->mldsa_level != 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_DEPLOYMENT_CANDIDATE_MLDSA:
		if (candidate->mlkem_level != 0U ||
		    !mldsa_level_valid(candidate->mldsa_level)) {
			return -EINVAL;
		}
		break;
	case PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE:
		if (!mlkem_level_valid(candidate->mlkem_level) ||
		    !mldsa_level_valid(candidate->mldsa_level)) {
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static uint32_t operation_bit(enum pqcp_deployment_operation operation)
{
	switch (operation) {
	case PQCP_DEPLOYMENT_OPERATION_KEM:
		return PQCP_DEPLOYMENT_OPERATION_MASK_KEM;
	case PQCP_DEPLOYMENT_OPERATION_SIGNATURE:
		return PQCP_DEPLOYMENT_OPERATION_MASK_SIGNATURE;
	case PQCP_DEPLOYMENT_OPERATION_HYBRID_TLS:
		return PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS;
	case PQCP_DEPLOYMENT_OPERATION_ONBOARDING:
		return PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING;
	case PQCP_DEPLOYMENT_OPERATION_RECONNECT:
		return PQCP_DEPLOYMENT_OPERATION_MASK_RECONNECT;
	case PQCP_DEPLOYMENT_OPERATION_FIRMWARE_UPDATE:
		return PQCP_DEPLOYMENT_OPERATION_MASK_FIRMWARE_UPDATE;
	case PQCP_DEPLOYMENT_OPERATION_TELEMETRY_SESSION:
		return PQCP_DEPLOYMENT_OPERATION_MASK_TELEMETRY;
	default:
		return 0U;
	}
}

static uint32_t evidence_to_gap(uint32_t missing_evidence)
{
	uint32_t gaps = 0U;

	if ((missing_evidence & PQCP_DEPLOYMENT_EVIDENCE_KAT) != 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_KAT;
	}
	if ((missing_evidence & PQCP_DEPLOYMENT_EVIDENCE_ACVP) != 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_ACVP;
	}
	if ((missing_evidence & PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE) != 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_CT_SMOKE;
	}
	if ((missing_evidence & PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE) != 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_REPRODUCIBILITY;
	}
	if ((missing_evidence & PQCP_DEPLOYMENT_EVIDENCE_BASELINE) != 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_BASELINE;
	}
	if ((missing_evidence & PQCP_DEPLOYMENT_EVIDENCE_HARDWARE) != 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_HARDWARE;
	}
	if ((missing_evidence & PQCP_DEPLOYMENT_EVIDENCE_SIMULATION) != 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_SIMULATION;
	}
	if ((missing_evidence & PQCP_DEPLOYMENT_EVIDENCE_POLICY) != 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_POLICY;
	}
	if ((missing_evidence & PQCP_DEPLOYMENT_EVIDENCE_PROVIDER) != 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_PROVIDER;
	}
	if ((missing_evidence & PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT) != 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_TRANSCRIPT;
	}

	return gaps;
}

static uint32_t metric_gaps(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate)
{
	uint32_t gaps = 0U;

	if (scenario->latency_budget_us != 0U && candidate->latency_us == 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_LATENCY;
	}
	if (scenario->ram_budget_bytes != 0U && candidate->ram_bytes == 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_RAM;
	}
	if (scenario->stack_budget_bytes != 0U && candidate->stack_bytes == 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_STACK;
	}
	if (scenario->heap_budget_bytes != 0U && candidate->heap_bytes == 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_HEAP;
	}
	if (scenario->flash_budget_bytes != 0U && candidate->flash_bytes == 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_FLASH;
	}
	if (scenario->energy_budget_uj != 0U && candidate->energy_uj == 0U) {
		gaps |= PQCP_DEPLOYMENT_GAP_ENERGY;
	}

	return gaps;
}

static uint32_t budget_blockers(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate)
{
	uint32_t blockers = 0U;

	if (scenario->latency_budget_us != 0U && candidate->latency_us != 0U &&
	    candidate->latency_us > scenario->latency_budget_us) {
		blockers |= PQCP_DEPLOYMENT_BLOCKER_LATENCY;
	}
	if (scenario->ram_budget_bytes != 0U && candidate->ram_bytes != 0U &&
	    candidate->ram_bytes > scenario->ram_budget_bytes) {
		blockers |= PQCP_DEPLOYMENT_BLOCKER_RAM;
	}
	if (scenario->stack_budget_bytes != 0U && candidate->stack_bytes != 0U &&
	    candidate->stack_bytes > scenario->stack_budget_bytes) {
		blockers |= PQCP_DEPLOYMENT_BLOCKER_STACK;
	}
	if (scenario->heap_budget_bytes != 0U && candidate->heap_bytes != 0U &&
	    candidate->heap_bytes > scenario->heap_budget_bytes) {
		blockers |= PQCP_DEPLOYMENT_BLOCKER_HEAP;
	}
	if (scenario->flash_budget_bytes != 0U && candidate->flash_bytes != 0U &&
	    candidate->flash_bytes > scenario->flash_budget_bytes) {
		blockers |= PQCP_DEPLOYMENT_BLOCKER_FLASH;
	}
	if (scenario->energy_budget_uj != 0U && candidate->energy_uj != 0U &&
	    candidate->energy_uj > scenario->energy_budget_uj) {
		blockers |= PQCP_DEPLOYMENT_BLOCKER_ENERGY;
	}

	return blockers;
}

static uint32_t environment_gaps(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate)
{
	uint32_t environments = candidate->evidence_mask &
		(PQCP_DEPLOYMENT_EVIDENCE_HARDWARE |
		 PQCP_DEPLOYMENT_EVIDENCE_SIMULATION);

	if (scenario->require_hardware_evidence ||
	    scenario->required_evidence_level ==
		    PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT) {
		return (candidate->evidence_mask &
			PQCP_DEPLOYMENT_EVIDENCE_HARDWARE) != 0U ?
			0U : PQCP_DEPLOYMENT_GAP_HARDWARE;
	}
	if (scenario->required_evidence_level ==
		    PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PAPER ||
	    scenario->required_evidence_level ==
		    PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PARTNER_DEMO) {
		return environments != 0U ? 0U :
			PQCP_DEPLOYMENT_GAP_SIMULATION;
	}

	return 0U;
}

static uint32_t candidate_gap_mask(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate)
{
	uint32_t required = pqcp_deployment_required_evidence_mask(
		scenario->required_evidence_level);
	uint32_t missing = required & ~candidate->evidence_mask;
	uint32_t gaps = metric_gaps(scenario, candidate) |
			evidence_to_gap(missing) |
			environment_gaps(scenario, candidate);

	if (scenario->required_evidence_level !=
		    PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE &&
	    !candidate->independent_evidence) {
		gaps |= PQCP_DEPLOYMENT_GAP_INDEPENDENT;
	}

	return gaps;
}

static struct score_weights weights_for_preference(
	enum pqcp_deployment_preference preference)
{
	switch (preference) {
	case PQCP_DEPLOYMENT_PREFERENCE_CONSERVATIVE_SECURITY:
		return (struct score_weights) {
			.security = 30U,
			.latency = 10U,
			.footprint = 15U,
			.evidence = 45U,
		};
	case PQCP_DEPLOYMENT_PREFERENCE_COMPACT_ARTIFACTS:
		return (struct score_weights) {
			.security = 15U,
			.latency = 10U,
			.footprint = 35U,
			.evidence = 40U,
		};
	case PQCP_DEPLOYMENT_PREFERENCE_LOW_LATENCY:
		return (struct score_weights) {
			.security = 15U,
			.latency = 35U,
			.footprint = 15U,
			.evidence = 35U,
		};
	case PQCP_DEPLOYMENT_PREFERENCE_BALANCED:
	default:
		return (struct score_weights) {
			.security = 20U,
			.latency = 20U,
			.footprint = 20U,
			.evidence = 40U,
		};
	}
}

static uint32_t metric_budget_score(uint64_t value, uint64_t budget,
				    uint32_t weight)
{
	if (value == 0U) {
		return 0U;
	}
	if (budget == 0U) {
		return weight / 2U;
	}
	if (value > budget) {
		return 0U;
	}
	if (value <= budget / 4U) {
		return weight;
	}
	if (value <= budget / 2U) {
		return (weight * 3U) / 4U;
	}
	if (value <= (budget * 3U) / 4U) {
		return weight / 2U;
	}

	return weight / 4U;
}

static uint32_t footprint_score(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	uint32_t weight)
{
	uint32_t score = 0U;
	uint32_t metrics = 0U;

#define ADD_FOOTPRINT_SCORE(value_, budget_) \
	do { \
		if ((value_) != 0U || (budget_) != 0U) { \
			score += metric_budget_score((value_), (budget_), weight); \
			metrics++; \
		} \
	} while (false)

	ADD_FOOTPRINT_SCORE(candidate->ram_bytes, scenario->ram_budget_bytes);
	ADD_FOOTPRINT_SCORE(candidate->stack_bytes, scenario->stack_budget_bytes);
	ADD_FOOTPRINT_SCORE(candidate->heap_bytes, scenario->heap_budget_bytes);
	ADD_FOOTPRINT_SCORE(candidate->flash_bytes, scenario->flash_budget_bytes);

#undef ADD_FOOTPRINT_SCORE

	if (metrics == 0U) {
		return weight / 2U;
	}

	return score / metrics;
}

static uint32_t evidence_score(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	uint32_t weight)
{
	uint32_t required = pqcp_deployment_required_evidence_mask(
		scenario->required_evidence_level);
	uint32_t required_count = bit_count(required);
	uint32_t present_count = bit_count(required & candidate->evidence_mask);
	uint32_t score;

	if (required_count == 0U) {
		score = weight;
	} else {
		score = (present_count * weight) / required_count;
	}
	if (candidate->independent_evidence && score < weight) {
		score++;
	}

	return score > weight ? weight : score;
}

static uint32_t candidate_score(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	uint32_t blockers)
{
	struct score_weights weights = weights_for_preference(
		scenario->preference);
	uint32_t score;

	if (blockers != 0U) {
		return 0U;
	}

	score = (candidate->security_level * weights.security) / 5U;
	score += metric_budget_score(candidate->latency_us,
				     scenario->latency_budget_us,
				     weights.latency);
	score += footprint_score(scenario, candidate, weights.footprint);
	score += evidence_score(scenario, candidate, weights.evidence);

	return score > 100U ? 100U : score;
}

static uint32_t candidate_confidence(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	uint32_t blockers,
	uint32_t gaps)
{
	uint32_t required = pqcp_deployment_required_evidence_mask(
		scenario->required_evidence_level);
	uint32_t required_count = bit_count(required);
	uint32_t present_count = bit_count(required & candidate->evidence_mask);
	uint32_t confidence = required_count == 0U ?
		70U : (present_count * 70U) / required_count;

	confidence += (bit_count(candidate->evidence_mask) * 20U) /
		      bit_count(PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK);
	if (candidate->independent_evidence) {
		confidence += 10U;
	}
	if (blockers != 0U) {
		confidence /= 2U;
	}
	if (gaps != 0U && confidence > bit_count(gaps) * 2U) {
		confidence -= bit_count(gaps) * 2U;
	}

	return confidence > 100U ? 100U : confidence;
}

int pqcp_deployment_candidate_evaluate(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	uint32_t candidate_index,
	struct pqcp_deployment_candidate_result *result)
{
	uint32_t blockers = 0U;
	uint32_t gaps = 0U;
	bool feasible;
	bool evidence_ready;

	if (pqcp_deployment_scenario_validate(scenario) != 0 ||
	    candidate == NULL || result == NULL) {
		return -EINVAL;
	}

	if (pqcp_deployment_candidate_validate(candidate) != 0) {
		blockers |= PQCP_DEPLOYMENT_BLOCKER_INVALID_FACTS;
	} else {
		if ((candidate->operation_mask & operation_bit(
			     scenario->operation)) == 0U) {
			blockers |= PQCP_DEPLOYMENT_BLOCKER_OPERATION;
		}
		if (candidate->security_level <
		    scenario->minimum_security_level) {
			blockers |= PQCP_DEPLOYMENT_BLOCKER_SECURITY_LEVEL;
		}
		if (scenario->target_class != PQCP_DEPLOYMENT_TARGET_ANY &&
		    candidate->target_class != scenario->target_class) {
			blockers |= PQCP_DEPLOYMENT_BLOCKER_TARGET_CLASS;
		}
		if (!candidate->policy_allowed) {
			blockers |= PQCP_DEPLOYMENT_BLOCKER_POLICY;
		}
		if (scenario->require_native_provider &&
		    !candidate->native_provider) {
			blockers |= PQCP_DEPLOYMENT_BLOCKER_PROVIDER;
		}
		blockers |= budget_blockers(scenario, candidate);
		gaps = candidate_gap_mask(scenario, candidate);
	}

	feasible = blockers == 0U;
	evidence_ready = feasible && gaps == 0U;
	*result = (struct pqcp_deployment_candidate_result) {
		.candidate_index = candidate_index,
		.rank = 0U,
		.candidate_id = candidate->candidate_id,
		.status = evidence_ready ?
			PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED :
			(feasible ? PQCP_DEPLOYMENT_RECOMMENDATION_CONDITIONAL :
				    PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED),
		.blocker_mask = blockers,
		.gap_mask = gaps,
		.score = candidate_score(scenario, candidate, blockers),
		.confidence = candidate_confidence(
			scenario, candidate, blockers, gaps),
		.feasible = feasible,
		.evidence_ready = evidence_ready,
	};

	return 0;
}

static bool result_ranks_before(
	const struct pqcp_deployment_candidate_result *left,
	const struct pqcp_deployment_candidate_result *right)
{
	if (left->status != right->status) {
		return left->status > right->status;
	}
	if (left->score != right->score) {
		return left->score > right->score;
	}
	if (left->confidence != right->confidence) {
		return left->confidence > right->confidence;
	}

	return strcmp(left->candidate_id, right->candidate_id) < 0;
}

static void assign_ranks(struct pqcp_deployment_candidate_result *results,
			 size_t candidate_count)
{
	bool ranked[PQCP_DEPLOYMENT_MAX_CANDIDATES] = { false };
	uint32_t next_rank = 1U;

	for (size_t selected = 0U; selected < candidate_count; ++selected) {
		size_t best = candidate_count;

		for (size_t i = 0U; i < candidate_count; ++i) {
			if (ranked[i] ||
			    results[i].status ==
				    PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED) {
				continue;
			}
			if (best == candidate_count ||
			    result_ranks_before(&results[i], &results[best])) {
				best = i;
			}
		}
		if (best == candidate_count) {
			break;
		}
		results[best].rank = next_rank++;
		ranked[best] = true;
	}
}

int pqcp_deployment_advise(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	size_t candidate_count,
	struct pqcp_deployment_candidate_result *results,
	struct pqcp_deployment_report *report)
{
	uint32_t feasible_count = 0U;
	uint32_t accepted_count = 0U;
	uint32_t conditional_count = 0U;
	uint32_t rejected_count = 0U;
	uint32_t top_result_index = UINT32_MAX;

	if (pqcp_deployment_scenario_validate(scenario) != 0 ||
	    candidates == NULL || results == NULL || report == NULL ||
	    candidate_count == 0U) {
		return -EINVAL;
	}
	if (candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES) {
		return -E2BIG;
	}

	for (size_t i = 0U; i < candidate_count; ++i) {
		int ret = pqcp_deployment_candidate_evaluate(
			scenario, &candidates[i], (uint32_t)i, &results[i]);

		if (ret != 0) {
			return ret;
		}
		if (results[i].feasible) {
			feasible_count++;
		}
		switch (results[i].status) {
		case PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED:
			accepted_count++;
			break;
		case PQCP_DEPLOYMENT_RECOMMENDATION_CONDITIONAL:
			conditional_count++;
			break;
		case PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED:
			rejected_count++;
			break;
		default:
			return -EBADMSG;
		}
	}

	assign_ranks(results, candidate_count);
	for (size_t i = 0U; i < candidate_count; ++i) {
		if (results[i].rank == 1U) {
			top_result_index = (uint32_t)i;
			break;
		}
	}

	*report = (struct pqcp_deployment_report) {
		.schema_version = PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION,
		.scenario_id = scenario->scenario_id,
		.candidate_count = (uint32_t)candidate_count,
		.feasible_count = feasible_count,
		.accepted_count = accepted_count,
		.conditional_count = conditional_count,
		.rejected_count = rejected_count,
		.top_result_index = top_result_index,
		.recommendation_ready = accepted_count > 0U,
	};

	return 0;
}

static const struct gap_metadata *metadata_for_gap(uint32_t gap)
{
	for (size_t i = 0U; i < ARRAY_SIZE(gap_metadata); ++i) {
		if (gap_metadata[i].gap == gap) {
			return &gap_metadata[i];
		}
	}

	return NULL;
}

static uint64_t acceptance_max_for_gap(
	const struct pqcp_deployment_scenario *scenario,
	uint32_t gap)
{
	switch (gap) {
	case PQCP_DEPLOYMENT_GAP_LATENCY:
		return scenario->latency_budget_us;
	case PQCP_DEPLOYMENT_GAP_RAM:
		return scenario->ram_budget_bytes;
	case PQCP_DEPLOYMENT_GAP_STACK:
		return scenario->stack_budget_bytes;
	case PQCP_DEPLOYMENT_GAP_HEAP:
		return scenario->heap_budget_bytes;
	case PQCP_DEPLOYMENT_GAP_FLASH:
		return scenario->flash_budget_bytes;
	case PQCP_DEPLOYMENT_GAP_ENERGY:
		return scenario->energy_budget_uj;
	default:
		return 0U;
	}
}

static size_t result_index_for_rank(
	const struct pqcp_deployment_candidate_result *results,
	size_t candidate_count,
	uint32_t rank)
{
	for (size_t i = 0U; i < candidate_count; ++i) {
		if (results[i].rank == rank) {
			return i;
		}
	}

	return candidate_count;
}

static int append_candidate_gaps(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	const struct pqcp_deployment_candidate_result *result,
	struct pqcp_deployment_gap_plan_entry *entries,
	size_t entry_capacity,
	size_t *written,
	uint32_t *priority)
{
	uint32_t gaps = result->gap_mask;

	for (size_t i = 0U; i < ARRAY_SIZE(gap_metadata); ++i) {
		const struct gap_metadata *metadata = &gap_metadata[i];

		if ((gaps & metadata->gap) == 0U) {
			continue;
		}
		if (*written >= entry_capacity) {
			return -ENOSPC;
		}
		entries[*written] = (struct pqcp_deployment_gap_plan_entry) {
			.priority = (*priority)++,
			.candidate_index = result->candidate_index,
			.candidate_id = candidate->candidate_id,
			.gap = metadata->gap,
			.maturity = scenario->required_evidence_level,
			.acceptance_max = acceptance_max_for_gap(
				scenario, metadata->gap),
			.expected_artifact = metadata->expected_artifact,
			.claim_token = metadata->claim_token,
		};
		(*written)++;
	}

	return 0;
}

int pqcp_deployment_plan_gaps(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	const struct pqcp_deployment_candidate_result *results,
	size_t candidate_count,
	struct pqcp_deployment_gap_plan_entry *entries,
	size_t entry_capacity,
	size_t *entry_count)
{
	bool have_feasible = false;
	size_t written = 0U;
	uint32_t priority = 1U;
	int final_ret = 0;

	if (pqcp_deployment_scenario_validate(scenario) != 0 ||
	    candidates == NULL || results == NULL || entries == NULL ||
	    entry_count == NULL || candidate_count == 0U ||
	    candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES ||
	    entry_capacity == 0U) {
		return -EINVAL;
	}

	for (size_t i = 0U; i < candidate_count; ++i) {
		if (results[i].feasible) {
			have_feasible = true;
			break;
		}
	}

	for (uint32_t rank = 1U; rank <= candidate_count; ++rank) {
		size_t index = result_index_for_rank(results, candidate_count, rank);

		if (index == candidate_count) {
			break;
		}
		if (results[index].gap_mask == 0U) {
			continue;
		}
		if (append_candidate_gaps(
			    scenario, &candidates[index], &results[index],
			    entries, entry_capacity, &written, &priority) != 0) {
			final_ret = -ENOSPC;
			goto out;
		}
	}

	if (!have_feasible) {
		for (size_t i = 0U; i < candidate_count; ++i) {
			if (results[i].status !=
				    PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED ||
			    results[i].gap_mask == 0U) {
				continue;
			}
			if (append_candidate_gaps(
				    scenario, &candidates[i], &results[i],
				    entries, entry_capacity, &written,
				    &priority) != 0) {
				final_ret = -ENOSPC;
				goto out;
			}
		}
	}

out:
	*entry_count = written;
	return final_ret;
}

int pqcp_deployment_scenario_emit(
	const struct pqcp_deployment_scenario *scenario)
{
	if (pqcp_deployment_scenario_validate(scenario) != 0) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_SCENARIO schema=%u id=%s operation=%s target=%s security=%u preference=%s evidence_level=%s latency_budget_us=%llu ram_budget=%llu stack_budget=%llu heap_budget=%llu flash_budget=%llu energy_budget_uj=%llu native_required=%u hardware_required=%u\n",
	       PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION,
	       scenario->scenario_id,
	       pqcp_deployment_operation_str(scenario->operation),
	       pqcp_deployment_target_class_str(scenario->target_class),
	       scenario->minimum_security_level,
	       pqcp_deployment_preference_str(scenario->preference),
	       pqcp_deployment_evidence_level_str(
		       scenario->required_evidence_level),
	       (unsigned long long)scenario->latency_budget_us,
	       (unsigned long long)scenario->ram_budget_bytes,
	       (unsigned long long)scenario->stack_budget_bytes,
	       (unsigned long long)scenario->heap_budget_bytes,
	       (unsigned long long)scenario->flash_budget_bytes,
	       (unsigned long long)scenario->energy_budget_uj,
	       scenario->require_native_provider ? 1U : 0U,
	       scenario->require_hardware_evidence ? 1U : 0U);

	return 0;
}

int pqcp_deployment_candidate_result_emit(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	const struct pqcp_deployment_candidate_result *result)
{
	if (pqcp_deployment_scenario_validate(scenario) != 0 ||
	    candidate == NULL || result == NULL ||
	    !recommendation_status_valid(result->status) ||
	    (result->blocker_mask & ~PQCP_DEPLOYMENT_BLOCKER_KNOWN_MASK) != 0U ||
	    (result->gap_mask & ~PQCP_DEPLOYMENT_GAP_KNOWN_MASK) != 0U ||
	    result->score > 100U || result->confidence > 100U ||
	    !has_text(result->candidate_id) ||
	    strcmp(result->candidate_id, candidate->candidate_id) != 0) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_CANDIDATE scenario=%s rank=%u id=%s kind=%s target=%s status=%s score=%u confidence=%u blockers=0x%08x gaps=0x%08x security=%u mlkem=%u mldsa=%u latency_us=%llu ram=%llu stack=%llu heap=%llu flash=%llu energy_uj=%llu evidence=0x%08x independent=%u\n",
	       scenario->scenario_id,
	       result->rank,
	       candidate->candidate_id,
	       pqcp_deployment_candidate_kind_str(candidate->kind),
	       pqcp_deployment_target_class_str(candidate->target_class),
	       pqcp_deployment_recommendation_status_str(result->status),
	       result->score,
	       result->confidence,
	       result->blocker_mask,
	       result->gap_mask,
	       candidate->security_level,
	       candidate->mlkem_level,
	       candidate->mldsa_level,
	       (unsigned long long)candidate->latency_us,
	       (unsigned long long)candidate->ram_bytes,
	       (unsigned long long)candidate->stack_bytes,
	       (unsigned long long)candidate->heap_bytes,
	       (unsigned long long)candidate->flash_bytes,
	       (unsigned long long)candidate->energy_uj,
	       candidate->evidence_mask,
	       candidate->independent_evidence ? 1U : 0U);

	return 0;
}

int pqcp_deployment_report_emit(
	const struct pqcp_deployment_report *report,
	const struct pqcp_deployment_candidate_result *results)
{
	const char *status;
	const char *top_id = "none";
	uint32_t top_score = 0U;
	uint32_t top_confidence = 0U;

	if (report == NULL || results == NULL ||
	    report->schema_version != PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION ||
	    !id_is_valid(report->scenario_id) ||
	    report->candidate_count == 0U ||
	    report->candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES ||
	    report->feasible_count > report->candidate_count ||
	    report->accepted_count + report->conditional_count +
		    report->rejected_count != report->candidate_count ||
	    report->recommendation_ready != (report->accepted_count > 0U)) {
		return -EINVAL;
	}

	if (report->top_result_index != UINT32_MAX) {
		if (report->top_result_index >= report->candidate_count) {
			return -EINVAL;
		}
		top_id = results[report->top_result_index].candidate_id;
		top_score = results[report->top_result_index].score;
		top_confidence = results[report->top_result_index].confidence;
	}

	status = report->recommendation_ready ? "PASS" :
		(report->conditional_count > 0U ? "WARN" : "FAIL");
	printk("PQCP_DEPLOYMENT_DECISION schema=%u id=%s status=%s candidates=%u feasible=%u accepted=%u conditional=%u rejected=%u top=%s top_score=%u top_confidence=%u\n",
	       report->schema_version,
	       report->scenario_id,
	       status,
	       report->candidate_count,
	       report->feasible_count,
	       report->accepted_count,
	       report->conditional_count,
	       report->rejected_count,
	       top_id,
	       top_score,
	       top_confidence);

	return report->recommendation_ready ? 0 : -ENODATA;
}

int pqcp_deployment_gap_plan_entry_emit(
	const struct pqcp_deployment_gap_plan_entry *entry)
{
	const struct gap_metadata *metadata;

	if (entry == NULL || entry->priority == 0U ||
	    !id_is_valid(entry->candidate_id) ||
	    !is_single_bit(entry->gap) ||
	    (entry->gap & ~PQCP_DEPLOYMENT_GAP_KNOWN_MASK) != 0U ||
	    !evidence_level_valid(entry->maturity) ||
	    !has_text(entry->expected_artifact) ||
	    !has_text(entry->claim_token)) {
		return -EINVAL;
	}

	metadata = metadata_for_gap(entry->gap);
	if (metadata == NULL ||
	    strcmp(metadata->expected_artifact, entry->expected_artifact) != 0 ||
	    strcmp(metadata->claim_token, entry->claim_token) != 0) {
		return -EBADMSG;
	}

	printk("PQCP_DEPLOYMENT_GAP priority=%u candidate=%s gap=%s maturity=%s acceptance_max=%llu expected=%s claim=%s\n",
	       entry->priority,
	       entry->candidate_id,
	       metadata->name,
	       pqcp_deployment_evidence_level_str(entry->maturity),
	       (unsigned long long)entry->acceptance_max,
	       entry->expected_artifact,
	       entry->claim_token);

	return 0;
}
