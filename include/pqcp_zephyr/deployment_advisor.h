/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - On-device PQC deployment advisor
 *
 * Stability: experimental decision-support API. This API evaluates
 * caller-supplied benchmark and evidence facts. It does not select providers,
 * execute cryptographic operations, or claim certification.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_ADVISOR_H_
#define PQCP_ZEPHYR_DEPLOYMENT_ADVISOR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment-advisor markers and result structures. */
#define PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION 1U

/** Maximum number of candidates accepted by one evaluation call. */
#define PQCP_DEPLOYMENT_MAX_CANDIDATES 16U
/** Maximum number of evidence-gap plan entries returned by one call. */
#define PQCP_DEPLOYMENT_MAX_GAPS 32U
/** Maximum length, including NUL, for caller-provided stable identifiers. */
#define PQCP_DEPLOYMENT_ID_MAX_CHARS 48U

/** Candidate supports KEM establishment. */
#define PQCP_DEPLOYMENT_OPERATION_MASK_KEM              (1U << 0)
/** Candidate supports message or artifact signatures. */
#define PQCP_DEPLOYMENT_OPERATION_MASK_SIGNATURE        (1U << 1)
/** Candidate supports a hybrid TLS-style handshake. */
#define PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS       (1U << 2)
/** Candidate supports device onboarding. */
#define PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING       (1U << 3)
/** Candidate supports reconnect/session resumption. */
#define PQCP_DEPLOYMENT_OPERATION_MASK_RECONNECT        (1U << 4)
/** Candidate supports firmware-update verification. */
#define PQCP_DEPLOYMENT_OPERATION_MASK_FIRMWARE_UPDATE  (1U << 5)
/** Candidate supports telemetry-session establishment. */
#define PQCP_DEPLOYMENT_OPERATION_MASK_TELEMETRY        (1U << 6)

/** All operation bits known by this API version. */
#define PQCP_DEPLOYMENT_OPERATION_MASK_KNOWN \
	(PQCP_DEPLOYMENT_OPERATION_MASK_KEM | \
	 PQCP_DEPLOYMENT_OPERATION_MASK_SIGNATURE | \
	 PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS | \
	 PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING | \
	 PQCP_DEPLOYMENT_OPERATION_MASK_RECONNECT | \
	 PQCP_DEPLOYMENT_OPERATION_MASK_FIRMWARE_UPDATE | \
	 PQCP_DEPLOYMENT_OPERATION_MASK_TELEMETRY)

/** Evidence includes a known-answer test result. */
#define PQCP_DEPLOYMENT_EVIDENCE_KAT              (1U << 0)
/** Evidence includes an ACVP-style interface result. */
#define PQCP_DEPLOYMENT_EVIDENCE_ACVP             (1U << 1)
/** Evidence includes timing-smoke regression output. */
#define PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE         (1U << 2)
/** Evidence includes repeated/reproducible measurement output. */
#define PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE     (1U << 3)
/** Evidence includes an independent or local comparison baseline. */
#define PQCP_DEPLOYMENT_EVIDENCE_BASELINE         (1U << 4)
/** Evidence includes a physical-hardware run. */
#define PQCP_DEPLOYMENT_EVIDENCE_HARDWARE         (1U << 5)
/** Evidence includes a QEMU or native-simulation run. */
#define PQCP_DEPLOYMENT_EVIDENCE_SIMULATION       (1U << 6)
/** Evidence includes a passing firmware-policy appraisal. */
#define PQCP_DEPLOYMENT_EVIDENCE_POLICY           (1U << 7)
/** Evidence includes a passing provider-contract appraisal. */
#define PQCP_DEPLOYMENT_EVIDENCE_PROVIDER         (1U << 8)
/** Evidence includes a hash-bound execution transcript. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT       (1U << 9)
/** Evidence includes a resource/footprint measurement. */
#define PQCP_DEPLOYMENT_EVIDENCE_RESOURCE         (1U << 10)
/** Evidence includes a latency/cycle measurement. */
#define PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE      (1U << 11)

/** All evidence bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_KAT | \
	 PQCP_DEPLOYMENT_EVIDENCE_ACVP | \
	 PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE | \
	 PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE | \
	 PQCP_DEPLOYMENT_EVIDENCE_BASELINE | \
	 PQCP_DEPLOYMENT_EVIDENCE_HARDWARE | \
	 PQCP_DEPLOYMENT_EVIDENCE_SIMULATION | \
	 PQCP_DEPLOYMENT_EVIDENCE_POLICY | \
	 PQCP_DEPLOYMENT_EVIDENCE_PROVIDER | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT | \
	 PQCP_DEPLOYMENT_EVIDENCE_RESOURCE | \
	 PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE)

/** Candidate does not support the scenario operation. */
#define PQCP_DEPLOYMENT_BLOCKER_OPERATION       (1U << 0)
/** Candidate security level is below the scenario requirement. */
#define PQCP_DEPLOYMENT_BLOCKER_SECURITY_LEVEL  (1U << 1)
/** Candidate target class does not match the required target class. */
#define PQCP_DEPLOYMENT_BLOCKER_TARGET_CLASS    (1U << 2)
/** Candidate latency exceeds the scenario budget. */
#define PQCP_DEPLOYMENT_BLOCKER_LATENCY         (1U << 3)
/** Candidate RAM use exceeds the scenario budget. */
#define PQCP_DEPLOYMENT_BLOCKER_RAM             (1U << 4)
/** Candidate stack use exceeds the scenario budget. */
#define PQCP_DEPLOYMENT_BLOCKER_STACK           (1U << 5)
/** Candidate heap use exceeds the scenario budget. */
#define PQCP_DEPLOYMENT_BLOCKER_HEAP            (1U << 6)
/** Candidate flash/code size exceeds the scenario budget. */
#define PQCP_DEPLOYMENT_BLOCKER_FLASH           (1U << 7)
/** Candidate energy use exceeds the scenario budget. */
#define PQCP_DEPLOYMENT_BLOCKER_ENERGY          (1U << 8)
/** Candidate is forbidden by caller-supplied policy state. */
#define PQCP_DEPLOYMENT_BLOCKER_POLICY          (1U << 9)
/** Candidate provider is not accepted for the requested scenario. */
#define PQCP_DEPLOYMENT_BLOCKER_PROVIDER        (1U << 10)
/** Candidate fields are internally invalid. */
#define PQCP_DEPLOYMENT_BLOCKER_INVALID_FACTS   (1U << 11)

/** All blocker bits known by this API version. */
#define PQCP_DEPLOYMENT_BLOCKER_KNOWN_MASK \
	(PQCP_DEPLOYMENT_BLOCKER_OPERATION | \
	 PQCP_DEPLOYMENT_BLOCKER_SECURITY_LEVEL | \
	 PQCP_DEPLOYMENT_BLOCKER_TARGET_CLASS | \
	 PQCP_DEPLOYMENT_BLOCKER_LATENCY | \
	 PQCP_DEPLOYMENT_BLOCKER_RAM | \
	 PQCP_DEPLOYMENT_BLOCKER_STACK | \
	 PQCP_DEPLOYMENT_BLOCKER_HEAP | \
	 PQCP_DEPLOYMENT_BLOCKER_FLASH | \
	 PQCP_DEPLOYMENT_BLOCKER_ENERGY | \
	 PQCP_DEPLOYMENT_BLOCKER_POLICY | \
	 PQCP_DEPLOYMENT_BLOCKER_PROVIDER | \
	 PQCP_DEPLOYMENT_BLOCKER_INVALID_FACTS)

/** Latency measurement is missing. */
#define PQCP_DEPLOYMENT_GAP_LATENCY          (1U << 0)
/** RAM measurement is missing. */
#define PQCP_DEPLOYMENT_GAP_RAM              (1U << 1)
/** Stack measurement is missing. */
#define PQCP_DEPLOYMENT_GAP_STACK            (1U << 2)
/** Heap measurement is missing. */
#define PQCP_DEPLOYMENT_GAP_HEAP             (1U << 3)
/** Flash/code-size measurement is missing. */
#define PQCP_DEPLOYMENT_GAP_FLASH            (1U << 4)
/** Energy measurement is missing. */
#define PQCP_DEPLOYMENT_GAP_ENERGY           (1U << 5)
/** Known-answer validation is missing. */
#define PQCP_DEPLOYMENT_GAP_KAT              (1U << 6)
/** ACVP-style interface validation is missing. */
#define PQCP_DEPLOYMENT_GAP_ACVP             (1U << 7)
/** Timing-smoke evidence is missing. */
#define PQCP_DEPLOYMENT_GAP_CT_SMOKE         (1U << 8)
/** Reproducibility evidence is missing. */
#define PQCP_DEPLOYMENT_GAP_REPRODUCIBILITY  (1U << 9)
/** Comparison baseline is missing. */
#define PQCP_DEPLOYMENT_GAP_BASELINE         (1U << 10)
/** Physical hardware evidence is missing. */
#define PQCP_DEPLOYMENT_GAP_HARDWARE         (1U << 11)
/** Simulation evidence is missing. */
#define PQCP_DEPLOYMENT_GAP_SIMULATION       (1U << 12)
/** Firmware policy evidence is missing. */
#define PQCP_DEPLOYMENT_GAP_POLICY           (1U << 13)
/** Provider-contract evidence is missing. */
#define PQCP_DEPLOYMENT_GAP_PROVIDER         (1U << 14)
/** Hash-bound transcript evidence is missing. */
#define PQCP_DEPLOYMENT_GAP_TRANSCRIPT       (1U << 15)
/** Candidate has no independent external evidence. */
#define PQCP_DEPLOYMENT_GAP_INDEPENDENT      (1U << 16)

/** All evidence-gap bits known by this API version. */
#define PQCP_DEPLOYMENT_GAP_KNOWN_MASK \
	(PQCP_DEPLOYMENT_GAP_LATENCY | \
	 PQCP_DEPLOYMENT_GAP_RAM | \
	 PQCP_DEPLOYMENT_GAP_STACK | \
	 PQCP_DEPLOYMENT_GAP_HEAP | \
	 PQCP_DEPLOYMENT_GAP_FLASH | \
	 PQCP_DEPLOYMENT_GAP_ENERGY | \
	 PQCP_DEPLOYMENT_GAP_KAT | \
	 PQCP_DEPLOYMENT_GAP_ACVP | \
	 PQCP_DEPLOYMENT_GAP_CT_SMOKE | \
	 PQCP_DEPLOYMENT_GAP_REPRODUCIBILITY | \
	 PQCP_DEPLOYMENT_GAP_BASELINE | \
	 PQCP_DEPLOYMENT_GAP_HARDWARE | \
	 PQCP_DEPLOYMENT_GAP_SIMULATION | \
	 PQCP_DEPLOYMENT_GAP_POLICY | \
	 PQCP_DEPLOYMENT_GAP_PROVIDER | \
	 PQCP_DEPLOYMENT_GAP_TRANSCRIPT | \
	 PQCP_DEPLOYMENT_GAP_INDEPENDENT)

/** Type of deployment operation being evaluated. */
enum pqcp_deployment_operation {
	PQCP_DEPLOYMENT_OPERATION_KEM = 0,
	PQCP_DEPLOYMENT_OPERATION_SIGNATURE,
	PQCP_DEPLOYMENT_OPERATION_HYBRID_TLS,
	PQCP_DEPLOYMENT_OPERATION_ONBOARDING,
	PQCP_DEPLOYMENT_OPERATION_RECONNECT,
	PQCP_DEPLOYMENT_OPERATION_FIRMWARE_UPDATE,
	PQCP_DEPLOYMENT_OPERATION_TELEMETRY_SESSION,
};

/** Device/target class represented by a scenario or evidence candidate. */
enum pqcp_deployment_target_class {
	PQCP_DEPLOYMENT_TARGET_ANY = 0,
	PQCP_DEPLOYMENT_TARGET_QEMU,
	PQCP_DEPLOYMENT_TARGET_NATIVE_SIM,
	PQCP_DEPLOYMENT_TARGET_CORTEX_M0,
	PQCP_DEPLOYMENT_TARGET_CORTEX_M4,
	PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
	PQCP_DEPLOYMENT_TARGET_RISCV_MCU,
	PQCP_DEPLOYMENT_TARGET_GATEWAY,
};

/** Candidate algorithm family shape. */
enum pqcp_deployment_candidate_kind {
	PQCP_DEPLOYMENT_CANDIDATE_MLKEM = 0,
	PQCP_DEPLOYMENT_CANDIDATE_MLDSA,
	PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE,
};

/** Scenario optimization preference. */
enum pqcp_deployment_preference {
	PQCP_DEPLOYMENT_PREFERENCE_BALANCED = 0,
	PQCP_DEPLOYMENT_PREFERENCE_CONSERVATIVE_SECURITY,
	PQCP_DEPLOYMENT_PREFERENCE_COMPACT_ARTIFACTS,
	PQCP_DEPLOYMENT_PREFERENCE_LOW_LATENCY,
};

/** Requested maturity of the recommendation evidence. */
enum pqcp_deployment_evidence_level {
	PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE = 0,
	PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PAPER,
	PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT,
	PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PARTNER_DEMO,
};

/** Candidate recommendation state. */
enum pqcp_deployment_recommendation_status {
	PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED = 0,
	PQCP_DEPLOYMENT_RECOMMENDATION_CONDITIONAL,
	PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED,
};

/** One constrained deployment scenario. Zero-valued budgets are unspecified. */
struct pqcp_deployment_scenario {
	/** Stable caller-owned scenario identifier. */
	const char *scenario_id;
	/** Required operation. */
	enum pqcp_deployment_operation operation;
	/** Required target class, or ANY. */
	enum pqcp_deployment_target_class target_class;
	/** Minimum NIST security level, normally 1, 2, 3, or 5. */
	uint32_t minimum_security_level;
	/** Maximum operation or flow latency in microseconds. */
	uint64_t latency_budget_us;
	/** Maximum RAM footprint in bytes. */
	uint64_t ram_budget_bytes;
	/** Maximum stack footprint in bytes. */
	uint64_t stack_budget_bytes;
	/** Maximum heap footprint in bytes. */
	uint64_t heap_budget_bytes;
	/** Maximum flash/code footprint in bytes. */
	uint64_t flash_budget_bytes;
	/** Maximum measured energy in microjoules. */
	uint64_t energy_budget_uj;
	/** Ranking preference. */
	enum pqcp_deployment_preference preference;
	/** Required evidence maturity. */
	enum pqcp_deployment_evidence_level required_evidence_level;
	/** True when only native-provider candidates may be accepted. */
	bool require_native_provider;
	/** True when physical-hardware evidence is mandatory. */
	bool require_hardware_evidence;
};

/** Measured facts and evidence flags for one deployment candidate. */
struct pqcp_deployment_candidate {
	/** Stable caller-owned candidate identifier. */
	const char *candidate_id;
	/** Candidate shape. */
	enum pqcp_deployment_candidate_kind kind;
	/** Target class represented by these measurements. */
	enum pqcp_deployment_target_class target_class;
	/** Supported operation bit mask. */
	uint32_t operation_mask;
	/** Effective NIST security level. */
	uint32_t security_level;
	/** ML-KEM parameter level, or zero when not used. */
	uint32_t mlkem_level;
	/** ML-DSA parameter level, or zero when not used. */
	uint32_t mldsa_level;
	/** Measured latency in microseconds, or zero when unavailable. */
	uint64_t latency_us;
	/** Measured cycle count, or zero when unavailable. */
	uint64_t cycles;
	/** Measured RAM footprint in bytes, or zero when unavailable. */
	uint64_t ram_bytes;
	/** Measured stack footprint in bytes, or zero when unavailable. */
	uint64_t stack_bytes;
	/** Measured heap footprint in bytes, or zero when unavailable. */
	uint64_t heap_bytes;
	/** Measured flash/code footprint in bytes, or zero when unavailable. */
	uint64_t flash_bytes;
	/** Measured energy in microjoules, or zero when unavailable. */
	uint64_t energy_uj;
	/** Available PQCP_DEPLOYMENT_EVIDENCE_* bit mask. */
	uint32_t evidence_mask;
	/** True when a second independent evidence source is represented. */
	bool independent_evidence;
	/** True when caller policy allows this candidate. */
	bool policy_allowed;
	/** True when candidate uses an accepted native provider. */
	bool native_provider;
};

/** Evaluation and ranking result for one candidate. */
struct pqcp_deployment_candidate_result {
	/** Index of the candidate in the caller-provided array. */
	uint32_t candidate_index;
	/** One-based rank after evaluation. Zero means rejected/unranked. */
	uint32_t rank;
	/** Stable candidate identifier. */
	const char *candidate_id;
	/** Recommendation state. */
	enum pqcp_deployment_recommendation_status status;
	/** Hard blocker bit mask. */
	uint32_t blocker_mask;
	/** Missing evidence/measurement bit mask. */
	uint32_t gap_mask;
	/** Deterministic weighted score from 0 to 100. */
	uint32_t score;
	/** Evidence-derived confidence from 0 to 100. */
	uint32_t confidence;
	/** True when all hard constraints passed. */
	bool feasible;
	/** True when required evidence maturity is satisfied. */
	bool evidence_ready;
};

/** Complete deployment-advisor report. */
struct pqcp_deployment_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Stable scenario identifier. */
	const char *scenario_id;
	/** Number of evaluated candidates. */
	uint32_t candidate_count;
	/** Number of feasible candidates. */
	uint32_t feasible_count;
	/** Number of accepted candidates. */
	uint32_t accepted_count;
	/** Number of conditional candidates. */
	uint32_t conditional_count;
	/** Number of rejected candidates. */
	uint32_t rejected_count;
	/** Index into results for the highest-ranked candidate. */
	uint32_t top_result_index;
	/** True when at least one candidate is accepted. */
	bool recommendation_ready;
};

/** One prioritized missing-evidence experiment proposal. */
struct pqcp_deployment_gap_plan_entry {
	/** One-based priority; lower is more urgent. */
	uint32_t priority;
	/** Index of the candidate that needs this experiment. */
	uint32_t candidate_index;
	/** Stable candidate identifier. */
	const char *candidate_id;
	/** One PQCP_DEPLOYMENT_GAP_* bit. */
	uint32_t gap;
	/** Required evidence maturity this experiment supports. */
	enum pqcp_deployment_evidence_level maturity;
	/** Maximum acceptable value for numeric metric gaps, or zero. */
	uint64_t acceptance_max;
	/** Stable artifact/marker token expected from the experiment. */
	const char *expected_artifact;
	/** Stable paper/product claim token supported by the experiment. */
	const char *claim_token;
};

/** Convert an operation to a stable transcript token. */
const char *pqcp_deployment_operation_str(enum pqcp_deployment_operation value);
/** Convert a target class to a stable transcript token. */
const char *pqcp_deployment_target_class_str(
	enum pqcp_deployment_target_class value);
/** Convert a candidate kind to a stable transcript token. */
const char *pqcp_deployment_candidate_kind_str(
	enum pqcp_deployment_candidate_kind value);
/** Convert a preference to a stable transcript token. */
const char *pqcp_deployment_preference_str(
	enum pqcp_deployment_preference value);
/** Convert an evidence level to a stable transcript token. */
const char *pqcp_deployment_evidence_level_str(
	enum pqcp_deployment_evidence_level value);
/** Convert a recommendation state to a stable transcript token. */
const char *pqcp_deployment_recommendation_status_str(
	enum pqcp_deployment_recommendation_status value);
/** Convert one evidence-gap bit to a stable transcript token. */
const char *pqcp_deployment_gap_str(uint32_t gap);

/**
 * @brief Return required evidence bits for an evidence maturity level.
 *
 * @param level Evidence maturity.
 *
 * @return PQCP_DEPLOYMENT_EVIDENCE_* mask, or zero for invalid values.
 */
uint32_t pqcp_deployment_required_evidence_mask(
	enum pqcp_deployment_evidence_level level);

/**
 * @brief Validate a deployment scenario.
 *
 * @retval 0 Scenario is valid.
 * @retval -EINVAL Scenario is malformed or contains unsupported values.
 */
int pqcp_deployment_scenario_validate(
	const struct pqcp_deployment_scenario *scenario);

/**
 * @brief Validate one deployment candidate.
 *
 * @retval 0 Candidate is internally consistent.
 * @retval -EINVAL Candidate is malformed.
 */
int pqcp_deployment_candidate_validate(
	const struct pqcp_deployment_candidate *candidate);

/**
 * @brief Evaluate one candidate against one scenario.
 *
 * @param scenario Scenario constraints.
 * @param candidate Candidate facts.
 * @param candidate_index Candidate's index in its source array.
 * @param result Caller-owned evaluation output.
 *
 * @retval 0 Result populated.
 * @retval -EINVAL Invalid pointer or malformed scenario.
 */
int pqcp_deployment_candidate_evaluate(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	uint32_t candidate_index,
	struct pqcp_deployment_candidate_result *result);

/**
 * @brief Evaluate and rank a candidate set without dynamic allocation.
 *
 * @param scenario Scenario constraints.
 * @param candidates Candidate array.
 * @param candidate_count Number of candidates.
 * @param results Caller-owned result array with candidate_count entries.
 * @param report Caller-owned summary report.
 *
 * @retval 0 Evaluation completed; inspect report->recommendation_ready.
 * @retval -EINVAL Invalid pointers/count/scenario.
 * @retval -E2BIG Candidate count exceeds PQCP_DEPLOYMENT_MAX_CANDIDATES.
 */
int pqcp_deployment_advise(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	size_t candidate_count,
	struct pqcp_deployment_candidate_result *results,
	struct pqcp_deployment_report *report);

/**
 * @brief Build a prioritized experiment plan from candidate evidence gaps.
 *
 * Rejected candidates are included only when no feasible candidate exists.
 * Each returned entry represents one concrete missing metric or evidence type.
 *
 * @param scenario Scenario constraints.
 * @param candidates Original candidate array.
 * @param results Evaluated candidate results.
 * @param candidate_count Candidate/result count.
 * @param entries Caller-owned output array.
 * @param entry_capacity Capacity of entries.
 * @param entry_count Number of entries written.
 *
 * @retval 0 Plan populated.
 * @retval -EINVAL Invalid pointers/count.
 * @retval -ENOSPC Plan was truncated to entry_capacity.
 */
int pqcp_deployment_plan_gaps(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	const struct pqcp_deployment_candidate_result *results,
	size_t candidate_count,
	struct pqcp_deployment_gap_plan_entry *entries,
	size_t entry_capacity,
	size_t *entry_count);

/** Emit one stable scenario marker. */
int pqcp_deployment_scenario_emit(
	const struct pqcp_deployment_scenario *scenario);
/** Emit one stable ranked candidate marker. */
int pqcp_deployment_candidate_result_emit(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	const struct pqcp_deployment_candidate_result *result);
/** Emit one stable deployment decision summary marker. */
int pqcp_deployment_report_emit(
	const struct pqcp_deployment_report *report,
	const struct pqcp_deployment_candidate_result *results);
/** Emit one stable experiment-gap marker. */
int pqcp_deployment_gap_plan_entry_emit(
	const struct pqcp_deployment_gap_plan_entry *entry);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_ADVISOR_H_ */
