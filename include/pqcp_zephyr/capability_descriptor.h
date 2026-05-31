/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Firmware capability descriptor
 *
 * Stability: stable evidence API for the 1.0.x line. This API summarizes
 * firmware-visible PQC capability, provider policy, profile readiness, and
 * evidence plumbing in one compact marker for partner review transcripts.
 */

#ifndef PQCP_ZEPHYR_CAPABILITY_DESCRIPTOR_H_
#define PQCP_ZEPHYR_CAPABILITY_DESCRIPTOR_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/firmware_policy.h>
#include <pqcp_zephyr/provider.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for PQCP_CAPABILITY_DESCRIPTOR transcript markers. */
#define PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION 1U

/** Build manifest reporting is compiled into this image. */
#define PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST     (1U << 0)
/** Provider contract reporting is compiled into this image. */
#define PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT  (1U << 1)
/** Firmware policy reporting is compiled into this image. */
#define PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY    (1U << 2)
/** Assurance status/device-evidence helpers are compiled into this image. */
#define PQCP_CAPABILITY_EVIDENCE_ASSURANCE_STATUS   (1U << 3)
/** Evidence session markers are compiled into this image. */
#define PQCP_CAPABILITY_EVIDENCE_SESSION            (1U << 4)
/** Reusable firmware evidence runner is compiled into this image. */
#define PQCP_CAPABILITY_EVIDENCE_RUNNER             (1U << 5)
/** C transcript replay verifier is compiled into this image. */
#define PQCP_CAPABILITY_EVIDENCE_TRANSCRIPT_REPLAY  (1U << 6)
/** Firmware scorecard appraisal is compiled into this image. */
#define PQCP_CAPABILITY_EVIDENCE_SCORECARD          (1U << 7)

/** All evidence capability bits known by this API version. */
#define PQCP_CAPABILITY_EVIDENCE_KNOWN_MASK \
	(PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST | \
	 PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT | \
	 PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY | \
	 PQCP_CAPABILITY_EVIDENCE_ASSURANCE_STATUS | \
	 PQCP_CAPABILITY_EVIDENCE_SESSION | \
	 PQCP_CAPABILITY_EVIDENCE_RUNNER | \
	 PQCP_CAPABILITY_EVIDENCE_TRANSCRIPT_REPLAY | \
	 PQCP_CAPABILITY_EVIDENCE_SCORECARD)

/**
 * @brief Provider summary for enabled ML-KEM/ML-DSA families.
 */
enum pqcp_capability_provider_summary {
	/** No native ML-KEM/ML-DSA family is enabled. */
	PQCP_CAPABILITY_PROVIDER_DISABLED = 0,
	/** Enabled native families are all PQ Code Package native. */
	PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE,
	/** Enabled native families are all portable-C baseline paths. */
	PQCP_CAPABILITY_PROVIDER_BASELINE_C,
	/** Enabled native families mix provider families. */
	PQCP_CAPABILITY_PROVIDER_MIXED,
	/** At least one enabled native family violates provider policy. */
	PQCP_CAPABILITY_PROVIDER_INVALID,
};

/**
 * @brief Firmware capability descriptor.
 *
 * The descriptor is evidence metadata only. It does not claim certification,
 * does not prove side-channel security, and does not select crypto providers.
 */
struct pqcp_capability_descriptor {
	/** Marker schema version. */
	uint32_t schema_version;
	/** PQCP module semantic version. */
	const char *pqcp_version;
	/** Zephyr kernel version. */
	const char *zephyr_version;
	/** Zephyr board name. */
	const char *board;
	/** Selected firmware policy profile. */
	enum pqcp_firmware_policy_profile profile;
	/** Enabled ML-KEM level mask from the build manifest. */
	uint32_t mlkem_level_mask;
	/** Enabled ML-DSA level mask from the build manifest. */
	uint32_t mldsa_level_mask;
	/** Stable RNG mode token from the build manifest. */
	const char *rng_mode;
	/** Native-family provider summary. */
	enum pqcp_capability_provider_summary provider_summary;
	/** Backend selector from the provider contract. */
	const char *backend_selector;
	/** Compiled evidence capability bit mask. */
	uint32_t evidence_capabilities;
	/** Firmware policy blocker mask. */
	uint32_t policy_blockers;
	/** True when firmware policy passed. */
	bool policy_passed;
	/** True when policy allows production interpretation. */
	bool production_allowed;
	/** Deterministic 0-100 evidence-readiness score; not a certification. */
	uint32_t evidence_readiness_score;
};

/**
 * @brief Convert a provider summary to a stable evidence token.
 *
 * @param summary Provider summary value.
 *
 * @return Static token, or "unknown" for invalid values.
 */
const char *pqcp_capability_provider_summary_str(
	enum pqcp_capability_provider_summary summary);

/**
 * @brief Return compiled-in evidence capability bits for the current image.
 *
 * @return PQCP_CAPABILITY_EVIDENCE_* bit mask.
 */
uint32_t pqcp_capability_evidence_capabilities_current(void);

/**
 * @brief Build a descriptor from already-evaluated firmware facts.
 *
 * @param manifest Build manifest.
 * @param contract Provider contract.
 * @param policy_result Firmware policy result.
 * @param descriptor Caller-owned descriptor output.
 *
 * @retval 0 Descriptor populated.
 * @retval -EINVAL Required pointer or manifest field is invalid.
 * @retval -EBADMSG Provider/policy metadata is internally inconsistent.
 */
int pqcp_capability_descriptor_build(
	const struct pqcp_build_manifest *manifest,
	const struct pqcp_provider_contract *contract,
	const struct pqcp_firmware_policy_result *policy_result,
	struct pqcp_capability_descriptor *descriptor);

/**
 * @brief Build a descriptor for the current firmware image.
 *
 * @param descriptor Caller-owned descriptor output.
 *
 * @retval 0 Descriptor populated.
 * @retval -EINVAL Required current-image input is invalid.
 * @retval -EBADMSG Provider/policy metadata is internally inconsistent.
 */
int pqcp_capability_descriptor_current(
	struct pqcp_capability_descriptor *descriptor);

/**
 * @brief Validate a populated capability descriptor.
 *
 * @param descriptor Descriptor to validate.
 *
 * @retval 0 Descriptor is internally consistent.
 * @retval -EINVAL Required field or enum value is invalid.
 * @retval -EBADMSG Policy/evidence fields contradict each other.
 */
int pqcp_capability_descriptor_validate(
	const struct pqcp_capability_descriptor *descriptor);

/**
 * @brief Emit a stable capability descriptor transcript marker.
 *
 * Emits:
 * `PQCP_CAPABILITY_DESCRIPTOR schema=<n> profile=<name> status=<PASS|FAIL> production_allowed=<0|1> provider=<summary> backend=<selector> mlkem_levels=<hex> mldsa_levels=<hex> rng=<mode> evidence=<hex> blockers=<hex> readiness=<0-100>`
 *
 * @param descriptor Descriptor to emit.
 *
 * @retval 0 Marker emitted.
 * @retval -EINVAL Required field or enum value is invalid.
 * @retval -EBADMSG Policy/evidence fields contradict each other.
 */
int pqcp_capability_descriptor_emit(
	const struct pqcp_capability_descriptor *descriptor);

/**
 * @brief Build and emit the current firmware capability descriptor.
 *
 * @retval 0 Marker emitted.
 * @retval -EINVAL Required current-image input is invalid.
 * @retval -EBADMSG Provider/policy metadata is internally inconsistent.
 */
int pqcp_capability_descriptor_emit_current(void);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_CAPABILITY_DESCRIPTOR_H_ */
