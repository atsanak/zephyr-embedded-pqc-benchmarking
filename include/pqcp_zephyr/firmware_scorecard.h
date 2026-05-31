/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Firmware evidence scorecard
 *
 * Stability: stable evidence API for the 1.0.x line. This API appraises the
 * firmware-visible evidence chain; it does not select providers, alter crypto
 * APIs, change ACVP wire formats, or modify benchmark row ordering.
 */

#ifndef PQCP_ZEPHYR_FIRMWARE_SCORECARD_H_
#define PQCP_ZEPHYR_FIRMWARE_SCORECARD_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/assurance.h>
#include <pqcp_zephyr/firmware_policy.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for PQCP_FIRMWARE_SCORECARD transcript markers. */
#define PQCP_FIRMWARE_SCORECARD_SCHEMA_VERSION 1U

/** Build manifest validation failed. */
#define PQCP_FIRMWARE_SCORECARD_BLOCKER_BUILD_MANIFEST (1U << 0)
/** Provider contract validation failed. */
#define PQCP_FIRMWARE_SCORECARD_BLOCKER_PROVIDER_CONTRACT (1U << 1)
/** Firmware policy reported blockers. */
#define PQCP_FIRMWARE_SCORECARD_BLOCKER_FIRMWARE_POLICY (1U << 2)
/** Capability descriptor validation failed. */
#define PQCP_FIRMWARE_SCORECARD_BLOCKER_CAPABILITY_DESCRIPTOR (1U << 3)
/** Assurance digest manifest validation failed. */
#define PQCP_FIRMWARE_SCORECARD_BLOCKER_ASSURANCE_MANIFEST (1U << 4)
/** Device-evidence nonce or transcript hash was malformed. */
#define PQCP_FIRMWARE_SCORECARD_BLOCKER_DEVICE_INPUT (1U << 5)
/** Required evidence-session event mask was invalid. */
#define PQCP_FIRMWARE_SCORECARD_BLOCKER_SESSION_REQUIREMENTS (1U << 6)

/** All firmware scorecard blocker bits known by this API version. */
#define PQCP_FIRMWARE_SCORECARD_BLOCKER_KNOWN_MASK \
	(PQCP_FIRMWARE_SCORECARD_BLOCKER_BUILD_MANIFEST | \
	 PQCP_FIRMWARE_SCORECARD_BLOCKER_PROVIDER_CONTRACT | \
	 PQCP_FIRMWARE_SCORECARD_BLOCKER_FIRMWARE_POLICY | \
	 PQCP_FIRMWARE_SCORECARD_BLOCKER_CAPABILITY_DESCRIPTOR | \
	 PQCP_FIRMWARE_SCORECARD_BLOCKER_ASSURANCE_MANIFEST | \
	 PQCP_FIRMWARE_SCORECARD_BLOCKER_DEVICE_INPUT | \
	 PQCP_FIRMWARE_SCORECARD_BLOCKER_SESSION_REQUIREMENTS)

/** Evidence profile is lab/review oriented, not production-allowed. */
#define PQCP_FIRMWARE_SCORECARD_WARNING_NON_PRODUCTION_PROFILE (1U << 0)
/** Assurance manifest has no artifact hashes. */
#define PQCP_FIRMWARE_SCORECARD_WARNING_NO_ARTIFACTS (1U << 1)
/** Custom RNG is allowed only for this selected policy/profile. */
#define PQCP_FIRMWARE_SCORECARD_WARNING_CUSTOM_RNG (1U << 2)
/** No ML-KEM or ML-DSA algorithm levels are compiled into the image. */
#define PQCP_FIRMWARE_SCORECARD_WARNING_NO_NATIVE_ALGORITHMS (1U << 3)
/** Transcript hash is a placeholder all-zero digest. */
#define PQCP_FIRMWARE_SCORECARD_WARNING_PLACEHOLDER_TRANSCRIPT (1U << 4)

/** All firmware scorecard warning bits known by this API version. */
#define PQCP_FIRMWARE_SCORECARD_WARNING_KNOWN_MASK \
	(PQCP_FIRMWARE_SCORECARD_WARNING_NON_PRODUCTION_PROFILE | \
	 PQCP_FIRMWARE_SCORECARD_WARNING_NO_ARTIFACTS | \
	 PQCP_FIRMWARE_SCORECARD_WARNING_CUSTOM_RNG | \
	 PQCP_FIRMWARE_SCORECARD_WARNING_NO_NATIVE_ALGORITHMS | \
	 PQCP_FIRMWARE_SCORECARD_WARNING_PLACEHOLDER_TRANSCRIPT)

/**
 * @brief Firmware evidence scorecard result.
 */
struct pqcp_firmware_scorecard {
	/** Marker schema version. */
	uint32_t schema_version;
	/** Evaluated policy profile. */
	enum pqcp_firmware_policy_profile profile;
	/** Blocking issue bit mask; zero means scorecard passed. */
	uint32_t blocker_mask;
	/** Non-blocking concern bit mask. */
	uint32_t warning_mask;
	/** Required evidence-session events for the current manifest. */
	uint32_t required_events;
	/** Number of release artifacts in the assurance manifest. */
	uint32_t artifact_count;
	/** Deterministic evidence-readiness score from 0 to 100. */
	uint32_t readiness_score;
	/** True when policy and capability state permit production interpretation. */
	bool production_allowed;
	/** True when blocker_mask is zero. */
	bool passed;
};

/**
 * @brief Evaluate firmware evidence readiness from current build facts.
 *
 * @param manifest Assurance manifest that will be emitted in the session.
 * @param nonce_hex Device-evidence nonce encoded as 32 hex characters.
 * @param transcript_sha256 Transcript digest encoded as 64 hex characters.
 * @param scorecard Caller-owned result output.
 *
 * @retval 0 Scorecard populated.
 * @retval -EINVAL Required pointers are missing.
 */
int pqcp_firmware_scorecard_evaluate(
	const struct pqcp_assurance_manifest *manifest,
	const char *nonce_hex,
	const char *transcript_sha256,
	struct pqcp_firmware_scorecard *scorecard);

/**
 * @brief Emit a stable firmware scorecard transcript marker.
 *
 * Emits:
 * `PQCP_FIRMWARE_SCORECARD schema=<n> profile=<name> status=<PASS|FAIL> production_allowed=<0|1> blockers=<hex> warnings=<hex> readiness=<0-100> required_events=<hex> artifacts=<n>`
 *
 * @param scorecard Evaluated scorecard.
 *
 * @retval 0 Marker emitted and no blockers remain.
 * @retval -EINVAL Result pointer is invalid.
 * @retval -EBADMSG Result contains unknown blocker or warning bits.
 * @retval -EPERM Marker emitted but blockers remain.
 */
int pqcp_firmware_scorecard_emit(
	const struct pqcp_firmware_scorecard *scorecard);

/**
 * @brief Evaluate and emit the current firmware image scorecard marker.
 *
 * @param manifest Assurance manifest that will be emitted in the session.
 * @param nonce_hex Device-evidence nonce encoded as 32 hex characters.
 * @param transcript_sha256 Transcript digest encoded as 64 hex characters.
 *
 * @retval 0 Marker emitted and no blockers remain.
 * @retval -EINVAL Required pointers are invalid.
 * @retval -EBADMSG Result contains unknown blocker or warning bits.
 * @retval -EPERM Marker emitted but blockers remain.
 */
int pqcp_firmware_scorecard_emit_current(
	const struct pqcp_assurance_manifest *manifest,
	const char *nonce_hex,
	const char *transcript_sha256);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FIRMWARE_SCORECARD_H_ */
