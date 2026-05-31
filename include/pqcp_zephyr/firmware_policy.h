/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Firmware policy/readiness evidence
 *
 * Stability: stable evidence API for the 1.0.x line. This API evaluates
 * firmware-visible profile, provider, algorithm-level, and RNG constraints
 * for transcript evidence. It does not select providers, change public crypto
 * APIs, alter ACVP wire formats, or modify benchmark row ordering.
 */

#ifndef PQCP_ZEPHYR_FIRMWARE_POLICY_H_
#define PQCP_ZEPHYR_FIRMWARE_POLICY_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/provider.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for PQCP_FIRMWARE_POLICY transcript markers. */
#define PQCP_FIRMWARE_POLICY_SCHEMA_VERSION 1U

/** Build manifest did not validate. */
#define PQCP_FIRMWARE_POLICY_REASON_BUILD_MANIFEST_INVALID (1U << 0)
/** Provider contract did not validate. */
#define PQCP_FIRMWARE_POLICY_REASON_PROVIDER_CONTRACT_INVALID (1U << 1)
/** Required provider-contract reporting is not compiled in. */
#define PQCP_FIRMWARE_POLICY_REASON_PROVIDER_CONTRACT_MISSING (1U << 2)
/** Required ML-KEM level mask is not fully enabled. */
#define PQCP_FIRMWARE_POLICY_REASON_MLKEM_LEVEL_MISSING (1U << 3)
/** Required ML-DSA level mask is not fully enabled. */
#define PQCP_FIRMWARE_POLICY_REASON_MLDSA_LEVEL_MISSING (1U << 4)
/** RNG mode is not allowed for the selected policy. */
#define PQCP_FIRMWARE_POLICY_REASON_RNG_NOT_ALLOWED (1U << 5)
/** Enabled native-family provider is not an accepted native source. */
#define PQCP_FIRMWARE_POLICY_REASON_NATIVE_PROVIDER_INVALID (1U << 6)
/** Policy profile is unknown or not supported. */
#define PQCP_FIRMWARE_POLICY_REASON_PROFILE_INVALID (1U << 7)

/** All firmware-policy blocker bits known by this API version. */
#define PQCP_FIRMWARE_POLICY_REASON_KNOWN_MASK \
	(PQCP_FIRMWARE_POLICY_REASON_BUILD_MANIFEST_INVALID | \
	 PQCP_FIRMWARE_POLICY_REASON_PROVIDER_CONTRACT_INVALID | \
	 PQCP_FIRMWARE_POLICY_REASON_PROVIDER_CONTRACT_MISSING | \
	 PQCP_FIRMWARE_POLICY_REASON_MLKEM_LEVEL_MISSING | \
	 PQCP_FIRMWARE_POLICY_REASON_MLDSA_LEVEL_MISSING | \
	 PQCP_FIRMWARE_POLICY_REASON_RNG_NOT_ALLOWED | \
	 PQCP_FIRMWARE_POLICY_REASON_NATIVE_PROVIDER_INVALID | \
	 PQCP_FIRMWARE_POLICY_REASON_PROFILE_INVALID)

/**
 * @brief Firmware policy profile evaluated from local build facts.
 */
enum pqcp_firmware_policy_profile {
	/** Build-only or QEMU evidence sample; not production-allowed. */
	PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB = 0,
	/** MCU-minimal production profile. */
	PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL,
	/** Gateway production profile. */
	PQCP_FIRMWARE_POLICY_PROFILE_GATEWAY,
	/** Native/QEMU lab profile; not production-allowed. */
	PQCP_FIRMWARE_POLICY_PROFILE_NATIVE_LAB,
};

/**
 * @brief Firmware policy requirements.
 *
 * Applications normally use pqcp_firmware_policy_default(), but tests and
 * specialized samples may pass custom requirements to prove policy behavior.
 */
struct pqcp_firmware_policy {
	/** Profile being evaluated. */
	enum pqcp_firmware_policy_profile profile;
	/** Required ML-KEM level mask, using PQCP_BUILD_MLKEM_LEVEL_* bits. */
	uint32_t required_mlkem_levels;
	/** Required ML-DSA level mask, using PQCP_BUILD_MLDSA_LEVEL_* bits. */
	uint32_t required_mldsa_levels;
	/** True when custom RNG is allowed for this profile. */
	bool allow_custom_rng;
	/** True when deterministic test RNG is allowed for this profile. */
	bool allow_deterministic_rng;
	/** True when provider-contract reporting must be compiled in. */
	bool require_provider_contract;
	/** True when enabled ML-KEM/ML-DSA families must use native sources. */
	bool require_native_provider;
	/** True when this policy can represent production-suitable firmware. */
	bool production_profile;
};

/**
 * @brief Firmware policy evaluation result.
 */
struct pqcp_firmware_policy_result {
	/** Marker schema version used for this result. */
	uint32_t schema_version;
	/** Profile that was evaluated. */
	enum pqcp_firmware_policy_profile profile;
	/** Required ML-KEM levels from the policy. */
	uint32_t required_mlkem_levels;
	/** Required ML-DSA levels from the policy. */
	uint32_t required_mldsa_levels;
	/** Observed ML-KEM levels from the manifest. */
	uint32_t observed_mlkem_levels;
	/** Observed ML-DSA levels from the manifest. */
	uint32_t observed_mldsa_levels;
	/** Blocker bit mask; zero means the policy passed. */
	uint32_t blocker_mask;
	/** True when the build manifest validated. */
	bool build_manifest_valid;
	/** True when the provider contract validated. */
	bool provider_contract_valid;
	/** True when the RNG mode is allowed for this policy. */
	bool rng_allowed;
	/** True when the provider requirement passed. */
	bool provider_required_met;
	/** True when enabled native families use accepted native sources. */
	bool native_provider_met;
	/** True when the policy permits production interpretation. */
	bool production_allowed;
	/** True when blocker_mask is zero. */
	bool passed;
};

/**
 * @brief Convert a firmware policy profile to a stable evidence token.
 *
 * @param profile Profile value.
 *
 * @return Static token, or "unknown" for invalid values.
 */
const char *pqcp_firmware_policy_profile_str(
	enum pqcp_firmware_policy_profile profile);

/**
 * @brief Return default requirements for a firmware policy profile.
 *
 * @param profile Profile value.
 *
 * @return Default policy requirements. Invalid profiles are returned with a
 *         blocker-only profile that cannot pass evaluation.
 */
struct pqcp_firmware_policy pqcp_firmware_policy_default(
	enum pqcp_firmware_policy_profile profile);

/**
 * @brief Select the policy profile implied by a build manifest.
 *
 * The selection is deterministic: MCU minimal, gateway, native lab, then
 * evidence lab if no known profile bit is set.
 *
 * @param manifest Build manifest.
 *
 * @return Derived firmware policy profile.
 */
enum pqcp_firmware_policy_profile pqcp_firmware_policy_profile_from_manifest(
	const struct pqcp_build_manifest *manifest);

/**
 * @brief Evaluate firmware policy requirements against local evidence facts.
 *
 * @param policy Policy requirements to evaluate.
 * @param manifest Build manifest to check.
 * @param contract Provider contract to check.
 * @param result Caller-owned result structure.
 *
 * @retval 0 Result populated.
 * @retval -EINVAL Required pointers are missing.
 */
int pqcp_firmware_policy_evaluate(
	const struct pqcp_firmware_policy *policy,
	const struct pqcp_build_manifest *manifest,
	const struct pqcp_provider_contract *contract,
	struct pqcp_firmware_policy_result *result);

/**
 * @brief Emit a stable firmware policy transcript marker.
 *
 * Emits:
 * `PQCP_FIRMWARE_POLICY schema=<n> profile=<name> status=<PASS|FAIL> production_allowed=<0|1> blockers=<hex> required_mlkem=<hex> observed_mlkem=<hex> required_mldsa=<hex> observed_mldsa=<hex> rng_allowed=<0|1> provider_contract=<0|1> native_provider=<0|1>`
 *
 * @param result Evaluated policy result.
 *
 * @retval 0 Marker emitted.
 * @retval -EINVAL Result pointer is invalid.
 * @retval -EBADMSG Result contains unknown blocker bits.
 */
int pqcp_firmware_policy_emit_result(
	const struct pqcp_firmware_policy_result *result);

/**
 * @brief Evaluate and emit the current firmware image policy marker.
 *
 * @retval 0 The current image passed the derived policy.
 * @retval -EPERM The policy marker was emitted but blockers remain.
 * @retval -EINVAL Required current-image inputs are invalid.
 * @retval -EBADMSG Result contains unknown blocker bits.
 */
int pqcp_firmware_policy_emit_current(void);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FIRMWARE_POLICY_H_ */
