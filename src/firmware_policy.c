/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware policy/readiness evidence.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/firmware_policy.h>

static bool pqcp_firmware_policy_profile_valid(
	enum pqcp_firmware_policy_profile profile)
{
	return profile == PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB ||
	       profile == PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL ||
	       profile == PQCP_FIRMWARE_POLICY_PROFILE_GATEWAY ||
	       profile == PQCP_FIRMWARE_POLICY_PROFILE_NATIVE_LAB;
}

const char *pqcp_firmware_policy_profile_str(
	enum pqcp_firmware_policy_profile profile)
{
	switch (profile) {
	case PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB:
		return "evidence_lab";
	case PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL:
		return "mcu_minimal";
	case PQCP_FIRMWARE_POLICY_PROFILE_GATEWAY:
		return "gateway";
	case PQCP_FIRMWARE_POLICY_PROFILE_NATIVE_LAB:
		return "native_lab";
	default:
		return "unknown";
	}
}

struct pqcp_firmware_policy pqcp_firmware_policy_default(
	enum pqcp_firmware_policy_profile profile)
{
	const uint32_t all_mlkem = PQCP_BUILD_MLKEM_LEVEL_512 |
				   PQCP_BUILD_MLKEM_LEVEL_768 |
				   PQCP_BUILD_MLKEM_LEVEL_1024;
	const uint32_t all_mldsa = PQCP_BUILD_MLDSA_LEVEL_44 |
				   PQCP_BUILD_MLDSA_LEVEL_65 |
				   PQCP_BUILD_MLDSA_LEVEL_87;

	switch (profile) {
	case PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB:
		return (struct pqcp_firmware_policy) {
			.profile = profile,
			.required_mlkem_levels = 0U,
			.required_mldsa_levels = 0U,
			.allow_custom_rng = true,
			.allow_deterministic_rng = true,
			.require_provider_contract = true,
			.require_native_provider = true,
			.production_profile = false,
		};
	case PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL:
		return (struct pqcp_firmware_policy) {
			.profile = profile,
			.required_mlkem_levels = PQCP_BUILD_MLKEM_LEVEL_768,
			.required_mldsa_levels = PQCP_BUILD_MLDSA_LEVEL_65,
			.allow_custom_rng = false,
			.allow_deterministic_rng = false,
			.require_provider_contract = true,
			.require_native_provider = true,
			.production_profile = true,
		};
	case PQCP_FIRMWARE_POLICY_PROFILE_GATEWAY:
		return (struct pqcp_firmware_policy) {
			.profile = profile,
			.required_mlkem_levels = all_mlkem,
			.required_mldsa_levels = all_mldsa,
			.allow_custom_rng = false,
			.allow_deterministic_rng = false,
			.require_provider_contract = true,
			.require_native_provider = true,
			.production_profile = true,
		};
	case PQCP_FIRMWARE_POLICY_PROFILE_NATIVE_LAB:
		return (struct pqcp_firmware_policy) {
			.profile = profile,
			.required_mlkem_levels = all_mlkem,
			.required_mldsa_levels = all_mldsa,
			.allow_custom_rng = true,
			.allow_deterministic_rng = true,
			.require_provider_contract = true,
			.require_native_provider = true,
			.production_profile = false,
		};
	default:
		return (struct pqcp_firmware_policy) {
			.profile = profile,
			.required_mlkem_levels = 0U,
			.required_mldsa_levels = 0U,
			.allow_custom_rng = false,
			.allow_deterministic_rng = false,
			.require_provider_contract = true,
			.require_native_provider = true,
			.production_profile = false,
		};
	}
}

enum pqcp_firmware_policy_profile pqcp_firmware_policy_profile_from_manifest(
	const struct pqcp_build_manifest *manifest)
{
	if (manifest == NULL) {
		return PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB;
	}
	if ((manifest->profile_flags & PQCP_BUILD_PROFILE_MCU_MINIMAL) != 0U) {
		return PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL;
	}
	if ((manifest->profile_flags & PQCP_BUILD_PROFILE_GATEWAY) != 0U) {
		return PQCP_FIRMWARE_POLICY_PROFILE_GATEWAY;
	}
	if ((manifest->profile_flags & PQCP_BUILD_PROFILE_NATIVE_LAB) != 0U) {
		return PQCP_FIRMWARE_POLICY_PROFILE_NATIVE_LAB;
	}

	return PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB;
}

static bool pqcp_firmware_policy_rng_allowed(
	const struct pqcp_firmware_policy *policy,
	const char *rng_mode)
{
	if (rng_mode == NULL) {
		return false;
	}
	if (strcmp(rng_mode, "zephyr_entropy") == 0 ||
	    strcmp(rng_mode, "psa") == 0) {
		return true;
	}
	if (strcmp(rng_mode, "custom") == 0) {
		return policy->allow_custom_rng;
	}
	if (strcmp(rng_mode, "deterministic_test") == 0) {
		return policy->allow_deterministic_rng;
	}

	return false;
}

static bool pqcp_firmware_policy_native_family_ok(
	bool enabled, enum pqcp_provider_family family)
{
	if (!enabled) {
		return true;
	}

	return family == PQCP_PROVIDER_FAMILY_PQCP_NATIVE ||
	       family == PQCP_PROVIDER_FAMILY_BASELINE_C;
}

static uint32_t pqcp_firmware_policy_level_blockers(
	const struct pqcp_firmware_policy *policy,
	const struct pqcp_build_manifest *manifest)
{
	uint32_t blockers = 0U;

	if ((policy->required_mlkem_levels & ~manifest->mlkem_level_mask) != 0U) {
		blockers |= PQCP_FIRMWARE_POLICY_REASON_MLKEM_LEVEL_MISSING;
	}
	if ((policy->required_mldsa_levels & ~manifest->mldsa_level_mask) != 0U) {
		blockers |= PQCP_FIRMWARE_POLICY_REASON_MLDSA_LEVEL_MISSING;
	}

	return blockers;
}

int pqcp_firmware_policy_evaluate(
	const struct pqcp_firmware_policy *policy,
	const struct pqcp_build_manifest *manifest,
	const struct pqcp_provider_contract *contract,
	struct pqcp_firmware_policy_result *result)
{
	uint32_t blockers = 0U;
	bool manifest_valid = false;
	bool contract_valid = false;
	bool rng_allowed = false;
	bool provider_required_met = false;
	bool native_provider_met = false;

	if ((policy == NULL) || (manifest == NULL) || (contract == NULL) ||
	    (result == NULL)) {
		return -EINVAL;
	}

	manifest_valid = pqcp_build_manifest_validate(manifest) == 0;
	contract_valid = pqcp_provider_contract_validate(contract) == 0;
	if (!manifest_valid) {
		blockers |= PQCP_FIRMWARE_POLICY_REASON_BUILD_MANIFEST_INVALID;
	}
	if (!contract_valid) {
		blockers |= PQCP_FIRMWARE_POLICY_REASON_PROVIDER_CONTRACT_INVALID;
	}
	if (!pqcp_firmware_policy_profile_valid(policy->profile)) {
		blockers |= PQCP_FIRMWARE_POLICY_REASON_PROFILE_INVALID;
	}

	rng_allowed = pqcp_firmware_policy_rng_allowed(policy, manifest->rng_mode);
	if (!rng_allowed) {
		blockers |= PQCP_FIRMWARE_POLICY_REASON_RNG_NOT_ALLOWED;
	}

	provider_required_met = !policy->require_provider_contract ||
				manifest->provider_contract_enabled;
	if (!provider_required_met) {
		blockers |= PQCP_FIRMWARE_POLICY_REASON_PROVIDER_CONTRACT_MISSING;
	}

	native_provider_met =
		!policy->require_native_provider ||
		(pqcp_firmware_policy_native_family_ok(
			 contract->mlkem_enabled, contract->mlkem_family) &&
		 pqcp_firmware_policy_native_family_ok(
			 contract->mldsa_enabled, contract->mldsa_family) &&
		 !contract->external_native_family_allowed);
	if (!native_provider_met) {
		blockers |= PQCP_FIRMWARE_POLICY_REASON_NATIVE_PROVIDER_INVALID;
	}

	if (manifest_valid) {
		blockers |= pqcp_firmware_policy_level_blockers(policy, manifest);
	}

	*result = (struct pqcp_firmware_policy_result) {
		.schema_version = PQCP_FIRMWARE_POLICY_SCHEMA_VERSION,
		.profile = policy->profile,
		.required_mlkem_levels = policy->required_mlkem_levels,
		.required_mldsa_levels = policy->required_mldsa_levels,
		.observed_mlkem_levels = manifest->mlkem_level_mask,
		.observed_mldsa_levels = manifest->mldsa_level_mask,
		.blocker_mask = blockers,
		.build_manifest_valid = manifest_valid,
		.provider_contract_valid = contract_valid,
		.rng_allowed = rng_allowed,
		.provider_required_met = provider_required_met,
		.native_provider_met = native_provider_met,
		.production_allowed = policy->production_profile &&
				      blockers == 0U,
		.passed = blockers == 0U,
	};

	return 0;
}

int pqcp_firmware_policy_emit_result(
	const struct pqcp_firmware_policy_result *result)
{
	if (result == NULL) {
		return -EINVAL;
	}
	if ((result->blocker_mask & ~PQCP_FIRMWARE_POLICY_REASON_KNOWN_MASK) != 0U) {
		return -EBADMSG;
	}

	printk("PQCP_FIRMWARE_POLICY schema=%u profile=%s status=%s production_allowed=%u blockers=0x%08x required_mlkem=0x%08x observed_mlkem=0x%08x required_mldsa=0x%08x observed_mldsa=0x%08x rng_allowed=%u provider_contract=%u native_provider=%u\n",
	       result->schema_version,
	       pqcp_firmware_policy_profile_str(result->profile),
	       result->passed ? "PASS" : "FAIL",
	       result->production_allowed ? 1U : 0U,
	       result->blocker_mask,
	       result->required_mlkem_levels,
	       result->observed_mlkem_levels,
	       result->required_mldsa_levels,
	       result->observed_mldsa_levels,
	       result->rng_allowed ? 1U : 0U,
	       result->provider_required_met ? 1U : 0U,
	       result->native_provider_met ? 1U : 0U);

	return 0;
}

int pqcp_firmware_policy_emit_current(void)
{
	const struct pqcp_build_manifest *manifest = pqcp_build_manifest_get();
	const struct pqcp_provider_contract *contract = pqcp_provider_contract_get();
	enum pqcp_firmware_policy_profile profile =
		pqcp_firmware_policy_profile_from_manifest(manifest);
	struct pqcp_firmware_policy policy = pqcp_firmware_policy_default(profile);
	struct pqcp_firmware_policy_result result;
	int ret = pqcp_firmware_policy_evaluate(
		&policy, manifest, contract, &result);

	if (ret != 0) {
		return ret;
	}

	ret = pqcp_firmware_policy_emit_result(&result);
	if (ret != 0) {
		return ret;
	}

	return result.passed ? 0 : -EPERM;
}
