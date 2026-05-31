/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware capability descriptor.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/capability_descriptor.h>

static bool has_text(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool profile_valid(enum pqcp_firmware_policy_profile profile)
{
	return profile == PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB ||
	       profile == PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL ||
	       profile == PQCP_FIRMWARE_POLICY_PROFILE_GATEWAY ||
	       profile == PQCP_FIRMWARE_POLICY_PROFILE_NATIVE_LAB;
}

static bool provider_summary_valid(
	enum pqcp_capability_provider_summary summary)
{
	return summary == PQCP_CAPABILITY_PROVIDER_DISABLED ||
	       summary == PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE ||
	       summary == PQCP_CAPABILITY_PROVIDER_BASELINE_C ||
	       summary == PQCP_CAPABILITY_PROVIDER_MIXED ||
	       summary == PQCP_CAPABILITY_PROVIDER_INVALID;
}

const char *pqcp_capability_provider_summary_str(
	enum pqcp_capability_provider_summary summary)
{
	switch (summary) {
	case PQCP_CAPABILITY_PROVIDER_DISABLED:
		return "disabled";
	case PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE:
		return "pqcp_native";
	case PQCP_CAPABILITY_PROVIDER_BASELINE_C:
		return "baseline_c";
	case PQCP_CAPABILITY_PROVIDER_MIXED:
		return "mixed";
	case PQCP_CAPABILITY_PROVIDER_INVALID:
		return "invalid";
	default:
		return "unknown";
	}
}

uint32_t pqcp_capability_evidence_capabilities_current(void)
{
	uint32_t capabilities = 0U;

	if (IS_ENABLED(CONFIG_PQCP_BUILD_MANIFEST)) {
		capabilities |= PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST;
	}
	if (IS_ENABLED(CONFIG_PQCP_PROVIDER_CONTRACT)) {
		capabilities |= PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT;
	}
	if (IS_ENABLED(CONFIG_PQCP_FIRMWARE_POLICY)) {
		capabilities |= PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY;
	}
	if (IS_ENABLED(CONFIG_PQCP_ASSURANCE_STATUS)) {
		capabilities |= PQCP_CAPABILITY_EVIDENCE_ASSURANCE_STATUS;
	}
	if (IS_ENABLED(CONFIG_PQCP_EVIDENCE_SESSION)) {
		capabilities |= PQCP_CAPABILITY_EVIDENCE_SESSION;
	}
	if (IS_ENABLED(CONFIG_PQCP_FIRMWARE_EVIDENCE)) {
		capabilities |= PQCP_CAPABILITY_EVIDENCE_RUNNER;
	}
	if (IS_ENABLED(CONFIG_PQCP_EVIDENCE_TRANSCRIPT)) {
		capabilities |= PQCP_CAPABILITY_EVIDENCE_TRANSCRIPT_REPLAY;
	}
	if (IS_ENABLED(CONFIG_PQCP_FIRMWARE_SCORECARD)) {
		capabilities |= PQCP_CAPABILITY_EVIDENCE_SCORECARD;
	}

	return capabilities;
}

static bool provider_family_enabled(bool enabled,
				    enum pqcp_provider_family family)
{
	return enabled && family != PQCP_PROVIDER_FAMILY_DISABLED;
}

static enum pqcp_capability_provider_summary summarize_provider(
	const struct pqcp_provider_contract *contract)
{
	enum pqcp_provider_family first_family = PQCP_PROVIDER_FAMILY_DISABLED;
	bool have_enabled = false;

	if (contract->external_native_family_allowed ||
	    contract->mlkem_family == PQCP_PROVIDER_FAMILY_FORBIDDEN ||
	    contract->mldsa_family == PQCP_PROVIDER_FAMILY_FORBIDDEN) {
		return PQCP_CAPABILITY_PROVIDER_INVALID;
	}

	if (provider_family_enabled(contract->mlkem_enabled,
				    contract->mlkem_family)) {
		first_family = contract->mlkem_family;
		have_enabled = true;
	}
	if (provider_family_enabled(contract->mldsa_enabled,
				    contract->mldsa_family)) {
		if (!have_enabled) {
			first_family = contract->mldsa_family;
			have_enabled = true;
		} else if (contract->mldsa_family != first_family) {
			return PQCP_CAPABILITY_PROVIDER_MIXED;
		}
	}

	if (!have_enabled) {
		return PQCP_CAPABILITY_PROVIDER_DISABLED;
	}

	switch (first_family) {
	case PQCP_PROVIDER_FAMILY_PQCP_NATIVE:
		return PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE;
	case PQCP_PROVIDER_FAMILY_BASELINE_C:
		return PQCP_CAPABILITY_PROVIDER_BASELINE_C;
	default:
		return PQCP_CAPABILITY_PROVIDER_INVALID;
	}
}

static bool level_requirements_met(
	const struct pqcp_firmware_policy_result *policy_result)
{
	if ((policy_result->required_mlkem_levels &
	     ~policy_result->observed_mlkem_levels) != 0U) {
		return false;
	}
	if ((policy_result->required_mldsa_levels &
	     ~policy_result->observed_mldsa_levels) != 0U) {
		return false;
	}

	return true;
}

static uint32_t readiness_score(
	const struct pqcp_firmware_policy_result *policy_result,
	enum pqcp_capability_provider_summary provider_summary,
	uint32_t evidence_capabilities)
{
	uint32_t score = 0U;

	if (policy_result->build_manifest_valid) {
		score += 10U;
	}
	if (policy_result->provider_contract_valid) {
		score += 15U;
	}
	if (policy_result->native_provider_met &&
	    provider_summary != PQCP_CAPABILITY_PROVIDER_INVALID) {
		score += 15U;
	}
	if (policy_result->rng_allowed) {
		score += 15U;
	}
	if (level_requirements_met(policy_result)) {
		score += 15U;
	}
	if ((evidence_capabilities &
	     (PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST |
	      PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT |
	      PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY)) ==
	    (PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST |
	     PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT |
	     PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY)) {
		score += 10U;
	}
	if (policy_result->passed) {
		score += 10U;
	}
	if (policy_result->production_allowed) {
		score += 10U;
	}

	return score > 100U ? 100U : score;
}

int pqcp_capability_descriptor_build(
	const struct pqcp_build_manifest *manifest,
	const struct pqcp_provider_contract *contract,
	const struct pqcp_firmware_policy_result *policy_result,
	struct pqcp_capability_descriptor *descriptor)
{
	enum pqcp_capability_provider_summary provider_summary;
	uint32_t evidence_capabilities;

	if ((manifest == NULL) || (contract == NULL) ||
	    (policy_result == NULL) || (descriptor == NULL)) {
		return -EINVAL;
	}
	if (pqcp_build_manifest_validate(manifest) != 0) {
		return -EINVAL;
	}
	if (!has_text(contract->backend_selector)) {
		return -EINVAL;
	}
	if ((policy_result->blocker_mask &
	     ~PQCP_FIRMWARE_POLICY_REASON_KNOWN_MASK) != 0U) {
		return -EBADMSG;
	}

	provider_summary = summarize_provider(contract);
	evidence_capabilities = pqcp_capability_evidence_capabilities_current();

	*descriptor = (struct pqcp_capability_descriptor) {
		.schema_version = PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION,
		.pqcp_version = manifest->pqcp_version,
		.zephyr_version = manifest->zephyr_version,
		.board = manifest->board,
		.profile = policy_result->profile,
		.mlkem_level_mask = manifest->mlkem_level_mask,
		.mldsa_level_mask = manifest->mldsa_level_mask,
		.rng_mode = manifest->rng_mode,
		.provider_summary = provider_summary,
		.backend_selector = contract->backend_selector,
		.evidence_capabilities = evidence_capabilities,
		.policy_blockers = policy_result->blocker_mask,
		.policy_passed = policy_result->passed,
		.production_allowed = policy_result->production_allowed,
		.evidence_readiness_score = readiness_score(
			policy_result, provider_summary, evidence_capabilities),
	};

	return pqcp_capability_descriptor_validate(descriptor);
}

int pqcp_capability_descriptor_current(
	struct pqcp_capability_descriptor *descriptor)
{
	const struct pqcp_build_manifest *manifest = pqcp_build_manifest_get();
	const struct pqcp_provider_contract *contract = pqcp_provider_contract_get();
	enum pqcp_firmware_policy_profile profile =
		pqcp_firmware_policy_profile_from_manifest(manifest);
	struct pqcp_firmware_policy policy =
		pqcp_firmware_policy_default(profile);
	struct pqcp_firmware_policy_result policy_result;
	int ret;

	if (descriptor == NULL) {
		return -EINVAL;
	}

	ret = pqcp_firmware_policy_evaluate(
		&policy, manifest, contract, &policy_result);
	if (ret != 0) {
		return ret;
	}

	return pqcp_capability_descriptor_build(
		manifest, contract, &policy_result, descriptor);
}

int pqcp_capability_descriptor_validate(
	const struct pqcp_capability_descriptor *descriptor)
{
	if ((descriptor == NULL) ||
	    (descriptor->schema_version !=
	     PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION) ||
	    !has_text(descriptor->pqcp_version) ||
	    !has_text(descriptor->zephyr_version) ||
	    !has_text(descriptor->board) ||
	    !has_text(descriptor->rng_mode) ||
	    !has_text(descriptor->backend_selector) ||
	    !profile_valid(descriptor->profile) ||
	    !provider_summary_valid(descriptor->provider_summary) ||
	    descriptor->evidence_readiness_score > 100U) {
		return -EINVAL;
	}
	if ((descriptor->evidence_capabilities &
	     ~PQCP_CAPABILITY_EVIDENCE_KNOWN_MASK) != 0U ||
	    (descriptor->policy_blockers &
	     ~PQCP_FIRMWARE_POLICY_REASON_KNOWN_MASK) != 0U) {
		return -EBADMSG;
	}
	if (descriptor->policy_passed &&
	    (descriptor->policy_blockers != 0U ||
	     descriptor->provider_summary == PQCP_CAPABILITY_PROVIDER_INVALID)) {
		return -EBADMSG;
	}
	if (descriptor->production_allowed && !descriptor->policy_passed) {
		return -EBADMSG;
	}

	return 0;
}

int pqcp_capability_descriptor_emit(
	const struct pqcp_capability_descriptor *descriptor)
{
	int ret = pqcp_capability_descriptor_validate(descriptor);

	if (ret != 0) {
		return ret;
	}

	printk("PQCP_CAPABILITY_DESCRIPTOR schema=%u profile=%s status=%s production_allowed=%u provider=%s backend=%s mlkem_levels=0x%08x mldsa_levels=0x%08x rng=%s evidence=0x%08x blockers=0x%08x readiness=%u\n",
	       descriptor->schema_version,
	       pqcp_firmware_policy_profile_str(descriptor->profile),
	       descriptor->policy_passed ? "PASS" : "FAIL",
	       descriptor->production_allowed ? 1U : 0U,
	       pqcp_capability_provider_summary_str(
		       descriptor->provider_summary),
	       descriptor->backend_selector,
	       descriptor->mlkem_level_mask,
	       descriptor->mldsa_level_mask,
	       descriptor->rng_mode,
	       descriptor->evidence_capabilities,
	       descriptor->policy_blockers,
	       descriptor->evidence_readiness_score);

	return 0;
}

int pqcp_capability_descriptor_emit_current(void)
{
	struct pqcp_capability_descriptor descriptor;
	int ret = pqcp_capability_descriptor_current(&descriptor);

	if (ret != 0) {
		return ret;
	}

	return pqcp_capability_descriptor_emit(&descriptor);
}
