/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware evidence scorecard.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/capability_descriptor.h>
#include <pqcp_zephyr/evidence_session.h>
#include <pqcp_zephyr/firmware_scorecard.h>
#include <pqcp_zephyr/provider.h>

#define PQCP_SCORECARD_REQUIRED_BASE \
	(PQCP_EVIDENCE_EVENT_BUILD_MANIFEST | \
	 PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT | \
	 PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY | \
	 PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR | \
	 PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD | \
	 PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS | \
	 PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE)

static bool digest_is_all_zero(const char *value)
{
	if (!pqcp_assurance_is_sha256_hex(value)) {
		return false;
	}

	for (size_t i = 0U; i < PQCP_ASSURANCE_SHA256_HEX_CHARS; ++i) {
		if (value[i] != '0') {
			return false;
		}
	}

	return true;
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

static uint32_t score_from_masks(uint32_t blockers, uint32_t warnings)
{
	uint32_t penalty = bit_count(blockers) * 25U +
			   bit_count(warnings) * 5U;

	return penalty >= 100U ? 0U : 100U - penalty;
}

static uint32_t required_events_for_manifest(
	const struct pqcp_assurance_manifest *manifest)
{
	uint32_t events = PQCP_SCORECARD_REQUIRED_BASE;

	if ((manifest != NULL) && (manifest->artifact_count > 0U)) {
		events |= PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS;
	}

	return events;
}

int pqcp_firmware_scorecard_evaluate(
	const struct pqcp_assurance_manifest *manifest,
	const char *nonce_hex,
	const char *transcript_sha256,
	struct pqcp_firmware_scorecard *scorecard)
{
	const struct pqcp_build_manifest *build = pqcp_build_manifest_get();
	const struct pqcp_provider_contract *contract =
		pqcp_provider_contract_get();
	enum pqcp_firmware_policy_profile profile =
		pqcp_firmware_policy_profile_from_manifest(build);
	struct pqcp_firmware_policy policy =
		pqcp_firmware_policy_default(profile);
	struct pqcp_firmware_policy_result policy_result = { 0 };
	struct pqcp_capability_descriptor capability = { 0 };
	uint32_t blockers = 0U;
	uint32_t warnings = 0U;
	uint32_t required_events;
	bool production_allowed = false;

	if ((manifest == NULL) || (nonce_hex == NULL) ||
	    (transcript_sha256 == NULL) || (scorecard == NULL)) {
		return -EINVAL;
	}

	if (pqcp_build_manifest_validate(build) != 0) {
		blockers |= PQCP_FIRMWARE_SCORECARD_BLOCKER_BUILD_MANIFEST;
	}
	if (pqcp_provider_contract_validate(contract) != 0) {
		blockers |= PQCP_FIRMWARE_SCORECARD_BLOCKER_PROVIDER_CONTRACT;
	}
	if (pqcp_firmware_policy_evaluate(
		    &policy, build, contract, &policy_result) != 0 ||
	    !policy_result.passed) {
		blockers |= PQCP_FIRMWARE_SCORECARD_BLOCKER_FIRMWARE_POLICY;
	}
	if (pqcp_capability_descriptor_current(&capability) != 0 ||
	    pqcp_capability_descriptor_validate(&capability) != 0) {
		blockers |=
			PQCP_FIRMWARE_SCORECARD_BLOCKER_CAPABILITY_DESCRIPTOR;
	}
	if (pqcp_assurance_manifest_validate(manifest) != 0) {
		blockers |= PQCP_FIRMWARE_SCORECARD_BLOCKER_ASSURANCE_MANIFEST;
	}
	if (!pqcp_assurance_is_nonce128_hex(nonce_hex) ||
	    !pqcp_assurance_is_sha256_hex(transcript_sha256)) {
		blockers |= PQCP_FIRMWARE_SCORECARD_BLOCKER_DEVICE_INPUT;
	}

	required_events = required_events_for_manifest(manifest);
	if (pqcp_evidence_event_mask_validate(required_events) != 0) {
		blockers |= PQCP_FIRMWARE_SCORECARD_BLOCKER_SESSION_REQUIREMENTS;
	}

	if (!policy_result.production_allowed || !capability.production_allowed) {
		warnings |=
			PQCP_FIRMWARE_SCORECARD_WARNING_NON_PRODUCTION_PROFILE;
	}
	if (manifest->artifact_count == 0U) {
		warnings |= PQCP_FIRMWARE_SCORECARD_WARNING_NO_ARTIFACTS;
	}
	if (build->rng_mode != NULL && strcmp(build->rng_mode, "custom") == 0) {
		warnings |= PQCP_FIRMWARE_SCORECARD_WARNING_CUSTOM_RNG;
	}
	if ((build->mlkem_level_mask == 0U) &&
	    (build->mldsa_level_mask == 0U)) {
		warnings |= PQCP_FIRMWARE_SCORECARD_WARNING_NO_NATIVE_ALGORITHMS;
	}
	if (digest_is_all_zero(transcript_sha256)) {
		warnings |=
			PQCP_FIRMWARE_SCORECARD_WARNING_PLACEHOLDER_TRANSCRIPT;
	}

	production_allowed = policy_result.production_allowed &&
			     capability.production_allowed &&
			     blockers == 0U;

	*scorecard = (struct pqcp_firmware_scorecard) {
		.schema_version = PQCP_FIRMWARE_SCORECARD_SCHEMA_VERSION,
		.profile = profile,
		.blocker_mask = blockers,
		.warning_mask = warnings,
		.required_events = required_events,
		.artifact_count = (uint32_t)manifest->artifact_count,
		.readiness_score = score_from_masks(blockers, warnings),
		.production_allowed = production_allowed,
		.passed = blockers == 0U,
	};

	return 0;
}

int pqcp_firmware_scorecard_emit(
	const struct pqcp_firmware_scorecard *scorecard)
{
	if (scorecard == NULL) {
		return -EINVAL;
	}
	if ((scorecard->schema_version !=
	     PQCP_FIRMWARE_SCORECARD_SCHEMA_VERSION) ||
	    (pqcp_evidence_event_mask_validate(scorecard->required_events) != 0) ||
	    (scorecard->passed != (scorecard->blocker_mask == 0U)) ||
	    (scorecard->blocker_mask &
	     ~PQCP_FIRMWARE_SCORECARD_BLOCKER_KNOWN_MASK) != 0U ||
	    (scorecard->warning_mask &
	     ~PQCP_FIRMWARE_SCORECARD_WARNING_KNOWN_MASK) != 0U ||
	    (scorecard->readiness_score > 100U)) {
		return -EBADMSG;
	}

	printk("PQCP_FIRMWARE_SCORECARD schema=%u profile=%s status=%s production_allowed=%u blockers=0x%08x warnings=0x%08x readiness=%u required_events=0x%08x artifacts=%u\n",
	       scorecard->schema_version,
	       pqcp_firmware_policy_profile_str(scorecard->profile),
	       scorecard->passed ? "PASS" : "FAIL",
	       scorecard->production_allowed ? 1U : 0U,
	       scorecard->blocker_mask,
	       scorecard->warning_mask,
	       scorecard->readiness_score,
	       scorecard->required_events,
	       scorecard->artifact_count);

	return scorecard->passed ? 0 : -EPERM;
}

int pqcp_firmware_scorecard_emit_current(
	const struct pqcp_assurance_manifest *manifest,
	const char *nonce_hex,
	const char *transcript_sha256)
{
	struct pqcp_firmware_scorecard scorecard;
	int ret = pqcp_firmware_scorecard_evaluate(
		manifest, nonce_hex, transcript_sha256, &scorecard);

	if (ret != 0) {
		return ret;
	}

	return pqcp_firmware_scorecard_emit(&scorecard);
}
