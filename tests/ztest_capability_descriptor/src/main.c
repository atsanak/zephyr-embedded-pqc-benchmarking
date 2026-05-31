/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware capability descriptor tests.
 */

#include <errno.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/capability_descriptor.h>

static const struct pqcp_build_manifest evidence_manifest = {
	.pqcp_version = "1.0.0",
	.zephyr_version = "4.4.0",
	.board = "qemu_x86_64",
	.profile_flags = 0U,
	.mlkem_level_mask = 0U,
	.mldsa_level_mask = 0U,
	.rng_mode = "custom",
	.provider_contract_enabled = true,
};

static const struct pqcp_build_manifest mcu_manifest = {
	.pqcp_version = "1.0.0",
	.zephyr_version = "4.4.0",
	.board = "nucleo_h743zi",
	.profile_flags = PQCP_BUILD_PROFILE_MCU_MINIMAL,
	.mlkem_level_mask = PQCP_BUILD_MLKEM_LEVEL_768,
	.mldsa_level_mask = PQCP_BUILD_MLDSA_LEVEL_65,
	.rng_mode = "zephyr_entropy",
	.provider_contract_enabled = true,
};

static const struct pqcp_build_manifest bad_rng_manifest = {
	.pqcp_version = "1.0.0",
	.zephyr_version = "4.4.0",
	.board = "nucleo_h743zi",
	.profile_flags = PQCP_BUILD_PROFILE_MCU_MINIMAL,
	.mlkem_level_mask = PQCP_BUILD_MLKEM_LEVEL_768,
	.mldsa_level_mask = PQCP_BUILD_MLDSA_LEVEL_65,
	.rng_mode = "deterministic_test",
	.provider_contract_enabled = true,
};

static const struct pqcp_provider_contract disabled_contract = {
	.mlkem_enabled = false,
	.mldsa_enabled = false,
	.mlkem_family = PQCP_PROVIDER_FAMILY_DISABLED,
	.mldsa_family = PQCP_PROVIDER_FAMILY_DISABLED,
	.mlkem_source = "disabled",
	.mldsa_source = "disabled",
	.backend_selector = "auto",
	.external_native_family_allowed = false,
	.experimental_non_native_inventory = false,
};

static const struct pqcp_provider_contract native_contract = {
	.mlkem_enabled = true,
	.mldsa_enabled = true,
	.mlkem_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
	.mldsa_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
	.mlkem_source = "mlkem-native",
	.mldsa_source = "mldsa-native",
	.backend_selector = "auto",
	.external_native_family_allowed = false,
	.experimental_non_native_inventory = false,
};

static const struct pqcp_provider_contract mixed_contract = {
	.mlkem_enabled = true,
	.mldsa_enabled = true,
	.mlkem_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
	.mldsa_family = PQCP_PROVIDER_FAMILY_BASELINE_C,
	.mlkem_source = "mlkem-native",
	.mldsa_source = "mldsa-native",
	.backend_selector = "auto",
	.external_native_family_allowed = false,
	.experimental_non_native_inventory = false,
};

static const struct pqcp_provider_contract forbidden_contract = {
	.mlkem_enabled = true,
	.mldsa_enabled = true,
	.mlkem_family = PQCP_PROVIDER_FAMILY_FORBIDDEN,
	.mldsa_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
	.mlkem_source = "mlkem-native",
	.mldsa_source = "mldsa-native",
	.backend_selector = "forbidden",
	.external_native_family_allowed = true,
	.experimental_non_native_inventory = false,
};

static struct pqcp_firmware_policy_result evaluate(
	const struct pqcp_build_manifest *manifest,
	const struct pqcp_provider_contract *contract)
{
	enum pqcp_firmware_policy_profile profile =
		pqcp_firmware_policy_profile_from_manifest(manifest);
	struct pqcp_firmware_policy policy =
		pqcp_firmware_policy_default(profile);
	struct pqcp_firmware_policy_result result;

	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, manifest, contract, &result),
		      0);

	return result;
}

ZTEST(pqcp_capability_descriptor, test_provider_summary_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_capability_provider_summary_str(
			PQCP_CAPABILITY_PROVIDER_DISABLED),
		"disabled");
	zassert_str_equal(
		pqcp_capability_provider_summary_str(
			PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE),
		"pqcp_native");
	zassert_str_equal(
		pqcp_capability_provider_summary_str(
			PQCP_CAPABILITY_PROVIDER_BASELINE_C),
		"baseline_c");
	zassert_str_equal(
		pqcp_capability_provider_summary_str(
			PQCP_CAPABILITY_PROVIDER_MIXED),
		"mixed");
	zassert_str_equal(
		pqcp_capability_provider_summary_str(
			PQCP_CAPABILITY_PROVIDER_INVALID),
		"invalid");
}

ZTEST(pqcp_capability_descriptor, test_evidence_lab_descriptor_passes_not_production)
{
	struct pqcp_firmware_policy_result policy =
		evaluate(&evidence_manifest, &disabled_contract);
	struct pqcp_capability_descriptor descriptor;

	zassert_equal(pqcp_capability_descriptor_build(
			      &evidence_manifest, &disabled_contract,
			      &policy, &descriptor),
		      0);
	zassert_equal(descriptor.schema_version,
		      PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION);
	zassert_equal(descriptor.profile,
		      PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB);
	zassert_equal(descriptor.provider_summary,
		      PQCP_CAPABILITY_PROVIDER_DISABLED);
	zassert_true(descriptor.policy_passed);
	zassert_false(descriptor.production_allowed);
	zassert_equal(descriptor.policy_blockers, 0U);
	zassert_true(descriptor.evidence_readiness_score >= 80U);
	zassert_equal(pqcp_capability_descriptor_validate(&descriptor), 0);
}

ZTEST(pqcp_capability_descriptor, test_mcu_native_descriptor_is_production_allowed)
{
	struct pqcp_firmware_policy_result policy =
		evaluate(&mcu_manifest, &native_contract);
	struct pqcp_capability_descriptor descriptor;

	zassert_equal(pqcp_capability_descriptor_build(
			      &mcu_manifest, &native_contract,
			      &policy, &descriptor),
		      0);
	zassert_equal(descriptor.profile,
		      PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL);
	zassert_equal(descriptor.provider_summary,
		      PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE);
	zassert_true(descriptor.policy_passed);
	zassert_true(descriptor.production_allowed);
	zassert_equal(descriptor.mlkem_level_mask, PQCP_BUILD_MLKEM_LEVEL_768);
	zassert_equal(descriptor.mldsa_level_mask, PQCP_BUILD_MLDSA_LEVEL_65);
	zassert_equal(descriptor.evidence_readiness_score, 100U);
}

ZTEST(pqcp_capability_descriptor, test_bad_rng_blocks_production_descriptor)
{
	struct pqcp_firmware_policy_result policy =
		evaluate(&bad_rng_manifest, &native_contract);
	struct pqcp_capability_descriptor descriptor;

	zassert_equal(pqcp_capability_descriptor_build(
			      &bad_rng_manifest, &native_contract,
			      &policy, &descriptor),
		      0);
	zassert_false(descriptor.policy_passed);
	zassert_false(descriptor.production_allowed);
	zassert_true((descriptor.policy_blockers &
		      PQCP_FIRMWARE_POLICY_REASON_RNG_NOT_ALLOWED) != 0U);
	zassert_true(descriptor.evidence_readiness_score < 100U);
	zassert_equal(pqcp_capability_descriptor_validate(&descriptor), 0);
}

ZTEST(pqcp_capability_descriptor, test_mixed_provider_summary_is_visible)
{
	struct pqcp_firmware_policy_result policy =
		evaluate(&mcu_manifest, &mixed_contract);
	struct pqcp_capability_descriptor descriptor;

	zassert_equal(pqcp_capability_descriptor_build(
			      &mcu_manifest, &mixed_contract,
			      &policy, &descriptor),
		      0);
	zassert_equal(descriptor.provider_summary,
		      PQCP_CAPABILITY_PROVIDER_MIXED);
	zassert_true(descriptor.policy_passed);
}

ZTEST(pqcp_capability_descriptor, test_forbidden_provider_is_rejected)
{
	struct pqcp_firmware_policy_result policy =
		evaluate(&mcu_manifest, &forbidden_contract);
	struct pqcp_capability_descriptor descriptor;

	zassert_equal(pqcp_capability_descriptor_build(
			      &mcu_manifest, &forbidden_contract,
			      &policy, &descriptor),
		      0);
	zassert_equal(descriptor.provider_summary,
		      PQCP_CAPABILITY_PROVIDER_INVALID);
	zassert_false(descriptor.policy_passed);
	zassert_true((descriptor.policy_blockers &
		      PQCP_FIRMWARE_POLICY_REASON_PROVIDER_CONTRACT_INVALID) !=
		     0U);
}

ZTEST(pqcp_capability_descriptor, test_current_descriptor_emits)
{
	struct pqcp_capability_descriptor descriptor;

	zassert_equal(pqcp_capability_descriptor_current(&descriptor), 0);
	zassert_equal(pqcp_capability_descriptor_validate(&descriptor), 0);
	zassert_equal(pqcp_capability_descriptor_emit(&descriptor), 0);
	zassert_true((descriptor.evidence_capabilities &
		      PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST) != 0U);
	zassert_true((descriptor.evidence_capabilities &
		      PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT) != 0U);
	zassert_true((descriptor.evidence_capabilities &
		      PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY) != 0U);
}

ZTEST(pqcp_capability_descriptor, test_validation_rejects_contradictions)
{
	struct pqcp_firmware_policy_result policy =
		evaluate(&mcu_manifest, &native_contract);
	struct pqcp_capability_descriptor descriptor;

	zassert_equal(pqcp_capability_descriptor_build(
			      &mcu_manifest, &native_contract,
			      &policy, &descriptor),
		      0);

	descriptor.evidence_readiness_score = 101U;
	zassert_equal(pqcp_capability_descriptor_validate(&descriptor),
		      -EINVAL);

	zassert_equal(pqcp_capability_descriptor_build(
			      &mcu_manifest, &native_contract,
			      &policy, &descriptor),
		      0);
	descriptor.policy_passed = true;
	descriptor.policy_blockers =
		PQCP_FIRMWARE_POLICY_REASON_RNG_NOT_ALLOWED;
	zassert_equal(pqcp_capability_descriptor_validate(&descriptor),
		      -EBADMSG);

	zassert_equal(pqcp_capability_descriptor_build(
			      &mcu_manifest, &native_contract,
			      &policy, &descriptor),
		      0);
	descriptor.evidence_capabilities = 0x80000000U;
	zassert_equal(pqcp_capability_descriptor_validate(&descriptor),
		      -EBADMSG);
}

ZTEST_SUITE(pqcp_capability_descriptor, NULL, NULL, NULL, NULL, NULL);
