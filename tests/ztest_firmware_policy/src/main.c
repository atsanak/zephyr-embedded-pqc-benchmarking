/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware policy evidence tests.
 */

#include <errno.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/firmware_policy.h>

static const struct pqcp_provider_contract native_provider = {
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

static void assert_reason(uint32_t blockers, uint32_t reason)
{
	zassert_true((blockers & reason) != 0U,
		     "expected blocker 0x%08x in 0x%08x",
		     reason, blockers);
}

ZTEST(pqcp_firmware_policy, test_profile_strings_are_stable)
{
	zassert_str_equal(pqcp_firmware_policy_profile_str(
				  PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB),
			  "evidence_lab");
	zassert_str_equal(pqcp_firmware_policy_profile_str(
				  PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL),
			  "mcu_minimal");
	zassert_str_equal(pqcp_firmware_policy_profile_str(
				  PQCP_FIRMWARE_POLICY_PROFILE_GATEWAY),
			  "gateway");
	zassert_str_equal(pqcp_firmware_policy_profile_str(
				  PQCP_FIRMWARE_POLICY_PROFILE_NATIVE_LAB),
			  "native_lab");
	zassert_str_equal(pqcp_firmware_policy_profile_str(99), "unknown");
}

ZTEST(pqcp_firmware_policy, test_profile_selection_from_manifest)
{
	struct pqcp_build_manifest manifest = mcu_manifest;

	zassert_equal(pqcp_firmware_policy_profile_from_manifest(&manifest),
		      PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL);

	manifest.profile_flags = PQCP_BUILD_PROFILE_GATEWAY;
	zassert_equal(pqcp_firmware_policy_profile_from_manifest(&manifest),
		      PQCP_FIRMWARE_POLICY_PROFILE_GATEWAY);

	manifest.profile_flags = PQCP_BUILD_PROFILE_NATIVE_LAB;
	zassert_equal(pqcp_firmware_policy_profile_from_manifest(&manifest),
		      PQCP_FIRMWARE_POLICY_PROFILE_NATIVE_LAB);

	manifest.profile_flags = 0U;
	zassert_equal(pqcp_firmware_policy_profile_from_manifest(&manifest),
		      PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB);
}

ZTEST(pqcp_firmware_policy, test_current_evidence_lab_profile_passes)
{
	const struct pqcp_build_manifest *manifest = pqcp_build_manifest_get();
	const struct pqcp_provider_contract *contract = pqcp_provider_contract_get();
	struct pqcp_firmware_policy policy = pqcp_firmware_policy_default(
		PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB);
	struct pqcp_firmware_policy_result result;

	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, manifest, contract, &result),
		      0);
	zassert_true(result.passed);
	zassert_false(result.production_allowed);
	zassert_true(result.rng_allowed);
	zassert_equal(result.blocker_mask, 0U);
	zassert_equal(pqcp_firmware_policy_emit_result(&result), 0);
}

ZTEST(pqcp_firmware_policy, test_mcu_profile_passes_with_required_evidence)
{
	struct pqcp_firmware_policy policy = pqcp_firmware_policy_default(
		PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL);
	struct pqcp_firmware_policy_result result;

	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, &mcu_manifest, &native_provider, &result),
		      0);
	zassert_true(result.passed);
	zassert_true(result.production_allowed);
	zassert_equal(result.blocker_mask, 0U);
	zassert_equal(result.required_mlkem_levels, PQCP_BUILD_MLKEM_LEVEL_768);
	zassert_equal(result.required_mldsa_levels, PQCP_BUILD_MLDSA_LEVEL_65);
}

ZTEST(pqcp_firmware_policy, test_missing_required_levels_fail)
{
	struct pqcp_build_manifest manifest = mcu_manifest;
	struct pqcp_firmware_policy policy = pqcp_firmware_policy_default(
		PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL);
	struct pqcp_firmware_policy_result result;

	manifest.mlkem_level_mask = 0U;
	manifest.mldsa_level_mask = 0U;

	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, &manifest, &native_provider, &result),
		      0);
	zassert_false(result.passed);
	zassert_false(result.production_allowed);
	assert_reason(result.blocker_mask,
		      PQCP_FIRMWARE_POLICY_REASON_MLKEM_LEVEL_MISSING);
	assert_reason(result.blocker_mask,
		      PQCP_FIRMWARE_POLICY_REASON_MLDSA_LEVEL_MISSING);
}

ZTEST(pqcp_firmware_policy, test_rng_policy_blocks_custom_in_production)
{
	struct pqcp_build_manifest manifest = mcu_manifest;
	struct pqcp_firmware_policy policy = pqcp_firmware_policy_default(
		PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL);
	struct pqcp_firmware_policy_result result;

	manifest.rng_mode = "custom";

	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, &manifest, &native_provider, &result),
		      0);
	zassert_false(result.passed);
	zassert_false(result.rng_allowed);
	assert_reason(result.blocker_mask,
		      PQCP_FIRMWARE_POLICY_REASON_RNG_NOT_ALLOWED);

	manifest.rng_mode = "deterministic_test";
	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, &manifest, &native_provider, &result),
		      0);
	zassert_false(result.passed);
	zassert_false(result.rng_allowed);
	assert_reason(result.blocker_mask,
		      PQCP_FIRMWARE_POLICY_REASON_RNG_NOT_ALLOWED);
}

ZTEST(pqcp_firmware_policy, test_native_provider_policy_blocks_external_family)
{
	struct pqcp_provider_contract provider = native_provider;
	struct pqcp_firmware_policy policy = pqcp_firmware_policy_default(
		PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL);
	struct pqcp_firmware_policy_result result;

	provider.mlkem_family = PQCP_PROVIDER_FAMILY_FORBIDDEN;
	provider.external_native_family_allowed = true;

	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, &mcu_manifest, &provider, &result),
		      0);
	zassert_false(result.passed);
	zassert_false(result.provider_contract_valid);
	zassert_false(result.native_provider_met);
	assert_reason(result.blocker_mask,
		      PQCP_FIRMWARE_POLICY_REASON_PROVIDER_CONTRACT_INVALID);
	assert_reason(result.blocker_mask,
		      PQCP_FIRMWARE_POLICY_REASON_NATIVE_PROVIDER_INVALID);
}

ZTEST(pqcp_firmware_policy, test_provider_contract_requirement_is_enforced)
{
	struct pqcp_build_manifest manifest = mcu_manifest;
	struct pqcp_firmware_policy policy = pqcp_firmware_policy_default(
		PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL);
	struct pqcp_firmware_policy_result result;

	manifest.provider_contract_enabled = false;

	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, &manifest, &native_provider, &result),
		      0);
	zassert_false(result.passed);
	zassert_false(result.provider_required_met);
	assert_reason(result.blocker_mask,
		      PQCP_FIRMWARE_POLICY_REASON_PROVIDER_CONTRACT_MISSING);
}

ZTEST(pqcp_firmware_policy, test_invalid_inputs_and_emit_validation)
{
	struct pqcp_firmware_policy policy = pqcp_firmware_policy_default(
		PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL);
	struct pqcp_firmware_policy_result result;

	zassert_equal(pqcp_firmware_policy_evaluate(
			      NULL, &mcu_manifest, &native_provider, &result),
		      -EINVAL);
	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, NULL, &native_provider, &result),
		      -EINVAL);
	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, &mcu_manifest, NULL, &result),
		      -EINVAL);
	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, &mcu_manifest, &native_provider, NULL),
		      -EINVAL);
	zassert_equal(pqcp_firmware_policy_emit_result(NULL), -EINVAL);

	zassert_equal(pqcp_firmware_policy_evaluate(
			      &policy, &mcu_manifest, &native_provider, &result),
		      0);
	result.blocker_mask = 0x80000000U;
	zassert_equal(pqcp_firmware_policy_emit_result(&result), -EBADMSG);
}

ZTEST_SUITE(pqcp_firmware_policy, NULL, NULL, NULL, NULL, NULL);
