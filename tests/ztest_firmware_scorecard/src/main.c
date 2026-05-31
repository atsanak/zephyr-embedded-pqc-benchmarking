/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware scorecard tests.
 */

#include <errno.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/firmware_scorecard.h>

#define GOOD_SHA \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define ZERO_SHA \
	"0000000000000000000000000000000000000000000000000000000000000000"
#define BAD_SHA \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"
#define GOOD_NONCE "0123456789abcdef0123456789abcdef"
#define BAD_NONCE "0123456789abcdef0123456789abcdeg"

static const struct pqcp_assurance_artifact artifacts[] = {
	{
		.name = "assurance_ledger.json",
		.sha256 = GOOD_SHA,
	},
};

static const struct pqcp_assurance_manifest manifest_without_artifacts = {
	.version = "1.0.0",
	.digest_sha256 = GOOD_SHA,
	.schema_version = 7U,
	.artifacts = NULL,
	.artifact_count = 0U,
};

static const struct pqcp_assurance_manifest manifest_with_artifacts = {
	.version = "1.0.0",
	.digest_sha256 = GOOD_SHA,
	.schema_version = 7U,
	.artifacts = artifacts,
	.artifact_count = ARRAY_SIZE(artifacts),
};

ZTEST(pqcp_firmware_scorecard, test_lab_scorecard_passes_with_warnings)
{
	struct pqcp_firmware_scorecard scorecard;

	zassert_equal(pqcp_firmware_scorecard_evaluate(
			      &manifest_without_artifacts,
			      GOOD_NONCE,
			      ZERO_SHA,
			      &scorecard),
		      0);
	zassert_true(scorecard.passed);
	zassert_equal(scorecard.blocker_mask, 0U);
	zassert_true((scorecard.warning_mask &
		      PQCP_FIRMWARE_SCORECARD_WARNING_NON_PRODUCTION_PROFILE) !=
		     0U);
	zassert_true((scorecard.warning_mask &
		      PQCP_FIRMWARE_SCORECARD_WARNING_NO_ARTIFACTS) != 0U);
	zassert_true((scorecard.warning_mask &
		      PQCP_FIRMWARE_SCORECARD_WARNING_PLACEHOLDER_TRANSCRIPT) !=
		     0U);
	zassert_true(scorecard.readiness_score < 100U);
	zassert_false(scorecard.production_allowed);
}

ZTEST(pqcp_firmware_scorecard, test_manifest_artifact_removes_artifact_warning)
{
	struct pqcp_firmware_scorecard scorecard;

	zassert_equal(pqcp_firmware_scorecard_evaluate(
			      &manifest_with_artifacts,
			      GOOD_NONCE,
			      GOOD_SHA,
			      &scorecard),
		      0);
	zassert_true(scorecard.passed);
	zassert_equal(scorecard.blocker_mask, 0U);
	zassert_false((scorecard.warning_mask &
		       PQCP_FIRMWARE_SCORECARD_WARNING_NO_ARTIFACTS) != 0U);
	zassert_false((scorecard.warning_mask &
		       PQCP_FIRMWARE_SCORECARD_WARNING_PLACEHOLDER_TRANSCRIPT) !=
		      0U);
	zassert_equal(scorecard.artifact_count, ARRAY_SIZE(artifacts));
}

ZTEST(pqcp_firmware_scorecard, test_bad_manifest_blocks_scorecard)
{
	struct pqcp_assurance_manifest manifest = manifest_without_artifacts;
	struct pqcp_firmware_scorecard scorecard;

	manifest.digest_sha256 = BAD_SHA;

	zassert_equal(pqcp_firmware_scorecard_evaluate(
			      &manifest,
			      GOOD_NONCE,
			      GOOD_SHA,
			      &scorecard),
		      0);
	zassert_false(scorecard.passed);
	zassert_true((scorecard.blocker_mask &
		      PQCP_FIRMWARE_SCORECARD_BLOCKER_ASSURANCE_MANIFEST) != 0U);
	zassert_equal(pqcp_firmware_scorecard_emit(&scorecard), -EPERM);
}

ZTEST(pqcp_firmware_scorecard, test_bad_device_input_blocks_scorecard)
{
	struct pqcp_firmware_scorecard scorecard;

	zassert_equal(pqcp_firmware_scorecard_evaluate(
			      &manifest_without_artifacts,
			      BAD_NONCE,
			      GOOD_SHA,
			      &scorecard),
		      0);
	zassert_false(scorecard.passed);
	zassert_true((scorecard.blocker_mask &
		      PQCP_FIRMWARE_SCORECARD_BLOCKER_DEVICE_INPUT) != 0U);
}

ZTEST(pqcp_firmware_scorecard, test_emit_current_prints_marker)
{
	zassert_equal(pqcp_firmware_scorecard_emit_current(
			      &manifest_with_artifacts,
			      GOOD_NONCE,
			      GOOD_SHA),
		      0);
}

ZTEST(pqcp_firmware_scorecard, test_invalid_arguments_and_unknown_masks_fail)
{
	struct pqcp_firmware_scorecard scorecard = {
		.schema_version = PQCP_FIRMWARE_SCORECARD_SCHEMA_VERSION,
		.profile = PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB,
		.blocker_mask = 0x80000000U,
		.warning_mask = 0U,
		.required_events = 0U,
		.artifact_count = 0U,
		.readiness_score = 90U,
		.production_allowed = false,
		.passed = true,
	};

	zassert_equal(pqcp_firmware_scorecard_evaluate(
			      NULL,
			      GOOD_NONCE,
			      GOOD_SHA,
			      &scorecard),
		      -EINVAL);
	zassert_equal(pqcp_firmware_scorecard_evaluate(
			      &manifest_without_artifacts,
			      NULL,
			      GOOD_SHA,
			      &scorecard),
		      -EINVAL);
	zassert_equal(pqcp_firmware_scorecard_emit(NULL), -EINVAL);
	zassert_equal(pqcp_firmware_scorecard_emit(&scorecard), -EBADMSG);
}

ZTEST_SUITE(pqcp_firmware_scorecard, NULL, NULL, NULL, NULL, NULL);
