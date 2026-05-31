/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware evidence runner tests.
 */

#include <errno.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/firmware_evidence.h>

#define GOOD_SHA \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define GOOD_NONCE "0123456789abcdef0123456789abcdef"

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

static int build_ret;
static int provider_ret;
static int policy_ret;
static int capability_ret;
static int scorecard_ret;
static int status_ret;
static int device_ret;
static uint32_t build_calls;
static uint32_t provider_calls;
static uint32_t policy_calls;
static uint32_t capability_calls;
static uint32_t scorecard_calls;
static uint32_t status_calls;
static uint32_t device_calls;

static void reset_fake_hooks(void)
{
	build_ret = 0;
	provider_ret = 0;
	policy_ret = 0;
	capability_ret = 0;
	scorecard_ret = 0;
	status_ret = 0;
	device_ret = 0;
	build_calls = 0U;
	provider_calls = 0U;
	policy_calls = 0U;
	capability_calls = 0U;
	scorecard_calls = 0U;
	status_calls = 0U;
	device_calls = 0U;
}

static int fake_build_manifest(void)
{
	build_calls++;
	return build_ret;
}

static int fake_provider_contract(void)
{
	provider_calls++;
	return provider_ret;
}

static int fake_firmware_policy(void)
{
	policy_calls++;
	return policy_ret;
}

static int fake_capability_descriptor(void)
{
	capability_calls++;
	return capability_ret;
}

static int fake_firmware_scorecard(
	const struct pqcp_assurance_manifest *manifest,
	const char *nonce_hex,
	const char *transcript_sha256)
{
	scorecard_calls++;
	zassert_not_null(manifest);
	zassert_str_equal(nonce_hex, GOOD_NONCE);
	zassert_str_equal(transcript_sha256, GOOD_SHA);
	return scorecard_ret;
}

static int fake_assurance_status(
	const struct pqcp_assurance_manifest *manifest)
{
	status_calls++;
	zassert_not_null(manifest);
	return status_ret;
}

static int fake_device_evidence(
	const struct pqcp_assurance_manifest *manifest,
	const char *nonce_hex,
	const char *transcript_sha256)
{
	device_calls++;
	zassert_not_null(manifest);
	zassert_str_equal(nonce_hex, GOOD_NONCE);
	zassert_str_equal(transcript_sha256, GOOD_SHA);
	return device_ret;
}

static const struct pqcp_firmware_evidence_hooks fake_hooks = {
	.emit_build_manifest = fake_build_manifest,
	.emit_provider_contract = fake_provider_contract,
	.emit_firmware_policy = fake_firmware_policy,
	.emit_capability_descriptor = fake_capability_descriptor,
	.emit_firmware_scorecard = fake_firmware_scorecard,
	.emit_assurance_status = fake_assurance_status,
	.emit_device_evidence = fake_device_evidence,
};

static struct pqcp_firmware_evidence_config fake_config(
	const struct pqcp_assurance_manifest *manifest)
{
	return (struct pqcp_firmware_evidence_config) {
		.manifest = manifest,
		.device_nonce_hex = GOOD_NONCE,
		.transcript_sha256 = GOOD_SHA,
		.hooks = &fake_hooks,
	};
}

ZTEST(pqcp_firmware_evidence, test_required_events_include_artifacts_when_present)
{
	zassert_equal(
		pqcp_firmware_evidence_required_events(&manifest_without_artifacts),
		PQCP_FIRMWARE_EVIDENCE_REQUIRED_BASE);
	zassert_equal(
		pqcp_firmware_evidence_required_events(&manifest_with_artifacts),
		PQCP_FIRMWARE_EVIDENCE_REQUIRED_BASE |
			PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS);
}

ZTEST(pqcp_firmware_evidence, test_fake_hooks_pass_without_artifacts)
{
	struct pqcp_firmware_evidence_config config =
		fake_config(&manifest_without_artifacts);
	struct pqcp_firmware_evidence_result result;

	reset_fake_hooks();

	zassert_equal(pqcp_firmware_evidence_run(&config, &result), 0);
	zassert_true(result.passed);
	zassert_equal(result.required_events,
		      PQCP_FIRMWARE_EVIDENCE_REQUIRED_BASE);
	zassert_equal(result.observed_events,
		      PQCP_FIRMWARE_EVIDENCE_REQUIRED_BASE);
	zassert_equal(result.failed_events, 0U);
	zassert_equal(result.missing_events, 0U);
	zassert_equal(build_calls, 1U);
	zassert_equal(provider_calls, 1U);
	zassert_equal(policy_calls, 1U);
	zassert_equal(capability_calls, 1U);
	zassert_equal(scorecard_calls, 1U);
	zassert_equal(status_calls, 1U);
	zassert_equal(device_calls, 1U);
}

ZTEST(pqcp_firmware_evidence, test_fake_hooks_pass_with_artifacts)
{
	struct pqcp_firmware_evidence_config config =
		fake_config(&manifest_with_artifacts);
	struct pqcp_firmware_evidence_result result;

	reset_fake_hooks();

	zassert_equal(pqcp_firmware_evidence_run(&config, &result), 0);
	zassert_true(result.passed);
	zassert_equal(result.required_events,
		      PQCP_FIRMWARE_EVIDENCE_REQUIRED_BASE |
			      PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS);
	zassert_equal(result.observed_events, result.required_events);
	zassert_equal(result.failed_events, 0U);
	zassert_equal(result.missing_events, 0U);
}

ZTEST(pqcp_firmware_evidence, test_provider_failure_closes_session_and_stops)
{
	struct pqcp_firmware_evidence_config config =
		fake_config(&manifest_without_artifacts);
	struct pqcp_firmware_evidence_result result;

	reset_fake_hooks();
	provider_ret = -EIO;

	zassert_equal(pqcp_firmware_evidence_run(&config, &result), -EIO);
	zassert_false(result.passed);
	zassert_equal(result.first_failed_event,
		      PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT);
	zassert_equal(result.first_error, -EIO);
	zassert_equal(result.observed_events,
		      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST);
	zassert_equal(result.failed_events,
		      PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT);
	zassert_true((result.missing_events &
		      PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY) != 0U);
	zassert_equal(build_calls, 1U);
	zassert_equal(provider_calls, 1U);
	zassert_equal(policy_calls, 0U);
	zassert_equal(capability_calls, 0U);
	zassert_equal(scorecard_calls, 0U);
	zassert_equal(status_calls, 0U);
	zassert_equal(device_calls, 0U);
}

ZTEST(pqcp_firmware_evidence, test_capability_failure_records_capability_blocker)
{
	struct pqcp_firmware_evidence_config config =
		fake_config(&manifest_without_artifacts);
	struct pqcp_firmware_evidence_result result;

	reset_fake_hooks();
	capability_ret = -EPERM;

	zassert_equal(pqcp_firmware_evidence_run(&config, &result), -EPERM);
	zassert_false(result.passed);
	zassert_equal(result.first_failed_event,
		      PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR);
	zassert_equal(result.failed_events,
		      PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR);
	zassert_true((result.observed_events &
		      PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY) != 0U);
	zassert_equal(capability_calls, 1U);
	zassert_equal(scorecard_calls, 0U);
	zassert_equal(status_calls, 0U);
	zassert_equal(device_calls, 0U);
}

ZTEST(pqcp_firmware_evidence, test_scorecard_failure_records_scorecard_blocker)
{
	struct pqcp_firmware_evidence_config config =
		fake_config(&manifest_without_artifacts);
	struct pqcp_firmware_evidence_result result;

	reset_fake_hooks();
	scorecard_ret = -EPERM;

	zassert_equal(pqcp_firmware_evidence_run(&config, &result), -EPERM);
	zassert_false(result.passed);
	zassert_equal(result.first_failed_event,
		      PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD);
	zassert_equal(result.failed_events,
		      PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD);
	zassert_true((result.observed_events &
		      PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR) != 0U);
	zassert_equal(scorecard_calls, 1U);
	zassert_equal(status_calls, 0U);
	zassert_equal(device_calls, 0U);
}

ZTEST(pqcp_firmware_evidence, test_status_failure_records_status_blocker)
{
	struct pqcp_firmware_evidence_config config =
		fake_config(&manifest_without_artifacts);
	struct pqcp_firmware_evidence_result result;

	reset_fake_hooks();
	status_ret = -EBADMSG;

	zassert_equal(pqcp_firmware_evidence_run(&config, &result), -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_failed_event,
		      PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS);
	zassert_equal(result.failed_events,
		      PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS);
	zassert_true((result.observed_events &
		      PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY) != 0U);
	zassert_true((result.observed_events &
		      PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR) != 0U);
	zassert_equal(capability_calls, 1U);
	zassert_equal(scorecard_calls, 1U);
	zassert_equal(device_calls, 0U);
}

ZTEST(pqcp_firmware_evidence, test_default_hooks_emit_current_evidence)
{
	struct pqcp_firmware_evidence_result result;

	zassert_equal(pqcp_firmware_evidence_run_default(
			      &manifest_without_artifacts,
			      GOOD_NONCE,
			      GOOD_SHA,
			      &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.observed_events,
		      PQCP_FIRMWARE_EVIDENCE_REQUIRED_BASE);
	zassert_equal(result.failed_events, 0U);
}

ZTEST(pqcp_firmware_evidence, test_invalid_configuration_is_rejected)
{
	struct pqcp_firmware_evidence_config config =
		fake_config(&manifest_without_artifacts);
	struct pqcp_firmware_evidence_hooks bad_hooks = fake_hooks;
	struct pqcp_firmware_evidence_result result;

	zassert_equal(pqcp_firmware_evidence_run(NULL, &result), -EINVAL);

	config.manifest = NULL;
	zassert_equal(pqcp_firmware_evidence_run(&config, &result), -EINVAL);

	config = fake_config(&manifest_without_artifacts);
	config.device_nonce_hex = NULL;
	zassert_equal(pqcp_firmware_evidence_run(&config, &result), -EINVAL);

	config = fake_config(&manifest_without_artifacts);
	config.transcript_sha256 = NULL;
	zassert_equal(pqcp_firmware_evidence_run(&config, &result), -EINVAL);

	bad_hooks.emit_firmware_scorecard = NULL;
	config = fake_config(&manifest_without_artifacts);
	config.hooks = &bad_hooks;
	zassert_equal(pqcp_firmware_evidence_run(&config, &result), -EINVAL);
}

ZTEST_SUITE(pqcp_firmware_evidence, NULL, NULL, NULL, NULL, NULL);
