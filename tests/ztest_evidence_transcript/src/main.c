/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware evidence transcript replay tests.
 */

#include <errno.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/evidence_transcript.h>

#define GOOD_SHA \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define BAD_SHA \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"
#define GOOD_NONCE "0123456789abcdef0123456789abcdef"

#define BUILD_LINE \
	"PQCP_BUILD_MANIFEST pqcp=1.0.0 zephyr=4.4.0 board=qemu_x86_64 profiles=0x00000000 mlkem_levels=0x00000000 mldsa_levels=0x00000000 rng=custom provider_contract=1"
#define PROVIDER_LINE \
	"PQCP_PROVIDER_CONTRACT mlkem=disabled mlkem_family=disabled mlkem_source=none mldsa=disabled mldsa_family=disabled mldsa_source=none backend=auto external_native_allowed=0 non_native_inventory=0"
#define POLICY_PASS_LINE \
	"PQCP_FIRMWARE_POLICY schema=1 profile=evidence_lab status=PASS production_allowed=0 blockers=0x00000000 required_mlkem=0x00000000 observed_mlkem=0x00000000 required_mldsa=0x00000000 observed_mldsa=0x00000000 rng_allowed=1 provider_contract=1 native_provider=1"
#define POLICY_FAIL_LINE \
	"PQCP_FIRMWARE_POLICY schema=1 profile=gateway status=FAIL production_allowed=1 blockers=0x00000020 required_mlkem=0x00000002 observed_mlkem=0x00000002 required_mldsa=0x00000002 observed_mldsa=0x00000002 rng_allowed=0 provider_contract=1 native_provider=1"
#define CAPABILITY_PASS_LINE \
	"PQCP_CAPABILITY_DESCRIPTOR schema=1 profile=evidence_lab status=PASS production_allowed=0 provider=disabled backend=auto mlkem_levels=0x00000000 mldsa_levels=0x00000000 rng=custom evidence=0x000000ff blockers=0x00000000 readiness=90"
#define CAPABILITY_FAIL_LINE \
	"PQCP_CAPABILITY_DESCRIPTOR schema=1 profile=gateway status=FAIL production_allowed=1 provider=invalid backend=auto mlkem_levels=0x00000002 mldsa_levels=0x00000002 rng=deterministic evidence=0x000000ff blockers=0x00000021 readiness=40"
#define SCORECARD_PASS_ARTIFACT_LINE \
	"PQCP_FIRMWARE_SCORECARD schema=1 profile=evidence_lab status=PASS production_allowed=0 blockers=0x00000000 warnings=0x00000005 readiness=90 required_events=0x000000ff artifacts=1"
#define SCORECARD_PASS_NO_ARTIFACT_LINE \
	"PQCP_FIRMWARE_SCORECARD schema=1 profile=evidence_lab status=PASS production_allowed=0 blockers=0x00000000 warnings=0x00000017 readiness=80 required_events=0x000000f7 artifacts=0"
#define SCORECARD_FAIL_LINE \
	"PQCP_FIRMWARE_SCORECARD schema=1 profile=gateway status=FAIL production_allowed=0 blockers=0x00000020 warnings=0x00000000 readiness=75 required_events=0x00000080 artifacts=0"
#define STATUS_NO_ARTIFACT_LINE \
	"PQCP_ASSURANCE_STATUS version=1.0.0 digest=" GOOD_SHA " artifact_count=0 schema=7"
#define STATUS_ONE_ARTIFACT_LINE \
	"PQCP_ASSURANCE_STATUS version=1.0.0 digest=" GOOD_SHA " artifact_count=1 schema=7"
#define STATUS_TWO_ARTIFACTS_LINE \
	"PQCP_ASSURANCE_STATUS version=1.0.0 digest=" GOOD_SHA " artifact_count=2 schema=7"
#define STATUS_BAD_HASH_LINE \
	"PQCP_ASSURANCE_STATUS version=1.0.0 digest=" BAD_SHA " artifact_count=0 schema=7"
#define ARTIFACT_LINE \
	"PQCP_ASSURANCE_ARTIFACT name=assurance_ledger.json sha256=" GOOD_SHA
#define ARTIFACT_BAD_HASH_LINE \
	"PQCP_ASSURANCE_ARTIFACT name=assurance_ledger.json sha256=" BAD_SHA
#define DEVICE_NO_ARTIFACT_LINE \
	"PQCP_DEVICE_EVIDENCE nonce=" GOOD_NONCE " digest=" GOOD_SHA " artifact_count=0 schema=7 transcript_sha256=" GOOD_SHA
#define DEVICE_ONE_ARTIFACT_LINE \
	"PQCP_DEVICE_EVIDENCE nonce=" GOOD_NONCE " digest=" GOOD_SHA " artifact_count=1 schema=7 transcript_sha256=" GOOD_SHA

static int replay_lines(
	const char *const *lines,
	size_t line_count,
	struct pqcp_evidence_transcript_result *result)
{
	struct pqcp_evidence_transcript_state state;
	int ret;

	zassert_equal(pqcp_evidence_transcript_init(&state), 0);

	for (size_t i = 0U; i < line_count; ++i) {
		ret = pqcp_evidence_transcript_ingest_line(&state, lines[i]);
		if (ret != 0) {
			break;
		}
	}

	return pqcp_evidence_transcript_finish(&state, result);
}

static void assert_replay_error(
	const char *const *lines,
	size_t line_count,
	enum pqcp_evidence_transcript_error expected_error)
{
	struct pqcp_evidence_transcript_result result;

	zassert_equal(replay_lines(lines, line_count, &result), -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_error, expected_error,
		      "unexpected replay error: %s",
		      pqcp_evidence_transcript_error_str(result.first_error));
	zassert_not_equal(result.first_error_line, 0U);
}

ZTEST(pqcp_evidence_transcript, test_valid_transcript_with_artifact_passes)
{
	static const char *const lines[] = {
		"*** Booting Zephyr OS build v4.4.0 ***",
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x000000ff",
		BUILD_LINE,
		"PQCP_EVIDENCE_EVENT idx=0 name=build_manifest status=PASS code=0 observed=0x00000001 failed=0x00000000",
		PROVIDER_LINE,
		"PQCP_EVIDENCE_EVENT idx=1 name=provider_contract status=PASS code=0 observed=0x00000003 failed=0x00000000",
		POLICY_PASS_LINE,
		"PQCP_EVIDENCE_EVENT idx=2 name=firmware_policy status=PASS code=0 observed=0x00000023 failed=0x00000000",
		CAPABILITY_PASS_LINE,
		"PQCP_EVIDENCE_EVENT idx=3 name=capability_descriptor status=PASS code=0 observed=0x00000063 failed=0x00000000",
		SCORECARD_PASS_ARTIFACT_LINE,
		"PQCP_EVIDENCE_EVENT idx=4 name=firmware_scorecard status=PASS code=0 observed=0x000000e3 failed=0x00000000",
		STATUS_ONE_ARTIFACT_LINE,
		ARTIFACT_LINE,
		"PQCP_EVIDENCE_EVENT idx=5 name=assurance_status status=PASS code=0 observed=0x000000e7 failed=0x00000000",
		"PQCP_EVIDENCE_EVENT idx=6 name=assurance_artifacts status=PASS code=0 observed=0x000000ef failed=0x00000000",
		DEVICE_ONE_ARTIFACT_LINE,
		"PQCP_EVIDENCE_EVENT idx=7 name=device_evidence status=PASS code=0 observed=0x000000ff failed=0x00000000",
		"PQCP_EVIDENCE_SESSION_END events=8 required=0x000000ff observed=0x000000ff failed=0x00000000 missing=0x00000000 status=PASS",
	};
	struct pqcp_evidence_transcript_result result;

	zassert_equal(replay_lines(lines, ARRAY_SIZE(lines), &result), 0);
	zassert_true(result.passed);
	zassert_equal(result.required_events, 0x000000ffU);
	zassert_equal(result.observed_events, 0x000000ffU);
	zassert_equal(result.failed_events, 0U);
	zassert_equal(result.declared_artifact_count, 1U);
	zassert_equal(result.observed_artifact_count, 1U);
	zassert_true((result.marker_mask &
		      PQCP_EVIDENCE_TRANSCRIPT_MARKER_CAPABILITY_DESCRIPTOR) != 0U);
	zassert_true((result.marker_mask &
		      PQCP_EVIDENCE_TRANSCRIPT_MARKER_FIRMWARE_SCORECARD) != 0U);
	zassert_true((result.marker_mask &
		      PQCP_EVIDENCE_TRANSCRIPT_MARKER_DEVICE_EVIDENCE) != 0U);
}

ZTEST(pqcp_evidence_transcript, test_valid_transcript_without_artifacts_passes)
{
	static const char *const lines[] = {
		"noise before evidence",
		"PQCP_METRIC,driver,keygen,MLKEM,768,time,1,us",
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x000000f7",
		BUILD_LINE,
		"PQCP_EVIDENCE_EVENT idx=0 name=build_manifest status=PASS code=0 observed=0x00000001 failed=0x00000000",
		PROVIDER_LINE,
		"PQCP_EVIDENCE_EVENT idx=1 name=provider_contract status=PASS code=0 observed=0x00000003 failed=0x00000000",
		POLICY_PASS_LINE,
		"PQCP_EVIDENCE_EVENT idx=2 name=firmware_policy status=PASS code=0 observed=0x00000023 failed=0x00000000",
		CAPABILITY_PASS_LINE,
		"PQCP_EVIDENCE_EVENT idx=3 name=capability_descriptor status=PASS code=0 observed=0x00000063 failed=0x00000000",
		SCORECARD_PASS_NO_ARTIFACT_LINE,
		"PQCP_EVIDENCE_EVENT idx=4 name=firmware_scorecard status=PASS code=0 observed=0x000000e3 failed=0x00000000",
		STATUS_NO_ARTIFACT_LINE,
		"PQCP_EVIDENCE_EVENT idx=5 name=assurance_status status=PASS code=0 observed=0x000000e7 failed=0x00000000",
		DEVICE_NO_ARTIFACT_LINE,
		"PQCP_EVIDENCE_EVENT idx=6 name=device_evidence status=PASS code=0 observed=0x000000f7 failed=0x00000000",
		"PQCP_EVIDENCE_SESSION_END events=7 required=0x000000f7 observed=0x000000f7 failed=0x00000000 missing=0x00000000 status=PASS",
		"PROJECT EXECUTION SUCCESSFUL",
	};
	struct pqcp_evidence_transcript_result result;

	zassert_equal(replay_lines(lines, ARRAY_SIZE(lines), &result), 0);
	zassert_true(result.passed);
	zassert_equal(result.required_events, 0x000000f7U);
	zassert_equal(result.event_count, 7U);
	zassert_equal(result.declared_artifact_count, 0U);
	zassert_equal(result.observed_artifact_count, 0U);
}

ZTEST(pqcp_evidence_transcript, test_missing_session_begin_fails)
{
	static const char *const lines[] = {
		BUILD_LINE,
		"PQCP_EVIDENCE_EVENT idx=0 name=build_manifest status=PASS code=0 observed=0x00000001 failed=0x00000000",
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_BAD_SEQUENCE);
}

ZTEST(pqcp_evidence_transcript, test_event_without_concrete_marker_fails)
{
	static const char *const lines[] = {
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x00000001",
		"PQCP_EVIDENCE_EVENT idx=0 name=build_manifest status=PASS code=0 observed=0x00000001 failed=0x00000000",
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_MARKER_MISSING);
}

ZTEST(pqcp_evidence_transcript, test_bad_artifact_count_fails)
{
	static const char *const lines[] = {
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x000000ff",
		BUILD_LINE,
		"PQCP_EVIDENCE_EVENT idx=0 name=build_manifest status=PASS code=0 observed=0x00000001 failed=0x00000000",
		PROVIDER_LINE,
		"PQCP_EVIDENCE_EVENT idx=1 name=provider_contract status=PASS code=0 observed=0x00000003 failed=0x00000000",
		POLICY_PASS_LINE,
		"PQCP_EVIDENCE_EVENT idx=2 name=firmware_policy status=PASS code=0 observed=0x00000023 failed=0x00000000",
		CAPABILITY_PASS_LINE,
		"PQCP_EVIDENCE_EVENT idx=3 name=capability_descriptor status=PASS code=0 observed=0x00000063 failed=0x00000000",
		SCORECARD_PASS_ARTIFACT_LINE,
		"PQCP_EVIDENCE_EVENT idx=4 name=firmware_scorecard status=PASS code=0 observed=0x000000e3 failed=0x00000000",
		STATUS_TWO_ARTIFACTS_LINE,
		ARTIFACT_LINE,
		"PQCP_EVIDENCE_EVENT idx=5 name=assurance_status status=PASS code=0 observed=0x000000e7 failed=0x00000000",
		"PQCP_EVIDENCE_EVENT idx=6 name=assurance_artifacts status=PASS code=0 observed=0x000000ef failed=0x00000000",
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_ARTIFACT_COUNT);
}

ZTEST(pqcp_evidence_transcript, test_invalid_hash_fails)
{
	static const char *const status_lines[] = {
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x00000037",
		STATUS_BAD_HASH_LINE,
	};
	static const char *const artifact_lines[] = {
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x0000003f",
		STATUS_ONE_ARTIFACT_LINE,
		ARTIFACT_BAD_HASH_LINE,
	};

	assert_replay_error(status_lines, ARRAY_SIZE(status_lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_HASH_INVALID);
	assert_replay_error(artifact_lines, ARRAY_SIZE(artifact_lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_HASH_INVALID);
}

ZTEST(pqcp_evidence_transcript, test_event_index_mismatch_fails)
{
	static const char *const lines[] = {
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x00000001",
		BUILD_LINE,
		"PQCP_EVIDENCE_EVENT idx=7 name=build_manifest status=PASS code=0 observed=0x00000001 failed=0x00000000",
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_INDEX);
}

ZTEST(pqcp_evidence_transcript, test_policy_fail_marker_fails)
{
	static const char *const lines[] = {
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x00000020",
		POLICY_FAIL_LINE,
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL);
}

ZTEST(pqcp_evidence_transcript, test_capability_fail_marker_fails)
{
	static const char *const lines[] = {
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x00000040",
		CAPABILITY_FAIL_LINE,
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL);
}

ZTEST(pqcp_evidence_transcript, test_scorecard_fail_marker_fails)
{
	static const char *const lines[] = {
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x00000080",
		SCORECARD_FAIL_LINE,
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL);
}

ZTEST(pqcp_evidence_transcript, test_session_end_mismatch_fails)
{
	static const char *const lines[] = {
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x00000001",
		BUILD_LINE,
		"PQCP_EVIDENCE_EVENT idx=0 name=build_manifest status=PASS code=0 observed=0x00000001 failed=0x00000000",
		"PQCP_EVIDENCE_SESSION_END events=1 required=0x00000001 observed=0x00000000 failed=0x00000000 missing=0x00000000 status=PASS",
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_MISMATCH);
}

ZTEST(pqcp_evidence_transcript, test_unclosed_session_fails_on_finish)
{
	static const char *const lines[] = {
		"PQCP_EVIDENCE_SESSION_BEGIN schema=1 required=0x00000001",
		BUILD_LINE,
		"PQCP_EVIDENCE_EVENT idx=0 name=build_manifest status=PASS code=0 observed=0x00000001 failed=0x00000000",
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_EVIDENCE_TRANSCRIPT_ERROR_SESSION_INCOMPLETE);
}

ZTEST_SUITE(pqcp_evidence_transcript, NULL, NULL, NULL, NULL, NULL);
