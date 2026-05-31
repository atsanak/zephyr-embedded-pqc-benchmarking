/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware evidence session tests.
 */

#include <errno.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/evidence_session.h>

#define REQUIRED_CORE_EVENTS \
	(PQCP_EVIDENCE_EVENT_BUILD_MANIFEST | \
	 PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT | \
	 PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY | \
	 PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR | \
	 PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD | \
	 PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS | \
	 PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE)

ZTEST(pqcp_evidence_session, test_event_names_are_stable)
{
	zassert_str_equal(
		pqcp_evidence_event_name(PQCP_EVIDENCE_EVENT_BUILD_MANIFEST),
		"build_manifest");
	zassert_str_equal(
		pqcp_evidence_event_name(PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT),
		"provider_contract");
	zassert_str_equal(
		pqcp_evidence_event_name(PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS),
		"assurance_status");
	zassert_str_equal(
		pqcp_evidence_event_name(PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS),
		"assurance_artifacts");
	zassert_str_equal(
		pqcp_evidence_event_name(PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE),
		"device_evidence");
	zassert_str_equal(
		pqcp_evidence_event_name(PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY),
		"firmware_policy");
	zassert_str_equal(
		pqcp_evidence_event_name(
			PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR),
		"capability_descriptor");
	zassert_str_equal(
		pqcp_evidence_event_name(
			PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD),
		"firmware_scorecard");
	zassert_str_equal(pqcp_evidence_event_name(0x80000000U), "unknown");
}

ZTEST(pqcp_evidence_session, test_event_mask_validation)
{
	zassert_equal(pqcp_evidence_event_mask_validate(REQUIRED_CORE_EVENTS), 0);
	zassert_equal(pqcp_evidence_event_mask_validate(0U), -EINVAL);
	zassert_equal(
		pqcp_evidence_event_mask_validate(
			REQUIRED_CORE_EVENTS | 0x80000000U),
		-EINVAL);
}

ZTEST(pqcp_evidence_session, test_session_records_required_events)
{
	struct pqcp_evidence_session session;

	zassert_equal(pqcp_evidence_session_begin(&session,
						  REQUIRED_CORE_EVENTS),
		      0);
	zassert_true(session.active);
	zassert_equal(session.schema_version,
		      PQCP_EVIDENCE_SESSION_SCHEMA_VERSION);

	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST,
			      0),
		      0);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT,
			      0),
		      0);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY,
			      0),
		      0);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR,
			      0),
		      0);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD,
			      0),
		      0);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS,
			      0),
		      0);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE,
			      0),
		      0);

	zassert_equal(session.observed_events, REQUIRED_CORE_EVENTS);
	zassert_equal(session.failed_events, 0U);
	zassert_equal(session.event_count, 7U);
	zassert_equal(pqcp_evidence_session_end(&session), 0);
	zassert_false(session.active);
}

ZTEST(pqcp_evidence_session, test_missing_required_event_fails_end)
{
	struct pqcp_evidence_session session;

	zassert_equal(pqcp_evidence_session_begin(&session,
						  REQUIRED_CORE_EVENTS),
		      0);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST,
			      0),
		      0);

	zassert_equal(pqcp_evidence_session_end(&session), -ENODATA);
}

ZTEST(pqcp_evidence_session, test_failed_event_blocks_session_pass)
{
	struct pqcp_evidence_session session;

	zassert_equal(pqcp_evidence_session_begin(
			      &session,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST),
		      0);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST,
			      -EIO),
		      -EIO);
	zassert_equal(session.observed_events, 0U);
	zassert_equal(session.failed_events,
		      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST);
	zassert_equal(pqcp_evidence_session_end(&session), -ENODATA);
}

ZTEST(pqcp_evidence_session, test_duplicate_event_fails)
{
	struct pqcp_evidence_session session;

	zassert_equal(pqcp_evidence_session_begin(
			      &session,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST),
		      0);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST,
			      0),
		      0);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST,
			      0),
		      -EALREADY);
	zassert_equal(pqcp_evidence_session_end(&session), -EIO);
}

ZTEST(pqcp_evidence_session, test_rejects_invalid_session_transitions)
{
	struct pqcp_evidence_session session = { 0 };

	zassert_equal(pqcp_evidence_session_begin(NULL,
						  REQUIRED_CORE_EVENTS),
		      -EINVAL);
	zassert_equal(pqcp_evidence_session_begin(&session, 0U), -EINVAL);
	zassert_equal(pqcp_evidence_session_record(
			      NULL,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST,
			      0),
		      -EINVAL);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST,
			      0),
		      -EINVAL);
	zassert_equal(pqcp_evidence_session_end(NULL), -EINVAL);
	zassert_equal(pqcp_evidence_session_end(&session), -EINVAL);

	zassert_equal(pqcp_evidence_session_begin(
			      &session,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST),
		      0);
	zassert_equal(pqcp_evidence_session_record(&session, 0U, 0), -EINVAL);
	zassert_equal(pqcp_evidence_session_record(
			      &session,
			      PQCP_EVIDENCE_EVENT_BUILD_MANIFEST |
				      PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT,
			      0),
		      -EINVAL);
	zassert_equal(pqcp_evidence_session_end(&session), -ENODATA);
}

ZTEST_SUITE(pqcp_evidence_session, NULL, NULL, NULL, NULL, NULL);
