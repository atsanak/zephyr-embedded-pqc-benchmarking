/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware evidence session helpers.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/evidence_session.h>

const char *pqcp_evidence_event_name(uint32_t event)
{
	switch (event) {
	case PQCP_EVIDENCE_EVENT_BUILD_MANIFEST:
		return "build_manifest";
	case PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT:
		return "provider_contract";
	case PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS:
		return "assurance_status";
	case PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS:
		return "assurance_artifacts";
	case PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE:
		return "device_evidence";
	case PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY:
		return "firmware_policy";
	case PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR:
		return "capability_descriptor";
	case PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD:
		return "firmware_scorecard";
	default:
		return "unknown";
	}
}

static bool pqcp_evidence_is_single_event(uint32_t event)
{
	return (event != 0U) && ((event & (event - 1U)) == 0U) &&
	       ((event & PQCP_EVIDENCE_EVENT_KNOWN_MASK) == event);
}

int pqcp_evidence_event_mask_validate(uint32_t events)
{
	if (events == 0U) {
		return -EINVAL;
	}
	if ((events & ~PQCP_EVIDENCE_EVENT_KNOWN_MASK) != 0U) {
		return -EINVAL;
	}

	return 0;
}

int pqcp_evidence_session_begin(struct pqcp_evidence_session *session,
				uint32_t required_events)
{
	if (session == NULL) {
		return -EINVAL;
	}
	if (pqcp_evidence_event_mask_validate(required_events) != 0) {
		return -EINVAL;
	}

	memset(session, 0, sizeof(*session));
	session->schema_version = PQCP_EVIDENCE_SESSION_SCHEMA_VERSION;
	session->required_events = required_events;
	session->active = true;

	printk("PQCP_EVIDENCE_SESSION_BEGIN schema=%u required=0x%08x\n",
	       session->schema_version, session->required_events);

	return 0;
}

int pqcp_evidence_session_record(struct pqcp_evidence_session *session,
				 uint32_t event, int status_code)
{
	const char *status = "PASS";
	int ret = status_code;

	if ((session == NULL) || !session->active ||
	    !pqcp_evidence_is_single_event(event)) {
		return -EINVAL;
	}

	if ((session->observed_events & event) != 0U) {
		status = "DUPLICATE";
		ret = -EALREADY;
		session->failed_events |= event;
	} else if (status_code != 0) {
		status = "FAIL";
		session->failed_events |= event;
	} else {
		session->observed_events |= event;
	}

	printk("PQCP_EVIDENCE_EVENT idx=%u name=%s status=%s code=%d observed=0x%08x failed=0x%08x\n",
	       session->event_count,
	       pqcp_evidence_event_name(event),
	       status,
	       ret,
	       session->observed_events,
	       session->failed_events);
	session->event_count++;

	return ret;
}

int pqcp_evidence_session_end(struct pqcp_evidence_session *session)
{
	uint32_t missing_events;
	const char *status = "PASS";
	int ret = 0;

	if ((session == NULL) || !session->active) {
		return -EINVAL;
	}

	missing_events = session->required_events & ~session->observed_events;
	if (missing_events != 0U) {
		status = "FAIL";
		ret = -ENODATA;
	} else if (session->failed_events != 0U) {
		status = "FAIL";
		ret = -EIO;
	}

	printk("PQCP_EVIDENCE_SESSION_END events=%u required=0x%08x observed=0x%08x failed=0x%08x missing=0x%08x status=%s\n",
	       session->event_count,
	       session->required_events,
	       session->observed_events,
	       session->failed_events,
	       missing_events,
	       status);

	session->active = false;

	return ret;
}
