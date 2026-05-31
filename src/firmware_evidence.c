/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware evidence runner.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/capability_descriptor.h>
#include <pqcp_zephyr/firmware_evidence.h>
#include <pqcp_zephyr/firmware_policy.h>
#include <pqcp_zephyr/firmware_scorecard.h>
#include <pqcp_zephyr/provider.h>

static const struct pqcp_firmware_evidence_hooks default_hooks = {
	.emit_build_manifest = pqcp_build_manifest_emit,
	.emit_provider_contract = pqcp_provider_emit_contract,
	.emit_firmware_policy = pqcp_firmware_policy_emit_current,
	.emit_capability_descriptor = pqcp_capability_descriptor_emit_current,
	.emit_firmware_scorecard = pqcp_firmware_scorecard_emit_current,
	.emit_assurance_status = pqcp_assurance_emit_status,
	.emit_device_evidence = pqcp_assurance_emit_device_evidence,
};

const struct pqcp_firmware_evidence_hooks *
pqcp_firmware_evidence_default_hooks(void)
{
	return &default_hooks;
}

uint32_t pqcp_firmware_evidence_required_events(
	const struct pqcp_assurance_manifest *manifest)
{
	uint32_t events = PQCP_FIRMWARE_EVIDENCE_REQUIRED_BASE;

	if ((manifest != NULL) && (manifest->artifact_count > 0U)) {
		events |= PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS;
	}

	return events;
}

static int pqcp_firmware_evidence_hooks_validate(
	const struct pqcp_firmware_evidence_hooks *hooks)
{
	if ((hooks == NULL) ||
	    (hooks->emit_build_manifest == NULL) ||
	    (hooks->emit_provider_contract == NULL) ||
	    (hooks->emit_firmware_policy == NULL) ||
	    (hooks->emit_capability_descriptor == NULL) ||
	    (hooks->emit_firmware_scorecard == NULL) ||
	    (hooks->emit_assurance_status == NULL) ||
	    (hooks->emit_device_evidence == NULL)) {
		return -EINVAL;
	}

	return 0;
}

static void pqcp_firmware_evidence_result_init(
	struct pqcp_firmware_evidence_result *result,
	uint32_t required_events)
{
	if (result == NULL) {
		return;
	}

	memset(result, 0, sizeof(*result));
	result->required_events = required_events;
}

static void pqcp_firmware_evidence_result_update(
	struct pqcp_firmware_evidence_result *result,
	const struct pqcp_evidence_session *session,
	int first_error,
	uint32_t first_failed_event,
	int session_end_code)
{
	if ((result == NULL) || (session == NULL)) {
		return;
	}

	result->required_events = session->required_events;
	result->observed_events = session->observed_events;
	result->failed_events = session->failed_events;
	result->missing_events = session->required_events &
				 ~session->observed_events;
	result->first_failed_event = first_failed_event;
	result->first_error = first_error;
	result->session_end_code = session_end_code;
	result->passed = (first_error == 0) && (session_end_code == 0);
}

static int pqcp_firmware_evidence_record_step(
	struct pqcp_evidence_session *session,
	uint32_t event,
	int emit_ret,
	int *first_error,
	uint32_t *first_failed_event)
{
	int record_ret = pqcp_evidence_session_record(session, event, emit_ret);

	if ((*first_error == 0) && (record_ret != 0)) {
		*first_error = record_ret;
		*first_failed_event = event;
	}
	if ((*first_error == 0) && (emit_ret != 0)) {
		*first_error = emit_ret;
		*first_failed_event = event;
	}

	return *first_error;
}

static int pqcp_firmware_evidence_finish(
	struct pqcp_evidence_session *session,
	struct pqcp_firmware_evidence_result *result,
	int first_error,
	uint32_t first_failed_event)
{
	int end_ret = pqcp_evidence_session_end(session);

	pqcp_firmware_evidence_result_update(
		result, session, first_error, first_failed_event, end_ret);

	if (first_error != 0) {
		return first_error;
	}

	return end_ret;
}

int pqcp_firmware_evidence_run(
	const struct pqcp_firmware_evidence_config *config,
	struct pqcp_firmware_evidence_result *result)
{
	struct pqcp_evidence_session session;
	const struct pqcp_firmware_evidence_hooks *hooks;
	uint32_t required_events;
	int first_error = 0;
	uint32_t first_failed_event = 0U;
	int ret;

	if ((config == NULL) || (config->manifest == NULL) ||
	    (config->device_nonce_hex == NULL) ||
	    (config->transcript_sha256 == NULL)) {
		return -EINVAL;
	}

	hooks = config->hooks != NULL ?
		config->hooks : pqcp_firmware_evidence_default_hooks();
	ret = pqcp_firmware_evidence_hooks_validate(hooks);
	if (ret != 0) {
		return ret;
	}

	required_events =
		pqcp_firmware_evidence_required_events(config->manifest);
	pqcp_firmware_evidence_result_init(result, required_events);

	ret = pqcp_evidence_session_begin(&session, required_events);
	if (ret != 0) {
		if (result != NULL) {
			result->first_error = ret;
			result->session_end_code = ret;
			result->passed = false;
		}
		return ret;
	}

	ret = hooks->emit_build_manifest();
	if (pqcp_firmware_evidence_record_step(
		    &session, PQCP_EVIDENCE_EVENT_BUILD_MANIFEST, ret,
		    &first_error, &first_failed_event) != 0) {
		return pqcp_firmware_evidence_finish(
			&session, result, first_error, first_failed_event);
	}

	ret = hooks->emit_provider_contract();
	if (pqcp_firmware_evidence_record_step(
		    &session, PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT, ret,
		    &first_error, &first_failed_event) != 0) {
		return pqcp_firmware_evidence_finish(
			&session, result, first_error, first_failed_event);
	}

	ret = hooks->emit_firmware_policy();
	if (pqcp_firmware_evidence_record_step(
		    &session, PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY, ret,
		    &first_error, &first_failed_event) != 0) {
		return pqcp_firmware_evidence_finish(
			&session, result, first_error, first_failed_event);
	}

	ret = hooks->emit_capability_descriptor();
	if (pqcp_firmware_evidence_record_step(
		    &session, PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR, ret,
		    &first_error, &first_failed_event) != 0) {
		return pqcp_firmware_evidence_finish(
			&session, result, first_error, first_failed_event);
	}

	ret = hooks->emit_firmware_scorecard(
		config->manifest,
		config->device_nonce_hex,
		config->transcript_sha256);
	if (pqcp_firmware_evidence_record_step(
		    &session, PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD, ret,
		    &first_error, &first_failed_event) != 0) {
		return pqcp_firmware_evidence_finish(
			&session, result, first_error, first_failed_event);
	}

	ret = hooks->emit_assurance_status(config->manifest);
	if (pqcp_firmware_evidence_record_step(
		    &session, PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS, ret,
		    &first_error, &first_failed_event) != 0) {
		return pqcp_firmware_evidence_finish(
			&session, result, first_error, first_failed_event);
	}

	if (config->manifest->artifact_count > 0U) {
		if (pqcp_firmware_evidence_record_step(
			    &session,
			    PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS,
			    0,
			    &first_error,
			    &first_failed_event) != 0) {
			return pqcp_firmware_evidence_finish(
				&session, result, first_error,
				first_failed_event);
		}
	}

	ret = hooks->emit_device_evidence(
		config->manifest,
		config->device_nonce_hex,
		config->transcript_sha256);
	if (pqcp_firmware_evidence_record_step(
		    &session, PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE, ret,
		    &first_error, &first_failed_event) != 0) {
		return pqcp_firmware_evidence_finish(
			&session, result, first_error, first_failed_event);
	}

	return pqcp_firmware_evidence_finish(
		&session, result, first_error, first_failed_event);
}

int pqcp_firmware_evidence_run_default(
	const struct pqcp_assurance_manifest *manifest,
	const char *nonce_hex,
	const char *transcript_sha256,
	struct pqcp_firmware_evidence_result *result)
{
	const struct pqcp_firmware_evidence_config config = {
		.manifest = manifest,
		.device_nonce_hex = nonce_hex,
		.transcript_sha256 = transcript_sha256,
		.hooks = pqcp_firmware_evidence_default_hooks(),
	};

	return pqcp_firmware_evidence_run(&config, result);
}
