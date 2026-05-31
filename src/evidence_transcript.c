/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware evidence transcript replay verifier.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/capability_descriptor.h>
#include <pqcp_zephyr/evidence_transcript.h>
#include <pqcp_zephyr/firmware_scorecard.h>

#define FIELD_VALUE_MAX 96U

static bool starts_with(const char *value, const char *prefix)
{
	return strncmp(value, prefix, strlen(prefix)) == 0;
}

static bool is_line_break(char c)
{
	return (c == '\0') || (c == '\n') || (c == '\r');
}

static int transcript_fail(struct pqcp_evidence_transcript_state *state,
			   enum pqcp_evidence_transcript_error error)
{
	if ((state != NULL) &&
	    (state->first_error == PQCP_EVIDENCE_TRANSCRIPT_ERROR_NONE)) {
		state->first_error = error;
		state->first_error_line = state->lines_seen;
	}

	return -EBADMSG;
}

static int field_value(const char *line, const char *key,
		       char *out, size_t out_len)
{
	const size_t key_len = strlen(key);
	const char *p = line;

	if ((line == NULL) || (key == NULL) || (out == NULL) ||
	    (out_len == 0U)) {
		return -EINVAL;
	}

	while (*p != '\0') {
		if (((p == line) || (*(p - 1) == ' ')) &&
		    (strncmp(p, key, key_len) == 0) && (p[key_len] == '=')) {
			const char *value = p + key_len + 1;
			size_t len = 0U;

			while ((value[len] != '\0') && (value[len] != ' ') &&
			       (value[len] != '\n') && (value[len] != '\r')) {
				++len;
			}
			if ((len == 0U) || (len >= out_len)) {
				return -EINVAL;
			}
			memcpy(out, value, len);
			out[len] = '\0';
			return 0;
		}
		++p;
	}

	return -ENOENT;
}

static int parse_u32_dec(const char *value, uint32_t *out)
{
	uint32_t result = 0U;

	if ((value == NULL) || (out == NULL) || (*value == '\0')) {
		return -EINVAL;
	}

	for (const char *p = value; *p != '\0'; ++p) {
		if ((*p < '0') || (*p > '9')) {
			return -EINVAL;
		}
		if (result > ((UINT32_MAX - (uint32_t)(*p - '0')) / 10U)) {
			return -EINVAL;
		}
		result = (result * 10U) + (uint32_t)(*p - '0');
	}

	*out = result;
	return 0;
}

static int parse_i32_dec(const char *value, int32_t *out)
{
	int sign = 1;
	uint32_t magnitude;

	if ((value == NULL) || (out == NULL) || (*value == '\0')) {
		return -EINVAL;
	}

	if (*value == '-') {
		sign = -1;
		++value;
		if (*value == '\0') {
			return -EINVAL;
		}
	}

	if (parse_u32_dec(value, &magnitude) != 0) {
		return -EINVAL;
	}
	if ((sign > 0) && (magnitude > INT32_MAX)) {
		return -EINVAL;
	}
	if ((sign < 0) && (magnitude > ((uint32_t)INT32_MAX + 1U))) {
		return -EINVAL;
	}

	*out = sign > 0 ? (int32_t)magnitude : -(int32_t)magnitude;
	return 0;
}

static int hex_nibble(char c)
{
	if ((c >= '0') && (c <= '9')) {
		return c - '0';
	}
	if ((c >= 'a') && (c <= 'f')) {
		return c - 'a' + 10;
	}
	if ((c >= 'A') && (c <= 'F')) {
		return c - 'A' + 10;
	}

	return -1;
}

static int parse_u32_hex(const char *value, uint32_t *out)
{
	uint32_t result = 0U;
	const char *p = value;

	if ((value == NULL) || (out == NULL) || (*value == '\0')) {
		return -EINVAL;
	}

	if ((p[0] == '0') && ((p[1] == 'x') || (p[1] == 'X'))) {
		p += 2;
		if (*p == '\0') {
			return -EINVAL;
		}
	}

	while (*p != '\0') {
		const int nibble = hex_nibble(*p);

		if (nibble < 0) {
			return -EINVAL;
		}
		if (result > (UINT32_MAX >> 4)) {
			return -EINVAL;
		}
		result = (result << 4) | (uint32_t)nibble;
		++p;
	}

	*out = result;
	return 0;
}

static int get_u32_dec(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_VALUE_MAX];

	if (field_value(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}

	return parse_u32_dec(value, out);
}

static int get_i32_dec(const char *line, const char *key, int32_t *out)
{
	char value[FIELD_VALUE_MAX];

	if (field_value(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}

	return parse_i32_dec(value, out);
}

static int get_u32_hex(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_VALUE_MAX];

	if (field_value(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}

	return parse_u32_hex(value, out);
}

static int get_field(const char *line, const char *key,
		     char *out, size_t out_len)
{
	if (field_value(line, key, out, out_len) != 0) {
		return -EINVAL;
	}

	return 0;
}

static uint32_t event_for_name(const char *name)
{
	if (strcmp(name, "build_manifest") == 0) {
		return PQCP_EVIDENCE_EVENT_BUILD_MANIFEST;
	}
	if (strcmp(name, "provider_contract") == 0) {
		return PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT;
	}
	if (strcmp(name, "assurance_status") == 0) {
		return PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS;
	}
	if (strcmp(name, "assurance_artifacts") == 0) {
		return PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS;
	}
	if (strcmp(name, "device_evidence") == 0) {
		return PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE;
	}
	if (strcmp(name, "firmware_policy") == 0) {
		return PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY;
	}
	if (strcmp(name, "capability_descriptor") == 0) {
		return PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR;
	}
	if (strcmp(name, "firmware_scorecard") == 0) {
		return PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD;
	}

	return 0U;
}

static uint32_t marker_for_event(uint32_t event)
{
	switch (event) {
	case PQCP_EVIDENCE_EVENT_BUILD_MANIFEST:
		return PQCP_EVIDENCE_TRANSCRIPT_MARKER_BUILD_MANIFEST;
	case PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT:
		return PQCP_EVIDENCE_TRANSCRIPT_MARKER_PROVIDER_CONTRACT;
	case PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS:
		return PQCP_EVIDENCE_TRANSCRIPT_MARKER_ASSURANCE_STATUS;
	case PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS:
		return PQCP_EVIDENCE_TRANSCRIPT_MARKER_ASSURANCE_ARTIFACT;
	case PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE:
		return PQCP_EVIDENCE_TRANSCRIPT_MARKER_DEVICE_EVIDENCE;
	case PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY:
		return PQCP_EVIDENCE_TRANSCRIPT_MARKER_FIRMWARE_POLICY;
	case PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR:
		return PQCP_EVIDENCE_TRANSCRIPT_MARKER_CAPABILITY_DESCRIPTOR;
	case PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD:
		return PQCP_EVIDENCE_TRANSCRIPT_MARKER_FIRMWARE_SCORECARD;
	default:
		return 0U;
	}
}

static bool is_single_event(uint32_t event)
{
	return (event != 0U) && ((event & (event - 1U)) == 0U) &&
	       ((event & PQCP_EVIDENCE_EVENT_KNOWN_MASK) == event);
}

static int require_active(struct pqcp_evidence_transcript_state *state)
{
	if (!state->active || state->closed) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_BAD_SEQUENCE);
	}

	return 0;
}

static int set_marker(struct pqcp_evidence_transcript_state *state,
		      uint32_t marker)
{
	if (require_active(state) != 0) {
		return -EBADMSG;
	}

	state->marker_mask |= marker;
	return 0;
}

static void fill_result(const struct pqcp_evidence_transcript_state *state,
			struct pqcp_evidence_transcript_result *result,
			bool passed)
{
	if ((state == NULL) || (result == NULL)) {
		return;
	}

	result->schema_version = PQCP_EVIDENCE_TRANSCRIPT_SCHEMA_VERSION;
	result->lines_seen = state->lines_seen;
	result->required_events = state->required_events;
	result->observed_events = state->observed_events;
	result->failed_events = state->failed_events;
	result->missing_events = state->missing_events;
	result->marker_mask = state->marker_mask;
	result->event_count = state->next_event_index;
	result->declared_artifact_count = state->declared_artifact_count;
	result->observed_artifact_count = state->observed_artifact_count;
	result->first_error_line = state->first_error_line;
	result->first_error = state->first_error;
	result->passed = passed;
}

const char *pqcp_evidence_transcript_error_str(
	enum pqcp_evidence_transcript_error error)
{
	switch (error) {
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_NONE:
		return "none";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD:
		return "malformed_field";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_BAD_SEQUENCE:
		return "bad_sequence";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_DUPLICATE_SESSION:
		return "duplicate_session";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_INDEX:
		return "event_index";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_UNKNOWN_EVENT:
		return "unknown_event";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_MISMATCH:
		return "event_mismatch";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_MARKER_MISSING:
		return "marker_missing";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_HASH_INVALID:
		return "hash_invalid";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL:
		return "status_fail";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_SESSION_MISSING:
		return "session_missing";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_SESSION_INCOMPLETE:
		return "session_incomplete";
	case PQCP_EVIDENCE_TRANSCRIPT_ERROR_ARTIFACT_COUNT:
		return "artifact_count";
	default:
		return "unknown";
	}
}

int pqcp_evidence_transcript_init(
	struct pqcp_evidence_transcript_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->schema_version = PQCP_EVIDENCE_TRANSCRIPT_SCHEMA_VERSION;
	state->first_error = PQCP_EVIDENCE_TRANSCRIPT_ERROR_NONE;

	return 0;
}

static int ingest_session_begin(
	struct pqcp_evidence_transcript_state *state,
	const char *line)
{
	uint32_t schema;
	uint32_t required;

	if (state->active || state->closed || state->required_events != 0U) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_DUPLICATE_SESSION);
	}
	if ((get_u32_dec(line, "schema", &schema) != 0) ||
	    (get_u32_hex(line, "required", &required) != 0) ||
	    (schema != PQCP_EVIDENCE_SESSION_SCHEMA_VERSION) ||
	    (pqcp_evidence_event_mask_validate(required) != 0)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}

	state->required_events = required;
	state->active = true;
	return 0;
}

static int ingest_session_event(
	struct pqcp_evidence_transcript_state *state,
	const char *line)
{
	uint32_t idx;
	uint32_t parsed_observed;
	uint32_t parsed_failed;
	uint32_t event;
	uint32_t marker;
	int32_t code;
	char name[FIELD_VALUE_MAX];
	char status[FIELD_VALUE_MAX];

	if (require_active(state) != 0) {
		return -EBADMSG;
	}
	if ((get_u32_dec(line, "idx", &idx) != 0) ||
	    (get_field(line, "name", name, sizeof(name)) != 0) ||
	    (get_field(line, "status", status, sizeof(status)) != 0) ||
	    (get_i32_dec(line, "code", &code) != 0) ||
	    (get_u32_hex(line, "observed", &parsed_observed) != 0) ||
	    (get_u32_hex(line, "failed", &parsed_failed) != 0)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if (idx != state->next_event_index) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_INDEX);
	}

	event = event_for_name(name);
	if (!is_single_event(event)) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_UNKNOWN_EVENT);
	}

	marker = marker_for_event(event);
	if (strcmp(status, "PASS") == 0) {
		if (code != 0) {
			return transcript_fail(
				state,
				PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_MISMATCH);
		}
		if ((state->marker_mask & marker) == 0U) {
			return transcript_fail(
				state,
				PQCP_EVIDENCE_TRANSCRIPT_ERROR_MARKER_MISSING);
		}
		state->observed_events |= event;
	} else if ((strcmp(status, "FAIL") == 0) ||
		   (strcmp(status, "DUPLICATE") == 0)) {
		if (code == 0) {
			return transcript_fail(
				state,
				PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_MISMATCH);
		}
		state->failed_events |= event;
	} else {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}

	if ((parsed_observed != state->observed_events) ||
	    (parsed_failed != state->failed_events)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_MISMATCH);
	}

	if ((event == PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS) &&
	    ((state->declared_artifact_count == 0U) ||
	     (state->observed_artifact_count !=
	      state->declared_artifact_count))) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_ARTIFACT_COUNT);
	}

	state->next_event_index++;
	if (state->failed_events != 0U) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL);
	}

	return 0;
}

static int ingest_session_end(
	struct pqcp_evidence_transcript_state *state,
	const char *line)
{
	uint32_t events;
	uint32_t required;
	uint32_t observed;
	uint32_t failed;
	uint32_t missing;
	char status[FIELD_VALUE_MAX];

	if (require_active(state) != 0) {
		return -EBADMSG;
	}
	if ((get_u32_dec(line, "events", &events) != 0) ||
	    (get_u32_hex(line, "required", &required) != 0) ||
	    (get_u32_hex(line, "observed", &observed) != 0) ||
	    (get_u32_hex(line, "failed", &failed) != 0) ||
	    (get_u32_hex(line, "missing", &missing) != 0) ||
	    (get_field(line, "status", status, sizeof(status)) != 0)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}

	state->missing_events = state->required_events & ~state->observed_events;
	if ((events != state->next_event_index) ||
	    (required != state->required_events) ||
	    (observed != state->observed_events) ||
	    (failed != state->failed_events) ||
	    (missing != state->missing_events)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_MISMATCH);
	}

	state->end_status_passed = strcmp(status, "PASS") == 0;
	if (!state->end_status_passed && (strcmp(status, "FAIL") != 0)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if (state->end_status_passed &&
	    ((state->failed_events != 0U) || (state->missing_events != 0U))) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_MISMATCH);
	}
	if (!state->end_status_passed &&
	    ((state->failed_events == 0U) && (state->missing_events == 0U))) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_MISMATCH);
	}

	state->active = false;
	state->closed = true;

	if (!state->end_status_passed) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL);
	}

	return 0;
}

static int ingest_build_manifest(
	struct pqcp_evidence_transcript_state *state)
{
	return set_marker(
		state, PQCP_EVIDENCE_TRANSCRIPT_MARKER_BUILD_MANIFEST);
}

static int ingest_provider_contract(
	struct pqcp_evidence_transcript_state *state)
{
	return set_marker(
		state, PQCP_EVIDENCE_TRANSCRIPT_MARKER_PROVIDER_CONTRACT);
}

static int ingest_firmware_policy(
	struct pqcp_evidence_transcript_state *state,
	const char *line)
{
	uint32_t blockers;
	char status[FIELD_VALUE_MAX];
	int ret = set_marker(
		state, PQCP_EVIDENCE_TRANSCRIPT_MARKER_FIRMWARE_POLICY);

	if (ret != 0) {
		return ret;
	}
	if ((get_field(line, "status", status, sizeof(status)) != 0) ||
	    (get_u32_hex(line, "blockers", &blockers) != 0)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if ((strcmp(status, "PASS") != 0) || (blockers != 0U)) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL);
	}

	return 0;
}

static int ingest_assurance_status(
	struct pqcp_evidence_transcript_state *state,
	const char *line)
{
	char digest[PQCP_ASSURANCE_SHA256_HEX_CHARS + 1U];
	uint32_t artifact_count;
	uint32_t schema;
	int ret = set_marker(
		state, PQCP_EVIDENCE_TRANSCRIPT_MARKER_ASSURANCE_STATUS);

	if (ret != 0) {
		return ret;
	}
	if ((get_field(line, "digest", digest, sizeof(digest)) != 0) ||
	    (get_u32_dec(line, "artifact_count", &artifact_count) != 0) ||
	    (get_u32_dec(line, "schema", &schema) != 0)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if (!pqcp_assurance_is_sha256_hex(digest) || (schema == 0U)) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_HASH_INVALID);
	}

	memcpy(state->assurance_digest, digest, sizeof(state->assurance_digest));
	state->declared_artifact_count = artifact_count;
	if (state->scorecard_seen &&
	    (state->scorecard_artifact_count != artifact_count)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_ARTIFACT_COUNT);
	}
	state->assurance_schema = schema;
	return 0;
}

static int ingest_capability_descriptor(
	struct pqcp_evidence_transcript_state *state,
	const char *line)
{
	char profile[FIELD_VALUE_MAX];
	char status[FIELD_VALUE_MAX];
	char provider[FIELD_VALUE_MAX];
	char backend[FIELD_VALUE_MAX];
	char rng[FIELD_VALUE_MAX];
	uint32_t schema;
	uint32_t production_allowed;
	uint32_t mlkem_levels;
	uint32_t mldsa_levels;
	uint32_t evidence;
	uint32_t blockers;
	uint32_t readiness;
	int ret = set_marker(
		state, PQCP_EVIDENCE_TRANSCRIPT_MARKER_CAPABILITY_DESCRIPTOR);

	if (ret != 0) {
		return ret;
	}
	if ((get_u32_dec(line, "schema", &schema) != 0) ||
	    (get_field(line, "profile", profile, sizeof(profile)) != 0) ||
	    (get_field(line, "status", status, sizeof(status)) != 0) ||
	    (get_u32_dec(line, "production_allowed",
			 &production_allowed) != 0) ||
	    (get_field(line, "provider", provider, sizeof(provider)) != 0) ||
	    (get_field(line, "backend", backend, sizeof(backend)) != 0) ||
	    (get_u32_hex(line, "mlkem_levels", &mlkem_levels) != 0) ||
	    (get_u32_hex(line, "mldsa_levels", &mldsa_levels) != 0) ||
	    (get_field(line, "rng", rng, sizeof(rng)) != 0) ||
	    (get_u32_hex(line, "evidence", &evidence) != 0) ||
	    (get_u32_hex(line, "blockers", &blockers) != 0) ||
	    (get_u32_dec(line, "readiness", &readiness) != 0)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	(void)mlkem_levels;
	(void)mldsa_levels;

	if ((schema != PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION) ||
	    (production_allowed > 1U) || (readiness > 100U) ||
	    (profile[0] == '\0') || (provider[0] == '\0') ||
	    (backend[0] == '\0') || (rng[0] == '\0') ||
	    ((evidence & ~PQCP_CAPABILITY_EVIDENCE_KNOWN_MASK) != 0U)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if ((strcmp(status, "PASS") != 0) || (blockers != 0U)) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL);
	}

	return 0;
}

static int ingest_firmware_scorecard(
	struct pqcp_evidence_transcript_state *state,
	const char *line)
{
	char profile[FIELD_VALUE_MAX];
	char status[FIELD_VALUE_MAX];
	uint32_t schema;
	uint32_t production_allowed;
	uint32_t blockers;
	uint32_t warnings;
	uint32_t readiness;
	uint32_t required_events;
	uint32_t artifacts;
	int ret = set_marker(
		state, PQCP_EVIDENCE_TRANSCRIPT_MARKER_FIRMWARE_SCORECARD);

	if (ret != 0) {
		return ret;
	}
	if ((get_u32_dec(line, "schema", &schema) != 0) ||
	    (get_field(line, "profile", profile, sizeof(profile)) != 0) ||
	    (get_field(line, "status", status, sizeof(status)) != 0) ||
	    (get_u32_dec(line, "production_allowed",
			 &production_allowed) != 0) ||
	    (get_u32_hex(line, "blockers", &blockers) != 0) ||
	    (get_u32_hex(line, "warnings", &warnings) != 0) ||
	    (get_u32_dec(line, "readiness", &readiness) != 0) ||
	    (get_u32_hex(line, "required_events", &required_events) != 0) ||
	    (get_u32_dec(line, "artifacts", &artifacts) != 0)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if ((schema != PQCP_FIRMWARE_SCORECARD_SCHEMA_VERSION) ||
	    (profile[0] == '\0') || (production_allowed > 1U) ||
	    (readiness > 100U) ||
	    ((blockers & ~PQCP_FIRMWARE_SCORECARD_BLOCKER_KNOWN_MASK) != 0U) ||
	    ((warnings & ~PQCP_FIRMWARE_SCORECARD_WARNING_KNOWN_MASK) != 0U) ||
	    (required_events != state->required_events)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if ((strcmp(status, "PASS") == 0) && (blockers == 0U)) {
		state->scorecard_artifact_count = artifacts;
		state->scorecard_seen = true;
		return 0;
	}
	if ((strcmp(status, "FAIL") == 0) && (blockers != 0U)) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL);
	}

	return transcript_fail(
		state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
}

static int ingest_assurance_artifact(
	struct pqcp_evidence_transcript_state *state,
	const char *line)
{
	char sha256[PQCP_ASSURANCE_SHA256_HEX_CHARS + 1U];
	int ret;

	if ((state->marker_mask &
	     PQCP_EVIDENCE_TRANSCRIPT_MARKER_ASSURANCE_STATUS) == 0U) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_BAD_SEQUENCE);
	}

	ret = set_marker(
		state, PQCP_EVIDENCE_TRANSCRIPT_MARKER_ASSURANCE_ARTIFACT);
	if (ret != 0) {
		return ret;
	}
	if (get_field(line, "sha256", sha256, sizeof(sha256)) != 0) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if (!pqcp_assurance_is_sha256_hex(sha256)) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_HASH_INVALID);
	}

	state->observed_artifact_count++;
	if (state->observed_artifact_count > state->declared_artifact_count) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_ARTIFACT_COUNT);
	}

	return 0;
}

static int ingest_device_evidence(
	struct pqcp_evidence_transcript_state *state,
	const char *line)
{
	char nonce[PQCP_ASSURANCE_NONCE128_HEX_CHARS + 1U];
	char digest[PQCP_ASSURANCE_SHA256_HEX_CHARS + 1U];
	char transcript_sha[PQCP_ASSURANCE_SHA256_HEX_CHARS + 1U];
	uint32_t artifact_count;
	uint32_t schema;
	int ret;

	if ((state->marker_mask &
	     PQCP_EVIDENCE_TRANSCRIPT_MARKER_ASSURANCE_STATUS) == 0U) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_BAD_SEQUENCE);
	}

	ret = set_marker(
		state, PQCP_EVIDENCE_TRANSCRIPT_MARKER_DEVICE_EVIDENCE);
	if (ret != 0) {
		return ret;
	}
	if ((get_field(line, "nonce", nonce, sizeof(nonce)) != 0) ||
	    (get_field(line, "digest", digest, sizeof(digest)) != 0) ||
	    (get_u32_dec(line, "artifact_count", &artifact_count) != 0) ||
	    (get_u32_dec(line, "schema", &schema) != 0) ||
	    (get_field(line, "transcript_sha256", transcript_sha,
		       sizeof(transcript_sha)) != 0)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if (!pqcp_assurance_is_nonce128_hex(nonce) ||
	    !pqcp_assurance_is_sha256_hex(digest) ||
	    !pqcp_assurance_is_sha256_hex(transcript_sha)) {
		return transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_HASH_INVALID);
	}
	if ((artifact_count != state->declared_artifact_count) ||
	    (state->observed_artifact_count != state->declared_artifact_count) ||
	    (schema != state->assurance_schema) ||
	    (strcmp(digest, state->assurance_digest) != 0)) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_ARTIFACT_COUNT);
	}

	state->device_schema = schema;
	return 0;
}

int pqcp_evidence_transcript_ingest_line(
	struct pqcp_evidence_transcript_state *state,
	const char *line)
{
	if ((state == NULL) || (line == NULL)) {
		return -EINVAL;
	}

	state->lines_seen++;
	if (state->first_error != PQCP_EVIDENCE_TRANSCRIPT_ERROR_NONE) {
		return -EBADMSG;
	}
	if (is_line_break(line[0])) {
		return 0;
	}

	if (starts_with(line, "PQCP_EVIDENCE_SESSION_BEGIN ")) {
		return ingest_session_begin(state, line);
	}
	if (starts_with(line, "PQCP_EVIDENCE_EVENT ")) {
		return ingest_session_event(state, line);
	}
	if (starts_with(line, "PQCP_EVIDENCE_SESSION_END ")) {
		return ingest_session_end(state, line);
	}
	if (starts_with(line, "PQCP_BUILD_MANIFEST ")) {
		return ingest_build_manifest(state);
	}
	if (starts_with(line, "PQCP_PROVIDER_CONTRACT ")) {
		return ingest_provider_contract(state);
	}
	if (starts_with(line, "PQCP_FIRMWARE_POLICY ")) {
		return ingest_firmware_policy(state, line);
	}
	if (starts_with(line, "PQCP_CAPABILITY_DESCRIPTOR ")) {
		return ingest_capability_descriptor(state, line);
	}
	if (starts_with(line, "PQCP_FIRMWARE_SCORECARD ")) {
		return ingest_firmware_scorecard(state, line);
	}
	if (starts_with(line, "PQCP_ASSURANCE_STATUS ")) {
		return ingest_assurance_status(state, line);
	}
	if (starts_with(line, "PQCP_ASSURANCE_ARTIFACT ")) {
		return ingest_assurance_artifact(state, line);
	}
	if (starts_with(line, "PQCP_DEVICE_EVIDENCE ")) {
		return ingest_device_evidence(state, line);
	}
	if (starts_with(line, "PQCP_EVIDENCE_") ||
	    starts_with(line, "PQCP_ASSURANCE_") ||
	    starts_with(line, "PQCP_FIRMWARE_") ||
	    starts_with(line, "PQCP_CAPABILITY_")) {
		return transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}

	return 0;
}

int pqcp_evidence_transcript_finish(
	struct pqcp_evidence_transcript_state *state,
	struct pqcp_evidence_transcript_result *result)
{
	uint32_t required_markers = 0U;

	if (state == NULL) {
		return -EINVAL;
	}

	if (state->first_error != PQCP_EVIDENCE_TRANSCRIPT_ERROR_NONE) {
		fill_result(state, result, false);
		return -EBADMSG;
	}
	if (state->required_events == 0U) {
		transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_SESSION_MISSING);
		fill_result(state, result, false);
		return -EBADMSG;
	}
	if (!state->closed || state->active) {
		transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_SESSION_INCOMPLETE);
		fill_result(state, result, false);
		return -EBADMSG;
	}
	if (!state->end_status_passed || (state->failed_events != 0U) ||
	    (state->missing_events != 0U) ||
	    ((state->required_events & ~state->observed_events) != 0U)) {
		transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL);
		fill_result(state, result, false);
		return -EBADMSG;
	}

	for (uint32_t event = 1U; event <= PQCP_EVIDENCE_EVENT_KNOWN_MASK;
	     event <<= 1) {
		if ((state->observed_events & event) != 0U) {
			required_markers |= marker_for_event(event);
		}
	}

	if ((required_markers & ~state->marker_mask) != 0U) {
		transcript_fail(
			state, PQCP_EVIDENCE_TRANSCRIPT_ERROR_MARKER_MISSING);
		fill_result(state, result, false);
		return -EBADMSG;
	}

	if ((state->declared_artifact_count != state->observed_artifact_count) ||
	    (((state->required_events &
	       PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS) == 0U) &&
	     (state->declared_artifact_count != 0U))) {
		transcript_fail(
			state,
			PQCP_EVIDENCE_TRANSCRIPT_ERROR_ARTIFACT_COUNT);
		fill_result(state, result, false);
		return -EBADMSG;
	}

	fill_result(state, result, true);
	return 0;
}
