/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Firmware evidence transcript verifier
 *
 * Stability: stable evidence API for the 1.0.x line. This API replays the
 * firmware-visible evidence marker grammar and verifies that the session
 * summary is bound to the concrete markers that appeared in the transcript.
 */

#ifndef PQCP_ZEPHYR_EVIDENCE_TRANSCRIPT_H_
#define PQCP_ZEPHYR_EVIDENCE_TRANSCRIPT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/assurance.h>
#include <pqcp_zephyr/evidence_session.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for the C transcript replay verifier. */
#define PQCP_EVIDENCE_TRANSCRIPT_SCHEMA_VERSION 1U

/** Build manifest line was observed. */
#define PQCP_EVIDENCE_TRANSCRIPT_MARKER_BUILD_MANIFEST   (1U << 0)
/** Provider contract line was observed. */
#define PQCP_EVIDENCE_TRANSCRIPT_MARKER_PROVIDER_CONTRACT (1U << 1)
/** Firmware policy line was observed. */
#define PQCP_EVIDENCE_TRANSCRIPT_MARKER_FIRMWARE_POLICY  (1U << 2)
/** Assurance status line was observed. */
#define PQCP_EVIDENCE_TRANSCRIPT_MARKER_ASSURANCE_STATUS (1U << 3)
/** One or more assurance artifact lines were observed. */
#define PQCP_EVIDENCE_TRANSCRIPT_MARKER_ASSURANCE_ARTIFACT (1U << 4)
/** Device evidence line was observed. */
#define PQCP_EVIDENCE_TRANSCRIPT_MARKER_DEVICE_EVIDENCE  (1U << 5)
/** Capability descriptor line was observed. */
#define PQCP_EVIDENCE_TRANSCRIPT_MARKER_CAPABILITY_DESCRIPTOR (1U << 6)
/** Firmware scorecard line was observed. */
#define PQCP_EVIDENCE_TRANSCRIPT_MARKER_FIRMWARE_SCORECARD (1U << 7)

/** All marker bits known by this API version. */
#define PQCP_EVIDENCE_TRANSCRIPT_MARKER_KNOWN_MASK \
	(PQCP_EVIDENCE_TRANSCRIPT_MARKER_BUILD_MANIFEST | \
	 PQCP_EVIDENCE_TRANSCRIPT_MARKER_PROVIDER_CONTRACT | \
	 PQCP_EVIDENCE_TRANSCRIPT_MARKER_FIRMWARE_POLICY | \
	 PQCP_EVIDENCE_TRANSCRIPT_MARKER_ASSURANCE_STATUS | \
	 PQCP_EVIDENCE_TRANSCRIPT_MARKER_ASSURANCE_ARTIFACT | \
	 PQCP_EVIDENCE_TRANSCRIPT_MARKER_DEVICE_EVIDENCE | \
	 PQCP_EVIDENCE_TRANSCRIPT_MARKER_CAPABILITY_DESCRIPTOR | \
	 PQCP_EVIDENCE_TRANSCRIPT_MARKER_FIRMWARE_SCORECARD)

/**
 * @brief Replay error reason for firmware evidence transcripts.
 */
enum pqcp_evidence_transcript_error {
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_NONE = 0,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_INVALID_ARGUMENT,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_MALFORMED_FIELD,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_BAD_SEQUENCE,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_DUPLICATE_SESSION,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_INDEX,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_UNKNOWN_EVENT,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_EVENT_MISMATCH,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_MARKER_MISSING,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_HASH_INVALID,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_STATUS_FAIL,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_SESSION_MISSING,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_SESSION_INCOMPLETE,
	PQCP_EVIDENCE_TRANSCRIPT_ERROR_ARTIFACT_COUNT,
};

/**
 * @brief Stateful transcript replay verifier.
 *
 * The state is caller-owned and can live on the stack. Feed transcript lines
 * to pqcp_evidence_transcript_ingest_line(), then call
 * pqcp_evidence_transcript_finish() once all lines have been consumed.
 */
struct pqcp_evidence_transcript_state {
	/** Verifier schema version. */
	uint32_t schema_version;
	/** Number of transcript lines seen by this replay state. */
	uint32_t lines_seen;
	/** First line that caused a replay error, or zero when none failed. */
	uint32_t first_error_line;
	/** First replay error reason. */
	enum pqcp_evidence_transcript_error first_error;
	/** Required events parsed from PQCP_EVIDENCE_SESSION_BEGIN. */
	uint32_t required_events;
	/** Observed events reconstructed from PQCP_EVIDENCE_EVENT records. */
	uint32_t observed_events;
	/** Failed events reconstructed from PQCP_EVIDENCE_EVENT records. */
	uint32_t failed_events;
	/** Missing events parsed and verified from PQCP_EVIDENCE_SESSION_END. */
	uint32_t missing_events;
	/** Concrete evidence marker bits observed in the transcript. */
	uint32_t marker_mask;
	/** Expected event index for the next PQCP_EVIDENCE_EVENT line. */
	uint32_t next_event_index;
	/** Number of artifact records declared by PQCP_ASSURANCE_STATUS. */
	uint32_t declared_artifact_count;
	/** Artifact count declared by PQCP_FIRMWARE_SCORECARD. */
	uint32_t scorecard_artifact_count;
	/** Number of PQCP_ASSURANCE_ARTIFACT lines observed. */
	uint32_t observed_artifact_count;
	/** Assurance schema parsed from PQCP_ASSURANCE_STATUS. */
	uint32_t assurance_schema;
	/** Device-evidence schema parsed from PQCP_DEVICE_EVIDENCE. */
	uint32_t device_schema;
	/** True after session begin and before session end. */
	bool active;
	/** True after PQCP_EVIDENCE_SESSION_END was replayed. */
	bool closed;
	/** True after PQCP_FIRMWARE_SCORECARD was replayed. */
	bool scorecard_seen;
	/** True when the end marker reports status=PASS. */
	bool end_status_passed;
	/** Digest parsed from PQCP_ASSURANCE_STATUS. */
	char assurance_digest[PQCP_ASSURANCE_SHA256_HEX_CHARS + 1U];
};

/**
 * @brief Final transcript replay result.
 */
struct pqcp_evidence_transcript_result {
	/** Verifier schema version. */
	uint32_t schema_version;
	/** Number of transcript lines consumed. */
	uint32_t lines_seen;
	/** Required event bit mask. */
	uint32_t required_events;
	/** Observed event bit mask. */
	uint32_t observed_events;
	/** Failed event bit mask. */
	uint32_t failed_events;
	/** Missing event bit mask. */
	uint32_t missing_events;
	/** Concrete marker bits observed. */
	uint32_t marker_mask;
	/** Number of evidence event records consumed. */
	uint32_t event_count;
	/** Declared assurance artifact count. */
	uint32_t declared_artifact_count;
	/** Observed assurance artifact count. */
	uint32_t observed_artifact_count;
	/** First error line, or zero when passed. */
	uint32_t first_error_line;
	/** First replay error reason. */
	enum pqcp_evidence_transcript_error first_error;
	/** True when all required session events are bound to concrete markers. */
	bool passed;
};

/**
 * @brief Convert a replay error code to a stable diagnostic token.
 *
 * @param error Error code.
 *
 * @return Static diagnostic token.
 */
const char *pqcp_evidence_transcript_error_str(
	enum pqcp_evidence_transcript_error error);

/**
 * @brief Initialize transcript replay state.
 *
 * @param state Caller-owned state to initialize.
 *
 * @retval 0 State initialized.
 * @retval -EINVAL Invalid pointer.
 */
int pqcp_evidence_transcript_init(
	struct pqcp_evidence_transcript_state *state);

/**
 * @brief Feed one transcript line into the replay verifier.
 *
 * The verifier ignores unrelated QEMU/Zephyr lines and unrelated PQCP metric
 * rows. Evidence marker lines are parsed strictly; malformed fields, bad
 * ordering, marker/event mismatches, failed policy markers, and invalid hashes
 * cause the first error to be recorded and a nonzero status to be returned.
 *
 * @param state Replay state initialized with pqcp_evidence_transcript_init().
 * @param line One NUL-terminated transcript line.
 *
 * @retval 0 Line accepted or ignored.
 * @retval -EINVAL Invalid pointer.
 * @retval -EBADMSG Evidence line failed replay validation.
 */
int pqcp_evidence_transcript_ingest_line(
	struct pqcp_evidence_transcript_state *state,
	const char *line);

/**
 * @brief Finish replay and verify the session summary.
 *
 * @param state Replay state.
 * @param result Optional final result output.
 *
 * @retval 0 Transcript passed replay validation.
 * @retval -EINVAL Invalid state pointer.
 * @retval -EBADMSG Replay failed.
 */
int pqcp_evidence_transcript_finish(
	struct pqcp_evidence_transcript_state *state,
	struct pqcp_evidence_transcript_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_EVIDENCE_TRANSCRIPT_H_ */
