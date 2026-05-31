/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware evidence session helpers.
 */

#ifndef PQCP_ZEPHYR_EVIDENCE_SESSION_H_
#define PQCP_ZEPHYR_EVIDENCE_SESSION_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for PQCP_EVIDENCE_SESSION_* transcript markers. */
#define PQCP_EVIDENCE_SESSION_SCHEMA_VERSION 1U

/** Build manifest marker was emitted. */
#define PQCP_EVIDENCE_EVENT_BUILD_MANIFEST   (1u << 0)
/** Provider contract marker was emitted. */
#define PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT (1u << 1)
/** Assurance status marker was emitted. */
#define PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS (1u << 2)
/** Assurance artifact markers were emitted. */
#define PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS (1u << 3)
/** Device evidence marker was emitted. */
#define PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE  (1u << 4)
/** Firmware policy marker was emitted. */
#define PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY  (1u << 5)
/** Capability descriptor marker was emitted. */
#define PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR (1u << 6)
/** Firmware scorecard marker was emitted. */
#define PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD (1u << 7)

/** All event bits known by this API version. */
#define PQCP_EVIDENCE_EVENT_KNOWN_MASK \
	(PQCP_EVIDENCE_EVENT_BUILD_MANIFEST | \
	 PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT | \
	 PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS | \
	 PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS | \
	 PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE | \
	 PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY | \
	 PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR | \
	 PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD)

/**
 * @brief Firmware evidence session state.
 *
 * A session records which high-level evidence markers were expected and which
 * were successfully emitted. The state is caller-owned and can live on the
 * stack. It is intentionally small so samples can use it on QEMU and MCUs.
 */
struct pqcp_evidence_session {
	/** Marker schema version used by this session. */
	uint32_t schema_version;
	/** Required PQCP_EVIDENCE_EVENT_* bit mask. */
	uint32_t required_events;
	/** Successfully observed PQCP_EVIDENCE_EVENT_* bit mask. */
	uint32_t observed_events;
	/** Failed or duplicate PQCP_EVIDENCE_EVENT_* bit mask. */
	uint32_t failed_events;
	/** Number of record calls emitted in this session. */
	uint32_t event_count;
	/** True after begin and before end. */
	bool active;
};

/**
 * @brief Return the stable name for one event bit.
 *
 * @param event One PQCP_EVIDENCE_EVENT_* bit.
 *
 * @return Stable event name, or "unknown" for invalid bits.
 */
const char *pqcp_evidence_event_name(uint32_t event);

/**
 * @brief Validate that a mask contains only known event bits.
 *
 * @param events Event mask to validate.
 *
 * @retval 0 The mask is nonzero and contains only known events.
 * @retval -EINVAL The mask is zero or contains unknown bits.
 */
int pqcp_evidence_event_mask_validate(uint32_t events);

/**
 * @brief Start a firmware evidence session and emit the begin marker.
 *
 * Emits:
 * `PQCP_EVIDENCE_SESSION_BEGIN schema=<n> required=<hex>`
 *
 * @param session Caller-owned session state.
 * @param required_events Bit mask of required PQCP_EVIDENCE_EVENT_* markers.
 *
 * @retval 0 Session started.
 * @retval -EINVAL Invalid pointer or event mask.
 */
int pqcp_evidence_session_begin(struct pqcp_evidence_session *session,
				uint32_t required_events);

/**
 * @brief Record one evidence event and emit the event marker.
 *
 * Emits:
 * `PQCP_EVIDENCE_EVENT idx=<n> name=<name> status=<PASS|FAIL|DUPLICATE> code=<ret> observed=<hex> failed=<hex>`
 *
 * A successful event sets the observed bit. A failed or duplicate event sets
 * the failed bit so the session end marker cannot silently pass.
 *
 * @param session Active session state.
 * @param event One PQCP_EVIDENCE_EVENT_* bit.
 * @param status_code Return code from the evidence-emitting helper.
 *
 * @retval 0 Event recorded as successful.
 * @retval -EINVAL Invalid pointer, inactive session, or invalid event.
 * @retval -EALREADY Event was already recorded.
 * @retval status_code If @p status_code is nonzero.
 */
int pqcp_evidence_session_record(struct pqcp_evidence_session *session,
				 uint32_t event, int status_code);

/**
 * @brief Finish the session and emit the end marker.
 *
 * Emits:
 * `PQCP_EVIDENCE_SESSION_END events=<n> required=<hex> observed=<hex> failed=<hex> missing=<hex> status=<PASS|FAIL>`
 *
 * @param session Active session state.
 *
 * @retval 0 All required events were observed and no event failed.
 * @retval -ENODATA One or more required events were missing.
 * @retval -EIO One or more events failed.
 * @retval -EINVAL Invalid pointer or inactive session.
 */
int pqcp_evidence_session_end(struct pqcp_evidence_session *session);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_EVIDENCE_SESSION_H_ */
