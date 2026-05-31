/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Firmware evidence runner
 *
 * Stability: stable evidence API for the 1.0.x line. This API orchestrates
 * firmware-visible evidence markers in a fixed transcript order. It does not
 * select cryptographic providers, alter public crypto APIs, change ACVP wire
 * formats, or modify benchmark row ordering.
 */

#ifndef PQCP_ZEPHYR_FIRMWARE_EVIDENCE_H_
#define PQCP_ZEPHYR_FIRMWARE_EVIDENCE_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/assurance.h>
#include <pqcp_zephyr/evidence_session.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Required event mask for a firmware evidence run without artifacts. */
#define PQCP_FIRMWARE_EVIDENCE_REQUIRED_BASE \
	(PQCP_EVIDENCE_EVENT_BUILD_MANIFEST | \
	 PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT | \
	 PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY | \
	 PQCP_EVIDENCE_EVENT_CAPABILITY_DESCRIPTOR | \
	 PQCP_EVIDENCE_EVENT_FIRMWARE_SCORECARD | \
	 PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS | \
	 PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE)

/**
 * @brief Injectable evidence emit hooks.
 *
 * The default hooks call the real PQCP firmware evidence helpers. Tests may
 * pass their own hooks to prove failure handling without patching global state.
 */
struct pqcp_firmware_evidence_hooks {
	/** Emit PQCP_BUILD_MANIFEST. */
	int (*emit_build_manifest)(void);
	/** Emit PQCP_PROVIDER_CONTRACT. */
	int (*emit_provider_contract)(void);
	/** Emit PQCP_FIRMWARE_POLICY. */
	int (*emit_firmware_policy)(void);
	/** Emit PQCP_CAPABILITY_DESCRIPTOR. */
	int (*emit_capability_descriptor)(void);
	/** Emit PQCP_FIRMWARE_SCORECARD. */
	int (*emit_firmware_scorecard)(
		const struct pqcp_assurance_manifest *manifest,
		const char *nonce_hex,
		const char *transcript_sha256);
	/** Emit PQCP_ASSURANCE_STATUS and PQCP_ASSURANCE_ARTIFACT records. */
	int (*emit_assurance_status)(
		const struct pqcp_assurance_manifest *manifest);
	/** Emit PQCP_DEVICE_EVIDENCE. */
	int (*emit_device_evidence)(
		const struct pqcp_assurance_manifest *manifest,
		const char *nonce_hex,
		const char *transcript_sha256);
};

/**
 * @brief Firmware evidence run configuration.
 */
struct pqcp_firmware_evidence_config {
	/** Assurance manifest to emit. */
	const struct pqcp_assurance_manifest *manifest;
	/** Device-evidence nonce encoded as 32 hex characters. */
	const char *device_nonce_hex;
	/** Transcript digest encoded as 64 hex characters. */
	const char *transcript_sha256;
	/** Optional emit hooks; NULL selects the default hooks. */
	const struct pqcp_firmware_evidence_hooks *hooks;
};

/**
 * @brief Firmware evidence run result.
 */
struct pqcp_firmware_evidence_result {
	/** Required event mask for this run. */
	uint32_t required_events;
	/** Observed event mask recorded by the session. */
	uint32_t observed_events;
	/** Failed event mask recorded by the session. */
	uint32_t failed_events;
	/** Required events not observed when the session ended. */
	uint32_t missing_events;
	/** Event bit associated with the first emit failure. */
	uint32_t first_failed_event;
	/** Return code from the first failed emit or record operation. */
	int first_error;
	/** Return code from pqcp_evidence_session_end(). */
	int session_end_code;
	/** True when all required events passed and session end succeeded. */
	bool passed;
};

/**
 * @brief Return the default firmware evidence hooks.
 *
 * @return Pointer to static immutable hooks that call the production helpers.
 */
const struct pqcp_firmware_evidence_hooks *
pqcp_firmware_evidence_default_hooks(void);

/**
 * @brief Calculate required events for an assurance manifest.
 *
 * Artifact events are required only when the manifest has at least one artifact.
 *
 * @param manifest Assurance manifest.
 *
 * @return Required PQCP_EVIDENCE_EVENT_* mask.
 */
uint32_t pqcp_firmware_evidence_required_events(
	const struct pqcp_assurance_manifest *manifest);

/**
 * @brief Emit a complete firmware evidence transcript.
 *
 * The transcript order is fixed:
 * evidence-session begin, build manifest, provider contract, firmware policy,
 * capability descriptor, scorecard, assurance status, optional artifact event,
 * device evidence, evidence-session end. On the first failure the runner
 * records the failed event, closes the session, and returns a nonzero status.
 *
 * @param config Evidence run configuration.
 * @param result Optional caller-owned result; may be NULL.
 *
 * @retval 0 Complete evidence transcript passed.
 * @retval -EINVAL Invalid configuration or missing hook.
 * @retval <0 First emit/record failure, or the session-end failure code.
 */
int pqcp_firmware_evidence_run(
	const struct pqcp_firmware_evidence_config *config,
	struct pqcp_firmware_evidence_result *result);

/**
 * @brief Convenience wrapper using the default hooks.
 *
 * @param manifest Assurance manifest to emit.
 * @param nonce_hex Device-evidence nonce encoded as 32 hex characters.
 * @param transcript_sha256 Transcript digest encoded as 64 hex characters.
 * @param result Optional caller-owned result; may be NULL.
 *
 * @retval 0 Complete evidence transcript passed.
 * @retval -EINVAL Invalid configuration.
 * @retval <0 First emit/record failure, or the session-end failure code.
 */
int pqcp_firmware_evidence_run_default(
	const struct pqcp_assurance_manifest *manifest,
	const char *nonce_hex,
	const char *transcript_sha256,
	struct pqcp_firmware_evidence_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FIRMWARE_EVIDENCE_H_ */
