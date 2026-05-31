/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Firmware assurance status helpers
 *
 * Stability: stable evidence API for the 1.0.x line. The printed
 * PQCP_ASSURANCE_* marker grammar is stable and intended for local release
 * replay tooling, device-evidence capture, and partner review.
 */

#ifndef PQCP_ZEPHYR_ASSURANCE_H_
#define PQCP_ZEPHYR_ASSURANCE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Number of hexadecimal characters in a SHA-256 digest. */
#define PQCP_ASSURANCE_SHA256_HEX_CHARS 64U

/** Default nonce size used by the build-only device-evidence sample. */
#define PQCP_ASSURANCE_NONCE128_HEX_CHARS 32U

/**
 * @brief One hash-bound artifact inside a release evidence digest.
 *
 * The strings are caller-owned and must remain valid until the emit or
 * validation function returns. Artifact names are machine-readable release-pack
 * paths or stable artifact identifiers; hashes are lowercase or uppercase
 * SHA-256 hex strings.
 */
struct pqcp_assurance_artifact {
	/** Stable artifact name or release-pack relative path. */
	const char *name;
	/** SHA-256 digest of the artifact contents encoded as 64 hex chars. */
	const char *sha256;
};

/**
 * @brief Firmware-visible assurance digest manifest.
 *
 * This structure mirrors the generated release-pack digest header used by
 * samples/pqcp_assurance_status. Firmware can validate and emit this manifest
 * without knowing how the host generated the release evidence pack.
 */
struct pqcp_assurance_manifest {
	/** Release or firmware evidence version string. */
	const char *version;
	/** Canonical SHA-256 digest root for the assurance artifact set. */
	const char *digest_sha256;
	/** Host-generated digest schema version; zero is invalid. */
	uint32_t schema_version;
	/** Optional array of artifact hash records; NULL when count is zero. */
	const struct pqcp_assurance_artifact *artifacts;
	/** Number of entries in @ref artifacts. */
	size_t artifact_count;
};

/**
 * @brief Validate that a string is exactly one SHA-256 digest in hex form.
 *
 * @param value Candidate digest string.
 *
 * @return true when @p value is non-NULL, NUL-terminated after exactly
 *         PQCP_ASSURANCE_SHA256_HEX_CHARS characters, and every character is
 *         hexadecimal.
 */
bool pqcp_assurance_is_sha256_hex(const char *value);

/**
 * @brief Validate that a string is exactly one 128-bit nonce in hex form.
 *
 * @param value Candidate nonce string.
 *
 * @return true when @p value is non-NULL, NUL-terminated after exactly
 *         PQCP_ASSURANCE_NONCE128_HEX_CHARS characters, and every character is
 *         hexadecimal.
 */
bool pqcp_assurance_is_nonce128_hex(const char *value);

/**
 * @brief Validate a firmware assurance manifest before emitting it.
 *
 * @param manifest Manifest to validate.
 *
 * @retval 0 Manifest is internally consistent.
 * @retval -EINVAL Required pointer or scalar field is invalid.
 * @retval -EBADMSG A digest or artifact hash is malformed.
 */
int pqcp_assurance_manifest_validate(
	const struct pqcp_assurance_manifest *manifest);

/**
 * @brief Emit stable release assurance status and artifact hash markers.
 *
 * The output grammar intentionally matches the existing sample contract:
 *
 * `PQCP_ASSURANCE_STATUS version=<v> digest=<sha256> artifact_count=<n> schema=<n>`
 * `PQCP_ASSURANCE_ARTIFACT name=<name> sha256=<sha256>`
 *
 * @param manifest Validated manifest to emit.
 *
 * @retval 0 Markers emitted successfully.
 * @retval -EINVAL Required pointer or scalar field is invalid.
 * @retval -EBADMSG A digest or artifact hash is malformed.
 */
int pqcp_assurance_emit_status(
	const struct pqcp_assurance_manifest *manifest);

/**
 * @brief Emit a stable device-evidence marker bound to the manifest digest.
 *
 * The output grammar intentionally matches the existing sample contract:
 *
 * `PQCP_DEVICE_EVIDENCE nonce=<hex> digest=<sha256> artifact_count=<n> schema=<n> transcript_sha256=<sha256>`
 *
 * @param manifest Validated manifest whose digest is reported.
 * @param nonce_hex 128-bit challenge/nonce encoded as 32 hex characters.
 * @param transcript_sha256 SHA-256 digest of the captured device transcript.
 *
 * @retval 0 Marker emitted successfully.
 * @retval -EINVAL Required pointer or nonce field is invalid.
 * @retval -EBADMSG A digest or artifact hash is malformed.
 */
int pqcp_assurance_emit_device_evidence(
	const struct pqcp_assurance_manifest *manifest,
	const char *nonce_hex,
	const char *transcript_sha256);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_ASSURANCE_H_ */
