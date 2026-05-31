/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware assurance status helpers.
 */

#include <errno.h>
#include <stddef.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/assurance.h>

static bool pqcp_assurance_is_hex_char(char c)
{
	return ((c >= '0') && (c <= '9')) ||
	       ((c >= 'a') && (c <= 'f')) ||
	       ((c >= 'A') && (c <= 'F'));
}

static bool pqcp_assurance_is_hex_string_len(const char *value, size_t len)
{
	if (value == NULL) {
		return false;
	}

	for (size_t i = 0; i < len; ++i) {
		if (!pqcp_assurance_is_hex_char(value[i])) {
			return false;
		}
	}

	return value[len] == '\0';
}

bool pqcp_assurance_is_sha256_hex(const char *value)
{
	return pqcp_assurance_is_hex_string_len(
		value, PQCP_ASSURANCE_SHA256_HEX_CHARS);
}

bool pqcp_assurance_is_nonce128_hex(const char *value)
{
	return pqcp_assurance_is_hex_string_len(
		value, PQCP_ASSURANCE_NONCE128_HEX_CHARS);
}

int pqcp_assurance_manifest_validate(
	const struct pqcp_assurance_manifest *manifest)
{
	if ((manifest == NULL) || (manifest->version == NULL) ||
	    (manifest->version[0] == '\0') || (manifest->schema_version == 0U)) {
		return -EINVAL;
	}

	if (!pqcp_assurance_is_sha256_hex(manifest->digest_sha256)) {
		return -EBADMSG;
	}

	if ((manifest->artifact_count > 0U) && (manifest->artifacts == NULL)) {
		return -EINVAL;
	}

	for (size_t i = 0; i < manifest->artifact_count; ++i) {
		const struct pqcp_assurance_artifact *artifact =
			&manifest->artifacts[i];

		if ((artifact->name == NULL) || (artifact->name[0] == '\0') ||
		    (artifact->sha256 == NULL)) {
			return -EINVAL;
		}
		if (!pqcp_assurance_is_sha256_hex(artifact->sha256)) {
			return -EBADMSG;
		}
	}

	return 0;
}

int pqcp_assurance_emit_status(
	const struct pqcp_assurance_manifest *manifest)
{
	int ret = pqcp_assurance_manifest_validate(manifest);

	if (ret != 0) {
		return ret;
	}

	printk("PQCP_ASSURANCE_STATUS version=%s digest=%s artifact_count=%u schema=%u\n",
	       manifest->version,
	       manifest->digest_sha256,
	       (unsigned int)manifest->artifact_count,
	       manifest->schema_version);

	for (size_t i = 0; i < manifest->artifact_count; ++i) {
		printk("PQCP_ASSURANCE_ARTIFACT name=%s sha256=%s\n",
		       manifest->artifacts[i].name,
		       manifest->artifacts[i].sha256);
	}

	return 0;
}

int pqcp_assurance_emit_device_evidence(
	const struct pqcp_assurance_manifest *manifest,
	const char *nonce_hex,
	const char *transcript_sha256)
{
	int ret = pqcp_assurance_manifest_validate(manifest);

	if (ret != 0) {
		return ret;
	}
	if (!pqcp_assurance_is_nonce128_hex(nonce_hex)) {
		return -EINVAL;
	}
	if (!pqcp_assurance_is_sha256_hex(transcript_sha256)) {
		return -EBADMSG;
	}

	printk("PQCP_DEVICE_EVIDENCE nonce=%s digest=%s artifact_count=%u schema=%u transcript_sha256=%s\n",
	       nonce_hex,
	       manifest->digest_sha256,
	       (unsigned int)manifest->artifact_count,
	       manifest->schema_version,
	       transcript_sha256);

	return 0;
}
