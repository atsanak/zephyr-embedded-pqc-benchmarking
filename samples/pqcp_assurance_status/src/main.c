/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Build-only assurance status sample.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/assurance.h>
#include <pqcp_zephyr/firmware_evidence.h>

#include <pqcp_assurance_digest_generated.h>

static struct pqcp_assurance_artifact
	pqcp_sample_artifacts[ARRAY_SIZE(pqcp_assurance_digest_artifact_names)];

static void pqcp_sample_populate_artifacts(void)
{
	for (size_t i = 0; i < PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT; ++i) {
		pqcp_sample_artifacts[i].name =
			pqcp_assurance_digest_artifact_names[i];
		pqcp_sample_artifacts[i].sha256 =
			pqcp_assurance_digest_artifact_sha256[i];
	}
}

int main(void)
{
	struct pqcp_firmware_evidence_result result;
	const struct pqcp_assurance_manifest manifest = {
		.version = PQCP_ASSURANCE_DIGEST_VERSION,
		.digest_sha256 = PQCP_ASSURANCE_DIGEST_ROOT_SHA256,
		.schema_version = PQCP_ASSURANCE_DIGEST_SCHEMA_VERSION,
		.artifacts = PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT > 0 ?
			pqcp_sample_artifacts : NULL,
		.artifact_count = PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT,
	};

	pqcp_sample_populate_artifacts();

	if (pqcp_firmware_evidence_run_default(
		&manifest,
		PQCP_ASSURANCE_DEVICE_EVIDENCE_NONCE,
		PQCP_ASSURANCE_DEVICE_EVIDENCE_TRANSCRIPT_SHA256,
		&result) != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}

	printk("PROJECT EXECUTION SUCCESSFUL\n");
	return 0;
}
