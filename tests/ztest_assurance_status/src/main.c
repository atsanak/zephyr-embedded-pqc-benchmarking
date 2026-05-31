/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware assurance status tests.
 */

#include <errno.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/assurance.h>

#define GOOD_SHA \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define GOOD_SHA_UPPER \
	"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
#define BAD_SHA_SHORT \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
#define BAD_SHA_NONHEX \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"
#define GOOD_NONCE "0123456789abcdef0123456789abcdef"
#define BAD_NONCE_SHORT "0123456789abcdef0123456789abcde"

static const struct pqcp_assurance_artifact good_artifacts[] = {
	{
		.name = "assurance_ledger.json",
		.sha256 = GOOD_SHA,
	},
	{
		.name = "pqc_cbom.cdx.json",
		.sha256 = GOOD_SHA_UPPER,
	},
};

static const struct pqcp_assurance_manifest good_manifest = {
	.version = "1.0.0",
	.digest_sha256 = GOOD_SHA,
	.schema_version = 6U,
	.artifacts = good_artifacts,
	.artifact_count = ARRAY_SIZE(good_artifacts),
};

ZTEST(pqcp_assurance_status, test_sha256_hex_validation)
{
	zassert_true(pqcp_assurance_is_sha256_hex(GOOD_SHA));
	zassert_true(pqcp_assurance_is_sha256_hex(GOOD_SHA_UPPER));
	zassert_false(pqcp_assurance_is_sha256_hex(NULL));
	zassert_false(pqcp_assurance_is_sha256_hex(BAD_SHA_SHORT));
	zassert_false(pqcp_assurance_is_sha256_hex(BAD_SHA_NONHEX));
}

ZTEST(pqcp_assurance_status, test_nonce_hex_validation)
{
	zassert_true(pqcp_assurance_is_nonce128_hex(GOOD_NONCE));
	zassert_false(pqcp_assurance_is_nonce128_hex(NULL));
	zassert_false(pqcp_assurance_is_nonce128_hex(BAD_NONCE_SHORT));
	zassert_false(pqcp_assurance_is_nonce128_hex("not-a-hex-nonce-value-000000000"));
}

ZTEST(pqcp_assurance_status, test_manifest_validate_accepts_good_manifest)
{
	zassert_equal(pqcp_assurance_manifest_validate(&good_manifest), 0);
}

ZTEST(pqcp_assurance_status, test_manifest_validate_accepts_zero_artifacts)
{
	const struct pqcp_assurance_manifest manifest = {
		.version = "1.0.0",
		.digest_sha256 = GOOD_SHA,
		.schema_version = 1U,
		.artifacts = NULL,
		.artifact_count = 0U,
	};

	zassert_equal(pqcp_assurance_manifest_validate(&manifest), 0);
}

ZTEST(pqcp_assurance_status, test_manifest_validate_rejects_missing_fields)
{
	struct pqcp_assurance_manifest manifest = good_manifest;

	zassert_equal(pqcp_assurance_manifest_validate(NULL), -EINVAL);

	manifest = good_manifest;
	manifest.version = NULL;
	zassert_equal(pqcp_assurance_manifest_validate(&manifest), -EINVAL);

	manifest = good_manifest;
	manifest.version = "";
	zassert_equal(pqcp_assurance_manifest_validate(&manifest), -EINVAL);

	manifest = good_manifest;
	manifest.schema_version = 0U;
	zassert_equal(pqcp_assurance_manifest_validate(&manifest), -EINVAL);

	manifest = good_manifest;
	manifest.artifacts = NULL;
	zassert_equal(pqcp_assurance_manifest_validate(&manifest), -EINVAL);
}

ZTEST(pqcp_assurance_status, test_manifest_validate_rejects_bad_hashes)
{
	struct pqcp_assurance_artifact artifacts[] = {
		{
			.name = "assurance_ledger.json",
			.sha256 = GOOD_SHA,
		},
	};
	struct pqcp_assurance_manifest manifest = good_manifest;

	manifest.digest_sha256 = BAD_SHA_SHORT;
	zassert_equal(pqcp_assurance_manifest_validate(&manifest), -EBADMSG);

	manifest = good_manifest;
	artifacts[0].sha256 = BAD_SHA_NONHEX;
	manifest.artifacts = artifacts;
	manifest.artifact_count = ARRAY_SIZE(artifacts);
	zassert_equal(pqcp_assurance_manifest_validate(&manifest), -EBADMSG);
}

ZTEST(pqcp_assurance_status, test_manifest_validate_rejects_bad_artifacts)
{
	struct pqcp_assurance_artifact artifacts[] = {
		{
			.name = "",
			.sha256 = GOOD_SHA,
		},
	};
	struct pqcp_assurance_manifest manifest = good_manifest;

	manifest.artifacts = artifacts;
	manifest.artifact_count = ARRAY_SIZE(artifacts);
	zassert_equal(pqcp_assurance_manifest_validate(&manifest), -EINVAL);

	artifacts[0].name = NULL;
	zassert_equal(pqcp_assurance_manifest_validate(&manifest), -EINVAL);

	artifacts[0].name = "assurance_ledger.json";
	artifacts[0].sha256 = NULL;
	zassert_equal(pqcp_assurance_manifest_validate(&manifest), -EINVAL);
}

ZTEST(pqcp_assurance_status, test_emit_helpers_validate_inputs)
{
	zassert_equal(pqcp_assurance_emit_status(&good_manifest), 0);
	zassert_equal(pqcp_assurance_emit_device_evidence(
			      &good_manifest, GOOD_NONCE, GOOD_SHA),
		      0);
	zassert_equal(pqcp_assurance_emit_device_evidence(
			      &good_manifest, BAD_NONCE_SHORT, GOOD_SHA),
		      -EINVAL);
	zassert_equal(pqcp_assurance_emit_device_evidence(
			      &good_manifest, GOOD_NONCE, BAD_SHA_SHORT),
		      -EBADMSG);
}

ZTEST_SUITE(pqcp_assurance_status, NULL, NULL, NULL, NULL, NULL);
