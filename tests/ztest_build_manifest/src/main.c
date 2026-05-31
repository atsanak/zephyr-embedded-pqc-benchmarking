/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware build manifest tests.
 */

#include <errno.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/version.h>

ZTEST(pqcp_build_manifest, test_current_manifest_is_valid)
{
	const struct pqcp_build_manifest *manifest =
		pqcp_build_manifest_get();

	zassert_not_null(manifest);
	zassert_not_null(manifest->pqcp_version);
	zassert_not_null(manifest->zephyr_version);
	zassert_not_null(manifest->board);
	zassert_not_null(manifest->rng_mode);
	zassert_equal(pqcp_build_manifest_validate(manifest), 0);
	zassert_equal(pqcp_build_manifest_emit(), 0);
}

ZTEST(pqcp_build_manifest, test_current_manifest_reports_expected_test_build)
{
	const struct pqcp_build_manifest *manifest =
		pqcp_build_manifest_get();

	zassert_mem_equal(manifest->pqcp_version, PQCP_VERSION_STRING,
			  sizeof(PQCP_VERSION_STRING));
	zassert_equal(manifest->profile_flags, 0U);
	zassert_equal(manifest->mlkem_level_mask, 0U);
	zassert_equal(manifest->mldsa_level_mask, 0U);
	zassert_true(manifest->provider_contract_enabled);
	zassert_mem_equal(manifest->rng_mode, "custom", sizeof("custom"));
}

ZTEST(pqcp_build_manifest, test_synthetic_enabled_level_masks_pass)
{
	const struct pqcp_build_manifest manifest = {
		.pqcp_version = "1.0.0",
		.zephyr_version = "4.4.0",
		.board = "qemu_x86_64",
		.profile_flags = PQCP_BUILD_PROFILE_NATIVE_LAB,
		.mlkem_level_mask = PQCP_BUILD_MLKEM_LEVEL_512 |
				    PQCP_BUILD_MLKEM_LEVEL_768 |
				    PQCP_BUILD_MLKEM_LEVEL_1024,
		.mldsa_level_mask = PQCP_BUILD_MLDSA_LEVEL_44 |
				    PQCP_BUILD_MLDSA_LEVEL_65 |
				    PQCP_BUILD_MLDSA_LEVEL_87,
		.rng_mode = "zephyr_entropy",
		.provider_contract_enabled = true,
	};

	zassert_equal(pqcp_build_manifest_validate(&manifest), 0);
}

ZTEST(pqcp_build_manifest, test_missing_strings_fail)
{
	struct pqcp_build_manifest manifest = {
		.pqcp_version = "1.0.0",
		.zephyr_version = "4.4.0",
		.board = "qemu_x86_64",
		.profile_flags = 0U,
		.mlkem_level_mask = 0U,
		.mldsa_level_mask = 0U,
		.rng_mode = "custom",
		.provider_contract_enabled = true,
	};

	zassert_equal(pqcp_build_manifest_validate(NULL), -EINVAL);

	manifest.pqcp_version = NULL;
	zassert_equal(pqcp_build_manifest_validate(&manifest), -EINVAL);

	manifest.pqcp_version = "";
	zassert_equal(pqcp_build_manifest_validate(&manifest), -EINVAL);

	manifest.pqcp_version = "1.0.0";
	manifest.board = NULL;
	zassert_equal(pqcp_build_manifest_validate(&manifest), -EINVAL);

	manifest.board = "qemu_x86_64";
	manifest.rng_mode = "";
	zassert_equal(pqcp_build_manifest_validate(&manifest), -EINVAL);
}

ZTEST(pqcp_build_manifest, test_unknown_bits_fail)
{
	struct pqcp_build_manifest manifest = {
		.pqcp_version = "1.0.0",
		.zephyr_version = "4.4.0",
		.board = "qemu_x86_64",
		.profile_flags = 0U,
		.mlkem_level_mask = 0U,
		.mldsa_level_mask = 0U,
		.rng_mode = "custom",
		.provider_contract_enabled = true,
	};

	manifest.profile_flags = 1U << 31;
	zassert_equal(pqcp_build_manifest_validate(&manifest), -EBADMSG);

	manifest.profile_flags = 0U;
	manifest.mlkem_level_mask = 1U << 31;
	zassert_equal(pqcp_build_manifest_validate(&manifest), -EBADMSG);

	manifest.mlkem_level_mask = 0U;
	manifest.mldsa_level_mask = 1U << 31;
	zassert_equal(pqcp_build_manifest_validate(&manifest), -EBADMSG);
}

ZTEST_SUITE(pqcp_build_manifest, NULL, NULL, NULL, NULL, NULL);
