/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP firmware build manifest reporting.
 */

#include <errno.h>

#include <zephyr/sys/printk.h>
#include <zephyr/version.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/version.h>

#ifndef KERNEL_VERSION_STRING
#define KERNEL_VERSION_STRING "unknown"
#endif

#ifndef CONFIG_BOARD
#define CONFIG_BOARD "unknown"
#endif

#if defined(CONFIG_PQCP_PROFILE_MCU_MINIMAL)
#define PQCP_BUILD_PROFILE_MCU_MINIMAL_SELECTED PQCP_BUILD_PROFILE_MCU_MINIMAL
#else
#define PQCP_BUILD_PROFILE_MCU_MINIMAL_SELECTED 0U
#endif

#if defined(CONFIG_PQCP_PROFILE_GATEWAY)
#define PQCP_BUILD_PROFILE_GATEWAY_SELECTED PQCP_BUILD_PROFILE_GATEWAY
#else
#define PQCP_BUILD_PROFILE_GATEWAY_SELECTED 0U
#endif

#if defined(CONFIG_PQCP_PROFILE_NATIVE_LAB)
#define PQCP_BUILD_PROFILE_NATIVE_LAB_SELECTED PQCP_BUILD_PROFILE_NATIVE_LAB
#else
#define PQCP_BUILD_PROFILE_NATIVE_LAB_SELECTED 0U
#endif

#define PQCP_BUILD_PROFILE_MASK \
	(PQCP_BUILD_PROFILE_MCU_MINIMAL_SELECTED | \
	 PQCP_BUILD_PROFILE_GATEWAY_SELECTED | \
	 PQCP_BUILD_PROFILE_NATIVE_LAB_SELECTED)

#if defined(CONFIG_PQCP_MLKEM_LEVEL_512)
#define PQCP_BUILD_MLKEM_LEVEL_512_SELECTED PQCP_BUILD_MLKEM_LEVEL_512
#else
#define PQCP_BUILD_MLKEM_LEVEL_512_SELECTED 0U
#endif

#if defined(CONFIG_PQCP_MLKEM_LEVEL_768)
#define PQCP_BUILD_MLKEM_LEVEL_768_SELECTED PQCP_BUILD_MLKEM_LEVEL_768
#else
#define PQCP_BUILD_MLKEM_LEVEL_768_SELECTED 0U
#endif

#if defined(CONFIG_PQCP_MLKEM_LEVEL_1024)
#define PQCP_BUILD_MLKEM_LEVEL_1024_SELECTED PQCP_BUILD_MLKEM_LEVEL_1024
#else
#define PQCP_BUILD_MLKEM_LEVEL_1024_SELECTED 0U
#endif

#define PQCP_BUILD_MLKEM_LEVEL_MASK \
	(PQCP_BUILD_MLKEM_LEVEL_512_SELECTED | \
	 PQCP_BUILD_MLKEM_LEVEL_768_SELECTED | \
	 PQCP_BUILD_MLKEM_LEVEL_1024_SELECTED)

#if defined(CONFIG_PQCP_MLDSA_LEVEL_44)
#define PQCP_BUILD_MLDSA_LEVEL_44_SELECTED PQCP_BUILD_MLDSA_LEVEL_44
#else
#define PQCP_BUILD_MLDSA_LEVEL_44_SELECTED 0U
#endif

#if defined(CONFIG_PQCP_MLDSA_LEVEL_65)
#define PQCP_BUILD_MLDSA_LEVEL_65_SELECTED PQCP_BUILD_MLDSA_LEVEL_65
#else
#define PQCP_BUILD_MLDSA_LEVEL_65_SELECTED 0U
#endif

#if defined(CONFIG_PQCP_MLDSA_LEVEL_87)
#define PQCP_BUILD_MLDSA_LEVEL_87_SELECTED PQCP_BUILD_MLDSA_LEVEL_87
#else
#define PQCP_BUILD_MLDSA_LEVEL_87_SELECTED 0U
#endif

#define PQCP_BUILD_MLDSA_LEVEL_MASK \
	(PQCP_BUILD_MLDSA_LEVEL_44_SELECTED | \
	 PQCP_BUILD_MLDSA_LEVEL_65_SELECTED | \
	 PQCP_BUILD_MLDSA_LEVEL_87_SELECTED)

#if defined(CONFIG_PQCP_RNG_DETERMINISTIC_TEST)
#define PQCP_BUILD_RNG_MODE "deterministic_test"
#elif defined(CONFIG_PQCP_RNG_ZEPHYR_ENTROPY)
#define PQCP_BUILD_RNG_MODE "zephyr_entropy"
#elif defined(CONFIG_PQCP_RNG_PSA)
#define PQCP_BUILD_RNG_MODE "psa"
#elif defined(CONFIG_PQCP_RNG_CUSTOM)
#define PQCP_BUILD_RNG_MODE "custom"
#else
#define PQCP_BUILD_RNG_MODE "unknown"
#endif

static const struct pqcp_build_manifest pqcp_build_manifest = {
	.pqcp_version = PQCP_VERSION_STRING,
	.zephyr_version = KERNEL_VERSION_STRING,
	.board = CONFIG_BOARD,
	.profile_flags = PQCP_BUILD_PROFILE_MASK,
	.mlkem_level_mask = PQCP_BUILD_MLKEM_LEVEL_MASK,
	.mldsa_level_mask = PQCP_BUILD_MLDSA_LEVEL_MASK,
	.rng_mode = PQCP_BUILD_RNG_MODE,
	.provider_contract_enabled =
#if defined(CONFIG_PQCP_PROVIDER_CONTRACT)
		true,
#else
		false,
#endif
};

const struct pqcp_build_manifest *pqcp_build_manifest_get(void)
{
	return &pqcp_build_manifest;
}

static bool pqcp_build_manifest_has_text(const char *value)
{
	return value != NULL && value[0] != '\0';
}

int pqcp_build_manifest_validate(
	const struct pqcp_build_manifest *manifest)
{
	const uint32_t allowed_profiles = PQCP_BUILD_PROFILE_MCU_MINIMAL |
					  PQCP_BUILD_PROFILE_GATEWAY |
					  PQCP_BUILD_PROFILE_NATIVE_LAB;
	const uint32_t allowed_mlkem = PQCP_BUILD_MLKEM_LEVEL_512 |
				       PQCP_BUILD_MLKEM_LEVEL_768 |
				       PQCP_BUILD_MLKEM_LEVEL_1024;
	const uint32_t allowed_mldsa = PQCP_BUILD_MLDSA_LEVEL_44 |
				       PQCP_BUILD_MLDSA_LEVEL_65 |
				       PQCP_BUILD_MLDSA_LEVEL_87;

	if (manifest == NULL ||
	    !pqcp_build_manifest_has_text(manifest->pqcp_version) ||
	    !pqcp_build_manifest_has_text(manifest->zephyr_version) ||
	    !pqcp_build_manifest_has_text(manifest->board) ||
	    !pqcp_build_manifest_has_text(manifest->rng_mode)) {
		return -EINVAL;
	}
	if ((manifest->profile_flags & ~allowed_profiles) != 0U ||
	    (manifest->mlkem_level_mask & ~allowed_mlkem) != 0U ||
	    (manifest->mldsa_level_mask & ~allowed_mldsa) != 0U) {
		return -EBADMSG;
	}

	return 0;
}

int pqcp_build_manifest_emit(void)
{
	const struct pqcp_build_manifest *manifest = pqcp_build_manifest_get();
	int ret = pqcp_build_manifest_validate(manifest);

	if (ret != 0) {
		return ret;
	}

	printk("PQCP_BUILD_MANIFEST pqcp=%s zephyr=%s board=%s profiles=0x%08x mlkem_levels=0x%08x mldsa_levels=0x%08x rng=%s provider_contract=%u\n",
	       manifest->pqcp_version,
	       manifest->zephyr_version,
	       manifest->board,
	       manifest->profile_flags,
	       manifest->mlkem_level_mask,
	       manifest->mldsa_level_mask,
	       manifest->rng_mode,
	       manifest->provider_contract_enabled ? 1U : 0U);

	return 0;
}
