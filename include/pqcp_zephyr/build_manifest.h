/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Firmware build manifest reporting
 *
 * Stability: stable evidence API for the 1.0.x line. This API reports
 * build-time evidence metadata from firmware; it does not change runtime
 * provider selection, public crypto APIs, ACVP wire format, or benchmark row
 * ordering.
 */

#ifndef PQCP_ZEPHYR_BUILD_MANIFEST_H_
#define PQCP_ZEPHYR_BUILD_MANIFEST_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Firmware profile bit for CONFIG_PQCP_PROFILE_MCU_MINIMAL. */
#define PQCP_BUILD_PROFILE_MCU_MINIMAL  (1U << 0)
/** Firmware profile bit for CONFIG_PQCP_PROFILE_GATEWAY. */
#define PQCP_BUILD_PROFILE_GATEWAY      (1U << 1)
/** Firmware profile bit for CONFIG_PQCP_PROFILE_NATIVE_LAB. */
#define PQCP_BUILD_PROFILE_NATIVE_LAB   (1U << 2)

/** ML-KEM level bit for CONFIG_PQCP_MLKEM_LEVEL_512. */
#define PQCP_BUILD_MLKEM_LEVEL_512      (1U << 0)
/** ML-KEM level bit for CONFIG_PQCP_MLKEM_LEVEL_768. */
#define PQCP_BUILD_MLKEM_LEVEL_768      (1U << 1)
/** ML-KEM level bit for CONFIG_PQCP_MLKEM_LEVEL_1024. */
#define PQCP_BUILD_MLKEM_LEVEL_1024     (1U << 2)

/** ML-DSA level bit for CONFIG_PQCP_MLDSA_LEVEL_44. */
#define PQCP_BUILD_MLDSA_LEVEL_44       (1U << 0)
/** ML-DSA level bit for CONFIG_PQCP_MLDSA_LEVEL_65. */
#define PQCP_BUILD_MLDSA_LEVEL_65       (1U << 1)
/** ML-DSA level bit for CONFIG_PQCP_MLDSA_LEVEL_87. */
#define PQCP_BUILD_MLDSA_LEVEL_87       (1U << 2)

/**
 * @brief Firmware-visible build manifest.
 *
 * The manifest captures the local build facts that matter for replayable
 * evidence: module version, Zephyr baseline, board, enabled algorithm levels,
 * active profile bits, RNG mode, and whether provider-contract reporting is
 * compiled into the image.
 */
struct pqcp_build_manifest {
	/** PQCP module semantic version string. */
	const char *pqcp_version;
	/** Zephyr kernel version string reported by the build. */
	const char *zephyr_version;
	/** Zephyr board name reported by CONFIG_BOARD. */
	const char *board;
	/** Bitmask of enabled PQCP_BUILD_PROFILE_* profile flags. */
	uint32_t profile_flags;
	/** Bitmask of enabled PQCP_BUILD_MLKEM_LEVEL_* flags. */
	uint32_t mlkem_level_mask;
	/** Bitmask of enabled PQCP_BUILD_MLDSA_LEVEL_* flags. */
	uint32_t mldsa_level_mask;
	/** Stable token for the configured RNG mode. */
	const char *rng_mode;
	/** True when CONFIG_PQCP_PROVIDER_CONTRACT is compiled in. */
	bool provider_contract_enabled;
};

/**
 * @brief Return the build-time manifest for the current firmware image.
 *
 * @return Pointer to a static immutable manifest.
 */
const struct pqcp_build_manifest *pqcp_build_manifest_get(void);

/**
 * @brief Validate a firmware build manifest.
 *
 * @param manifest Manifest to validate.
 *
 * @retval 0 Manifest is internally consistent.
 * @retval -EINVAL Required string fields are missing or empty.
 * @retval -EBADMSG Unknown algorithm-level or profile bits are set.
 */
int pqcp_build_manifest_validate(
	const struct pqcp_build_manifest *manifest);

/**
 * @brief Emit a stable firmware build-manifest transcript marker.
 *
 * The marker is additive and uses key/value fields so release tooling can bind
 * firmware output to Kconfig-derived metadata:
 *
 * `PQCP_BUILD_MANIFEST pqcp=<version> zephyr=<version> board=<board> profiles=<hex> mlkem_levels=<hex> mldsa_levels=<hex> rng=<mode> provider_contract=<0|1>`
 *
 * @retval 0 Marker emitted successfully.
 * @retval -EINVAL Required string fields are missing or empty.
 * @retval -EBADMSG Unknown algorithm-level or profile bits are set.
 */
int pqcp_build_manifest_emit(void);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_BUILD_MANIFEST_H_ */
