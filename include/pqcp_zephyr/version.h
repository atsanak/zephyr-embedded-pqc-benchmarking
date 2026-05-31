/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Version Information
 *
 * Stability: stable production API for the 1.0.x line.
 */

#ifndef PQCP_ZEPHYR_VERSION_H_
#define PQCP_ZEPHYR_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Major version of the PQCP Zephyr module. */
#define PQCP_ZEPHYR_VERSION_MAJOR 1

/** @brief Minor version of the PQCP Zephyr module. */
#define PQCP_ZEPHYR_VERSION_MINOR 0

/** @brief Patch version of the PQCP Zephyr module. */
#define PQCP_ZEPHYR_VERSION_PATCH 0

/** @brief Packed semantic version for simple compile-time comparisons. */
#define PQCP_ZEPHYR_VERSION_HEX \
    ((PQCP_ZEPHYR_VERSION_MAJOR << 16) | \
     (PQCP_ZEPHYR_VERSION_MINOR << 8) | \
     PQCP_ZEPHYR_VERSION_PATCH)

/** @brief Human-readable semantic version string. */
#define PQCP_ZEPHYR_VERSION_STRING "1.0.0"

/*
 * Backward-compatible version aliases retained for existing tooling and
 * downstream consumers that already key off the shorter macro names.
 */
#define PQCP_VERSION_MAJOR PQCP_ZEPHYR_VERSION_MAJOR
#define PQCP_VERSION_MINOR PQCP_ZEPHYR_VERSION_MINOR
#define PQCP_VERSION_PATCH PQCP_ZEPHYR_VERSION_PATCH
#define PQCP_VERSION_HEX PQCP_ZEPHYR_VERSION_HEX
#define PQCP_VERSION_STRING "1.0.0"

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_VERSION_H_ */
