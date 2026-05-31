/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Provider contract reporting
 *
 * Stability: stable evidence API for the 1.0.x line. This API reports the
 * configured provider family and backend policy for release evidence; it does
 * not select implementations at runtime and does not change cryptographic
 * operation semantics.
 */

#ifndef PQCP_ZEPHYR_PROVIDER_H_
#define PQCP_ZEPHYR_PROVIDER_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Provider family reported for a native PQC algorithm family.
 */
enum pqcp_provider_family {
	PQCP_PROVIDER_FAMILY_DISABLED = 0, /**< Algorithm family is disabled. */
	PQCP_PROVIDER_FAMILY_PQCP_NATIVE,  /**< PQ Code Package native family. */
	PQCP_PROVIDER_FAMILY_BASELINE_C,   /**< Portable-C baseline from native package. */
	PQCP_PROVIDER_FAMILY_FORBIDDEN,    /**< Unsupported external native-family path. */
};

/**
 * @brief Firmware-visible provider contract snapshot.
 *
 * The fields are derived from Kconfig at build time and are intentionally
 * simple strings/booleans so release tooling can bind them into transcripts.
 */
struct pqcp_provider_contract {
	bool mlkem_enabled; /**< ML-KEM wrapper is compiled into this image. */
	bool mldsa_enabled; /**< ML-DSA wrapper is compiled into this image. */
	enum pqcp_provider_family mlkem_family; /**< ML-KEM provider family. */
	enum pqcp_provider_family mldsa_family; /**< ML-DSA provider family. */
	const char *mlkem_source; /**< Expected ML-KEM implementation source. */
	const char *mldsa_source; /**< Expected ML-DSA implementation source. */
	const char *backend_selector; /**< auto, force_c, force_native, or baseline_c. */
	bool external_native_family_allowed; /**< Must remain false for ML-KEM/ML-DSA. */
	bool experimental_non_native_inventory; /**< Non-native inventory gate state. */
};

/**
 * @brief Convert a provider family enum to a stable evidence token.
 *
 * @param family Provider family value.
 *
 * @return Static string token suitable for logs and evidence transcripts.
 */
const char *pqcp_provider_family_str(enum pqcp_provider_family family);

/**
 * @brief Return the build-time provider contract for the current firmware.
 *
 * @return Pointer to a static immutable provider contract.
 */
const struct pqcp_provider_contract *pqcp_provider_contract_get(void);

/**
 * @brief Validate a provider contract snapshot.
 *
 * This catches evidence-breaking configurations where ML-KEM/ML-DSA are
 * claimed as enabled but no native implementation source is reported, or where
 * an external provider is reported as allowed for the native families.
 *
 * @param contract Contract to validate.
 *
 * @retval 0 Contract is internally consistent.
 * @retval -EINVAL Required pointers or enum fields are invalid.
 * @retval -EBADMSG Native-family source or external-provider policy is invalid.
 */
int pqcp_provider_contract_validate(
	const struct pqcp_provider_contract *contract);

/**
 * @brief Emit a stable provider-contract transcript marker.
 *
 * The marker is additive and does not change any existing ACVP, benchmark, or
 * assurance status marker:
 *
 * `PQCP_PROVIDER_CONTRACT mlkem=<enabled|disabled> mlkem_family=<family> mlkem_source=<source> mldsa=<enabled|disabled> mldsa_family=<family> mldsa_source=<source> backend=<selector> external_native_allowed=<0|1> non_native_inventory=<0|1>`
 *
 * @retval 0 Marker emitted successfully.
 * @retval -EINVAL Required pointers or enum fields are invalid.
 * @retval -EBADMSG Native-family source or external-provider policy is invalid.
 */
int pqcp_provider_emit_contract(void);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_PROVIDER_H_ */
