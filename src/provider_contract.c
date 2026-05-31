/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP provider contract reporting.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/provider.h>

#define PQCP_PROVIDER_SOURCE_DISABLED "disabled"
#define PQCP_PROVIDER_SOURCE_MLKEM_NATIVE "mlkem-native"
#define PQCP_PROVIDER_SOURCE_MLDSA_NATIVE "mldsa-native"

#if defined(CONFIG_PQCP_IMPLEMENTATION_BASELINE)
#define PQCP_PROVIDER_NATIVE_FAMILY PQCP_PROVIDER_FAMILY_BASELINE_C
#define PQCP_PROVIDER_BACKEND_SELECTOR "baseline_c"
#elif defined(CONFIG_PQCP_IMPLEMENTATION_PQCP)
#define PQCP_PROVIDER_NATIVE_FAMILY PQCP_PROVIDER_FAMILY_PQCP_NATIVE
#if defined(CONFIG_PQCP_BACKEND_FORCE_C)
#define PQCP_PROVIDER_BACKEND_SELECTOR "force_c"
#elif defined(CONFIG_PQCP_BACKEND_FORCE_NATIVE)
#define PQCP_PROVIDER_BACKEND_SELECTOR "force_native"
#else
#define PQCP_PROVIDER_BACKEND_SELECTOR "auto"
#endif
#else
#define PQCP_PROVIDER_NATIVE_FAMILY PQCP_PROVIDER_FAMILY_FORBIDDEN
#define PQCP_PROVIDER_BACKEND_SELECTOR "forbidden"
#endif

#if defined(CONFIG_PQCP_MLKEM)
#define PQCP_PROVIDER_MLKEM_ENABLED true
#define PQCP_PROVIDER_MLKEM_FAMILY PQCP_PROVIDER_NATIVE_FAMILY
#define PQCP_PROVIDER_MLKEM_SOURCE PQCP_PROVIDER_SOURCE_MLKEM_NATIVE
#else
#define PQCP_PROVIDER_MLKEM_ENABLED false
#define PQCP_PROVIDER_MLKEM_FAMILY PQCP_PROVIDER_FAMILY_DISABLED
#define PQCP_PROVIDER_MLKEM_SOURCE PQCP_PROVIDER_SOURCE_DISABLED
#endif

#if defined(CONFIG_PQCP_MLDSA)
#define PQCP_PROVIDER_MLDSA_ENABLED true
#define PQCP_PROVIDER_MLDSA_FAMILY PQCP_PROVIDER_NATIVE_FAMILY
#define PQCP_PROVIDER_MLDSA_SOURCE PQCP_PROVIDER_SOURCE_MLDSA_NATIVE
#else
#define PQCP_PROVIDER_MLDSA_ENABLED false
#define PQCP_PROVIDER_MLDSA_FAMILY PQCP_PROVIDER_FAMILY_DISABLED
#define PQCP_PROVIDER_MLDSA_SOURCE PQCP_PROVIDER_SOURCE_DISABLED
#endif

static const struct pqcp_provider_contract pqcp_provider_contract = {
	.mlkem_enabled = PQCP_PROVIDER_MLKEM_ENABLED,
	.mldsa_enabled = PQCP_PROVIDER_MLDSA_ENABLED,
	.mlkem_family = PQCP_PROVIDER_MLKEM_FAMILY,
	.mldsa_family = PQCP_PROVIDER_MLDSA_FAMILY,
	.mlkem_source = PQCP_PROVIDER_MLKEM_SOURCE,
	.mldsa_source = PQCP_PROVIDER_MLDSA_SOURCE,
	.backend_selector = PQCP_PROVIDER_BACKEND_SELECTOR,
	.external_native_family_allowed = false,
	.experimental_non_native_inventory =
		IS_ENABLED(CONFIG_PQCP_LIBOQS_EXPERIMENTAL),
};

const char *pqcp_provider_family_str(enum pqcp_provider_family family)
{
	switch (family) {
	case PQCP_PROVIDER_FAMILY_DISABLED:
		return "disabled";
	case PQCP_PROVIDER_FAMILY_PQCP_NATIVE:
		return "pqcp_native";
	case PQCP_PROVIDER_FAMILY_BASELINE_C:
		return "baseline_c";
	case PQCP_PROVIDER_FAMILY_FORBIDDEN:
		return "forbidden";
	default:
		return "unknown";
	}
}

const struct pqcp_provider_contract *pqcp_provider_contract_get(void)
{
	return &pqcp_provider_contract;
}

static bool pqcp_provider_family_valid(enum pqcp_provider_family family)
{
	return family == PQCP_PROVIDER_FAMILY_DISABLED ||
	       family == PQCP_PROVIDER_FAMILY_PQCP_NATIVE ||
	       family == PQCP_PROVIDER_FAMILY_BASELINE_C ||
	       family == PQCP_PROVIDER_FAMILY_FORBIDDEN;
}

static int pqcp_provider_validate_native_source(bool enabled,
					       enum pqcp_provider_family family,
					       const char *source,
					       const char *expected_source)
{
	if (!pqcp_provider_family_valid(family) || (source == NULL)) {
		return -EINVAL;
	}

	if (!enabled) {
		return strcmp(source, PQCP_PROVIDER_SOURCE_DISABLED) == 0 ?
			0 : -EBADMSG;
	}
	if (family == PQCP_PROVIDER_FAMILY_FORBIDDEN ||
	    family == PQCP_PROVIDER_FAMILY_DISABLED) {
		return -EBADMSG;
	}

	return strcmp(source, expected_source) == 0 ? 0 : -EBADMSG;
}

int pqcp_provider_contract_validate(
	const struct pqcp_provider_contract *contract)
{
	int ret;

	if ((contract == NULL) || (contract->backend_selector == NULL)) {
		return -EINVAL;
	}
	if (contract->external_native_family_allowed) {
		return -EBADMSG;
	}

	ret = pqcp_provider_validate_native_source(
		contract->mlkem_enabled,
		contract->mlkem_family,
		contract->mlkem_source,
		PQCP_PROVIDER_SOURCE_MLKEM_NATIVE);
	if (ret != 0) {
		return ret;
	}

	ret = pqcp_provider_validate_native_source(
		contract->mldsa_enabled,
		contract->mldsa_family,
		contract->mldsa_source,
		PQCP_PROVIDER_SOURCE_MLDSA_NATIVE);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

int pqcp_provider_emit_contract(void)
{
	const struct pqcp_provider_contract *contract = pqcp_provider_contract_get();
	int ret = pqcp_provider_contract_validate(contract);

	if (ret != 0) {
		return ret;
	}

	printk("PQCP_PROVIDER_CONTRACT mlkem=%s mlkem_family=%s mlkem_source=%s mldsa=%s mldsa_family=%s mldsa_source=%s backend=%s external_native_allowed=%u non_native_inventory=%u\n",
	       contract->mlkem_enabled ? "enabled" : "disabled",
	       pqcp_provider_family_str(contract->mlkem_family),
	       contract->mlkem_source,
	       contract->mldsa_enabled ? "enabled" : "disabled",
	       pqcp_provider_family_str(contract->mldsa_family),
	       contract->mldsa_source,
	       contract->backend_selector,
	       contract->external_native_family_allowed ? 1U : 0U,
	       contract->experimental_non_native_inventory ? 1U : 0U);

	return 0;
}
