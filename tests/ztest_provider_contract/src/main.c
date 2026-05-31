/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP provider contract tests.
 */

#include <errno.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/provider.h>

ZTEST(pqcp_provider_contract, test_current_disabled_contract_is_valid)
{
	const struct pqcp_provider_contract *contract =
		pqcp_provider_contract_get();

	zassert_not_null(contract);
	zassert_false(contract->mlkem_enabled);
	zassert_false(contract->mldsa_enabled);
	zassert_equal(contract->mlkem_family, PQCP_PROVIDER_FAMILY_DISABLED);
	zassert_equal(contract->mldsa_family, PQCP_PROVIDER_FAMILY_DISABLED);
	zassert_equal(pqcp_provider_contract_validate(contract), 0);
	zassert_equal(pqcp_provider_emit_contract(), 0);
}

ZTEST(pqcp_provider_contract, test_family_tokens_are_stable)
{
	zassert_mem_equal(pqcp_provider_family_str(PQCP_PROVIDER_FAMILY_DISABLED),
			  "disabled", sizeof("disabled"));
	zassert_mem_equal(pqcp_provider_family_str(PQCP_PROVIDER_FAMILY_PQCP_NATIVE),
			  "pqcp_native", sizeof("pqcp_native"));
	zassert_mem_equal(pqcp_provider_family_str(PQCP_PROVIDER_FAMILY_BASELINE_C),
			  "baseline_c", sizeof("baseline_c"));
	zassert_mem_equal(pqcp_provider_family_str(PQCP_PROVIDER_FAMILY_FORBIDDEN),
			  "forbidden", sizeof("forbidden"));
	zassert_mem_equal(pqcp_provider_family_str((enum pqcp_provider_family)99),
			  "unknown", sizeof("unknown"));
}

ZTEST(pqcp_provider_contract, test_enabled_native_contract_passes)
{
	const struct pqcp_provider_contract contract = {
		.mlkem_enabled = true,
		.mldsa_enabled = true,
		.mlkem_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
		.mldsa_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
		.mlkem_source = "mlkem-native",
		.mldsa_source = "mldsa-native",
		.backend_selector = "auto",
		.external_native_family_allowed = false,
		.experimental_non_native_inventory = false,
	};

	zassert_equal(pqcp_provider_contract_validate(&contract), 0);
}

ZTEST(pqcp_provider_contract, test_baseline_still_reports_native_sources)
{
	const struct pqcp_provider_contract contract = {
		.mlkem_enabled = true,
		.mldsa_enabled = true,
		.mlkem_family = PQCP_PROVIDER_FAMILY_BASELINE_C,
		.mldsa_family = PQCP_PROVIDER_FAMILY_BASELINE_C,
		.mlkem_source = "mlkem-native",
		.mldsa_source = "mldsa-native",
		.backend_selector = "baseline_c",
		.external_native_family_allowed = false,
		.experimental_non_native_inventory = false,
	};

	zassert_equal(pqcp_provider_contract_validate(&contract), 0);
}

ZTEST(pqcp_provider_contract, test_external_native_family_policy_fails)
{
	struct pqcp_provider_contract contract = {
		.mlkem_enabled = true,
		.mldsa_enabled = true,
		.mlkem_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
		.mldsa_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
		.mlkem_source = "mlkem-native",
		.mldsa_source = "mldsa-native",
		.backend_selector = "auto",
		.external_native_family_allowed = true,
		.experimental_non_native_inventory = false,
	};

	zassert_equal(pqcp_provider_contract_validate(&contract), -EBADMSG);
}

ZTEST(pqcp_provider_contract, test_wrong_native_source_fails)
{
	struct pqcp_provider_contract contract = {
		.mlkem_enabled = true,
		.mldsa_enabled = true,
		.mlkem_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
		.mldsa_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
		.mlkem_source = "not-native",
		.mldsa_source = "mldsa-native",
		.backend_selector = "auto",
		.external_native_family_allowed = false,
		.experimental_non_native_inventory = false,
	};

	zassert_equal(pqcp_provider_contract_validate(&contract), -EBADMSG);

	contract.mlkem_source = "mlkem-native";
	contract.mldsa_source = "not-native";
	zassert_equal(pqcp_provider_contract_validate(&contract), -EBADMSG);
}

ZTEST(pqcp_provider_contract, test_disabled_family_must_report_disabled_source)
{
	struct pqcp_provider_contract contract = {
		.mlkem_enabled = false,
		.mldsa_enabled = false,
		.mlkem_family = PQCP_PROVIDER_FAMILY_DISABLED,
		.mldsa_family = PQCP_PROVIDER_FAMILY_DISABLED,
		.mlkem_source = "mlkem-native",
		.mldsa_source = "disabled",
		.backend_selector = "auto",
		.external_native_family_allowed = false,
		.experimental_non_native_inventory = false,
	};

	zassert_equal(pqcp_provider_contract_validate(&contract), -EBADMSG);
}

ZTEST(pqcp_provider_contract, test_missing_fields_fail)
{
	struct pqcp_provider_contract contract = {
		.mlkem_enabled = true,
		.mldsa_enabled = true,
		.mlkem_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
		.mldsa_family = PQCP_PROVIDER_FAMILY_PQCP_NATIVE,
		.mlkem_source = "mlkem-native",
		.mldsa_source = "mldsa-native",
		.backend_selector = NULL,
		.external_native_family_allowed = false,
		.experimental_non_native_inventory = false,
	};

	zassert_equal(pqcp_provider_contract_validate(NULL), -EINVAL);
	zassert_equal(pqcp_provider_contract_validate(&contract), -EINVAL);

	contract.backend_selector = "auto";
	contract.mlkem_source = NULL;
	zassert_equal(pqcp_provider_contract_validate(&contract), -EINVAL);
}

ZTEST(pqcp_provider_contract, test_forbidden_family_fails_when_enabled)
{
	const struct pqcp_provider_contract contract = {
		.mlkem_enabled = true,
		.mldsa_enabled = false,
		.mlkem_family = PQCP_PROVIDER_FAMILY_FORBIDDEN,
		.mldsa_family = PQCP_PROVIDER_FAMILY_DISABLED,
		.mlkem_source = "mlkem-native",
		.mldsa_source = "disabled",
		.backend_selector = "auto",
		.external_native_family_allowed = false,
		.experimental_non_native_inventory = false,
	};

	zassert_equal(pqcp_provider_contract_validate(&contract), -EBADMSG);
}

ZTEST_SUITE(pqcp_provider_contract, NULL, NULL, NULL, NULL, NULL);
