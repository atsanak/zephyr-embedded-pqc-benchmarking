/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */
/*
 * Power-on self-test for the PQCP module.
 *
 * Compiled only when CONFIG_PQCP_KAT_BOOT_VERIFY=y. Installs a SYS_INIT
 * hook at APPLICATION level (priority 90) that:
 *
 *   1. Seeds the deterministic test RNG with a fixed seed so the
 *      self-verify is reproducible across boots and does not depend on
 *      the platform RNG, which may not be ready at SYS_INIT time.
 *   2. For every enabled ML-KEM parameter set, runs
 *      keygen → encaps → decaps and asserts the two shared secrets
 *      agree (PQCP_MLKEM_SUCCESS + ss_a == ss_b).
 *   3. For every enabled ML-DSA parameter set, runs
 *      keygen → sign → verify on a fixed transcript and asserts the
 *      verifier returns PQCP_MLDSA_SUCCESS.
 *   4. On any failure, calls k_panic() so the system never proceeds
 *      with cryptographic services that have not passed the
 *      power-on self-test.
 *
 * After the self-verify completes successfully, the deterministic RNG
 * state is intentionally left primed; production callers MUST replace
 * the RNG with a real entropy source via pqcp_rng_register() before
 * serving traffic. The Kconfig help text states this contract.
 *
 * The implementation deliberately uses the public PQCP API
 * (pqcp_mlkem_*, pqcp_mldsa_*, pqcp_rng_*) and never reaches into
 * upstream mlkem-native or mldsa-native internals — this keeps the
 * self-test layered the same way a downstream consumer would call the
 * primitives.
 */

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

LOG_MODULE_REGISTER(pqcp_boot_verify, CONFIG_LOG_DEFAULT_LEVEL);

/* Deterministic 48-byte seed for the boot self-verify. The exact bytes
 * do not matter cryptographically (we are testing functional correctness,
 * not entropy); they are fixed only so the boot path is reproducible.
 */
static const uint8_t kat_boot_seed[48] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
};

static const uint8_t kat_boot_message[] = "PQCP boot self-verify";

#if defined(CONFIG_PQCP_MLKEM_LEVEL_512) || \
	defined(CONFIG_PQCP_MLKEM_LEVEL_768) || \
	defined(CONFIG_PQCP_MLKEM_LEVEL_1024)
#define PQCP_KAT_BOOT_VERIFY_HAS_MLKEM 1
#endif

#if defined(CONFIG_PQCP_MLDSA_LEVEL_44) || \
	defined(CONFIG_PQCP_MLDSA_LEVEL_65) || \
	defined(CONFIG_PQCP_MLDSA_LEVEL_87)
#define PQCP_KAT_BOOT_VERIFY_HAS_MLDSA 1
#endif

/* Static buffers sized at maxima to avoid touching the heap during boot. */
#ifdef PQCP_KAT_BOOT_VERIFY_HAS_MLKEM
static uint8_t kem_pk[PQCP_MLKEM_PK_SIZE_MAX];
static uint8_t kem_sk[PQCP_MLKEM_SK_SIZE_MAX];
static uint8_t kem_ct[PQCP_MLKEM_CT_SIZE_MAX];
static uint8_t kem_ss_a[PQCP_MLKEM_SS_SIZE];
static uint8_t kem_ss_b[PQCP_MLKEM_SS_SIZE];

static int kat_verify_mlkem(pqcp_mlkem_level_t level, const char *label)
{
	int rc = pqcp_mlkem_keypair(level, kem_pk, kem_sk);
	if (rc != PQCP_MLKEM_SUCCESS) {
		LOG_ERR("PQCP_KAT_BOOT_VERIFY[%s]: keygen failed (%d)", label, rc);
		return rc;
	}
	rc = pqcp_mlkem_encapsulate(level, kem_pk, kem_ct, kem_ss_a);
	if (rc != PQCP_MLKEM_SUCCESS) {
		LOG_ERR("PQCP_KAT_BOOT_VERIFY[%s]: encaps failed (%d)", label, rc);
		return rc;
	}
	rc = pqcp_mlkem_decapsulate(level, kem_ct, kem_sk, kem_ss_b);
	if (rc != PQCP_MLKEM_SUCCESS) {
		LOG_ERR("PQCP_KAT_BOOT_VERIFY[%s]: decaps failed (%d)", label, rc);
		return rc;
	}
	if (memcmp(kem_ss_a, kem_ss_b, PQCP_MLKEM_SS_SIZE) != 0) {
		LOG_ERR("PQCP_KAT_BOOT_VERIFY[%s]: shared-secret mismatch", label);
		return -EIO;
	}
	LOG_INF("PQCP_KAT_BOOT_VERIFY[%s]: ok", label);
	return 0;
}
#endif /* PQCP_KAT_BOOT_VERIFY_HAS_MLKEM */

#ifdef PQCP_KAT_BOOT_VERIFY_HAS_MLDSA
static uint8_t dsa_pk[PQCP_MLDSA_PK_SIZE_MAX];
static uint8_t dsa_sk[PQCP_MLDSA_SK_SIZE_MAX];
static uint8_t dsa_sig[PQCP_MLDSA_SIG_SIZE_MAX];

static int kat_verify_mldsa(pqcp_mldsa_level_t level, const char *label)
{
	int rc = pqcp_mldsa_keypair(level, dsa_pk, dsa_sk);
	if (rc != PQCP_MLDSA_SUCCESS) {
		LOG_ERR("PQCP_KAT_BOOT_VERIFY[%s]: keygen failed (%d)", label, rc);
		return rc;
	}
	rc = pqcp_mldsa_sign(level, dsa_sk, kat_boot_message,
			     sizeof(kat_boot_message) - 1U, NULL, 0U, dsa_sig);
	if (rc != PQCP_MLDSA_SUCCESS) {
		LOG_ERR("PQCP_KAT_BOOT_VERIFY[%s]: sign failed (%d)", label, rc);
		return rc;
	}
	rc = pqcp_mldsa_verify(level, dsa_pk, kat_boot_message,
			       sizeof(kat_boot_message) - 1U, NULL, 0U, dsa_sig);
	if (rc != PQCP_MLDSA_SUCCESS) {
		LOG_ERR("PQCP_KAT_BOOT_VERIFY[%s]: verify failed (%d)", label, rc);
		return rc;
	}
	LOG_INF("PQCP_KAT_BOOT_VERIFY[%s]: ok", label);
	return 0;
}
#endif /* PQCP_KAT_BOOT_VERIFY_HAS_MLDSA */

static int pqcp_kat_boot_verify(void)
{
	LOG_INF("PQCP_KAT_BOOT_VERIFY: starting power-on self-test");

	int rc = pqcp_rng_init();
	if (rc != 0) {
		LOG_ERR("PQCP_KAT_BOOT_VERIFY: pqcp_rng_init failed (%d)", rc);
		return rc;
	}
	rc = pqcp_rng_deterministic_seed(kat_boot_seed, sizeof(kat_boot_seed));
	if (rc != 0) {
		LOG_ERR("PQCP_KAT_BOOT_VERIFY: rng seed failed (%d)", rc);
		return rc;
	}

#if defined(CONFIG_PQCP_MLKEM_LEVEL_512)
	if ((rc = kat_verify_mlkem(PQCP_MLKEM_512, "MLKEM-512")) != 0) {
		return rc;
	}
#endif
#if defined(CONFIG_PQCP_MLKEM_LEVEL_768)
	if ((rc = kat_verify_mlkem(PQCP_MLKEM_768, "MLKEM-768")) != 0) {
		return rc;
	}
#endif
#if defined(CONFIG_PQCP_MLKEM_LEVEL_1024)
	if ((rc = kat_verify_mlkem(PQCP_MLKEM_1024, "MLKEM-1024")) != 0) {
		return rc;
	}
#endif

#if defined(CONFIG_PQCP_MLDSA_LEVEL_44)
	if ((rc = kat_verify_mldsa(PQCP_MLDSA_44, "MLDSA-44")) != 0) {
		return rc;
	}
#endif
#if defined(CONFIG_PQCP_MLDSA_LEVEL_65)
	if ((rc = kat_verify_mldsa(PQCP_MLDSA_65, "MLDSA-65")) != 0) {
		return rc;
	}
#endif
#if defined(CONFIG_PQCP_MLDSA_LEVEL_87)
	if ((rc = kat_verify_mldsa(PQCP_MLDSA_87, "MLDSA-87")) != 0) {
		return rc;
	}
#endif

	LOG_INF("PQCP_KAT_BOOT_VERIFY: all enabled primitives passed");
	return 0;
}

static int pqcp_kat_boot_verify_init(void)
{
	int rc = pqcp_kat_boot_verify();
	if (rc != 0) {
		/*
		 * Halt the system rather than allow a module that failed its
		 * power-on self-test to serve cryptographic requests. The
		 * Kconfig help text explicitly documents this behavior.
		 */
		LOG_ERR("PQCP_KAT_BOOT_VERIFY: panic — refusing to boot with broken PQCP");
		k_panic();
	}
	return rc;
}

SYS_INIT(pqcp_kat_boot_verify_init, APPLICATION, 90);
