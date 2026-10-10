/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Repeated deployment measurement campaigns
 *
 * Stability: experimental evidence API. The campaign accumulator summarizes
 * caller-supplied observations and does not execute cryptographic operations.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_CAMPAIGN_H_
#define PQCP_ZEPHYR_DEPLOYMENT_CAMPAIGN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_advisor.h>

/** Measurement identity bits used by the standalone campaign component. */
#define PQCP_DEPLOYMENT_METRIC_LATENCY (1U << 0)
#define PQCP_DEPLOYMENT_METRIC_RAM     (1U << 1)
#define PQCP_DEPLOYMENT_METRIC_STACK   (1U << 2)
#define PQCP_DEPLOYMENT_METRIC_HEAP    (1U << 3)
#define PQCP_DEPLOYMENT_METRIC_FLASH   (1U << 4)
#define PQCP_DEPLOYMENT_METRIC_ENERGY  (1U << 5)
#define PQCP_DEPLOYMENT_METRIC_KNOWN_MASK ((1U << 6) - 1U)

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment campaign markers and result structures. */
#define PQCP_DEPLOYMENT_CAMPAIGN_SCHEMA_VERSION 1U
/** Maximum observations summarized by one campaign state. */
#define PQCP_DEPLOYMENT_CAMPAIGN_MAX_OBSERVATIONS 64U
/** Default minimum observations before reproducibility evidence is credited. */
#define PQCP_DEPLOYMENT_CAMPAIGN_DEFAULT_MIN_SAMPLES 5U
/** Default coefficient-of-variation warning threshold in basis points. */
#define PQCP_DEPLOYMENT_CAMPAIGN_DEFAULT_CV_WARN_BPS 1000U
/** Default static footprint drift threshold in permille. */
#define PQCP_DEPLOYMENT_CAMPAIGN_DEFAULT_STATIC_DRIFT_WARN_PERMILLE 50U

/** No usable samples were supplied. */
#define PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_EMPTY              (1U << 0)
/** Fewer than the configured minimum sample count were supplied. */
#define PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_INSUFFICIENT       (1U << 1)
/** One or more observations were marked failed. */
#define PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_FAILED_OBSERVATION (1U << 2)
/** Latency or cycle measurements are missing. */
#define PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_PERFORMANCE (1U << 3)
/** One or more footprint measurements are missing. */
#define PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_RESOURCE   (1U << 4)
/** One or more metric groups exceed the configured CV threshold. */
#define PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_HIGH_VARIANCE      (1U << 5)
/** One or more metric groups contain robust-MAD outliers. */
#define PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_OUTLIERS           (1U << 6)
/** Footprint metrics drifted even though they should be mostly static. */
#define PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_STATIC_DRIFT       (1U << 7)
/** Projection could not produce a usable deployment candidate. */
#define PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_PROJECTION_FAILED  (1U << 8)

/** All quality bits known by this API version. */
#define PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_KNOWN_MASK \
	(PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_EMPTY | \
	 PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_INSUFFICIENT | \
	 PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_FAILED_OBSERVATION | \
	 PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_PERFORMANCE | \
	 PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_RESOURCE | \
	 PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_HIGH_VARIANCE | \
	 PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_OUTLIERS | \
	 PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_STATIC_DRIFT | \
	 PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_PROJECTION_FAILED)

/** Statistic used to project variable metrics into a candidate. */
enum pqcp_deployment_campaign_projection {
	PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_MEDIAN = 0,
	PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90,
	PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P99,
	PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_MAX,
};

/** One campaign observation supplied by benchmark or board code. */
struct pqcp_deployment_campaign_observation {
	/** True when the measured operation succeeded. */
	bool passed;
	/** Operation latency in microseconds, or zero if not captured. */
	uint64_t latency_us;
	/** Operation cycles, or zero if not captured. */
	uint64_t cycles;
	/** RAM footprint in bytes, or zero if not captured. */
	uint64_t ram_bytes;
	/** Stack footprint in bytes, or zero if not captured. */
	uint64_t stack_bytes;
	/** Heap footprint in bytes, or zero if not captured. */
	uint64_t heap_bytes;
	/** Flash/code footprint in bytes, or zero if not captured. */
	uint64_t flash_bytes;
	/** Energy in microjoules, or zero if not captured. */
	uint64_t energy_uj;
};

/** Caller-supplied campaign configuration. */
struct pqcp_deployment_campaign_config {
	/** Stable campaign identifier. */
	const char *campaign_id;
	/** Candidate template that receives projected measurement facts. */
	struct pqcp_deployment_candidate candidate_template;
	/** Projection policy for latency/cycles/energy. */
	enum pqcp_deployment_campaign_projection projection;
	/** Minimum successful samples required for reproducibility credit. */
	uint32_t min_samples;
	/** CV warning threshold in basis points. Zero selects the default. */
	uint32_t cv_warn_bps;
	/** Static resource drift threshold in permille. Zero selects default. */
	uint32_t static_drift_warn_permille;
};

/** Caller-owned campaign accumulator. */
struct pqcp_deployment_campaign_state {
	/** Campaign schema version. */
	uint32_t schema_version;
	/** Effective campaign configuration. */
	struct pqcp_deployment_campaign_config config;
	/** Caller-owned observation storage. */
	struct pqcp_deployment_campaign_observation *observations;
	/** Capacity of observation storage. */
	size_t observation_capacity;
	/** Number of observations recorded. */
	size_t observation_count;
	/** Number of observations recorded with passed=false. */
	uint32_t failed_count;
};

/** Statistics for one metric group. */
struct pqcp_deployment_metric_stats {
	/** One PQCP_DEPLOYMENT_METRIC_* bit, or zero for cycles. */
	uint32_t metric;
	/** Stable metric token. */
	const char *name;
	/** Nonzero samples summarized. */
	uint32_t count;
	/** Missing or zero samples. */
	uint32_t missing_count;
	/** Minimum sample. */
	uint64_t min;
	/** Maximum sample. */
	uint64_t max;
	/** Integer mean. */
	uint64_t mean;
	/** Median using floor(0.50 * (n - 1)) indexing, without interpolation. */
	uint64_t median;
	/** p90 using floor(0.90 * (n - 1)) indexing. */
	uint64_t p90;
	/** p99 using floor(0.99 * (n - 1)) indexing. */
	uint64_t p99;
	/** Median absolute deviation. */
	uint64_t mad;
	/** Coefficient of variation in basis points. */
	uint32_t cv_bps;
	/** Robust-MAD outlier count. */
	uint32_t outlier_count;
	/** True when this metric met sample and variance quality thresholds. */
	bool stable;
};

/** Complete campaign summary and projected advisor input. */
struct pqcp_deployment_campaign_summary {
	/** Summary schema version. */
	uint32_t schema_version;
	/** Stable campaign identifier. */
	const char *campaign_id;
	/** Observation count. */
	uint32_t observation_count;
	/** Successful observation count. */
	uint32_t successful_count;
	/** Failed observation count. */
	uint32_t failed_count;
	/** Effective projection policy. */
	enum pqcp_deployment_campaign_projection projection;
	/** Quality bit mask. Zero means no reviewer-visible concern. */
	uint32_t quality_mask;
	/** Latency stats. */
	struct pqcp_deployment_metric_stats latency;
	/** Cycle stats. */
	struct pqcp_deployment_metric_stats cycles;
	/** RAM stats. */
	struct pqcp_deployment_metric_stats ram;
	/** Stack stats. */
	struct pqcp_deployment_metric_stats stack;
	/** Heap stats. */
	struct pqcp_deployment_metric_stats heap;
	/** Flash stats. */
	struct pqcp_deployment_metric_stats flash;
	/** Energy stats. */
	struct pqcp_deployment_metric_stats energy;
	/** Candidate projected from the summarized observations. */
	struct pqcp_deployment_candidate projected_candidate;
	/** True when projected_candidate is internally valid. */
	bool projected_candidate_valid;
};

/** Convert projection policy to a stable transcript token. */
const char *pqcp_deployment_campaign_projection_str(
	enum pqcp_deployment_campaign_projection projection);

/** Convert one campaign quality bit to a stable transcript token. */
const char *pqcp_deployment_campaign_quality_str(uint32_t quality);

/** Initialize a caller-owned campaign state and observation buffer. */
int pqcp_deployment_campaign_init(
	struct pqcp_deployment_campaign_state *state,
	const struct pqcp_deployment_campaign_config *config,
	struct pqcp_deployment_campaign_observation *observations,
	size_t observation_capacity);

/** Add one observation to a campaign. */
int pqcp_deployment_campaign_add(
	struct pqcp_deployment_campaign_state *state,
	const struct pqcp_deployment_campaign_observation *observation);

/** Summarize recorded observations and project a candidate. */
int pqcp_deployment_campaign_summarize(
	const struct pqcp_deployment_campaign_state *state,
	struct pqcp_deployment_campaign_summary *summary);

/** Emit one stable campaign summary marker and metric rows. */
int pqcp_deployment_campaign_summary_emit(
	const struct pqcp_deployment_campaign_summary *summary);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_CAMPAIGN_H_ */
