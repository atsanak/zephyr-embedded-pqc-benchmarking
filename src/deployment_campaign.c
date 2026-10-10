/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free repeated deployment measurement campaigns.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/deployment_campaign.h>

#define CAMPAIGN_VALUE_MAX (UINT64_MAX / PQCP_DEPLOYMENT_CAMPAIGN_MAX_OBSERVATIONS)
#define METRIC_CYCLES 0U

struct metric_source {
	uint32_t metric;
	const char *name;
	uint64_t (*read)(const struct pqcp_deployment_campaign_observation *obs);
	bool resource_metric;
};

static bool stable_id_valid(const char *value)
{
	size_t length;

	if (value == NULL || value[0] == '\0') {
		return false;
	}
	length = strlen(value);
	if (length >= PQCP_DEPLOYMENT_ID_MAX_CHARS) {
		return false;
	}
	for (size_t i = 0U; i < length; ++i) {
		char c = value[i];

		if ((c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') ||
		    c == '_' || c == '-' || c == '.') {
			continue;
		}
		return false;
	}

	return true;
}

static uint64_t read_latency(
	const struct pqcp_deployment_campaign_observation *obs)
{
	return obs->latency_us;
}

static uint64_t read_cycles(
	const struct pqcp_deployment_campaign_observation *obs)
{
	return obs->cycles;
}

static uint64_t read_ram(
	const struct pqcp_deployment_campaign_observation *obs)
{
	return obs->ram_bytes;
}

static uint64_t read_stack(
	const struct pqcp_deployment_campaign_observation *obs)
{
	return obs->stack_bytes;
}

static uint64_t read_heap(
	const struct pqcp_deployment_campaign_observation *obs)
{
	return obs->heap_bytes;
}

static uint64_t read_flash(
	const struct pqcp_deployment_campaign_observation *obs)
{
	return obs->flash_bytes;
}

static uint64_t read_energy(
	const struct pqcp_deployment_campaign_observation *obs)
{
	return obs->energy_uj;
}

static const struct metric_source metric_sources[] = {
	{ PQCP_DEPLOYMENT_METRIC_LATENCY, "latency", read_latency, false },
	{ METRIC_CYCLES, "cycles", read_cycles, false },
	{ PQCP_DEPLOYMENT_METRIC_RAM, "ram", read_ram, true },
	{ PQCP_DEPLOYMENT_METRIC_STACK, "stack", read_stack, true },
	{ PQCP_DEPLOYMENT_METRIC_HEAP, "heap", read_heap, true },
	{ PQCP_DEPLOYMENT_METRIC_FLASH, "flash", read_flash, true },
	{ PQCP_DEPLOYMENT_METRIC_ENERGY, "energy", read_energy, false },
};

static bool projection_valid(enum pqcp_deployment_campaign_projection value)
{
	return value >= PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_MEDIAN &&
	       value <= PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_MAX;
}

const char *pqcp_deployment_campaign_projection_str(
	enum pqcp_deployment_campaign_projection projection)
{
	switch (projection) {
	case PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_MEDIAN:
		return "median";
	case PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90:
		return "p90";
	case PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P99:
		return "p99";
	case PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_MAX:
		return "max";
	default:
		return "unknown";
	}
}

const char *pqcp_deployment_campaign_quality_str(uint32_t quality)
{
	switch (quality) {
	case PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_EMPTY:
		return "empty";
	case PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_INSUFFICIENT:
		return "insufficient_samples";
	case PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_FAILED_OBSERVATION:
		return "failed_observation";
	case PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_PERFORMANCE:
		return "missing_performance";
	case PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_RESOURCE:
		return "missing_resource";
	case PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_HIGH_VARIANCE:
		return "high_variance";
	case PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_OUTLIERS:
		return "outliers";
	case PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_STATIC_DRIFT:
		return "static_drift";
	case PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_PROJECTION_FAILED:
		return "projection_failed";
	default:
		return "unknown";
	}
}

static uint32_t effective_min_samples(
	const struct pqcp_deployment_campaign_config *config)
{
	return config->min_samples == 0U ?
		PQCP_DEPLOYMENT_CAMPAIGN_DEFAULT_MIN_SAMPLES :
		config->min_samples;
}

static uint32_t effective_cv_warn_bps(
	const struct pqcp_deployment_campaign_config *config)
{
	return config->cv_warn_bps == 0U ?
		PQCP_DEPLOYMENT_CAMPAIGN_DEFAULT_CV_WARN_BPS :
		config->cv_warn_bps;
}

static uint32_t effective_static_drift_warn_permille(
	const struct pqcp_deployment_campaign_config *config)
{
	return config->static_drift_warn_permille == 0U ?
		PQCP_DEPLOYMENT_CAMPAIGN_DEFAULT_STATIC_DRIFT_WARN_PERMILLE :
		config->static_drift_warn_permille;
}

int pqcp_deployment_campaign_init(
	struct pqcp_deployment_campaign_state *state,
	const struct pqcp_deployment_campaign_config *config,
	struct pqcp_deployment_campaign_observation *observations,
	size_t observation_capacity)
{
	if (state == NULL || config == NULL || observations == NULL ||
	    observation_capacity == 0U ||
	    observation_capacity > PQCP_DEPLOYMENT_CAMPAIGN_MAX_OBSERVATIONS ||
	    !stable_id_valid(config->campaign_id) ||
	    !projection_valid(config->projection) ||
	    effective_min_samples(config) > observation_capacity ||
	    pqcp_deployment_candidate_validate(
		    &config->candidate_template) != 0) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	memset(observations, 0, sizeof(*observations) * observation_capacity);
	state->schema_version = PQCP_DEPLOYMENT_CAMPAIGN_SCHEMA_VERSION;
	state->config = *config;
	state->config.min_samples = effective_min_samples(config);
	state->config.cv_warn_bps = effective_cv_warn_bps(config);
	state->config.static_drift_warn_permille =
		effective_static_drift_warn_permille(config);
	state->observations = observations;
	state->observation_capacity = observation_capacity;

	return 0;
}

static bool observation_value_valid(uint64_t value)
{
	return value <= CAMPAIGN_VALUE_MAX;
}

int pqcp_deployment_campaign_add(
	struct pqcp_deployment_campaign_state *state,
	const struct pqcp_deployment_campaign_observation *observation)
{
	if (state == NULL || observation == NULL ||
	    state->schema_version != PQCP_DEPLOYMENT_CAMPAIGN_SCHEMA_VERSION ||
	    state->observations == NULL ||
	    state->observation_capacity == 0U ||
	    state->observation_capacity > PQCP_DEPLOYMENT_CAMPAIGN_MAX_OBSERVATIONS ||
	    state->failed_count > state->observation_count ||
	    state->observation_count >= state->observation_capacity ||
	    !observation_value_valid(observation->latency_us) ||
	    !observation_value_valid(observation->cycles) ||
	    !observation_value_valid(observation->ram_bytes) ||
	    !observation_value_valid(observation->stack_bytes) ||
	    !observation_value_valid(observation->heap_bytes) ||
	    !observation_value_valid(observation->flash_bytes) ||
	    !observation_value_valid(observation->energy_uj)) {
		return -EINVAL;
	}

	state->observations[state->observation_count++] = *observation;
	if (!observation->passed) {
		state->failed_count++;
	}

	return 0;
}

static void sort_u64(uint64_t *values, uint32_t count)
{
	for (uint32_t i = 1U; i < count; ++i) {
		uint64_t value = values[i];
		uint32_t j = i;

		while (j > 0U && values[j - 1U] > value) {
			values[j] = values[j - 1U];
			j--;
		}
		values[j] = value;
	}
}

static uint64_t percentile_sorted(
	const uint64_t *values,
	uint32_t count,
	uint32_t percentile)
{
	uint32_t index;

	if (count == 0U) {
		return 0U;
	}
	index = (percentile * (count - 1U)) / 100U;
	return values[index];
}

static uint64_t isqrt_u64(uint64_t value)
{
	uint64_t result = 0U;
	uint64_t bit = 1ULL << 62;

	while (bit > value) {
		bit >>= 2U;
	}
	while (bit != 0U) {
		if (value >= result + bit) {
			value -= result + bit;
			result = (result >> 1U) + bit;
		} else {
			result >>= 1U;
		}
		bit >>= 2U;
	}

	return result;
}

static uint32_t ratio_bps(uint64_t numerator, uint64_t denominator)
{
	uint64_t scaled;

	if (numerator == 0U || denominator == 0U) {
		return 0U;
	}
	if (numerator <= UINT64_MAX / 10000U) {
		scaled = (numerator * 10000U) / denominator;
	} else {
		uint64_t divisor = denominator / 10000U;

		scaled = divisor == 0U ? UINT32_MAX : numerator / divisor;
	}
	return scaled > UINT32_MAX ? UINT32_MAX : (uint32_t)scaled;
}

static uint32_t ratio_permille(uint64_t numerator, uint64_t denominator)
{
	uint64_t scaled;

	if (numerator == 0U || denominator == 0U) {
		return 0U;
	}
	if (numerator <= UINT64_MAX / 1000U) {
		scaled = (numerator * 1000U) / denominator;
	} else {
		uint64_t divisor = denominator / 1000U;

		scaled = divisor == 0U ? UINT32_MAX : numerator / divisor;
	}
	return scaled > UINT32_MAX ? UINT32_MAX : (uint32_t)scaled;
}

static uint64_t absolute_delta(uint64_t left, uint64_t right)
{
	return left > right ? left - right : right - left;
}

static uint64_t median_absolute_deviation(
	const uint64_t *values,
	uint32_t count,
	uint64_t median)
{
	uint64_t deviations[PQCP_DEPLOYMENT_CAMPAIGN_MAX_OBSERVATIONS];

	for (uint32_t i = 0U; i < count; ++i) {
		deviations[i] = absolute_delta(values[i], median);
	}
	sort_u64(deviations, count);
	return percentile_sorted(deviations, count, 50U);
}

static uint32_t count_outliers(
	const uint64_t *values,
	uint32_t count,
	uint64_t median,
	uint64_t mad)
{
	uint32_t outliers = 0U;

	for (uint32_t i = 0U; i < count; ++i) {
		uint64_t delta = absolute_delta(values[i], median);

		if ((mad == 0U && delta != 0U) ||
		    (mad != 0U && delta > (mad * 6U))) {
			outliers++;
		}
	}

	return outliers;
}

static uint32_t coefficient_of_variation_bps(
	const uint64_t *values,
	uint32_t count,
	uint64_t mean)
{
	uint64_t normalized_square_sum = 0U;

	if (count < 2U || mean == 0U) {
		return 0U;
	}
	for (uint32_t i = 0U; i < count; ++i) {
		uint32_t deviation_bps =
			ratio_bps(absolute_delta(values[i], mean), mean);

		normalized_square_sum +=
			(uint64_t)deviation_bps * (uint64_t)deviation_bps;
	}

	return (uint32_t)isqrt_u64(normalized_square_sum / count);
}

static int summarize_metric(
	const struct pqcp_deployment_campaign_state *state,
	const struct metric_source *source,
	struct pqcp_deployment_metric_stats *stats)
{
	uint64_t values[PQCP_DEPLOYMENT_CAMPAIGN_MAX_OBSERVATIONS];
	uint64_t sum = 0U;
	uint32_t count = 0U;
	uint32_t missing = 0U;

	memset(stats, 0, sizeof(*stats));
	stats->metric = source->metric;
	stats->name = source->name;
	for (size_t i = 0U; i < state->observation_count; ++i) {
		const struct pqcp_deployment_campaign_observation *obs =
			&state->observations[i];
		uint64_t value;

		if (!obs->passed) {
			continue;
		}
		value = source->read(obs);
		if (value == 0U) {
			missing++;
			continue;
		}
		if (UINT64_MAX - sum < value) {
			return -ERANGE;
		}
		values[count++] = value;
		sum += value;
	}

	stats->count = count;
	stats->missing_count = missing;
	if (count == 0U) {
		stats->stable = false;
		return 0;
	}

	sort_u64(values, count);
	stats->min = values[0];
	stats->max = values[count - 1U];
	stats->mean = sum / count;
	stats->median = percentile_sorted(values, count, 50U);
	stats->p90 = percentile_sorted(values, count, 90U);
	stats->p99 = percentile_sorted(values, count, 99U);
	stats->mad = median_absolute_deviation(values, count, stats->median);
	stats->cv_bps = coefficient_of_variation_bps(
		values, count, stats->mean);
	stats->outlier_count = count_outliers(
		values, count, stats->median, stats->mad);
	stats->stable = count >= state->config.min_samples &&
		stats->cv_bps <= state->config.cv_warn_bps &&
		stats->outlier_count == 0U;

	return 0;
}

static void init_empty_metric_identities(
	struct pqcp_deployment_campaign_summary *summary)
{
	struct pqcp_deployment_metric_stats *stats[] = {
		&summary->latency,
		&summary->cycles,
		&summary->ram,
		&summary->stack,
		&summary->heap,
		&summary->flash,
		&summary->energy,
	};

	for (size_t i = 0U; i < ARRAY_SIZE(metric_sources); ++i) {
		memset(stats[i], 0, sizeof(*stats[i]));
		stats[i]->metric = metric_sources[i].metric;
		stats[i]->name = metric_sources[i].name;
	}
}

static uint64_t projected_variable_value(
	const struct pqcp_deployment_metric_stats *stats,
	enum pqcp_deployment_campaign_projection projection)
{
	if (stats->count == 0U) {
		return 0U;
	}
	switch (projection) {
	case PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_MEDIAN:
		return stats->median;
	case PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90:
		return stats->p90;
	case PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P99:
		return stats->p99;
	case PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_MAX:
		return stats->max;
	default:
		return 0U;
	}
}

static uint32_t resource_quality_mask(
	const struct pqcp_deployment_campaign_state *state,
	const struct pqcp_deployment_metric_stats *stats)
{
	uint32_t quality = 0U;

	if (stats->missing_count != 0U || stats->count == 0U) {
		quality |= PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_RESOURCE;
	}
	if (stats->count != 0U && stats->max != 0U &&
	    ratio_permille(stats->max - stats->min, stats->max) >
		    state->config.static_drift_warn_permille) {
		quality |= PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_STATIC_DRIFT;
	}
	return quality;
}

static void apply_metric_quality(
	const struct pqcp_deployment_campaign_state *state,
	const struct pqcp_deployment_metric_stats *stats,
	bool performance_metric,
	bool resource_metric,
	uint32_t *quality)
{
	if (stats->missing_count != 0U || stats->count == 0U) {
		if (performance_metric) {
			*quality |=
				PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_PERFORMANCE;
		}
		if (resource_metric) {
			*quality |= resource_quality_mask(state, stats);
		}
	}
	if (stats->count != 0U &&
	    stats->cv_bps > state->config.cv_warn_bps) {
		*quality |= PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_HIGH_VARIANCE;
	}
	if (stats->outlier_count != 0U) {
		*quality |= PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_OUTLIERS;
	}
	if (resource_metric) {
		*quality |= resource_quality_mask(state, stats);
	}
}

static int fill_all_stats(
	const struct pqcp_deployment_campaign_state *state,
	struct pqcp_deployment_campaign_summary *summary)
{
	struct pqcp_deployment_metric_stats *stats[] = {
		&summary->latency,
		&summary->cycles,
		&summary->ram,
		&summary->stack,
		&summary->heap,
		&summary->flash,
		&summary->energy,
	};

	for (size_t i = 0U; i < ARRAY_SIZE(metric_sources); ++i) {
		int ret = summarize_metric(state, &metric_sources[i], stats[i]);

		if (ret != 0) {
			return ret;
		}
		apply_metric_quality(
			state, stats[i],
			metric_sources[i].metric == PQCP_DEPLOYMENT_METRIC_LATENCY,
			metric_sources[i].resource_metric,
			&summary->quality_mask);
	}

	return 0;
}

static bool resource_stats_present(
	const struct pqcp_deployment_campaign_summary *summary)
{
	return summary->ram.count != 0U ||
	       summary->stack.count != 0U ||
	       summary->heap.count != 0U ||
	       summary->flash.count != 0U;
}

static void project_candidate(
	const struct pqcp_deployment_campaign_state *state,
	struct pqcp_deployment_campaign_summary *summary)
{
	struct pqcp_deployment_candidate candidate =
		state->config.candidate_template;

	/* Campaign-derived evidence must not survive from the input template. */
	candidate.evidence_mask &= ~(PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE |
				    PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
				    PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE);
	candidate.latency_us = projected_variable_value(
		&summary->latency, state->config.projection);
	candidate.cycles = projected_variable_value(
		&summary->cycles, state->config.projection);
	candidate.energy_uj = projected_variable_value(
		&summary->energy, state->config.projection);
	candidate.ram_bytes = summary->ram.max;
	candidate.stack_bytes = summary->stack.max;
	candidate.heap_bytes = summary->heap.max;
	candidate.flash_bytes = summary->flash.max;

	if (summary->latency.count != 0U) {
		candidate.evidence_mask |= PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
	}
	if (resource_stats_present(summary)) {
		candidate.evidence_mask |= PQCP_DEPLOYMENT_EVIDENCE_RESOURCE;
	}
	if (summary->latency.count == 0U || !resource_stats_present(summary)) {
		summary->projected_candidate = candidate;
		summary->projected_candidate_valid = false;
		summary->quality_mask |=
			PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_PROJECTION_FAILED;
		return;
	}
	if (summary->quality_mask == 0U) {
		candidate.evidence_mask |= PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE;
	}

	summary->projected_candidate = candidate;
	summary->projected_candidate_valid =
		pqcp_deployment_candidate_validate(&candidate) == 0;
	if (!summary->projected_candidate_valid) {
		summary->quality_mask |=
			PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_PROJECTION_FAILED;
	}
}

int pqcp_deployment_campaign_summarize(
	const struct pqcp_deployment_campaign_state *state,
	struct pqcp_deployment_campaign_summary *summary)
{
	int ret;

	if (state == NULL || summary == NULL ||
	    state->schema_version != PQCP_DEPLOYMENT_CAMPAIGN_SCHEMA_VERSION ||
	    state->observations == NULL ||
	    state->observation_capacity == 0U ||
	    state->observation_capacity > PQCP_DEPLOYMENT_CAMPAIGN_MAX_OBSERVATIONS ||
	    state->observation_count > state->observation_capacity ||
	    state->failed_count > state->observation_count ||
	    state->config.min_samples == 0U ||
	    state->config.min_samples > state->observation_capacity ||
	    !stable_id_valid(state->config.campaign_id) ||
	    !projection_valid(state->config.projection)) {
		return -EINVAL;
	}

	memset(summary, 0, sizeof(*summary));
	summary->schema_version = PQCP_DEPLOYMENT_CAMPAIGN_SCHEMA_VERSION;
	summary->campaign_id = state->config.campaign_id;
	summary->observation_count = (uint32_t)state->observation_count;
	summary->failed_count = state->failed_count;
	summary->successful_count =
		(uint32_t)state->observation_count - state->failed_count;
	summary->projection = state->config.projection;

	if (state->observation_count == 0U) {
		init_empty_metric_identities(summary);
		summary->quality_mask |= PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_EMPTY |
					 PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_INSUFFICIENT |
					 PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_PROJECTION_FAILED;
		return 0;
	}
	if (summary->successful_count < state->config.min_samples) {
		summary->quality_mask |=
			PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_INSUFFICIENT;
	}
	if (state->failed_count != 0U) {
		summary->quality_mask |=
			PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_FAILED_OBSERVATION;
	}

	ret = fill_all_stats(state, summary);
	if (ret != 0) {
		return ret;
	}
	project_candidate(state, summary);

	return 0;
}

static int metric_stats_validate(
	const struct pqcp_deployment_metric_stats *stats)
{
	if (stats == NULL || stats->name == NULL ||
	    (stats->metric & ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) != 0U ||
	    (stats->count == 0U &&
	     (stats->min != 0U || stats->max != 0U || stats->mean != 0U ||
	      stats->median != 0U || stats->p90 != 0U || stats->p99 != 0U ||
	      stats->mad != 0U || stats->cv_bps != 0U ||
	      stats->outlier_count != 0U || stats->stable)) ||
	    (stats->count != 0U &&
	     (stats->min > stats->median || stats->median > stats->p90 ||
	      stats->p90 > stats->p99 || stats->p99 > stats->max))) {
		return -EINVAL;
	}

	return 0;
}

static int emit_metric_stats(
	const struct pqcp_deployment_campaign_summary *summary,
	const struct pqcp_deployment_metric_stats *stats)
{
	if (metric_stats_validate(stats) != 0) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_CAMPAIGN_METRIC campaign=%s metric=%s count=%u missing=%u min=%llu median=%llu p90=%llu p99=%llu max=%llu mean=%llu mad=%llu cv_bps=%u outliers=%u stable=%u\n",
	       summary->campaign_id,
	       stats->name,
	       stats->count,
	       stats->missing_count,
	       (unsigned long long)stats->min,
	       (unsigned long long)stats->median,
	       (unsigned long long)stats->p90,
	       (unsigned long long)stats->p99,
	       (unsigned long long)stats->max,
	       (unsigned long long)stats->mean,
	       (unsigned long long)stats->mad,
	       stats->cv_bps,
	       stats->outlier_count,
	       stats->stable ? 1U : 0U);
	return 0;
}

int pqcp_deployment_campaign_summary_emit(
	const struct pqcp_deployment_campaign_summary *summary)
{
	if (summary == NULL) {
		return -EINVAL;
	}

	const struct pqcp_deployment_metric_stats *stats[] = {
		&summary->latency,
		&summary->cycles,
		&summary->ram,
		&summary->stack,
		&summary->heap,
		&summary->flash,
		&summary->energy,
	};

	if (summary->schema_version != PQCP_DEPLOYMENT_CAMPAIGN_SCHEMA_VERSION ||
	    !stable_id_valid(summary->campaign_id) ||
	    !projection_valid(summary->projection) ||
	    (summary->quality_mask &
	     ~PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_KNOWN_MASK) != 0U ||
	    summary->successful_count + summary->failed_count !=
		    summary->observation_count) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_CAMPAIGN_SUMMARY schema=%u id=%s projection=%s observations=%u successful=%u failed=%u quality=0x%08x projected=%u candidate=%s evidence=0x%08x\n",
	       summary->schema_version,
	       summary->campaign_id,
	       pqcp_deployment_campaign_projection_str(summary->projection),
	       summary->observation_count,
	       summary->successful_count,
	       summary->failed_count,
	       summary->quality_mask,
	       summary->projected_candidate_valid ? 1U : 0U,
	       summary->projected_candidate_valid ?
		       summary->projected_candidate.candidate_id : "none",
	       summary->projected_candidate_valid ?
		       summary->projected_candidate.evidence_mask : 0U);

	for (size_t i = 0U; i < ARRAY_SIZE(stats); ++i) {
		int ret = emit_metric_stats(summary, stats[i]);

		if (ret != 0) {
			return ret;
		}
	}

	return summary->quality_mask == 0U ? 0 : -ENODATA;
}
