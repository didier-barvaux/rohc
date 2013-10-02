#ifndef ROHC_STATS_H
#define ROHC_STATS_H

#include <stdint.h>
#include <stdlib.h>

#include "dllexport.h"


/**
 * Record ROHC statistics with a rolling window
 */
struct rohc_stats
{
	uint32_t values[16];  /**< The window of statistics value */
	size_t oldest;        /**< The index of the oldest value */
	size_t next;          /**< The index of the next value */
	size_t count;         /**< The number of values */
};


void ROHC_EXPORT rohc_stats_add(struct rohc_stats *const stats,
                                const uint32_t value)
	__attribute__((nonnull(1)));

uint32_t ROHC_EXPORT rohc_stats_sum(const struct rohc_stats *const stats)
	__attribute__((nonnull(1), pure));

uint32_t ROHC_EXPORT rohc_stats_mean(const struct rohc_stats *const stats)
	__attribute__((nonnull(1), pure));

#endif

