
#include "rohc_stats.h"


/**
 * @brief Add a new value in the given statistics context
 *
 * @param stats  The statistics context
 * @param value  The value to add
 */
void rohc_stats_add(struct rohc_stats *const stats,
                    const uint32_t value)
{
	/* if window is full, an entry is overwritten */
	if(stats->count == 16)
	{
		stats->oldest = (stats->oldest + 1) & 0xf;
	}
	else
	{
		stats->count++;
	}

	stats->values[stats->next] = value;
	stats->next = (stats->next + 1) & 0xf;
}


/**
 * @brief Compute the sum of all the recorded values
 *
 * This function is used for statistics.
 *
 * @param stats  The statistics context
 * @return       The sum of the recorded values
 */
uint32_t ROHC_EXPORT rohc_stats_sum(const struct rohc_stats *const stats)
{
	size_t entry;
	int sum = 0;
	size_t i;

	if(stats->count == 0)
	{
		return 0;
	}

	for(i = stats->count, entry = stats->oldest;
	    i > 0;
	    i--, entry = (entry + 1) & 0xf)
	{
		sum += stats->values[entry];
	}

	return sum;
}


/**
 * @brief Compute the mean of all the recorded values
 *
 * @param stats  The statistics context
 * @return       The mean of the recorded values
 */
uint32_t rohc_stats_mean(const struct rohc_stats *const stats)
{
	if(stats->count == 0)
	{
		return 0;
	}
	return (rohc_stats_sum(stats) / stats->count);
}

