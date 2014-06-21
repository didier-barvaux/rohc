/*
 * Copyright 2013 Didier Barvaux
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file   rohc_stats.h
 * @brief  Handle a rolling window of values for statistics
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_STATS_H
#define ROHC_STATS_H

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

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

#endif /* ROHC_ENABLE_DEPRECATED_API */

#endif

