/*
 * Copyright 2013,2014 Didier Barvaux
 * Copyright 2010,2013 Viveris Technologies
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file    rohc_time.h
 * @brief   ROHC functions and definitions related to time
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author  Thales Communications
 */

#ifndef ROHC_TIME_H
#define ROHC_TIME_H

#include "rohc.h"

#ifndef __KERNEL__
#	include <sys/time.h>
#endif


static inline uint64_t rohc_time_interval(const struct rohc_ts begin,
                                          const struct rohc_ts end)
	__attribute__((warn_unused_result, const));


#ifndef __KERNEL__

/**
 * @brief Get the current time in seconds
 *
 * @return The current time in seconds
 */
static inline uint64_t rohc_get_seconds(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return tv.tv_sec;
}

#else /* __KERNEL__ */

/**
 * @brief Get the current time in seconds
 *
 * @return The current time in seconds
 */
static inline uint64_t rohc_get_seconds(void)
{
	struct timespec ts;

	ktime_get_ts(&ts);

	return ts.tv_sec;
}

#endif /* __KERNEL__ */


/**
 * @brief Compute the interval of time between 2 timestamps
 *
 * @param begin  The begin timestamp (in seconds and nanoseconds)
 * @param end    The end timestamp (in seconds and nanoseconds)
 * @return       The interval of time in microseconds
 */
static inline uint64_t rohc_time_interval(const struct rohc_ts begin,
                                          const struct rohc_ts end)
{
	uint64_t interval;

	interval = end.sec - begin.sec; /* difference btw seconds */
	interval *= 1e9;                /* convert in nanoseconds */
	interval += end.nsec;           /* additional end nanoseconds */
	interval -= begin.nsec;         /* superfluous begin nanoseconds */
	interval /= 1e3;

	return interval;
}

#endif

