/*
 * Copyright 2013,2014 Didier Barvaux
 * Copyright 2010,2013 Viveris Technologies
 * Copyright 2009,2010 Thales Communications
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
 * @file    rohc_time_internal.h
 * @brief   ROHC internal functions related to time
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author  Thales Communications
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_TIME_INTERNAL_H
#define ROHC_TIME_INTERNAL_H

#include "rohc_math64.h"
#include "rohc_time.h" /* for public definition of struct rohc_ts */

#ifndef __KERNEL__
#  include <sys/time.h>
#endif


static inline uint64_t rohc_time_interval(const struct rohc_ts begin,
                                          const struct rohc_ts end)
	__attribute__((warn_unused_result, const));


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
	interval *= 1000000000UL;       /* convert in nanoseconds */
	interval += end.nsec;           /* additional end nanoseconds */
	interval -= begin.nsec;         /* superfluous begin nanoseconds */
	rohc_do_div(interval, 1000UL);  /* convert in microseconds */

	return interval;
}


#endif /* ROHC_TIME_INTERNAL_H */

