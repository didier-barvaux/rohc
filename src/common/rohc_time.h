/*
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

#ifndef __KERNEL__
#	include <sys/time.h>
#endif

#ifndef __KERNEL__

/**
 * @brief Get the current time in milliseconds
 *
 * @return The current time in milliseconds
 */
static inline unsigned int get_milliseconds(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

#else /* __KERNEL__ */

/**
 * @brief Get the current time in milliseconds
 *
 * @return The current time in milliseconds
 */
static inline unsigned int get_milliseconds(void)
{
	struct timespec ts;
	ktime_get_ts(&ts);
	return ts.tv_sec * MSEC_PER_SEC + ts.tv_nsec / NSEC_PER_MSEC;
}

#endif /* __KERNEL__ */

#endif

