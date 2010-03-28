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
 */

#ifndef ROHC_TIME_H
#define ROHC_TIME_H

#include <sys/time.h>


/**
 * @brief Get the current time in microseconds
 *
 * @return The current time in microseconds
 */
static inline unsigned int get_microseconds(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}


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


#endif

