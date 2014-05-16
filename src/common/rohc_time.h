/*
 * Copyright 2013,2014 Didier Barvaux
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

/**
 * @file    rohc_time.h
 * @brief   ROHC public definitions related to time
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_TIME_H
#define ROHC_TIME_H

#ifdef __cplusplus
extern "C"
{
#endif

/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
	#define ROHC_EXPORT __declspec(dllexport)
#else
	#define ROHC_EXPORT
#endif

#include <stdint.h>


/**
 * @brief A timestamp for the ROHC library
 *
 * Could be easily created from \e struct \e timespec on UNIX:
 * \code
   struct rohc_ts rohc_ts;
   struct timespec unix_ts;
   ...
   rohc_ts.sec = unix_ts.tv_sec;
   rohc_ts.nsec = unix_ts.tv_nsec;
   ...
\endcode
 *
 * @ingroup rohc
 */
struct rohc_ts
{
	uint64_t sec;   /**< The seconds part of the timestamp */
	uint64_t nsec;  /**< The nanoseconds part of the timestamp */
};

#ifdef __cplusplus
}
#endif

#endif /* ROHC_TIME_H */

