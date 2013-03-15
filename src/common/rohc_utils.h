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
 * @file   rohc_utils.h
 * @brief  Miscellaneous utils for ROHC libraries
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_UTILS_H
#define ROHC_UTILS_H

#include <stdint.h>

#include "dllexport.h"

/** Get the max value of the 2 given */
#define rohc_max(value1, value2) \
	( ((value1) >= (value2)) ? (value1) : (value2) )

/** Get the max value of the 2 given */
#define rohc_min(value1, value2) \
	( ((value1) <= (value2)) ? (value1) : (value2) )

#ifndef __KERNEL__
uint32_t ROHC_EXPORT ntohl(const uint32_t netlong) __attribute__((const));
uint16_t ROHC_EXPORT ntohs(const uint16_t netshort) __attribute__((const));
uint32_t ROHC_EXPORT htonl(const uint32_t hostlong) __attribute__((const));
uint16_t ROHC_EXPORT htons(const uint16_t hostshort) __attribute__((const));
#endif

#endif

