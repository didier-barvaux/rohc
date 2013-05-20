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
 * a32 with this program; if not, write to the Free Software
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

uint32_t ROHC_EXPORT rohc_ntoh32(const uint32_t net32)
	__attribute__((const));
uint16_t ROHC_EXPORT rohc_ntoh16(const uint16_t net16)
	__attribute__((const));
uint32_t ROHC_EXPORT rohc_hton32(const uint32_t host32)
	__attribute__((const));
uint16_t ROHC_EXPORT rohc_hton16(const uint16_t host16)
	__attribute__((const));

#endif

