/*
 * Copyright 2012,2013 Didier Barvaux
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
 * @file   rohc_utils.h
 * @brief  Miscellaneous utils for ROHC libraries
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_UTILS_H
#define ROHC_UTILS_H

#include <stdint.h>
#include <stdbool.h>


/** TODO */
typedef enum
{
	ROHC_TRISTATE_NONE = 0,
	ROHC_TRISTATE_YES  = 1,
	ROHC_TRISTATE_NO   = 2,
} rohc_tristate_t;


/** Get the max value of the 2 given */
#define rohc_max(value1, value2) \
	( ((value1) >= (value2)) ? (value1) : (value2) )

/** Get the max value of the 2 given */
#define rohc_min(value1, value2) \
	( ((value1) <= (value2)) ? (value1) : (value2) )


static inline unsigned int rohc_b2u(const bool boolean)
	__attribute__((warn_unused_result, const));

uint32_t rohc_ntoh32(const uint32_t net32)
	__attribute__((warn_unused_result, const));
uint16_t rohc_ntoh16(const uint16_t net16)
	__attribute__((warn_unused_result, const));
uint32_t rohc_hton32(const uint32_t host32)
	__attribute__((warn_unused_result, const));
uint16_t rohc_hton16(const uint16_t host16)
	__attribute__((warn_unused_result, const));


/**
 * @brief Convert the given boolean value to one unsigned integer
 *
 * true is converted to 1 ; false is converted to 0
 *
 * @param boolean  The boolean value to convert
 * @return         The converted unsigned integer value
 */
static inline unsigned int rohc_b2u(const bool boolean)
{
	return (boolean ? 1 : 0);
}

#endif

