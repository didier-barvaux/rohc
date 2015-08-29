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
 * @file   rohc_utils.c
 * @brief  Miscellaneous utils for ROHC libraries
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_utils.h"

#ifdef __KERNEL__
#  include <endian.h>
#else
#  include "config.h" /* for WORDS_BIGENDIAN */
#endif


/*
 * Prototypes of private functions
 */

static inline uint32_t rohc_bswap32(const uint32_t value)
	__attribute__((const));
static inline uint16_t rohc_bswap16(const uint16_t value)
	__attribute__((const));


/*
 * Definitions of public functions
 */


/**
 * @brief Convert a 32-bit long integer from network to host byte orders
 *
 * @param net32  The 32-bit long integer in network byte order
 * @return       The 32-bit long integer converted in host byte order
 */
uint32_t rohc_ntoh32(const uint32_t net32)
{
#if WORDS_BIGENDIAN == 1
	return net32;
#else
	return rohc_bswap32(net32);
#endif
}


/**
 * @brief Convert a 16-bit short integer from network to host byte orders
 *
 * @param net16  The 16-bit short integer in network byte order
 * @return       The 16-bit short integer converted in host byte order
 */
uint16_t rohc_ntoh16(const uint16_t net16)
{
#if WORDS_BIGENDIAN == 1
	return net16;
#else
	return rohc_bswap16(net16);
#endif

}


/**
 * @brief Convert a 32-bit long integer from host to network byte orders
 *
 * @param host32  The 32-bit long integer in host byte order
 * @return        The 32-bit long integer converted in network byte order
 */
uint32_t rohc_hton32(const uint32_t host32)
{
#if WORDS_BIGENDIAN == 1
	return host32;
#else
	return rohc_bswap32(host32);
#endif
}


/**
 * @brief Convert a 16-bit short integer from host to network byte orders
 *
 * @param host16  The 16-bit short integer in host byte order
 * @return        The 16-bit short integer converted in network byte order
 */
uint16_t rohc_hton16(const uint16_t host16)
{
#if WORDS_BIGENDIAN == 1
	return host16;
#else
	return rohc_bswap16(host16);
#endif
}


/*
 * Definitions of private functions
 */


/**
 * @brief Swap bytes of the given 32-bit integer
 *
 * @param value  The 32-bit value to swap byte for
 * @return       The 32-bit value with swapped bytes
 */
static uint32_t rohc_bswap32(const uint32_t value)
{
	return (((value & 0xff000000) >> 24) |
	        ((value & 0x00ff0000) >>  8) |
	        ((value & 0x0000ff00) <<  8) |
	        ((value & 0x000000ff) << 24));
}


/**
 * @brief Swap bytes of the given 16-bit integer
 *
 * @param value  The 16-bit value to swap byte for
 * @return       The 16-bit value with swapped bytes
 */
static uint16_t rohc_bswap16(const uint16_t value)
{
	return (((value >> 8) & 0xff) | ((value & 0xff) << 8));
}

