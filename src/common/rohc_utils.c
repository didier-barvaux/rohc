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
 * @file   rohc_utils.c
 * @brief  Miscellaneous utils for ROHC libraries
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_utils.h"

#include "config.h" /* for WORDS_BIGENDIAN */


/*
 * Prototypes of private functions
 */

static inline uint32_t bswap32(const uint32_t value) __attribute__((const));
static inline uint16_t bswap16(const uint16_t value) __attribute__((const));


/*
 * Definitions of public functions
 */


/**
 * @brief Convert a 32-bit long integer from network to host byte orders
 *
 * @param netlong  The 32-bit long integer in network byte order
 * @return         The 32-bit long integer converted in host byte order
 */
uint32_t ntohl(const uint32_t netlong)
{
#if WORDS_BIGENDIAN == 1
	return netlong;
#else
	return bswap32(netlong);
#endif
}


/**
 * @brief Convert a 16-bit short integer from network to host byte orders
 *
 * @param netshort  The 16-bit short integer in network byte order
 * @return          The 16-bit short integer converted in host byte order
 */
uint16_t ntohs(const uint16_t netshort)
{
#if WORDS_BIGENDIAN == 1
	return netshort;
#else
	return bswap16(netshort);
#endif

}


/**
 * @brief Convert a 32-bit long integer from host to network byte orders
 *
 * @param hostlong  The 32-bit long integer in host byte order
 * @return          The 32-bit long integer converted in network byte order
 */
uint32_t htonl(const uint32_t hostlong)
{
#if WORDS_BIGENDIAN == 1
	return hostlong;
#else
	return bswap32(hostlong);
#endif
}


/**
 * @brief Convert a 16-bit short integer from host to network byte orders
 *
 * @param hostshort  The 16-bit short integer in host byte order
 * @return           The 16-bit short integer converted in network byte order
 */
uint16_t htons(const uint16_t hostshort)
{
#if WORDS_BIGENDIAN == 1
	return hostshort;
#else
	return bswap16(hostshort);
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
static uint32_t bswap32(const uint32_t value)
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
static uint16_t bswap16(const uint16_t value)
{
	return (((value >> 8) & 0xff) | ((value & 0xff) << 8));
}

