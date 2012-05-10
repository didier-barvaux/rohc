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
 * @file    rohc_bit_ops.h
 * @brief   Bitwised operations for ROHC compression/decompression
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author  The hackers from ROHC for Linux
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_BIT_OPS_H
#define ROHC_BIT_OPS_H

#include <endian.h>


/*
 * GET_BIT_n(x) macros: extract the (n+1) th bit from byte x starting from
 *                      the right and do not right-shift it
 */

#define GET_BIT_0(x)  ((*(x)) & 0x01)
#define GET_BIT_1(x)  ((*(x)) & 0x02)
#define GET_BIT_2(x)  ((*(x)) & 0x04)
#define GET_BIT_3(x)  ((*(x)) & 0x08)
#define GET_BIT_4(x)  ((*(x)) & 0x10)
#define GET_BIT_5(x)  ((*(x)) & 0x20)
#define GET_BIT_6(x)  ((*(x)) & 0x40)
#define GET_BIT_7(x)  ((*(x)) & 0x80)


/*
 * GET_BIT_0_m(x) macros: extract bits 0 to m included from byte x and do not
 *                        right-shift them
 */

#define GET_BIT_0_2(x)  ((*(x)) & 0x07)
#define GET_BIT_0_4(x)  ((*(x)) & 0x1f)
#define GET_BIT_0_3(x)  ((*(x)) & 0x0f)
#define GET_BIT_0_5(x)  ((*(x)) & 0x3f)
#define GET_BIT_0_6(x)  ((*(x)) & 0x7f)
#define GET_BIT_0_7(x)  ((*(x)) & 0xff)


/*
 * GET_BIT_n_m(x) macros: extract bits n to m included from byte x and
 *                        right-shift them
 */

#define GET_BIT_1_7(x)  ( ((*(x)) & 0xfe) >> 1 )
#define GET_BIT_3_4(x)  ( ((*(x)) & 0x18) >> 3 )
#define GET_BIT_3_5(x)  ( ((*(x)) & 0x38) >> 3 )
#define GET_BIT_3_6(x)  ( ((*(x)) & 0x78) >> 3 )
#define GET_BIT_3_7(x)  ( ((*(x)) & 0xf8) >> 3 )
#define GET_BIT_4_7(x)  ( ((*(x)) & 0xf0) >> 4 )
#define GET_BIT_5_7(x)  ( ((*(x)) & 0xe0) >> 5 )
#define GET_BIT_6_7(x)  ( ((*(x)) & 0xc0) >> 6 )
#define GET_BIT_4_6(x)  ( ((*(x)) & 0x70) >> 4 )


/**
 * @brief Convert GET_BIT_* values to 0 or 1
 *
 * example: GET_REAL(GET_BIT_5(data_ptr));
 */
#define GET_REAL(x)  ((x) ? 1 : 0)


/**
 * @brief Get the next 16 bits at the given memory location
 *        in Network Byte Order
 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	#define GET_NEXT_16_BITS(x) \
		((((*((x) + 1)) << 8) & 0xff00) | ((*(x)) & 0x00ff))
#elif __BYTE_ORDER == __BIG_ENDIAN
	#define GET_NEXT_16_BITS(x) \
		((((*(x)) << 8) & 0xff00) | ((*((x) + 1)) & 0x00ff))
#else
	#error "Adjust your <bits/endian.h> defines"
#endif


#endif

