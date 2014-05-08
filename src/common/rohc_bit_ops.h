/*
 * Copyright 2010,2012,2013 Didier Barvaux
 * Copyright 2013 Viveris Technologies
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file    rohc_bit_ops.h
 * @brief   Bitwised operations for ROHC compression/decompression
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_BIT_OPS_H
#define ROHC_BIT_OPS_H

#ifdef __KERNEL__
#	include <endian.h>
#else
#	include "config.h" /* for WORDS_BIGENDIAN */
#endif


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
 * @brief Convert GET_BIT_* values to boolean
 *
 * example: GET_BOOL(GET_BIT_5(data_ptr));
 */
#define GET_BOOL(x)  ((x) ? true : false)


/**
 * @brief Get the next 16 bits at the given memory location
 *        in Network Byte Order
 */
#if WORDS_BIGENDIAN == 1
	#define GET_NEXT_16_BITS(x) \
		((((*(x)) << 8) & 0xff00) | ((*((x) + 1)) & 0x00ff))
#else
	#define GET_NEXT_16_BITS(x) \
		((((*((x) + 1)) << 8) & 0xff00) | ((*(x)) & 0x00ff))
#endif


/** Append new LSB bits to already extracted bits */
#define APPEND_BITS(field_descr, ext_no, field, field_nr, bits, bits_nr, max) \
	do \
	{ \
		/* ensure not to eval variables several times */ \
		const typeof(bits) _bits = (bits); \
		const size_t _bits_nr = (bits_nr); \
		const size_t _max = (max); \
		/* print a description of what we do */ \
		rohc_decomp_debug(context, \
		                  "%zd bits of " #field_descr " found in %s = 0x%x\n", \
		                  (_bits_nr), rohc_get_ext_descr(ext_no), (_bits)); \
		/* is there enough room for all existing and new bits? */ \
		if(((field_nr) + (_bits_nr)) <= (_max)) \
		{ \
			/* enough room: make and clear room, copy LSB */ \
			field <<= (_bits_nr); \
			field &= ~((1 << (_bits_nr)) - 1); \
			field |= (_bits); \
			field_nr += (_bits_nr); \
		} \
		else \
		{ \
			/* not enough room: drop some MSB */ \
			typeof(field) _mask; \
			assert((_bits_nr) > 0); \
			assert((_bits_nr) <= (_max)); \
			/* remove extra MSB (warn if dropped MSB are non-zero) */ \
			_mask = (1 << ((_max) - (_bits_nr))) - 1; \
			if((field & _mask) != field) \
			{ \
				rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id, \
				          "too many bits for " #field_descr ": %zd bits " \
				          "found in %s, and %zd bits already found before " \
				          "for a %zd-bit field\n", (_bits_nr), \
				          rohc_get_ext_descr(ext_no), (field_nr), (_max)); \
			} \
			field &= _mask; \
			/* make room and clear that room for new LSB */ \
			field <<= (_bits_nr); \
			field &= ~((1 << (_bits_nr)) - 1); \
			/* add new LSB */ \
			field |= (_bits); \
			field_nr = (_max); \
		} \
	} \
	while(0)

/** SN: append new LSB bits to already extracted bits */
#define APPEND_SN_BITS(ext_no, base, bits, bits_nr) \
	APPEND_BITS(SN, ext_no, \
	            (base)->sn, (base)->sn_nr, \
	            (bits), (bits_nr), 32)

/** Outer IP-ID: append new LSB bits to already extracted bits */
#define APPEND_OUTER_IP_ID_BITS(ext_no, base, bits, bits_nr) \
	APPEND_BITS(outer IP-ID, ext_no, \
	            (base)->outer_ip.id, (base)->outer_ip.id_nr, \
	            (bits), (bits_nr), 16)

/** Inner IP-ID: append new LSB bits to already extracted bits */
#define APPEND_INNER_IP_ID_BITS(ext_no, base, bits, bits_nr) \
	APPEND_BITS(inner IP-ID, ext_no, \
	            (base)->inner_ip.id, (base)->inner_ip.id_nr, \
	            (bits), (bits_nr), 16)

/** TS: append new LSB bits to already extracted bits */
#define APPEND_TS_BITS(ext_no, base, bits, bits_nr) \
	APPEND_BITS(TS, ext_no, \
	            (base)->ts, (base)->ts_nr, \
	            (bits), (bits_nr), 32)

#endif

