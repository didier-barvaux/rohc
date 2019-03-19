/*
 * Copyright 2011,2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010,2013 Viveris Technologies
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
 * @file   schemes/decomp_wlsb.h
 * @brief  Window-based Least Significant Bits (W-LSB) decoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_SCHEMES_WLSB_H
#define ROHC_DECOMP_SCHEMES_WLSB_H

#include "interval.h" /* for rohc_lsb_shift_t */
#include "rohc_internal.h" /* for bits_nr_t */

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


/*
 * Public structures and types
 */


/** The different reference values for LSB decoding */
typedef enum
{
	ROHC_LSB_REF_MINUS_1 = 0,  /**< Use the 'ref -1' reference value */
	ROHC_LSB_REF_0       = 1,  /**< Use the 'ref 0' reference value */
	ROHC_LSB_REF_MAX           /**< The number of different reference values */

} rohc_lsb_ref_t;


/**
 * @brief The Least Significant Bits (LSB) decoding object
 *
 * See RFC 3095, §4.5.1
 */
struct rohc_lsb_decode
{
	/** The reference values (ref -1 and ref 0) */
	uint32_t v_ref_d[ROHC_LSB_REF_MAX];

	bool is_init;         /**< Whether the reference value was initialized */
	uint8_t max_len;      /**< The max length (in bits) of the uncomp. field */
	uint8_t unused[6];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct rohc_lsb_decode, v_ref_d) % 8) == 0,
               "v_ref_d in rohc_lsb_decode should be aligned on 8 bytes");
_Static_assert((sizeof(struct rohc_lsb_decode) % 8) == 0,
               "rohc_lsb_decode length should be multiple of 8 bytes");
#endif


/** The context to parse and decode one LSB-encoded 32-bit field */
struct rohc_lsb_field32
{
	int32_t p;          /**< The LSB shift parameter to decode extracted bits */
	uint32_t bits;      /**< The bits extracted from the ROHC packet */
	bits_nr_t bits_nr;  /**< The number of bits extracted from the ROHC packet */
	uint8_t unused[7];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((sizeof(struct rohc_lsb_field32) % 8) == 0,
               "rohc_lsb_field32 length should be multiple of 8 bytes");
#endif


/** The context to parse and decode one LSB-encoded 16-bit field */
struct rohc_lsb_field16
{
	int32_t p;          /**< The LSB shift parameter to decode extracted bits */
	uint16_t bits;      /**< The bits extracted from the ROHC packet */
	bits_nr_t bits_nr;  /**< The number of bits extracted from the ROHC packet */
	uint8_t unused[1];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((sizeof(struct rohc_lsb_field16) % 8) == 0,
               "rohc_lsb_field16 length should be multiple of 8 bytes");
#endif


/** The context to parse and decode one LSB-encoded 8-bit field */
struct rohc_lsb_field8
{
	int32_t p;          /**< The LSB shift parameter to decode extracted bits */
	uint8_t bits;       /**< The bits extracted from the ROHC packet */
	bits_nr_t bits_nr;  /**< The number of bits extracted from the ROHC packet */
	uint8_t unused[2];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((sizeof(struct rohc_lsb_field8) % 8) == 0,
               "rohc_lsb_field8 length should be multiple of 8 bytes");
#endif


/*
 * Function prototypes
 */

void rohc_lsb_init(struct rohc_lsb_decode *const lsb, const size_t max_len)
	__attribute__((nonnull(1)));

bool rohc_lsb_is_ready(const struct rohc_lsb_decode *const lsb)
	__attribute__((warn_unused_result, nonnull(1), pure));

bool rohc_lsb_decode(const struct rohc_lsb_decode *const lsb,
                     const rohc_lsb_ref_t ref_type,
                     const uint32_t v_ref_d_offset,
                     const uint32_t m,
                     const size_t k,
                     const int32_t p,
                     uint32_t *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 7)));

void rohc_lsb_set_ref(struct rohc_lsb_decode *const lsb,
                      const uint32_t v_ref_d,
                      const bool keep_ref_minus_1)
	__attribute__((nonnull(1)));

uint32_t rohc_lsb_get_ref(const struct rohc_lsb_decode *const lsb,
                          const rohc_lsb_ref_t ref_type)
	__attribute__((nonnull(1), warn_unused_result));

#endif

