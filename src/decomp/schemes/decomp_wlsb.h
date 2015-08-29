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

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#ifdef __KERNEL__
#  include <linux/types.h>
#else
#  include <stdbool.h>
#endif


/* The definition of the Least Significant Bits decoding object is private */
struct rohc_lsb_decode;


/** The different reference values for LSB decoding */
typedef enum
{
	ROHC_LSB_REF_MINUS_1 = 0,  /**< Use the 'ref -1' reference value */
	ROHC_LSB_REF_0       = 1,  /**< Use the 'ref 0' reference value */
	ROHC_LSB_REF_MAX           /**< The number of different reference values */

} rohc_lsb_ref_t;


/** The context to parse and decode one LSB-encoded 32-bit field */
struct rohc_lsb_field32
{
	uint32_t bits;        /**< The bits extracted from the ROHC packet */
	size_t bits_nr;       /**< The number of bits extracted from the ROHC packet */
	rohc_lsb_shift_t p;   /**< The LSB shift parameter to decode extracted bits */
};


/** The context to parse and decode one LSB-encoded 16-bit field */
struct rohc_lsb_field16
{
	uint16_t bits;        /**< The bits extracted from the ROHC packet */
	size_t bits_nr;       /**< The number of bits extracted from the ROHC packet */
	rohc_lsb_shift_t p;   /**< The LSB shift parameter to decode extracted bits */
};


/** The context to parse and decode one LSB-encoded 8-bit field */
struct rohc_lsb_field8
{
	uint8_t bits;         /**< The bits extracted from the ROHC packet */
	size_t bits_nr;       /**< The number of bits extracted from the ROHC packet */
	rohc_lsb_shift_t p;   /**< The LSB shift parameter to decode extracted bits */
};


/*
 * Function prototypes
 */

struct rohc_lsb_decode * rohc_lsb_new(const size_t max_len)
	__attribute__((warn_unused_result));

void rohc_lsb_free(struct rohc_lsb_decode *const lsb)
	__attribute__((nonnull(1)));

bool rohc_lsb_is_ready(const struct rohc_lsb_decode *const lsb)
	__attribute__((warn_unused_result, nonnull(1), pure));

bool rohc_lsb_decode(const struct rohc_lsb_decode *const lsb,
                     const rohc_lsb_ref_t ref_type,
                     const uint32_t v_ref_d_offset,
                     const uint32_t m,
                     const size_t k,
                     const rohc_lsb_shift_t p,
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

