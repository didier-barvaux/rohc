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
 * @file   lsb_decode.h
 * @brief  Least Significant Bits (LSB) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#ifndef ROHC_COMMON_LSB_DECODE_H
#define ROHC_COMMON_LSB_DECODE_H

#include "interval.h" /* for rohc_lsb_shift_t */
#include "dllexport.h"

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
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



/*
 * Function prototypes
 */

struct rohc_lsb_decode * ROHC_EXPORT rohc_lsb_new(const rohc_lsb_shift_t p,
																  const size_t max_len)
	__attribute__((warn_unused_result));

void ROHC_EXPORT rohc_lsb_free(struct rohc_lsb_decode *const lsb);

rohc_lsb_shift_t ROHC_EXPORT lsb_get_p(const struct rohc_lsb_decode *const lsb)
	__attribute__((warn_unused_result, nonnull(1), pure));

bool ROHC_EXPORT rohc_lsb_decode(const struct rohc_lsb_decode *const lsb,
                                 const rohc_lsb_ref_t ref_type,
                                 const uint32_t v_ref_d_offset,
                                 const uint32_t m,
                                 const size_t k,
                                 const rohc_lsb_shift_t p,
                                 uint32_t *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 7)));

void ROHC_EXPORT rohc_lsb_set_ref(struct rohc_lsb_decode *const lsb,
                                  const uint32_t v_ref_d,
                                  const bool keep_ref_minus_1)
	__attribute__((nonnull(1)));

uint32_t ROHC_EXPORT rohc_lsb_get_ref(struct rohc_lsb_decode *const lsb,
                                      const rohc_lsb_ref_t ref_type)
	__attribute__((nonnull(1), warn_unused_result));

#endif

