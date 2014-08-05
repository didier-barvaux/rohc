/*
 * Copyright 2011,2012,2013,2014 Didier Barvaux
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
 * @file   schemes/decomp_wlsb.c
 * @brief  Window-based Least Significant Bits (W-LSB) decoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "decomp_wlsb.h"
#include "interval.h" /* for the rohc_f_32bits() function */

#ifndef __KERNEL__
#  include <string.h>
#endif
#include <assert.h>


/*
 * Private structures and types
 */

/**
 * @brief The Least Significant Bits (LSB) decoding object
 *
 * See RFC 3095, §4.5.1
 */
struct rohc_lsb_decode
{
	bool is_init;         /**< Whether the reference value was initialized */
	rohc_lsb_shift_t p;   /**< The p shift parameter */
	size_t max_len;       /**< The max length (in bits) of the uncomp. field */

	/** The reference values (ref -1 and ref 0) */
	uint32_t v_ref_d[ROHC_LSB_REF_MAX];
};


/*
 * Private functions
 */

static bool rohc_lsb_decode32(const struct rohc_lsb_decode *const lsb,
                              const rohc_lsb_ref_t ref_type,
                              const uint32_t v_ref_d_offset,
                              const uint32_t m,
                              const size_t k,
                              const rohc_lsb_shift_t p,
                              uint32_t *const decoded)
	__attribute__((nonnull(1, 7), warn_unused_result));

static bool rohc_lsb_decode16(const struct rohc_lsb_decode *const lsb,
                              const rohc_lsb_ref_t ref_type,
                              const uint16_t v_ref_d_offset,
                              const uint16_t m,
                              const size_t k,
                              const rohc_lsb_shift_t p,
                              uint16_t *const decoded)
	__attribute__((nonnull(1, 7), warn_unused_result));


/*
 * Public functions
 */

/**
 * @brief Create a new Least Significant Bits (LSB) decoding context
 *
 * See 4.5.1 in the RFC 3095 for details about LSB encoding.
 *
 * @param p        The p value used to efficiently encode/decode the values
 * @param max_len  The max length (in bits) of the non-compressed field
 * @return         The new LSB decoding context in case of success, NULL
 *                 otherwise
 */
struct rohc_lsb_decode * rohc_lsb_new(const rohc_lsb_shift_t p,
                                      const size_t max_len)
{
	struct rohc_lsb_decode *lsb;

	assert(max_len == 16 || max_len == 32);

	lsb = malloc(sizeof(struct rohc_lsb_decode));
	if(lsb != NULL)
	{
		lsb->p = p;
		lsb->max_len = max_len;
		lsb->is_init = false;
	}

	return lsb;
}


/**
 * @brief Destroy a given Least Significant Bits (LSB) decoding context
 *
 * See 4.5.1 in the RFC 3095 for details about LSB encoding.
 *
 * @param lsb  The LSB decoding context to destroy
 */
void rohc_lsb_free(struct rohc_lsb_decode *const lsb)
{
	free(lsb);
}


/**
 * @brief Get the shift parameter p of the LSB decoding context
 *
 * @param lsb  The LSB object used to decode
 * @return     The shift parameter p
 */
rohc_lsb_shift_t lsb_get_p(const struct rohc_lsb_decode *const lsb)
{
	assert(lsb != NULL);
	return lsb->p;
}


/**
 * @brief Decode a LSB-encoded value
 *
 * See 4.5.1 in the RFC 3095 for details about LSB encoding.
 *
 * @param lsb             The LSB object used to decode
 * @param ref_type        The reference value to use to decode
 *                        (used for context repair upon CRC failure)
 * @param v_ref_d_offset  The offset to apply on v_ref_d
 *                        (used for context repair upon CRC failure)
 * @param m               The LSB value to decode
 * @param k               The length of the LSB value to decode
 * @param p               The shift value p used to efficiently encode/decode
 *                        the values
 * @param decoded         OUT: The decoded value
 * @return                true in case of success, false otherwise
 */
bool rohc_lsb_decode(const struct rohc_lsb_decode *const lsb,
                     const rohc_lsb_ref_t ref_type,
                     const uint32_t v_ref_d_offset,
                     const uint32_t m,
                     const size_t k,
                     const rohc_lsb_shift_t p,
                     uint32_t *const decoded)
{
	bool is_success;

	assert(lsb != NULL);
	assert(lsb->is_init == true);
	assert(decoded != NULL);
	assert(ref_type == ROHC_LSB_REF_MINUS_1 || ref_type == ROHC_LSB_REF_0);

	if(lsb->max_len == 16)
	{
		uint16_t decoded16 = 0; /* initialized for GCC 4.0.x */

		assert(lsb->max_len == 16);
		assert(k <= 16);

		is_success = rohc_lsb_decode16(lsb, ref_type, v_ref_d_offset, m, k, p,
		                               &decoded16);
		if(is_success)
		{
			*decoded = ((uint32_t) decoded16) & 0xffff;
		}
	}
	else /* 32-bit value */
	{
		assert(lsb->max_len == 32);
		assert(k <= 32);

		is_success = rohc_lsb_decode32(lsb, ref_type, v_ref_d_offset, m, k, p,
		                               decoded);
	}

	return is_success;
}


/**
 * @brief Decode a 32-bit LSB-encoded value
 *
 * See 4.5.1 in the RFC 3095 for details about LSB encoding.
 *
 * @param lsb             The LSB object used to decode
 * @param ref_type        The reference value to use to decode
 *                        (used for context repair upon CRC failure)
 * @param v_ref_d_offset  The offset to apply on v_ref_d
 *                        (used for context repair upon CRC failure)
 * @param m               The LSB value to decode
 * @param k               The length of the LSB value to decode
 * @param p               The shift value p used to efficiently encode/decode
 *                        the values
 * @param decoded         OUT: The decoded value
 * @return                true in case of success, false otherwise
 */
static bool rohc_lsb_decode32(const struct rohc_lsb_decode *const lsb,
                              const rohc_lsb_ref_t ref_type,
                              const uint32_t v_ref_d_offset,
                              const uint32_t m,
                              const size_t k,
                              const rohc_lsb_shift_t p,
                              uint32_t *const decoded)
{
	struct rohc_interval32 interval;
	uint32_t decoded_value;
	uint32_t try;
	uint32_t mask;
	bool is_found = false;

	/* compute the mask for k bits (and avoid integer overflow) */
	if(k == 32)
	{
		mask = 0xffffffff;
	}
	else
	{
		mask = ((1 << k) - 1);
	}
	assert((m & mask) == m);

	/* determine the interval in which the decoded value should be present */
	interval = rohc_f_32bits(lsb->v_ref_d[ref_type] + v_ref_d_offset, k, p);

	/* search the value that matches the k lower bits of the value m to decode */
	if(interval.min <= interval.max)
	{
		/* the interpretation interval does not straddle the field boundaries */

		/* find the minimum value in the interval [min ; max] with the same k LSB
		 * bits as m */
		try = (interval.min & (~mask)) | m;
		if((interval.min & mask) > m)
		{
			/* value is not in the interval (lower than min), try next value */
			try += mask + 1;
		}
		if(try >= interval.min && try <= interval.max)
		{
			/* value is in the interval: corresponding value found */
			is_found = true;
			decoded_value = try;
		}
	}
	else
	{
		/* the interpretation interval does straddle the field boundaries */

		/* find the first value in the interval [min ; max] with the same
		 * k LSB bits as m */
		try = (interval.min & (~mask)) | m;
		if((interval.min & mask) > m)
		{
			/* value is not in the interval (lower than min), try next value */
			try += mask + 1;
		}
		if(try >= interval.min || try <= interval.max)
		{
			/* value is in the interval: corresponding value found */
			is_found = true;
			decoded_value = try;
		}
	}

	if(is_found)
	{
		assert((decoded_value & mask) == m);
		memcpy(decoded, &decoded_value, sizeof(uint32_t));
	}

	return is_found;
}


/**
 * @brief Decode a 16-bit LSB-encoded value
 *
 * See \ref rohc_lsb_decode32 for details.
 *
 * @param lsb             The LSB object used to decode
 * @param ref_type        The reference value to use to decode
 *                        (used for context repair upon CRC failure)
 * @param v_ref_d_offset  The offset to apply on v_ref_d
 *                        (used for context repair upon CRC failure)
 * @param m               The LSB value to decode
 * @param k               The length of the LSB value to decode
 * @param p               The shift value p used to efficiently encode/decode
 *                        the values
 * @param decoded         OUT: The decoded value
 * @return                true in case of success, false otherwise
 */
static bool rohc_lsb_decode16(const struct rohc_lsb_decode *const lsb,
                              const rohc_lsb_ref_t ref_type,
                              const uint16_t v_ref_d_offset,
                              const uint16_t m,
                              const size_t k,
                              const rohc_lsb_shift_t p,
                              uint16_t *const decoded)
{
	uint32_t m32;
	uint32_t decoded32;
	bool is_success;

	m32 = ((uint32_t) m) & 0xffff;

	is_success = rohc_lsb_decode32(lsb, ref_type, v_ref_d_offset, m32, k, p,
	                               &decoded32);
	if(is_success)
	{
		*decoded = (uint16_t) (decoded32 & 0xffff);
	}

	return is_success;
}


/**
 * @brief Update the LSB reference value
 *
 * This function is called after a CRC success to update the last decoded
 * value (for example, the SN value). See 4.5.1 in the RFC 3095 for details
 * about LSB encoding.
 *
 * @param lsb               The LSB object
 * @param v_ref_d           The new reference value
 * @param keep_ref_minus_1  Keep ref -1 unchanged (used for SN context repair
 *                          after CRC failure, see RFC3095 §5.3.2.2.5)
 */
void rohc_lsb_set_ref(struct rohc_lsb_decode *const lsb,
                      const uint32_t v_ref_d,
                      const bool keep_ref_minus_1)
{
	/* replace ref -1 by ref 0 if not doing context repair */
	if(!keep_ref_minus_1)
	{
		lsb->v_ref_d[ROHC_LSB_REF_MINUS_1] = lsb->v_ref_d[ROHC_LSB_REF_0];
	}

	/* always replace ref 0 by new value */
	lsb->v_ref_d[ROHC_LSB_REF_0] = v_ref_d;

	lsb->is_init = true;
}


/**
 * @brief Get the current LSB reference value (ref 0)
 *
 * @param lsb       The LSB object
 * @param ref_type  The reference value to retrieve
 * @return          The current reference value
 */
uint32_t rohc_lsb_get_ref(const struct rohc_lsb_decode *const lsb,
                          const rohc_lsb_ref_t ref_type)
{
	assert(lsb != NULL);
	assert(lsb->is_init == true);
	assert(ref_type == ROHC_LSB_REF_MINUS_1 || ref_type == ROHC_LSB_REF_0);
	return lsb->v_ref_d[ref_type];
}

