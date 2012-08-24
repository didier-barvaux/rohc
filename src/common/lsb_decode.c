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
 * @file   lsb_decode.c
 * @brief  Least Significant Bits (LSB) decoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#include "lsb_decode.h"
#include "interval.h" /* for the rohc_f_32bits() function */

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
	bool is_init;        /**< Whether the reference value was initialized */
	uint32_t v_ref_d;    /**< The reference value */
	rohc_lsb_shift_t p;  /**< The p shift parameter */
};


/*
 * Public functions
 */

/**
 * @brief Create a new Least Significant Bits (LSB) decoding context
 *
 * See 4.5.1 in the RFC 3095 for details about LSB encoding.
 *
 * @param p        The p value used to efficiently encode/decode the values
 * @return         The new LSB decoding context in case of success, NULL
 *                 otherwise
 */
struct rohc_lsb_decode * rohc_lsb_new(const rohc_lsb_shift_t p)
{
	struct rohc_lsb_decode *lsb;

	lsb = malloc(sizeof(struct rohc_lsb_decode));
	if(lsb != NULL)
	{
		lsb->p = p;
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
	assert(lsb != NULL);
	free(lsb);
}


/**
 * @brief Decode a 32-bit LSB-encoded value
 *
 * See 4.5.1 in the RFC 3095 for details about LSB encoding.
 *
 * @param lsb      The LSB object used to decode
 * @param m        The LSB value to decode
 * @param k        The length of the LSB value to decode
 * @param decoded  OUT: The decoded value
 * @return         true in case of success, false otherwise
 */
bool rohc_lsb_decode32(const struct rohc_lsb_decode *const lsb,
                       const uint32_t m,
                       const size_t k,
                       uint32_t *const decoded)
{
	uint32_t min;
	uint32_t max;
	uint32_t try;
	uint32_t mask;
	bool is_found = false;

	assert(lsb != NULL);
	assert(lsb->is_init == true);
	assert(k <= 32);
	assert(decoded != NULL);

	/* compute the mask for k bits (and avoid integer overflow) */
	if(k == 32)
	{
		mask = 0xffffffff;
	}
	else
	{
		mask = ((1 << k) - 1);
	}

	/* determine the interval in which the decoded value should be present */
	rohc_f_32bits(lsb->v_ref_d, k, lsb->p, &min, &max);

	/* search the value that matches the k lower bits of the value m to decode:
	   try all values from the interval starting from the smallest one */
	if(min <= max)
	{
		/* the interpretation interval does not straddle the field boundaries */
		for(try = min; try <= max; try++)
		{
			if((try & mask) == (m & mask))
			{
				/* corresponding value found */
				is_found = true;
				*decoded = try;
				break;
			}
		}
	}
	else
	{
		/* the interpretation interval does straddle the field boundaries:
		 * search in the first part of the interval */
		for(try = min; try <= 0xffffffff; try++)
		{
			if((try & mask) == (m & mask))
			{
				/* corresponding value found */
				is_found = true;
				*decoded = try;
				break;
			}
		}
		/* then, if not successful, search in the last part of the interval */
		if(!is_found)
		{
			for(try = 0; try <= max; try++)
			{
				if((try & mask) == (m & mask))
				{
					/* corresponding value found */
					is_found = true;
					*decoded = try;
					break;
				}
			}
		}
	}

	return is_found;
}


/**
 * @brief Decode a 16-bit LSB-encoded value
 *
 * See \ref rohc_lsb_decode32 for details.
 *
 * @param lsb      The LSB object used to decode
 * @param m        The LSB value to decode
 * @param k        The length of the LSB value to decode
 * @param decoded  OUT: The decoded value
 * @return         true in case of success, false otherwise
 */
bool rohc_lsb_decode16(const struct rohc_lsb_decode *const lsb,
                       const uint16_t m,
                       const size_t k,
                       uint16_t *const decoded)
{
	uint32_t m32;
	uint32_t decoded32;
	bool is_success;

	assert(lsb != NULL);
	assert(lsb->is_init == true);
	assert(k <= 16);
	assert(decoded != NULL);

	m32 = ((uint32_t) m) & 0xffff;

	is_success = rohc_lsb_decode32(lsb, m32, k, &decoded32);
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
 * @param lsb     The LSB object
 * @param v_ref_d The new reference value
 */
void rohc_lsb_set_ref(struct rohc_lsb_decode *const lsb,
                      const uint32_t v_ref_d)
{
	assert(lsb != NULL);
	lsb->v_ref_d = v_ref_d;
	lsb->is_init = true;
}


/**
 * @brief Get the current LSB reference value
 *
 * @param lsb  The LSB object
 * @return     The current reference value
 */
uint32_t rohc_lsb_get_ref(struct rohc_lsb_decode *const lsb)
{
	assert(lsb->is_init == true);
	return lsb->v_ref_d;
}

