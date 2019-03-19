/*
 * Copyright 2011,2012,2013 Didier Barvaux
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
 * @file interval.c
 * @brief Compute the interpretation interval for LSB and W-LSB encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 */

#include "interval.h"

#include <assert.h>


/**
 * @brief The f function as defined in LSB encoding for 32-bit fields
 *
 * Find out the interval [v_ref - p, v_ref + (2^k - 1) - p] for a given k.
 * See 4.5.1 in the RFC 3095 for details.
 *
 * As stated RFC, the values to be encoded have a finite range and the
 * interpretation interval can straddle the wraparound boundary. So, the min
 * value may be greater than the max value!
 *
 * @param v_ref The reference value
 * @param k     The number of least significant bits of the value that are
 *              transmitted
 * @param p     The shift parameter (may be negative)
 * @return      The computed interval
 */
struct rohc_interval32 rohc_f_32bits(const uint32_t v_ref,
                                     const size_t k,
                                     const int32_t p)
{
	struct rohc_interval32 interval32;
	uint32_t interval_width;

	/* compute the interval width = 2^k - 1 */
	if(k == 32)
	{
		interval_width = 0xffffffff;
	}
	else
	{
		interval_width = (1U << k) - 1; /* (1 << k) = 2^k */
	}

	/* compute the minimal and maximal values of the interval:
	 *   min = v_ref - p
	 *   max = v_ref + interval_with - p
	 *
	 * Straddling the lower and upper wraparound boundaries
	 * is handled without additional operation */
	interval32.min = v_ref - p;
	interval32.max = v_ref + interval_width - p;

	return interval32;
}


/**
 * @brief Get shift parameter p from number of bytes k and reorder ratio
 *
 * @param k              The number of least significant bits of the value
 *                       that are transmitted
 * @param reorder_ratio  The reordering ratio
 * @return               The shift parameter p
 */
int32_t rohc_interval_get_rfc5225_msn_p(const size_t k,
                                        const rohc_reordering_offset_t reorder_ratio)
{
	int32_t p;

	if(reorder_ratio == ROHC_REORDERING_NONE)
	{
		p = 1;
	}
	else if(reorder_ratio == ROHC_REORDERING_QUARTER)
	{
		p = (1 << k) / 4 - 1;
	}
	else if(reorder_ratio == ROHC_REORDERING_HALF)
	{
		p = (1 << k) / 2 - 1;
	}
	else
	{
		assert(reorder_ratio == ROHC_REORDERING_THREEQUARTERS);
		p = (1 << k) * 3 / 4 - 1;
	}

	return p;
}


/**
 * @brief Get shift parameter p from number of bytes k for ip_id_lsb 
 *
 * @param k  The number of least significant bits of the value
 *           that are transmitted
 * @return   The shift parameter p
 */
int32_t rohc_interval_get_rfc5225_id_id_p(const size_t k)
{
	return ((1 << k) / 4 - 1);
}

