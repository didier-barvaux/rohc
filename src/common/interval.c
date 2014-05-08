/*
 * Copyright 2011,2012,2013 Didier Barvaux
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
 * @file interval.c
 * @brief Compute the interpretation interval for LSB and W-LSB encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 */

#include "interval.h"

#include <assert.h>


/**
 * @brief The f function as defined in LSB encoding for 16-bit fields
 *
 * Find out the interval \f$[v\_ref - p, v\_ref + (2^k - 1) - p]\f$ for a
 * given k. See 4.5.1 in the RFC 3095 for details.
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
struct rohc_interval16 rohc_f_16bits(const uint16_t v_ref,
                                     const size_t k,
                                     const rohc_lsb_shift_t p)
{
	struct rohc_interval32 interval32;
	struct rohc_interval16 interval16;

	/* do not accept more bits than the field may contain */
	assert(k <= 16);

	/* use the function for 32-bit fields, then ensure that nothing is greater
	 * than 0xffff */
	interval32 = rohc_f_32bits(v_ref, k, p);
	interval16.min = interval32.min & 0xfffff;
	interval16.max = interval32.max & 0xfffff;

	return interval16;
}


/**
 * @brief The f function as defined in LSB encoding for 32-bit fields
 *
 * Find out the interval \f$[v\_ref - p, v\_ref + (2^k - 1) - p]\f$ for a
 * given k. See 4.5.1 in the RFC 3095 for details.
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
                                     const rohc_lsb_shift_t p)
{
	struct rohc_interval32 interval32;
	uint32_t interval_width;
	int32_t computed_p;

	/* accept at most 32 bits */
	assert(k <= 32);

	/* compute the interval width = 2^k - 1 */
	if(k == 32)
	{
		interval_width = 0xffffffff;
	}
	else
	{
		interval_width = (1 << k) - 1; /* (1 << k) = 2^k */
	}

	/* determine the real p value to use */
	computed_p = rohc_interval_compute_p(k, p);

	/* compute the minimal and maximal values of the interval:
	 *   min = v_ref - p
	 *   max = v_ref + interval_with - p
	 *
	 * Straddling the lower and upper wraparound boundaries
	 * is handled without additional operation */
	interval32.min = v_ref - computed_p;
	interval32.max = v_ref + interval_width - computed_p;

	return interval32;
}

