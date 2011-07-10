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
 * @file interval.c
 * @brief Compute the interpretation interval for LSB and W-LSB encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 * @author The hackers from ROHC for Linux
 */

#include "interval.h"

#include <assert.h>


/**
 * @brief The f function as defined in the LSB calculation algorithm
 *
 * Find out the interval \f$[v\_ref - p, v\_ref + (2^k - 1) - p]\f$ for a given k.
 * See 4.5.1 in the RFC 3095.
 *
 * @param v_ref The reference value
 * @param k     The number of least significant bits of the value that are
 *              transmitted
 * @param p     The shift parameter (may be negative)
 * @param min   OUT: The lower limit of the interval
 * @param max   OUT: The upper limit of the interval
 */
void f(const uint32_t v_ref, const size_t k, const int32_t p,
       uint32_t *const min, uint32_t *const max)
{
	const uint32_t interval_width = (1 << k) - 1; /* (1 << k) = 2^k */
	int32_t computed_p;

	/* sanity check: check for value that will cause an integer overflow */
	assert(k < 32);

	/* determine the p value to use */
	if(p == 2)
	{
		/* special computation for timestamp encoding */
		if(k <= 2)
		{
			computed_p = 0;
		}
		else
		{
			computed_p = (1 << (k - 2)) - 1;
		}
	}
	else if(p == 3)
	{
		/* special computation for SN encoding */
		if(k <= 4)
		{
			computed_p = 1;
		}
		else
		{
			computed_p = (1 << (k - 5)) - 1;
		}
	}
	else
	{
		/* otherwise: use the p value given as parameter */
		computed_p = p;
	}

	/* compute the minimal value of the interval */
	if(v_ref > computed_p)
	{
		*min = v_ref - computed_p;
	}
	else
	{
		/* do not straddle the wraparound boundary */
		*min = 0;
	}

	/* compute the maximal value of the interval */
	if(interval_width <= computed_p ||
	   v_ref <= (0xffffffff - (interval_width - computed_p)))
	{
		*max = v_ref + interval_width - computed_p;
	}
	else
	{
		/* do not straddle the wraparound boundary */
		*max = 0xffffffff;
	}
}

