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
 * @file interval.h
 * @brief Compute the interpretation interval for LSB and W-LSB encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef INTERVAL_H
#define INTERVAL_H

#include <stdlib.h>
#include <stdint.h>


/**
 * @brief the different values of the shift parameter of the LSB algorithm
 *
 * The shift parameter is also named 'p' in some RFCs.
 *
 * Some values are the real values to use directly. Some others are code
 * that means that the real value to use shall be computed from the number
 * of least significant bits that are transmitted.
 */
typedef enum
{
	ROHC_LSB_SHIFT_IP_ID  =  0,  /**< real value for IP-ID */
	ROHC_LSB_SHIFT_RTP_TS =  2,  /**< need to compute real value for RTP TS */
	ROHC_LSB_SHIFT_RTP_SN =  3,  /**< need to compute real value for RTP SN */
	ROHC_LSB_SHIFT_ESP_SN =  3,  /**< need to compute real value for ESP SN */
	ROHC_LSB_SHIFT_SN     = -1,  /**< real value for non-RTP SN */
	ROHC_LSB_SHIFT_STATS  = -1,  /**< real value for internal statistics */
	ROHC_LSB_SHIFT_VAR    =  1,  /**< real value is variable */
} rohc_lsb_shift_t;


/**
 * @brief An interval of 16-bit values
 *
 * Lower and upper bound values are always included in the interval.
 *
 * The upper bound may be greater that the lower bound of the interval if the
 * interval straddles the interval boundaries.
 *
 * Example of interval that does not straddle field boundaries:
 *   [1, 3]
 *
 * Example of interval that straddles field boundaries (16-bit field):
 *   [65530, 4]
 */
struct rohc_interval16
{
	uint16_t min;  /**< The lower bound of the interval */
	uint16_t max;  /**< The upper bound of the interval */
};


/**
 * @brief An interval of 32-bit values
 *
 * Lower and upper bound values are always included in the interval.
 *
 * The upper bound may be greater that the lower bound of the interval if the
 * interval straddles the interval boundaries.
 *
 * Example of interval that does not straddle field boundaries:
 *   [1, 3]
 *
 * Example of interval that straddles field boundaries (32-bit field):
 *   [65530, 4]
 */
struct rohc_interval32
{
	uint32_t min;  /**< The lower bound of the interval */
	uint32_t max;  /**< The upper bound of the interval */
};


/*
 * Public function prototypes:
 */

static inline int32_t rohc_interval_compute_p(const size_t k,
                                              const rohc_lsb_shift_t p)
	__attribute__((warn_unused_result, const));

const struct rohc_interval16 rohc_f_16bits(const uint16_t v_ref,
                                           const size_t k,
                                           const rohc_lsb_shift_t p)
	__attribute__((warn_unused_result, const));

const struct rohc_interval32 rohc_f_32bits(const uint32_t v_ref,
                                           const size_t k,
                                           const rohc_lsb_shift_t p)
	__attribute__((warn_unused_result, const));


/**
 * @brief Compute the shift parameter p for the f function
 *
 * @param k  The number of least significant bits of the value that are
 *           transmitted
 * @param p  The shift parameter (may be negative)
 * @return   The computed shift parameter p
 */
static inline int32_t rohc_interval_compute_p(const size_t k,
                                              const rohc_lsb_shift_t p)
{
	int32_t computed_p;

	/* determine the real p value to use */
	switch(p)
	{
		case ROHC_LSB_SHIFT_RTP_TS: /* special computation for RTP TS encoding */
		{
			if(k <= 2)
			{
				computed_p = 0;
			}
			else
			{
				computed_p = (1 << (k - 2)) - 1;
			}
		}
		break;

		/* special computation for RTP and ESP SN encoding */
		case ROHC_LSB_SHIFT_RTP_SN: /* = ROHC_LSB_SHIFT_ESP_SN */
		{
			if(k <= 4)
			{
				computed_p = 1;
			}
			else
			{
				computed_p = (1 << (k - 5)) - 1;
			}
		}
		break;

		default: /* otherwise: use the p value given as parameter */
		{
			computed_p = p;
		}
	}

	return computed_p;
}

#endif

