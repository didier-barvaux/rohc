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
	ROHC_LSB_SHIFT_SN     = -1,  /**< real value for non-RTP SN */
	ROHC_LSB_SHIFT_STATS  = -1,  /**< real value for internal statistics */
} rohc_lsb_shift_t;


/*
 * Public function prototypes:
 */

void rohc_f_16bits(const uint16_t v_ref,
                   const size_t k,
                   const rohc_lsb_shift_t p,
                   uint16_t *const min,
                   uint16_t *const max);

void rohc_f_32bits(const uint32_t v_ref,
                   const size_t k,
                   const rohc_lsb_shift_t p,
                   uint32_t *const min,
                   uint32_t *const max);

#endif

