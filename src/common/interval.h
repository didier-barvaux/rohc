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
 * @file interval.h
 * @brief Compute the interpretation interval for LSB and W-LSB encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMMON_INTERVAL_H
#define ROHC_COMMON_INTERVAL_H

#include <rohc/rohc.h> /* for rohc_reordering_offset_t */

#include <stdlib.h>
#include <stdint.h>


/** The maximum width of the W-LSB window (implementation specific) */
#define ROHC_WLSB_WIDTH_MAX  64U


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
	ROHC_LSB_SHIFT_SN         = -1,      /**< real value for non-RTP SN */
#define ROHC_LSB_SHIFT_TCP_TS_1B  ROHC_LSB_SHIFT_SN /**< real value for TCP TS */
#define ROHC_LSB_SHIFT_TCP_TS_2B  ROHC_LSB_SHIFT_SN /**< real value for TCP TS */
	ROHC_LSB_SHIFT_IP_ID      =  0,      /**< real value for IP-ID */
	ROHC_LSB_SHIFT_TCP_TTL    =  3,      /**< real value for TCP TTL/HL */
#define ROHC_LSB_SHIFT_TCP_ACK_SCALED  ROHC_LSB_SHIFT_TCP_TTL
	ROHC_LSB_SHIFT_TCP_SN     =  4,      /**< real value for TCP MSN */
	ROHC_LSB_SHIFT_TCP_SEQ_SCALED =  7,      /**< real value for TCP seq/ack scaled */
	ROHC_LSB_SHIFT_RTP_TS     =  100,    /**< need to compute real value for RTP TS */
	ROHC_LSB_SHIFT_RTP_SN     =  101,    /**< need to compute real value for RTP SN */
	ROHC_LSB_SHIFT_ESP_SN     =  102,    /**< need to compute real value for ESP SN */
	ROHC_LSB_SHIFT_VAR        =  103,    /**< real value is variable */
	ROHC_LSB_SHIFT_TCP_WINDOW = 16383,   /**< real value for TCP window */
	ROHC_LSB_SHIFT_TCP_TS_3B  = 0x00040000, /**< real value for TCP TS */
	ROHC_LSB_SHIFT_TCP_TS_4B  = 0x04000000, /**< real value for TCP TS */
} rohc_lsb_shift_t;


/**
 * @brief An interval of 8-bit values
 *
 * Lower and upper bound values are always included in the interval.
 *
 * The upper bound may be greater that the lower bound of the interval if the
 * interval straddles the interval boundaries.
 *
 * Example of interval that does not straddle field boundaries:
 *   [1, 3]
 *
 * Example of interval that straddles field boundaries (8-bit field):
 *   [250, 4]
 */
struct rohc_interval8
{
	uint8_t min;  /**< The lower bound of the interval */
	uint8_t max;  /**< The upper bound of the interval */
};


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

struct rohc_interval32 rohc_f_32bits(const uint32_t v_ref,
                                     const size_t k,
                                     const rohc_lsb_shift_t p)
	__attribute__((warn_unused_result, const));

int32_t rohc_interval_get_rfc5225_msn_p(const size_t k,
                                        rohc_reordering_offset_t reorder_ratio)
	__attribute__((warn_unused_result, const));

int32_t rohc_interval_get_rfc5225_id_id_p(const size_t k)
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
	if(p == ROHC_LSB_SHIFT_RTP_TS)
	{
		/* special computation for RTP TS encoding */
		computed_p = (k <= 2 ? 0 : (1 << (k - 2)) - 1);
	}
	else if(p == ROHC_LSB_SHIFT_RTP_SN || p == ROHC_LSB_SHIFT_ESP_SN)
	{
		/* special computation for RTP and ESP SN encoding */
		computed_p = (k <= 4 ? 1 : (1 << (k - 5)) - 1);
	}
	else
	{
		/* otherwise: use the p value given as parameter */
		computed_p = p;
	}

	return computed_p;
}

#endif

