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
#define ROHC_WLSB_WIDTH_MAX  UINT8_MAX


/**
 * @brief The different values of the shift parameter of the LSB algorithm
 *
 * The shift parameter is also named 'p' in some RFCs.
 */
typedef enum
{
	ROHC_LSB_SHIFT_SN             = -1,  /**< LSB shift for non-RTP SN */
#define ROHC_LSB_SHIFT_TCP_TS_1B  ROHC_LSB_SHIFT_SN /**< LSB shift for TCP TS */
#define ROHC_LSB_SHIFT_TCP_TS_2B  ROHC_LSB_SHIFT_SN /**< LSB shift for TCP TS */
	ROHC_LSB_SHIFT_IP_ID          =  0,  /**< LSB shift for IP-ID */
	ROHC_LSB_SHIFT_TCP_TTL        =  3,  /**< LSB shift for TCP TTL/HL */
#define ROHC_LSB_SHIFT_TCP_ACK_SCALED  ROHC_LSB_SHIFT_TCP_TTL
	ROHC_LSB_SHIFT_TCP_SN         =  4,  /**< LSB shift for TCP MSN */
	ROHC_LSB_SHIFT_TCP_SEQ_SCALED =  7,  /**< LSB shift for TCP seq scaled */
	ROHC_LSB_SHIFT_TCP_WINDOW     = 16383,       /**< LSB shift for TCP window */
	ROHC_LSB_SHIFT_TCP_TS_3B      = 0x00040000,  /**< LSB shift for TCP TS */
	ROHC_LSB_SHIFT_TCP_TS_4B      = 0x04000000,  /**< LSB shift for TCP TS */
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

struct rohc_interval32 rohc_f_32bits(const uint32_t v_ref,
                                     const size_t k,
                                     const int32_t p)
	__attribute__((warn_unused_result, const));

static inline int32_t rohc_interval_compute_p_rtp_ts(const size_t k)
	__attribute__((warn_unused_result, const));

static inline int32_t rohc_interval_compute_p_rtp_sn(const size_t k)
	__attribute__((warn_unused_result, const));

static inline int32_t rohc_interval_compute_p_esp_sn(const size_t k)
	__attribute__((warn_unused_result, const));

int32_t rohc_interval_get_rfc5225_msn_p(const size_t k,
                                        const rohc_reordering_offset_t reorder_ratio)
	__attribute__((warn_unused_result, const));

int32_t rohc_interval_get_rfc5225_id_id_p(const size_t k)
	__attribute__((warn_unused_result, const));


/**
 * @brief Compute the shift parameter p for the f function
 *
 * @param k  The number of least significant bits of the value that are
 *           transmitted
 * @return   The computed shift parameter p
 */
static inline int32_t rohc_interval_compute_p_rtp_ts(const size_t k)
{
	return (k <= 2 ? 0 : (1 << (k - 2)) - 1);
}


/**
 * @brief Compute the shift parameter p for the f function
 *
 * @param k  The number of least significant bits of the value that are
 *           transmitted
 * @return   The computed shift parameter p
 */
static inline int32_t rohc_interval_compute_p_rtp_sn(const size_t k)
{
	return (k <= 4 ? 1 : (1 << (k - 5)) - 1);
}


/**
 * @brief Compute the shift parameter p for the f function
 *
 * @param k  The number of least significant bits of the value that are
 *           transmitted
 * @return   The computed shift parameter p
 */
static inline int32_t rohc_interval_compute_p_esp_sn(const size_t k)
{
	return rohc_interval_compute_p_rtp_sn(k);
}

#endif

