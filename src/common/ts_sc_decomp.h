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
 * @file ts_sc_decomp.h
 * @brief Scaled RTP Timestamp decoding
 * @author David Moreau from TAS
 */

#ifndef TS_SC_DECOMP_H
#define TS_SC_DECOMP_H

#include "lsb.h"

#include <stdint.h>


/**
 * @brief Scaled RTP Timestamp decoding object
 *
 * See section 4.5.3 of RFC 3095 for details about Scaled RTP Timestamp
 * decoding.
 */
struct ts_sc_decomp
{
	/// The TS_STRIDE value
	uint32_t ts_stride;

	/// The TS_SCALED value
	uint32_t ts_scaled;
	/// The LSB-encoded TS_SCALED value
	struct d_lsb_decode lsb_ts_scaled;

	/// The TS_OFFSET value
	uint32_t ts_offset;

	/// The timestamp (TS) value
	uint32_t ts;
	/// The previous timestamp value
	uint32_t old_ts;

	/// The sequence number (SN)
	uint16_t sn;
	/// The previous sequence number
	uint16_t old_sn;
};



/*
 * Function prototypes
 */

void d_create_sc(struct ts_sc_decomp *const ts_sc);

void d_add_ts(struct ts_sc_decomp *const ts_sc,
              const uint32_t ts,
              const uint16_t sn);
void d_add_ts_stride(struct ts_sc_decomp *const ts_sc,
                     const uint32_t ts_stride);

int d_decode_ts(struct ts_sc_decomp *const ts_sc,
                const uint32_t ts_scaled,
                const size_t bits_nr,
                uint32_t *const decoded_ts);
uint32_t ts_deducted(struct ts_sc_decomp *const ts_sc,
                     const uint16_t sn);

#endif

