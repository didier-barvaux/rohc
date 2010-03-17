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

#include "rohc.h"


/**
 * @brief Scaled RTP Timestamp decoding object
 *
 * See section 4.5.3 of RFC 3095 for details about Scaled RTP Timestamp
 * decoding.
 */
struct ts_sc_decomp
{
	/// The TS_STRIDE value
	int ts_stride;
	/// The LSB-encoded TS_STRIDE value
	struct d_lsb_decode lsb_ts_stride;

	/// The TS_SCALED value
	int ts_scaled;
	/// The LSB-encoded TS_SCALED value
	struct d_lsb_decode lsb_ts_scaled;

	/// The TS_OFFSET value
	int ts_offset;

	/// The timestamp (TS) value
	unsigned int ts;
	/// The previous timestamp value
	unsigned int old_ts;

	/// The sequence number (SN)
	unsigned int sn;
	/// The previous sequence number
	unsigned int old_sn;
};



/*
 * Function prototypes
 */

void d_create_sc(struct ts_sc_decomp *ts_sc);

void d_add_ts(struct ts_sc_decomp *ts_sc, unsigned int ts, unsigned int sn);
void d_add_ts_stride(struct ts_sc_decomp *ts_sc, int ts_stride);

unsigned int d_decode_ts(struct ts_sc_decomp *ts_sc, int ts_scaled, int nb_bits);
unsigned int ts_deducted(struct ts_sc_decomp *ts_sc, unsigned int sn);

void update_ts_sc(struct ts_sc_decomp *ts_sc);

#endif

