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
 * @file ts_sc_decomp.c
 * @brief Scaled RTP Timestamp decoding
 * @author David Moreau from TAS
 */

#include "ts_sc_decomp.h"
#include "rohc_traces.h"


/**
 * @brief Create the ts_sc_decomp object
 *
 * @param ts_sc  The ts_sc_decomp object to create
 */
void d_create_sc(struct ts_sc_decomp *ts_sc)
{
	ts_sc->ts_stride = 0;
	ts_sc->ts_scaled = 0;
	ts_sc->ts_offset = 0;
	ts_sc->ts = 0;
	ts_sc->old_ts = 0;
	ts_sc->old_sn = 0;
	ts_sc->sn = 0;
}


/**
 * @brief Store a new timestamp
 *
 * @param ts_sc  The ts_sc_decomp object
 * @param ts     The timestamp to add
 * @param sn     The Sequence Number of the current packet
 */
void d_add_ts(struct ts_sc_decomp *ts_sc, unsigned int ts, unsigned int sn)
{
	ts_sc->old_ts = ts_sc->ts;
	ts_sc->old_sn = ts_sc->sn;
	ts_sc->ts = ts;
	ts_sc->sn = sn;
	rohc_debugf(3, "new TS = %u - old TS = %u\n", ts_sc->ts, ts_sc->old_ts);
	update_ts_sc(ts_sc);
}


/**
 * @brief Store the new TS_STRIDE value
 *
 * @param ts_sc      The ts_sc_decomp object
 * @param ts_stride  The TS_STRIDE value to add
 */
void d_add_ts_stride(struct ts_sc_decomp *ts_sc, int ts_stride)
{
	ts_sc->ts_stride = ts_stride;
	rohc_debugf(3, "ts_stride = %d\n", ts_sc->ts_stride);
}


/**
 * @brief Update a ts_sc_decomp object
 *
 * @param ts_sc  The ts_sc_decomp object to update
 */
void update_ts_sc(struct ts_sc_decomp *ts_sc)
{
	if(ts_sc->ts_stride != 0)
	{
		rohc_debugf(3, "timestamp = %u\n", ts_sc->ts);
		rohc_debugf(3, "ts_stride = %d\n", ts_sc->ts_stride);

		ts_sc->ts_offset = ts_sc->ts % ts_sc->ts_stride;
		rohc_debugf(3, "ts_offset = %u modulo %d = %d\n",
		            ts_sc->ts, ts_sc->ts_stride, ts_sc->ts_offset);

		ts_sc->ts_scaled = (ts_sc->ts - ts_sc->ts_offset) / ts_sc->ts_stride;
		rohc_debugf(3, "ts_scaled = (%u - %d) / %d = %d\n", ts_sc->ts,
		            ts_sc->ts_offset, ts_sc->ts_stride, ts_sc->ts_scaled);

		/* update LSB */
		d_lsb_sync_ref(&ts_sc->lsb_ts_scaled);
		d_lsb_update(&ts_sc->lsb_ts_scaled, ts_sc->ts_scaled);
	}
}


/**
 * @brief Decode timestamp (TS) value with TS_SCALED value
 *
 * @param ts_sc        The ts_sc_decomp object
 * @param ts_scaled    The W-LSB-encoded TS_SCALED value
 * @param nb_bits      The number of bits of TS_SCALED (W-LSB)
 * @return             The decoded TS
 */
unsigned int d_decode_ts(struct ts_sc_decomp *ts_sc, int ts_scaled, int nb_bits)
{
	rohc_debugf(3, "reference decode value = %u\n", d_get_lsb_ref(&ts_sc->lsb_ts_scaled));
	rohc_debugf(3, "ts_scaled value to decode = %u\n", ts_scaled);

	ts_sc->ts_scaled = d_lsb_decode(&ts_sc->lsb_ts_scaled, ts_scaled, nb_bits);
	rohc_debugf(3, "ts_scaled decoded = %u / 0x%x with %d bits\n",
	            ts_sc->ts_scaled, ts_sc->ts_scaled, nb_bits);

	/* TS calculation */
	unsigned int ts = ts_sc->ts_stride * ts_sc->ts_scaled + ts_sc->ts_offset;
	rohc_debugf(3, "TS calculated = %u\n", ts);

	return ts;
}


/**
 * @brief Deduct timestamp (TS) from Sequence Number (SN)
 *
 * @param ts_sc        The ts_sc_decomp object
 * @param sn           The SN
 * @return             The decoded TS
 */
unsigned int ts_deducted(struct ts_sc_decomp *ts_sc, unsigned int sn)
{
	int timestamp = 0;
	int ts_scaled = ts_sc->ts_scaled;
	int ts_stride = ts_sc->ts_stride;
	int ts_offset = ts_sc->ts_offset;

	rohc_debugf(3, "old ts_scaled = %d\n", ts_scaled);
	ts_scaled += (sn - ts_sc->sn);
	rohc_debugf(3, "sn = %u, ts_sc->sn = %u\n", sn, ts_sc->sn);
	rohc_debugf(3, "new ts_scaled = %d\n", ts_scaled);

	timestamp = ts_scaled * ts_stride + ts_offset;

	ts_sc->ts_scaled = ts_scaled;
	ts_sc->ts = timestamp;

	return timestamp;
}

