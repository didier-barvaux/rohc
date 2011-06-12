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


/* prototypes of private functions */
static void update_ts_sc(struct ts_sc_decomp *const ts_sc);


/*
 * Public functions
 */

/**
 * @brief Create the ts_sc_decomp object
 *
 * @param ts_sc  The ts_sc_decomp object to create
 */
void d_create_sc(struct ts_sc_decomp *const ts_sc)
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
void d_add_ts(struct ts_sc_decomp *const ts_sc,
              const uint32_t ts,
              const uint16_t sn)
{
	ts_sc->old_ts = ts_sc->ts;
	ts_sc->old_sn = ts_sc->sn;
	ts_sc->ts = ts;
	ts_sc->sn = sn;
	rohc_debugf(3, "new SN %u replaced old SN %u\n", ts_sc->sn, ts_sc->old_sn);
	rohc_debugf(3, "new TS %u replaced old TS %u\n", ts_sc->ts, ts_sc->old_ts);
	update_ts_sc(ts_sc);
}


/**
 * @brief Store the new TS_STRIDE value
 *
 * @param ts_sc      The ts_sc_decomp object
 * @param ts_stride  The TS_STRIDE value to add
 */
void d_add_ts_stride(struct ts_sc_decomp *const ts_sc,
                     const uint32_t ts_stride)
{
	ts_sc->ts_stride = ts_stride;
	rohc_debugf(3, "ts_stride = %u\n", ts_sc->ts_stride);
}


/**
 * @brief Decode timestamp (TS) value with TS_SCALED value
 *
 * @param ts_sc        The ts_sc_decomp object
 * @param ts_scaled    The W-LSB-encoded TS_SCALED value
 * @param bits_nr      The number of bits of TS_SCALED (W-LSB)
 * @param decoded_ts   OUT: The decoded TS
 * @return             1 in case of success, 0 otherwise
 */
int d_decode_ts(struct ts_sc_decomp *const ts_sc,
                const uint32_t ts_scaled,
                const size_t bits_nr,
                uint32_t *const decoded_ts)
{
	int lsb_decode_ok;
	int is_success;

	rohc_debugf(3, "decode %zd-bit TS_SCALED %u (reference = %u)\n", bits_nr,
	            ts_scaled, d_get_lsb_ref(&ts_sc->lsb_ts_scaled));
	lsb_decode_ok = d_lsb_decode32(&ts_sc->lsb_ts_scaled, ts_scaled, bits_nr,
	                               &(ts_sc->ts_scaled));
	if(!lsb_decode_ok)
	{
		rohc_debugf(0, "failed to decode %zd-bit TS_SCALED %u\n", bits_nr,
		            ts_scaled);
		is_success = 0;
	}
	else
	{
		rohc_debugf(3, "ts_scaled decoded = %u / 0x%x with %zd bits\n",
		            ts_sc->ts_scaled, ts_sc->ts_scaled, bits_nr);

		/* TS calculation */
		*decoded_ts = ts_sc->ts_stride * ts_sc->ts_scaled + ts_sc->ts_offset;
		rohc_debugf(3, "TS calculated = %u\n", *decoded_ts);

		is_success = 1;
	}

	return is_success;
}


/**
 * @brief Deduct timestamp (TS) from Sequence Number (SN)
 *
 * @param ts_sc        The ts_sc_decomp object
 * @param sn           The SN
 * @return             The decoded TS
 */
uint32_t ts_deducted(struct ts_sc_decomp *const ts_sc,
                     const uint16_t sn)
{
	uint32_t timestamp;
	uint32_t ts_scaled;

	ts_scaled = ts_sc->ts_scaled + (sn - ts_sc->sn);
	rohc_debugf(3, "new TS_SCALED = %u (ref TS_SCALED = %u, new SN = %u, "
	            "ref SN = %u)\n", ts_scaled, ts_sc->ts_scaled, sn, ts_sc->sn);

	timestamp = ts_scaled * ts_sc->ts_stride + ts_sc->ts_offset;
	rohc_debugf(3, "new TS = %u (TS_SCALED = %u, TS_STRIDE = %u, "
	            "TS_OFFSET = %u)\n", timestamp, ts_scaled, ts_sc->ts_stride,
	            ts_sc->ts_offset);

	ts_sc->ts_scaled = ts_scaled;
	ts_sc->ts = timestamp;

	return timestamp;
}


/*
 * Private functions
 */

/**
 * @brief Update a ts_sc_decomp object
 *
 * @param ts_sc  The ts_sc_decomp object to update
 */
static void update_ts_sc(struct ts_sc_decomp *const ts_sc)
{
	if(ts_sc->ts_stride != 0)
	{
		rohc_debugf(3, "timestamp = %u\n", ts_sc->ts);
		rohc_debugf(3, "ts_stride = %u\n", ts_sc->ts_stride);

		ts_sc->ts_offset = ts_sc->ts % ts_sc->ts_stride;
		rohc_debugf(3, "ts_offset = %u modulo %u = %u\n",
		            ts_sc->ts, ts_sc->ts_stride, ts_sc->ts_offset);

		ts_sc->ts_scaled = (ts_sc->ts - ts_sc->ts_offset) / ts_sc->ts_stride;
		rohc_debugf(3, "ts_scaled = (%u - %u) / %u = %u\n", ts_sc->ts,
		            ts_sc->ts_offset, ts_sc->ts_stride, ts_sc->ts_scaled);

		/* update LSB */
		d_lsb_sync_ref(&ts_sc->lsb_ts_scaled);
		d_lsb_update(&ts_sc->lsb_ts_scaled, ts_sc->ts_scaled);
	}
}

