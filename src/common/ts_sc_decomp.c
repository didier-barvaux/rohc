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
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "ts_sc_decomp.h"
#include "rohc_traces.h"


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

	ts_sc->old_ts = 0;
	ts_sc->old_sn = 0;
	ts_sc->ts = 0;
	ts_sc->sn = 0;

	ts_sc->new_ts_stride = 0;
	ts_sc->new_ts_scaled = 0;
	ts_sc->new_ts_offset = 0;

	d_lsb_init(&ts_sc->lsb_ts_scaled, 0, ROHC_LSB_SHIFT_RTP_TS);
}


/**
 * @brief Store a new timestamp
 *
 * @param ts_sc  The ts_sc_decomp object
 * @param ts     The new decoded TimeStamp (TS)
 * @param sn     The new decoded Sequence Number (SN)
 */
void ts_update_context(struct ts_sc_decomp *const ts_sc,
                       const uint32_t ts,
                       const uint16_t sn)
{
	/* replace the old TS/SN with the new ones, keep backup of the old ones */
	ts_sc->old_ts = ts_sc->ts;
	ts_sc->old_sn = ts_sc->sn;
	ts_sc->ts = ts;
	ts_sc->sn = sn;
	rohc_debugf(3, "old SN %u replaced by new SN %u\n", ts_sc->old_sn, ts_sc->sn);
	rohc_debugf(3, "old TS %u replaced by new TS %u\n", ts_sc->old_ts, ts_sc->ts);

	/* replace the old TS_* values with the new ones computed during packet
	   parsing */
	if(ts_sc->new_ts_scaled != ts_sc->ts_scaled)
	{
		rohc_debugf(3, "old TS_SCALED %u replaced by new TS_SCALED %u\n",
		            ts_sc->ts_scaled, ts_sc->new_ts_scaled);
		ts_sc->ts_scaled = ts_sc->new_ts_scaled;
	}
	else
	{
		rohc_debugf(3, "old TS_SCALED %u kept unchanged\n", ts_sc->ts_scaled);
	}
	if(ts_sc->new_ts_stride != ts_sc->ts_stride)
	{
		rohc_debugf(3, "old TS_STRIDE %u replaced by new TS_STRIDE %u\n",
		            ts_sc->ts_stride, ts_sc->new_ts_stride);
		ts_sc->ts_stride = ts_sc->new_ts_stride;
	}
	else
	{
		rohc_debugf(3, "old TS_STRIDE %u kept unchanged\n", ts_sc->ts_stride);
	}
	if(ts_sc->new_ts_offset != ts_sc->ts_offset)
	{
		rohc_debugf(3, "old TS_OFFSET %u replaced by new TS_OFFSET %u\n",
		            ts_sc->ts_offset, ts_sc->new_ts_offset);
		ts_sc->ts_offset = ts_sc->new_ts_offset;
	}
	else
	{
		rohc_debugf(3, "old TS_OFFSET %u kept unchanged\n", ts_sc->ts_offset);
	}

	/* reset all the new TS_* values */
	ts_sc->new_ts_scaled = 0;
	ts_sc->new_ts_stride = 0;
	ts_sc->new_ts_offset = 0;

	/* update the LSB object for TS_SCALED */
	d_lsb_update(&ts_sc->lsb_ts_scaled, ts_sc->ts_scaled);
}


/**
 * @brief Store the newly-parsed TS_STRIDE value
 *
 * @param ts_sc      The ts_sc_decomp object
 * @param ts_stride  The TS_STRIDE value to add
 */
void d_record_ts_stride(struct ts_sc_decomp *const ts_sc,
                        const uint32_t ts_stride)
{
	rohc_debugf(3, "new TS_STRIDE %u recorded\n", ts_stride);
	ts_sc->new_ts_stride = ts_stride;
}


/**
 * @brief Decode timestamp (TS) value with TS_SCALED value
 *
 * Use the given TS and TS_SCALED bits.
 * Use the TS_STRIDE and TS_OFFSET values found in context.
 *
 * @param ts_sc        The ts_sc_decomp object
 * @param ts_scaled    The W-LSB-encoded TS_SCALED value
 * @param bits_nr      The number of bits of TS_SCALED (W-LSB)
 * @param decoded_ts   OUT: The decoded TS
 * @return             true in case of success, false otherwise
 */
bool ts_decode_scaled(struct ts_sc_decomp *const ts_sc,
                      const uint32_t ts_scaled,
                      const size_t bits_nr,
                      uint32_t *const decoded_ts)
{
	uint32_t ts_scaled_decoded;
	bool lsb_decode_ok;

	/* update TS_SCALED in context */
	rohc_debugf(3, "decode %zd-bit TS_SCALED %u (reference = %u)\n", bits_nr,
	            ts_scaled, d_get_lsb_ref(&ts_sc->lsb_ts_scaled));
	lsb_decode_ok = d_lsb_decode32(&ts_sc->lsb_ts_scaled, ts_scaled, bits_nr,
	                               &ts_scaled_decoded);
	if(!lsb_decode_ok)
	{
		rohc_debugf(0, "failed to decode %zd-bit TS_SCALED %u\n", bits_nr,
		            ts_scaled);
		goto error;
	}

	rohc_debugf(3, "ts_scaled decoded = %u / 0x%x with %zd bits\n",
	            ts_scaled_decoded, ts_scaled_decoded, bits_nr);

	/* TS computation with the TS_SCALED we just decoded and the
	   TS_STRIDE/TS_OFFSET values found in context */
	*decoded_ts = ts_sc->ts_stride * ts_scaled_decoded + ts_sc->ts_offset;
	rohc_debugf(3, "TS calculated = %u\n", *decoded_ts);

	/* store the updated TS_* values in context */
	ts_sc->new_ts_scaled = ts_scaled_decoded;
	ts_sc->new_ts_stride = ts_sc->ts_stride;
	ts_sc->new_ts_offset = ts_sc->ts_offset;

	return true;

error:
	return false;
}


/**
 * @brief Decode timestamp (TS) value with unscaled value
 *
 * Use the given unscaled TS bits.
 * If the TS_STRIDE value was updated by the current packet, compute new
 * TS_SCALED and TS_OFFSET values from the new TS_STRIDE value.
 *
 * @param ts_sc    The ts_sc_decomp object
 * @param ts_bits  The unscaled TS bits
 * @return         The decoded TS
 */
uint32_t ts_decode_unscaled(struct ts_sc_decomp *const ts_sc,
                            const uint32_t ts_bits)
{
	uint32_t effective_ts_stride;
	uint32_t new_ts_offset;
	uint32_t new_ts_scaled;

	/* which TS_STRIDE to use? */
	if(ts_sc->new_ts_stride != 0)
	{
		/* TS_STRIDE was updated by the ROHC packet being currently parsed */
		rohc_debugf(3, "decode unscaled TS bits %u with updated TS_STRIDE %u\n",
		            ts_bits, ts_sc->new_ts_stride);
		effective_ts_stride = ts_sc->new_ts_stride;
	}
	else
	{
		/* TS_STRIDE was not updated by the ROHC packet being currently parsed */
		rohc_debugf(3, "decode unscaled TS bits %u with context TS_STRIDE %u\n",
		            ts_bits, ts_sc->ts_stride);
		effective_ts_stride = ts_sc->ts_stride;
	}

	if(effective_ts_stride != 0)
	{
		/* compute the new TS_OFFSET value */
		new_ts_offset = ts_bits % effective_ts_stride;
		rohc_debugf(3, "TS_OFFSET = %u modulo %u = %u\n",
		            ts_bits, effective_ts_stride, new_ts_offset);

		/* compute the new TS_SCALED value */
		new_ts_scaled = (ts_bits - new_ts_offset) / effective_ts_stride;
		rohc_debugf(3, "TS_SCALED = (%u - %u) / %u = %u\n", ts_bits,
		            new_ts_offset, effective_ts_stride, new_ts_scaled);

		/* store the updated TS_* values in context */
		ts_sc->new_ts_scaled = new_ts_scaled;
		ts_sc->new_ts_stride = effective_ts_stride;
		ts_sc->new_ts_offset = new_ts_offset;
	}

	/* return the unscaled TS bits as decoded TS */
	return ts_bits;
}


/**
 * @brief Deduct timestamp (TS) from Sequence Number (SN)
 *
 * Use the given SN bits to compute the new TS_SCALED value.
 * Use the TS_STRIDE and TS_OFFSET values found in context.
 *
 * @param ts_sc        The ts_sc_decomp object
 * @param sn           The SN
 * @return             The decoded TS
 */
uint32_t ts_deduce_from_sn(struct ts_sc_decomp *const ts_sc,
                           const uint16_t sn)
{
	uint32_t new_ts_scaled;
	uint32_t new_ts;

	/* compute the new TS_SCALED according to the new SN value and
	   the SN/TS_SCALED reference value */
	new_ts_scaled = ts_sc->ts_scaled + (sn - ts_sc->sn);
	rohc_debugf(3, "new TS_SCALED = %u (ref TS_SCALED = %u, new SN = %u, "
	            "ref SN = %u)\n", new_ts_scaled, ts_sc->ts_scaled,
	            sn, ts_sc->sn);

	/* compute the new TS value according to the TS_SCALED value we just
	   computed and the TS_STRIDE/TS_OFFSET values found in context */
	new_ts = new_ts_scaled * ts_sc->ts_stride + ts_sc->ts_offset;
	rohc_debugf(3, "new TS = %u (TS_SCALED = %u, TS_STRIDE = %u, "
	            "TS_OFFSET = %u)\n", new_ts, new_ts_scaled, ts_sc->ts_stride,
	            ts_sc->ts_offset);

	/* store the updated TS_* values in context */
	ts_sc->new_ts_scaled = new_ts_scaled;
	ts_sc->new_ts_stride = ts_sc->ts_stride;
	ts_sc->new_ts_offset = ts_sc->ts_offset;

	return new_ts;
}

