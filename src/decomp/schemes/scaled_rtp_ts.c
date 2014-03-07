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
 * @file   decomp/schemes/scaled_rtp_ts.c
 * @brief  Scaled RTP Timestamp decoding
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "scaled_rtp_ts.h"
#include "wlsb.h"
#include "rohc_traces_internal.h"

#include <assert.h>


/** Print debug messages for the ts_sc_decomp module */
#define ts_debug(entity_struct, format, ...) \
	rohc_debug(entity_struct, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL, \
	           format, ##__VA_ARGS__)


/*
 * Structure and types
 */

/**
 * @brief The scaled RTP Timestamp decoding context
 *
 * See section 4.5.3 of RFC 3095 for details about Scaled RTP Timestamp
 * decoding.
 */
struct ts_sc_decomp
{
	/// The last computed or received TS_STRIDE value (validated by CRC)
	uint32_t ts_stride;

	/// The last computed or received TS_SCALED value (validated by CRC)
	uint32_t ts_scaled;
	/// The LSB-encoded TS_SCALED value
	struct rohc_lsb_decode *lsb_ts_scaled;

	/// The last computed or received TS_OFFSET value (validated by CRC)
	uint32_t ts_offset;

	/** The last timestamp (TS) value */
	uint32_t ts;
	/** The LSB-encoded unscaled timestamp (TS) value */
	struct rohc_lsb_decode *lsb_ts_unscaled;
	/// The previous timestamp value
	uint32_t old_ts;

	/// The sequence number (SN)
	uint16_t sn;
	/// The previous sequence number
	uint16_t old_sn;


	/* the attributes below are new TS_* values computed by not yet validated
	   by CRC check */

	/// The last computed or received TS_STRIDE value (not validated by CRC)
	uint32_t new_ts_stride;
	/// The last computed or received TS_SCALED value (not validated by CRC)
	uint32_t new_ts_scaled;
	/// The last computed or received TS_OFFSET value (not validated by CRC)
	uint32_t new_ts_offset;

	/** The callback function used to get log messages */
	rohc_trace_callback_t trace_callback;
};



/*
 * Public functions
 */

/**
 * @brief Create the scaled RTP Timestamp decoding context
 *
 * @param callback  The trace callback
 * @return          The scaled RTP Timestamp decoding context in case of
 *                  success, NULL otherwise
 */
struct ts_sc_decomp * d_create_sc(rohc_trace_callback_t callback)
{
	struct ts_sc_decomp *ts_sc;

	ts_sc = malloc(sizeof(struct ts_sc_decomp));
	if(ts_sc == NULL)
	{
		goto error;
	}

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

	ts_sc->lsb_ts_scaled = rohc_lsb_new(ROHC_LSB_SHIFT_RTP_TS, 32);
	if(ts_sc->lsb_ts_scaled == NULL)
	{
		goto free_context;
	}

	ts_sc->lsb_ts_unscaled = rohc_lsb_new(ROHC_LSB_SHIFT_RTP_TS, 32);
	if(ts_sc->lsb_ts_unscaled == NULL)
	{
		goto free_lsb_ts_scaled;
	}

	ts_sc->trace_callback = callback;

	return ts_sc;

free_lsb_ts_scaled:
	rohc_lsb_free(ts_sc->lsb_ts_scaled);
free_context:
	free(ts_sc);
error:
	return NULL;
}


/**
 * @brief Destroy the given ts_sc_decomp object
 *
 * @param ts_sc  The ts_sc_decomp object to destroy
 */
void rohc_ts_scaled_free(struct ts_sc_decomp *const ts_sc)
{
	assert(ts_sc != NULL);
	assert(ts_sc->lsb_ts_scaled != NULL);
	assert(ts_sc->lsb_ts_unscaled != NULL);
	rohc_lsb_free(ts_sc->lsb_ts_unscaled);
	rohc_lsb_free(ts_sc->lsb_ts_scaled);
	free(ts_sc);
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
	ts_debug(ts_sc, "old SN %u replaced by new SN %u\n", ts_sc->old_sn, ts_sc->sn);
	ts_debug(ts_sc, "old TS %u replaced by new TS %u\n", ts_sc->old_ts, ts_sc->ts);

	/* replace the old TS_* values with the new ones computed during packet
	   parsing */
	if(ts_sc->new_ts_scaled != ts_sc->ts_scaled)
	{
		ts_debug(ts_sc, "old TS_SCALED %u replaced by new TS_SCALED %u\n",
		         ts_sc->ts_scaled, ts_sc->new_ts_scaled);
		ts_sc->ts_scaled = ts_sc->new_ts_scaled;
	}
	else
	{
		ts_debug(ts_sc, "old TS_SCALED %u kept unchanged\n", ts_sc->ts_scaled);
	}
	if(ts_sc->new_ts_stride != ts_sc->ts_stride)
	{
		ts_debug(ts_sc, "old TS_STRIDE %u replaced by new TS_STRIDE %u\n",
		         ts_sc->ts_stride, ts_sc->new_ts_stride);
		ts_sc->ts_stride = ts_sc->new_ts_stride;
	}
	else
	{
		ts_debug(ts_sc, "old TS_STRIDE %u kept unchanged\n", ts_sc->ts_stride);
	}
	if(ts_sc->new_ts_offset != ts_sc->ts_offset)
	{
		ts_debug(ts_sc, "old TS_OFFSET %u replaced by new TS_OFFSET %u\n",
		            ts_sc->ts_offset, ts_sc->new_ts_offset);
		ts_sc->ts_offset = ts_sc->new_ts_offset;
	}
	else
	{
		ts_debug(ts_sc, "old TS_OFFSET %u kept unchanged\n", ts_sc->ts_offset);
	}

	/* reset all the new TS_* values */
	ts_sc->new_ts_scaled = 0;
	ts_sc->new_ts_stride = 0;
	ts_sc->new_ts_offset = 0;

	/* update the LSB objects for unscaled TS and TS_SCALED */
	rohc_lsb_set_ref(ts_sc->lsb_ts_unscaled, ts_sc->ts, false);
	rohc_lsb_set_ref(ts_sc->lsb_ts_scaled, ts_sc->ts_scaled, false);
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
	ts_debug(ts_sc, "new TS_STRIDE %u recorded\n", ts_stride);
	ts_sc->new_ts_stride = ts_stride;
}


/**
 * @brief Decode timestamp (TS) value with some LSB bits of the unscaled value
 *
 * Use the given unscaled TS bits.
 * If the TS_STRIDE value was updated by the current packet, compute new
 * TS_SCALED and TS_OFFSET values from the new TS_STRIDE value.
 *
 * @param ts_sc                The ts_sc_decomp object
 * @param ts_unscaled_bits     The W-LSB-encoded TS value
 * @param ts_unscaled_bits_nr  The number of bits of TS_SCALED (W-LSB)
 * @param decoded_ts           OUT: The decoded TS
 * @param compat_1_6_x         Keep the behaviour of <= 1.6.x versions
 * @return                     true in case of success, false otherwise
 */
bool ts_decode_unscaled_bits(struct ts_sc_decomp *const ts_sc,
                             const uint32_t ts_unscaled_bits,
                             const size_t ts_unscaled_bits_nr,
                             uint32_t *const decoded_ts,
                             const bool compat_1_6_x)
{
	uint32_t effective_ts_stride;
	uint32_t new_ts_offset;
	uint32_t new_ts_scaled;
	bool lsb_decode_ok;

	assert(ts_sc != NULL);
	assert(decoded_ts != NULL);

	/* which TS_STRIDE to use? */
	if(ts_sc->new_ts_stride != 0)
	{
		/* TS_STRIDE was updated by the ROHC packet being currently parsed */
		ts_debug(ts_sc, "decode unscaled TS bits %u with updated TS_STRIDE %u\n",
		         ts_unscaled_bits, ts_sc->new_ts_stride);
		effective_ts_stride = ts_sc->new_ts_stride;
	}
	else
	{
		/* TS_STRIDE was not updated by the ROHC packet being currently parsed */
		ts_debug(ts_sc, "decode unscaled TS bits %u with context TS_STRIDE %u\n",
		         ts_unscaled_bits, ts_sc->ts_stride);
		effective_ts_stride = ts_sc->ts_stride;
	}

	/* update unscaled TS in context */
	if(compat_1_6_x)
	{
		*decoded_ts = ts_unscaled_bits;
		ts_debug(ts_sc, "compat_1_6_x: unscaled TS decoded = %u / 0x%x\n",
		         *decoded_ts, *decoded_ts);
	}
	else if(ts_unscaled_bits_nr == 32)
	{
		*decoded_ts = ts_unscaled_bits;
		ts_debug(ts_sc, "absolute unscaled TS decoded = %u / 0x%x\n",
		         *decoded_ts, *decoded_ts);
	}
	else
	{
		ts_debug(ts_sc, "decode %zd-bit unscaled TS %u (reference = %u)\n",
		         ts_unscaled_bits_nr, ts_unscaled_bits,
		         rohc_lsb_get_ref(ts_sc->lsb_ts_unscaled, ROHC_LSB_REF_0));
		lsb_decode_ok = rohc_lsb_decode(ts_sc->lsb_ts_unscaled, ROHC_LSB_REF_0, 0,
		                                ts_unscaled_bits, ts_unscaled_bits_nr,
		                                ROHC_LSB_SHIFT_RTP_TS, decoded_ts);
		if(!lsb_decode_ok)
		{
			rohc_error(ts_sc, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "failed to decode %zd-bit unscaled TS %u\n",
			           ts_unscaled_bits_nr, ts_unscaled_bits);
			goto error;
		}
		ts_debug(ts_sc, "unscaled TS decoded = %u / 0x%x with %zd bits\n",
		         *decoded_ts, *decoded_ts, ts_unscaled_bits_nr);
	}

	if(effective_ts_stride != 0)
	{
		/* compute the new TS_OFFSET value */
		new_ts_offset = (*decoded_ts) % effective_ts_stride;
		ts_debug(ts_sc, "TS_OFFSET = %u modulo %u = %u\n",
		         *decoded_ts, effective_ts_stride, new_ts_offset);

		/* compute the new TS_SCALED value */
		new_ts_scaled = ((*decoded_ts) - new_ts_offset) / effective_ts_stride;
		ts_debug(ts_sc, "TS_SCALED = (%u - %u) / %u = %u\n", *decoded_ts,
		         new_ts_offset, effective_ts_stride, new_ts_scaled);

		/* store the updated TS_* values in context */
		ts_sc->new_ts_scaled = new_ts_scaled;
		ts_sc->new_ts_stride = effective_ts_stride;
		ts_sc->new_ts_offset = new_ts_offset;
	}

	return true;

error:
	return false;
}


/**
 * @brief Decode timestamp (TS) value with some LSB bits of the TS_SCALED value
 *
 * Use the given TS and TS_SCALED bits.
 * Use the TS_STRIDE and TS_OFFSET values found in context.
 *
 * @param ts_sc              The ts_sc_decomp object
 * @param ts_scaled_bits     The W-LSB-encoded TS_SCALED value
 * @param ts_scaled_bits_nr  The number of bits of TS_SCALED (W-LSB)
 * @param decoded_ts         OUT: The decoded TS
 * @return                   true in case of success, false otherwise
 */
bool ts_decode_scaled_bits(struct ts_sc_decomp *const ts_sc,
                           const uint32_t ts_scaled_bits,
                           const size_t ts_scaled_bits_nr,
                           uint32_t *const decoded_ts)
{
	uint32_t effective_ts_stride;
	uint32_t ts_scaled_decoded;
	bool lsb_decode_ok;

	assert(ts_sc != NULL);
	assert(decoded_ts != NULL);

	/* which TS_STRIDE to use? */
	if(ts_sc->new_ts_stride != 0)
	{
		/* TS_STRIDE was updated by the ROHC packet being currently parsed */
		ts_debug(ts_sc, "decode scaled TS bits %u with updated TS_STRIDE %u\n",
		         ts_scaled_bits, ts_sc->new_ts_stride);
		effective_ts_stride = ts_sc->new_ts_stride;
	}
	else
	{
		/* TS_STRIDE was not updated by the ROHC packet being currently parsed */
		ts_debug(ts_sc, "decode scaled TS bits %u with context TS_STRIDE %u\n",
		         ts_scaled_bits, ts_sc->ts_stride);
		effective_ts_stride = ts_sc->ts_stride;
	}

	/* TS_STRIDE shall not be 0 when using TS_SCALED */
	if(effective_ts_stride == 0)
	{
		ts_debug(ts_sc, "cannot decode TS_SCALED because TS_STRIDE is not "
		         "initialized or 0\n");
		goto error;
	}

	/* update TS_SCALED in context */
	ts_debug(ts_sc, "decode %zd-bit TS_SCALED %u (reference = %u)\n",
	         ts_scaled_bits_nr, ts_scaled_bits,
	         rohc_lsb_get_ref(ts_sc->lsb_ts_scaled, ROHC_LSB_REF_0));
	lsb_decode_ok = rohc_lsb_decode(ts_sc->lsb_ts_scaled, ROHC_LSB_REF_0, 0,
	                                ts_scaled_bits, ts_scaled_bits_nr,
	                                ROHC_LSB_SHIFT_RTP_TS, &ts_scaled_decoded);
	if(!lsb_decode_ok)
	{
		rohc_error(ts_sc, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "failed to decode %zd-bit TS_SCALED %u\n",
		           ts_scaled_bits_nr, ts_scaled_bits);
		goto error;
	}
	ts_debug(ts_sc, "TS_SCALED decoded = %u / 0x%x with %zd bits\n",
	         ts_scaled_decoded, ts_scaled_decoded, ts_scaled_bits_nr);

	/* TS computation with the TS_SCALED we just decoded and the
	   TS_STRIDE/TS_OFFSET values found in context */
	*decoded_ts = effective_ts_stride * ts_scaled_decoded + ts_sc->ts_offset;
	ts_debug(ts_sc, "TS = %u (TS_STRIDE = %u, TS_OFFSET = %u)\n", *decoded_ts,
	         effective_ts_stride, ts_sc->ts_offset);

	/* store the updated TS_* values in context */
	ts_sc->new_ts_scaled = ts_scaled_decoded;
	ts_sc->new_ts_stride = effective_ts_stride;
	ts_sc->new_ts_offset = ts_sc->ts_offset;

	return true;

error:
	return false;
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
	ts_debug(ts_sc, "new TS_SCALED = %u (ref TS_SCALED = %u, new SN = %u, "
	         "ref SN = %u)\n", new_ts_scaled, ts_sc->ts_scaled,
	         sn, ts_sc->sn);

	/* compute the new TS value according to the TS_SCALED value we just
	   computed and the TS_STRIDE/TS_OFFSET values found in context */
	new_ts = new_ts_scaled * ts_sc->ts_stride + ts_sc->ts_offset;
	ts_debug(ts_sc, "new TS = %u (TS_SCALED = %u, TS_STRIDE = %u, "
	         "TS_OFFSET = %u)\n", new_ts, new_ts_scaled, ts_sc->ts_stride,
	         ts_sc->ts_offset);

	/* store the updated TS_* values in context */
	ts_sc->new_ts_scaled = new_ts_scaled;
	ts_sc->new_ts_stride = ts_sc->ts_stride;
	ts_sc->new_ts_offset = ts_sc->ts_offset;

	return new_ts;
}

