/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2013 Viveris Technologies
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
 * @file   schemes/comp_scaled_rtp_ts.c
 * @brief  Scaled RTP Timestamp encoding
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "comp_scaled_rtp_ts.h"
#include "sdvl.h"
#include "rohc_traces_internal.h"

#include <assert.h>


/** Print debug messages for the ts_sc_comp module */
#define ts_debug(entity_struct, format, ...) \
	rohc_debug(entity_struct, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, \
	           format, ##__VA_ARGS__)


/**
 * @brief Create the ts_sc_comp object
 *
 * @param ts_sc              The ts_sc_comp object to create
 * @param wlsb_window_width  The width of the W-LSB sliding window to use
 *                           for TS_STRIDE (must be > 0)
 * @param trace_cb           The trace callback
 * @param trace_cb_priv      An optional private context for the trace
 *                           callback, may be NULL
 * @return                   true if creation is successful, false otherwise
 */
bool c_create_sc(struct ts_sc_comp *const ts_sc,
                 const size_t wlsb_window_width,
                 rohc_trace_callback2_t trace_cb,
                 void *const trace_cb_priv)
{
	bool is_ok;

	assert(wlsb_window_width > 0);

	ts_sc->old.ts = 0;
	ts_sc->old.sn = 0;
	ts_sc->old.state = INIT_TS;
	ts_sc->old.ts_stride = 0;
	ts_sc->old.ts_offset = 0;
	ts_sc->old.ts_scaled = 0;
	ts_sc->old.is_ts_scaled_deducible = false;

	ts_sc->are_old_val_init = false;
	ts_sc->nr_init_stride_packets = 0;

	ts_sc->trace_callback = trace_cb;
	ts_sc->trace_callback_priv = trace_cb_priv;

	/* W-LSB context for TS_SCALED */
	is_ok = wlsb_new(&ts_sc->ts_scaled_wlsb, wlsb_window_width);
	if(!is_ok)
	{
		rohc_error(ts_sc, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "cannot create a W-LSB window for TS_SCALED");
		goto error;
	}

	/* W-LSB context for unscaled TS */
	is_ok = wlsb_new(&ts_sc->ts_unscaled_wlsb, wlsb_window_width);
	if(!is_ok)
	{
		rohc_error(ts_sc, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "cannot create a W-LSB window for unscaled TS");
		goto free_ts_scaled_wlsb;
	}

	return true;

free_ts_scaled_wlsb:
	wlsb_free(&ts_sc->ts_scaled_wlsb);
error:
	return false;
}


/**
 * @brief Destroy the ts_sc_comp object
 *
 * @param ts_sc        The ts_sc_comp object to destroy
 */
void c_destroy_sc(struct ts_sc_comp *const ts_sc)
{
	wlsb_free(&ts_sc->ts_unscaled_wlsb);
	wlsb_free(&ts_sc->ts_scaled_wlsb);
}


/**
 * @brief Store the new TS, calculate new values and update the state
 *
 * @param ts_sc                 The ts_sc_comp object
 * @param new_ts                The new TS to encode
 * @param new_sn                The new RTP Sequence Number (SN)
 * @param do_refresh_ts_stride  Whether TS_STRIDE value shall be refreshed or not
 * @param[out] new              The detected changes related to TS
 */
void ts_detect_changes(const struct ts_sc_comp *const ts_sc,
                       const uint32_t new_ts,
                       const uint16_t new_sn,
                       const bool do_refresh_ts_stride,
                       struct ts_sc_changes *const new)
{
	uint16_t sn_delta;
	uint32_t ts_delta;

	ts_debug(ts_sc, "RTP Timestamp = %u", new_ts);

	/* consider that TS bits are not deducible by default */
	new->is_ts_scaled_deducible = false;
	/* new state is current state by default */
	new->state = ts_sc->old.state;

	/* store the new TS and SN values */
	new->ts = new_ts;
	new->sn = new_sn;

	/* if we had no old values, TS_STRIDE cannot be computed yet */
	if(!ts_sc->are_old_val_init)
	{
		assert(new->state == INIT_TS);
		ts_debug(ts_sc, "TS_STRIDE cannot be computed, stay in INIT_TS state");
		return;
	}

	/* compute the absolute delta between new and old SN */
	/* abs() on unsigned 16-bit values seems to be a problem sometimes */
	if(new->sn >= ts_sc->old.sn)
	{
		sn_delta = new->sn - ts_sc->old.sn;
	}
	else
	{
		sn_delta = ts_sc->old.sn - new->sn;
	}
	ts_debug(ts_sc, "SN delta = %u", sn_delta);

	/* compute the absolute delta between new and old TS */
	/* abs() on unsigned 32-bit values seems to be a problem sometimes */
	if(new->ts >= ts_sc->old.ts)
	{
		ts_delta = new->ts - ts_sc->old.ts;
	}
	else
	{
		ts_delta = ts_sc->old.ts - new->ts;
	}
	ts_debug(ts_sc, "TS delta = %u", ts_delta);

	/* go back to INIT_TS state if TS is constant */
	if(ts_delta == 0)
	{
		ts_debug(ts_sc, "TS is constant, go in INIT_TS state");
		new->state = INIT_TS;
		return;
	}

	/* go back to INIT_TS state if TS_STRIDE cannot be SDVL-encoded */
	if(!sdvl_can_value_be_encoded(ts_delta))
	{
		/* TS_STRIDE is too large for SDVL encoding */
		ts_debug(ts_sc, "TS_STRIDE is too large for SDVL encoding, "
		         "go in INIT_TS state");
		new->state = INIT_TS;
		return;
	}

	/* TS_STRIDE can be computed, so leave INIT_TS state */
	if(new->state == INIT_TS)
	{
		ts_debug(ts_sc, "TS_STRIDE can be computed, go to INIT_STRIDE state");
		new->state = INIT_STRIDE;
	}

	/* force INIT_STRIDE state if refresh is required in SEND_SCALED state */
	if(new->state == SEND_SCALED && do_refresh_ts_stride)
	{
		ts_debug(ts_sc, "TS_STRIDE shall be refreshed, go to INIT_STRIDE state");
		new->state = INIT_STRIDE;
	}

	/* TS_STRIDE can be computed, so only INIT_STRIDE/SEND_SCALED states possible */
	assert(new->state == INIT_STRIDE || new->state == SEND_SCALED);

	/* compute TS_STRIDE depending on INIT_STRIDE/SEND_SCALED state */
	if(new->state == INIT_STRIDE)
	{
		/* TS is changing and TS_STRIDE can be computed but TS_STRIDE was
		 * not transmitted enough times to the decompressor to be used */
		ts_debug(ts_sc, "state INIT_STRIDE");

		/* reset INIT_STRIDE counter if TS_STRIDE/TS_OFFSET changed */
		ts_debug(ts_sc, "TS_STRIDE = %u -> %u ?", ts_sc->old.ts_stride, ts_delta);
		if(ts_delta != ts_sc->old.ts_stride ||
		   (new->ts % ts_delta) != ts_sc->old.ts_offset)
		{
			ts_debug(ts_sc, "TS_STRIDE and/or TS_OFFSET changed");
		}

		/* compute TS_STRIDE, TS_OFFSET and TS_SCALED */
		new->ts_stride = ts_delta;
		ts_debug(ts_sc, "TS_STRIDE = %u", new->ts_stride);

		/* compute TS_OFFSET */
		assert(new->ts_stride != 0);
		new->ts_offset = new->ts % new->ts_stride;
		ts_debug(ts_sc, "TS_OFFSET = %u modulo %u = %u",
		         new->ts, new->ts_stride, new->ts_offset);

		/* compute TS_SCALED */
		assert(new->ts_stride != 0);
		new->ts_scaled = (new->ts - new->ts_offset) / new->ts_stride;
		ts_debug(ts_sc, "TS_SCALED = (%u - %u) / %u = %u", new->ts,
		         new->ts_offset, new->ts_stride, new->ts_scaled);
	}
	else /* SEND_SCALED */
	{
		/* TS is changing, TS_STRIDE can be computed, and TS_STRIDE was
		 * transmitted enough times to the decompressor to be used */
		ts_debug(ts_sc, "state SEND_SCALED");

		/* does TS delta changed? */
		ts_debug(ts_sc, "TS delta = %u -> %u ?", ts_sc->old.ts_stride, ts_delta);
		if(ts_delta == ts_sc->old.ts_stride)
		{
			/* TS delta did not change, keep TS_STRIDE unchanged */
			new->ts_stride = ts_sc->old.ts_stride;
		}
		else
		{
			/* TS delta did change, do we change TS_STRIDE? */
			assert(ts_sc->old.ts_stride != 0);
			if((ts_delta % ts_sc->old.ts_stride) != 0)
			{
				/* TS delta changed and is not a multiple of previous TS_STRIDE:
				 * record the new value as TS_STRIDE and transmit it several
				 * times for robustness purposes */
				ts_debug(ts_sc, "TS_STRIDE changed, but is not a multiple of previous "
				         "TS_STRIDE, so change TS_STRIDE and transmit it several times "
				         "along all TS bits (probably a clock resync at source)");
				new->state = INIT_STRIDE;
				new->ts_stride = ts_delta;
			}
			else if((ts_delta / ts_sc->old.ts_stride) != sn_delta)
			{
				/* TS delta changed but is a multiple of previous TS_STRIDE:
				 * do not change TS_STRIDE, but transmit all TS bits several
				 * times for robustness purposes */
				ts_debug(ts_sc, "TS delta changed, is a multiple of previous TS_STRIDE, "
				         "but does not follow SN changes, so do not change TS_STRIDE, "
				         "but retransmit it several times along all TS bits (probably "
				         "a RTP TS jump at source)");
				new->state = INIT_STRIDE;
				new->ts_stride = ts_sc->old.ts_stride;
			}
			else
			{
				/* do not change TS_STRIDE, probably a packet loss */
				ts_debug(ts_sc, "TS delta changed, is a multiple of previous TS_STRIDE "
				         "and follows SN changes, so do not change TS_STRIDE (probably "
				         "a packet loss)");
				new->ts_stride = ts_sc->old.ts_stride;
			}
		}
		ts_debug(ts_sc, "TS_STRIDE = %u", new->ts_stride);
	}

	/* compute TS_OFFSET */
	assert(new->ts_stride != 0);
	new->ts_offset = new->ts % new->ts_stride;
	ts_debug(ts_sc, "TS_OFFSET = %u modulo %u = %u",
	         new->ts, new->ts_stride, new->ts_offset);

	/* compute TS_SCALED */
	assert(new->ts_stride != 0);
	new->ts_scaled = (new->ts - new->ts_offset) / new->ts_stride;
	ts_debug(ts_sc, "TS_SCALED = (%u - %u) / %u = %u", new->ts,
	         new->ts_offset, new->ts_stride, new->ts_scaled);

	/* could TS_SCALED be deduced from SN? */
	if(new->state != SEND_SCALED)
	{
		new->is_ts_scaled_deducible = false;
	}
	else
	{
		uint32_t ts_scaled_delta;

		/* be cautious with positive and negative deltas */
		if(new->ts_scaled >= ts_sc->old.ts_scaled)
		{
			ts_scaled_delta = new->ts_scaled - ts_sc->old.ts_scaled;

			if(new->sn >= ts_sc->old.sn)
			{
				new->is_ts_scaled_deducible = !!(ts_scaled_delta == sn_delta);
			}
			else
			{
				new->is_ts_scaled_deducible = false;
			}
		}
		else
		{
			ts_scaled_delta = ts_sc->old.ts_scaled - new->ts_scaled;

			if(ts_sc->old.sn >= new->sn)
			{
				new->is_ts_scaled_deducible = !!(ts_scaled_delta == sn_delta);
			}
			else
			{
				new->is_ts_scaled_deducible = false;
			}
		}
	}
	if(new->is_ts_scaled_deducible)
	{
		ts_debug(ts_sc, "TS can be deducted from SN (TS_SCALED = %u -> %u, "
		         "SN = %u -> %u)", ts_sc->old.ts_scaled, new->ts_scaled,
		         ts_sc->old.sn, new->sn);
	}
	else
	{
		ts_debug(ts_sc, "TS can not be deducted from SN (TS_SCALED = %u -> %u, "
		         "SN = %u -> %u)", ts_sc->old.ts_scaled, new->ts_scaled,
		         ts_sc->old.sn, new->sn);
	}

	/* handle TS wraparound (see RFC 4815 section 4.4.3) */
	if(new->ts < ts_sc->old.ts)
	{
		ts_debug(ts_sc, "TS wraparound detected");
		if(ts_sc->old.ts_offset != new->ts_offset)
		{
			ts_debug(ts_sc, "TS_OFFSET changed, re-initialize TS_STRIDE");
			new->state = INIT_STRIDE;
		}
		else
		{
			ts_debug(ts_sc, "TS_OFFSET is unchanged, do not re-initialize TS_STRIDE");
		}
	}
}


/**
 * @brief Return the number of bits needed to encode unscaled TS
 *
 * @param ts_unscaled_wlsb  The W-LSB window of unscaled TS
 * @param new_ts_unscaled   The new unscaled TS value to encode
 * @return                  The number of bits needed to encode the unscaled TS
 */
size_t nb_bits_unscaled(const struct c_wlsb *const ts_unscaled_wlsb,
                        const uint32_t new_ts_unscaled)
{
	size_t nr_ts_bits;

	if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                              0, rohc_interval_compute_p_rtp_ts(0)))
	{
		nr_ts_bits = 0;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   5, rohc_interval_compute_p_rtp_ts(5)))
	{
		nr_ts_bits = 5;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   6, rohc_interval_compute_p_rtp_ts(6)))
	{
		nr_ts_bits = 6;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   7, rohc_interval_compute_p_rtp_ts(7)))
	{
		nr_ts_bits = 7;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   8, rohc_interval_compute_p_rtp_ts(8)))
	{
		nr_ts_bits = 8;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   9, rohc_interval_compute_p_rtp_ts(9)))
	{
		nr_ts_bits = 9;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   12, rohc_interval_compute_p_rtp_ts(12)))
	{
		nr_ts_bits = 12;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   13, rohc_interval_compute_p_rtp_ts(13)))
	{
		nr_ts_bits = 13;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   14, rohc_interval_compute_p_rtp_ts(14)))
	{
		nr_ts_bits = 14;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   16, rohc_interval_compute_p_rtp_ts(16)))
	{
		nr_ts_bits = 16;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   17, rohc_interval_compute_p_rtp_ts(17)))
	{
		nr_ts_bits = 17;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   19, rohc_interval_compute_p_rtp_ts(19)))
	{
		nr_ts_bits = 19;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   20, rohc_interval_compute_p_rtp_ts(20)))
	{
		nr_ts_bits = 20;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   21, rohc_interval_compute_p_rtp_ts(21)))
	{
		nr_ts_bits = 21;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   25, rohc_interval_compute_p_rtp_ts(25)))
	{
		nr_ts_bits = 25;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   26, rohc_interval_compute_p_rtp_ts(26)))
	{
		nr_ts_bits = 26;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   27, rohc_interval_compute_p_rtp_ts(27)))
	{
		nr_ts_bits = 27;
	}
	else if(wlsb_is_kp_possible_32bits(ts_unscaled_wlsb, new_ts_unscaled,
	                                   29, rohc_interval_compute_p_rtp_ts(29)))
	{
		nr_ts_bits = 29;
	}
	else
	{
		nr_ts_bits = 32;
	}

	return nr_ts_bits;
}


/**
 * @brief Return the number of bits needed to encode TS_SCALED
 *
 * @param ts_scaled_wlsb          The W-LSB window of TS_SCALED
 * @param new_ts_scaled           The new TS_SCALED value to encode
 * @param is_ts_scaled_deducible  Whether TS_SCALED is deducible from SN or not
 * @return                        The number of bits needed to encode TS_SCALED
 */
size_t nb_bits_scaled(const struct c_wlsb *const ts_scaled_wlsb,
                      const uint32_t new_ts_scaled,
                      const bool is_ts_scaled_deducible)
{
	size_t nr_ts_bits;

	/* do not send 0 bit of TS if TS is not deducible, because decompressor
	 * will interprets a 0-bit value as deducible */
	if(!is_ts_scaled_deducible)
	{
		nr_ts_bits = 1;
	}
	else
	{
		nr_ts_bits = nb_bits_unscaled(ts_scaled_wlsb, new_ts_scaled);
	}

	return nr_ts_bits;
}


/**
 * @brief Update the TS Scaled context with last changes
 *
 * @param ts_sc    The ts_sc_comp object
 * @param changes  The last changes
 */
void ts_sc_update(struct ts_sc_comp *const ts_sc,
                  const struct ts_sc_changes *const changes)
{
	/* if old TS and SN values were not initialized yet, they should now be */
	if(!ts_sc->are_old_val_init)
	{
		assert(ts_sc->old.state == INIT_TS);
		ts_sc->are_old_val_init = true;
	}

	/* reset transmission counter:
	 *  - if compressor just changed to INIT_STRIDE state,
	 *  - if TS_STRIDE/TS_OFFSET just changed in INIT_STRIDE state */
	if((changes->state == INIT_STRIDE && ts_sc->old.state != INIT_STRIDE) ||
	   changes->ts_stride != ts_sc->old.ts_stride ||
	   changes->ts_offset != ts_sc->old.ts_offset)
	{
		ts_sc->nr_init_stride_packets = 0;
	}

	/* update context with all temporary values */
	memcpy(&ts_sc->old, changes, sizeof(struct ts_sc_changes));

	/* update context with new TS_SCALED value */
	if(changes->state == SEND_SCALED)
	{
		c_add_wlsb(&ts_sc->ts_scaled_wlsb, changes->sn, changes->ts_scaled);
	}

	/* update context with new TS unscaled value */
	c_add_wlsb(&ts_sc->ts_unscaled_wlsb, changes->sn, changes->ts);

}



