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

	ts_sc->ts_stride = 0;
	ts_sc->ts_scaled = 0;
	ts_sc->ts_offset = 0;
	ts_sc->old_ts = 0;
	ts_sc->ts = 0;
	ts_sc->old_sn = 0;
	ts_sc->sn = 0;
	ts_sc->is_deducible = false;
	ts_sc->state = INIT_TS;
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
 * @param ts_sc        The ts_sc_comp object
 * @param ts           The timestamp to add
 * @param sn           The sequence number of the RTP packet
 */
void c_add_ts(struct ts_sc_comp *const ts_sc,
              const uint32_t ts,
              const uint16_t sn)
{
	uint16_t sn_delta;
	uint32_t ts_delta;

	ts_debug(ts_sc, "Timestamp = %u", ts);

	/* consider that TS bits are not deducible by default */
	ts_sc->is_deducible = false;

	/* we save the old value */
	ts_sc->old_ts = ts_sc->ts;
	ts_sc->old_sn = ts_sc->sn;

	/* we store the new value */
	ts_sc->ts = ts;
	ts_sc->sn = sn;

	/* if we had no old values, TS_STRIDE cannot be computed yet */
	if(!ts_sc->are_old_val_init)
	{
		assert(ts_sc->state == INIT_TS);
		ts_debug(ts_sc, "TS_STRIDE cannot be computed, stay in INIT_TS state");
		ts_sc->are_old_val_init = true;
		return;
	}

	/* compute the absolute delta between new and old SN */
	/* abs() on unsigned 16-bit values seems to be a problem sometimes */
	if(ts_sc->sn >= ts_sc->old_sn)
	{
		sn_delta = ts_sc->sn - ts_sc->old_sn;
	}
	else
	{
		sn_delta = ts_sc->old_sn - ts_sc->sn;
	}
	ts_debug(ts_sc, "SN delta = %u", sn_delta);

	/* compute the absolute delta between new and old TS */
	/* abs() on unsigned 32-bit values seems to be a problem sometimes */
	if(ts_sc->ts >= ts_sc->old_ts)
	{
		ts_delta = ts_sc->ts - ts_sc->old_ts;
	}
	else
	{
		ts_delta = ts_sc->old_ts - ts_sc->ts;
	}
	ts_debug(ts_sc, "TS delta = %u", ts_delta);

	/* go back to INIT_TS state if TS is constant */
	if(ts_delta == 0)
	{
		ts_debug(ts_sc, "TS is constant, go in INIT_TS state");
		ts_sc->state = INIT_TS;
		return;
	}

	/* go back to INIT_TS state if TS_STRIDE cannot be SDVL-encoded */
	if(!sdvl_can_value_be_encoded(ts_delta))
	{
		/* TS_STRIDE is too large for SDVL encoding */
		ts_debug(ts_sc, "TS_STRIDE is too large for SDVL encoding, "
		         "go in INIT_TS state");
		ts_sc->state = INIT_TS;
		return;
	}

	/* TS_STRIDE can be computed, so leave INIT_TS state */
	if(ts_sc->state == INIT_TS)
	{
		ts_debug(ts_sc, "TS_STRIDE can be computed, go to INIT_STRIDE state");
		ts_sc->state = INIT_STRIDE;
		ts_sc->nr_init_stride_packets = 0;
	}

	if(ts_sc->state == INIT_STRIDE)
	{
		/* TS is changing and TS_STRIDE can be computed but TS_STRIDE was
		 * not transmitted enough times to the decompressor to be used */
		ts_debug(ts_sc, "state INIT_STRIDE");

		/* reset INIT_STRIDE counter if TS_STRIDE/TS_OFFSET changed */
		if(ts_delta != ts_sc->ts_stride ||
		   (ts_sc->ts % ts_delta) != ts_sc->ts_offset)
		{
			ts_debug(ts_sc, "TS_STRIDE and/or TS_OFFSET changed");
			ts_sc->nr_init_stride_packets = 0;
		}

		/* compute TS_STRIDE, TS_OFFSET and TS_SCALED */
		ts_sc->ts_stride = ts_delta;
		ts_debug(ts_sc, "TS_STRIDE = %u", ts_sc->ts_stride);
		assert(ts_sc->ts_stride != 0);
		ts_sc->ts_offset = ts_sc->ts % ts_sc->ts_stride;
		ts_debug(ts_sc, "TS_OFFSET = %u modulo %u = %u",
		         ts_sc->ts, ts_sc->ts_stride, ts_sc->ts_offset);
		assert(ts_sc->ts_stride != 0);
		ts_sc->ts_scaled = (ts_sc->ts - ts_sc->ts_offset) / ts_sc->ts_stride;
		ts_debug(ts_sc, "TS_SCALED = (%u - %u) / %u = %u", ts_sc->ts,
		         ts_sc->ts_offset, ts_sc->ts_stride, ts_sc->ts_scaled);
	}
	else if(ts_sc->state == SEND_SCALED)
	{
		const uint32_t old_scaled = ts_sc->ts_scaled;
		const uint32_t old_offset = ts_sc->ts_offset;

		/* TS is changing, TS_STRIDE can be computed, and TS_STRIDE was
		 * transmitted enough times to the decompressor to be used */
		ts_debug(ts_sc, "state SEND_SCALED");

		/* does TS_STRIDE changed? */
		ts_debug(ts_sc, "TS_STRIDE calculated = %u", ts_delta);
		ts_debug(ts_sc, "previous TS_STRIDE = %u", ts_sc->ts_stride);
		if(ts_delta != ts_sc->ts_stride)
		{
			assert(ts_sc->ts_stride != 0);
			if((ts_delta % ts_sc->ts_stride) != 0)
			{
				/* TS delta changed and is not a multiple of previous TS_STRIDE:
				 * record the new value as TS_STRIDE and transmit it several
				 * times for robustness purposes */
				ts_debug(ts_sc, "/!\\ TS_STRIDE changed and is not a multiple "
				         "of previous TS_STRIDE, so change TS_STRIDE and "
				         "transmit it several times along all TS bits "
				         "(probably a clock resync at source)");
				ts_sc->state = INIT_STRIDE;
				ts_sc->nr_init_stride_packets = 0;
				ts_debug(ts_sc, "state -> INIT_STRIDE");
				ts_sc->ts_stride = ts_delta;
			}
			else if((ts_delta / ts_sc->ts_stride) != sn_delta)
			{
				/* TS delta changed but is a multiple of previous TS_STRIDE:
				 * do not change TS_STRIDE, but transmit all TS bits several
				 * times for robustness purposes */
				ts_debug(ts_sc, "/!\\ TS delta changed but is a multiple of "
				         "previous TS_STRIDE, so do not change TS_STRIDE, but "
				         "retransmit it several times along all TS bits "
				         "(probably a RTP TS jump at source)");
				ts_sc->state = INIT_STRIDE;
				ts_sc->nr_init_stride_packets = 0;
				ts_debug(ts_sc, "state -> INIT_STRIDE");
			}
			else
			{
				/* do not change TS_STRIDE, probably a packet loss */
				ts_debug(ts_sc, "/!\\ TS delta changed, is a multiple of "
				         "previous TS_STRIDE and follows SN changes, so do "
				         "not change TS_STRIDE (probably a packet loss)");
			}
		}
		ts_debug(ts_sc, "TS_STRIDE = %u", ts_sc->ts_stride);

		/* update TS_OFFSET is needed */
		assert(ts_sc->ts_stride != 0);
		ts_sc->ts_offset = ts_sc->ts % ts_sc->ts_stride;
		ts_debug(ts_sc, "TS_OFFSET = %u modulo %u = %u",
		         ts_sc->ts, ts_sc->ts_stride, ts_sc->ts_offset);

		/* compute TS_SCALED */
		assert(ts_sc->ts_stride != 0);
		ts_sc->ts_scaled = (ts_sc->ts - ts_sc->ts_offset) / ts_sc->ts_stride;
		ts_debug(ts_sc, "TS_SCALED = (%u - %u) / %u = %u", ts_sc->ts,
		         ts_sc->ts_offset, ts_sc->ts_stride, ts_sc->ts_scaled);

		/* could TS_SCALED be deduced from SN? */
		if(ts_sc->state != SEND_SCALED)
		{
			ts_sc->is_deducible = false;
		}
		else
		{
			uint32_t ts_scaled_delta;

			/* be cautious with positive and negative deltas */
			if(ts_sc->ts_scaled >= old_scaled)
			{
				ts_scaled_delta = ts_sc->ts_scaled - old_scaled;

				if(ts_sc->sn >= ts_sc->old_sn)
				{
					ts_sc->is_deducible = (ts_scaled_delta == sn_delta);
				}
				else
				{
					ts_sc->is_deducible = false;
				}
			}
			else
			{
				ts_scaled_delta = old_scaled - ts_sc->ts_scaled;

				if(ts_sc->old_sn >= ts_sc->sn)
				{
					ts_sc->is_deducible = (ts_scaled_delta == sn_delta);
				}
				else
				{
					ts_sc->is_deducible = false;
				}
			}
		}
		if(ts_sc->is_deducible)
		{
			ts_debug(ts_sc, "TS can be deducted from SN (old TS_SCALED = %u, "
			         "new TS_SCALED = %u, old SN = %u, new SN = %u)",
			         old_scaled, ts_sc->ts_scaled, ts_sc->old_sn, ts_sc->sn);
		}
		else
		{
			ts_debug(ts_sc, "TS can not be deducted from SN (old TS_SCALED = %u, "
			         "new TS_SCALED = %u, old SN = %u, new SN = %u)",
			         old_scaled, ts_sc->ts_scaled, ts_sc->old_sn, ts_sc->sn);
		}

		/* Wraparound (See RFC 4815 Section 4.4.3) */
		if(ts_sc->ts < ts_sc->old_ts)
		{
			ts_debug(ts_sc, "TS wraparound detected");
			if(old_offset != ts_sc->ts_offset)
			{
				ts_debug(ts_sc, "TS_OFFSET changed, re-initialize TS_STRIDE");
				ts_sc->state = INIT_STRIDE;
				ts_sc->nr_init_stride_packets = 0;
			}
			else
			{
				ts_debug(ts_sc, "TS_OFFSET is unchanged");
			}
		}
	}
	else
	{
		/* invalid state, should not happen */
		ts_debug(ts_sc, "invalid state (%d), should not happen", ts_sc->state);
		assert(0);
		return;
	}
}


/**
 * @brief Return the number of bits needed to encode unscaled TS
 *
 * @param ts_sc  The ts_sc_comp object
 * @return       The number of bits needed to encode the unscaled TS
 */
size_t nb_bits_unscaled(const struct ts_sc_comp *const ts_sc)
{
	size_t nr_ts_bits;

	if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                              0, rohc_interval_compute_p_rtp_ts(0)))
	{
		nr_ts_bits = 0;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   5, rohc_interval_compute_p_rtp_ts(5)))
	{
		nr_ts_bits = 5;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   6, rohc_interval_compute_p_rtp_ts(6)))
	{
		nr_ts_bits = 6;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   7, rohc_interval_compute_p_rtp_ts(7)))
	{
		nr_ts_bits = 7;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   8, rohc_interval_compute_p_rtp_ts(8)))
	{
		nr_ts_bits = 8;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   9, rohc_interval_compute_p_rtp_ts(9)))
	{
		nr_ts_bits = 9;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   12, rohc_interval_compute_p_rtp_ts(12)))
	{
		nr_ts_bits = 12;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   13, rohc_interval_compute_p_rtp_ts(13)))
	{
		nr_ts_bits = 13;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   14, rohc_interval_compute_p_rtp_ts(14)))
	{
		nr_ts_bits = 14;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   16, rohc_interval_compute_p_rtp_ts(16)))
	{
		nr_ts_bits = 16;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   17, rohc_interval_compute_p_rtp_ts(17)))
	{
		nr_ts_bits = 17;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   19, rohc_interval_compute_p_rtp_ts(19)))
	{
		nr_ts_bits = 19;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   20, rohc_interval_compute_p_rtp_ts(20)))
	{
		nr_ts_bits = 20;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   21, rohc_interval_compute_p_rtp_ts(21)))
	{
		nr_ts_bits = 21;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   25, rohc_interval_compute_p_rtp_ts(25)))
	{
		nr_ts_bits = 25;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   26, rohc_interval_compute_p_rtp_ts(26)))
	{
		nr_ts_bits = 26;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
	                                   27, rohc_interval_compute_p_rtp_ts(27)))
	{
		nr_ts_bits = 27;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_unscaled_wlsb, ts_sc->ts,
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
 * @brief Add a new unscaled TS value to the ts_sc_comp object
 *
 * @param ts_sc  The ts_sc_comp object
 * @param sn     The Sequence Number
 */
void add_unscaled(struct ts_sc_comp *const ts_sc, const uint16_t sn)
{
	c_add_wlsb(&ts_sc->ts_unscaled_wlsb, sn, ts_sc->ts);
}


/**
 * @brief Return the number of bits needed to encode TS_SCALED
 *
 * @param ts_sc  The ts_sc_comp object
 * @return       The number of bits needed to encode TS_SCALED
 */
size_t nb_bits_scaled(const struct ts_sc_comp *const ts_sc)
{
	size_t nr_ts_bits;

	if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                              0, rohc_interval_compute_p_rtp_ts(0)))
	{
		nr_ts_bits = 0;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   5, rohc_interval_compute_p_rtp_ts(5)))
	{
		nr_ts_bits = 5;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   6, rohc_interval_compute_p_rtp_ts(6)))
	{
		nr_ts_bits = 6;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   7, rohc_interval_compute_p_rtp_ts(7)))
	{
		nr_ts_bits = 7;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   8, rohc_interval_compute_p_rtp_ts(8)))
	{
		nr_ts_bits = 8;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   9, rohc_interval_compute_p_rtp_ts(9)))
	{
		nr_ts_bits = 9;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   12, rohc_interval_compute_p_rtp_ts(12)))
	{
		nr_ts_bits = 12;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   13, rohc_interval_compute_p_rtp_ts(13)))
	{
		nr_ts_bits = 13;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   14, rohc_interval_compute_p_rtp_ts(14)))
	{
		nr_ts_bits = 14;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   16, rohc_interval_compute_p_rtp_ts(16)))
	{
		nr_ts_bits = 16;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   17, rohc_interval_compute_p_rtp_ts(17)))
	{
		nr_ts_bits = 17;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   19, rohc_interval_compute_p_rtp_ts(19)))
	{
		nr_ts_bits = 19;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   20, rohc_interval_compute_p_rtp_ts(20)))
	{
		nr_ts_bits = 20;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   21, rohc_interval_compute_p_rtp_ts(21)))
	{
		nr_ts_bits = 21;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   25, rohc_interval_compute_p_rtp_ts(25)))
	{
		nr_ts_bits = 25;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   26, rohc_interval_compute_p_rtp_ts(26)))
	{
		nr_ts_bits = 26;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   27, rohc_interval_compute_p_rtp_ts(27)))
	{
		nr_ts_bits = 27;
	}
	else if(wlsb_is_kp_possible_32bits(&ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled,
	                                   29, rohc_interval_compute_p_rtp_ts(29)))
	{
		nr_ts_bits = 29;
	}
	else
	{
		nr_ts_bits = 32;
	}

	/* do not send 0 bit of TS if TS is not deducible, because decompressor
	 * will interprets a 0-bit value as deducible */
	if(!ts_sc->is_deducible)
	{
		nr_ts_bits = 1;
	}

	return nr_ts_bits;
}


/**
 * @brief Add a new TS_SCALED value to the ts_sc_comp object
 *
 * @param ts_sc        The ts_sc_comp object
 * @param sn           The Sequence Number
 */
void add_scaled(struct ts_sc_comp *const ts_sc, const uint16_t sn)
{
	c_add_wlsb(&ts_sc->ts_scaled_wlsb, sn, ts_sc->ts_scaled);
}


/**
 * @brief Return the TS_STRIDE value
 *
 * @param ts_sc        The ts_sc_comp object
 * @return             TS_STRIDE value
 */
uint32_t get_ts_stride(const struct ts_sc_comp *const ts_sc)
{
	return ts_sc->ts_stride;
}


/**
 * @brief Return the TS_SCALED value
 *
 * @param ts_sc        The ts_sc_comp object
 * @return             The TS_SCALED value
 */
uint32_t get_ts_scaled(const struct ts_sc_comp *const ts_sc)
{
	return ts_sc->ts_scaled;
}


/**
 * @brief Return the unscaled TS value
 *
 * @param ts_sc  The ts_sc_comp object
 * @return       The unscaled TS value
 */
uint32_t get_ts_unscaled(const struct ts_sc_comp *const ts_sc)
{
	return ts_sc->ts;
}


/**
 * @brief Whether TimeStamp (TS) is deducible from the Sequence Number (SN)
 *        or not
 *
 * @param ts_sc  The TS SCALED compression context
 * @return       true if TS is deducible from SN, false otherwise
 */
bool rohc_ts_sc_is_deducible(const struct ts_sc_comp *const ts_sc)
{
	return ts_sc->is_deducible;
}

