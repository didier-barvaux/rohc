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
 * @file   src/comp/schemes/scaled_rtp_ts.c
 * @brief  Scaled RTP Timestamp encoding
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "scaled_rtp_ts.h"
#include "sdvl.h"
#include "rohc_traces_internal.h"

#include <stdlib.h> /* for abs(3) */
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
 * @param trace_cb           The old trace callback
 * @param trace_cb2          The new trace callback
 * @param trace_cb_priv      An optional private context for the trace
 *                           callback, may be NULL
 * @return                   true if creation is successful, false otherwise
 */
bool c_create_sc(struct ts_sc_comp *const ts_sc,
                 const size_t wlsb_window_width,
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
                 rohc_trace_callback_t trace_cb,
#endif
                 rohc_trace_callback2_t trace_cb2,
                 void *const trace_cb_priv)
{
	assert(ts_sc != NULL);
	assert(wlsb_window_width > 0);

	ts_sc->ts_stride = 0;
	ts_sc->ts_scaled = 0;
	ts_sc->ts_offset = 0;
	ts_sc->old_ts = 0;
	ts_sc->ts = 0;
	ts_sc->ts_delta = 0;
	ts_sc->old_sn = 0;
	ts_sc->sn = 0;
	ts_sc->is_deducible = 0;
	ts_sc->state = INIT_TS;
	ts_sc->are_old_val_init = false;
	ts_sc->nr_init_stride_packets = 0;

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	ts_sc->trace_callback = trace_cb;
#endif
	ts_sc->trace_callback2 = trace_cb2;
	ts_sc->trace_callback_priv = trace_cb_priv;

	/* W-LSB context for TS_SCALED */
	ts_sc->ts_scaled_wlsb = c_create_wlsb(32, wlsb_window_width,
	                                      ROHC_LSB_SHIFT_RTP_TS);
	if(ts_sc->ts_scaled_wlsb == NULL)
	{
		rohc_error(ts_sc, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "cannot create a W-LSB window for TS_SCALED");
		goto error;
	}

	/* W-LSB context for unscaled TS */
	ts_sc->ts_unscaled_wlsb = c_create_wlsb(32, wlsb_window_width,
	                                        ROHC_LSB_SHIFT_RTP_TS);
	if(ts_sc->ts_unscaled_wlsb == NULL)
	{
		rohc_error(ts_sc, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "cannot create a W-LSB window for unscaled TS");
		goto free_ts_scaled_wlsb;
	}

	return true;

free_ts_scaled_wlsb:
	c_destroy_wlsb(ts_sc->ts_scaled_wlsb);
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
	assert(ts_sc != NULL);
	assert(ts_sc->ts_unscaled_wlsb != NULL);
	assert(ts_sc->ts_scaled_wlsb != NULL);
	c_destroy_wlsb(ts_sc->ts_unscaled_wlsb);
	c_destroy_wlsb(ts_sc->ts_scaled_wlsb);
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

	assert(ts_sc != NULL);

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
		ts_sc->ts_delta = ts_sc->ts - ts_sc->old_ts;
	}
	else
	{
		ts_sc->ts_delta = ts_sc->old_ts - ts_sc->ts;
	}
	ts_debug(ts_sc, "TS delta = %u", ts_sc->ts_delta);

	/* go back to INIT_TS state if TS is constant */
	if(ts_sc->ts_delta == 0)
	{
		ts_debug(ts_sc, "TS is constant, go in INIT_TS state");
		ts_sc->state = INIT_TS;
		return;
	}

	/* go back to INIT_TS state if TS_STRIDE cannot be SDVL-encoded */
	if(!sdvl_can_value_be_encoded(ts_sc->ts_delta))
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
		if(ts_sc->ts_delta != ts_sc->ts_stride ||
		   (ts_sc->ts % ts_sc->ts_delta) != ts_sc->ts_offset)
		{
			ts_debug(ts_sc, "TS_STRIDE and/or TS_OFFSET changed");
			ts_sc->nr_init_stride_packets = 0;
		}

		/* compute TS_STRIDE, TS_OFFSET and TS_SCALED */
		ts_sc->ts_stride = ts_sc->ts_delta;
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
		ts_debug(ts_sc, "TS_STRIDE calculated = %u", ts_sc->ts_delta);
		ts_debug(ts_sc, "previous TS_STRIDE = %u", ts_sc->ts_stride);
		if(ts_sc->ts_delta != ts_sc->ts_stride)
		{
			assert(ts_sc->ts_stride != 0);
			if((ts_sc->ts_delta % ts_sc->ts_stride) != 0)
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
				ts_sc->ts_stride = ts_sc->ts_delta;
			}
			else if((ts_sc->ts_delta / ts_sc->ts_stride) != sn_delta)
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
			ts_sc->is_deducible = 0;
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
					ts_sc->is_deducible = 0;
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
					ts_sc->is_deducible = 0;
				}
			}
		}
		if(ts_sc->is_deducible)
		{
			ts_debug(ts_sc, "TS can be deducted from SN (old TS_SCALED = %u, "
			         "new TS_SCALED = %u, old SN = %u, new SN = %u)",
			         old_scaled, ts_sc->ts_scaled, ts_sc->old_sn, ts_sc->sn);
			ts_sc->is_deducible = 1;
		}
		else
		{
			ts_debug(ts_sc, "TS can not be deducted from SN (old TS_SCALED = %u, "
			         "new TS_SCALED = %u, old SN = %u, new SN = %u)",
			         old_scaled, ts_sc->ts_scaled, ts_sc->old_sn, ts_sc->sn);
			ts_sc->is_deducible = 0;
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
 * @param ts_sc    The ts_sc_comp object
 * @param bits_nr  OUT: The number of bits needed
 * @return         true in case of success,
 *                 false if the minimal number of bits can not be found
 */
bool nb_bits_unscaled(const struct ts_sc_comp *const ts_sc,
                      size_t *const bits_nr)
{
	return wlsb_get_k_32bits(ts_sc->ts_unscaled_wlsb, ts_sc->ts, bits_nr);
}


/**
 * @brief Add a new unscaled TS value to the ts_sc_comp object
 *
 * @param ts_sc  The ts_sc_comp object
 * @param sn     The Sequence Number
 */
void add_unscaled(const struct ts_sc_comp *const ts_sc, const uint16_t sn)
{
	assert(ts_sc != NULL);
	c_add_wlsb(ts_sc->ts_unscaled_wlsb, sn, ts_sc->ts);
}


/**
 * @brief Return the number of bits needed to encode TS_SCALED
 *
 * @param ts_sc    The ts_sc_comp object
 * @param bits_nr  OUT: The number of bits needed
 * @return         true in case of success,
 *                 false if the minimal number of bits can not be found
 */
bool nb_bits_scaled(const struct ts_sc_comp *const ts_sc,
                    size_t *const bits_nr)
{
	return wlsb_get_k_32bits(ts_sc->ts_scaled_wlsb, ts_sc->ts_scaled, bits_nr);
}


/**
 * @brief Add a new TS_SCALED value to the ts_sc_comp object
 *
 * @param ts_sc        The ts_sc_comp object
 * @param sn           The Sequence Number
 */
void add_scaled(const struct ts_sc_comp *const ts_sc, const uint16_t sn)
{
	assert(ts_sc != NULL);
	c_add_wlsb(ts_sc->ts_scaled_wlsb, sn, ts_sc->ts_scaled);
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

