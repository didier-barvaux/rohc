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
 * @file ts_sc_comp.c
 * @brief Scaled RTP Timestamp encoding
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "ts_sc_comp.h"
#include "sdvl.h"
#include "rohc_traces.h"

#include <stdlib.h> /* for abs(3) */
#include <assert.h>


/**
 * @brief Create the ts_sc_comp object
 *
 * @param ts_sc              The ts_sc_comp object to create
 * @param wlsb_window_width  The width of the W-LSB sliding window to use
 *                           for TS_STRIDE (must be > 0)
 * @return                   1 if creation is successful, 0 otherwise
 */
int c_create_sc(struct ts_sc_comp *const ts_sc,
                const size_t wlsb_window_width)
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
	ts_sc->is_deductible = 0;
	ts_sc->state = INIT_TS;
	ts_sc->nr_init_stride_packets = 0;

	ts_sc->scaled_window = c_create_wlsb(32, wlsb_window_width,
	                                     ROHC_LSB_SHIFT_RTP_TS);
	if(ts_sc->scaled_window == NULL)
	{
		rohc_debugf(0, "cannot create a W-LSB window for TS scaled\n");
		goto error;
	}

	return 1;

error:
	return 0;
}


/**
 * @brief Destroy the ts_sc_comp object
 *
 * @param ts_sc        The ts_sc_comp object to destroy
 */
void c_destroy_sc(struct ts_sc_comp *const ts_sc)
{
	assert(ts_sc != NULL);
	assert(ts_sc->scaled_window != NULL);
	c_destroy_wlsb(ts_sc->scaled_window);
}


/**
 * @brief Store the new TS, calculate new values and update the state
 *
 * @param ts_sc        The ts_sc_comp object
 * @param ts           The timestamp to add
 * @param sn           The sequence number of the RTP packet
 */
void c_add_ts(struct ts_sc_comp *const ts_sc, const uint32_t ts, const uint16_t sn)
{
	assert(ts_sc != NULL);

	rohc_debugf(2, "Timestamp = %u\n", ts);

	/* we save the old value */
	ts_sc->old_ts = ts_sc->ts;
	ts_sc->old_sn = ts_sc->sn;

	/* we store the new value */
	ts_sc->ts = ts;
	ts_sc->sn = sn;

	/* compute the absolute delta between new and old TS */
	ts_sc->ts_delta = abs(ts_sc->ts - ts_sc->old_ts);
	rohc_debugf(2, "TS delta = %u\n", ts_sc->ts_delta);

	switch(ts_sc->state)
	{
		case INIT_TS:
		{
			rohc_debugf(2, "state INIT_TS\n");
			break;
		}

		case INIT_STRIDE:
		{
			rohc_debugf(2, "state INIT_STRIDE\n");

			if(!sdvl_can_value_be_encoded(ts_sc->ts_delta))
			{
				/* TS is changing and TS_STRIDE is very large: go back to INIT_TS
				 * state if TS_STRIDE cannot be SDVL-encoded */
				rohc_debugf(2, "TS_STRIDE is too large for SDVL encoding, "
				            "go in INIT_TS state\n");
				ts_sc->state = INIT_TS;
			}
			else if(ts_sc->ts_delta == 0)
			{
				/* TS is constant (TS_STRIDE = 0), TS_SCALED cannot be computed,
				 * so stay in INIT_STRIDE state */
				rohc_debugf(2, "TS is constant (TS_STRIDE = 0), stay in "
				            "INIT_STRIDE state\n");
				ts_sc->nr_init_stride_packets = 0;
			}
			else
			{
				/* TS is changing and TS_STRIDE is OK */

				/* reset TS_STRIDE transmission counter if TS_STRIDE changes */
				if(ts_sc->ts_delta != ts_sc->ts_stride)
				{
					rohc_debugf(2, "/!\\ TS_STRIDE changed\n");
					ts_sc->nr_init_stride_packets = 0;
				}

				rohc_debugf(3, "ts_stride = %u\n", ts_sc->ts_delta);
				ts_sc->ts_stride = ts_sc->ts_delta;
				assert(ts_sc->ts_stride != 0);
				ts_sc->ts_offset = ts_sc->ts % ts_sc->ts_stride;
				rohc_debugf(3, "ts_offset = %u modulo %d = %d\n",
				            ts_sc->ts, ts_sc->ts_stride, ts_sc->ts_offset);
				ts_sc->ts_scaled = (ts_sc->ts - ts_sc->ts_offset) / ts_sc->ts_stride;
				rohc_debugf(3, "ts_scaled = (%u - %d) / %d = %d\n", ts_sc->ts,
				            ts_sc->ts_offset, ts_sc->ts_stride, ts_sc->ts_scaled);
			}
			break;
		}

		case SEND_SCALED:
		{
			uint32_t old_scaled = ts_sc->ts_scaled;
			uint32_t rest;

			rohc_debugf(2, "state SEND_SCALED\n");

			/* go back to lower states if TS_STRIDE = 0 or if TS_STRIDE is
			 * too large to be SDVL-encoded */
			if(ts_sc->ts_delta == 0)
			{
				/* TS is constant, go back in INIT_STRIDE state because TS_SCALED
				 * cannot be used if TS_STRIDE = 0 (see RFC 4815 section 4.4.1) */
				rohc_debugf(3, "TS_STRIDE = 0, go in INIT_STRIDE state\n");
				ts_sc->state = INIT_STRIDE;
				ts_sc->nr_init_stride_packets = 0;
				return;
			}
			else if(!sdvl_can_value_be_encoded(ts_sc->ts_delta))
			{
				/* TS is changing and TS_STRIDE is very large: go back to INIT_TS
				 * state if TS_STRIDE cannot be SDVL-encoded */
				rohc_debugf(2, "TS_STRIDE is too large for SDVL encoding, "
				            "go in INIT_TS state\n");
				ts_sc->state = INIT_TS;
				return;
			}

			/* TS_STRIDE is OK, let's use it */
			rohc_debugf(3, "ts_stride calculated = %u\n", ts_sc->ts_delta);
			rohc_debugf(3, "previous ts_stride = %u\n", ts_sc->ts_stride);
			assert(ts_sc->ts_stride != 0);
			rest = ts_sc->ts_delta % ts_sc->ts_stride;
			if(rest != 0)
			{
				/* ts_stride has changed */
				rohc_debugf(2, "/!\\ ts_stride changed\n");
				ts_sc->state = INIT_STRIDE;
				ts_sc->nr_init_stride_packets = 0;
				rohc_debugf(2, "state -> INIT_STRIDE\n");
				ts_sc->ts_stride = ts_sc->ts_delta;
			}

			rohc_debugf(3, "ts_stride = %u\n", ts_sc->ts_stride);
			assert(ts_sc->ts_stride != 0);
			ts_sc->ts_offset = ts_sc->ts % ts_sc->ts_stride;
			rohc_debugf(3, "ts_offset = %u modulo %u = %u\n",
			            ts_sc->ts, ts_sc->ts_stride, ts_sc->ts_offset);
			assert(ts_sc->ts_stride != 0);
			ts_sc->ts_scaled = (ts_sc->ts - ts_sc->ts_offset) / ts_sc->ts_stride;
			rohc_debugf(3, "ts_scaled = (%u - %u) / %u = %u\n", ts_sc->ts,
			            ts_sc->ts_offset, ts_sc->ts_stride, ts_sc->ts_scaled);

			if((ts_sc->ts_scaled - old_scaled) == (ts_sc->sn - ts_sc->old_sn))
			{
				rohc_debugf(2, "TS can be deducted from SN (old TS_SCALED = %u, "
				            "new TS_SCALED = %u, old SN = %u, new SN = %u)\n",
				            old_scaled, ts_sc->ts_scaled, ts_sc->old_sn, ts_sc->sn);
				ts_sc->is_deductible = 1;
			}
			else
			{
				rohc_debugf(2, "TS can not be deducted from SN (old TS_SCALED = %u, "
				            "new TS_SCALED = %u, old SN = %u, new SN = %u)\n",
				            old_scaled, ts_sc->ts_scaled, ts_sc->old_sn, ts_sc->sn);
				ts_sc->is_deductible = 0;
			}

			/* Wraparound (See RFC 4815 Section 4.4.3) */
			if(rest == 0 && (ts_sc->ts < ts_sc->old_ts))
			{
				rohc_debugf(2, "TS wraparound detected\n");
				if(ts_sc->ts_stride % 2 != 0)
				{
					rohc_debugf(3, "ts_stride is not a power of two");
					ts_sc->state = INIT_STRIDE;
					ts_sc->nr_init_stride_packets = 0;
				}
			}
			break;
		}

		default:
		{
			/* invalid state, should not happen */
			assert(0);
		}
	}
}


/**
 * @brief Return the number of bits needed to encode TS_SCALED
 *
 * @param ts_sc    The ts_sc_comp object
 * @param bits_nr  OUT: The number of bits needed
 * @return         true in case of success,
 *                 false if the minimal number of bits can not be found
 */
bool nb_bits_scaled(const struct ts_sc_comp ts_sc, size_t *const bits_nr)
{
	bool is_success;

	if(ts_sc.is_deductible)
	{
		*bits_nr = 0;
		is_success = true;
	}
	else
	{
		is_success = wlsb_get_k_32bits(ts_sc.scaled_window, ts_sc.ts_scaled,
		                               bits_nr);
	}

	return is_success;
}


/**
 * @brief Add a new TS_SCALED value to the ts_sc_comp object
 *
 * @param ts_sc        The ts_sc_comp object
 * @param sn           The Sequence Number
 */
void add_scaled(const struct ts_sc_comp *const ts_sc, uint16_t sn)
{
	assert(ts_sc != NULL);
	c_add_wlsb(ts_sc->scaled_window, sn, ts_sc->ts_scaled);
}


/**
 * @brief Return the TS_STRIDE value
 *
 * @param ts_sc        The ts_sc_comp object
 * @return             TS_STRIDE value
 */
uint32_t get_ts_stride(const struct ts_sc_comp ts_sc)
{
	return ts_sc.ts_stride;
}


/**
 * @brief Return the TS_SCALED value
 *
 * @param ts_sc        The ts_sc_comp object
 * @return             The TS_SCALED value
 */
uint32_t get_ts_scaled(const struct ts_sc_comp ts_sc)
{
	return ts_sc.ts_scaled;
}

