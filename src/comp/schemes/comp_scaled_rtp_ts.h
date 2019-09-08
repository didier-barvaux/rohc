/*
 * Copyright 2010,2011,2012,2013 Didier Barvaux
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
 * @file   schemes/comp_scaled_rtp_ts.h
 * @brief  Scaled RTP Timestamp encoding
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * See section 4.5.3 of RFC 3095 for details about Scaled RTP Timestamp
 * encoding.
 */

#ifndef ROHC_COMP_SCHEMES_SCALED_RTP_TS_H
#define ROHC_COMP_SCHEMES_SCALED_RTP_TS_H

#include "comp_wlsb.h"
#include "rohc_traces.h"

#include <stdbool.h>


/**
 * @brief State of scaled RTP Timestamp encoding
 *
 * See section 4.5.3 of RFC 3095 for details about Scaled RTP Timestamp
 * encoding.
 */
typedef enum
{
	/// Initialization state (TS_STRIDE value not yet computed)
	INIT_TS = 1,
	/// Initialization state (TS_STRIDE value computed and sent)
	INIT_STRIDE = 2,
	/// Compression state (TS_SCALED value computed and sent)
	SEND_SCALED = 3,
} ts_sc_state;


/** The changes detected in TS Scaling */
struct ts_sc_changes
{
	uint32_t ts;        /**< The new TimeStamp (TS) value */
	uint16_t sn;        /**< The new Sequence Number (SN) value */

	ts_sc_state state;  /**< The new TS Scaling state */

	uint32_t ts_stride; /**< The new TS_STRIDE value */
	uint32_t ts_offset; /**< The new TS_OFFSET value */
	uint32_t ts_scaled; /**< The new TS_SCALED value */

	/** Whether the new TS_SCALED value is deducible from SN ? */
	bool is_ts_scaled_deducible;
};


/**
 * @brief Scaled RTP Timestamp encoding object
 *
 * See section 4.5.3 of RFC 3095 for details about Scaled RTP Timestamp
 * encoding.
 */
struct ts_sc_comp
{
	/** The last changes detected in TS Scaling */
	struct ts_sc_changes old;

	/** The W-LSB object used to encode the TS_SCALED value */
	struct c_wlsb ts_scaled_wlsb;

	/** The W-LSB object used to encode the TS value */
	struct c_wlsb ts_unscaled_wlsb;

	/** Whether old SN/TS values are initialized or not */
	bool are_old_val_init;
	/// The number of packets sent in state INIT_STRIDE
	size_t nr_init_stride_packets;

	/** The callback function used to manage traces */
	rohc_trace_callback2_t trace_callback;
	/** The private context of the callback function used to manage traces */
	void *trace_callback_priv;
};



/*
 * Function prototypes
 */

bool c_create_sc(struct ts_sc_comp *const ts_sc,
                 const size_t wlsb_window_width,
                 rohc_trace_callback2_t trace_cb,
                 void *const trace_cb_priv)
	__attribute__((warn_unused_result, nonnull(1)));
void c_destroy_sc(struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1)));

void ts_detect_changes(const struct ts_sc_comp *const ts_sc,
                       const uint32_t new_ts,
                       const uint16_t new_sn,
                       const bool do_refresh_ts_stride,
                       struct ts_sc_changes *const new)
	__attribute__((nonnull(1, 5)));

size_t nb_bits_unscaled(const struct c_wlsb *const ts_unscaled_wlsb,
                        const uint32_t new_ts_unscaled)
	__attribute__((nonnull(1), warn_unused_result));

size_t nb_bits_scaled(const struct c_wlsb *const ts_scaled_wlsb,
                      const uint32_t new_ts_scaled,
                      const bool is_ts_scaled_deducible)
	__attribute__((nonnull(1), warn_unused_result));

void ts_sc_update(struct ts_sc_comp *const ts_sc,
                  const struct ts_sc_changes *const changes)
	__attribute__((nonnull(1, 2)));

#endif

