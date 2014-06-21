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
 * @file   src/comp/schemes/scaled_rtp_ts.h
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

#include "wlsb.h"
#include "rohc_traces.h"

#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif

#include "dllexport.h"

#include "config.h" /* for ROHC_ENABLE_DEPRECATED_API */


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


/**
 * @brief Scaled RTP Timestamp encoding object
 *
 * See section 4.5.3 of RFC 3095 for details about Scaled RTP Timestamp
 * encoding.
 */
struct ts_sc_comp
{
	/// The TS_STRIDE value
	uint32_t ts_stride;

	/// The TS_SCALED value
	uint32_t ts_scaled;
	/** The W-LSB object used to encode the TS_SCALED value */
	struct c_wlsb *ts_scaled_wlsb;

	/// The TS_OFFSET value
	uint32_t ts_offset;

	/// The timestamp (TS)
	uint32_t ts;
	/** The W-LSB object used to encode the TS value */
	struct c_wlsb *ts_unscaled_wlsb;
	/// The previous timestamp
	uint32_t old_ts;

	/// The sequence number (SN)
	uint16_t sn;
	/// The previous sequence number
	uint16_t old_sn;

	/// Whether timestamp is deducible from SN or not
	bool is_deducible;

	/// The state of the scaled RTP Timestamp encoding object
	ts_sc_state state;
	/** Whether old SN/TS values are initialized or not */
	bool are_old_val_init;
	/// The number of packets sent in state INIT_STRIDE
	size_t nr_init_stride_packets;

	/// The difference between old and current TS
	uint32_t ts_delta;

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	/** The old callback function used to manage traces */
	rohc_trace_callback_t trace_callback;
#endif
	/** The new callback function used to manage traces */
	rohc_trace_callback2_t trace_callback2;
	/** The private context of the callback function used to manage traces */
	void *trace_callback_priv;
};



/*
 * Function prototypes
 */

bool ROHC_EXPORT c_create_sc(struct ts_sc_comp *const ts_sc,
                             const size_t wlsb_window_width,
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
                             rohc_trace_callback_t trace_cb,
#endif
                             rohc_trace_callback2_t trace_cb2,
                             void *const trace_cb_priv)
	__attribute__((warn_unused_result));
void ROHC_EXPORT c_destroy_sc(struct ts_sc_comp *const ts_sc);

void ROHC_EXPORT c_add_ts(struct ts_sc_comp *const ts_sc,
                          const uint32_t ts,
                          const uint16_t sn);

bool ROHC_EXPORT nb_bits_unscaled(const struct ts_sc_comp *const ts_sc,
                                  size_t *const bits_nr)
	__attribute__((nonnull(1), warn_unused_result));
void ROHC_EXPORT add_unscaled(const struct ts_sc_comp *const ts_sc,
                              const uint16_t sn);

bool ROHC_EXPORT nb_bits_scaled(const struct ts_sc_comp *const ts_sc,
                                size_t *const bits_nr)
	__attribute__((nonnull(1), warn_unused_result));
void ROHC_EXPORT add_scaled(const struct ts_sc_comp *const ts_sc,
                            const uint16_t sn);

uint32_t ROHC_EXPORT get_ts_stride(const struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1), warn_unused_result, pure));
uint32_t ROHC_EXPORT get_ts_scaled(const struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1), warn_unused_result, pure));
uint32_t ROHC_EXPORT get_ts_unscaled(const struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1), warn_unused_result, pure));

bool ROHC_EXPORT rohc_ts_sc_is_deducible(const struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1), warn_unused_result, pure));

#endif

