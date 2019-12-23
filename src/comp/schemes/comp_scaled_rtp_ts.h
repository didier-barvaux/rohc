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
	struct c_wlsb ts_scaled_wlsb;

	/// The TS_OFFSET value
	uint32_t ts_offset;

	/// The timestamp (TS)
	uint32_t ts;
	/** The W-LSB object used to encode the TS value */
	struct c_wlsb ts_unscaled_wlsb;
	/// The previous timestamp
	uint32_t old_ts;

	/// The sequence number (SN)
	uint16_t sn;
	/// The previous sequence number
	uint16_t old_sn;

	/// The number of packets sent in state INIT_STRIDE
	uint32_t nr_init_stride_packets:8;
	/// Whether timestamp is deducible from SN or not
	uint32_t is_deducible:1;
	/// The state of the scaled RTP Timestamp encoding object
	uint32_t state:2;
	/** Whether old SN/TS values are initialized or not */
	uint32_t are_old_val_init:1;
	uint32_t unused:20;

	/// The difference between old and current TS
	uint32_t ts_delta;

	/** The callback function used to manage traces */
	rohc_trace_callback2_t trace_callback;
	/** The private context of the callback function used to manage traces */
	void *trace_callback_priv;
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct ts_sc_comp, ts_offset) % 8) == 0,
               "ts_offset in ts_sc_comp should be aligned on 8 bytes");
_Static_assert((offsetof(struct ts_sc_comp, old_ts) % 8) == 0,
               "old_ts in ts_sc_comp should be aligned on 8 bytes");
_Static_assert((sizeof(struct ts_sc_comp) % 8) == 0,
               "struct ts_sc_comp length should be multiple of 8 bytes");
#endif



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

void c_add_ts(struct ts_sc_comp *const ts_sc,
              const uint32_t ts,
              const uint16_t sn)
	__attribute__((nonnull(1)));

size_t nb_bits_unscaled(const struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1), warn_unused_result));
void add_unscaled(struct ts_sc_comp *const ts_sc, const uint16_t sn)
	__attribute__((nonnull(1)));

size_t nb_bits_scaled(const struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1), warn_unused_result));
void add_scaled(struct ts_sc_comp *const ts_sc, const uint16_t sn)
	__attribute__((nonnull(1)));

uint32_t get_ts_stride(const struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1), warn_unused_result, pure));
uint32_t get_ts_scaled(const struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1), warn_unused_result, pure));
uint32_t get_ts_unscaled(const struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1), warn_unused_result, pure));

bool rohc_ts_sc_is_deducible(const struct ts_sc_comp *const ts_sc)
	__attribute__((nonnull(1), warn_unused_result, pure));

#endif

