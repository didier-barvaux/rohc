/*
 * Copyright 2007,2008 CNES
 * Copyright 2011,2012,2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2010,2012,2013,2014 Viveris Technologies
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
 * @file   schemes/decomp_scaled_rtp_ts.h
 * @brief  Scaled RTP Timestamp decoding
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_SCHEMES_SCALED_RTP_TS_H
#define ROHC_DECOMP_SCHEMES_SCALED_RTP_TS_H

#include "rohc_traces.h"

#include <stdlib.h>
#include <stdint.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif


/* The definition of the scaled RTP Timestamp decoding context is private */
struct ts_sc_decomp;


/*
 * Function prototypes
 */

struct ts_sc_decomp * d_create_sc(rohc_trace_callback2_t trace_cb,
                                  void *const trace_cb_priv)
	__attribute__((warn_unused_result));
void rohc_ts_scaled_free(struct ts_sc_decomp *const ts_scaled)
	__attribute__((nonnull(1)));

void ts_update_context(struct ts_sc_decomp *const ts_sc,
                       const uint32_t ts,
                       const uint16_t sn);

void d_record_ts_stride(struct ts_sc_decomp *const ts_sc,
                        const uint32_t ts_stride);

bool ts_decode_unscaled_bits(struct ts_sc_decomp *const ts_sc,
                             const uint32_t ts_unscaled_bits,
                             const size_t ts_unscaled_bits_nr,
                             uint32_t *const decoded_ts)
	__attribute__((warn_unused_result));

bool ts_decode_scaled_bits(struct ts_sc_decomp *const ts_sc,
                           const uint32_t ts_scaled_bits,
                           const size_t ts_scaled_bits_nr,
                           uint32_t *const decoded_ts)
	__attribute__((warn_unused_result));

uint32_t ts_deduce_from_sn(struct ts_sc_decomp *const ts_sc,
                           const uint16_t sn)
	__attribute__((warn_unused_result));

#endif

