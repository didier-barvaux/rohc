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
 * @file ts_sc_decomp.h
 * @brief Scaled RTP Timestamp decoding
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef TS_SC_DECOMP_H
#define TS_SC_DECOMP_H

#include "lsb_decode.h"
#include "rohc_traces.h"

#include <stdint.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif

#include "dllexport.h"


/* The definition of the scaled RTP Timestamp decoding context is private */
struct ts_sc_decomp;


/*
 * Function prototypes
 */

struct ts_sc_decomp * ROHC_EXPORT d_create_sc(rohc_trace_callback_t callback);
void ROHC_EXPORT rohc_ts_scaled_free(struct ts_sc_decomp *const ts_scaled);

void ROHC_EXPORT ts_update_context(struct ts_sc_decomp *const ts_sc,
                                   const uint32_t ts,
                                   const uint16_t sn);

void ROHC_EXPORT d_record_ts_stride(struct ts_sc_decomp *const ts_sc,
                                    const uint32_t ts_stride);

bool ROHC_EXPORT ts_decode_unscaled_bits(struct ts_sc_decomp *const ts_sc,
                                         const uint32_t ts_unscaled_bits,
                                         const size_t ts_unscaled_bits_nr,
                                         uint32_t *const decoded_ts)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT ts_decode_scaled_bits(struct ts_sc_decomp *const ts_sc,
                                       const uint32_t ts_scaled_bits,
                                       const size_t ts_scaled_bits_nr,
                                       uint32_t *const decoded_ts)
	__attribute__((warn_unused_result));

uint32_t ROHC_EXPORT ts_deduce_from_sn(struct ts_sc_decomp *const ts_sc,
                                       const uint16_t sn)
	__attribute__((warn_unused_result));

#endif

