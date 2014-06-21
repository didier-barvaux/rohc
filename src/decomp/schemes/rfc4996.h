/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2012 WBX
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
 * @file   decomp/schemes/rfc4996.h
 * @brief  Library of decoding methods from RFC4997 and RFC4996
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_SCHEMES_RFC4996_H
#define ROHC_DECOMP_SCHEMES_RFC4996_H

#include "protocols/tcp.h"
#include "wlsb.h"

#include <stdint.h>

struct rohc_decomp_ctxt;

extern unsigned int lsb_xor_masks[];


// RFC4997 page 27
uint32_t d_lsb(const struct rohc_decomp_ctxt *const context,
               int num_lsbs_param,
               int offset_param,
               unsigned int context_value,
               unsigned int value);

int d_static_or_irreg8(const uint8_t *rohc_data,
                       const uint8_t context_value,
                       const int indicator,
                       uint8_t *const decoded_value)
	__attribute__((warn_unused_result, nonnull(1, 4)));

int d_static_or_irreg16(const uint8_t *rohc_data,
                        const uint16_t context_value,
                        const int indicator,
                        uint16_t *const decoded_value)
	__attribute__((warn_unused_result, nonnull(1, 4)));

// RFC4996 page 46
extern unsigned int variable_length_32_size[];

int variable_length_32_dec(const struct rohc_lsb_decode *const lsb,
                           const struct rohc_decomp_ctxt *const context,
                           const uint8_t *rohc_data,
                           const int indicator,
                           uint32_t *const decoded_value)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

int d_optional32(const int flag,
                 const uint8_t *const data,
                 const size_t data_len,
                 uint32_t context_value,
                 uint32_t *const decoded_value)
	__attribute__((warn_unused_result, nonnull(2, 5)));

// RFC4996 page 49
uint32_t d_field_scaling(const uint32_t stride_value,
                         const uint32_t scaled_value,
                         const uint32_t residue_field)
	__attribute__((warn_unused_result, const));

// RFC4996 page 71
unsigned int rsf_index_dec( unsigned int rsf_index );

// RFC4996 page 75
uint16_t d_ip_id_lsb(const struct rohc_decomp_ctxt *const context,
                     const int behavior,
                     const unsigned int k,
                     const unsigned int p,
                     const uint16_t context_ip_id,
                     const uint16_t value,
                     const uint16_t msn)
	__attribute__((warn_unused_result, nonnull(1)));

// RFC4996 page 76
int d_optional_ip_id_lsb(const struct rohc_decomp_ctxt *const context,
                         const uint8_t *const rohc_data,
                         const int behavior,
                         const int indicator,
                         const uint16_t context_ip_id,
                         uint16_t *const ip_id,
                         const uint16_t msn)
	__attribute__((warn_unused_result, nonnull(1, 2, 6)));

int dscp_decode(const uint8_t *const rohc_data,
                const uint8_t context_value,
                const int indicator,
                uint8_t *const decoded_value)
	__attribute__((warn_unused_result, nonnull(1, 4)));

#endif /* ROHC_DECOMP_RFC4996_DECODING_H */

