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
#include "decomp_wlsb.h"

#include <stdint.h>

struct rohc_decomp_ctxt;


int d_static_or_irreg8(const uint8_t *const rohc_data,
                       const size_t rohc_len,
                       const int indicator,
                       struct rohc_lsb_field8 *const lsb)
	__attribute__((warn_unused_result, nonnull(1, 4)));

int d_static_or_irreg16(const uint8_t *const rohc_data,
                        const size_t rohc_len,
                        const int indicator,
                        struct rohc_lsb_field16 *const lsb)
	__attribute__((warn_unused_result, nonnull(1, 4)));

int variable_length_32_dec(const uint8_t *const rohc_data,
                           const size_t rohc_len,
                           const int indicator,
                           struct rohc_lsb_field32 *const lsb)
	__attribute__((warn_unused_result, nonnull(1, 4)));

int d_optional32(const int flag,
                 const uint8_t *const data,
                 const size_t data_len,
                 uint32_t context_value,
                 uint32_t *const decoded_value)
	__attribute__((warn_unused_result, nonnull(2, 5)));

// RFC4996 page 71
unsigned int rsf_index_dec(const unsigned int rsf_index)
	__attribute__((warn_unused_result, const));

// RFC4996 page 75
bool d_ip_id_lsb(const struct rohc_decomp_ctxt *const context,
                 const struct rohc_lsb_decode *const ip_id_lsb_ctxt,
                 const int behavior,
                 const uint16_t msn,
                 const uint32_t ip_id_bits,
                 const size_t ip_id_bits_nr,
                 const rohc_lsb_shift_t p,
                 uint16_t *const ip_id)
	__attribute__((warn_unused_result, nonnull(1, 2, 8)));

// RFC4996 page 76
int d_optional_ip_id_lsb(const struct rohc_decomp_ctxt *const context,
                         const uint8_t *const rohc_data,
                         const size_t data_len,
                         const int behavior,
                         const int indicator,
                         struct rohc_lsb_field16 *const lsb)
	__attribute__((warn_unused_result, nonnull(1, 2, 6)));

#endif /* ROHC_DECOMP_RFC4996_DECODING_H */

