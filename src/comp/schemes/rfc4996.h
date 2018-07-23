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
 * @file   src/comp/schemes/rfc4996.h
 * @brief  Library of encoding methods from RFC4997 and RFC4996
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_COMP_SCHEMES_RFC4996_H
#define ROHC_COMP_SCHEMES_RFC4996_H

#include "comp_wlsb.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


struct rohc_comp_ctxt;


/* static_or_irreg encoding for 8-bit and 16-bit values */
int c_static_or_irreg8(const uint8_t packet_value,
                       const bool is_static,
                       uint8_t *const rohc_data,
                       const size_t rohc_max_len,
                       int *const indicator)
	__attribute__((warn_unused_result, nonnull(3, 5)));
int c_static_or_irreg16(const uint16_t packet_value,
                        const bool is_static,
                        uint8_t *const rohc_data,
                        const size_t rohc_max_len,
                        int *const indicator)
	__attribute__((warn_unused_result, nonnull(3, 5)));
int c_static_or_irreg32(const uint32_t packet_value,
                        const bool is_static,
                        uint8_t *const rohc_data,
                        const size_t rohc_max_len,
                        int *const indicator)
	__attribute__((warn_unused_result, nonnull(3, 5)));

/* zero_or_irreg encoding for 16-bit and 32-bit values */
int c_zero_or_irreg16(const uint16_t packet_value,
                      uint8_t *const rohc_data,
                      const size_t rohc_max_len,
                      int *const indicator)
	__attribute__((warn_unused_result, nonnull(2, 4)));
int c_zero_or_irreg32(const uint32_t packet_value,
                      uint8_t *const rohc_data,
                      const size_t rohc_max_len,
                      int *const indicator)
	__attribute__((warn_unused_result, nonnull(2, 4)));

/* variable_length_32_enc encoding method */
int variable_length_32_enc(const uint32_t old_value,
                           const uint32_t new_value,
                           const struct c_wlsb *const wlsb,
                           uint8_t *const rohc_data,
                           const size_t rohc_max_len,
                           int *const indicator)
	__attribute__((nonnull(3, 4, 6), warn_unused_result));

/* RFC4996 page 49 */
void c_field_scaling(uint32_t *const scaled_value,
                     uint32_t *const residue_field,
                     const uint32_t scaling_factor,
                     const uint32_t unscaled_value)
	__attribute__((nonnull(1, 2)));

// RFC4996 page 71
bool rsf_index_enc_possible(const uint8_t rsf_flags)
	__attribute__((warn_unused_result, const));
unsigned int rsf_index_enc(const uint8_t rsf_flags)
	__attribute__((warn_unused_result, const));

/* optional_ip_id_lsb encoding method */
int c_optional_ip_id_lsb(const int behavior,
                         const uint16_t ip_id_nbo,
                         const uint16_t ip_id_offset,
                         const struct c_wlsb *const wlsb,
                         const rohc_lsb_shift_t p,
                         uint8_t *const rohc_data,
                         const size_t rohc_max_len,
                         int *const indicator)
	__attribute__((warn_unused_result, nonnull(4, 6, 8)));

// RFC4996 page 75
int dscp_encode(const uint8_t context_value,
                const uint8_t packet_value,
                uint8_t *const rohc_data,
                const size_t rohc_max_len,
                int *const indicator)
	__attribute__((warn_unused_result, nonnull(3, 5)));

/* helper functions related to Scaled ACK and ACK Stride */
bool tcp_is_ack_scaled_possible(const uint16_t ack_stride,
                                const size_t nr_trans)
	__attribute__((warn_unused_result, const));
bool tcp_is_ack_stride_static(const uint16_t ack_stride,
                              const size_t nr_trans)
	__attribute__((warn_unused_result, const));

#endif /* ROHC_COMP_RFC4996_ENCODING_H */

