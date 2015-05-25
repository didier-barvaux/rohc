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

#include "protocols/tcp.h"
#include "schemes/comp_wlsb.h"

#include <stdint.h>


struct rohc_comp_ctxt;


/**
 * @brief Define union of different compressed datas pointers
 */
typedef union
{
	unsigned int uint;
	uint8_t *uint8;
	uint16_t *uint16;
	uint32_t *uint32;

	ip_opt_static_t *ip_opt_static;
	ip_opt_dynamic_t *ip_opt_dynamic;

	ip_dest_opt_static_t *ip_dest_opt_static;
	ip_dest_opt_dynamic_t *ip_dest_opt_dynamic;
	ip_hop_opt_static_t *ip_hop_opt_static;
	ip_hop_opt_dynamic_t *ip_hop_opt_dynamic;
	ip_rout_opt_static_t *ip_rout_opt_static;

	ipv4_static_t *ipv4_static;
	ipv4_dynamic1_t *ipv4_dynamic1;
	ipv4_dynamic2_t *ipv4_dynamic2;
	ipv6_static1_t *ipv6_static1;
	ipv6_static2_t *ipv6_static2;
	ipv6_dynamic_t *ipv6_dynamic;
	tcp_static_t *tcp_static;
	tcp_dynamic_t *tcp_dynamic;
	co_common_t *co_common;
	rnd_1_t *rnd1;
	rnd_2_t *rnd2;
	rnd_3_t *rnd3;
	rnd_4_t *rnd4;
	rnd_5_t *rnd5;
	rnd_6_t *rnd6;
	rnd_7_t *rnd7;
	rnd_8_t *rnd8;
	seq_1_t *seq1;
	seq_2_t *seq2;
	seq_3_t *seq3;
	seq_4_t *seq4;
	seq_5_t *seq5;
	seq_6_t *seq6;
	seq_7_t *seq7;
	seq_8_t *seq8;
} multi_ptr_t;


/* static_or_irreg encoding for 8-bit and 16-bit values */
int c_static_or_irreg8(const uint8_t context_value,
                       const uint8_t packet_value,
                       uint8_t *const rohc_data,
                       int *const indicator)
	__attribute__((warn_unused_result, nonnull(3, 4)));
int c_static_or_irreg16(const uint16_t packet_value,
                        const bool is_static,
                        uint8_t *const rohc_data,
                        int *const indicator)
	__attribute__((warn_unused_result, nonnull(3, 4)));

/* zero_or_irreg encoding for 8-bit, 16-bit and 32-bit values */
int c_zero_or_irreg8(const uint8_t packet_value,
                     uint8_t *const rohc_data,
                     int *const indicator)
	__attribute__((warn_unused_result, nonnull(2, 3)));
int c_zero_or_irreg16(const uint16_t packet_value,
                      uint8_t *const rohc_data,
                      int *const indicator)
	__attribute__((warn_unused_result, nonnull(2, 3)));
int c_zero_or_irreg32(const uint32_t packet_value,
                      uint8_t *const rohc_data,
                      int *const indicator)
	__attribute__((warn_unused_result, nonnull(2, 3)));

/* variable_length_32_enc encoding method */
size_t variable_length_32_enc(const uint32_t old_value,
                              const uint32_t new_value,
                              const size_t nr_bits_63,
                              const size_t nr_bits_16383,
                              uint8_t *const rohc_data,
                              int *const indicator)
	__attribute__((nonnull(5, 6), warn_unused_result));

/* optional32 encoding method */
int c_optional32(const int indicator,
                 const uint32_t packet_value,
                 uint8_t *const rohc_data)
	__attribute__((warn_unused_result, nonnull(3)));

/* RFC4996 page 49 */
void c_field_scaling(uint32_t *const scaled_value,
                     uint32_t *const residue_field,
                     const uint32_t scaling_factor,
                     const uint32_t unscaled_value)
	__attribute__((nonnull(1, 2)));

// RFC4996 page 71
bool rsf_index_enc_possible(const uint8_t rsf_flags)
	__attribute__((warn_unused_result, const));
unsigned int rsf_index_enc(const struct rohc_comp_ctxt *const context,
                           unsigned int rsf_flags);

/* optional_ip_id_lsb encoding method */
int c_optional_ip_id_lsb(const struct rohc_comp_ctxt *const context,
                         const int behavior,
                         const uint16_t ip_id,
                         const uint16_t ip_id_offset,
                         const size_t nr_bits_wlsb,
                         uint8_t *const rohc_data,
                         int *const indicator)
	__attribute__((warn_unused_result, nonnull(1, 6, 7)));

// RFC4996 page 75
int dscp_encode(const uint8_t context_value,
                const uint8_t packet_value,
                uint8_t *const rohc_data,
                int *const indicator)
	__attribute__((warn_unused_result, nonnull(3, 4)));

#endif /* ROHC_COMP_RFC4996_ENCODING_H */

