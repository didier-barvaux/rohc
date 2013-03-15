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
 * @file   rfc4996_decoding.h
 * @brief  Library of decoding methods from RFC4997 and RFC4996
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "protocols/tcp.h"

#include <stdint.h>

struct d_context;

extern unsigned int lsb_masks[];
extern unsigned int lsb_xor_masks[];


// RFC4997 page 27
uint32_t d_lsb(const struct d_context *const context,
               int num_lsbs_param,
               int offset_param,
               unsigned int context_value,
               unsigned int value);

// RFC4996 page 46
uint8_t d_static_or_irreg8( multi_ptr_t *pmptr, uint8_t context_value, int indicator );
uint16_t d_static_or_irreg16( multi_ptr_t *pmptr, uint16_t context_value, int indicator );
// RFC4996 page 46
extern unsigned int variable_length_32_size[];
uint32_t variable_length_32_dec(const struct d_context *const context,
                                multi_ptr_t *pmptr,
                                int indicator);
uint32_t d_optional32( multi_ptr_t *pmptr, int flag, uint32_t context_value );
// RFC4996 page 47
uint32_t d_lsb_7_31( multi_ptr_t *pmptr );
#ifdef USE_ROHC_TCP_MACROS
// RFC4996 page 49
#define d_field_scaling(scaling_factor,scaled_value,residue_field) \
   ( (scaled_value) * (scaling_factor) ) + (residue_field);
#else
uint32_t d_field_scaling( uint32_t stride_value, uint32_t scaled_value, uint32_t residue_field );
#endif
// RFC4996 page 71
unsigned int rsf_index_dec( unsigned int rsf_index );
// RFC4996 page 75
uint16_t d_ip_id_lsb(const struct d_context *const context,
                     int behavior,
                     unsigned int k,
                     unsigned int p,
                     WB_t context_ip_id,
                     uint16_t value,
                     uint16_t msn);
// RFC4996 page 76
void d_optional_ip_id_lsb(const struct d_context *const context,
                          multi_ptr_t *pmptr,
                          int behavior,
                          int indicator,
                          WB_t context_ip_id,
                          uint16_t *ip_id,
                          uint16_t msn);
uint8_t dscp_decode( multi_ptr_t *pmptr, uint8_t context_value, int indicator );

