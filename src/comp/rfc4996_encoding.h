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
 * @file rfc4996_encoding.h
 * @brief Library of encoding methods from RFC4997 and RFC4996
 * @author FWX <rohc_team@dialine.fr>
 */

extern unsigned int lsb_masks[];
extern unsigned int lsb_xor_masks[];


// RFC4997 page 27
u_int32_t c_lsb( int num_lsbs_param, unsigned int offset_param, unsigned int context_value,
                 unsigned int original_value );

// RFC4996 page 46
u_int8_t c_static_or_irreg8( multi_ptr_t *pmptr, u_int8_t context_value, u_int8_t value );
u_int16_t c_static_or_irreg16( multi_ptr_t *pmptr, u_int16_t context_value, u_int16_t value );
u_int8_t c_zero_or_irreg8( multi_ptr_t *pmptr, u_int8_t value );
u_int16_t c_zero_or_irreg16( multi_ptr_t *pmptr, u_int16_t value );
// RFC4996 page 46
unsigned int variable_length_32_enc( multi_ptr_t *pmptr, u_int32_t *puint32 );
// RFC4996 page 47
unsigned int c_optional32( multi_ptr_t *pmptr, u_int32_t context_value, u_int32_t value );
// RFC4996 page 47
void c_lsb_7_31( multi_ptr_t *pmptr, u_int32_t value );

#ifdef USE_ROHC_TCP_MACROS
// RFC4996 page 49
#define c_field_scaling(scaled_value,residue_field,scaling_factor,unscaled_value) \
   if(scaling_factor == 0) \
	{ \
		residue_field = unscaled_value; \
		scaled_value = 0; \
	} \
   else \
	{ \
		residue_field = unscaled_value % scaling_factor; \
		scaled_value = unscaled_value / scaling_factor; \
		assert( unscaled_value == ( ( scaled_value * scaling_factor ) + residue_field ) ); \
	}
#else
void c_field_scaling( u_int32_t *scaled_value, u_int32_t *residue_field, u_int32_t scaling_factor,
                      u_int32_t unscaled_value );
#endif

// RFC4996 page 71
unsigned int rsf_index_enc( unsigned int rsf_flags );
// RFC4996 page 75
unsigned int c_ip_id_lsb( int behavior, unsigned int k, unsigned int p, WB_t context_ip_id,
                          WB_t ip_id,
                          u_int16_t msn );
// RFC4996 page 76
unsigned int c_optional_ip_id_lsb( multi_ptr_t *pmptr, int behavior, WB_t context_ip_id, WB_t ip_id,
                                   u_int16_t msn );
// RFC4996 page 75
unsigned int dscp_encode( multi_ptr_t *pmptr, u_int8_t context_value, u_int8_t value );

