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
 * @file   rfc4996_decoding.c
 * @brief  Library of decoding methods from RFC4997 and RFC4996
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_traces_internal.h"
#include "rohc_decomp_internals.h"
#include "rohc_time.h"
#include "rohc_debug.h"
#include "rohc_bit_ops.h"
#include "rohc_utils.h"
#include "wlsb.h"
#include "sdvl.h"
#include "crc.h"
#include "protocols/tcp.h"
#include "rfc4996_decoding.h"
#include "rohc_packets.h"
#include "rohc_decomp.h"

#include <string.h>
#include <assert.h>


/**
 * @brief Table of the mask for lsb()
 */

unsigned int lsb_xor_masks[] =
{
	0xFFFFFFFF,
	0xFFFFFFFE, 0xFFFFFFFC, 0xFFFFFFF8, 0xFFFFFFF0,
	0xFFFFFFE0, 0xFFFFFFC0, 0xFFFFFF80, 0xFFFFFF00,
	0xFFFFFE00, 0xFFFFFC00, 0xFFFFF800, 0xFFFFF000,
	0xFFFFE000, 0xFFFFC000, 0xFFFF8000, 0xFFFF0000,
	0xFFFE0000, 0xFFFC0000, 0xFFF80000, 0xFFF00000
};

/**
 * @brief Decompress the lower bits from the given value and the context value.
 *
 * See RFC4997 page 27
 *
 * @param context          The decompression context
 * @param num_lsbs_param   The number of bits
 * @param offset_param     The offset
 * @param context_value    The value of the context
 * @param value            The compressed value
 * @return                 The uncompressed value
 */
uint32_t d_lsb(const struct d_context *const context,
               int num_lsbs_param,
               int offset_param,
               unsigned int context_value,
               unsigned int value)
{
	assert(context != NULL);
	assert( num_lsbs_param < 20 );
	rohc_decomp_debug(context, "num_lsbs_param = %d, context_value = 0x%x, "
	                  "mask = 0x%x, value = 0x%x -> 0x%x\n", num_lsbs_param,
	                  context_value, lsb_xor_masks[num_lsbs_param], value,
	                  (context_value & lsb_xor_masks[num_lsbs_param]) | value);
	return ( context_value & lsb_xor_masks[num_lsbs_param] ) | value;
}


/**
 * @brief Decompress the 8 bits given value, according to the indicator
 *
 * See RFC4996 page 46
 *
 * @param pmptr            Pointer to the compressed value
 * @param context_value    The value of the context
 * @param indicator        Indicator of compression
 * @return                 The uncompressed value
 */

uint8_t d_static_or_irreg8( multi_ptr_t *pmptr, uint8_t context_value, int indicator )
{
	if(indicator == 0)
	{
		return context_value;
	}
	else
	{
		return *(pmptr->uint8)++;
	}
}


/**
 * @brief Decompress the 16 bits given value, according to the indicator
 *
 * @param pmptr            Pointer to the compressed value
 * @param context_value    The value of the context
 * @param indicator        Indicator of compression
 * @return                 The uncompressed value
 */

uint16_t d_static_or_irreg16( multi_ptr_t *pmptr, uint16_t context_value, int indicator )
{
	if(indicator == 0)
	{
		return context_value;
	}
	else
	{
		return READ16_FROM_PMPTR(pmptr);
	}
}


/**
 * @brief Table of the size of the variable_length_32 encode value.
 */

unsigned int variable_length_32_size[4] =
{
	0,1,2,4
};

/**
 * @brief Decode the 32 bits value, according to the indicator
 *
 * See RFC4996 page 46
 *
 * @param context    The decompression context
 * @param pmptr      Pointer to the compressed value
 * @param indicator  Indicator of compression
 * @return           The uncompressed value
 */
uint32_t variable_length_32_dec(const struct d_context *const context,
                                multi_ptr_t *pmptr,
                                int indicator)
{
	uint32_t value;

	assert(context != NULL);

	switch(indicator)
	{
		case 0:
			value = 0;
			break;
		case 1:
			value = (*pmptr->uint8) & 0x000f;
			pmptr->uint8++;
			break;
		case 2:
			value = 0;
			value |= ((*pmptr->uint8) << 8) & 0x00f0;
			pmptr->uint8++;
			value |= (*pmptr->uint8) & 0x000f;
			pmptr->uint8++;
			break;
		case 3:
			memcpy(&value, pmptr->uint8, sizeof(uint32_t));
			pmptr->uint8 += 4;
			break;
		default:
			/* should not happen */
			assert(0);
			break;
	}

	rohc_decomp_debug(context, "indicator = %d, return value = %u (0x%x)\n",
	                  indicator, value, value);

	return value;
}


/**
 * @brief Decode the 32 bits value, according to the indicator
 *
 * See RFC4996 page 47
 *
 * @param pmptr            Pointer to the compressed value
 * @param flag             Flag of compression
 * @param context_value    The context value
 * @return                 The uncompressed value
 */

uint32_t d_optional32( multi_ptr_t *pmptr, int flag, uint32_t context_value )
{
	if(flag == 1)
	{
		return READ32_FROM_PMPTR(pmptr);
	}
	return context_value;
}


/**
 * @brief Decompress the 7 or 31 bits of a 32 bits value
 *
 * See RFC4996 page 47
 *
 * @param pmptr            Pointer to the compressed value
 * @return                 The uncompressed value
 */

uint32_t d_lsb_7_31( multi_ptr_t *pmptr )
{
	if( (*pmptr->uint8) & 0x80)
	{
		return ntohl( READ32_FROM_PMPTR(pmptr) ) & 0x7FFFFFFF;
	}
	else
	{
		return *(pmptr->uint8++);
	}
}


#ifndef USE_ROHC_TCP_MACROS

/**
 * @brief Calculate the value from the scaling factor, scaled value and residue
 *
 * See RFC4996 page 49
 *
 * @param scaling_factor   The scaling factor
 * @param scaled_value     The scaled value
 * @param residue_field    The residue value
 * @return                 The unscaled value
 */

uint32_t d_field_scaling( uint32_t scaling_factor, uint32_t scaled_value,
                           uint32_t residue_field )
{
	uint32_t unscaled_value;

	if(scaling_factor == 0)
	{
		unscaled_value = residue_field;
	}
	else
	{
		unscaled_value = ( scaled_value * scaling_factor ) + residue_field;
	}
	return unscaled_value;
}


#endif

/**
 * @brief Calculate the rsf flags from the rsf index
 *
 * See RFC4996 page 71
 *
 * @param rsf_index    The rsf index
 * @return             The rsf flags
 */

unsigned int rsf_index_dec( unsigned int rsf_index )
{
	switch(rsf_index)
	{
		case 0:
			return 0;
		case 1:
			return RSF_RST_ONLY;
		case 2:
			return RSF_SYN_ONLY;
		case 3:
			return RSF_FIN_ONLY;
		default:
			return 0;
	}
}


/**
 * @brief Compress the lower bits of the given value.
 *
 * See RFC4997 page 27
 *
 * @param context          The compressor context
 * @param num_lsbs_param   The number of bits
 * @param offset_param     The offset
 * @param context_value    The value of the context
 * @param original_value   The value to compress
 * @return                 The compressed value with num_lsbs_param bits
 *
 * @todo TODO: duplicated code from rfc4996_encoding.c
 */
static uint32_t d_c_lsb(const struct d_context *const context,
                        int num_lsbs_param,
                        unsigned int offset_param,
                        unsigned int context_value,
                        unsigned int original_value)
{
	unsigned int lower_bound;
	unsigned int upper_bound;
	unsigned int value;

	assert(context != NULL);

	rohc_decomp_debug(context, "num_lsb = %d, offset_param = %d, "
	                  "context_value = 0x%x, original_value = 0x%x\n",
	                  num_lsbs_param, offset_param, context_value,
	                  original_value);

	assert( num_lsbs_param > 0 && num_lsbs_param <= 18 );

	lower_bound = context_value - offset_param;
	upper_bound = context_value + lsb_masks[num_lsbs_param] - offset_param;

	value = original_value & lsb_masks[num_lsbs_param];

	rohc_decomp_debug(context, "0x%x < value (0x%x) < 0x%x => return 0x%x\n",
	                  lower_bound, original_value, upper_bound, value);

	return value;
}


/**
 * @brief Decompress the lower bits of IP-ID
 *
 * See RFC4996 page 75
 *
 * @param context        The decompression context
 * @param behavior       The IP-ID behavior
 * @param k              The num_lsbs_param parameter for d_lsb()
 * @param p              The offset parameter for d_lsb()
 * @param context_ip_id  The context IP-ID value
 * @param value          The value to decompress
 * @param msn            The Master Sequence Number
 * @return               The IP-ID
 */
uint16_t d_ip_id_lsb(const struct d_context *const context,
                     int behavior,
                     unsigned int k,
                     unsigned int p,
                     WB_t context_ip_id,
                     uint16_t value,
                     uint16_t msn)
{
	uint16_t ip_id_offset;
	WB_t ip_id;

	assert(context != NULL);

	rohc_decomp_debug(context, "behavior = %d, k = %d, p = %d, "
	                  "context_ip_id = 0x%04x, value = 0x%04x, msn = 0x%04x\n",
	                  behavior, k, p, context_ip_id.uint16, value, msn);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQUENTIAL:
			ip_id.uint16 = context_ip_id.uint16 + 1;
			ip_id_offset = ip_id.uint16 - msn;
			ip_id_offset = d_c_lsb(context, k, p, context_ip_id.uint16 - msn,
			                       ip_id_offset);
			rohc_decomp_debug(context, "new ip_id = 0x%04x, ip_id_offset = 0x%x, "
			                  "value = 0x%x\n", ip_id.uint16, ip_id_offset, value);
			assert( ip_id_offset == value );
			return ip_id.uint16;
		case IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED:
			ip_id.uint8[0] = context_ip_id.uint8[1];
			ip_id.uint8[1] = context_ip_id.uint8[0];
			++ip_id.uint16;
			ip_id_offset = ip_id.uint16 - msn;
			ip_id_offset = d_c_lsb(context, k, p, ip_id.uint16 - 1 - msn,
			                       ip_id_offset);
			rohc_decomp_debug(context, "new ip_id = 0x%04x, ip_id_offset = 0x%x, "
			                  "value = 0x%x\n", ip_id.uint16, ip_id_offset, value);
			assert( ip_id_offset == value );
			return ip_id.uint16;
	}

	return 0;
}


/**
 * @brief Decompress the IP-ID
 *
 * See RFC4996 page 76
 *
 * @param context        The decompression context
 * @param pmptr          Pointer to the compressed value
 * @param behavior       The IP-ID behavior
 * @param indicator      The compression indicator
 * @param context_ip_id  The context IP-ID value
 * @param ip_id          Pointer to the uncompressed IP-ID
 * @param msn            The Master Sequence Number
 */
void d_optional_ip_id_lsb(const struct d_context *const context,
                          multi_ptr_t *pmptr,
                          int behavior,
                          int indicator,
                          WB_t context_ip_id,
                          uint16_t *ip_id,
                          uint16_t msn)
{
	assert(context != NULL);

	rohc_decomp_debug(context, "behavior = %d, indicator = %d, "
	                  "context_ip_id = 0x%x, msn = 0x%x\n", behavior,
	                  indicator, context_ip_id.uint16, msn);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQUENTIAL:
			if(indicator == 0)
			{
				*ip_id = (context_ip_id.uint16 & 0xFF00) |
				         d_ip_id_lsb(context, behavior, 8, 3, context_ip_id,
				                     *pmptr->uint8, msn);
				rohc_decomp_debug(context, "read ip_id = 0x%x -> 0x%x\n",
				                  *pmptr->uint8, *ip_id);
				pmptr->uint8++;
			}
			else
			{
				*ip_id = ntohs( READ16_FROM_PMPTR(pmptr) );
				rohc_decomp_debug(context, "read ip_id = 0x%x\n", *ip_id);
			}
			break;
		case IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED:
		{
			WB_t swapped_context_ip_id;
			swapped_context_ip_id.uint8[0] = context_ip_id.uint8[1];
			swapped_context_ip_id.uint8[1] = context_ip_id.uint8[0];
			if(indicator == 0)
			{
				*ip_id = (swapped_context_ip_id.uint16 & 0xFF00) |
				          d_ip_id_lsb(context, behavior, 8, 3, context_ip_id,
				                      *pmptr->uint8, msn);
				rohc_decomp_debug(context, "read ip_id = 0x%x -> 0x%x\n",
				                  *pmptr->uint8, *ip_id);
				pmptr->uint8++;
			}
			else
			{
				*ip_id = ntohs( READ16_FROM_PMPTR(pmptr) );
				rohc_decomp_debug(context, "read ip_id = 0x%x\n", *ip_id);
			}
		}
		break;
		case IP_ID_BEHAVIOR_RANDOM:
			break;
		case IP_ID_BEHAVIOR_ZERO:
			*ip_id = 0;
			break;
		default:
			break;
	}
}


/**
 * @brief Decode the DSCP field
 *
 * @param pmptr          Pointer to the compressed value
 * @param context_value  The context DSCP value
 * @param indicator      Indicator of the compression
 * @return               The DSCP decoded
 */

uint8_t dscp_decode( multi_ptr_t *pmptr, uint8_t context_value, int indicator )
{
	if(indicator == 0)
	{
		return context_value;
	}
	return (*(pmptr->uint8)++) & 0x3F;
}

