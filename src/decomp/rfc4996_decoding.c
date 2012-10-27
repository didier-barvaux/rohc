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
 * @file rfc4996_decoding.c
 * @brief Library of decoding methods from RFC4997 and RFC4996
 * @author FWX <rohc_team@dialine.fr>
 */

#include "d_generic.h"
#include "d_rtp.h"
#include "config.h" /* for RTP_BIT_TYPE definition */
#include "rohc_traces.h"
#include "rohc_time.h"
#include "rohc_debug.h"
#include "rohc_packets.h"
#include "rohc_bit_ops.h"
#include "wlsb.h"
#include "sdvl.h"
#include "crc.h"

#include <assert.h>

#include "trace.h" //FWX2
#include "protocols/tcp.h" //FWX2
#include "rfc4996_decoding.h"
#include "d_tcp.h" // FWX2
#include "../comp/rfc4996_encoding.h"


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
 * @param num_lsbs_param   The number of bits
 * @param offset_param     The offset
 * @param context_value    The value of the context
 * @param value            The compressed value
 * @return                 The uncompressed value
 */

u_int32_t d_lsb( int num_lsbs_param, int offset_param, unsigned int context_value,
                 unsigned int value )
{
	assert( num_lsbs_param < 20 );
	rohc_debugf(3, "d_lsb() num_lsbs_param %d context_value %Xh mask %Xh value %Xh -> %Xh\n",
	            num_lsbs_param,context_value,lsb_xor_masks[num_lsbs_param],value,
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

u_int8_t d_static_or_irreg8( multi_ptr_t *pmptr, u_int8_t context_value, int indicator )
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

u_int16_t d_static_or_irreg16( multi_ptr_t *pmptr, u_int16_t context_value, int indicator )
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
 * @param pmptr            Pointer to the compressed value
 * @param indicator        Indicator of compression
 * @return                 The uncompressed value
 */
u_int32_t variable_length_32_dec( multi_ptr_t *pmptr, int indicator )
{
	u_int32_t value;

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

	rohc_debugf(3, "indicator %d return value %u (0x%x)\n", indicator, value,
	            value);

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

u_int32_t d_optional32( multi_ptr_t *pmptr, int flag, u_int32_t context_value )
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

u_int32_t d_lsb_7_31( multi_ptr_t *pmptr )
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

u_int32_t d_field_scaling( u_int32_t scaling_factor, u_int32_t scaled_value,
                           u_int32_t residue_field )
{
	u_int32_t unscaled_value;

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
 * @brief Decompress the lower bits of IP-ID
 *
 * See RFC4996 page 75
 *
 * @param behavior       The IP-ID behavior
 * @param k              The num_lsbs_param parameter for d_lsb()
 * @param p              The offset parameter for d_lsb()
 * @param context_ip_id  The context IP-ID value
 * @param value          The value to decompress
 * @param msn            The Master Sequence Number
 * @return               The IP-ID
 */

u_int16_t d_ip_id_lsb( int behavior, unsigned int k, unsigned int p, WB_t context_ip_id,
                       u_int16_t value,
                       u_int16_t msn )
{
	u_int16_t ip_id_offset;
	WB_t ip_id;


	rohc_debugf(3, "behavior %d k=%d p=%d context_ip_id %4.4Xh value %4.4Xh msn %4.4Xh\n",behavior,k,
	            p,context_ip_id.uint16,value,
	            msn);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQUENTIAL:
			ip_id.uint16 = context_ip_id.uint16 + 1;
			ip_id_offset = ip_id.uint16 - msn;
			ip_id_offset = c_lsb( k, p, context_ip_id.uint16 - msn, ip_id_offset );
			rohc_debugf(3, "new ip_id %4.4Xh ip_id_offset %Xh value %Xh\n",ip_id.uint16,ip_id_offset,
			            value);
			assert( ip_id_offset == value );
			return ip_id.uint16;
		case IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED:
			ip_id.uint8[0] = context_ip_id.uint8[1];
			ip_id.uint8[1] = context_ip_id.uint8[0];
			++ip_id.uint16;
			ip_id_offset = ip_id.uint16 - msn;
			ip_id_offset = c_lsb( k, p, ip_id.uint16 - 1 - msn, ip_id_offset );
			rohc_debugf(3, "new ip_id %4.4Xh ip_id_offset %Xh value %Xh\n",ip_id.uint16,ip_id_offset,
			            value);
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
 * @param pmptr          Pointer to the compressed value
 * @param behavior       The IP-ID behavior
 * @param indicator      The compression indicator
 * @param context_ip_id  The context IP-ID value
 * @param ip_id          Pointer to the uncompressed IP-ID
 * @param msn            The Master Sequence Number
 * @return               Nothing
 */

void d_optional_ip_id_lsb( multi_ptr_t *pmptr, int behavior, int indicator, WB_t context_ip_id,
                           u_int16_t *ip_id,
                           u_int16_t msn )
{
	rohc_debugf(3, "behavior %d indicator %d context_ip_id %Xh msn %Xh\n",behavior,indicator,
	            context_ip_id.uint16,
	            msn);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQUENTIAL:
			if(indicator == 0)
			{
				*ip_id =
				   ( context_ip_id.uint16 &
			 0xFF00 ) | d_ip_id_lsb(behavior,8,3,context_ip_id,*(pmptr->uint8)++,
				                     msn);
				rohc_debugf(3, "read ip_id %Xh -> %Xh\n",*(pmptr->uint8 - 1),*ip_id);
			}
			else
			{
				*ip_id = ntohs( READ16_FROM_PMPTR(pmptr) );
				rohc_debugf(3, "read ip_id %Xh\n",*ip_id);
			}
			break;
		case IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED:
		{
			WB_t swapped_context_ip_id;
			swapped_context_ip_id.uint8[0] = context_ip_id.uint8[1];
			swapped_context_ip_id.uint8[1] = context_ip_id.uint8[0];
			if(indicator == 0)
			{
				*ip_id =
				   ( swapped_context_ip_id.uint16 &
				 0xFF00 ) | d_ip_id_lsb(behavior,8,3,context_ip_id,*(pmptr->uint8)++,
				                        msn);
				rohc_debugf(3, "read ip_id %Xh -> %Xh\n",*(pmptr->uint8 - 1),*ip_id);
			}
			else
			{
				*ip_id = ntohs( READ16_FROM_PMPTR(pmptr) );
				rohc_debugf(3, "read ip_id %Xh\n",*ip_id);
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

u_int8_t dscp_decode( multi_ptr_t *pmptr, u_int8_t context_value, int indicator )
{
	if(indicator == 0)
	{
		return context_value;
	}
	return (*(pmptr->uint8)++) & 0x3F;
}


