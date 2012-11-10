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
 * @file   rfc4996_encoding.c
 * @brief  Library of encoding methods from RFC4997 and RFC4996
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_traces.h"
#include "rohc_debug.h"
#include "rohc_bit_ops.h"
#include "rohc_utils.h"
#include "protocols/tcp.h" // For IP_ID_BEHAVIOR
#include "rfc4996_encoding.h"
#include "trace.h" // FWX2
#include "crc.h"

#include <math.h> // TODO: required?
#include <assert.h>


/**
 * @brief Table of the mask for lsb()
 */

unsigned int lsb_masks[] =
{
	0x00000,
	0x00001, 0x00003, 0x00007, 0x0000F,
	0x0001F, 0x0003F, 0x0007F, 0x000FF,
	0x001FF, 0x003FF, 0x007FF, 0x00FFF,
	0x01FFF, 0x03FFF, 0x07FFF, 0x0FFFF,
	0x1FFFF, 0x3FFFF, 0x7FFFF, 0xFFFFF
};

/* idem lsb_masks[]
static unsigned int lsb_power[] =
{
   ( 1 << 0 ) - 1,
   ( 1 << 1 ) - 1,
   ( 1 << 2 ) - 1,
   ( 1 << 3 ) - 1,
   ( 1 << 4 ) - 1,
   ( 1 << 5 ) - 1,
   ( 1 << 6 ) - 1,
   ( 1 << 7 ) - 1,
   ( 1 << 8 ) - 1,
   ( 1 << 9 ) - 1,
   ( 1 << 10 ) - 1,
   ( 1 << 11 ) - 1,
   ( 1 << 12 ) - 1,
   ( 1 << 13 ) - 1,
   ( 1 << 14 ) - 1,
   ( 1 << 15 ) - 1,
   ( 1 << 16 ) - 1,
   ( 1 << 17 ) - 1,
   ( 1 << 18 ) - 1
};
*/

/**
 * @brief Compress the lower bits of the given value.
 *
 * See RFC4997 page 27
 *
 * @param num_lsbs_param   The number of bits
 * @param offset_param     The offset
 * @param context_value    The value of the context
 * @param original_value   The value to compress
 * @return                 The compressed value with num_lsbs_param bits
 */

uint32_t c_lsb( int num_lsbs_param, unsigned int offset_param, unsigned int context_value,
                 unsigned int original_value )
{
	unsigned int lower_bound;
	unsigned int upper_bound;
	unsigned int value;

	rohc_debugf(3, "c_lsb() num_lsb %d offset_param %d context_value %Xh original_value %Xh\n",
	            num_lsbs_param,offset_param,context_value,original_value);

	assert( num_lsbs_param > 0 && num_lsbs_param <= 18 );

	lower_bound = context_value - offset_param;
//	upper_bound = context_value + lsb_power[num_lsbs_param] - offset_param;
	upper_bound = context_value + lsb_masks[num_lsbs_param] - offset_param;

	value = original_value & lsb_masks[num_lsbs_param];

//	rohc_debugf(3, "c_lsb() %u < value %u < %d return %u\n",lower_bound,original_value,upper_bound,value);
	rohc_debugf(3, "c_lsb() %Xh < value %Xh < %Xh return %Xh\n",lower_bound,original_value,
	            upper_bound,
	            value);

//	assert( ( ( context_value & ( ~lsb_masks[num_lsbs_param] ) ) | value ) >= lower_bound );
//	assert( ( ( context_value & ( ~lsb_masks[num_lsbs_param] ) ) | value ) <= upper_bound );
//	assert( ( context_value - value ) >= lower_bound );
//	assert( ( context_value + value ) <= upper_bound );

//	assert( original_value >= lower_bound );
//	assert( original_value <= upper_bound );

	return value;
}


/**
 * @brief Compress the 8 bits given, depending of the context value.
 *
 * See RFC4996 page 46
 *
 * @param pmptr            The destination pointer, where to store the compressed value
 * @param context_value    The value of the context
 * @param value            The value to compress
 * @return                 The size of the compressed value in octets
 */

uint8_t c_static_or_irreg8( multi_ptr_t *pmptr, uint8_t context_value, uint8_t value )
{
	if(value == context_value)
	{
		return 0;
	}
	else
	{
		*(pmptr->uint8)++ = value;
		return 1;
	}
}


/**
 * @brief Compress the 16 bits given, depending of the context value.
 *
 * @param pmptr            The destination pointer, where to store the compressed value
 * @param context_value    The value of the context
 * @param value            The value to compress
 * @return                 The size of the compressed value in octets
 */

uint16_t c_static_or_irreg16( multi_ptr_t *pmptr, uint16_t context_value, uint16_t value )
{
	if(value == context_value)
	{
		return 0;
	}
	else
	{
		WRITE16_TO_PMPTR(pmptr,value);
		return 1;
	}
}


/**
 * @brief Compress the 8 bits value, regarding if null or not
 *
 * @param pmptr            The destination of the compress value
 * @param value            The value to compress
 * @return                 1 if null value, 0 otherwise
 */

uint8_t c_zero_or_irreg8( multi_ptr_t *pmptr, uint8_t value )
{
	if(value != 0)
	{
		*(pmptr->uint8)++ = value;
		return 0;
	}
	else
	{
		return 1;
	}
}


/**
 * @brief Compress the 16 bits value, regarding if null or not
 *
 * @param pmptr            The destination of the compress value
 * @param value            The value to compress
 * @return                 1 if null value, 0 otherwise
 */

uint16_t c_zero_or_irreg16( multi_ptr_t *pmptr, uint16_t value )
{
	if(value != 0)
	{
		WRITE16_TO_PMPTR(pmptr,value);
		return 0;
	}
	else
	{
		return 1;
	}
}


/**
 * @brief Compress a 32 bits value
 *
 * @param pmptr            The destination for the compressed value
 * @param puint32          Pointer to the 32 bits value to compress
 * @return                 Size of the compressed value, in octets
 */

// See RFC4996 page 46

unsigned int variable_length_32_enc( multi_ptr_t *pmptr, uint32_t *puint32 )
{
	multi_ptr_t mptr;

	if(*puint32 == 0)
	{
		return 0;
	}
	mptr.uint32 = puint32;
	if(READNI16_FROM_MPTR(mptr) == 0)
	{
		++mptr.uint16;
		if(*mptr.uint8 == 0)
		{
			*(pmptr->uint8)++ = *(++mptr.uint8);
			return 1;
		}
		else
		{
			WRITE16_TO_PMPTR(pmptr,READNI16_FROM_MPTR(mptr));
			return 2;
		}
	}
	else
	{
		WRITE32_TO_PMPTR(pmptr,READNI32_FROM_MPTR(mptr));
		return 3;
	}
}


/**
 * @brief Compress a 32 bits value, regarding the context value
 *
 * See RFC4996 page 47
 *
 * @param pmptr            The destination for the compressed value
 * @param context_value    The context value
 * @param value            The value to compress
 * @return                 Indicator 1 if compressed, 0 if same than context value
 */

unsigned int c_optional32( multi_ptr_t *pmptr, uint32_t context_value, uint32_t value )
{
	if(value == context_value)
	{
		return 0;
	}
	WRITE32_TO_PMPTR(pmptr,value);
	return 1;
}


/**
 * @brief Compress a 32 bits value to 7 or 31 bits
 *
 * See RFC4996 page 47
 *
 * @param pmptr            The destination for the compressed value
 * @param value            The value to compress
 * @return                 Nothing
 */

void c_lsb_7_31( multi_ptr_t *pmptr, uint32_t value )
{
	if(value > 0x7F)
	{
		WRITE32_TO_PMPTR(pmptr, ( htonl(value) & htonl(0x7FFFFFFF) ) | htonl(0x80000000) );
	}
	else
	{
		*(pmptr->uint8++) = value & 0x7F;
	}
}


#ifndef USE_ROHC_TCP_MACROS

/**
 * @brief Calculate the scaled and residue values from unscaled value and scaling factor
 *
 * See RFC4996 page 49
 *
 * @param scaled_value     TODO
 * @param residue_field    TODO
 * @param scaling_factor   TODO
 * @param unscaled_value   TODO
 */
void c_field_scaling( uint32_t *scaled_value, uint32_t *residue_field, uint32_t scaling_factor,
                      uint32_t unscaled_value )
{
	if(scaling_factor == 0)
	{
		*residue_field = unscaled_value;
		*scaled_value = 0;
	}
	else
	{
		*residue_field = unscaled_value % scaling_factor;
		*scaled_value = unscaled_value / scaling_factor;
		assert( unscaled_value == ( *scaled_value * scaling_factor ) + *residue_field );
	}
}


#endif

/**
 * @brief Calculate the rsf_index from the rsf flags
 *
 * See RFC4996 page 71
 *
 * @param rsf_flags        The RSF flags
 * @return                 The rsf index
 */

unsigned int rsf_index_enc( unsigned int rsf_flags )
{
	switch(rsf_flags)
	{
		case RSF_NONE:
			return 0;
		case RSF_RST_ONLY:
			return 1;
		case RSF_SYN_ONLY:
			return 2;
		case RSF_FIN_ONLY:
			return 3;
		default:
			rohc_debugf(3, "TCP RSF_UNKNOWN!\n");
			return 0;
	}
}


/**
 * @brief Compress the lower bits of IP-ID
 *
 * See RFC4996 page 75
 *
 * @param behavior         The IP-ID behavior
 * @param k                The num_lsbs_param parameter for c_lsb()
 * @param p                The offset parameter for c_lsb()
 * @param context_ip_id    The context value of IP-ID
 * @param ip_id            The IP-ID value to compress
 * @param msn              The Master Sequence Number
 * @return                 The lsb of offset between IP-ID and MSN
 */

unsigned int c_ip_id_lsb( int behavior, unsigned int k, unsigned int p, WB_t context_ip_id,
                          WB_t ip_id,
                          uint16_t msn )
{
	uint16_t ip_id_offset;
	WB_t ip_id_nbo;
	WB_t swapped_context_ip_id;

	assert( behavior == IP_ID_BEHAVIOR_SEQUENTIAL ||
	        behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED );

	rohc_debugf(3, "behavior %d context_ip_id %4.4Xh ip_id=%4.4Xh msn=%4.4Xh\n",behavior,
	            context_ip_id.uint16,ip_id.uint16,
	            msn);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQUENTIAL:
			ip_id_offset = ip_id.uint16 - msn;
			rohc_debugf(3, "ip_id_offset = %Xh - %Xh = %Xh\n",ip_id.uint16,msn,ip_id_offset);
			//  rohc_debugf(3, "context_ip_id - msn = %Xh - %Xh = %Xh\n",context_ip_id,msn,context_ip_id-msn);
			//   ip_id_offset = c_lsb( k , p , context_ip_id - msn , ip_id_offset );
			ip_id_offset = c_lsb( k, p, context_ip_id.uint16 - msn, ip_id_offset );
			rohc_debugf(3, "ip_id_offset = %Xh\n",ip_id_offset);
			break;
		case IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED:
			// ip_id_nbo = ( ip_id / 256 ) + ( ( ip_id % 256 ) * 256 );
			ip_id_nbo.uint8[0] = ip_id.uint8[1];
			ip_id_nbo.uint8[1] = ip_id.uint8[0];
			rohc_debugf(3, "ip_id_nbo = %Xh\n",ip_id_nbo.uint16);
			ip_id_offset = ip_id_nbo.uint16 - msn;
			rohc_debugf(3, "ip_id_offset = %Xh\n",ip_id_offset);
			swapped_context_ip_id.uint8[0] = context_ip_id.uint8[1];
			swapped_context_ip_id.uint8[1] = context_ip_id.uint8[0];
			ip_id_offset = c_lsb( k, p, swapped_context_ip_id.uint16 - msn, ip_id_offset );
			rohc_debugf(3, "ip_id_offset = %Xh\n",ip_id_offset);
			break;
		default:
			/* should not happen */
			assert(0);
	}
	return ip_id_offset;
}


/**
 * @brief Compress or not the IP-ID
 *
 * See RFC4996 page 76
 *
 * @param pmptr            The destination for the compressed value
 * @param behavior         The IP-ID behavior
 * @param context_ip_id    The context value of IP-ID
 * @param ip_id            The IP-ID value to compress
 * @param msn              The Master Sequence Number
 * @return                 Indicator : 0 if short, 1 if long
 */

unsigned int c_optional_ip_id_lsb( multi_ptr_t *pmptr, int behavior, WB_t context_ip_id, WB_t ip_id,
                                   uint16_t msn )
{

	rohc_debugf(3, "behavior %Xh context_ip_id %Xh ip_id %Xh msn %Xh\n",behavior,
	            context_ip_id.uint16,ip_id.uint16,
	            msn);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQUENTIAL:
			if( ( context_ip_id.uint16 & 0xFF00 ) == ( ip_id.uint16 & 0xFF00 ) )
			{
				*(pmptr->uint8)++ = c_ip_id_lsb(behavior,8,3,context_ip_id,ip_id,msn);
				rohc_debugf(3, "write ip_id %Xh\n",*(pmptr->uint8 - 1));
				return 0;
			}
			else
			{
				WRITE16_TO_PMPTR(pmptr,htons(ip_id.uint16));
				rohc_debugf(3, "write ip_id %Xh\n",ip_id.uint16);
				return 1;
			}
			break;
		case IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED:
			if( ( context_ip_id.uint16 & 0x00FF ) == ( ip_id.uint16 & 0x00FF ) )
			{
				*(pmptr->uint8)++ = c_ip_id_lsb(behavior,8,3,context_ip_id,ip_id,msn);
				rohc_debugf(3, "write ip_id %Xh\n",*(pmptr->uint8 - 1));
				return 0;
			}
			else
			{
				WB_t swapped_ip_id;
				swapped_ip_id.uint8[0] = ip_id.uint8[1];
				swapped_ip_id.uint8[1] = ip_id.uint8[0];
				WRITE16_TO_PMPTR(pmptr,htons(swapped_ip_id.uint16));
				rohc_debugf(3, "write ip_id %Xh\n",swapped_ip_id.uint16);
				return 1;
			}
			break;
		case IP_ID_BEHAVIOR_RANDOM:
		case IP_ID_BEHAVIOR_ZERO:
		default:
			break;
	}

	return 0;
}


/**
 * @brief Encode the DSCP field
 *
 * See RFC4996 page 75
 *
 * @param pmptr            The destination for the compressed value
 * @param context_value    The context value of DSCP
 * @param value            The DSCP value to compress
 * @return                 Indicator 1 if value compressed, 0 otherwise
 */

unsigned int dscp_encode( multi_ptr_t *pmptr, uint8_t context_value, uint8_t value )
{
	if(value == context_value)
	{
		return 0;
	}
	// 6 bits + 2 bits padding
	*(pmptr->uint8)++ = value & 0x3F;
	return 1;
}


