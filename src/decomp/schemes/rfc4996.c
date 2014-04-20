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
 * @file   decomp/schemes/rfc4996.c
 * @brief  Library of decoding methods from RFC4997 and RFC4996
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rfc4996.h"

#include "rohc_bit_ops.h"
#include "rohc_traces_internal.h"
#include "rohc_decomp_internals.h"
#include "rohc_time.h"
#include "rohc_debug.h"
#include "rohc_utils.h"
#include "crc.h"
#include "protocols/tcp.h"
#include "rohc_packets.h"
#include "rohc_decomp.h"

#ifndef __KERNEL__
#  include <string.h>
#endif
#include <assert.h>


/* TODO: to be removed once c_lsb and d_c_lsb are removed */
/**
 * @brief Table of the mask for lsb()
 */
static unsigned int lsb_masks[] =
{
	0x00000,
	0x00001, 0x00003, 0x00007, 0x0000F,
	0x0001F, 0x0003F, 0x0007F, 0x000FF,
	0x001FF, 0x003FF, 0x007FF, 0x00FFF,
	0x01FFF, 0x03FFF, 0x07FFF, 0x0FFFF,
	0x1FFFF, 0x3FFFF, 0x7FFFF, 0xFFFFF
};


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
               int offset_param __attribute__((unused)),
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
 * @brief Decompress the 8-bit given value, according to the indicator
 *
 * @param rohc_data           The packet value
 * @param context_value       The context value
 * @param indicator           The indicator of compression
 * @param[out] decoded_value  The decoded value
 * @return                    The length (in bytes) of the compressed value,
 *                            -1 if ROHC data is malformed
 */
int d_static_or_irreg8(const uint8_t *rohc_data,
                       const uint8_t context_value,
                       const int indicator,
                       uint8_t *const decoded_value)
{
	size_t length;

	if(indicator == 0)
	{
		*decoded_value = context_value;
		length = 0;
	}
	else
	{
		/* TODO: check ROHC packet length */
		*decoded_value = rohc_data[0];
		length = 1;
	}

	return length;
}


/**
 * @brief Decompress the 16-bit given value, according to the indicator
 *
 * @param rohc_data           The packet value
 * @param context_value       The context value
 * @param indicator           The indicator of compression
 * @param[out] decoded_value  The decoded value
 * @return                    The length (in bytes) of the compressed value,
 *                            -1 if ROHC data is malformed
 */
int d_static_or_irreg16(const uint8_t *rohc_data,
                        const uint16_t context_value,
                        const int indicator,
                        uint16_t *const decoded_value)
{
	size_t length;

	if(indicator == 0)
	{
		*decoded_value = context_value;
		length = 0;
	}
	else
	{
		/* TODO: check ROHC packet length */
		memcpy(decoded_value, rohc_data, sizeof(uint16_t));
		length = sizeof(uint16_t);
	}

	return length;
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
 * @param lsb                 The WLSB decoding context
 * @param context             The decompression context
 * @param rohc_data           The compressed value
 * @param indicator           The indicator of compression
 * @param[out] decoded_value  The decoded value (in NBO)
 * @return                    The length (in bytes) of the compressed value,
 *                            -1 if ROHC data is malformed
 */
int variable_length_32_dec(const struct rohc_lsb_decode *const lsb,
                           const struct d_context *const context,
                           const uint8_t *rohc_data,
                           const int indicator,
                           uint32_t *const decoded_value)
{
	uint32_t value;
	size_t length = 0;
	bool decode_ok;

	assert(context != NULL);
	assert(rohc_data != NULL);
	assert(decoded_value != NULL);

	/* TODO: check ROHC packet length */
	switch(indicator)
	{
		case 0:
			value = rohc_lsb_get_ref(lsb, ROHC_LSB_REF_0);
			*decoded_value = rohc_hton32(value);
			break;
		case 1:
			value = rohc_data[0] & 0xff;
			rohc_data++;
			length++;
			decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, value,
			                            8, 63, decoded_value);
			if(!decode_ok)
			{
				goto error;
			}
			*decoded_value = rohc_hton32(*decoded_value);
			break;
		case 2:
			value = 0;
			value |= (rohc_data[0] << 8) & 0xff00;
			rohc_data++;
			length++;
			value |= rohc_data[0] & 0xff;
			rohc_data++;
			length++;
			decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, value,
			                            16, 16383, decoded_value);
			if(!decode_ok)
			{
				goto error;
			}
			*decoded_value = rohc_hton32(*decoded_value);
			break;
		case 3:
			memcpy(&value, rohc_data, sizeof(uint32_t));
#ifndef __clang_analyzer__ /* silent warning about dead decrement */
			rohc_data += sizeof(uint32_t);
#endif
			length += sizeof(uint32_t);
			*decoded_value = value;
			break;
		default: /* should not happen */
#if defined(NDEBUG) || defined(__KERNEL__)
			value = 0;
#endif
			assert(0);
			break;
	}

	rohc_decomp_debug(context, "indicator = %d, return value = %u (0x%x)\n",
	                  indicator, *decoded_value, *decoded_value);

	return length;

error:
	return -1;
}


/**
 * @brief Decode the 32 bits value, according to the indicator
 *
 * See RFC4996 page 47
 *
 * @param flag                Flag of compression
 * @param data                The remaining part of the ROHC packet
 * @param data_len            The length of the remaining part of the packet
 * @param context_value       The context value
 * @param[out] decoded_value  The uncompressed value
 * @return                    The number of ROHC bytes parsed,
 *                            -1 if packet is malformed
 */
int d_optional32(const int flag,
                 const uint8_t *const data,
                 const size_t data_len,
                 uint32_t context_value,
                 uint32_t *const decoded_value)
{
	size_t length;

	if(flag == 1)
	{
		if(data_len < sizeof(uint32_t))
		{
			goto error;
		}
		memcpy(decoded_value, data, sizeof(uint32_t));
		length = sizeof(uint32_t);
	}
	else
	{
		*decoded_value = context_value;
		length = 0;
	}

	return length;

error:
	return -1;
}


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
uint32_t d_field_scaling(const uint32_t scaling_factor,
                         const uint32_t scaled_value,
                         const uint32_t residue_field)
{
	return ((scaled_value * scaling_factor) + residue_field);
}


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
                     const int behavior,
                     const unsigned int k,
                     const unsigned int p,
                     const uint16_t context_ip_id,
                     const uint16_t value,
                     const uint16_t msn)
{
	uint16_t ip_id_offset;
	uint16_t ip_id;

	assert(context != NULL);

	rohc_decomp_debug(context, "behavior = %d, k = %d, p = %d, "
	                  "context_ip_id = 0x%04x, value = 0x%04x, msn = 0x%04x\n",
	                  behavior, k, p, context_ip_id, value, msn);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQ:
			ip_id = context_ip_id + 1;
			ip_id_offset = ip_id - msn;
			ip_id_offset = d_c_lsb(context, k, p, context_ip_id - msn,
			                       ip_id_offset);
			rohc_decomp_debug(context, "new ip_id = 0x%04x, ip_id_offset = "
			                  "0x%04x, value = 0x%04x\n", ip_id, ip_id_offset,
			                  value);
			assert(ip_id_offset == value); /* TODO: should not assert */
			return ip_id;
		case IP_ID_BEHAVIOR_SEQ_SWAP:
			ip_id = swab16(context_ip_id);
			ip_id++;
			ip_id_offset = ip_id - msn;
			ip_id_offset = d_c_lsb(context, k, p, ip_id - 1 - msn, ip_id_offset);
			rohc_decomp_debug(context, "new ip_id = 0x%04x, ip_id_offset = "
			                  "0x%04x, value = 0x%04x\n", ip_id, ip_id_offset,
			                  value);
			assert(ip_id_offset == value); /* TODO: should not assert */
			return ip_id;
	}

	return 0;
}


/**
 * @brief Decompress the IP-ID
 *
 * See RFC4996 page 76
 *
 * @param context        The decompression context
 * @param rohc_data      The compressed value
 * @param behavior       The IP-ID behavior
 * @param indicator      The compression indicator
 * @param context_ip_id  The context IP-ID value
 * @param ip_id          Pointer to the uncompressed IP-ID
 * @param msn            The Master Sequence Number
 * @return               The length (in bytes) of the compressed value,
 *                       -1 if ROHC data is malformed
 */
int d_optional_ip_id_lsb(const struct d_context *const context,
                         const uint8_t *const rohc_data,
                         const int behavior,
                         const int indicator,
                         const uint16_t context_ip_id,
                         uint16_t *const ip_id,
                         const uint16_t msn)
{
	size_t length = 0;

	assert(context != NULL);

	rohc_decomp_debug(context, "behavior = %d, indicator = %d, "
	                  "context_ip_id = 0x%04x, msn = 0x%04x\n", behavior,
	                  indicator, context_ip_id, msn);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQ:
			if(indicator == 0)
			{
				*ip_id = (context_ip_id & 0xff00) |
				         d_ip_id_lsb(context, behavior, 8, 3, context_ip_id,
				                     rohc_data[0], msn);
				rohc_decomp_debug(context, "read ip_id = 0x%04x -> 0x%04x\n",
				                  rohc_data[0], *ip_id);
				length++;
			}
			else
			{
				memcpy(ip_id, rohc_data, sizeof(uint16_t));
				length += sizeof(uint16_t);
				*ip_id = rohc_ntoh16(*ip_id);
				rohc_decomp_debug(context, "read ip_id = 0x%04x\n", *ip_id);
			}
			break;
		case IP_ID_BEHAVIOR_SEQ_SWAP:
		{
			const uint16_t swapped_context_ip_id = swab16(context_ip_id);
			if(indicator == 0)
			{
				*ip_id = (swapped_context_ip_id & 0xff00) |
				          d_ip_id_lsb(context, behavior, 8, 3, context_ip_id,
				                      rohc_data[0], msn);
				rohc_decomp_debug(context, "read ip_id = 0x%04x -> 0x%04x\n",
				                  rohc_data[0], *ip_id);
				length++;
			}
			else
			{
				memcpy(ip_id, rohc_data, sizeof(uint16_t));
				length += sizeof(uint16_t);
				*ip_id = rohc_ntoh16(*ip_id);
				rohc_decomp_debug(context, "read ip_id = 0x%04x\n", *ip_id);
			}
			break;
		}
		case IP_ID_BEHAVIOR_RAND:
			break;
		case IP_ID_BEHAVIOR_ZERO:
			*ip_id = 0;
			break;
		default:
			break;
	}

	return length;
}


/**
 * @brief Decode the DSCP field
 *
 * @param rohc_data           The compressed value
 * @param context_value       The context DSCP value
 * @param indicator           The indicator of the compression
 * @param[out] decoded_value  The decoded value
 * @return                    The length (in bytes) of the compressed value,
 *                            -1 if ROHC data is malformed
 */
int dscp_decode(const uint8_t *const rohc_data,
                const uint8_t context_value,
                const int indicator,
                uint8_t *const decoded_value)
{
	size_t length;

	if(indicator == 0)
	{
		/* DSCP value not transmitted in packet, take value from context */
		*decoded_value = context_value;
		length = 0;
	}
	else
	{
		/* TODO: check packet length */
		/* DSCP value transmitted in packet */
		*decoded_value = (rohc_data[0] & 0x3f);
		length = 1;
	}

	return length;
}

