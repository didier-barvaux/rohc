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
 * @file   decomp/schemes/rfc4996.c
 * @brief  Library of decoding methods from RFC4997 and RFC4996
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rfc4996.h"

#include "rohc_bit_ops.h"
#include "rohc_traces_internal.h"
#include "rohc_decomp_internals.h"
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
uint32_t d_lsb(const struct rohc_decomp_ctxt *const context,
               int num_lsbs_param,
               int offset_param __attribute__((unused)),
               unsigned int context_value,
               unsigned int value)
{
	assert(context != NULL);
	assert( num_lsbs_param < 20 );
	rohc_decomp_debug(context, "num_lsbs_param = %d, context_value = 0x%x, "
	                  "mask = 0x%x, value = 0x%x -> 0x%x", num_lsbs_param,
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
		*decoded_value = rohc_ntoh16(*decoded_value);
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
                           const struct rohc_decomp_ctxt *const context,
                           const uint8_t *rohc_data,
                           const int indicator,
                           uint32_t *const decoded_value)
{
	uint32_t decoded_hbo;
	uint32_t decoded_nbo;
	uint32_t bits;
	size_t length = 0;
	bool decode_ok;

	assert(context != NULL);
	assert(rohc_data != NULL);
	assert(decoded_value != NULL);

	/* TODO: check ROHC packet length */
	switch(indicator)
	{
		case 0:
			decoded_hbo = rohc_lsb_get_ref(lsb, ROHC_LSB_REF_0);
			decoded_nbo = rohc_hton32(decoded_hbo);
			break;
		case 1:
			bits = rohc_data[0] & 0xff;
			rohc_data++;
			length++;
			decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, bits, 8, 63,
												 &decoded_hbo);
			if(!decode_ok)
			{
				goto error;
			}
			decoded_nbo = rohc_hton32(decoded_hbo);
			break;
		case 2:
			bits = 0;
			bits |= (rohc_data[0] << 8) & 0xff00;
			rohc_data++;
			length++;
			bits |= rohc_data[0] & 0xff;
			rohc_data++;
			length++;
			decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, bits, 16, 16383,
												 &decoded_hbo);
			if(!decode_ok)
			{
				goto error;
			}
			decoded_nbo = rohc_hton32(decoded_hbo);
			break;
		case 3:
			memcpy(&decoded_nbo, rohc_data, sizeof(uint32_t));
#ifndef __clang_analyzer__ /* silent warning about dead decrement */
			rohc_data += sizeof(uint32_t);
#endif
			length += sizeof(uint32_t);
			break;
		default: /* should not happen */
			assert(0);
			goto error;
	}

	rohc_decomp_debug(context, "indicator = %d, return value = %u (0x%x)",
	                  indicator, decoded_nbo, decoded_nbo);
	memcpy(decoded_value, &decoded_nbo, sizeof(uint32_t));

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
 * @brief Decompress the lower bits of IP-ID
 *
 * See RFC4996 page 75
 *
 * @param context            The decompression context
 * @param ip_id_lsb_ctxt     The LSB decoding context for the IP-ID offset
 * @param behavior           The IP-ID behavior
 * @param msn                The Master Sequence Number
 * @param ip_id_bits         The received IP-ID offset bits to decode
 * @param ip_id_bits_nr      The number of received IP-ID offset bits to decode
 * @param p                  The offset parameter p to use for LSB decoding
 * @param[out] ip_id_offset  The decoded IP-ID offset value
 * @param[out] ip_id         The decoded IP-ID value
 * @return                   true if IP-ID was successfully decoded,
 *                           false if decoding failed
 */
bool d_ip_id_lsb(const struct rohc_decomp_ctxt *const context,
                 const struct rohc_lsb_decode *const ip_id_lsb_ctxt,
                 const int behavior,
                 const uint16_t msn,
                 const uint32_t ip_id_bits,
                 const size_t ip_id_bits_nr,
                 const rohc_lsb_shift_t p,
                 uint16_t *const ip_id_offset,
                 uint16_t *const ip_id)
{
	bool decode_ok;
	uint32_t ip_id_offset32;

	assert(context != NULL);
	assert(ip_id_lsb_ctxt != NULL);
	assert(ip_id_offset != NULL);
	assert(ip_id != NULL);

	decode_ok = rohc_lsb_decode(ip_id_lsb_ctxt, ROHC_LSB_REF_0, 0,
	                            ip_id_bits, ip_id_bits_nr, p, &ip_id_offset32);
	if(!decode_ok)
	{
		rohc_decomp_warn(context, "failed to decode %zu innermost IP-ID offset "
		                 "bits 0x%x with p = %u", ip_id_bits_nr, ip_id_bits, p);
		goto error;
	}
	*ip_id_offset = (uint16_t) (ip_id_offset32 & 0xffff);
	rohc_decomp_debug(context, "decoded IP-ID offset = 0x%x (%zu bits 0x%x with "
	                  "p = %d)", *ip_id_offset, ip_id_bits_nr, ip_id_bits, p);

	// TODO: check for unexpected behaviors
	/* add the decoded offset with SN, taking care of overflow */
	*ip_id = (msn + (*ip_id_offset)) & 0xffff;
	if(behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		*ip_id = swab16(*ip_id);
	}
	rohc_decomp_debug(context, "decoded IP-ID = 0x%04x (MSN = 0x%04x, "
	                  "behavior = %d)", *ip_id, msn, behavior);

	return true;

error:
	return false;
}


/**
 * @brief Decompress the IP-ID
 *
 * See RFC4996 page 76
 *
 * @param context            The decompression context
 * @param ip_id_lsb_ctxt     The LSB decoding context for the IP-ID offset
 * @param rohc_data          The compressed IP-ID offset value
 * @param behavior           The IP-ID behavior
 * @param indicator          The compression indicator
 * @param[out] ip_id_offset  The decoded IP-ID offset value
 * @param[out] ip_id         The decoded IP-ID value
 * @param msn                The Master Sequence Number
 * @return                   The length (in bytes) of the compressed value,
 *                           -1 if ROHC data is malformed
 */
int d_optional_ip_id_lsb(const struct rohc_decomp_ctxt *const context,
                         const struct rohc_lsb_decode *const ip_id_lsb_ctxt,
                         const uint8_t *const rohc_data,
                         const int behavior,
                         const int indicator,
                         uint16_t *const ip_id_offset,
                         uint16_t *const ip_id,
                         const uint16_t msn)
{
	int length;

	assert(context != NULL);

	// TODO: check rohc_data length

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQ:
		case IP_ID_BEHAVIOR_SEQ_SWAP:
		{
			if(indicator == 0)
			{
				const bool decode_ok =
					d_ip_id_lsb(context, ip_id_lsb_ctxt, behavior, msn, rohc_data[0],
					            8, 3, ip_id_offset, ip_id);
				if(!decode_ok)
				{
					rohc_decomp_warn(context, "failed to decode innermost IP-ID offset");
					goto error;
				}
				rohc_decomp_debug(context, "read ip_id = 0x%02x -> 0x%04x",
				                  rohc_data[0], *ip_id);
				length = 1;
			}
			else
			{
				memcpy(ip_id, rohc_data, sizeof(uint16_t));
				length = sizeof(uint16_t);
				*ip_id = rohc_ntoh16(*ip_id);
				rohc_decomp_debug(context, "read ip_id = 0x%04x", *ip_id);
			}
			break;
		}
		case IP_ID_BEHAVIOR_RAND:
		case IP_ID_BEHAVIOR_ZERO:
		{
			rohc_decomp_debug(context, "IP-ID not present since IP-ID behavior is %d",
			                  behavior);
			length = 0;
			break;
		}
		default:
		{
			rohc_decomp_warn(context, "failed to decode innermost IP-ID offset: "
			                 "unexpected behavior %d", behavior);
			goto error;
		}
	}

	return length;

error:
	return -1;
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

