/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2012 WBX
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

/**
 * @file   src/comp/schemes/rfc4996.c
 * @brief  Library of encoding methods from RFC4997 and RFC4996
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_comp_internals.h"
#include "rohc_traces_internal.h"
#include "rohc_debug.h"
#include "rohc_bit_ops.h"
#include "rohc_utils.h"
#include "protocols/tcp.h" // For IP_ID_BEHAVIOR
#include "rfc4996.h"
#include "crc.h"

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
 */
uint32_t c_lsb(const struct rohc_comp_ctxt *const context,
               int num_lsbs_param,
               unsigned int offset_param,
               unsigned int context_value,
               unsigned int original_value)
{
	unsigned int lower_bound;
	unsigned int upper_bound;
	unsigned int value;

	assert(context != NULL);

	rohc_comp_debug(context, "num_lsb = %d, offset_param = %d, "
	                "context_value = 0x%x, original_value = 0x%x",
	                num_lsbs_param, offset_param, context_value,
	                original_value);

	assert( num_lsbs_param > 0 && num_lsbs_param <= 18 );

	lower_bound = context_value - offset_param;
	upper_bound = context_value + lsb_masks[num_lsbs_param] - offset_param;

	value = original_value & lsb_masks[num_lsbs_param];

	rohc_comp_debug(context, "0x%x < value (0x%x) < 0x%x => return 0x%x",
	                lower_bound, original_value, upper_bound, value);

	return value;
}


/**
 * @brief Compress the 8 bits given, depending of the context value.
 *
 * See RFC4996 page 46
 *
 * @param context_value    The context value
 * @param packet_value     The packet value
 * @param[out] rohc_data   The compressed value
 * @param[out] indicator   The indicator: 1 if present, 0 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_static_or_irreg8(const uint8_t context_value,
                       const uint8_t packet_value,
                       uint8_t *const rohc_data,
                       int *const indicator)
{
	size_t length;

	if(packet_value == context_value)
	{
		*indicator = 0;
		length = 0;
	}
	else
	{
		rohc_data[0] = packet_value;
		*indicator = 1;
		length = 1;
	}

	return length;
}


/**
 * @brief Compress the 16 bits given, depending of the context value.
 *
 * @param context_value    The context value
 * @param packet_value     The packet value
 * @param[out] rohc_data   The compressed value
 * @param[out] indicator   The indicator: 1 if present, 0 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_static_or_irreg16(const uint16_t context_value,
                        const uint16_t packet_value,
                        uint8_t *const rohc_data,
                        int *const indicator)
{
	size_t length;

	if(packet_value == context_value)
	{
		*indicator = 0;
		length = 0;
	}
	else
	{
		memcpy(rohc_data, &packet_value, sizeof(uint16_t));
		*indicator = 1;
		length = 2;
	}

	return length;
}


/**
 * @brief Compress the 8 bits value, regarding if null or not
 *
 * @param packet_value     The packet value
 * @param[out] rohc_data   The compressed value
 * @param[out] indicator   The indicator: 1 if present, 0 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_zero_or_irreg8(const uint8_t packet_value,
                     uint8_t *const rohc_data,
                     int *const indicator)
{
	size_t length;

	if(packet_value != 0)
	{
		rohc_data[0] = packet_value;
		*indicator = 0;
		length = 1;
	}
	else
	{
		*indicator = 1;
		length = 0;
	}

	return length;
}


/**
 * @brief Compress the 16 bits value, regarding if null or not
 *
 * @param packet_value     The packet value
 * @param[out] rohc_data   The compressed value
 * @param[out] indicator   The indicator: 1 if present, 0 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_zero_or_irreg16(const uint16_t packet_value,
                      uint8_t *const rohc_data,
                      int *const indicator)
{
	size_t length;

	if(packet_value != 0)
	{
		memcpy(rohc_data, &packet_value, sizeof(uint16_t));
		*indicator = 0;
		length = sizeof(uint16_t);
	}
	else
	{
		*indicator = 1;
		length = 0;
	}

	return length;
}


/**
 * @brief Compress the 32 bits value, regarding if null or not
 *
 * @param packet_value     The packet value
 * @param[out] rohc_data   The compressed value
 * @param[out] indicator   The indicator: 1 if present, 0 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_zero_or_irreg32(const uint32_t packet_value,
                      uint8_t *const rohc_data,
                      int *const indicator)
{
	size_t length;

	if(packet_value != 0)
	{
		memcpy(rohc_data, &packet_value, sizeof(uint32_t));
		*indicator = 0;
		length = sizeof(uint32_t);
	}
	else
	{
		*indicator = 1;
		length = 0;
	}

	return length;
}


/**
 * @brief Compress the given 32-bit value
 *
 * See variable_length_32_enc in RFC4996 page 46.
 *
 * @param old_value       The previous 32-bit value
 * @param new_value       The 32-bit value to compress
 * @param nr_bits_63      The number of bits required for W-LSB encoding
 *                        with p = 63
 * @param nr_bits_16383   The number of bits required for W-LSB encoding
 *                        with p = 16383
 * @param[out] rohc_data  The compressed value
 * @param[out] indicator  The indicator for the compressed value
 * @return                The number of ROHC bytes written
 */
size_t variable_length_32_enc(const uint32_t old_value,
                              const uint32_t new_value,
                              const size_t nr_bits_63,
                              const size_t nr_bits_16383,
                              uint8_t *const rohc_data,
                              int *const indicator)
{
	size_t encoded_len;

	assert(nr_bits_63 <= 32);
	assert(nr_bits_16383 <= 32);

	if(new_value == old_value)
	{
		/* 0-byte value */
		encoded_len = 0;
		*indicator = 0;
	}
	else if(nr_bits_63 <= 8)
	{
		/* 1-byte value */
		encoded_len = 1;
		*indicator = 1;
		rohc_data[0] = new_value & 0xff;
	}
	else if(nr_bits_16383 <= 16)
	{
		/* 2-byte value */
		encoded_len = 2;
		*indicator = 2;
		rohc_data[0] = (new_value >> 8) & 0xff;
		rohc_data[1] = new_value & 0xff;
	}
	else
	{
		/* 4-byte value */
		encoded_len = 4;
		*indicator = 3;
		rohc_data[0] = (new_value >> 24) & 0xff;
		rohc_data[1] = (new_value >> 16) & 0xff;
		rohc_data[2] = (new_value >> 8) & 0xff;
		rohc_data[3] = new_value & 0xff;
	}

	assert(encoded_len <= sizeof(uint32_t));
	assert((*indicator) >= 0 && (*indicator) <= 3);

	return encoded_len;
}


/**
 * @brief Compress a 32 bits value, regarding the context value
 *
 * See RFC4996 page 47
 *
 * @param indicator     The indicator: 1 if present, 0 if not
 * @param packet_value  The packet value
 * @param rohc_data     The compressed value
 * @return              The number of ROHC bytes written,
 *                      -1 if a problem occurs
 */
int c_optional32(const int indicator,
                 const uint32_t packet_value,
                 uint8_t *const rohc_data)
{
	size_t length;

	if(indicator == 0)
	{
		length = 0;
	}
	else
	{
		memcpy(rohc_data, &packet_value, sizeof(uint32_t));
		length = sizeof(uint32_t);
	}

	return length;
}


/**
 * @brief Compress a 32 bits value to 7 or 31 bits
 *
 * See RFC4996 page 47
 *
 * @param context_value   The context value
 * @param packet_value    The packet value
 * @param[out] rohc_data  The compressed value
 * @return                The number of ROHC bytes written,
 *                        -1 if a problem occurs
 */
int c_lsb_7_or_31(const uint32_t context_value,
                  const uint32_t packet_value,
                  uint8_t *const rohc_data)
{
	size_t length;

	/* TODO: to rework to use wlsb_get_kp_32bits() */
	if((packet_value & 0xFFFFFF80) == (context_value & 0xFFFFFF80))
	{
		/* 1-bit discriminator + 7-bit LSB */
		rohc_data[0] = packet_value & 0x7f;
		length = 1;
	}
	else
	{
		/* 1-bit discriminator + 31-bit LSB */
		const uint32_t swapped_value = rohc_hton32(packet_value & 0x7fffffff);
		memcpy(rohc_data, &swapped_value, sizeof(uint32_t));
		rohc_data[0] |= 0x80;
		length = sizeof(uint32_t);
	}

	return length;
}


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
void c_field_scaling(uint32_t *const scaled_value,
                     uint32_t *const residue_field,
                     const uint32_t scaling_factor,
                     const uint32_t unscaled_value)
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
		assert(unscaled_value ==
		       (((*scaled_value) * scaling_factor) + (*residue_field)));
	}
}


/**
 * @brief Calculate the rsf_index from the rsf flags
 *
 * See RFC4996 page 71
 *
 * @param context    The compressor context
 * @param rsf_flags  The RSF flags
 * @return           The rsf index
 */
unsigned int rsf_index_enc(const struct rohc_comp_ctxt *const context,
                           unsigned int rsf_flags)
{
	assert(context != NULL);

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
			rohc_comp_debug(context, "TCP RSF_UNKNOWN!");
			return 0;
	}
}


/**
 * @brief Compress the lower bits of IP-ID
 *
 * See RFC4996 page 75
 *
 * @param context          The compressor context
 * @param behavior         The IP-ID behavior
 * @param k                The num_lsbs_param parameter for c_lsb()
 * @param p                The offset parameter for c_lsb()
 * @param context_ip_id    The context value of IP-ID
 * @param ip_id            The IP-ID value to compress
 * @param msn              The Master Sequence Number
 * @return                 The lsb of offset between IP-ID and MSN
 */
uint16_t c_ip_id_lsb(const struct rohc_comp_ctxt *const context,
                     const int behavior,
                     const unsigned int k,
                     const unsigned int p,
                     const uint16_t context_ip_id,
                     const uint16_t ip_id,
                     const uint16_t msn)
{
	uint16_t ip_id_offset;
	uint16_t ip_id_nbo;
	uint16_t swapped_context_ip_id;

	assert(context != NULL);
	assert(behavior == IP_ID_BEHAVIOR_SEQ ||
	       behavior == IP_ID_BEHAVIOR_SEQ_SWAP );

	rohc_comp_debug(context, "behavior = %d, context_ip_id = 0x%04x, "
	                "ip_id = 0x%04x, msn = 0x%04x", behavior,
	                context_ip_id, ip_id, msn);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQ:
			ip_id_offset = ip_id - msn;
			rohc_comp_debug(context, "ip_id_offset = 0x%04x - 0x%04x = 0x%04x",
			                ip_id, msn, ip_id_offset);
			ip_id_offset = c_lsb(context, k, p, context_ip_id - msn,
			                     ip_id_offset);
			rohc_comp_debug(context, "ip_id_offset = 0x%04x", ip_id_offset);
			break;
		case IP_ID_BEHAVIOR_SEQ_SWAP:
			ip_id_nbo = swab16(ip_id);
			rohc_comp_debug(context, "ip_id_nbo = 0x%04x", ip_id_nbo);
			ip_id_offset = ip_id_nbo - msn;
			rohc_comp_debug(context, "ip_id_offset = 0x%04x", ip_id_offset);
			swapped_context_ip_id = swab16(context_ip_id);
			ip_id_offset = c_lsb(context, k, p, swapped_context_ip_id - msn,
			                     ip_id_offset);
			rohc_comp_debug(context, "ip_id_offset = 0x%04x", ip_id_offset);
			break;
		default:
			/* should not happen */
#if defined(NDEBUG) || defined(__KERNEL__) || defined(ENABLE_DEAD_CODE)
			ip_id_offset = 0;
#endif
			assert(0);
			break;
	}
	return ip_id_offset;
}


/**
 * @brief Compress or not the IP-ID
 *
 * See RFC4996 page 76
 *
 * @param context          The compressor context
 * @param behavior         The IP-ID behavior
 * @param context_ip_id    The context value of IP-ID
 * @param ip_id            The IP-ID value to compress
 * @param msn              The Master Sequence Number
 * @param[out] rohc_data   The compressed value
 * @param[out] indicator   The indicator: 0 if short, 1 if long
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_optional_ip_id_lsb(const struct rohc_comp_ctxt *const context,
                         const int behavior,
                         const uint16_t context_ip_id,
                         const uint16_t ip_id,
                         const uint16_t msn,
                         uint8_t *const rohc_data,
                         int *const indicator)
{
	size_t length = 0;

	assert(context != NULL);

	rohc_comp_debug(context, "behavior = 0x%04x, context_ip_id = 0x%04x, "
	                "ip_id = 0x%04x, msn = 0x%04x", behavior, context_ip_id,
	                ip_id, msn);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQ:
			if((context_ip_id & 0xff00) == (ip_id & 0xff00))
			{
				rohc_data[0] = c_ip_id_lsb(context, behavior, 8, 3,
				                           context_ip_id, ip_id, msn);
				*indicator = 0;
				length++;
				rohc_comp_debug(context, "write ip_id = 0x%02x", rohc_data[0]);
			}
			else
			{
				const uint16_t ip_id_nbo = rohc_hton16(ip_id);
				memcpy(rohc_data, &ip_id_nbo, sizeof(uint16_t));
				length += sizeof(uint16_t);
				*indicator = 1;
				rohc_comp_debug(context, "write ip_id = 0x%04x", ip_id);
			}
			break;
		case IP_ID_BEHAVIOR_SEQ_SWAP:
			if((context_ip_id & 0x00ff) == (ip_id & 0x00ff))
			{
				rohc_data[0] = c_ip_id_lsb(context, behavior, 8, 3,
				                           context_ip_id, ip_id, msn);
				*indicator = 0;
				length++;
				rohc_comp_debug(context, "write ip_id = 0x%02x", rohc_data[0]);
			}
			else
			{
				const uint16_t swapped_ip_id = swab16(ip_id);
				const uint16_t swapped_ip_id_nbo = rohc_hton16(swapped_ip_id);
				memcpy(rohc_data, &swapped_ip_id_nbo, sizeof(uint16_t));
				*indicator = 1;
				length += sizeof(uint16_t);
				rohc_comp_debug(context, "write ip_id = 0x%04x", swapped_ip_id_nbo);
			}
			break;
		case IP_ID_BEHAVIOR_RAND:
		case IP_ID_BEHAVIOR_ZERO:
			*indicator = 0;
			length = 0;
			break;
		default:
			assert(0); /* should never happen */
			*indicator = 0;
			length = 0;
			break;
	}

	return length;
}


/**
 * @brief Encode the DSCP field
 *
 * See RFC4996 page 75
 *
 * @param pmptr            The destination for the compressed value
 * @param context_value    The DSCP value in the compression context
 * @param packet_value     The DSCP value in the packet to compress
 * @return                 Indicator 1 if value compressed, 0 otherwise
 */
unsigned int dscp_encode(multi_ptr_t *pmptr,
                         const uint8_t context_value,
                         const uint8_t packet_value)
{
	if(packet_value == context_value)
	{
		return 0;
	}
	else
	{
		/* 6 bits + 2 bits padding */
		*(pmptr->uint8)++ = packet_value & 0x3F;
		return 1;
	}
}

