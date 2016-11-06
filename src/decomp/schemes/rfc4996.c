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

#include <string.h>
#include <assert.h>


/**
 * @brief Decompress the 8-bit given value, according to the indicator
 *
 * @param rohc_data  The ROHC data to parse
 * @param rohc_len   The length of the ROHC data to parse (in bytes)
 * @param indicator  The indicator of compression
 * @param[out] lsb   The LSB bits extracted from the ROHC packet
 * @return           The length (in bytes) of the compressed value,
 *                   -1 if ROHC data is malformed
 */
int d_static_or_irreg8(const uint8_t *const rohc_data,
                       const size_t rohc_len,
                       const int indicator,
                       struct rohc_lsb_field8 *const lsb)
{
	size_t length = 0;

	if(indicator == 1)
	{
		if(rohc_len < 1)
		{
			goto error;
		}
		lsb->bits = rohc_data[0];
		lsb->bits_nr = 8;
		length++;
	}

	return length;

error:
	return -1;
}


/**
 * @brief Decompress the 16-bit given value, according to the indicator
 *
 * @param rohc_data  The ROHC data to parse
 * @param rohc_len   The length of the ROHC data to parse (in bytes)
 * @param indicator  The indicator of compression
 * @param[out] lsb   The LSB bits extracted from the ROHC packet
 * @return           The length (in bytes) of the compressed value,
 *                   -1 if ROHC data is malformed
 */
int d_static_or_irreg16(const uint8_t *const rohc_data,
                        const size_t rohc_len,
                        const int indicator,
                        struct rohc_lsb_field16 *const lsb)
{
	size_t length;

	if(indicator == 0)
	{
		lsb->bits_nr = 0;
		length = 0;
	}
	else if(indicator == 1)
	{
		if(rohc_len < 2)
		{
			goto error;
		}
		memcpy(&(lsb->bits), rohc_data, sizeof(uint16_t));
		lsb->bits = rohc_ntoh16(lsb->bits);
		lsb->bits_nr = 16;
		length = sizeof(uint16_t);
	}
	else
	{
		goto error;
	}

	return length;

error:
	return -1;
}


/**
 * @brief Decompress the 32-bit given value, according to the indicator
 *
 * @param rohc_data  The ROHC data to parse
 * @param rohc_len   The length of the ROHC data to parse (in bytes)
 * @param indicator  The indicator of compression
 * @param[out] lsb   The LSB bits extracted from the ROHC packet
 * @return           The length (in bytes) of the compressed value,
 *                   -1 if ROHC data is malformed
 */
int d_static_or_irreg32(const uint8_t *const rohc_data,
                        const size_t rohc_len,
                        const int indicator,
                        struct rohc_lsb_field32 *const lsb)
{
	size_t length;

	if(indicator == 0)
	{
		lsb->bits_nr = 0;
		length = 0;
	}
	else if(indicator == 1)
	{
		if(rohc_len < 4)
		{
			goto error;
		}
		memcpy(&(lsb->bits), rohc_data, sizeof(uint32_t));
		lsb->bits = rohc_ntoh32(lsb->bits);
		lsb->bits_nr = 32;
		length = sizeof(uint32_t);
	}
	else
	{
		goto error;
	}

	return length;

error:
	return -1;
}


/**
 * @brief Decode the 32 bits value, according to the indicator
 *
 * See RFC4996 page 46
 *
 * @param rohc_data  The ROHC data to parse
 * @param rohc_len   The length of the ROHC data to parse (in bytes)
 * @param indicator  The indicator of compression
 * @param[out] lsb   The LSB bits extracted from the ROHC packet
 * @return           The length (in bytes) of the compressed value,
 *                   -1 if ROHC data is malformed
 */
int variable_length_32_dec(const uint8_t *const rohc_data,
                           const size_t rohc_len,
                           const int indicator,
                           struct rohc_lsb_field32 *const lsb)
{
	size_t length = 0;

	switch(indicator)
	{
		case 0:
			lsb->bits_nr = 0;
			break;
		case 1:
			if(rohc_len < 1)
			{
				goto error;
			}
			lsb->bits = rohc_data[0] & 0xff;
			lsb->bits_nr = 8;
			lsb->p = 63;
			length++;
			break;
		case 2:
			if(rohc_len < 2)
			{
				goto error;
			}
			lsb->bits = (rohc_data[0] << 8) & 0xff00;
			length++;
			lsb->bits_nr += 8;
			lsb->bits |= rohc_data[1] & 0xff;
			length++;
			lsb->bits_nr += 8;
			lsb->p = 16383;
			break;
		case 3:
			if(rohc_len < 4)
			{
				goto error;
			}
			memcpy(&(lsb->bits), rohc_data, sizeof(uint32_t));
			lsb->bits = rohc_ntoh32(lsb->bits);
			lsb->bits_nr = 32;
			length += sizeof(uint32_t);
			break;
		default: /* should not happen */
			assert(0);
			goto error;
	}

	return length;

error:
	return -1;
}


/**
 * @brief Calculate the rsf flags from the rsf index
 *
 * See RFC4996 page 71
 *
 * @param rsf_index    The rsf index
 * @return             The rsf flags
 */
unsigned int rsf_index_dec(const unsigned int rsf_index)
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
 * @param msn                The Master Sequence Number
 * @param ip_id_bits         The received IP-ID offset bits to decode
 * @param ip_id_bits_nr      The number of received IP-ID offset bits to decode
 * @param p                  The offset parameter p to use for LSB decoding
 * @param[out] ip_id         The decoded IP-ID value
 * @return                   true if IP-ID was successfully decoded,
 *                           false if decoding failed
 *
 * @todo TODO: could be merged with decomp/schemes/ip_id_offset.[ch] module
 */
bool d_ip_id_lsb(const struct rohc_decomp_ctxt *const context,
                 const struct rohc_lsb_decode *const ip_id_lsb_ctxt,
                 const uint16_t msn,
                 const uint32_t ip_id_bits,
                 const size_t ip_id_bits_nr,
                 const rohc_lsb_shift_t p,
                 uint16_t *const ip_id)
{
	bool decode_ok;
	uint32_t ip_id_offset32;
	uint16_t ip_id_offset;

	assert(context != NULL);
	assert(ip_id_lsb_ctxt != NULL);
	assert(ip_id != NULL);

	decode_ok = rohc_lsb_decode(ip_id_lsb_ctxt, ROHC_LSB_REF_0, 0,
	                            ip_id_bits, ip_id_bits_nr, p, &ip_id_offset32);
	if(!decode_ok)
	{
		rohc_decomp_warn(context, "failed to decode %zu innermost IP-ID offset "
		                 "bits 0x%x with p = %u", ip_id_bits_nr, ip_id_bits, p);
		goto error;
	}
	ip_id_offset = (uint16_t) (ip_id_offset32 & 0xffff);
	rohc_decomp_debug(context, "decoded IP-ID offset = 0x%x (%zu bits 0x%x with "
	                  "p = %d)", ip_id_offset, ip_id_bits_nr, ip_id_bits, p);

	/* add the decoded offset with SN, taking care of overflow */
	*ip_id = (msn + ip_id_offset) & 0xffff;
	rohc_decomp_debug(context, "decoded IP-ID = 0x%04x (MSN = 0x%04x)", *ip_id, msn);

	return true;

error:
	return false;
}


/**
 * @brief Decompress the IP-ID
 *
 * See RFC4996 page 76
 *
 * @param context    The decompression context
 * @param rohc_data  The ROHC data to parse
 * @param data_len   The length of the ROHC data to parse (in bytes)
 * @param behavior   The IP-ID behavior
 * @param indicator  The compression indicator
 * @param[out] lsb   The LSB bits extracted from the ROHC packet
 * @return           The length (in bytes) of the compressed value,
 *                   -1 if ROHC data is malformed
 */
int d_optional_ip_id_lsb(const struct rohc_decomp_ctxt *const context,
                         const uint8_t *const rohc_data,
                         const size_t data_len,
                         const int behavior,
                         const int indicator,
                         struct rohc_lsb_field16 *const lsb)
{
	int length;

	assert(context != NULL);

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQ:
		case IP_ID_BEHAVIOR_SEQ_SWAP:
		{
			if(indicator == 0)
			{
				if(data_len < 1)
				{
					rohc_decomp_warn(context, "ROHC packet too small for optional_ip_id "
					                 "(len = %zu)", data_len);
					goto error;
				}
				lsb->bits = rohc_data[0];
				lsb->bits_nr = 8;
				lsb->p = 3;
				length = 1;
			}
			else
			{
				if(data_len < 2)
				{
					rohc_decomp_warn(context, "ROHC packet too small for optional_ip_id "
					                 "(len = %zu)", data_len);
					goto error;
				}
				memcpy(&(lsb->bits), rohc_data, sizeof(uint16_t));
				lsb->bits = rohc_ntoh16(lsb->bits);
				lsb->bits_nr = 16;
				lsb->p = 3;
				length = sizeof(uint16_t);
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

