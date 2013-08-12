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
 * @file decode.c
 * @brief ROHC packet related routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#include "decode.h"
#include "rohc_bit_ops.h"

#include "config.h" /* for RTP_BIT_TYPE definition */


/**
 * @brief Find out whether the field is a segment field or not
 *
 * @param data The field to analyze
 * @return     Whether the field is a segment field or not
 */
bool d_is_segment(const uint8_t *const data)
{
	return (GET_BIT_1_7(data) == D_SEGMENT);
}


/**
 * @brief Find out whether the field is a padding field or not
 *
 * @param data The field to analyze
 * @return     Whether the field is a padding field or not
 */
bool d_is_padding(const uint8_t *const data)
{
	return (GET_BIT_0_7(data) == D_PADDING);
}


/**
 * @brief Find out whether a ROHC packet is a Feedback packet or not
 *
 * @param data The ROHC packet to analyze
 * @return     Whether the ROHC packet is a Feedback packet or not
 */
bool d_is_feedback(const uint8_t *const data)
{
	return (GET_BIT_3_7(data) == D_FEEDBACK);
}


/**
 * @brief Find out the size of the feedback
 *
 * See 5.2.2 in the RFC 3095 for details.
 *
 * @param data The feedback header
 * @return     The size of the feedback
 */
size_t d_feedback_size(const uint8_t *const data)
{
	uint8_t code;
	size_t size;

	/* extract the code field */
	code = GET_BIT_0_2(data);

	/* code:
	 *  - 0 indicates that a size field is present just after the code field
	 *  - 1-7 indicates the size of the feedback data field in octets. */
	if(code != 0)
	{
		size = code;
	}
	else
	{
		/* extract the size octet */
		size = GET_BIT_0_7(data + 1);
	}

	return size;
}


/**
 * @brief Find out the size of the feedback header
 *
 * See 5.2.2 in the RFC 3095 for details.
 *
 * @param data The feedback header
 * @return     The size of the feedback header (1 or 2 bytes)
 */
size_t d_feedback_headersize(const uint8_t *const data)
{
	uint8_t code;
	size_t size;

	/* extract the code field */
	code = GET_BIT_0_2(data);

	if(code == 0)
	{
		size = 2; /* a size field is present */
	}
	else
	{
		size = 1; /* no size field is present */
	}

	return size;
}


/**
 * @brief Find out whether a ROHC packet is an IR packet or not
 *
 * @param data  The ROHC packet to analyze
 * @param len   The length of the ROHC packet
 * @return      Whether the ROHC packet is an IR packet or not
 */
bool d_is_ir(const uint8_t *const data, const size_t len)
{
	return (len > 0 && GET_BIT_1_7(data) == D_IR_PACKET);
}


/**
 * @brief Find out whether a ROHC packet is an IR-DYN packet or not
 *
 * @param data  The ROHC packet to analyze
 * @param len   The length of the ROHC packet
 * @return      Whether the ROHC packet is an IR-DYN packet or not
 */
bool d_is_irdyn(const uint8_t *const data, const size_t len)
{
	return (len > 0 && GET_BIT_0_7(data) == D_IR_DYN_PACKET);
}


/**
 * @brief Find out whether a ROHC packet is an UO-0 packet or not
 *
 * @param data  The ROHC packet to analyze
 * @param len   The length of the ROHC packet
 * @return      Whether the ROHC packet is an UO-0 packet or not
 */
bool d_is_uo0(const uint8_t *const data, const size_t len)
{
	return (len > 0 && GET_BIT_7(data) == 0);
}


/**
 * @brief Find out whether a ROHC packet is an UO-1* packet or not
 *
 * @param data  The ROHC packet to analyze
 * @param len   The length of the ROHC packet
 * @return      Whether the ROHC packet is an UO-1* packet or not
 */
bool d_is_uo1(const uint8_t *const data, const size_t len)
{
	return (len > 0 && GET_BIT_6_7(data) == 0x02);
}


/**
 * @brief Find out whether a ROHC packet is an UOR-2* packet or not
 *
 * @param data  The ROHC packet to analyze
 * @param len   The length of the ROHC packet
 * @return      Whether the ROHC packet is an UOR-2* packet or not
 */
bool d_is_uor2(const uint8_t *const data, const size_t len)
{
	return (len > 0 && GET_BIT_5_7(data) == 0x06);
}


/**
 * @brief Find out whether a ROHC packet is an UOR-2-TS packet or not
 *
 * Check the T field that discriminates between UOR-2-TS and UOR-2-ID.
 *
 * @param data           The ROHC packet to analyze
 * @param data_len       The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               Whether the ROHC packet is an UOR-2-TS packet or not
 */
bool d_is_uor2_ts(const uint8_t *const data,
                  const size_t data_len,
                  const size_t large_cid_len)
{
	return (data_len > (1 + large_cid_len) &&
	        GET_BIT_7(data + 1 + large_cid_len) != 0);
}


/**
 * @brief Find out whether a ROHC packet is an UOR-2-RTP packet or not
 *
 * If RTP disambiguation bit is enabled, check it. Otherwise, always return
 * true.
 *
 * The RTP disambiguation bit type is a proprietary extension to the ROHC
 * standard. It was introduced to avoid reparsing the UOR-2* headers in cases
 * where RND changes in extension 3.
 *
 * @param data           The ROHC packet to analyze
 * @param data_len       The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               Whether the ROHC packet is an UOR-2-RTP packet or not
 */
bool d_is_uor2_rtp(const uint8_t *const data,
                   const size_t data_len,
                   const size_t large_cid_len)
{
#if RTP_BIT_TYPE
	return (data_len > (1 + large_cid_len + 1) &&
	        GET_BIT_6(data + 1 + large_cid_len + 1) == 0);
#else
	return true;
#endif
}


/**
 * @brief Check whether a ROHC packet starts with an add-CID byte or not
 *
 * @param data The ROHC packet with a possible add-CID byte
 * @return     Whether the ROHC packet starts with an add-CID byte or not
 */
bool d_is_add_cid(const uint8_t *const data)
{
	return (GET_BIT_4_7(data) == D_ADD_CID);
}


/**
 * @brief Decode the add-CID byte of a ROHC packet (if the add-CID byte is
 *        present)
 *
 * @param data The ROHC packet with a possible add-CID byte
 * @return     0 if no add-CID byte is present, the CID value otherwise
 */
uint8_t d_decode_add_cid(const uint8_t *const data)
{
	uint8_t cid;

	if(d_is_add_cid(data))
	{
		cid = GET_BIT_0_3(data);
	}
	else
	{
		cid = 0;
	}

	return cid;
}

