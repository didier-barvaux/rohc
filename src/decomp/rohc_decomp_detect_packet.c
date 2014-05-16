/*
 * Copyright 2010,2011,2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010 Viveris Technologies
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
 * @file   rohc_decomp_detect_packet.c
 * @brief  Functions related to packet detection
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_decomp_detect_packet.h"
#include "rohc_bit_ops.h"


/** The magic bits to find out whether a field is a segment field or not */
#define D_SEGMENT        (0xfe >> 1)

/** The magic byte to find out whether a field is a padding field or not */
#define D_PADDING        0xe0

/** The magic bits to find out whether a ROHC packet is a feedback packet */
#define D_FEEDBACK       (0xf0 >> 3)

/** The magic bits to find out whether a ROHC packet is an IR packet or not */
#define D_IR_PACKET      (0xfc >> 1)

/** The magic byte to find out whether a ROHC packet is an IR-DYN packet */
#define D_IR_DYN_PACKET  0xf8


/**
 * @brief Find out whether the field is a segment field or not
 *
 * @param data The field to analyze
 * @return     Whether the field is a segment field or not
 */
bool rohc_decomp_packet_is_segment(const uint8_t *const data)
{
	return (GET_BIT_1_7(data) == D_SEGMENT);
}


/**
 * @brief Find out whether the field is a padding field or not
 *
 * @param data The field to analyze
 * @return     Whether the field is a padding field or not
 */
bool rohc_decomp_packet_is_padding(const uint8_t *const data)
{
	return (GET_BIT_0_7(data) == D_PADDING);
}


/**
 * @brief Find out whether a ROHC packet is a Feedback packet or not
 *
 * @param data The ROHC packet to analyze
 * @return     Whether the ROHC packet is a Feedback packet or not
 */
bool rohc_decomp_packet_is_feedback(const uint8_t *const data)
{
	return (GET_BIT_3_7(data) == D_FEEDBACK);
}


/**
 * @brief Find out whether a ROHC packet is an IR packet or not
 *
 * @param data  The ROHC packet to analyze
 * @param len   The length of the ROHC packet
 * @return      Whether the ROHC packet is an IR packet or not
 */
bool rohc_decomp_packet_is_ir(const uint8_t *const data, const size_t len)
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
bool rohc_decomp_packet_is_irdyn(const uint8_t *const data, const size_t len)
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
bool rohc_decomp_packet_is_uo0(const uint8_t *const data, const size_t len)
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
bool rohc_decomp_packet_is_uo1(const uint8_t *const data, const size_t len)
{
	return (len > 0 && GET_BIT_6_7(data) == 0x02);
}


/**
 * @brief Find out whether a ROHC packet is an UO-1-TS packet or not
 *
 * Check the T field that discriminates between UO-1-TS and UO-1-ID.
 *
 * @param data  The ROHC packet to analyze
 * @param len   The length of the ROHC packet
 * @return      Whether the ROHC packet is an UO-1-TS packet or not
 */
bool rohc_decomp_packet_is_uo1_ts(const uint8_t *const data, const size_t len)
{
	return (len > 0 && GET_BIT_5(data) != 0);
}


/**
 * @brief Find out whether a ROHC packet is an UOR-2* packet or not
 *
 * @param data  The ROHC packet to analyze
 * @param len   The length of the ROHC packet
 * @return      Whether the ROHC packet is an UOR-2* packet or not
 */
bool rohc_decomp_packet_is_uor2(const uint8_t *const data, const size_t len)
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
bool rohc_decomp_packet_is_uor2_ts(const uint8_t *const data,
                  const size_t data_len,
                  const size_t large_cid_len)
{
	return (data_len > (1 + large_cid_len) &&
	        GET_BIT_7(data + 1 + large_cid_len) != 0);
}

