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
 * @author The hackers from ROHC for Linux
 */

#include "decode.h"


/**
 * @brief Find out whether the field is a segment field or not
 *
 * @param data The field to analyze
 * @return     Whether the field is a segment field or not
 */
int d_is_segment(const unsigned char *data)
{
	return (GET_BIT_1_7(data) == D_SEGMENT);
}


/**
 * @brief Find out whether the field is a padding field or not
 *
 * @param data The field to analyze
 * @return     Whether the field is a padding field or not
 */
int d_is_padding(const unsigned char *data)
{
	return (GET_BIT_0_7(data) == D_PADDING);
}


/**
 * @brief Find out whether a ROHC packet is a Feedback packet or not
 *
 * @param data The ROHC packet to analyze
 * @return     Whether the ROHC packet is a Feedback packet or not
 */
int d_is_feedback(const unsigned char *data)
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
int d_feedback_size(const unsigned char *data)
{
	int size, code;

	/* extract the code field */
	code = GET_BIT_0_2(data);

	/* code:
	 *  - 0 indicates that a size field is present just after the code field
	 *  - 1-7 indicates the size of the feedback data field in octets. */
	if(code != 0)
		size = code;
	else
	{
		/* extract the size octet */
		data++;
		size = GET_BIT_0_7(data);
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
int d_feedback_headersize(const unsigned char *data)
{
	int size, code;

	/* extract the code field */
	code = GET_BIT_0_2(data);

	if(code == 0)
		size = 2; /* a size field is present */
	else
		size = 1; /* no size field is present */

	return size;
}


/**
 * @brief Find out whether a ROHC packet is an IR packet or not
 *
 * @param data The ROHC packet to analyze
 * @return     Whether the ROHC packet is an IR packet or not
 */
int d_is_ir(const unsigned char *data)
{
	return (GET_BIT_1_7(data) == D_IR_PACKET);
}


/**
 * @brief Find out whether a ROHC packet is an IR-DYN packet or not
 *
 * @param data The ROHC packet to analyze
 * @return     Whether the ROHC packet is an IR-DYN packet or not
 */
int d_is_irdyn(const unsigned char *data)
{
	return (GET_BIT_0_7(data) == D_IR_DYN_PACKET);
}


/**
 * @brief Check whether a ROHC packet starts with an add-CID byte or not
 *
 * @param data The ROHC packet with a possible add-CID byte
 * @return     Whether the ROHC packet starts with an add-CID byte or not
 */
int d_is_add_cid(const unsigned char *data)
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
int d_decode_add_cid(const unsigned char *data)
{
	int cid;

	if(d_is_add_cid(data))
		cid = GET_BIT_0_3(data);
	else
		cid = 0;

	return cid;
}

