/*
 * Copyright 2012,2013,2014,2016 Didier Barvaux
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
 * @file   rohc_packets.c
 * @brief  Descriptions of ROHC packets and extensions
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_packets.h"

#include <assert.h>
#include <string.h>


/**
 * @brief Give a description for the given type of ROHC packet
 *
 * Give a description for the given type of ROHC packet.
 *
 * The descriptions are not part of the API. They may change between
 * releases without any warning. Do NOT use them for other means that
 * providing to users a textual description of the packets used by the
 * library. If unsure, ask on the mailing list.
 *
 * @param packet_type  The type of packet to get a description for
 * @return             A string that describes the given packet type
 *
 * @ingroup rohc
 */
const char * rohc_get_packet_descr(const rohc_packet_t packet_type)
{
	switch(packet_type)
	{
		case ROHC_PACKET_IR:
			return "IR";
		case ROHC_PACKET_IR_DYN:
			return "IR-DYN";

		case ROHC_PACKET_UO_0:
			return "ROHCv1/UO-0";

		case ROHC_PACKET_UO_1:
			return "ROHCv1/non-RTP/UO-1";
		case ROHC_PACKET_UO_1_ID:
			return "ROHCv1/RTP/UO-1-ID";
		case ROHC_PACKET_UO_1_TS:
			return "ROHCv1/RTP/UO-1-TS";
		case ROHC_PACKET_UO_1_RTP:
			return "ROHCv1/RTP/UO-1";

		case ROHC_PACKET_UOR_2:
			return "ROHCv1/non-RTP/UOR-2";
		case ROHC_PACKET_UOR_2_RTP:
			return "ROHCv1/RTP/UOR-2";
		case ROHC_PACKET_UOR_2_ID:
			return "ROHCv1/RTP/UOR-2-ID";
		case ROHC_PACKET_UOR_2_TS:
			return "ROHCv1/RTP/UOR-2-TS";

		case ROHC_PACKET_NORMAL:
			return "ROHCv1/Uncomp/Normal";

		case ROHC_PACKET_CO_COMMON:
			return "co_common";

		case ROHC_PACKET_TCP_RND_1:
			return "ROHCv1/TCP/rnd_1";
		case ROHC_PACKET_TCP_RND_2:
			return "ROHCv1/TCP/rnd_2";
		case ROHC_PACKET_TCP_RND_3:
			return "ROHCv1/TCP/rnd_3";
		case ROHC_PACKET_TCP_RND_4:
			return "ROHCv1/TCP/rnd_4";
		case ROHC_PACKET_TCP_RND_5:
			return "ROHCv1/TCP/rnd_5";
		case ROHC_PACKET_TCP_RND_6:
			return "ROHCv1/TCP/rnd_6";
		case ROHC_PACKET_TCP_RND_7:
			return "ROHCv1/TCP/rnd_7";
		case ROHC_PACKET_TCP_RND_8:
			return "ROHCv1/TCP/rnd_8";

		case ROHC_PACKET_TCP_SEQ_1:
			return "ROHCv1/TCP/seq_1";
		case ROHC_PACKET_TCP_SEQ_2:
			return "ROHCv1/TCP/seq_2";
		case ROHC_PACKET_TCP_SEQ_3:
			return "ROHCv1/TCP/seq_3";
		case ROHC_PACKET_TCP_SEQ_4:
			return "ROHCv1/TCP/seq_4";
		case ROHC_PACKET_TCP_SEQ_5:
			return "ROHCv1/TCP/seq_5";
		case ROHC_PACKET_TCP_SEQ_6:
			return "ROHCv1/TCP/seq_6";
		case ROHC_PACKET_TCP_SEQ_7:
			return "ROHCv1/TCP/seq_7";
		case ROHC_PACKET_TCP_SEQ_8:
			return "ROHCv1/TCP/seq_8";

		case ROHC_PACKET_IR_CR:
			return "ROHCv1/IR-CR";

		/* packet types for all ROHCv2 profiles (RFC 5225) */
		case ROHC_PACKET_CO_REPAIR:
			return "ROHCv2/co_repair";
		case ROHC_PACKET_PT_0_CRC3:
			return "ROHCv2/pt_0_crc3";

		/* packet types for all non-RTP ROHCv2 profiles (RFC 5225) */
		case ROHC_PACKET_NORTP_PT_0_CRC7:
			return "ROHCv2/non-RTP/pt_0_crc7";
		case ROHC_PACKET_NORTP_PT_1_SEQ_ID:
			return "ROHCv2/non-RTP/pt_1_seq_id";
		case ROHC_PACKET_NORTP_PT_2_SEQ_ID:
			return "ROHCv2/non-RTP/pt_2_seq_id";

		/* packet types for all RTP ROHCv2 profiles (RFC 5225) */
		case ROHC_PACKET_RTP_PT_0_CRC7:
			return "ROHCv2/RTP/pt_0_crc7";
		case ROHC_PACKET_RTP_PT_1_RND:
			return "ROHCv2/RTP/pt_1_rnd";
		case ROHC_PACKET_RTP_PT_1_SEQ_ID:
			return "ROHCv2/RTP/pt_1_seq_id";
		case ROHC_PACKET_RTP_PT_1_SEQ_TS:
			return "ROHCv2/RTP/pt_1_seq_ts";
		case ROHC_PACKET_RTP_PT_2_RND:
			return "ROHCv2/RTP/pt_2_rnd";
		case ROHC_PACKET_RTP_PT_2_SEQ_ID:
			return "ROHCv2/RTP/pt_2_seq_id";
		case ROHC_PACKET_RTP_PT_2_SEQ_TS:
			return "ROHCv2/RTP/pt_2_seq_ts";
		case ROHC_PACKET_RTP_PT_2_SEQ_BOTH:
			return "ROHCv2/RTP/pt_2_seq_both";

		case ROHC_PACKET_UNKNOWN:
		case ROHC_PACKET_MAX:
		default:
			return "unknown ROHC packet";
	}
}


/**
 * @brief Give a description for the given type of ROHC extension
 *
 * Give a description for the given type of ROHC extension.
 *
 * The descriptions are not part of the API. They may change between
 * releases without any warning. Do NOT use them for other means that
 * providing to users a textual description of the extensions used by
 * the library. If unsure, ask on the mailing list.
 *
 * @param ext_type  The type of extension to get a description for
 * @return          A string that describes the given extension type
 *
 * @ingroup rohc
 */
const char * rohc_get_ext_descr(const rohc_ext_t ext_type)
{
	switch(ext_type)
	{
		case ROHC_EXT_0:
			return "EXT-0";
		case ROHC_EXT_1:
			return "EXT-1";
		case ROHC_EXT_2:
			return "EXT-2";
		case ROHC_EXT_3:
			return "EXT-3";
		case ROHC_EXT_NONE:
			return "none";
		case ROHC_EXT_UNKNOWN:
		default:
			return "unknown ROHC extension";
	}
}


/**
 * @brief Get the packet type from a packet identifier
 *
 * @param packet_id  The identifier of packet (NULL-terminated string)
 * @return           The corresponding packet type
 *
 * @ingroup rohc
 */
rohc_packet_t rohc_get_packet_type(const char *const packet_id)
{
	if(strcmp(packet_id, "ir") == 0)
	{
		return ROHC_PACKET_IR;
	}
	else if(strcmp(packet_id, "irdyn") == 0)
	{
		return ROHC_PACKET_IR_DYN;
	}
	else if(strcmp(packet_id, "uo0") == 0)
	{
		return ROHC_PACKET_UO_0;
	}
	else if(strcmp(packet_id, "uo1") == 0)
	{
		return ROHC_PACKET_UO_1;
	}
	else if(strcmp(packet_id, "uo1id") == 0)
	{
		return ROHC_PACKET_UO_1_ID;
	}
	else if(strcmp(packet_id, "uo1ts") == 0)
	{
		return ROHC_PACKET_UO_1_TS;
	}
	else if(strcmp(packet_id, "uo1rtp") == 0)
	{
		return ROHC_PACKET_UO_1_RTP;
	}
	else if(strcmp(packet_id, "uor2") == 0)
	{
		return ROHC_PACKET_UOR_2;
	}
	else if(strcmp(packet_id, "uor2rtp") == 0)
	{
		return ROHC_PACKET_UOR_2_RTP;
	}
	else if(strcmp(packet_id, "uor2id") == 0)
	{
		return ROHC_PACKET_UOR_2_ID;
	}
	else if(strcmp(packet_id, "uor2ts") == 0)
	{
		return ROHC_PACKET_UOR_2_TS;
	}
	else if(strcmp(packet_id, "uncomp-normal") == 0)
	{
		return ROHC_PACKET_NORMAL;
	}
	else if(strcmp(packet_id, "tcp-co-common") == 0)
	{
		return ROHC_PACKET_TCP_CO_COMMON;
	}
	else if(strcmp(packet_id, "tcp-rnd-1") == 0)
	{
		return ROHC_PACKET_TCP_RND_1;
	}
	else if(strcmp(packet_id, "tcp-rnd-2") == 0)
	{
		return ROHC_PACKET_TCP_RND_2;
	}
	else if(strcmp(packet_id, "tcp-rnd-3") == 0)
	{
		return ROHC_PACKET_TCP_RND_3;
	}
	else if(strcmp(packet_id, "tcp-rnd-4") == 0)
	{
		return ROHC_PACKET_TCP_RND_4;
	}
	else if(strcmp(packet_id, "tcp-rnd-5") == 0)
	{
		return ROHC_PACKET_TCP_RND_5;
	}
	else if(strcmp(packet_id, "tcp-rnd-6") == 0)
	{
		return ROHC_PACKET_TCP_RND_6;
	}
	else if(strcmp(packet_id, "tcp-rnd-7") == 0)
	{
		return ROHC_PACKET_TCP_RND_7;
	}
	else if(strcmp(packet_id, "tcp-rnd-8") == 0)
	{
		return ROHC_PACKET_TCP_RND_8;
	}
	else if(strcmp(packet_id, "tcp-seq-1") == 0)
	{
		return ROHC_PACKET_TCP_SEQ_1;
	}
	else if(strcmp(packet_id, "tcp-seq-2") == 0)
	{
		return ROHC_PACKET_TCP_SEQ_2;
	}
	else if(strcmp(packet_id, "tcp-seq-3") == 0)
	{
		return ROHC_PACKET_TCP_SEQ_3;
	}
	else if(strcmp(packet_id, "tcp-seq-4") == 0)
	{
		return ROHC_PACKET_TCP_SEQ_4;
	}
	else if(strcmp(packet_id, "tcp-seq-5") == 0)
	{
		return ROHC_PACKET_TCP_SEQ_5;
	}
	else if(strcmp(packet_id, "tcp-seq-6") == 0)
	{
		return ROHC_PACKET_TCP_SEQ_6;
	}
	else if(strcmp(packet_id, "tcp-seq-7") == 0)
	{
		return ROHC_PACKET_TCP_SEQ_7;
	}
	else if(strcmp(packet_id, "tcp-seq-8") == 0)
	{
		return ROHC_PACKET_TCP_SEQ_8;
	}
	else if(strcmp(packet_id, "ir-cr") == 0)
	{
		return ROHC_PACKET_IR_CR;
	}
	else if(strcmp(packet_id, "co-repair") == 0)
	{
		return ROHC_PACKET_CO_REPAIR;
	}
	else if(strcmp(packet_id, "co-common") == 0)
	{
		return ROHC_PACKET_CO_COMMON;
	}
	else if(strcmp(packet_id, "pt-0-crc3") == 0)
	{
		return ROHC_PACKET_PT_0_CRC3;
	}
	else if(strcmp(packet_id, "nortp-pt-0-crc7") == 0)
	{
		return ROHC_PACKET_NORTP_PT_0_CRC7;
	}
	else if(strcmp(packet_id, "nortp-pt-1-seq-id") == 0)
	{
		return ROHC_PACKET_NORTP_PT_1_SEQ_ID;
	}
	else if(strcmp(packet_id, "nortp-pt-2-seq-id") == 0)
	{
		return ROHC_PACKET_NORTP_PT_2_SEQ_ID;
	}
	else if(strcmp(packet_id, "rtp-pt-0-crc7") == 0)
	{
		return ROHC_PACKET_RTP_PT_0_CRC7;
	}
	else if(strcmp(packet_id, "rtp-pt-1-rnd") == 0)
	{
		return ROHC_PACKET_RTP_PT_1_RND;
	}
	else if(strcmp(packet_id, "rtp-pt-1-seq-id") == 0)
	{
		return ROHC_PACKET_RTP_PT_1_SEQ_ID;
	}
	else if(strcmp(packet_id, "rtp-pt-1-seq-ts") == 0)
	{
		return ROHC_PACKET_RTP_PT_1_SEQ_TS;
	}
	else if(strcmp(packet_id, "rtp-pt-2-rnd") == 0)
	{
		return ROHC_PACKET_RTP_PT_2_RND;
	}
	else if(strcmp(packet_id, "rtp-pt-2-seq-id") == 0)
	{
		return ROHC_PACKET_RTP_PT_2_SEQ_ID;
	}
	else if(strcmp(packet_id, "rtp-pt-2-seq-ts") == 0)
	{
		return ROHC_PACKET_RTP_PT_2_SEQ_TS;
	}
	else if(strcmp(packet_id, "rtp-pt-2-seq-both") == 0)
	{
		return ROHC_PACKET_RTP_PT_2_SEQ_BOTH;
	}
	else
	{
		return ROHC_PACKET_UNKNOWN;
	}
}


/**
 * @brief Is the packet one IR, IR-DYN or IR-CR packet?
 *
 * @param packet_type  The type of packet
 * @return             true if packet is IR, IR-DYN or IR-CR,
 *                     false if it does not
 */
bool rohc_packet_is_ir(const rohc_packet_t packet_type)
{
	return (packet_type == ROHC_PACKET_IR ||
	        packet_type == ROHC_PACKET_IR_CR ||
	        packet_type == ROHC_PACKET_IR_DYN);
}


/**
 * @brief Does packet type carry static information?
 *
 * @param packet_type  The type of packet
 * @return             true if packet carries static information,
 *                     false if it does not
 */
bool rohc_packet_carry_static_info(const rohc_packet_t packet_type)
{
	return (packet_type == ROHC_PACKET_IR || packet_type == ROHC_PACKET_IR_CR);
}


/**
 * @brief Does packet type carry 7- or 8-bit CRC?
 *
 * @param packet_type  The type of packet
 * @return             true if packet carries 7- or 8-bit CRC,
 *                     false if it does not
 */
bool rohc_packet_carry_crc_7_or_8(const rohc_packet_t packet_type)
{
	bool carry_crc_7_or_8;

	switch(packet_type)
	{
		case ROHC_PACKET_IR:
		case ROHC_PACKET_IR_CR:
		case ROHC_PACKET_IR_DYN:
		case ROHC_PACKET_UOR_2:
		case ROHC_PACKET_UOR_2_RTP:
		case ROHC_PACKET_UOR_2_TS:
		case ROHC_PACKET_UOR_2_ID:
		case ROHC_PACKET_TCP_CO_COMMON:
		case ROHC_PACKET_TCP_SEQ_8:
		case ROHC_PACKET_TCP_RND_8:
		case ROHC_PACKET_CO_REPAIR:
		case ROHC_PACKET_NORTP_PT_0_CRC7:
		case ROHC_PACKET_NORTP_PT_2_SEQ_ID:
		case ROHC_PACKET_RTP_PT_0_CRC7:
		case ROHC_PACKET_RTP_PT_2_RND:
		case ROHC_PACKET_RTP_PT_2_SEQ_ID:
		case ROHC_PACKET_RTP_PT_2_SEQ_TS:
		case ROHC_PACKET_RTP_PT_2_SEQ_BOTH:
			carry_crc_7_or_8 = true;
			break;
		case ROHC_PACKET_UO_0:
		case ROHC_PACKET_UO_1:
		case ROHC_PACKET_UO_1_RTP:
		case ROHC_PACKET_UO_1_TS:
		case ROHC_PACKET_UO_1_ID:
		case ROHC_PACKET_NORMAL:
		case ROHC_PACKET_TCP_SEQ_1:
		case ROHC_PACKET_TCP_SEQ_2:
		case ROHC_PACKET_TCP_SEQ_3:
		case ROHC_PACKET_TCP_SEQ_4:
		case ROHC_PACKET_TCP_SEQ_5:
		case ROHC_PACKET_TCP_SEQ_6:
		case ROHC_PACKET_TCP_SEQ_7:
		case ROHC_PACKET_TCP_RND_1:
		case ROHC_PACKET_TCP_RND_2:
		case ROHC_PACKET_TCP_RND_3:
		case ROHC_PACKET_TCP_RND_4:
		case ROHC_PACKET_TCP_RND_5:
		case ROHC_PACKET_TCP_RND_6:
		case ROHC_PACKET_TCP_RND_7:
		case ROHC_PACKET_PT_0_CRC3:
		case ROHC_PACKET_RTP_PT_1_RND:
		case ROHC_PACKET_RTP_PT_1_SEQ_ID:
		case ROHC_PACKET_RTP_PT_1_SEQ_TS:
		case ROHC_PACKET_NORTP_PT_1_SEQ_ID:
			carry_crc_7_or_8 = false;
			break;
		case ROHC_PACKET_UNKNOWN:
		case ROHC_PACKET_MAX:
		default:
			carry_crc_7_or_8 = false;
			break;
	}

	return carry_crc_7_or_8;
}

