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
#ifndef __KERNEL__
#  include <string.h>
#else
#  include <linux/string.h>
#endif


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
			return "UO-0";

		case ROHC_PACKET_UO_1:
			return "UO-1";
		case ROHC_PACKET_UO_1_ID:
			return "RTP/UO-1-ID";
		case ROHC_PACKET_UO_1_TS:
			return "RTP/UO-1-TS";
		case ROHC_PACKET_UO_1_RTP:
			return "RTP/UO-1";

		case ROHC_PACKET_UOR_2:
			return "UOR-2";
		case ROHC_PACKET_UOR_2_RTP:
			return "RTP/UOR-2";
		case ROHC_PACKET_UOR_2_ID:
			return "UOR-2-ID";
		case ROHC_PACKET_UOR_2_TS:
			return "UOR-2-TS";

		case ROHC_PACKET_NORMAL:
			return "Uncomp/Normal";

		case ROHC_PACKET_TCP_CO_COMMON:
			return "TCP/co_common";

		case ROHC_PACKET_TCP_RND_1:
			return "TCP/rnd_1";
		case ROHC_PACKET_TCP_RND_2:
			return "TCP/rnd_2";
		case ROHC_PACKET_TCP_RND_3:
			return "TCP/rnd_3";
		case ROHC_PACKET_TCP_RND_4:
			return "TCP/rnd_4";
		case ROHC_PACKET_TCP_RND_5:
			return "TCP/rnd_5";
		case ROHC_PACKET_TCP_RND_6:
			return "TCP/rnd_6";
		case ROHC_PACKET_TCP_RND_7:
			return "TCP/rnd_7";
		case ROHC_PACKET_TCP_RND_8:
			return "TCP/rnd_8";

		case ROHC_PACKET_TCP_SEQ_1:
			return "TCP/seq_1";
		case ROHC_PACKET_TCP_SEQ_2:
			return "TCP/seq_2";
		case ROHC_PACKET_TCP_SEQ_3:
			return "TCP/seq_3";
		case ROHC_PACKET_TCP_SEQ_4:
			return "TCP/seq_4";
		case ROHC_PACKET_TCP_SEQ_5:
			return "TCP/seq_5";
		case ROHC_PACKET_TCP_SEQ_6:
			return "TCP/seq_6";
		case ROHC_PACKET_TCP_SEQ_7:
			return "TCP/seq_7";
		case ROHC_PACKET_TCP_SEQ_8:
			return "TCP/seq_8";

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
	else
	{
		return ROHC_PACKET_UNKNOWN;
	}
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
	return (packet_type == ROHC_PACKET_IR);
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
		case ROHC_PACKET_IR_DYN:
		case ROHC_PACKET_UOR_2:
		case ROHC_PACKET_UOR_2_RTP:
		case ROHC_PACKET_UOR_2_TS:
		case ROHC_PACKET_UOR_2_ID:
		case ROHC_PACKET_TCP_CO_COMMON:
		case ROHC_PACKET_TCP_SEQ_8:
		case ROHC_PACKET_TCP_RND_8:
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

