/*
 * Copyright 2012,2013,2014 Didier Barvaux
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file   rohc_packets.c
 * @brief  Descriptions of ROHC packets and extensions
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_packets.h"

#include <assert.h>


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

		case ROHC_PACKET_CCE:
			return "UDP-Lite/CCE";
		case ROHC_PACKET_CCE_OFF:
			return "UDP-Lite/CCE(OFF)";
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

		default:
			assert(0);
#ifdef __KERNEL__
			return "no description";
#endif
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
		default:
			assert(0);
#ifdef __KERNEL__
			return "no description";
#endif
	}
}

