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
 * @file    rohc_packets.h
 * @brief   Definition of ROHC packets and extensions
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_PACKETS_H
#define ROHC_PACKETS_H


/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
	#define ROHC_EXPORT __declspec(dllexport)
#else
	#define ROHC_EXPORT 
#endif



/**
 * @brief The different types of ROHC packets
 *
 * If you add a new packet type, please also add the corresponding textual
 * description in \ref rohc_get_packet_descr.
 */
typedef enum
{
	/* IR and IR-DYN packets */
	PACKET_IR        =  0, /**< ROHC IR packet */
	PACKET_IR_DYN    =  1, /**< ROHC IR-DYN packet */

	/* UO-0 packets */
	PACKET_UO_0      =  2, /**< ROHC UO-0 packet */

	/* UO-1 packets */
	PACKET_UO_1      =  3, /**< ROHC UO-1 packet (for all non-RTP profiles) */
	PACKET_UO_1_ID   =  4, /**< ROHC UO-1-ID packet (RTP profile only) */
	PACKET_UO_1_TS   =  5, /**< ROHC UO-1-TS packet (RTP profile only) */
	PACKET_UO_1_RTP  =  6, /**< ROHC UO-1-RTP packet (RTP profile only) */

	/* UOR-2 packets */
	PACKET_UOR_2     =  7, /**< ROHC UOR-2 packet (for all non-RTP profiles) */
	PACKET_UOR_2_RTP =  8, /**< ROHC UO-2 packet (RTP profile only) */
	PACKET_UOR_2_ID  =  9, /**< ROHC UO-2-ID packet (RTP profile only) */
	PACKET_UOR_2_TS  = 10, /**< ROHC UO-2-TS packet (RTP profile only) */

	/* CCE packets (UDP-Lite profile only) */
	PACKET_CCE       = 11, /**< ROHC CCE packet (UDP-Lite profile only) */
	PACKET_CCE_OFF   = 12, /**< ROHC CCE(OFF) packet (UDP-Lite profile only) */

	/* Normal packet (Uncompressed profile only) */
	PACKET_NORMAL    = 13, /**< ROHC Normal packet (Uncompressed profile only) */

	PACKET_UNKNOWN   = 14, /**< Unknown packet type */

	/* packets for TCP profile */
	PACKET_TCP_CO_COMMON = 100, /**< TCP co_common packet */
	PACKET_TCP_RND_1     = 111, /**< TCP rnd_1 packet */
	PACKET_TCP_RND_2     = 112, /**< TCP rnd_2 packet */
	PACKET_TCP_RND_3     = 113, /**< TCP rnd_3 packet */
	PACKET_TCP_RND_4     = 114, /**< TCP rnd_4 packet */
	PACKET_TCP_RND_5     = 115, /**< TCP rnd_5 packet */
	PACKET_TCP_RND_6     = 116, /**< TCP rnd_6 packet */
	PACKET_TCP_RND_7     = 117, /**< TCP rnd_7 packet */
	PACKET_TCP_RND_8     = 118, /**< TCP rnd_8 packet */
	PACKET_TCP_SEQ_1     = 121, /**< TCP seq_1 packet */
	PACKET_TCP_SEQ_2     = 122, /**< TCP seq_2 packet */
	PACKET_TCP_SEQ_3     = 123, /**< TCP seq_3 packet */
	PACKET_TCP_SEQ_4     = 124, /**< TCP seq_4 packet */
	PACKET_TCP_SEQ_5     = 125, /**< TCP seq_5 packet */
	PACKET_TCP_SEQ_6     = 126, /**< TCP seq_6 packet */
	PACKET_TCP_SEQ_7     = 127, /**< TCP seq_7 packet */
	PACKET_TCP_SEQ_8     = 128, /**< TCP seq_8 packet */

} rohc_packet_t;


/**
 * @brief The different types of extensions for UO-1-ID and UOR-2* packets
 *
 * If you add a new extension type, please also add the corresponding textual
 * description in \ref rohc_get_ext_descr.
 */
typedef enum
{
	PACKET_EXT_0 = 0,  /**< The EXT-0 extension for UO-1-ID/UOR-2* packets */
	PACKET_EXT_1 = 1,  /**< The EXT-1 extension for UO-1-ID/UOR-2* packets */
	PACKET_EXT_2 = 2,  /**< The EXT-2 extension for UO-1-ID/UOR-2* packets */
	PACKET_EXT_3 = 3,  /**< The EXT-3 extension for UO-1-ID/UOR-2* packets */
	PACKET_NOEXT = 4,  /**< No extension for UO-1-ID/UOR-2* packets */
	PACKET_EXT_UNKNOWN = 5, /**< Unknown packet extension type */
} rohc_ext_t;


/*
 * Prototypes of public functions
 */

const char * ROHC_EXPORT rohc_get_packet_descr(const rohc_packet_t packet_type);

const char * ROHC_EXPORT rohc_get_ext_descr(const rohc_ext_t ext_type);


#undef ROHC_EXPORT /* do not pollute outside this header */

#endif

