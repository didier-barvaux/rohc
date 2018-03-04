/*
 * Copyright 2010,2012,2013,2014,2016 Didier Barvaux
 * Copyright 2010,2013 Viveris Technologies
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
 * @file    rohc_packets.h
 * @brief   Definition of ROHC packets and extensions
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_PACKETS_H
#define ROHC_PACKETS_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __KERNEL__
#  include <linux/types.h>
#else
#  include <stdbool.h>
#endif

/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
#  define ROHC_EXPORT __declspec(dllexport)
#else
#  define ROHC_EXPORT
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
	ROHC_PACKET_IR        =  0, /**< ROHC IR packet */
	ROHC_PACKET_IR_DYN    =  1, /**< ROHC IR-DYN packet */

	/* UO-0 packets */
	ROHC_PACKET_UO_0      =  2, /**< ROHC UO-0 packet */

	/* UO-1 packets */
	ROHC_PACKET_UO_1      =  3, /**< ROHC UO-1 packet (for all non-RTP profiles) */
	ROHC_PACKET_UO_1_ID   =  4, /**< ROHC UO-1-ID packet (RTP profile only) */
	ROHC_PACKET_UO_1_TS   =  5, /**< ROHC UO-1-TS packet (RTP profile only) */
	ROHC_PACKET_UO_1_RTP  =  6, /**< ROHC UO-1-RTP packet (RTP profile only) */

	/* UOR-2 packets */
	ROHC_PACKET_UOR_2     =  7, /**< ROHC UOR-2 packet (for all non-RTP profiles) */
	ROHC_PACKET_UOR_2_RTP =  8, /**< ROHC UO-2 packet (RTP profile only) */
	ROHC_PACKET_UOR_2_ID  =  9, /**< ROHC UO-2-ID packet (RTP profile only) */
	ROHC_PACKET_UOR_2_TS  = 10, /**< ROHC UO-2-TS packet (RTP profile only) */

	/* values 11 and 12 were used by CCE packets of the UDP-Lite profile */

	/* Normal packet (Uncompressed profile only) */
	ROHC_PACKET_NORMAL    = 13, /**< ROHC Normal packet (Uncompressed profile only) */

	ROHC_PACKET_UNKNOWN   = 14, /**< Unknown packet type */

	/* packets for TCP profile */
	ROHC_PACKET_TCP_CO_COMMON = 15, /**< TCP co_common packet */
	ROHC_PACKET_TCP_RND_1     = 16, /**< TCP rnd_1 packet */
	ROHC_PACKET_TCP_RND_2     = 17, /**< TCP rnd_2 packet */
	ROHC_PACKET_TCP_RND_3     = 18, /**< TCP rnd_3 packet */
	ROHC_PACKET_TCP_RND_4     = 19, /**< TCP rnd_4 packet */
	ROHC_PACKET_TCP_RND_5     = 20, /**< TCP rnd_5 packet */
	ROHC_PACKET_TCP_RND_6     = 21, /**< TCP rnd_6 packet */
	ROHC_PACKET_TCP_RND_7     = 22, /**< TCP rnd_7 packet */
	ROHC_PACKET_TCP_RND_8     = 23, /**< TCP rnd_8 packet */
	ROHC_PACKET_TCP_SEQ_1     = 24, /**< TCP seq_1 packet */
	ROHC_PACKET_TCP_SEQ_2     = 25, /**< TCP seq_2 packet */
	ROHC_PACKET_TCP_SEQ_3     = 26, /**< TCP seq_3 packet */
	ROHC_PACKET_TCP_SEQ_4     = 27, /**< TCP seq_4 packet */
	ROHC_PACKET_TCP_SEQ_5     = 28, /**< TCP seq_5 packet */
	ROHC_PACKET_TCP_SEQ_6     = 29, /**< TCP seq_6 packet */
	ROHC_PACKET_TCP_SEQ_7     = 30, /**< TCP seq_7 packet */
	ROHC_PACKET_TCP_SEQ_8     = 31, /**< TCP seq_8 packet */

	/* Context Replication (CR) */
	ROHC_PACKET_IR_CR         = 32, /**< ROHC IR-CR packet */

	/* packet types for all ROHCv2 profiles (RFC 5225) */
#define ROHC_PACKET_CO_COMMON ROHC_PACKET_TCP_CO_COMMON /**< ROHCv2 co_common packet */
	ROHC_PACKET_CO_REPAIR         = 33, /**< ROHCv2 CO-REPAIR packet */
	ROHC_PACKET_PT_0_CRC3         = 34, /**< ROHCv2 PT-0-CRC3 packet */
	/* packet types for all non-RTP ROHCv2 profiles (RFC 5225) */
	ROHC_PACKET_NORTP_PT_0_CRC7   = 35, /**< ROHCv2 PT-0-CRC7 packet (non-RTP) */
	ROHC_PACKET_NORTP_PT_1_SEQ_ID = 36, /**< ROHCv2 PT-1-SEQ-ID packet (non-RTP) */
	ROHC_PACKET_NORTP_PT_2_SEQ_ID = 37, /**< ROHCv2 PT-2-SEQ-ID packet (non-RTP) */
	/* packet types for all RTP ROHCv2 profiles (RFC 5225) */
	ROHC_PACKET_RTP_PT_0_CRC7     = 38, /**< ROHCv2 PT-0-CRC7 packet (RTP) */
	ROHC_PACKET_RTP_PT_1_RND      = 39, /**< ROHCv2 PT-1-RND packet (RTP) */
	ROHC_PACKET_RTP_PT_1_SEQ_ID   = 40, /**< ROHCv2 PT-1-SEQ-ID packet (RTP) */
	ROHC_PACKET_RTP_PT_1_SEQ_TS   = 41, /**< ROHCv2 PT-1-SEQ-TS packet (RTP) */
	ROHC_PACKET_RTP_PT_2_RND      = 42, /**< ROHCv2 PT-2-RND packet (RTP) */
	ROHC_PACKET_RTP_PT_2_SEQ_ID   = 43, /**< ROHCv2 PT-2-SEQ-ID packet (RTP) */
	ROHC_PACKET_RTP_PT_2_SEQ_TS   = 44, /**< ROHCv2 PT-2-SEQ-TS packet (RTP) */
	ROHC_PACKET_RTP_PT_2_SEQ_BOTH = 45, /**< ROHCv2 PT-2-SEQ-BOTH packet (RTP) */

	/* UO-1-ID packet with extensions */
	ROHC_PACKET_UO_1_ID_EXT0      = 46, /**< ROHC UO-1-ID packet with EXT-0 (RTP profile only) */
	ROHC_PACKET_UO_1_ID_EXT1      = 47, /**< ROHC UO-1-ID packet with EXT-1 (RTP profile only) */
	ROHC_PACKET_UO_1_ID_EXT2      = 48, /**< ROHC UO-1-ID packet with EXT-2 (RTP profile only) */
	ROHC_PACKET_UO_1_ID_EXT3      = 49, /**< ROHC UO-1-ID packet with EXT-3 (RTP profile only) */

	/* UOR-2 packets with extensions */
	ROHC_PACKET_UOR_2_EXT0        = 50, /**< ROHC UOR-2 packet with EXT-0 (non-RTP profiles) */
	ROHC_PACKET_UOR_2_EXT1        = 51, /**< ROHC UOR-2 packet with EXT-1 (non-RTP profiles) */
	ROHC_PACKET_UOR_2_EXT2        = 52, /**< ROHC UOR-2 packet with EXT-2 (non-RTP profiles) */
	ROHC_PACKET_UOR_2_EXT3        = 53, /**< ROHC UOR-2 packet with EXT-3 (non-RTP profiles) */
	ROHC_PACKET_UOR_2_RTP_EXT0    = 54, /**< ROHC UOR-2 packet with EXT-0 (RTP profile only) */
	ROHC_PACKET_UOR_2_RTP_EXT1    = 55, /**< ROHC UOR-2 packet with EXT-1 (RTP profile only) */
	ROHC_PACKET_UOR_2_RTP_EXT2    = 56, /**< ROHC UOR-2 packet with EXT-2 (RTP profile only) */
	ROHC_PACKET_UOR_2_RTP_EXT3    = 57, /**< ROHC UOR-2 packet with EXT-3 (RTP profile only) */
	ROHC_PACKET_UOR_2_ID_EXT0     = 58, /**< ROHC UOR-2-ID packet with EXT-0 (RTP profile only) */
	ROHC_PACKET_UOR_2_ID_EXT1     = 59, /**< ROHC UOR-2-ID packet with EXT-1 (RTP profile only) */
	ROHC_PACKET_UOR_2_ID_EXT2     = 60, /**< ROHC UOR-2-ID packet with EXT-2 (RTP profile only) */
	ROHC_PACKET_UOR_2_ID_EXT3     = 61, /**< ROHC UOR-2-ID packet with EXT-3 (RTP profile only) */
	ROHC_PACKET_UOR_2_TS_EXT0     = 62, /**< ROHC UOR-2-TS packet with EXT-0 (RTP profile only) */
	ROHC_PACKET_UOR_2_TS_EXT1     = 63, /**< ROHC UOR-2-TS packet with EXT-1 (RTP profile only) */
	ROHC_PACKET_UOR_2_TS_EXT2     = 64, /**< ROHC UOR-2-TS packet with EXT-2 (RTP profile only) */
	ROHC_PACKET_UOR_2_TS_EXT3     = 65, /**< ROHC UOR-2-TS packet with EXT-3 (RTP profile only) */

	ROHC_PACKET_MAX                 /**< The number of packet types */
} rohc_packet_t;


/**
 * @brief The different types of extensions for UO-1-ID and UOR-2* packets
 *
 * If you add a new extension type, please also add the corresponding textual
 * description in \ref rohc_get_ext_descr.
 */
typedef enum
{
	ROHC_EXT_0       = 0,  /**< The EXT-0 extension for UO-1-ID/UOR-2* packets */
	ROHC_EXT_1       = 1,  /**< The EXT-1 extension for UO-1-ID/UOR-2* packets */
	ROHC_EXT_2       = 2,  /**< The EXT-2 extension for UO-1-ID/UOR-2* packets */
	ROHC_EXT_3       = 3,  /**< The EXT-3 extension for UO-1-ID/UOR-2* packets */
	ROHC_EXT_NONE    = 4,  /**< No extension for UO-1-ID/UOR-2* packets */
	ROHC_EXT_UNKNOWN = 5,  /**< Unknown packet extension type */
} rohc_ext_t;


/*
 * Prototypes of public functions
 */

const char * ROHC_EXPORT rohc_get_packet_descr(const rohc_packet_t packet_type)
	__attribute__((warn_unused_result, const));

const char * ROHC_EXPORT rohc_get_ext_descr(const rohc_ext_t ext_type)
	__attribute__((warn_unused_result, const));

rohc_packet_t ROHC_EXPORT rohc_get_packet_type(const char *const packet_id)
	__attribute__((warn_unused_result, nonnull(1)));

bool ROHC_EXPORT rohc_packet_is_ir(const rohc_packet_t packet_type)
	__attribute__((warn_unused_result, const));

bool ROHC_EXPORT rohc_packet_carry_static_info(const rohc_packet_t packet_type)
	__attribute__((warn_unused_result, const));

bool ROHC_EXPORT rohc_packet_carry_crc_7_or_8(const rohc_packet_t packet_type)
	__attribute__((warn_unused_result, const));

#undef ROHC_EXPORT /* do not pollute outside this header */

#ifdef __cplusplus
}
#endif

#endif /* ROHC_PACKETS_H */

