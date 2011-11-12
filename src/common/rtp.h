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
 * @file rtp.h
 * @brief RTP header
 * @author David Moreau from TAS
 *
 * See section 5.1 of RFC 1889 for details.
 */

#ifndef RTP_H
#define RTP_H

#include <sys/types.h>


/**
 * @brief RTP header
 *
 * See section 5.1 of RFC 1889 for details.
 */
struct rtphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int16_t cc:4;          ///< CSRC Count
	u_int16_t extension:1;   ///< Extension bit
	u_int16_t padding:1;     ///< Padding bit
	u_int16_t version:2;     ///< RTP version
	u_int16_t pt:7;          ///< Payload Type
	u_int16_t m:1;           ///< Marker
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int16_t version:2;
	u_int16_t padding:1;
	u_int16_t extension:1;
	u_int16_t cc:4;
	u_int16_t m:1;
	u_int16_t pt:7;
#else
#	error "Adjust your <bits/endian.h> defines"
#endif
	u_int16_t sn;            ///< Sequence Number
	u_int32_t timestamp;     ///< Timestamp
	u_int32_t ssrc;          ///< Synchronization SouRCe (SSRC) identifier
//	u_int32_t * csrc;
} __attribute__((packed));


#endif

