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
 * @file c_rtp.h
 * @brief ROHC compression context for the RTP profile.
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef C_RTP_H
#define C_RTP_H

#include "c_generic.h"
#include "ts_sc_comp.h"
#include "protocols/udp.h"
#include "protocols/rtp.h"


/**
 * @brief Define the RTP and UDP specific temporary variables in the profile
 *        compression context.
 *
 * This object must be used by the RTP-specific decompression context
 * sc_rtp_context.
 *
 * @see sc_rtp_context
 */
struct rtp_tmp_vars
{
	/// The number of UDP/RTP fields that changed in the UDP/RTP headers
	int send_rtp_dynamic;

	/// The number of bits needed to encode ts_send
	size_t nr_ts_bits;

	/// The number of bits of TS to place in the extension 3 header
	size_t nr_ts_bits_ext3;

	/// The real timestamp of the last RTP message
	uint32_t timestamp;

	/// The TS field to send (ts_scaled or ts)
	uint32_t ts_send;

	/// Whether the Marker (M) bit is set in the RTP header or not
	bool is_marker_bit_set;

	/** Whether the Padding (P) bit changed or not */
	bool padding_bit_changed;

	/// Whether the eXtension (X) bit changed or not
	bool extension_bit_changed;

	/// Whether the Payload Type (PT) field changed or not
	int rtp_pt_changed;
};


/**
 * @brief Define the RTP part of the profile decompression context.
 *
 * This object must be used with the generic part of the decompression
 * context c_generic_context.
 *
 * @warning The 2 first fields MUST stay at the beginning of the structure
 *          to be compatible with \ref sc_udp_context
 *
 * @see c_generic_context
 */
struct sc_rtp_context
{
	/// @brief The number of times the UDP checksum field was added to the
	///        compressed header
	int udp_checksum_change_count;

	/// The previous UDP header
	struct udphdr old_udp;

	/// @brief The number of times the RTP Payload Type (PT) field was added to
	///        the compressed header
	int rtp_pt_change_count;

	/// @brief The number of times the RTP Padding (P) bit was added to
	///        the compressed header
	size_t rtp_padding_change_count;

	/// @brief The number of times the RTP eXtension (X) bit was added to
	///        the compressed header
	size_t rtp_extension_change_count;

	/// The previous RTP header
	struct rtphdr old_rtp;

	/// @brief RTP-specific temporary variables that are used during one single
	///        compression of packet
	struct rtp_tmp_vars tmp;

	/// Scaled RTP Time Stamp
	int tss;

	/// Whether the Time Stride field is present or not
	int tis;

	/// Structure to encode the TS field
	struct ts_sc_comp ts_sc;
};


/*
 * Function prototypes.
 */

/* no public function */

#endif

