/*
 * Copyright 2007,2008 CNES
 * Copyright 2010,2011,2012,2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2009,2010 Viveris Technologies
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
 * @file c_rtp.h
 * @brief ROHC compression context for the RTP profile.
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMP_RTP_H
#define ROHC_COMP_RTP_H

#include "rohc_comp_rfc3095.h"
#include "schemes/comp_scaled_rtp_ts.h"
#include "protocols/udp.h"
#include "protocols/rtp.h"


/** The RTP-specific temporary variables */
struct rtp_tmp_vars
{
	/** Whether the UDP checksum changed of behavior with the current packet */
	uint16_t udp_check_behavior_just_changed:1;
	/** Whether the UDP checksum changed of behavior with the last few packets */
	uint16_t udp_check_behavior_changed:1;
	/** Whether the RTP Version changed with the current packet */
	uint16_t rtp_version_just_changed:1;
	/** Whether the RTP Version changed with the last few packets */
	uint16_t rtp_version_changed:1;
	/** Whether the RTP Padding (P) bit changed with the current packet */
	uint16_t rtp_padding_just_changed:1;
	/** Whether the RTP Padding (P) bit changed with the last few packets */
	uint16_t rtp_padding_changed:1;
	/** Whether the RTP eXtension (X) bit changed with the current packet */
	uint16_t rtp_ext_just_changed:1;
	/** Whether the RTP eXtension (X) bit changed with the last few packets */
	uint16_t rtp_ext_changed:1;
	uint16_t is_marker_bit_set:1;   /**< Whether RTP Marker (M) bit is set */
	/** Whether the RTP Payload Type (PT) changed with the current packet */
	uint16_t rtp_pt_just_changed:1;
	/** Whether the RTP Payload Type (PT) changed with the last few packets */
	uint16_t rtp_pt_changed:1;
	uint16_t unused:5;

	/** The TS field to send (ts_scaled or ts) */
	uint32_t ts_send;
	/** The number of bits needed to encode ts_send */
	uint8_t nr_ts_bits;
	/** The number of bits of TS to place in the extension 3 header */
	uint8_t nr_ts_bits_ext3;
};


/**
 * @brief Define the RTP part of the profile decompression context.
 *
 * This object must be used with the generic part of the decompression
 * context rohc_comp_rfc3095_ctxt.
 *
 * @see rohc_comp_rfc3095_ctxt
 */
struct sc_rtp_context
{
	/** Structure to encode the TS field */
	struct ts_sc_comp ts_sc;

	/** The number of times the checksum field was transmitted since last change */
	uint8_t udp_checksum_trans_nr;
	/** The nr of times the RTP Version field was added to compressed headers */
	uint8_t rtp_version_trans_nr;
	/** The nr of times the RTP Padding (P) bit was added to compressed headers */
	uint8_t rtp_padding_trans_nr;
	/** The nr of times the RTP eXtension (X) bit was added to compressed headers */
	uint8_t rtp_ext_trans_nr;
	/** The nr of times the RTP PT field was added to compressed headers */
	uint8_t rtp_pt_trans_nr;

	uint16_t old_udp_check;       /**< The UDP checksum in previous UDP header */
	uint16_t old_rtp_version:2;   /**< The RTP Version in previous RTP header */
	uint16_t old_rtp_padding:1;   /**< The RTP Padding in previous RTP header */
	uint16_t old_rtp_extension:1; /**< The RTP Extension in previous RTP header */
	uint16_t old_rtp_pt:7;        /**< The RTP Payload Type in previous RTP header */
	uint16_t unused:5;

	/// @brief RTP-specific temporary variables that are used during one single
	///        compression of packet
	struct rtp_tmp_vars tmp;
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((sizeof(struct sc_rtp_context) % 8) == 0,
               "sc_rtp_context length should be multiple of 8 bytes");
#endif


/*
 * Function prototypes.
 */

/* no public function */

#endif

