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
 * @file d_rtp.h
 * @brief ROHC decompression context for the RTP profile.
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef D_RTP_H
#define D_RTP_H

#include "rtp.h"
#include "d_generic.h"
#include "d_udp.h"
#include "ts_sc_decomp.h"

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>


/**
 * @brief Define the RTP part of the decompression profile context.
 * 
 * This object must be used with the generic part of the decompression
 * context d_generic_context.
 *
 * @see d_generic_context
 */
struct d_rtp_context
{
	/// Whether the UDP checksum field is encoded in the ROHC packet or not
	int udp_checksum_present;

	/// The LSB-encoded Timestamp
	struct d_lsb_decode ts;

	/// The structure to decompress TS_STRIDE
	struct ts_sc_decomp ts_sc;
};


/*
 * Public function prototypes.
 */

int rtp_decode_static_rtp(struct d_generic_context *context,
                          const unsigned char *packet,
                          unsigned int length,
                          unsigned char *dest);

int rtp_decode_dynamic_rtp(struct d_generic_context *context,
                           const unsigned char *packet,
                           unsigned int length,
                           unsigned char *dest);

int rtp_build_uncompressed_rtp(struct d_generic_context *context,
                               struct d_generic_changes *active,
                               unsigned char *dest,
                               int payload_size);
int rtp_get_static_part(void);

#endif

