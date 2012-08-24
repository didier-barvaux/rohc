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
 * @file c_udp_lite.c
 * @brief ROHC compression context for the UDP-Lite profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef C_UDP_LITE_H
#define C_UDP_LITE_H

#include <netinet/udp.h>

#include "c_generic.h"


/// @brief The maximal number of times the checksum coverage dit not change
///        or may be inferred
#define MAX_LITE_COUNT 2


/**
 * @brief Define the UDP-Lite-specific temporary variables in the profile
 *        compression context.
 *
 * This object must be used by the UDP-specific compression context
 * sc_udp_lite_context.
 *
 * @see sc_udp_lite_context
 */
struct udp_lite_tmp_vars
{
	/// The size of the UDP-Lite packet (header + payload)
	int udp_size;
};


/**
 * @brief Define the UDP-Lite part of the profile compression context.
 *
 * This object must be used with the generic part of the compression
 * context c_generic_context.
 *
 * @see c_generic_context
 */
struct sc_udp_lite_context
{
	/// Whether the Coverage Field is Present or not
	int cfp;
	/// Whether the Coverage Field is Inferred or not
	int cfi;

	/// The F and K bits in the CCE packet (see appendix B in the RFC 4019)
	unsigned char FK;

	/// The number of times the checksum coverage field did not change
	int coverage_equal_count;
	/// The number of times the checksum coverage field may be inferred
	int coverage_inferred_count;
	/// Temporary variables related to the checksum coverage field
	int tmp_coverage;

	/// The number of CCE() packets sent by the compressor
	int sent_cce_only_count;
	/// The number of CCE(ON) packets sent by the compressor
	int sent_cce_on_count;
	/// The number of CCE(OFF) packets sent by the compressor
	int sent_cce_off_count;

	/// The previous UDP-Lite header
	struct udphdr old_udp_lite;

	/// @brief UDP-Lite-specific temporary variables that are used during one
	///        single compression of packet
	struct udp_lite_tmp_vars tmp;
};


#endif

