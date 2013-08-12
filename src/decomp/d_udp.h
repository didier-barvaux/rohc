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
 * @file d_udp.h
 * @brief ROHC decompression context for the UDP profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#ifndef D_UDP_H
#define D_UDP_H

#include "d_generic.h"
#include "d_ip.h"

#include <stdint.h>
#ifndef __KERNEL__
#	include <string.h>
#endif


/**
 * @brief Define the UDP part of the decompression profile context.
 *
 * This object must be used with the generic part of the decompression
 * context d_generic_context.
 *
 * @see d_generic_context
 */
struct d_udp_context
{
	/** UDP source port */
	uint16_t sport;
	/** UDP destination port */
	uint16_t dport;
	/// Whether the UDP checksum field is encoded in the ROHC packet or not
	int udp_checksum_present;
};


/*
 * Public function prototypes.
 */

int udp_parse_static_udp(const struct d_context *const context,
                         const unsigned char *packet,
                         size_t length,
                         struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

void udp_update_context(const struct d_context *context,
                        const struct rohc_decoded_values decoded)
	__attribute__((nonnull(1)));

#endif

