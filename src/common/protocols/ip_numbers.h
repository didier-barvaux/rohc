/**
 * @file   ip_numbers.h
 * @brief  Defines the IPv4 protocol numbers
 * @author Free Software Foundation, Inc
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * This file contains some parts from the GNU C library. It is copied here to
 * be portable on all platforms, even the platforms that miss the
 * declarations or got different declarations, such as Microsoft Windows or
 * FreeBSD.
 */

#ifndef ROHC_PROTOCOLS_NUMBERS_H
#define ROHC_PROTOCOLS_NUMBERS_H

#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#	include <stdint.h>
#endif

#include "dllexport.h"


/**
 * @brief The IP numbers defined by IANA
 *
 * Full list at:
 *   http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
 */
enum
{
	/** The IP protocol number for Hop-by-Hop option */
	ROHC_IPPROTO_HOPOPTS   = 0,
	/** The IP protocol number for IPv4-in-IPv4 tunnels */
	ROHC_IPPROTO_IPIP      = 4,
	/** The IP protocol number for Transmission Control Protocol (TCP) */
	ROHC_IPPROTO_TCP       = 6,
	/** The IP protocol number for the User Datagram Protocol (UDP) */
	ROHC_IPPROTO_UDP       = 17,
	/** The IP protocol number for IPv6 */
	ROHC_IPPROTO_IPV6      = 41,
	/** The IP protocol number for IPv6 routing header */
	ROHC_IPPROTO_ROUTING   = 43,
	/** The IP protocol number for IPv6 fragment header */
	ROHC_IPPROTO_FRAGMENT  = 44,
	/** The IP protocol number for Generic Routing Encapsulation (GRE) */
	ROHC_IPPROTO_GRE       = 47,
	/** The IP protocol number for the Encapsulating Security Payload (ESP)  */
	ROHC_IPPROTO_ESP       = 50,
	/** The IP protocol number for Authentication Header */
	ROHC_IPPROTO_AH        = 51,
	/** The IP protocol number for Minimal Encapsulation within IP (RFC 2004) */
	ROHC_IPPROTO_MINE      = 55,
	/** The IP protocol number for IPv6 destination option */
	ROHC_IPPROTO_DSTOPTS   = 60,
	/** The IP protocol number for Mobility Header */
	ROHC_IPPROTO_MOBILITY  = 135,
	/** The IP protocol number for UDP-Lite */
	ROHC_IPPROTO_UDPLITE   = 136,
	/** The IP protocol number for the Host Identity Protocol (HIP) */
	ROHC_IPPROTO_HIP       = 139,
	/** The IP protocol number for the Shim6 Protocol */
	ROHC_IPPROTO_SHIM      = 140,
	/** The IP protocol number reserved for experimentation and testing */
	ROHC_IPPROTO_RESERVED1 = 253,
	/** The IP protocol number reserved for experimentation and testing */
	ROHC_IPPROTO_RESERVED2 = 254,
};


bool ROHC_EXPORT rohc_is_tunneling(const uint8_t protocol)
	__attribute((warn_unused_result, pure));

bool ROHC_EXPORT rohc_is_ipv6_opt(const uint8_t protocol)
	__attribute((warn_unused_result, pure));

#endif
