/*
 * Copyright 2013,2014 Didier Barvaux
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
 * @file   ip_numbers.c
 * @brief  Defines the IPv4 protocol numbers
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "ip_numbers.h"


/**
 * @brief Whether the given protocol is IP tunneling
 *
 * @param protocol  The protocol number to check for
 * @return          true if the protocol is IP/IP or IPv6,
 *                  false otherwise
 */
bool rohc_is_tunneling(const uint8_t protocol)
{
	return (protocol == ROHC_IPPROTO_IPIP ||
	        protocol == ROHC_IPPROTO_IPV6);
}


/**
 * @brief Whether the given protocol is an IPv6 option
 *
 * Handle GRE, Authentication (AH), MINE, and all IPv6 extension headers.
 *
 * The list of IPv6 extension headers was retrieved from the registry
 * maintained by IANA at:
 *   http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
 * Remember to update \ref get_index_ipv6_table if you update the list.
 *
 * @param protocol  The protocol number to check for
 * @return          true if the protocol is an IPv6 option,
 *                  false otherwise
 */
bool rohc_is_ipv6_opt(const uint8_t protocol)
{
	return (protocol == ROHC_IPPROTO_HOPOPTS ||
	        protocol == ROHC_IPPROTO_ROUTING ||
	        protocol == ROHC_IPPROTO_FRAGMENT ||
#if 0 /* TODO: add support for GRE header */
	        protocol == ROHC_IPPROTO_GRE ||
#endif
#if 0 /* TODO: add support for null ESP header */
	        protocol == ROHC_IPPROTO_ESP ||
#endif
#if 0 /* TODO: add support for AH header */
	        protocol == ROHC_IPPROTO_AH ||
#endif
#if 0 /* TODO: add support for MINE header */
	        protocol == ROHC_IPPROTO_MINE ||
#endif
	        protocol == ROHC_IPPROTO_DSTOPTS ||
	        protocol == ROHC_IPPROTO_MOBILITY ||
	        protocol == ROHC_IPPROTO_HIP ||
	        protocol == ROHC_IPPROTO_SHIM ||
	        protocol == ROHC_IPPROTO_RESERVED1 ||
	        protocol == ROHC_IPPROTO_RESERVED2);
}

