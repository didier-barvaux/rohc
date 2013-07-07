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
 * Handle Hop-by-Hop, routing, GRE, Authentication, MINE, and destination
 * options.
 *
 * @param protocol  The protocol number to check for
 * @return          true if the protocol is an IPv6 option,
 *                  false otherwise
 */
bool rohc_is_ipv6_opt(const uint8_t protocol)
{
	return (protocol == ROHC_IPPROTO_HOPOPTS ||
	        protocol == ROHC_IPPROTO_ROUTING ||
	        protocol == ROHC_IPPROTO_GRE ||
	        protocol == ROHC_IPPROTO_AH ||
	        protocol == ROHC_IPPROTO_MINE ||
	        protocol == ROHC_IPPROTO_DSTOPTS);
}

