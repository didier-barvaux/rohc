/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2008,2009,2010,2012,2013,2014 Viveris Technologies
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
 * @file   common/ip.c
 * @brief  IP-agnostic packet
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "ip.h"
#include "rohc_utils.h"
#include "protocols/ip_numbers.h"
#include "protocols/ip.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"

#include <string.h>
#include <assert.h>


/*
 * Generic IP functions (apply to both IPv4 and IPv6):
 */


/**
 * @brief Set the IP version of an IP packet
 *
 * @param ip     The IP packet to modify
 * @param value  The version value
 */
void ip_set_version(struct ip_packet *const ip, const ip_version value)
{
	ip->version = value;
}


/**
 * @brief Get the protocol transported by an IP packet
 *
 * The protocol returned is the one transported by the last known IP extension
 * header if any is found.
 *
 * The function handles \ref ip_packet whose \ref ip_packet::version is
 * \ref IP_UNKNOWN. It always returns the special value 0.
 *
 * @param ip  The IP packet to analyze
 * @return    The protocol number that identify the protocol transported
 *            by the given IP packet, 0 if the packet is not IPv4 nor IPv6
 */
uint8_t ip_get_protocol(const struct ip_packet *const ip)
{
	return ip->nl.proto;
}


/**
 * @brief Set the protocol transported by an IP packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip     The IP packet to modify
 * @param value  The protocol value
 */
void ip_set_protocol(struct ip_packet *const ip, const uint8_t value)
{
	if(ip->version == IPV4)
	{
		ip->header.v4.protocol = value & 0xff;
		ip->nl.proto = value & 0xff;
	}
	else if(ip->version == IPV6)
	{
		ip->header.v6.nh = value & 0xff;
		ip->nl.proto = value & 0xff;
	}
	else
	{
		/* function does not handle non-IPv4/IPv6 packets */
		assert(0);
	}
}


/**
 * @brief Get the IPv4 Type Of Service (TOS) or IPv6 Traffic Class (TC)
 *        of an IP packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip The IP packet to analyze
 * @return   The TOS or TC value if successful, 0 otherwise
 */
unsigned int ip_get_tos(const struct ip_packet *const ip)
{
	unsigned int tos;

	if(ip->version == IPV4)
	{
		tos = ip->header.v4.tos;
	}
	else if(ip->version == IPV6)
	{
		tos = ipv6_get_tc(&ip->header.v6);
	}
	else
	{
		/* function does not handle non-IPv4/IPv6 packets */
#if defined(NDEBUG) || defined(__KERNEL__) || defined(ENABLE_DEAD_CODE)
		tos = 0;
#endif
		assert(0);
	}

	return tos;
}


/**
 * @brief Set the IPv4 Type Of Service (TOS) or IPv6 Traffic Class (TC)
 *        of an IP packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip     The IP packet to modify
 * @param value  The TOS/TC value
 */
void ip_set_tos(struct ip_packet *const ip, const uint8_t value)
{
	if(ip->version == IPV4)
	{
		ip->header.v4.tos = value & 0xff;
	}
	else if(ip->version == IPV6)
	{
		ipv6_set_tc(&ip->header.v6, value);
	}
	else
	{
		/* function does not handle non-IPv4/IPv6 packets */
		assert(0);
	}
}


/**
 * @brief Get the IPv4 Time To Live (TTL) or IPv6 Hop Limit (HL)
 *        of an IP packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip The IP packet to analyze
 * @return   The TTL or HL value if successful, 0 otherwise
 */
unsigned int ip_get_ttl(const struct ip_packet *const ip)
{
	unsigned int ttl;

	if(ip->version == IPV4)
	{
		ttl = ip->header.v4.ttl;
	}
	else if(ip->version == IPV6)
	{
		ttl = ip->header.v6.hl;
	}
	else
	{
		/* function does not handle non-IPv4/IPv6 packets */
#if defined(NDEBUG) || defined(__KERNEL__) || defined(ENABLE_DEAD_CODE)
		ttl = 0;
#endif
		assert(0);
	}

	return ttl;
}


/**
 * @brief Set the IPv4 Time To Live (TTL) or IPv6 Hop Limit (HL)
 *        of an IP packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip     The IP packet to modify
 * @param value  The TTL/HL value
 */
void ip_set_ttl(struct ip_packet *const ip, const uint8_t value)
{
	if(ip->version == IPV4)
	{
		ip->header.v4.ttl = value & 0xff;
	}
	else if(ip->version == IPV6)
	{
		ip->header.v6.hl = value & 0xff;
	}
	else
	{
		/* function does not handle non-IPv4/IPv6 packets */
		assert(0);
	}
}


/**
 * @brief Set the Source Address of an IP packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip     The IP packet to modify
 * @param value  The IP address value
 */
void ip_set_saddr(struct ip_packet *const ip, const uint8_t *value)
{
	if(ip->version == IPV4)
	{
		memcpy(&ip->header.v4.saddr, value, sizeof(uint32_t));
	}
	else if(ip->version == IPV6)
	{
		memcpy(&ip->header.v6.saddr, value, sizeof(struct ipv6_addr));
	}
	else
	{
		/* function does not handle non-IPv4/IPv6 packets */
		assert(0);
	}
}


/**
 * @brief Set the Destination Address of an IP packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip     The IP packet to modify
 * @param value  The IP address value
 */
void ip_set_daddr(struct ip_packet *const ip, const uint8_t *value)
{
	if(ip->version == IPV4)
	{
		memcpy(&ip->header.v4.daddr, value, sizeof(uint32_t));
	}
	else if(ip->version == IPV6)
	{
		memcpy(&ip->header.v6.daddr, value, sizeof(struct ipv6_addr));
	}
	else
	{
		/* function does not handle non-IPv4/IPv6 packets */
		assert(0);
	}
}

