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

#ifndef __KERNEL__
#  include <string.h>
#endif
#include <assert.h>


static bool ip_find_next_layer(const struct ip_packet *const ip,
                               struct net_hdr *const nh,
                               struct net_hdr *const nl)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static bool ext_get_next_layer(const struct net_hdr *const nh,
                               struct net_hdr *const nl)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool ext_get_next_header(const uint8_t *const ext,
                                const size_t ext_len,
                                struct net_hdr *const nh)
	__attribute__((warn_unused_result, nonnull(1, 3)));



/*
 * Generic IP functions (apply to both IPv4 and IPv6):
 */


/**
 * @brief Create an IP packet from raw data
 *
 * @param ip     OUT: The IP packet to create
 * @param packet The IP packet data
 * @param size   The length of the IP packet data
 * @return       Whether the IP packet was successfully created or not
 */
bool ip_create(struct ip_packet *const ip,
               const uint8_t *const packet,
               const size_t size)
{
	const struct ip_hdr *const ip_hdr = (struct ip_hdr *) packet;

	/* get the version of the IP packet */
	if(size >= sizeof(struct ip_hdr))
	{
		ip->version = ip_hdr->version;
	}
	else
	{
		ip->version = IP_UNKNOWN;
	}

	/* check packet's validity according to IP version */
	if(ip->version == IPV4)
	{
		/* IPv4: packet must be at least 20-byte long (= min header length)
		 *       packet must be large enough for options if any (= 20 bytes)
		 *       packet length must be accurate with the Total Length field */

		if(size < sizeof(struct ipv4_hdr))
		{
			goto malformed;
		}

		/* copy the IPv4 header */
		memcpy(&ip->header.v4, packet, sizeof(struct ipv4_hdr));

		if(ip_get_hdrlen(ip) < sizeof(struct ipv4_hdr) ||
		   ip_get_hdrlen(ip) > size)
		{
			goto malformed;
		}

		if(ip_get_totlen(ip) != size)
		{
			goto malformed;
		}

		/* point to the whole IPv4 packet */
		ip->data = packet;
		ip->size = size;
	}
	else if(ip->version == IPV6)
	{
		/* IPv6: packet must be at least 40-byte long (= header length)
		 *       packet length == header length + Payload Length field */

		if(size < sizeof(struct ipv6_hdr))
		{
			goto malformed;
		}

		/* copy the IPv6 header */
		memcpy(&ip->header.v6, packet, sizeof(struct ipv6_hdr));

		if(ip_get_totlen(ip) != size)
		{
			goto malformed;
		}

		/* point to the whole IPv6 packet */
		ip->data = packet;
		ip->size = size;
	}
	else /* IP_UNKNOWN */
	{
		goto unknown;
	}

	/* find the next header and layer */
	if(!ip_find_next_layer(ip, &ip->nh, &ip->nl))
	{
		goto malformed;
	}

	return 1;

malformed:
	/* manage the malformed IP packet */
	if(ip->version == IPV4)
	{
		ip->version = IPV4_MALFORMED;
	}
	else if(ip->version == IPV6)
	{
		ip->version = IPV6_MALFORMED;
	}
	else
	{
		goto error;
	}
	ip->data = packet;
	ip->size = size;
	ip->nh.proto = 0;
	ip->nh.data = NULL;
	ip->nh.len = 0;
	ip->nl.proto = 0;
	ip->nl.data = NULL;
	ip->nl.len = 0;
	return 1;

unknown:
	/* manage the IP packet that the library cannot handle as IPv4 nor IPv6
	 * as unknown data */
	ip->version = IP_UNKNOWN;
	ip->data = packet;
	ip->size = size;
	ip->nh.proto = 0;
	ip->nh.data = NULL;
	ip->nh.len = 0;
	ip->nl.proto = 0;
	ip->nl.data = NULL;
	ip->nl.len = 0;
	return 1;

error:
	return 0;
}


/**
 * @brief Get the IP raw data (header + payload)
 *
 * The function handles \ref ip_packet whose \ref ip_packet::version is
 * \ref IP_UNKNOWN.
 *
 * @param ip The IP packet to analyze
 * @return   The IP raw data (header + payload)
 */
const uint8_t * ip_get_raw_data(const struct ip_packet *const ip)
{
	return ip->data;
}


/**
 * @brief Get the inner IP packet (IP in IP)
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param outer The outer IP packet to analyze
 * @param inner The inner IP packet to create
 * @return      Whether the inner IP header is successfully created or not
 */
bool ip_get_inner_packet(const struct ip_packet *const outer,
                         struct ip_packet *const inner)
{
	/* create an IP packet with the next header data */
	return ip_create(inner, outer->nl.data, outer->nl.len);
}


/**
 * @brief Get the IP next header
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip   The IP packet to analyze
 * @param type OUT: The type of the next header
 * @return     The next header if successful, NULL otherwise
 */
uint8_t * ip_get_next_header(const struct ip_packet *const ip,
                             uint8_t *const type)
{
	/* function does not handle non-IPv4/IPv6 packets */
	assert(ip->version != IP_UNKNOWN);

	*type = ip->nh.proto;
	return ip->nh.data;
}


/**
 * @brief Get the next header (but skip IP extensions)
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip   The IP packet to analyze
 * @return     The next header that is not an IP extension if there is one,
 *             NULL if there is none
 */
uint8_t * ip_get_next_layer(const struct ip_packet *const ip)
{
	/* function does not handle non-IPv4/IPv6 packets */
	assert(ip->version == IPV4 || ip->version == IPV6);

	return ip->nl.data;
}


/**
 * @brief Get the next extension header of IPv6 packets from
 *        an IPv6 header
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip   The IP packet to analyze
 * @param type OUT: The type of the next header
 *             If there is no next header the value must be ignored
 * @return     The next extension header,
 *             NULL if there is no extension
 */
uint8_t * ip_get_next_ext_from_ip(const struct ip_packet *const ip,
                                  uint8_t *const type)
{
	uint8_t *next_header;

	/* function does not handle non-IPv4/IPv6 packets */
	assert(ip->version != IP_UNKNOWN);

	if(ip->version != IPV6)
	{
		return NULL;
	}

	/* get the next header data in the IP packet */
	next_header = ip_get_next_header(ip, type);

	if(rohc_is_ipv6_opt(*type))
	{
		/* known extension headers */
		return next_header;
	}
	else
	{
		return NULL;
	}
}


/**
 * @brief Get the next extension header of IPv6 packets from
 *        another extension
 *
 * @param ext  The extension to analyse
 * @param type OUT: The type of the next header
 *             If there is no next header the value must be ignored
 * @return     The next extension header,
 *             NULL if there is no more extension
 */
uint8_t * ip_get_next_ext_from_ext(const uint8_t *const ext,
                                   uint8_t *const type)
{
	uint8_t *next_header;
	uint8_t length;

	*type = ext[0];

	if(rohc_is_ipv6_opt(*type))
	{
		/* known extension headers */
		length = ext[1];
		next_header = (uint8_t *)(ext + (length + 1) * 8);
	}
	else
	{
		next_header = NULL;
	}

	return next_header;
}


/**
 * @brief Get the size of an IPv6 extension
 *
 * @param ext The extension
 * @return    The size of the extension
 */
unsigned short ip_get_extension_size(const uint8_t *const ext)
{
	const uint8_t ext_length = ext[1];

	return (ext_length + 1) * 8;
}


/**
 * @brief Get the size of the extension list
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip The packet to analyse
 * @return   The size of extension list
 */
unsigned short ip_get_total_extension_size(const struct ip_packet *const ip)
{
	uint8_t *ext;
	uint8_t next_hdr_type;
	unsigned short total_ext_size = 0;

	/* TODO: not very performant */
	ext = ip_get_next_ext_from_ip(ip, &next_hdr_type);
	while(ext != NULL)
	{
		total_ext_size += ip_get_extension_size(ext);
		ext = ip_get_next_ext_from_ext(ext, &next_hdr_type);
	}

	return total_ext_size;
}


/**
 * @brief Whether the IP packet is an IP fragment or not
 *
 * The IP packet is a fragment if the  MF (More Fragments) bit is set
 * or the Fragment Offset field is non-zero.
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip The IP packet to analyze
 * @return   Whether the IP packet is an IP fragment or not
 */
bool ip_is_fragment(const struct ip_packet *const ip)
{
	bool is_fragment;

	if(ip->version == IPV4)
	{
		is_fragment = ipv4_is_fragment(&ip->header.v4);
	}
	else if(ip->version == IPV6)
	{
		is_fragment = false;
	}
	else
	{
		/* function does not handle non-IPv4/IPv6 packets */
#if defined(NDEBUG) || defined(__KERNEL__) || defined(ENABLE_DEAD_CODE)
		is_fragment = false;
#endif
		assert(0);
	}

	return is_fragment;
}


/**
 * @brief Get the total length of an IP packet
 *
 * The function handles \ref ip_packet whose \ref ip_packet::version is
 * \ref IP_UNKNOWN.
 *
 * @param ip The IP packet to analyze
 * @return   The total length of the IP packet
 */
unsigned int ip_get_totlen(const struct ip_packet *const ip)
{
	uint16_t len;

	if(ip->version == IPV4)
	{
		len = rohc_ntoh16(ip->header.v4.tot_len);
	}
	else if(ip->version == IPV6)
	{
		len = sizeof(struct ipv6_hdr) + rohc_ntoh16(ip->header.v6.plen);
	}
	else /* IP_UNKNOWN */
	{
		len = ip->size;
	}

	return len;
}


/**
 * @brief Get the length of an IP header
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is \ref IP_UNKNOWN.
 *
 * @param ip The IP packet to analyze
 * @return   The length of the IP header if successful, 0 otherwise
 */
unsigned int ip_get_hdrlen(const struct ip_packet *const ip)
{
	unsigned int len;

	if(ip->version == IPV4)
	{
		len = ip->header.v4.ihl * 4;
	}
	else if(ip->version == IPV6)
	{
		len = sizeof(struct ipv6_hdr);
	}
	else
	{
		/* function does not handle non-IPv4/IPv6 packets */
#if defined(NDEBUG) || defined(__KERNEL__) || defined(ENABLE_DEAD_CODE)
		len = 0;
#endif
		assert(0);
	}

	return len;
}


/**
 * @brief Get the IP version of an IP packet
 *
 * The function handles \ref ip_packet whose \ref ip_packet::version is
 * \ref IP_UNKNOWN.
 *
 * @param ip The IP packet to analyze
 * @return   The version of the IP packet
 */
ip_version ip_get_version(const struct ip_packet *const ip)
{
	return ip->version;
}


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


/*
 * IPv4 specific functions:
 */


/**
 * @brief Get the IPv4 header
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV4.
 *
 * @param ip The IP packet to analyze
 * @return   The IP header
 */
const struct ipv4_hdr * ipv4_get_header(const struct ip_packet *const ip)
{
	assert(ip->version == IPV4);
	return &(ip->header.v4);
}


/**
 * @brief Get the IP-ID of an IPv4 packet
 *
 * The IP-ID value is returned as-is (ie. not automatically converted to
 * the host byte order).
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV4.
 *
 * @param ip  The IP packet to analyze
 * @return    The IP-ID
 */
uint16_t ipv4_get_id(const struct ip_packet *const ip)
{
	assert(ip->version == IPV4);
	return ipv4_get_id_nbo(ip, 1);
}


/**
 * @brief Get the IP-ID of an IPv4 packet in Network Byte Order
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV4.
 *
 * @param ip  The IP packet to analyze
 * @param nbo The NBO flag (if RND = 1, use NBO = 1)
 * @return    The IP-ID
 */
uint16_t ipv4_get_id_nbo(const struct ip_packet *const ip,
                         const unsigned int nbo)
{
	uint16_t id;

	assert(ip->version == IPV4);

	id = ip->header.v4.id;
	if(!nbo)
	{
		/* If IP-ID is not transmitted in Network Byte Order,
		 * swap the two bytes */
		id = swab16(id);
	}

	return id;
}


/**
 * @brief Set the IP-ID of an IPv4 packet
 *
 * The IP-ID value is set as-is (ie. not automatically converted to
 * the host byte order).
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV4.
 *
 * @param ip     The IP packet to modify
 * @param value  The IP-ID value
 */
void ipv4_set_id(struct ip_packet *const ip, const int value)
{
	assert(ip->version == IPV4);
	ip->header.v4.id = value & 0xffff;
}


/**
 * @brief Get the Don't Fragment (DF) bit of an IPv4 packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV4.
 *
 * @param ip The IP packet to analyze
 * @return   The DF bit
 */
int ipv4_get_df(const struct ip_packet *const ip)
{
	assert(ip->version == IPV4);
	return ip->header.v4.df;
}


/**
 * @brief Set the Don't Fragment (DF) bit of an IPv4 packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV4.
 *
 * @param ip     The IP packet to modify
 * @param value  The value of the DF bit
 */
void ipv4_set_df(struct ip_packet *const ip, const int value)
{
	assert(ip->version == IPV4);
	ip->header.v4.df = value;
}


/**
 * @brief Get the source address of an IPv4 packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV4.
 *
 * @param ip The IPv4 packet to analyze
 * @return   The source address of the given IPv4 packet
 */
uint32_t ipv4_get_saddr(const struct ip_packet *const ip)
{
	assert(ip->version == IPV4);
	return ip->header.v4.saddr;
}


/**
 * @brief Get the destination address of an IPv4 packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV4.
 *
 * @param ip The IPv4 packet to analyze
 * @return   The source address of the given IPv4 packet
 */
uint32_t ipv4_get_daddr(const struct ip_packet *const ip)
{
	assert(ip->version == IPV4);
	return ip->header.v4.daddr;
}


/*
 * IPv6 specific functions:
 */


/**
 * @brief Get the IPv6 header
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV6.
 *
 * @param ip The IP packet to analyze
 * @return   The IP header if IPv6
 */
const struct ipv6_hdr * ipv6_get_header(const struct ip_packet *const ip)
{
	assert(ip->version == IPV6);
	return &(ip->header.v6);
}


/**
 * @brief Get the flow label of an IPv6 packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV6.
 *
 * @param ip The IPv6 packet to analyze
 * @return   The flow label of the given IPv6 packet
 */
uint32_t ip_get_flow_label(const struct ip_packet *const ip)
{
	assert(ip->version == IPV6);
	return ipv6_get_flow_label(&ip->header.v6);
}


/**
 * @brief Set the flow label of an IPv6 packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV6.
 *
 * @param ip     The IPv6 packet to modify
 * @param value  The flow label value
 */
void ip_set_flow_label(struct ip_packet *const ip, const uint32_t value)
{
	assert(ip->version == IPV6);
	ipv6_set_flow_label(&ip->header.v6, value);
}


/**
 * @brief Get the source address of an IPv6 packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV6.
 *
 * @param ip The IPv6 packet to analyze
 * @return   The source address of the given IPv6 packet
 */
const struct ipv6_addr * ipv6_get_saddr(const struct ip_packet *const ip)
{
	assert(ip->version == IPV6);
	return &(ip->header.v6.saddr);
}


/**
 * @brief Get the destination address of an IPv6 packet
 *
 * The function does not handle \ref ip_packet whose \ref ip_packet::version
 * is not \ref IPV6.
 *
 * @param ip The IPv6 packet to analyze
 * @return   The source address of the given IPv6 packet
 */
const struct ipv6_addr * ipv6_get_daddr(const struct ip_packet *const ip)
{
	assert(ip->version == IPV6);
	return &(ip->header.v6.daddr);
}


/**
 * Private functions used by the IP module:
 * (please do not use directly)
 */

/**
 * @brief Find the next header and next layer transported by an IP packet
 *
 * @param ip       The IP packet to analyze
 * @param[out] nh  The first IP extension or the transport layer
 * @param[out] nl  The transport layer
 * @return         true if all extensions are well-formed,
 *                 false otherwise
 */
static bool ip_find_next_layer(const struct ip_packet *const ip,
                               struct net_hdr *const nh,
                               struct net_hdr *const nl)
{
	if(ip->version == IPV4)
	{
		size_t ip_hdr_len;

		/* find next header after IPv4 header */
		nh->proto = ip->header.v4.protocol;

		if(ip->size < sizeof(struct ipv4_hdr))
		{
			goto error;
		}
		ip_hdr_len = ip_get_hdrlen(ip);

		nh->data = ((uint8_t *) ip->data) + ip_hdr_len;
		nh->len = ip->size - ip_hdr_len;

		/* no support for IPv4 extension headers, so next layer is next header */
		nl->proto = nh->proto;
		nl->data = nh->data;
		nl->len = nh->len;
	}
	else if(ip->version == IPV6)
	{
		/* find next header after IPv6 header */
		nh->proto = ip->header.v6.nh;

		if(ip->size < sizeof(struct ipv6_hdr))
		{
			goto error;
		}
		nh->data = ((uint8_t *) ip->data) + sizeof(struct ipv6_hdr);
		nh->len = ip->size - sizeof(struct ipv6_hdr);

		/* find next layer after IPv6 extension headers */
		if(!ext_get_next_layer(nh, nl))
		{
			goto error;
		}
	}
	else /* IP_UNKNOWN */
	{
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Find the next layer transported by an IP extension
 *
 * @param nh       The first IP extension
 * @param[out] nl  The next layer
 * @return         true if all extensions are well-formed,
 *                 false otherwise
 */
static bool ext_get_next_layer(const struct net_hdr *const nh,
                               struct net_hdr *const nl)
{
	size_t ext_types_count[ROHC_IPPROTO_MAX + 1] = { 0 };
	unsigned int ext_type;
	size_t remain_len = nh->len;
	size_t ext_nr = 0;

	nl->proto = nh->proto;
	nl->data = nh->data;
	nl->len = nh->len;

	/* parse packet until all extension headers are parsed */
	while(rohc_is_ipv6_opt(nl->proto))
	{
		ext_types_count[nl->proto]++;
		ext_nr++;

		/* RFC 2460 §4 reads:
		 *   The Hop-by-Hop Options header, when present, must immediately follow
		 *   the IPv6 header. */
		if(nl->proto == ROHC_IPPROTO_HOPOPTS && ext_nr != 1)
		{
			return false;
		}

		/* parse extension header */
		if(!ext_get_next_header(nl->data, remain_len, nl))
		{
			return false;
		}
		remain_len -= nl->len;
	}
	nl->len = remain_len;

	/* RFC 2460 §4.1 reads:
	 *   Each extension header should occur at most once, except for the Destination
	 *   Options header which should occur at most twice (once before a Routing
	 *   header and once before the upper-layer header). */
	for(ext_type = 0; ext_type <= ROHC_IPPROTO_MAX; ext_type++)
	{
		if((ext_type == ROHC_IPPROTO_DSTOPTS && ext_types_count[ext_type] > 2) ||
		   (ext_type != ROHC_IPPROTO_DSTOPTS && ext_types_count[ext_type] > 1))
		{
			return false;
		}
	}

	return true;
}


/**
 * @brief Find the next header transported by an IP extension
 *
 * @param ext      The extension header
 * @param ext_len  The maximum length of the extension
 * @param[out] nh  The next header transported by the extension header
 * @return         true if the extension is well-formed,
 *                 false otherwise
 */
static bool ext_get_next_header(const uint8_t *const ext,
                                const size_t ext_len,
                                struct net_hdr *const nh)
{
	/* parse the Next Header and Length fields */
	if(ext_len < 2)
	{
		goto error;
	}
	nh->proto = ext[0];
	nh->len = (ext[1] + 1) * 8;

	if(nh->len > ext_len)
	{
		goto error;
	}
	nh->data = (uint8_t *) ext + nh->len;

	return true;

error:
	return false;
}

