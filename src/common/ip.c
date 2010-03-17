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
 * @file ip.c
 * @brief IP-agnostic packet
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "ip.h"
#include "rohc_traces.h"


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
int ip_create(struct ip_packet *ip, unsigned char *packet, unsigned int size)
{
	ip_version version;
	int ret = 0;

	/* get the version of the IP packet */
	if(!get_ip_version(packet, size, &version))
	{
		rohc_debugf(1, "bad IP version (%d)\n", version);
		goto quit;
	}

	ip->version = version;

	/* check packet's validity according to IP version */
	if(version == IPV4)
	{
		/* IPv4: packet must be at least 20-byte long (= header length)
		 *       header must not contain options (= 20 bytes)
		 *       packet length must be accurate with the Total Length field */

		if(size < sizeof(struct iphdr))
		{
			rohc_debugf(1, "IP packet too short (%d bytes)\n", size);
			goto quit;
		}

		/* copy the IPv4 header */
		memcpy(&ip->header.v4, packet, sizeof(struct iphdr));

		if(ip_get_hdrlen(*ip) != sizeof(struct iphdr))
		{
			rohc_debugf(1, "bad IP header size (%d bytes)\n",
			            ip_get_hdrlen(*ip));
			goto quit;
		}

		if(ip_get_totlen(*ip) != size)
		{
			rohc_debugf(1, "bad IP packet length (%d bytes != %d bytes)\n",
			            ip_get_totlen(*ip), size);
			goto quit;
		}

		/* point to the whole IPv4 packet */
		ip->data = packet;
	}
	else /* IPV6 */
	{
		/* IPv6: packet must be at least 40-byte long (= header length)
		 *       packet length == header length + Payload Length field */

		if(size < sizeof(struct ip6_hdr))
		{
			rohc_debugf(1, "IP packet too short (%d bytes)\n", size);
			goto quit;
		}

		/* copy the IPv6 header */
		memcpy(&ip->header.v6, packet, sizeof(struct ip6_hdr));

		if(ip_get_totlen(*ip) != size)
		{
			rohc_debugf(1, "bad IP packet length (%d bytes != %d bytes)\n",
			            ip_get_totlen(*ip), size);
			goto quit;
		}

		/* point to the whole IPv6 packet */
		ip->data = packet;
	}

	ret = 1;

quit:
	return ret;
}


/**
 * @brief Create an empty IP packet
 *
 * @param ip      OUT: The IP packet to create
 * @param version The version of the IP packet
 * @return        Whether the IP packet was successfully created or not
 */
void ip_new(struct ip_packet *ip, ip_version version)
{
	/* initialize the IP info to zero */
	bzero(ip, sizeof(*ip));

	/* set the IP version of the packet */
	ip->version = version;

	/* set the IP version and the STATIC-KNOWN fields */
	if(version == IPV4)
	{
		ip->header.v4.version = version;

		/* STATIC-KNOWN fields */
		ip->header.v4.ihl = 5;
		/* the Reserved flag, the Don't Fragment flag and the Fragment Offset
		 * field are already set to 0 by the bzero() call */
	}
	else /* IPV6 */
	{
		IPV6_SET_VERSION(&ip->header.v6, version);

		/* no STATIC-KNOWN field */
	}
}


/**
 * @brief Get the IP raw data (header + payload)
 *
 * @param ip The IP packet to analyze
 * @return   The IP raw data (header + payload)
 */
unsigned char * ip_get_raw_data(struct ip_packet ip)
{
	return ip.data;
}


/**
 * @brief Get the inner IP packet (IP in IP)
 *
 * @param outer The outer IP packet to analyze
 * @param inner The inner IP packet to create
 * @return      Whether the inner IP header is successfully created or not
 */
int ip_get_inner_packet(struct ip_packet outer, struct ip_packet *inner)
{
	unsigned char *next_header;

	/* get the next header data in the IP packet (skip IP extensions) */
	next_header = ip_get_next_layer(&outer);

	/* create an IP packet with the next header data */
	rohc_debugf(3, "size of outer :%d \n", ip_get_plen(outer));
	return ip_create(inner, next_header, ip_get_plen(outer));
}


/**
 * @brief Get the IP next header
 *        
 * @param ip   The IP packet to analyze
 * @param type OUT: The type of the next header
 * @return     The next header
 */
unsigned char *ip_get_next_header(const struct ip_packet *ip,
                                  uint8_t *type)
{
	unsigned char *next_header;

	/* find the start of the next header data */
	if(ip->version == IPV4)
	{
		*type = ip->header.v4.protocol;
		next_header = ip->data + sizeof(struct iphdr);
	}
	else /* IPV6 */
	{
		*type = ip->header.v6.ip6_nxt; 
		next_header = ip->data + sizeof(struct ip6_hdr);
	}

	return next_header;
}


/**
 * @brief Get the next header (but skip IP extensions)
 *        
 * @param ip   The IP packet to analyze
 * @return     The next header that is not an IP extension
 */
unsigned char *ip_get_next_layer(const struct ip_packet *ip)
{
	unsigned char *next_header;
	uint8_t next_header_type;
	uint8_t length;

	/* get the next header data in the IP packet */
	next_header = ip_get_next_header(ip, &next_header_type);

	/* skip IPv6 extensions */
	if(ip->version == IPV6)
	{
		/* TODO: stop when IP total length is reached */
		while(next_header_type == IPV6_EXT_HOP_BY_HOP ||
		      next_header_type == IPV6_EXT_DESTINATION ||
		      next_header_type == IPV6_EXT_ROUTING ||
		      next_header_type == IPV6_EXT_AUTH)
		{
			/* next header is an IPv4 extension header, skip it and
			   get the next header */
			next_header_type = next_header[0];
			length = next_header[1];
			next_header = next_header + (length + 1) * 8 ;
		}
	}

	return next_header;
}


/**
 * @brief Get the next extension header of IPv6 packets from
 *        an IPv6 header
 *
 * @param ip   The IP packet to analyze
 * @param type OUT: The type of the next header
 *             If there is no next header the value must be ignored
 * @return     The next extension header,
 *             NULL if there is no extension
 */
unsigned char *ip_get_next_ext_header_from_ip(const struct ip_packet *ip,
                                              uint8_t *type)
{
	unsigned char *next_header;

	if(ip->version != IPV6)
	{
		return NULL;
	}

	/* get the next header data in the IP packet */
	next_header = ip_get_next_header(ip, type);
	switch(*type)
	{
		case IPV6_EXT_HOP_BY_HOP:
		case IPV6_EXT_DESTINATION:
		case IPV6_EXT_ROUTING:
		case IPV6_EXT_AUTH:
			/* known extension headers */
			break;
		default:
			goto end;
	}

	return next_header;

end:
	return NULL;
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
unsigned char *ip_get_next_ext_header_from_ext(const unsigned char *ext,
                                               uint8_t *type)
{
	unsigned char *next_header;
	uint8_t length;

	*type = ext[0];
	
	switch(*type)
	{
		case IPV6_EXT_HOP_BY_HOP:
		case IPV6_EXT_DESTINATION:
		case IPV6_EXT_ROUTING:
		case IPV6_EXT_AUTH:
			/* known extension headers */
			length = ext[1];
			next_header = (unsigned char *)(ext + (length + 1) * 8);
			break;
		default:
			goto end;
	}

	return next_header;

end:
	return NULL;
}


/**
 * @brief Get the size of an IPv6 extension
 *
 * @param ext The extension
 * @return    The size of the extension
 */
uint8_t ip_get_extension_size(unsigned char *ext)
{
	uint8_t ext_length;
	
	ext_length = ext[1];

	return (ext_length + 1) * 8;
}


/**
 * @brief Get the size of the extension list
 *
 * @param ip The packet to analyse
 * @return   The size of extension list
 */
uint8_t ip_get_total_extension_size(struct ip_packet ip)
{
	unsigned char *ext;
	uint8_t next_hdr_type;
	uint8_t total_ext_size = 0;
	
	ext = ip_get_next_ext_header_from_ip(&ip, &next_hdr_type);
	while(ext != NULL)
	{
		total_ext_size += ip_get_extension_size(ext);
		ext = ip_get_next_ext_header_from_ext(ext, &next_hdr_type);
	}

	return total_ext_size;
}


/**
 * @brief Whether the IP packet is an IP fragment or not
 *
 * The IP packet is a fragment if the  MF (More Fragments) bit is set
 * or the Fragment Offset field is non-zero.
 *
 * @param ip The IP packet to analyze
 * @return   Whether the IP packet is an IP fragment or not
 */
int ip_is_fragment(struct ip_packet ip)
{
	int is_fragment;

	if(ip.version == IPV4)
		is_fragment = ((ntohs(ip.header.v4.frag_off) & (~IP_DF)) != 0);
	else /* IPV6 */
		is_fragment = 0;

	return is_fragment;
}


/**
 * @brief Get the total length of an IP packet
 *
 * @param ip The IP packet to analyze
 * @return   The total length of the IP packet
 */
unsigned int ip_get_totlen(struct ip_packet ip)
{
	uint16_t len;

	if(ip.version == IPV4)
		len = ntohs(ip.header.v4.tot_len);
	else
		len = sizeof(struct ip6_hdr) + ntohs(ip.header.v6.ip6_plen);

	return len;
}


/**
 * @brief Get the length of an IP header
 *
 * @param ip The IP packet to analyze
 * @return   The length of the IP header
 */
unsigned int ip_get_hdrlen(struct ip_packet ip)
{
	unsigned int len;

	if(ip.version == IPV4)
		len = ip.header.v4.ihl * 4;
	else
		len = sizeof(struct ip6_hdr);

	return len;
}


/**
 * @brief Get the length of an IP payload
 *
 * @param ip The IP packet to analyze
 * @return   The length of the IP payload
 */
unsigned int ip_get_plen(struct ip_packet ip)
{
	uint16_t len;
	int size_list = 0;
	uint8_t next_header_type;

	if(ip.version == IPV4)
		len = ntohs(ip.header.v4.tot_len) - ip.header.v4.ihl * 4;
	else
	{
		next_header_type = ip.header.v6.ip6_nxt;
		switch (next_header_type)
		{
			case IPV6_EXT_HOP_BY_HOP:
			case IPV6_EXT_DESTINATION:
			case IPV6_EXT_ROUTING:
			case IPV6_EXT_AUTH:
				/* known extension headers */
				size_list = ip_get_total_extension_size(ip);
				break;
			default:
				break;
		}
		len = ntohs(ip.header.v6.ip6_plen) - size_list;
	}

	return len;
}


/**
 * @brief Get the IP version of an IP packet
 *
 * @param ip The IP packet to analyze
 * @return   The version of the IP packet
 */
ip_version ip_get_version(struct ip_packet ip)
{
	return ip.version;
}


/**
 * @brief Get the protocol transported by an IP packet
 *
 * The protocol returned is the one transported by the last known IP extension
 * header if any is found.
 *
 * @param ip The IP packet to analyze
 * @return   The protocol number that identify the protocol transported
 *           by the given IP packet
 */
unsigned int ip_get_protocol(struct ip_packet ip)
{
	uint8_t protocol;
	unsigned char * next_header;
	uint8_t next_header_type;

	if(ip.version == IPV4)
		protocol = ip.header.v4.protocol;
	else /* IPV6 */
	{
		next_header_type = ip.header.v6.ip6_nxt;
		switch (next_header_type)
		{
			case IPV6_EXT_HOP_BY_HOP:
			case IPV6_EXT_DESTINATION:
			case IPV6_EXT_ROUTING:
			case IPV6_EXT_AUTH:
				/* known extension headers */
				next_header = ip.data + sizeof(struct ip6_hdr);
				protocol = ext_get_protocol(next_header);
				break;
			default:
				protocol = next_header_type;
				break;
		}
	}

	return protocol;
}


/**
 * @brief Get the protocol transported by the last IPv6 extension
 *
 * @param ext The first extension
 * @return    The protocol number that identify the protocol transported
 *            by the given IP extension
 */
unsigned int ext_get_protocol(unsigned char * ext)
{
	uint8_t type;
	uint8_t length;
	uint8_t protocol;
	unsigned char * next_header;

	type = ext[0];
	length = ext[1];
	switch(type)
	{
		case IPV6_EXT_HOP_BY_HOP:
		case IPV6_EXT_DESTINATION:
		case IPV6_EXT_ROUTING:
		case IPV6_EXT_AUTH:
			/* known extension headers */
			next_header = ext + (length + 1) * 8 ;
			protocol = ext_get_protocol(next_header);
			break;
		default:
			protocol = type;
			break;
	}

	return protocol;
}


/**
 * @brief Set the protocol transported by an IP packet
 *
 * @param ip     The IP packet to modify
 * @param value  The protocol value
 */
void ip_set_protocol(struct ip_packet *ip, uint8_t value)
{
	if(ip->version == IPV4)
		ip->header.v4.protocol = value & 0xff;
	else /* IPV6 */
		ip->header.v6.ip6_nxt = value & 0xff;
}


/**
 * @brief Get the IPv4 Type Of Service (TOS) or IPv6 Traffic Class (TC)
 *        of an IP packet
 *
 * @param ip The IP packet to analyze
 * @return   The TOS or TC value
 */
unsigned int ip_get_tos(struct ip_packet ip)
{
	unsigned int tos;

	if(ip.version == IPV4)
		tos = ip.header.v4.tos;
	else /* IPV6 */
		tos = IPV6_GET_TC(ip.header.v6);

	return tos;
}


/**
 * @brief Set the IPv4 Type Of Service (TOS) or IPv6 Traffic Class (TC)
 *        of an IP packet
 *
 * @param ip     The IP packet to modify
 * @param value  The TOS/TC value
 */
void ip_set_tos(struct ip_packet *ip, uint8_t value)
{
	if(ip->version == IPV4)
		ip->header.v4.tos = value & 0xff;
	else /* IPV6 */
		IPV6_SET_TC(&ip->header.v6, value);
}


/**
 * @brief Get the IPv4 Time To Live (TTL) or IPv6 Hop Limit (HL)
 *        of an IP packet
 *
 * @param ip The IP packet to analyze
 * @return   The TTL or HL value
 */
unsigned int ip_get_ttl(struct ip_packet ip)
{
	unsigned int ttl;

	if(ip.version == IPV4)
		ttl = ip.header.v4.ttl;
	else /* IPV6 */
		ttl = ip.header.v6.ip6_hlim;

	return ttl;
}


/**
 * @brief Set the IPv4 Time To Live (TTL) or IPv6 Hop Limit (HL)
 *        of an IP packet
 *
 * @param ip     The IP packet to modify
 * @param value  The TTL/HL value
 */
void ip_set_ttl(struct ip_packet *ip, uint8_t value)
{
	if(ip->version == IPV4)
		ip->header.v4.ttl = value & 0xff;
	else /* IPV6 */
		ip->header.v6.ip6_hlim = value & 0xff;
}


/**
 * @brief Set the Source Address of an IP packet
 *
 * @param ip     The IP packet to modify
 * @param value  The IP address value
 */
void ip_set_saddr(struct ip_packet *ip, const unsigned char *value)
{
	if(ip->version == IPV4)
		memcpy(&ip->header.v4.saddr, value, sizeof(struct in_addr));
	else /* IPV6 */
		memcpy(&ip->header.v6.ip6_src, value, sizeof(struct in6_addr));
}


/**
 * @brief Set the Destination Address of an IP packet
 *
 * @param ip     The IP packet to modify
 * @param value  The IP address value
 */
void ip_set_daddr(struct ip_packet *ip, const unsigned char *value)
{
	if(ip->version == IPV4)
		memcpy(&ip->header.v4.daddr, value, sizeof(struct in_addr));
	else /* IPV6 */
		memcpy(&ip->header.v6.ip6_dst, value, sizeof(struct in6_addr));
}


/*
 * IPv4 specific functions:
 */


/**
 * @brief Get the IPv4 header
 *
 * @param ip The IP packet to analyze
 * @return   The IP header if IPv4, NULL otherwise
 */
struct iphdr * ipv4_get_header(struct ip_packet ip)
{
	struct iphdr *header;

	if(ip.version == IPV4)
		header = &ip.header.v4;
	else
		header = NULL;

	return header;
}


/**
 * @brief Get the IP-ID of an IPv4 packet
 *
 * The IP-ID value is returned as-is (ie. not automatically converted to
 * the host byte order).
 *
 * @param ip The IP packet to analyze
 * @return   The IP-ID if the given packet is IPv4, -1 otherwise
 */
int ipv4_get_id(struct ip_packet ip)
{
	uint16_t id;

	if(ip.version == IPV4)
		id = ip.header.v4.id;
	else /* IPV6 */
		id = -1;

	return id;
}


/**
 * @brief Set the IP-ID of an IPv4 packet
 *
 * The IP-ID value is set as-is (ie. not automatically converted to
 * the host byte order).
 *
 * @param ip     The IP packet to modify
 * @param value  The IP-ID value
 */
void ipv4_set_id(struct ip_packet *ip, int value)
{
	if(ip->version == IPV4)
		ip->header.v4.id = value & 0xffff;
}


/**
 * @brief Get the Don't Fragment (DF) bit of an IPv4 packet
 *
 * @param ip The IP packet to analyze
 * @return   The DF bit of the IPv4 header if the given packet is IPv4,
 *           -1 otherwise
 */
int ipv4_get_df(struct ip_packet ip)
{
	int df;

	if(ip.version == IPV4)
		df = IPV4_GET_DF(ip.header.v4);
	else /* IPV6 */
		df = -1;

	return df;
}


/**
 * @brief Set the Don't Fragment (DF) bit of an IPv4 packet
 *
 * @param ip     The IP packet to modify
 * @param value  The value of the DF bit
 */
void ipv4_set_df(struct ip_packet *ip, int value)
{
	if(ip->version == IPV4)
		IPV4_SET_DF(&ip->header.v4, value);
}


/**
 * @brief Get the source address of an IPv4 packet
 *
 * @param ip The IPv4 packet to analyze
 * @return   The source address of the given IPv4 packet
 */
uint32_t ipv4_get_saddr(struct ip_packet ip)
{
	if(ip.version == IPV4)
		return ip.header.v4.saddr;

	return 0;
}


/**
 * @brief Get the destination address of an IPv4 packet
 *
 * @param ip The IPv4 packet to analyze
 * @return   The source address of the given IPv4 packet
 */
uint32_t ipv4_get_daddr(struct ip_packet ip)
{
	if(ip.version == IPV4)
		return ip.header.v4.daddr;

	return 0;
}


/*
 * IPv6 specific functions:
 */


/**
 * @brief Get the IPv6 header
 *
 * @param ip The IP packet to analyze
 * @return   The IP header if IPv6, NULL otherwise
 */
struct ip6_hdr * ipv6_get_header(struct ip_packet ip)
{
	struct ip6_hdr *header;

	if(ip.version == IPV6)
		header = &ip.header.v6;
	else
		header = NULL;

	return header;
}


/**
 * @brief Get the flow label of an IPv6 packet
 *
 * @param ip The IPv6 packet to analyze
 * @return   The flow label of the given IPv6 packet
 */
uint32_t ipv6_get_flow_label(struct ip_packet ip)
{
	if(ip.version == IPV6)
		return IPV6_GET_FLOW_LABEL(ip.header.v6);

	return 0;
}


/**
 * @brief Set the flow label of an IPv6 packet
 *
 * @param ip     The IPv6 packet to modify
 * @param value  The flow label value
 */
void ipv6_set_flow_label(struct ip_packet *ip, uint32_t value)
{
	if(ip->version == IPV6)
		IPV6_SET_FLOW_LABEL(&ip->header.v6, value);
}


/**
 * @brief Get the source address of an IPv6 packet
 *
 * @param ip The IPv6 packet to analyze
 * @return   The source address of the given IPv6 packet
 */
struct in6_addr * ipv6_get_saddr(struct ip_packet *ip)
{
	if(ip->version == IPV6)
		return &ip->header.v6.ip6_src;

	return NULL;
}


/**
 * @brief Get the destination address of an IPv6 packet
 *
 * @param ip The IPv6 packet to analyze
 * @return   The source address of the given IPv6 packet
 */
struct in6_addr * ipv6_get_daddr(struct ip_packet *ip)
{
	if(ip->version == IPV6)
		return &ip->header.v6.ip6_dst;

	return NULL;
}

/**
 * Private functions used by the IP module:
 * (please do not use directly)
 */


/*
 * @brief Get the version of an IP packet
 *
 * If the function returns an error (bad IP packet), the value of 'version'
 * is unchanged.
 *
 * @param packet  The IP data
 * @param size    The length of the IP data
 * @param version OUT: the version of the IP packet: IPV4 or IPV6
 * @return        Whether the given packet is an IPv4 or IPv6 packet or not
 */
int get_ip_version(const unsigned char *packet,
                   unsigned int size,
                   ip_version *version)
{
	int ret = 1;

	/* check the length of the packet */
	if(size <= 0)
	{
		ret = 0;
		*version = IPV4;
		goto quit;
	}

	/* check the version field */
	switch((packet[0] & 0xf0) >> 4)
	{
		case 4:
			*version = IPV4;
			break;
		case 6:
			*version = IPV6;
			break;
		default:
			ret = 0;
			*version = IPV4;
			break;
	}
	return ret;

quit:
	return ret;
}

