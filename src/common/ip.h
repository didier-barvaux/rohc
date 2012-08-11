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
 * @file ip.h
 * @brief IP-agnostic packet
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef IP_H
#define IP_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>


/*
 * Next header codes for IPv6 extensions:
 */

/** Next header code for Hop-by-Hop options */
#define IPV6_EXT_HOP_BY_HOP 0
/** Next header code for Destination options */
#define IPV6_EXT_DESTINATION 60
/** Next header code for Routing extension */
#define IPV6_EXT_ROUTING 43
/** Next header code for Authentification Header */
#define IPV6_EXT_AUTH 51


/** The selected IP header */
typedef enum
{
	ROHC_IP_HDR_NONE   = 0,  /**< No IP header selected */
	ROHC_IP_HDR_FIRST  = 1,  /**< The first IP header is selected */
	ROHC_IP_HDR_SECOND = 2,  /**< The second IP header is selected */
	/* max 2 IP headers hanlded at the moment */
} ip_header_pos_t;


/// IP version
typedef enum
{
	/// IP version 4
	IPV4 = 4,
	/// IP version 6
	IPV6 = 6,
	/// not IP
	IP_UNKNOWN,
} ip_version;


/**
 * @brief Defines an IP-agnostic packet that can handle
 *        an IPv4 or IPv6 packet
 */
struct ip_packet
{
	/// The version of the IP packet
	ip_version version;

	/// The IP header
	union
	{
		/// The IPv4 header
		struct iphdr v4;
		/// The IPv6 header
		struct ip6_hdr v6;
	} header;

	/// The whole IP data (header + payload) if not NULL
	const unsigned char *data;

	/// The length (in bytes) of the whole IP data (header + payload)
	unsigned int size;
};

/* AH header */
struct ip6_ahhdr
{
	/// The next header
	uint8_t ip6ah_nxt;
	/// AH payload length
	uint8_t ip6ah_len;
	/// reserved field
	uint16_t ip6ah_reserved;
	/// Security Parameters Index (SPI)
	uint32_t ip6ah_secur;
	/// Sequence Number Field
	uint32_t ip6ah_sn;
	/* followed by Authentication Data */
};


/*
 * Generic IP macros:
 */

/// Get a subpart of a 16-bit IP field
#define IP_GET_16_SUBFIELD(field, bitmask, offset) \
	((ntohs(field) & (bitmask)) >> (offset))

/// Get a subpart of a 32-bit IP field
#define IP_GET_32_SUBFIELD(field, bitmask, offset) \
	((ntohl(field) & (bitmask)) >> (offset))

/// Set a subpart of a 16-bit IP field
#define IP_SET_16_SUBFIELD(field, bitmask, offset, value) \
	(field) = (((field) & htons(~(bitmask))) | htons(((value) << (offset)) & (bitmask)))

/// Set a subpart of a 32-bit IP field
#define IP_SET_32_SUBFIELD(field, bitmask, offset, value) \
	(field) = (((field) & htonl(~(bitmask))) | htonl(((value) << (offset)) & (bitmask)))


/*
 * IPv4 definitions & macros:
 */

/// The offset for the DF flag in an iphdr->frag_off variable
#define IPV4_DF_OFFSET  14

/// Get the IPv4 Don't Fragment (DF) bit from an iphdr object
#define IPV4_GET_DF(ip4) \
	IP_GET_16_SUBFIELD((ip4).frag_off, IP_DF, IPV4_DF_OFFSET)

/// Set the IPv4 Don't Fragment (DF) bit in an iphdr object
#define IPV4_SET_DF(ip4, value) \
	IP_SET_16_SUBFIELD((ip4)->frag_off, IP_DF, IPV4_DF_OFFSET, (value))

/// The format to print an IPv4 address
#define IPV4_ADDR_FORMAT \
	"%02x%02x%02x%02x (%u.%u.%u.%u)"

/// The data to print an IPv4 address in raw format
#define IPV4_ADDR_RAW(x) \
	(x)[0], (x)[1], (x)[2], (x)[3], \
	(x)[0], (x)[1], (x)[2], (x)[3]


/*
 * IPv6 definitions & macros:
 */

/// The bitmask for the Version field in an ip6_hdr->ip6_flow variable
#define IPV6_VERSION_MASK  0xf0000000
/// The offset for the Version field in an ip6_hdr->ip6_flow variable
#define IPV6_VERSION_OFFSET  28

/// The bitmask for the Traffic Class (TC) field in an ip6_hdr->ip6_flow variable
#define IPV6_TC_MASK  0x0ff00000
/// The offset for the Traffic Class (TC) field in an ip6_hdr->ip6_flow variable
#define IPV6_TC_OFFSET  20

/// The bitmask for the FLow Label field in an ip6_hdr->ip6_flow variable
#define IPV6_FLOW_LABEL_MASK  0x000fffff

/// Get the IPv6 Version 4-bit field from ip6_hdr object
#define IPV6_GET_VERSION(ip6) \
	IP_GET_32_SUBFIELD((ip6).ip6_flow, IPV6_VERSION_MASK, IPV6_VERSION_OFFSET)

/// Set the IPv6 Version 4-bit field in an ip6_hdr object
#define IPV6_SET_VERSION(ip6, value) \
	IP_SET_32_SUBFIELD((ip6)->ip6_flow, IPV6_VERSION_MASK, IPV6_VERSION_OFFSET, (value))

/// Get the IPv6 Traffic Class (TC) byte from an ip6_hdr object
#define IPV6_GET_TC(ip6) \
	IP_GET_32_SUBFIELD((ip6).ip6_flow, IPV6_TC_MASK, IPV6_TC_OFFSET)

/// Set the IPv6 Traffic Class (TC) byte in an ip6_hdr object
#define IPV6_SET_TC(ip6, value) \
	IP_SET_32_SUBFIELD((ip6)->ip6_flow, IPV6_TC_MASK, IPV6_TC_OFFSET, (value))

/// Get the IPv6 Flow Label 20-bit field from an ip6_hdr object
#define IPV6_GET_FLOW_LABEL(ip6) \
	IP_GET_32_SUBFIELD((ip6).ip6_flow, IPV6_FLOW_LABEL_MASK, 0)

/// Set the IPv6 Flow Label 20-bit field in an ip6_hdr variable
#define IPV6_SET_FLOW_LABEL(ip6, value) \
	IP_SET_32_SUBFIELD((ip6)->ip6_flow, IPV6_FLOW_LABEL_MASK, 0, (value))

/// The format to print an IPv6 address
#define IPV6_ADDR_FORMAT \
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"

/// The data to print an IPv6 address in (struct in6_addr *) format
#define IPV6_ADDR_IN6(x) \
	IPV6_ADDR_RAW((x)->s6_addr)

/// The data to print an IPv6 address in raw format
#define IPV6_ADDR_RAW(x) \
	(x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5], (x)[6], (x)[7], \
	(x)[8], (x)[9], (x)[10], (x)[11], (x)[12], (x)[13], (x)[14], (x)[15]

/// Compare two IPv6 addresses in (struct in6_addr *) format
#define IPV6_ADDR_CMP(x, y) \
	((x)->s6_addr32[0] == (y)->s6_addr32[0] && \
	 (x)->s6_addr32[1] == (y)->s6_addr32[1] && \
	 (x)->s6_addr32[2] == (y)->s6_addr32[2] && \
	 (x)->s6_addr32[3] == (y)->s6_addr32[3])


/*
 * Inline functions
 */

/**
 * @brief In-place change the byte order in a two-byte value.
 *
 * @param value The two-byte value to modify
 * @return      The same value with the byte order changed
 */
static inline uint16_t swab16(uint16_t value)
{
	return ((value & 0x00ff) << 8) | ((value & 0xff00) >> 8);
}


#ifdef __i386__

/**
 * @brief This is a version of ip_compute_csum() optimized for IP headers,
 *        which always checksum on 4 octet boundaries.
 *
 * @author Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
 *         Arnt Gulbrandsen.
 *
 * @param iph The IPv4 header
 * @param ihl The length of the IPv4 header
 * @return    The IPv4 checksum
 */
static inline uint16_t ip_fast_csum(unsigned char *iph, size_t ihl)
{
	uint32_t sum;

	__asm__ __volatile__(
	   " \n\
       movl (%1), %0      \n\
       subl $4, %2		\n\
       jbe 2f		\n\
       addl 4(%1), %0	\n\
       adcl 8(%1), %0	\n\
       adcl 12(%1), %0	\n\
1:     adcl 16(%1), %0	\n\
       lea 4(%1), %1	\n\
       decl %2		\n\
       jne 1b		\n\
       adcl $0, %0		\n\
       movl %0, %2		\n\
       shrl $16, %0	\n\
       addw %w2, %w0	\n\
       adcl $0, %0		\n\
       notl %0		\n\
2:     \n\
       "
	   /* Since the input registers which are loaded with iph and ipl
	      are modified, we must also specify them as outputs, or gcc
	      will assume they contain their original values. */
		: "=r" (sum), "=r" (iph), "=r" (ihl)
		: "1" (iph), "2" (ihl)
		: "memory");

	return (uint16_t) (sum & 0xffff);
}


#else

static inline uint16_t from32to16(uint32_t x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

/**
 *  This is a version of ip_compute_csum() optimized for IP headers,
 *  which always checksum on 4 octet boundaries.
 */
static inline uint16_t ip_fast_csum(unsigned char *iph, size_t ihl)
{
	const unsigned char *buff = iph;
	size_t len = ihl * 4;
	bool odd;
	size_t count;
	uint32_t result = 0;

	if(len <= 0)
	{
		goto out;
	}
	odd = 1 & (unsigned long) buff;
	if(odd)
	{
#ifdef __LITTLE_ENDIAN
		result = *buff;
#else
		result += (*buff << 8);
#endif
		len--;
		buff++;
	}
	count = len >> 1; /* nr of 16-bit words.. */
	if(count)
	{
		if(2 & (unsigned long) buff)
		{
			result += *(uint16_t *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1; /* nr of 32-bit words.. */
		if(count)
		{
			uint32_t carry = 0;
			do
			{
				uint32_t word = *(uint32_t *) buff;
				count--;
				buff += sizeof(uint32_t);
				result += carry;
				result += word;
				carry = (word > result);
			}
			while(count);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if(len & 2)
		{
			result += *(uint16_t *) buff;
			buff += 2;
		}
	}
	if(len & 1)
	{
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	}
	result = from32to16(result);
	if(odd)
	{
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
out:
	return ~result;
}


#endif


/*
 * Function prototypes.
 */

/* Generic functions */

int ip_create(struct ip_packet *const ip,
              const unsigned char *packet,
              const unsigned int size);
int ip_get_inner_packet(const struct ip_packet *const outer,
                        struct ip_packet *const inner);

const unsigned char * ip_get_raw_data(const struct ip_packet *const ip);
unsigned char * ip_get_next_header(const struct ip_packet *const ip,
                                   uint8_t *const type);
unsigned char * ip_get_next_layer(const struct ip_packet *const ip);
unsigned char * ip_get_next_ext_from_ip(const struct ip_packet *const ip,
                                        uint8_t *const type);
unsigned char * ip_get_next_ext_from_ext(const unsigned char *const ext,
                                         uint8_t *const type);

unsigned int ip_get_totlen(const struct ip_packet *const ip);
unsigned int ip_get_hdrlen(const struct ip_packet *const ip);
unsigned int ip_get_plen(const struct ip_packet *const ip);

int ip_is_fragment(const struct ip_packet *const ip);
ip_version ip_get_version(const struct ip_packet *const ip);
unsigned int ip_get_protocol(const struct ip_packet *const ip);
unsigned int ext_get_protocol(const unsigned char *const ext);
unsigned int ip_get_tos(const struct ip_packet *const ip);
unsigned int ip_get_ttl(const struct ip_packet *const ip);

void ip_set_version(struct ip_packet *const ip, const ip_version value);
void ip_set_protocol(struct ip_packet *const ip, const uint8_t value);
void ip_set_tos(struct ip_packet *const ip, const uint8_t value);
void ip_set_ttl(struct ip_packet *const ip, const uint8_t value);
void ip_set_saddr(struct ip_packet *const ip, const unsigned char *value);
void ip_set_daddr(struct ip_packet *const ip, const unsigned char *value);

/* IPv4 specific functions */

const struct iphdr * ipv4_get_header(const struct ip_packet *const ip);
int ipv4_get_id(const struct ip_packet *const ip);
int ipv4_get_id_nbo(const struct ip_packet *const ip, const unsigned int nbo);
int ipv4_get_df(const struct ip_packet *const ip);
uint32_t ipv4_get_saddr(const struct ip_packet *const ip);
uint32_t ipv4_get_daddr(const struct ip_packet *const ip);

void ipv4_set_id(struct ip_packet *const ip, const int value);
void ipv4_set_df(struct ip_packet *const ip, const int value);

/* IPv6 specific functions */

const struct ip6_hdr * ipv6_get_header(const struct ip_packet *const ip);
uint32_t ipv6_get_flow_label(const struct ip_packet *const ip);
const struct in6_addr * ipv6_get_saddr(const struct ip_packet *const ip);
const struct in6_addr * ipv6_get_daddr(const struct ip_packet *const ip);
void ipv6_set_flow_label(struct ip_packet *const ip, const uint32_t value);
unsigned short ip_get_extension_size(const unsigned char *const ext);
unsigned short ip_get_total_extension_size(const struct ip_packet *const ip);

/* Private functions (do not use directly) */
int get_ip_version(const unsigned char *const packet,
                   const unsigned int size,
                   ip_version *const version);


#endif

