/**
 * @file ip.h
 * @brief IP-agnostic packet
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 */

#ifndef IP_H
#define IP_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>


/// IP version
typedef enum
{
	/// IP version 4
	IPV4 = 4,
	/// IP version 6
	IPV6 = 6,
} ip_version;


/**
 * @brief Defines an IP-agnostic packet that can handle
 *        an IPv4 or IPv6 packet
 */
struct ip_packet
{
	/// The version of the IP packet
	ip_version  version;

	/// The IP header
	union
	{
		/// The IPv4 header
		struct iphdr v4;
		/// The IPv6 header
		struct ip6_hdr v6;
	} header;

	/// The whole IP data (header + payload) if not NULL
	unsigned char *data;
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
#define IPV6_ADDR(x) \
	(x)->s6_addr[0], (x)->s6_addr[1], (x)->s6_addr[2], (x)->s6_addr[3], \
	(x)->s6_addr[4], (x)->s6_addr[5], (x)->s6_addr[6], (x)->s6_addr[7], \
	(x)->s6_addr[8], (x)->s6_addr[9], (x)->s6_addr[10], (x)->s6_addr[11], \
	(x)->s6_addr[12], (x)->s6_addr[13], (x)->s6_addr[14], (x)->s6_addr[15]

/// Compare two IPv6 addresses in (struct in6_addr *) format
#define IPV6_ADDR_CMP(x, y) \
	((x)->s6_addr32[0] == (y)->s6_addr32[0] && \
	 (x)->s6_addr32[1] == (y)->s6_addr32[1] && \
	 (x)->s6_addr32[2] == (y)->s6_addr32[2] && \
	 (x)->s6_addr32[3] == (y)->s6_addr32[3])


/*
 * Function prototypes.
 */

/* Generic functions */

int ip_create(struct ip_packet *ip, unsigned char *packet, unsigned int size);
int ip_get_inner_packet(struct ip_packet outer, struct ip_packet *inner);

void ip_new(struct ip_packet *ip, ip_version version);

unsigned char * ip_get_raw_data(struct ip_packet ip);
unsigned char * ip_get_next_header(struct ip_packet ip);

unsigned int ip_get_totlen(struct ip_packet ip);
unsigned int ip_get_hdrlen(struct ip_packet ip);
unsigned int ip_get_plen(struct ip_packet ip);

int ip_is_fragment(struct ip_packet ip);
ip_version ip_get_version(struct ip_packet ip);
unsigned int ip_get_protocol(struct ip_packet ip);
unsigned int ip_get_tos(struct ip_packet ip);
unsigned int ip_get_ttl(struct ip_packet ip);

void ip_set_protocol(struct ip_packet *ip, uint8_t value);
void ip_set_tos(struct ip_packet *ip, uint8_t value);
void ip_set_ttl(struct ip_packet *ip, uint8_t value);
void ip_set_saddr(struct ip_packet *ip, const unsigned char *value);
void ip_set_daddr(struct ip_packet *ip, const unsigned char *value);

/* IPv4 specific functions */

struct iphdr * ipv4_get_header(struct ip_packet ip);
int ipv4_get_id(struct ip_packet ip);
int ipv4_get_df(struct ip_packet ip);
uint32_t ipv4_get_saddr(struct ip_packet ip);
uint32_t ipv4_get_daddr(struct ip_packet ip);

void ipv4_set_id(struct ip_packet *ip, int value);
void ipv4_set_df(struct ip_packet *ip, int value);

/* IPv6 specific functions */

struct ip6_hdr * ipv6_get_header(struct ip_packet ip);
uint32_t ipv6_get_flow_label(struct ip_packet ip);
struct in6_addr * ipv6_get_saddr(struct ip_packet *ip);
struct in6_addr * ipv6_get_daddr(struct ip_packet *ip);

void ipv6_set_flow_label(struct ip_packet *ip, uint32_t value);

/* Private functions (do not use directly) */
int get_ip_version(unsigned char *packet, unsigned int size, ip_version *version);


#endif

