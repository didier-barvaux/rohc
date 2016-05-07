/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2009,2010,2013,2014 Viveris Technologies
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
 * @file   common/ip.h
 * @brief  IP-agnostic packet
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMMON_IP_H
#define ROHC_COMMON_IP_H

#include "protocols/ipv4.h"
#include "protocols/ipv6.h"

#include <stdlib.h>
#include <stdint.h>
#ifdef __KERNEL__
#  include <linux/types.h>
#else
#  include <stdbool.h>
#endif


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
	IP_UNKNOWN = 0,
	/// IP version 4 (malformed)
	IPV4_MALFORMED = 1,
	/// IP version 6 (malformed)
	IPV6_MALFORMED = 2,
} ip_version;


/** A network header */
struct net_hdr
{
	uint8_t proto;  /**< The header protocol */
	uint8_t *data;  /**< The header data */
	size_t len;     /**< The header length (in bytes) */
};


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
		struct ipv4_hdr v4;
		/// The IPv6 header
		struct ipv6_hdr v6;
	} header;

	/// The whole IP data (header + payload) if not NULL
	const uint8_t *data;

	/// The length (in bytes) of the whole IP data (header + payload)
	size_t size;

	struct net_hdr nh;  /**< The next header (extension headers included) */
	struct net_hdr nl;  /**< The next layer (extension headers excluded) */
};


/*
 * Inline functions
 */

#ifndef __KERNEL__ /* already provided by Linux kernel */

static inline uint16_t swab16(const uint16_t value)
	__attribute__((warn_unused_result, const));

/**
 * @brief In-place change the byte order in a two-byte value.
 *
 * @param value The two-byte value to modify
 * @return      The same value with the byte order changed
 */
static inline uint16_t swab16(const uint16_t value)
{
	return ((value & 0x00ff) << 8) | ((value & 0xff00) >> 8);
}


#if defined(__i386__) || defined(__x86_64__)

static inline uint16_t ip_fast_csum(const uint8_t *iph,
                                    const size_t ihl)
	__attribute__((nonnull(1), warn_unused_result, pure));

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
static inline uint16_t ip_fast_csum(const uint8_t *iph,
                                    const size_t ihl)
{
	uint32_t __ihl = ihl;
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
	   /* Since the input registers which are loaded with iph and ihl
	      are modified, we must also specify them as outputs, or gcc
	      will assume they contain their original values. */
		: "=r" (sum), "=r" (iph), "=r" (__ihl)
		: "1" (iph), "2" (__ihl)
		: "memory");

	return (uint16_t) (sum & 0xffff);
}


#else

static inline uint16_t from32to16(const uint32_t x)
	__attribute__((warn_unused_result, const));

static inline uint16_t from32to16(const uint32_t x)
{
	uint32_t y;
	/* add up 16-bit and 16-bit for 16+c bit */
	y = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	y = (y & 0xffff) + (y >> 16);
	return y;
}

static inline uint16_t ip_fast_csum(const uint8_t *const iph,
                                    const size_t ihl)
	__attribute__((nonnull(1), warn_unused_result, pure));

/**
 *  This is a version of ip_compute_csum() optimized for IP headers,
 *  which always checksum on 4 octet boundaries.
 */
static inline uint16_t ip_fast_csum(const uint8_t *const iph,
                                    const size_t ihl)
{
	const uint8_t *buff = iph;
	size_t len = ihl * 4;
	bool odd;
	size_t count;
	uint32_t result = 0;

	if(len == 0)
	{
		goto out;
	}
	odd = 1 & (uintptr_t) buff;
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
		if(2 & (uintptr_t) buff)
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


#endif /* !__i386__ && !__x86_64__ */

#else /* !__KERNEL__ */
#  include <asm/checksum.h>
#endif /* __KERNEL__ */


/*
 * Function prototypes.
 */

/* Generic functions */

bool ip_create(struct ip_packet *const ip,
               const uint8_t *const packet,
               const size_t size)
	__attribute__((warn_unused_result, nonnull(1, 2)));
bool ip_get_inner_packet(const struct ip_packet *const outer,
                         struct ip_packet *const inner)
	__attribute__((warn_unused_result, nonnull(1, 2)));

const uint8_t * ip_get_raw_data(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
uint8_t * ip_get_next_header(const struct ip_packet *const ip,
                             uint8_t *const type)
	__attribute__((warn_unused_result, nonnull(1, 2)));
uint8_t * ip_get_next_layer(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1)));
uint8_t * ip_get_next_ext_from_ip(const struct ip_packet *const ip,
                                  uint8_t *const type)
	__attribute__((warn_unused_result, nonnull(1, 2)));
uint8_t * ip_get_next_ext_from_ext(const uint8_t *const ext,
                                   uint8_t *const type)
	__attribute__((warn_unused_result, nonnull(1, 2)));

unsigned int ip_get_totlen(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
unsigned int ip_get_hdrlen(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1)));

bool ip_is_fragment(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
ip_version ip_get_version(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
uint8_t ip_get_protocol(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
unsigned int ip_get_tos(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
unsigned int ip_get_ttl(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));

void ip_set_version(struct ip_packet *const ip, const ip_version value)
	__attribute__((nonnull(1)));
void ip_set_protocol(struct ip_packet *const ip, const uint8_t value)
	__attribute__((nonnull(1)));
void ip_set_tos(struct ip_packet *const ip, const uint8_t value)
	__attribute__((nonnull(1)));
void ip_set_ttl(struct ip_packet *const ip, const uint8_t value)
	__attribute__((nonnull(1)));
void ip_set_saddr(struct ip_packet *const ip, const uint8_t *value)
	__attribute__((nonnull(1, 2)));
void ip_set_daddr(struct ip_packet *const ip, const uint8_t *value)
	__attribute__((nonnull(1, 2)));

/* IPv4 specific functions */

const struct ipv4_hdr * ipv4_get_header(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
uint16_t ipv4_get_id(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
uint16_t ipv4_get_id_nbo(const struct ip_packet *const ip, const unsigned int nbo)
	__attribute__((warn_unused_result, nonnull(1), pure));
int ipv4_get_df(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
uint32_t ipv4_get_saddr(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
uint32_t ipv4_get_daddr(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));

void ipv4_set_id(struct ip_packet *const ip, const int value)
	__attribute__((nonnull(1)));
void ipv4_set_df(struct ip_packet *const ip, const int value)
	__attribute__((nonnull(1)));

/* IPv6 specific functions */

const struct ipv6_hdr * ipv6_get_header(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
uint32_t ip_get_flow_label(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
const struct ipv6_addr * ipv6_get_saddr(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
const struct ipv6_addr * ipv6_get_daddr(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1), pure));
void ip_set_flow_label(struct ip_packet *const ip, const uint32_t value)
	__attribute__((nonnull(1)));
unsigned short ip_get_extension_size(const uint8_t *const ext)
	__attribute__((warn_unused_result, nonnull(1), pure));
unsigned short ip_get_total_extension_size(const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1)));


#endif

