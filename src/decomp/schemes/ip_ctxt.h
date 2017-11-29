/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2013,2014,2018 Viveris Technologies
 * Copyright 2012 WBX
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
 * @file   decomp/schemes/ip_ctxt.h
 * @brief  The decompression context for IP headers
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_DECOMP_SCHEMES_IP_CTXT_H
#define ROHC_DECOMP_SCHEMES_IP_CTXT_H

#include "protocols/ip.h"
#include "protocols/tcp.h"


/**
 * @brief Define the IPv6 option context for Destination, Hop-by-Hop
 *        and Routing option
 */
typedef struct
{
	uint8_t data[IPV6_OPT_CTXT_LEN_MAX];
	uint16_t data_len; /* max length = (0xff + 1) * 8 = 2048 bytes */

} ipv6_generic_option_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((sizeof(ipv6_generic_option_context_t) % 8) == 0,
               "ipv6_generic_option_context_t length should be multiple of 8 bytes");
#endif


/** The decompression context for one IP extension header */
typedef struct
{
	uint16_t len;      /**< The length (in bytes) of the extension header */

	uint8_t proto;     /**< The protocol of the extension header */
	uint8_t nh_proto;  /**< The protocol of the next header */
	uint8_t unused[4];

	ipv6_generic_option_context_t generic; /**< IPv6 generic extension header */

} ip_option_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(ip_option_context_t, generic) % 8) == 0,
               "generic in ip_option_context_t should be aligned on 8 bytes");
_Static_assert((sizeof(ip_option_context_t) % 8) == 0,
               "ip_option_context_t length should be multiple of 8 bytes");
#endif


/**
 * @brief Define the common IP header context to IPv4 and IPv6
 */
typedef struct __attribute__((packed)) ipvx_context
{
	uint8_t version:4;
	uint8_t ip_id_behavior:2;
	uint8_t unused:2;

	union
	{
		struct
		{
			uint8_t dscp:6;
			uint8_t ip_ecn_flags:2;
		};
		uint8_t tos_tc;
	} __attribute__((packed));

	uint8_t next_header;

	uint8_t ttl_hopl;

} ipvx_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert(sizeof(ipvx_context_t) == 4,
               "ipvx_context_t should be 4 bytes length");
#endif


/**
 * @brief Define the IPv4 header context
 */
typedef struct __attribute__((packed)) ipv4_context
{
	uint8_t version:4;
	uint8_t ip_id_behavior:2;
	uint8_t df:1;
	uint8_t unused:1;

	union
	{
		struct
		{
			uint8_t dscp:6;
			uint8_t ip_ecn_flags:2;
		};
		uint8_t tos;
	} __attribute__((packed));

	uint8_t protocol;

	uint8_t ttl;

	uint16_t ip_id;

	uint32_t src_addr;
	uint32_t dst_addr;

} ipv4_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert(sizeof(ipv4_context_t) == 14,
               "ipv4_context_t should be 14 bytes length");
#endif


/**
 * @brief Define the IPv6 header context
 */
typedef struct __attribute__((packed)) ipv6_context
{
	uint8_t version:4;
	uint8_t ip_id_behavior:2;
	uint8_t unused:2;

	union
	{
		struct
		{
			uint8_t dscp:6;
			uint8_t ip_ecn_flags:2;
		};
		uint8_t tc;
	} __attribute__((packed));

	uint8_t next_header;

	uint8_t hopl;

	uint32_t flow_label:20; /**< IPv6 Flow Label */
	uint32_t unused2:12;

	uint32_t src_addr[4];
	uint32_t dest_addr[4];

} ipv6_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(ipv6_context_t, src_addr) % 8) == 0,
               "src_addr in ip_context_t should be aligned on 8 bytes");
_Static_assert((sizeof(ipv6_context_t) % 8) == 0,
               "ipv6_context_t length should be multiple of 8 bytes");
#endif


/**
 * @brief Define union of IP contexts
 */
typedef struct
{
	union
	{
		ipvx_context_t vx;
		ipv4_context_t v4;
		ipv6_context_t v6;
	} ctxt;

	ip_option_context_t opts[ROHC_MAX_IP_EXT_HDRS];
	uint16_t opts_len; /* no more than the max IPv6 length, ie. 65535 */
	uint8_t opts_nr;

	ip_version version;

} ip_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(ip_context_t, ctxt) % 8) == 0,
               "ctxt in ip_context_t should be aligned on 8 bytes");
_Static_assert((offsetof(ip_context_t, opts) % 8) == 0,
               "opts in ip_context_t should be aligned on 8 bytes");
_Static_assert((offsetof(ip_context_t, opts_len) % 8) == 0,
               "opts_len in ip_context_t should be aligned on 8 bytes");
_Static_assert((sizeof(ip_context_t) % 8) == 0,
               "ip_context_t length should be multiple of 8 bytes");
#endif


#endif /* ROHC_DECOMP_SCHEMES_IP_CTXT_H */

