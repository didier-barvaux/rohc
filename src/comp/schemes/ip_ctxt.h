/*
 * Copyright 2012,2013,2014,2015,2016 Didier Barvaux
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
 * @file   src/comp/schemes/ip_ctxt.h
 * @brief  The compression context for IP headers
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMP_SCHEMES_IP_CTXT_H
#define ROHC_COMP_SCHEMES_IP_CTXT_H

#include "protocols/ip.h"
#include "protocols/ipv6.h"
#include "protocols/tcp.h"
#include "ip.h"


/**
 * @brief Define the IPv6 generic option context
 */
typedef struct
{
	uint8_t data[IPV6_OPT_CTXT_LEN_MAX];
	uint16_t option_length; /* max length = (0xff + 1) * 8 = 2048 bytes */
	uint8_t next_header;
	uint8_t unused[7]; /**< pad struct up to multiple of 8 bytes, align next fields */

} ipv6_generic_option_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((sizeof(ipv6_generic_option_context_t) % 8) == 0,
               "ipv6_generic_option_context_t length should be multiple of 8 bytes");
#endif


/**
 * @brief Define the common IP header context to IPv4 and IPv6
 */
typedef struct __attribute__((packed)) ipvx_context
{
	uint8_t version:4;
	uint8_t ip_id_behavior:2;
	uint8_t last_ip_id_behavior:2;

	union
	{
		struct
		{
			uint8_t dscp:6;
			uint8_t ip_ecn_flags:2;
		};
		uint8_t tos_tc;
	};

	uint8_t next_header;

	uint8_t ttl_hopl;

} ipvx_context_t;


/**
 * @brief Define the IPv4 header context
 */
typedef struct __attribute__((packed)) ipv4_context
{
	uint8_t version:4;
	uint8_t ip_id_behavior:2;
	uint8_t last_ip_id_behavior:2;

	union
	{
		struct
		{
			uint8_t dscp:6;
			uint8_t ip_ecn_flags:2;
		};
		uint8_t tos;
	};

	uint8_t protocol;

	uint8_t ttl;

	uint16_t last_ip_id;
	uint8_t df:1;
	uint8_t unused:3;

	uint8_t unused2[1];

	uint32_t src_addr;
	uint32_t dst_addr;

} ipv4_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(ipv4_context_t, src_addr) % 8) == 0,
               "src_addr in ipv4_context_t should be aligned on 8 bytes");
_Static_assert((sizeof(ipv4_context_t) % 8) == 0,
               "ipv4_context_t length should be multiple of 8 bytes");
#endif


/** The compression context for one IPv6 extension header */
typedef union
{
	ipv6_generic_option_context_t generic; /**< IPv6 generic extension header */
	/* TODO: GRE not yet supported */
	/* TODO: MINE not yet supported */
	/* TODO: AH not yet supported */
} ip_option_context_t;


/**
 * @brief Define the IPv6 header context
 */
typedef struct __attribute__((packed)) ipv6_context
{
	uint8_t version:4;
	uint8_t ip_id_behavior:2;
	uint8_t last_ip_id_behavior:2;

	union
	{
		struct
		{
			uint8_t dscp:6;
			uint8_t ip_ecn_flags:2;
		};
		uint8_t tc;
	};

	uint8_t next_header;

	uint8_t hopl;

	uint32_t flow_label:20;
	uint32_t unused:12;

	uint32_t src_addr[4];
	uint32_t dest_addr[4];

} ipv6_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(ipv6_context_t, src_addr) % 8) == 0,
               "src_addr in ipv6_context_t should be aligned on 8 bytes");
_Static_assert((offsetof(ipv6_context_t, dest_addr) % 8) == 0,
               "dest_addr in ipv6_context_t should be aligned on 8 bytes");
_Static_assert((sizeof(ipv4_context_t) % 8) == 0,
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
	uint8_t opts_nr;

	ip_version version;

	/* Context Replication */
	bool cr_ttl_hopl_present;

	uint8_t unused[5];

} ip_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(ip_context_t, ctxt) % 8) == 0,
               "ctxt in ip_context_t should be aligned on 8 bytes");
_Static_assert((offsetof(ip_context_t, opts) % 8) == 0,
               "opts in ip_context_t should be aligned on 8 bytes");
_Static_assert((sizeof(ip_context_t) % 8) == 0,
               "ip_context_t length should be multiple of 8 bytes");
#endif

#endif /* ROHC_COMP_SCHEMES_IP_CTXT_H */

