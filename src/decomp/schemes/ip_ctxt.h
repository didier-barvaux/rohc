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
 * @brief The TCP decompression context for one IPv4 or IPv6 header
 */
typedef struct
{
	uint32_t flow_label:20; /**< IPv6 Flow Label */
	union
	{
		struct
		{
			uint32_t dscp:6;
			uint32_t ip_ecn_flags:2;
		};
		uint32_t tos_tc:8;
	};
	uint32_t df:1;
	uint32_t unused:3;

	uint16_t ip_id;
	uint8_t next_header;
	uint8_t ttl_hopl;

	uint32_t saddr[4];
	uint32_t daddr[4];

	ip_option_context_t opts[ROHC_MAX_IP_EXT_HDRS];
	uint16_t opts_len; /* no more than the max IPv6 length, ie. 65535 */
	uint8_t opts_nr;

	uint8_t version:4;
	uint8_t ip_id_behavior:2;
	uint8_t unused2:2;
	uint8_t unused3[4];

} ip_context_t;

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(ip_context_t, saddr) % 8) == 0,
               "saddr in ip_context_t should be aligned on 8 bytes");
_Static_assert((offsetof(ip_context_t, daddr) % 8) == 0,
               "daddr in ip_context_t should be aligned on 8 bytes");
_Static_assert((offsetof(ip_context_t, opts_len) % 8) == 0,
               "opts_len in ip_context_t should be aligned on 8 bytes");
_Static_assert((offsetof(ip_context_t, opts) % 8) == 0,
               "opts in ip_context_t should be aligned on 8 bytes");
_Static_assert((sizeof(ip_context_t) % 8) == 0,
               "ip_context_t length should be multiple of 8 bytes");
#endif

#endif /* ROHC_DECOMP_SCHEMES_IP_CTXT_H */

