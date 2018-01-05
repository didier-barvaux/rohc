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
typedef struct __attribute__((packed))
{
	size_t data_len;
	uint8_t data[IPV6_OPT_CTXT_LEN_MAX];

} ipv6_generic_option_context_t;


/**
 * @brief Define the IPv6 option context for GRE option
 */
typedef struct __attribute__((packed)) ipv6_gre_option_context
{
	uint8_t c_flag:1;
	uint8_t k_flag:1;
	uint8_t s_flag:1;
	uint8_t protocol:1;
	uint8_t padding:4;

	uint32_t key;               // if k_flag set
	uint32_t sequence_number;   // if s_flag set

} ipv6_gre_option_context_t;


/**
 * @brief Define the IPv6 option context for MIME option
 */
typedef struct __attribute__((packed)) ipv6_mime_option_context
{
	uint8_t s_bit:1;
	uint8_t res_bits:7;
	uint32_t orig_dest;
	uint32_t orig_src;         // if s_bit set

} ipv6_mime_option_context_t;


/**
 * @brief Define the IPv6 option context for AH option
 */
typedef struct __attribute__((packed)) ipv6_ah_option_context
{
	uint32_t spi;
	uint32_t sequence_number;
	uint32_t auth_data[1];
} ipv6_ah_option_context_t;


/** The decompression context for one IP extension header */
typedef struct
{
	size_t len;        /**< The length (in bytes) of the extension header */
	uint8_t proto;     /**< The protocol of the extension header */
	uint8_t nh_proto;  /**< The protocol of the next header */

	union
	{
		ipv6_generic_option_context_t generic; /**< IPv6 generic extension header */
		ipv6_gre_option_context_t gre;         /**< IPv6 GRE extension header */
		ipv6_mime_option_context_t mime;       /**< IPv6 MIME extension header */
		ipv6_ah_option_context_t ah;           /**< IPv6 AH extension header */
	};

} ip_option_context_t;


/**
 * @brief Define the common IP header context to IPv4 and IPv6
 */
typedef struct __attribute__((packed)) ipvx_context
{
	uint8_t version:4;
	uint8_t unused:4;

	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;

	uint8_t next_header;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;

} ipvx_context_t;


/**
 * @brief Define the IPv4 header context
 */
typedef struct __attribute__((packed)) ipv4_context
{
	uint8_t version:4;
	uint8_t df:1;
	uint8_t unused:3;

	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;

	uint8_t protocol;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;
	uint16_t ip_id;

	uint32_t src_addr;
	uint32_t dst_addr;

} ipv4_context_t;


/**
 * @brief Define the IPv6 header context
 */
typedef struct __attribute__((packed)) ipv6_context
{
	uint8_t version:4;
	uint8_t unused:4;

	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;

	uint8_t next_header;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;

	uint32_t flow_label:20; /**< IPv6 Flow Label */

	uint32_t src_addr[4];
	uint32_t dest_addr[4];

} ipv6_context_t;


/**
 * @brief Define union of IP contexts
 */
typedef struct
{
	ip_version version;
	union
	{
		ipvx_context_t vx;
		ipv4_context_t v4;
		ipv6_context_t v6;
	} ctxt;

	size_t opts_nr;
	size_t opts_len;
	ip_option_context_t opts[ROHC_MAX_IP_EXT_HDRS];

} ip_context_t;

#endif /* ROHC_DECOMP_SCHEMES_IP_CTXT_H */

