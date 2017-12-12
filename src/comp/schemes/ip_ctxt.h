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
typedef struct __attribute__((packed)) ipv6_generic_option_context
{
	size_t option_length;
	uint8_t next_header;
	uint8_t data[IPV6_OPT_CTXT_LEN_MAX];

} ipv6_generic_option_context_t;


/**
 * @brief Define the common IP header context to IPv4 and IPv6
 */
typedef struct __attribute__((packed)) ipvx_context
{
	uint8_t version:4;
	uint8_t unused:4;

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

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;

} ipvx_context_t;


/**
 * @brief Define the IPv4 header context
 */
typedef struct __attribute__((packed)) ipv4_context
{
	uint8_t version:4;
	uint8_t df:1;
	uint8_t unused:3;

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

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;
	uint16_t last_ip_id;

	uint32_t src_addr;
	uint32_t dst_addr;

} ipv4_context_t;


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
	uint8_t unused:4;

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

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;

	uint32_t flow_label:20;

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

	/* Context Replication */
	bool cr_ttl_hopl_present;

	size_t opts_nr;
	ip_option_context_t opts[ROHC_MAX_IP_EXT_HDRS];

} ip_context_t;

#endif /* ROHC_COMP_SCHEMES_IP_CTXT_H */

