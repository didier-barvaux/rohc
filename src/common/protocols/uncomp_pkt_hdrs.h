/*
 * Copyright 2018 Didier Barvaux
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
 * @file   protocols/uncomp_pkt_hdrs.h
 * @brief  Information about the uncompressed packet headers
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_PROTOCOLS_UNCOMP_PKT_HDRS_H
#define ROHC_PROTOCOLS_UNCOMP_PKT_HDRS_H

#include "protocols/ip.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/esp.h"
#include "protocols/rtp.h"

#include <stdint.h>

#ifdef __KERNEL__
#  include <endian.h>
#else
#  include "config.h" /* for WORDS_BIGENDIAN */
#endif


/**
 * @brief The information collected about one of the packet IP extension headers
 */
struct rohc_pkt_ip_ext_hdr
{
	const uint8_t *data;
	uint8_t type;
	uint8_t len;
};


/**
 * @brief The information collected about one of the packet IP headers
 */
struct rohc_pkt_ip_hdr
{
	union
	{
		const uint8_t *data;
		const struct ip_hdr *ip;
		const struct ipv4_hdr *ipv4;
		const struct ipv6_hdr *ipv6;
	};
	uint8_t version;
	uint8_t next_proto;
	uint16_t ip_hdr_len;
	uint16_t tot_len;
	union
	{
		uint8_t tos_tc;     /**< The IPv4 TOS or IPv6 TC field */
		struct
		{
#if WORDS_BIGENDIAN == 1
			uint8_t dscp:6;  /**< The IPv4/v6 DSCP value */
			uint8_t ecn:2;   /**< The IPv4/v6 ECN value */
#else
			uint8_t ecn:2;
			uint8_t dscp:6;
#endif
		} __attribute__((packed));
	};
	uint8_t ttl_hl;    /**< The IPv4 TTL or IPv6 Hop Limit */

	uint8_t exts_len;  /**< The length of IP extensions headers */
	uint8_t exts_nr;   /**< The number of IP extensions headers */
	struct rohc_pkt_ip_ext_hdr exts[ROHC_MAX_IP_EXT_HDRS]; /**< The IP ext. headers */
};


/**
 * @brief The information collected about the packet headers
 *
 * The information about the packet headers is collected while the best profile
 * is detected, and that information may be later used while the best context is
 * detected or while changes with the compression context are detected.
 *
 * The collection of information avoids parsing the packet headers several times.
 */
struct rohc_pkt_hdrs
{
	/* The network headers */
	uint8_t ip_hdrs_nr;                               /**< The number of IP headers */
	struct rohc_pkt_ip_hdr ip_hdrs[ROHC_MAX_IP_HDRS]; /**< The IP headers */
	const struct rohc_pkt_ip_hdr *innermost_ip_hdr;   /**< The innermost IP header */

	/* The transport header */
	union
	{
		struct
		{
			const struct tcphdr *tcp;    /**< The TCP header (if any) */
			struct
			{
				uint8_t nr;
				uint8_t tot_len;
				const uint8_t *data[ROHC_TCP_OPTS_MAX];
				uint8_t types[ROHC_TCP_OPTS_MAX];
				uint8_t lengths[ROHC_TCP_OPTS_MAX];
			} tcp_opts;
		};
		const struct udphdr *udp;       /**< The UDP header (if any) */
		const struct esphdr *esp;       /**< The ESP header (if any) */
		const uint8_t *transport;       /**< The transport header (if any) */
	};

	const struct rtphdr *rtp;          /**< The RTP header (if any) */

	uint16_t all_hdrs_len;             /**< The cumulated length of all headers */
	const uint8_t *all_hdrs;           /**< All raw headers */
	uint16_t payload_len;              /**< The length of the packet payload */
	const uint8_t *payload;            /**< The packet payload */
};

#endif

