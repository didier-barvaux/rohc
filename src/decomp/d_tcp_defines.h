/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2013,2014 Viveris Technologies
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
 * @file   d_tcp_defines.h
 * @brief  Main definitions for the TCP decompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_DECOMP_TCP_DEFINES_H
#define ROHC_DECOMP_TCP_DEFINES_H

#include "ip.h"
#include "protocols/tcp.h"

#include <stdint.h>

/**
 * @brief Define the IPv6 option context for Destination, Hop-by-Hop
 *        and Routing option
 */
typedef struct __attribute__((packed)) ipv6_option_context
{
	uint8_t context_length;
	uint8_t option_length;
	uint8_t next_header;
	uint8_t length;
	uint8_t data[0];

} ipv6_generic_option_context_t;


/**
 * @brief Define the IPv6 option context for GRE option
 */
typedef struct __attribute__((packed)) ipv6_gre_option_context
{
	uint8_t context_length;
	uint8_t option_length;

	uint8_t next_header;

	uint8_t c_flag : 1;
	uint8_t k_flag : 1;
	uint8_t s_flag : 1;
	uint8_t protocol : 1;
	uint8_t padding : 4;

	uint32_t key;               // if k_flag set
	uint32_t sequence_number;   // if s_flag set

} ipv6_gre_option_context_t;


/**
 * @brief Define the IPv6 option context for MIME option
 */
typedef struct __attribute__((packed)) ipv6_mime_option_context
{
	uint8_t context_length;
	uint8_t option_length;

	uint8_t next_header;

	uint8_t s_bit : 1;
	uint8_t res_bits : 7;
	uint32_t orig_dest;
	uint32_t orig_src;         // if s_bit set

} ipv6_mime_option_context_t;


/**
 * @brief Define the IPv6 option context for AH option
 */
typedef struct __attribute__((packed)) ipv6_ah_option_context
{
	uint8_t context_length;
	uint8_t option_length;

	uint8_t next_header;
	uint8_t length;
	uint32_t spi;
	uint32_t sequence_number;
	uint32_t auth_data[1];
} ipv6_ah_option_context_t;


/** The decompression context for one IPv6 extension header */
typedef union
{
	ipv6_generic_option_context_t generic; /**< IPv6 generic extension header */
	ipv6_gre_option_context_t gre;         /**< IPv6 GRE extension header */
	ipv6_mime_option_context_t mime;       /**< IPv6 MIME extension header */
	ipv6_ah_option_context_t ah;           /**< IPv6 AH extension header */
} ipv6_option_context_t;


/**
 * @brief Define the common IP header context to IPv4 and IPv6.
 */
typedef struct __attribute__((packed)) ipvx_context
{
	uint8_t version : 4;
	uint8_t unused : 4;

	uint8_t context_length;

	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;

	uint8_t next_header;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;

} ipvx_context_t;


/**
 * @brief Define the IPv4 header context.
 */
typedef struct __attribute__((packed)) ipv4_context
{
	uint8_t version : 4;
	uint8_t df : 1;
	uint8_t unused : 3;

	uint8_t context_length;

	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;

	uint8_t protocol;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;
	uint16_t ip_id;

	uint32_t src_addr;
	uint32_t dst_addr;

} ipv4_context_t;


#define ROHC_TCP_MAX_IP_HDRS        10U
#define ROHC_TCP_MAX_IPv6_EXT_HDRS  10U

/**
 * @brief Define the IPv6 header context.
 */
typedef struct __attribute__((packed)) ipv6_context
{
	uint8_t version : 4;
	uint8_t unused : 4;

	uint8_t context_length;

	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;

	uint8_t next_header;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;

	uint8_t flow_label1 : 4;
	uint16_t flow_label2;

	uint32_t src_addr[4];
	uint32_t dest_addr[4];

	size_t opts_nr;
	size_t opts_len;
	ipv6_option_context_t opts[ROHC_TCP_MAX_IPv6_EXT_HDRS];

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

} ip_context_t;


/** Define the TCP part of the decompression profile context */
struct d_tcp_context
{
	/** The LSB decoding context of MSN */
	struct rohc_lsb_decode *msn_lsb_ctxt;
	uint16_t msn_tmp;

	/** The LSB decoding context of innermost IP-ID */
	struct rohc_lsb_decode *ip_id_lsb_ctxt;

	// Explicit Congestion Notification used
	uint8_t ecn_used;

	/* TCP static part */
	uint16_t tcp_src_port; /**< The TCP source port */
	uint16_t tcp_dst_port; /**< The TCP dest port */

	/* TCP dynamic part (temporary) */
	uint8_t res_flags:4;
	uint8_t ecn_flags:2;
	uint8_t urg_flag:1;
	uint8_t ack_flag:1;
	uint8_t psh_flag:1;
	uint8_t rsf_flags:3;
	uint32_t seq_num;
	uint32_t ack_num;
	uint16_t checksum;
	uint16_t urg_ptr;
#define MAX_TCP_DATA_OFFSET_WORDS  ((1 << 4) - 1)
#define MAX_TCP_DATA_OFFSET_BYTES  (MAX_TCP_DATA_OFFSET_WORDS * sizeof(uint32_t))
#define MAX_TCP_OPTIONS_LEN        (MAX_TCP_DATA_OFFSET_BYTES - sizeof(tcphdr_t))
	size_t options_len;
	uint8_t options[MAX_TCP_OPTIONS_LEN];

	/** The LSB decoding context of TCP window */
	struct rohc_lsb_decode *window_lsb_ctxt;
	uint16_t window_tmp;

	uint32_t seq_num_scaled;
	uint32_t seq_num_residue;
	struct rohc_lsb_decode *seq_lsb_ctxt;
	struct rohc_lsb_decode *seq_scaled_lsb_ctxt;

	uint16_t ack_stride;
	uint32_t ack_num_scaled;
	uint32_t ack_num_residue;
	struct rohc_lsb_decode *ack_lsb_ctxt;

	// Table of TCP options
	uint8_t tcp_options_list[ROHC_TCP_OPTS_MAX];   // see RFC4996 page 27
	uint8_t tcp_options_offset[ROHC_TCP_OPTS_MAX];
	uint16_t tcp_option_maxseg;
	uint8_t tcp_option_window;
	/** The structure of the list of TCP options */
	uint8_t tcp_opts_list_struct[ROHC_TCP_OPTS_MAX];
	/** Whether the content of every TCP options was transmitted or not */
	bool is_tcp_opts_list_item_present[ROHC_TCP_OPTS_MAX]; /* TODO: should be in tmp part */
	/** TODO */
	size_t tcp_opts_list_item_uncomp_length[ROHC_TCP_OPTS_MAX]; /* TODO: should be in tmp part */

	struct tcp_option_timestamp tcp_option_timestamp;
	struct rohc_lsb_decode *opt_ts_req_lsb_ctxt;
	struct rohc_lsb_decode *opt_ts_reply_lsb_ctxt;

	uint8_t tcp_option_sack_length;
	uint8_t tcp_option_sackblocks[8 * 4];
	uint8_t tcp_options_free_offset;
#define MAX_TCP_OPT_SIZE 64
	uint8_t tcp_options_values[MAX_TCP_OPT_SIZE];

	tcphdr_t old_tcphdr;

	size_t ip_contexts_nr;
	ip_context_t ip_contexts[ROHC_TCP_MAX_IP_HDRS];
};

#endif /* ROHC_DECOMP_TCP_DEFINES_H */

