/*
 * Copyright 2012,2013,2014,2015,2016 Didier Barvaux
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
 * @file   c_tcp_defines.h
 * @brief  Main definitions for the TCP compression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_DECOMP_TCP_DEFINES_H
#define ROHC_DECOMP_TCP_DEFINES_H

#include "protocols/tcp.h"
#include "c_tcp_opts_list.h"

/**
 * @brief Define the TCP-specific temporary variables in the profile
 *        compression context.
 *
 * This object must be used by the TCP-specific decompression context
 * sc_tcp_context.
 *
 * @see sc_tcp_context
 */
struct tcp_tmp_variables
{
	/** Whether at least one of the static part of the IPv6 extensions changed
	 * in the current packet */
	bool is_ipv6_exts_list_static_changed;
	/** Whether at least one of the dynamic part of the IPv6 extensions changed
	 * in the current packet */
	bool is_ipv6_exts_list_dyn_changed;
	/** The new number of IP extensions headers (for every IP header) */
	size_t ip_exts_nr[ROHC_TCP_MAX_IP_HDRS];

	/* the length of the TCP payload (headers and options excluded) */
	size_t payload_len;

	/** The minimal number of bits required to encode the MSN value */
	size_t nr_msn_bits;

	/** Whether the TCP window changed or not */
	size_t tcp_window_changed;
	/** The minimal number of bits required to encode the TCP window */
	size_t nr_window_bits_16383;

	/** Whether the TCP sequence number changed or not */
	bool tcp_seq_num_changed;
	/** The minimal number of bits required to encode the TCP scaled sequence
	 *  number */
	size_t nr_seq_scaled_bits;

	/** Whether the ACK number changed or not */
	bool tcp_ack_num_changed;
	/** The minimal number of bits required to encode the TCP ACK number
	 *  with p = 16383 */
	size_t nr_ack_bits_16383;
	/** The minimal number of bits required to encode the TCP scaled ACK
	 * number */
	size_t nr_ack_scaled_bits;

	/** The IP-ID / SN delta (with bits swapped if necessary) */
	uint16_t ip_id_delta;
	/** Whether the behavior of the IP-ID field changed with current packet */
	bool ip_id_behavior_changed;
	/** The minimal number of bits required to encode the innermost IP-ID value
	 *  with p = 3 */
	size_t nr_ip_id_bits_3;
	/** The minimal number of bits required to encode the innermost IP-ID value
	 *  with p = 1 */
	size_t nr_ip_id_bits_1;

	/* innermost IPv4 TTL or IPv6 Hop Limit */
	uint8_t ttl_hopl;
	size_t nr_ttl_hopl_bits;
	bool ttl_hopl_changed;
	/* outer IPv4 TTLs or IPv6 Hop Limits */
	int ttl_irreg_chain_flag;
	bool outer_ip_ttl_changed;

	bool ip_df_changed;
	bool dscp_changed;

	bool tcp_ack_flag_changed;
	bool tcp_urg_flag_present;
	bool tcp_urg_flag_changed;

	/** Whether the ecn_used flag changed or not */
	bool ecn_used_changed;
};


/**
 * @brief Define the IPv6 generic option context.
 */
typedef struct __attribute__((packed)) ipv6_generic_option_context
{
	size_t option_length;
	uint8_t next_header;
	uint8_t data[IPV6_OPT_CTXT_LEN_MAX];

} ipv6_generic_option_context_t;


/**
 * @brief Define the common IP header context to IPv4 and IPv6.
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
	uint8_t last_ip_id_behavior;

} ipvx_context_t;


/**
 * @brief Define the IPv4 header context.
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
 * @brief Define the IPv6 header context.
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

	size_t opts_nr;
	ip_option_context_t opts[ROHC_TCP_MAX_IP_EXT_HDRS];

} ip_context_t;


/** Define the TCP part of the profile decompression context */
struct sc_tcp_context
{
	/// The number of times the sequence number field was added to the compressed header
	int tcp_seq_num_change_count;
	/** The number of times the window field was added to the compressed header */
	size_t tcp_window_change_count;

	/** Explicit Congestion Notification used */
	bool ecn_used;
	/** The number of times the ECN fields were added to the compressed header */
	size_t ecn_used_change_count;
	/** The number of times the ECN fields were not needed */
	size_t ecn_used_zero_count;

	uint16_t msn;               /**< The Master Sequence Number (MSN) */
	struct c_wlsb msn_wlsb;    /**< The W-LSB decoding context for MSN */

	/** The MSN of the last packet that updated the context (used to determine
	 * if a positive ACK may cause a transition to a higher compression state) */
	uint16_t msn_of_last_ctxt_updating_pkt;

	struct c_wlsb ttl_hopl_wlsb;
	size_t ttl_hopl_change_count;

	struct c_wlsb ip_id_wlsb;

// lsb(15, 16383)
	struct c_wlsb window_wlsb; /**< The W-LSB decoding context for TCP window */

	uint32_t seq_num;
	struct c_wlsb seq_wlsb;
	struct c_wlsb seq_scaled_wlsb;

	uint32_t seq_num_scaled;
	uint32_t seq_num_residue;
	size_t seq_num_factor;
	size_t seq_num_scaling_nr;

	uint32_t ack_num;
	struct c_wlsb ack_wlsb;
	struct c_wlsb ack_scaled_wlsb;

	size_t ack_deltas_next;
	uint16_t ack_deltas_width[20];
	uint16_t ack_stride;
	uint32_t ack_num_scaled;
	uint16_t ack_num_residue;
	size_t ack_num_scaling_nr;

	/** The compression context for TCP options */
	struct c_tcp_opts_ctxt tcp_opts;

	/// The previous TCP header
	struct tcphdr old_tcphdr;

	/// @brief TCP-specific temporary variables that are used during one single
	///        compression of packet
	struct tcp_tmp_variables tmp;

	size_t ip_contexts_nr;
	ip_context_t ip_contexts[ROHC_TCP_MAX_IP_HDRS];
};

#endif /* ROHC_DECOMP_TCP_DEFINES_H */

