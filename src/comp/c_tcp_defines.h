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

#ifndef ROHC_COMP_TCP_DEFINES_H
#define ROHC_COMP_TCP_DEFINES_H

#include "protocols/ip.h"
#include "protocols/tcp.h"
#include "schemes/ip_ctxt.h"
#include "c_tcp_opts_list.h"


/**
 * @brief Define the TCP-specific temporary variables in the profile
 *        compression context.
 *
 * This object must be used by the TCP-specific compression context
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
	size_t ip_exts_nr[ROHC_MAX_IP_HDRS];

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


/** Define the TCP part of the profile compression context */
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

	uint16_t msn;            /**< The Master Sequence Number (MSN) */
	struct c_wlsb msn_wlsb;  /**< The W-LSB decoding context for MSN */

	/** The MSN of the last packet that updated the context (used to determine
	 * if a positive ACK may cause a transition to a higher compression state) */
	uint16_t msn_of_last_ctxt_updating_pkt;

	struct c_wlsb ttl_hopl_wlsb;
	size_t ttl_hopl_change_count;

	struct c_wlsb ip_id_wlsb;

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

	/* Context Replication */
	bool cr_tcp_window_present;
	bool cr_tcp_urg_ptr_present;
	bool cr_tcp_ack_num_present;

	/** The compression context for TCP options */
	struct c_tcp_opts_ctxt tcp_opts;

	/// The previous TCP header
	struct tcphdr old_tcphdr;

	/// @brief TCP-specific temporary variables that are used during one single
	///        compression of packet
	struct tcp_tmp_variables tmp;

	size_t ip_contexts_nr;
	ip_context_t ip_contexts[ROHC_MAX_IP_HDRS];
};

#endif /* ROHC_COMP_TCP_DEFINES_H */

