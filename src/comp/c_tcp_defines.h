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
	uint32_t seq_num;
	uint32_t ack_num;

	/** The IP-ID / SN delta (with bits swapped if necessary) */
	uint16_t ip_id_delta;

	/** Whether at least one of the static part of the IPv6 extensions changed
	 * in the current packet */
	uint16_t is_ipv6_exts_list_static_changed:1;
	/** Whether at least one of the dynamic part of the IPv6 extensions changed
	 * in the current packet */
	uint16_t is_ipv6_exts_list_dyn_changed:1;
	/** Whether the TCP window changed or not */
	uint16_t tcp_window_changed:1;
	/** Whether the sequence number changed or not */
	uint16_t tcp_seq_num_unchanged:1;
	/** Whether the ACK number changed or not */
	uint16_t tcp_ack_num_unchanged:1;
	/** Whether the behavior of the IP-ID field changed with current packet */
	uint16_t ip_id_behavior_changed:1;
	uint16_t ttl_hopl_changed:1;
	uint16_t ttl_irreg_chain_flag:1; /* outer IPv4 TTLs or IPv6 Hop Limits */
	uint16_t outer_ip_ttl_changed:1;
	uint16_t ip_df_changed:1;
	uint16_t dscp_changed:1;
	uint16_t tcp_ack_flag_changed:1;
	uint16_t tcp_urg_flag_present:1;
	uint16_t tcp_urg_flag_changed:1;
	uint16_t tcp_urg_ptr_changed:1;
	uint16_t ecn_used_changed:1; /**< Whether the ecn_used flag changed or not */

	/** The temporary part of the context for TCP options */
	struct c_tcp_opts_ctxt_tmp tcp_opts;
};


/** Define the TCP part of the profile decompression context */
struct sc_tcp_context
{
	uint16_t msn;               /**< The Master Sequence Number (MSN) */
	/** The MSN of the last packet that updated the context (used to determine
	 * if a positive ACK may cause a transition to a higher compression state) */
	uint16_t msn_of_last_ctxt_updating_pkt;

	uint32_t seq_num;
	uint32_t seq_num_scaled;
	uint32_t seq_num_residue;
	uint32_t seq_num_factor;

	uint32_t ack_num;
	uint16_t ack_deltas_width[20];
	uint32_t ack_num_scaled;
	uint32_t ack_num_residue;
	uint16_t ack_stride;
	uint8_t ack_deltas_next;

	/** The number of TCP sequence number transmissions since last change */
	uint8_t tcp_seq_num_trans_nr:4;
	/** The number of TCP ACK number transmissions since last change */
	uint8_t tcp_ack_num_trans_nr:4;
	uint8_t seq_num_scaling_nr:4;
	uint8_t ack_num_scaling_nr:4;
	/** The number of times the window field was added to the compressed header */
	uint8_t tcp_window_change_count:4;
	/** The number of times the ECN fields were added to the compressed header */
	uint8_t ecn_used_change_count:4;
	/** The number of times the ECN fields were not needed */
	uint8_t ecn_used_zero_count:4;
	uint8_t ttl_hopl_change_count:4;
	/** The number of innermost IP-ID behavior transmissions since last change */
	uint8_t innermost_ip_id_behavior_trans_nr;
	/** The number of innermost DSCP transmissions since last change */
	uint8_t innermost_dscp_trans_nr;
	/** The number of IPv6 exts static transmissions since last change */
	uint8_t ipv6_exts_list_static_trans_nr;
	/** The number of IPv6 exts dynamic transmissions since last change */
	uint8_t ipv6_exts_list_dyn_trans_nr;
	/** The number of TCP options static transmissions since last change */
	uint8_t tcp_opts_list_static_trans_nr;
	/** The number of TCP URG pointer transmissions since last change */
	uint8_t tcp_urg_ptr_trans_nr;

	uint8_t ecn_used:1; /**< Explicit Congestion Notification used */
	/* Context Replication */
	uint8_t cr_tcp_window_present:1;
	uint8_t cr_tcp_urg_ptr_present:1;
	uint8_t cr_tcp_ack_num_present:1;

	uint8_t res_flags:4;
	uint8_t urg_flag:1;
	uint8_t ack_flag:1;
	uint8_t unused2:6;

	struct c_wlsb msn_wlsb;    /**< The W-LSB decoding context for MSN */
	struct c_wlsb ttl_hopl_wlsb;
	struct c_wlsb ip_id_wlsb;
	struct c_wlsb window_wlsb; /**< The W-LSB decoding context for TCP window */
	struct c_wlsb seq_wlsb;
	struct c_wlsb seq_scaled_wlsb;
	struct c_wlsb ack_wlsb;
	struct c_wlsb ack_scaled_wlsb;

	/** The compression context for TCP options */
	struct c_tcp_opts_ctxt tcp_opts;

	uint16_t urg_ptr_nbo;
	uint16_t window_nbo;

	uint8_t ip_contexts_nr;
	ip_context_t ip_contexts[ROHC_MAX_IP_HDRS];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct sc_tcp_context, seq_num_scaled) % 8) == 0,
               "seq_num_scaled in sc_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct sc_tcp_context, ack_deltas_width) % 8) == 0,
               "ack_deltas_width in sc_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct sc_tcp_context, msn_wlsb) % 8) == 0,
               "msn_wlsb in sc_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct sc_tcp_context, ttl_hopl_wlsb) % 8) == 0,
               "ttl_hopl_wlsb in sc_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct sc_tcp_context, tcp_opts) % 8) == 0,
               "tcp_opts in sc_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct sc_tcp_context, ip_contexts) % 8) == 0,
               "ip_contexts in sc_tcp_context should be aligned on 8 bytes");
_Static_assert((sizeof(struct sc_tcp_context) % 8) == 0,
               "sc_tcp_context length should be multiple of 8 bytes");
#endif


#endif /* ROHC_COMP_TCP_DEFINES_H */

