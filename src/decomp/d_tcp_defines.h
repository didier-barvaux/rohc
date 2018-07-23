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
#include "interval.h"
#include "protocols/ip.h"
#include "protocols/tcp.h"
#include "protocols/rfc6846.h"
#include "schemes/ip_ctxt.h"
#include "schemes/decomp_wlsb.h"
#include "schemes/tcp_ts.h"
#include "schemes/tcp_sack.h"

#include <stdint.h>


/** The decompression context for one TCP option */
struct d_tcp_opt_ctxt /* TODO: doxygen */
{
	union
	{
		struct
		{
			bool is_static;
			uint8_t len;
		} eol;
		struct
		{
			bool is_static;
			uint16_t value;
		} mss;
		struct
		{
			bool is_static;
			uint8_t value;
		} ws;
		struct
		{
			struct rohc_lsb_field32 req;  /**< The context for the TS request field */
			struct rohc_lsb_field32 rep;  /**< The context for the TS reply field */
		} ts;
		struct d_tcp_opt_sack sack; /* TODO: ptr inside is not needed */
		struct
		{
			uint8_t load[ROHC_TCP_OPT_MAX_LEN];
			enum
			{
				TCP_GENERIC_OPT_STATIC,
				TCP_GENERIC_OPT_STABLE,
				TCP_GENERIC_OPT_FULL,
			} type;
			uint8_t load_len;
		} generic;
	} data;
	bool used;
	uint8_t type;
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct d_tcp_opt_ctxt, data) % 8) == 0,
               "data in d_tcp_opt_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_opt_ctxt, data.eol) % 8) == 0,
               "data.eol in d_tcp_opt_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_opt_ctxt, data.mss) % 8) == 0,
               "data.mss in d_tcp_opt_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_opt_ctxt, data.ws) % 8) == 0,
               "data.ws in d_tcp_opt_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_opt_ctxt, data.ts) % 8) == 0,
               "data.ts in d_tcp_opt_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_opt_ctxt, data.sack) % 8) == 0,
               "data.sack in d_tcp_opt_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_opt_ctxt, data.generic) % 8) == 0,
               "data.generic in d_tcp_opt_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_opt_ctxt, data.generic.load) % 8) == 0,
               "data.generic.load in d_tcp_opt_ctxt should be aligned on 8 bytes");
_Static_assert((sizeof(struct d_tcp_opt_ctxt) % 8) == 0,
               "d_tcp_opt_ctxt length should be multiple of 8 bytes");
#endif


/** The decompression context for TCP options */
struct d_tcp_opts_ctxt
{
	/** The structure of the list of TCP options */
	uint8_t structure[ROHC_TCP_OPTS_MAX];

	/** The number of options in the list of TCP options */
	uint8_t nr;

	/** Whether the TCP options are expected in the dynamic part? */
	bool expected_dynamic[ROHC_TCP_OPTS_MAX];
	uint8_t unused2[1]; /**< pad struct up to multiple of 8 bytes, align next fields */

	/** The TCP options that were found or not */
	bool found[ROHC_TCP_OPTS_MAX];
	uint8_t unused3[1]; /**< pad struct up to multiple of 8 bytes, align next fields */

	/** The bits of TCP options extracted from the dynamic chain, the tail of
	 * co_common/seq_8/rnd_8 packets, or the irregular chain */
	struct d_tcp_opt_ctxt bits[MAX_TCP_OPTION_INDEX + 1];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct d_tcp_opts_ctxt, structure) % 8) == 0,
               "structure in d_tcp_opts_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_opts_ctxt, expected_dynamic) % 8) == 0,
               "expected_dynamic in d_tcp_opts_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_opts_ctxt, found) % 8) == 0,
               "found in d_tcp_opts_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_opts_ctxt, bits) % 8) == 0,
               "bits in d_tcp_opts_ctxt should be aligned on 8 bytes");
_Static_assert((sizeof(struct d_tcp_opts_ctxt) % 8) == 0,
               "d_tcp_opts_ctxt length should be multiple of 8 bytes");
#endif


/** Define the TCP part of the decompression profile context */
struct d_tcp_context
{
	/** The LSB decoding context of MSN */
	struct rohc_lsb_decode msn_lsb_ctxt;

	/** The LSB decoding context of innermost IP-ID */
	struct rohc_lsb_decode ip_id_lsb_ctxt;
	/** The LSB decoding context of innermost TTL/HL */
	struct rohc_lsb_decode ttl_hl_lsb_ctxt;

	struct rohc_lsb_decode seq_lsb_ctxt;
	struct rohc_lsb_decode seq_scaled_lsb_ctxt;
	struct rohc_lsb_decode ack_lsb_ctxt;
	struct rohc_lsb_decode ack_scaled_lsb_ctxt;
	/** The LSB decoding context of TCP window */
	struct rohc_lsb_decode window_lsb_ctxt;

	uint32_t seq_num_residue;
	uint32_t ack_stride;
	uint32_t ack_num_residue;

	uint16_t tcp_src_port; /**< The TCP source port */
	uint16_t tcp_dst_port; /**< The TCP dest port */

	/** The URG pointer */
	uint16_t urg_ptr;

	/* TCP flags */
	uint8_t res_flags:4;  /**< The TCP reserved flags */
	uint8_t ecn_used:1;   /**< Whether ECN flag is used */
	uint8_t ecn_flags:2;  /**< The TCP ECN flags */
	uint8_t urg_flag:1;   /**< The TCP URG flag */
	uint8_t ack_flag:1;   /**< The TCP ACK flag */
	uint8_t rsf_flags:3;  /**< The TCP RSF flag */
	uint8_t unused:4;

	uint8_t unused2[3];

	uint8_t ip_contexts_nr;
	ip_context_t ip_contexts[ROHC_MAX_IP_HDRS];

	/** The decoded values of TCP options */
	struct d_tcp_opts_ctxt tcp_opts;
	/* TCP TS option */
	struct rohc_lsb_decode opt_ts_req_lsb_ctxt;
	struct rohc_lsb_decode opt_ts_rep_lsb_ctxt;
	/* TCP SACK option */
	struct d_tcp_opt_sack opt_sack_blocks;  /**< The TCP SACK blocks */

};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct d_tcp_context, seq_lsb_ctxt) % 8) == 0,
               "seq_lsb_ctxt in d_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_context, seq_scaled_lsb_ctxt) % 8) == 0,
               "seq_scaled_lsb_ctxt in d_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_context, ack_lsb_ctxt) % 8) == 0,
               "ack_lsb_ctxt in d_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_context, ack_scaled_lsb_ctxt) % 8) == 0,
               "ack_scaled_lsb_ctxt in d_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_context, window_lsb_ctxt) % 8) == 0,
               "window_lsb_ctxt in d_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_context, tcp_opts) % 8) == 0,
               "tcp_opts in d_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_context, opt_ts_req_lsb_ctxt) % 8) == 0,
               "opt_ts_req_lsb_ctxt in d_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_context, opt_ts_rep_lsb_ctxt) % 8) == 0,
               "opt_ts_rep_lsb_ctxt in d_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_context, opt_sack_blocks) % 8) == 0,
               "opt_sack_blocks in d_tcp_context should be aligned on 8 bytes");
_Static_assert((offsetof(struct d_tcp_context, ip_contexts) % 8) == 0,
               "ip_contexts in d_tcp_context should be aligned on 8 bytes");
_Static_assert((sizeof(struct d_tcp_context) % 8) == 0,
               "d_tcp_context length should be multiple of 8 bytes");
#endif


/** The outer or inner IP bits extracted from ROHC headers */
struct rohc_tcp_extr_ip_bits
{
	struct rohc_lsb_field16 id;  /**< The IP-ID bits */
	struct rohc_lsb_field8 ttl_hl;  /**< The IP TTL/HL bits */

	uint8_t saddr[16];   /**< The source address bits found in static chain of
	                          IR header */
	uint8_t daddr[16];   /**< The destination address bits found in static
	                          chain of IR header */

	/** The parsed IP extension headers */
	ip_option_context_t opts[ROHC_MAX_IP_EXT_HDRS];
	uint16_t opts_len; /**< The length of the parsed IP extension headers */
	uint8_t opts_nr;  /**< The number of parsed IP extension headers */

	uint8_t proto;   /**< The protocol/next header bits found static chain
	                      of IR header or in extension header */

	uint32_t flowid:20;   /**< The IPv6 flow ID bits found in static chain of IR hdr */
	uint32_t dscp_bits:6; /**< The IP DSCP bits */
	uint32_t df:1;        /**< The DF bits found in dynamic chain of IR/IR-DYN
	                           header or in extension header */
	uint32_t unused:5;    /**< padding */

	uint8_t version:4;        /**< The version bits found in static chain of IR hdr */
	uint8_t ecn_flags_bits:2; /**< The IP ECN flag bits */
	uint8_t id_behavior:2;    /**< The IP-ID behavior bits */

	bits_nr_t ecn_flags_bits_nr;  /**< The number of IP ECN flag bits */
	bits_nr_t id_behavior_nr;     /**< The number of IP-ID behavior bits */
	bits_nr_t proto_nr;           /**< The number of protocol/next header bits */
	bits_nr_t df_nr;              /**< The number of DF bits found */
	bits_nr_t dscp_bits_nr;       /**< The number of IP DSCP bits */
	bits_nr_t flowid_nr;          /**< The number of flow label bits */
	bits_nr_t saddr_nr;           /**< The number of source address bits */

	bits_nr_t daddr_nr;           /**< The number of source address bits */
	uint8_t unused2[7];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct rohc_tcp_extr_ip_bits, id) % 8) == 0,
               "id in rohc_tcp_extr_ip_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_ip_bits, ttl_hl) % 8) == 0,
               "ttl_hl in rohc_tcp_extr_ip_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_ip_bits, saddr) % 8) == 0,
               "saddr in rohc_tcp_extr_ip_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_ip_bits, daddr) % 8) == 0,
               "daddr in rohc_tcp_extr_ip_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_ip_bits, opts) % 8) == 0,
               "opts in rohc_tcp_extr_ip_bits should be aligned on 8 bytes");
_Static_assert((sizeof(struct rohc_tcp_extr_ip_bits) % 8) == 0,
               "rohc_tcp_extr_ip_bits length should be multiple of 8 bytes");
#endif


/** The bits extracted from ROHC TCP header */
struct rohc_tcp_extr_bits
{
	/** The extracted bits of the Master Sequence Number (MSN) of the packet */
	struct rohc_lsb_field16 msn;

	/* TCP header */
	struct rohc_lsb_field32 seq;         /**< The TCP sequence number bits */
	struct rohc_lsb_field32 seq_scaled;  /**< The TCP scaled sequence number bits */
	struct rohc_lsb_field32 ack;         /**< The TCP acknowledgment number bits */
	struct rohc_lsb_field32 ack_scaled;  /**< The TCP scaled ACK number bits */
	struct rohc_lsb_field16 ack_stride;  /**< The TCP ACK stride bits */
	struct rohc_lsb_field16 window;      /**< The TCP window bits */
	struct rohc_lsb_field16 urg_ptr;     /**< The TCP Urgent pointer bits */
	uint16_t src_port;    /**< The TCP source port bits found in static chain */
	uint16_t dst_port;    /**< The TCP destination port bits in static chain */
	uint16_t tcp_check;   /**< The TCP checksum bits found in dynamic chain of
	                           IR/IR-DYN header or in irregular chain of CO header */
	uint16_t res_flags_bits:4;            /**< The TCP reserved flag bits */
	uint16_t ecn_used_bits:1;             /**< The TCP ECN used flag bits */
	uint16_t ecn_flags_bits:2;            /**< The TCP ECN flag bits */
	uint16_t urg_flag_bits:1;             /**< The TCP URG flag bits */
	uint16_t ack_flag_bits:1;             /**< The TCP ACK flag bits */
	uint16_t psh_flag_bits:1;             /**< The TCP PSH flag bits */
	uint16_t rsf_flags_bits:3;            /**< The TCP RSF flag bits */
	uint16_t unused:3;

	/** The bits of TCP options extracted from the dynamic chain, the tail of
	 * co_common/seq_8/rnd_8 packets, or the irregular chain */
	struct d_tcp_opts_ctxt tcp_opts;

	/** The extracted bits related to the IP headers */
	struct rohc_tcp_extr_ip_bits ip[ROHC_MAX_IP_HDRS];
	uint8_t ip_nr;   /**< The number of parsed IP headers */

	bits_nr_t src_port_nr;   /**< The number of TCP source port bits */
	bits_nr_t dst_port_nr;   /**< The number of TCP destination port bits */
	bits_nr_t res_flags_bits_nr;         /**< The number of TCP reserved flag bits */
	bits_nr_t ecn_used_bits_nr;          /**< The number of ECN used flag bits */
	bits_nr_t ecn_flags_bits_nr;         /**< The number of TCP ECN flag bits */
	bits_nr_t urg_flag_bits_nr;          /**< The number of TCP URG flag bits */
	bits_nr_t ack_flag_bits_nr;          /**< The number of TCP ACK flag bits */

	bits_nr_t psh_flag_bits_nr;          /**< The number of TCP PSG flag bits */
	bits_nr_t rsf_flags_bits_nr;         /**< The number of TCP RSF flag bits */

	/** The base context for Context Replication (CR) */
	rohc_cid_t cr_base_cid;
	/** Whether Context Replication (CR) is used */
	bool do_ctxt_replication;

	/** Whether TTL/HL of outer IP headers is included in the dynamic chain */
	bool ttl_dyn_chain_flag;
	/** Whether TTL/HL of outer IP headers is included in the irregular chain */
	bool ttl_irreg_chain_flag;

	uint8_t unused2;
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct rohc_tcp_extr_bits, msn) % 8) == 0,
               "msn in rohc_tcp_extr_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_bits, seq) % 8) == 0,
               "seq in rohc_tcp_extr_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_bits, seq_scaled) % 8) == 0,
               "seq_scaled in rohc_tcp_extr_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_bits, ack) % 8) == 0,
               "ack in rohc_tcp_extr_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_bits, ack_scaled) % 8) == 0,
               "ack_scaled in rohc_tcp_extr_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_bits, tcp_opts) % 8) == 0,
               "tcp_opts in rohc_tcp_extr_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_bits, ip) % 8) == 0,
               "ip in rohc_tcp_extr_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_bits, ip_nr) % 8) == 0,
               "ip_nr in rohc_tcp_extr_bits should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_extr_bits, psh_flag_bits_nr) % 8) == 0,
               "psh_flag_bits_nr in rohc_tcp_extr_bits should be aligned on 8 bytes");
_Static_assert((sizeof(struct rohc_tcp_extr_bits) % 8) == 0,
               "rohc_tcp_extr_bits length should be multiple of 8 bytes");
#endif


/** The IP values decoded from the extracted ROHC bits */
struct rohc_tcp_decoded_ip_values
{
	uint8_t saddr[16];   /**< The decoded source address field */
	uint8_t daddr[16];   /**< The decoded destination address field */

	/** The decoded IP extension headers */
	ip_option_context_t opts[ROHC_MAX_IP_EXT_HDRS];
	uint16_t opts_len; /**< The length of the decoded IP extension headers */
	uint8_t opts_nr;   /**< The number of decoded IP extension headers */

	uint8_t ttl;         /**< The decoded TTL/HL field */
	uint16_t id;         /**< The decoded IP-ID field (IPv4 only) */
	uint8_t proto;       /**< The decoded protocol/NH field */

	uint8_t df:1;        /**< The decoded DF field (IPv4 only) */
	uint8_t nbo:1;       /**< The decoded NBO field (IPv4 only) */
	uint8_t rnd:1;       /**< The decoded RND field (IPv4 only) */
	uint8_t id_behavior:2; /**< The decoded IP-ID behavior (Ipv4 only) */
	uint8_t unused:3;

	uint32_t flowid:20;  /**< The decoded flow ID field (IPv6 only) */
	uint32_t ecn_flags:2; /**< The decoded ECN flags */
	uint32_t dscp:6;      /**< The decoded DSCP field */
	uint32_t version:4;   /**< The decoded version field */

	uint8_t unused2[4];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct rohc_tcp_decoded_ip_values, saddr) % 8) == 0,
               "saddr in rohc_tcp_decoded_ip_values should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_decoded_ip_values, daddr) % 8) == 0,
               "daddr in rohc_tcp_decoded_ip_values should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_decoded_ip_values, opts) % 8) == 0,
               "opts in rohc_tcp_decoded_ip_values should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_decoded_ip_values, opts_len) % 8) == 0,
               "opts_len in rohc_tcp_decoded_ip_values should be aligned on 8 bytes");
_Static_assert((sizeof(struct rohc_tcp_decoded_ip_values) % 8) == 0,
               "rohc_tcp_decoded_ip_values length should be multiple of 8 bytes");
#endif


/** The values decoded from the bits extracted from ROHC TCP header */
struct rohc_tcp_decoded_values
{
	/* TCP TS option */
	uint32_t opt_ts_req;  /**< The echo request value of the TCP TS option */
	uint32_t opt_ts_rep;  /**< The echo reply value of the TCP TS option */

	/* TCP sequence & acknowledgment numbers */
	uint32_t seq_num;          /**< The TCP sequence number */
	uint32_t seq_num_scaled;   /**< The scaled TCP sequence number */
	uint32_t seq_num_residue;  /**< The residue of the scaled TCP sequence number */
	uint32_t ack_num;          /**< The TCP acknowledgment number */
	uint32_t ack_num_scaled;   /**< The scaled TCP acknowledgment number */
	uint16_t ack_num_residue;  /**< The residue of the scaled TCP ACK number */
	uint16_t ack_stride;       /**< The ACK stride */

	/** The Master Sequence Number (MSN) of the packet */
	uint16_t msn;

	/* TCP window, checksum and Urgent pointer */
	uint16_t window;     /**< The TCP window */
	uint16_t tcp_check;  /**< The TCP checksum */
	uint16_t urg_ptr;    /**< The TCP Urgent pointer */

	/* TCP source & destination ports */
	uint16_t src_port;   /**< The TCP source port */
	uint16_t dst_port;   /**< The TCP destination port */

	/* TCP flags */
	uint8_t ecn_used:1;        /**< Whether the TCP ECN flags are used */
	uint8_t urg_flag:1;        /**< The TCP URG flag */
	uint8_t ack_flag:1;        /**< The TCP ACK flag */
	uint8_t psh_flag:1;        /**< The TCP PSH flag */
	uint8_t res_flags:4;  /**< The TCP reserved flags */
	uint8_t ecn_flags:2;  /**< The TCP ECN flags */
	uint8_t rsf_flags:3;  /**< The TCP RSF flags */

	/** Whether TTL/HL of outer IP headers is included in the dynamic chain */
	uint8_t ttl_dyn_chain_flag:1;
	/** Whether TTL/HL of outer IP headers is included in the irregular chain */
	uint8_t ttl_irreg_chain_flag:1;

	/** Whether Context Replication (CR) is used */
	uint8_t do_ctxt_replication:1;
	/** The base context for Context Replication (CR) */
	rohc_cid_t cr_base_cid;

	/** The decoded values of TCP options */
	struct d_tcp_opts_ctxt tcp_opts;
	/* TCP SACK option */
	struct d_tcp_opt_sack opt_sack_blocks;  /**< The TCP SACK blocks */

	/** The decoded values related to the IP headers */
	struct rohc_tcp_decoded_ip_values ip[ROHC_MAX_IP_HDRS];
	uint8_t ip_nr;  /**< The number of the decoded IP headers */
	uint8_t unused[7];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct rohc_tcp_decoded_values, opt_ts_req) % 8) == 0,
               "opt_ts_req in rohc_tcp_decoded_values should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_decoded_values, tcp_opts) % 8) == 0,
               "tcp_opts in rohc_tcp_decoded_values should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_decoded_values, opt_sack_blocks) % 8) == 0,
               "opt_sack_blocks in rohc_tcp_decoded_values should be aligned on 8 bytes");
_Static_assert((offsetof(struct rohc_tcp_decoded_values, ip) % 8) == 0,
               "ip in rohc_tcp_decoded_values should be aligned on 8 bytes");
_Static_assert((sizeof(struct rohc_tcp_decoded_values) % 8) == 0,
               "rohc_tcp_decoded_values length should be multiple of 8 bytes");
#endif


#endif /* ROHC_DECOMP_TCP_DEFINES_H */

