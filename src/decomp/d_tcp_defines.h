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

#include "crc.h"
#include "ip.h"
#include "interval.h"
#include "protocols/tcp.h"
#include "schemes/decomp_wlsb.h"
#include "schemes/tcp_ts.h"
#include "schemes/tcp_sack.h"

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
#define ROHC_TCP_MAX_IPV6_EXT_HDRS  10U

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
	ipv6_option_context_t opts[ROHC_TCP_MAX_IPV6_EXT_HDRS];

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

	/** The LSB decoding context of innermost IP-ID */
	struct rohc_lsb_decode *ip_id_lsb_ctxt;
	/** The LSB decoding context of innermost TTL/HL */
	struct rohc_lsb_decode *ttl_hl_lsb_ctxt;

	/* TCP static part */
	uint16_t tcp_src_port; /**< The TCP source port */
	uint16_t tcp_dst_port; /**< The TCP dest port */

	uint32_t seq_num_residue;
	struct rohc_lsb_decode *seq_lsb_ctxt;
	struct rohc_lsb_decode *seq_scaled_lsb_ctxt;

	uint16_t ack_stride;
	uint32_t ack_num_residue;
	struct rohc_lsb_decode *ack_lsb_ctxt;
	struct rohc_lsb_decode *ack_scaled_lsb_ctxt;

	/* TCP flags */
	uint8_t res_flags:4;  /**< The TCP reserved flags */
	bool ecn_used;        /**< Whether ECN flag is used */
	uint8_t ecn_flags:2;  /**< The TCP ECN flags */
	bool urg_flag;        /**< The TCP URG flag */
	bool ack_flag;        /**< The TCP ACK flag */
	uint8_t rsf_flags:3;  /**< The TCP RSF flag */

	/** The LSB decoding context of TCP window */
	struct rohc_lsb_decode *window_lsb_ctxt;

	// Table of TCP options
	uint8_t tcp_options_list[ROHC_TCP_OPTS_MAX];   // see RFC4996 page 27
	uint8_t tcp_options_offset[ROHC_TCP_OPTS_MAX];
	uint16_t tcp_option_maxseg;
	uint8_t tcp_option_window;
	/** The structure of the list of TCP options */
	uint8_t tcp_opts_list_struct[ROHC_TCP_OPTS_MAX];

	struct tcp_option_timestamp tcp_opt_ts;
	struct rohc_lsb_decode *opt_ts_req_lsb_ctxt;
	struct rohc_lsb_decode *opt_ts_rep_lsb_ctxt;

	uint8_t tcp_opt_sack_length;
	uint8_t tcp_opt_sackblocks[sizeof(sack_block_t) * TCP_SACK_BLOCKS_MAX_NR];
	uint8_t tcp_options_free_offset;
#define MAX_TCP_OPT_SIZE 64
	uint8_t tcp_options_values[MAX_TCP_OPT_SIZE];

	size_t ip_contexts_nr;
	ip_context_t ip_contexts[ROHC_TCP_MAX_IP_HDRS];


	/*
	 * for correction upon CRC failure
	 */
	/* TODO: duplicated from rfc3095_ctxt, to be merged in rohc_decomp_ctxt */

	/** The algorithm being used for correction CRC failure */
	rohc_decomp_crc_corr_t crc_corr;
	/** Correction counter (see e and f in 5.3.2.2.4 of the RFC 3095) */
	size_t correction_counter;
	/** The arrival time of the current packet */
	struct rohc_ts cur_arrival_time;
};


/** The outer or inner IP bits extracted from ROHC headers */
struct rohc_tcp_extr_ip_bits
{
	uint8_t version:4;  /**< The version bits found in static chain of IR header */

	uint8_t dscp_bits:6;         /**< The IP DSCP bits */
	size_t dscp_bits_nr;         /**< The number of IP DSCP bits */
	uint8_t ecn_flags_bits:2;    /**< The IP ECN flag bits */
	size_t ecn_flags_bits_nr;    /**< The number of IP ECN flag bits */

	uint8_t id_behavior:2;       /**< The IP-ID behavior bits */
	size_t id_behavior_nr;       /**< The number of IP-ID behavior bits */
	struct rohc_lsb_field16 id;  /**< The IP-ID bits */

	uint8_t df:1;    /**< The DF bits found in dynamic chain of IR/IR-DYN
	                      header or in extension header */
	size_t df_nr;    /**< The number of DF bits found */

	struct rohc_lsb_field8 ttl_hl;  /**< The IP TTL/HL bits */
	uint8_t proto;   /**< The protocol/next header bits found static chain
	                      of IR header or in extension header */
	size_t proto_nr; /**< The number of protocol/next header bits */

	uint32_t flowid:20;  /**< The IPv6 flow ID bits found in static chain of
	                          IR header */
	size_t flowid_nr;    /**< The number of flow label bits */

	uint8_t saddr[16];   /**< The source address bits found in static chain of
	                          IR header */
	size_t saddr_nr;     /**< The number of source address bits */

	uint8_t daddr[16];   /**< The destination address bits found in static
	                          chain of IR header */
	size_t daddr_nr;     /**< The number of source address bits */

	/** The parsed IP extension headers (IPv6 only) */
	ipv6_option_context_t opts[ROHC_TCP_MAX_IPV6_EXT_HDRS];
	size_t opts_nr;  /**< The number of parsed IP extension headers */
	size_t opts_len; /**< The length of the parsed IP extension headers */
};


/** The bits extracted from ROHC TCP header */
struct rohc_tcp_extr_bits
{
	/** The extracted bits related to the IP headers */
	struct rohc_tcp_extr_ip_bits ip[ROHC_TCP_MAX_IP_HDRS];
	size_t ip_nr;   /**< The number of parsed IP headers */

	/** The extracted bits of the Master Sequence Number (MSN) of the packet */
	struct rohc_lsb_field16 msn;

	/** Whether at least one of IP headers changed its TTL/HL */
	bool ttl_irregular_chain_flag;

	/* TCP header */
	uint16_t src_port;    /**< The TCP source port bits found in static chain */
	size_t src_port_nr;   /**< The number of TCP source port bits */
	uint16_t dst_port;    /**< The TCP destination port bits in static chain */
	size_t dst_port_nr;   /**< The number of TCP destination port bits */
	struct rohc_lsb_field32 seq;         /**< The TCP sequence number bits */
	struct rohc_lsb_field32 seq_scaled;  /**< The TCP scaled sequence number bits */
	struct rohc_lsb_field32 ack;         /**< The TCP acknowledgment number bits */
	struct rohc_lsb_field16 ack_stride;  /**< The TCP ACK stride bits */
	struct rohc_lsb_field32 ack_scaled;  /**< The TCP scaled ACK number bits */
	uint8_t ecn_used_bits;               /**< The TCP ECN used flag bits */
	size_t ecn_used_bits_nr;             /**< The number of ECN used flag bits */
	uint8_t res_flags_bits;              /**< The TCP reserved flag bits */
	size_t res_flags_bits_nr;            /**< The number of TCP reserved flag bits */
	uint8_t ecn_flags_bits;              /**< The TCP ECN flag bits */
	size_t ecn_flags_bits_nr;            /**< The number of TCP ECN flag bits */
	uint8_t urg_flag_bits;               /**< The TCP URG flag bits */
	size_t urg_flag_bits_nr;             /**< The number of TCP URG flag bits */
	uint8_t ack_flag_bits;               /**< The TCP ACK flag bits */
	size_t ack_flag_bits_nr;             /**< The number of TCP ACK flag bits */
	uint8_t psh_flag_bits;               /**< The TCP PSH flag bits */
	size_t psh_flag_bits_nr;             /**< The number of TCP PSG flag bits */
	uint8_t rsf_flags_bits;              /**< The TCP RSF flag bits */
	size_t rsf_flags_bits_nr;            /**< The number of TCP RSF flag bits */
	struct rohc_lsb_field16 window;      /**< The TCP window bits */
	uint16_t tcp_check;   /**< The TCP checksum bits found in dynamic chain of
	                           IR/IR-DYN header or in irregular chain of CO header */
	struct rohc_lsb_field16 urg_ptr;     /**< The TCP Urgent pointer bits */

	/* CRC */
	rohc_crc_type_t crc_type; /**< The type of CRC that protect the ROHC header */
	uint8_t crc;              /**< The CRC bits found in ROHC header */
	size_t crc_nr;            /**< The number of CRC bits found in ROHC header */

	/* Whether the list of TCP options is present in co_common/seq_8/rnd_8 packets */
	bool is_list_present;

	/** Whether the content of TCP options was transmitted or not */
	bool is_tcp_opts_list_item_present[ROHC_TCP_OPTS_MAX];
	/** The lengths of the TCP options that are transmitted */
	size_t tcp_opts_list_item_uncomp_length[ROHC_TCP_OPTS_MAX];

	struct d_tcp_opt_ts opt_ts;     /**< The parsed TCP TimeStamp option */
	struct d_tcp_opt_sack opt_sack; /**< The parsed TCP SACK option */

	/* TODO: do not decode TCP options other than TS/SACK before parsing is over */
#define MAX_TCP_DATA_OFFSET_WORDS  ((1 << 4) - 1)
#define MAX_TCP_DATA_OFFSET_BYTES  (MAX_TCP_DATA_OFFSET_WORDS * sizeof(uint32_t))
#define MAX_TCP_OPTIONS_LEN        (MAX_TCP_DATA_OFFSET_BYTES - sizeof(tcphdr_t))
	size_t opts_len;                    /**< The length of the parsed TCP options */
	uint8_t opts[MAX_TCP_OPTIONS_LEN];  /**< The parsed TCP options */
};


/** The IP values decoded from the extracted ROHC bits */
struct rohc_tcp_decoded_ip_values
{
	uint8_t version:4;   /**< The decoded version field */
	uint8_t ecn_flags:2; /**< The decoded ECN flags */
	uint8_t dscp:6;      /**< The decoded DSCP field */
	tcp_ip_id_behavior_t id_behavior; /**< The decoded IP-ID behavior (Ipv4 only) */
	uint16_t id;         /**< The decoded IP-ID field (IPv4 only) */
	uint8_t df:1;        /**< The decoded DF field (IPv4 only) */
	uint8_t ttl;         /**< The decoded TTL/HL field */
	uint8_t proto;       /**< The decoded protocol/NH field */
	uint8_t nbo:1;       /**< The decoded NBO field (IPv4 only) */
	uint8_t rnd:1;       /**< The decoded RND field (IPv4 only) */
	uint8_t sid:1;       /**< The decoded SID field (IPv4 only) */
	uint32_t flowid:20;  /**< The decoded flow ID field (IPv6 only) */
	uint8_t saddr[16];   /**< The decoded source address field */
	uint8_t daddr[16];   /**< The decoded destination address field */

	/** The decoded IP extension headers (IPv6 only) */
	ipv6_option_context_t opts[ROHC_TCP_MAX_IPV6_EXT_HDRS];
	size_t opts_nr;  /**< The number of decoded IP extension headers */
	size_t opts_len; /**< The length of the decoded IP extension headers */
};


/** The values decoded from the bits extracted from ROHC TCP header */
struct rohc_tcp_decoded_values
{
	/** The decoded values related to the IP headers */
	struct rohc_tcp_decoded_ip_values ip[ROHC_TCP_MAX_IP_HDRS];
	size_t ip_nr;  /**< The number of the decoded IP headers */

	/** The Master Sequence Number (MSN) of the packet */
	uint16_t msn;

	/* TCP source & destination ports */
	uint16_t src_port;        /**< The TCP source port */
	uint16_t dst_port;        /**< The TCP destination port */

	/* TCP sequence & acknowledgment numbers */
	uint32_t seq_num;          /**< The TCP sequence number */
	uint32_t seq_num_scaled;   /**< The scaled TCP sequence number */
	uint32_t seq_num_residue;  /**< The residue of the scaled TCP sequence number */
	uint32_t ack_num;          /**< The TCP acknowledgment number */
	uint32_t ack_num_scaled;   /**< The scaled TCP acknowledgment number */
	uint32_t ack_num_residue;  /**< The residue of the scaled TCP ACK number */
	uint32_t ack_stride;       /**< The ACK stride */

	/* TCP flags */
	bool ecn_used;        /**< Whether the TCP ECN flags are used */
	uint8_t res_flags:4;  /**< The TCP reserved flags */
	uint8_t ecn_flags:2;  /**< The TCP ECN flags */
	bool urg_flag;        /**< The TCP URG flag */
	bool ack_flag;        /**< The TCP ACK flag */
	bool psh_flag;        /**< The TCP PSH flag */
	uint8_t rsf_flags:3;  /**< The TCP RSF flags */

	/* TCP window, checksum and Urgent pointer */
	uint16_t window;     /**< The TCP window */
	uint16_t tcp_check;  /**< The TCP checksum */
	uint16_t urg_ptr;    /**< The TCP Urgent pointer */

	/* TCP TS option */
	bool opt_ts_present;  /**< Whether the TCP TS option is present */
	uint32_t opt_ts_req;  /**< The echo request value of the TCP TS option */
	uint32_t opt_ts_rep;  /**< The echo reply value of the TCP TS option */
	/** TCP SACK option */
	uint8_t opt_sack[sizeof(sack_block_t) * TCP_SACK_BLOCKS_MAX_NR];
	uint8_t opt_sack_length;  /**< The length of the TCP SACK option (in bytes) */
	/* TODO: do not decode TCP options other than TS/SACK before parsing is over */
	uint8_t opts[MAX_TCP_OPTIONS_LEN]; /**< The uncompressed TCP options */
	size_t opts_len;  /**< The length of the uncompressed TCP options */
};

#endif /* ROHC_DECOMP_TCP_DEFINES_H */

