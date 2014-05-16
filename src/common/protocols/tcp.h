/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2013 Viveris Technologies
 * Copyright 2012 WBX
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

/**
 * @file   tcp.h
 * @brief  TCP header description.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_PROTOCOLS_TCP_H
#define ROHC_PROTOCOLS_TCP_H

#include <stdint.h>

#ifdef __KERNEL__
#	include <endian.h>
#else
#	include "config.h" /* for WORDS_BIGENDIAN */
#endif


/* See RFC4996 page 37-40 */

#define ROHC_PACKET_TYPE_IR      0xFD
#define ROHC_PACKET_TYPE_IR_DYN  0xF8

/**
 * @brief Define the IPv6 option header.
 *
 */

typedef struct __attribute__((packed)) ipv6_opt
{
	uint8_t next_header;
	uint8_t length;
	uint8_t value[1];
} ipv6_opt_t;

/**
 * @brief Define the static part of IPv6 option header.
 *
 */

typedef struct __attribute__((packed)) ip_opt_static
{
	uint8_t next_header;
	uint8_t length;
} ip_opt_static_t;

/**
 * @brief Define the dynamic part of IPv6 option header.
 *
 */

typedef struct __attribute__((packed)) ip_opt_dynamic
{
	uint8_t value[1];
} ip_opt_dynamic_t;

/**
 * @brief Define the IPv6 Destination options header
 *
 */

typedef struct __attribute__((packed)) ip_dest_opt
{
	uint8_t next_header;
	uint8_t length;
	uint8_t value[1];
} ip_dest_opt_t;

/**
 * @brief Define the static part of IPv6 Destination option header.
 *
 */

typedef struct __attribute__((packed)) ip_dest_opt_static
{
	uint8_t next_header;
	uint8_t length;
} ip_dest_opt_static_t;

/**
 * @brief Define the dynamic part of IPv6 Destination option header.
 *
 */

typedef struct __attribute__((packed)) ip_dest_opt_dynamic
{
	uint8_t value[1];
} ip_dest_opt_dynamic_t;

/**
 * @brief Define the IPv6 Hop-by-Hop option header.
 *
 */

typedef struct __attribute__((packed)) ip_hop_opt
{
	uint8_t next_header;
	uint8_t length;
	uint8_t value[1];
} ip_hop_opt_t;

/**
 * @brief Define the static part of IPv6 Hop-by-Hop option header.
 *
 */

typedef struct __attribute__((packed)) ip_hop_opt_static
{
	uint8_t next_header;
	uint8_t length;
} ip_hop_opt_static_t;

/**
 * @brief Define the dynamic part of IPv6 Hop-by-Hop option header.
 *
 */

typedef struct __attribute__((packed)) ip_hop_opt_dynamic
{
	uint8_t value[1];
} ip_hop_opt_dynamic_t;

/**
 * @brief Define the IPv6 Routing option header.
 *
 */

typedef struct __attribute__((packed)) ip_rout_opt
{
	uint8_t next_header;
	uint8_t length;
	uint8_t value[1];
} ip_rout_opt_t;

/**
 * @brief Define the static part of IPv6 Routing option header.
 *
 */

typedef struct __attribute__((packed)) ip_rout_opt_static
{
	uint8_t next_header;
	uint8_t length;
	uint8_t value[1];
} ip_rout_opt_static_t;

/**
 * @brief Define the IPv6 GRE option header.
 *
 * See RFC5225 page 55
 */

typedef struct __attribute__((packed)) ip_gre_opt
{
#if WORDS_BIGENDIAN != 1
	uint8_t reserved2 : 4;
	uint8_t s_flag : 1;
	uint8_t k_flag : 1;
	uint8_t r_flag : 1;
	uint8_t c_flag : 1;

	uint8_t version : 3;
	uint8_t reserved1 : 5;
#else
	uint16_t c_flag : 1;
	uint16_t r_flag : 1;
	uint16_t k_flag : 1;
	uint16_t s_flag : 1;
	uint16_t reserved0 : 9;
	uint16_t version : 3;
#endif
	uint16_t protocol;
	uint32_t datas[1];
} ip_gre_opt_t;

/**
 * @brief Define the static part of IPv6 GRE option header.
 *
 */

typedef struct __attribute__((packed)) ip_gre_opt_static
{
#if WORDS_BIGENDIAN != 1
	uint8_t padding : 4;
	uint8_t s_flag : 1;
	uint8_t k_flag : 1;
	uint8_t c_flag : 1;
	uint8_t protocol : 1;
#else
	uint8_t protocol : 1;
	uint8_t c_flag : 1;
	uint8_t k_flag : 1;
	uint8_t s_flag : 1;
	uint8_t padding : 4;
#endif
	uint8_t options[0];     // if k_flag
} ip_gre_opt_static_t;

/**
 * @brief Define the IPv6 MIME option header.
 *
 */

typedef struct __attribute__((packed)) ip_mime_opt
{
	uint8_t next_header;
#if WORDS_BIGENDIAN != 1
	uint8_t res_bits : 7;
	uint8_t s_bit : 1;
#else
	uint8_t s_bit : 1;
	uint8_t res_bits : 7;
#endif
	uint16_t checksum;
	uint32_t orig_dest;
	uint32_t orig_src;         // if s_bit set
} ip_mime_opt_t;

/**
 * @brief Define the static part of IPv6 MIME option header.
 *
 */

typedef struct __attribute__((packed)) ip_mime_opt_static
{
	uint8_t next_header;
#if WORDS_BIGENDIAN != 1
	uint8_t res_bits : 7;
	uint8_t s_bit : 1;
#else
	uint8_t s_bit : 1;
	uint8_t res_bits : 7;
#endif
	uint32_t orig_dest;
	uint32_t orig_src;         // if s_bit set
} ip_mime_opt_static_t;

/**
 * @brief Define the IPv6 Authentication option header.
 *
 */

typedef struct __attribute__((packed)) ip_ah_opt
{
	uint8_t next_header;
	uint8_t length;
	uint16_t res_bits;
	uint32_t spi;
	uint32_t sequence_number;
	uint32_t auth_data[1];
} ip_ah_opt_t;

/**
 * @brief Define the static part of IPv6 Authentication option header.
 *
 */

typedef struct __attribute__((packed)) ip_ah_opt_static
{
	uint8_t next_header;
	uint8_t length;
	uint32_t spi;
} ip_ah_opt_static_t;

/**
 * @brief Define the dynamic part of IPv6 Authentication option header.
 *
 */

typedef struct __attribute__((packed)) ip_ah_opt_dynamic
{
	uint32_t sequence_number;
	uint32_t auth_data[0];
} ip_ah_opt_dynamic_t;

/**
 * @brief Define the common IP v4/v6 header.
 *
 */

typedef struct __attribute__((packed)) base_header_ip_vx
{
#if WORDS_BIGENDIAN != 1
	uint8_t reserved : 4;
	uint8_t version : 4;
#else
	uint8_t version : 4;
	uint8_t reserved : 4;
#endif
} base_header_ip_vx_t;

/**
 * @brief Define the IPv4 header.
 *
 * See RFC4996 page 77
 */

typedef struct __attribute__((packed)) base_header_ip_v4
{
#if WORDS_BIGENDIAN != 1
	uint8_t header_length : 4;
	uint8_t version : 4;
	uint8_t ip_ecn_flags : 2;
	uint8_t dscp : 6;
#else
	uint8_t version : 4;
	uint8_t header_length : 4;
	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;
#endif
	uint16_t length;
	uint16_t ip_id;
#if WORDS_BIGENDIAN != 1
	uint8_t frag_offset1 : 5;
	uint8_t mf : 1;
	uint8_t df : 1;
	uint8_t rf : 1;
	uint8_t frag_offset2;
#else
	uint16_t rf : 1;
	uint16_t df : 1;
	uint16_t mf : 1;
	uint16_t frag_offset : 13;
#endif
	uint8_t ttl_hopl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_addr;
	uint32_t dest_addr;
	// extension_headers
} base_header_ip_v4_t;

/**
 * @brief Define the IP v6 header.
 *
 * See RFC4996 page 78
 */

typedef struct __attribute__((packed)) base_header_ip_v6
{
#if WORDS_BIGENDIAN != 1
	uint8_t dscp1 : 4;
	uint8_t version : 4;
	uint8_t flow_label1 : 4;
	uint8_t ip_ecn_flags : 2;
	uint8_t dscp2 : 2;
#else
	uint16_t version : 4;
	uint16_t dscp1:4;
	uint16_t dscp2:2;
	uint16_t ip_ecn_flags : 2;
	uint16_t flow_label1 : 4;
#endif
	uint16_t flow_label2;
	uint16_t payload_length;
	uint8_t next_header;
	uint8_t ttl_hopl;
	uint32_t src_addr[4];
	uint32_t dest_addr[4];
	// extension_headers
} base_header_ip_v6_t;

#define DSCP_V6(ptr)       (((ptr)->dscp1 << 2) | (ptr)->dscp2)
#define FLOW_LABEL_V6(ptr) (((ptr->flow_label1) << 16) | ptr->flow_label2)

/**
 * @brief Define the IP v4 static part.
 *
 * See RFC4996 page 62
 */

typedef struct __attribute__((packed)) ipv4_static
{
#if WORDS_BIGENDIAN != 1
	uint8_t reserved : 7;
	uint8_t version_flag : 1;
#else
	uint8_t version_flag : 1;
	uint8_t reserved : 7;
#endif
	uint8_t protocol;
	uint32_t src_addr;
	uint32_t dst_addr;
} ipv4_static_t;


/** The different IP-ID behaviors */
typedef enum
{
	IP_ID_BEHAVIOR_SEQ       = 0, /**< IP-ID increases */
	IP_ID_BEHAVIOR_SEQ_SWAP  = 1, /**< IP-ID increases in little endian */
	IP_ID_BEHAVIOR_RAND      = 2, /**< IP-ID is random */
	IP_ID_BEHAVIOR_ZERO      = 3, /**< IP-ID is constant zero */
} tcp_ip_id_behavior_t;


/**
 * @brief Define the IP v4 dynamic part without ip_id.
 *
 * See RFC4996 page 62
 */

typedef struct __attribute__((packed)) ipv4_dynamic1
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_id_behavior : 2;
	uint8_t df : 1;
	uint8_t reserved : 5;
	uint8_t ip_ecn_flags : 2;
	uint8_t dscp : 6;
#else
	uint8_t reserved : 5;
	uint8_t df : 1;
	uint8_t ip_id_behavior : 2;
	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;
#endif
	uint8_t ttl_hopl;
} ipv4_dynamic1_t;

/**
 * @brief Define the IP v4 dynamic part with ip_id field.
 *
 * See RFC4996 page 62
 */

typedef struct __attribute__((packed)) ipv4_dynamic2
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_id_behavior : 2;
	uint8_t df : 1;
	uint8_t reserved : 5;
	uint8_t ip_ecn_flags : 2;
	uint8_t dscp : 6;
#else
	uint8_t reserved : 5;
	uint8_t df : 1;
	uint8_t ip_id_behavior : 2;
	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;
#endif
	uint8_t ttl_hopl;
	uint16_t ip_id;
} ipv4_dynamic2_t;

/**
 * @brief Define the IP v4 replicate part.
 *
 * See RFC4996 page 63
 */

typedef struct __attribute__((packed)) ipv4_replicate
{
#if WORDS_BIGENDIAN != 1
	uint8_t df : 1;
	uint8_t ttl_flag : 1;
	uint8_t ip_id_behavior : 2;
	uint8_t reserved : 4;
	uint8_t ip_ecn_flags : 2;
	uint8_t dscp : 6;
#else
	uint8_t reserved : 4;
	uint8_t ip_id_behavior : 2;
	uint8_t ttl_flag : 1;
	uint8_t df : 1;
	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;
#endif
//  uint16_t	ip_id;
//  uint8_t	ttl_hopl;
} ipv4_replicate_t;

/**
 * @brief Define the IP v6 static part, null flow_label encoded with 1 bit
 *
 * See RFC4996 page 58
 */

typedef struct __attribute__((packed)) ipv6_static1
{
#if WORDS_BIGENDIAN != 1
	uint8_t reserved2 : 4;
	uint8_t flow_label_enc_discriminator : 1;
	uint8_t reserved1 : 2;
	uint8_t version_flag : 1;
#else
	uint8_t version_flag : 1;
	uint8_t reserved1 : 2;
	uint8_t flow_label_enc_discriminator : 1;
	uint8_t reserved2 : 4;
#endif
	uint8_t next_header;
	uint32_t src_addr[4];
	uint32_t dst_addr[4];
} ipv6_static1_t;

/**
 * @brief Define the IP v6 static part, flow_label encoded with 1+20 bits
 *
 * See RFC4996 page 59
 */

typedef struct __attribute__((packed)) ipv6_static2
{
#if WORDS_BIGENDIAN != 1
	uint8_t flow_label1 : 4;
	uint8_t flow_label_enc_discriminator : 1;
	uint8_t reserved : 2;
	uint8_t version_flag : 1;
#else
	uint8_t version_flag : 1;
	uint8_t reserved : 2;
	uint8_t flow_label_enc_discriminator : 1;
	uint8_t flow_label1 : 4;
#endif
	uint16_t flow_label2;
	uint8_t next_header;
	uint32_t src_addr[4];
	uint32_t dst_addr[4];
} ipv6_static2_t;

/**
 * @brief Define the IP v6 dynamic part.
 *
 * See RFC4996 page 59
 */

typedef struct __attribute__((packed)) ipv6_dynamic
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_ecn_flags : 2;
	uint8_t dscp : 6;
#else
	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;
#endif
	uint8_t ttl_hopl;
} ipv6_dynamic_t;

/**
 * @brief Define the IP v6 replicate part, flow_label encoded with 5 bits
 *
 * See RFC4996 page 59
 */

typedef struct __attribute__((packed)) ipv6_replicate1
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_ecn_flags : 2;
	uint8_t dscp : 6;
	uint8_t flow_label : 5;
	uint8_t reserved : 3;
#else
	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;
	uint8_t reserved : 3;
	uint8_t flow_label : 5;
#endif
} ipv6_replicate1_t;

/**
 * @brief Define the IP v6 replicate part, flow_label encoded with 21 bits
 *
 * See RFC4996 page 59
 */

typedef struct __attribute__((packed)) ipv6_replicate2
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_ecn_flags : 2;
	uint8_t dscp : 6;
	uint8_t flow_label1 : 5;
	uint8_t reserved : 3;
#else
	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;
	uint8_t reserved : 3;
	uint8_t flow_label1 : 5;
#endif
	uint16_t flow_label2;
} ipv6_replicate2_t;

/**
 * @brief Define the IP v6 extension
 *
 */

/* The high-order 3 bits of the option type define the behavior
 * when processing an unknown option and whether or not the option
 * content changes in flight.
 */

typedef struct  __attribute__((packed)) ipv6_extension
{
	uint8_t next_header;
	uint8_t extension_length;
	uint8_t datas[1];
} ipv6_extension_t;

/**
 * @brief Define the Selective Acknowlegment TCP option
 *
 * See RFC2018 for TCP Selective Acknowledgement Options
 * See RFC4996 page 66
 */

typedef struct __attribute__((packed))
{
	uint32_t block_start;
	uint32_t block_end;
} sack_block_t;

/**
 * @brief Define the TCP header
 *
 * See RFC4996 page 72/73
 */

typedef struct __attribute__((packed)) tcphdr
{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
#if WORDS_BIGENDIAN != 1
	uint8_t res_flags : 4;
	uint8_t data_offset : 4;
	uint8_t rsf_flags : 3;
	uint8_t psh_flag : 1;
	uint8_t ack_flag : 1;
	uint8_t urg_flag : 1;
	uint8_t ecn_flags : 2;
#else
	uint8_t data_offset : 4;
	uint8_t res_flags : 4;
	uint8_t ecn_flags : 2;
	uint8_t urg_flag : 1;
	uint8_t ack_flag : 1;
	uint8_t psh_flag : 1;
	uint8_t rsf_flags : 3;
#endif
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
	uint8_t options[0];          /**< The beginning of the TCP options */
} tcphdr_t;


/** The largest index that may be used to identify one TCP option */
#define MAX_TCP_OPTION_INDEX 15U

/**
 * @brief The maximum of TCP options
 *
 * One TCP header may contain up to 40 bytes of options, so it may contain
 * up 40 1-byte options, so the ROHC (de)compressors should expect such TCP
 * packets. However the m field in the compressed list of TCP options (see
 * RFC 6846, section 6.3.3 for more details) cannot be larger than 15, so
 * restrict the number of TCP options that value. One TCP packet with more
 * than 15 TCP options will be compressed with the IP-only profile.
 * */
#define ROHC_TCP_OPTS_MAX  15U


/** The Timestamp option of the TCP header */
struct tcp_option_timestamp
{
	uint32_t ts;        /**< The timestamp value */
	uint32_t ts_reply;  /**< The timestamp echo reply value */
} __attribute__((packed));


/**
 * @brief Define the RSF flags
 *
 */

#define RSF_RST_ONLY  0x04
#define RSF_SYN_ONLY  0x02
#define RSF_FIN_ONLY  0x01
#define RSF_NONE      0x00

/**
 * @brief Define the TCP static part.
 *
 * See RFC4996 page 73/74
 */

typedef struct __attribute__((packed)) tcp_static
{
	uint16_t src_port;               // =:= irregular(16)                               [ 16 ];
	uint16_t dst_port;               // =:= irregular(16)                               [ 16 ];
} tcp_static_t;

/**
 * @brief Define the TCP dynamic part.
 *
 * See RFC4996 page 73/74
 */

typedef struct __attribute__((packed)) tcp_dynamic
{
#if WORDS_BIGENDIAN != 1
	uint8_t tcp_res_flags : 4;     // =:= irregular(4)                                [ 4 ];
	uint8_t urp_zero : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t ack_zero : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t ack_stride_flag : 1;   // =:= irregular(1)                                [ 1 ];
	uint8_t ecn_used : 1;          // =:= one_bit_choice                              [ 1 ];

	uint8_t rsf_flags : 3;         // =:= irregular(3)                                [ 3 ];
	uint8_t psh_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t ack_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t urg_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t tcp_ecn_flags : 2;     // =:= irregular(2)                                [ 2 ];

#else

	uint8_t ecn_used : 1;          // =:= one_bit_choice                              [ 1 ];
	uint8_t ack_stride_flag : 1;   // =:= irregular(1)                                [ 1 ];
	uint8_t ack_zero : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t urp_zero : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t tcp_res_flags : 4;     // =:= irregular(4)                                [ 4 ];

	uint8_t tcp_ecn_flags : 2;     // =:= irregular(2)                                [ 2 ];
	uint8_t urg_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t ack_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t psh_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t rsf_flags : 3;         // =:= irregular(3)                                [ 3 ];

#endif

	uint16_t msn;                 // =:= irregular(16)                               [ 16 ];
	uint32_t seq_num;             // =:= irregular(32)                               [ 32 ];
//	uint32_t	ack_num;             // =:= zero_or_irreg(ack_zero.CVALUE, 32)          [ 0, 32 ];
//	uint16_t	window;              // =:= irregular(16)                               [ 16 ];
//	uint16_t	checksum;            // =:= irregular(16)                               [ 16 ];
//	uint16_t	urg_ptr;             // =:= zero_or_irreg(urp_zero.CVALUE, 16)          [ 0, 16 ];
//	uint16_t	ack_stride;          // =:= static_or_irreg(ack_stride_flag.CVALUE, 16) [ 0, 16 ];
//	options                          // =:= list_tcp_options                            [ VARIABLE ];
} tcp_dynamic_t;

/**
 * @brief Define the TCP replicate part.
 *
 * See RFC4996 page 74/75
 */

typedef struct __attribute__((packed)) tcp_replicate
{
#if WORDS_BIGENDIAN != 1

	uint8_t dst_port_presence : 2; // =:= irregular(2)                                [ 2 ];
	uint8_t src_port_presence : 2; // =:= irregular(2)                                [ 2 ];
	uint8_t list_present : 1;      // =:= irregular(1)                                [ 1 ];
	uint8_t window_presence : 1;   // =:= irregular(1)                                [ 1 ];
	uint8_t reserved : 1;          // =:= irregular(1)                                [ 1 ];

	uint8_t ecn_used : 1;          // =:= one_bit_choice                              [ 1 ];
	uint8_t rsf_flags : 2;         // =:= rsf_index_enc                               [ 2 ];
	uint8_t psh_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t ack_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t urg_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t urp_presence : 1;      // =:= irregular(1)                                [ 1 ];
	uint8_t ack_presence : 1;      // =:= irregular(1)                                [ 1 ];
	uint8_t ack_stride_flag : 1;   // =:= irregular(1)                                [ 1 ];

#else

	uint8_t reserved : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t window_presence : 1;   // =:= irregular(1)                                [ 1 ];
	uint8_t list_present : 1;      // =:= irregular(1)                                [ 1 ];
	uint8_t src_port_presence : 2; // =:= irregular(2)                                [ 2 ];
	uint8_t dst_port_presence : 2; // =:= irregular(2)                                [ 2 ];

	uint8_t ack_stride_flag : 1;   // =:= irregular(1)                                [ 1 ];
	uint8_t ack_presence : 1;      // =:= irregular(1)                                [ 1 ];
	uint8_t urp_presence : 1;      // =:= irregular(1)                                [ 1 ];
	uint8_t urg_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t ack_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t psh_flag : 1;          // =:= irregular(1)                                [ 1 ];
	uint8_t rsf_flags : 2;         // =:= rsf_index_enc                               [ 2 ];
	uint8_t ecn_used : 1;          // =:= one_bit_choice                              [ 1 ];

#endif

	uint16_t msn;                 // =:= irregular(16)                               [ 16 ];
	uint32_t seq_num;             // =:= irregular(32)                               [ 32 ];
//	uint16_t	src_port;            // =:= port_replicate(src_port_presence)           [ 0, 8, 16 ];
//	uint16_t	dst_port;            // =:= port_replicate(dst_port_presence)           [ 0, 8, 16 ];
//	uint16_t	window;              // =:= static_or_irreg(window_presence, 16)        [ 0, 16 ];
//	uint16_t	urg_point;           // =:= static_or_irreg(urp_presence, 16)           [ 0, 16 ];
//	uint32_t	ack_num;             // =:= static_or_irreg(ack_presence, 32)           [ 0, 32 ];
//	uint8_t		ecn_padding:2;       // =:= optional_2bit_padding(ecn_used.CVALUE)      [ 0, 2 ];
//	uint8_t		tcp_res_flags:4;     // =:= static_or_irreg(ecn_used.CVALUE, 4)         [ 0, 4 ];
//	uint8_t		tcp_ecn_flags:2;     // =:= static_or_irreg(ecn_used.CVALUE, 2)         [ 0, 2 ];
//	uint16_t	checksum;            // =:= irregular(16)                               [ 16 ];
//	uint16_t	ack_stride;          // =:= static_or_irreg(ack_stride_flag.CVALUE, 16) [ 0, 16 ];
//	options                          // =:= tcp_list_presence_enc(list_present.CVALUE)  [ VARIABLE ];

} tcp_replicate_t;

/**
 * @brief Define the TCP options.
 *
 */

#define TCP_OPT_EOL               0
#define TCP_OPT_NOP               1
#define TCP_OPT_MAXSEG            2
#define TCP_OLEN_MAXSEG           4
#define TCP_OPT_WINDOW            3
#define TCP_OLEN_WINDOW           3
#define TCP_OPT_SACK_PERMITTED    4               /* Experimental */
#define TCP_OLEN_SACK_PERMITTED   2
#define TCP_OPT_SACK              5               /* Experimental */
#define TCP_OPT_TIMESTAMP         8
#define TCP_OLEN_TIMESTAMP        10
#define TCP_OLEN_TSTAMP_APPA     (TCP_OLEN_TIMESTAMP + 2) /* appendix A */

#define TCP_OPT_TSTAMP_HDR      \
   (TCP_OPT_NOP << 24 | TCP_OPT_NOP << 16 | TCP_OPT_TIMESTAMP << 8 | TCP_OLEN_TIMESTAMP)

#define TCP_INDEX_NOP             0
#define TCP_INDEX_EOL             1
#define TCP_INDEX_MAXSEG          2
#define TCP_INDEX_WINDOW          3
#define TCP_INDEX_TIMESTAMP       4
#define TCP_INDEX_SACK_PERMITTED  5
#define TCP_INDEX_SACK            6

/**
 * @brief Define the Common compressed packet format
 *
 * See RFC4996 page 80/81
 */

typedef struct __attribute__((packed)) co_common
{
#if WORDS_BIGENDIAN != 1

	uint8_t ttl_hopl_outer_flag : 1;   // =:= compressed_value(1, ttl_irregular_chain_flag) [ 1 ];
	uint8_t discriminator : 7;         // =:= '1111101'

	uint8_t msn : 4;                   // =:= lsb(4, 4)                                     [ 4 ];
	uint8_t rsf_flags : 2;             // =:= rsf_index_enc                                 [ 2 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                  [ 1 ];
	uint8_t ack_flag : 1;              // =:= irregular(1)                                  [ 1 ];

	uint8_t urg_ptr_present : 1;       // =:= irregular(1)                                  [ 1 ];
	uint8_t ip_id_indicator : 1;       // =:= irregular(1)                                  [ 1 ];
	uint8_t window_indicator : 1;      // =:= irregular(1)                                  [ 1 ];
	uint8_t ack_stride_indicator : 1;  // =:= irregular(1)                                  [ 1 ];
	uint8_t ack_indicator : 2;         // =:= irregular(2)                                  [ 2 ];
	uint8_t seq_indicator : 2;         // =:= irregular(2)                                  [ 2 ];

	uint8_t urg_flag : 1;              // =:= irregular(1)                                  [ 1 ];
	uint8_t ip_id_behavior : 2;        // =:= ip_id_behavior_choice(true)                   [ 2 ];
	uint8_t list_present : 1;          // =:= irregular(1)                                  [ 1 ];
	uint8_t ttl_hopl_present : 1;      // =:= irregular(1)                                  [ 1 ];
	uint8_t dscp_present : 1;          // =:= irregular(1)                                  [ 1 ];
	uint8_t ecn_used : 1;              // =:= one_bit_choice                                [ 1 ];
	uint8_t reserved : 1;              // =:= compressed_value(1, 0)                        [ 1 ];

	uint8_t header_crc : 7;            // =:= crc7(THIS.UVALUE,THIS.ULENGTH)                [ 7 ];
	uint8_t df : 1;                    // =:= dont_fragment(version.UVALUE)                 [ 1 ];

#else

	uint8_t discriminator : 7;         // =:= '1111101'
	uint8_t ttl_hopl_outer_flag : 1;   // =:= compressed_value(1, ttl_irregular_chain_flag) [ 1 ];

	uint8_t ack_flag : 1;              // =:= irregular(1)                                  [ 1 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                  [ 1 ];
	uint8_t rsf_flags : 2;             // =:= rsf_index_enc                                 [ 2 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                     [ 4 ];

	uint8_t seq_indicator : 2;         // =:= irregular(2)                                  [ 2 ];
	uint8_t ack_indicator : 2;         // =:= irregular(2)                                  [ 2 ];
	uint8_t ack_stride_indicator : 1;  // =:= irregular(1)                                  [ 1 ];
	uint8_t window_indicator : 1;      // =:= irregular(1)                                  [ 1 ];
	uint8_t ip_id_indicator : 1;       // =:= irregular(1)                                  [ 1 ];
	uint8_t urg_ptr_present : 1;       // =:= irregular(1)                                  [ 1 ];

	uint8_t reserved : 1;              // =:= compressed_value(1, 0)                        [ 1 ];
	uint8_t ecn_used : 1;              // =:= one_bit_choice                                [ 1 ];
	uint8_t dscp_present : 1;          // =:= irregular(1)                                  [ 1 ];
	uint8_t ttl_hopl_present : 1;      // =:= irregular(1)                                  [ 1 ];
	uint8_t list_present : 1;          // =:= irregular(1)                                  [ 1 ];
	uint8_t ip_id_behavior : 2;        // =:= ip_id_behavior_choice(true)                   [ 2 ];
	uint8_t urg_flag : 1;              // =:= irregular(1)                                  [ 1 ];

	uint8_t df : 1;                    // =:= dont_fragment(version.UVALUE)                 [ 1 ];
	uint8_t header_crc : 7;            // =:= crc7(THIS.UVALUE,THIS.ULENGTH)                [ 7 ];

#endif

//  u_intXX_t	seq_num:X;              // =:= variable_length_32_enc(seq_indicator.CVALUE)                     [ 0, 8, 16, 32 ];
//  u_intXX_t	ack_num:X;              // =:= variable_length_32_enc(ack_indicator.CVALUE)                     [ 0, 8, 16, 32 ];
//  u_intXX_t	ack_stride:X;           // =:= static_or_irreg(ack_stride_indicator.CVALUE, 16)                 [ 0, 16 ];
//  u_intXX_t  window:X;               // =:= static_or_irreg(window_indicator.CVALUE, 16)                     [ 0, 16 ];
//  u_intXX_t  ip_id:X;                // =:= optional_ip_id_lsb(ip_id_behavior.UVALUE,ip_id_indicator.CVALUE) [ 0, 8, 16 ];
//  u_intXX_t  urg_ptr:X;              // =:= static_or_irreg(urg_ptr_present.CVALUE, 16)                      [ 0, 16 ];
//  u_intXX_t	dscp:X;                 // =:= dscp_enc-dscp_present.CVALUE)                                    [ 0, 8 ];
//  u_intXX_t	ttl_hopl:X;             // =:= static_or_irreg(ttl_hopl_present.CVALUE, 8)                      [ 0, 8 ];
//  options                            // =:= tcp_list_presence_enc(list_present.CVALUE)                       [ VARIABLE ];

} co_common_t;


/**
 * @brief Define the rnd_1 compressed packet format
 *
 * Send LSBs of sequence number
 * See RFC4996 page 81
 */
typedef struct __attribute__((packed)) rnd_1
{
#if WORDS_BIGENDIAN != 1
	uint8_t seq_num1:2;           // =:= lsb(18, 65535)           [ 18 ];
	uint8_t discriminator : 6;         // =:= '101110'                                       [ 6 ];
	uint16_t seq_num2;            // =:= lsb(18, 65535)           [ 18 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t discriminator : 6;         // =:= '101110'                                       [ 6 ];
	uint8_t seq_num1:2;          // =:= lsb(18, 65535)           [ 18 ];
	uint16_t seq_num2;           // =:= lsb(18, 65535)           [ 18 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} rnd_1_t;


/**
 * @brief Define the rnd_2 compressed packet format
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 81
 */
typedef struct __attribute__((packed)) rnd_2
{
#if WORDS_BIGENDIAN != 1
	uint8_t seq_num_scaled:4;     // =:= lsb(4, 7)             [ 4 ];
	uint8_t discriminator : 4;         // =:= '1100'                                         [ 4 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t discriminator : 4;         // =:= '1100'                                         [ 4 ];
	uint8_t seq_num_scaled:4;    // =:= lsb(4, 7)             [ 4 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} rnd_2_t;


/**
 * @brief Define the rnd_3 compressed packet format
 *
 * Send acknowlegment number LSBs
 * See RFC4996 page 81
 */
typedef struct __attribute__((packed)) rnd_3
{
#if WORDS_BIGENDIAN != 1
	uint8_t ack_num1:7;         // =:= lsb(15, 8191)               [ 15 ];
	uint8_t discriminator : 1;         // =:= '0'                                            [ 4 ];
	uint8_t ack_num2:8;         // =:= lsb(15, 8191)               [ 15 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint16_t discriminator : 1;        // =:= '0'                                            [ 4 ];
	uint8_t ack_num1:7;        // =:= lsb(15, 8191)                [ 15 ];
	uint8_t ack_num2;          // =:= lsb(15, 8191)                [ 15 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} rnd_3_t;


/**
 * @brief Define the rnd_4 compressed packet format
 *
 * Send acknowlegment number scaled
 * See RFC4996 page 81
 */
typedef struct __attribute__((packed)) rnd_4
{
#if WORDS_BIGENDIAN != 1
	uint8_t ack_num_scaled:4;   // =:= lsb(4, 3)                [ 4 ];
	uint8_t discriminator : 4;         // =:= '1101'                                         [ 4 ];

	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t discriminator : 4;         // =:= '1101'                                         [ 4 ];
	uint8_t ack_num_scaled:4;   // =:= lsb(4, 3)                [ 4 ];

	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} rnd_4_t;


/**
 * @brief Define the rnd_5 compressed packet format
 *
 * Send ACK and sequence number
 * See RFC4996 page 82
 */
typedef struct __attribute__((packed)) rnd_5
{
#if WORDS_BIGENDIAN != 1
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t discriminator : 3;         // =:= '100'                                          [ 3 ];

	uint8_t seq_num1:5;          // =:= lsb(15, 8191)           [ 15 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t seq_num2;            // =:= lsb(15, 8191)           [ 15 ];
	uint8_t ack_num1:7;          // =:= lsb(15, 8191)           [ 15 ];
	uint8_t seq_num3:1;          // =:= lsb(15, 8191)           [ 15 ];
	uint8_t ack_num2;            // =:= lsb(15, 8191)           [ 15 ];
#else
	uint8_t discriminator : 3;         // =:= '100'                                          [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];

	uint32_t header_crc : 3;           // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint32_t seq_num1:5;        // =:= lsb(14, 8191)            [ 14 ];
	uint32_t seq_num2:8;        // =:= lsb(14, 8191)            [ 14 ];
	uint32_t seq_num3:1;        // =:= lsb(14, 8191)            [ 14 ];
	uint32_t ack_num1:7;        // =:= lsb(15, 8191)            [ 15 ];
	uint32_t ack_num2:8;        // =:= lsb(15, 8191)            [ 15 ];
#endif
} rnd_5_t;


/**
 * @brief Define the rnd_6 compressed packet format
 *
 * Send both ACK and scaled sequence number LSBs
 * See RFC4996 page 82
 */
typedef struct __attribute__((packed)) rnd_6
{
#if WORDS_BIGENDIAN != 1
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t discriminator : 4;         // =:= '1010'                                         [ 4 ];
#else
	uint8_t discriminator : 4;         // =:= '1010'                                         [ 4 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
#endif
	uint16_t ack_num;            // =:= lsb(16, 16383)        [ 16 ];
#if WORDS_BIGENDIAN != 1
	uint8_t seq_num_scaled:4;    // =:= lsb(4, 7)             [ 4 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t seq_num_scaled:4;    // =:= lsb(4, 7)             [ 4 ];
#endif
} rnd_6_t;


/**
 * @brief Define the rnd_7 compressed packet format
 *
 * Send ACK and window
 * See RFC4996 page 82
 */
typedef struct __attribute__((packed)) rnd_7
{
#if WORDS_BIGENDIAN != 1
	uint8_t ack_num1:2;         // =:= lsb(18, 65535)            [ 18 ];
	uint8_t discriminator : 6;         // =:= '101111'                                       [ 6 ];
	uint16_t ack_num2;          // =:= lsb(18, 65535)            [ 18 ];
#else
	uint8_t discriminator : 6;         // =:= '101111'                                       [ 6 ];
	uint8_t ack_num1:2;         // =:= lsb(18, 65535)            [ 18 ];
	uint16_t ack_num2;          // =:= lsb(18, 65535)            [ 18 ];
#endif
	uint16_t window;                   // =:= irregular(16)                                  [ 16 ];
#if WORDS_BIGENDIAN != 1
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} rnd_7_t;


/**
 * @brief Define the rnd_8 compressed packet format
 *
 * Can send LSBs of TTL, RSF flags, change ECN behavior and options list
 * See RFC4996 page 82
 */
typedef struct __attribute__((packed)) rnd_8
{
#if WORDS_BIGENDIAN != 1
	uint8_t list_present : 1;          // =:= irregular(1)                                   [ 1 ];
	uint8_t rsf_flags : 2;             // =:= rsf_index_enc                                  [ 2 ];
	uint8_t discriminator : 5;         // =:= '10110'                                        [ 5 ];
	uint8_t msn1 : 1;                  // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t header_crc : 7;            // =:= crc7(THIS.UVALUE, THIS.ULENGTH)                [ 7 ];
	uint8_t ecn_used : 1;              // =:= one_bit_choice                                 [ 1 ];
	uint8_t ttl_hopl : 3;              // =:= lsb(3, 3)                                      [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn2 : 3;                  // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t discriminator : 5;         // =:= '10110'                                        [ 5 ];
	uint8_t rsf_flags : 2;             // =:= rsf_index_enc                                  [ 2 ];
	uint8_t list_present : 1;          // =:= irregular(1)                                   [ 1 ];
	uint16_t header_crc : 7;           // =:= crc7(THIS.UVALUE, THIS.ULENGTH)                [ 7 ];
	uint16_t msn1 : 1;                  // =:= lsb(4, 4)                                      [ 4 ];
	uint16_t msn2 : 3;                  // =:= lsb(4, 4)                                      [ 4 ];
	uint16_t psh_flag : 1;             // =:= irregular(1)                                   [ 1 ];
	uint16_t ttl_hopl : 3;             // =:= lsb(3, 3)                                      [ 3 ];
	uint16_t ecn_used : 1;             // =:= one_bit_choice                                 [ 1 ];
#endif
	uint16_t seq_num;           // =:= lsb(16, 65535)             [ 16 ];
	uint16_t ack_num;           // =:= lsb(16, 16383)             [ 16 ];
	uint8_t options[0];                // =:= tcp_list_presence_enc(list_present.CVALUE)     [ VARIABLE ];
} rnd_8_t;


/**
 * @brief Define the seq_1 compressed packet format
 *
 * Send LSBs of sequence number
 * See RFC4996 page 83
 */
typedef struct __attribute__((packed)) seq_1
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_id : 4;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 4, 3)         [ 4 ];
	uint8_t discriminator : 4;         // =:= '1010'                                         [ 4 ];
#else
	uint8_t discriminator : 4;         // =:= '1010'                                         [ 4 ];
	uint8_t ip_id : 4;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 4, 3)         [ 4 ];
#endif
	uint16_t seq_num;          // =:= lsb(16, 32767)             [ 16 ];
#if WORDS_BIGENDIAN != 1
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} seq_1_t;


/**
 * @brief Define the seq_2 compressed packet format
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 83
 */
typedef struct __attribute__((packed)) seq_2
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_id1 : 3;                // =:= ip_id_lsb(ip_id_behavior.UVALUE, 7, 3)        [ 3 ];
	uint8_t discriminator : 5;         // =:= '11010'                                        [ 5 ];
	uint8_t seq_num_scaled:4;   // =:= lsb(4, 7)                [ 4 ];
	uint8_t ip_id2 : 4;                // =:= ip_id_lsb(ip_id_behavior.UVALUE, 7, 3)        [ 4 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint16_t discriminator : 5;        // =:= '11010'                                        [ 5 ];
	uint16_t ip_id1 : 3;               // =:= ip_id_lsb(ip_id_behavior.UVALUE, 7, 3)         [ 7 ];
	uint16_t ip_id2 : 4;               // =:= ip_id_lsb(ip_id_behavior.UVALUE, 7, 3)         [ 7 ];
	uint16_t seq_num_scaled : 4;    // =:= lsb(4, 7)                                      [ 4 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} seq_2_t;


/**
 * @brief Define the seq_3 compressed packet format
 *
 * Send acknowledgment number LSBs
 * See RFC4996 page 83
 */
typedef struct __attribute__((packed)) seq_3
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_id : 4;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 4, 3)         [ 4 ];
	uint8_t discriminator : 4;         // =:= '1001'                                         [ 4 ];
#else
	uint8_t discriminator : 4;         // =:= '1001'                                         [ 4 ];
	uint8_t ip_id : 4;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 4, 3)         [ 4 ];
#endif
	uint16_t ack_num;          // =:= lsb(16, 16383)               [ 16 ];
#if WORDS_BIGENDIAN != 1
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} seq_3_t;


/**
 * @brief Define the seq_4 compressed packet format
 *
 * Send scaled acknowledgment number scaled
 * See RFC4996 page 84
 */
typedef struct __attribute__((packed)) seq_4
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_id : 3;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 3, 1)         [ 3 ];
	uint8_t ack_num_scaled:4;  // =:= lsb(4, 3)                 [ 4 ];
	uint8_t discriminator : 1;         // =:= '0'                                            [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t discriminator : 1;         // =:= '0'                                            [ 1 ];
	uint8_t ack_num_scaled:4;  // =:= lsb(4, 3)                 [ 4 ];
	uint8_t ip_id : 3;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 3, 1)         [ 3 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} seq_4_t;


/**
 * @brief Define the seq_5 compressed packet format
 *
 * Send ACK and sequence number
 * See RFC4996 page 84
 */
typedef struct __attribute__((packed)) seq_5
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_id : 4;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 4, 3)         [ 4 ];
	uint8_t discriminator : 4;         // =:= '1000'                                         [ 4 ];
#else
	uint8_t discriminator : 4;         // =:= '1000'                                         [ 4 ];
	uint8_t ip_id : 4;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 4, 3)         [ 4 ];
#endif
	uint16_t ack_num;          // =:= lsb(16, 16383)              [ 16 ];
	uint16_t seq_num;          // =:= lsb(16, 32767)              [ 16 ];
#if WORDS_BIGENDIAN != 1
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} seq_5_t;


/**
 * @brief Define the seq_6 compressed packet format
 *
 * Send both ACK and scaled sequence number LSBs
 * See RFC4996 page 84
 */
typedef struct __attribute__((packed)) seq_6
{
#if WORDS_BIGENDIAN != 1
	uint8_t seq_num_scaled1:3;   // =:= lsb(4, 7)                  [ 3 ];
	uint8_t discriminator : 5;         // =:= '11011'                                        [ 5 ];
	uint8_t ip_id : 7;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 7, 3)         [ 7 ];
	uint8_t seq_num_scaled2:1;   // =:= lsb(4, 7)                  [ 1 ];
#else
	uint16_t discriminator : 5;        // =:= '11011'                                        [ 5 ];
	uint16_t seq_num_scaled1:3;  // =:= lsb(4, 7)                  [ 4 ];
	uint16_t seq_num_scaled2:1;  // =:= lsb(4, 7)                  [ 4 ];
	uint16_t ip_id : 7;                // =:= ip_id_lsb(ip_id_behavior.UVALUE, 7, 3)         [ 7 ];
#endif
	uint16_t ack_num;            // =:= lsb(16, 16383)             [ 16 ];
#if WORDS_BIGENDIAN != 1
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;            // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} seq_6_t;


/**
 * @brief Define the seq_7 compressed packet format
 *
 * Send ACK and window
 * See RFC4996 page 85
 */
typedef struct __attribute__((packed)) seq_7
{
#if WORDS_BIGENDIAN != 1
	uint8_t window1 : 4;      // =:= lsb(15, 16383)                                 [ 15 ];
	uint8_t discriminator : 4;   // =:= '1100'                                         [ 4 ];

	uint8_t window2;

	uint8_t ip_id : 5;     // =:= ip_id_lsb(ip_id_behavior.UVALUE, 5, 3)         [ 5 ];
	uint8_t window3 : 3;

	uint16_t ack_num;      // =:= lsb(16, 32767)                [ 16 ];

	uint8_t header_crc : 3;      // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
	uint8_t psh_flag : 1;     // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;          // =:= lsb(4, 4)                                      [ 4 ];
#else
	uint8_t discriminator : 4;   // =:= '1100'                                         [ 4 ];
	uint8_t window1 : 4;      // =:= lsb(15, 16383)                                 [ 15 ];

	uint8_t window2;

	uint8_t window3 : 3;
	uint8_t ip_id : 5;     // =:= ip_id_lsb(ip_id_behavior.UVALUE, 5, 3)         [ 5 ];

	uint16_t ack_num;      // =:= lsb(16, 32767)                [ 16 ];

	uint8_t msn : 4;          // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;     // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 3;      // =:= crc3(THIS.UVALUE, THIS.ULENGTH)                [ 3 ];
#endif
} seq_7_t;


/**
 * @brief Define the seq_8 compressed packet format
 *
 * Can send LSBs of TTL, RSF flags, change ECN behavior, and options list
 * See RFC4996 page 85
 */
typedef struct __attribute__((packed)) seq_8
{
#if WORDS_BIGENDIAN != 1
	uint8_t ip_id : 4;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 4, 3)         [ 4 ];
	uint8_t discriminator : 4;         // =:= '1011'                                         [ 4 ];
	uint8_t header_crc : 7;            // =:= crc7(THIS.UVALUE, THIS.ULENGTH)                [ 7 ];
	uint8_t list_present : 1;          // =:= irregular(1)                                   [ 1 ];
	uint8_t ttl_hopl : 3;              // =:= lsb(3, 3)                                      [ 3 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t ack_num1:7;       // =:= lsb(15, 8191)               [ 15 ];
	uint8_t ecn_used : 1;              // =:= one_bit_choice                                 [ 1 ];
	uint8_t ack_num2;         // =:= lsb(15, 8191)               [ 15 ];
	uint8_t seq_num1:6;       // =:= lsb(14, 8191)               [ 14 ];
	uint8_t rsf_flags : 2;             // =:= rsf_index_enc                                  [ 2 ];
	uint8_t seq_num2:8;       // =:= lsb(14, 8191)               [ 14 ];
#else
	uint8_t discriminator : 4;         // =:= '1011'                                         [ 4 ];
	uint8_t ip_id : 4;                 // =:= ip_id_lsb(ip_id_behavior.UVALUE, 4, 3)         [ 4 ];
	uint8_t list_present : 1;          // =:= irregular(1)                                   [ 1 ];
	uint8_t header_crc : 7;            // =:= crc7(THIS.UVALUE, THIS.ULENGTH)                [ 7 ];
	uint8_t msn : 4;                   // =:= lsb(4, 4)                                      [ 4 ];
	uint8_t psh_flag : 1;              // =:= irregular(1)                                   [ 1 ];
	uint8_t ttl_hopl : 3;              // =:= lsb(3, 3)                                      [ 3 ];
	uint8_t ecn_used : 1;              // =:= one_bit_choice                                 [ 1 ];
	uint8_t ack_num1:7;      // =:= lsb(15, 8191)                [ 15 ];
	uint8_t ack_num2;        // =:= lsb(15, 8191)                [ 15 ];
	uint8_t rsf_flags : 2;             // =:= rsf_index_enc                                  [ 2 ];
	uint8_t seq_num1 : 6;    // =:= lsb(14, 8191)                [ 14 ];
	uint8_t seq_num2;        // =:= lsb(14, 8191)                [ 14 ];
#endif
	uint8_t options[0];                // =:= tcp_list_presence_enc(list_present.CVALUE)     [ VARIABLE ];
} seq_8_t;


/**
 * @brief Define union of different header pointers
 */
typedef union
{
	unsigned int uint;
	uint8_t *uint8;
	uint16_t *uint16;
	base_header_ip_vx_t *ipvx;
	base_header_ip_v4_t *ipv4;
	base_header_ip_v6_t *ipv6;
	ipv6_opt_t *ipv6_opt;
	ip_dest_opt_t *ip_dest_opt;
	ip_hop_opt_t *ip_hop_opt;
	ip_rout_opt_t *ip_rout_opt;
	ip_gre_opt_t *ip_gre_opt;
	ip_mime_opt_t *ip_mime_opt;
	ip_ah_opt_t *ip_ah_opt;
	tcphdr_t *tcphdr;
} base_header_ip_t;


#endif /* ROHC_PROTOCOLS_TCP_H */

