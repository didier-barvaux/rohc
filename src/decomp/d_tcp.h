/*
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file   d_tcp.h
 * @brief  ROHC decompression context for the TCP profile.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef D_TCP_H
#define D_TCP_H

#include "protocols/tcp.h"

#include <string.h>
#include <stdint.h>

#define PACKET_TCP_RND1     1
#define PACKET_TCP_RND2     2
#define PACKET_TCP_RND3     3
#define PACKET_TCP_RND4     4
#define PACKET_TCP_RND5     5
#define PACKET_TCP_RND6     6
#define PACKET_TCP_RND7     7
#define PACKET_TCP_RND8     8

#define PACKET_TCP_SEQ1     9
#define PACKET_TCP_SEQ2    10
#define PACKET_TCP_SEQ3    11
#define PACKET_TCP_SEQ4    12
#define PACKET_TCP_SEQ5    13
#define PACKET_TCP_SEQ6    14
#define PACKET_TCP_SEQ7    15
#define PACKET_TCP_SEQ8    16

#define PACKET_TCP_COMMON  17

#define PACKET_TCP_UNKNOWN 0xFF

/**
 * @brief Define the IPv6 option context for Destination, Hop-by-Hop and Routing option
 *
 */

typedef struct __attribute__((packed)) ipv6_option_context
{
	uint8_t context_length;
	uint8_t option_length;

	uint8_t next_header;
	uint8_t length;

	uint8_t value[6];

} ipv6_option_context_t;

/**
 * @brief Define the IPv6 option context for GRE option
 *
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
 *
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
 *
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

/**
 * @brief Define the common IP header context to IPv4 and IPv6.
 *
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
 *
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
	WB_t last_ip_id;

	uint32_t src_addr;
	uint32_t dst_addr;

} ipv4_context_t;

/**
 * @brief Define the IPv6 header context.
 *
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

} ipv6_context_t;


/**
 * @brief Define union of IP contexts pointers.
 *
 * TODO: merge with same definition in c_tcp.h
 */
typedef union
{
	uint8_t *uint8;
	ipvx_context_t *vx;
	ipv4_context_t *v4;
	ipv6_context_t *v6;
	ipv6_option_context_t *v6_option;
	ipv6_gre_option_context_t *v6_gre_option;
	ipv6_mime_option_context_t *v6_mime_option;
	ipv6_ah_option_context_t *v6_ah_option;
} ip_context_ptr_t;

#define MAX_IP_CONTEXT_SIZE  (((sizeof(ipv4_context_t) + sizeof(ipv6_context_t) + \
                                sizeof(ipv6_option_context_t)) * 2))

/**
 * @brief Define the TCP part of the decompression profile context.
 *
 * This object must be used with the generic part of the decompression
 * context d_generic_context.
 *
 * @see d_generic_context
 */
struct d_tcp_context
{
	// The Master Sequence Number
	uint16_t msn;

	// Explicit Congestion Notification used
	uint8_t ecn_used;

	// The static part:
	// The TCP source port
	uint16_t tcp_src_port;
	// The TCP dest port
	uint16_t tcp_dst_port;

	uint32_t seq_number_scaled;
	uint32_t seq_number_residue;

	uint16_t ack_stride;
	uint32_t ack_number_scaled;
	uint32_t ack_number_residue;

	// Table of TCP options
	uint8_t tcp_options_list[16];      // see RFC4996 page 27
	uint8_t tcp_options_offset[16];
	uint16_t tcp_option_maxseg;
	uint8_t tcp_option_window;
	uint8_t tcp_option_timestamp[8];
	uint8_t tcp_option_sack_length;
	uint8_t tcp_option_sackblocks[8 * 4];
	uint8_t tcp_options_free_offset;
#define MAX_TCP_OPT_SIZE 64
	uint8_t tcp_options_values[MAX_TCP_OPT_SIZE];

	tcphdr_t old_tcphdr;

	uint8_t ip_context[MAX_IP_CONTEXT_SIZE];
};


#endif

