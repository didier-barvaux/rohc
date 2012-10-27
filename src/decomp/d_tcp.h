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
 * @file d_tcp.h
 * @brief ROHC decompression context for the TCP profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 * @author FWX <rohc_team@dialine.fr>
 */

#ifndef D_TCP_H
#define D_TCP_H

#include <netinet/ip.h>
#include <string.h>

#include "protocols/tcp.h"
#include "d_generic.h"
#include "d_ip.h"

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
	u_int8_t context_length;
	u_int8_t option_length;

	u_int8_t next_header;
	u_int8_t length;

	u_int8_t value[6];

} ipv6_option_context_t;

/**
 * @brief Define the IPv6 option context for GRE option
 *
 */

typedef struct __attribute__((packed)) ipv6_gre_option_context
{
	u_int8_t context_length;
	u_int8_t option_length;

	u_int8_t next_header;

	u_int8_t c_flag : 1;
	u_int8_t k_flag : 1;
	u_int8_t s_flag : 1;
	u_int8_t protocol : 1;
	u_int8_t padding : 4;

	u_int32_t key;               // if k_flag set
	u_int32_t sequence_number;   // if s_flag set

} ipv6_gre_option_context_t;

/**
 * @brief Define the IPv6 option context for MIME option
 *
 */

typedef struct __attribute__((packed)) ipv6_mime_option_context
{
	u_int8_t context_length;
	u_int8_t option_length;

	u_int8_t next_header;

	u_int8_t s_bit : 1;
	u_int8_t res_bits : 7;
	u_int32_t orig_dest;
	u_int32_t orig_src;         // if s_bit set

} ipv6_mime_option_context_t;

/**
 * @brief Define the IPv6 option context for AH option
 *
 */

typedef struct __attribute__((packed)) ipv6_ah_option_context
{
	u_int8_t context_length;
	u_int8_t option_length;

	u_int8_t next_header;
	u_int8_t length;
	u_int32_t spi;
	u_int32_t sequence_number;
	u_int32_t auth_data[1];
} ipv6_ah_option_context_t;

/**
 * @brief Define the common IP header context to IPv4 and IPv6.
 *
 */

typedef struct __attribute__((packed)) ipvx_context
{
	u_int8_t version : 4;
	u_int8_t unused : 4;

	u_int8_t context_length;

	u_int8_t dscp : 6;
	u_int8_t ip_ecn_flags : 2;

	u_int8_t next_header;

	u_int8_t ttl_hopl;

	u_int8_t ip_id_behavior;

} ipvx_context_t;

/**
 * @brief Define the IPv4 header context.
 *
 */

typedef struct __attribute__((packed)) ipv4_context
{
	u_int8_t version : 4;
	u_int8_t df : 1;
	u_int8_t unused : 3;

	u_int8_t context_length;

	u_int8_t dscp : 6;
	u_int8_t ip_ecn_flags : 2;

	u_int8_t protocol;

	u_int8_t ttl_hopl;

	u_int8_t ip_id_behavior;
	WB_t last_ip_id;

	u_int32_t src_addr;
	u_int32_t dst_addr;

} ipv4_context_t;

/**
 * @brief Define the IPv6 header context.
 *
 */

typedef struct __attribute__((packed)) ipv6_context
{
	u_int8_t version : 4;
	u_int8_t unused : 4;

	u_int8_t context_length;

	u_int8_t dscp : 6;
	u_int8_t ip_ecn_flags : 2;

	u_int8_t next_header;

	u_int8_t ttl_hopl;

	u_int8_t ip_id_behavior;

	u_int8_t flow_label1 : 4;
	u_int16_t flow_label2;

	u_int32_t src_addr[4];
	u_int32_t dest_addr[4];

} ipv6_context_t;

/**
 * @brief Define union of IP contexts pointers.
 *
 */

typedef union
{
	u_int8_t *uint8;
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
	u_int16_t msn;

	// Explicit Congestion Notification used
	u_int8_t ecn_used;

	// The static part:
	// The TCP source port
	u_int16_t tcp_src_port;
	// The TCP dest port
	u_int16_t tcp_dst_port;

	u_int32_t seq_number_scaled;
	u_int32_t seq_number_residue;

	u_int16_t ack_stride;
	u_int32_t ack_number_scaled;
	u_int32_t ack_number_residue;

	// Table of TCP options
	u_int8_t tcp_options_list[16];      // see RFC4996 page 27
	u_int8_t tcp_options_offset[16];
	u_int16_t tcp_option_maxseg;
	u_int8_t tcp_option_window;
	u_int8_t tcp_option_timestamp[8];
	u_int8_t tcp_option_sack_length;
	u_int8_t tcp_option_sackblocks[8 * 4];
	u_int8_t tcp_options_free_offset;
#define MAX_TCP_OPT_SIZE 64
	u_int8_t tcp_options_values[MAX_TCP_OPT_SIZE];

	tcphdr_t old_tcphdr;

	u_int8_t ip_context[MAX_IP_CONTEXT_SIZE];
};


#endif

