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
 * @file   c_tcp.h
 * @brief  ROHC compression context for the TCP profile.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef C_TCP_H
#define C_TCP_H

#include "protocols/tcp.h"
#include "c_generic.h"

#include <stdint.h>


/**
 * @brief Define the TCP-specific temporary variables in the profile compression
 *        context.
 *
 * This object must be used by the TCP-specific decompression context sc_tcp_context.
 *
 * @see sc_tcp_context
 */
#ifdef LMQJSLMQJs  // DBX
struct tcp_tmp_variables
{
	/// The number of TCP fields that changed in the TCP header
	int send_tcp_dynamic;
};
#endif

#define MAX_IPV6_OPTION_LENGTH        6   // FOR Destination/Hop-by-Hop/Routing/ah
#define MAX_IPV6_CONTEXT_OPTION_SIZE  (2 + ((MAX_IPV6_OPTION_LENGTH + 1) << 3))

/**
 * @brief Define the IPv6 generic option context.
 *
 */

typedef struct __attribute__((packed)) ipv6_option_context
{
	uint8_t context_length;
	uint8_t option_length;

	uint8_t next_header;
	uint8_t length;

	uint8_t value[1];
} ipv6_option_context_t;

/**
 * @brief Define the IPv6 GRE option context.
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
	uint8_t padding : 5;

	uint16_t protocol;

	uint32_t key;               // if k_flag set
	uint32_t sequence_number;   // if s_flag set

} ipv6_gre_option_context_t;

/**
 * @brief Define the IPv6 MIME option context.
 *
 */

typedef struct __attribute__((packed)) ipv6_mime_option_context
{
	uint8_t context_length;
	uint8_t option_length;

	uint8_t next_header;

	uint8_t s_bit : 1;
	uint8_t res_bits : 7;
	uint16_t checksum;
	uint32_t orig_dest;
	uint32_t orig_src;         // if s_bit set

} ipv6_mime_option_context_t;

/**
 * @brief Define the IPv6 AH option context.
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

	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;

	uint8_t next_header;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;

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

	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;

	uint8_t protocol;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;
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

	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;

	uint8_t next_header;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;

	uint8_t flow_label1 : 4;
	uint16_t flow_label2;

	uint32_t src_addr[4];
	uint32_t dest_addr[4];

} ipv6_context_t;


/**
 * @brief Define union of IP contexts pointers.
 *
 * TODO: merge with same definition in d_tcp.h
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


/**
 * @brief Define the TCP part of the profile decompression context.
 *
 * This object must be used with the generic part of the decompression
 * context c_generic_context.
 *
 * @see c_generic_context
 */
struct sc_tcp_context
{
	/// The number of times the sequence number field was added to the compressed header
	int tcp_seq_number_change_count;

	// The Master Sequence Number
	uint16_t msn;

	// Explicit Congestion Notification used
	uint8_t ecn_used;

	uint32_t tcp_last_seq_number;

	uint16_t window;
	uint32_t seq_number;
	uint32_t ack_number;

	uint32_t seq_number_scaled;
	uint32_t seq_number_residue;

	uint16_t ack_stride;
	uint32_t ack_number_scaled;
	uint32_t ack_number_residue;

	uint8_t tcp_options_list[16];         // see RFC4996 page 27
	uint8_t tcp_options_offset[16];
	uint16_t tcp_option_maxseg;
	uint8_t tcp_option_window;
	struct tcp_option_timestamp tcp_option_timestamp;
	uint8_t tcp_option_sack_length;
	sack_block_t tcp_option_sackblocks[4];
	uint8_t tcp_options_free_offset;
#define MAX_TCP_OPT_SIZE 64
	uint8_t tcp_options_values[MAX_TCP_OPT_SIZE];

	/// The previous TCP header
	tcphdr_t old_tcphdr;

	/// @brief TCP-specific temporary variables that are used during one single
	///        compression of packet
#ifdef TODO
	struct tcp_tmp_variables tmp_variables;
#endif

	uint8_t ip_context[1];
};

/*
 * Function prototypes.
 */

int c_tcp_create(struct c_context *const context, const struct ip_packet *ip);

int c_tcp_check_context(const struct c_context *context,
                        const struct ip_packet *ip);

int c_tcp_encode(struct c_context *const context,
                 const struct ip_packet *ip,
                 const int packet_size,
                 unsigned char *const dest,
                 const int dest_size,
                 rohc_packet_t *const packet_type,
                 int *const payload_offset);

void tcp_decide_state(struct c_context *const context);

#endif

