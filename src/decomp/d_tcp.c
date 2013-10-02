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
 * @file   d_tcp.c
 * @brief  ROHC decompression context for the TCP profile.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_bit_ops.h"
#include "rohc_traces_internal.h"
#include "rohc_utils.h"
#include "rohc_debug.h"
#include "rohc_time.h"
#include "schemes/rfc4996.h"
#include "schemes/wlsb.h"
#include "protocols/tcp.h"
#include "crc.h"
#include "d_generic.h"

#include "config.h" /* for WORDS_BIGENDIAN and ROHC_EXTRA_DEBUG */

#ifndef __KERNEL__
#  include <string.h>
#endif
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

	uint8_t value[6];

} ipv6_option_context_t;


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
	WB_t last_ip_id;

	uint32_t src_addr;
	uint32_t dst_addr;

} ipv4_context_t;


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


#define MAX_IP_CONTEXT_SIZE  \
	(rohc_max(sizeof(ipv4_context_t), \
	          sizeof(ipv6_context_t) + sizeof(ipv6_option_context_t) * 10) \
	 * 4)


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
	struct rohc_lsb_decode *seq_lsb_ctxt;

	uint16_t ack_stride;
	uint32_t ack_number_scaled;
	uint32_t ack_number_residue;

	// Table of TCP options
	uint8_t tcp_options_list[16];      // see RFC4996 page 27
	uint8_t tcp_options_offset[16];
	uint16_t tcp_option_maxseg;
	uint8_t tcp_option_window;

	struct tcp_option_timestamp tcp_option_timestamp;
	struct rohc_lsb_decode *opt_ts_req_lsb_ctxt;
	struct rohc_lsb_decode *opt_ts_reply_lsb_ctxt;

	uint8_t tcp_option_sack_length;
	uint8_t tcp_option_sackblocks[8 * 4];
	uint8_t tcp_options_free_offset;
#define MAX_TCP_OPT_SIZE 64
	uint8_t tcp_options_values[MAX_TCP_OPT_SIZE];

	tcphdr_t old_tcphdr;

	uint8_t ip_context[MAX_IP_CONTEXT_SIZE];
};


/*
 * Private function prototypes.
 */

static void * d_tcp_create(const struct d_context *const context);
static void d_tcp_destroy(void *const context);

static int tcp_decode_static_ipv6_option(struct d_context *const context,
                                         ip_context_ptr_t ip_context,
                                         uint8_t protocol,
                                         multi_ptr_t c_base_header,
                                         unsigned int length,
                                         base_header_ip_t base_header);
static unsigned int tcp_copy_static_ipv6_option(const struct d_context *const context,
                                                uint8_t protocol,
                                                ip_context_ptr_t ip_context,
                                                base_header_ip_t base_header);
static int tcp_decode_dynamic_ipv6_option(struct d_context *const context,
                                          ip_context_ptr_t ip_context,
                                          uint8_t protocol,
                                          multi_ptr_t c_base_header,
                                          unsigned int length,
                                          base_header_ip_t base_header);

static int tcp_decode_static_ip(struct d_context *const context,
                                ip_context_ptr_t ip_context,
                                multi_ptr_t c_base_header,
                                unsigned int length,
                                unsigned char *dest);
static unsigned int tcp_copy_static_ip(const struct d_context *const context,
                                       ip_context_ptr_t ip_context,
                                       base_header_ip_t base_header);
static int tcp_decode_dynamic_ip(struct d_context *const context,
                                 ip_context_ptr_t ip_context,
                                 multi_ptr_t c_base_header,
                                 unsigned int length,
                                 unsigned char *dest);
static uint8_t * tcp_decode_irregular_ip(struct d_context *const context,
                                         ip_context_ptr_t ip_context,
                                         base_header_ip_t base_header,
                                         multi_ptr_t mptr,
                                         int is_innermost,
                                         int ttl_irregular_chain_flag,
                                         int ip_inner_ecn);
static int tcp_decode_static_tcp(struct d_context *const context,
                                 tcp_static_t *tcp_static,
                                 unsigned int length,
                                 tcphdr_t *tcp);
static unsigned int tcp_copy_static_tcp(struct d_context *const context,
                                        tcphdr_t *tcp);
static int tcp_decode_dynamic_tcp(struct d_context *const context,
                                  tcp_dynamic_t *tcp_dynamic,
                                  unsigned int length,
                                  tcphdr_t *tcp);

static rohc_packet_t tcp_detect_packet_type(const struct rohc_decomp *const decomp,
                                            const struct d_context *const context,
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len);

static int d_tcp_decode_ir(struct rohc_decomp *decomp,
                           struct d_context *context,
                           const unsigned char *const rohc_packet,
                           const unsigned int rohc_length,
                           const size_t add_cid_len,
                           const size_t large_cid_len,
                           unsigned char *dest);
static int d_tcp_decode_CO(struct rohc_decomp *decomp,
                           struct d_context *context,
                           const unsigned char *const rohc_packet,
                           const unsigned int rohc_length,
                           const size_t add_cid_len,
                           const size_t large_cid_len,
                           const rohc_packet_t packet_type,
                           unsigned char *dest);

static bool rohc_decomp_tcp_decode_seq(const struct rohc_decomp *const decomp,
                                       const struct d_context *const context,
                                       const uint32_t seq_bits,
                                       const size_t seq_bits_nr,
                                       const rohc_lsb_shift_t p,
                                       uint32_t *const seq)
	__attribute__((warn_unused_result, nonnull(1, 2, 6)));

static uint32_t d_tcp_get_msn(const struct d_context *const context)
	__attribute__((warn_unused_result, nonnull(1), pure));


/**
 * @brief Create the TCP decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The decompression context
 * @return         The newly-created TCP decompression context
 */
static void * d_tcp_create(const struct d_context *const context)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;

	/* create the generic context */
	g_context = d_generic_create(context,
	                             context->decompressor->trace_callback,
	                             context->profile->id);
	if(g_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the generic decompression context\n");
		goto quit;
	}

	/* create the TCP-specific part of the context */
	tcp_context = malloc(sizeof(struct d_tcp_context));
	if(tcp_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the TCP-specific context\n");
		goto destroy_context;
	}
	memset(tcp_context, 0, sizeof(struct d_tcp_context));
	g_context->specific = tcp_context;

	/* create the LSB decoding context for the sequence number */
	tcp_context->seq_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_VAR, 32);
	if(tcp_context->seq_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the sequence "
		           "number\n");
		goto free_tcp_context;
	}

	/* the TCP source and destination ports will be initialized
	 * with the IR packets */
	tcp_context->tcp_src_port = 0xFFFF;
	tcp_context->tcp_dst_port = 0xFFFF;

	memset(tcp_context->tcp_options_list,0xFF,16);

	/* create the LSB decoding context for the TCP option Timestamp echo
	 * request */
	tcp_context->opt_ts_req_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_VAR, 32);
	if(tcp_context->opt_ts_req_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the TCP "
		           "option Timestamp echo request\n");
		goto free_lsb_seq;
	}

	/* create the LSB decoding context for the TCP option Timestamp echo
	 * reply */
	tcp_context->opt_ts_reply_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_VAR, 32);
	if(tcp_context->opt_ts_reply_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the TCP "
		           "option Timestamp echo reply\n");
		goto free_lsb_ts_opt_req;
	}

	/* some TCP-specific values and functions */
	g_context->next_header_len = sizeof(tcphdr_t);
	g_context->build_next_header = NULL;
#ifdef TODO
	g_context->decode_static_next_header = tcp_decode_static_tcp;
	g_context->decode_dynamic_next_header = tcp_decode_dynamic_tcp;
	g_context->decode_uo_tail = NULL;
#endif
	g_context->compute_crc_static = tcp_compute_crc_static;
	g_context->compute_crc_dynamic = tcp_compute_crc_dynamic;

	/* create the TCP-specific part of the header changes */
	g_context->outer_ip_changes->next_header_len = sizeof(tcphdr_t);
	g_context->outer_ip_changes->next_header =
		(unsigned char *) malloc(sizeof(tcphdr_t));
	if(g_context->outer_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the TCP-specific part of the "
		           "outer IP header changes\n");
		goto free_lsb_ts_opt_reply;
	}
	memset(g_context->outer_ip_changes->next_header, 0, sizeof(tcphdr_t));

	g_context->inner_ip_changes->next_header_len = sizeof(tcphdr_t);
	g_context->inner_ip_changes->next_header =
		(unsigned char *) malloc(sizeof(tcphdr_t));
	if(g_context->inner_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the TCP-specific part of the "
		           "inner IP header changes\n");
		goto free_outer_next_header;
	}
	memset(g_context->inner_ip_changes->next_header, 0, sizeof(tcphdr_t));

	/* set next header to TCP */
	g_context->next_header_proto = ROHC_IPPROTO_TCP;

	return g_context;

free_outer_next_header:
	zfree(g_context->outer_ip_changes->next_header);
free_lsb_ts_opt_reply:
	rohc_lsb_free(tcp_context->opt_ts_reply_lsb_ctxt);
free_lsb_ts_opt_req:
	rohc_lsb_free(tcp_context->opt_ts_req_lsb_ctxt);
free_lsb_seq:
	rohc_lsb_free(tcp_context->seq_lsb_ctxt);
free_tcp_context:
	zfree(tcp_context);
destroy_context:
	d_generic_destroy(g_context);
quit:
	return NULL;
}


/**
 * @brief Destroy the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
static void d_tcp_destroy(void *const context)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;

	assert(context != NULL);
	g_context = (struct d_generic_context *) context;
	assert(g_context->specific != NULL);
	tcp_context = (struct d_tcp_context *) g_context->specific;

	/* clean TCP-specific memory */
	assert(g_context->outer_ip_changes != NULL);
	assert(g_context->outer_ip_changes->next_header != NULL);
	zfree(g_context->outer_ip_changes->next_header);
	assert(g_context->inner_ip_changes != NULL);
	assert(g_context->inner_ip_changes->next_header != NULL);
	zfree(g_context->inner_ip_changes->next_header);

	/* destroy the LSB decoding context for the TCP option Timestamp echo
	 * request */
	rohc_lsb_free(tcp_context->opt_ts_req_lsb_ctxt);
	/* destroy the LSB decoding context for the TCP option Timestamp echo
	 * reply */
	rohc_lsb_free(tcp_context->opt_ts_reply_lsb_ctxt);
	/* destroy the LSB decoding context for the sequence number */
	rohc_lsb_free(tcp_context->seq_lsb_ctxt);

#if 0 /* TODO: sn_lsb_ctxt is not initialized, either remove it or use it fully */
	/* destroy the LSB decoding context for SN */
	rohc_lsb_free(g_context->sn_lsb_ctxt);
#endif

	/* destroy the generic decompression context (g_context->specific is
	 * destroyed by d_generic_destroy) */
	d_generic_destroy(g_context);
}


/**
 * @brief Detect the type of ROHC packet for the TCP profile
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               The packet type
 */
static rohc_packet_t tcp_detect_packet_type(const struct rohc_decomp *const decomp,
                                            const struct d_context *const context,
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
	ip_context_ptr_t ip_context;
	bool is_ip_id_seq;
	rohc_packet_t type;

	assert(decomp != NULL);
	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;
	ip_context.uint8 = tcp_context->ip_context;
	assert(rohc_packet != NULL);

	is_ip_id_seq =
		(ip_context.v4->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED);

	if(rohc_length < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small to read the first byte that "
		             "contains the packet type (len = %zd)\n", rohc_length);
		goto error;
	}

	rohc_decomp_debug(context, "try to determine the header from first byte "
	                  "0x%02x and ip_id_behavior = %d\n", rohc_packet[0],
	                  ip_context.v4->ip_id_behavior);

	if(rohc_packet[0] == ROHC_PACKET_TYPE_IR)
	{
		type = ROHC_PACKET_IR;
	}
	else if(rohc_packet[0] == ROHC_PACKET_TYPE_IR_DYN)
	{
		type = ROHC_PACKET_IR_DYN;
	}
	else if(rohc_packet[0] & 0x80)
	{
		switch(rohc_packet[0] & 0xf0)
		{
			case 0x80: /* 1000 = seq_5 / rnd_5 */
				type = (is_ip_id_seq ? ROHC_PACKET_TCP_SEQ_5 : ROHC_PACKET_TCP_RND_5);
				break;
			case 0x90: /* 1001 = seq_3 / rnd_5 */
				type = (is_ip_id_seq ? ROHC_PACKET_TCP_SEQ_3 : ROHC_PACKET_TCP_RND_5);
				break;
			case 0xa0: /* 1010 = seq_1 / rnd_6 */
				type = (is_ip_id_seq ? ROHC_PACKET_TCP_SEQ_1 : ROHC_PACKET_TCP_RND_6);
				break;
			case 0xb0: /* 1011 = seq_8 / rnd_1 / rnd_7 / rnd_8 */
				if(is_ip_id_seq)
				{
					type = ROHC_PACKET_TCP_SEQ_8;
				}
				else if(rohc_packet[0] & 0x08)
				{
					if(rohc_packet[0] & 0x04)
					{
						type = ROHC_PACKET_TCP_RND_7;
					}
					else
					{
						type = ROHC_PACKET_TCP_RND_1;
					}
				}
				else
				{
					type = ROHC_PACKET_TCP_RND_8;
				}
				break;
			case 0xc0: /* 1100 = seq_7 / rnd_2 */
				type = (is_ip_id_seq ? ROHC_PACKET_TCP_SEQ_7 : ROHC_PACKET_TCP_RND_2);
				break;
			case 0xd0: /* 1101 = seq_2 / seq_6 / rnd_4 */
				if(is_ip_id_seq)
				{
					if(rohc_packet[0] & 0x08)
					{
						type = ROHC_PACKET_TCP_SEQ_6;
					}
					else
					{
						type = ROHC_PACKET_TCP_SEQ_2;
					}
				}
				else
				{
					type = ROHC_PACKET_TCP_RND_4;
				}
				break;
			case 0xf0: /* 1111 = common */
				if((rohc_packet[0] & 0xfe) == 0xfa)
				{
					type = ROHC_PACKET_TCP_CO_COMMON;
				}
				else
				{
					type = ROHC_PACKET_UNKNOWN;
				}
				break;
			default:
				type = ROHC_PACKET_UNKNOWN;
				break;
		}
	}
	else
	{
		/* seq_4 / rnd_3 */
		type = (is_ip_id_seq ? ROHC_PACKET_TCP_SEQ_4 : ROHC_PACKET_TCP_RND_3);
	}

	return type;

error:
	return ROHC_PACKET_UNKNOWN;
}


/**
 * @brief Decode one IR, IR-DYN, IR-CO IR-CR packet for TCP profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param arrival_time   The time at which packet was received (0 if unknown,
 *                       or to disable time-related features in ROHC protocol)
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param add_cid_len    The length of the optional Add-CID field
 * @param large_cid_len  The length of the optional large CID field
 * @param dest           OUT: The decoded IP packet
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @return               The length of the uncompressed IP packet
 *                       or ROHC_ERROR if an error occurs
 *                       or ROHC_ERROR_CRC if a CRC error occurs
 */
static int d_tcp_decode(struct rohc_decomp *const decomp,
                        struct d_context *const context,
                        const struct rohc_timestamp arrival_time,
                        const unsigned char *const rohc_packet,
                        const size_t rohc_length,
                        const size_t add_cid_len,
                        const size_t large_cid_len,
                        unsigned char *const dest,
                        rohc_packet_t *const packet_type)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header;
	multi_ptr_t c_base_header;
	tcphdr_t *tcp;
	unsigned int payload_size;
	int length = ROHC_ERROR;
	uint8_t protocol;
	int size;
	int read;

	assert(decomp != NULL);
	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;
	assert(rohc_packet != NULL);
	assert(add_cid_len == 0 || add_cid_len == 1);
	assert(large_cid_len >= 0 && large_cid_len <= 2);
	assert(dest != NULL);

	rohc_decomp_debug(context, "decomp = %p, context = %p, rohc_packet = %p, "
	                  "rohc_length = %zu, add_cid_len = %zu, "
	                  "large_cid_len = %zu, dest = %p\n", decomp, context,
	                  rohc_packet, rohc_length, add_cid_len, large_cid_len,
	                  dest);

	rohc_decomp_debug(context, "parse packet type '%s' (%d)\n",
	                  rohc_get_packet_descr(*packet_type), *packet_type);

	ip_context.uint8 = tcp_context->ip_context;

	if((*packet_type) == ROHC_PACKET_IR)
	{
		size = d_tcp_decode_ir(decomp, context, rohc_packet, rohc_length,
		                       add_cid_len, large_cid_len, dest);
	}
	else if((*packet_type) == ROHC_PACKET_IR_DYN)
	{
		/* skip:
		 *  - the first byte of the ROHC packet (field 2)
		 *  - the Profile byte (field 4) */
		length = 2;
		c_base_header.uint8 = (uint8_t*)( rohc_packet + large_cid_len + length);

		/* parse CRC */
		/* TODO Didier */
		c_base_header.uint8++;
		length++;

		base_header.uint8 = dest;
		ip_context.uint8 = tcp_context->ip_context;
		size = 0;

		do
		{
			/* Init static part in IP header */
			size += tcp_copy_static_ip(context, ip_context, base_header);

			/* Decode dynamic part */
			read = tcp_decode_dynamic_ip(context, ip_context, c_base_header,
			                             rohc_length - length, base_header.uint8);
			if(read < 0)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "malformed ROHC packet: malformed IP dynamic part\n");
				goto error;
			}
			length += read;
			c_base_header.uint8 += read;
			rohc_decomp_debug(context, "length = %d, read = %d, size = %d\n",
			                  length, read, size);

			if(ip_context.vx->version == IPV4)
			{
				protocol = ip_context.v4->protocol;
				++base_header.ipv4;
				++ip_context.v4;
			}
			else
			{
				protocol = ip_context.v6->next_header;
				++base_header.ipv6;
				++ip_context.v6;
				while(rohc_is_ipv6_opt(protocol))
				{
					size += tcp_copy_static_ipv6_option(context, protocol,
					                                    ip_context, base_header);
					protocol = ip_context.v6_option->next_header;
					base_header.uint8 += ip_context.v6_option->option_length;
					ip_context.uint8 += ip_context.v6_option->context_length;
				}
			}
			if(ip_context.uint8 >= &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE])
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "decompressor does not support as many IP headers "
				             "as ROHC packet contains\n");
				goto error;
			}
		}
		while(rohc_is_tunneling(protocol));

		tcp = base_header.tcphdr;

		tcp_copy_static_tcp(context, tcp);

// TODO: to be completed? loop on dynamic chain?
		read = tcp_decode_dynamic_tcp(context, c_base_header.tcp_dynamic,
		                              rohc_length - length, tcp);
		if(read < 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "malformed ROHC packet: malformed TCP dynamic part\n");
			goto error;
		}
		length += read;
		c_base_header.uint8 += read;
		rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "current IP packet", dest, size);


		/* add TCP header and TCP options */
		size += (tcp->data_offset << 2);

		rohc_decomp_debug(context, "read = %d, length = %d, size = %d\n",
		                  read, length, size);

		memcpy(&tcp_context->old_tcphdr,tcp,sizeof(tcphdr_t));

		payload_size = rohc_length - length - large_cid_len;

		// Calculate scaled value and residue (see RFC4996 page 32/33)
		if(payload_size != 0)
		{
			tcp_context->seq_number_scaled = rohc_ntoh32(tcp->seq_number) / payload_size;
			tcp_context->seq_number_residue = rohc_ntoh32(tcp->seq_number) % payload_size;
		}

		// copy payload datas
		memcpy(dest + size, c_base_header.uint8, payload_size);
		rohc_decomp_debug(context, "copy %d bytes of payload\n", payload_size);
		size += payload_size;

		base_header.uint8 = dest;
		ip_context.uint8 = tcp_context->ip_context;

		length = size;

		do
		{

			if(ip_context.vx->version == IPV4)
			{
				base_header.ipv4->length = rohc_hton16(length);
				base_header.ipv4->checksum = 0;
				base_header.ipv4->checksum =
					ip_fast_csum(base_header.uint8,
					             base_header.ipv4->header_length);
				rohc_decomp_debug(context, "IP checksum = 0x%04x for %d\n",
				                  rohc_ntoh16(base_header.ipv4->checksum),
				                  base_header.ipv4->header_length);
				protocol = ip_context.v4->protocol;
				length -= sizeof(base_header_ip_v4_t);
				++base_header.ipv4;
				++ip_context.v4;
			}
			else
			{
				length -= sizeof(base_header_ip_v6_t);
				base_header.ipv6->payload_length = rohc_hton16(length);
				rohc_decomp_debug(context, "payload_length = %d\n",
				                  rohc_ntoh16(base_header.ipv6->payload_length));
				protocol = ip_context.v6->next_header;
				++base_header.ipv6;
				++ip_context.v6;
				while(rohc_is_ipv6_opt(protocol))
				{
					protocol = ip_context.v6_option->next_header;
					length -= ip_context.v6_option->option_length;
					base_header.uint8 += ip_context.v6_option->option_length;
					ip_context.uint8 += ip_context.v6_option->context_length;
				}
			}
			if(ip_context.uint8 >= &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE])
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "decompressor does not support as many IP headers "
				             "as ROHC packet contains\n");
				goto error;
			}
		}
		while(rohc_is_tunneling(protocol));

		rohc_decomp_debug(context, "new MSN = 0x%x\n", tcp_context->msn);

		rohc_decomp_debug(context, "Total length = %d\n", size);

		/* update context (to be completed) */
		rohc_lsb_set_ref(tcp_context->seq_lsb_ctxt, rohc_ntoh32(tcp->seq_number),
		                 false);
		rohc_decomp_debug(context, "sequence number 0x%08x is the new reference\n",
		                  rohc_ntoh32(tcp->seq_number));
	}
	else
	{
		// Uncompressed CO packet
		size = d_tcp_decode_CO(decomp, context, rohc_packet, rohc_length,
		                       add_cid_len, large_cid_len, *packet_type, dest);
	}

	rohc_decomp_debug(context, "return %d\n", size);
	return size;

error:
	return ROHC_ERROR;
}


/**
 * @brief Decode one IR packet for the TCP profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param rohc_packet     The ROHC packet to decode
 * @param rohc_length     The length of the ROHC packet to decode
 * @param add_cid_len     The length of the optional Add-CID field
 * @param large_cid_len   The length of the optional large CID field
 * @param dest            The decoded IP packet
 * @return                The length of the uncompressed IP packet
 *                        or ROHC_OK_NO_DATA if packet is feedback only
 *                        or ROHC_ERROR if an error occurs
 */
static int d_tcp_decode_ir(struct rohc_decomp *decomp,
                           struct d_context *context,
                           const unsigned char *const rohc_packet,
                           const unsigned int rohc_length,
                           const size_t add_cid_len,
                           const size_t large_cid_len,
                           unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	struct d_tcp_context *tcp_context = g_context->specific;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header;
	multi_ptr_t c_base_header;
	tcphdr_t *tcp;
	unsigned int payload_size;
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t uncomp_len;
	uint8_t protocol;
	uint16_t size;
	int read;

	c_base_header.uint8 = (uint8_t *) rohc_packet;

	rohc_decomp_debug(context, "decomp = %p, context = %p, rohc_packet = %p, "
	                  "rohc_length = %d, add_cid_len = %zd, "
	                  "large_cid_len = %zd, dest = %p\n", decomp, context,
	                  rohc_packet, rohc_length, add_cid_len, large_cid_len,
	                  dest);

	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "IR packet", rohc_packet, rohc_length);

	/* skip:
	 * - the first byte of the ROHC packet (field 2)
	 * - the Profile byte (field 4) */
	if(remain_len < (1 + large_cid_len + 1))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "malformed ROHC packet: too short for first byte, large "
		             "CID bytes, and profile byte\n");
		goto error;
	}
	c_base_header.uint8 += 1 + large_cid_len + 1;
	remain_data += 1 + large_cid_len + 1;
	remain_len -= 1 + large_cid_len + 1;

	/* parse CRC */
	if(remain_len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "malformed ROHC packet: too short for the CRC bytes\n");
		goto error;
	}
	/* TODO: check CRC */
	c_base_header.uint8++;
	remain_data++;
	remain_len--;

	base_header.uint8 = dest;
	ip_context.uint8 = tcp_context->ip_context;

	/* static chain (IP and TCP parts) */
	size = 0;
	do
	{
		/* IP static part */
		read = tcp_decode_static_ip(context, ip_context, c_base_header,
		                            remain_len, base_header.uint8);
		if(read < 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "malformed ROHC packet: malformed IP static part\n");
			goto error;
		}
		rohc_decomp_debug(context, "IPv%d static part is %d-byte length\n",
								base_header.ipvx->version, read);
		assert(remain_len >= read);
		c_base_header.uint8 += read;
		remain_data += read;
		remain_len -= read;

		protocol = ip_context.vx->next_header;
		ip_context.uint8 += ip_context.vx->context_length;
		if(base_header.ipvx->version == IPV4)
		{
			++base_header.ipv4;
			size += sizeof(base_header_ip_v4_t);
		}
		else
		{
			++base_header.ipv6;
			size += sizeof(base_header_ip_v6_t);
			while(rohc_is_ipv6_opt(protocol))
			{
				read =
				   tcp_decode_static_ipv6_option(context, ip_context, protocol,
				                                 c_base_header, remain_len,
				                                 base_header);
				if(read < 0)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					             "malformed ROHC packet: malformed IPv6 static "
					             "option part\n");
					goto error;
				}
				rohc_decomp_debug(context, "IPv6 static option part is %d-byte "
										"length\n", read);
				assert(remain_len >= read);
				c_base_header.uint8 += read;
				remain_data += read;
				remain_len -= read;

				size += ip_context.v6_option->option_length;
				protocol = ip_context.v6_option->next_header;
				base_header.uint8 += ip_context.v6_option->option_length;
				ip_context.uint8 += ip_context.v6_option->context_length;
			}
		}
		if(ip_context.uint8 >= &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE])
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "decompressor does not support as many IP headers as "
			             "ROHC packet contains\n");
			goto error;
		}
		rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "current IP packet", dest, size);
	}
	while(rohc_is_tunneling(protocol));

	tcp = base_header.tcphdr;

	/* TCP static part */
	read = tcp_decode_static_tcp(context, c_base_header.tcp_static, remain_len,
	                             tcp);
	if(read < 0)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "malformed ROHC packet: malformed TCP static part\n");
		goto error;
	}
	rohc_decomp_debug(context, "TCP static part is %d-byte length\n", read);
	assert(remain_len >= read);
	c_base_header.uint8 += read;
	remain_data += read;
	remain_len -= read;

	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "current IP packet", dest, size);

	/* dynamic chain (IP and TCP parts) */
	base_header.uint8 = dest;
	ip_context.uint8 = tcp_context->ip_context;
	do
	{
		/* IP dynamic part */
		read = tcp_decode_dynamic_ip(context, ip_context, c_base_header,
		                             remain_len, base_header.uint8);
		if(read < 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "malformed ROHC packet: malformed IP dynamic part\n");
			goto error;
		}
		rohc_decomp_debug(context, "IPv%d dynamic part is %d-byte length\n",
								base_header.ipvx->version, read);
		assert(remain_len >= read);
		c_base_header.uint8 += read;
		remain_data += read;
		remain_len -= read;

		protocol = ip_context.vx->next_header;
		ip_context.uint8 += ip_context.vx->context_length;
		if(base_header.ipvx->version == IPV4)
		{
			++base_header.ipv4;
		}
		else
		{
			++base_header.ipv6;
			while(rohc_is_ipv6_opt(protocol))
			{
				read =
				   tcp_decode_dynamic_ipv6_option(context, ip_context, protocol,
				                                  c_base_header, remain_len,
				                                  base_header);
				if(read < 0)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					             "malformed ROHC packet: malformed IPv6 dynamic "
					             "option part\n");
					goto error;
				}
				rohc_decomp_debug(context, "IPv6 dynamic option part is %d-byte "
										"length\n", read);
				assert(remain_len >= read);
				c_base_header.uint8 += read;
				remain_data += read;
				remain_len -= read;

				protocol = ip_context.v6_option->next_header;
				base_header.uint8 += ip_context.v6_option->option_length;
				ip_context.uint8 += ip_context.v6_option->context_length;
			}
		}
		if(ip_context.uint8 >= &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE])
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "decompressor does not support as many IP headers as "
			             "ROHC packet contains\n");
			goto error;
		}
		rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "current IP packet", dest, size);
	}
	while(rohc_is_tunneling(protocol));

	/* TCP dynamic part */
	read = tcp_decode_dynamic_tcp(context, c_base_header.tcp_dynamic,
	                              remain_len, tcp);
	if(read < 0)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "malformed ROHC packet: malformed TCP dynamic part\n");
		goto error;
	}
	rohc_decomp_debug(context, "TCP dynamic part is %d-byte length\n", read);
	assert(remain_len >= read);
	c_base_header.uint8 += read;
	remain_data += read;
	remain_len -= read;

	/* add TCP header and TCP options */
	size += (tcp->data_offset << 2);

	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "current IP+TCP packet", dest, size);

	memcpy(&tcp_context->old_tcphdr, tcp, sizeof(tcphdr_t));

	rohc_decomp_debug(context, "ROHC header is %zu-byte length\n",
	                  rohc_length - remain_len);
	rohc_decomp_debug(context, "uncompressed header is %d-byte length\n", size);
	payload_size = remain_len;
	rohc_decomp_debug(context, "ROHC payload is %d-byte length\n", payload_size);

	// Calculate scaled value and residue (see RFC4996 page 32/33)
	if(payload_size != 0)
	{
		tcp_context->seq_number_scaled = rohc_ntoh32(tcp->seq_number) / payload_size;
		tcp_context->seq_number_residue = rohc_ntoh32(tcp->seq_number) % payload_size;
	}

	// copy payload
	memcpy(dest + size, remain_data, payload_size);
	rohc_decomp_debug(context, "copy %d bytes of payload\n", payload_size);
	size += payload_size;

	rohc_decomp_debug(context, "Total length = %d\n", size);

	base_header.uint8 = dest;
	ip_context.uint8 = tcp_context->ip_context;

	uncomp_len = size;

	do
	{
		if(base_header.ipvx->version == IPV4)
		{
			protocol = base_header.ipv4->protocol;
			base_header.ipv4->length = rohc_hton16(uncomp_len);
			base_header.ipv4->checksum = 0;
			base_header.ipv4->checksum =
				ip_fast_csum(base_header.uint8,
				             base_header.ipv4->header_length);
			rohc_decomp_debug(context, "IP checksum = 0x%04x for %d\n",
			                  rohc_ntoh16(base_header.ipv4->checksum),
			                  base_header.ipv4->header_length);
			++base_header.ipv4;
			++ip_context.v4;
			uncomp_len -= sizeof(base_header_ip_v4_t);
		}
		else
		{
			protocol = base_header.ipv6->next_header;
			uncomp_len -= sizeof(base_header_ip_v6_t);
			base_header.ipv6->payload_length = rohc_hton16(uncomp_len);
			rohc_decomp_debug(context, "IPv6 payload length = %d\n",
			                  rohc_ntoh16(base_header.ipv6->payload_length));
			++base_header.ipv6;
			++ip_context.v6;
			while(rohc_is_ipv6_opt(protocol))
			{
				uncomp_len -= ip_context.v6_option->option_length;
				protocol = base_header.ipv6_opt->next_header;
				base_header.uint8 += ip_context.v6_option->option_length;
				ip_context.uint8 += ip_context.v6_option->context_length;
			}
		}
		if(ip_context.uint8 >= &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE])
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "decompressor does not support as many IP headers as "
			             "ROHC packet contains\n");
			goto error;
		}
	}
	while(rohc_is_tunneling(protocol));

	/* update context (to be completed) */
	rohc_lsb_set_ref(tcp_context->seq_lsb_ctxt, rohc_ntoh32(tcp->seq_number),
	                 false);
	rohc_decomp_debug(context, "sequence number 0x%08x is the new reference\n",
	                  rohc_ntoh32(tcp->seq_number));

	// TODO: to be reworked
	context->state = ROHC_DECOMP_STATE_FC;

	rohc_decomp_debug(context, "return %d\n", size);
	return size;

error:
	return ROHC_ERROR;
}


/**
 * @brief Decode the static IP v6 option header of the rohc packet.
 *
 * @param context        The decompression context
 * @param ip_context     The specific IP decompression context
 * @param protocol       The IPv6 protocol option
 * @param c_base_header  The compressed IP header of the rohc packet
 * @param length         The remain length of the rohc packet
 * @param base_header    The decoded IP packet
 * @return               The length of static IP header in case of success,
 *                       -1 if an error occurs
 */
static int tcp_decode_static_ipv6_option(struct d_context *const context,
                                         ip_context_ptr_t ip_context,
                                         uint8_t protocol,
                                         multi_ptr_t c_base_header,
                                         unsigned int length,
                                         base_header_ip_t base_header)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
	int size;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;

	rohc_decomp_debug(context, "tcp_context = %p, ip_context = %p, "
	                  "protocol = %d, c_base_header = %p, length = %d, "
	                  "base_header = %p\n", tcp_context, ip_context.uint8,
	                  protocol, c_base_header.uint8, length, base_header.uint8);

	/* at least 1 byte required to read the next header and length */
	if(length < 2)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "malformed ROHC packet: too short for the version flag "
		             "of the IP static part\n");
		goto error;
	}
	ip_context.v6_option->next_header = c_base_header.ip_opt_static->next_header;
	base_header.ipv6_opt->next_header = c_base_header.ip_opt_static->next_header;

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
			size = sizeof(ip_hop_opt_static_t);
			if(length < size)
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id,
				             "malformed ROHC packet: too short for the static "
				             "part of the IPv6 Hop-by-Hop option\n");
				goto error;
			}
			ip_context.v6_option->option_length = ( c_base_header.ip_opt_static->length + 1 ) << 3;
			ip_context.v6_option->context_length = 2 + ip_context.v6_option->option_length;
			rohc_decomp_debug(context, "IPv6 option Hop-by-Hop: length = %d, "
			                  "context_length = %d, option_length = %d\n",
			                  c_base_header.ip_opt_static->length,
			                  ip_context.v6_option->context_length,
			                  ip_context.v6_option->option_length);
			ip_context.v6_option->length = c_base_header.ip_opt_static->length;
			base_header.ipv6_opt->length = ip_context.v6_option->length;
			break;
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
			size = (c_base_header.ip_opt_static->length + 1) << 3;
			if(length < size)
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id,
				             "malformed ROHC packet: too short for the static "
				             "part of the IPv6 Routing option\n");
				goto error;
			}
			ip_context.v6_option->context_length = 2 + size;
			ip_context.v6_option->option_length = size;
			memcpy(&ip_context.v6_option->length,&c_base_header.ip_rout_opt_static->length,size - 1);
			memcpy(&base_header.ipv6_opt->length,&ip_context.v6_option->length,size - 1);
			break;
		case ROHC_IPPROTO_GRE:
			size = c_base_header.ip_gre_opt_static->c_flag +
			       c_base_header.ip_gre_opt_static->k_flag +
			       c_base_header.ip_gre_opt_static->s_flag + 1;
			if(length < size)
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id,
				             "malformed ROHC packet: too short for the static "
				             "part of the IPv6 GRE option\n");
				goto error;
			}
			ip_context.v6_option->context_length = sizeof(ipv6_gre_option_context_t);
			ip_context.v6_option->option_length = size << 3;
			if( ( ip_context.v6_gre_option->protocol ==
			      c_base_header.ip_gre_opt_static->protocol ) == 0)
			{
				base_header.ip_gre_opt->protocol = rohc_hton16(0x0800);
			}
			else
			{
				base_header.ip_gre_opt->protocol = rohc_hton16(0x86DD);
			}
			ip_context.v6_gre_option->c_flag = c_base_header.ip_gre_opt_static->c_flag;
			base_header.ip_gre_opt->c_flag = ip_context.v6_gre_option->c_flag;
			ip_context.v6_gre_option->s_flag = c_base_header.ip_gre_opt_static->s_flag;
			base_header.ip_gre_opt->s_flag = ip_context.v6_gre_option->s_flag;
			if( ( ip_context.v6_gre_option->k_flag = c_base_header.ip_gre_opt_static->k_flag ) != 0)
			{
				base_header.ip_gre_opt->k_flag = 1;
				ip_context.v6_gre_option->key = c_base_header.ip_gre_opt_static->key;
				base_header.ip_gre_opt->datas[ip_context.v6_gre_option->c_flag] =
				   ip_context.v6_gre_option->key;
				size = sizeof(ip_gre_opt_static_t);
				break;
			}
			base_header.ip_gre_opt->k_flag = 0;
			size = sizeof(ip_gre_opt_static_t) - sizeof(uint32_t);
			break;
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
			size = sizeof(ip_dest_opt_static_t);
			if(length < size)
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id,
				             "malformed ROHC packet: too short for the static "
				             "part of the IPv6 Destination option\n");
				goto error;
			}
			ip_context.v6_option->option_length = ( c_base_header.ip_opt_static->length + 1 ) << 3;
			ip_context.v6_option->context_length = 2 + ip_context.v6_option->option_length;
			rohc_decomp_debug(context, "IPv6 option Destination: length = %d, "
			                  "context_length = %d, option_length = %d\n",
			                  c_base_header.ip_opt_static->length,
			                  ip_context.v6_option->context_length,
			                  ip_context.v6_option->option_length);
			ip_context.v6_option->length = c_base_header.ip_dest_opt_static->length;
			base_header.ipv6_opt->length = ip_context.v6_option->length;
			break;
		case ROHC_IPPROTO_MINE:
			size = sizeof(ip_mime_opt_static_t) -
			       (c_base_header.ip_mime_opt_static->s_bit * sizeof(uint32_t));
			if(length < size)
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id,
				             "malformed ROHC packet: too short for the static "
				             "part of the IPv6 Destination option\n");
				goto error;
			}
			ip_context.v6_option->context_length = sizeof(ipv6_mime_option_context_t);
			ip_context.v6_option->option_length = ( 2 + c_base_header.ip_mime_opt_static->s_bit ) << 3;
			ip_context.v6_mime_option->s_bit = c_base_header.ip_mime_opt_static->s_bit;
			base_header.ip_mime_opt->s_bit = ip_context.v6_mime_option->s_bit;
			ip_context.v6_mime_option->res_bits = c_base_header.ip_mime_opt_static->res_bits;
			base_header.ip_mime_opt->res_bits = ip_context.v6_mime_option->res_bits;
			ip_context.v6_mime_option->orig_dest = c_base_header.ip_mime_opt_static->orig_dest;
			base_header.ip_mime_opt->orig_dest = ip_context.v6_mime_option->orig_dest;
			if(ip_context.v6_mime_option->s_bit != 0)
			{
				ip_context.v6_mime_option->orig_src = c_base_header.ip_mime_opt_static->orig_src;
				base_header.ip_mime_opt->orig_src = ip_context.v6_mime_option->orig_src;
			}
			break;
		case ROHC_IPPROTO_AH:
			size = sizeof(ip_ah_opt_static_t);
			if(length < size)
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id,
				             "malformed ROHC packet: too short for the static "
				             "part of the IPv6 Destination option\n");
				goto error;
			}
			ip_context.v6_option->context_length = sizeof(ipv6_ah_option_context_t);
			ip_context.v6_option->option_length = sizeof(ip_ah_opt_t) - sizeof(uint32_t) +
			                                      ( c_base_header.ip_ah_opt_static->length <<
			                                        4 ) - sizeof(int32_t);
			ip_context.v6_ah_option->length = c_base_header.ip_ah_opt_static->length;
			base_header.ipv6_opt->length = ip_context.v6_ah_option->length;
			ip_context.v6_ah_option->spi = c_base_header.ip_ah_opt_static->spi;
			base_header.ip_ah_opt->spi = ip_context.v6_ah_option->spi;
			break;
		default:
			goto error;
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "IPv6 option static part",
	                 c_base_header.uint8, size);
#endif

	return size;

error:
	return -1;
}


/**
 * @brief Copy the static IP part to the IPv6 option header
 *
 * @param context        The decompression context
 * @param protocol       The IPv6 protocol option
 * @param ip_context     The specific IP decompression context
 * @param base_header    The IP header
 * @return               The size of the static part
 */
static unsigned int tcp_copy_static_ipv6_option(const struct d_context *const context,
                                                uint8_t protocol,
                                                ip_context_ptr_t ip_context,
                                                base_header_ip_t base_header)
{
	int size;

	assert(context != NULL);

	rohc_decomp_debug(context, "protocol = %d, ip_context = %p, "
	                  "base_header = %p\n", protocol, ip_context.uint8,
	                  base_header.ipvx);

	base_header.ipv6_opt->next_header = ip_context.v6_option->next_header;

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
			//             base_header.ipv6_opt->length = ip_context.v6_option->length;
			size = ( ip_context.v6_option->length + 1 ) << 3;
			memcpy(&base_header.ipv6_opt->length,&ip_context.v6_option->length,size - 1);
			break;
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
			size = (ip_context.v6_option->length + 1) << 3;
			memcpy(&base_header.ipv6_opt->length,&ip_context.v6_option->length,size - 1);
			break;
		case ROHC_IPPROTO_GRE:
			base_header.ip_gre_opt->r_flag = 0;
#if WORDS_BIGENDIAN != 1
			base_header.ip_gre_opt->reserved1 = 0;
			base_header.ip_gre_opt->reserved2 = 0;
#else
			base_header.ip_gre_opt->reserved0 = 0;
#endif
			base_header.ip_gre_opt->version = 0;
			if(ip_context.v6_gre_option->protocol == 0)
			{
				base_header.ip_gre_opt->protocol = rohc_hton16(0x0800);
			}
			else
			{
				base_header.ip_gre_opt->protocol = rohc_hton16(0x86DD);
			}
			base_header.ip_gre_opt->c_flag = ip_context.v6_gre_option->c_flag;
			base_header.ip_gre_opt->s_flag = ip_context.v6_gre_option->s_flag;
			if( ( base_header.ip_gre_opt->k_flag = ip_context.v6_gre_option->k_flag ) != 0)
			{
				base_header.ip_gre_opt->datas[ip_context.v6_gre_option->c_flag] =
				   ip_context.v6_gre_option->key;
			}
			size = sizeof(ip_gre_opt_t) - sizeof(uint32_t) +
			       ( ( ip_context.v6_gre_option->c_flag + ip_context.v6_gre_option->k_flag +
			           ip_context.v6_gre_option->s_flag ) * sizeof(uint32_t) );
			break;
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
			//     base_header.ipv6_opt->length = ip_context.v6_option->length;
			size = ( ip_context.v6_option->length + 1 ) << 3;
			memcpy(&base_header.ipv6_opt->length,&ip_context.v6_option->length,size - 1);
			break;
		case ROHC_IPPROTO_MINE:

			base_header.ip_mime_opt->s_bit = ip_context.v6_mime_option->s_bit;
			base_header.ip_mime_opt->res_bits = ip_context.v6_mime_option->res_bits;
			base_header.ip_mime_opt->orig_dest = ip_context.v6_mime_option->orig_dest;
			if(ip_context.v6_mime_option->s_bit != 0)
			{
				base_header.ip_mime_opt->orig_src = ip_context.v6_mime_option->orig_src;
				size = sizeof(ip_mime_opt_t);
				break;
			}
			size = sizeof(ip_mime_opt_t) - sizeof(uint32_t);
			break;
		case ROHC_IPPROTO_AH:
			base_header.ip_ah_opt->length = ip_context.v6_ah_option->length;
			base_header.ip_ah_opt->res_bits = 0;
			base_header.ip_ah_opt->spi = ip_context.v6_ah_option->spi;
			size = sizeof(ip_ah_opt_t) + ( ip_context.v6_ah_option->length << 4 );
			break;
		default:
			size = 0;
			break;
	}

	return size;
}


/**
 * @brief Decode the dynamic IP v6 option header of the rohc packet.
 *
 * @param context        The decompression context
 * @param ip_context     The specific IP decompression context
 * @param protocol       The IPv6 protocol option
 * @param c_base_header  The compressed IP header of the rohc packet
 * @param length         The remain length of the rohc packet
 * @param base_header    The decoded IP packet
 * @return               The length of dynamic IP header
 *                       0 if an error occurs
 */
static int tcp_decode_dynamic_ipv6_option(struct d_context *const context,
                                          ip_context_ptr_t ip_context,
                                          uint8_t protocol,
                                          multi_ptr_t c_base_header,
                                          unsigned int length,
                                          base_header_ip_t base_header)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
#if ROHC_EXTRA_DEBUG == 1
	uint8_t *data_orig = c_base_header.uint8;
#endif
	size_t remain_len = length;
	int size;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;

	rohc_decomp_debug(context, "tcp_context = %p, ip_context = %p, "
	                  "protocol = %d, c_base_header = %p, length = %d, "
	                  "base_header = %p\n", tcp_context, ip_context.uint8,
	                  protocol, c_base_header.uint8, length, base_header.uint8);

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
			size = ((ip_context.v6_option->length + 1) << 3) - 2;
			if(remain_len < size)
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id, "malformed IPv6 option: "
				             "malformed option %u: %zu bytes available while %d "
				             "bytes required\n", protocol, remain_len, size);
				goto error;
			}
			memcpy(ip_context.v6_option->value, c_base_header.uint8, size);
			memcpy(base_header.ipv6_opt->value, ip_context.v6_option->value, size);
			remain_len -= size;
			break;
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
			size = 0;
			break;
		case ROHC_IPPROTO_GRE:
			size = 0;
			if(ip_context.v6_gre_option->c_flag != 0)
			{
				if(remain_len < sizeof(uint32_t))
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
					             context->profile->id, "malformed IPv6 option: "
					             "malformed option GRE: %zu bytes available while "
					             "4 bytes required\n", remain_len);
					goto error;
				}
				base_header.ip_gre_opt->datas[0] = READ32_FROM_MPTR(c_base_header);
				size += sizeof(uint32_t);
				remain_len -= sizeof(uint32_t);
			}
			if(ip_context.v6_gre_option->s_flag != 0)
			{
				if(remain_len < sizeof(uint32_t))
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
					             context->profile->id, "malformed IPv6 option: "
					             "malformed option GRE: %zu bytes available while "
					             "4 bytes required\n", remain_len);
					goto error;
				}
				base_header.ip_gre_opt->datas[ip_context.v6_gre_option->c_flag] =
					READ32_FROM_MPTR(c_base_header);
				size += sizeof(uint32_t);
				remain_len -= sizeof(uint32_t);
			}
			break;
		case ROHC_IPPROTO_MINE:
			size = 0;
			break;
		case ROHC_IPPROTO_AH:
			size = ip_context.v6_ah_option->length << 2;
			if(remain_len < size)
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id, "malformed IPv6 option: "
				             "malformed option AH: %zu bytes available while %d "
				             "bytes required\n", remain_len, size);
				goto error;
			}
			ip_context.v6_ah_option->sequence_number =
			   c_base_header.ip_ah_opt_dynamic->sequence_number;
			memcpy(ip_context.v6_ah_option->auth_data,
			       c_base_header.ip_ah_opt_dynamic->auth_data,
			       size - sizeof(uint32_t));
			break;
		default:
			size = 0;
			break;
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "IPv6 option dynamic part",
	                 data_orig, size);
#endif

	return size;

error:
	return -1;
}


/**
 * @brief Decode the static IP header of the rohc packet.
 *
 * @param context        The decompression context
 * @param ip_context     The specific IP decompression context
 * @param c_base_header  The compressed IP header of the rohc packet
 * @param length         The remain length of the rohc packet
 * @param dest           The decoded IP packet
 * @return               The length of static IP header in case of success,
 *                       -1 if an error occurs
 */
static int tcp_decode_static_ip(struct d_context *const context,
                                ip_context_ptr_t ip_context,
                                multi_ptr_t c_base_header,
                                unsigned int length,
                                unsigned char *dest)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
	base_header_ip_t base_header;   // Destination
	int size;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;

	rohc_decomp_debug(context, "tcp_context = %p, ip_context = %p, "
	                  "base_header = %p, length = %d, dest = %p\n",
	                  tcp_context, ip_context.uint8, c_base_header.uint8,
	                  length, dest);

	base_header.uint8 = dest;

	/* at least 1 byte required to read the version flag */
	if(length < 1)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "malformed ROHC packet: too short for the version flag "
		             "of the IP static part\n");
		goto error;
	}

	if(c_base_header.ipv4_static->version_flag == 0)
	{
		if(length < sizeof(ipv4_static_t))
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id,
			             "malformed ROHC packet: too short for the IPv4 static "
			             "part\n");
			goto error;
		}

		base_header.ipv4->version = IPV4;
		base_header.ipv4->header_length = sizeof(base_header_ip_v4_t) >> 2;
		base_header.ipv4->protocol = c_base_header.ipv4_static->protocol;
		base_header.ipv4->src_addr = c_base_header.ipv4_static->src_addr;
		base_header.ipv4->dest_addr = c_base_header.ipv4_static->dst_addr;

		ip_context.v4->version = IPV4;
		ip_context.v4->context_length = sizeof(ipv4_context_t);
		ip_context.v4->protocol = c_base_header.ipv4_static->protocol;
		ip_context.v4->src_addr = c_base_header.ipv4_static->src_addr;
		ip_context.v4->dst_addr = c_base_header.ipv4_static->dst_addr;
		size = sizeof(ipv4_static_t);
	}
	else
	{
		/* at least 1 byte required to read the version flag */
		if(length < 1)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id,
			             "malformed ROHC packet: too short for the first byte "
			             "of the IPv6 static part\n");
			goto error;
		}

		base_header.ipv6->version = IPV6;
		ip_context.v6->version = IPV6;
		ip_context.v6->context_length = sizeof(ipv6_context_t);
		if(c_base_header.ipv6_static1->flow_label_enc_discriminator == 0)
		{
			if(length < sizeof(ipv6_static1_t))
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id,
				             "malformed ROHC packet: too short for the IPv6 "
				             "static part\n");
				goto error;
			}

			base_header.ipv6->flow_label1 = 0;
			base_header.ipv6->flow_label2 = 0;
			base_header.ipv6->next_header = c_base_header.ipv6_static1->next_header;
			memcpy(base_header.ipv6->src_addr,c_base_header.ipv6_static1->src_addr,
			       sizeof(uint32_t) * 4 * 2);

			ip_context.v6->flow_label1 = 0;
			ip_context.v6->flow_label2 = 0;
			ip_context.v6->next_header = c_base_header.ipv6_static1->next_header;
			memcpy(ip_context.v6->src_addr,c_base_header.ipv6_static1->src_addr,
			       sizeof(uint32_t) * 4 * 2);
			size = sizeof(ipv6_static1_t);
		}
		else
		{
			if(length < sizeof(ipv6_static2_t))
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id,
				             "malformed ROHC packet: too short for the IPv6 "
				             "static part\n");
				goto error;
			}

			base_header.ipv6->flow_label1 = c_base_header.ipv6_static2->flow_label1;
			base_header.ipv6->flow_label2 = c_base_header.ipv6_static2->flow_label2;
			base_header.ipv6->next_header = c_base_header.ipv6_static2->next_header;
			memcpy(base_header.ipv6->src_addr,c_base_header.ipv6_static2->src_addr,
			       sizeof(uint32_t) * 4 * 2);

			ip_context.v6->flow_label1 = c_base_header.ipv6_static2->flow_label1;
			ip_context.v6->flow_label2 = c_base_header.ipv6_static2->flow_label2;
			ip_context.v6->next_header = c_base_header.ipv6_static2->next_header;
			memcpy(ip_context.v6->src_addr,c_base_header.ipv6_static2->src_addr,
			       sizeof(uint32_t) * 4 * 2);
			size = sizeof(ipv6_static2_t);
		}
	}
	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "IP static part", c_base_header.uint8,
	                 size);

	return size;

error:
	return -1;
}


/**
 * @brief Copy the static IP part to the IP header
 *
 * @param context       The decompression context
 * @param ip_context    The specific IP decompression context
 * @param base_header   The IP header
 * @return              The size of the static part
 */
static unsigned int tcp_copy_static_ip(const struct d_context *const context,
                                       ip_context_ptr_t ip_context,
                                       base_header_ip_t base_header)
{
	assert(context != NULL);

	rohc_decomp_debug(context, "ip_context = %p, base_header = %p\n",
	                  ip_context.uint8, base_header.ipvx);

	if(ip_context.vx->version == IPV4)
	{
		base_header.ipv4->version = IPV4;
		base_header.ipv4->header_length = sizeof(base_header_ip_v4_t) >> 2;
		base_header.ipv4->protocol = ip_context.v4->protocol;
		base_header.ipv4->src_addr = ip_context.v4->src_addr;
		base_header.ipv4->dest_addr = ip_context.v4->dst_addr;
		return sizeof(base_header_ip_v4_t);
	}
	else
	{
		base_header.ipv6->version = IPV6;
		base_header.ipv6->flow_label1 = ip_context.v6->flow_label1;
		base_header.ipv6->flow_label2 = ip_context.v6->flow_label2;
		base_header.ipv6->next_header = ip_context.v6->next_header;
		memcpy(base_header.ipv6->src_addr,ip_context.v6->src_addr,sizeof(uint32_t) * 4 * 2);
		return sizeof(base_header_ip_v6_t);
	}
}


/**
 * @brief Decode the dynamic IP header of the rohc packet.
 *
 * @param context        The decompression context
 * @param ip_context     The specific IP decompression context
 * @param c_base_header  The dynamic compressed IP header of the rohc packet
 * @param length         The remain length of the rohc packet
 * @param dest           The decoded IP packet
 * @return               The length of dynamic IP header in case of success,
 *                       -1 if an error occurs
 */
static int tcp_decode_dynamic_ip(struct d_context *const context,
                                 ip_context_ptr_t ip_context,
                                 multi_ptr_t c_base_header,
                                 unsigned int length,
                                 unsigned char *dest)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
	base_header_ip_t base_header;   // Destination
	int size;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;

	rohc_decomp_debug(context, "tcp_context = %p, ip_context = %p, "
	                  "base_header = %p, length = %d, dest = %p\n",
	                  tcp_context, ip_context.uint8, c_base_header.uint8,
	                  length, dest);

	base_header.uint8 = dest;

	if(ip_context.vx->version == IPV4)
	{
		if(length < sizeof(ipv4_dynamic1_t))
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id, "malformed ROHC packet: too "
			             "short for IPv4 dynamic part\n");
			goto error;
		}

		base_header.ipv4->rf = 0;
		base_header.ipv4->df = c_base_header.ipv4_dynamic1->df;
		base_header.ipv4->mf = 0;
		base_header.ipv4->dscp = c_base_header.ipv4_dynamic1->dscp;
		base_header.ipv4->ip_ecn_flags = c_base_header.ipv4_dynamic1->ip_ecn_flags;
		base_header.ipv4->ttl_hopl = c_base_header.ipv4_dynamic1->ttl_hopl;
		rohc_decomp_debug(context, "DSCP = 0x%x, ip_ecn_flags = %d\n",
		                  base_header.ipv4->dscp, base_header.ipv4->ip_ecn_flags);
#if WORDS_BIGENDIAN != 1
		base_header.ipv4->frag_offset1 = 0;
		base_header.ipv4->frag_offset2 = 0;
#else
		base_header.ipv4->frag_offset = 0;
#endif

		ip_context.v4->df = c_base_header.ipv4_dynamic1->df;
		ip_context.v4->ip_id_behavior = c_base_header.ipv4_dynamic1->ip_id_behavior;
		rohc_decomp_debug(context, "ip_id_behavior = %d\n",
		                  ip_context.v4->ip_id_behavior);
		ip_context.v4->dscp = c_base_header.ipv4_dynamic1->dscp;
		ip_context.v4->ip_ecn_flags = c_base_header.ipv4_dynamic1->ip_ecn_flags;
		ip_context.v4->ttl_hopl = c_base_header.ipv4_dynamic1->ttl_hopl;
		rohc_decomp_debug(context, "DSCP = 0x%x, ip_ecn_flags = %d, "
		                  "ttl_hopl = 0x%x\n", ip_context.v4->dscp,
		                  ip_context.v4->ip_ecn_flags, ip_context.v4->ttl_hopl);
		// cf RFC4996 page 60/61 ip_id_enc_dyn()
		if(c_base_header.ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
		{
			base_header.ipv4->ip_id = 0;
			ip_context.v4->last_ip_id.uint16 = 0;
			rohc_decomp_debug(context, "new last IP-ID = 0x%04x\n",
			                  ip_context.v4->last_ip_id.uint16);
			size = sizeof(ipv4_dynamic1_t);
		}
		else
		{
			if(length < sizeof(ipv4_dynamic2_t))
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id, "malformed ROHC packet: too "
				             "short for IPv4 dynamic part\n");
				goto error;
			}

			if(c_base_header.ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
			{
				base_header.ipv4->ip_id = swab16(c_base_header.ipv4_dynamic2->ip_id);
			}
			else
			{
				base_header.ipv4->ip_id = c_base_header.ipv4_dynamic2->ip_id;
			}
			ip_context.v4->last_ip_id.uint16 = rohc_ntoh16(base_header.ipv4->ip_id);
			rohc_decomp_debug(context, "new last IP-ID = 0x%04x\n",
			                  ip_context.v4->last_ip_id.uint16);
			size = sizeof(ipv4_dynamic2_t);
		}
		rohc_decomp_debug(context, "IP-ID = 0x%04x\n",
		                  rohc_ntoh16(base_header.ipv4->ip_id));
	}
	else
	{
		if(length < sizeof(ipv6_dynamic_t))
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id, "malformed ROHC packet: too "
			             "short for IPv6 dynamic part\n");
			goto error;
		}

		base_header.ipv6->dscp1 = c_base_header.ipv6_dynamic->dscp >> 2;
		base_header.ipv6->dscp2 = c_base_header.ipv6_dynamic->dscp & 0x03;
		base_header.ipv6->ip_ecn_flags = c_base_header.ipv6_dynamic->ip_ecn_flags;
		base_header.ipv6->ttl_hopl = c_base_header.ipv6_dynamic->ttl_hopl;

		ip_context.v6->dscp = c_base_header.ipv6_dynamic->dscp;
		ip_context.v6->ip_ecn_flags = c_base_header.ipv6_dynamic->ip_ecn_flags;
		ip_context.v6->ttl_hopl = c_base_header.ipv6_dynamic->ttl_hopl;
		ip_context.v6->ip_id_behavior = IP_ID_BEHAVIOR_RANDOM;
		size = sizeof(ipv6_dynamic_t);
	}

	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "IP dynamic part", c_base_header.uint8,
	                 size);

	return size;

error:
	return -1;
}


/**
 * @brief Decode the irregular IP header of the rohc packet.
 *
 * @param context                   The decompression context
 * @param ip_context                The specific IP decompression context
 * @param base_header               The IP header under built
 * @param mptr                      The irregular compressed IP header of the rohc packet
 * @param is_innermost              True if the IP header is the innermost of the packet
 * @param ttl_irregular_chain_flag  True if one of the TTL value of header change
 * @param ip_inner_ecn              The ECN flags of inner IP header
 * @return                          The current point of the remain rohc_data
 */
static uint8_t * tcp_decode_irregular_ip(struct d_context *const context,
                                         ip_context_ptr_t ip_context,
                                         base_header_ip_t base_header,
                                         multi_ptr_t mptr,
                                         int is_innermost,
                                         int ttl_irregular_chain_flag,
                                         int ip_inner_ecn)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
#if ROHC_EXTRA_DEBUG == 1
	uint8_t *ptr = mptr.uint8;
#endif

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;

	rohc_decomp_debug(context, "tcp_context = %p, ip_context = %p, "
	                  "base_header = %p, mptr = %p\n", tcp_context,
	                  ip_context.uint8, base_header.uint8, mptr.uint8);
	rohc_decomp_debug(context, "is_innermost = %d, ttl_irregular_chain_flag = %d, "
	                  "ip_inner_ecn = %d\n", is_innermost,
	                  ttl_irregular_chain_flag, ip_inner_ecn);

	if(ip_context.vx->version == IPV4)
	{
		// ip_id =:= ip_id_enc_irreg( ip_id_behavior.UVALUE )
		if(ip_context.v4->ip_id_behavior == IP_ID_BEHAVIOR_RANDOM)
		{
			base_header.ipv4->ip_id = READ16_FROM_MPTR(mptr);
			rohc_decomp_debug(context, "read ip_id = 0x%04x (ip_id_behavior = %d)\n",
			                  base_header.ipv4->ip_id, ip_context.v4->ip_id_behavior);
			ip_context.v4->last_ip_id.uint16 = rohc_ntoh16(base_header.ipv4->ip_id);
			rohc_decomp_debug(context, "new last IP-ID = 0x%04x\n",
			                  ip_context.v4->last_ip_id.uint16);
		}
		if(is_innermost == 0)
		{
			// ipv4_outer_with/without_ttl_irregular
			// dscp =:= static_or_irreg( ecn_used.UVALUE )
			// ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE )
			if(tcp_context->ecn_used != 0)
			{
				base_header.ipv4->dscp = *mptr.uint8 >> 2;
				base_header.ipv4->ip_ecn_flags = *(mptr.uint8++) & 0x03;
				rohc_decomp_debug(context, "read DSCP = 0x%x, ip_ecn_flags = %d\n",
				                  base_header.ipv4->dscp,
				                  base_header.ipv4->ip_ecn_flags);
			}
			if(ttl_irregular_chain_flag == 1)
			{
				// ipv4_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				base_header.ipv4->ttl_hopl = *(mptr.uint8++);
				rohc_decomp_debug(context, "read ttl_hopl = 0x%x\n",
				                  base_header.ipv4->ttl_hopl);
			}
			/* else: ipv4_outer_without_ttl_irregular */
		}
		else
		{
			// ipv4_innermost_irregular
			// assert( ip_inner_ecn == base_header.ipv4->ip_ecn_flags );
			base_header.ipv4->ip_ecn_flags = ip_inner_ecn; // TODO: review ???
		}
	}
	else
	{
		// IPv6
		if(is_innermost == 0)
		{
			// ipv6_outer_with/without_ttl_irregular
			// dscp =:= static_or_irreg( ecn_used.UVALUE )
			// ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE )
			if(tcp_context->ecn_used != 0)
			{
				base_header.ipv6->dscp1 = (*mptr.uint8) >> 4;
				base_header.ipv6->dscp2 = ((*mptr.uint8) >> 2 ) & 0x03;
				base_header.ipv4->ip_ecn_flags = *(mptr.uint8++) & 0x03;
			}
			if(ttl_irregular_chain_flag == 1)
			{
				rohc_decomp_debug(context, "irregular ttl_hopl 0x%x != 0x%x\n",
				                  base_header.ipv6->ttl_hopl,
				                  ip_context.vx->ttl_hopl);
				// ipv6_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				base_header.ipv6->ttl_hopl = *(mptr.uint8++);
				rohc_decomp_debug(context, "read ttl_hopl = 0x%x\n",
				                  base_header.ipv6->ttl_hopl);
			}
			/* else: ipv6_outer_without_ttl_irregular */
		}
		/* else: ipv6_innermost_irregular */
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "IP irregular part", ptr,
	                 mptr.uint8 - ptr);
#endif

	return mptr.uint8;
}


/**
 * @brief Decode the TCP static part of the ROHC packet.
 *
 * @param context     The decompression context
 * @param tcp_static  The TCP static part to decode
 * @param length      The length of the ROHC packet
 * @param tcp         The decoded TCP header
 * @return            The number of bytes read in the ROHC packet,
 *                    -1 in case of failure
 */
static int tcp_decode_static_tcp(struct d_context *const context,
                                 tcp_static_t *tcp_static,
                                 unsigned int length,
                                 tcphdr_t *tcp)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;

	rohc_decomp_debug(context, "tcp_context = %p, tcp_static = %p, "
	                  "length = %d, dest = %p\n", tcp_context, tcp_static,
	                  length, tcp);

	/* check the minimal length to decode the TCP static part */
	if(length < sizeof(tcp_static_t))
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "TCP static part",
	                 (unsigned char *) tcp_static, sizeof(tcp_static_t));

	/* TCP source port */
	tcp_context->tcp_src_port =
	   tcp->src_port = tcp_static->src_port;
	rohc_decomp_debug(context, "TCP source port = %d\n", rohc_ntoh16(tcp->src_port));

	/* TCP destination port */
	tcp_context->tcp_dst_port =
	   tcp->dst_port = tcp_static->dst_port;
	rohc_decomp_debug(context, "TCP dest port = %d\n", rohc_ntoh16(tcp->dst_port));

	/* number of bytes read from the packet */
	rohc_decomp_debug(context, "TCP static part is %zu-byte long\n",
	                  sizeof(tcp_static_t));
	return sizeof(tcp_static_t);

error:
	return -1;
}


/**
 * @brief Copy the TCP static part of the TCP header.
 *
 * @param context  The decompression context
 * @param tcp      The decoded TCP header
 * @return         The number of bytes copied to the TCP header
 */
static unsigned int tcp_copy_static_tcp(struct d_context *const context,
                                        tcphdr_t *tcp)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;

	rohc_decomp_debug(context, "tcp_context = %p, tcp = %p\n", tcp_context, tcp);

	tcp->src_port = tcp_context->tcp_src_port;
	rohc_decomp_debug(context, "source port = %d (0x%04x)\n",
	                  rohc_ntoh16(tcp->src_port), rohc_ntoh16(tcp->src_port));

	tcp->dst_port = tcp_context->tcp_dst_port;
	rohc_decomp_debug(context, "destination port = %d (0x%04x)\n",
	                  rohc_ntoh16(tcp->dst_port), rohc_ntoh16(tcp->dst_port));

	return sizeof(tcphdr_t);
}


/**
 * @brief Decode the TCP dynamic part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param tcp_dynamic  The TCP dynamic part to decode
 * @param length       The length of the ROHC packet
 * @param tcp          The decoded TCP header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int tcp_decode_dynamic_tcp(struct d_context *const context,
                                  tcp_dynamic_t *tcp_dynamic,
                                  unsigned int length,
                                  tcphdr_t *tcp)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
	multi_ptr_t mptr;
	const uint8_t *remain_data;
	size_t remain_len;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;
	assert(tcp_dynamic != NULL);
	assert(tcp != NULL);

	remain_data = (const uint8_t *) tcp_dynamic;
	remain_len = length;

	rohc_decomp_debug(context, "context = %p, tcp_context = %p, "
	                  "tcp_dynamic = %p, length = %d, dest = %p\n",
	                  context, tcp_context, tcp_dynamic, length, tcp);

	/* check the minimal length to decode the TCP dynamic part */
	if(remain_len < sizeof(tcp_dynamic_t))
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
		             context->profile->id, "malformed TCP dynamic part: only "
		             "%zu bytes available while at least %zu bytes required "
		             "for mandatory fields of the TCP dynamic part\n",
		             remain_len, sizeof(tcp_dynamic_t));
		goto error;
	}

	mptr.tcp_dynamic = tcp_dynamic + 1;
	remain_data += sizeof(tcp_dynamic_t);
	remain_len -= sizeof(tcp_dynamic_t);
	rohc_decomp_debug(context, "TCP tcp_dynamic = %p, mptr.tcp_dynamic = %p\n",
	                  tcp_dynamic, mptr.tcp_dynamic);

	rohc_decomp_debug(context, "TCP res_flags = %d, ecn_flags = %d, "
	                  "rsf_flags = %d, URG = %d, ACK = %d, PSH = %d\n",
	                  tcp_dynamic->tcp_res_flags, tcp_dynamic->tcp_ecn_flags,
	                  tcp_dynamic->rsf_flags, tcp_dynamic->urg_flag,
	                  tcp_dynamic->ack_flag, tcp_dynamic->psh_flag);

	/* retrieve the TCP sequence number from the ROHC packet */
	tcp_context->ecn_used = tcp_dynamic->ecn_used;
	tcp->res_flags = tcp_dynamic->tcp_res_flags;
	tcp->ecn_flags = tcp_dynamic->tcp_ecn_flags;
	tcp->urg_flag = tcp_dynamic->urg_flag;
	tcp->ack_flag = tcp_dynamic->ack_flag;
	tcp->psh_flag = tcp_dynamic->psh_flag;
	tcp->rsf_flags = tcp_dynamic->rsf_flags;
	tcp_context->msn = rohc_ntoh16(tcp_dynamic->msn);
	rohc_decomp_debug(context, "MSN = 0x%04x\n", tcp_context->msn);
	tcp->seq_number = tcp_dynamic->seq_number;

	/* optional ACK number */
	if(tcp_dynamic->ack_zero == 1)
	{
		tcp->ack_number = 0;
	}
	else
	{
		if(remain_len < sizeof(uint32_t))
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id, "malformed TCP dynamic part: "
			             "only %zu bytes available while at least %zu bytes "
			             "required for the ACK number\n", remain_len,
			             sizeof(uint32_t));
			goto error;
		}
		tcp->ack_number = READ32_FROM_MPTR(mptr);
		remain_data += sizeof(uint32_t);
		remain_len -= sizeof(uint32_t);
	}
	rohc_decomp_debug(context, "tcp = %p, seq_number = 0x%x, "
	                  "ack_number = 0x%x\n", tcp, rohc_ntoh32(tcp->seq_number),
	                  rohc_ntoh32(tcp->ack_number));

	/* window */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
		             context->profile->id, "malformed TCP dynamic part: only "
		             "%zu bytes available while at least %zu bytes required "
		             "for the window\n", remain_len, sizeof(uint16_t));
		goto error;
	}
	tcp->window = READ16_FROM_MPTR(mptr);
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP window = 0x%04x\n",
	                  rohc_ntoh16(tcp->window));

	/* checksum */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
		             context->profile->id, "malformed TCP dynamic part: only "
		             "%zu bytes available while at least %zu bytes required "
		             "for the checksum\n", remain_len, sizeof(uint16_t));
		goto error;
	}
	tcp->checksum = READ16_FROM_MPTR(mptr);
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP checksum = 0x%04x\n",
	                  rohc_ntoh16(tcp->checksum));

	/* URG pointer */
	if(tcp_dynamic->urp_zero == 1)
	{
		tcp->urg_ptr = 0;
	}
	else
	{
		if(remain_len < sizeof(uint16_t))
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id, "malformed TCP dynamic part: "
			             "only %zu bytes available while at least %zu bytes "
			             "required for the URG pointer\n", remain_len,
			             sizeof(uint16_t));
			goto error;
		}
		tcp->urg_ptr = READ16_FROM_MPTR(mptr);
		remain_data += sizeof(uint16_t);
		remain_len -= sizeof(uint16_t);
	}
	rohc_decomp_debug(context, "TCP urg_ptr = 0x%04x\n",
	                  rohc_ntoh16(tcp->urg_ptr));

	/* ACK stride */
	if(tcp_dynamic->ack_stride_flag == 1)
	{
		tcp_context->ack_stride = 0;
	}
	else
	{
		if(remain_len < sizeof(uint16_t))
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id, "malformed TCP dynamic part: "
			             "only %zu bytes available while at least %zu bytes "
			             "required for the ACK stride\n", remain_len,
			             sizeof(uint16_t));
			goto error;
		}
		tcp_context->ack_stride = rohc_ntoh16(READ16_FROM_MPTR(mptr));
		remain_data += sizeof(uint16_t);
		remain_len -= sizeof(uint16_t);
	}
	if(tcp_context->ack_stride != 0)
	{
		// Calculate the Ack Number residue
		tcp_context->ack_number_residue =
			rohc_ntoh32(tcp->ack_number) % tcp_context->ack_stride;
	}
	rohc_decomp_debug(context, "TCP ack_stride = 0x%04x, ack_number_residue = "
	                  "0x%04x\n", tcp_context->ack_stride,
	                  tcp_context->ack_number_residue);

	/* we need at least one byte to check whether TCP options are present or
	 * not */
	if(remain_len < 1)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
		             context->profile->id, "malformed TCP dynamic part: only "
		             "%zu bytes available while at least 1 byte required for "
		             "the first byte of TCP options\n", remain_len);
		goto error;
	}

	/* If TCP option list compression present */
	if(((*mptr.uint8) & 0x0F) != 0)
	{
		uint8_t *pBeginOptions;
		uint8_t *pBeginList;
		uint8_t reserved;
		uint8_t PS;
		uint8_t present;
		uint8_t opt_idx;
		uint8_t m;
		uint8_t i;
		uint8_t *tcp_options;
		size_t opt_padding_len;
		int size;
		size_t indexes_len;

		/* read number of XI item(s) in the compressed list */
		reserved = remain_data[0] & 0xe0;
		m = remain_data[0] & 0x0F;
		PS = remain_data[0] & 0x10;
		if(reserved != 0)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id, "malformed TCP dynamic part: "
			             "malformed compressed list of TCP options: reserved "
			             "bits must be zero, but first byte is 0x%02x\n",
			             remain_data[0]);
			goto error;
		}
		mptr.uint8++;
		remain_data++;
		remain_len--;

		/* compute the length of the indexes, and the position of items */
		if(PS != 0)
		{
			indexes_len = m;
		}
		else
		{
			indexes_len = ((m + 1) >> 1);
		}
		rohc_decomp_debug(context, "TCP options list: %u %u-bit indexes "
		                  "transmitted on %zu bytes\n", m, (PS != 0 ? 8 : 4),
		                  indexes_len);

		/* enough remaining data for all indexes? */
		if(remain_len < indexes_len)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id, "malformed TCP dynamic part: "
			             "only %zu bytes available while at least %zu bytes "
			             "required for the list indexes\n", remain_len,
			             indexes_len);
			goto error;
		}
		pBeginList = mptr.uint8;
		mptr.uint8 += indexes_len;
		remain_data += indexes_len;
		remain_len -= indexes_len;

		/* save the begin of the item(s) */
		pBeginOptions = mptr.uint8;

		/* for all item(s) in the list */
		for(i = 0, size = 0; i < m; ++i)
		{
			/* if PS=1 indicating 8-bit XI field */
			if(PS != 0)
			{
				present = (*pBeginList) & 0x80;
				opt_idx = (*pBeginList) & 0x0F;
				++pBeginList;
			}
			else
			{
				/* if odd position */
				if(i & 1)
				{
					present = (*pBeginList) & 0x08;
					opt_idx = (*pBeginList) & 0x07;
					++pBeginList;
				}
				else
				{
					present = (*pBeginList) & 0x80;
					opt_idx = ((*pBeginList) & 0x70) >> 4;
				}
			}
			rohc_decomp_debug(context, "TCP options list: XI #%u: item for "
			                  "index %u is %s\n", i, opt_idx,
			                  (present ? "present" : "absent"));
			// item must present in dynamic part
			if(present == 0)
			{
				rohc_decomp_debug(context, "list item #%u not present: not "
				                  "allowed in dynamic part, packet is "
				                  "malformed\n", i);
				goto error;
			}
			/* if known index (see RFC4996 page 27) */
			if(opt_idx <= TCP_INDEX_SACK)
			{
				uint8_t opt_type;

				rohc_decomp_debug(context, "TCP options list: XI #%u: item for "
				                  "index %u is a known index\n", i, opt_idx);

				/* enough data for first byte of option? */
				if(remain_len < 1)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
					             context->profile->id, "malformed TCP dynamic "
					             "part: malformed TCP option items: only %zu "
					             "bytes available while at least 1 byte "
					             "required for next option\n", remain_len);
					goto error;
				}

				/* retrieve option type */
				opt_type = remain_data[0];
				rohc_decomp_debug(context, "TCP option type 0x%02x (%u)\n",
				                  opt_type, opt_type);
				mptr.uint8++;
				size++;
				remain_data++;
				remain_len--;

				/* save TCP option for this index */
				tcp_context->tcp_options_list[opt_idx] = opt_type;

				if(opt_type == TCP_OPT_EOL)
				{
					/* 1-byte EOL option */
					rohc_decomp_debug(context, "TCP option EOL\n");
				}
				else if(opt_type == TCP_OPT_NOP)
				{
					/* 1-byte NOP option */
					rohc_decomp_debug(context, "TCP option NOP\n");
				}
				else
				{
					/* option with type + length + data */

					uint8_t opt_len;

					/* enough data for the Length field? */
					if(remain_len < 1)
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "malformed TCP dynamic "
						             "part: malformed TCP option items: only %zu "
						             "bytes available while at least 1 byte "
						             "required for next option\n", remain_len);
						goto error;
					}

					/* retrieve option length */
					opt_len = remain_data[0];
					rohc_decomp_debug(context, "TCP option is %u-byte long (type "
					                  "and length fields included)\n", opt_len);
					if(opt_len < 2)
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "malformed TCP dynamic "
						             "part: malformed TCP option items: option "
						             "length should be at least 2 bytes, but is "
						             "only %u byte(s)\n", opt_len);
						goto error;
					}
					mptr.uint8++;
					size++;
					remain_data++;
					remain_len--;

					/* enough data for the remaining option data? */
					if(remain_len < (opt_len - 2))
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "malformed TCP dynamic "
						             "part: malformed TCP option items: only %zu "
						             "bytes available while at least %u bytes "
						             "required for next option\n", remain_len,
						             opt_len - 2);
						goto error;
					}

					switch(opt_type)
					{
						case TCP_OPT_MAXSEG:
							if(opt_len != TCP_OLEN_MAXSEG)
							{
								rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
								             context->profile->id, "malformed TCP "
								             "dynamic part: malformed TCP option "
								             "items: TCP option MAXSEG is %u-byte "
								             "long instead of %u-byte long\n",
								             opt_len, TCP_OLEN_MAXSEG);
								goto error;
							}
							memcpy(&tcp_context->tcp_option_maxseg, mptr.uint8, 2);
							rohc_decomp_debug(context, "TCP option MAXSEG = %d (0x%x)\n",
							                  rohc_ntoh16(tcp_context->tcp_option_maxseg),
							                  rohc_ntoh16(tcp_context->tcp_option_maxseg));
							break;
						case TCP_OPT_WINDOW:
							if(opt_len != TCP_OLEN_WINDOW)
							{
								rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
								             context->profile->id, "malformed TCP "
								             "dynamic part: malformed TCP option "
								             "items: TCP option WINDOW is %u-byte "
								             "long instead of %u-byte long\n",
								             opt_len, TCP_OLEN_WINDOW);
								goto error;
							}
							tcp_context->tcp_option_window = *mptr.uint8;
							rohc_decomp_debug(context, "TCP option WINDOW = %d\n",
							                  tcp_context->tcp_option_window);
							break;
						case TCP_OPT_SACK_PERMITTED:
							if(opt_len != TCP_OLEN_SACK_PERMITTED)
							{
								rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
								             context->profile->id, "malformed TCP "
								             "dynamic part: malformed TCP option "
								             "items: TCP option SACK PERMITTED is "
								             "%u-byte long instead of %u-byte long\n",
								             opt_len, TCP_OLEN_SACK_PERMITTED);
								goto error;
							}
							rohc_decomp_debug(context, "TCP option SACK PERMITTED\n");
							break;
						case TCP_OPT_SACK:
							tcp_context->tcp_option_sack_length = opt_len - 2;
							rohc_decomp_debug(context, "TCP option SACK Length = 2 + %d\n",
							                  tcp_context->tcp_option_sack_length);
							if(tcp_context->tcp_option_sack_length > (8 * 4))
							{
								rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
								             context->profile->id, "TCP dynamic "
								             "part: unexpected large %u-byte SACK "
								             "option\n",
								             tcp_context->tcp_option_sack_length);
								goto error;
							}
							memcpy(tcp_context->tcp_option_sackblocks, mptr.uint8,
							       tcp_context->tcp_option_sack_length);
							break;
						case TCP_OPT_TIMESTAMP:
							if(opt_len != TCP_OLEN_TIMESTAMP)
							{
								rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
								             context->profile->id, "malformed TCP "
								             "dynamic part: malformed TCP option "
								             "items: TCP option TIMESTAMP is %u-byte "
								             "long instead of %u-byte long\n",
								             opt_len, TCP_OLEN_TIMESTAMP);
								goto error;
							}
							rohc_decomp_debug(context, "TCP option TIMESTAMP\n");
							memcpy(&tcp_context->tcp_option_timestamp, mptr.uint8,
							       sizeof(struct tcp_option_timestamp));
							rohc_lsb_set_ref(tcp_context->opt_ts_req_lsb_ctxt,
							                 rohc_ntoh32(tcp_context->tcp_option_timestamp.ts),
							                 false);
							rohc_lsb_set_ref(tcp_context->opt_ts_reply_lsb_ctxt,
							                 rohc_ntoh32(tcp_context->tcp_option_timestamp.ts_reply),
							                 false);
							break;
						default:
							rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
							             context->profile->id, "TCP options list: "
							             "ignore unknown %u-byte option type 0x%02x "
							             "(%u)\n", opt_len, opt_type, opt_type);
							break;
					}

					/* skip the remaining option data */
					mptr.uint8 += opt_len - 2;
					size += opt_len - 2;
					remain_data += opt_len - 2;
					remain_len -= opt_len - 2;
				}
			}
			else /* unknown index */
			{
				uint8_t opt_type;
				uint8_t opt_len_lsb;
				uint8_t *pValue;

				rohc_decomp_debug(context, "TCP options list: XI #%u: item for "
				                  "index %u is an unknown index\n", i, opt_idx);

				/* enough data for first 2 bytes of option? */
				if(remain_len < 2)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
					             context->profile->id, "malformed TCP dynamic "
					             "part: malformed TCP option items: only %zu "
					             "bytes available while at least 2 bytes required "
					             "for next option\n", remain_len);
					goto error;
				}

				/* retrieve option type */
				opt_type = remain_data[0];
				mptr.uint8++;
				remain_data++;
				remain_len--;

				/* retrieve option length */
				opt_len_lsb = (*mptr.uint8) & 0x7f;
				if(opt_len_lsb < 2)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
					             context->profile->id, "malformed TCP dynamic "
					             "part: malformed TCP option items: option length "
					             "should be at least 2 bytes, but is only %u "
					             "byte(s)\n", opt_len_lsb);
					goto error;
				}
				mptr.uint8++;
				remain_data++;
				remain_len--;

				/* was index already used? */
				if(tcp_context->tcp_options_list[opt_idx] == 0xff)
				{

					/* index was never used before */
					/* save TCP option for this index */
					tcp_context->tcp_options_list[opt_idx] = opt_type;
					tcp_context->tcp_options_offset[opt_idx] =
						tcp_context->tcp_options_free_offset;
					pValue = tcp_context->tcp_options_values +
					         tcp_context->tcp_options_free_offset;
					/* save length (without option_static) */
					*pValue = opt_len_lsb - 2;
					rohc_decomp_debug(context, "%d-byte TCP option of type %d\n",
					                  *pValue, tcp_context->tcp_options_list[opt_idx]);
					/* enough data for last bytes of option? */
					if(remain_len < (*pValue))
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "malformed TCP dynamic "
						             "part: malformed TCP option items: only %zu "
						             "bytes available while at least %u bytes "
						             "required for next option\n", remain_len,
						             (*pValue));
						goto error;
					}
					/* save value */
					memcpy(pValue + 1, remain_data, *pValue);
					mptr.uint8 += *pValue;
					remain_data += *pValue;
					remain_len -= *pValue;
					/* update first free offset */
					tcp_context->tcp_options_free_offset += 1 + (*pValue);
					if(tcp_context->tcp_options_free_offset >= MAX_TCP_OPT_SIZE)
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "TCP options too large: "
						             "%u bytes while only %u are accepted\n",
						             tcp_context->tcp_options_free_offset,
						             MAX_TCP_OPT_SIZE);
						goto error;
					}
				}
				else /* index already used */
				{
					/* verify the value with the recorded one */
					rohc_decomp_debug(context, "tcp_options_list[%u] = %d <=> %d\n",
					                  opt_idx,
					                  tcp_context->tcp_options_list[opt_idx],
					                  opt_type);
					if(tcp_context->tcp_options_list[opt_idx] != opt_type)
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "unexpected TCP option "
						             "at index %u: 0x%02x received while 0x%02x "
						             "expected\n", opt_idx, opt_type,
						             tcp_context->tcp_options_list[opt_idx]);
						goto error;
					}
					pValue = tcp_context->tcp_options_values +
					         tcp_context->tcp_options_offset[opt_idx];
					if((opt_len_lsb - 2) != (*pValue))
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "malformed TCP dynamic "
						             "part: unexpected TCP option with index %u: "
						             "option length in packet (%u) does not match "
						             "option length in context (%u)\n", opt_idx,
						             opt_len_lsb, (*pValue) + 2);
						goto error;
					}
					if(memcmp(pValue + 1, remain_data, *pValue) != 0)
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "malformed TCP dynamic "
						             "part: unexpected TCP option with index %u: "
						             "option data in packet does not match option "
						             "option data in context\n", opt_idx);
						goto error;
					}
					mptr.uint8 += *pValue;
					remain_data += *pValue;
					remain_len -= *pValue;
				}
			}
		}

		/* copy TCP options from the ROHC packet after the TCP base header */
		tcp_options = ((uint8_t *) tcp) + sizeof(tcphdr_t);
		memcpy(tcp_options, pBeginOptions, mptr.uint8 - pBeginOptions);

		/* add padding after TCP options (they must be aligned on 32-bit words) */
		opt_padding_len =
			(sizeof(uint32_t) - (size % sizeof(uint32_t))) % sizeof(uint32_t);
		for(i = 0; i < opt_padding_len; i++)
		{
			rohc_decomp_debug(context, "add TCP EOL option for padding\n");
			tcp_options[size + i] = TCP_OPT_EOL;
		}
		size += opt_padding_len;
		assert((size % sizeof(uint32_t)) == 0);

		/* print TCP options */
		rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "decompressed TCP options",
		                 tcp_options, size);

		/* update data offset */
		tcp->data_offset = (sizeof(tcphdr_t) + size) >> 2;
		// read += 1 + ( mptr.uint8 - pBeginList );
	}
	else
	{
		/* update data offset */
		tcp->data_offset = sizeof(tcphdr_t) >> 2;
		rohc_decomp_debug(context, "TCP no options!\n");
		remain_data++;
		remain_len--;
	}

	assert(remain_len <= length);
	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "TCP dynamic part",
	                 (unsigned char *) tcp_dynamic, length - remain_len);

	return (length - remain_len);

error:
	return -1;
}


/**
 * @brief Decode the irregular TCP header of the rohc packet.
 *
 * See RFC4996 page 75
 *
 * @param context            The decompression context
 * @param base_header_inner  The inner IP header under built
 * @param tcp                The TCP header under built
 * @param rohc_data          The remain datas of the rohc packet
 * @return                   The current remain datas of the rohc packet
 */
static uint8_t * tcp_decode_irregular_tcp(struct d_context *const context,
                                           base_header_ip_t base_header_inner,
                                           tcphdr_t *tcp,
                                           uint8_t *rohc_data)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
	multi_ptr_t mptr;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;

	rohc_decomp_debug(context, "tcp_context = %p, base_header_inner = %p, "
	                  "tcp = %p, rohc_data = %p\n", tcp_context,
	                  base_header_inner.uint8, tcp, rohc_data);

	mptr.uint8 = rohc_data;

	// ip_ecn_flags = := tcp_irreg_ip_ecn(ip_inner_ecn)
	// tcp_res_flags =:= static_or_irreg(ecn_used.CVALUE,4)
	// tcp_ecn_flags =:= static_or_irreg(ecn_used.CVALUE,2)
	if(tcp_context->ecn_used != 0)
	{
		// See RFC4996 page 71
		if(base_header_inner.ipvx->version == IPV4)
		{
			base_header_inner.ipv4->ip_ecn_flags = *mptr.uint8 >> 6;
			rohc_decomp_debug(context, "read ip_ecn_flags = %d\n",
			                  base_header_inner.ipv4->ip_ecn_flags);
		}
		else
		{
			base_header_inner.ipv6->ip_ecn_flags = *mptr.uint8 >> 6;
			rohc_decomp_debug(context, "read ip_ecn_flags = %d\n",
			                  base_header_inner.ipv6->ip_ecn_flags);
		}
		tcp->ecn_flags = ( *mptr.uint8 >> 4 ) & 0x03;
		tcp->res_flags = *(mptr.uint8)++ & 0x0F;
		rohc_decomp_debug(context, "read TCP ecn_flags = %d, res_flags = %d\n",
		                  tcp->ecn_flags, tcp->res_flags);
	}
	else
	{
		// See RFC4996 page 71
		if(base_header_inner.ipvx->version == IPV4)
		{
			base_header_inner.ipv4->ip_ecn_flags = 0;
		}
		else
		{
			base_header_inner.ipv6->ip_ecn_flags = 0;
		}
		tcp->ecn_flags = 0;
		tcp->res_flags = 0;
		rohc_decomp_debug(context, "ip_ecn_flag = 0, tcp_ecn_flag = 0, and "
		                  "tcp_res_flag = 0\n");
	}

	// checksum =:= irregular(16)
	tcp->checksum = READ16_FROM_MPTR(mptr);
	rohc_decomp_debug(context, "read TCP checksum = 0x%04x\n",
	                  rohc_ntoh16(tcp->checksum));

	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "TCP irregular part", rohc_data,
	                 mptr.uint8 - rohc_data);

	return mptr.uint8;
}


/**
 * @brief Decompress the LSBs bits of TimeStamp TCP option
 *
 * See RFC4996 page 65
 *
 * @param context    The decompression context
 * @param lsb        The LSB decoding context
 * @param ptr        Pointer to the compressed value
 * @param timestamp  Pointer to the uncompressed value
 * @return           Pointer to the next compressed value
 */
static uint8_t * d_ts_lsb(const struct d_context *const context,
                          const struct rohc_lsb_decode *const lsb,
                          uint8_t *ptr,
                          uint32_t *const timestamp)
{
	uint32_t ts_bits;
	size_t ts_bits_nr;
	rohc_lsb_shift_t p;
	bool decode_ok;
	uint32_t decoded;

	assert(context != NULL);
	assert(lsb != NULL);
	assert(ptr != NULL);
	assert(timestamp != NULL);

	if(((*ptr) & 0x80) == 0)
	{
		/* discriminator '0' */
		ts_bits = *(ptr++);
		ts_bits_nr = 7;
		p = -1;
	}
	else if(((*ptr) & 0x40) == 0)
	{
		/* discriminator '10' */
		ts_bits = (*(ptr++) & 0x3F) << 8;
		ts_bits |= *(ptr++);
		ts_bits_nr = 14;
		p = -1;
	}
	else if(((*ptr) & 0x20) == 0)
	{
		/* discriminator '110' */
		ts_bits = (*(ptr++) & 0x1F) << 16;
		ts_bits |= *(ptr++) << 8;
		ts_bits |= *(ptr++);
		ts_bits_nr = 21;
		p = 0x40000;
	}
	else
	{
		/* discriminator '111' */
		ts_bits = (*(ptr++) & 0x1F) << 24;
		ts_bits |= *(ptr++) << 16;
		ts_bits |= *(ptr++) << 8;
		ts_bits |= *(ptr++);
		ts_bits_nr = 29;
		p = 0x40000;
	}

	decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, ts_bits, ts_bits_nr, p,
	                            &decoded);
	if(!decode_ok)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
		             context->profile->id,
		             "failed to decode %zu timestamp bits 0x%x with p = %u\n",
		             ts_bits_nr, ts_bits, p);
		goto error;
	}
	rohc_decomp_debug(context, "decoded timestamp = 0x%08x (%zu bits 0x%x "
	                  "with p = %d)\n", decoded, ts_bits_nr, ts_bits, p);

	*timestamp = rohc_hton32(decoded);

	return ptr;

error:
	return NULL;
}


/**
 * @brief Calculate the size of TimeStamp compressed TCP option
 *
 * @param ptr   Pointer to the compressed value
 * @return      Return the size of the compressed TCP option
 */
static int d_size_ts_lsb(uint8_t *ptr)
{
	if(*ptr & 0x80)
	{
		if(*ptr & 0x40)
		{
			if(*ptr & 0x20)
			{
				// Discriminator '111'
				return 4;
			}
			else
			{
				// Discriminator '110'
				return 3;
			}
		}
		else
		{
			// Discriminator '10'
			return 2;
		}
	}
	else
	{
		// Discriminator '0'
		return 1;
	}
}


/**
 * @brief Uncompress the SACK field value.
 *
 * See RFC6846 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param ptr       Pointer to the compressed value
 * @param base      The base value
 * @param field     Pointer to the uncompressed value
 * @return          Number of bytes read, -1 if error
 */
static int d_sack_pure_lsb(uint8_t *ptr,
                           uint32_t base,
                           uint32_t *field)
{
	uint32_t sack_field;
	size_t len;

	if(((*ptr) & 0x80) == 0)
	{
		/* discriminator '0' */
		sack_field = *(ptr++) << 8;
		sack_field |= *(ptr++);
		len = 2;
	}
	else if(((*ptr) & 0x40) == 0)
	{
		/* discriminator '10' */
		sack_field = *(ptr++) & 0x3f;
		sack_field <<= 8;
		sack_field |= *(ptr++);
		sack_field <<= 8;
		sack_field |= *(ptr++);
		len = 3;
	}
	else if(((*ptr) & 0x20) == 0)
	{
		/* discriminator '110' */
		sack_field = *(ptr++) & 0x1f;
		sack_field <<= 8;
		sack_field |= *(ptr++);
		sack_field <<= 8;
		sack_field |= *(ptr++);
		sack_field <<= 8;
		sack_field |= *(ptr++);
		len = 4;
	}
	else if((*ptr) == 0xff)
	{
		/* discriminator '11111111' */
		ptr++; /* skip discriminator */
		sack_field = *(ptr++);
		sack_field <<= 8;
		sack_field |= *(ptr++);
		sack_field <<= 8;
		sack_field |= *(ptr++);
		sack_field <<= 8;
		sack_field |= *(ptr++);
		len = 5;
	}
	else
	{
		goto error;
	}

	*field = rohc_hton32(base + sack_field);

	return len;

error:
	return -1;
}


/**
 * @brief Uncompress a SACK block
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param ptr        Pointer to the compressed value
 * @param reference  The reference value
 * @param sack_block Pointer to the uncompressed sack_block
 * @return           Pointer to the next compressed value
 */
static uint8_t * d_sack_block(uint8_t *ptr,
                              uint32_t reference,
                              sack_block_t *sack_block)
{
	int ret;

	/* decode block start */
	ret = d_sack_pure_lsb(ptr, reference, &sack_block->block_start);
	if(ret < 0)
	{
		goto error;
	}
	ptr += ret;

	/* decode block end */
	ret = d_sack_pure_lsb(ptr, rohc_ntoh32(sack_block->block_start),
	                      &sack_block->block_end);
	if(ret < 0)
	{
		goto error;
	}
	ptr += ret;

	return ptr;

error:
	return NULL;
}


/**
 * @brief Uncompress the SACK TCP option
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context    The decompression context
 * @param ptr        Pointer to the compressed value
 * @param pOptions   Pointer to the uncompressed option
 * @param ack_value  The ack value
 * @return           Pointer to the next compressed value
 */
static uint8_t * d_tcp_opt_sack(const struct d_context *const context,
                                uint8_t *ptr,
                                uint8_t **pOptions,
                                uint32_t ack_value)
{
	sack_block_t *sack_block;
	uint8_t discriminator;
	uint8_t *options;
	int i;

	assert(context != NULL);

	rohc_decomp_debug(context, "parse SACK option (reference ACK = 0x%08x)\n",
	                  ack_value);

	options = *pOptions;

	/* parse discriminator */
	discriminator = *ptr;
	ptr++;
	if(discriminator > 4)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "invalid discriminator value (%d)\n", discriminator);
		goto error;
	}

	/* option ID */
	*(options++) = TCP_OPT_SACK;
	/* option length */
	*(options++) = ( discriminator << 3 ) + 2;

	sack_block = (sack_block_t *) options;

	for(i = 0; i < discriminator; i++)
	{
		ptr = d_sack_block(ptr, ack_value, sack_block);
		if(ptr == NULL)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id,
			             "failed to decode block #%d of SACK option\n", i + 1);
			goto error;
		}
		rohc_decomp_debug(context, "block #%d of SACK option: start = 0x%08x, "
		                  "end = 0x%08x\n", i + 1,
		                  rohc_ntoh32(sack_block->block_start),
		                  rohc_ntoh32(sack_block->block_end));
		sack_block++;
	}
	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "TCP option SACK", options - 2,
	                 *(options - 1));
	*pOptions = (uint8_t *) sack_block;

	return ptr;

error:
	return NULL;
}


/**
 * @brief Calculate the size of the compressed SACK field value
 *
 * See RFC6846 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param ptr    Pointer to the compressed sack field value
 * @return       The size (in octets) of the compressed value
 */
static int d_sack_var_length_size_dec(uint8_t *ptr)
{
	int len;

	if(((*ptr) & 0x80) == 0)
	{
		/* discriminator '0' */
		len = 2;
	}
	else if(((*ptr) & 0x40) == 0)
	{
		/* discriminator '10' */
		len = 3;
	}
	else if(((*ptr) & 0x20) == 0)
	{
		/* discriminator '110' */
		len = 4;
	}
	else if((*ptr) == 0xff)
	{
		/* discriminator '11111111' */
		len = 5;
	}
	else
	{
		len = -1;
	}

	return len;
}


/**
 * @brief Calculate the size of the compressed SACK block
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param ptr          Pointer to the compressed sack block
 * @return             The size (in octets) of the compressed SACK block,
 *                     -1 in case of problem
 */
static int d_sack_block_size(uint8_t *ptr)
{
	int size;

	/* decode block start */
	size = d_sack_var_length_size_dec(ptr);
	if(size < 0)
	{
		goto error;
	}
	ptr += size;

	/* decode block end */
	size += d_sack_var_length_size_dec(ptr);
	if(size < 0)
	{
		goto error;
	}

	return size;

error:
	return -1;
}


/**
 * @brief Calculate the size of the SACK TCP option
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context            The decompression context
 * @param ptr                Pointer to the compressed SACK TCP option
 * @param uncompressed_size  Pointer to the uncompressed TCP option size
 * @return                   The size (in octets) of the compressed SACK TCP
 *                           option, -1 in case of problem
 */
static int d_tcp_size_opt_sack(const struct d_context *const context,
                               uint8_t *ptr,
                               uint16_t *uncompressed_size)
{
	uint8_t discriminator;
	int size = 0;
	int i;

	assert(context != NULL);

	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "next 16 bytes starting from the "
	                 "compressed TCP SACK option", ptr, 16);

	/* parse discriminator */
	discriminator = *ptr;
	ptr++;
	size++;
	if(discriminator > 4)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "invalid discriminator value (%d)\n", discriminator);
		goto error;
	}

	for(i = 0; i < discriminator; i++)
	{
		const int block_len = d_sack_block_size(ptr);
		if(block_len < 0)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id, "failed to determine the length "
			             " of SACK block #%d\n", i + 1);
			goto error;
		}
		size += block_len;
		ptr += block_len;
	}

	rohc_decomp_debug(context, "TCP SACK option is compressed on %d bytes\n",
	                  size);

	return size;

error:
	return -1;
}


/**
 * @brief Uncompress a generic TCP option
 *
 * See RFC4996 page 67
 *
 * @param tcp_context  The specific TCP context
 * @param ptr          Pointer to the compressed TCP option
 * @param pOptions     Pointer to the uncompressed TCP option
 * @return             Pointer to the next compressed value
 */
static uint8_t * d_tcp_opt_generic(struct d_tcp_context *tcp_context,
                                   uint8_t *ptr,
                                   uint8_t * *pOptions)
{
	uint8_t *options;

	options = *pOptions;

	// A COMPLETER

	switch(*ptr)
	{
		case 0x00:  // generic_full_irregular
			break;
		case 0xFF:  // generic_stable_irregular
			break;
	}

	*pOptions = options;

	return ptr;
}


/**
 * @brief Calculate the size of a generic TCP option
 *
 * See RFC4996 page 67
 *
 * @param tcp_context        The specific TCP context
 * @param ptr                Pointer to the compressed TCP option
 * @param uncompressed_size  Pointer to the uncompressed TCP option size
 * @return                   Pointer to the next compressed value
 */
static int d_tcp_size_opt_generic(struct d_tcp_context *tcp_context,
                                  uint8_t *ptr,
                                  uint16_t *uncompressed_size)
{
	int size = 0;

	/* to be completed */

	return size;
}


/**
 * @brief Uncompress the TCP options
 *
 * @param context  The decompression context
 * @param tcp      The TCP header
 * @param ptr      Pointer to the compressed TCP options
 * @return         Pointer to the next compressed value
 */
static uint8_t * tcp_decompress_tcp_options(struct d_context *const context,
                                            tcphdr_t *tcp,
                                            uint8_t *ptr)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
	uint8_t *compressed_options;
	uint8_t *options;
	uint8_t present;
	uint8_t *pValue;
	uint8_t PS;
	uint8_t opt_idx;
	int m;
	int i;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;

	/* init pointer to destination TCP options */
	options = (uint8_t*) ( tcp + 1 );

	// see RFC4996 page 25-26
	PS = *ptr & 0x10;
	m = *(ptr++) & 0x0F;

	rohc_decomp_debug(context, "tcp = %p, options = %p, PS = 0x%x, m = %d\n",
	                  tcp, options, PS, m);

	if(PS == 0)
	{
		compressed_options = ptr + ( (m + 1) >> 1 );
	}
	else
	{
		compressed_options = ptr + m;
	}

	for(i = 0; m != 0; --m)
	{

		/* 4-bit XI fields */
		if(PS == 0)
		{
			/* if odd digit */
			if(i & 1)
			{
				opt_idx = *(ptr++);
			}
			else
			{
				opt_idx = (*ptr) >> 4;
			}
			present = opt_idx & 0x08;
			opt_idx &= 0x07;
			++i;
		}
		else
		{
			/* 8-bit XI fields */
			present = (*ptr) & 0x80;
			opt_idx = *(ptr++) & 0x0F;
		}

		rohc_decomp_debug(context, "TCP option index %u %s\n", opt_idx,
		                  present == 0 ? "" : "present");

		if(present)
		{
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:  // NOP
					*(options++) = TCP_OPT_NOP;
					break;
				case TCP_INDEX_EOL:  // EOL
					*(options++) = TCP_OPT_EOL;
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					*(options++) = TCP_OPT_MAXSEG;
					// Length
					*(options++) = TCP_OLEN_MAXSEG;
					// Max segment size
					memcpy(&tcp_context->tcp_option_maxseg,compressed_options,2);
					*(options++) = *(compressed_options++);
					*(options++) = *(compressed_options++);
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					*(options++) = TCP_OPT_WINDOW;
					// Length
					*(options++) = TCP_OLEN_WINDOW;
					// Window scale
					tcp_context->tcp_option_window =
					   *(options++) = *(compressed_options++);
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
					*(options++) = TCP_OPT_TIMESTAMP;
					// Length
					*(options++) = TCP_OLEN_TIMESTAMP;
					// Timestamp
					// compressed_options = d_tcp_opt_ts(compressed_options);
					compressed_options =
						d_ts_lsb(context, tcp_context->opt_ts_req_lsb_ctxt,
						         compressed_options, (uint32_t *) options);
					if(compressed_options == NULL)
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "failed to decompress "
						             "TCP option Timestamp echo request\n");
						goto error;
					}
					rohc_lsb_set_ref(tcp_context->opt_ts_req_lsb_ctxt,
					                 rohc_ntoh32(*((uint32_t *) options)), false);
					compressed_options =
					   d_ts_lsb(context, tcp_context->opt_ts_reply_lsb_ctxt,
					            compressed_options, (uint32_t *) (options + 4));
					if(compressed_options == NULL)
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "failed to decompress "
						             "TCP option Timestamp echo reply\n");
						goto error;
					}
					rohc_lsb_set_ref(tcp_context->opt_ts_reply_lsb_ctxt,
					                 rohc_ntoh32(*((uint32_t *) (options + 4))),
					                 false);
					memcpy(&tcp_context->tcp_option_timestamp, options,
							 sizeof(struct tcp_option_timestamp));
					options += sizeof(struct tcp_option_timestamp);
					break;
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					*(options++) = TCP_OPT_SACK_PERMITTED;
					// Length
					*(options++) = TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					                   // TODO: save into context
					compressed_options = d_tcp_opt_sack(context, compressed_options,
					                                    &options,
					                                    rohc_ntoh32(tcp->ack_number));
					if(compressed_options == NULL)
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "failed to decompress "
						             "TCP SACK option\n");
						goto error;
					}
					break;
				default:  // Generic options
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
					             context->profile->id, "TCP option with index %u "
					             "not handled\n", opt_idx);
					// TODO
					compressed_options = d_tcp_opt_generic(tcp_context,compressed_options,&options);
					break;
			}
		}
		else
		{
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:  // NOP
					*(options++) = TCP_OPT_NOP;
					break;
				case TCP_INDEX_EOL:  // EOL
					*(options++) = TCP_OPT_EOL;
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					*(options++) = TCP_OPT_MAXSEG;
					// Length
					*(options++) = TCP_OLEN_MAXSEG;
					// Max segment size value
					memcpy(options,&tcp_context->tcp_option_maxseg,2);
					options += TCP_OLEN_MAXSEG - 2;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					*(options++) = TCP_OPT_WINDOW;
					// Length
					*(options++) = TCP_OLEN_WINDOW;
					// Window scale value
					*(options++) = tcp_context->tcp_option_window;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
					*(options++) = TCP_OPT_TIMESTAMP;
					// Length
					*(options++) = TCP_OLEN_TIMESTAMP;
					// Timestamp value
					memcpy(options, &tcp_context->tcp_option_timestamp,
							 sizeof(struct tcp_option_timestamp));
					options += TCP_OLEN_TIMESTAMP - 2;
					break;
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					*(options++) = TCP_OPT_SACK_PERMITTED;
					// Length
					*(options++) = TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					*(options++) = TCP_OPT_SACK;
					// Length
					*(options++) = tcp_context->tcp_option_sack_length;
					// Value
					memcpy(options,&tcp_context->tcp_option_sackblocks,
					       tcp_context->tcp_option_sack_length);
					options += tcp_context->tcp_option_sack_length;
					break;
				default:  // Generic options
					rohc_decomp_debug(context, "TCP option with index %u not "
					                  "handled\n", opt_idx);
					*(options++) = tcp_context->tcp_options_list[opt_idx];
					pValue = tcp_context->tcp_options_values +
					         tcp_context->tcp_options_offset[opt_idx];
					// Length
					*(options++) = *pValue;
					// Value
					memcpy(options,pValue + 1,*pValue);
					options += (*pValue) + 2;
					break;
			}
		}
	}

	// Pad with nul
	for(i = options - ( (uint8_t*) tcp ); i & 0x03; ++i)
	{
		rohc_decomp_debug(context, "add TCP EOL option for padding\n");
		*(options++) = TCP_OPT_EOL;
	}

	/* Calculate TCP header length with TCP options */
	tcp->data_offset = ( options - ( (uint8_t*) tcp ) )  >> 2;
	rohc_decomp_debug(context, "TCP data_offset = %d (0x%x)\n",
	                  tcp->data_offset, tcp->data_offset);
	if(tcp->data_offset > ( sizeof(tcphdr_t) >> 2 ) )
	{
		rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "TCP options",
		                 (unsigned char *) (tcp + 1),
		                 (tcp->data_offset << 2) - sizeof(tcphdr_t));
	}

	return compressed_options;

error:
	return NULL;
}


/**
 * @brief Calculate the compressed TCP options size
 *
 * See RFC6846 pages 26-27.
 *
 * @param context            The decompression context
 * @param ptr                Pointer to the compressed TCP options
 * @param uncompressed_size  Pointer to the uncompressed TCP option size
 * @return                   Pointer to the next compressed value
 */
static int tcp_size_decompress_tcp_options(struct d_context *const context,
                                           uint8_t *ptr,
                                           uint16_t *uncompressed_size)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
	uint8_t *items;
	uint8_t present;
	uint8_t PS;
	uint8_t opt_idx;
	size_t xi_len;
	int comp_size;
	int m;
	int i;
	int j;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;

	comp_size = 0;
	*uncompressed_size = 0;

	/* PS/m byte */
	PS = *ptr & 0x10;
	m = *ptr & 0x0F;
	ptr++;
	comp_size++;

	if(PS == 0)
	{
		/* 4-bit XI fields */
		xi_len = (m + 1) >> 1;
	}
	else
	{
		/* 8-bit XI fields */
		xi_len = m;
	}
	rohc_decomp_debug(context, "TCP options list: %d-bit XI fields are used "
							"on %zd bytes\n", (PS == 0 ? 4 : 8), xi_len);
	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "XI bytes of compressed list of TCP "
	                 "options", ptr, xi_len);
	comp_size += xi_len;
	items = ptr + xi_len;

	for(i = 0; m != 0; i++, m--)
	{

		/* 4-bit XI fields */
		if(PS == 0)
		{
			/* if odd digit */
			if(i & 1)
			{
				opt_idx = *(ptr++);
			}
			else
			{
				opt_idx = (*ptr) >> 4;
			}
			present = opt_idx & 0x08;
			opt_idx &= 0x07;
			rohc_decomp_debug(context, "TCP options list: 4-bit XI field #%d: "
			                  "item with index %u is %s\n", i, opt_idx,
			                  present ? "present" : "not present");
		}
		else
		{
			/* 8-bit XI fields */
			present = (*ptr) & 0x80;
			opt_idx = *(ptr++) & 0x0F;
			rohc_decomp_debug(context, "TCP options list: 8-bit XI field #%d: "
			                  "item with index %u is %s\n", i, opt_idx,
			                  present ? "present" : "not present");
		}

		// If item present
		if(present)
		{
			size_t comp_opt_len = 0;

			switch(opt_idx)
			{
				case TCP_INDEX_NOP:  // NOP
					++(*uncompressed_size);
					break;
				case TCP_INDEX_EOL:  // EOL
					++(*uncompressed_size);
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					*uncompressed_size += TCP_OLEN_MAXSEG;
					comp_opt_len += 2;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					*uncompressed_size += TCP_OLEN_WINDOW;
					comp_opt_len++;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
					*uncompressed_size += TCP_OLEN_TIMESTAMP;
					j = d_size_ts_lsb(items);
					items += j;
					comp_opt_len += j;
					j = d_size_ts_lsb(items);
					items += j;
					comp_opt_len += j;
					break;
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					*uncompressed_size += TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					j = d_tcp_size_opt_sack(context, items, uncompressed_size);
					if(j < 0)
					{
						rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
						             context->profile->id, "failed to determine "
						             "the length of compressed TCP SACK option\n");
					}
					items += j;
					comp_opt_len += j;
					break;
				default:  // Generic options
					rohc_decomp_debug(context, "TCP option with index %u not "
					                  "handled\n", opt_idx);
					j = d_tcp_size_opt_generic(tcp_context, items,
					                           uncompressed_size);
					items += j;
					comp_opt_len += j;
					break;
			}
			rohc_decomp_debug(context, "TCP option with index %u is %zd-byte "
			                  "long in compressed packet\n", opt_idx,
			                  comp_opt_len);
			comp_size += comp_opt_len;
		}
		else
		{
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:  // NOP
					++(*uncompressed_size);
					break;
				case TCP_INDEX_EOL:  // EOL
					++(*uncompressed_size);
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					*uncompressed_size += TCP_OLEN_MAXSEG;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					*uncompressed_size += TCP_OLEN_WINDOW;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
					*uncompressed_size += TCP_OLEN_TIMESTAMP;
					break;
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					*uncompressed_size += TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					*uncompressed_size += *(tcp_context->tcp_options_values +
					                        tcp_context->tcp_options_list[opt_idx]);
					break;
				default:  // Generic options
					*uncompressed_size += *(tcp_context->tcp_options_values +
					                        tcp_context->tcp_options_list[opt_idx]);
					break;
			}
		}
	}

	rohc_decomp_debug(context, "TCP options: compressed length = %d bytes, "
	                  "uncompressed length = %d bytes\n", comp_size,
	                  *uncompressed_size);

	return comp_size;
}


/**
 * @brief Decode one CO packet.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param add_cid_len    The length of the optional Add-CID field
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    The type of the ROHC packet to parse
 * @param dest           OUT: The decoded IP packet
 * @return               The length of the uncompressed IP packet
 *                       or ROHC_ERROR if an error occurs
 *                       or ROHC_ERROR_CRC if a CRC error occurs
 */
static int d_tcp_decode_CO(struct rohc_decomp *decomp,
                           struct d_context *context,
                           const unsigned char *const rohc_packet,
                           const unsigned int rohc_length,
                           const size_t add_cid_len,
                           const size_t large_cid_len,
                           const rohc_packet_t packet_type,
                           unsigned char *dest)
{
	struct d_generic_context *g_context;
	struct d_tcp_context *tcp_context;
	ip_context_ptr_t ip_inner_context;
	ip_context_ptr_t ip_context;
	uint16_t tcp_options_size = 0;
	uint8_t seq_number_scaled_used = 0;
	uint32_t seq_number_scaled = 0;
	uint8_t header_crc;
	uint8_t protocol;
	uint8_t crc;
	uint16_t msn;
	int size_header;
	int size_options = 0;
	int size;
	WB_t wb;
	int ttl_irregular_chain_flag = 0;
	int ip_inner_ecn;
	WB_t ip_id;

	size_t crc_type;
	bool is_list_present = false;

	/* lengths of ROHC and uncompressed headers to be computed during parsing */
	unsigned int rohc_header_len;
	unsigned int uncomp_header_len;

	/* remaining ROHC data not parsed yet */
	unsigned char *rohc_remain_data;

	/* ROHC and uncompressed payloads (they are the same) */
	unsigned int payload_len;

	base_header_ip_t base_header_inner;
	base_header_ip_t base_header;
	multi_ptr_t c_base_header;
	multi_ptr_t mptr;
	tcphdr_t *tcp;

	assert(decomp != NULL);
	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	tcp_context = g_context->specific;
	assert(rohc_packet != NULL);
	rohc_remain_data = (unsigned char *) rohc_packet;
	assert(add_cid_len == 0 || add_cid_len == 1);
	assert(large_cid_len >= 0 && large_cid_len <= 2);
	assert(dest != NULL);

	ip_context.uint8 = tcp_context->ip_context;

	rohc_decomp_debug(context, "context = %p, g_context = %p, "
	                  "tcp_context = %p, add_cid_len = %zd, "
	                  "large_cid_len = %zd, rohc_packet = %p, "
	                  "rohc_length = %d\n", context, g_context, tcp_context,
	                  add_cid_len, large_cid_len, rohc_packet, rohc_length);

	rohc_decomp_debug(context, "copy octet 0x%02x to offset %zd\n",
	                  *rohc_packet, large_cid_len);
	c_base_header.uint8 = (uint8_t*) rohc_packet + large_cid_len;
	*c_base_header.uint8 = *rohc_packet;

	/* skip the optional large CID bytes */
	rohc_remain_data += large_cid_len;
	rohc_header_len = large_cid_len;


	rohc_decomp_debug(context, "context = %p, remain_data = %p\n", context,
	                  rohc_remain_data);

	rohc_decomp_debug(context, "rohc_packet = %p, compressed base header = %p\n",
	                  rohc_packet, c_base_header.uint8);

	switch(packet_type)
	{
		case ROHC_PACKET_TCP_RND_1:
			assert( c_base_header.rnd1->discriminator == 0x2E ); // '101110'
			size_header = sizeof(rnd_1_t);
			header_crc = c_base_header.rnd1->header_crc;
			c_base_header.rnd1->header_crc = 0;
			msn = c_base_header.rnd1->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_RND_2:
			assert( c_base_header.rnd2->discriminator == 0x0C ); // '1100'
			size_header = sizeof(rnd_2_t);
			header_crc = c_base_header.rnd2->header_crc;
			c_base_header.rnd2->header_crc = 0;
			msn = c_base_header.rnd2->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_RND_3:
			assert( c_base_header.rnd3->discriminator == 0x00 ); // '0'
			size_header = sizeof(rnd_3_t);
			header_crc = c_base_header.rnd3->header_crc;
			c_base_header.rnd3->header_crc = 0;
			msn = c_base_header.rnd3->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_RND_4:
			assert( c_base_header.rnd4->discriminator == 0x0D ); // '1101'
			size_header = sizeof(rnd_4_t);
			header_crc = c_base_header.rnd4->header_crc;
			c_base_header.rnd4->header_crc = 0;
			msn = c_base_header.rnd4->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_RND_5:
			assert( c_base_header.rnd5->discriminator == 0x04 ); // '100'
			size_header = sizeof(rnd_5_t);
			header_crc = c_base_header.rnd5->header_crc;
			c_base_header.rnd5->header_crc = 0;
			msn = c_base_header.rnd5->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_RND_6:
			assert( c_base_header.rnd6->discriminator == 0x0A ); // '1010'
			size_header = sizeof(rnd_6_t);
			header_crc = c_base_header.rnd6->header_crc;
			c_base_header.rnd6->header_crc = 0;
			msn = c_base_header.rnd6->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_RND_7:
			assert( c_base_header.rnd7->discriminator == 0x2F ); // '101111'
			size_header = sizeof(rnd_7_t);
			header_crc = c_base_header.rnd7->header_crc;
			c_base_header.rnd7->header_crc = 0;
			msn = c_base_header.rnd7->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_RND_8:
			assert( c_base_header.rnd8->discriminator == 0x16 ); // '10110'
			size_header = sizeof(rnd_8_t);
			header_crc = c_base_header.rnd8->header_crc;
			c_base_header.rnd8->header_crc = 0;
			msn = (c_base_header.rnd8->msn1 << 3) | c_base_header.rnd8->msn2;
			rohc_decomp_debug(context, "rnd_8: size_header = %d\n", size_header);
			if(c_base_header.rnd8->list_present)
			{
				is_list_present = true;
			}
			crc_type = 7;
			break;

		case ROHC_PACKET_TCP_SEQ_1:
			assert( c_base_header.seq1->discriminator == 0x0A ); // '1010'
			size_header = sizeof(seq_1_t);
			header_crc = c_base_header.seq1->header_crc;
			c_base_header.seq1->header_crc = 0;
			msn = c_base_header.seq1->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_SEQ_2:
			assert( c_base_header.seq2->discriminator == 0x1A ); // '11010'
			size_header = sizeof(seq_2_t);
			header_crc = c_base_header.seq2->header_crc;
			c_base_header.seq2->header_crc = 0;
			msn = c_base_header.seq2->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_SEQ_3:
			assert( c_base_header.seq3->discriminator == 0x09 ); // '1001'
			size_header = sizeof(seq_3_t);
			header_crc = c_base_header.seq3->header_crc;
			c_base_header.seq3->header_crc = 0;
			msn = c_base_header.seq3->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_SEQ_4:
			assert( c_base_header.seq4->discriminator == 0x00 ); // '0'
			size_header = sizeof(seq_4_t);
			header_crc = c_base_header.seq4->header_crc;
			c_base_header.seq4->header_crc = 0;
			msn = c_base_header.seq4->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_SEQ_5:
			assert( c_base_header.seq5->discriminator == 0x08 ); // '1000'
			size_header = sizeof(seq_5_t);
			header_crc = c_base_header.seq5->header_crc;
			c_base_header.seq5->header_crc = 0;
			msn = c_base_header.seq5->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_SEQ_6:
			assert( c_base_header.seq6->discriminator == 0x1B ); // '11011'
			size_header = sizeof(seq_6_t);
			header_crc = c_base_header.seq6->header_crc;
			c_base_header.seq6->header_crc = 0;
			msn = c_base_header.seq6->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_SEQ_7:
			assert( c_base_header.seq7->discriminator == 0x0C ); // '1100'
			size_header = sizeof(seq_7_t);
			header_crc = c_base_header.seq7->header_crc;
			c_base_header.seq7->header_crc = 0;
			msn = c_base_header.seq7->msn;
			crc_type = 3;
			break;

		case ROHC_PACKET_TCP_SEQ_8:
			assert( c_base_header.seq8->discriminator == 0x0B ); // '1011'
			size_header = sizeof(seq_8_t);
			header_crc = c_base_header.seq8->header_crc;
			c_base_header.seq8->header_crc = 0;
			msn = c_base_header.seq8->msn;
			rohc_decomp_debug(context, "seq_8: size_header = %d\n", size_header);
			if(c_base_header.seq8->list_present)
			{
				is_list_present = true;
			}
			crc_type = 7;
			break;

		case ROHC_PACKET_TCP_CO_COMMON:
			assert( c_base_header.co_common->discriminator == 0x7D ); // '1111101'
			size_header = sizeof(co_common_t);
			size_options +=
				variable_length_32_size[c_base_header.co_common->seq_indicator];
			rohc_decomp_debug(context, "seq_indicator = %d => %d bytes of "
			                  "options\n",
			                  c_base_header.co_common->seq_indicator,
			                  size_options);
			size_options +=
				variable_length_32_size[c_base_header.co_common->ack_indicator];
			rohc_decomp_debug(context, "ack_indicator = %d => %d bytes of "
			                  "options\n",
			                  c_base_header.co_common->ack_indicator,
			                  size_options);
			size_options += c_base_header.co_common->ack_stride_indicator << 1;
			rohc_decomp_debug(context, "ack_stride_indicator = %d => %d bytes "
			                  "of options\n",
	   		               c_base_header.co_common->ack_stride_indicator,
									size_options);
			size_options += c_base_header.co_common->window_indicator << 1;
			rohc_decomp_debug(context, "window_indicator = %d => %d bytes of "
			                  "options\n",
			                  c_base_header.co_common->window_indicator,
			                  size_options);
			if(c_base_header.co_common->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL ||
			   c_base_header.co_common->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
			{
				size_options += c_base_header.co_common->ip_id_indicator + 1;
			}
			rohc_decomp_debug(context, "ip_id_behavior = %d, ip_id_indicator "
			                  "= %d => %d bytes of options\n",
			                  c_base_header.co_common->ip_id_behavior,
			                  c_base_header.co_common->ip_id_indicator,
			                  size_options);
			size_options += c_base_header.co_common->urg_ptr_present << 1;
			rohc_decomp_debug(context, "urg_ptr_present = %d => %d bytes of "
			                  "options\n",
			                  c_base_header.co_common->urg_ptr_present,
			                  size_options);
			size_options += c_base_header.co_common->dscp_present;
			rohc_decomp_debug(context, "dscp_present = %d => %d bytes of "
			                  "options\n", c_base_header.co_common->dscp_present,
			                  size_options);
			size_options += c_base_header.co_common->ttl_hopl_present;
			rohc_decomp_debug(context, "ttl_hopl_present = %d => %d bytes of "
			                  "options\n",
			                  c_base_header.co_common->ttl_hopl_present,
			                  size_options);
			rohc_decomp_debug(context, "list_present = %d\n",
			                  c_base_header.co_common->list_present);

			rohc_decomp_debug(context, "common size = header (%d) + options "
			                  "(%d) = %d\n", size_header, size_options,
			                  size_header + size_options);

			/* check the crc */
			header_crc = c_base_header.co_common->header_crc;
			c_base_header.co_common->header_crc = 0;

			msn = c_base_header.co_common->msn;

			if(c_base_header.co_common->list_present)
			{
				is_list_present = true;
			}
			else
			{
				mptr.uint8 = c_base_header.uint8 + size_header + size_options;
			}
			crc_type = 7;
			break;

		default:
			/* should not happen */
			assert(0);
			goto error;
	}

	if(is_list_present)
	{
		mptr.uint8 = c_base_header.uint8 + size_header + size_options;
		rohc_decomp_debug(context, "list present at %p: PS_m = 0x%x\n",
		                  mptr.uint8, *mptr.uint8);
		rohc_dump_packet(context->decompressor->trace_callback,
		                 ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "list of options", mptr.uint8,
		                 16); /* TODO: why 16 ??? */
		size_options += tcp_size_decompress_tcp_options(context, mptr.uint8,
		                                                &tcp_options_size);
		rohc_decomp_debug(context, "size = header (%d) + options (%d) = %d\n",
		                  size_header, size_options, size_header + size_options);
	}

	switch(crc_type)
	{
		case 7:
			crc = crc_calculate(ROHC_CRC_TYPE_7,  c_base_header.uint8,
			                    size_header + size_options, CRC_INIT_7,
			                    decomp->crc_table_7);
			break;
		case 3:
			mptr.uint8 = c_base_header.uint8 + size_header;
			crc = crc_calculate(ROHC_CRC_TYPE_3,  c_base_header.uint8,
			                    size_header, CRC_INIT_3, decomp->crc_table_3);
			break;
		default:
			/* should not happen */
			assert(0);
			goto error;
	}

	if(header_crc != crc)
	{
		rohc_decomp_debug(context, "header_crc (0x%x) != crc (0x%x) on %d "
		                  "bytes\n", header_crc, crc,
		                  size_header + size_options);
		rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "decompressed packet",
							  c_base_header.uint8, size_header);
		goto error;
	}
	rohc_decomp_debug(context, "header_crc (0x%x) == crc (0x%x) on %d bytes\n",
	                  header_crc, crc, size_header);

	// Check the MSN received with MSN required
	if( ( (tcp_context->msn + 1) & 0x000F ) != msn)
	{
		rohc_decomp_debug(context, "last_msn = 0x%04x, waiting for msn = 0x%x, "
		                  "received 0x%x!\n", tcp_context->msn,
		                  (tcp_context->msn + 1) & 0x000F, msn);
		// To be completed !!!
		// Store and rework packets
	}
	else
	{
		rohc_decomp_debug(context, "last msn (0x%04x) + 1 = 0x%04x, received = "
		                  "0x%x\n", tcp_context->msn, tcp_context->msn + 1,
		                  msn);
	}
	msn = d_lsb(context, 4, 4, tcp_context->msn + 1, msn);
	rohc_decomp_debug(context, "MSN = 0x%04x\n", msn);

	rohc_decomp_debug(context, "rohc_length = %d, size header = %d "
	                  "-> payload_len = %d\n", rohc_length, size_header +
	                  size_options, rohc_length - (size_header + size_options));

	rohc_header_len += size_header + size_options;


	payload_len = rohc_length - (size_header + size_options) + large_cid_len;
	rohc_header_len = size_header + size_options + large_cid_len;
	rohc_decomp_debug(context, "payload_len = %d\n", payload_len);

	/* reset the correction counter */
	g_context->correction_counter = 0;

	/* build the IP headers */
	base_header.uint8 = (uint8_t*) dest;
	ip_context.uint8 = tcp_context->ip_context;
	uncomp_header_len = 0;

	do
	{
		base_header_inner.uint8 = base_header.uint8;
		ip_inner_context.uint8 = ip_context.uint8;

		/* check minimal length */
		if(ip_context.vx->version == IPV4)
		{
			if((ip_context.uint8 + sizeof(ipv4_context_t)) >
				(tcp_context->ip_context + MAX_IP_CONTEXT_SIZE))
			{
				goto error;
			}
		}
		else if(ip_context.vx->version == IPV6)
		{
			if((ip_context.uint8 + sizeof(ipv6_context_t)) >
			   (tcp_context->ip_context + MAX_IP_CONTEXT_SIZE))
			{
				goto error;
			}
		}
		else
		{
			goto error;
		}

		/* Init static part in IP header */
		uncomp_header_len += tcp_copy_static_ip(context, ip_context, base_header);

		/* Copy last dynamic ip */
		if(ip_context.vx->version == IPV4)
		{
			base_header.ipv4->dscp = ip_context.v4->dscp;
			ip_inner_ecn =
			   base_header.ipv4->ip_ecn_flags = ip_context.v4->ip_ecn_flags;
			base_header.ipv4->mf = 0;
			base_header.ipv4->rf = 0;
#if WORDS_BIGENDIAN != 1
			base_header.ipv4->frag_offset1 = 0;
			base_header.ipv4->frag_offset2 = 0;
#else
			base_header.ipv4->frag_offset = 0;
#endif
			base_header.ipv4->ttl_hopl = ip_context.v4->ttl_hopl;
			protocol = ip_context.v4->protocol;
			++base_header.ipv4;
			++ip_context.v4;
		}
		else
		{
			ip_inner_ecn = base_header.ipv6->ip_ecn_flags;
			base_header.ipv6->dscp1 = ip_context.v6->dscp >> 2;
			base_header.ipv6->dscp2 = ip_context.v6->dscp & 0x03;
			base_header.ipv6->ttl_hopl = ip_context.v6->ttl_hopl;
			protocol = ip_context.v6->next_header;
			++base_header.ipv6;
			++ip_context.v6;
		}

		rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "current IP packet", dest,
		                 uncomp_header_len);

		assert(ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE]);

	}
	while(protocol != ROHC_IPPROTO_TCP);

	tcp = base_header.tcphdr;
	assert( tcp == (tcphdr_t*)( dest + uncomp_header_len ) );

	/* static TCP part */
	tcp_copy_static_tcp(context, tcp);

	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "current IP + TCP packet", dest,
	                 uncomp_header_len + sizeof(tcphdr_t));

	/* dynamic part */

	assert( packet_type != ROHC_PACKET_UNKNOWN );

	// Reinit pointer
	mptr.uint8 = c_base_header.uint8 + size_header;

	rohc_decomp_debug(context, "packet type = %d, begin compressed options "
	                  "= %p\n", packet_type, mptr.uint8);

	if(packet_type == ROHC_PACKET_TCP_CO_COMMON)
	{
		rohc_decomp_debug(context, "decode co_common packet\n");

		tcp->res_flags = tcp_context->old_tcphdr.res_flags;
		tcp->urg_flag = tcp_context->old_tcphdr.urg_flag;
		tcp->urg_ptr = tcp_context->old_tcphdr.urg_ptr;

		ttl_irregular_chain_flag = c_base_header.co_common->ttl_hopl_outer_flag;
		tcp->ack_flag = c_base_header.co_common->ack_flag;
		tcp->psh_flag = c_base_header.co_common->psh_flag;
		tcp->rsf_flags = rsf_index_dec( c_base_header.co_common->rsf_flags );
		rohc_decomp_debug(context, "ack_flag = %d, psh_flag = %d, "
		                  "rsf_flags = %d\n", tcp->ack_flag, tcp->psh_flag,
		                  tcp->rsf_flags);
		tcp->seq_number = variable_length_32_dec(context, &mptr,
		                                         c_base_header.co_common->seq_indicator);
		rohc_decomp_debug(context, "seq_number = 0x%x\n", rohc_ntoh32(tcp->seq_number));
		tcp->ack_number = variable_length_32_dec(context, &mptr,
		                                         c_base_header.co_common->ack_indicator);
		rohc_decomp_debug(context, "ack_number = 0x%x\n", rohc_ntoh32(tcp->ack_number));
		tcp_context->ack_stride =
		   rohc_hton16( d_static_or_irreg16(&mptr,tcp_context->ack_stride,
		                              c_base_header.co_common->ack_stride_indicator) );
		rohc_decomp_debug(context, "ack_stride = 0x%x\n", tcp_context->ack_stride);
		tcp->window = d_static_or_irreg16(&mptr,tcp_context->old_tcphdr.window,
		                                  c_base_header.co_common->window_indicator);
		rohc_decomp_debug(context, "window = 0x%x (old_window = 0x%x)\n",
		                  rohc_ntoh16(tcp->window),
		                  rohc_ntoh16(tcp_context->old_tcphdr.window));
		ip_inner_context.v4->ip_id_behavior = c_base_header.co_common->ip_id_behavior;
		d_optional_ip_id_lsb(context, &mptr,
		                     c_base_header.co_common->ip_id_behavior,
		                     c_base_header.co_common->ip_id_indicator,
		                     ip_inner_context.v4->last_ip_id,
		                     &ip_id.uint16, msn);
		rohc_decomp_debug(context, "ip_id_behavior = %d, ip_id_indicator = %d\n",
		                  c_base_header.co_common->ip_id_behavior,
		                  c_base_header.co_common->ip_id_indicator);
		tcp->urg_ptr = d_static_or_irreg16(&mptr,tcp_context->old_tcphdr.urg_ptr,
		                                   c_base_header.co_common->urg_ptr_present);
		rohc_decomp_debug(context, "ecn_used = %d\n",
		                  c_base_header.co_common->ecn_used);
		tcp_context->ecn_used = c_base_header.co_common->ecn_used;
		if(ip_inner_context.vx->version == IPV4)
		{
			/* DSCP */
			base_header_inner.ipv4->dscp =
				dscp_decode(&mptr, ip_inner_context.vx->dscp,
				            c_base_header.co_common->dscp_present);
			rohc_decomp_debug(context, "DSCP = 0x%02x (indicator = %d, context "
			                  "= 0x%02x)\n", base_header_inner.ipv4->dscp,
			                  c_base_header.co_common->dscp_present,
			                  ip_inner_context.vx->dscp);
			ip_inner_context.vx->dscp = base_header_inner.ipv4->dscp;

			ip_inner_context.v4->df = c_base_header.co_common->df;
			base_header_inner.ipv4->ttl_hopl =
				d_static_or_irreg8(&mptr, ip_inner_context.vx->ttl_hopl,
				                   c_base_header.co_common->ttl_hopl_present);
			rohc_decomp_debug(context, "TTL = 0x%x\n",
			                  base_header_inner.ipv4->ttl_hopl);
			ip_inner_context.v4->ttl_hopl = base_header_inner.ipv4->ttl_hopl;
		}
		else
		{
			uint8_t dscp;

			dscp = dscp_decode(&mptr, ip_inner_context.vx->dscp,
			                   c_base_header.co_common->dscp_present);
			base_header_inner.ipv6->dscp1 = dscp >> 2;
			base_header_inner.ipv6->dscp2 = dscp & 0x03;
			rohc_decomp_debug(context, "DSCP = 0x%02x (indicator = %d, context "
			                  "= 0x%02x)\n", DSCP_V6(base_header_inner.ipv6),
			                  c_base_header.co_common->dscp_present,
			                  ip_inner_context.vx->dscp);
			ip_inner_context.vx->dscp = DSCP_V6(base_header_inner.ipv6);

			base_header_inner.ipv6->ttl_hopl =
				d_static_or_irreg8(&mptr, ip_inner_context.vx->ttl_hopl,
				                   c_base_header.co_common->ttl_hopl_present);
			rohc_decomp_debug(context, "HL = 0x%x\n",
			                  base_header_inner.ipv6->ttl_hopl);
			ip_inner_context.v6->ttl_hopl = base_header_inner.ipv6->ttl_hopl;
		}
		tcp->urg_flag = c_base_header.co_common->urg_flag;
		/* if TCP options list present */
		if(c_base_header.co_common->list_present)
		{
			// options
			mptr.uint8 = tcp_decompress_tcp_options(context, tcp, mptr.uint8);
		}
		else
		{
			tcp->data_offset = sizeof(tcphdr_t) >> 2;
		}
	}
	else
	{
		uint32_t ack_number_scaled;
		uint8_t ttl_hopl;

		tcp->seq_number = tcp_context->old_tcphdr.seq_number;
		tcp->ack_number = tcp_context->old_tcphdr.ack_number;
		tcp->data_offset = sizeof(tcphdr_t) >> 2;
		tcp->res_flags = tcp_context->old_tcphdr.res_flags;
		tcp->ecn_flags = tcp_context->old_tcphdr.ecn_flags;
		tcp->urg_flag = tcp_context->old_tcphdr.urg_flag;
		tcp->ack_flag = tcp_context->old_tcphdr.ack_flag;
		tcp->rsf_flags = tcp_context->old_tcphdr.rsf_flags;
		tcp->window = tcp_context->old_tcphdr.window;
		tcp->urg_ptr = tcp_context->old_tcphdr.urg_ptr;

		switch(packet_type)
		{
			case ROHC_PACKET_TCP_RND_1:
			{
				uint32_t encoded_seq_number;
				uint32_t decoded_seq_number;

				rohc_decomp_debug(context, "decode rnd_1 packet\n");

				encoded_seq_number = (c_base_header.rnd1->seq_number1 << 16) |
				                     rohc_ntoh16(c_base_header.rnd1->seq_number2);

				/* decode sequence number from packet bits and context */
				if(!rohc_decomp_tcp_decode_seq(decomp, context, encoded_seq_number,
				                               18, 65535, &decoded_seq_number))
				{
					goto error;
				}
				tcp->seq_number = rohc_hton32(decoded_seq_number);

				tcp->psh_flag = c_base_header.rnd1->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_RND_2:
			{
				rohc_decomp_debug(context, "decode rnd_2 packet\n");
				seq_number_scaled = d_lsb(context, 4,7,tcp_context->seq_number_scaled,
				                          c_base_header.rnd2->seq_number_scaled);
				seq_number_scaled_used = 1;
				tcp->psh_flag = c_base_header.rnd2->psh_flag;
				//  assert( payload_size != 0 );
				// TODO: To be completed/reworked
				// tcp->seq_number = d_field_scaling(payload_size,seq_number_scaled,seq_number_residue);
				break;
			}
			case ROHC_PACKET_TCP_RND_3:
			{
				rohc_decomp_debug(context, "decode rnd_3 packet\n");
				// tcp->ack_number = rohc_hton32( d_lsb(context, 15,8191,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),rohc_ntoh16(c_base_header.rnd3->ack_number)) );
#if WORDS_BIGENDIAN != 1
				wb.uint8[1] =
				   c_base_header.uint8[OFFSET_RND3_ACK_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_RND3_ACK_NUMBER & 0x07) ];
				wb.uint8[0] = c_base_header.uint8[(OFFSET_RND3_ACK_NUMBER >> 3) + 1];
#else
				wb.uint8[0] =
				   c_base_header.uint8[OFFSET_RND3_ACK_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_RND3_ACK_NUMBER & 0x07) ];
				wb.uint8[1] = c_base_header.uint8[(OFFSET_RND3_ACK_NUMBER >> 3) + 1];
#endif
				tcp->ack_number =
				   rohc_hton32( d_lsb(context, 15,8191,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),wb.uint16) );
				tcp->psh_flag = c_base_header.rnd3->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_RND_4:
			{
				rohc_decomp_debug(context, "decode rnd_4 packet\n");
				if(tcp_context->ack_stride != 0)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
									 context->profile->id, "cannot decode rnd_4 packet "
									 "with ack_stride.UVALUE == 0");
					goto error;
				}
				ack_number_scaled = d_lsb(context, 4,3,rohc_ntoh32(
				                             tcp_context->old_tcphdr.ack_number),
				                          c_base_header.rnd4->ack_number_scaled);
				assert( tcp_context->ack_stride != 0 );
				tcp->ack_number = d_field_scaling(tcp_context->ack_stride,
				                                  ack_number_scaled,
				                                  tcp_context->ack_number_residue);
				rohc_decomp_debug(context, "ack_number_scaled = 0x%x, "
				                  "ack_number_residue = 0x%x -> ack_number = "
				                  "0x%x\n", ack_number_scaled,
				                  tcp_context->ack_number_residue,
				                  rohc_ntoh32(tcp->ack_number));
				tcp->psh_flag = c_base_header.rnd4->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_RND_5:
			{
				uint32_t decoded_seq_number;

				rohc_decomp_debug(context, "decode rnd_5 packet\n");
				tcp->psh_flag = c_base_header.rnd5->psh_flag;
#if WORDS_BIGENDIAN != 1
				wb.uint8[1] = ( c_base_header.uint8[OFFSET_RND5_ACK_NUMBER >> 3] & 0x1F ) << 1;
				wb.uint8[1] |= c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 1] << 7;
				wb.uint8[0] = c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 1] << 1;
				wb.uint8[0] |= c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 2] >> 7;
#else
				wb.uint8[0] = ( c_base_header.uint8[OFFSET_RND5_ACK_NUMBER >> 3] & 0x1F ) << 1;
				wb.uint8[0] |= c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 1] << 7;
				wb.uint8[1] = c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 1] << 1;
				wb.uint8[1] |= c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 2] >> 7;
#endif

				/* decode sequence number from packet bits and context */
				if(!rohc_decomp_tcp_decode_seq(decomp, context, wb.uint16,
				                               14, 8191, &decoded_seq_number))
				{
					goto error;
				}
				tcp->seq_number = rohc_hton32(decoded_seq_number);

				// tcp->ack_number = rohc_hton32( d_lsb(context, 15,8191,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),rohc_ntoh16(c_base_header.rnd5->ack_number)) );
#if WORDS_BIGENDIAN != 1
				wb.uint8[1] = c_base_header.uint8[OFFSET_RND5_SEQ_NUMBER >> 3] & 0x7F;
				wb.uint8[0] = c_base_header.uint8[(OFFSET_RND5_SEQ_NUMBER >> 3) + 1] << 1;
#else
				wb.uint8[0] = c_base_header.uint8[OFFSET_RND5_SEQ_NUMBER >> 3] & 0x7F;
				wb.uint8[1] = c_base_header.uint8[(OFFSET_RND5_SEQ_NUMBER >> 3) + 1] << 1;
#endif
				tcp->ack_number =
				   rohc_hton32( d_lsb(context, 15,8191,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),wb.uint16) );
				rohc_decomp_debug(context, "ack_number = 0x%x, uint16 = 0x%04x "
				                  "(0x%02x 0x%02x)\n", rohc_ntoh32(tcp->ack_number),
				                  wb.uint16, wb.uint8[0], wb.uint8[1]);
				break;
			}
			case ROHC_PACKET_TCP_RND_6:
			{
				rohc_decomp_debug(context, "decode rnd_6 packet\n");
				tcp->psh_flag = c_base_header.rnd6->psh_flag;
				tcp->ack_number =
				   rohc_hton32( d_lsb(context, 16,16383,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),
				                rohc_ntoh16(c_base_header.rnd6->ack_number)) );
				seq_number_scaled = d_lsb(context, 4,7,tcp_context->seq_number_scaled,
				                          c_base_header.rnd6->seq_number_scaled);
				seq_number_scaled_used = 1;
				//  assert( payload_size != 0 );
				// TODO: to be completed/reworked
				// tcp->seq_number = d_field_scaling(payload_size,seq_number_scaled,seq_number_residue);
				break;
			}
			case ROHC_PACKET_TCP_RND_7:
			{
				uint32_t ack_number;
				rohc_decomp_debug(context, "decode rnd_7 packet\n");
				// tcp->ack_number = rohc_hton32( d_lsb(context, 18,65535,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),rohc_ntoh32(c_base_header.rnd7->ack_number)) );
				ack_number = ( c_base_header.rnd7->ack_number1 << 16 ) | rohc_ntoh16(
				   c_base_header.rnd7->ack_number2);
				tcp->ack_number =
				   rohc_hton32( d_lsb(context, 18,65535,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),ack_number) );
				tcp->window = c_base_header.rnd7->window;
				tcp->psh_flag = c_base_header.rnd7->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_RND_8:
			{
				uint32_t encoded_seq_number;
				uint32_t decoded_seq_number;

				rohc_decomp_debug(context, "decode rnd_8 packet\n");
				tcp->rsf_flags = rsf_index_dec( c_base_header.rnd8->rsf_flags );
				tcp->psh_flag = c_base_header.rnd8->psh_flag;
				ttl_hopl = d_lsb(context, 3, 3, ip_inner_context.vx->ttl_hopl,
				                 c_base_header.rnd8->ttl_hopl);
				if(ip_inner_context.vx->version == IPV4)
				{
					base_header.ipv4->ttl_hopl = ttl_hopl;
					ip_inner_context.v4->ttl_hopl = base_header.ipv4->ttl_hopl;
					rohc_decomp_debug(context, "IPv4 TTL = 0x%02x (%u)\n",
					                  ttl_hopl, ttl_hopl);
				}
				else
				{
					base_header.ipv6->ttl_hopl = ttl_hopl;
					ip_inner_context.v6->ttl_hopl = base_header.ipv6->ttl_hopl;
					rohc_decomp_debug(context, "IPv6 HL = 0x%02x (%u)\n",
					                  ttl_hopl, ttl_hopl);
				}
				rohc_decomp_debug(context, "ecn_used = %d\n",
				                  c_base_header.rnd8->ecn_used);
				tcp_context->ecn_used = c_base_header.rnd8->ecn_used;

				/* decode sequence number from packet bits and context */
				encoded_seq_number = rohc_ntoh16(c_base_header.rnd8->seq_number);
				if(!rohc_decomp_tcp_decode_seq(decomp, context, encoded_seq_number,
				                               16, 65535, &decoded_seq_number))
				{
					goto error;
				}
				tcp->seq_number = rohc_hton32(decoded_seq_number);

				tcp->ack_number =
				   rohc_hton32( d_lsb(context, 16,16383,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),
				                rohc_ntoh16(c_base_header.rnd8->ack_number)) );
				if(c_base_header.rnd8->list_present)
				{
					rohc_dump_packet(context->decompressor->trace_callback,
					                 ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
					                 "compressed TCP options", mptr.uint8, 10);
					// options
					mptr.uint8 = tcp_decompress_tcp_options(context, tcp,
					                                        mptr.uint8);
					rohc_decomp_debug(context, "end of compressed TCP options at "
					                  "%p\n", mptr.uint8);
				}
				else
				{
					rohc_decomp_debug(context, "no compressed TCP options\n");
					tcp->data_offset = sizeof(tcphdr_t) >> 2;
				}
				break;
			}
			case ROHC_PACKET_TCP_SEQ_1:
			{
				uint32_t encoded_seq_number;
				uint32_t decoded_seq_number;

				rohc_decomp_debug(context, "decode seq_1 packet\n");
				ip_id.uint16 =
				   d_ip_id_lsb(context, ip_inner_context.v4->ip_id_behavior,4,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq1->ip_id,
				               msn);

				/* decode sequence number from packet bits and context */
				encoded_seq_number = rohc_ntoh16(c_base_header.seq1->seq_number);
				if(!rohc_decomp_tcp_decode_seq(decomp, context, encoded_seq_number,
				                               16, 32767, &decoded_seq_number))
				{
					goto error;
				}
				tcp->seq_number = rohc_hton32(decoded_seq_number);

				tcp->psh_flag = c_base_header.seq1->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_2:
			{
					uint8_t ip_id_lsb;
				rohc_decomp_debug(context, "decode seq_2 packet\n");
					ip_id_lsb = (c_base_header.seq2->ip_id1 << 4) |
					            c_base_header.seq2->ip_id2;
					ip_id.uint16 =
						d_ip_id_lsb(context, ip_inner_context.v4->ip_id_behavior,
						            7, 3, ip_inner_context.v4->last_ip_id,
						            ip_id_lsb, msn);
				seq_number_scaled = d_lsb(context, 4,7,tcp_context->seq_number_scaled,
				                          c_base_header.seq2->seq_number_scaled);
				seq_number_scaled_used = 1;
				tcp->psh_flag = c_base_header.seq2->psh_flag;
				//  assert( payload_size != 0 );
				// TODO: To be completed/reworked
				// tcp->seq_number = d_field_scaling(payload_size,seq_number_scaled,seq_number_residue);
				break;
			}
			case ROHC_PACKET_TCP_SEQ_3:
			{
				rohc_decomp_debug(context, "decode seq_3 packet\n");
				ip_id.uint16 =
				   d_ip_id_lsb(context, ip_inner_context.v4->ip_id_behavior,4,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq3->ip_id,
				               msn);
				tcp->ack_number =
				   rohc_hton32( d_lsb(context, 16,16383,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),
				                rohc_ntoh16(c_base_header.seq3->ack_number)) );
				tcp->psh_flag = c_base_header.seq3->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_4:
			{
				rohc_decomp_debug(context, "decode seq_4 packet\n");
				if(tcp_context->ack_stride != 0)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
									 context->profile->id, "cannot decode seq_4 packet "
									 "with ack_stride.UVALUE == 0");
					goto error;
				}
				ack_number_scaled = d_lsb(context, 4,3,rohc_ntoh32(
				                             tcp_context->old_tcphdr.ack_number),
				                          c_base_header.seq4->ack_number_scaled);
				tcp->ack_number = d_field_scaling(tcp_context->ack_stride,
				                                  ack_number_scaled,
				                                  tcp_context->ack_number_residue);
				rohc_decomp_debug(context, "ack_number_scaled = 0x%x, "
				                  "ack_number_residue = 0x%x -> ack_number = "
				                  "0x%x\n", ack_number_scaled,
				                  tcp_context->ack_number_residue,
				                  rohc_ntoh32(tcp->ack_number));
				ip_id.uint16 =
				   d_ip_id_lsb(context, ip_inner_context.v4->ip_id_behavior,3,1,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq4->ip_id,
				               msn);
				tcp->psh_flag = c_base_header.seq4->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_5:
			{
				uint32_t encoded_seq_number;
				uint32_t decoded_seq_number;

				rohc_decomp_debug(context, "decode seq_5 packet\n");
				ip_id.uint16 =
				   d_ip_id_lsb(context, ip_inner_context.v4->ip_id_behavior,4,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq5->ip_id,
				               msn);
				tcp->ack_number =
				   rohc_hton32( d_lsb(context, 16,16383,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),
				                rohc_ntoh16(c_base_header.seq5->ack_number)) );

				/* decode sequence number from packet bits and context */
				encoded_seq_number = rohc_ntoh16(c_base_header.seq5->seq_number);
				if(!rohc_decomp_tcp_decode_seq(decomp, context, encoded_seq_number,
				                               16, 32767, &decoded_seq_number))
				{
					goto error;
				}
				tcp->seq_number = rohc_hton32(decoded_seq_number);

				tcp->psh_flag = c_base_header.seq5->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_6:
			{
				uint8_t seq_scaled_lsb;
				rohc_decomp_debug(context, "decode seq_6 packet\n");
				seq_scaled_lsb = (c_base_header.seq6->seq_number_scaled1 << 1) |
				                 c_base_header.seq6->seq_number_scaled2;
				seq_number_scaled =
					d_lsb(context, 4, 7, tcp_context->seq_number_scaled,
					      seq_scaled_lsb);
				seq_number_scaled_used = 1;
				//  assert( payload_size != 0 );
				// TODO: to be completed/reworked
				// tcp->seq_number = d_field_scaling(payload_size,seq_number_scaled,seq_number_residue);
				ip_id.uint16 =
				   d_ip_id_lsb(context, ip_inner_context.v4->ip_id_behavior,7,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq6->ip_id,
				               msn);
				tcp->ack_number =
				   rohc_hton32( d_lsb(context, 16,16383,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),
				                rohc_ntoh16(c_base_header.seq6->ack_number)) );
				tcp->psh_flag = c_base_header.seq6->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_7:
			{
				uint16_t window;
				rohc_decomp_debug(context, "decode seq_7 packet\n");
				// tcp->window = rohc_hton16( d_lsb(context, 15,16383,rohc_ntoh16(tcp_context->old_tcphdr.window),rohc_ntoh16(c_base_header.seq7->window)) );
				window =
				   ( c_base_header.seq7->window1 <<
				     11 ) | ( c_base_header.seq7->window2 << 3 ) | c_base_header.seq7->window3;
				tcp->window = rohc_hton16( d_lsb(context, 15,16383,rohc_ntoh16(tcp_context->old_tcphdr.window),window) );
				ip_id.uint16 =
				   d_ip_id_lsb(context, ip_inner_context.v4->ip_id_behavior,5,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq7->ip_id,
				               msn);
				tcp->ack_number =
				   rohc_hton32( d_lsb(context, 16,32767,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),
				                rohc_ntoh16(c_base_header.seq7->ack_number)) );
				tcp->psh_flag = c_base_header.seq7->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_8:
			{
				uint32_t decoded_seq_number;

				rohc_decomp_debug(context, "decode seq_8 packet\n");
				ip_id.uint16 =
				   d_ip_id_lsb(context, ip_inner_context.v4->ip_id_behavior,4,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq8->ip_id,
				               msn);
				tcp->psh_flag = c_base_header.seq8->psh_flag;
				ttl_hopl = d_lsb(context, 3, 3, ip_inner_context.vx->ttl_hopl,
				                 c_base_header.seq8->ttl_hopl);
				if(ip_inner_context.vx->version == IPV4)
				{
					base_header.ipv4->ttl_hopl = ttl_hopl;
					ip_inner_context.v4->ttl_hopl = base_header.ipv4->ttl_hopl;
					rohc_decomp_debug(context, "IPv4 TTL = 0x%02x (%u)\n",
					                  ttl_hopl, ttl_hopl);
				}
				else
				{
					base_header.ipv6->ttl_hopl = ttl_hopl;
					ip_inner_context.v6->ttl_hopl = base_header.ipv6->ttl_hopl;
					rohc_decomp_debug(context, "IPv6 HL = 0x%02x (%u)\n",
					                  ttl_hopl, ttl_hopl);
				}
				rohc_decomp_debug(context, "ecn_used = %d\n",
				                  c_base_header.seq8->ecn_used);
				tcp_context->ecn_used = c_base_header.seq8->ecn_used;
				// tcp->ack_number = rohc_hton32( d_lsb(context, 15,8191,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),rohc_ntoh16(c_base_header.seq8->ack_number)) );
#if WORDS_BIGENDIAN != 1
				wb.uint8[1] =
				   c_base_header.uint8[OFFSET_SEQ8_ACK_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_SEQ8_ACK_NUMBER & 0x07) ];
				wb.uint8[0] = c_base_header.uint8[(OFFSET_SEQ8_ACK_NUMBER >> 3) + 1];
#else
				wb.uint8[0] =
				   c_base_header.uint8[OFFSET_SEQ8_ACK_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_SEQ8_ACK_NUMBER & 0x07) ];
				wb.uint8[1] = c_base_header.uint8[(OFFSET_SEQ8_ACK_NUMBER >> 3) + 1];
#endif
				tcp->ack_number =
				   rohc_hton32( d_lsb(context, 15,8191,rohc_ntoh32(tcp_context->old_tcphdr.ack_number),wb.uint16) );
				rohc_decomp_debug(context, "ack_number = 0x%02x 0x%02x => "
				                  "0x%04x, ack_number = 0x%x\n", wb.uint8[0],
				                  wb.uint8[1], wb.uint16, rohc_ntoh32(tcp->ack_number));
				tcp->rsf_flags = rsf_index_dec( c_base_header.seq8->rsf_flags );

#if WORDS_BIGENDIAN != 1
				wb.uint8[1] =
				   c_base_header.uint8[OFFSET_SEQ8_SEQ_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_SEQ8_SEQ_NUMBER & 0x07) ];
				wb.uint8[0] = c_base_header.uint8[(OFFSET_SEQ8_SEQ_NUMBER >> 3) + 1];
#else
				wb.uint8[0] =
				   c_base_header.uint8[OFFSET_SEQ8_SEQ_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_SEQ8_SEQ_NUMBER & 0x07) ];
				wb.uint8[1] = c_base_header.uint8[(OFFSET_SEQ8_SEQ_NUMBER >> 3) + 1];
#endif

				/* decode sequence number from packet bits and context */
				if(!rohc_decomp_tcp_decode_seq(decomp, context, wb.uint16,
				                               14, 8191, &decoded_seq_number))
				{
					goto error;
				}
				tcp->seq_number = rohc_hton32(decoded_seq_number);

				if(c_base_header.seq8->list_present)
				{
					// options
					mptr.uint8 = tcp_decompress_tcp_options(context, tcp,
					                                        mptr.uint8);
				}
				else
				{
					tcp->data_offset = sizeof(tcphdr_t) >> 2;
				}
				break;
			}
			default:
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
								 context->profile->id, "unsupported packet type (%d)\n",
								 packet_type);
				goto error;
			}
		}
	}

	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "current IP + TCP packet", dest,
	                 uncomp_header_len + sizeof(tcphdr_t));

	tcp_context->msn = msn;

	// Now decode irregular chain
	rohc_remain_data = mptr.uint8;

	base_header.uint8 = (uint8_t*) dest;
	ip_context.uint8 = tcp_context->ip_context;

	do
	{
		mptr.uint8 = tcp_decode_irregular_ip(context, ip_context, base_header,
		                                     mptr,
		                                     base_header.uint8 == base_header_inner.uint8, // int is_innermost,
		                                     ttl_irregular_chain_flag,
		                                     ip_inner_ecn);

		if(ip_context.vx->version == IPV4)
		{
			protocol = ip_context.v4->protocol;
			++base_header.ipv4;
			++ip_context.v4;
		}
		else
		{
			protocol = ip_context.v6->next_header;
			++base_header.ipv6;
			++ip_context.v6;
		}

		assert( ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE] );

	}
	while(protocol != ROHC_IPPROTO_TCP);

	mptr.uint8 = tcp_decode_irregular_tcp(context, base_header_inner, tcp,
	                                      mptr.uint8);
	// Add irregular chain length
	rohc_header_len += mptr.uint8 - rohc_remain_data;

	/* decode IP-ID according to its behavior */
	if(ip_inner_context.vx->version == IPV4)
	{
		rohc_decomp_debug(context, "decode IP-ID field\n");

		switch(ip_inner_context.v4->ip_id_behavior)
		{
			case IP_ID_BEHAVIOR_SEQUENTIAL:
			{
				rohc_decomp_debug(context, "IP-ID follows a sequential behavior\n");
				if(packet_type >= ROHC_PACKET_TCP_RND_1 && packet_type <= ROHC_PACKET_TCP_RND_8)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
					             context->profile->id,
					             "IP-ID got a sequential behavior but packet is "
					             "RND_%d\n", packet_type - ROHC_PACKET_TCP_RND_1 + 1);
					goto error;
				}
				base_header_inner.ipv4->ip_id = rohc_hton16(ip_id.uint16);
				ip_inner_context.v4->last_ip_id.uint16 = ip_id.uint16;
				break;
			}
			case IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED:
			{
				WB_t swapped_ip_id;

				rohc_decomp_debug(context, "IP-ID follows a swapped sequential "
										"behavior\n");

				if(packet_type >= ROHC_PACKET_TCP_RND_1 && packet_type <= ROHC_PACKET_TCP_RND_8)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
					             context->profile->id,
					             "IP-ID got a swapped sequential behavior but packet "
					             "is RND_%d\n", packet_type - ROHC_PACKET_TCP_RND_1 + 1);
					goto error;
				}

				swapped_ip_id.uint8[0] = ip_id.uint8[1];
				swapped_ip_id.uint8[1] = ip_id.uint8[0];
				base_header_inner.ipv4->ip_id = rohc_hton16(swapped_ip_id.uint16);
				ip_inner_context.v4->last_ip_id.uint16 = swapped_ip_id.uint16;
				break;
			}
			case IP_ID_BEHAVIOR_RANDOM:
			{
				rohc_decomp_debug(context, "IP-ID follows a random behavior\n");
				/* already done by tcp_decode_irregular_ip() */
				break;
			}
			case IP_ID_BEHAVIOR_ZERO:
			{
				rohc_decomp_debug(context, "IP-ID follows a zero behavior\n");
				base_header_inner.ipv4->ip_id = 0;
				ip_inner_context.v4->last_ip_id.uint16 = 0;
				break;
			}
			default:
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id, "unknown IP-ID behavior (%d)\n",
				             ip_inner_context.v4->ip_id_behavior);
				goto error;
			}
		}
	}

	uncomp_header_len += tcp->data_offset << 2;
	rohc_decomp_debug(context, "uncomp_header_len = %d (+ %d)\n",
	                  uncomp_header_len, tcp->data_offset << 2);
	payload_len = rohc_length - ( mptr.uint8 - (uint8_t*) rohc_packet );
	rohc_decomp_debug(context, "size compressed = %d\n",
	                  (int) (mptr.uint8 - (uint8_t *) rohc_packet));
	rohc_decomp_debug(context, "size IPv4 header = %zd, IPv6 header = %zd, "
	                  "TCP header = %zd\n", sizeof(base_header_ip_v4_t),
	                  sizeof(base_header_ip_v6_t), sizeof(tcphdr_t));
	rohc_decomp_debug(context, "uncomp_header_length = %d, payload_len = %d, "
	                  "total = %d\n", uncomp_header_len, payload_len,
	                  uncomp_header_len + payload_len);
	rohc_decomp_debug(context, "rohc_packet = %p, end compressed header = %p, "
	                  "size = %d\n", rohc_packet, mptr.uint8,
	                  (int) (mptr.uint8 - (uint8_t *) rohc_packet));

	if(payload_len != 0)
	{
		rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "payload, max 100 bytes", mptr.uint8,
		                 rohc_min(payload_len, 100));
	}

	if(seq_number_scaled_used != 0)
	{
		assert( payload_len != 0 );
		tcp->seq_number = rohc_hton32(
		   ( seq_number_scaled * payload_len ) + tcp_context->seq_number_residue );
		rohc_decomp_debug(context, "seq_number_scaled = 0x%x, "
		                  "seq_number_residue = 0x%x -> seq_number = 0x%x\n",
		                  seq_number_scaled, tcp_context->seq_number_residue,
		                  rohc_ntoh32(tcp->seq_number));
	}

	base_header.uint8 = (uint8_t*) dest;
	ip_context.uint8 = tcp_context->ip_context;
	size = uncomp_header_len + payload_len;

	do
	{

		if(ip_context.vx->version == IPV4)
		{
			base_header.ipv4->df = ip_context.v4->df;
			base_header.ipv4->length = rohc_hton16(size);
			base_header.ipv4->checksum = 0;
			base_header.ipv4->checksum =
				ip_fast_csum(base_header.uint8,
				             base_header.ipv4->header_length);
			rohc_decomp_debug(context, "IP checksum = 0x%04x for %d bytes\n",
			                  rohc_ntoh16(base_header.ipv4->checksum),
			                  base_header.ipv4->header_length);
			protocol = ip_context.v4->protocol;
			size -= sizeof(base_header_ip_v4_t);
			++base_header.ipv4;
			++ip_context.v4;
		}
		else
		{
			// A REVOIR ->payload_length
			base_header.ipv6->payload_length = rohc_hton16( ( tcp->data_offset << 2 ) + payload_len );
			rohc_decomp_debug(context, "payload_length = %d\n",
			                  rohc_ntoh16(base_header.ipv6->payload_length));
			/*
			base_header.ipv6->payload_length = rohc_hton16( length - sizeof(base_header_ip_v6_t) );
			rohc_decomp_debug(context, "payload_length = %d\n",
			                  rohc_ntoh16(base_header.ipv6->payload_length));
			*/
			protocol = ip_context.v6->next_header;
			size -= sizeof(base_header_ip_v6_t);
			++base_header.ipv6;
			++ip_context.v6;
		}

		assert( ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE] );

	}
	while(protocol != ROHC_IPPROTO_TCP);

	if(ip_context.vx->version == IPV4)
	{
		rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "current IPv6 + TCP packet", dest,
		                 sizeof(base_header_ip_v4_t) + sizeof(tcphdr_t));
	}
	else
	{
		rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
		                 ROHC_TRACE_DEBUG, "current IPv4 + TCP packet", dest,
		                 sizeof(base_header_ip_v6_t) + sizeof(tcphdr_t));
	}

	memcpy(&tcp_context->old_tcphdr,tcp,sizeof(tcphdr_t));

	size = tcp->data_offset << 2;
	rohc_decomp_debug(context, "TCP header size = %d (0x%x)\n", size, size);
	rohc_dump_packet(context->decompressor->trace_callback, ROHC_TRACE_DECOMP,
	                 ROHC_TRACE_DEBUG, "current IP+TCP packet", dest,
	                 (((unsigned char *) tcp) - dest) + size);

	rohc_decomp_debug(context, "uncomp_header_len = %d (0x%x)\n",
	                  uncomp_header_len, uncomp_header_len);

	// TODO: to be reworked
	context->state = ROHC_DECOMP_STATE_FC;

	rohc_decomp_debug(context, "size_header = %d, size_options = %d, "
	                  "rohc_length = %d\n", size_header, size_options,
	                  rohc_length);

	/* copy the payload */
	rohc_decomp_debug(context, "ROHC payload (length = %u bytes) starts at "
	                  "offset %u\n", payload_len, rohc_header_len);

	if((rohc_header_len + payload_len) != rohc_length)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC CO header (%u bytes) and payload (%u bytes) "
		             "do not match the full ROHC CO packet (%u bytes)\n",
		             rohc_header_len, payload_len, rohc_length);
		goto error;
	}
	if(payload_len != 0)
	{
		memcpy(((uint8_t*)(tcp)) + size, mptr.uint8, payload_len);
	}

	/* update context */
	rohc_lsb_set_ref(tcp_context->seq_lsb_ctxt, rohc_ntoh32(tcp->seq_number),
	                 false);
	rohc_decomp_debug(context, "sequence number 0x%08x is the new reference\n",
	                  rohc_ntoh32(tcp->seq_number));
	memcpy(&tcp_context->old_tcphdr,tcp,sizeof(tcphdr_t));
	rohc_decomp_debug(context, "tcp = %p, save seq_number = 0x%x, "
	                  "save ack_number = 0x%x\n", tcp,
	                  rohc_ntoh32(tcp_context->old_tcphdr.seq_number),
	                  rohc_ntoh32(tcp_context->old_tcphdr.ack_number));

	/* statistics */
	context->header_compressed_size += rohc_header_len;
	context->header_uncompressed_size += uncomp_header_len;
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	rohc_stats_add(&context->header_16_compressed, rohc_header_len);
	rohc_stats_add(&context->header_16_uncompressed, uncomp_header_len);
#endif

	return (uncomp_header_len + payload_len);

error:
	return ROHC_ERROR;
}


/**
 * @brief Decode the TCP sequence number from packet and context information
 *
 */
static bool rohc_decomp_tcp_decode_seq(const struct rohc_decomp *const decomp,
                                       const struct d_context *const context,
                                       const uint32_t seq_bits,
                                       const size_t seq_bits_nr,
                                       const rohc_lsb_shift_t p,
                                       uint32_t *const seq)
{
	const struct d_generic_context *const g_context = context->specific;
	const struct d_tcp_context *const tcp_context = g_context->specific;
	bool decode_ok;

	decode_ok = rohc_lsb_decode(tcp_context->seq_lsb_ctxt, ROHC_LSB_REF_0, 0,
	                            seq_bits, seq_bits_nr, p, seq);
	if(!decode_ok)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to decode %zu sequence number bits 0x%x with "
		             "p = %u\n", seq_bits_nr, seq_bits, p);
		return false;
	}
	rohc_decomp_debug(context, "decoded sequence number = 0x%08x (%zu bits "
	                  "0x%x with p = %d)\n", *seq, seq_bits_nr, seq_bits, p);
	return true;
}


/**
 * @brief Get the reference MSN value of the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The decompression context
 * @return        The reference MSN value
 */
static uint32_t d_tcp_get_msn(const struct d_context *const context)
{
	const struct d_generic_context *const g_context = context->specific;
	const struct d_tcp_context *const tcp_context = g_context->specific;

	rohc_decomp_debug(context, "MSN = %u (0x%x)\n", tcp_context->msn,
	                  tcp_context->msn);

	return tcp_context->msn;
}


/**
 * @brief Define the decompression part of the TCP profile as described
 *        in the RFC 3095.
 */
struct d_profile d_tcp_profile =
{
	ROHC_PROFILE_TCP,       /* profile ID (see 8 in RFC 3095) */
	.detect_packet_type = tcp_detect_packet_type,
	d_tcp_decode,
	d_tcp_create,
	d_tcp_destroy,
	d_tcp_get_msn
};

