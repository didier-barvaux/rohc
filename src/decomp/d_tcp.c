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
 * @file   d_tcp.c
 * @brief  ROHC decompression context for the TCP profile.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "rohc_bit_ops.h"
#include "rohc_traces_internal.h"
#include "rohc_utils.h"
#include "rohc_debug.h"
#include "schemes/rfc4996.h"
#include "schemes/decomp_wlsb.h"
#include "protocols/tcp.h"
#include "crc.h"
#include "rohc_decomp_rfc3095.h"

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


/** TODO */
typedef union
{
	ipv6_generic_option_context_t generic;
	ipv6_gre_option_context_t gre;
	ipv6_mime_option_context_t mime;
	ipv6_ah_option_context_t ah;
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
#define ROHC_TCP_MAX_IPv6_EXT_HDRS  10U

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
	ipv6_option_context_t opts[ROHC_TCP_MAX_IPv6_EXT_HDRS];

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


#if 0
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
#endif


/**
 * @brief Define the TCP part of the decompression profile context.
 *
 * This object must be used with the generic part of the decompression
 * context rohc_decomp_rfc3095_ctxt.
 *
 * @see rohc_decomp_rfc3095_ctxt
 */
struct d_tcp_context
{
	// The Master Sequence Number
	uint16_t msn;

	/** The LSB decoding context of innermost IP-ID */
	struct rohc_lsb_decode *ip_id_lsb_ctxt;

	// Explicit Congestion Notification used
	uint8_t ecn_used;

	/* TCP static part */
	uint16_t tcp_src_port; /**< The TCP source port */
	uint16_t tcp_dst_port; /**< The TCP dest port */

	/* TCP dynamic part (temporary) */
	uint8_t res_flags:4;
	uint8_t ecn_flags:2;
	uint8_t urg_flag:1;
	uint8_t ack_flag:1;
	uint8_t psh_flag:1;
	uint8_t rsf_flags:3;
	uint32_t seq_num;
	uint32_t ack_num;
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
#define MAX_TCP_DATA_OFFSET_WORDS  ((1 << 4) - 1)
#define MAX_TCP_DATA_OFFSET_BYTES  (MAX_TCP_DATA_OFFSET_WORDS * sizeof(uint32_t))
#define MAX_TCP_OPTIONS_LEN        (MAX_TCP_DATA_OFFSET_BYTES - sizeof(tcphdr_t))
	uint8_t options[MAX_TCP_OPTIONS_LEN];
	size_t options_len;

	uint32_t seq_num_scaled;
	uint32_t seq_num_residue;
	struct rohc_lsb_decode *seq_lsb_ctxt;
	struct rohc_lsb_decode *seq_scaled_lsb_ctxt;

	uint16_t ack_stride;
	uint32_t ack_num_scaled;
	uint32_t ack_num_residue;
	struct rohc_lsb_decode *ack_lsb_ctxt;

	// Table of TCP options
	uint8_t tcp_options_list[ROHC_TCP_OPTS_MAX];   // see RFC4996 page 27
	uint8_t tcp_options_offset[ROHC_TCP_OPTS_MAX];
	uint16_t tcp_option_maxseg;
	uint8_t tcp_option_window;
	/** The structure of the list of TCP options */
	uint8_t tcp_opts_list_struct[ROHC_TCP_OPTS_MAX];
	/** Whether the content of every TCP options was transmitted or not */
	bool is_tcp_opts_list_item_present[ROHC_TCP_OPTS_MAX]; /* TODO: should be in tmp part */
	/** TODO */
	size_t tcp_opts_list_item_uncomp_length[ROHC_TCP_OPTS_MAX]; /* TODO: should be in tmp part */

	struct tcp_option_timestamp tcp_option_timestamp;
	struct rohc_lsb_decode *opt_ts_req_lsb_ctxt;
	struct rohc_lsb_decode *opt_ts_reply_lsb_ctxt;

	uint8_t tcp_option_sack_length;
	uint8_t tcp_option_sackblocks[8 * 4];
	uint8_t tcp_options_free_offset;
#define MAX_TCP_OPT_SIZE 64
	uint8_t tcp_options_values[MAX_TCP_OPT_SIZE];

	tcphdr_t old_tcphdr;

	ip_context_t ip_contexts[ROHC_TCP_MAX_IP_HDRS];
	size_t ip_contexts_nr;
};


/*
 * Private function prototypes.
 */

static void * d_tcp_create(const struct rohc_decomp_ctxt *const context);
static void d_tcp_destroy(void *const context);

static rohc_status_t d_tcp_decode(struct rohc_decomp *const decomp,
                                  struct rohc_decomp_ctxt *const context,
                                  const struct rohc_buf rohc_packet,
                                  const size_t add_cid_len,
                                  const size_t large_cid_len,
                                  struct rohc_buf *const uncomp_packet,
                                  rohc_packet_t *const packet_type)
		__attribute__((warn_unused_result, nonnull(1, 2, 6, 7)));

static int tcp_parse_static_ipv6_option(struct rohc_decomp_ctxt *const context,
                                        ip_context_t *const ip_context,
                                        ipv6_option_context_t *const opt_context,
                                        const uint8_t protocol,
                                        const unsigned char *const rohc_packet,
                                        const size_t rohc_length);
static int tcp_parse_dynamic_ipv6_option(struct rohc_decomp_ctxt *const context,
                                         ipv6_option_context_t *const opt_context,
                                         const uint8_t protocol,
                                         const unsigned char *const rohc_packet,
                                         const size_t rohc_length);

static int tcp_parse_static_ip(struct rohc_decomp_ctxt *const context,
                               ip_context_t *const ip_context,
                               const unsigned char *const rohc_packet,
                               const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int tcp_parse_dynamic_ip(struct rohc_decomp_ctxt *const context,
                                ip_context_t *const ip_context,
                                const unsigned char *const rohc_packet,
                                const size_t rohc_length);
static int tcp_parse_irregular_ip(struct rohc_decomp_ctxt *const context,
                                  ip_context_t *const ip_context,
                                  const uint8_t *rohc_data,
                                  const size_t rohc_data_len,
                                  const bool is_innermost,
                                  int ttl_irregular_chain_flag,
                                  int ip_inner_ecn)
	__attribute__((warn_unused_result));
static int tcp_parse_static_tcp(struct rohc_decomp_ctxt *const context,
                                const unsigned char *const rohc_packet,
                                const size_t rohc_length);
static int tcp_parse_dynamic_tcp(struct rohc_decomp_ctxt *const context,
                                 const unsigned char *const rohc_packet,
                                 const size_t rohc_length);

static rohc_packet_t tcp_detect_packet_type(const struct rohc_decomp_ctxt *const context,
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static rohc_status_t d_tcp_decode_ir(struct rohc_decomp_ctxt *context,
                                     const unsigned char *const rohc_packet,
                                     const size_t rohc_length,
                                     const size_t large_cid_len,
                                     struct rohc_buf *const uncomp_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));
static rohc_status_t d_tcp_decode_irdyn(struct rohc_decomp_ctxt *context,
                                        const unsigned char *const rohc_packet,
                                        const size_t rohc_length,
                                        const size_t large_cid_len,
                                        struct rohc_buf *const uncomp_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));
static rohc_status_t d_tcp_decode_CO(struct rohc_decomp *decomp,
                                     struct rohc_decomp_ctxt *context,
                                     const unsigned char *const rohc_packet,
                                     const size_t rohc_length,
                                     const size_t add_cid_len,
                                     const size_t large_cid_len,
                                     const rohc_packet_t packet_type,
                                     struct rohc_buf *const uncomp_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 8)));

static bool rohc_decomp_tcp_decode_seq(const struct rohc_decomp_ctxt *const context,
                                       const uint32_t seq_bits,
                                       const size_t seq_bits_nr,
                                       const rohc_lsb_shift_t p,
                                       uint32_t *const seq)
	__attribute__((warn_unused_result, nonnull(1, 5)));

static bool rohc_decomp_tcp_decode_ack(const struct rohc_decomp_ctxt *const context,
                                       const uint8_t ack_flag,
                                       const uint32_t ack_bits,
                                       const size_t ack_bits_nr,
                                       const rohc_lsb_shift_t p,
                                       uint32_t *const ack)
	__attribute__((warn_unused_result, nonnull(1, 6)));

static uint32_t d_tcp_get_msn(const struct rohc_decomp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1), pure));

static int d_ts_lsb(const struct rohc_decomp_ctxt *const context,
                    const struct rohc_lsb_decode *const lsb,
                    const uint8_t *const data,
                    const size_t data_len,
                    uint32_t *const timestamp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int d_tcp_opt_sack(const struct rohc_decomp_ctxt *const context,
                          const uint8_t *const data,
                          const size_t data_len,
                          uint8_t **pOptions,
                          uint32_t ack_value)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));


/**
 * @brief Create the TCP decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The decompression context
 * @return         The newly-created TCP decompression context
 */
static void * d_tcp_create(const struct rohc_decomp_ctxt *const context)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_tcp_context *tcp_context;

	/* create the generic context */
	rfc3095_ctxt =
		rohc_decomp_rfc3095_create(context,
		                           context->decompressor->trace_callback,
		                           context->decompressor->trace_callback_priv,
		                           context->profile->id);
	if(rfc3095_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the generic decompression context");
		goto quit;
	}

	/* create the TCP-specific part of the context */
	tcp_context = malloc(sizeof(struct d_tcp_context));
	if(tcp_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the TCP-specific context");
		goto destroy_context;
	}
	memset(tcp_context, 0, sizeof(struct d_tcp_context));
	rfc3095_ctxt->specific = tcp_context;

	/* create the LSB decoding context for the innermost IP-ID */
	tcp_context->ip_id_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_SN, 16);
	if(tcp_context->ip_id_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the innermost "
		           "IP-ID");
		goto free_tcp_context;
	}

	/* create the LSB decoding context for the sequence number */
	tcp_context->seq_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_VAR, 32);
	if(tcp_context->seq_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the sequence "
		           "number");
		goto free_lsb_ip_id;
	}

	/* create the LSB decoding context for the scaled sequence number */
	tcp_context->seq_scaled_lsb_ctxt = rohc_lsb_new(7, 32);
	if(tcp_context->seq_scaled_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the scaled "
		           "sequence number");
		goto free_lsb_seq;
	}

	/* create the LSB decoding context for the ACK number */
	tcp_context->ack_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_VAR, 32);
	if(tcp_context->ack_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the ACK "
		           "number");
		goto free_lsb_scaled_seq;
	}

	/* the TCP source and destination ports will be initialized
	 * with the IR packets */
	tcp_context->tcp_src_port = 0xFFFF;
	tcp_context->tcp_dst_port = 0xFFFF;

	memset(tcp_context->tcp_options_list, 0xff, ROHC_TCP_OPTS_MAX);
	memset(tcp_context->tcp_opts_list_struct, 0xff, ROHC_TCP_OPTS_MAX);

	/* create the LSB decoding context for the TCP option Timestamp echo
	 * request */
	tcp_context->opt_ts_req_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_VAR, 32);
	if(tcp_context->opt_ts_req_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the TCP "
		           "option Timestamp echo request");
		goto free_lsb_ack;
	}

	/* create the LSB decoding context for the TCP option Timestamp echo
	 * reply */
	tcp_context->opt_ts_reply_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_VAR, 32);
	if(tcp_context->opt_ts_reply_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the TCP "
		           "option Timestamp echo reply");
		goto free_lsb_ts_opt_req;
	}

	/* some TCP-specific values and functions */
	rfc3095_ctxt->next_header_len = sizeof(tcphdr_t);
	rfc3095_ctxt->build_next_header = NULL;
#ifdef TODO
	rfc3095_ctxt->decode_static_next_header = tcp_decode_static_tcp;
	rfc3095_ctxt->decode_dynamic_next_header = tcp_decode_dynamic_tcp;
	rfc3095_ctxt->decode_uo_tail = NULL;
#endif
	rfc3095_ctxt->compute_crc_static = tcp_compute_crc_static;
	rfc3095_ctxt->compute_crc_dynamic = tcp_compute_crc_dynamic;

	/* create the TCP-specific part of the header changes */
	rfc3095_ctxt->outer_ip_changes->next_header_len = sizeof(tcphdr_t);
	rfc3095_ctxt->outer_ip_changes->next_header = malloc(sizeof(tcphdr_t));
	if(rfc3095_ctxt->outer_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the TCP-specific part of the "
		           "outer IP header changes");
		goto free_lsb_ts_opt_reply;
	}
	memset(rfc3095_ctxt->outer_ip_changes->next_header, 0, sizeof(tcphdr_t));

	rfc3095_ctxt->inner_ip_changes->next_header_len = sizeof(tcphdr_t);
	rfc3095_ctxt->inner_ip_changes->next_header = malloc(sizeof(tcphdr_t));
	if(rfc3095_ctxt->inner_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the TCP-specific part of the "
		           "inner IP header changes");
		goto free_outer_next_header;
	}
	memset(rfc3095_ctxt->inner_ip_changes->next_header, 0, sizeof(tcphdr_t));

	/* set next header to TCP */
	rfc3095_ctxt->next_header_proto = ROHC_IPPROTO_TCP;

	return rfc3095_ctxt;

free_outer_next_header:
	zfree(rfc3095_ctxt->outer_ip_changes->next_header);
free_lsb_ts_opt_reply:
	rohc_lsb_free(tcp_context->opt_ts_reply_lsb_ctxt);
free_lsb_ts_opt_req:
	rohc_lsb_free(tcp_context->opt_ts_req_lsb_ctxt);
free_lsb_ack:
	rohc_lsb_free(tcp_context->ack_lsb_ctxt);
free_lsb_scaled_seq:
	rohc_lsb_free(tcp_context->seq_scaled_lsb_ctxt);
free_lsb_seq:
	rohc_lsb_free(tcp_context->seq_lsb_ctxt);
free_lsb_ip_id:
	rohc_lsb_free(tcp_context->ip_id_lsb_ctxt);
free_tcp_context:
	zfree(tcp_context);
destroy_context:
	rohc_decomp_rfc3095_destroy(rfc3095_ctxt);
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
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_tcp_context *tcp_context;

	assert(context != NULL);
	rfc3095_ctxt = (struct rohc_decomp_rfc3095_ctxt *) context;
	assert(rfc3095_ctxt->specific != NULL);
	tcp_context = (struct d_tcp_context *) rfc3095_ctxt->specific;

	/* clean TCP-specific memory */
	assert(rfc3095_ctxt->outer_ip_changes != NULL);
	zfree(rfc3095_ctxt->outer_ip_changes->next_header);
	assert(rfc3095_ctxt->inner_ip_changes != NULL);
	zfree(rfc3095_ctxt->inner_ip_changes->next_header);

	/* destroy the LSB decoding context for the TCP option Timestamp echo
	 * request */
	rohc_lsb_free(tcp_context->opt_ts_req_lsb_ctxt);
	/* destroy the LSB decoding context for the TCP option Timestamp echo
	 * reply */
	rohc_lsb_free(tcp_context->opt_ts_reply_lsb_ctxt);
	/* destroy the LSB decoding context for the ACK number */
	rohc_lsb_free(tcp_context->ack_lsb_ctxt);
	/* destroy the LSB decoding context for the scaled sequence number */
	rohc_lsb_free(tcp_context->seq_scaled_lsb_ctxt);
	/* destroy the LSB decoding context for the sequence number */
	rohc_lsb_free(tcp_context->seq_lsb_ctxt);
	/* destroy the LSB decoding context for the innermost IP-ID */
	rohc_lsb_free(tcp_context->ip_id_lsb_ctxt);

#if 0 /* TODO: sn_lsb_ctxt is not initialized, either remove it or use it fully */
	/* destroy the LSB decoding context for SN */
	rohc_lsb_free(rfc3095_ctxt->sn_lsb_ctxt);
#endif

	/* destroy the generic decompression context (rfc3095_ctxt->specific is
	 * destroyed by rohc_decomp_rfc3095_destroy) */
	rohc_decomp_rfc3095_destroy(rfc3095_ctxt);
}


/**
 * @brief Detect the type of ROHC packet for the TCP profile
 *
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               The packet type
 */
static rohc_packet_t tcp_detect_packet_type(const struct rohc_decomp_ctxt *const context,
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len __attribute__((unused)))
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_tcp_context *tcp_context;
	rohc_packet_t type;

	assert(context != NULL);
	assert(context->specific != NULL);
	rfc3095_ctxt = context->specific;
	assert(rfc3095_ctxt->specific != NULL);
	tcp_context = rfc3095_ctxt->specific;
	assert(rohc_packet != NULL);

	if(rohc_length < 1)
	{
		rohc_decomp_warn(context, "ROHC packet too small to read the packet "
		                 "type (len = %zu)", rohc_length);
		goto error;
	}

	rohc_decomp_debug(context, "try to determine the header from first byte "
	                  "0x%02x", rohc_packet[0]);

	if(rohc_packet[0] == ROHC_PACKET_TYPE_IR)
	{
		type = ROHC_PACKET_IR;
	}
	else if(rohc_packet[0] == ROHC_PACKET_TYPE_IR_DYN)
	{
		type = ROHC_PACKET_IR_DYN;
	}
	else
	{
		uint8_t innermost_ip_id_behavior;
		bool is_ip_id_seq;

		/* detect the version and IP-ID behavior of the innermost IP header */
		{
			if(tcp_context->ip_contexts_nr == 0)
			{
				rohc_decomp_warn(context, "non IR(-DYN) packet received without "
				                 "initialized context: cannot determine the packet "
				                 "type");
				goto error;
			}
			const ip_context_t *const innermost_hdr_ctxt =
				&(tcp_context->ip_contexts[tcp_context->ip_contexts_nr - 1]);
			innermost_ip_id_behavior = innermost_hdr_ctxt->ctxt.vx.ip_id_behavior;
			is_ip_id_seq = (innermost_ip_id_behavior <= IP_ID_BEHAVIOR_SEQ_SWAP);
			rohc_decomp_debug(context, "IPv%u header #%zu is the innermost IP header",
			                  innermost_hdr_ctxt->version, tcp_context->ip_contexts_nr);
		}

		rohc_decomp_debug(context, "try to determine the header from first byte "
		                  "0x%02x and innermost IP-ID behavior %s", rohc_packet[0],
		                  tcp_ip_id_behavior_get_descr(innermost_ip_id_behavior));

		if(rohc_packet[0] & 0x80)
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
 * @param decomp              The ROHC decompressor
 * @param context             The decompression context
 * @param rohc_packet         The ROHC packet to decode
 * @param add_cid_len         The length of the optional Add-CID field
 * @param large_cid_len       The length of the optional large CID field
 * @param[out] uncomp_packet  The uncompressed packet
 * @param packet_type         IN:  The type of the ROHC packet to parse
 *                            OUT: The type of the parsed ROHC packet
 * @return                    ROHC_STATUS_OK if packet is successfully decoded,
 *                            ROHC_STATUS_MALFORMED if packet is malformed,
 *                            ROHC_STATUS_BAD_CRC if a CRC error occurs,
 *                            ROHC_STATUS_ERROR if an error occurs
 */
static rohc_status_t d_tcp_decode(struct rohc_decomp *const decomp,
                                  struct rohc_decomp_ctxt *const context,
                                  const struct rohc_buf rohc_packet,
                                  const size_t add_cid_len,
                                  const size_t large_cid_len,
                                  struct rohc_buf *const uncomp_packet,
                                  rohc_packet_t *const packet_type)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt = context->specific;
	struct d_tcp_context *tcp_context = rfc3095_ctxt->specific;
	rohc_status_t parse_ret;
	size_t i;

	assert(add_cid_len == 0 || add_cid_len == 1);
	assert(large_cid_len <= 2);

	rohc_decomp_debug(context, "rohc_length = %zu, add_cid_len = %zu, "
	                  "large_cid_len = %zu", rohc_packet.len, add_cid_len,
	                  large_cid_len);

	rohc_decomp_debug(context, "parse packet type '%s' (%d)",
	                  rohc_get_packet_descr(*packet_type), *packet_type);

	for(i = 0; i < ROHC_TCP_OPTS_MAX; i++)
	{
		tcp_context->is_tcp_opts_list_item_present[i] = false;
		tcp_context->tcp_opts_list_item_uncomp_length[i] = 0;
	}

	/* TODO: check dest max size */
	if((*packet_type) == ROHC_PACKET_IR)
	{
		/* decode IR packet */
		parse_ret = d_tcp_decode_ir(context, rohc_buf_data(rohc_packet),
		                            rohc_packet.len, large_cid_len, uncomp_packet);
	}
	else if((*packet_type) == ROHC_PACKET_IR_DYN)
	{
		/* decode IR-DYN packet */
		parse_ret = d_tcp_decode_irdyn(context, rohc_buf_data(rohc_packet),
		                               rohc_packet.len, large_cid_len, uncomp_packet);
	}
	else
	{
		/* decode CO packet */
		parse_ret = d_tcp_decode_CO(decomp, context, rohc_buf_data(rohc_packet),
		                            rohc_packet.len, add_cid_len, large_cid_len,
		                            *packet_type, uncomp_packet);
	}

	rohc_decomp_debug(context, "return %d", parse_ret);
	return parse_ret;
}


/**
 * @brief Decode one IR packet for the TCP profile.
 *
 * @param context             The decompression context
 * @param rohc_packet         The ROHC packet to decode
 * @param rohc_length         The length of the ROHC packet to decode
 * @param add_cid_len         The length of the optional Add-CID field
 * @param large_cid_len       The length of the optional large CID field
 * @param[out] uncomp_packet  The uncompressed packet
 * @return                    ROHC_STATUS_OK if decompression was successful,
 *                            ROHC_ERROR_CRC if a CRC failure occured,
 *                            ROHC_ERROR if another error occured
 */
static rohc_status_t d_tcp_decode_ir(struct rohc_decomp_ctxt *context,
                                     const unsigned char *const rohc_packet,
                                     const size_t rohc_length,
                                     const size_t large_cid_len,
                                     struct rohc_buf *const uncomp_packet)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt = context->specific;
	struct d_tcp_context *tcp_context = rfc3095_ctxt->specific;
	size_t ip_contexts_nr;
	size_t payload_size;
	const uint8_t *remain_data;
	size_t remain_len;
	uint8_t protocol;
	size_t uncomp_hdr_size;
	int read;

	remain_data = rohc_packet;
	remain_len = rohc_length;

	/* skip:
	 * - the first byte of the ROHC packet (field 2)
	 * - the Profile byte (field 4) */
	if(remain_len < (1 + large_cid_len + 1))
	{
		rohc_decomp_warn(context, "malformed ROHC packet: too short for first "
		                 "byte, large CID bytes, and profile byte");
		goto error;
	}
	remain_data += 1 + large_cid_len + 1;
	remain_len -= 1 + large_cid_len + 1;

	/* parse CRC */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
		                 "CRC byte");
		goto error;
	}
	/* TODO: check CRC */
	remain_data++;
	remain_len--;

	/* parse static IP chain */
	ip_contexts_nr = 0;
	do
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_contexts_nr]);

		/* IP static part */
		read = tcp_parse_static_ip(context, ip_context, remain_data, remain_len);
		if(read < 0)
		{
			rohc_decomp_warn(context, "malformed ROHC packet: malformed IP "
			                 "static part");
			goto error;
		}
		rohc_decomp_debug(context, "IPv%u static part is %d-byte length",
								ip_context->version, read);
		assert(remain_len >= ((size_t) read));
		remain_data += read;
		remain_len -= read;

		protocol = ip_context->ctxt.vx.next_header;
		ip_contexts_nr++;
	}
	while(rohc_is_tunneling(protocol) && ip_contexts_nr < ROHC_TCP_MAX_IP_HDRS);

	if(rohc_is_tunneling(protocol) && ip_contexts_nr >= ROHC_TCP_MAX_IP_HDRS)
	{
		rohc_decomp_warn(context, "too many IP headers to decompress");
		goto error;
	}
	tcp_context->ip_contexts_nr = ip_contexts_nr;

	/* parse TCP static part */
	read = tcp_parse_static_tcp(context, remain_data, remain_len);
	if(read < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed TCP static "
		                 "part");
		goto error;
	}
	rohc_decomp_debug(context, "TCP static part is %d-byte length", read);
	assert(remain_len >= ((size_t) read));
	remain_data += read;
	remain_len -= read;

	/* parse dynamic chain (IPv4/IPv6 headers and extension headers) */
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_contexts_nr]);

		/* IP dynamic part */
		read = tcp_parse_dynamic_ip(context, ip_context, remain_data, remain_len);
		if(read < 0)
		{
			rohc_decomp_warn(context, "malformed ROHC packet: malformed IP "
			                 "dynamic part");
			goto error;
		}
		rohc_decomp_debug(context, "IPv%u dynamic part is %d-byte length",
								ip_context->version, read);
		assert(remain_len >= ((size_t) read));
		remain_data += read;
		remain_len -= read;
	}

	/* parse TCP dynamic part */
	read = tcp_parse_dynamic_tcp(context, remain_data, remain_len);
	if(read < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed TCP "
		                 "dynamic part");
		goto error;
	}
	rohc_decomp_debug(context, "TCP dynamic part is %d-byte length", read);
	assert(remain_len >= ((size_t) read));
	remain_data += read;
	remain_len -= read;

	rohc_decomp_debug(context, "ROHC header is %zu-byte length",
	                  rohc_length - remain_len);
	payload_size = remain_len;
	rohc_decomp_debug(context, "ROHC payload is %zu-byte length", payload_size);

	// Calculate scaled value and residue (see RFC4996 page 32/33)
	if(payload_size != 0)
	{
		tcp_context->seq_num_scaled = rohc_ntoh32(tcp_context->seq_num) / payload_size;
		tcp_context->seq_num_residue = rohc_ntoh32(tcp_context->seq_num) % payload_size;
		rohc_decomp_debug(context, "seq_number = 0x%x, payload size = %zu -> "
		                  "seq_number_residue = 0x%x, seq_number_scaled = 0x%x",
		                  rohc_ntoh32(tcp_context->seq_num), payload_size,
		                  tcp_context->seq_num_residue,
		                  tcp_context->seq_num_scaled);
	}

	/*
	 * build uncompressed packet
	 */

	/* IP headers */
	uncomp_hdr_size = 0;
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[ip_contexts_nr]);

		if(ip_context->version == IPV4)
		{
			base_header_ip_v4_t *const ipv4 =
				(base_header_ip_v4_t *) rohc_buf_data(*uncomp_packet);

			if(rohc_buf_avail_len(*uncomp_packet) < sizeof(base_header_ip_v4_t))
			{
				rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
				                 "IPv4 header #%zu", sizeof(base_header_ip_v4_t),
				                 ip_contexts_nr + 1);
				goto error;
			}

			/* static part */
			ipv4->version = IPV4;
			ipv4->header_length = sizeof(base_header_ip_v4_t) >> 2;
			ipv4->protocol = ip_context->ctxt.v4.protocol;
			ipv4->src_addr = ip_context->ctxt.v4.src_addr;
			ipv4->dest_addr = ip_context->ctxt.v4.dst_addr;
			/* dynamic part */
			ipv4->rf = 0;
			ipv4->df = ip_context->ctxt.v4.df;
			ipv4->mf = 0;
			ipv4->dscp = ip_context->ctxt.v4.dscp;
			ipv4->ip_ecn_flags = ip_context->ctxt.v4.ip_ecn_flags;
			ipv4->ttl_hopl = ip_context->ctxt.v4.ttl_hopl;
			rohc_decomp_debug(context, "DSCP = 0x%x, ip_ecn_flags = %d",
			                  ipv4->dscp, ipv4->ip_ecn_flags);
#if WORDS_BIGENDIAN != 1
			ipv4->frag_offset1 = 0;
			ipv4->frag_offset2 = 0;
#else
			ipv4->frag_offset = 0;
#endif
			/* IP-ID */
			ipv4->ip_id = rohc_hton16(ip_context->ctxt.v4.ip_id);

			/* length and checksums will be computed once all headers are built */

			uncomp_packet->len += sizeof(base_header_ip_v4_t);
			rohc_buf_pull(uncomp_packet, sizeof(base_header_ip_v4_t));
			uncomp_hdr_size += sizeof(base_header_ip_v4_t);
		}
		else
		{
			base_header_ip_v6_t *const ipv6 =
				(base_header_ip_v6_t *) rohc_buf_data(*uncomp_packet);
			const size_t ipv6_exts_len = ip_context->ctxt.v6.opts_len;
			const size_t full_ipv6_len =
				sizeof(base_header_ip_v6_t) + ipv6_exts_len;

			if(rohc_buf_avail_len(*uncomp_packet) < full_ipv6_len)
			{
				rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
				                 "IPv6 header #%zu (with %zu bytes of extension "
				                 "headers)", full_ipv6_len, ip_contexts_nr + 1,
				                 ipv6_exts_len);
				goto error;
			}
			rohc_decomp_debug(context, "build %zu-byte IPv6 header %zu (with %zu "
			                  "bytes of extension headers)", full_ipv6_len,
			                  ip_contexts_nr + 1, ipv6_exts_len);

			/* static part */
			ipv6->version = IPV6;
			ipv6->flow_label1 = ip_context->ctxt.v6.flow_label1;
			ipv6->flow_label2 = ip_context->ctxt.v6.flow_label2;
			ipv6->next_header = ip_context->ctxt.v6.next_header;
			memcpy(ipv6->src_addr, ip_context->ctxt.v6.src_addr, sizeof(uint32_t) * 4);
			memcpy(ipv6->dest_addr, ip_context->ctxt.v6.dest_addr, sizeof(uint32_t) * 4);
			/* dynamic part */
			ipv6->dscp1 = ip_context->ctxt.v6.dscp >> 2;
			ipv6->dscp2 = ip_context->ctxt.v6.dscp & 0x03;
			ipv6->ip_ecn_flags = ip_context->ctxt.v6.ip_ecn_flags;
			ipv6->ttl_hopl = ip_context->ctxt.v6.ttl_hopl;

			/* total length will be computed once all headers are built */

			uncomp_packet->len += sizeof(base_header_ip_v6_t);
			rohc_buf_pull(uncomp_packet, sizeof(base_header_ip_v6_t));
			uncomp_hdr_size += sizeof(base_header_ip_v6_t);
		}
	}

	/* TCP header */
	{
		tcphdr_t *const tcp = (tcphdr_t *) rohc_buf_data(*uncomp_packet);
		const size_t full_tcp_len = sizeof(tcphdr_t) + tcp_context->options_len;

		if(rohc_buf_avail_len(*uncomp_packet) < full_tcp_len)
		{
			rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
			                 "TCP header and TCP options", full_tcp_len);
			goto error;
		}
		rohc_decomp_debug(context, "build %zu-byte TCP header (with %zu bytes "
		                  "of options)", full_tcp_len, tcp_context->options_len);

		/* static part */
		tcp->src_port = tcp_context->tcp_src_port;
		tcp->dst_port = tcp_context->tcp_dst_port;
		/* dynamic part */
		tcp->data_offset = (full_tcp_len >> 2) & 0xf;
		tcp->res_flags = tcp_context->res_flags;
		tcp->ecn_flags = tcp_context->ecn_flags;
		tcp->urg_flag = tcp_context->urg_flag;
		tcp->ack_flag = tcp_context->ack_flag;
		tcp->psh_flag = tcp_context->psh_flag;
		tcp->rsf_flags = tcp_context->rsf_flags;
		tcp->seq_num = tcp_context->seq_num;
		tcp->ack_num = tcp_context->ack_num;
		tcp->window = tcp_context->window;
		tcp->checksum = tcp_context->checksum;
		tcp->urg_ptr = tcp_context->urg_ptr;
		memcpy(tcp->options, tcp_context->options, tcp_context->options_len);

		uncomp_packet->len += full_tcp_len;
		rohc_buf_pull(uncomp_packet, full_tcp_len);
		uncomp_hdr_size += full_tcp_len;

		/* update context (should only be done at the very end, to be moved) */
		memcpy(&tcp_context->old_tcphdr, tcp, sizeof(tcphdr_t));
	}

	/* payload */
	rohc_decomp_debug(context, "uncompressed header is %zu-byte length",
	                  uncomp_hdr_size);
	rohc_decomp_debug(context, "copy %zu bytes of payload", payload_size);
	rohc_buf_append(uncomp_packet, remain_data, payload_size);
	rohc_buf_push(uncomp_packet, uncomp_hdr_size);
	rohc_decomp_debug(context, "uncompressed packet is %zu-byte length",
	                  uncomp_packet->len);

	/* compute payload lengths and checksums for all headers */
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[ip_contexts_nr]);

		if(ip_context->version == IPV4)
		{
			base_header_ip_v4_t *const ipv4 =
				(base_header_ip_v4_t *) rohc_buf_data(*uncomp_packet);
			ipv4->length = rohc_hton16(uncomp_packet->len);
			ipv4->checksum = 0;
			ipv4->checksum =
				ip_fast_csum(rohc_buf_data(*uncomp_packet), ipv4->header_length);
			rohc_decomp_debug(context, "IP checksum = 0x%04x on %zu bytes",
			                  rohc_ntoh16(ipv4->checksum),
			                  ipv4->header_length * sizeof(uint32_t));
			rohc_buf_pull(uncomp_packet, ipv4->header_length * sizeof(uint32_t));
		}
		else
		{
			base_header_ip_v6_t *const ipv6 =
				(base_header_ip_v6_t *) rohc_buf_data(*uncomp_packet);
			rohc_buf_pull(uncomp_packet, sizeof(base_header_ip_v6_t));
			ipv6->payload_length = rohc_hton16(uncomp_packet->len);
			rohc_decomp_debug(context, "IPv6 payload length = %d",
			                  rohc_ntoh16(ipv6->payload_length));
			rohc_buf_pull(uncomp_packet, ip_context->ctxt.v6.opts_len);
		}
	}
	{
		const size_t full_tcp_len = sizeof(tcphdr_t) + tcp_context->options_len;
		rohc_buf_push(uncomp_packet, uncomp_hdr_size - full_tcp_len);
	}

	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "current IP + TCP packet",
	              rohc_buf_data(*uncomp_packet), uncomp_hdr_size);

	/* update context (to be completed) */
	{
		assert(tcp_context->ip_contexts_nr > 0);
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[tcp_context->ip_contexts_nr - 1]);
		const ip_version innermost_ip_version = ip_context->ctxt.vx.version;
		const uint16_t inner_ip_id = ip_context->ctxt.v4.ip_id;
		const uint16_t inner_ip_id_offset = inner_ip_id - tcp_context->msn;
		if(innermost_ip_version == IPV4)
		{
			rohc_lsb_set_ref(tcp_context->ip_id_lsb_ctxt, inner_ip_id_offset, false);
			rohc_decomp_debug(context, "innermost IP-ID offset 0x%04x is the new "
			                  "reference", inner_ip_id_offset);
		}
	}
	rohc_lsb_set_ref(tcp_context->seq_lsb_ctxt, rohc_ntoh32(tcp_context->seq_num), false);
	rohc_decomp_debug(context, "sequence number 0x%08x is the new reference",
	                  rohc_ntoh32(tcp_context->seq_num));
	if(payload_size != 0)
	{
		rohc_lsb_set_ref(tcp_context->seq_scaled_lsb_ctxt,
		                 tcp_context->seq_num_scaled, false);
		rohc_decomp_debug(context, "scaled sequence number 0x%08x is the new "
		                  "reference", tcp_context->seq_num_scaled);
	}
	rohc_lsb_set_ref(tcp_context->ack_lsb_ctxt, rohc_ntoh32(tcp_context->ack_num), false);
	rohc_decomp_debug(context, "ACK number 0x%08x is the new reference",
	                  rohc_ntoh32(tcp_context->ack_num));

	// TODO: to be reworked
	context->state = ROHC_DECOMP_STATE_FC;

	return ROHC_STATUS_OK;

error:
	return ROHC_STATUS_ERROR;
}


/**
 * @brief Decode one IR-DYN packet for the TCP profile.
 *
 * @param context             The decompression context
 * @param rohc_packet         The ROHC packet to decode
 * @param rohc_length         The length of the ROHC packet to decode
 * @param large_cid_len       The length of the optional large CID field
 * @param dest                The decoded IP packet
 * @param[out] uncomp_packet  The uncompressed packet
 * @return                    ROHC_STATUS_OK if decompression was successful,
 *                            ROHC_ERROR_CRC if a CRC failure occured,
 *                            ROHC_ERROR if another error occured
 */
static rohc_status_t d_tcp_decode_irdyn(struct rohc_decomp_ctxt *context,
                                        const unsigned char *const rohc_packet,
                                        const size_t rohc_length,
                                        const size_t large_cid_len,
                                        struct rohc_buf *const uncomp_packet)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt = context->specific;
	struct d_tcp_context *tcp_context = rfc3095_ctxt->specific;
	size_t ip_contexts_nr;
	size_t payload_size;
	const uint8_t *remain_data;
	size_t remain_len;
	size_t uncomp_hdr_size;
	int read;

	remain_data = rohc_packet;
	remain_len = rohc_length;

	/* skip:
	 * - the first byte of the ROHC packet (field 2)
	 * - the Profile byte (field 4) */
	if(remain_len < (1 + large_cid_len + 1))
	{
		rohc_decomp_warn(context, "malformed ROHC packet: too short for first "
		                 "byte, large CID bytes, and profile byte");
		goto error;
	}
	remain_data += 1 + large_cid_len + 1;
	remain_len -= 1 + large_cid_len + 1;

	/* parse CRC */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
		                 "CRC byte");
		goto error;
	}
	/* TODO: check CRC */
	remain_data++;
	remain_len--;

	/* parse dynamic chain (IPv4/IPv6 headers and extension headers) */
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_contexts_nr]);

		/* IP dynamic part */
		read = tcp_parse_dynamic_ip(context, ip_context, remain_data, remain_len);
		if(read < 0)
		{
			rohc_decomp_warn(context, "malformed ROHC packet: malformed IP "
			                 "dynamic part");
			goto error;
		}
		rohc_decomp_debug(context, "IPv%u dynamic part is %d-byte length",
								ip_context->version, read);
		assert(remain_len >= ((size_t) read));
		remain_data += read;
		remain_len -= read;
	}

	/* parse TCP dynamic part */
	read = tcp_parse_dynamic_tcp(context, remain_data, remain_len);
	if(read < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed TCP "
		                 "dynamic part");
		goto error;
	}
	rohc_decomp_debug(context, "TCP dynamic part is %d-byte length", read);
	remain_data += read;
	remain_len -= read;

	rohc_decomp_debug(context, "ROHC header is %zu-byte length",
	                  rohc_length - remain_len);
	payload_size = remain_len;
	rohc_decomp_debug(context, "ROHC payload is %zu-byte length", payload_size);

	// Calculate scaled value and residue (see RFC4996 page 32/33)
	if(payload_size != 0)
	{
		tcp_context->seq_num_scaled = rohc_ntoh32(tcp_context->seq_num) / payload_size;
		tcp_context->seq_num_residue = rohc_ntoh32(tcp_context->seq_num) % payload_size;
		rohc_decomp_debug(context, "seq_number = 0x%x, payload size = %zu -> "
		                  "seq_number_residue = 0x%x, seq_number_scaled = 0x%x",
		                  rohc_ntoh32(tcp_context->seq_num), payload_size,
		                  tcp_context->seq_num_residue,
		                  tcp_context->seq_num_scaled);
	}

	/* TODO: duplicated from IR */
	/*
	 * build uncompressed packet
	 */

	/* IP headers */
	uncomp_hdr_size = 0;
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[ip_contexts_nr]);

		if(ip_context->version == IPV4)
		{
			base_header_ip_v4_t *const ipv4 =
				(base_header_ip_v4_t *) rohc_buf_data(*uncomp_packet);

			if(rohc_buf_avail_len(*uncomp_packet) < sizeof(base_header_ip_v4_t))
			{
				rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
				                 "IPv4 header #%zu", sizeof(base_header_ip_v4_t),
				                 ip_contexts_nr + 1);
				goto error;
			}

			/* static part */
			ipv4->version = IPV4;
			ipv4->header_length = sizeof(base_header_ip_v4_t) >> 2;
			ipv4->protocol = ip_context->ctxt.v4.protocol;
			ipv4->src_addr = ip_context->ctxt.v4.src_addr;
			ipv4->dest_addr = ip_context->ctxt.v4.dst_addr;
			/* dynamic part */
			ipv4->rf = 0;
			ipv4->df = ip_context->ctxt.v4.df;
			ipv4->mf = 0;
			ipv4->dscp = ip_context->ctxt.v4.dscp;
			ipv4->ip_ecn_flags = ip_context->ctxt.v4.ip_ecn_flags;
			ipv4->ttl_hopl = ip_context->ctxt.v4.ttl_hopl;
			rohc_decomp_debug(context, "DSCP = 0x%x, ip_ecn_flags = %d",
			                  ipv4->dscp, ipv4->ip_ecn_flags);
#if WORDS_BIGENDIAN != 1
			ipv4->frag_offset1 = 0;
			ipv4->frag_offset2 = 0;
#else
			ipv4->frag_offset = 0;
#endif
			/* IP-ID */
			ipv4->ip_id = rohc_hton16(ip_context->ctxt.v4.ip_id);

			/* length and checksums will be computed once all headers are built */

			uncomp_packet->len += sizeof(base_header_ip_v4_t);
			rohc_buf_pull(uncomp_packet, sizeof(base_header_ip_v4_t));
			uncomp_hdr_size += sizeof(base_header_ip_v4_t);
		}
		else
		{
			base_header_ip_v6_t *const ipv6 =
				(base_header_ip_v6_t *) rohc_buf_data(*uncomp_packet);
			const size_t ipv6_exts_len = ip_context->ctxt.v6.opts_len;
			const size_t full_ipv6_len =
				sizeof(base_header_ip_v6_t) + ipv6_exts_len;

			if(rohc_buf_avail_len(*uncomp_packet) < full_ipv6_len)
			{
				rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
				                 "IPv6 header #%zu (with %zu bytes of extension "
				                 "headers)", full_ipv6_len, ip_contexts_nr + 1,
				                 ipv6_exts_len);
				goto error;
			}
			rohc_decomp_debug(context, "build %zu-byte IPv6 header %zu (with %zu "
			                  "bytes of extension headers)", full_ipv6_len,
			                  ip_contexts_nr + 1, ipv6_exts_len);

			/* static part */
			ipv6->version = IPV6;
			ipv6->flow_label1 = ip_context->ctxt.v6.flow_label1;
			ipv6->flow_label2 = ip_context->ctxt.v6.flow_label2;
			ipv6->next_header = ip_context->ctxt.v6.next_header;
			memcpy(ipv6->src_addr, ip_context->ctxt.v6.src_addr, sizeof(uint32_t) * 4);
			memcpy(ipv6->dest_addr, ip_context->ctxt.v6.dest_addr, sizeof(uint32_t) * 4);
			/* dynamic part */
			ipv6->dscp1 = ip_context->ctxt.v6.dscp >> 2;
			ipv6->dscp2 = ip_context->ctxt.v6.dscp & 0x03;
			ipv6->ip_ecn_flags = ip_context->ctxt.v6.ip_ecn_flags;
			ipv6->ttl_hopl = ip_context->ctxt.v6.ttl_hopl;

			/* total length will be computed once all headers are built */

			uncomp_packet->len += sizeof(base_header_ip_v6_t);
			rohc_buf_pull(uncomp_packet, sizeof(base_header_ip_v6_t));
			uncomp_hdr_size += sizeof(base_header_ip_v6_t);
		}
	}

	/* TCP header */
	{
		tcphdr_t *const tcp = (tcphdr_t *) rohc_buf_data(*uncomp_packet);
		const size_t full_tcp_len = sizeof(tcphdr_t) + tcp_context->options_len;

		if(rohc_buf_avail_len(*uncomp_packet) < full_tcp_len)
		{
			rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
			                 "TCP header and TCP options", full_tcp_len);
			goto error;
		}
		rohc_decomp_debug(context, "build %zu-byte TCP header (with %zu bytes "
		                  "of options)", full_tcp_len, tcp_context->options_len);

		/* static part */
		tcp->src_port = tcp_context->tcp_src_port;
		tcp->dst_port = tcp_context->tcp_dst_port;
		/* dynamic part */
		tcp->data_offset = (full_tcp_len >> 2) & 0xf;
		tcp->res_flags = tcp_context->res_flags;
		tcp->ecn_flags = tcp_context->ecn_flags;
		tcp->urg_flag = tcp_context->urg_flag;
		tcp->ack_flag = tcp_context->ack_flag;
		tcp->psh_flag = tcp_context->psh_flag;
		tcp->rsf_flags = tcp_context->rsf_flags;
		tcp->seq_num = tcp_context->seq_num;
		tcp->ack_num = tcp_context->ack_num;
		tcp->window = tcp_context->window;
		tcp->checksum = tcp_context->checksum;
		tcp->urg_ptr = tcp_context->urg_ptr;
		memcpy(tcp->options, tcp_context->options, tcp_context->options_len);

		uncomp_packet->len += full_tcp_len;
		rohc_buf_pull(uncomp_packet, full_tcp_len);
		uncomp_hdr_size += full_tcp_len;

		/* update context (should only be done at the very end, to be moved) */
		memcpy(&tcp_context->old_tcphdr, tcp, sizeof(tcphdr_t));
	}

	/* payload */
	rohc_decomp_debug(context, "uncompressed header is %zu-byte length",
	                  uncomp_hdr_size);
	rohc_decomp_debug(context, "copy %zu bytes of payload", payload_size);
	rohc_buf_append(uncomp_packet, remain_data, payload_size);
	rohc_buf_push(uncomp_packet, uncomp_hdr_size);
	rohc_decomp_debug(context, "uncompressed packet is %zu-byte length",
	                  uncomp_packet->len);

	/* compute payload lengths and checksums for all headers */
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[ip_contexts_nr]);

		if(ip_context->version == IPV4)
		{
			base_header_ip_v4_t *const ipv4 =
				(base_header_ip_v4_t *) rohc_buf_data(*uncomp_packet);
			ipv4->length = rohc_hton16(uncomp_packet->len);
			ipv4->checksum = 0;
			ipv4->checksum =
				ip_fast_csum(rohc_buf_data(*uncomp_packet), ipv4->header_length);
			rohc_decomp_debug(context, "IP checksum = 0x%04x on %zu bytes",
			                  rohc_ntoh16(ipv4->checksum),
			                  ipv4->header_length * sizeof(uint32_t));
			rohc_buf_pull(uncomp_packet, ipv4->header_length * sizeof(uint32_t));
		}
		else
		{
			base_header_ip_v6_t *const ipv6 =
				(base_header_ip_v6_t *) rohc_buf_data(*uncomp_packet);
			rohc_buf_pull(uncomp_packet, sizeof(base_header_ip_v6_t));
			ipv6->payload_length = rohc_hton16(uncomp_packet->len);
			rohc_decomp_debug(context, "IPv6 payload length = %d",
			                  rohc_ntoh16(ipv6->payload_length));
			rohc_buf_pull(uncomp_packet, ip_context->ctxt.v6.opts_len);
		}
	}
	{
		const size_t full_tcp_len = sizeof(tcphdr_t) + tcp_context->options_len;
		rohc_buf_push(uncomp_packet, uncomp_hdr_size - full_tcp_len);
	}

	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "current IP + TCP packet",
	              rohc_buf_data(*uncomp_packet), uncomp_hdr_size);

	/* TODO: duplicated from IR */
	/* update context (to be completed) */
	{
		assert(tcp_context->ip_contexts_nr > 0);
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[tcp_context->ip_contexts_nr - 1]);
		const ip_version innermost_ip_version = ip_context->ctxt.vx.version;
		const uint16_t inner_ip_id = ip_context->ctxt.v4.ip_id;
		const uint16_t inner_ip_id_offset = inner_ip_id - tcp_context->msn;
		if(innermost_ip_version == IPV4)
		{
			rohc_lsb_set_ref(tcp_context->ip_id_lsb_ctxt, inner_ip_id_offset, false);
			rohc_decomp_debug(context, "innermost IP-ID offset 0x%04x is the new "
			                  "reference", inner_ip_id_offset);
		}
	}
	rohc_lsb_set_ref(tcp_context->seq_lsb_ctxt, rohc_ntoh32(tcp_context->seq_num), false);
	rohc_decomp_debug(context, "sequence number 0x%08x is the new reference",
	                  rohc_ntoh32(tcp_context->seq_num));
	if(payload_size != 0)
	{
		rohc_lsb_set_ref(tcp_context->seq_scaled_lsb_ctxt,
		                 tcp_context->seq_num_scaled, false);
		rohc_decomp_debug(context, "scaled sequence number 0x%08x is the new "
		                  "reference", tcp_context->seq_num_scaled);
	}
	rohc_lsb_set_ref(tcp_context->ack_lsb_ctxt, rohc_ntoh32(tcp_context->ack_num), false);
	rohc_decomp_debug(context, "ACK number 0x%08x is the new reference",
	                  rohc_ntoh32(tcp_context->ack_num));

	return ROHC_STATUS_OK;

error:
	return ROHC_STATUS_ERROR;
}


/**
 * @brief Decode the static IP v6 option header of the rohc packet.
 *
 * @param context        The decompression context
 * @param ip_context     The specific IP decompression context
 * @param protocol       The IPv6 protocol option
 * @param rohc_packet    The remaining part of the ROHC packet
 * @param rohc_length    The remaining length (in bytes) of the ROHC packet
 * @param base_header    The decoded IP packet
 * @return               The length of static IP header in case of success,
 *                       -1 if an error occurs
 */
static int tcp_parse_static_ipv6_option(struct rohc_decomp_ctxt *const context,
                                        ip_context_t *const ip_context,
                                        ipv6_option_context_t *const opt_context,
                                        const uint8_t protocol,
                                        const unsigned char *const rohc_packet,
                                        const size_t rohc_length)
{
	const ip_opt_static_t *ip_opt_static;
	size_t size;
#if 0
	int ret;
#endif

	assert(context != NULL);
	assert(rohc_packet != NULL);

	rohc_decomp_debug(context, "parse static part of IPv6 extension header");

	/* at least 1 byte required to read the next header and length */
	if(rohc_length < 2)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
		                 "version flag of the IP static part");
		goto error;
	}
	ip_opt_static = (ip_opt_static_t *) rohc_packet;
	opt_context->generic.next_header = ip_opt_static->next_header;

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
		{
			size = sizeof(ip_hop_opt_static_t);
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Hop-by-Hop option");
				goto error;
			}
			opt_context->generic.option_length = (ip_opt_static->length + 1) << 3;
			opt_context->generic.context_length = 2 + opt_context->generic.option_length;
			rohc_decomp_debug(context, "IPv6 option Hop-by-Hop: length = %d, "
			                  "context_length = %d, option_length = %d",
			                  ip_opt_static->length,
			                  opt_context->generic.context_length,
			                  opt_context->generic.option_length);
			opt_context->generic.length = ip_opt_static->length;
			break;
		}
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
		{
			const ip_rout_opt_static_t *const ip_rout_opt_static =
				(ip_rout_opt_static_t *) ip_opt_static;
			size = (ip_opt_static->length + 1) << 3;
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Routing option");
				goto error;
			}
			if(size > (6 + 2))
			{
				rohc_decomp_warn(context, "static part of the IPv6 Routing "
				                 "option too large for implementation: %zu "
				                 "bytes required while only %u bytes "
				                 "available", size, 6U + 2U);
				goto error;
			}
			opt_context->generic.context_length = 2 + size;
			opt_context->generic.option_length = size;
			memcpy(&opt_context->generic.length, &ip_rout_opt_static->length,
			       size - 1);
			break;
		}
		case ROHC_IPPROTO_GRE:
		{
			const ip_gre_opt_static_t *const ip_gre_opt_static =
				(ip_gre_opt_static_t *) ip_opt_static;

			if(rohc_length < sizeof(ip_gre_opt_static_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 GRE option");
				goto error;
			}
			opt_context->generic.context_length = sizeof(ipv6_gre_option_context_t);
#if 0 /* to be clarified */
			if((opt_context->gre.protocol ==
			    ip_gre_opt_static->protocol) == 0) // TODO: check that
			{
				base_header.ip_gre_opt->protocol = rohc_hton16(0x0800);
			}
			else
			{
				base_header.ip_gre_opt->protocol = rohc_hton16(0x86DD);
			}
#endif
			opt_context->gre.c_flag = ip_gre_opt_static->c_flag;
			opt_context->gre.s_flag = ip_gre_opt_static->s_flag;
			opt_context->gre.k_flag = ip_gre_opt_static->k_flag;
			size = sizeof(ip_gre_opt_static_t);

#if 0 /* to be moved after parsing */
			ret = d_optional32(ip_gre_opt_static->k_flag,
			                   ip_gre_opt_static->options,
			                   rohc_length - size,
			                   opt_context->gre.key,
			                   &(base_header.ip_gre_opt->datas[opt_context->gre.c_flag]));
			if(ret < 0)
			{
				rohc_decomp_warn(context, "ROHC packet too small for optional "
				                 "key field in GRE static part");
				goto error;
			}
			opt_context->gre.key =
				base_header.ip_gre_opt->datas[opt_context->gre.c_flag];
			size += ret;
#endif

			opt_context->generic.option_length = size << 3;

#if 0 /* to be moved after parsing */
			if(ip_gre_opt_static->k_flag != 0)
			{
				base_header.ip_gre_opt->datas[opt_context->gre.c_flag] =
				   opt_context->gre.key;
			}
#endif
			break;
		}
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
		{
			const ip_dest_opt_static_t *const ip_dest_opt_static =
				(ip_dest_opt_static_t *) ip_opt_static;
			size = sizeof(ip_dest_opt_static_t);
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Destination option");
				goto error;
			}
			opt_context->generic.option_length = (ip_opt_static->length + 1) << 3;
			opt_context->generic.context_length = 2 + opt_context->generic.option_length;
			rohc_decomp_debug(context, "IPv6 option Destination: length = %d, "
			                  "context_length = %d, option_length = %d",
			                  ip_opt_static->length,
			                  opt_context->generic.context_length,
			                  opt_context->generic.option_length);
			opt_context->generic.length = ip_dest_opt_static->length;
			break;
		}
		case ROHC_IPPROTO_MINE:
		{
			const ip_mime_opt_static_t *const ip_mime_opt_static =
				(ip_mime_opt_static_t *) ip_opt_static;
			size = sizeof(ip_mime_opt_static_t) -
			       (ip_mime_opt_static->s_bit * sizeof(uint32_t));
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Destination option");
				goto error;
			}
			opt_context->generic.context_length = sizeof(ipv6_mime_option_context_t);
			opt_context->generic.option_length = (2 + ip_mime_opt_static->s_bit) << 3;
			opt_context->mime.s_bit = ip_mime_opt_static->s_bit;
			opt_context->mime.res_bits = ip_mime_opt_static->res_bits;
			opt_context->mime.orig_dest = ip_mime_opt_static->orig_dest;
			if(opt_context->mime.s_bit != 0)
			{
				opt_context->mime.orig_src = ip_mime_opt_static->orig_src;
			}
			break;
		}
		case ROHC_IPPROTO_AH:
		{
			const ip_ah_opt_static_t *const ip_ah_opt_static =
				(ip_ah_opt_static_t *) ip_opt_static;
			size = sizeof(ip_ah_opt_static_t);
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Destination option");
				goto error;
			}
			opt_context->generic.context_length = sizeof(ipv6_ah_option_context_t);
			opt_context->generic.option_length =
				sizeof(ip_ah_opt_t) - sizeof(uint32_t) +
				(ip_ah_opt_static->length << 4) - sizeof(int32_t);
			opt_context->ah.length = ip_ah_opt_static->length;
			opt_context->ah.spi = ip_ah_opt_static->spi;
			break;
		}
		default:
		{
			goto error;
		}
	}
	ip_context->ctxt.v6.opts_len += opt_context->generic.option_length;

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IPv6 option static part", rohc_packet, size);
#endif

	return size;

error:
	return -1;
}


/**
 * @brief Decode the dynamic IP v6 option header of the rohc packet.
 *
 * @param context        The decompression context
 * @param ip_context     The specific IP decompression context
 * @param protocol       The IPv6 protocol option
 * @param rohc_packet    The remaining part of the ROHC packet
 * @param rohc_length    The remaining length (in bytes) of the ROHC packet
 * @param base_header    The decoded IP packet
 * @return               The length of dynamic IP header
 *                       0 if an error occurs
 */
static int tcp_parse_dynamic_ipv6_option(struct rohc_decomp_ctxt *const context,
                                         ipv6_option_context_t *const opt_context,
                                         const uint8_t protocol,
                                         const unsigned char *const rohc_packet,
                                         const size_t rohc_length)
{
	size_t remain_len = rohc_length;
	size_t size = 0;
#if 0
	int ret;
#endif

	assert(context != NULL);
	assert(rohc_packet != NULL);

	rohc_decomp_debug(context, "parse dynamic part of IPv6 extension header");

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
		{
			size += ((opt_context->generic.length + 1) << 3) - 2;
			if(remain_len < size)
			{
				rohc_decomp_warn(context, "malformed IPv6 option: malformed "
				                 "option %u: %zu bytes available while %zu bytes "
				                 "required", protocol, remain_len, size);
				goto error;
			}
			if(size > 6)
			{
				rohc_decomp_warn(context, "static part of the IPv6 %u too "
				                 "large for implementation: %zu bytes required "
				                 "while only %u bytes available", protocol,
				                 size, 6U);
				goto error;
			}
			memcpy(opt_context->generic.value, rohc_packet, size);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
			remain_len -= size;
#endif
			break;
		}
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
		{
			break;
		}
		case ROHC_IPPROTO_GRE:
		{
			if(opt_context->gre.c_flag != 0)
			{
				if(remain_len < sizeof(uint32_t))
				{
					rohc_decomp_warn(context, "malformed IPv6 option: malformed "
					                 "option GRE: %zu bytes available while 4 "
					                 "bytes required", remain_len);
					goto error;
				}
#if 0 /* to be moved after parsing */
				memcpy(base_header.ip_gre_opt->datas, rohc_packet + size,
				       sizeof(uint32_t));
#endif
				size += sizeof(uint32_t);
				remain_len -= sizeof(uint32_t);
			}
#if 0 /* to be moved after parsing */
			ret = d_optional32(opt_context->gre.s_flag,
			                   rohc_packet + size, remain_len,
			                   base_header.ip_gre_opt->datas[opt_context->gre.c_flag],
			                   &base_header.ip_gre_opt->datas[opt_context->gre.c_flag]);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "malformed IPv6 option: malformed "
				                 "option GRE");
				goto error;
			}
			size += ret;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
			remain_len -= ret;
#endif
#endif
			break;
		}
		case ROHC_IPPROTO_MINE:
		{
			break;
		}
		case ROHC_IPPROTO_AH:
		{
			const ip_ah_opt_dynamic_t *const ip_ah_opt_dynamic =
				(ip_ah_opt_dynamic_t *) rohc_packet;

			size += opt_context->ah.length << 2;
			if(remain_len < size)
			{
				rohc_decomp_warn(context, "malformed IPv6 option: malformed "
				                 "option AH: %zu bytes available while %zu bytes "
				                 "required", remain_len, size);
				goto error;
			}
			opt_context->ah.sequence_number =
			   ip_ah_opt_dynamic->sequence_number;
			memcpy(opt_context->ah.auth_data,
			       ip_ah_opt_dynamic->auth_data, size - sizeof(uint32_t));
			break;
		}
		default:
		{
			break;
		}
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IPv6 option dynamic part", rohc_packet, size);
#endif

	return size;

error:
	return -1;
}


/**
 * @brief Decode the static IP header of the rohc packet.
 *
 * @param context             The decompression context
 * @param ip_context          The specific IP decompression context
 * @param rohc_packet         The remaining part of the ROHC packet
 * @param rohc_length         The remaining length (in bytes) of the ROHC packet
 * @return                    The length of static IP header in case of success,
 *                            -1 if an error occurs
 */
static int tcp_parse_static_ip(struct rohc_decomp_ctxt *const context,
                               ip_context_t *const ip_context,
                               const unsigned char *const rohc_packet,
                               const size_t rohc_length)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t read = 0;
	int ret;

	rohc_decomp_debug(context, "parse IP static part");

	/* at least 1 byte required to read the version flag */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
		                 "version flag of the IP static part");
		goto error;
	}

	/* parse IPv4 static part or IPv6 static part? */
	if(GET_BIT_7(remain_data) == 0)
	{
		const ipv4_static_t *const ipv4_static = (ipv4_static_t *) remain_data;

		if(remain_len < sizeof(ipv4_static_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
			                 "IPv4 static part");
			goto error;
		}

		ip_context->version = IPV4;
		ip_context->ctxt.v4.version = IPV4;
		ip_context->ctxt.v4.context_length = sizeof(ipv4_context_t);
		ip_context->ctxt.v4.protocol = ipv4_static->protocol;
		ip_context->ctxt.v4.src_addr = ipv4_static->src_addr;
		ip_context->ctxt.v4.dst_addr = ipv4_static->dst_addr;

		read += sizeof(ipv4_static_t);
		remain_data += sizeof(ipv4_static_t);
		remain_len -= sizeof(ipv4_static_t);
	}
	else
	{
		uint8_t protocol;

		ip_context->version = IPV6;
		ip_context->ctxt.v6.version = IPV6;
		ip_context->ctxt.v6.context_length = sizeof(ipv6_context_t);

		/* static 1 or static 2 variant? */
		if(GET_BIT_4(remain_data) == 0)
		{
			const ipv6_static1_t *const ipv6_static1 =
				(ipv6_static1_t *) remain_data;

			if(remain_len < sizeof(ipv6_static1_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the IPv6 static part");
				goto error;
			}

			ip_context->ctxt.v6.flow_label1 = 0;
			ip_context->ctxt.v6.flow_label2 = 0;
			ip_context->ctxt.v6.next_header = ipv6_static1->next_header;
			memcpy(ip_context->ctxt.v6.src_addr, ipv6_static1->src_addr,
			       sizeof(uint32_t) * 4 * 2);

			read += sizeof(ipv6_static1_t);
			remain_data += sizeof(ipv6_static1_t);
			remain_len -= sizeof(ipv6_static1_t);
		}
		else
		{
			const ipv6_static2_t *const ipv6_static2 =
				(ipv6_static2_t *) remain_data;

			if(remain_len < sizeof(ipv6_static2_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the IPv6 static part");
				goto error;
			}

			ip_context->ctxt.v6.flow_label1 = ipv6_static2->flow_label1;
			ip_context->ctxt.v6.flow_label2 = ipv6_static2->flow_label2;
			ip_context->ctxt.v6.next_header = ipv6_static2->next_header;
			memcpy(ip_context->ctxt.v6.src_addr, ipv6_static2->src_addr,
			       sizeof(uint32_t) * 4 * 2);

			read += sizeof(ipv6_static2_t);
			remain_data += sizeof(ipv6_static2_t);
			remain_len -= sizeof(ipv6_static2_t);
		}

		protocol = ip_context->ctxt.v6.next_header;
		ip_context->ctxt.v6.opts_nr = 0;
		while(rohc_is_ipv6_opt(protocol))
		{
			ipv6_option_context_t *opt;

			if(ip_context->ctxt.v6.opts_nr >= ROHC_TCP_MAX_IPv6_EXT_HDRS)
			{
				rohc_decomp_warn(context, "too many IPv6 extension headers");
				goto error;
			}
			opt = &(ip_context->ctxt.v6.opts[ip_context->ctxt.v6.opts_nr]);

			ret = tcp_parse_static_ipv6_option(context, ip_context, opt,
			                                   protocol, remain_data, remain_len);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: malformed "
				                 "IPv6 static option part");
				goto error;
			}
			rohc_decomp_debug(context, "IPv6 static option part is %d-byte length",
			                  ret);
			assert(remain_len >= ((size_t) ret));
			read += ret;
			remain_data += ret;
			remain_len -= ret;

			protocol = opt->generic.next_header;
			ip_context->ctxt.v6.opts_nr++;
		}
		rohc_decomp_debug(context, "IPv6 header is followed by %zu extension "
		                  "headers", ip_context->ctxt.v6.opts_nr);
	}
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IP static part", rohc_packet, read);

	return read;

error:
	return -1;
}


/**
 * @brief Decode the dynamic IP header of the rohc packet.
 *
 * @param context        The decompression context
 * @param ip_context     The specific IP decompression context
 * @param rohc_packet    The remaining part of the ROHC packet
 * @param rohc_length    The remaining length (in bytes) of the ROHC packet
 * @return               The length of dynamic IP header in case of success,
 *                       -1 if an error occurs
 */
static int tcp_parse_dynamic_ip(struct rohc_decomp_ctxt *const context,
                                ip_context_t *const ip_context,
                                const unsigned char *const rohc_packet,
                                const size_t rohc_length)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t size = 0;
	int ret;

	rohc_decomp_debug(context, "parse IP dynamic part");

	if(ip_context->ctxt.vx.version == IPV4)
	{
		const ipv4_dynamic1_t *const ipv4_dynamic1 =
			(ipv4_dynamic1_t *) remain_data;

		if(remain_len < sizeof(ipv4_dynamic1_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for "
			                 "IPv4 dynamic part");
			goto error;
		}

		ip_context->ctxt.v4.df = ipv4_dynamic1->df;
		ip_context->ctxt.v4.ip_id_behavior = ipv4_dynamic1->ip_id_behavior;
		rohc_decomp_debug(context, "ip_id_behavior = %d",
		                  ip_context->ctxt.v4.ip_id_behavior);
		ip_context->ctxt.v4.dscp = ipv4_dynamic1->dscp;
		ip_context->ctxt.v4.ip_ecn_flags = ipv4_dynamic1->ip_ecn_flags;
		ip_context->ctxt.v4.ttl_hopl = ipv4_dynamic1->ttl_hopl;
		rohc_decomp_debug(context, "DSCP = 0x%x, ip_ecn_flags = %d, "
		                  "ttl_hopl = 0x%x", ip_context->ctxt.v4.dscp,
		                  ip_context->ctxt.v4.ip_ecn_flags,
		                  ip_context->ctxt.v4.ttl_hopl);
		// cf RFC4996 page 60/61 ip_id_enc_dyn()
		if(ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
		{
			ip_context->ctxt.v4.ip_id = 0;
			rohc_decomp_debug(context, "new last IP-ID = 0x%04x",
			                  ip_context->ctxt.v4.ip_id);
			size += sizeof(ipv4_dynamic1_t);
			remain_data += sizeof(ipv4_dynamic1_t);
			remain_len -= sizeof(ipv4_dynamic1_t);
		}
		else
		{
			const ipv4_dynamic2_t *const ipv4_dynamic2 =
				(ipv4_dynamic2_t *) remain_data;
			uint16_t ip_id;

			if(remain_len < sizeof(ipv4_dynamic2_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "IPv4 dynamic part");
				goto error;
			}

			if(ipv4_dynamic2->ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
			{
				ip_id = swab16(ipv4_dynamic2->ip_id);
			}
			else
			{
				ip_id = ipv4_dynamic2->ip_id;
			}
			ip_context->ctxt.v4.ip_id = rohc_ntoh16(ip_id);
			rohc_decomp_debug(context, "new last IP-ID = 0x%04x",
			                  ip_context->ctxt.v4.ip_id);

			size += sizeof(ipv4_dynamic2_t);
			remain_data += sizeof(ipv4_dynamic2_t);
			remain_len -= sizeof(ipv4_dynamic2_t);
		}
		rohc_decomp_debug(context, "IP-ID = 0x%04x", ip_context->ctxt.v4.ip_id);
	}
	else
	{
		const ipv6_dynamic_t *const ipv6_dynamic =
			(ipv6_dynamic_t *) remain_data;
		uint8_t protocol;
		size_t opts_nr;

		if(remain_len < sizeof(ipv6_dynamic_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for "
			                 "IPv6 dynamic part");
			goto error;
		}

		ip_context->ctxt.v6.dscp = ipv6_dynamic->dscp;
		ip_context->ctxt.v6.ip_ecn_flags = ipv6_dynamic->ip_ecn_flags;
		ip_context->ctxt.v6.ttl_hopl = ipv6_dynamic->ttl_hopl;
		ip_context->ctxt.v6.ip_id_behavior = IP_ID_BEHAVIOR_RAND;

		size += sizeof(ipv6_dynamic_t);
		remain_data += sizeof(ipv6_dynamic_t);
		remain_len -= sizeof(ipv6_dynamic_t);

		protocol = ip_context->ctxt.v6.next_header;
		for(opts_nr = 0; opts_nr < ip_context->ctxt.v6.opts_nr; opts_nr++)
		{
			ipv6_option_context_t *const opt =
				&(ip_context->ctxt.v6.opts[ip_context->ctxt.v6.opts_nr]);

			ret = tcp_parse_dynamic_ipv6_option(context, opt, protocol,
			                                    remain_data, remain_len);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: malformed "
				                 "IPv6 dynamic option part");
				goto error;
			}
			rohc_decomp_debug(context, "IPv6 dynamic option part is %d-byte "
									"length", ret);
			assert(remain_len >= ((size_t) ret));
			size += ret;
			remain_data += ret;
			remain_len -= ret;

			protocol = opt->generic.next_header;
		}
	}

	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IP dynamic part", rohc_packet, size);

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
 * @param rohc_data                 The remaining part of the ROHC packet
 * @param rohc_data_len             The length of remaining part of the ROHC packet
 * @param is_innermost              True if the IP header is the innermost of the packet
 * @param ttl_irregular_chain_flag  True if one of the TTL value of header change
 * @param ip_inner_ecn              The ECN flags of inner IP header
 * @return                          The number of ROHC bytes parsed,
 *                                  -1 if packet is malformed
 */
static int tcp_parse_irregular_ip(struct rohc_decomp_ctxt *const context,
                                  ip_context_t *const ip_context,
                                  const uint8_t *rohc_data,
                                  const size_t rohc_data_len,
                                  const bool is_innermost,
                                  int ttl_irregular_chain_flag,
                                  int ip_inner_ecn)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_tcp_context *tcp_context;
	const uint8_t *remain_data;
	size_t remain_len;

	assert(context != NULL);
	assert(context->specific != NULL);
	rfc3095_ctxt = context->specific;
	assert(rfc3095_ctxt->specific != NULL);
	tcp_context = rfc3095_ctxt->specific;

	remain_data = rohc_data;
	remain_len = rohc_data_len;

	rohc_decomp_debug(context, "is_innermost = %d, ttl_irregular_chain_flag = %d, "
	                  "ip_inner_ecn = %d", is_innermost,
	                  ttl_irregular_chain_flag, ip_inner_ecn);

	if(ip_context->ctxt.vx.version == IPV4)
	{
		// ip_id =:= ip_id_enc_irreg( ip_id_behavior.UVALUE )
		if(ip_context->ctxt.v4.ip_id_behavior == IP_ID_BEHAVIOR_RAND)
		{
			uint16_t ip_id;

			if(remain_len < sizeof(uint16_t))
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
				             "packet too short for random IP-ID: only %zu bytes "
				             "available while at least %zu bytes required",
				             remain_len, sizeof(uint16_t));
				goto error;
			}
			memcpy(&ip_id, remain_data, sizeof(uint16_t));
			remain_data += sizeof(uint16_t);
			rohc_decomp_debug(context, "read ip_id = 0x%04x (ip_id_behavior = %d)",
			                  ip_id, ip_context->ctxt.v4.ip_id_behavior);
			ip_context->ctxt.v4.ip_id = rohc_ntoh16(ip_id);
			rohc_decomp_debug(context, "new IP-ID = 0x%04x",
			                  ip_context->ctxt.v4.ip_id);
		}
		if(is_innermost)
		{
			// ipv4_innermost_irregular
			// assert( ip_inner_ecn == base_header.ipv4->ip_ecn_flags );
			ip_context->ctxt.v4.ip_ecn_flags = ip_inner_ecn; // TODO: review ???
		}
		else
		{
			// ipv4_outer_with/without_ttl_irregular
			// dscp =:= static_or_irreg( ecn_used.UVALUE )
			// ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE )
			if(tcp_context->ecn_used != 0)
			{
				if(remain_len < 1)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
					             "packet too short for DSCP/ECN: only %zu bytes "
					             "available while at least 1 byte required", remain_len);
					goto error;
				}
				ip_context->ctxt.v4.dscp = remain_data[0] >> 2;
				ip_context->ctxt.v4.ip_ecn_flags = remain_data[0] & 0x03;
				remain_data++;
				rohc_decomp_debug(context, "read DSCP = 0x%x, ip_ecn_flags = %d",
				                  ip_context->ctxt.v4.dscp,
				                  ip_context->ctxt.v4.ip_ecn_flags);
			}
			if(ttl_irregular_chain_flag == 1)
			{
				// ipv4_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				if(remain_len < 1)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
					             "packet too short for TTL/HL: only %zu bytes "
					             "available while at least 1 byte required", remain_len);
					goto error;
				}
				ip_context->ctxt.v4.ttl_hopl = remain_data[0];
				remain_data++;
				rohc_decomp_debug(context, "read ttl_hopl = 0x%x",
				                  ip_context->ctxt.v4.ttl_hopl);
			}
			/* else: ipv4_outer_without_ttl_irregular */
		}
	}
	else
	{
		// IPv6
		if(!is_innermost)
		{
			// ipv6_outer_with/without_ttl_irregular
			// dscp =:= static_or_irreg( ecn_used.UVALUE )
			// ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE )
			if(tcp_context->ecn_used != 0)
			{
				if(remain_len < 1)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
					             "packet too short for DSCP/ECN: only %zu bytes "
					             "available while at least 1 byte required", remain_len);
					goto error;
				}
				ip_context->ctxt.v6.dscp = (remain_data[0] >> 2) & 0x3f;
				ip_context->ctxt.v6.ip_ecn_flags = (remain_data[0] & 0x03);
				remain_data++;
			}
			if(ttl_irregular_chain_flag == 1)
			{
				if(remain_len < 1)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
					             "packet too short for TTL/HL: only %zu bytes "
					             "available while at least 1 byte required", remain_len);
					goto error;
				}
				// ipv6_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				ip_context->ctxt.v6.ttl_hopl = remain_data[0];
				remain_data++;
				rohc_decomp_debug(context, "read ttl_hopl = 0x%x",
				                  ip_context->ctxt.v6.ttl_hopl);
			}
			/* else: ipv6_outer_without_ttl_irregular */
		}
		/* else: ipv6_innermost_irregular */
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IP irregular part", rohc_data, remain_data - rohc_data);
#endif

	return (remain_data - rohc_data);

error:
	return -1;
}


/**
 * @brief Decode the TCP static part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param rohc_packet  The remaining part of the ROHC packet
 * @param rohc_length  The remaining length (in bytes) of the ROHC packet
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int tcp_parse_static_tcp(struct rohc_decomp_ctxt *const context,
                                const unsigned char *const rohc_packet,
                                const size_t rohc_length)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_tcp_context *tcp_context;
	const tcp_static_t *tcp_static;

	assert(context != NULL);
	assert(context->specific != NULL);
	rfc3095_ctxt = context->specific;
	assert(rfc3095_ctxt->specific != NULL);
	tcp_context = rfc3095_ctxt->specific;
	assert(rohc_packet != NULL);

	rohc_decomp_debug(context, "parse TCP static part");

	/* check the minimal length to decode the TCP static part */
	if(rohc_length < sizeof(tcp_static_t))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 rohc_length);
		goto error;
	}
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "TCP static part", rohc_packet, sizeof(tcp_static_t));
	tcp_static = (tcp_static_t *) rohc_packet;

	/* TCP source port */
	tcp_context->tcp_src_port = tcp_static->src_port;
	rohc_decomp_debug(context, "TCP source port = %u",
	                  rohc_ntoh16(tcp_context->tcp_src_port));

	/* TCP destination port */
	tcp_context->tcp_dst_port = tcp_static->dst_port;
	rohc_decomp_debug(context, "TCP dest port = %u",
	                  rohc_ntoh16(tcp_context->tcp_dst_port));

	/* number of bytes read from the packet */
	rohc_decomp_debug(context, "TCP static part is %zu-byte long",
	                  sizeof(tcp_static_t));
	return sizeof(tcp_static_t);

error:
	return -1;
}


/**
 * @brief Decode the TCP dynamic part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param rohc_packet  The remaining part of the ROHC packet
 * @param rohc_length  The remaining length (in bytes) of the ROHC packet
 * @param tcp          The decoded TCP header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int tcp_parse_dynamic_tcp(struct rohc_decomp_ctxt *const context,
                                 const unsigned char *const rohc_packet,
                                 const size_t rohc_length)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_tcp_context *tcp_context;
	const tcp_dynamic_t *tcp_dynamic;
	const uint8_t *remain_data;
	size_t remain_len;

	assert(context != NULL);
	assert(context->specific != NULL);
	rfc3095_ctxt = context->specific;
	assert(rfc3095_ctxt->specific != NULL);
	tcp_context = rfc3095_ctxt->specific;
	assert(rohc_packet != NULL);

	remain_data = rohc_packet;
	remain_len = rohc_length;

	rohc_decomp_debug(context, "parse TCP dynamic part");

	/* check the minimal length to decode the TCP dynamic part */
	if(remain_len < sizeof(tcp_dynamic_t))
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu bytes "
		                 "available while at least %zu bytes required for "
		                 "mandatory fields of the TCP dynamic part",
		                 remain_len, sizeof(tcp_dynamic_t));
		goto error;
	}
	tcp_dynamic = (tcp_dynamic_t *) remain_data;
	remain_data += sizeof(tcp_dynamic_t);
	remain_len -= sizeof(tcp_dynamic_t);

	rohc_decomp_debug(context, "TCP res_flags = %d, ecn_flags = %d, "
	                  "rsf_flags = %d, URG = %d, ACK = %d, PSH = %d",
	                  tcp_dynamic->tcp_res_flags, tcp_dynamic->tcp_ecn_flags,
	                  tcp_dynamic->rsf_flags, tcp_dynamic->urg_flag,
	                  tcp_dynamic->ack_flag, tcp_dynamic->psh_flag);

	/* retrieve the TCP sequence number from the ROHC packet */
	tcp_context->ecn_used = tcp_dynamic->ecn_used;
	tcp_context->res_flags = tcp_dynamic->tcp_res_flags;
	tcp_context->ecn_flags = tcp_dynamic->tcp_ecn_flags;
	tcp_context->urg_flag = tcp_dynamic->urg_flag;
	tcp_context->ack_flag = tcp_dynamic->ack_flag;
	tcp_context->psh_flag = tcp_dynamic->psh_flag;
	tcp_context->rsf_flags = tcp_dynamic->rsf_flags;
	tcp_context->msn = rohc_ntoh16(tcp_dynamic->msn);
	rohc_decomp_debug(context, "MSN = 0x%04x", tcp_context->msn);
	tcp_context->seq_num = tcp_dynamic->seq_num;

	/* optional ACK number */
	if(tcp_dynamic->ack_zero == 1)
	{
		tcp_context->ack_num = 0;
	}
	else
	{
		if(remain_len < sizeof(uint32_t))
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu "
			                 "bytes available while at least %zu bytes required "
			                 "for the ACK number", remain_len, sizeof(uint32_t));
			goto error;
		}
		memcpy(&tcp_context->ack_num, remain_data, sizeof(uint32_t));
		remain_data += sizeof(uint32_t);
		remain_len -= sizeof(uint32_t);

		if(tcp_context->ack_flag == 0)
		{
			rohc_decomp_debug(context, "ACK flag not set, but ACK number was "
			                  "transmitted anyway");
		}
	}
	rohc_decomp_debug(context, "seq_number = 0x%x, ack_number = 0x%x",
	                  rohc_ntoh32(tcp_context->seq_num),
	                  rohc_ntoh32(tcp_context->ack_num));

	/* window */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu bytes "
		                 "available while at least %zu bytes required for the "
		                 "window", remain_len, sizeof(uint16_t));
		goto error;
	}
	memcpy(&tcp_context->window, remain_data, sizeof(uint16_t));
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP window = 0x%04x",
	                  rohc_ntoh16(tcp_context->window));

	/* checksum */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu bytes "
		                 "available while at least %zu bytes required for the "
		                 "checksum", remain_len, sizeof(uint16_t));
		goto error;
	}
	memcpy(&tcp_context->checksum, remain_data, sizeof(uint16_t));
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP checksum = 0x%04x",
	                  rohc_ntoh16(tcp_context->checksum));

	/* URG pointer */
	if(tcp_dynamic->urp_zero == 1)
	{
		tcp_context->urg_ptr = 0;
	}
	else
	{
		if(remain_len < sizeof(uint16_t))
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu "
			                 "bytes available while at least %zu bytes required "
			                 "for the URG pointer", remain_len, sizeof(uint16_t));
			goto error;
		}
		memcpy(&tcp_context->urg_ptr, remain_data, sizeof(uint16_t));
		remain_data += sizeof(uint16_t);
		remain_len -= sizeof(uint16_t);
	}
	rohc_decomp_debug(context, "TCP urg_ptr = 0x%04x",
	                  rohc_ntoh16(tcp_context->urg_ptr));

	/* ACK stride */
	if(tcp_dynamic->ack_stride_flag == 0)
	{
		tcp_context->ack_stride = 0;
	}
	else
	{
		if(remain_len < sizeof(uint16_t))
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu "
			                 "bytes available while at least %zu bytes required "
			                 "for the ACK stride", remain_len, sizeof(uint16_t));
			goto error;
		}
		memcpy(&tcp_context->ack_stride, remain_data, sizeof(uint16_t));
		tcp_context->ack_stride = rohc_ntoh16(tcp_context->ack_stride);
		remain_data += sizeof(uint16_t);
		remain_len -= sizeof(uint16_t);
	}
	if(tcp_context->ack_stride != 0)
	{
		// Calculate the Ack Number residue
		tcp_context->ack_num_residue =
			rohc_ntoh32(tcp_context->ack_num) % tcp_context->ack_stride;
	}
	rohc_decomp_debug(context, "TCP ack_stride = 0x%04x, ack_number_residue = "
	                  "0x%04x", tcp_context->ack_stride,
	                  tcp_context->ack_num_residue);

	/* we need at least one byte to check whether TCP options are present or
	 * not */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu bytes "
		                 "available while at least 1 byte required for the "
		                 "first byte of TCP options", remain_len);
		goto error;
	}

	/* If TCP option list compression present */
	if((remain_data[0] & 0x0f) != 0)
	{
		const uint8_t *tcp_opts_indexes;
		uint8_t reserved;
		uint8_t PS;
		uint8_t present;
		uint8_t opt_idx;
		uint8_t m;
		uint8_t i;
		uint8_t *tcp_options = tcp_context->options;
		size_t opt_padding_len;
		size_t opts_full_len;
		size_t indexes_len;
		uint8_t opt_type;
		uint8_t opt_len;

		/* read number of XI item(s) in the compressed list */
		reserved = remain_data[0] & 0xe0;
		m = remain_data[0] & 0x0F;
		PS = remain_data[0] & 0x10;
		if(reserved != 0)
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: malformed "
			                 "compressed list of TCP options: reserved bits "
			                 "must be zero, but first byte is 0x%02x",
			                 remain_data[0]);
			goto error;
		}
		remain_data++;
		remain_len--;
		if(m >= MAX_TCP_OPTION_INDEX)
		{
			rohc_decomp_warn(context, "TCP dynamic part: compressed list of TCP "
			                 "options: too many options");
			goto error;
		}

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
		                  "transmitted on %zu bytes", m, (PS != 0 ? 8 : 4),
		                  indexes_len);

		/* enough remaining data for all indexes? */
		if(remain_len < indexes_len)
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu "
			                 "bytes available while at least %zu bytes required "
			                 "for the list indexes", remain_len, indexes_len);
			goto error;
		}
		tcp_opts_indexes = remain_data;
		remain_data += indexes_len;
		remain_len -= indexes_len;

		/* for all item(s) in the list */
		for(i = 0, opts_full_len = 0; i < m; ++i)
		{
			/* if PS=1 indicating 8-bit XI field */
			if(PS != 0)
			{
				present = tcp_opts_indexes[0] & 0x80;
				opt_idx = tcp_opts_indexes[0] & 0x0F;
				tcp_opts_indexes++;
			}
			else
			{
				/* if odd position */
				if(i & 1)
				{
					present = tcp_opts_indexes[0] & 0x08;
					opt_idx = tcp_opts_indexes[0] & 0x07;
					tcp_opts_indexes++;
				}
				else
				{
					present = tcp_opts_indexes[0] & 0x80;
					opt_idx = (tcp_opts_indexes[0] & 0x70) >> 4;
				}
			}
			rohc_decomp_debug(context, "  TCP options list: XI #%u:", i);
			rohc_decomp_debug(context, "    item for index %u is %s", opt_idx,
			                  (present ? "present" : "absent"));
			// item must present in dynamic part
			if(present == 0)
			{
				rohc_decomp_debug(context, "list item #%u not present: not "
				                  "allowed in dynamic part, packet is malformed", i);
				goto error;
			}
			tcp_context->is_tcp_opts_list_item_present[i] = true;

			rohc_decomp_debug(context, "    index %u is a known index", opt_idx);

			/* determine option type */ /* TODO: dedicated function */
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:
				{
					rohc_decomp_debug(context, "    TCP option NOP");
					opt_type = TCP_OPT_NOP;
					opt_len = 1;
					break;
				}
				case TCP_INDEX_EOL:
				{
					rohc_decomp_debug(context, "    TCP option EOL");
					opt_type = TCP_OPT_EOL;
					// TODO: check length
					opt_len = remain_data[0] + 1;
					if(remain_len < 1)
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least %zu bytes "
						                 "required for next option", remain_len,
						                 sizeof(uint8_t));
						goto error;
					}
					memset(tcp_options + opts_full_len + 1, TCP_OPT_EOL,
					       remain_data[0]);
					remain_data++;
					remain_len--;
					break;
				}
				case TCP_INDEX_MAXSEG:
				{
					opt_type = TCP_OPT_MAXSEG;
					opt_len = TCP_OLEN_MAXSEG;
					if(remain_len < sizeof(uint16_t))
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least %zu bytes "
						                 "required for next option", remain_len,
						                 sizeof(uint16_t));
						goto error;
					}
					memcpy(&tcp_context->tcp_option_maxseg, remain_data,
					       sizeof(uint16_t));
					memcpy(tcp_options + opts_full_len + 2, remain_data,
					       sizeof(uint16_t));
					remain_data += sizeof(uint16_t);
					remain_len -= sizeof(uint16_t);
					rohc_decomp_debug(context, "    TCP option MAXSEG = %u (0x%x)",
					                  rohc_ntoh16(tcp_context->tcp_option_maxseg),
					                  rohc_ntoh16(tcp_context->tcp_option_maxseg));
					break;
				}
				case TCP_INDEX_WINDOW:
				{
					opt_type = TCP_OPT_WINDOW;
					opt_len = TCP_OLEN_WINDOW;
					if(remain_len < sizeof(uint8_t))
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least %zu bytes "
						                 "required for next option", remain_len,
						                 sizeof(uint8_t));
						goto error;
					}
					tcp_context->tcp_option_window = remain_data[0];
					tcp_options[opts_full_len + 2] = remain_data[0];
					remain_data++;
					remain_len--;
					rohc_decomp_debug(context, "    TCP option WINDOW = %d",
					                  tcp_context->tcp_option_window);
					break;
				}
				case TCP_INDEX_TIMESTAMP:
				{
					const struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) remain_data;

					rohc_decomp_debug(context, "    TCP option TIMESTAMP");
					opt_type = TCP_OPT_TIMESTAMP;
					opt_len = TCP_OLEN_TIMESTAMP;

					if(remain_len < (sizeof(uint32_t) * 2))
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least %zu bytes "
						                 "required for next option", remain_len,
						                 sizeof(uint32_t) * 2);
						goto error;
					}
					tcp_context->tcp_option_timestamp.ts = opt_ts->ts;
					tcp_context->tcp_option_timestamp.ts_reply = opt_ts->ts_reply;
					rohc_lsb_set_ref(tcp_context->opt_ts_req_lsb_ctxt,
					                 rohc_ntoh32(opt_ts->ts), false);
					rohc_lsb_set_ref(tcp_context->opt_ts_reply_lsb_ctxt,
					                 rohc_ntoh32(opt_ts->ts_reply), false);
					memcpy(tcp_options + opts_full_len + 2, remain_data, sizeof(uint32_t) * 2);
					remain_data += sizeof(uint32_t) * 2;
					remain_len -= sizeof(uint32_t) * 2;
					break;
				}
				case TCP_INDEX_SACK_PERMITTED:
				{
					rohc_decomp_debug(context, "    TCP option SACK permitted");
					opt_type = TCP_OPT_SACK_PERMITTED;
					opt_len = TCP_OLEN_SACK_PERMITTED;
					break;
				}
				case TCP_INDEX_SACK:
				{
					uint8_t *uncomp_sack_opt = tcp_options + opts_full_len;
					int ret;

					ret = d_tcp_opt_sack(context, remain_data, remain_len,
					                     &uncomp_sack_opt,
					                     rohc_ntoh32(tcp_context->ack_num));
					if(ret < 0)
					{
						rohc_decomp_warn(context, "failed to decompress TCP SACK "
						                 "option");
						goto error;
					}
					remain_data += ret;
					remain_len -= ret;

					opt_type = TCP_OPT_SACK;
					opt_len = uncomp_sack_opt - (tcp_options + opts_full_len);

					tcp_context->tcp_option_sack_length = opt_len - 2;
					rohc_decomp_debug(context, "    TCP option SACK Length = 2 + %u",
					                  tcp_context->tcp_option_sack_length);
					if(tcp_context->tcp_option_sack_length > (8 * 4))
					{
						rohc_decomp_warn(context, "TCP dynamic part: unexpected "
						                 "large %u-byte SACK option",
						                 tcp_context->tcp_option_sack_length);
						goto error;
					}
					memcpy(tcp_context->tcp_option_sackblocks, uncomp_sack_opt,
					       tcp_context->tcp_option_sack_length);
					break;
				}
				default: /* generic options */
				{
					uint8_t *save_opt;

					/* option type */
					if(remain_len < 1)
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least 1 byte "
						                 "required for next option", remain_len);
						goto error;
					}
					opt_type = remain_data[0];
					remain_data++;
					remain_len--;

					/* option length */
					if(remain_len < 1)
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least 1 byte "
						                 "required for next option", remain_len);
						goto error;
					}
					opt_len = remain_data[0] & 0x7f;
					remain_data++;
					remain_len--;
					if(opt_len < 2)
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: option "
						                 "length should be at least 2 bytes, but "
						                 "is only %u byte(s)", opt_len);
						goto error;
					}

					/* was index already used? */
					if(tcp_context->tcp_options_list[opt_idx] == 0xff)
					{
						/* index was never used before */
						tcp_context->tcp_options_offset[opt_idx] =
							tcp_context->tcp_options_free_offset;
						save_opt = tcp_context->tcp_options_values +
						           tcp_context->tcp_options_free_offset;
						/* save length (without option_static) */
						save_opt[0] = opt_len - 2;
						rohc_decomp_debug(context, "    %d-byte TCP option of type %d",
						                  save_opt[0], opt_type);
						/* enough data for last bytes of option? */
						if(remain_len < save_opt[0])
						{
							rohc_decomp_warn(context, "malformed TCP dynamic part: "
							                 "malformed TCP option items: only %zu "
							                 "bytes available while at least %u "
							                 "bytes required for next option",
							                 remain_len, save_opt[0]);
							goto error;
						}
						/* save value */
						memcpy(save_opt + 1, remain_data, save_opt[0]);
						memcpy(tcp_options + opts_full_len + 2, remain_data, save_opt[0]);
						remain_data += save_opt[0];
						remain_len -= save_opt[0];
						/* update first free offset */
						tcp_context->tcp_options_free_offset += 1 + save_opt[0];
						if(tcp_context->tcp_options_free_offset >= MAX_TCP_OPT_SIZE)
						{
							rohc_decomp_warn(context, "TCP options too large: "
							                 "%u bytes while only %u are accepted",
							                 tcp_context->tcp_options_free_offset,
							                 MAX_TCP_OPT_SIZE);
							goto error;
						}
					}
					else /* index already used */
					{
						/* verify the value with the recorded one */
						rohc_decomp_debug(context, "tcp_options_list[%u] = %d <=> %d",
						                  opt_idx, tcp_context->tcp_options_list[opt_idx],
						                  opt_type);
						if(tcp_context->tcp_options_list[opt_idx] != opt_type)
						{
							rohc_decomp_warn(context, "unexpected TCP option at "
							                 "index %u: 0x%02x received while "
							                 "0x%02x expected", opt_idx, opt_type,
							                 tcp_context->tcp_options_list[opt_idx]);
							goto error;
						}
						save_opt = tcp_context->tcp_options_values +
						           tcp_context->tcp_options_offset[opt_idx];
						if((opt_len - 2) != save_opt[0])
						{
							rohc_decomp_warn(context, "malformed TCP dynamic part: "
							                 "unexpected TCP option with index %u: "
							                 "option length in packet (%u) does not "
							                 "match option length in context (%u)",
							                 opt_idx, opt_len, save_opt[0] + 2);
							goto error;
						}
						if(memcmp(save_opt + 1, remain_data, save_opt[0]) != 0)
						{
							rohc_decomp_warn(context, "malformed TCP dynamic part: "
							                 "unexpected TCP option with index %u: "
							                 "option data in packet does not match "
							                 "option option data in context",
							                 opt_idx);
							goto error;
						}
						memcpy(tcp_options + opts_full_len + 2, remain_data, save_opt[0]);
						remain_data += save_opt[0];
						remain_len -= save_opt[0];
					}
					break;
				}
			}
			rohc_decomp_debug(context, "    TCP option type 0x%02x (%u)",
			                  opt_type, opt_type);
			tcp_options[opts_full_len] = opt_type;
			if(opt_type == TCP_OPT_EOL)
			{
				assert(opt_len >= 1);
				rohc_decomp_debug(context, "    TCP option is %u-byte long (type "
				                  "and padding fields included)", opt_len);
			}
			else if(opt_type == TCP_OPT_NOP)
			{
				assert(opt_len == 1);
				rohc_decomp_debug(context, "    TCP option is 1-byte long");
			}
			else
			{
				assert(opt_len >= 2);
				rohc_decomp_debug(context, "    TCP option is %u-byte long (type "
				                  "and length fields included)", opt_len);
				tcp_options[opts_full_len + 1] = opt_len;
			}
			opts_full_len += opt_len;

			/* save TCP option for this index */
			tcp_context->tcp_opts_list_struct[i] = opt_type;
			tcp_context->tcp_options_list[opt_idx] = opt_type;
			tcp_context->tcp_opts_list_item_uncomp_length[i] = opt_len;
		}
		memset(tcp_context->tcp_opts_list_struct + m, 0xff,
		       ROHC_TCP_OPTS_MAX - m);

		rohc_decomp_debug(context, "  %zu bytes of TCP options appended to the "
		                  "TCP base header", opts_full_len);

		/* add padding after TCP options (they must be aligned on 32-bit words) */
		opt_padding_len = sizeof(uint32_t) - (opts_full_len % sizeof(uint32_t));
		opt_padding_len %= sizeof(uint32_t);
		for(i = 0; i < opt_padding_len; i++)
		{
			rohc_decomp_warn(context, "  add missing TCP EOL option for padding");
			tcp_options[opts_full_len + i] = TCP_OPT_EOL;
		}
		opts_full_len += opt_padding_len;
		assert((opts_full_len % sizeof(uint32_t)) == 0);

		/* print TCP options */
		rohc_dump_buf(context->decompressor->trace_callback,
		              context->decompressor->trace_callback_priv,
		              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
		              "decompressed TCP options", tcp_options, opts_full_len);

		/* update context */
		tcp_context->options_len = opts_full_len;
	}
	else
	{
		/* update data offset */
		tcp_context->options_len = 0;
		rohc_decomp_debug(context, "TCP no options!");
		remain_data++;
		remain_len--;
		memset(tcp_context->tcp_opts_list_struct, 0xff, ROHC_TCP_OPTS_MAX);
	}

	assert(remain_len <= rohc_length);
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG, "TCP dynamic part",
	              (unsigned char *) tcp_dynamic, rohc_length - remain_len);

	return (rohc_length - remain_len);

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
 * @param rohc_data          The remain data of the rohc packet
 * @param rohc_data_len      The length of the remain data of the rohc packet
 * @return                   The number of ROHC bytes parsed,
 *                           -1 if packet is malformed
 */
static int tcp_parse_irregular_tcp(struct rohc_decomp_ctxt *const context,
                                   ip_context_t *const ip_inner_context,
                                   const uint8_t *const rohc_data,
                                   const size_t rohc_data_len)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt = context->specific;
	struct d_tcp_context *tcp_context = rfc3095_ctxt->specific;
	const uint8_t *remain_data;
	size_t remain_len;
	uint8_t *tcp_options = tcp_context->options;
	size_t tcp_opts_len;
	size_t i;
	int ret;

	rohc_decomp_debug(context, "decode TCP irregular chain");

	remain_data = rohc_data;
	remain_len = rohc_data_len;

	// ip_ecn_flags = := tcp_irreg_ip_ecn(ip_inner_ecn)
	// tcp_res_flags =:= static_or_irreg(ecn_used.CVALUE,4)
	// tcp_ecn_flags =:= static_or_irreg(ecn_used.CVALUE,2)
	if(tcp_context->ecn_used != 0)
	{
		// See RFC4996 page 71
		if(remain_len < 1)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for ECN: only %zu bytes available "
			             "while at least 1 byte required", remain_len);
			goto error;
		}
		if(ip_inner_context->ctxt.vx.version == IPV4)
		{
			ip_inner_context->ctxt.v4.ip_ecn_flags = (remain_data[0] >> 6);
			rohc_decomp_debug(context, "read ip_ecn_flags = %d",
			                  ip_inner_context->ctxt.v4.ip_ecn_flags);
		}
		else
		{
			ip_inner_context->ctxt.v6.ip_ecn_flags = (remain_data[0] >> 6);
			rohc_decomp_debug(context, "read ip_ecn_flags = %d",
			                  ip_inner_context->ctxt.v6.ip_ecn_flags);
		}
		tcp_context->ecn_flags = (remain_data[0] >> 4) & 0x03;
		tcp_context->res_flags = remain_data[0] & 0x0f;
		remain_data++;
		remain_len--;
		rohc_decomp_debug(context, "read TCP ecn_flags = %d, res_flags = %d",
		                  tcp_context->ecn_flags, tcp_context->res_flags);
	}
	else
	{
		// See RFC4996 page 71
		if(ip_inner_context->ctxt.vx.version == IPV4)
		{
			ip_inner_context->ctxt.v4.ip_ecn_flags = 0;
		}
		else
		{
			ip_inner_context->ctxt.v6.ip_ecn_flags = 0;
		}
		tcp_context->ecn_flags = 0;
		tcp_context->res_flags = 0;
		rohc_decomp_debug(context, "ip_ecn_flag = 0, tcp_ecn_flag = 0, and "
		                  "tcp_res_flag = 0");
	}

	// checksum =:= irregular(16)
	if(remain_len < sizeof(uint16_t))
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
		             "packet too short for TCP checksum: only %zu bytes available "
		             "while at least %zu bytes required", remain_len,
		             sizeof(uint16_t));
		goto error;
	}
	memcpy(&tcp_context->checksum, remain_data, sizeof(uint16_t));
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "read TCP checksum = 0x%04x",
	                  rohc_ntoh16(tcp_context->checksum));

	/* complete TCP options with the irregular part */
	tcp_opts_len = 0;
	for(i = 0;
	    i < ROHC_TCP_OPTS_MAX && tcp_context->tcp_opts_list_struct[i] != 0xff;
	    i++)
	{
		if(tcp_context->is_tcp_opts_list_item_present[i])
		{
			rohc_decomp_debug(context, "TCP irregular part: option %u is not present",
			                  tcp_context->tcp_opts_list_struct[i]);
			tcp_options += tcp_context->tcp_opts_list_item_uncomp_length[i];
			tcp_opts_len += tcp_context->tcp_opts_list_item_uncomp_length[i];
		}
		else
		{
			rohc_decomp_debug(context, "TCP irregular part: option %u is present",
			                  tcp_context->tcp_opts_list_struct[i]);
			tcp_options[0] = tcp_context->tcp_opts_list_struct[i];
			tcp_options++;
			tcp_opts_len++;

			switch(tcp_context->tcp_opts_list_struct[i])
			{
				case TCP_OPT_NOP:
				case TCP_OPT_EOL:
					break;
				case TCP_OPT_MAXSEG:
					// Length
					tcp_options[0] = TCP_OLEN_MAXSEG;
					tcp_options++;
					tcp_opts_len++;
					// Max segment size value
					memcpy(tcp_options, &tcp_context->tcp_option_maxseg, 2);
					tcp_options += TCP_OLEN_MAXSEG - 2;
					tcp_opts_len += TCP_OLEN_MAXSEG - 2;
					break;
				case TCP_OPT_WINDOW:
					// Length
					tcp_options[0] = TCP_OLEN_WINDOW;
					tcp_options++;
					tcp_opts_len++;
					// Window scale value
					tcp_options[0] = tcp_context->tcp_option_window;
					tcp_options++;
					tcp_opts_len++;
					break;
				case TCP_OPT_TIMESTAMP:
				{
					struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) (tcp_options + 1);

					// Length
					tcp_options[0] = TCP_OLEN_TIMESTAMP;
					tcp_options++;
					tcp_opts_len++;

					/* decode TS echo request with method ts_lsb() */
					ret = d_ts_lsb(context, tcp_context->opt_ts_req_lsb_ctxt,
					               remain_data, remain_len, (uint32_t *) &opt_ts->ts);
					if(ret < 0)
					{
						rohc_decomp_warn(context, "TCP irregular part: failed to "
						                 "decompress TCP option Timestamp echo "
						                 "request");
						goto error;
					}
					remain_data += ret;
					remain_len -= ret;
					rohc_lsb_set_ref(tcp_context->opt_ts_req_lsb_ctxt,
					                 rohc_ntoh32(opt_ts->ts), false);

					/* decode TS echo reply with method ts_lsb() */
					ret = d_ts_lsb(context, tcp_context->opt_ts_reply_lsb_ctxt,
					               remain_data, remain_len,
					               (uint32_t *) &opt_ts->ts_reply);
					if(ret < 0)
					{
						rohc_decomp_warn(context, "TCP irregular part: failed to "
						                 "decompress TCP option Timestamp echo "
						                 "reply");
						goto error;
					}
					remain_data += ret;
					remain_len -= ret;
					rohc_lsb_set_ref(tcp_context->opt_ts_reply_lsb_ctxt,
					                 rohc_ntoh32(opt_ts->ts_reply), false);

					tcp_context->tcp_option_timestamp.ts = opt_ts->ts;
					tcp_context->tcp_option_timestamp.ts_reply = opt_ts->ts_reply;

					tcp_options += TCP_OLEN_TIMESTAMP - 2;
					tcp_opts_len += TCP_OLEN_TIMESTAMP - 2;
					break;
				}
				case TCP_OPT_SACK_PERMITTED:
					// Length
					tcp_options[0] = TCP_OLEN_SACK_PERMITTED;
					tcp_options++;
					tcp_opts_len++;
					break;
				case TCP_OPT_SACK:
				{
					tcp_options--; /* remove option type */
					tcp_opts_len--;
					ret = d_tcp_opt_sack(context, remain_data, remain_len,
					                     &tcp_options, rohc_ntoh32(tcp_context->ack_num));
					if(ret < 0)
					{
						rohc_decomp_warn(context, "failed to decompress TCP SACK "
						                 "option");
						goto error;
					}
					remain_data += ret;
					remain_len -= ret;
					tcp_opts_len += ret;
					break;
				}
				default:  // Generic options
					rohc_decomp_debug(context, "TCP option %u not handled",
					                  tcp_context->tcp_opts_list_struct[i]);
					break;
			}
		}
	}
	assert(i <= ROHC_TCP_OPTS_MAX);

	/* update TCP data offset */
	tcp_context->options_len = tcp_opts_len;

	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "TCP irregular part", rohc_data, rohc_data_len - remain_len);

	return (rohc_data_len - remain_len);

error:
	return -1;
}


/**
 * @brief Decompress the LSBs bits of TimeStamp TCP option
 *
 * See RFC4996 page 65
 *
 * @param context    The decompression context
 * @param lsb        The LSB decoding context
 * @param data       The data to decode
 * @param data_len   The length of the data to decode
 * @param timestamp  Pointer to the uncompressed value
 * @return           The number of data bytes parsed,
 *                   -1 if data is malformed
 */
static int d_ts_lsb(const struct rohc_decomp_ctxt *const context,
                    const struct rohc_lsb_decode *const lsb,
                    const uint8_t *const data,
                    const size_t data_len,
                    uint32_t *const timestamp)
{
	uint32_t ts_bits;
	size_t ts_bits_nr;
	rohc_lsb_shift_t p;
	bool decode_ok;
	uint32_t decoded;
	uint32_t decoded_nbo;
	const uint8_t *remain_data;
	size_t remain_len;

	assert(context != NULL);
	assert(lsb != NULL);
	assert(data != NULL);
	assert(timestamp != NULL);

	remain_data = data;
	remain_len = data_len;

	if(remain_len < 1)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
		             "packet too short for TS LSB: only %zu bytes available "
		             "while at least 1 byte required", remain_len);
		goto error;
	}

	if((remain_data[0] & 0x80) == 0)
	{
		/* discriminator '0' */
		ts_bits = remain_data[0];
		ts_bits_nr = 7;
		p = -1;
		remain_len--;
	}
	else if((remain_data[0] & 0x40) == 0)
	{
		/* discriminator '10' */
		if(remain_len < 2)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for TS LSB: only %zu bytes available "
			             "while at least 2 bytes required", remain_len);
			goto error;
		}
		ts_bits = (remain_data[0] & 0x3f) << 8;
		ts_bits |= remain_data[1];
		ts_bits_nr = 14;
		p = -1;
		remain_len -= 2;
	}
	else if((remain_data[0] & 0x20) == 0)
	{
		/* discriminator '110' */
		if(remain_len < 3)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for TS LSB: only %zu bytes available "
			             "while at least 3 bytes required", remain_len);
			goto error;
		}
		ts_bits = (remain_data[0] & 0x1f) << 16;
		ts_bits |= remain_data[1] << 8;
		ts_bits |= remain_data[2];
		ts_bits_nr = 21;
		p = 0x40000;
		remain_len -= 3;
	}
	else
	{
		/* discriminator '111' */
		if(remain_len < 4)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for TS LSB: only %zu bytes available "
			             "while at least 4 bytes required", remain_len);
			goto error;
		}
		ts_bits = (remain_data[0] & 0x1f) << 24;
		ts_bits |= remain_data[1] << 16;
		ts_bits |= remain_data[2] << 8;
		ts_bits |= remain_data[3];
		ts_bits_nr = 29;
		p = 0x40000;
		remain_len -= 4;
	}

	decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, ts_bits, ts_bits_nr, p,
	                            &decoded);
	if(!decode_ok)
	{
		rohc_decomp_warn(context, "failed to decode %zu timestamp bits 0x%x "
		                 "with p = %u", ts_bits_nr, ts_bits, p);
		goto error;
	}
	rohc_decomp_debug(context, "decoded timestamp = 0x%08x (%zu bits 0x%x "
	                  "with ref 0x%08x and p = %d)", decoded, ts_bits_nr,
	                  ts_bits, rohc_lsb_get_ref(lsb, ROHC_LSB_REF_0), p);

	decoded_nbo = rohc_hton32(decoded);
	memcpy(timestamp, &decoded_nbo, sizeof(uint32_t));

	return (data_len - remain_len);

error:
	return -1;
}


/**
 * @brief Calculate the size of TimeStamp compressed TCP option
 *
 * @param context      The decompression context
 * @param rohc_data    The remaining ROHC data
 * @param rohc_length  The length (in bytes) of the remaining ROHC data
 * @return             The length (in bytes) of the compressed TCP option,
 *                     -1 in case of problem
 */
static int d_size_ts_lsb(const struct rohc_decomp_ctxt *const context,
                         const uint8_t *const rohc_data,
                         const size_t rohc_length)
{
	size_t lsb_len;

	/* enough data for the discriminator byte? */
	if(rohc_length < 1)
	{
		rohc_decomp_warn(context, "remaining ROHC data too small (%zu bytes) "
		                 "for the LSB-encoded TCP TimeStamp value", rohc_length);
		goto error;
	}

	if(rohc_data[0] & 0x80)
	{
		if(rohc_data[0] & 0x40)
		{
			if(rohc_data[0] & 0x20)
			{
				// Discriminator '111'
				lsb_len = 4;
			}
			else
			{
				// Discriminator '110'
				lsb_len = 3;
			}
		}
		else
		{
			// Discriminator '10'
			lsb_len = 2;
		}
	}
	else
	{
		// Discriminator '0'
		lsb_len = 1;
	}

	/* enough data for the full LSB field? */
	if(rohc_length < lsb_len)
	{
		rohc_decomp_warn(context, "remaining ROHC data too small (%zu bytes) "
		                 "for the %zu-byte LSB-encoded TCP TimeStamp value",
		                 rohc_length, lsb_len);
		goto error;
	}

	return lsb_len;

error:
	return -1;
}


/**
 * @brief Uncompress the SACK field value.
 *
 * See RFC6846 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context    The decompression context
 * @param data       The data to decode
 * @param data_len   The length of the data to decode
 * @param base       The base value
 * @param field      Pointer to the uncompressed value
 * @return           The number of data bytes parsed,
 *                   -1 if data is malformed
 */
static int d_sack_pure_lsb(const struct rohc_decomp_ctxt *const context,
									const uint8_t *const data,
                           const size_t data_len,
                           uint32_t base,
                           uint32_t *field)
{
	const uint8_t *remain_data = data;
	size_t remain_len = data_len;
	uint32_t sack_field;

	if(remain_len < 2)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
		             "packet too short for the discriminator of the TCP pure "
		             "field: only %zu bytes available while at least 2 bytes "
		             "required", remain_len);
		goto error;
	}

	if((remain_data[0] & 0x80) == 0)
	{
		/* discriminator '0' */
		sack_field = *(remain_data++) << 8;
		sack_field |= *(remain_data++);
		remain_len -= 2;
	}
	else if((remain_data[0] & 0x40) == 0)
	{
		/* discriminator '10' */
		if(remain_len < 3)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for the discriminator of the TCP pure "
			             "field: only %zu bytes available while at least 3 bytes "
			             "required", remain_len);
			goto error;
		}
		sack_field = *(remain_data++) & 0x3f;
		sack_field <<= 8;
		sack_field |= *(remain_data++);
		sack_field <<= 8;
		sack_field |= *(remain_data++);
		remain_len -= 3;
	}
	else if((remain_data[0] & 0x20) == 0)
	{
		/* discriminator '110' */
		if(remain_len < 4)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for the discriminator of the TCP pure "
			             "field: only %zu bytes available while at least 4 bytes "
			             "required", remain_len);
			goto error;
		}
		sack_field = *(remain_data++) & 0x1f;
		sack_field <<= 8;
		sack_field |= *(remain_data++);
		sack_field <<= 8;
		sack_field |= *(remain_data++);
		sack_field <<= 8;
		sack_field |= *(remain_data++);
		remain_len -= 4;
	}
	else if(remain_data[0] == 0xff)
	{
		/* discriminator '11111111' */
		if(remain_len < 5)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for the discriminator of the TCP pure "
			             "field: only %zu bytes available while at least 5 bytes "
			             "required", remain_len);
			goto error;
		}
		remain_data++; /* skip discriminator */
		sack_field = *(remain_data++);
		sack_field <<= 8;
		sack_field |= *(remain_data++);
		sack_field <<= 8;
		sack_field |= *(remain_data++);
		sack_field <<= 8;
		sack_field |= *(remain_data++);
		remain_len -= 5;
	}
	else
	{
		goto error;
	}

	*field = rohc_hton32(base + sack_field);

	return (data_len - remain_len);

error:
	return -1;
}


/**
 * @brief Uncompress a SACK block
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context    The decompression context
 * @param data       The data to decode
 * @param data_len   The length of the data to decode
 * @param reference  The reference value
 * @param sack_block Pointer to the uncompressed sack_block
 * @return           The number of data bytes parsed,
 *                   -1 if data is malformed
 */
static int d_sack_block(const struct rohc_decomp_ctxt *const context,
								const uint8_t *const data,
                        const size_t data_len,
                        uint32_t reference,
                        sack_block_t *sack_block)
{
	const uint8_t *remain_data = data;
	size_t remain_len = data_len;
	int ret;

	/* decode block start */
	ret = d_sack_pure_lsb(context, remain_data, remain_len, reference,
	                      &sack_block->block_start);
	if(ret < 0)
	{
		goto error;
	}
	remain_data += ret;
	remain_len -= ret;

	/* decode block end */
	ret = d_sack_pure_lsb(context, remain_data, remain_len,
	                      rohc_ntoh32(sack_block->block_start),
	                      &sack_block->block_end);
	if(ret < 0)
	{
		goto error;
	}
	remain_data += ret;
	remain_len -= ret;

	return (data_len - remain_len);

error:
	return -1;
}


/**
 * @brief Uncompress the SACK TCP option
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context    The decompression context
 * @param data       The data to decode
 * @param data_len   The length of the data to decode
 * @param pOptions   Pointer to the uncompressed option
 * @param ack_value  The ack value
 * @return           The number of ROHC bytes parsed,
 *                   -1 if packet is malformed
 */
static int d_tcp_opt_sack(const struct rohc_decomp_ctxt *const context,
                          const uint8_t *const data,
                          const size_t data_len,
                          uint8_t **pOptions,
                          uint32_t ack_value)
{
	const uint8_t *remain_data;
	size_t remain_len;
	sack_block_t *sack_block;
	uint8_t discriminator;
	uint8_t *options;
	int i;

	assert(context != NULL);
	assert(data != NULL);

	rohc_decomp_debug(context, "parse SACK option (reference ACK = 0x%08x)",
	                  ack_value);

	remain_data = data;
	remain_len = data_len;
	options = *pOptions;

	/* parse discriminator */
	if(remain_len < 1)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
		             "packet too short for the discriminator of the TCP SACK "
		             "option: only %zu bytes available while at least 1 byte "
		             "required", remain_len);
		goto error;
	}
	discriminator = remain_data[0];
	remain_data++;
	remain_len--;
	if(discriminator > 4)
	{
		rohc_decomp_warn(context, "invalid discriminator value (%d)",
		                 discriminator);
		goto error;
	}

	/* option ID */
	*(options++) = TCP_OPT_SACK;
	/* option length */
	*(options++) = ( discriminator << 3 ) + 2;

	sack_block = (sack_block_t *) options;

	for(i = 0; i < discriminator; i++)
	{
		const int ret =
			d_sack_block(context, remain_data, remain_len, ack_value, sack_block);
		if(ret < 0)
		{
// TODO: use rohc_decomp_warn()
			rohc_decomp_warn(context, "failed to decode block #%d of SACK "
			                 "option", i + 1);
			goto error;
		}
		remain_data += ret;
		remain_len -= ret;
		rohc_decomp_debug(context, "block #%d of SACK option: start = 0x%08x, "
		                  "end = 0x%08x", i + 1,
		                  rohc_ntoh32(sack_block->block_start),
		                  rohc_ntoh32(sack_block->block_end));
		sack_block++;
	}
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "TCP option SACK", options - 2, *(options - 1));
	*pOptions = (uint8_t *) sack_block;

	return (data_len - remain_len);

error:
	return -1;
}


/**
 * @brief Calculate the size of the compressed SACK field value
 *
 * See RFC6846 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context      The decompression context
 * @param rohc_data    The remaining ROHC data to decode
 * @param rohc_length  The length (in bytes) of the remaining ROHC data
 * @return             The size (in bytes) of the compressed value,
 *                     -1 in case of problem
 */
static int d_sack_var_length_size_dec(const struct rohc_decomp_ctxt *const context,
                                      const uint8_t *const rohc_data,
                                      const size_t rohc_length)
{
	size_t block_len;

	/* enough data for discriminator? */
	if(rohc_length < 1)
	{
		rohc_decomp_warn(context, "remaining ROHC data too small (%zu bytes) "
		                 "for the discriminator of SACK block_start or SACK "
		                 "block_end", rohc_length);
		goto error;
	}

	if((rohc_data[0] & 0x80) == 0)
	{
		/* discriminator '0' */
		block_len = 2;
	}
	else if((rohc_data[0] & 0x40) == 0)
	{
		/* discriminator '10' */
		block_len = 3;
	}
	else if((rohc_data[0] & 0x20) == 0)
	{
		/* discriminator '110' */
		block_len = 4;
	}
	else if(rohc_data[0] == 0xff)
	{
		/* discriminator '11111111' */
		block_len = 5;
	}
	else
	{
		rohc_decomp_warn(context, "invalid discriminator (%u) for the SACK "
		                 "block_start or SACK block_end", rohc_data[0]);
		block_len = -1;
	}

	/* enough data for the whole compressed data? */
	if(rohc_length < block_len)
	{
		rohc_decomp_warn(context, "remaining ROHC data too small (%zu bytes) "
		                 "for the %zu-byte SACK block_start or SACK block_end",
		                 rohc_length, block_len);
		goto error;
	}

	return block_len;

error:
	return -1;
}


/**
 * @brief Calculate the size of the compressed SACK block
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context      The decompression context
 * @param rohc_data    The remaining ROHC data to decode
 * @param rohc_length  The length (in bytes) of the remaining ROHC data
 * @return             The size (in bytes) of the compressed value,
 *                     -1 in case of problem
 */
static int d_sack_block_size(const struct rohc_decomp_ctxt *const context,
                             const uint8_t *const rohc_data,
                             const size_t rohc_length)
{
	const uint8_t *remain_data = rohc_data;
	size_t remain_len = rohc_length;
	size_t size = 0;
	int ret;

	/* decode block start */
	ret = d_sack_var_length_size_dec(context, remain_data, remain_len);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to decode the TCP SACK block_start");
		goto error;
	}
	remain_data += ret;
	remain_len -= ret;
	size += ret;

	/* decode block end */
	ret = d_sack_var_length_size_dec(context, remain_data, remain_len);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to decode the TCP SACK block_end");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += ret;
	remain_len -= ret;
#endif
	size += ret;

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
 * @param context      The decompression context
 * @param rohc_data    The remaining ROHC data to decode
 * @param rohc_length  The length (in bytes) of the remaining ROHC data
 * @param uncomp_len   The length (in bytes) of the uncompressed TCP option
 * @return             The size (in bytes) of the compressed value,
 *                     -1 in case of problem
 */
static int d_tcp_size_opt_sack(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const rohc_data,
                               const size_t rohc_length,
                               uint16_t *const uncomp_len)
{
	const uint8_t *remain_data;
	size_t remain_len;
	uint8_t discriminator;
	size_t size = 0;
	size_t i;

	assert(context != NULL);
	assert(rohc_data != NULL);
	assert(uncomp_len != NULL);

	remain_data = rohc_data;
	remain_len = rohc_length;

	/* parse discriminator */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "remaining ROHC data too small (%zu bytes) "
		                 "for the discriminator of the compressed TCP SACK "
		                 "option", remain_len);
		goto error;
	}
	discriminator = remain_data[0];
	remain_data++;
	remain_len--;
	size++;
	if(discriminator > 4)
	{
		rohc_decomp_warn(context, "invalid discriminator value (%d)",
		                 discriminator);
		goto error;
	}

	for(i = 0; i < discriminator; i++)
	{
		const int block_len = d_sack_block_size(context, remain_data, remain_len);
		if(block_len < 0)
		{
			rohc_decomp_warn(context, "failed to determine the length of SACK "
			                 "block #%zu", i + 1);
			goto error;
		}
		remain_data += block_len;
		remain_len -= block_len;
		size += block_len;
	}

	rohc_decomp_debug(context, "TCP SACK option is compressed on %zu bytes",
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
 * @param ptr          Pointer to the compressed TCP option
 * @param pOptions     Pointer to the uncompressed TCP option
 * @return             Pointer to the next compressed value
 */
static const uint8_t * d_tcp_opt_generic(const uint8_t *ptr,
                                         uint8_t **pOptions)
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
 * @param tcp_context  The specific TCP context
 * @param rohc_data    The remaining ROHC data
 * @param rohc_length  The length (in bytes) of the remaining ROHC data
 * @param uncomp_len   The length (in bytes) of the uncompressed TCP option
 * @return             The number of ROHC bytes parsed
 */
static int d_tcp_size_opt_generic(struct d_tcp_context *tcp_context __attribute__((unused)),
                                  const uint8_t *const rohc_data __attribute__((unused)),
                                  const size_t rohc_length __attribute__((unused)),
                                  uint16_t *const uncomp_len __attribute__((unused)))
{
	size_t size = 0;

	/* TODO: to be completed */

	return size;
}


/**
 * @brief Uncompress the TCP options
 *
 * @param context      The decompression context
 * @param data         The compressed TCP options
 * @param data_len     The length (in bytes) of compressed TCP options
 * @param[in,out] tcp  The TCP header where to append uncompressed TCP options
 * @return             Pointer on data after the compressed TCP options,
 *                     NULL in case of malformed data
 */
static const uint8_t * tcp_decompress_tcp_options(struct rohc_decomp_ctxt *const context,
																  const uint8_t *const data,
																  const size_t data_len)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_tcp_context *tcp_context;
	uint8_t present;
	uint8_t *pValue;
	uint8_t PS;
	uint8_t opt_idx;
	size_t xi_len;
	uint8_t m;
	size_t i;
	int ret;

	uint8_t *remain_data;
	size_t remain_len;
	const uint8_t *compressed_options;
	size_t comp_opts_len;
	uint8_t *options;
	size_t opts_len = 0;

	assert(context != NULL);
	assert(context->specific != NULL);
	rfc3095_ctxt = context->specific;
	assert(rfc3095_ctxt->specific != NULL);
	tcp_context = rfc3095_ctxt->specific;
	assert(data != NULL);

	remain_data = (uint8_t *) data;
	remain_len = data_len;

	/* init pointer to destination TCP options */
	options = tcp_context->options;

	/* PS/m byte */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "ROHC packet is too small for compressed TCP "
		                 "options: at least 1 byte required");
		goto error;
	}
	PS = remain_data[0] & 0x10;
	m = remain_data[0] & 0x0f;
	remain_data++;
	remain_len--;
	if(m > MAX_TCP_OPTION_INDEX)
	{
		rohc_decomp_warn(context, "compressed list of TCP options: too many "
		                 "options");
		goto error;
	}

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
							"on %zd bytes", (PS == 0 ? 4 : 8), xi_len);
	if(remain_len < xi_len)
	{
		rohc_decomp_warn(context, "ROHC packet is too small for compressed TCP "
		                 "options: at least %zu bytes required", xi_len);
		goto error;
	}
	compressed_options = remain_data + xi_len;
	comp_opts_len = remain_len - xi_len;

	for(i = 0; i < m; i++)
	{
		/* 4-bit XI fields */
		if(PS == 0)
		{
			/* if odd digit */
			if(i & 1)
			{
				opt_idx = remain_data[0];
				remain_data++;
				remain_len--;
			}
			else
			{
				opt_idx = remain_data[0] >> 4;
			}
			present = opt_idx & 0x08;
			opt_idx &= 0x07;
			rohc_decomp_debug(context, "TCP options list: 4-bit XI field #%zu: "
			                  "item with index %u is %s", i, opt_idx,
			                  present ? "present" : "not present");
		}
		else
		{
			/* 8-bit XI fields */
			present = remain_data[0] & 0x80;
			opt_idx = remain_data[0] & 0x0f;
			remain_data++;
			remain_len--;
			rohc_decomp_debug(context, "TCP options list: 8-bit XI field #%zu: "
			                  "item with index %u is %s", i, opt_idx,
			                  present ? "present" : "not present");
		}

		if(present)
		{
			uint8_t opt_type;

			/* option content is present */
			tcp_context->is_tcp_opts_list_item_present[i] = true;

			/* TODO: check ROHC packet length */
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:  // NOP
					opt_type = TCP_OPT_NOP;
					*(options++) = TCP_OPT_NOP;
					tcp_context->tcp_opts_list_item_uncomp_length[i] = 1;
					break;
				case TCP_INDEX_EOL:  // EOL
					opt_type = TCP_OPT_EOL;
					*(options++) = TCP_OPT_EOL;
					tcp_context->tcp_opts_list_item_uncomp_length[i] = 1;
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					opt_type = TCP_OPT_MAXSEG;
					*(options++) = TCP_OPT_MAXSEG;
					// Length
					*(options++) = TCP_OLEN_MAXSEG;
					// Max segment size
					if(comp_opts_len < 2)
					{
						rohc_decomp_warn(context, "ROHC packet is too small for "
						                 "compressed TCP option MAXSEQ: at least "
						                 "2 bytes required");
						goto error;
					}
					memcpy(&tcp_context->tcp_option_maxseg,compressed_options,2);
					*(options++) = *(compressed_options++);
					*(options++) = *(compressed_options++);
					comp_opts_len -= 2;
					tcp_context->tcp_opts_list_item_uncomp_length[i] = 4;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					opt_type = TCP_OPT_WINDOW;
					*(options++) = TCP_OPT_WINDOW;
					// Length
					*(options++) = TCP_OLEN_WINDOW;
					// Window scale
					if(comp_opts_len < 1)
					{
						rohc_decomp_warn(context, "ROHC packet is too small for "
						                 "compressed TCP option WINDOW: at least "
						                 "1 byte required");
						goto error;
					}
					options[0] = compressed_options[0];
					options++;
					tcp_context->tcp_option_window = compressed_options[0];
					compressed_options++;
					comp_opts_len -= 1;
					tcp_context->tcp_opts_list_item_uncomp_length[i] = 3;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
				{
					const struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) (options + 2);

					opt_type = TCP_OPT_TIMESTAMP;
					*(options++) = TCP_OPT_TIMESTAMP;
					// Length
					*(options++) = TCP_OLEN_TIMESTAMP;

					/* decode TS echo request with method ts_lsb() */
					ret = d_ts_lsb(context, tcp_context->opt_ts_req_lsb_ctxt,
					               compressed_options, comp_opts_len,
					               (uint32_t *) options);
					if(ret < 0)
					{
						rohc_decomp_warn(context, "failed to decompress TCP option "
						                 "Timestamp echo request");
						goto error;
					}
					compressed_options += ret;
					comp_opts_len -= ret;
					rohc_lsb_set_ref(tcp_context->opt_ts_req_lsb_ctxt,
					                 rohc_ntoh32(opt_ts->ts), false);

					/* decode TS echo reply with method ts_lsb() */
					ret = d_ts_lsb(context, tcp_context->opt_ts_reply_lsb_ctxt,
					               compressed_options, comp_opts_len,
					               (uint32_t *) (options + 4));
					if(ret < 0)
					{
						rohc_decomp_warn(context, "failed to decompress TCP option "
						                 "Timestamp echo reply");
						goto error;
					}
					compressed_options += ret;
					comp_opts_len -= ret;
					rohc_lsb_set_ref(tcp_context->opt_ts_reply_lsb_ctxt,
					                 rohc_ntoh32(opt_ts->ts_reply), false);

					tcp_context->tcp_option_timestamp.ts = opt_ts->ts;
					tcp_context->tcp_option_timestamp.ts_reply = opt_ts->ts_reply;

					options += sizeof(struct tcp_option_timestamp);

					tcp_context->tcp_opts_list_item_uncomp_length[i] =
						2 + sizeof(struct tcp_option_timestamp);
					break;
				}
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					opt_type = TCP_OPT_SACK_PERMITTED;
					*(options++) = TCP_OPT_SACK_PERMITTED;
					// Length
					*(options++) = TCP_OLEN_SACK_PERMITTED;
					tcp_context->tcp_opts_list_item_uncomp_length[i] = 2;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					                   // TODO: save into context
				{
					const uint8_t *const start_opt = options;
					opt_type = TCP_OPT_SACK;
					ret = d_tcp_opt_sack(context, compressed_options, comp_opts_len,
					                     &options, rohc_ntoh32(tcp_context->ack_num));
					if(compressed_options == NULL)
					{
						rohc_decomp_warn(context, "failed to decompress TCP SACK "
						                 "option");
						goto error;
					}
					tcp_context->tcp_opts_list_item_uncomp_length[i] = (options - start_opt);
					tcp_context->tcp_option_sack_length = (options - start_opt);
					break;
				}
				default:  // Generic options
				{
					const uint8_t *const start_opt = options;
					rohc_decomp_warn(context, "TCP option with index %u not "
					                 "handled", opt_idx);
					// TODO
					opt_type = 0xff;
					compressed_options =
						d_tcp_opt_generic(compressed_options, &options);
					tcp_context->tcp_opts_list_item_uncomp_length[i] = (options - start_opt);
					break;
				}
			}
			tcp_context->tcp_opts_list_struct[i] = opt_type;
			opts_len += tcp_context->tcp_opts_list_item_uncomp_length[i];
		}
		else
		{
			uint8_t opt_type;

			/* option content not present */
			tcp_context->is_tcp_opts_list_item_present[i] = false;

			/* TODO: check ROHC packet length */
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:  // NOP
					opt_type = TCP_OPT_NOP;
					*(options++) = TCP_OPT_NOP;
					opts_len++;
					break;
				case TCP_INDEX_EOL:  // EOL
					opt_type = TCP_OPT_EOL;
					*(options++) = TCP_OPT_EOL;
					opts_len++;
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					opt_type = TCP_OPT_MAXSEG;
					*(options++) = TCP_OPT_MAXSEG;
					opts_len++;
					// Length
					*(options++) = TCP_OLEN_MAXSEG;
					opts_len++;
					// Max segment size value
					memcpy(options,&tcp_context->tcp_option_maxseg,2);
					options += TCP_OLEN_MAXSEG - 2;
					opts_len += TCP_OLEN_MAXSEG - 2;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					opt_type = TCP_OPT_WINDOW;
					*(options++) = TCP_OPT_WINDOW;
					opts_len++;
					// Length
					*(options++) = TCP_OLEN_WINDOW;
					opts_len++;
					// Window scale value
					*(options++) = tcp_context->tcp_option_window;
					opts_len++;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
				{
					struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) (options + 2);

					opt_type = TCP_OPT_TIMESTAMP;
					*(options++) = TCP_OPT_TIMESTAMP;
					opts_len++;
					// Length
					*(options++) = TCP_OLEN_TIMESTAMP;
					opts_len++;
					// Timestamp value
					opt_ts->ts = tcp_context->tcp_option_timestamp.ts;
					opt_ts->ts_reply = tcp_context->tcp_option_timestamp.ts_reply;
					options += TCP_OLEN_TIMESTAMP - 2;
					opts_len += TCP_OLEN_TIMESTAMP - 2;
					break;
				}
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					opt_type = TCP_OPT_SACK_PERMITTED;
					*(options++) = TCP_OPT_SACK_PERMITTED;
					opts_len++;
					// Length
					*(options++) = TCP_OLEN_SACK_PERMITTED;
					opts_len++;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					opt_type = TCP_OPT_SACK;
					*(options++) = TCP_OPT_SACK;
					opts_len++;
					// Length
					*(options++) = tcp_context->tcp_option_sack_length;
					opts_len++;
					// Value
					memcpy(options,&tcp_context->tcp_option_sackblocks,
					       tcp_context->tcp_option_sack_length);
					options += tcp_context->tcp_option_sack_length;
					opts_len += tcp_context->tcp_option_sack_length;
					break;
				default:  // Generic options
					rohc_decomp_debug(context, "TCP option with index %u not "
					                  "handled", opt_idx);
					opt_type = tcp_context->tcp_options_list[opt_idx];
					*(options++) = tcp_context->tcp_options_list[opt_idx];
					opts_len++;
					pValue = tcp_context->tcp_options_values +
					         tcp_context->tcp_options_offset[opt_idx];
					// Length
					*(options++) = *pValue;
					opts_len++;
					// Value
					memcpy(options,pValue + 1,*pValue);
					options += (*pValue) + 2;
					opts_len += (*pValue) + 2;
					break;
			}
			tcp_context->tcp_opts_list_struct[i] = opt_type;
		}
	}
	memset(tcp_context->tcp_opts_list_struct + m, 0xff, ROHC_TCP_OPTS_MAX - m);

	// Pad with nul
	for(i = opts_len; i & 0x03; i++)
	{
		rohc_decomp_debug(context, "add TCP EOL option for padding");
		*(options++) = TCP_OPT_EOL;
		opts_len++;
	}

	/* Calculate TCP header length with TCP options */
	tcp_context->options_len = opts_len;

	return compressed_options;

error:
	return NULL;
}


/**
 * @brief Calculate the compressed TCP options size
 *
 * See RFC6846 pages 26-27.
 *
 * @param context          The decompression context
 * @param data             The compressed TCP options
 * @param data_len         The length (in bytes) of compressed TCP options
 * @param[out] uncomp_len  The length (in bytes) of uncompressed TCP options
 * @return                 The length of compressed TCP options,
 *                         -1 in case of malformed data
 */
static int tcp_size_decompress_tcp_options(struct rohc_decomp_ctxt *const context,
                                           const uint8_t *data,
                                           const size_t data_len,
                                           uint16_t *uncomp_len)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_tcp_context *tcp_context;
	const uint8_t *items;
	size_t items_max_len;
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
	rfc3095_ctxt = context->specific;
	assert(rfc3095_ctxt->specific != NULL);
	tcp_context = rfc3095_ctxt->specific;

	comp_size = 0;
	*uncomp_len = 0;

	/* PS/m byte */
	if(data_len < 1)
	{
		rohc_decomp_warn(context, "ROHC packet is too small for compressed TCP "
		                 "options: at least 1 byte required");
		goto error;
	}
	PS = *data & 0x10;
	m = *data & 0x0F;
	data++;
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
							"on %zd bytes", (PS == 0 ? 4 : 8), xi_len);
	if(data_len < (1 + xi_len))
	{
		rohc_decomp_warn(context, "ROHC packet is too small for compressed TCP "
		                 "options: at least %zu bytes required", 1 + xi_len);
		goto error;
	}
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "XI bytes of compressed list of TCP options", data, xi_len);
	comp_size += xi_len;
	items = data + xi_len;
	items_max_len = data_len - comp_size;

	for(i = 0; m != 0; i++, m--)
	{
		/* 4-bit XI fields */
		if(PS == 0)
		{
			/* if odd digit */
			if(i & 1)
			{
				opt_idx = *(data++);
			}
			else
			{
				opt_idx = (*data) >> 4;
			}
			present = opt_idx & 0x08;
			opt_idx &= 0x07;
			rohc_decomp_debug(context, "TCP options list: 4-bit XI field #%d: "
			                  "item with index %u is %s", i, opt_idx,
			                  present ? "present" : "not present");
		}
		else
		{
			/* 8-bit XI fields */
			present = (*data) & 0x80;
			opt_idx = *(data++) & 0x0F;
			rohc_decomp_debug(context, "TCP options list: 8-bit XI field #%d: "
			                  "item with index %u is %s", i, opt_idx,
			                  present ? "present" : "not present");
		}

		// If item present
		if(present)
		{
			size_t comp_opt_len = 0;

			/* TODO: check ROHC packet length */
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:  // NOP
					(*uncomp_len)++;
					break;
				case TCP_INDEX_EOL:  // EOL
					(*uncomp_len)++;
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					(*uncomp_len) += TCP_OLEN_MAXSEG;
					items += 2;
					items_max_len -= 2;
					comp_opt_len += 2;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					(*uncomp_len) += TCP_OLEN_WINDOW;
					items++;
					items_max_len--;
					comp_opt_len++;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
					(*uncomp_len) += TCP_OLEN_TIMESTAMP;
					j = d_size_ts_lsb(context, items, items_max_len);
					if(j < 0)
					{
						rohc_decomp_warn(context, "failed to find the length of "
						                 "the compressed TCP Timestamp option");
						goto error;
					}
					items += j;
					items_max_len -= j;
					comp_opt_len += j;
					j = d_size_ts_lsb(context, items, items_max_len);
					if(j < 0)
					{
						rohc_decomp_warn(context, "failed to find the length of "
						                 "the compressed TCP Timestamp option");
						goto error;
					}
					items += j;
					items_max_len -= j;
					comp_opt_len += j;
					break;
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					(*uncomp_len) += TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					j = d_tcp_size_opt_sack(context, items, items_max_len,
					                        uncomp_len);
					if(j < 0)
					{
						rohc_decomp_warn(context, "failed to find the length of "
						                 "the compressed TCP SACK option");
						goto error;
					}
					items += j;
					items_max_len -= j;
					comp_opt_len += j;
					break;
				default:  // Generic options
					rohc_decomp_debug(context, "TCP option with index %u not "
					                  "handled", opt_idx);
					j = d_tcp_size_opt_generic(tcp_context, items, items_max_len,
					                           uncomp_len);
					if(j < 0)
					{
						rohc_decomp_warn(context, "failed to find the length of "
						                 "the compressed TCP generic option");
						goto error;
					}
					items += j;
					items_max_len -= j;
					comp_opt_len += j;
					break;
			}
			rohc_decomp_debug(context, "TCP option with index %u is %zd-byte "
			                  "long in compressed packet", opt_idx,
			                  comp_opt_len);
			comp_size += comp_opt_len;
		}
		else
		{
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:  // NOP
					(*uncomp_len)++;
					break;
				case TCP_INDEX_EOL:  // EOL
					(*uncomp_len)++;
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					(*uncomp_len) += TCP_OLEN_MAXSEG;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					(*uncomp_len) += TCP_OLEN_WINDOW;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
					(*uncomp_len) += TCP_OLEN_TIMESTAMP;
					break;
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					(*uncomp_len) += TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					(*uncomp_len) += *(tcp_context->tcp_options_values +
					                   tcp_context->tcp_options_list[opt_idx]);
					break;
				default:  // Generic options
					(*uncomp_len) += *(tcp_context->tcp_options_values +
					                   tcp_context->tcp_options_list[opt_idx]);
					break;
			}
		}
	}

	rohc_decomp_debug(context, "TCP options: compressed length = %d bytes, "
	                  "uncompressed length = %d bytes", comp_size,
	                  *uncomp_len);

	return comp_size;

error:
	return -1;
}


/**
 * @brief Decode one CO packet.
 *
 * \verbatim

  RFC 6846, section 7.3. Compressed (CO) Packets

     0   1   2   3   4   5   6   7
    --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :  if for small CIDs and CID 1-15
    +---+---+---+---+---+---+---+---+
 2  |   First octet of base header  |  (with type indication)
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /   0, 1, or 2 octets of CID    /  1-2 octets if large CIDs
    :                               :
    +---+---+---+---+---+---+---+---+
 4  /   Remainder of base header    /  variable number of octets
    +---+---+---+---+---+---+---+---+
    :        Irregular chain        :
 5  /   (including irregular chain  /  variable
    :    items for TCP options)     :
     --- --- --- --- --- --- --- ---
    |                               |
 6  /            Payload            / variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param decomp           The ROHC decompressor
 * @param context          The decompression context
 * @param rohc_packet      The ROHC packet to decode
 * @param rohc_length      The length of the ROHC packet
 * @param add_cid_len      The length of the optional Add-CID field
 * @param large_cid_len    The length of the optional large CID field
 * @param packet_type      The type of the ROHC packet to parse
 * @param dest             OUT: The decoded IP packet
 * @param[out] uncomp_len  The length of the uncompressed IP packet
 * @return                 ROHC_STATUS_OK if decompression was successful,
 *                         ROHC_ERROR_CRC if a CRC failure occured,
 *                         ROHC_ERROR if another error occured
 */
static rohc_status_t d_tcp_decode_CO(struct rohc_decomp *decomp,
                                     struct rohc_decomp_ctxt *context,
                                     const unsigned char *const rohc_packet,
                                     const size_t rohc_length,
                                     const size_t add_cid_len,
                                     const size_t large_cid_len,
                                     const rohc_packet_t packet_type,
                                     struct rohc_buf *const uncomp_packet)
{
	unsigned char *packed_rohc_packet = malloc(5000); // TODO: change that
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_tcp_context *tcp_context;
	size_t ip_contexts_nr;
	uint16_t tcp_options_size = 0;
	uint32_t seq_num_scaled_bits = 0;
	size_t seq_num_scaled_nr = 0;
	uint8_t header_crc;
	uint8_t crc_computed;
	uint16_t msn;
	size_t rohc_opts_len;
	int ttl_irregular_chain_flag = 0;
	uint16_t ip_id_offset;
	uint16_t ip_id;
	int ret;

	size_t crc_type;

	const uint8_t *rohc_opts_data = NULL;
	bool is_list_present = false;

	/* lengths of ROHC and uncompressed headers to be computed during parsing */
	size_t rohc_header_len;
	size_t uncomp_header_len;

	/* remaining ROHC data not parsed yet */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* ROHC and uncompressed payloads (they are the same) */
	size_t payload_len;

	assert(decomp != NULL);
	assert(context != NULL);
	assert(context->specific != NULL);
	rfc3095_ctxt = context->specific;
	assert(rfc3095_ctxt->specific != NULL);
	tcp_context = rfc3095_ctxt->specific;
	assert(rohc_packet != NULL);
	assert(add_cid_len == 0 || add_cid_len == 1);
	assert(large_cid_len <= 2);
	assert(packet_type != ROHC_PACKET_UNKNOWN);

#ifndef __clang_analyzer__ /* silent warning about value never read */
	rohc_remain_data = (unsigned char *) rohc_packet;
#endif
	rohc_remain_len = rohc_length;

	rohc_decomp_debug(context, "add_cid_len = %zu, large_cid_len = %zu, "
	                  "rohc_length = %zu", add_cid_len, large_cid_len,
	                  rohc_length);

	assert(tcp_context->ip_contexts_nr > 0);
	ip_context_t *const ip_inner_context =
		&(tcp_context->ip_contexts[tcp_context->ip_contexts_nr - 1]);

	/* check if the ROHC packet is large enough to parse parts 2, 3 and 4 */
	if(rohc_remain_len <= (1 + large_cid_len))
	{
		rohc_decomp_warn(context, "rohc packet too small (len = %zu)",
		                 rohc_remain_len);
		goto error;
	}

	/* copy the first byte of header over the last byte of the large CID field
	 * to be able to map packet strutures to the ROHC bytes */
	if((rohc_remain_len - large_cid_len) > 5000)
	{
		rohc_decomp_warn(context, "internal problem: internal buffer too small");
		goto error;
	}
	packed_rohc_packet[0] = rohc_packet[0];
	memcpy(packed_rohc_packet + 1, rohc_packet + 1 + large_cid_len,
	       rohc_remain_len - 1 - large_cid_len);
	rohc_remain_data = packed_rohc_packet;
	rohc_remain_len -= large_cid_len;
	rohc_header_len = 0;

	/* decode the packet type we detected earlier */
	switch(packet_type)
	{
		case ROHC_PACKET_TCP_RND_1:
		{
			const rnd_1_t *const rnd_1 = (rnd_1_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse rnd_1 */
			if(rohc_remain_len < sizeof(rnd_1_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for rnd_1 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(rnd_1->discriminator == 0x2e); /* '101110' */
			rohc_header_len += sizeof(rnd_1_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = rnd_1->header_crc;
			msn = rnd_1->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_RND_2:
		{
			const rnd_2_t *const rnd_2 = (rnd_2_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse rnd_2 */
			if(rohc_remain_len < sizeof(rnd_2_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for rnd_2 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(rnd_2->discriminator == 0x0c); /* '1100' */
			rohc_header_len += sizeof(rnd_2_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = rnd_2->header_crc;
			msn = rnd_2->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_RND_3:
		{
			const rnd_3_t *const rnd_3 = (rnd_3_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse rnd_3 */
			if(rohc_remain_len < sizeof(rnd_3_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for rnd_3 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(rnd_3->discriminator == 0x00); /* '0' */
			rohc_header_len += sizeof(rnd_3_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = rnd_3->header_crc;
			msn = rnd_3->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_RND_4:
		{
			const rnd_4_t *const rnd_4 = (rnd_4_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse rnd_4 */
			if(rohc_remain_len < sizeof(rnd_4_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for rnd_4 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(rnd_4->discriminator == 0x0d); /* '1101' */
			rohc_header_len += sizeof(rnd_4_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = rnd_4->header_crc;
			msn = rnd_4->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_RND_5:
		{
			const rnd_5_t *const rnd_5 = (rnd_5_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse rnd_5 */
			if(rohc_remain_len < sizeof(rnd_5_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for rnd_5 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(rnd_5->discriminator == 0x04); /* '100' */
			rohc_header_len += sizeof(rnd_5_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = rnd_5->header_crc;
			msn = rnd_5->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_RND_6:
		{
			const rnd_6_t *const rnd_6 = (rnd_6_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse rnd_6 */
			if(rohc_remain_len < sizeof(rnd_6_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for rnd_6 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(rnd_6->discriminator == 0x0a); /* '1010' */
			rohc_header_len += sizeof(rnd_6_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = rnd_6->header_crc;
			msn = rnd_6->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_RND_7:
		{
			const rnd_7_t *const rnd_7 = (rnd_7_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse rnd_7 */
			if(rohc_remain_len < sizeof(rnd_7_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for rnd_7 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(rnd_7->discriminator == 0x2f); /* '101111' */
			rohc_header_len += sizeof(rnd_7_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = rnd_7->header_crc;
			msn = rnd_7->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_RND_8:
		{
			const rnd_8_t *const rnd_8 = (rnd_8_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse rnd_8 */
			if(rohc_remain_len < sizeof(rnd_8_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for rnd_8 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(rnd_8->discriminator == 0x16); /* '10110' */
			rohc_header_len += sizeof(rnd_8_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = rnd_8->header_crc;
			msn = (rnd_8->msn1 << 3) | rnd_8->msn2;
			rohc_decomp_debug(context, "rnd_8 header is %zu-byte long",
			                  rohc_header_len);
			is_list_present = !!rnd_8->list_present;
			crc_type = 7;
			break;
		}
		case ROHC_PACKET_TCP_SEQ_1:
		{
			const seq_1_t *const seq_1 = (seq_1_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse seq_1 */
			if(rohc_remain_len < sizeof(seq_1_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for seq_1 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(seq_1->discriminator == 0x0a); /* '1010' */
			rohc_header_len += sizeof(seq_1_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = seq_1->header_crc;
			msn = seq_1->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_SEQ_2:
		{
			const seq_2_t *const seq_2 = (seq_2_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse seq_2 */
			if(rohc_remain_len < sizeof(seq_2_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for seq_2 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(seq_2->discriminator == 0x1a); /* '11010' */
			rohc_header_len += sizeof(seq_2_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = seq_2->header_crc;
			msn = seq_2->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_SEQ_3:
		{
			const seq_3_t *const seq_3 = (seq_3_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse seq_3 */
			if(rohc_remain_len < sizeof(seq_3_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for seq_3 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(seq_3->discriminator == 0x09); /* '1001' */
			rohc_header_len += sizeof(seq_3_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = seq_3->header_crc;
			msn = seq_3->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_SEQ_4:
		{
			const seq_4_t *const seq_4 = (seq_4_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse seq_4 */
			if(rohc_remain_len < sizeof(seq_4_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for seq_4 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(seq_4->discriminator == 0x00); /* '0' */
			rohc_header_len += sizeof(seq_4_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = seq_4->header_crc;
			msn = seq_4->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_SEQ_5:
		{
			const seq_5_t *const seq_5 = (seq_5_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse seq_5 */
			if(rohc_remain_len < sizeof(seq_5_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for seq_5 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(seq_5->discriminator == 0x08); /* '1000' */
			rohc_header_len += sizeof(seq_5_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = seq_5->header_crc;
			msn = seq_5->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_SEQ_6:
		{
			const seq_6_t *const seq_6 = (seq_6_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse seq_6 */
			if(rohc_remain_len < sizeof(seq_6_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for seq_6 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(seq_6->discriminator == 0x1b); /* '11011' */
			rohc_header_len += sizeof(seq_6_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = seq_6->header_crc;
			msn = seq_6->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_SEQ_7:
		{
			const seq_7_t *const seq_7 = (seq_7_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse seq_7 */
			if(rohc_remain_len < sizeof(seq_7_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for seq_7 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(seq_7->discriminator == 0x0c); /* '1100' */
			rohc_header_len += sizeof(seq_7_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = seq_7->header_crc;
			msn = seq_7->msn;
			crc_type = 3;
			break;
		}
		case ROHC_PACKET_TCP_SEQ_8:
		{
			const seq_8_t *const seq_8 = (seq_8_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse seq_8 */
			if(rohc_remain_len < sizeof(seq_8_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for seq_8 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(seq_8->discriminator == 0x0b); /* '1011' */
			rohc_header_len += sizeof(seq_8_t);
			assert(rohc_header_len <= rohc_length);
			header_crc = seq_8->header_crc;
			msn = seq_8->msn;
			rohc_decomp_debug(context, "seq_8 header is %zu-byte long",
			                  rohc_header_len);
			is_list_present = !!seq_8->list_present;
			crc_type = 7;
			break;
		}
		case ROHC_PACKET_TCP_CO_COMMON:
		{
			const co_common_t *const co_common =
				(co_common_t *) rohc_remain_data;
			size_t co_common_opt_len = 0;

			/* check if the ROHC packet is large enough to parse co_common */
			if(rohc_remain_len < sizeof(co_common_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for co_common "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(co_common->discriminator == 0x7d); /* '1111101' */
			rohc_header_len += sizeof(co_common_t);
			assert(rohc_header_len <= rohc_length);

			co_common_opt_len +=
				variable_length_32_size[co_common->seq_indicator];
			rohc_decomp_debug(context, "seq_indicator = %d => %zu bytes of "
			                  "options", co_common->seq_indicator,
			                  co_common_opt_len);
			co_common_opt_len += variable_length_32_size[co_common->ack_indicator];
			rohc_decomp_debug(context, "ack_indicator = %d => %zu bytes of "
			                  "options", co_common->ack_indicator,
			                  co_common_opt_len);
			co_common_opt_len += co_common->ack_stride_indicator << 1;
			rohc_decomp_debug(context, "ack_stride_indicator = %d => %zu bytes "
			                  "of options", co_common->ack_stride_indicator,
									co_common_opt_len);
			co_common_opt_len += co_common->window_indicator << 1;
			rohc_decomp_debug(context, "window_indicator = %d => %zu bytes of "
			                  "options", co_common->window_indicator,
			                  co_common_opt_len);
			if(co_common->ip_id_behavior == IP_ID_BEHAVIOR_SEQ ||
			   co_common->ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
			{
				co_common_opt_len += co_common->ip_id_indicator + 1;
			}
			rohc_decomp_debug(context, "ip_id_behavior = %d, ip_id_indicator "
			                  "= %d => %zu bytes of options",
			                  co_common->ip_id_behavior,
			                  co_common->ip_id_indicator, co_common_opt_len);
			co_common_opt_len += co_common->urg_ptr_present << 1;
			rohc_decomp_debug(context, "urg_ptr_present = %d => %zu bytes of "
			                  "options", co_common->urg_ptr_present,
			                  co_common_opt_len);
			co_common_opt_len += co_common->dscp_present;
			rohc_decomp_debug(context, "dscp_present = %d => %zu bytes of "
			                  "options", co_common->dscp_present,
			                  co_common_opt_len);
			co_common_opt_len += co_common->ttl_hopl_present;
			rohc_decomp_debug(context, "ttl_hopl_present = %d => %zu bytes of "
			                  "options", co_common->ttl_hopl_present,
			                  co_common_opt_len);
			rohc_decomp_debug(context, "list_present = %d",
			                  co_common->list_present);
			rohc_decomp_debug(context, "common size = header (%zu) + options "
			                  "(%zu) = %zu", rohc_header_len, co_common_opt_len,
			                  rohc_header_len + co_common_opt_len);
			rohc_header_len += co_common_opt_len;
			assert(rohc_header_len <= rohc_length);

			/* check the crc */
			header_crc = co_common->header_crc;

			msn = co_common->msn;

			is_list_present = !!co_common->list_present;
			crc_type = 7;
			break;
		}
		default:
		{
			assert(0); /* should not happen */
			goto error;
		}
	}
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "ROHC base header", rohc_remain_data, rohc_header_len);
	rohc_remain_data += rohc_header_len;
	rohc_remain_len -= rohc_header_len;

	if(is_list_present)
	{
		rohc_decomp_debug(context, "compressed list of TCP options found after "
		                  "the %zu-byte ROHC base header", rohc_header_len);
		ret = tcp_size_decompress_tcp_options(context, rohc_remain_data,
		                                      rohc_remain_len, &tcp_options_size);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "failed to parse compressed TCP options");
			goto error;
		}
		rohc_opts_len = ret;
	}
	else
	{
		size_t i;
		rohc_decomp_debug(context, "no compressed list of TCP options found "
		                  "after the %zu-byte ROHC base header", rohc_header_len);
		for(i = 0; i < ROHC_TCP_OPTS_MAX; i++)
		{
			tcp_context->is_tcp_opts_list_item_present[i] = false;
		}
		rohc_opts_len = 0;
	}
	rohc_decomp_debug(context, "ROHC packet = header (%zu bytes) + "
	                  "options (%zu bytes) = %zu bytes", rohc_header_len,
	                  rohc_opts_len, rohc_header_len + rohc_opts_len);
	rohc_remain_data += rohc_opts_len;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_len -= rohc_opts_len;
#endif
	rohc_header_len += rohc_opts_len;

	// Check the MSN received with MSN required
	if( ( (tcp_context->msn + 1) & 0x000F ) != msn)
	{
		rohc_decomp_debug(context, "last_msn = 0x%04x, waiting for msn = 0x%x, "
		                  "received 0x%x!", tcp_context->msn,
		                  (tcp_context->msn + 1) & 0x000F, msn);
		// To be completed !!!
		// Store and rework packets
	}
	else
	{
		rohc_decomp_debug(context, "last msn (0x%04x) + 1 = 0x%04x, received = "
		                  "0x%x", tcp_context->msn, tcp_context->msn + 1, msn);
	}
	msn = d_lsb(context, 4, 4, tcp_context->msn + 1, msn);
	rohc_decomp_debug(context, "MSN = 0x%04x", msn);

	/* reset the correction counter */
	rfc3095_ctxt->correction_counter = 0;

	/* parse dynamic part */
	if(packet_type == ROHC_PACKET_TCP_CO_COMMON)
	{
		const co_common_t *const co_common =
			(co_common_t *) packed_rohc_packet; /* TODO: check size */

		rohc_decomp_debug(context, "decode co_common packet");

		tcp_context->res_flags = tcp_context->old_tcphdr.res_flags;
		tcp_context->urg_ptr = tcp_context->old_tcphdr.urg_ptr;

		ttl_irregular_chain_flag = co_common->ttl_hopl_outer_flag;
		tcp_context->ack_flag = co_common->ack_flag;
		tcp_context->psh_flag = co_common->psh_flag;
		tcp_context->urg_flag = co_common->urg_flag;
		tcp_context->rsf_flags = rsf_index_dec(co_common->rsf_flags);
		rohc_decomp_debug(context, "ack_flag = %d, psh_flag = %d, rsf_flags = "
		                  "%d", tcp_context->ack_flag, tcp_context->psh_flag,
		                  tcp_context->rsf_flags);

		/* beginning of the variable part */
		rohc_opts_data = packed_rohc_packet + sizeof(co_common_t);

		/* sequence number */
		ret = variable_length_32_dec(tcp_context->seq_lsb_ctxt, context,
		                             rohc_opts_data, co_common->seq_indicator,
		                             &tcp_context->seq_num);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "variable_length_32(seq_number) failed");
			goto error;
		}
		rohc_decomp_debug(context, "seq_number = 0x%x (%d bytes in packet)",
		                  rohc_ntoh32(tcp_context->seq_num), ret);
		rohc_opts_data += ret;

		/* ACK number */
		if(co_common->ack_indicator != 0)
		{
			rohc_decomp_debug(context, "ACK flag not set, but indicator for "
			                  "ACK number is %u instead of 0",
			                  co_common->ack_indicator);
		}
		ret = variable_length_32_dec(tcp_context->ack_lsb_ctxt, context,
		                             rohc_opts_data, co_common->ack_indicator,
		                             &tcp_context->ack_num);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "variable_length_32(ack_number) failed");
			goto error;
		}
		rohc_decomp_debug(context, "ack_number = 0x%x (%d bytes in packet)",
		                  rohc_ntoh32(tcp_context->ack_num), ret);
		rohc_opts_data += ret;

		/* ACK stride */
		ret = d_static_or_irreg16(rohc_opts_data, tcp_context->ack_stride,
		                          co_common->ack_stride_indicator,
		                          &tcp_context->ack_stride);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "static_or_irreg(ack_stride) failed");
			goto error;
		}
		tcp_context->ack_stride = rohc_hton16(tcp_context->ack_stride);
		rohc_decomp_debug(context, "ack_stride = 0x%x (%d bytes in packet)",
		                  tcp_context->ack_stride, ret);
		rohc_opts_data += ret;

		/* window */
		ret = d_static_or_irreg16(rohc_opts_data,
		                          tcp_context->old_tcphdr.window,
		                          co_common->window_indicator, &tcp_context->window);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "static_or_irreg(window) failed");
			goto error;
		}
		rohc_decomp_debug(context, "window = 0x%x (old_window = 0x%x, %d bytes "
		                  "in packet)", rohc_ntoh16(tcp_context->window),
		                  rohc_ntoh16(tcp_context->old_tcphdr.window), ret);
		rohc_opts_data += ret;

		/* IP-ID behavior */
		ip_inner_context->ctxt.v4.ip_id_behavior = co_common->ip_id_behavior;
		ret = d_optional_ip_id_lsb(context, tcp_context->ip_id_lsb_ctxt,
		                           rohc_opts_data, co_common->ip_id_behavior,
		                           co_common->ip_id_indicator,
		                           &ip_id_offset, &ip_id, msn);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "optional_ip_id_lsb(ip_id) failed");
			goto error;
		}
		rohc_decomp_debug(context, "IP-ID = 0x%04x (%d bytes in packet)",
		                  ip_id, ret);
		rohc_opts_data += ret;

		/* URG pointer */
		ret = d_static_or_irreg16(rohc_opts_data,
		                          tcp_context->old_tcphdr.urg_ptr,
		                          co_common->urg_ptr_present, &tcp_context->urg_ptr);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "static_or_irreg(urg_ptr) failed");
			goto error;
		}
		rohc_opts_data += ret;

		rohc_decomp_debug(context, "ecn_used = %d", co_common->ecn_used);
		tcp_context->ecn_used = co_common->ecn_used;

		if(ip_inner_context->ctxt.vx.version == IPV4)
		{
			uint8_t dscp;
			uint8_t ttl_hopl;

			/* DSCP */
			ret = dscp_decode(rohc_opts_data, ip_inner_context->ctxt.v4.dscp,
			                  co_common->dscp_present, &dscp);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "dscp_decode(dscp) failed");
				goto error;
			}
			rohc_decomp_debug(context, "DSCP = 0x%02x (indicator = %d, context "
			                  "= 0x%02x)", dscp, co_common->dscp_present,
			                  ip_inner_context->ctxt.v4.dscp);
			ip_inner_context->ctxt.v4.dscp = dscp;
			rohc_opts_data += ret;

			/* DF */
			ip_inner_context->ctxt.v4.df = co_common->df;

			/* TTL */
			ret = d_static_or_irreg8(rohc_opts_data,
			                         ip_inner_context->ctxt.v4.ttl_hopl,
			                         co_common->ttl_hopl_present, &ttl_hopl);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "static_or_irreg(ttl) failed");
				goto error;
			}
			rohc_decomp_debug(context, "TTL = 0x%x", ttl_hopl);
			ip_inner_context->ctxt.v4.ttl_hopl = ttl_hopl;
			rohc_opts_data += ret;
		}
		else
		{
			uint8_t dscp;
			uint8_t ttl_hopl;

			ret = dscp_decode(rohc_opts_data, ip_inner_context->ctxt.v6.dscp,
			                  co_common->dscp_present, &dscp);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "dscp_decode(dscp) failed");
				goto error;
			}
			rohc_decomp_debug(context, "DSCP = 0x%02x (indicator = %d, context "
			                  "= 0x%02x)", dscp, co_common->dscp_present,
			                  ip_inner_context->ctxt.v6.dscp);
			ip_inner_context->ctxt.v6.dscp = dscp;
			rohc_opts_data += ret;

			ret = d_static_or_irreg8(rohc_opts_data,
			                         ip_inner_context->ctxt.v6.ttl_hopl,
			                         co_common->ttl_hopl_present, &ttl_hopl);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "static_or_irreg(hl failed)");
				goto error;
			}
			rohc_decomp_debug(context, "HL = 0x%x", ttl_hopl);
			ip_inner_context->ctxt.v6.ttl_hopl = ttl_hopl;
			rohc_opts_data += ret;
		}
	}
	else
	{
		uint32_t ack_num_bits;
		uint32_t ack_num_bits_nr = 0;
		uint32_t ack_num_p;
		uint32_t ack_num_scaled;
		uint8_t ttl_hopl;

		tcp_context->seq_num = tcp_context->old_tcphdr.seq_num;
		tcp_context->ack_num = tcp_context->old_tcphdr.ack_num;
		tcp_context->res_flags = tcp_context->old_tcphdr.res_flags;
		tcp_context->ecn_flags = tcp_context->old_tcphdr.ecn_flags;
		tcp_context->urg_flag = tcp_context->old_tcphdr.urg_flag;
		tcp_context->ack_flag = tcp_context->old_tcphdr.ack_flag;
		tcp_context->rsf_flags = tcp_context->old_tcphdr.rsf_flags;
		tcp_context->window = tcp_context->old_tcphdr.window;
		tcp_context->urg_ptr = tcp_context->old_tcphdr.urg_ptr;

		switch(packet_type)
		{
			case ROHC_PACKET_TCP_RND_1:
			{
				const rnd_1_t *const rnd_1 = (rnd_1_t *) packed_rohc_packet;
				uint32_t encoded_seq_num;
				uint32_t decoded_seq_num;

				rohc_decomp_debug(context, "decode rnd_1 packet");

				encoded_seq_num =
					(rnd_1->seq_num1 << 16) | rohc_ntoh16(rnd_1->seq_num2);

				/* decode sequence number from packet bits and context */
				if(!rohc_decomp_tcp_decode_seq(context, encoded_seq_num,
				                               18, 65535, &decoded_seq_num))
				{
					goto error;
				}
				tcp_context->seq_num = rohc_hton32(decoded_seq_num);

				tcp_context->psh_flag = rnd_1->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_RND_2:
			{
				const rnd_2_t *const rnd_2 = (rnd_2_t *) packed_rohc_packet;

				rohc_decomp_debug(context, "decode rnd_2 packet");

				seq_num_scaled_bits = rnd_2->seq_num_scaled;
				seq_num_scaled_nr = 4;
				rohc_decomp_debug(context, "rnd_2: %zu bits of scaled sequence "
				                  "number 0x%x", seq_num_scaled_nr,
				                  seq_num_scaled_bits);
				tcp_context->psh_flag = rnd_2->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_RND_3:
			{
				const rnd_3_t *const rnd_3 = (rnd_3_t *) packed_rohc_packet;

				rohc_decomp_debug(context, "decode rnd_3 packet");

				/* retrieve ACK number bits */
				ack_num_bits = (rnd_3->ack_num1 << 1) | rnd_3->ack_num2;
				ack_num_bits_nr = 15;
				ack_num_p = 8191;

				tcp_context->psh_flag = rnd_3->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_RND_4:
			{
				const rnd_4_t *const rnd_4 = (rnd_4_t *) packed_rohc_packet;

				rohc_decomp_debug(context, "decode rnd_4 packet");

				if(tcp_context->ack_stride == 0)
				{
					rohc_decomp_warn(context, "cannot decode rnd_4 packet with "
					                 "ack_stride.UVALUE == 0");
					goto error;
				}
				ack_num_scaled = d_lsb(context, 4, 3,
				                       rohc_ntoh32(tcp_context->old_tcphdr.ack_num),
				                       rnd_4->ack_num_scaled);
				assert(tcp_context->ack_stride != 0);
				tcp_context->ack_num =
					d_field_scaling(tcp_context->ack_stride, ack_num_scaled,
					                tcp_context->ack_num_residue);
				rohc_decomp_debug(context, "ack_number_scaled = 0x%x, "
				                  "ack_number_residue = 0x%x -> ack_number = "
				                  "0x%x", ack_num_scaled,
				                  tcp_context->ack_num_residue,
				                  rohc_ntoh32(tcp_context->ack_num));
				tcp_context->psh_flag = rnd_4->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_RND_5:
			{
				const rnd_5_t *const rnd_5 = (rnd_5_t *) packed_rohc_packet;
				uint32_t decoded_seq_num;
				uint16_t enc_seq_num;

				rohc_decomp_debug(context, "decode rnd_5 packet");

				tcp_context->psh_flag = rnd_5->psh_flag;

				/* decode sequence number from packet bits and context */
				enc_seq_num = (rnd_5->seq_num1 << 9) |
				              (rnd_5->seq_num2 << 1) |
				              rnd_5->seq_num3;
				if(!rohc_decomp_tcp_decode_seq(context, enc_seq_num, 14, 8191,
				                               &decoded_seq_num))
				{
					goto error;
				}
				tcp_context->seq_num = rohc_hton32(decoded_seq_num);

				/* retrieve ACK number bits */
				ack_num_bits = (rnd_5->ack_num1 << 8) | rnd_5->ack_num2;
				ack_num_bits_nr = 15;
				ack_num_p = 8191;

				break;
			}
			case ROHC_PACKET_TCP_RND_6:
			{
				const rnd_6_t *const rnd_6 = (rnd_6_t *) packed_rohc_packet;

				rohc_decomp_debug(context, "decode rnd_6 packet");

				tcp_context->psh_flag = rnd_6->psh_flag;

				/* retrieve ACK number bits */
				ack_num_bits = rohc_ntoh16(rnd_6->ack_num);
				ack_num_bits_nr = 16;
				ack_num_p = 16383;

				seq_num_scaled_bits = rnd_6->seq_num_scaled;
				seq_num_scaled_nr = 4;
				rohc_decomp_debug(context, "rnd_6: %zu bits of scaled sequence "
				                  "number 0x%x", seq_num_scaled_nr,
				                  seq_num_scaled_bits);
				break;
			}
			case ROHC_PACKET_TCP_RND_7:
			{
				const rnd_7_t *const rnd_7 = (rnd_7_t *) packed_rohc_packet;

				rohc_decomp_debug(context, "decode rnd_7 packet");

				/* retrieve ACK number bits */
				ack_num_bits = (rnd_7->ack_num1 << 16) |
				                rohc_ntoh16(rnd_7->ack_num2);
				ack_num_bits_nr = 18;
				ack_num_p = 65535;

				tcp_context->window = rnd_7->window;
				tcp_context->psh_flag = rnd_7->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_RND_8:
			{
				const rnd_8_t *const rnd_8 = (rnd_8_t *) packed_rohc_packet;
				uint32_t encoded_seq_num;
				uint32_t decoded_seq_num;

				rohc_decomp_debug(context, "decode rnd_8 packet");

				tcp_context->rsf_flags = rsf_index_dec(rnd_8->rsf_flags);
				tcp_context->psh_flag = rnd_8->psh_flag;
				ttl_hopl = d_lsb(context, 3, 3, ip_inner_context->ctxt.vx.ttl_hopl,
				                 rnd_8->ttl_hopl);
				if(ip_inner_context->ctxt.vx.version == IPV4)
				{
					ip_inner_context->ctxt.v4.ttl_hopl = ttl_hopl;
					rohc_decomp_debug(context, "IPv4 TTL = 0x%02x (%u)",
					                  ttl_hopl, ttl_hopl);
				}
				else
				{
					ip_inner_context->ctxt.v6.ttl_hopl = ttl_hopl;
					rohc_decomp_debug(context, "IPv6 HL = 0x%02x (%u)",
					                  ttl_hopl, ttl_hopl);
				}
				rohc_decomp_debug(context, "ecn_used = %d", rnd_8->ecn_used);
				tcp_context->ecn_used = rnd_8->ecn_used;

				/* decode sequence number from packet bits and context */
				encoded_seq_num = rohc_ntoh16(rnd_8->seq_num);
				if(!rohc_decomp_tcp_decode_seq(context, encoded_seq_num,
				                               16, 65535, &decoded_seq_num))
				{
					goto error;
				}
				tcp_context->seq_num = rohc_hton32(decoded_seq_num);

				/* retrieve ACK number bits */
				ack_num_bits = rohc_ntoh16(rnd_8->ack_num);
				ack_num_bits_nr = 16;
				ack_num_p = 16383;

				/* beginning of the compressed list of TCP options */
				rohc_opts_data = packed_rohc_packet + sizeof(rnd_8_t);

				break;
			}
			case ROHC_PACKET_TCP_SEQ_1:
			{
				const seq_1_t *const seq_1 = (seq_1_t *) packed_rohc_packet;
				uint32_t encoded_seq_num;
				uint32_t decoded_seq_num;

				assert(ip_inner_context->ctxt.vx.version == IPV4);

				rohc_decomp_debug(context, "decode seq_1 packet");

				/* decode innermost IP-ID offset from packet bits and context */
				if(!d_ip_id_lsb(context, tcp_context->ip_id_lsb_ctxt,
				                ip_inner_context->ctxt.v4.ip_id_behavior, msn,
				                seq_1->ip_id, 4, 3, &ip_id_offset, &ip_id))
				{
					goto error;
				}

				/* decode sequence number from packet bits and context */
				encoded_seq_num = rohc_ntoh16(seq_1->seq_num);
				if(!rohc_decomp_tcp_decode_seq(context, encoded_seq_num,
				                               16, 32767, &decoded_seq_num))
				{
					goto error;
				}
				tcp_context->seq_num = rohc_hton32(decoded_seq_num);

				tcp_context->psh_flag = seq_1->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_2:
			{
				const seq_2_t *const seq_2 = (seq_2_t *) packed_rohc_packet;
				uint8_t ip_id_lsb;

				assert(ip_inner_context->ctxt.vx.version == IPV4);

				rohc_decomp_debug(context, "decode seq_2 packet");

				/* decode innermost IP-ID offset from packet bits and context */
				ip_id_lsb = (seq_2->ip_id1 << 4) | seq_2->ip_id2;
				if(!d_ip_id_lsb(context, tcp_context->ip_id_lsb_ctxt,
				                ip_inner_context->ctxt.v4.ip_id_behavior, msn,
				                ip_id_lsb, 7, 3, &ip_id_offset, &ip_id))
				{
					goto error;
				}

				seq_num_scaled_bits = seq_2->seq_num_scaled;
				seq_num_scaled_nr = 4;
				rohc_decomp_debug(context, "seq_2: %zu bits of scaled sequence "
				                  "number 0x%x", seq_num_scaled_nr,
				                  seq_num_scaled_bits);
				tcp_context->psh_flag = seq_2->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_3:
			{
				const seq_3_t *const seq_3 = (seq_3_t *) packed_rohc_packet;

				assert(ip_inner_context->ctxt.vx.version == IPV4);

				rohc_decomp_debug(context, "decode seq_3 packet");

				/* decode innermost IP-ID offset from packet bits and context */
				if(!d_ip_id_lsb(context, tcp_context->ip_id_lsb_ctxt,
				                ip_inner_context->ctxt.v4.ip_id_behavior, msn,
				                seq_3->ip_id, 4, 3, &ip_id_offset, &ip_id))
				{
					goto error;
				}

				/* retrieve ACK number bits */
				ack_num_bits = rohc_ntoh16(seq_3->ack_num);
				ack_num_bits_nr = 16;
				ack_num_p = 16383;

				tcp_context->psh_flag = seq_3->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_4:
			{
				const seq_4_t *const seq_4 = (seq_4_t *) packed_rohc_packet;

				assert(ip_inner_context->ctxt.vx.version == IPV4);

				rohc_decomp_debug(context, "decode seq_4 packet");

				if(tcp_context->ack_stride == 0)
				{
					rohc_decomp_warn(context, "cannot decode seq_4 packet with "
					                 "ack_stride.UVALUE == 0");
					goto error;
				}
				ack_num_scaled =
					d_lsb(context, 4, 3,
					      rohc_ntoh32(tcp_context->old_tcphdr.ack_num),
					      seq_4->ack_num_scaled);
				tcp_context->ack_num =
					d_field_scaling(tcp_context->ack_stride, ack_num_scaled,
					                tcp_context->ack_num_residue);
				rohc_decomp_debug(context, "ack_number_scaled = 0x%x, "
				                  "ack_number_residue = 0x%x -> ack_number = "
				                  "0x%x", ack_num_scaled,
				                  tcp_context->ack_num_residue,
				                  rohc_ntoh32(tcp_context->ack_num));

				/* decode innermost IP-ID offset from packet bits and context */
				if(!d_ip_id_lsb(context, tcp_context->ip_id_lsb_ctxt,
				                ip_inner_context->ctxt.v4.ip_id_behavior, msn,
				                seq_4->ip_id, 3, 1, &ip_id_offset, &ip_id))
				{
					goto error;
				}

				tcp_context->psh_flag = seq_4->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_5:
			{
				const seq_5_t *const seq_5 = (seq_5_t *) packed_rohc_packet;
				uint32_t encoded_seq_num;
				uint32_t decoded_seq_num;

				assert(ip_inner_context->ctxt.vx.version == IPV4);

				rohc_decomp_debug(context, "decode seq_5 packet");

				/* decode innermost IP-ID offset from packet bits and context */
				if(!d_ip_id_lsb(context, tcp_context->ip_id_lsb_ctxt,
				                ip_inner_context->ctxt.v4.ip_id_behavior, msn,
				                seq_5->ip_id, 4, 3, &ip_id_offset, &ip_id))
				{
					goto error;
				}

				/* retrieve ACK number bits */
				ack_num_bits = rohc_ntoh16(seq_5->ack_num);
				ack_num_bits_nr = 16;
				ack_num_p = 16383;

				/* decode sequence number from packet bits and context */
				encoded_seq_num = rohc_ntoh16(seq_5->seq_num);
				if(!rohc_decomp_tcp_decode_seq(context, encoded_seq_num,
				                               16, 32767, &decoded_seq_num))
				{
					goto error;
				}
				tcp_context->seq_num = rohc_hton32(decoded_seq_num);

				tcp_context->psh_flag = seq_5->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_6:
			{
				const seq_6_t *const seq_6 = (seq_6_t *) packed_rohc_packet;

				assert(ip_inner_context->ctxt.vx.version == IPV4);

				rohc_decomp_debug(context, "decode seq_6 packet");

				seq_num_scaled_bits =
					(seq_6->seq_num_scaled1 << 1) | seq_6->seq_num_scaled2;
				seq_num_scaled_nr = 4;
				rohc_decomp_debug(context, "seq_6: %zu bits of scaled sequence "
				                  "number 0x%x", seq_num_scaled_nr,
				                  seq_num_scaled_bits);

				/* decode innermost IP-ID offset from packet bits and context */
				if(!d_ip_id_lsb(context, tcp_context->ip_id_lsb_ctxt,
				                ip_inner_context->ctxt.v4.ip_id_behavior, msn,
				                seq_6->ip_id, 7, 3, &ip_id_offset, &ip_id))
				{
					goto error;
				}

				/* retrieve ACK number bits */
				ack_num_bits = rohc_ntoh16(seq_6->ack_num);
				ack_num_bits_nr = 16;
				ack_num_p = 16383;

				tcp_context->psh_flag = seq_6->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_7:
			{
				const seq_7_t *const seq_7 = (seq_7_t *) packed_rohc_packet;
				uint16_t window;

				assert(ip_inner_context->ctxt.vx.version == IPV4);

				rohc_decomp_debug(context, "decode seq_7 packet");

				window = (seq_7->window1 << 11) | (seq_7->window2 << 3) |
				         seq_7->window3;
				tcp_context->window = rohc_hton16( d_lsb(context, 15,16383,rohc_ntoh16(tcp_context->old_tcphdr.window),window) );

				/* decode innermost IP-ID offset from packet bits and context */
				if(!d_ip_id_lsb(context, tcp_context->ip_id_lsb_ctxt,
				                ip_inner_context->ctxt.v4.ip_id_behavior, msn,
				                seq_7->ip_id, 5, 3, &ip_id_offset, &ip_id))
				{
					goto error;
				}

				/* retrieve ACK number bits */
				ack_num_bits = rohc_ntoh16(seq_7->ack_num);
				ack_num_bits_nr = 16;
				ack_num_p = 32767;

				tcp_context->psh_flag = seq_7->psh_flag;
				break;
			}
			case ROHC_PACKET_TCP_SEQ_8:
			{
				const seq_8_t *const seq_8 = (seq_8_t *) packed_rohc_packet;
				uint32_t decoded_seq_num;
				uint16_t enc_seq_num;

				assert(ip_inner_context->ctxt.vx.version == IPV4);

				rohc_decomp_debug(context, "decode seq_8 packet");

				/* decode innermost IP-ID offset from packet bits and context */
				if(!d_ip_id_lsb(context, tcp_context->ip_id_lsb_ctxt,
				                ip_inner_context->ctxt.v4.ip_id_behavior, msn,
				                seq_8->ip_id, 4, 3, &ip_id_offset, &ip_id))
				{
					goto error;
				}

				tcp_context->psh_flag = seq_8->psh_flag;
				ttl_hopl = d_lsb(context, 3, 3, ip_inner_context->ctxt.v4.ttl_hopl,
				                 seq_8->ttl_hopl);
				ip_inner_context->ctxt.v4.ttl_hopl = ttl_hopl;
				rohc_decomp_debug(context, "IPv4 TTL = 0x%02x (%u)",
				                  ttl_hopl, ttl_hopl);
				rohc_decomp_debug(context, "ecn_used = %d", seq_8->ecn_used);
				tcp_context->ecn_used = seq_8->ecn_used;

				/* retrieve ACK number bits */
				ack_num_bits = (seq_8->ack_num1 << 8) | seq_8->ack_num2;
				ack_num_bits_nr = 15;
				ack_num_p = 8191;

				tcp_context->rsf_flags = rsf_index_dec(seq_8->rsf_flags);

				/* decode sequence number from packet bits and context */
				enc_seq_num = (seq_8->seq_num1 << 8) | seq_8->seq_num2;
				if(!rohc_decomp_tcp_decode_seq(context, enc_seq_num, 14, 8191,
				                               &decoded_seq_num))
				{
					goto error;
				}
				tcp_context->seq_num = rohc_hton32(decoded_seq_num);

				/* beginning of the compressed list of TCP options */
				rohc_opts_data = packed_rohc_packet + sizeof(seq_8_t);

				break;
			}
			default:
			{
				rohc_decomp_warn(context, "unsupported packet type (%d)",
				                 packet_type);
				goto error;
			}
		}

		/* decode the transmitted ACK bits if any */
		if(ack_num_bits_nr > 0)
		{
			uint32_t decoded_ack_num;

			if(!rohc_decomp_tcp_decode_ack(context, tcp_context->ack_flag,
			                               ack_num_bits, ack_num_bits_nr,
			                               ack_num_p, &decoded_ack_num))
			{
				goto error;
			}
			tcp_context->ack_num = rohc_hton32(decoded_ack_num);
		}
	}

	/* decode the TCP options list if present */
	if(is_list_present)
	{
		tcp_decompress_tcp_options(context, rohc_opts_data,
		                           1500 /* TODO: real length */);
	}
	else
	{
		tcp_context->options_len = 0;
	}

	tcp_context->msn = msn;

	/* parse irregular chain: IP parts */
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_contexts_nr]);
		const bool is_inner_ip =
			(ip_contexts_nr == (tcp_context->ip_contexts_nr - 1));
		const uint8_t ip_ecn_flags = ip_context->ctxt.vx.ip_ecn_flags;

		ret = tcp_parse_irregular_ip(context, ip_context, rohc_remain_data,
		                             rohc_remain_len, is_inner_ip,
		                             ttl_irregular_chain_flag, ip_ecn_flags);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "failed to decode IP part of irregular chain");
			goto error;
		}
		rohc_remain_data += ret;
		assert(rohc_remain_len >= (size_t) ret);
		rohc_remain_len -= ret;
		rohc_header_len += ret;
		assert(rohc_header_len <= rohc_length);
	}

	/* irregular chain: TCP part */
	ret = tcp_parse_irregular_tcp(context, ip_inner_context,
	                              rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to decode TCP part of irregular chain");
		goto error;
	}
	rohc_remain_data += ret;
	assert(rohc_remain_len >= (size_t) ret);
	rohc_remain_len -= ret;
	rohc_header_len += ret;
	assert(rohc_header_len <= rohc_length);

	/* decode IP-ID according to its behavior */
	if(ip_inner_context->ctxt.vx.version == IPV4)
	{
		rohc_decomp_debug(context, "decode IP-ID field");

		switch(ip_inner_context->ctxt.v4.ip_id_behavior)
		{
			case IP_ID_BEHAVIOR_SEQ:
			{
				rohc_decomp_debug(context, "IP-ID follows a sequential behavior");
				if(packet_type >= ROHC_PACKET_TCP_RND_1 && packet_type <= ROHC_PACKET_TCP_RND_8)
				{
					rohc_decomp_warn(context, "IP-ID got a sequential behavior "
					                 "but packet is rnd_%d",
					                 packet_type - ROHC_PACKET_TCP_RND_1 + 1);
					goto error;
				}
				ip_inner_context->ctxt.v4.ip_id = ip_id;
				break;
			}
			case IP_ID_BEHAVIOR_SEQ_SWAP:
			{
				const uint16_t swapped_ip_id = swab16(ip_id);

				rohc_decomp_debug(context, "IP-ID follows a swapped sequential "
										"behavior");

				if(packet_type >= ROHC_PACKET_TCP_RND_1 && packet_type <= ROHC_PACKET_TCP_RND_8)
				{
					rohc_decomp_warn(context, "IP-ID got a swapped sequential "
					                 "behavior but packet is rnd_%d",
					                 packet_type - ROHC_PACKET_TCP_RND_1 + 1);
					goto error;
				}

				ip_inner_context->ctxt.v4.ip_id = swapped_ip_id;
				break;
			}
			case IP_ID_BEHAVIOR_RAND:
			{
				rohc_decomp_debug(context, "IP-ID follows a random behavior");
				/* already done by tcp_decode_irregular_ip() */
				break;
			}
			case IP_ID_BEHAVIOR_ZERO:
			{
				rohc_decomp_debug(context, "IP-ID follows a zero behavior");
				ip_inner_context->ctxt.v4.ip_id = 0;
				break;
			}
			default:
			{
				rohc_decomp_warn(context, "unknown IP-ID behavior (%d)",
				                 ip_inner_context->ctxt.v4.ip_id_behavior);
				goto error;
			}
		}
	}

	/* count large CID in header length now */
	rohc_header_len += large_cid_len;
	assert(rohc_header_len <= rohc_length);

	payload_len = rohc_length - rohc_header_len;
	rohc_decomp_debug(context, "payload length = %zu bytes", payload_len);

	if(seq_num_scaled_nr > 0)
	{
		bool decode_ok;

		/* decode LSB bits of scaled sequence number */
		decode_ok = rohc_lsb_decode(tcp_context->seq_scaled_lsb_ctxt,
		                            ROHC_LSB_REF_0, 0, seq_num_scaled_bits,
		                            seq_num_scaled_nr, 7,
		                            &tcp_context->seq_num_scaled);
		if(!decode_ok)
		{
			rohc_decomp_warn(context, "failed to decode %zu scaled sequence "
			                 "number bits 0x%x with p = 7",
			                 seq_num_scaled_nr, seq_num_scaled_bits);
			goto error;
		}
		rohc_decomp_debug(context, "decoded scaled sequence number = 0x%08x "
		                  "(%zu bits 0x%x with p = 7)",
		                  tcp_context->seq_num_scaled, seq_num_scaled_nr,
		                  seq_num_scaled_bits);

		/* decode scaled sequence number */
		if(payload_len == 0)
		{
			rohc_decomp_warn(context, "cannot use scaled TCP sequence number "
			                 "for a packet with an empty payload");
			goto error;
		}
		tcp_context->seq_num =
			rohc_hton32(tcp_context->seq_num_scaled * payload_len +
			            tcp_context->seq_num_residue);
		rohc_decomp_debug(context, "seq_number_scaled = 0x%x, payload size = %zu, "
		                  "seq_number_residue = 0x%x -> seq_number = 0x%x",
		                  tcp_context->seq_num_scaled, payload_len,
		                  tcp_context->seq_num_residue,
		                  rohc_ntoh32(tcp_context->seq_num));
	}
	else if(payload_len != 0)
	{
		tcp_context->seq_num_scaled = rohc_ntoh32(tcp_context->seq_num) / payload_len;
		tcp_context->seq_num_residue = rohc_ntoh32(tcp_context->seq_num) % payload_len;
		rohc_decomp_debug(context, "seq_number = 0x%x, payload size = %zu -> "
		                  "seq_number_residue = 0x%x, seq_number_scaled = 0x%x",
		                  rohc_ntoh32(tcp_context->seq_num), payload_len,
		                  tcp_context->seq_num_residue,
		                  tcp_context->seq_num_scaled);
	}

	/* TODO: duplicated from IR */
	/*
	 * build uncompressed packet
	 */

	/* IP headers */
	uncomp_header_len = 0;
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[ip_contexts_nr]);

		if(ip_context->version == IPV4)
		{
			base_header_ip_v4_t *const ipv4 =
				(base_header_ip_v4_t *) rohc_buf_data(*uncomp_packet);

			if(rohc_buf_avail_len(*uncomp_packet) < sizeof(base_header_ip_v4_t))
			{
				rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
				                 "IPv4 header #%zu", sizeof(base_header_ip_v4_t),
				                 ip_contexts_nr + 1);
				goto error;
			}

			/* static part */
			ipv4->version = IPV4;
			ipv4->header_length = sizeof(base_header_ip_v4_t) >> 2;
			ipv4->protocol = ip_context->ctxt.v4.protocol;
			ipv4->src_addr = ip_context->ctxt.v4.src_addr;
			ipv4->dest_addr = ip_context->ctxt.v4.dst_addr;
			/* dynamic part */
			ipv4->rf = 0;
			ipv4->df = ip_context->ctxt.v4.df;
			ipv4->mf = 0;
			ipv4->dscp = ip_context->ctxt.v4.dscp;
			ipv4->ip_ecn_flags = ip_context->ctxt.v4.ip_ecn_flags;
			ipv4->ttl_hopl = ip_context->ctxt.v4.ttl_hopl;
			rohc_decomp_debug(context, "DSCP = 0x%x, ip_ecn_flags = %d",
			                  ipv4->dscp, ipv4->ip_ecn_flags);
#if WORDS_BIGENDIAN != 1
			ipv4->frag_offset1 = 0;
			ipv4->frag_offset2 = 0;
#else
			ipv4->frag_offset = 0;
#endif
			/* IP-ID */
			ipv4->ip_id = rohc_hton16(ip_context->ctxt.v4.ip_id);

			/* length and checksums will be computed once all headers are built */

			uncomp_packet->len += sizeof(base_header_ip_v4_t);
			rohc_buf_pull(uncomp_packet, sizeof(base_header_ip_v4_t));
			uncomp_header_len += sizeof(base_header_ip_v4_t);
		}
		else
		{
			base_header_ip_v6_t *const ipv6 =
				(base_header_ip_v6_t *) rohc_buf_data(*uncomp_packet);
			const size_t ipv6_exts_len = ip_context->ctxt.v6.opts_len;
			const size_t full_ipv6_len =
				sizeof(base_header_ip_v6_t) + ipv6_exts_len;

			if(rohc_buf_avail_len(*uncomp_packet) < full_ipv6_len)
			{
				rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
				                 "IPv6 header #%zu (with %zu bytes of extension "
				                 "headers)", full_ipv6_len, ip_contexts_nr + 1,
				                 ipv6_exts_len);
				goto error;
			}
			rohc_decomp_debug(context, "build %zu-byte IPv6 header %zu (with %zu "
			                  "bytes of extension headers)", full_ipv6_len,
			                  ip_contexts_nr + 1, ipv6_exts_len);

			/* static part */
			ipv6->version = IPV6;
			ipv6->flow_label1 = ip_context->ctxt.v6.flow_label1;
			ipv6->flow_label2 = ip_context->ctxt.v6.flow_label2;
			ipv6->next_header = ip_context->ctxt.v6.next_header;
			memcpy(ipv6->src_addr, ip_context->ctxt.v6.src_addr, sizeof(uint32_t) * 4);
			memcpy(ipv6->dest_addr, ip_context->ctxt.v6.dest_addr, sizeof(uint32_t) * 4);
			/* dynamic part */
			ipv6->dscp1 = ip_context->ctxt.v6.dscp >> 2;
			ipv6->dscp2 = ip_context->ctxt.v6.dscp & 0x03;
			ipv6->ip_ecn_flags = ip_context->ctxt.v6.ip_ecn_flags;
			ipv6->ttl_hopl = ip_context->ctxt.v6.ttl_hopl;

			/* total length will be computed once all headers are built */

			uncomp_packet->len += sizeof(base_header_ip_v6_t);
			rohc_buf_pull(uncomp_packet, sizeof(base_header_ip_v6_t));
			uncomp_header_len += sizeof(base_header_ip_v6_t);
		}
	}

	/* TCP header */
	{
		tcphdr_t *const tcp = (tcphdr_t *) rohc_buf_data(*uncomp_packet);
		const size_t full_tcp_len = sizeof(tcphdr_t) + tcp_context->options_len;

		if(rohc_buf_avail_len(*uncomp_packet) < full_tcp_len)
		{
			rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
			                 "TCP header and TCP options", full_tcp_len);
			goto error;
		}
		rohc_decomp_debug(context, "build %zu-byte TCP header (with %zu bytes "
		                  "of options)", full_tcp_len, tcp_context->options_len);

		/* static part */
		tcp->src_port = tcp_context->tcp_src_port;
		tcp->dst_port = tcp_context->tcp_dst_port;
		/* dynamic part */
		tcp->data_offset = (full_tcp_len >> 2) & 0xf;
		tcp->res_flags = tcp_context->res_flags;
		tcp->ecn_flags = tcp_context->ecn_flags;
		tcp->urg_flag = tcp_context->urg_flag;
		tcp->ack_flag = tcp_context->ack_flag;
		tcp->psh_flag = tcp_context->psh_flag;
		tcp->rsf_flags = tcp_context->rsf_flags;
		tcp->seq_num = tcp_context->seq_num;
		tcp->ack_num = tcp_context->ack_num;
		tcp->window = tcp_context->window;
		tcp->checksum = tcp_context->checksum;
		tcp->urg_ptr = tcp_context->urg_ptr;
		memcpy(tcp->options, tcp_context->options, tcp_context->options_len);

		uncomp_packet->len += full_tcp_len;
		rohc_buf_pull(uncomp_packet, full_tcp_len);
		uncomp_header_len += full_tcp_len;

		/* update context (should only be done at the very end, to be moved) */
		memcpy(&tcp_context->old_tcphdr, tcp, sizeof(tcphdr_t));
	}

	/* payload */
	rohc_decomp_debug(context, "uncompressed header is %zu-byte length",
	                  uncomp_header_len);
	rohc_decomp_debug(context, "copy %zu bytes of payload", payload_len);
	rohc_buf_append(uncomp_packet, rohc_remain_data, payload_len);
	rohc_buf_push(uncomp_packet, uncomp_header_len);
	rohc_decomp_debug(context, "uncompressed packet is %zu-byte length",
	                  uncomp_packet->len);

	/* compute payload lengths and checksums for all headers */
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[ip_contexts_nr]);

		if(ip_context->version == IPV4)
		{
			base_header_ip_v4_t *const ipv4 =
				(base_header_ip_v4_t *) rohc_buf_data(*uncomp_packet);
			ipv4->length = rohc_hton16(uncomp_packet->len);
			ipv4->checksum = 0;
			ipv4->checksum =
				ip_fast_csum(rohc_buf_data(*uncomp_packet), ipv4->header_length);
			rohc_decomp_debug(context, "IP checksum = 0x%04x on %zu bytes",
			                  rohc_ntoh16(ipv4->checksum),
			                  ipv4->header_length * sizeof(uint32_t));
			rohc_buf_pull(uncomp_packet, ipv4->header_length * sizeof(uint32_t));
		}
		else
		{
			base_header_ip_v6_t *const ipv6 =
				(base_header_ip_v6_t *) rohc_buf_data(*uncomp_packet);
			rohc_buf_pull(uncomp_packet, sizeof(base_header_ip_v6_t));
			ipv6->payload_length = rohc_hton16(uncomp_packet->len);
			rohc_decomp_debug(context, "IPv6 payload length = %d",
			                  rohc_ntoh16(ipv6->payload_length));
			rohc_buf_pull(uncomp_packet, ip_context->ctxt.v6.opts_len);
		}
	}
	{
		const size_t full_tcp_len = sizeof(tcphdr_t) + tcp_context->options_len;
		rohc_buf_push(uncomp_packet, uncomp_header_len - full_tcp_len);
	}

	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "current IP + TCP packet",
	              rohc_buf_data(*uncomp_packet), uncomp_header_len);

	/* check CRC on decompressed headers */
	switch(crc_type)
	{
		case 7:
			crc_computed =
				crc_calculate(ROHC_CRC_TYPE_7, rohc_buf_data(*uncomp_packet),
				              uncomp_header_len, CRC_INIT_7, decomp->crc_table_7);
			break;
		case 3:
			crc_computed =
				crc_calculate(ROHC_CRC_TYPE_3, rohc_buf_data(*uncomp_packet),
				              uncomp_header_len, CRC_INIT_3, decomp->crc_table_3);
			break;
		default:
			/* should not happen */
			assert(0);
			goto error;
	}
	if(header_crc != crc_computed)
	{
		rohc_decomp_debug(context, "CRC computed on the %zu-byte decompressed "
		                  "header (0x%02x) doesn't match header CRC (0x%02x)",
		                  uncomp_header_len, crc_computed, header_crc);
		goto error_crc;
	}
	rohc_decomp_debug(context, "the %zu-byte decompressed header matches the "
	                  "CRC 0x%02x", uncomp_header_len, header_crc);

	// TODO: to be reworked
	context->state = ROHC_DECOMP_STATE_FC;

	/* TODO: duplicated from IR */
	/* update context (to be completed) */
	{
		assert(tcp_context->ip_contexts_nr > 0);
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[tcp_context->ip_contexts_nr - 1]);
		const ip_version innermost_ip_version = ip_context->ctxt.vx.version;
		const uint16_t inner_ip_id = ip_context->ctxt.v4.ip_id;
		const uint16_t inner_ip_id_offset = inner_ip_id - tcp_context->msn;
		if(innermost_ip_version == IPV4)
		{
			rohc_lsb_set_ref(tcp_context->ip_id_lsb_ctxt, inner_ip_id_offset, false);
			rohc_decomp_debug(context, "innermost IP-ID offset 0x%04x is the new "
			                  "reference", inner_ip_id_offset);
		}
	}
	rohc_lsb_set_ref(tcp_context->seq_lsb_ctxt, rohc_ntoh32(tcp_context->seq_num), false);
	rohc_decomp_debug(context, "sequence number 0x%08x is the new reference",
	                  rohc_ntoh32(tcp_context->seq_num));
	if(payload_len != 0)
	{
		rohc_lsb_set_ref(tcp_context->seq_scaled_lsb_ctxt,
		                 tcp_context->seq_num_scaled, false);
		rohc_decomp_debug(context, "scaled sequence number 0x%08x is the new "
		                  "reference", tcp_context->seq_num_scaled);
	}
	rohc_lsb_set_ref(tcp_context->ack_lsb_ctxt, rohc_ntoh32(tcp_context->ack_num), false);
	rohc_decomp_debug(context, "ACK number 0x%08x is the new reference",
	                  rohc_ntoh32(tcp_context->ack_num));

	/* statistics */
	context->header_compressed_size += rohc_header_len;
	context->header_uncompressed_size += uncomp_header_len;

	free(packed_rohc_packet);
	return ROHC_STATUS_OK;

error:
	free(packed_rohc_packet);
	return ROHC_STATUS_ERROR;
error_crc:
	free(packed_rohc_packet);
	return ROHC_STATUS_BAD_CRC;
}


/**
 * @brief decode the tcp sequence number from packet and context information
 *
 */
static bool rohc_decomp_tcp_decode_seq(const struct rohc_decomp_ctxt *const context,
                                       const uint32_t seq_bits,
                                       const size_t seq_bits_nr,
                                       const rohc_lsb_shift_t p,
                                       uint32_t *const seq)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	const struct d_tcp_context *const tcp_context = rfc3095_ctxt->specific;
	bool decode_ok;

	decode_ok = rohc_lsb_decode(tcp_context->seq_lsb_ctxt, ROHC_LSB_REF_0, 0,
	                            seq_bits, seq_bits_nr, p, seq);
	if(!decode_ok)
	{
		rohc_decomp_warn(context, "failed to decode %zu sequence number bits "
		                 "0x%x with p = %u", seq_bits_nr, seq_bits, p);
		return false;
	}
	rohc_decomp_debug(context, "decoded sequence number = 0x%08x (%zu bits "
	                  "0x%x with p = %d)", *seq, seq_bits_nr, seq_bits, p);

	return true;
}


/**
 * @brief Decode the TCP ACK number from packet and context information
 *
 */
static bool rohc_decomp_tcp_decode_ack(const struct rohc_decomp_ctxt *const context,
                                       const uint8_t ack_flag,
                                       const uint32_t ack_bits,
                                       const size_t ack_bits_nr,
                                       const rohc_lsb_shift_t p,
                                       uint32_t *const ack)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	const struct d_tcp_context *const tcp_context = rfc3095_ctxt->specific;
	bool decode_ok;

	decode_ok = rohc_lsb_decode(tcp_context->ack_lsb_ctxt, ROHC_LSB_REF_0, 0,
	                            ack_bits, ack_bits_nr, p, ack);
	if(!decode_ok)
	{
		rohc_decomp_warn(context, "failed to decode %zu ACK number bits 0x%x "
		                 "with p = %u", ack_bits_nr, ack_bits, p);
		goto error;
	}
	rohc_decomp_debug(context, "decoded ACK number = 0x%08x (%zu bits 0x%x "
	                  "with p = %d)", *ack, ack_bits_nr, ack_bits, p);

	if(ack_flag == 0)
	{
		rohc_decomp_debug(context, "ACK flag not set, but %zu bits 0x%x were "
		                  "transmitted for ACK number", ack_bits_nr, ack_bits);
	}

	return true;

error:
	return false;
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
static uint32_t d_tcp_get_msn(const struct rohc_decomp_ctxt *const context)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	const struct d_tcp_context *const tcp_context = rfc3095_ctxt->specific;

	rohc_decomp_debug(context, "MSN = %u (0x%x)", tcp_context->msn,
	                  tcp_context->msn);

	return tcp_context->msn;
}


/**
 * @brief Define the decompression part of the TCP profile as described
 *        in the RFC 3095.
 */
const struct rohc_decomp_profile d_tcp_profile =
{
	.id              = ROHC_PROFILE_TCP, /* profile ID (see 8 in RFC3095) */
	.new_context     = d_tcp_create,
	.free_context    = d_tcp_destroy,
	.decode          = d_tcp_decode,
	.detect_pkt_type = tcp_detect_packet_type,
	.get_sn          = d_tcp_get_msn
};

