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

#include "d_tcp_defines.h"
#include "d_tcp_static.h"
#include "d_tcp_dynamic.h"
#include "d_tcp_irregular.h"

#include "rohc_decomp.h"
#include "rohc_decomp_internals.h"
#include "rohc_packets.h"
#include "rohc_bit_ops.h"
#include "rohc_traces_internal.h"
#include "rohc_utils.h"
#include "rohc_debug.h"
#include "schemes/rfc4996.h"
#include "schemes/decomp_wlsb.h"
#include "schemes/tcp_sack.h"
#include "schemes/tcp_ts.h"
#include "protocols/tcp.h"
#include "protocols/ip_numbers.h"
#include "crc.h"

#include "config.h" /* for WORDS_BIGENDIAN and ROHC_EXTRA_DEBUG */

#ifndef __KERNEL__
#  include <string.h>
#endif
#include <stdint.h>


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

static rohc_packet_t tcp_detect_packet_type(const struct rohc_decomp_ctxt *const context,
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static uint32_t d_tcp_get_msn(const struct rohc_decomp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1), pure));

/* parsing */
static bool d_tcp_parse_packet(struct rohc_decomp_ctxt *const context,
                               const struct rohc_buf rohc_packet,
                               const size_t large_cid_len,
                               const rohc_packet_t packet_type,
                               struct rohc_tcp_extr_bits *const bits,
                               size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 5, 6)));
static bool d_tcp_parse_ir(struct rohc_decomp_ctxt *const context,
                           const unsigned char *const rohc_packet,
                           const size_t rohc_length,
                           const size_t large_cid_len,
                           struct rohc_tcp_extr_bits *const bits,
                           size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6)));
static bool d_tcp_parse_irdyn(struct rohc_decomp_ctxt *const context,
                              const unsigned char *const rohc_packet,
                              const size_t rohc_length,
                              const size_t large_cid_len,
                              struct rohc_tcp_extr_bits *const bits,
                              size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6)));
static bool d_tcp_parse_CO(struct rohc_decomp_ctxt *const context,
                           const unsigned char *const rohc_packet,
                           const size_t rohc_length,
                           const size_t large_cid_len,
                           const rohc_packet_t packet_type,
                           struct rohc_tcp_extr_bits *const bits,
                           size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 6, 7)));
static const uint8_t * d_tcp_parse_options(struct rohc_decomp_ctxt *const context,
                                           const uint8_t *const data,
                                           const size_t data_len,
                                           struct rohc_tcp_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static void d_tcp_reset_extr_bits(const struct rohc_decomp_ctxt *const context,
											 struct rohc_tcp_extr_bits *const bits)
	__attribute__((nonnull(1, 2)));

/* decoding */
static bool d_tcp_decode_values_from_bits(const struct rohc_decomp_ctxt *const context,
                                          const struct rohc_tcp_extr_bits bits,
                                          const size_t payload_len,
                                          struct rohc_tcp_decoded_values *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 4)));
static bool d_tcp_decode_opt_ts(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_lsb_decode *const req_lsb_ctxt,
                                const struct rohc_lsb_decode *const rep_lsb_ctxt,
                                const struct d_tcp_opt_ts ts,
                                bool *const ts_present,
                                uint32_t *const req_decoded,
                                uint32_t *const rep_decoded)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));
static bool d_tcp_decode_opt_ts_field(const struct rohc_decomp_ctxt *const context,
                                      const char *const descr,
                                      const struct rohc_lsb_decode *const lsb_ctxt,
                                      const struct rohc_lsb_field32 ts,
                                      uint32_t *const ts_decoded)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
static void d_tcp_decode_opt_sack(const struct rohc_decomp_ctxt *const context,
                                  const uint32_t ack_num,
                                  const struct d_tcp_opt_sack opt_sack,
                                  uint8_t *const decoded)
	__attribute__((nonnull(1, 4)));

static bool d_tcp_build_ipv4_hdr(const struct rohc_decomp_ctxt *const context,
                                 const struct rohc_tcp_decoded_ip_values decoded,
                                 struct rohc_buf *const uncomp_packet,
                                 size_t *const ip_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 4)));
static bool d_tcp_build_ipv6_hdr(const struct rohc_decomp_ctxt *const context,
                                 const struct rohc_tcp_decoded_ip_values decoded,
                                 struct rohc_buf *const uncomp_packet,
                                 size_t *const ip_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 4)));
static bool d_tcp_build_ip_hdr(const struct rohc_decomp_ctxt *const context,
                               const struct rohc_tcp_decoded_ip_values decoded,
                               struct rohc_buf *const uncomp_packet,
                               size_t *const ip_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 4)));
static bool d_tcp_build_ip_hdrs(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_tcp_decoded_values decoded,
                                struct rohc_buf *const uncomp_packet,
                                size_t *const ip_hdrs_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 4)));
static bool d_tcp_build_tcp_hdr(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_tcp_decoded_values decoded,
                                struct rohc_buf *const uncomp_packet,
                                size_t *const tcp_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 4)));
static rohc_status_t d_tcp_build_uncomp_hdrs(const struct rohc_decomp *const decomp,
                                             const struct rohc_decomp_ctxt *const context,
                                             const rohc_packet_t packet_type,
                                             const struct rohc_tcp_decoded_values decoded,
                                             const size_t payload_len,
                                             const rohc_crc_type_t crc_type,
                                             const uint8_t crc_packet,
                                             struct rohc_buf *const uncomp_hdrs,
                                             size_t *const uncomp_hdrs_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 8, 9)));
static bool d_tcp_check_uncomp_crc(const struct rohc_decomp *const decomp,
                                   const struct rohc_decomp_ctxt *const context,
                                   struct rohc_buf *const uncomp_hdrs,
                                   const rohc_crc_type_t crc_type,
                                   const uint8_t crc_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

/* CRC repair */
static bool d_tcp_attempt_repair(const struct rohc_decomp *const decomp,
                                 const struct rohc_decomp_ctxt *const context,
                                 struct rohc_tcp_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

/* updating context */
static void d_tcp_update_context(struct rohc_decomp_ctxt *const context,
                                 const struct rohc_tcp_decoded_values decoded,
                                 const size_t payload_len)
	__attribute__((nonnull(1)));


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
	struct d_tcp_context *tcp_context;

	/* allocate memory for the context */
	tcp_context = malloc(sizeof(struct d_tcp_context));
	if(tcp_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "not enough memory for the TCP decompression context");
		goto quit;
	}
	memset(tcp_context, 0, sizeof(struct d_tcp_context));

	/* create the LSB decoding context for the MSN */
	tcp_context->msn_lsb_ctxt = rohc_lsb_new(16);
	if(tcp_context->msn_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the MSN");
		goto destroy_context;
	}

	/* create the LSB decoding context for the innermost IP-ID */
	tcp_context->ip_id_lsb_ctxt = rohc_lsb_new(16);
	if(tcp_context->ip_id_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the innermost "
		           "IP-ID");
		goto free_lsb_msn;
	}

	/* create the LSB decoding context for the innermost TTL/HL */
	tcp_context->ttl_hl_lsb_ctxt = rohc_lsb_new(8);
	if(tcp_context->ttl_hl_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the innermost "
		           "TTL/HL");
		goto free_lsb_ip_id;
	}

	/* create the LSB decoding context for the TCP window */
	tcp_context->window_lsb_ctxt = rohc_lsb_new(16);
	if(tcp_context->window_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the TCP window");
		goto free_lsb_ttl_hl;
	}

	/* create the LSB decoding context for the sequence number */
	tcp_context->seq_lsb_ctxt = rohc_lsb_new(32);
	if(tcp_context->seq_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the sequence "
		           "number");
		goto free_lsb_window;
	}

	/* create the LSB decoding context for the scaled sequence number */
	tcp_context->seq_scaled_lsb_ctxt = rohc_lsb_new(32);
	if(tcp_context->seq_scaled_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the scaled "
		           "sequence number");
		goto free_lsb_seq;
	}

	/* create the LSB decoding context for the ACK number */
	tcp_context->ack_lsb_ctxt = rohc_lsb_new(32);
	if(tcp_context->ack_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the ACK "
		           "number");
		goto free_lsb_scaled_seq;
	}

	/* create the LSB decoding context for the scaled acknowledgment number */
	tcp_context->ack_scaled_lsb_ctxt = rohc_lsb_new(32);
	if(tcp_context->ack_scaled_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the scaled "
		           "acknowledgment number");
		goto free_lsb_ack;
	}

	/* the TCP source and destination ports will be initialized
	 * with the IR packets */
	tcp_context->tcp_src_port = 0xFFFF;
	tcp_context->tcp_dst_port = 0xFFFF;

	memset(tcp_context->tcp_options_list, 0xff, ROHC_TCP_OPTS_MAX);
	memset(tcp_context->tcp_opts_list_struct, 0xff, ROHC_TCP_OPTS_MAX);

	/* create the LSB decoding context for the TCP option Timestamp echo
	 * request */
	tcp_context->opt_ts_req_lsb_ctxt = rohc_lsb_new(32);
	if(tcp_context->opt_ts_req_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the TCP "
		           "option Timestamp echo request");
		goto free_lsb_scaled_ack;
	}

	/* create the LSB decoding context for the TCP option Timestamp echo
	 * reply */
	tcp_context->opt_ts_rep_lsb_ctxt = rohc_lsb_new(32);
	if(tcp_context->opt_ts_rep_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for the TCP "
		           "option Timestamp echo reply");
		goto free_lsb_ts_opt_req;
	}

	return tcp_context;

free_lsb_ts_opt_req:
	rohc_lsb_free(tcp_context->opt_ts_req_lsb_ctxt);
free_lsb_scaled_ack:
	rohc_lsb_free(tcp_context->ack_scaled_lsb_ctxt);
free_lsb_ack:
	rohc_lsb_free(tcp_context->ack_lsb_ctxt);
free_lsb_scaled_seq:
	rohc_lsb_free(tcp_context->seq_scaled_lsb_ctxt);
free_lsb_seq:
	rohc_lsb_free(tcp_context->seq_lsb_ctxt);
free_lsb_window:
	rohc_lsb_free(tcp_context->window_lsb_ctxt);
free_lsb_ttl_hl:
	rohc_lsb_free(tcp_context->ttl_hl_lsb_ctxt);
free_lsb_ip_id:
	rohc_lsb_free(tcp_context->ip_id_lsb_ctxt);
free_lsb_msn:
	rohc_lsb_free(tcp_context->msn_lsb_ctxt);
destroy_context:
	zfree(tcp_context);
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
	struct d_tcp_context *tcp_context = (struct d_tcp_context *) context;

	/* destroy the LSB decoding context for the TCP option Timestamp echo
	 * request */
	rohc_lsb_free(tcp_context->opt_ts_req_lsb_ctxt);
	/* destroy the LSB decoding context for the TCP option Timestamp echo
	 * reply */
	rohc_lsb_free(tcp_context->opt_ts_rep_lsb_ctxt);
	/* destroy the LSB decoding context for the scaled acknowledgment number */
	rohc_lsb_free(tcp_context->ack_scaled_lsb_ctxt);
	/* destroy the LSB decoding context for the ACK number */
	rohc_lsb_free(tcp_context->ack_lsb_ctxt);
	/* destroy the LSB decoding context for the scaled sequence number */
	rohc_lsb_free(tcp_context->seq_scaled_lsb_ctxt);
	/* destroy the LSB decoding context for the sequence number */
	rohc_lsb_free(tcp_context->seq_lsb_ctxt);
	/* destroy the LSB decoding context for the TCP window */
	rohc_lsb_free(tcp_context->window_lsb_ctxt);
	/* destroy the LSB decoding context for the innermost TTL/HL */
	rohc_lsb_free(tcp_context->ttl_hl_lsb_ctxt);
	/* destroy the LSB decoding context for the innermost IP-ID */
	rohc_lsb_free(tcp_context->ip_id_lsb_ctxt);
	/* destroy the LSB decoding context for the MSN */
	rohc_lsb_free(tcp_context->msn_lsb_ctxt);

	/* free the TCP decompression context itself */
	free(tcp_context);
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
	struct d_tcp_context *tcp_context = context->specific;
	rohc_packet_t type;

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
			const ip_context_t *innermost_hdr_ctxt;
			if(context->num_recv_packets <= 0)
			{
				rohc_decomp_warn(context, "non IR(-DYN) packet received without "
				                 "initialized context: cannot determine the packet "
				                 "type");
				goto error;
			}
			assert(tcp_context->ip_contexts_nr > 0);
			innermost_hdr_ctxt =
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
 * Steps:
 *  \li A. Parsing of ROHC header
 *  \li B. For IR and IR-DYN packet, check for correct compressed header (CRC)
 *  \li C. Decode extracted bits
 *  \li D. Build uncompressed headers (and check for correct decompression
 *         for UO* packets)
 *  \li E. Copy the payload (if any)
 *  \li F. Update the compression context
 *
 * Steps C and D may be repeated if packet or context repair is attempted
 * upon CRC failure.
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
	struct d_tcp_context *tcp_context = context->specific;

	struct rohc_tcp_extr_bits bits; /* bits extracted from ROHC packet */
	struct rohc_tcp_decoded_values decoded; /* values decoded from context & bits */

	/* length of the parsed ROHC header and of the uncompressed headers */
	size_t rohc_hdr_len;
	size_t uncomp_hdr_len;

	/* ROHC and uncompressed payloads (they are the same) */
	const uint8_t *payload_data;
	size_t payload_len;

	/* Whether to attempt packet correction or not */
	bool try_decoding_again;

	/* helper variables for values returned by functions */
	bool parsing_ok;
	bool decode_ok;
	rohc_status_t build_ret;

	assert(add_cid_len == 0 || add_cid_len == 1);
	assert(large_cid_len <= 2);
	assert((*packet_type) != ROHC_PACKET_UNKNOWN);

	/* remember the arrival time of the packet (used for repair upon CRC
	 * failure for example) */
	tcp_context->cur_arrival_time = rohc_packet.time;


	/* A. Parsing of ROHC base header, extension header and tail of header */

	/* let's parse the packet! */
	parsing_ok = d_tcp_parse_packet(context, rohc_packet, large_cid_len,
	                                *packet_type, &bits, &rohc_hdr_len);
	if(!parsing_ok)
	{
		rohc_decomp_warn(context, "failed to parse the %s header",
		                 rohc_get_packet_descr(*packet_type));
		goto error_malformed;
	}

	/* ROHC base header and its optional extension is now fully parsed,
	 * remaining data is the payload */
	payload_data = rohc_buf_data(rohc_packet) + rohc_hdr_len;
	payload_len = rohc_packet.len - rohc_hdr_len;
	rohc_decomp_debug(context, "ROHC payload (length = %zu bytes) starts at "
	                  "offset %zu", payload_len, rohc_hdr_len);


	/*
	 * B. Check for correct compressed header (CRC)
	 *
	 * Use the CRC on compressed headers to check whether IR header was
	 * correctly received. The optional Add-CID is part of the CRC.
	 */

	if((*packet_type) == ROHC_PACKET_IR || (*packet_type) == ROHC_PACKET_IR_DYN)
	{
		const bool crc_ok =
			rohc_decomp_check_ir_crc(decomp, context,
			                         rohc_buf_data(rohc_packet) - add_cid_len,
			                         add_cid_len + rohc_hdr_len,
			                         large_cid_len, add_cid_len, bits.crc);
		if(!crc_ok)
		{
			rohc_decomp_warn(context, "CRC detected a transmission failure for "
			                 "%s packet", rohc_get_packet_descr(*packet_type));
#if ROHC_EXTRA_DEBUG == 1
			rohc_dump_buf(decomp->trace_callback, decomp->trace_callback_priv,
			              ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING, "ROHC header",
			              rohc_buf_data(rohc_packet) - add_cid_len,
			              rohc_hdr_len + add_cid_len);
#endif
			goto error_crc;
		}

		/* reset the correction attempt */
		tcp_context->correction_counter = 0;
	}


	try_decoding_again = false;
	do
	{
		if(try_decoding_again)
		{
			rohc_decomp_warn(context, "CID %zu: CRC repair: try decoding packet "
			                 "again with new assumptions", context->cid);
		}


		/* C. Decode extracted bits
		 *
		 * All bits are now extracted from the packet, let's decode them.
		 */

		decode_ok =
			d_tcp_decode_values_from_bits(context, bits, payload_len, &decoded);
		if(!decode_ok)
		{
			rohc_decomp_warn(context, "failed to decode values from bits "
			                 "extracted from ROHC header");
			goto error;
		}


		/* D. Build uncompressed headers & check for correct decompression
		 *
		 * All fields are now decoded, let's build the uncompressed headers.
		 *
		 * Use the CRC on decompressed headers to check whether decompression was
		 * correct.
		 */

		/* build the uncompressed headers */
		build_ret = d_tcp_build_uncomp_hdrs(decomp, context, *packet_type, decoded,
		                                    payload_len, bits.crc_type, bits.crc,
		                                    uncomp_packet, &uncomp_hdr_len);
		if(build_ret == ROHC_STATUS_OK)
		{
			/* uncompressed headers successfully built and CRC is correct,
			 * no need to try decoding with different values */
			rohc_buf_pull(uncomp_packet, uncomp_hdr_len);

			if(tcp_context->crc_corr == ROHC_DECOMP_CRC_CORR_SN_NONE)
			{
				rohc_decomp_debug(context, "CRC is correct");
			}
			else
			{
				rohc_decomp_debug(context, "CID %zu: CRC repair: CRC is correct",
				                  context->cid);
				try_decoding_again = false;
			}
		}
		else if(build_ret == ROHC_STATUS_OUTPUT_TOO_SMALL)
		{
			rohc_decomp_warn(context, "CID %zu: failed to build uncompressed "
			                 "headers: output buffer too small", context->cid);
			goto error_output_too_small;
		}
		else if(build_ret != ROHC_STATUS_BAD_CRC)
		{
			/* uncompressed headers cannot be built, stop decoding */
			rohc_decomp_warn(context, "CID %zu: failed to build uncompressed "
			                 "headers", context->cid);
#if ROHC_EXTRA_DEBUG == 1
			rohc_dump_packet(decomp->trace_callback, decomp->trace_callback_priv,
			                 ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING,
			                 "compressed headers", rohc_packet);
#endif
			goto error;
		}
		else
		{
			/* uncompressed headers successfully built but CRC is incorrect,
			 * try decoding with different values (repair) */

			/* CRC for IR and IR-DYN packets checked before, so cannot fail here */
			assert((*packet_type) != ROHC_PACKET_IR);
			assert((*packet_type) != ROHC_PACKET_IR_DYN);

			rohc_decomp_warn(context, "CID %zu: failed to build uncompressed "
			                 "headers (CRC failure)", context->cid);

			/* attempt a context/packet repair */
			try_decoding_again = d_tcp_attempt_repair(decomp, context, &bits);

			/* report CRC failure if attempt is not possible */
			if(!try_decoding_again)
			{
				/* uncompressed headers successfully built, CRC is incorrect, repair
				 * was disabled or attempted without any success, so give up */
				rohc_decomp_warn(context, "CID %zu: failed to build uncompressed "
				                 "headers (CRC failure)", context->cid);
#if ROHC_EXTRA_DEBUG == 1
				rohc_dump_packet(decomp->trace_callback, decomp->trace_callback_priv,
				                 ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING,
				                 "compressed headers", rohc_packet);
#endif
				goto error_crc;
			}
		}
	}
	while(try_decoding_again);

	/* after CRC failure, if the SN value seems to be correctly guessed, we must
	 * wait for 3 CRC-valid packets before the correction is approved. Two
	 * packets are therefore thrown away. */
	if(tcp_context->crc_corr != ROHC_DECOMP_CRC_CORR_SN_NONE)
	{
		if(tcp_context->correction_counter > 1)
		{
			/* update context with decoded values even if we drop the packet */
			d_tcp_update_context(context, decoded, payload_len);

			tcp_context->correction_counter--;
			rohc_decomp_warn(context, "CID %zu: CRC repair: throw away packet, "
			                 "still %zu CRC-valid packets required",
			                 context->cid, tcp_context->correction_counter);

			goto error_crc;
		}
		else if(tcp_context->correction_counter == 1)
		{
			rohc_decomp_warn(context, "CID %zu: CRC repair: correction is "
			                 "successful, keep packet", context->cid);
			context->corrected_crc_failures++;
			switch(tcp_context->crc_corr)
			{
				case ROHC_DECOMP_CRC_CORR_SN_WRAP:
					context->corrected_sn_wraparounds++;
					break;
				case ROHC_DECOMP_CRC_CORR_SN_UPDATES:
					context->corrected_wrong_sn_updates++;
					break;
				case ROHC_DECOMP_CRC_CORR_SN_NONE:
				default:
					rohc_error(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					           "CID %zu: CRC repair: unsupported repair algorithm %d",
					           context->cid, tcp_context->crc_corr);
					assert(0);
					goto error;
			}
			tcp_context->crc_corr = ROHC_DECOMP_CRC_CORR_SN_NONE;
			tcp_context->correction_counter--;
		}
	}


	/* E. Copy the payload (if any) */

	if((rohc_hdr_len + payload_len) != rohc_packet.len)
	{
		rohc_decomp_warn(context, "ROHC %s header (%zu bytes) and payload "
		                 "(%zu bytes) do not match the full ROHC packet "
		                 "(%zu bytes)", rohc_get_packet_descr(*packet_type),
		                 rohc_hdr_len, payload_len, rohc_packet.len);
		goto error;
	}
	if(rohc_buf_avail_len(*uncomp_packet) < payload_len)
	{
		rohc_decomp_warn(context, "uncompressed packet too small (%zu bytes "
		                 "max) for the %zu-byte payload",
		                 rohc_buf_avail_len(*uncomp_packet), payload_len);
		goto error_output_too_small;
	}
	if(payload_len != 0)
	{
		rohc_buf_append(uncomp_packet, payload_data, payload_len);
		rohc_buf_pull(uncomp_packet, payload_len);
	}
	/* unhide the uncompressed headers and payload */
	rohc_buf_push(uncomp_packet, uncomp_hdr_len + payload_len);
	rohc_decomp_debug(context, "uncompressed packet length = %zu bytes",
	                  uncomp_packet->len);


	/* F. Update the compression context
	 *
	 * Once CRC check is done, update the compression context with the values
	 * that were decoded earlier.
	 *
	 * TODO: check what fields shall be updated in the context
	 */

	/* we are either already in full context state or we can transit
	 * through it */
	if(context->state != ROHC_DECOMP_STATE_FC)
	{
		rohc_decomp_debug(context, "change from state %d to state %d",
		                  context->state, ROHC_DECOMP_STATE_FC);
		context->state = ROHC_DECOMP_STATE_FC;
	}

	/* update context with decoded values */
	d_tcp_update_context(context, decoded, payload_len);

	/* update statistics */
	rohc_decomp_stats_add_success(context, rohc_hdr_len, uncomp_hdr_len);

	/* decompression is successful */
	return ROHC_STATUS_OK;

error:
	return ROHC_STATUS_ERROR;
error_output_too_small:
	return ROHC_STATUS_OUTPUT_TOO_SMALL;
error_crc:
	return ROHC_STATUS_BAD_CRC;
error_malformed:
	return ROHC_STATUS_MALFORMED;
}


/**
 * @brief Parse the given ROHC packet for the TCP profile
 *
 * @param context            The decompression context
 * @param rohc_packet        The ROHC packet to decode
 * @param large_cid_len      The length of the optional large CID field
 * @param packet_type        The type of the ROHC packet to parse
 * @param[out] bits          The bits extracted from the CO packet
 * @param[out] rohc_hdr_len  The length of the ROHC header (in bytes)
 * @return                   true if parsing was successful,
 *                           false if packet was malformed
 */
static bool d_tcp_parse_packet(struct rohc_decomp_ctxt *const context,
                               const struct rohc_buf rohc_packet,
                               const size_t large_cid_len,
                               const rohc_packet_t packet_type,
                               struct rohc_tcp_extr_bits *const bits,
                               size_t *const rohc_hdr_len)
{
	bool parsing_ok;

	rohc_decomp_debug(context, "parse packet type '%s' (%d)",
	                  rohc_get_packet_descr(packet_type), packet_type);

	rohc_decomp_debug(context, "rohc_length = %zu, large_cid_len = %zu",
	                  rohc_packet.len, large_cid_len);

	/* reset all extracted bits */
	d_tcp_reset_extr_bits(context, bits);

	if(packet_type == ROHC_PACKET_IR)
	{
		/* decode IR packet */
		parsing_ok = d_tcp_parse_ir(context, rohc_buf_data(rohc_packet),
		                            rohc_packet.len, large_cid_len,
		                            bits, rohc_hdr_len);
	}
	else if(packet_type == ROHC_PACKET_IR_DYN)
	{
		/* decode IR-DYN packet */
		parsing_ok = d_tcp_parse_irdyn(context, rohc_buf_data(rohc_packet),
		                               rohc_packet.len, large_cid_len,
		                               bits, rohc_hdr_len);
	}
	else
	{
		/* decode CO packet */
		parsing_ok = d_tcp_parse_CO(context, rohc_buf_data(rohc_packet),
		                            rohc_packet.len, large_cid_len, packet_type,
		                            bits, rohc_hdr_len);
	}

	return parsing_ok;
}


/**
 * @brief Parse the given IR packet for the TCP profile
 *
 * @param context            The decompression context
 * @param rohc_packet        The ROHC packet to decode
 * @param rohc_length        The length of the ROHC packet to decode
 * @param large_cid_len      The length of the optional large CID field
 * @param[out] bits          The bits extracted from the IR packet
 * @param[out] rohc_hdr_len  The length of the ROHC header (in bytes)
 * @return                   true if parsing was successful,
 *                           false if packet was malformed
 */
static bool d_tcp_parse_ir(struct rohc_decomp_ctxt *const context,
                           const unsigned char *const rohc_packet,
                           const size_t rohc_length,
                           const size_t large_cid_len,
                           struct rohc_tcp_extr_bits *const bits,
                           size_t *const rohc_hdr_len)
{
	const uint8_t *remain_data;
	size_t remain_len;
	size_t static_chain_len;
	size_t dyn_chain_len;

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
	bits->crc_type = ROHC_CRC_TYPE_NONE;
	bits->crc = remain_data[0];
	bits->crc_nr = 8;
	remain_data++;
	remain_len--;

	/* parse static chain */
	if(!tcp_parse_static_chain(context, remain_data, remain_len,
	                           bits, &static_chain_len))
	{
		rohc_decomp_warn(context, "failed to parse the static chain");
		goto error;
	}
	remain_data += static_chain_len;
	remain_len -= static_chain_len;

	/* parse dynamic chain */
	if(!tcp_parse_dyn_chain(context, remain_data, remain_len, bits, &dyn_chain_len))
	{
		rohc_decomp_warn(context, "failed to parse the dynamic chain");
		goto error;
	}
	remain_data += dyn_chain_len;
	remain_len -= dyn_chain_len;

	*rohc_hdr_len = remain_data - rohc_packet;
	return true;

error:
	return false;
}


/**
 * @brief Parse othe given IR-DYN packet for the TCP profile
 *
 * @param context            The decompression context
 * @param rohc_packet        The ROHC packet to decode
 * @param rohc_length        The length of the ROHC packet to decode
 * @param large_cid_len      The length of the optional large CID field
 * @param[out] bits          The bits extracted from the IR-DYN packet
 * @param[out] rohc_hdr_len  The length of the ROHC header (in bytes)
 * @return                   true if parsing was successful,
 *                           false if packet was malformed
 */
static bool d_tcp_parse_irdyn(struct rohc_decomp_ctxt *const context,
                              const unsigned char *const rohc_packet,
                              const size_t rohc_length,
                              const size_t large_cid_len,
                              struct rohc_tcp_extr_bits *const bits,
                              size_t *const rohc_hdr_len)
{
	const uint8_t *remain_data;
	size_t remain_len;
	size_t dyn_chain_len;

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
	bits->crc_type = ROHC_CRC_TYPE_NONE;
	bits->crc = remain_data[0];
	bits->crc_nr = 8;
	remain_data++;
	remain_len--;

	/* parse dynamic chain */
	if(!tcp_parse_dyn_chain(context, remain_data, remain_len, bits, &dyn_chain_len))
	{
		rohc_decomp_warn(context, "failed to parse the dynamic chain");
		goto error;
	}
	remain_data += dyn_chain_len;
	remain_len -= dyn_chain_len;

	*rohc_hdr_len = remain_data - rohc_packet;
	return true;

error:
	return false;
}


/**
 * @brief Uncompress a generic TCP option
 *
 * See RFC4996 page 67
 *
 * @param ptr              Pointer to the compressed TCP option
 * @param pOptions         Pointer to the uncompressed TCP option
 * @param opts_remain_len  The remaining length for decoded options (in bytes)
 * @return                 Pointer to the next compressed value
 */
static const uint8_t * d_tcp_opt_generic(const uint8_t *ptr,
                                         uint8_t **pOptions,
                                         const size_t opts_remain_len __attribute__((unused)))
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
 * @brief Parse the given CO packet for the TCP profile
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
 * @param context            The decompression context
 * @param rohc_packet        The ROHC packet to decode
 * @param rohc_length        The length of the ROHC packet
 * @param large_cid_len      The length of the optional large CID field
 * @param packet_type        The type of the ROHC packet to parse
 * @param[out] bits          The bits extracted from the CO packet
 * @param[out] rohc_hdr_len  The length of the ROHC header (in bytes)
 * @return                   true if parsing was successful,
 *                           false if packet was malformed
 */
static bool d_tcp_parse_CO(struct rohc_decomp_ctxt *const context,
                           const unsigned char *const rohc_packet,
                           const size_t rohc_length,
                           const size_t large_cid_len,
                           const rohc_packet_t packet_type,
                           struct rohc_tcp_extr_bits *const bits,
                           size_t *const rohc_hdr_len)
{
	unsigned char *packed_rohc_packet = malloc(5000); // TODO: change that
	struct d_tcp_context *const tcp_context = context->specific;
	int ret;

	/* remaining ROHC data not parsed yet */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	const ip_context_t *ip_inner_context;
	struct rohc_tcp_extr_ip_bits *inner_ip_bits;
	tcp_ip_id_behavior_t innermost_ip_id_behavior;

	assert(rohc_packet != NULL);
	assert(large_cid_len <= 2);
	assert(packet_type != ROHC_PACKET_UNKNOWN);

#ifndef __clang_analyzer__ /* silent warning about value never read */
	rohc_remain_data = (unsigned char *) rohc_packet;
#endif
	rohc_remain_len = rohc_length;

	rohc_decomp_debug(context, "large_cid_len = %zu, rohc_length = %zu",
	                  large_cid_len, rohc_length);

	assert(tcp_context->ip_contexts_nr > 0);
	ip_inner_context = &(tcp_context->ip_contexts[tcp_context->ip_contexts_nr - 1]);
	inner_ip_bits = &(bits->ip[bits->ip_nr - 1]);

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
	*rohc_hdr_len = 0;

	/* decode the packet type we detected earlier */
	rohc_decomp_debug(context, "decode %s packet (type %d)",
	                  rohc_get_packet_descr(packet_type), packet_type);
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
			bits->seq.bits = (rnd_1->seq_num1 << 16) | rohc_ntoh16(rnd_1->seq_num2);
			bits->seq.bits_nr = 18;
			bits->seq.p = 65535;
			bits->msn.bits = rnd_1->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = rnd_1->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = rnd_1->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(rnd_1_t);
			rohc_remain_len -= sizeof(rnd_1_t);
			*rohc_hdr_len += sizeof(rnd_1_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			bits->seq_scaled.bits = rnd_2->seq_num_scaled;
			bits->seq_scaled.bits_nr = 4;
			bits->msn.bits = rnd_2->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = rnd_2->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = rnd_2->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(rnd_2_t);
			rohc_remain_len -= sizeof(rnd_2_t);
			*rohc_hdr_len += sizeof(rnd_2_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			bits->ack.bits = (rnd_3->ack_num1 << 1) | rnd_3->ack_num2;
			bits->ack.bits_nr = 15;
			bits->ack.p = 8191;
			bits->msn.bits = rnd_3->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = rnd_3->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = rnd_3->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(rnd_3_t);
			rohc_remain_len -= sizeof(rnd_3_t);
			*rohc_hdr_len += sizeof(rnd_3_t);
			assert((*rohc_hdr_len) <= rohc_length);
			break;
		}
		case ROHC_PACKET_TCP_RND_4:
		{
			const rnd_4_t *const rnd_4 = (rnd_4_t *) rohc_remain_data;

			/* rnd_4 packet cannot be used if ack_stride is zero (it is used as
			 * divisor to compute the scaled acknowledgment number) */
			if(tcp_context->ack_stride == 0)
			{
				rohc_decomp_warn(context, "cannot decode rnd_4 packet with "
				                 "ack_stride.UVALUE == 0");
				goto error;
			}

			/* check if the ROHC packet is large enough to parse rnd_4 */
			if(rohc_remain_len < sizeof(rnd_4_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for rnd_4 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(rnd_4->discriminator == 0x0d); /* '1101' */
			bits->ack_scaled.bits = rnd_4->ack_num_scaled;
			bits->ack_scaled.bits_nr = 4;
			bits->msn.bits = rnd_4->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = rnd_4->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = rnd_4->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(rnd_4_t);
			rohc_remain_len -= sizeof(rnd_4_t);
			*rohc_hdr_len += sizeof(rnd_4_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			bits->psh_flag_bits = rnd_5->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->msn.bits = rnd_5->msn;
			bits->msn.bits_nr = 4;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = rnd_5->header_crc;
			bits->crc_nr = 3;
			bits->seq.bits = (rnd_5->seq_num1 << 9) |
			                 (rnd_5->seq_num2 << 1) |
			                 rnd_5->seq_num3;
			bits->seq.bits_nr = 14;
			bits->seq.p = 8191;
			bits->ack.bits = (rnd_5->ack_num1 << 8) | rnd_5->ack_num2;
			bits->ack.bits_nr = 15;
			bits->ack.p = 8191;

			rohc_remain_data += sizeof(rnd_5_t);
			rohc_remain_len -= sizeof(rnd_5_t);
			*rohc_hdr_len += sizeof(rnd_5_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = rnd_6->header_crc;
			bits->crc_nr = 3;
			bits->psh_flag_bits = rnd_6->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->ack.bits = rohc_ntoh16(rnd_6->ack_num);
			bits->ack.bits_nr = 16;
			bits->ack.p = 16383;
			bits->msn.bits = rnd_6->msn;
			bits->msn.bits_nr = 4;
			bits->seq_scaled.bits = rnd_6->seq_num_scaled;
			bits->seq_scaled.bits_nr = 4;

			rohc_remain_data += sizeof(rnd_6_t);
			rohc_remain_len -= sizeof(rnd_6_t);
			*rohc_hdr_len += sizeof(rnd_6_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			bits->ack.bits = (rnd_7->ack_num1 << 16) | rohc_ntoh16(rnd_7->ack_num2);
			bits->ack.bits_nr = 18;
			bits->ack.p = 65535;
			bits->window.bits = rohc_ntoh16(rnd_7->window);
			bits->window.bits_nr = 16;
			bits->msn.bits = rnd_7->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = rnd_7->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = rnd_7->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(rnd_7_t);
			rohc_remain_len -= sizeof(rnd_7_t);
			*rohc_hdr_len += sizeof(rnd_7_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			bits->rsf_flags_bits = rnd_8->rsf_flags;
			bits->rsf_flags_bits_nr = 2;
			bits->is_list_present = !!rnd_8->list_present;
			bits->crc_type = ROHC_CRC_TYPE_7;
			bits->crc = rnd_8->header_crc;
			bits->crc_nr = 7;
			bits->msn.bits = (rnd_8->msn1 << 3) | rnd_8->msn2;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = rnd_8->psh_flag;
			bits->psh_flag_bits_nr = 1;
			inner_ip_bits->ttl_hl.bits = rnd_8->ttl_hopl;
			inner_ip_bits->ttl_hl.bits_nr = 3;
			bits->ecn_used_bits = rnd_8->ecn_used;
			bits->ecn_used_bits_nr = 1;
			bits->seq.bits = rohc_ntoh16(rnd_8->seq_num);
			bits->seq.bits_nr = 16;
			bits->seq.p = 65535;
			bits->ack.bits = rohc_ntoh16(rnd_8->ack_num);
			bits->ack.bits_nr = 16;
			bits->ack.p = 16383;

			rohc_remain_data += sizeof(rnd_8_t);
			rohc_remain_len -= sizeof(rnd_8_t);
			*rohc_hdr_len += sizeof(rnd_8_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			inner_ip_bits->id.bits = seq_1->ip_id;
			inner_ip_bits->id.bits_nr = 4;
			inner_ip_bits->id.p = 3;
			bits->seq.bits = rohc_ntoh16(seq_1->seq_num);
			bits->seq.bits_nr = 16;
			bits->seq.p = 32767;
			bits->msn.bits = seq_1->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = seq_1->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = seq_1->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(seq_1_t);
			rohc_remain_len -= sizeof(seq_1_t);
			*rohc_hdr_len += sizeof(seq_1_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			inner_ip_bits->id.bits = (seq_2->ip_id1 << 4) | seq_2->ip_id2;
			inner_ip_bits->id.bits_nr = 7;
			inner_ip_bits->id.p = 3;
			bits->seq_scaled.bits = seq_2->seq_num_scaled;
			bits->seq_scaled.bits_nr = 4;
			bits->msn.bits = seq_2->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = seq_2->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = seq_2->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(seq_2_t);
			rohc_remain_len -= sizeof(seq_2_t);
			*rohc_hdr_len += sizeof(seq_2_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			inner_ip_bits->id.bits = seq_3->ip_id;
			inner_ip_bits->id.bits_nr = 4;
			inner_ip_bits->id.p = 3;
			bits->ack.bits = rohc_ntoh16(seq_3->ack_num);
			bits->ack.bits_nr = 16;
			bits->ack.p = 16383;
			bits->msn.bits = seq_3->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = seq_3->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = seq_3->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(seq_3_t);
			rohc_remain_len -= sizeof(seq_3_t);
			*rohc_hdr_len += sizeof(seq_3_t);
			assert((*rohc_hdr_len) <= rohc_length);
			break;
		}
		case ROHC_PACKET_TCP_SEQ_4:
		{
			const seq_4_t *const seq_4 = (seq_4_t *) rohc_remain_data;

			/* seq_4 packet cannot be used if ack_stride is zero (it is used as
			 * divisor to compute the scaled acknowledgment number) */
			if(tcp_context->ack_stride == 0)
			{
				rohc_decomp_warn(context, "cannot decode seq_4 packet with "
				                 "ack_stride.UVALUE == 0");
				goto error;
			}

			/* check if the ROHC packet is large enough to parse seq_4 */
			if(rohc_remain_len < sizeof(seq_4_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for seq_4 "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(seq_4->discriminator == 0x00); /* '0' */
			bits->ack_scaled.bits = seq_4->ack_num_scaled;
			bits->ack_scaled.bits_nr = 4;
			inner_ip_bits->id.bits = seq_4->ip_id;
			inner_ip_bits->id.bits_nr = 3;
			inner_ip_bits->id.p = 1;
			bits->msn.bits = seq_4->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = seq_4->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = seq_4->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(seq_4_t);
			rohc_remain_len -= sizeof(seq_4_t);
			*rohc_hdr_len += sizeof(seq_4_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			inner_ip_bits->id.bits = seq_5->ip_id;
			inner_ip_bits->id.bits_nr = 4;
			inner_ip_bits->id.p = 3;
			bits->ack.bits = rohc_ntoh16(seq_5->ack_num);
			bits->ack.bits_nr = 16;
			bits->ack.p = 16383;
			bits->seq.bits = rohc_ntoh16(seq_5->seq_num);
			bits->seq.bits_nr = 16;
			bits->seq.p = 32767;
			bits->msn.bits = seq_5->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = seq_5->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = seq_5->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(seq_5_t);
			rohc_remain_len -= sizeof(seq_5_t);
			*rohc_hdr_len += sizeof(seq_5_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			bits->seq_scaled.bits =
				(seq_6->seq_num_scaled1 << 1) | seq_6->seq_num_scaled2;
			bits->seq_scaled.bits_nr = 4;
			inner_ip_bits->id.bits = seq_6->ip_id;
			inner_ip_bits->id.bits_nr = 7;
			inner_ip_bits->id.p = 3;
			bits->ack.bits = rohc_ntoh16(seq_6->ack_num);
			bits->ack.bits_nr = 16;
			bits->ack.p = 16383;
			bits->msn.bits = seq_6->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = seq_6->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = seq_6->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(seq_6_t);
			rohc_remain_len -= sizeof(seq_6_t);
			*rohc_hdr_len += sizeof(seq_6_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			bits->window.bits =
				(seq_7->window1 << 11) | (seq_7->window2 << 3) | seq_7->window3;
			bits->window.bits_nr = 15;
			inner_ip_bits->id.bits = seq_7->ip_id;
			inner_ip_bits->id.bits_nr = 5;
			inner_ip_bits->id.p = 3;
			bits->ack.bits = rohc_ntoh16(seq_7->ack_num);
			bits->ack.bits_nr = 16;
			bits->ack.p = 32767;
			bits->msn.bits = seq_7->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = seq_7->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_3;
			bits->crc = seq_7->header_crc;
			bits->crc_nr = 3;

			rohc_remain_data += sizeof(seq_7_t);
			rohc_remain_len -= sizeof(seq_7_t);
			*rohc_hdr_len += sizeof(seq_7_t);
			assert((*rohc_hdr_len) <= rohc_length);
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
			inner_ip_bits->id.bits = seq_8->ip_id;
			inner_ip_bits->id.bits_nr = 4;
			inner_ip_bits->id.p = 3;
			bits->is_list_present = !!seq_8->list_present;
			bits->crc_type = ROHC_CRC_TYPE_7;
			bits->crc = seq_8->header_crc;
			bits->crc_nr = 7;
			bits->msn.bits = seq_8->msn;
			bits->msn.bits_nr = 4;
			bits->psh_flag_bits = seq_8->psh_flag;
			bits->psh_flag_bits_nr = 1;
			inner_ip_bits->ttl_hl.bits = seq_8->ttl_hopl;
			inner_ip_bits->ttl_hl.bits_nr = 3;
			bits->ecn_used_bits = seq_8->ecn_used;
			bits->ecn_used_bits_nr = 1;
			bits->ack.bits = (seq_8->ack_num1 << 8) | seq_8->ack_num2;
			bits->ack.bits_nr = 15;
			bits->ack.p = 8191;
			bits->rsf_flags_bits = seq_8->rsf_flags;
			bits->rsf_flags_bits_nr = 2;
			bits->seq.bits = (seq_8->seq_num1 << 8) | seq_8->seq_num2;
			bits->seq.bits_nr = 14;
			bits->seq.p = 8191;

			rohc_remain_data += sizeof(seq_8_t);
			rohc_remain_len -= sizeof(seq_8_t);
			*rohc_hdr_len += sizeof(seq_8_t);
			assert((*rohc_hdr_len) <= rohc_length);
			break;
		}
		case ROHC_PACKET_TCP_CO_COMMON:
		{
			const co_common_t *const co_common =
				(co_common_t *) rohc_remain_data;

			/* check if the ROHC packet is large enough to parse co_common */
			if(rohc_remain_len < sizeof(co_common_t))
			{
				rohc_decomp_warn(context, "ROHC packet too small for co_common "
				                 "(len = %zu)", rohc_remain_len);
				goto error;
			}

			assert(co_common->discriminator == 0x7d); /* '1111101' */
			bits->ttl_irregular_chain_flag = !!(co_common->ttl_hopl_outer_flag);
			bits->ack_flag_bits = co_common->ack_flag;
			bits->ack_flag_bits_nr = 1;
			bits->psh_flag_bits = co_common->psh_flag;
			bits->psh_flag_bits_nr = 1;
			bits->rsf_flags_bits = co_common->rsf_flags;
			bits->rsf_flags_bits_nr = 2;
			bits->msn.bits = co_common->msn;
			bits->msn.bits_nr = 4;
			bits->is_list_present = !!co_common->list_present;
			inner_ip_bits->id_behavior = co_common->ip_id_behavior;
			inner_ip_bits->id_behavior_nr = 2;
			bits->urg_flag_bits = co_common->urg_flag;
			bits->urg_flag_bits_nr = 1;
			bits->crc_type = ROHC_CRC_TYPE_7;
			bits->crc = co_common->header_crc;
			bits->crc_nr = 7;

			rohc_remain_data += sizeof(co_common_t);
			rohc_remain_len -= sizeof(co_common_t);
			*rohc_hdr_len += sizeof(co_common_t);
			assert((*rohc_hdr_len) <= rohc_length);
			rohc_decomp_debug(context, "ROHC co_common base header = %zu bytes",
			                  *rohc_hdr_len);

			/* sequence number */
			ret = variable_length_32_dec(rohc_remain_data, rohc_remain_len,
			                             co_common->seq_indicator, &bits->seq);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "variable_length_32(seq_number) failed");
				goto error;
			}
			rohc_decomp_debug(context, "found %zu bits of sequence number encoded "
			                  "on %d bytes", bits->seq.bits_nr, ret);
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
			*rohc_hdr_len += ret;

			/* ACK number */
			if(co_common->ack_indicator != 0)
			{
				rohc_decomp_debug(context, "ACK flag not set, but indicator for "
				                  "ACK number is %u instead of 0",
				                  co_common->ack_indicator);
			}
			ret = variable_length_32_dec(rohc_remain_data, rohc_remain_len,
			                             co_common->ack_indicator, &bits->ack);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "variable_length_32(ack_number) failed");
				goto error;
			}
			rohc_decomp_debug(context, "found %zu bits of acknowledgment number "
			                  "encoded on %d bytes", bits->ack.bits_nr, ret);
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
			*rohc_hdr_len += ret;

			/* ACK stride */
			ret = d_static_or_irreg16(rohc_remain_data, rohc_remain_len,
			                          co_common->ack_stride_indicator,
			                          &bits->ack_stride);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "static_or_irreg(ack_stride) failed");
				goto error;
			}
			rohc_decomp_debug(context, "found %zu bits of ACK stride encoded on "
			                  "%d bytes", bits->ack_stride.bits_nr, ret);
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
			*rohc_hdr_len += ret;

			/* window */
			ret = d_static_or_irreg16(rohc_remain_data, rohc_remain_len,
			                          co_common->window_indicator, &bits->window);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "static_or_irreg(window) failed");
				goto error;
			}
			rohc_decomp_debug(context, "found %zu bits of TCP window encoded on "
			                  "%d bytes", bits->window.bits_nr, ret);
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
			*rohc_hdr_len += ret;

			/* IP-ID behavior */
			if((co_common->ip_id_behavior == IP_ID_BEHAVIOR_SEQ ||
			    co_common->ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP) &&
			   ip_inner_context->ctxt.vx.version != IPV4)
			{
				rohc_decomp_warn(context, "packet and context mismatch: co_common "
				                 "packet advertizes that innermost IP-ID behaves "
				                 "as %s but innermost IP is IPv6 according to "
				                 "context",
				                 tcp_ip_id_behavior_get_descr(co_common->ip_id_behavior));
				goto error;
			}
			ret = d_optional_ip_id_lsb(context, rohc_remain_data, rohc_remain_len,
			                           co_common->ip_id_behavior,
			                           co_common->ip_id_indicator, &inner_ip_bits->id);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "optional_ip_id_lsb(ip_id) failed");
				goto error;
			}
			rohc_decomp_debug(context, "found %zu bits of innermost IP-ID encoded "
			                  "on %d bytes", inner_ip_bits->id.bits_nr, ret);
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
			*rohc_hdr_len += ret;

			/* URG pointer */
			ret = d_static_or_irreg16(rohc_remain_data, rohc_remain_len,
			                          co_common->urg_ptr_present, &bits->urg_ptr);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "static_or_irreg(urg_ptr) failed");
				goto error;
			}
			rohc_decomp_debug(context, "found %zu bits of TCP URG pointer encoded "
			                  "on %d bytes", bits->urg_ptr.bits_nr, ret);
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
			*rohc_hdr_len += ret;

			/* reserved field shall be zero */
			if(co_common->reserved != 0)
			{
				rohc_decomp_warn(context, "malformed ROHC co_common packet: "
				                 "reserved field shall be zero but it is %u",
				                 co_common->reserved);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
				goto error;
#endif
			}

			/* ECN */
			bits->ecn_used_bits = co_common->ecn_used;
			bits->ecn_used_bits_nr = 1;

			/* DSCP */
			if(co_common->dscp_present == 1)
			{
				uint8_t dscp_padding;

				if(rohc_remain_len < 1)
				{
					rohc_decomp_warn(context, "ROHC packet too small for DSCP "
					                 "(len = %zu)", rohc_remain_len);
					goto error;
				}

				inner_ip_bits->dscp_bits = (rohc_remain_data[0] >> 2) & 0x3f;
				inner_ip_bits->dscp_bits_nr = 6;
				rohc_decomp_debug(context, "found %zu bits of innermost DSCP "
				                  "encoded on %d bytes", inner_ip_bits->dscp_bits_nr, ret);
				dscp_padding = rohc_remain_data[0] & 0x3;
				rohc_remain_data++;
				rohc_remain_len--;
				(*rohc_hdr_len)++;

				/* padding field shall be zero */
				if(dscp_padding != 0)
				{
					rohc_decomp_warn(context, "malformed ROHC co_common packet: "
					                 "DSCP padding shall be zero but it is %u",
					                 dscp_padding);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
					goto error;
#endif
				}
			}

			/* DF */
			if(ip_inner_context->ctxt.vx.version == IPV4)
			{
				inner_ip_bits->df = co_common->df;
				inner_ip_bits->df_nr = 1;
				rohc_decomp_debug(context, "found %zu bits of innermost DF "
				                  "encoded on %d bytes", inner_ip_bits->df_nr, ret);
			}

			/* TTL / HL */
			ret = d_static_or_irreg8(rohc_remain_data, rohc_remain_len,
			                         co_common->ttl_hopl_present,
			                         &inner_ip_bits->ttl_hl);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "static_or_irreg(ttl) failed");
				goto error;
			}
			rohc_decomp_debug(context, "found %zu bits of innermost TTL/HL encoded "
			                  "on %d bytes", inner_ip_bits->ttl_hl.bits_nr, ret);
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
			*rohc_hdr_len += ret;
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
	              "ROHC base header", packed_rohc_packet, *rohc_hdr_len);

	/* innermost IP-ID behavior */
	if(inner_ip_bits->id_behavior_nr > 0)
	{
		assert(inner_ip_bits->id_behavior_nr == 2);
		innermost_ip_id_behavior = inner_ip_bits->id_behavior;
		rohc_decomp_debug(context, "use behavior '%s' defined in current packet "
		                  "for innermost IP-ID",
		                  tcp_ip_id_behavior_get_descr(innermost_ip_id_behavior));
	}
	else
	{
		innermost_ip_id_behavior = ip_inner_context->ctxt.vx.ip_id_behavior;
		rohc_decomp_debug(context, "use already-defined behavior '%s' for "
		                  "innermost IP-ID",
		                  tcp_ip_id_behavior_get_descr(innermost_ip_id_behavior));
	}

	/* parse the TCP options list if present */
	{
		const uint8_t *const rohc_opts_start = rohc_remain_data;
		const uint8_t *const rohc_opts_end =
				d_tcp_parse_options(context, rohc_remain_data, rohc_remain_len, bits);
		size_t rohc_opts_len = rohc_opts_end - rohc_opts_start;
		rohc_decomp_debug(context, "ROHC packet = header (%zu bytes) + "
		                  "options (%zu bytes) = %zu bytes", *rohc_hdr_len,
		                  rohc_opts_len, (*rohc_hdr_len) + rohc_opts_len);
		rohc_remain_data += rohc_opts_len;
		rohc_remain_len -= rohc_opts_len;
		*rohc_hdr_len += rohc_opts_len;
	}

	/* parse irregular chain */
	{
		size_t irreg_chain_len;

		if(!tcp_parse_irreg_chain(context, rohc_remain_data, rohc_remain_len,
		                          innermost_ip_id_behavior, bits, &irreg_chain_len))
		{
			rohc_decomp_warn(context, "failed to parse the irregular chain");
			goto error;
		}
		rohc_remain_data += irreg_chain_len;
		rohc_remain_len -= irreg_chain_len;
		*rohc_hdr_len += irreg_chain_len;
	}

	/* count large CID in header length now */
	*rohc_hdr_len += large_cid_len;
	assert((*rohc_hdr_len) <= rohc_length);

	free(packed_rohc_packet);
	return true;

error:
	free(packed_rohc_packet);
	return false;
}


/**
 * @brief Parse the TCP options
 *
 * @param context    The decompression context
 * @param data       The compressed TCP options
 * @param data_len   The length (in bytes) of compressed TCP options
 * @param[out] bits  The bits extracted from the compressed TCP options
 * @return           Pointer on data after the compressed TCP options,
 *                   NULL in case of malformed data
 */
static const uint8_t * d_tcp_parse_options(struct rohc_decomp_ctxt *const context,
                                           const uint8_t *const data,
                                           const size_t data_len,
                                           struct rohc_tcp_extr_bits *const bits)
{
	struct d_tcp_context *const tcp_context = context->specific;
	uint8_t present;
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
	size_t opt_padding_len;
	size_t opts_len = 0;

	assert(data != NULL);

	remain_data = (uint8_t *) data;
	remain_len = data_len;

	/* skip parsing if the compressed list of TCP options is not present */
	if(bits->is_list_present == 0)
	{
		rohc_decomp_debug(context, "no compressed list of TCP options found "
		                  "after the ROHC base header");
		for(i = 0; i < ROHC_TCP_OPTS_MAX; i++)
		{
			bits->is_tcp_opts_list_item_present[i] = false;
		}
		bits->opts_len = 0;
		return remain_data;
	}

	/* init pointer to destination TCP options */
	options = bits->opts;

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
		uint8_t opt_type;
		uint8_t opt_len;

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
			/* option content is present */
			bits->is_tcp_opts_list_item_present[i] = true;

			/* TODO: check ROHC packet length */
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:  // NOP
					opt_type = TCP_OPT_NOP;
					opt_len = 1;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte NOP option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = TCP_OPT_NOP;
					opts_len += opt_len;
					break;
				case TCP_INDEX_EOL:  // EOL
					opt_type = TCP_OPT_EOL;
					*(options++) = TCP_OPT_EOL;
					opt_len = 1;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte EOL option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					opts_len += opt_len;
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					opt_type = TCP_OPT_MAXSEG;
					opt_len = TCP_OLEN_MAXSEG;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte MSS option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
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
					opts_len += opt_len;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					opt_type = TCP_OPT_WINDOW;
					opt_len = TCP_OLEN_WINDOW;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte Window option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
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
					opts_len += opt_len;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
				{
					/* TS option cannot be present more than once in both option
					 * list of the co_common/seq_8/rnd_8 packets and in the irregular
					 * chain */
					if(bits->opt_ts.req.bits_nr > 0 || bits->opt_ts.rep.bits_nr > 0)
					{
						rohc_decomp_warn(context, "malformed irregular chain: "
						                 "unexpected duplicated TS option");
						goto error;
					}

					opt_type = TCP_OPT_TIMESTAMP;
					opt_len = TCP_OLEN_TIMESTAMP;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte Timestamp option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = TCP_OPT_TIMESTAMP;
					// Length
					*(options++) = TCP_OLEN_TIMESTAMP;

					/* parse TS echo request/reply fields */
					ret = d_tcp_ts_parse(context, compressed_options, comp_opts_len,
					                     &(bits->opt_ts));
					if(ret < 0)
					{
						rohc_decomp_warn(context, "failed to decompress TCP option "
						                 "TS echo request/reply fields");
						goto error;
					}
					bits->opt_ts.uncomp_opt_offset = opts_len + 2;
					compressed_options += ret;
					comp_opts_len -= ret;

					options += sizeof(struct tcp_option_timestamp);
					opts_len += opt_len;
					break;
				}
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					opt_type = TCP_OPT_SACK_PERMITTED;
					opt_len = TCP_OLEN_SACK_PERMITTED;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte SACK permitted option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = TCP_OPT_SACK_PERMITTED;
					// Length
					*(options++) = TCP_OLEN_SACK_PERMITTED;
					opts_len += opt_len;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					                   // TODO: save into context
				{
					size_t sack_opt_len;

					/* SACK option cannot be present more than once in both option
					 * list of the co_common/seq_8/rnd_8 packets and in the irregular
					 * chain */
					if(bits->opt_sack.blocks_nr > 0)
					{
						rohc_decomp_warn(context, "malformed irregular chain: "
						                 "unexpected duplicated SACK option");
						goto error;
					}

					opt_type = TCP_OPT_SACK;

					ret = d_tcp_sack_parse(context, compressed_options, comp_opts_len,
					                       &(bits->opt_sack));
					if(ret < 0)
					{
						rohc_decomp_warn(context, "failed to decompress TCP SACK "
						                 "option");
						goto error;
					}
					compressed_options += ret;
					comp_opts_len -= ret;

					sack_opt_len = 2 + sizeof(sack_block_t) * bits->opt_sack.blocks_nr;
					if(sack_opt_len > 0xff)
					{
						rohc_decomp_warn(context, "malformed ROHC packet: TCP SACK "
						                 "option is %zu-byte long according to ROHC "
						                 "packet, but maximum length is %u bytes",
						                 sack_opt_len, 0xff);
						goto error;
					}
					opt_len = sack_opt_len;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte SACK option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}

					options[0] = TCP_OPT_SACK;
					options[1] = opt_len;
					bits->opt_sack.uncomp_opt_offset = opts_len + 2;
					options += sack_opt_len;
					opts_len += opt_len;
					break;
				}
				default:  // Generic options
				{
					const uint8_t *const start_opt = options;
					size_t opt_remain_len = MAX_TCP_OPTIONS_LEN - opts_len;
					rohc_decomp_warn(context, "TCP option with index %u not "
					                 "handled", opt_idx);
					// TODO
					opt_type = 0xff;
					compressed_options =
						d_tcp_opt_generic(compressed_options, &options, opt_remain_len);
					if((options - start_opt) > 0xff)
					{
						rohc_decomp_warn(context, "malformed ROHC packet: TCP option "
						                 "is %ld-byte long according to ROHC packet, "
						                 "but maximum length is %u bytes",
						                 options - start_opt, 0xff);
						goto error;
					}
					opt_len = (options - start_opt);
					opts_len += opt_len;
					break;
				}
			}
			bits->tcp_opts_list_item_uncomp_length[i] = opt_len;
		}
		else
		{
			/* option content not present */
			bits->is_tcp_opts_list_item_present[i] = false;

			/* TODO: check ROHC packet length */
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:  // NOP
					opt_type = TCP_OPT_NOP;
					opt_len = 1;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte NOP option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = TCP_OPT_NOP;
					opts_len += opt_len;
					break;
				case TCP_INDEX_EOL:  // EOL
					opt_type = TCP_OPT_EOL;
					opt_len = 1;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte EOL option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = TCP_OPT_EOL;
					opts_len += opt_len;
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					opt_type = TCP_OPT_MAXSEG;
					opt_len = TCP_OLEN_MAXSEG;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte MSS option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = TCP_OPT_MAXSEG;
					// Length
					*(options++) = TCP_OLEN_MAXSEG;
					// Max segment size value
					memcpy(options, &tcp_context->tcp_option_maxseg, TCP_OLEN_MAXSEG - 2);
					options += TCP_OLEN_MAXSEG - 2;
					opts_len += opt_len;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					opt_type = TCP_OPT_WINDOW;
					opt_len = TCP_OLEN_WINDOW;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte Window option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = TCP_OPT_WINDOW;
					// Length
					*(options++) = TCP_OLEN_WINDOW;
					// Window scale value
					*(options++) = tcp_context->tcp_option_window;
					opts_len += opt_len;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
				{
					struct tcp_option_timestamp *const opt_ts_pkt =
						(struct tcp_option_timestamp *) (options + 2);

					opt_type = TCP_OPT_TIMESTAMP;
					opt_len = TCP_OLEN_TIMESTAMP;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte Timestamp option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = TCP_OPT_TIMESTAMP;
					// Length
					*(options++) = TCP_OLEN_TIMESTAMP;
					// Timestamp value
					opt_ts_pkt->ts = tcp_context->tcp_opt_ts.ts;
					opt_ts_pkt->ts_reply = tcp_context->tcp_opt_ts.ts_reply;
					options += TCP_OLEN_TIMESTAMP - 2;
					opts_len += opt_len;
					break;
				}
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					opt_type = TCP_OPT_SACK_PERMITTED;
					opt_len = TCP_OLEN_SACK_PERMITTED;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte SACK permitted option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = TCP_OPT_SACK_PERMITTED;
					opts_len++;
					// Length
					*(options++) = TCP_OLEN_SACK_PERMITTED;
					opts_len++;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					opt_type = TCP_OPT_SACK;
					if(tcp_context->tcp_opt_sack_length > (0xff - 2))
					{
						rohc_decomp_warn(context, "malformed ROHC packet: TCP SACK "
						                 "option is (%u+2)-byte long according to ROHC "
						                 "packet, but maximum length is %u bytes",
						                 tcp_context->tcp_opt_sack_length, 0xff);
						goto error;
					}
					opt_len = 2 + tcp_context->tcp_opt_sack_length;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte SACK option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = TCP_OPT_SACK;
					opts_len++;
					// Length
					*(options++) = opt_len;
					opts_len++;
					// Value
					memcpy(options, &tcp_context->tcp_opt_sackblocks,
					       tcp_context->tcp_opt_sack_length);
					options += tcp_context->tcp_opt_sack_length;
					opts_len += opt_len;
					break;
				default:  // Generic options
				{
					const uint8_t *pValue = tcp_context->tcp_options_values +
					                        tcp_context->tcp_options_offset[opt_idx];
					rohc_decomp_debug(context, "TCP option with index %u not "
					                  "handled", opt_idx);
					opt_type = tcp_context->tcp_options_list[opt_idx];
					if(pValue[0] > (0xff - 2))
					{
						rohc_decomp_warn(context, "malformed ROHC packet: TCP option "
						                 "is (%u+2)-byte long according to ROHC packet, "
						                 "but maximum length is %u bytes", pValue[0], 0xff);
						goto error;
					}
					opt_len = pValue[0] + 2;
					if((opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte TCP option",
						                 MAX_TCP_OPTIONS_LEN, opts_len, opt_len);
						goto error;
					}
					*(options++) = opt_type;
					// Length
					*(options++) = opt_len;
					// Value
					memcpy(options, pValue + 1, opt_len - 2);
					options += opt_len - 2;
					opts_len += opt_len;
					break;
				}
			}
		}
		tcp_context->tcp_opts_list_struct[i] = opt_type;
		rohc_decomp_debug(context, "    TCP option type 0x%02x (%u)",
		                  opt_type, opt_type);
		rohc_decomp_debug(context, "    TCP option is a %u-byte option", opt_len);
	}
	memset(tcp_context->tcp_opts_list_struct + m, 0xff, ROHC_TCP_OPTS_MAX - m);

	/* add padding after TCP options (they must be aligned on 32-bit words) */
	opt_padding_len = sizeof(uint32_t) - (opts_len % sizeof(uint32_t));
	opt_padding_len %= sizeof(uint32_t);
	if((opts_len + opt_padding_len) > MAX_TCP_OPTIONS_LEN)
	{
		rohc_decomp_warn(context, "malformed TCP options: more than %lu bytes "
		                 "of TCP options: %zu bytes already in + %zu-byte padding",
		                 MAX_TCP_OPTIONS_LEN, opts_len, opt_padding_len);
		goto error;
	}
	for(i = 0; i < opt_padding_len; i++)
	{
		rohc_decomp_debug(context, "  add missing TCP EOL option for padding");
		options[0] = TCP_OPT_EOL;
		options++;
	}
	opts_len += opt_padding_len;
	assert((opts_len % sizeof(uint32_t)) == 0);

	bits->opts_len = opts_len;
	assert(bits->opts_len <= MAX_TCP_OPTIONS_LEN);

	return compressed_options;

error:
	return NULL;
}


/**
 * @brief Reset the extracted bits for next parsing
 *
 * @param context    The decompression context
 * @param[out] bits  The extracted bits to reset
 */
static void d_tcp_reset_extr_bits(const struct rohc_decomp_ctxt *const context,
											 struct rohc_tcp_extr_bits *const bits)
{
	struct d_tcp_context *const tcp_context = context->specific;
	size_t i;

	/* set every bits and sizes to 0 */
	memset(bits, 0, sizeof(struct rohc_tcp_extr_bits));

	/* if context handled at least one packet, init the list of IP headers */
	if(context->num_recv_packets >= 1)
	{
		for(i = 0; i < tcp_context->ip_contexts_nr; i++)
		{
			bits->ip[i].version = tcp_context->ip_contexts[i].version;
			bits->ip[i].proto = tcp_context->ip_contexts[i].ctxt.vx.next_header;
			bits->ip[i].proto_nr = 8;
		}
		bits->ip_nr = tcp_context->ip_contexts_nr;
	}

	/* by default there is no TTL/HL field in the irregular chain */
	bits->ttl_irregular_chain_flag = false;

	/* default constant LSB shift parameters */
	bits->msn.p = ROHC_LSB_SHIFT_TCP_SN;
	bits->seq_scaled.p = ROHC_LSB_SHIFT_TCP_SEQ_SCALED;
	bits->ack_scaled.p = ROHC_LSB_SHIFT_TCP_ACK_SCALED;
	for(i = 0; i < ROHC_TCP_MAX_IP_HDRS; i++)
	{
		bits->ip[i].ttl_hl.p = ROHC_LSB_SHIFT_TCP_TTL;
	}

	/* by default there is no list of TCP options in co_common/seq_8/rnd_8 packets */
	bits->is_list_present = false;

	/* no TCP options at the beginning */
	for(i = 0; i < ROHC_TCP_OPTS_MAX; i++)
	{
		bits->is_tcp_opts_list_item_present[i] = false;
		bits->tcp_opts_list_item_uncomp_length[i] = 0;
	}
}


/**
 * @brief Decode values from extracted bits
 *
 * @param context       The decompression context
 * @param bits          The extracted bits
 * @param payload_len   The length of the packet payload (in bytes)
 * @param[out] decoded  The corresponding decoded values
 * @return              true if decoding is successful, false otherwise
 */
static bool d_tcp_decode_values_from_bits(const struct rohc_decomp_ctxt *const context,
                                          const struct rohc_tcp_extr_bits bits,
                                          const size_t payload_len,
                                          struct rohc_tcp_decoded_values *const decoded)
{
	struct d_tcp_context *const tcp_context = context->specific;
	size_t ip_hdr_nr;

	/* decode MSN */
	if(bits.msn.bits_nr == 16)
	{
		decoded->msn = bits.msn.bits;
		rohc_decomp_debug(context, "decoded MSN = 0x%04x (%zu bits 0x%x)",
		                  decoded->msn, bits.msn.bits_nr, bits.msn.bits);
	}
	else
	{
		uint32_t msn_decoded32;

		assert(bits.msn.bits_nr > 0); /* all packets contain some MSN bits */

		if(!rohc_lsb_decode(tcp_context->msn_lsb_ctxt, ROHC_LSB_REF_0, 0,
		                    bits.msn.bits, bits.msn.bits_nr, bits.msn.p,
		                    &msn_decoded32))
		{
			rohc_decomp_warn(context, "failed to decode %zu MSN bits 0x%x",
			                 bits.msn.bits_nr, bits.msn.bits);
			goto error;
		}
		decoded->msn = (uint16_t) (msn_decoded32 & 0xffff);
		rohc_decomp_debug(context, "decoded MSN = 0x%04x (%zu bits 0x%x)",
		                  decoded->msn, bits.msn.bits_nr, bits.msn.bits);
	}

	/* decode IP headers */
	assert(bits.ip_nr > 0);
	for(ip_hdr_nr = 0; ip_hdr_nr < bits.ip_nr; ip_hdr_nr++)
	{
		tcp_ip_id_behavior_t ip_id_behavior;
		const struct rohc_tcp_extr_ip_bits *const ip_bits =
			&(bits.ip[ip_hdr_nr]);
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[ip_hdr_nr]);
		struct rohc_tcp_decoded_ip_values *const ip_decoded =
			&(decoded->ip[ip_hdr_nr]);

		rohc_decomp_debug(context, "decode fields of IP header #%zu", ip_hdr_nr + 1);

		/* version */
		ip_decoded->version = ip_bits->version;

		/* ECN flags */
		if(ip_bits->ecn_flags_bits_nr > 0)
		{
			assert(ip_bits->ecn_flags_bits_nr == 2);
			ip_decoded->ecn_flags = ip_bits->ecn_flags_bits;
		}
		else
		{
			ip_decoded->ecn_flags = ip_context->ctxt.vx.ip_ecn_flags;
		}

		/* DSCP */
		if(ip_bits->dscp_bits_nr > 0)
		{
			assert(ip_bits->dscp_bits_nr == 6);
			ip_decoded->dscp = ip_bits->dscp_bits;
		}
		else
		{
			ip_decoded->dscp = ip_context->ctxt.v4.dscp;
		}

		/* IP-ID behavior */
		if(ip_bits->id_behavior_nr > 0)
		{
			assert(ip_bits->id_behavior_nr == 2);
			ip_id_behavior = ip_bits->id_behavior;
			rohc_decomp_debug(context, "  use behavior '%s' defined in current packet "
			                  "for IP-ID",
			                  tcp_ip_id_behavior_get_descr(ip_id_behavior));
		}
		else
		{
			ip_id_behavior = ip_context->ctxt.vx.ip_id_behavior;
			rohc_decomp_debug(context, "  use already-defined behavior '%s' for IP-ID",
			                  tcp_ip_id_behavior_get_descr(ip_id_behavior));
		}
		ip_decoded->id_behavior = ip_id_behavior;

		/* decode IP-ID according to its behavior */
		if(ip_bits->version == IPV4)
		{
			if(ip_bits->id.bits_nr == 16)
			{
				ip_decoded->id = ip_bits->id.bits;
				rohc_decomp_debug(context, "  IP-ID = 0x%04x (%zu-bit 0x%x from "
				                  "packet)", ip_decoded->id, ip_bits->id.bits_nr,
				                  ip_bits->id.bits);
			}
			else if(ip_bits->id.bits_nr > 0)
			{
				/* ROHC packet cannot contain partial IP-ID if it is not sequential */
				if(ip_id_behavior > IP_ID_BEHAVIOR_SEQ_SWAP)
				{
					rohc_decomp_warn(context, "packet and context mismatch for IP "
					                 "header %zu : received %zu bits of IP-ID in ROHC "
					                 "packet but IP-ID behavior is %s according to "
					                 "context", ip_hdr_nr + 1, ip_bits->id.bits_nr,
					                 tcp_ip_id_behavior_get_descr(ip_id_behavior));
					goto error;
				}

				/* decode IP-ID from packet bits and context */
				if(!d_ip_id_lsb(context, tcp_context->ip_id_lsb_ctxt, ip_id_behavior,
				                decoded->msn, ip_bits->id.bits, ip_bits->id.bits_nr,
				                ip_bits->id.p, &ip_decoded->id))
				{
					rohc_decomp_warn(context, "failed to decode %zu IP-ID bits "
					                 "0x%x with p = %d", ip_bits->id.bits_nr,
					                 ip_bits->id.bits, ip_bits->id.p);
					goto error;
				}
				rohc_decomp_debug(context, "  IP-ID = 0x%04x (decoded from "
				                  "%zu-bit 0x%x with p = %d)", ip_decoded->id,
				                  ip_bits->id.bits_nr, ip_bits->id.bits, ip_bits->id.p);
			}
			else if(ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
			{
				rohc_decomp_debug(context, "  IP-ID follows a zero behavior");
				ip_decoded->id = 0;
			}
		}
		else if(ip_bits->id.bits_nr > 0)
		{
			rohc_decomp_warn(context, "packet and context mismatch for IP header %zu: "
			                 "received %zu bits of IP-ID in ROHC packet but IP header "
			                 "is not IPv4 according to context", ip_hdr_nr + 1,
			                 ip_bits->id.bits_nr);
			goto error;
		}

		/* decode innermost TTL/HL */
		if(ip_bits->ttl_hl.bits_nr == 8)
		{
			ip_decoded->ttl = ip_bits->ttl_hl.bits;
			rohc_decomp_debug(context, "  decoded TTL/HL = 0x%02x (%zu bits 0x%x)",
			                  ip_decoded->ttl, ip_bits->ttl_hl.bits_nr,
			                  ip_bits->ttl_hl.bits);
		}
		else if(ip_bits->ttl_hl.bits_nr > 0)
		{
			uint32_t decoded32;

			if(!rohc_lsb_decode(tcp_context->ttl_hl_lsb_ctxt, ROHC_LSB_REF_0, 0,
			                    ip_bits->ttl_hl.bits, ip_bits->ttl_hl.bits_nr,
			                    ROHC_LSB_SHIFT_TCP_TTL, &decoded32))
			{
				rohc_decomp_warn(context, "failed to decode %zu TTL/HL bits 0x%x",
				                 ip_bits->ttl_hl.bits_nr, ip_bits->ttl_hl.bits);
				goto error;
			}
			ip_decoded->ttl = (uint8_t) (decoded32 & 0xff);
			rohc_decomp_debug(context, "  decoded TTL/HL = 0x%02x (%zu bits 0x%x)",
			                  ip_decoded->ttl, ip_bits->ttl_hl.bits_nr,
			                  ip_bits->ttl_hl.bits);
		}
		else
		{
			ip_decoded->ttl = ip_context->ctxt.vx.ttl_hopl;
			rohc_decomp_debug(context, "  TTL/HL = 0x%02x taken from context",
			                  ip_decoded->ttl);
		}

		/* change DF value if present in packet */
		if(ip_decoded->version == IPV4)
		{
			if(ip_bits->df_nr > 0)
			{
				assert(ip_bits->df_nr == 1);
				ip_decoded->df = ip_bits->df;
				rohc_decomp_debug(context, "  decoded DF = %d", ip_decoded->df);
			}
			else
			{
				ip_decoded->df = ip_context->ctxt.v4.df;
				rohc_decomp_debug(context, "  DF = %d taken from context",
				                  ip_decoded->df);
			}
		}
		else if(ip_bits->df_nr > 0 && ip_bits->df != 0)
		{
			rohc_decomp_warn(context, "malformed ROHC packet: DF shall be zero "
			                 "for innermost IPv6 header but it is %u", ip_bits->df);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}

		/* protocol / next header */
		if(ip_bits->proto_nr > 0)
		{
			assert(ip_bits->proto_nr == 8);
			ip_decoded->proto = ip_bits->proto;
			rohc_decomp_debug(context, "  decoded protocol/next header = 0x%02x (%d)",
			                  ip_decoded->proto, ip_decoded->proto);
		}
		else
		{
			ip_decoded->proto = ip_context->ctxt.vx.next_header;
			rohc_decomp_debug(context, "  protocol/next header = 0x%02x (%d) taken "
			                  "from context", ip_decoded->proto, ip_decoded->proto);
		}

		/* flow ID */
		if(ip_decoded->version == IPV6)
		{
			if(ip_bits->flowid_nr > 0)
			{
				assert(ip_bits->flowid_nr == 20);
				ip_decoded->flowid = ip_bits->flowid;
				rohc_decomp_debug(context, "  decoded flow label = 0x%03x",
				                  ip_decoded->flowid);
			}
			else
			{
				ip_decoded->flowid = (ip_context->ctxt.v6.flow_label1 << 16) |
				                     ip_context->ctxt.v6.flow_label2;
				rohc_decomp_debug(context, "  flow label = 0x%03x taken from context",
				                  ip_decoded->flowid);
			}
		}
		else /* IPv4 */
		{
			assert(ip_bits->flowid_nr == 0);
		}

		/* source address */
		if(ip_bits->saddr_nr > 0)
		{
			memcpy(ip_decoded->saddr, ip_bits->saddr, ip_bits->saddr_nr / 8);
			rohc_decomp_debug(context, "  %zu-byte source address (packet)",
			                  ip_bits->saddr_nr / 8);
		}
		else if(ip_decoded->version == IPV4)
		{
			memcpy(ip_decoded->saddr, &ip_context->ctxt.v4.src_addr, 4);
			rohc_decomp_debug(context, "  4-byte source address (context)");
		}
		else /* IPv6 */
		{
			memcpy(ip_decoded->saddr, ip_context->ctxt.v6.src_addr, 16);
			rohc_decomp_debug(context, "  16-byte source address (context)");
		}

		/* destination address */
		if(ip_bits->daddr_nr > 0)
		{
			memcpy(ip_decoded->daddr, ip_bits->daddr, ip_bits->daddr_nr / 8);
			rohc_decomp_debug(context, "  %zu-byte destination address (packet)",
			                  ip_bits->daddr_nr / 8);
		}
		else if(ip_decoded->version == IPV4)
		{
			memcpy(ip_decoded->daddr, &ip_context->ctxt.v4.dst_addr, 4);
			rohc_decomp_debug(context, "  4-byte destination address (context)");
		}
		else /* IPv6 */
		{
			memcpy(ip_decoded->daddr, ip_context->ctxt.v6.dest_addr, 16);
			rohc_decomp_debug(context, "  16-byte destination address (context)");
		}

		/* extension headers */
		if(ip_bits->version == IPV6)
		{
			ip_decoded->opts_nr = ip_bits->opts_nr;
			ip_decoded->opts_len = ip_bits->opts_len;
			assert(ip_bits->opts_len <= ROHC_TCP_MAX_IPV6_EXT_HDRS);
			memcpy(ip_decoded->opts, ip_bits->opts, ip_bits->opts_len);
			rohc_decomp_debug(context, "  %zu extension headers on %zu bytes",
			                  ip_decoded->opts_nr, ip_decoded->opts_len);
		}
		else
		{
			assert(ip_bits->opts_nr == 0);
			assert(ip_bits->opts_len == 0);
		}
	}
	decoded->ip_nr = bits.ip_nr;

	rohc_decomp_debug(context, "decode fields of TCP header");

	/* TCP source port */
	if(bits.src_port_nr > 0)
	{
		decoded->src_port = bits.src_port;
		rohc_decomp_debug(context, "  decoded source port %u", decoded->src_port);
	}
	else
	{
		decoded->src_port = tcp_context->tcp_src_port;
		rohc_decomp_debug(context, "  source port %u taken from context",
		                  decoded->src_port);
	}

	/* TCP destination port */
	if(bits.dst_port_nr > 0)
	{
		decoded->dst_port = bits.dst_port;
		rohc_decomp_debug(context, "  decoded destination port %u",
		                  decoded->dst_port);
	}
	else
	{
		decoded->dst_port = tcp_context->tcp_dst_port;
		rohc_decomp_debug(context, "  destination port %u taken from context",
		                  decoded->dst_port);
	}

	/* ROHC packet contains bits of scaled or unscaled TCP sequence number,
	 * but not both */
	assert(bits.seq.bits_nr == 0 || bits.seq_scaled.bits_nr == 0);

	/* TCP unscaled & scaled sequence number */
	if(bits.seq_scaled.bits_nr > 0)
	{
		/* decode scaled sequence number from packet bits and context */
		if(!rohc_lsb_decode(tcp_context->seq_scaled_lsb_ctxt, ROHC_LSB_REF_0, 0,
		                    bits.seq_scaled.bits, bits.seq_scaled.bits_nr,
		                    bits.seq_scaled.p, &decoded->seq_num_scaled))
		{
			rohc_decomp_warn(context, "failed to decode %zu scaled sequence "
			                 "number bits 0x%x with p = %d", bits.seq_scaled.bits_nr,
			                 bits.seq_scaled.bits, bits.seq_scaled.p);
			goto error;
		}
		rohc_decomp_debug(context, "  decoded scaled sequence number = 0x%08x "
		                  "(%zu bits 0x%x with p = %d)", decoded->seq_num_scaled,
		                  bits.seq_scaled.bits_nr, bits.seq_scaled.bits,
		                  bits.seq_scaled.p);

		/* decode sequence number from scaled sequence number */
		if(payload_len == 0)
		{
			rohc_decomp_warn(context, "cannot use scaled TCP sequence number "
			                 "for a packet with an empty payload");
			goto error;
		}
		decoded->seq_num = decoded->seq_num_scaled * payload_len +
		                   tcp_context->seq_num_residue;
		rohc_decomp_debug(context, "  seq_number_scaled = 0x%x, payload size = %zu, "
		                  "seq_number_residue = 0x%x -> seq_number = 0x%x",
		                  decoded->seq_num_scaled, payload_len,
		                  tcp_context->seq_num_residue, decoded->seq_num);
	}
	else
	{
		if(bits.seq.bits_nr == 32)
		{
			decoded->seq_num = bits.seq.bits;
			rohc_decomp_debug(context, "  TCP sequence number = 0x%08x (decoded from "
			                  "%zu-bit 0x%x)", decoded->seq_num, bits.seq.bits_nr,
			                  bits.seq.bits);
		}
		else if(bits.seq.bits_nr > 0)
		{
			/* decode unscaled sequence number from packet bits and context */
			if(!rohc_lsb_decode(tcp_context->seq_lsb_ctxt, ROHC_LSB_REF_0, 0,
			                    bits.seq.bits, bits.seq.bits_nr, bits.seq.p,
			                    &decoded->seq_num))
			{
				rohc_decomp_warn(context, "failed to decode TCP sequence number from "
				                 "%zu-bit 0x%x with p = %d", bits.seq.bits_nr,
				                 bits.seq.bits, bits.seq.p);
				goto error;
			}
			rohc_decomp_debug(context, "  TCP sequence number = 0x%08x (decoded from "
			                  "%zu-bit 0x%x with p = %d)", decoded->seq_num,
			                  bits.seq.bits_nr, bits.seq.bits, bits.seq.p);
		}
		else
		{
			const uint32_t old_seq =
				rohc_lsb_get_ref(tcp_context->seq_lsb_ctxt, ROHC_LSB_REF_0);
			rohc_decomp_debug(context, "  TCP sequence number = 0x%08x (re-used from "
			                  "previous packet)", old_seq);
			decoded->seq_num = old_seq;
		}

		/* compute scaled sequence number & residue */
		if(payload_len != 0)
		{
			decoded->seq_num_scaled = decoded->seq_num / payload_len;
			decoded->seq_num_residue = decoded->seq_num % payload_len;
			rohc_decomp_debug(context, "  TCP sequence number (0x%08x) = "
			                  "scaled (0x%x) * payload size (%zu) + residue (0x%x)",
			                  decoded->seq_num, decoded->seq_num_scaled, payload_len,
			                  decoded->seq_num_residue);
		}
	}

	/* ROHC packet contains bits of scaled or unscaled TCP acknowledgment number,
	 * but not both */
	assert(bits.ack.bits_nr == 0 || bits.ack_scaled.bits_nr == 0);

	/* TCP ACK stride */
	if(bits.ack_stride.bits_nr > 0)
	{
		assert(bits.ack_stride.bits_nr == 16);
		decoded->ack_stride = bits.ack_stride.bits;
	}

	/* TCP unscaled & scaled acknowledgement number */
	if(bits.ack_scaled.bits_nr > 0)
	{
		/* decode scaled acknowledgement number from packet bits and context */
		if(!rohc_lsb_decode(tcp_context->ack_scaled_lsb_ctxt, ROHC_LSB_REF_0, 0,
		                    bits.ack_scaled.bits, bits.ack_scaled.bits_nr,
		                    bits.ack_scaled.p, &decoded->ack_num_scaled))
		{
			rohc_decomp_warn(context, "failed to decode %zu scaled acknowledgement "
			                 "number bits 0x%x with p = %d", bits.ack_scaled.bits_nr,
			                 bits.ack_scaled.bits, bits.ack_scaled.p);
			goto error;
		}
		rohc_decomp_debug(context, "  decoded scaled acknowledgement number = 0x%08x "
		                  "(%zu bits 0x%x with p = %d)", decoded->ack_num_scaled,
		                  bits.ack_scaled.bits_nr, bits.ack_scaled.bits,
		                  bits.ack_scaled.p);

		/* decode acknowledgement number from scaled acknowledgement number */
		if(payload_len == 0)
		{
			rohc_decomp_warn(context, "cannot use scaled TCP acknowledgement "
			                 "numnber for a packet with an empty payload");
			goto error;
		}
		decoded->ack_num = decoded->ack_num_scaled * payload_len +
		                   tcp_context->ack_num_residue;
		rohc_decomp_debug(context, "  ack_number_scaled = 0x%x, payload size = %zu, "
		                  "ack_number_residue = 0x%x -> ack_number = 0x%x",
		                  decoded->ack_num_scaled, payload_len,
		                  tcp_context->ack_num_residue, decoded->ack_num);
	}
	else
	{
		if(bits.ack.bits_nr == 32)
		{
			decoded->ack_num = bits.ack.bits;
			rohc_decomp_debug(context, "  TCP ACK number = 0x%08x (decoded from "
			                  "%zu-bit 0x%x)", decoded->ack_num, bits.ack.bits_nr,
			                  bits.ack.bits);
		}
		else if(bits.ack.bits_nr > 0)
		{
			/* decode unscaled acknowledgement number from packet bits and context */
			if(!rohc_lsb_decode(tcp_context->ack_lsb_ctxt, ROHC_LSB_REF_0, 0,
			                    bits.ack.bits, bits.ack.bits_nr, bits.ack.p,
			                    &decoded->ack_num))
			{
				rohc_decomp_warn(context, "failed to decode TCP acknowledgement number "
				                 "from %zu-bit 0x%x with p = %d", bits.ack.bits_nr,
				                 bits.ack.bits, bits.ack.p);
				goto error;
			}
			rohc_decomp_debug(context, "  TCP ACK number = 0x%08x (decoded from "
			                  "%zu-bit 0x%x with p = %d)", decoded->ack_num,
			                  bits.ack.bits_nr, bits.ack.bits, bits.ack.p);
		}
		else
		{
			const uint32_t old_ack =
				rohc_lsb_get_ref(tcp_context->ack_lsb_ctxt, ROHC_LSB_REF_0);
			rohc_decomp_debug(context, "  TCP ACK number = 0x%08x (re-used from "
			                  "previous packet)", old_ack);
			decoded->ack_num = old_ack;
		}

		/* compute scaled acknowledgement number & residue */
		if(payload_len != 0)
		{
			decoded->ack_num_scaled = decoded->ack_num / payload_len;
			decoded->ack_num_residue = decoded->ack_num % payload_len;
			rohc_decomp_debug(context, "  TCP ACK number (0x%08x) = scaled (0x%x) "
									"* payload size (%zu) + residue (0x%x)",
			                  decoded->seq_num, decoded->ack_num_scaled, payload_len,
			                  decoded->ack_num_residue);
		}
	}

	/* TCP flags */
	if(bits.res_flags_bits_nr > 0)
	{
		assert(bits.res_flags_bits_nr == 4);
		decoded->res_flags = bits.res_flags_bits;
	}
	else
	{
		decoded->res_flags = tcp_context->res_flags;
	}
	if(bits.ecn_flags_bits_nr > 0)
	{
		assert(bits.ecn_flags_bits_nr == 2);
		decoded->ecn_flags = bits.ecn_flags_bits;
	}
	else
	{
		decoded->ecn_flags = tcp_context->ecn_flags;
	}
	if(bits.ecn_used_bits_nr > 0)
	{
		assert(bits.ecn_used_bits_nr == 1);
		decoded->ecn_used = !!bits.ecn_used_bits;
	}
	else
	{
		decoded->ecn_used = tcp_context->ecn_used;
	}
	if(bits.urg_flag_bits_nr > 0)
	{
		assert(bits.urg_flag_bits_nr == 1);
		decoded->urg_flag = !!bits.urg_flag_bits;
	}
	else
	{
		decoded->urg_flag = !!tcp_context->urg_flag;
	}
	if(bits.ack_flag_bits_nr > 0)
	{
		assert(bits.ack_flag_bits_nr == 1);
		decoded->ack_flag = !!bits.ack_flag_bits;
	}
	else
	{
		decoded->ack_flag = !!tcp_context->ack_flag;
	}
	if(!decoded->ack_flag && bits.ack.bits_nr > 0 && decoded->ack_num != 0)
	{
		rohc_decomp_debug(context, "ACK flag not set, but %zu bits 0x%x were "
		                  "transmitted for ACK number", bits.ack.bits_nr,
		                  bits.ack.bits);
	}
	assert(bits.psh_flag_bits_nr == 1); /* all packets contains the PSH flag */
	decoded->psh_flag = !!bits.psh_flag_bits;
	if(bits.rsf_flags_bits_nr == 3)
	{
		decoded->rsf_flags = bits.rsf_flags_bits;
	}
	else if(bits.rsf_flags_bits_nr == 2)
	{
		decoded->rsf_flags = rsf_index_dec(bits.rsf_flags_bits);
	}
	else
	{
		assert(bits.rsf_flags_bits_nr == 0);
		decoded->rsf_flags = tcp_context->rsf_flags;
	}
	rohc_decomp_debug(context, "  TCP flags: RES = 0x%x, ECN = 0x%x, URG = %u, "
	                  "ACK = %u, PSH = %u, RSF = 0x%x", decoded->res_flags,
	                  decoded->ecn_flags, rohc_b2u(decoded->urg_flag),
	                  rohc_b2u(decoded->ack_flag), rohc_b2u(decoded->psh_flag),
	                  decoded->rsf_flags);

	/* TCP window */
	if(bits.window.bits_nr == 16)
	{
		decoded->window = bits.window.bits;
		rohc_decomp_debug(context, "  TCP window = 0x%04x (%zu-bit 0x%x)",
		                  decoded->window, bits.window.bits_nr, bits.window.bits);
	}
	else if(bits.window.bits_nr > 0)
	{
		uint32_t win_decoded32;

		/* decode TCP window from packet bits and context */
		if(!rohc_lsb_decode(tcp_context->window_lsb_ctxt, ROHC_LSB_REF_0, 0,
		                    bits.window.bits, bits.window.bits_nr, bits.window.p,
		                    &win_decoded32))
		{
			rohc_decomp_warn(context, "failed to decode TCP window from %zu-bit "
			                 "0x%x", bits.window.bits_nr, bits.window.bits);
			goto error;
		}
		decoded->window = (uint16_t) (win_decoded32 & 0xffff);
		rohc_decomp_debug(context, "  TCP window = 0x%04x (%zu-bit 0x%x)",
		                  decoded->window, bits.window.bits_nr, bits.window.bits);
	}
	else
	{
		const uint16_t old_win =
			rohc_lsb_get_ref(tcp_context->window_lsb_ctxt, ROHC_LSB_REF_0);
		rohc_decomp_debug(context, "  TCP window = 0x%04x (re-used from previous "
		                  "packet)", old_win);
		decoded->window = old_win;
	}

	/* TCP checksum */
	decoded->tcp_check = bits.tcp_check;

	/* TCP urgent pointer */
	if(bits.urg_ptr.bits_nr > 0)
	{
		assert(bits.urg_ptr.bits_nr == 16);
		decoded->urg_ptr = bits.urg_ptr.bits;
	}
	else
	{
		decoded->urg_ptr = 0;
	}

	rohc_decomp_debug(context, "decode TCP options");

	/* copy TCP options from extracted bits to decoded values */
	/* TODO: do not decode TCP options other than TS/SACK before parsing is over */
	decoded->opts_len = bits.opts_len;
	memcpy(decoded->opts, bits.opts, decoded->opts_len);

	/* decode and build the TCP TimeStamp (TS) option */
	if(!d_tcp_decode_opt_ts(context, tcp_context->opt_ts_req_lsb_ctxt,
	                        tcp_context->opt_ts_rep_lsb_ctxt, bits.opt_ts,
	                        &decoded->opt_ts_present, &decoded->opt_ts_req,
	                        &decoded->opt_ts_rep))
	{
		rohc_decomp_warn(context, "failed to decode TCP TimeStamp option: failed to "
		                 "decode request/reply fields");
		goto error;
	}
	else if(decoded->opt_ts_present)
	{
		const uint32_t ts_req_nbo = rohc_hton32(decoded->opt_ts_req);
		const uint32_t ts_rep_nbo = rohc_hton32(decoded->opt_ts_rep);
		memcpy(decoded->opts + bits.opt_ts.uncomp_opt_offset, &ts_req_nbo,
		       sizeof(uint32_t));
		memcpy(decoded->opts + bits.opt_ts.uncomp_opt_offset + sizeof(uint32_t),
		       &ts_rep_nbo, sizeof(uint32_t));
	}

	/* decode and build the SACK blocks of the TCP SACK option */
	d_tcp_decode_opt_sack(context, decoded->ack_num, bits.opt_sack,
	                      decoded->opt_sack);
	if(bits.opt_sack.blocks_nr > 0)
	{
		if(bits.opt_sack.blocks_nr > TCP_SACK_BLOCKS_MAX_NR)
		{
			rohc_decomp_warn(context, "failed to decode TCP SACK option: too many "
			                 "%zu SACK blocks", bits.opt_sack.blocks_nr);
			goto error;
		}
		decoded->opt_sack_length = sizeof(sack_block_t) * bits.opt_sack.blocks_nr;
		memcpy(decoded->opts + bits.opt_sack.uncomp_opt_offset, decoded->opt_sack,
		       decoded->opt_sack_length);
		rohc_decomp_debug(context, "  %u-byte SACK option decoded",
		                  decoded->opt_sack_length + 2);
	}
	else
	{
		decoded->opt_sack_length = 0;
	}

	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "TCP options", decoded->opts, decoded->opts_len);

	return true;

error:
	return false;
}


/**
 * @brief Decode the TCP TimeStamp (TS) option
 *
 * @warning The available length in the \e opt_ts->uncomp_opt buffer shall have
 *          been checked before calling this function
 *
 * @param context           The decompression context
 * @param req_lsb_ctxt      The LSB decoding context to use for request field
 * @param rep_lsb_ctxt      The LSB decoding context to use for reply field
 * @param[out] ts           The TS request/reply bits extracted from the ROHC packet
 * @param[out] ts_present   Whether the TCP TS option is present in ROHC packet
 * @param[out] req_decoded  The TS request and reply fields
 * @param[out] rep_decoded  The TS request and reply fields
 * @return                  true if TS option was successfully decoded,
 *                          false if a problem occured during decoding
 */
static bool d_tcp_decode_opt_ts(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_lsb_decode *const req_lsb_ctxt,
                                const struct rohc_lsb_decode *const rep_lsb_ctxt,
                                const struct d_tcp_opt_ts ts,
                                bool *const ts_present,
                                uint32_t *const req_decoded,
                                uint32_t *const rep_decoded)
{
	/* both request/reply shall be present or absent */
	assert((ts.req.bits_nr > 0 && ts.rep.bits_nr > 0) ||
	       (ts.req.bits_nr == 0 && ts.rep.bits_nr == 0));

	*ts_present = !!(ts.req.bits_nr > 0);
	if(!(*ts_present))
	{
		goto skip;
	}

	rohc_decomp_debug(context, "  decode TS option");

	/* decode TS request field */
	if(!d_tcp_decode_opt_ts_field(context, "request", req_lsb_ctxt, ts.req,
	                              req_decoded))
	{
		rohc_decomp_warn(context, "failed to decode TimeStamp option: failed to "
		                 "decode request field");
		goto error;
	}
	rohc_decomp_debug(context, "    TS echo request = 0x%08x", *req_decoded);

	/* decode TS reply field */
	if(!d_tcp_decode_opt_ts_field(context, "reply", rep_lsb_ctxt, ts.rep,
	                              rep_decoded))
	{
		rohc_decomp_warn(context, "failed to decode TimeStamp option: failed to "
		                 "decode reply field");
		goto error;
	}
	rohc_decomp_debug(context, "    TS echo reply = 0x%08x", *rep_decoded);

skip:
	return true;

error:
	return false;
}


/**
 * @brief Decode the given TS field of the TCP TimeStamp (TS) option
 *
 * @warning The available length in the \e opt_ts->uncomp_opt buffer shall have
 *          been checked before calling this function
 *
 * @param context          The decompression context
 * @param descr            A description for the TS field being decoded
 * @param lsb_ctxt         The LSB decoding context to use for decoding
 * @param ts               The TS bits extracted from the ROHC packet
 * @param[out] ts_decoded  The decoded TS field (in HBO)
 * @return                 true if TS field was successfully decoded,
 *                         false if a problem occured during decoding
 */
static bool d_tcp_decode_opt_ts_field(const struct rohc_decomp_ctxt *const context,
                                      const char *const descr,
                                      const struct rohc_lsb_decode *const lsb_ctxt,
                                      const struct rohc_lsb_field32 ts,
                                      uint32_t *const ts_decoded)
{
	if(ts.bits_nr == 32)
	{
		*ts_decoded = ts.bits;
	}
	else
	{
		/* we cannot decode TS field if decompressor never received an uncompressed
		 * value */
		if(!rohc_lsb_is_ready(lsb_ctxt))
		{
			rohc_decomp_warn(context, "compressor sent a compressed TCP Timestamp "
			                 "option, but uncompressed value was not received yet");
			goto error;
		}

		/* decode TS field from packet bits and context */
		if(!rohc_lsb_decode(lsb_ctxt, ROHC_LSB_REF_0, 0, ts.bits, ts.bits_nr, ts.p,
		                    ts_decoded))
		{
			rohc_decomp_warn(context, "failed to decode %zu TimeStamp option %s bits "
			                 "0x%x with p = %u", ts.bits_nr, descr, ts.bits, ts.p);
			goto error;
		}
		rohc_decomp_debug(context, "decoded TimeStamp option %s = 0x%08x (%zu bits "
		                  "0x%x with ref 0x%08x and p = %d)", descr, *ts_decoded,
		                  ts.bits_nr, ts.bits,
		                  rohc_lsb_get_ref(lsb_ctxt, ROHC_LSB_REF_0), ts.p);
	}

	return true;

error:
	return false;
}


/**
 * @brief Decode the TCP SACK option
 *
 * @warning The available length in the \e opt_sack->uncomp_opt buffer shall have
 *          been checked before calling this function
 *
 * @param context       The decompression context
 * @param ack_num       The TCP ACK number of the current packet
 * @param opt_sack      The information of SACK option extracted from the packet
 * @param[out] decoded  The values decoded from the ROHC packet
 */
static void d_tcp_decode_opt_sack(const struct rohc_decomp_ctxt *const context,
                                  const uint32_t ack_num,
                                  const struct d_tcp_opt_sack opt_sack,
                                  uint8_t *const decoded)
{
	sack_block_t *sack_block;
	size_t i;

	if(opt_sack.blocks_nr > 0)
	{
		rohc_decomp_debug(context, "  decode SACK option (%zu blocks)",
		                  opt_sack.blocks_nr);
	}

	for(i = 0, sack_block = (sack_block_t *) decoded;
	    i < opt_sack.blocks_nr;
	    i++, sack_block++)
	{
		const uint32_t block_start = ack_num + opt_sack.blocks[i].block_start;
		const uint32_t block_end = block_start + opt_sack.blocks[i].block_end;
		sack_block->block_start = rohc_hton32(block_start);
		sack_block->block_end = rohc_hton32(block_end);
		rohc_decomp_debug(context, "decoded SACK option: block #%zu = "
		                  "[0x%08x, 0x%08x]", i + 1, block_start, block_end);
	}
}


/**
 * @brief Build all of the uncompressed IP headers
 *
 * Build all of the uncompressed IP headers - IPv4 or IPv6 - from the context
 * and packet informations.
 *
 * @param context             The decompression context
 * @param decoded             The values decoded from the ROHC packet
 * @param[out] uncomp_packet  The uncompressed packet being built
 * @param[out] ip_hdrs_len    The length of all the IP headers (in bytes)
 * @return                    true if IP headers were successfully built,
 *                            false if the output \e uncomp_packet was not
 *                            large enough
 */
static bool d_tcp_build_ip_hdrs(const struct rohc_decomp_ctxt *const context,
                                struct rohc_tcp_decoded_values decoded,
                                struct rohc_buf *const uncomp_packet,
                                size_t *const ip_hdrs_len)
{
	size_t ip_hdr_nr;

	assert(decoded.ip_nr > 0);

	rohc_decomp_debug(context, "build the %zu IP headers", decoded.ip_nr);

	*ip_hdrs_len = 0;
	for(ip_hdr_nr = 0; ip_hdr_nr < decoded.ip_nr; ip_hdr_nr++)
	{
		const struct rohc_tcp_decoded_ip_values *const ip_decoded =
			&(decoded.ip[ip_hdr_nr]);
		size_t ip_hdr_len = 0;

		if(!d_tcp_build_ip_hdr(context, *ip_decoded, uncomp_packet, &ip_hdr_len))
		{
			rohc_decomp_warn(context, "failed to build uncompressed IP header #%zu",
			                 ip_hdr_nr + 1);
			goto error;
		}
		*ip_hdrs_len += ip_hdr_len;
	}

	return true;

error:
	return false;
}


/**
 * @brief Build one single uncompressed IP header
 *
 * Build one single uncompressed IP header - IPv4 or IPv6 - from the context
 * and packet informations.
 *
 * @param context             The decompression context
 * @param decoded             The values decoded from the ROHC packet
 * @param[out] uncomp_packet  The uncompressed packet being built
 * @param[out] ip_hdr_len     The length of the IP header (in bytes)
 * @return                    true if IP header was successfully built,
 *                            false if the output \e uncomp_packet was not
 *                            large enough
 */
static bool d_tcp_build_ip_hdr(const struct rohc_decomp_ctxt *const context,
                               const struct rohc_tcp_decoded_ip_values decoded,
                               struct rohc_buf *const uncomp_packet,
                               size_t *const ip_hdr_len)
{
	if(decoded.version == IPV4)
	{
		if(!d_tcp_build_ipv4_hdr(context, decoded, uncomp_packet, ip_hdr_len))
		{
			rohc_decomp_warn(context, "failed to build uncompressed IPv4 header");
			goto error;
		}
	}
	else
	{
		if(!d_tcp_build_ipv6_hdr(context, decoded, uncomp_packet, ip_hdr_len))
		{
			rohc_decomp_warn(context, "failed to build uncompressed IPv6 header");
			goto error;
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Build one single uncompressed IPv4 header
 *
 * Build one single uncompressed IPv4 header from the context and packet
 * informations.
 *
 * @param context             The decompression context
 * @param decoded             The values decoded from the ROHC packet
 * @param[out] uncomp_packet  The uncompressed packet being built
 * @param[out] ip_hdr_len     The length of the IPv4 header (in bytes)
 * @return                    true if IPv4 header was successfully built,
 *                            false if the output \e uncomp_packet was not
 *                            large enough
 *
 * @todo TODO: replace base_header_ip_v4_t
 */
static bool d_tcp_build_ipv4_hdr(const struct rohc_decomp_ctxt *const context,
                                 const struct rohc_tcp_decoded_ip_values decoded,
                                 struct rohc_buf *const uncomp_packet,
                                 size_t *const ip_hdr_len)
{
	base_header_ip_v4_t *const ipv4 =
		(base_header_ip_v4_t *) rohc_buf_data(*uncomp_packet);
	const size_t hdr_len = sizeof(base_header_ip_v4_t);

	rohc_decomp_debug(context, "  build %zu-byte IPv4 header", hdr_len);

	if(rohc_buf_avail_len(*uncomp_packet) < hdr_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte IPv4 "
		                 "header", hdr_len);
		goto error;
	}

	/* static part */
	ipv4->version = decoded.version;
	rohc_decomp_debug(context, "    version = %u", ipv4->version);
	ipv4->header_length = hdr_len >> 2;
	rohc_decomp_debug(context, "    ihl = %u", ipv4->header_length);
	ipv4->protocol = decoded.proto;
	memcpy(&ipv4->src_addr, decoded.saddr, 4);
	memcpy(&ipv4->dest_addr, decoded.daddr, 4);

	/* dynamic part */
	ipv4->rf = 0;
	ipv4->df = decoded.df;
	ipv4->mf = 0;
	ipv4->dscp = decoded.dscp;
	ipv4->ip_ecn_flags = decoded.ecn_flags;
	ipv4->ttl_hopl = decoded.ttl;
	rohc_decomp_debug(context, "    DSCP = 0x%02x, ip_ecn_flags = %d",
	                  ipv4->dscp, ipv4->ip_ecn_flags);
#if WORDS_BIGENDIAN != 1
	ipv4->frag_offset1 = 0;
	ipv4->frag_offset2 = 0;
#else
	ipv4->frag_offset = 0;
#endif
	/* IP-ID */
	if(decoded.id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		ipv4->ip_id = rohc_hton16(swab16(decoded.id));
	}
	else
	{
		ipv4->ip_id = rohc_hton16(decoded.id);
	}
	rohc_decomp_debug(context, "    IP-ID = 0x%04x", rohc_ntoh16(ipv4->ip_id));

	/* length and checksums will be computed once all headers are built */

	/* skip IPv4 header */
	uncomp_packet->len += hdr_len;
	rohc_buf_pull(uncomp_packet, hdr_len);
	*ip_hdr_len += hdr_len;

	return true;

error:
	return false;
}


/**
 * @brief Build one single uncompressed IPv6 header
 *
 * Build one single uncompressed IPv6 header - including IPv6 extension
 * headers - from the context and packet informations.
 *
 * @param context             The decompression context
 * @param decoded             The values decoded from the ROHC packet
 * @param[out] uncomp_packet  The uncompressed packet being built
 * @param[out] ip_hdr_len     The length of the IPv6 header (in bytes)
 * @return                    true if IPv6 header was successfully built,
 *                            false if the output \e uncomp_packet was not
 *                            large enough
 *
 * @todo TODO: replace base_header_ip_v6_t
 */
static bool d_tcp_build_ipv6_hdr(const struct rohc_decomp_ctxt *const context,
                                 const struct rohc_tcp_decoded_ip_values decoded,
                                 struct rohc_buf *const uncomp_packet,
                                 size_t *const ip_hdr_len)
{
	base_header_ip_v6_t *const ipv6 =
		(base_header_ip_v6_t *) rohc_buf_data(*uncomp_packet);
	const size_t hdr_len = sizeof(base_header_ip_v6_t);
	const size_t ipv6_exts_len = decoded.opts_len;
	const size_t full_ipv6_len = hdr_len + ipv6_exts_len;
	size_t all_opts_len;
	size_t i;

	rohc_decomp_debug(context, "  build %zu-byte IPv6 header (with %zu bytes of "
	                  "extension headers)", full_ipv6_len, ipv6_exts_len);

	if(rohc_buf_avail_len(*uncomp_packet) < full_ipv6_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte IPv6 "
		                 "header (with %zu bytes of extension headers)",
		                 full_ipv6_len, ipv6_exts_len);
		goto error;
	}

	/* static part */
	ipv6->version = decoded.version;
	rohc_decomp_debug(context, "    version = %u", ipv6->version);
	ipv6->flow_label1 = (rohc_hton32(decoded.flowid) >> 20) & 0x7;
	ipv6->flow_label2 = rohc_hton32(decoded.flowid) & 0xffff;
	ipv6->next_header = decoded.proto;
	memcpy(ipv6->src_addr, decoded.saddr, sizeof(uint32_t) * 4);
	memcpy(ipv6->dest_addr, decoded.daddr, sizeof(uint32_t) * 4);

	/* dynamic part */
	ipv6->dscp1 = decoded.dscp >> 2;
	ipv6->dscp2 = decoded.dscp & 0x03;
	ipv6->ip_ecn_flags = decoded.ecn_flags;
	ipv6->ttl_hopl = decoded.ttl;

	/* total length will be computed once all headers are built */

	/* skip IPv6 header */
	uncomp_packet->len += hdr_len;
	rohc_buf_pull(uncomp_packet, hdr_len);
	*ip_hdr_len += hdr_len;

	/* copy IPv6 extension headers */
	all_opts_len = 0;
	for(i = 0; i < decoded.opts_nr; i++)
	{
		const ipv6_option_context_t *const opt = &(decoded.opts[i]);
		rohc_decomp_debug(context, "build %u-byte IPv6 extension header #%zu",
		                  opt->generic.option_length, i + 1);
		uncomp_packet->len += 2;
		rohc_buf_byte_at(*uncomp_packet, 0) = opt->generic.next_header;
		assert((opt->generic.option_length % 8) == 0);
		assert((opt->generic.option_length / 8) > 0);
		rohc_buf_byte_at(*uncomp_packet, 1) = opt->generic.option_length / 8 - 1;
		rohc_buf_append(uncomp_packet, opt->generic.data,
		                opt->generic.option_length - 2);
		rohc_buf_pull(uncomp_packet, opt->generic.option_length);
		*ip_hdr_len += opt->generic.option_length;
		all_opts_len += opt->generic.option_length;
	}
	assert(all_opts_len == ipv6_exts_len);

	return true;

error:
	return false;
}


/**
 * @brief Build the uncompressed TCP header
 *
 * Build the uncompressed TCP header - including the TCP options - from the
 * context and packet informations.
 *
 * @param context             The decompression context
 * @param decoded             The values decoded from ROHC header
 * @param[out] uncomp_packet  The uncompressed packet being built
 * @param[out] tcp_hdr_len    The length of the TCP header (in bytes)
 * @return                    true if TCP header was successfully built,
 *                            false if the output \e uncomp_packet was not
 *                            large enough
 */
static bool d_tcp_build_tcp_hdr(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_tcp_decoded_values decoded,
                                struct rohc_buf *const uncomp_packet,
                                size_t *const tcp_hdr_len)
{
	tcphdr_t *const tcp = (tcphdr_t *) rohc_buf_data(*uncomp_packet);
	const size_t full_tcp_len = sizeof(tcphdr_t) + decoded.opts_len;

	if(rohc_buf_avail_len(*uncomp_packet) < full_tcp_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
		                 "TCP header and TCP options", full_tcp_len);
		goto error;
	}
	rohc_decomp_debug(context, "build %zu-byte TCP header (with %zu bytes "
	                  "of options)", full_tcp_len, decoded.opts_len);

	/* TCP source & destination ports */
	tcp->src_port = rohc_hton16(decoded.src_port);
	tcp->dst_port = rohc_hton16(decoded.dst_port);
	/* TCP sequence & acknowledgement numbers */
	tcp->seq_num = rohc_hton32(decoded.seq_num);
	tcp->ack_num = rohc_hton32(decoded.ack_num);
	/* compute data offset */
	tcp->data_offset = (full_tcp_len >> 2) & 0xf;
	/* TCP flags */
	tcp->res_flags = decoded.res_flags;
	tcp->ecn_flags = decoded.ecn_flags;
	tcp->urg_flag = decoded.urg_flag;
	tcp->ack_flag = decoded.ack_flag;
	tcp->psh_flag = decoded.psh_flag;
	tcp->rsf_flags = decoded.rsf_flags;
	/* TCP window */
	tcp->window = rohc_ntoh16(decoded.window);
	/* TCP checksum */
	tcp->checksum = rohc_hton16(decoded.tcp_check);
	/* TCP Urgent pointer */
	tcp->urg_ptr = rohc_hton16(decoded.urg_ptr);
	/* TCP options */
	assert((decoded.opts_len % sizeof(uint32_t)) == 0);
	memcpy(tcp->options, decoded.opts, decoded.opts_len);

	/* skip TCP header and TCP options */
	uncomp_packet->len += full_tcp_len;
	rohc_buf_pull(uncomp_packet, full_tcp_len);
	*tcp_hdr_len += full_tcp_len;

	return true;

error:
	return false;
}


/**
 * @brief Build the uncompressed headers
 *
 * Build all the uncompressed IP headers, TCP headers from the context and
 * packet informations.
 *
 * @param decomp                The ROHC decompressor
 * @param context               The decompression context
 * @param packet_type           The type of ROHC packet
 * @param decoded               The values decoded from ROHC header
 * @param payload_len           The length of the packet payload (in bytes)
 * @param crc_type              The type of CRC
 * @param crc_packet            The CRC extracted from the ROHC header
 * @param[out] uncomp_hdrs      The uncompressed headers being built
 * @param[out] uncomp_hdrs_len  The length of the uncompressed headers written
 *                              into the buffer
 * @return                      Possible values:
 *                               \li ROHC_STATUS_OK if headers are built
 *                                   successfully,
 *                               \li ROHC_STATUS_BAD_CRC if headers do not
 *                                   match CRC,
 *                               \li ROHC_STATUS_OUTPUT_TOO_SMALL if
 *                                   \e uncomp_packet is too small
 */
static rohc_status_t d_tcp_build_uncomp_hdrs(const struct rohc_decomp *const decomp,
                                             const struct rohc_decomp_ctxt *const context,
                                             const rohc_packet_t packet_type,
                                             const struct rohc_tcp_decoded_values decoded,
                                             const size_t payload_len,
                                             const rohc_crc_type_t crc_type,
                                             const uint8_t crc_packet,
                                             struct rohc_buf *const uncomp_hdrs,
                                             size_t *const uncomp_hdrs_len)
{
	size_t ip_hdrs_len = 0;
	size_t tcp_hdr_len = 0;
	size_t ip_hdr_nr;

	rohc_decomp_debug(context, "build IP/TCP headers");

	*uncomp_hdrs_len = 0;

	/* build IP headers */
	if(!d_tcp_build_ip_hdrs(context, decoded, uncomp_hdrs, &ip_hdrs_len))
	{
		rohc_decomp_warn(context, "failed to build uncompressed IP headers");
		goto error_output_too_small;
	}
	*uncomp_hdrs_len += ip_hdrs_len;

	/* build TCP header */
	if(!d_tcp_build_tcp_hdr(context, decoded, uncomp_hdrs, &tcp_hdr_len))
	{
		rohc_decomp_warn(context, "failed to build uncompressed TCP header");
		goto error_output_too_small;
	}
	*uncomp_hdrs_len += tcp_hdr_len;

	/* unhide the IP/TCP headers */
	rohc_buf_push(uncomp_hdrs, *uncomp_hdrs_len);

	/* compute payload lengths and checksums for all IP headers */
	rohc_decomp_debug(context, "compute lengths and checksums for the %zu IP "
	                  "headers", decoded.ip_nr);
	assert(decoded.ip_nr > 0);
	for(ip_hdr_nr = 0; ip_hdr_nr < decoded.ip_nr; ip_hdr_nr++)
	{
		const struct rohc_tcp_decoded_ip_values *const ip_decoded =
			&(decoded.ip[ip_hdr_nr]);

		rohc_decomp_debug(context, "  IP header #%zu:", ip_hdr_nr + 1);
		if(ip_decoded->version == IPV4)
		{
			const uint16_t ipv4_tot_len = uncomp_hdrs->len + payload_len;
			base_header_ip_v4_t *const ipv4 =
				(base_header_ip_v4_t *) rohc_buf_data(*uncomp_hdrs);
			ipv4->length = rohc_hton16(ipv4_tot_len);
			rohc_decomp_debug(context, "    IP total length = 0x%04x", ipv4_tot_len);
			ipv4->checksum = 0;
			ipv4->checksum =
				ip_fast_csum(rohc_buf_data(*uncomp_hdrs), ipv4->header_length);
			rohc_decomp_debug(context, "    IP checksum = 0x%04x on %zu bytes",
			                  rohc_ntoh16(ipv4->checksum),
			                  ipv4->header_length * sizeof(uint32_t));
			rohc_buf_pull(uncomp_hdrs, ipv4->header_length * sizeof(uint32_t));
		}
		else
		{
			base_header_ip_v6_t *const ipv6 =
				(base_header_ip_v6_t *) rohc_buf_data(*uncomp_hdrs);
			rohc_buf_pull(uncomp_hdrs, sizeof(base_header_ip_v6_t));
			ipv6->payload_length = rohc_hton16(uncomp_hdrs->len + payload_len);
			rohc_decomp_debug(context, "    IPv6 payload length = %d",
			                  rohc_ntoh16(ipv6->payload_length));
			rohc_buf_pull(uncomp_hdrs, ip_decoded->opts_len);
		}
	}
	/* unhide the IP headers */
	rohc_buf_push(uncomp_hdrs, ip_hdrs_len);

	/* compute CRC on uncompressed headers if asked */
	if(crc_type != ROHC_CRC_TYPE_NONE)
	{
		const bool crc_ok = d_tcp_check_uncomp_crc(decomp, context, uncomp_hdrs,
		                                           crc_type, crc_packet);
		if(!crc_ok)
		{
			rohc_decomp_warn(context, "CRC detected a decompression failure for "
			                 "packet of type %s in state %s and mode %s",
			                 rohc_get_packet_descr(packet_type),
			                 rohc_decomp_get_state_descr(context->state),
			                 rohc_get_mode_descr(context->mode));
#if ROHC_EXTRA_DEBUG == 1
			rohc_dump_packet(decomp->trace_callback, decomp->trace_callback_priv,
			                 ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING,
			                 "uncompressed headers", *uncomp_hdrs);
#endif
			goto error_crc;
		}
	}

	rohc_dump_packet(decomp->trace_callback, decomp->trace_callback_priv,
	                 ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	                 "current IP/TCP headers", *uncomp_hdrs);

	return ROHC_STATUS_OK;

error_crc:
	return ROHC_STATUS_BAD_CRC;
error_output_too_small:
	return ROHC_STATUS_OUTPUT_TOO_SMALL;
}


/**
 * @brief Check whether the CRC on uncompressed header is correct or not
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param uncomp_hdrs  The uncompressed headers
 * @param crc_type     The type of CRC
 * @param crc_packet   The CRC extracted from the ROHC header
 * @return             true if the CRC is correct, false otherwise
 */
static bool d_tcp_check_uncomp_crc(const struct rohc_decomp *const decomp,
                                   const struct rohc_decomp_ctxt *const context,
                                   struct rohc_buf *const uncomp_hdrs,
                                   const rohc_crc_type_t crc_type,
                                   const uint8_t crc_packet)
{
	const unsigned char *crc_table;
	unsigned int crc_computed;

	/* determine the initial value and the pre-computed table for the CRC */
	switch(crc_type)
	{
		case ROHC_CRC_TYPE_3:
			crc_computed = CRC_INIT_3;
			crc_table = decomp->crc_table_3;
			break;
		case ROHC_CRC_TYPE_7:
			crc_computed = CRC_INIT_7;
			crc_table = decomp->crc_table_7;
			break;
		case ROHC_CRC_TYPE_8:
			crc_computed = CRC_INIT_8;
			crc_table = decomp->crc_table_8;
			break;
		default:
			rohc_decomp_warn(context, "unknown CRC type %d", crc_type);
			assert(0);
			goto error;
	}

	/* compute the CRC from built uncompressed headers */
	crc_computed =
		crc_calculate(crc_type, rohc_buf_data(*uncomp_hdrs), uncomp_hdrs->len,
		              crc_computed, crc_table);
	rohc_decomp_debug(context, "CRC-%d on uncompressed header = 0x%x",
	                  crc_type, crc_computed);

	/* does the computed CRC match the one in packet? */
	if(crc_computed != crc_packet)
	{
		rohc_decomp_warn(context, "CRC failure (computed = 0x%02x, packet = "
		                 "0x%02x)", crc_computed, crc_packet);
		goto error;
	}

	/* computed CRC matches the one in packet */
	return true;

error:
	return false;
}


/**
 * @brief Attempt a packet/context repair upon CRC failure
 *
 * @param decomp     The ROHC decompressor
 * @param context    The decompression context
 * @param[out] bits  The bits extracted from the ROHC header
 * @return           true if repair is possible, false if not
 */
static bool d_tcp_attempt_repair(const struct rohc_decomp *const decomp __attribute__((unused)),
                                 const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                 struct rohc_tcp_extr_bits *const bits __attribute__((unused)))
{
	rohc_decomp_debug(context, "will not attempt packet/context repair");
	return false; /* TODO: handle packet/context repair in TCP profile */
}


/**
 * @brief Update the decompression context with the infos of current packet
 *
 * @param context      The decompression context
 * @param decoded      The decoded values to update in the context
 * @param payload_len  The length of the packet payload (in bytes)
 */
static void d_tcp_update_context(struct rohc_decomp_ctxt *const context,
                                 const struct rohc_tcp_decoded_values decoded,
                                 const size_t payload_len)
{
	struct d_tcp_context *const tcp_context = context->specific;
	const uint16_t msn = decoded.msn;
	size_t ip_hdr_nr;

	/* MSN */
	rohc_lsb_set_ref(tcp_context->msn_lsb_ctxt, msn, false);
	rohc_decomp_debug(context, "MSN 0x%04x / %u is the new reference", msn, msn);

	/* update context for IP headers */
	assert(decoded.ip_nr > 0);
	for(ip_hdr_nr = 0; ip_hdr_nr < decoded.ip_nr; ip_hdr_nr++)
	{
		const struct rohc_tcp_decoded_ip_values *const ip_decoded =
			&(decoded.ip[ip_hdr_nr]);
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_nr]);
		const bool is_inner = !!(ip_hdr_nr == (decoded.ip_nr - 1));

		rohc_decomp_debug(context, "update context for IP header #%zu", ip_hdr_nr + 1);

		ip_context->version = ip_decoded->version;
		ip_context->ctxt.vx.version = ip_decoded->version;
		ip_context->ctxt.vx.dscp = ip_decoded->dscp;
		ip_context->ctxt.vx.ip_ecn_flags = ip_decoded->ecn_flags;
		ip_context->ctxt.vx.next_header = ip_decoded->proto;
		ip_context->ctxt.vx.ttl_hopl = ip_decoded->ttl;
		if(is_inner)
		{
			rohc_lsb_set_ref(tcp_context->ttl_hl_lsb_ctxt, ip_decoded->ttl, false);
		}
		ip_context->ctxt.vx.ip_id_behavior = ip_decoded->id_behavior;

		if(ip_context->version == IPV4)
		{
			ip_context->ctxt.v4.context_length = sizeof(ipv4_context_t);
			ip_context->ctxt.v4.df = ip_decoded->df;
			ip_context->ctxt.v4.ip_id = ip_decoded->id;
			memcpy(&ip_context->ctxt.v4.src_addr, ip_decoded->saddr, 4);
			memcpy(&ip_context->ctxt.v4.dst_addr, ip_decoded->daddr, 4);

			if(is_inner)
			{
				const uint16_t ip_id_offset = ip_context->ctxt.v4.ip_id - msn;
				rohc_lsb_set_ref(tcp_context->ip_id_lsb_ctxt, ip_id_offset, false);
				rohc_decomp_debug(context, "innermost IP-ID offset 0x%04x is the new "
				                  "reference", ip_id_offset);
			}
		}
		else /* IPv6 */
		{
			ip_context->ctxt.v6.context_length = sizeof(ipv4_context_t);
			memcpy(&ip_context->ctxt.v6.src_addr, ip_decoded->saddr, 16);
			memcpy(&ip_context->ctxt.v6.dest_addr, ip_decoded->daddr, 16);
		}
	}
	tcp_context->ip_contexts_nr = decoded.ip_nr;

	/* TCP source & destination ports */
	tcp_context->tcp_src_port = decoded.src_port;
	tcp_context->tcp_dst_port = decoded.dst_port;

	/* TCP (scaled) sequence number */
	rohc_lsb_set_ref(tcp_context->seq_lsb_ctxt, decoded.seq_num, false);
	rohc_decomp_debug(context, "sequence number 0x%08x is the new reference",
	                  decoded.seq_num);
	if(payload_len != 0)
	{
		rohc_lsb_set_ref(tcp_context->seq_scaled_lsb_ctxt,
		                 decoded.seq_num_scaled, false);
		rohc_decomp_debug(context, "scaled sequence number 0x%08x is the new "
		                  "reference", decoded.seq_num_scaled);
		tcp_context->seq_num_residue = decoded.seq_num_residue;
		rohc_decomp_debug(context, "scaled sequence residue 0x%08x is the new "
		                  "reference", decoded.seq_num_residue);
	}

	/* TCP (scaled) acknowledgment number */
	rohc_lsb_set_ref(tcp_context->ack_lsb_ctxt, decoded.ack_num, false);
	rohc_decomp_debug(context, "ACK number 0x%08x is the new reference",
	                  decoded.ack_num);
	if(payload_len != 0)
	{
		rohc_lsb_set_ref(tcp_context->ack_scaled_lsb_ctxt,
		                 decoded.ack_num_scaled, false);
		rohc_decomp_debug(context, "scaled acknowledgment number 0x%08x is the new "
		                  "reference", decoded.ack_num_scaled);
		tcp_context->ack_num_residue = decoded.ack_num_residue;
		rohc_decomp_debug(context, "scaled acknowledgment residue 0x%08x is the new "
		                  "reference", decoded.ack_num_residue);
	}

	/* TCP flags */
	tcp_context->res_flags = decoded.res_flags;
	tcp_context->ecn_flags = decoded.ecn_flags;
	tcp_context->urg_flag = rohc_b2u(decoded.urg_flag);
	tcp_context->ack_flag = rohc_b2u(decoded.ack_flag);
	/* PSH flag is sent every time, nothing to update in context */
	tcp_context->rsf_flags = decoded.rsf_flags;

	/* TCP window */
	rohc_lsb_set_ref(tcp_context->window_lsb_ctxt, decoded.window, false);
	rohc_decomp_debug(context, "window 0x%04x is the new reference",
	                  decoded.window);

	/* TCP checksum is sent every time, nothing to update in context */
	/* TCP Urgent pointer is sent every time, nothing to update in context */

	/* record the decoded TCP TimeStamp (TS) option in context for next packets
	 * that will compress out this option */
	if(decoded.opt_ts_present > 0)
	{
		tcp_context->tcp_opt_ts.ts = rohc_hton32(decoded.opt_ts_req);
		rohc_lsb_set_ref(tcp_context->opt_ts_req_lsb_ctxt, decoded.opt_ts_req, false);
		tcp_context->tcp_opt_ts.ts_reply = rohc_hton32(decoded.opt_ts_rep);
		rohc_lsb_set_ref(tcp_context->opt_ts_rep_lsb_ctxt, decoded.opt_ts_rep, false);
	}

	/* record the decoded TCP SACK option in context for next packets that will
	 * compress out this option */
	if(decoded.opt_sack_length > 0)
	{
		const size_t max_sack_len = sizeof(sack_block_t) * TCP_SACK_BLOCKS_MAX_NR;
		rohc_decomp_debug(context, "record TCP option SACK in context");
		tcp_context->tcp_opt_sack_length = decoded.opt_sack_length;
		assert(tcp_context->tcp_opt_sack_length <= max_sack_len);
		memcpy(tcp_context->tcp_opt_sackblocks, decoded.opt_sack,
		       tcp_context->tcp_opt_sack_length);
	}
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
	const struct d_tcp_context *const tcp_context = context->specific;
	const uint16_t msn = rohc_lsb_get_ref(tcp_context->msn_lsb_ctxt, ROHC_LSB_REF_0);
	rohc_decomp_debug(context, "MSN = %u (0x%x)", msn, msn);
	return msn;
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

