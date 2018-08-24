/*
 * Copyright 2012,2013,2014,2015 Didier Barvaux
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
 * @file   c_tcp.c
 * @brief  ROHC compression context for the TCP profile.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "rohc_comp_internals.h"
#include "rohc_traces_internal.h"
#include "rohc_utils.h"
#include "rohc_packets.h"
#include "rohc_buf.h"
#include "rohc_time_internal.h"
#include "protocols/ip_numbers.h"
#include "protocols/ip.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "protocols/tcp.h"
#include "schemes/cid.h"
#include "schemes/ip_id_offset.h"
#include "schemes/rfc4996.h"
#include "schemes/ipv6_exts.h"
#include "c_tcp_opts_list.h"
#include "sdvl.h"
#include "crc.h"
#include "rohc_bit_ops.h"
#include "c_tcp_defines.h"
#include "c_tcp_static.h"
#include "c_tcp_dynamic.h"
#include "c_tcp_replicate.h"
#include "c_tcp_irregular.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#ifdef __KERNEL__
#  include <endian.h>
#endif

#include "config.h" /* for WORDS_BIGENDIAN */


#define TRACE_GOTO_CHOICE \
	rohc_comp_debug(context, "Compressed format choice LINE %d", __LINE__ )


/*
 * Private function prototypes.
 */

static bool c_tcp_create_from_ctxt(struct rohc_comp_ctxt *const ctxt,
                                   const struct rohc_comp_ctxt *const base_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool c_tcp_create_from_pkt(struct rohc_comp_ctxt *const context,
                                  const struct rohc_buf *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static void c_tcp_destroy(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

static bool c_tcp_is_cr_possible(const struct rohc_comp_ctxt *const ctxt,
	                              const struct rohc_pkt_hdrs *const pkt_hdrs)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int c_tcp_encode(struct rohc_comp_ctxt *const context,
                        const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                        const struct rohc_buf *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 6)));

static uint16_t c_tcp_get_next_msn(const struct rohc_comp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1)));

static bool tcp_detect_changes(struct rohc_comp_ctxt *const context,
                               ip_context_t *const inner_ip_ctxt, /* TODO: const */
                               const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                               struct tcp_tmp_variables *const tmp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static bool tcp_detect_changes_ipv6_exts(struct rohc_comp_ctxt *const context,
                                         ip_context_t *const ip_context, /* TODO: const */
                                         struct tcp_tmp_variables *const tmp,
                                         uint8_t protocol,
                                         const uint8_t *const exts,
                                         const size_t max_exts_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
static bool tcp_detect_changes_tcp_hdr(struct rohc_comp_ctxt *const context,
                                       const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                       struct tcp_tmp_variables *const tmp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));


static void tcp_decide_state(struct rohc_comp_ctxt *const context,
                             struct rohc_ts pkt_time)
	__attribute__((nonnull(1)));

static rohc_packet_t tcp_decide_packet(const struct rohc_comp_ctxt *const context,
                                       const ip_context_t *const ip_inner_context,
                                       const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                       const struct tcp_tmp_variables *const tmp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static rohc_packet_t tcp_decide_FO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                          const struct tcp_tmp_variables *const tmp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static rohc_packet_t tcp_decide_SO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                          const struct tcp_tmp_variables *const tmp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static rohc_packet_t tcp_decide_FO_SO_packet(const struct rohc_comp_ctxt *const context,
                                             const ip_context_t *const ip_inner_context,
                                             const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                             const struct tcp_tmp_variables *const tmp,
                                             const bool crc7_at_least)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
                                                 const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                 const struct tcp_tmp_variables *const tmp,
                                                 const bool crc7_at_least)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
                                                 const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                 const struct tcp_tmp_variables *const tmp,
                                                 const bool crc7_at_least)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

/* IR and CO packets */
static int code_IR_packet(struct rohc_comp_ctxt *const context,
                          const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                          struct tcp_tmp_variables *const tmp,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

static int code_CO_packet(struct rohc_comp_ctxt *const context,
                          const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                          struct tcp_tmp_variables *const tmp,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static int co_baseheader(struct rohc_comp_ctxt *const context,
                         struct sc_tcp_context *const tcp_context,
                         ip_context_t *const ip_inner_context,
                         const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                         struct tcp_tmp_variables *const tmp,
                         uint8_t *const rohc_pkt,
                         const size_t rohc_pkt_max_len,
                         const rohc_packet_t packet_type,
                         const uint8_t crc)
	__attribute__((nonnull(1, 2, 3, 4, 5, 6), warn_unused_result));


/*
 * Functions that build the rnd_X packets
 */

static int c_tcp_build_rnd_1(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_2(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_3(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_4(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_5(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_6(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_7(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                             struct tcp_tmp_variables *const tmp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 5, 7), warn_unused_result));


/*
 * Functions that build the seq_X packets
 */

static int c_tcp_build_seq_1(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 9), warn_unused_result));

static int c_tcp_build_seq_2(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 9), warn_unused_result));

static int c_tcp_build_seq_3(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 9), warn_unused_result));

static int c_tcp_build_seq_4(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 9), warn_unused_result));

static int c_tcp_build_seq_5(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 9), warn_unused_result));

static int c_tcp_build_seq_6(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 9), warn_unused_result));

static int c_tcp_build_seq_7(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 9), warn_unused_result));

static int c_tcp_build_seq_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                             struct tcp_tmp_variables *const tmp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 5, 8), warn_unused_result));

static int c_tcp_build_co_common(const struct rohc_comp_ctxt *const context,
                                 const ip_context_t *const inner_ip_ctxt,
                                 struct sc_tcp_context *const tcp_context,
                                 const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                 struct tcp_tmp_variables *const tmp,
                                 const uint8_t crc,
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 5, 7), warn_unused_result));



/*
 * Misc functions
 */

static bool tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
                                         const uint8_t pkt_ecn_vals,
                                         const uint8_t pkt_outer_dscp_changed,
                                         const uint8_t pkt_res_val)
	__attribute__((nonnull(1), warn_unused_result));

static void tcp_field_descr_change(const struct rohc_comp_ctxt *const context,
                                   const char *const name,
                                   const bool changed,
                                   const size_t nr_trans)
	__attribute__((nonnull(1, 2)));

static void tcp_field_descr_present(const struct rohc_comp_ctxt *const context,
                                    const char *const name,
                                    const bool present)
	__attribute__((nonnull(1, 2)));

static bool c_tcp_feedback(struct rohc_comp_ctxt *const context,
                           const enum rohc_feedback_type feedback_type,
                           const uint8_t *const packet,
                           const size_t packet_len,
                           const uint8_t *const feedback_data,
                           const size_t feedback_data_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 5)));

static bool c_tcp_feedback_2(struct rohc_comp_ctxt *const context,
                             const uint8_t *const packet,
                             const size_t packet_len,
                             const uint8_t *const feedback_data,
                             const size_t feedback_data_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static void c_tcp_feedback_ack(struct rohc_comp_ctxt *const context,
                               const uint32_t sn_bits,
                               const size_t sn_bits_nr,
                               const bool sn_not_valid)
	__attribute__((nonnull(1)));


/**
 * @brief Create a new TCP context and initialize it thanks to the given context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param ctxt       The compression context to create
 * @param base_ctxt  The base context given to initialize the new context
 * @return           true if successful, false otherwise
 */
static bool c_tcp_create_from_ctxt(struct rohc_comp_ctxt *const ctxt,
                                   const struct rohc_comp_ctxt *const base_ctxt)
{
	const struct rohc_comp *const comp = ctxt->compressor;
	const struct sc_tcp_context *const base_tcp_ctxt = base_ctxt->specific;
	struct sc_tcp_context *tcp_ctxt;
	bool is_ok;

	/* create the TCP part of the profile context */
	tcp_ctxt = malloc(sizeof(struct sc_tcp_context));
	if(tcp_ctxt == NULL)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "no memory for the TCP part of the profile context");
		goto error;
	}
	ctxt->specific = tcp_ctxt;
	memcpy(ctxt->specific, base_ctxt->specific, sizeof(struct sc_tcp_context));

	/* keep the counter of compressed packets from the base context,
	 * since it is used to init some compression algorithms and we
	 * don't want the initialization to restart */
	ctxt->num_sent_packets = base_ctxt->num_sent_packets;

	/* MSN */
	is_ok = wlsb_copy(&tcp_ctxt->msn_wlsb, &base_tcp_ctxt->msn_wlsb);
	if(!is_ok)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "failed to create W-LSB context for MSN");
		goto free_context;
	}

	/* IP-ID offset */
	is_ok = wlsb_copy(&tcp_ctxt->ip_id_wlsb, &base_tcp_ctxt->ip_id_wlsb);
	if(!is_ok)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "failed to create W-LSB context for IP-ID offset");
		goto free_wlsb_msn;
	}

	/* innermost IPv4 TTL or IPv6 Hop Limit */
	is_ok = wlsb_copy(&tcp_ctxt->ttl_hopl_wlsb, &base_tcp_ctxt->ttl_hopl_wlsb);
	if(!is_ok)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "failed to create W-LSB context for innermost IPv4 TTL or "
		           "IPv6 Hop Limit");
		goto free_wlsb_ip_id;
	}

	/* TCP window */
	is_ok = wlsb_copy(&tcp_ctxt->window_wlsb, &base_tcp_ctxt->window_wlsb);
	if(!is_ok)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "failed to create W-LSB context for TCP window");
		goto free_wlsb_ttl_hopl;
	}

	/* TCP sequence number */
	is_ok = wlsb_copy(&tcp_ctxt->seq_wlsb, &base_tcp_ctxt->seq_wlsb);
	if(!is_ok)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "failed to create W-LSB context for TCP sequence number");
		goto free_wlsb_window;
	}
	is_ok = wlsb_copy(&tcp_ctxt->seq_scaled_wlsb, &base_tcp_ctxt->seq_scaled_wlsb);
	if(!is_ok)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "failed to create W-LSB context for TCP scaled sequence "
		           "number");
		goto free_wlsb_seq;
	}

	/* TCP acknowledgment (ACK) number */
	is_ok = wlsb_copy(&tcp_ctxt->ack_wlsb, &base_tcp_ctxt->ack_wlsb);
	if(!is_ok)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "failed to create W-LSB context for TCP ACK number");
		goto free_wlsb_seq_scaled;
	}
	is_ok = wlsb_copy(&tcp_ctxt->ack_scaled_wlsb, &base_tcp_ctxt->ack_scaled_wlsb);
	if(!is_ok)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "failed to create W-LSB context for TCP scaled ACK number");
		goto free_wlsb_ack;
	}

	/* init the Master Sequence Number to a random value */
	tcp_ctxt->msn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(ctxt, "MSN = 0x%04x / %u", tcp_ctxt->msn, tcp_ctxt->msn);

	/* TCP option Timestamp (request) */
	is_ok = wlsb_copy(&tcp_ctxt->tcp_opts.ts_req_wlsb, &base_tcp_ctxt->tcp_opts.ts_req_wlsb);
	if(!is_ok)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "failed to create W-LSB context for TCP option Timestamp "
		           "request");
		goto free_wlsb_ack_scaled;
	}
	/* TCP option Timestamp (reply) */
	is_ok = wlsb_copy(&tcp_ctxt->tcp_opts.ts_reply_wlsb, &base_tcp_ctxt->tcp_opts.ts_reply_wlsb);
	if(!is_ok)
	{
		rohc_error(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
		           "failed to create W-LSB context for TCP option Timestamp "
		           "reply");
		goto free_wlsb_opt_ts_req;
	}

	return true;

free_wlsb_opt_ts_req:
	wlsb_free(&tcp_ctxt->tcp_opts.ts_req_wlsb);
free_wlsb_ack_scaled:
	wlsb_free(&tcp_ctxt->ack_scaled_wlsb);
free_wlsb_ack:
	wlsb_free(&tcp_ctxt->ack_wlsb);
free_wlsb_seq_scaled:
	wlsb_free(&tcp_ctxt->seq_scaled_wlsb);
free_wlsb_seq:
	wlsb_free(&tcp_ctxt->seq_wlsb);
free_wlsb_window:
	wlsb_free(&tcp_ctxt->window_wlsb);
free_wlsb_ttl_hopl:
	wlsb_free(&tcp_ctxt->ttl_hopl_wlsb);
free_wlsb_ip_id:
	wlsb_free(&tcp_ctxt->ip_id_wlsb);
free_wlsb_msn:
	wlsb_free(&tcp_ctxt->msn_wlsb);
free_context:
	free(tcp_ctxt);
error:
	return false;
}


/**
 * @brief Create a new TCP context and initialize it thanks to the given IP/TCP
 *        packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The IP/TCP packet given to initialize the new context
 * @return         true if successful, false otherwise
 *
 * @todo TODO: the code that parses IP headers in IP/UDP/RTP profiles could
 *             probably be re-used (and maybe enhanced if needed)
 */
static bool c_tcp_create_from_pkt(struct rohc_comp_ctxt *const context,
                                  const struct rohc_buf *const packet)
{
	const struct rohc_comp *const comp = context->compressor;
	struct sc_tcp_context *tcp_context;
	const uint8_t *remain_data = rohc_buf_data(*packet);
	size_t remain_len = packet->len;
	const struct tcphdr *tcp;
	uint8_t proto;
	size_t i;
	bool is_ok;

	/* create the TCP part of the profile context */
	tcp_context = calloc(1, sizeof(struct sc_tcp_context));
	if(tcp_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the TCP part of the profile context");
		goto error;
	}
	context->specific = tcp_context;

	/* create contexts for IP headers and their extensions */
	tcp_context->ip_contexts_nr = 0;
	do
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;
		ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[tcp_context->ip_contexts_nr]);

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip->version);
		ip_context->version = ip->version;
		ip_context->version = ip->version;

		switch(ip->version)
		{
			case IPV4:
			{
				const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

				assert(remain_len >= sizeof(struct ipv4_hdr));
				proto = ipv4->protocol;

				ip_context->last_ip_id = rohc_ntoh16(ipv4->id);
				rohc_comp_debug(context, "IP-ID 0x%04x", ip_context->last_ip_id);
				ip_context->last_ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
				ip_context->ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
				ip_context->next_header = proto;
				ip_context->dscp = ipv4->dscp;
				ip_context->df = ipv4->df;
				ip_context->ttl_hopl = ipv4->ttl;
				ip_context->saddr[0] = ipv4->saddr;
				ip_context->daddr[0] = ipv4->daddr;

				remain_data += sizeof(struct ipv4_hdr);
				remain_len -= sizeof(struct ipv4_hdr);
				break;
			}
			case IPV6:
			{
				const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;

				assert(remain_len >= sizeof(struct ipv6_hdr));
				proto = ipv6->nh;

				ip_context->ip_id_behavior = ROHC_IP_ID_BEHAVIOR_RAND;
				ip_context->dscp = remain_data[1];
				ip_context->ttl_hopl = ipv6->hl;
				ip_context->flow_label = ipv6_get_flow_label(ipv6);
				memcpy(ip_context->saddr, &ipv6->saddr, sizeof(struct ipv6_addr));
				memcpy(ip_context->daddr, &ipv6->daddr, sizeof(struct ipv6_addr));

				remain_data += sizeof(struct ipv6_hdr);
				remain_len -= sizeof(struct ipv6_hdr);

				rohc_comp_debug(context, "parse IPv6 extension headers");
				while(rohc_is_ipv6_opt(proto))
				{
					const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
					size_t opt_len;
					assert(remain_len >= sizeof(struct ipv6_opt));
					opt_len = ipv6_opt_get_length(ipv6_opt);
					rohc_comp_debug(context, "  IPv6 extension header is %zu-byte long",
					                opt_len);
					remain_data += opt_len;
					remain_len -= opt_len;
					proto = ipv6_opt->next_header;
				}
				ip_context->next_header = proto;
				break;
			}
			default:
			{
				goto free_context;
			}
		}

		tcp_context->ip_contexts_nr++;
	}
	while(rohc_is_tunneling(proto) && tcp_context->ip_contexts_nr < ROHC_MAX_IP_HDRS);

	/* profile cannot handle the packet if it bypasses internal limit of IP headers
	 * (already checked by check_profile) */
	assert(rohc_is_tunneling(proto) == false);

	/* create context for TCP header */
	tcp_context->ttl_hopl_change_count = 0;
	tcp_context->tcp_window_change_count = 0;
	tcp_context->ecn_used = false;
	tcp_context->ecn_used_change_count = comp->oa_repetitions_nr;
	tcp_context->ecn_used_zero_count = 0;

	/* TCP header begins just after the IP headers */
	assert(remain_len >= sizeof(struct tcphdr));
	tcp = (struct tcphdr *) remain_data;
	tcp_context->res_flags = tcp->res_flags;
	tcp_context->urg_flag = tcp->urg_flag;
	tcp_context->ack_flag = tcp->ack_flag;
	tcp_context->urg_ptr_nbo = tcp->urg_ptr;
	tcp_context->window_nbo = tcp->window;

	/* MSN */
	is_ok = wlsb_new(&tcp_context->msn_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for MSN");
		goto free_context;
	}

	/* IP-ID offset */
	is_ok = wlsb_new(&tcp_context->ip_id_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for IP-ID offset");
		goto free_wlsb_msn;
	}

	/* innermost IPv4 TTL or IPv6 Hop Limit */
	is_ok = wlsb_new(&tcp_context->ttl_hopl_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for innermost IPv4 TTL or "
		           "IPv6 Hop Limit");
		goto free_wlsb_ip_id;
	}

	/* TCP window */
	is_ok = wlsb_new(&tcp_context->window_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP window");
		goto free_wlsb_ttl_hopl;
	}

	/* TCP sequence number */
	tcp_context->seq_num = rohc_ntoh32(tcp->seq_num);
	is_ok = wlsb_new(&tcp_context->seq_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP sequence number");
		goto free_wlsb_window;
	}
	is_ok = wlsb_new(&tcp_context->seq_scaled_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP scaled sequence "
		           "number");
		goto free_wlsb_seq;
	}

	/* TCP acknowledgment (ACK) number */
	tcp_context->ack_num = rohc_ntoh32(tcp->ack_num);
	is_ok = wlsb_new(&tcp_context->ack_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP ACK number");
		goto free_wlsb_seq_scaled;
	}
	is_ok = wlsb_new(&tcp_context->ack_scaled_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP scaled ACK number");
		goto free_wlsb_ack;
	}

	/* init the Master Sequence Number to a random value */
	tcp_context->msn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "MSN = 0x%04x / %u", tcp_context->msn, tcp_context->msn);

	tcp_context->ack_stride = 0;

	/* init the last list of TCP options */
	tcp_context->tcp_opts.structure_nr_trans = 0;
	tcp_context->tcp_opts.structure_nr = 0;
	// Initialize TCP options list index used
	for(i = 0; i <= MAX_TCP_OPTION_INDEX; i++)
	{
		tcp_context->tcp_opts.list[i].used = false;
	}

	/* TCP option Timestamp (request) */
	is_ok = wlsb_new(&tcp_context->tcp_opts.ts_req_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP option Timestamp "
		           "request");
		goto free_wlsb_ack_scaled;
	}
	/* TCP option Timestamp (reply) */
	is_ok = wlsb_new(&tcp_context->tcp_opts.ts_reply_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP option Timestamp "
		           "reply");
		goto free_wlsb_opt_ts_req;
	}

	return true;

free_wlsb_opt_ts_req:
	wlsb_free(&tcp_context->tcp_opts.ts_req_wlsb);
free_wlsb_ack_scaled:
	wlsb_free(&tcp_context->ack_scaled_wlsb);
free_wlsb_ack:
	wlsb_free(&tcp_context->ack_wlsb);
free_wlsb_seq_scaled:
	wlsb_free(&tcp_context->seq_scaled_wlsb);
free_wlsb_seq:
	wlsb_free(&tcp_context->seq_wlsb);
free_wlsb_window:
	wlsb_free(&tcp_context->window_wlsb);
free_wlsb_ttl_hopl:
	wlsb_free(&tcp_context->ttl_hopl_wlsb);
free_wlsb_ip_id:
	wlsb_free(&tcp_context->ip_id_wlsb);
free_wlsb_msn:
	wlsb_free(&tcp_context->msn_wlsb);
free_context:
	free(tcp_context);
error:
	return false;
}


/**
 * @brief Destroy the TCP context
 *
 * @param context  The TCP compression context to destroy
 */
static void c_tcp_destroy(struct rohc_comp_ctxt *const context)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	wlsb_free(&tcp_context->tcp_opts.ts_reply_wlsb);
	wlsb_free(&tcp_context->tcp_opts.ts_req_wlsb);
	wlsb_free(&tcp_context->ack_scaled_wlsb);
	wlsb_free(&tcp_context->ack_wlsb);
	wlsb_free(&tcp_context->seq_scaled_wlsb);
	wlsb_free(&tcp_context->seq_wlsb);
	wlsb_free(&tcp_context->window_wlsb);
	wlsb_free(&tcp_context->ip_id_wlsb);
	wlsb_free(&tcp_context->ttl_hopl_wlsb);
	wlsb_free(&tcp_context->msn_wlsb);
	free(tcp_context);
}


/**
 * @brief Check whether the given context is valid for Context Replication (CR)
 *
 * @param ctxt             The context to check Context Replication for
 * @param pkt_hdrs         The information collected about packet headers
 * @return                 true if CR is possible, false if CR is not possible
 */
static bool c_tcp_is_cr_possible(const struct rohc_comp_ctxt *const ctxt,
	                              const struct rohc_pkt_hdrs *const pkt_hdrs)
{
	const struct sc_tcp_context *const tcp_context = ctxt->specific;
	bool at_least_one_ipv6_hl_changed = false;
	size_t ip_hdr_pos;

	/* Context Replication is not possible if the IPv6 HL changed in any of the
	 * IP headers: indeed the IR-CR cannot transmit the changes */
	for(ip_hdr_pos = 0; ip_hdr_pos < pkt_hdrs->ip_hdrs_nr; ip_hdr_pos++)
	{
		const ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		const struct rohc_pkt_ip_hdr *const pkt_ip = &(pkt_hdrs->ip_hdrs[ip_hdr_pos]);

		if(pkt_ip->ipv6->version == IPV6 &&
		   pkt_ip->ipv6->hl != ip_context->ttl_hopl)
		{
			at_least_one_ipv6_hl_changed = true;
		}
	}
	if(at_least_one_ipv6_hl_changed)
	{
		return false;
	}

	/* Context Replication is not possible if the TCP RSF flags are abnormal:
	 * indeed the IR-CR packet encodes the TCP RSF flags with the rsf_index_enc()
	 * method that does not support the combination of RST, SYN or FIN flags */
	if(!rsf_index_enc_possible(pkt_hdrs->tcp->rsf_flags))
	{
		return false;
	}

	return true;
}


/**
 * @brief Encode an IP/TCP packet according to a pattern decided by several
 *        different factors.
 *
 * 1. Check if we have double IP headers.\n
 * 2. Check if the IP-ID fields are random and if they are in NBO.\n
 * 3. Decide in which state to go (IR, FO or SO).\n
 * 4. Decide how many bits are needed to send the IP-ID and SN fields and more
 *    important update the sliding windows.\n
 * 5. Decide which packet type to send.\n
 * 6. Code the packet.\n
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 *
 * @todo TODO: the code that parses IP headers in IP/UDP/RTP profiles could
 *             probably be re-used (and maybe enhanced if needed)
 */
static int c_tcp_encode(struct rohc_comp_ctxt *const context,
                        const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                        const struct rohc_buf *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct sc_tcp_context *const tcp_context = context->specific;
	struct c_tcp_opts_ctxt *const tcp_opts = &(tcp_context->tcp_opts);
	const struct tcphdr *const tcp = uncomp_pkt_hdrs->tcp;
	ip_context_t *const ip_inner_context =
		&(tcp_context->ip_contexts[uncomp_pkt_hdrs->ip_hdrs_nr - 1]);
	struct tcp_tmp_variables tmp;
	int counter;

	*packet_type = ROHC_PACKET_UNKNOWN;

	/* detect changes between new uncompressed packet and context */
	if(!tcp_detect_changes(context, ip_inner_context, uncomp_pkt_hdrs, &tmp))
	{
		rohc_comp_warn(context, "failed to detect changes in uncompressed packet");
		goto error;
	}
	if(tmp.tcp_opts.do_list_struct_changed)
	{
		tcp_context->tcp_opts_list_struct_trans_nr = 0;
	}
	else if(tcp_context->tcp_opts_list_struct_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "some TCP options were not present at the very "
		                "same location in the last few packets");
		tmp.tcp_opts.do_list_struct_changed = true;
	}
	if(tmp.tcp_opts.do_list_static_changed)
	{
		tcp_context->tcp_opts_list_static_trans_nr = 0;
	}
	else if(tcp_context->tcp_opts_list_static_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "some static TCP options changed in the last "
		                "few packets");
		tmp.tcp_opts.do_list_static_changed = true;
	}

	/* decide in which state to go */
	tcp_decide_state(context, uncomp_pkt->time);

	/* decide which packet to send */
	*packet_type = tcp_decide_packet(context, ip_inner_context, uncomp_pkt_hdrs, &tmp);

	/* does the packet update the decompressor context? */
	if(rohc_packet_carry_crc_7_or_8(*packet_type))
	{
		tcp_context->msn_of_last_ctxt_updating_pkt = tcp_context->msn;
	}

	/* code the chosen packet */
	if((*packet_type) == ROHC_PACKET_UNKNOWN)
	{
		rohc_comp_warn(context, "failed to find the packet type to encode");
		goto error;
	}
	else if((*packet_type) != ROHC_PACKET_IR &&
	        (*packet_type) != ROHC_PACKET_IR_CR &&
	        (*packet_type) != ROHC_PACKET_IR_DYN)
	{
		/* co_common, seq_X, or rnd_X */
		counter = code_CO_packet(context, uncomp_pkt_hdrs, &tmp,
		                         rohc_pkt, rohc_pkt_max_len, *packet_type);
		if(counter < 0)
		{
			rohc_comp_warn(context, "failed to build CO packet");
			goto error;
		}
	}
	else /* ROHC_PACKET_IR, ROHC_PACKET_IR_CR or ROHC_PACKET_IR_DYN */
	{
		assert((*packet_type) == ROHC_PACKET_IR ||
		       (*packet_type) == ROHC_PACKET_IR_CR ||
		       (*packet_type) == ROHC_PACKET_IR_DYN);

		counter = code_IR_packet(context, uncomp_pkt_hdrs, &tmp,
		                         rohc_pkt, rohc_pkt_max_len, *packet_type);
		if(counter < 0)
		{
			rohc_comp_warn(context, "failed to build IR(-DYN) packet");
			goto error;
		}
	}
	rohc_comp_dump_buf(context, "current ROHC packet", rohc_pkt, counter);

	rohc_comp_debug(context, "update context:");

	/* update the context with the new numbers of IP extension headers */
	{
		size_t ip_hdr_pos;
		for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
		{
			rohc_comp_debug(context, "  update context of IP header #%zu:",
			                ip_hdr_pos + 1);
			tcp_context->ip_contexts[ip_hdr_pos].opts_nr =
				uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos].exts_nr;
			rohc_comp_debug(context, "    %u extension headers",
			                tcp_context->ip_contexts[ip_hdr_pos].opts_nr);
		}
	}

	/* update the context with the new TCP header */
	tcp_context->seq_num = tmp.seq_num;
	tcp_context->ack_num = tmp.ack_num;
	tcp_context->res_flags = tcp->res_flags;
	tcp_context->urg_flag = tcp->urg_flag;
	tcp_context->ack_flag = tcp->ack_flag;
	tcp_context->urg_ptr_nbo = tcp->urg_ptr;
	tcp_context->window_nbo = tcp->window;

	/* add the new MSN to the W-LSB encoding object */
	c_add_wlsb(&tcp_context->msn_wlsb, tcp_context->msn, tcp_context->msn);

	if(uncomp_pkt_hdrs->innermost_ip_hdr->version == IPV4)
	{
		/* add the new innermost IP-ID / SN delta to the W-LSB encoding object */
		c_add_wlsb(&tcp_context->ip_id_wlsb, tcp_context->msn, tmp.ip_id_delta);
	}
	/* add the new innermost TTL/Hop Limit to the W-LSB encoding object */
	c_add_wlsb(&tcp_context->ttl_hopl_wlsb, tcp_context->msn,
	           uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl);

	/* sequence number */
	c_add_wlsb(&tcp_context->seq_wlsb, tcp_context->msn, tcp_context->seq_num);
	if(tcp_context->seq_num_factor != 0)
	{
		c_add_wlsb(&tcp_context->seq_scaled_wlsb, tcp_context->msn,
		           tcp_context->seq_num_scaled);

		/* sequence number sent once more, count the number of transmissions to
		 * know when scaled sequence number is possible */
		if(tcp_context->seq_num_scaling_nr < oa_repetitions_nr)
		{
			tcp_context->seq_num_scaling_nr++;
			rohc_comp_debug(context, "unscaled sequence number was transmitted "
			                "%u / %u times since the scaling factor or residue "
			                "changed", tcp_context->seq_num_scaling_nr,
			                oa_repetitions_nr);
		}
	}

	/* ACK number */
	c_add_wlsb(&tcp_context->ack_wlsb, tcp_context->msn, tcp_context->ack_num);
	if(tcp_context->ack_stride != 0)
	{
		c_add_wlsb(&tcp_context->ack_scaled_wlsb, tcp_context->msn,
		           tcp_context->ack_num_scaled);

		/* ACK number sent once more, count the number of transmissions to
		 * know when scaled ACK number is possible */
		if(tcp_context->ack_num_scaling_nr < oa_repetitions_nr)
		{
			tcp_context->ack_num_scaling_nr++;
			rohc_comp_debug(context, "unscaled ACK number was transmitted %u / %u "
			                "times since the scaling factor or residue changed",
			                tcp_context->ack_num_scaling_nr, oa_repetitions_nr);
		}
	}

	/* TCP window */
	c_add_wlsb(&tcp_context->window_wlsb, tcp_context->msn, rohc_ntoh16(tcp->window));

	/* TCP Timestamp option */
	if(tmp.tcp_opts.opt_ts_present)
	{
		c_add_wlsb(&tcp_opts->ts_req_wlsb, tcp_context->msn, tmp.tcp_opts.ts_req);
		c_add_wlsb(&tcp_opts->ts_reply_wlsb, tcp_context->msn, tmp.tcp_opts.ts_reply);
	}

	/* update transmission counters */
	if(tcp_context->tcp_seq_num_trans_nr < oa_repetitions_nr)
	{
		tcp_context->tcp_seq_num_trans_nr++;
	}
	if(tcp_context->tcp_ack_num_trans_nr < oa_repetitions_nr)
	{
		tcp_context->tcp_ack_num_trans_nr++;
	}
	if(tcp_context->tcp_window_change_count < oa_repetitions_nr)
	{
		tcp_context->tcp_window_change_count++;
	}
	if(tcp_context->tcp_urg_ptr_trans_nr < oa_repetitions_nr)
	{
		tcp_context->tcp_urg_ptr_trans_nr++;
	}
	if(tcp_context->ttl_hopl_change_count < oa_repetitions_nr)
	{
		tcp_context->ttl_hopl_change_count++;
	}
	if(tcp_context->innermost_ip_id_behavior_trans_nr < oa_repetitions_nr)
	{
		tcp_context->innermost_ip_id_behavior_trans_nr++;
	}
	if(tcp_context->innermost_dscp_trans_nr < oa_repetitions_nr)
	{
		tcp_context->innermost_dscp_trans_nr++;
	}
	if(tcp_context->ipv6_exts_list_static_trans_nr < oa_repetitions_nr)
	{
		tcp_context->ipv6_exts_list_static_trans_nr++;
	}
	if(tcp_context->ipv6_exts_list_dyn_trans_nr < oa_repetitions_nr)
	{
		tcp_context->ipv6_exts_list_dyn_trans_nr++;
	}
	if(tcp_context->tcp_opts_list_struct_trans_nr < oa_repetitions_nr)
	{
		tcp_context->tcp_opts_list_struct_trans_nr++;
	}
	if(tcp_context->tcp_opts_list_static_trans_nr < oa_repetitions_nr)
	{
		tcp_context->tcp_opts_list_static_trans_nr++;
	}

	return counter;

error:
	return -1;
}


/**
 * @brief Encode an IP/TCP packet as IR, IR-CR or IR-DYN packet
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for the compressed packet
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       The type of ROHC packet that is created
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_IR_packet(struct rohc_comp_ctxt *const context,
                          const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                          struct tcp_tmp_variables *const tmp,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type)
{
	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;
	size_t first_position;
	size_t crc_position;
	size_t rohc_hdr_len = 0;
	int ret;

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	ret = code_cid_values(context->compressor->medium.cid_type,
	                      context->cid, rohc_remain_data, rohc_remain_len,
	                      &first_position);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %u: maybe the %zu-byte "
		               "ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_remain_len);
		goto error;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_hdr_len += ret;
	rohc_comp_debug(context, "%s CID %u encoded on %d byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, ret - 1);

	/* type of packet */
	if(packet_type == ROHC_PACKET_IR)
	{
		rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR;
	}
	else if(packet_type == ROHC_PACKET_IR_CR)
	{
		rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR_CR;
	}
	else /* ROHC_PACKET_IR_DYN */
	{
		rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR_DYN;
	}
	rohc_comp_debug(context, "packet type = 0x%02x", rohc_pkt[first_position]);

	/* enough room for profile ID and CRC? */
	if(rohc_remain_len < 2)
	{
		rohc_comp_warn(context, "ROHC buffer too small for IR(-CR|-DYN) packet: "
		               "2 bytes required for profile ID and CRC, but only "
		               "%zu bytes available", rohc_remain_len);
		goto error;
	}

	/* profile ID */
	rohc_comp_debug(context, "profile ID = 0x%02x", context->profile->id);
	rohc_remain_data[0] = context->profile->id;
	rohc_remain_data++;
	rohc_remain_len--;
	rohc_hdr_len++;

	/* the CRC is computed later since it must be computed over the whole packet
	 * with an empty CRC field */
	rohc_comp_debug(context, "CRC = 0x00 for CRC calculation");
	crc_position = rohc_hdr_len;
	rohc_remain_data[0] = 0;
	rohc_remain_data++;
	rohc_remain_len--;
	rohc_hdr_len++;

	if(packet_type == ROHC_PACKET_IR || packet_type == ROHC_PACKET_IR_DYN)
	{
		/* add static chain for IR packet only */
		if(packet_type == ROHC_PACKET_IR)
		{
			ret = tcp_code_static_part(context, uncomp_pkt_hdrs,
			                           rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the static chain of the "
				               "IR packet");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
			rohc_hdr_len += ret;
			rohc_comp_dump_buf(context, "current ROHC packet (with static part)",
		                   rohc_pkt, rohc_hdr_len);
		}

		/* add dynamic chain for IR and IR-DYN packets only */
		ret = tcp_code_dyn_part(context, uncomp_pkt_hdrs, tmp,
		                        rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to build the dynamic chain of the "
			               "IR(-DYN) packet");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += ret;
		rohc_remain_len -= ret;
#endif
		rohc_hdr_len += ret;
		rohc_comp_dump_buf(context, "current ROHC packet (with dynamic part)",
		                   rohc_pkt, rohc_hdr_len);
	}
	else
	{
		uint8_t ir_cr_crc7;
		bool B;

		/* add replication base information for IR-CR packet only */
		if(rohc_remain_len < 1)
		{
			rohc_comp_warn(context, "ROHC buffer too small for IR-CR packet: "
			               "1 byte required for B and CRC7 fields, but only "
			               "%zu bytes available", rohc_remain_len);
			goto error;
		}
		B = !!(context->cid != context->cr_base_cid);

		/* encode base CID if different from IR-CR CID */
		ir_cr_crc7 =
			crc_calculate(ROHC_CRC_TYPE_7,
			              (const uint8_t *const) uncomp_pkt_hdrs->ip_hdrs[0].ip,
			              uncomp_pkt_hdrs->all_hdrs_len, CRC_INIT_7);
		rohc_remain_data[0] = (B ? 0x80 : 0x00) | (ir_cr_crc7 & 0x7f);
		rohc_comp_debug(context, "B (%d) + CRC7 (0x%x on %zu bytes) = 0x%02x",
		                GET_REAL(B), ir_cr_crc7, uncomp_pkt_hdrs->all_hdrs_len,
		                rohc_remain_data[0]);
		rohc_remain_data++;
		rohc_remain_len--;
		rohc_hdr_len++;
		if(B)
		{
			/* code small CID */
			if(context->compressor->medium.cid_type == ROHC_SMALL_CID)
			{
				if(rohc_remain_len < 1)
				{
					rohc_comp_warn(context, "ROHC buffer too small for IR-CR packet: "
					               "1 byte required for small Base CID, but only "
					               "%zu bytes available", rohc_remain_len);
					goto error;
				}
				assert(context->cr_base_cid <= ROHC_SMALL_CID_MAX);
				rohc_remain_data[0] = context->cr_base_cid;
				rohc_comp_debug(context, "small Base CID %u encoded as 0x%02x",
				                context->cr_base_cid, rohc_remain_data[0]);
				rohc_remain_data++;
				rohc_remain_len--;
				rohc_hdr_len++;
			}
			else /* ROHC_LARGE_CID */
			{
				ret = code_cid_values(context->compressor->medium.cid_type,
				                      context->cr_base_cid, rohc_remain_data - 1,
				                      rohc_remain_len + 1, &first_position);
				if(ret < 1)
				{
					rohc_comp_warn(context, "failed to encode large base CID %u: "
					               "maybe the %zu-byte ROHC buffer is too small",
					               context->cr_base_cid, rohc_remain_len);
					goto error;
				}
				assert(ret == 2 || ret == 3);
				rohc_remain_data += ret - 1;
				rohc_remain_len -= ret - 1;
				rohc_hdr_len += ret - 1;
				rohc_comp_debug(context, "large Base CID %u encoded on %d byte(s)",
				                context->cr_base_cid, ret - 1);
			}
		}

		/* add replicate chain for IR-CR packet only */
		ret = tcp_code_replicate_chain(context, uncomp_pkt_hdrs, tmp,
		                               rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to build the replicate chain of the "
			               "IR-CR packet");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += ret;
		rohc_remain_len -= ret;
#endif
		rohc_hdr_len += ret;
		rohc_comp_dump_buf(context, "current ROHC packet (with replicate part)",
		                   rohc_pkt, rohc_hdr_len);
	}

	/* IR(-CR|-DYN) header was successfully built, compute the CRC */
	rohc_pkt[crc_position] = crc_calculate(ROHC_CRC_TYPE_8, rohc_pkt,
	                                       rohc_hdr_len, CRC_INIT_8);
	rohc_comp_debug(context, "CRC (header length = %zu, crc = 0x%x)",
	                rohc_hdr_len, rohc_pkt[crc_position]);

	rohc_comp_debug(context, "IR(-CR|-DYN) packet, length %zu", rohc_hdr_len);
	rohc_comp_dump_buf(context, "current ROHC packet", rohc_pkt, rohc_hdr_len);

	return rohc_hdr_len;

error:
	return -1;
}


/**
 * @brief Build the CO packet.
 *
 * See RFC4996 page 46
 *
 * \verbatim

 CO packet (RFC4996 §7.3 page 41):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :  if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  |   First octet of base header  |  (with type indication)
    +---+---+---+---+---+---+---+---+
    |                               |
 3  /    0-2 octets of CID info     /  1-2 octets if for large CIDs
    |                               |
    +---+---+---+---+---+---+---+---+
 4  /   Remainder of base header    /  variable number of octets
    +---+---+---+---+---+---+---+---+
    :        Irregular chain        :
 5  /   (including irregular chain  /  variable
    :    items for TCP options)     :
    +---+---+---+---+---+---+---+---+
    |                               |
 6  /           Payload             /  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for the compressed packet
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       The type of ROHC packet to create
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_CO_packet(struct rohc_comp_ctxt *const context,
                          const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                          struct tcp_tmp_variables *const tmp,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	const uint8_t *const uncomp_data = (uint8_t *) uncomp_pkt_hdrs->ip_hdrs[0].ip;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	ip_context_t *const inner_ip_ctxt =
		&(tcp_context->ip_contexts[uncomp_pkt_hdrs->ip_hdrs_nr - 1]);

	size_t pos_1st_byte;
	size_t pos_2nd_byte;
	uint8_t save_first_byte;
	uint8_t crc_computed;
	int ret;

	rohc_comp_debug(context, "code CO packet (CID %u)", context->cid);

	/* compute the CRC on uncompressed headers */
	if(packet_type == ROHC_PACKET_TCP_SEQ_8 ||
	   packet_type == ROHC_PACKET_TCP_RND_8 ||
	   packet_type == ROHC_PACKET_TCP_CO_COMMON)
	{
		crc_computed =
			crc_calculate(ROHC_CRC_TYPE_7, uncomp_data, uncomp_pkt_hdrs->all_hdrs_len,
			              CRC_INIT_7);
		rohc_comp_debug(context, "CRC-7 on %zu-byte uncompressed header = 0x%x",
		                uncomp_pkt_hdrs->all_hdrs_len, crc_computed);
	}
	else
	{
		crc_computed =
			crc_calculate(ROHC_CRC_TYPE_3, uncomp_data, uncomp_pkt_hdrs->all_hdrs_len,
			              CRC_INIT_3);
		rohc_comp_debug(context, "CRC-3 on %zu-byte uncompressed header = 0x%x",
		                uncomp_pkt_hdrs->all_hdrs_len, crc_computed);
	}

	/* write Add-CID or large CID bytes: 'pos_1st_byte' indicates the location
	 * where first header byte shall be written, 'pos_2nd_byte' indicates the
	 * location where the next header bytes shall be written */
	ret = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                      rohc_remain_data, rohc_remain_len, &pos_1st_byte);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %u: maybe the "
		               "%zu-byte ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_remain_len);
		goto error;
	}
	pos_2nd_byte = ret;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "%s CID %u encoded on %d byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, ret - 1);

	/* The CO headers are written as a contiguous block. There is a problem in
	 * case of large CIDs. In such a case, the CID octets are not located at the
	 * beginning of the ROHC header. The first CO octet is located before the
	 * CID octet(s) and the remaining CO octets are located after the CID octet(s).
	 * To workaround that situation, the last CID octet is saved before writing
	 * the CO header and restored afterwards */
	save_first_byte = rohc_remain_data[-1];
	rohc_remain_data--;
	rohc_remain_len++;

	ret = co_baseheader(context, tcp_context, inner_ip_ctxt, uncomp_pkt_hdrs, tmp,
	                    rohc_remain_data, rohc_remain_len,
	                    packet_type, crc_computed);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the CO base header");
		goto error;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* add irregular chain */
	ret = tcp_code_irreg_chain(context, uncomp_pkt_hdrs, tmp,
	                           rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the irregular chain of the "
		               "CO packet");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

	/* end of workaround: restore the saved octet */
	if(context->compressor->medium.cid_type != ROHC_SMALL_CID)
	{
		rohc_pkt[pos_1st_byte] = rohc_pkt[pos_2nd_byte - 1];
		rohc_pkt[pos_2nd_byte - 1] = save_first_byte;
	}

	rohc_comp_dump_buf(context, "CO packet", rohc_pkt,
	                   rohc_pkt_max_len - rohc_remain_len);

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Compress the innermost IP header AND the TCP header
 *
 * See RFC4996 page 77
 *
 * @param context           The compression context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for the compressed packet
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param crc               The CRC on the uncompressed headers
 * @return                  The position in the rohc-packet-under-build buffer
 *                          -1 in case of problem
 */
static int co_baseheader(struct rohc_comp_ctxt *const context,
                         struct sc_tcp_context *const tcp_context,
                         ip_context_t *const inner_ip_ctxt,
                         const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                         struct tcp_tmp_variables *const tmp,
                         uint8_t *const rohc_pkt,
                         const size_t rohc_pkt_max_len,
                         const rohc_packet_t packet_type,
                         const uint8_t crc)
{
	const struct ip_hdr *const inner_ip_hdr = uncomp_pkt_hdrs->innermost_ip_hdr->ip;
	const size_t inner_ip_hdr_len = uncomp_pkt_hdrs->innermost_ip_hdr->tot_len;
	const struct tcphdr *const tcp = uncomp_pkt_hdrs->tcp;
	size_t rohc_hdr_len = 0;
	int ret;

	rohc_comp_debug(context, "code %s packet", rohc_get_packet_descr(packet_type));

	switch(packet_type)
	{
		case ROHC_PACKET_TCP_RND_1:
			ret = c_tcp_build_rnd_1(context, tcp_context, uncomp_pkt_hdrs->tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_2:
			ret = c_tcp_build_rnd_2(context, tcp_context, uncomp_pkt_hdrs->tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_3:
			ret = c_tcp_build_rnd_3(context, tcp_context, uncomp_pkt_hdrs->tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_4:
			ret = c_tcp_build_rnd_4(context, tcp_context, uncomp_pkt_hdrs->tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_5:
			ret = c_tcp_build_rnd_5(context, tcp_context, uncomp_pkt_hdrs->tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_6:
			ret = c_tcp_build_rnd_6(context, tcp_context, uncomp_pkt_hdrs->tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_7:
			ret = c_tcp_build_rnd_7(context, tcp_context, uncomp_pkt_hdrs->tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_8:
			ret = c_tcp_build_rnd_8(context, inner_ip_ctxt, tcp_context,
			                        uncomp_pkt_hdrs, tmp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_1:
			ret = c_tcp_build_seq_1(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp,
			                        tmp->ip_id_delta, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_2:
			ret = c_tcp_build_seq_2(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp,
			                        tmp->ip_id_delta, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_3:
			ret = c_tcp_build_seq_3(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp,
			                        tmp->ip_id_delta, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_4:
			ret = c_tcp_build_seq_4(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp,
			                        tmp->ip_id_delta, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_5:
			ret = c_tcp_build_seq_5(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp,
			                        tmp->ip_id_delta, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_6:
			ret = c_tcp_build_seq_6(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp,
			                        tmp->ip_id_delta, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_7:
			ret = c_tcp_build_seq_7(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp,
			                        tmp->ip_id_delta, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_8:
			ret = c_tcp_build_seq_8(context, inner_ip_ctxt, tcp_context,
			                        uncomp_pkt_hdrs, tmp, tmp->ip_id_delta, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_CO_COMMON:
			ret = c_tcp_build_co_common(context, inner_ip_ctxt, tcp_context,
			                            uncomp_pkt_hdrs, tmp, crc,
			                            rohc_pkt, rohc_pkt_max_len);
			break;
		default:
			rohc_comp_debug(context, "unexpected packet type %d", packet_type);
			assert(0);
			ret = -1;
			break;
	}
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build CO packet type '%s'",
		               rohc_get_packet_descr(packet_type));
		goto error;
	}
	rohc_hdr_len += ret;

	rohc_comp_dump_buf(context, "co_header", rohc_pkt, rohc_hdr_len);

	/* update context with new values (done at the very end to avoid wrongly
	 * updating the context in case of compression failure) */
	if(uncomp_pkt_hdrs->innermost_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 = uncomp_pkt_hdrs->innermost_ip_hdr->ipv4;
		inner_ip_ctxt->last_ip_id_behavior = inner_ip_ctxt->ip_id_behavior;
		inner_ip_ctxt->last_ip_id = rohc_ntoh16(inner_ipv4->id);
		inner_ip_ctxt->df = inner_ipv4->df;
		inner_ip_ctxt->dscp = inner_ipv4->dscp;
	}
	else
	{
		const struct ipv6_hdr *const inner_ipv6 = uncomp_pkt_hdrs->innermost_ip_hdr->ipv6;
		inner_ip_ctxt->dscp = ipv6_get_dscp(inner_ipv6);
	}
	inner_ip_ctxt->ttl_hopl = uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl;

	return rohc_hdr_len;

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_1 packet
 *
 * Send LSBs of sequence number
 * See RFC4996 page 81
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_1(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_1_t *const rnd1 = (rnd_1_t *) rohc_data;
	uint32_t seq_num;

	if(rohc_max_len < sizeof(rnd_1_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_1 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_1_t), rohc_max_len);
		goto error;
	}

	rnd1->discriminator = 0x2e; /* '101110' */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0x3ffff;
	rnd1->seq_num1 = (seq_num >> 16) & 0x3;
	rnd1->seq_num2 = rohc_hton16(seq_num & 0xffff);
	rnd1->msn = tcp_context->msn & 0xf;
	rnd1->psh_flag = tcp->psh_flag;
	rnd1->header_crc = crc;

	return sizeof(rnd_1_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_2 packet
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 81
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_2(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_2_t *const rnd2 = (rnd_2_t *) rohc_data;

	if(rohc_max_len < sizeof(rnd_2_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_2 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_2_t), rohc_max_len);
		goto error;
	}

	rnd2->discriminator = 0x0c; /* '1100' */
	rnd2->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	rnd2->msn = tcp_context->msn & 0xf;
	rnd2->psh_flag = tcp->psh_flag;
	rnd2->header_crc = crc;

	return sizeof(rnd_2_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_3 packet
 *
 * Send acknowlegment number LSBs
 * See RFC4996 page 81
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_3(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_3_t *const rnd3 = (rnd_3_t *) rohc_data;
	uint16_t ack_num;

	if(rohc_max_len < sizeof(rnd_3_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_3 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_3_t), rohc_max_len);
		goto error;
	}

	rnd3->discriminator = 0x0; /* '0' */
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x7fff;
	rnd3->ack_num1 = (ack_num >> 8) & 0x7f;
	rnd3->ack_num2 = ack_num & 0xff;
	rohc_comp_debug(context, "ack_number = 0x%04x (0x%02x 0x%02x)",
	                ack_num, rnd3->ack_num1, rnd3->ack_num2);
	rnd3->msn = tcp_context->msn & 0xf;
	rnd3->psh_flag = tcp->psh_flag;
	rnd3->header_crc = crc;

	return sizeof(rnd_3_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_4 packet
 *
 * Send acknowlegment number scaled
 * See RFC4996 page 81
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_4(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_4_t *const rnd4 = (rnd_4_t *) rohc_data;

	assert(tcp_context->ack_stride != 0);

	if(rohc_max_len < sizeof(rnd_4_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_4 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_4_t), rohc_max_len);
		goto error;
	}

	rnd4->discriminator = 0x0d; /* '1101' */
	rnd4->ack_num_scaled = tcp_context->ack_num_scaled & 0xf;
	rnd4->msn = tcp_context->msn & 0xf;
	rnd4->psh_flag = tcp->psh_flag;
	rnd4->header_crc = crc;

	return sizeof(rnd_4_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_5 packet
 *
 * Send ACK and sequence number
 * See RFC4996 page 82
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_5(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_5_t *const rnd5 = (rnd_5_t *) rohc_data;
	uint16_t seq_num;
	uint16_t ack_num;

	if(rohc_max_len < sizeof(rnd_5_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_5 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_5_t), rohc_max_len);
		goto error;
	}

	rnd5->discriminator = 0x04; /* '100' */
	rnd5->psh_flag = tcp->psh_flag;
	rnd5->msn = tcp_context->msn & 0xf;
	rnd5->header_crc = crc;

	/* sequence number */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0x3fff;
	rnd5->seq_num1 = (seq_num >> 9) & 0x1f;
	rnd5->seq_num2 = (seq_num >> 1) & 0xff;
	rnd5->seq_num3 = seq_num & 0x01;
	rohc_comp_debug(context, "seq_number = 0x%04x (0x%02x 0x%02x 0x%02x)",
	                seq_num, rnd5->seq_num1, rnd5->seq_num2, rnd5->seq_num3);

	/* ACK number */
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x7fff;
	rnd5->ack_num1 = (ack_num >> 8) & 0x7f;
	rnd5->ack_num2 = ack_num & 0xff;
	rohc_comp_debug(context, "ack_number = 0x%04x (0x%02x 0x%02x)",
	                ack_num, rnd5->ack_num1, rnd5->ack_num2);

	return sizeof(rnd_5_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_6 packet
 *
 * Send both ACK and scaled sequence number LSBs
 * See RFC4996 page 82
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_6(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_6_t *const rnd6 = (rnd_6_t *) rohc_data;

	if(rohc_max_len < sizeof(rnd_6_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_6 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_6_t), rohc_max_len);
		goto error;
	}

	rnd6->discriminator = 0x0a; /* '1010' */
	rnd6->header_crc = crc;
	rnd6->psh_flag = tcp->psh_flag;
	rnd6->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	rnd6->msn = tcp_context->msn & 0xf;
	rnd6->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;

	return sizeof(rnd_6_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_7 packet
 *
 * Send ACK and window
 * See RFC4996 page 82
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_7(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_7_t *const rnd7 = (rnd_7_t *) rohc_data;
	uint32_t ack_num;

	if(rohc_max_len < sizeof(rnd_7_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_7 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_7_t), rohc_max_len);
		goto error;
	}

	rnd7->discriminator = 0x2f; /* '101111' */
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x3ffff;
	rnd7->ack_num1 = (ack_num >> 16) & 0x03;
	rnd7->ack_num2 = rohc_hton16(ack_num & 0xffff);
	rnd7->window = tcp->window;
	rnd7->msn = tcp_context->msn & 0xf;
	rnd7->psh_flag = tcp->psh_flag;
	rnd7->header_crc = crc;

	return sizeof(rnd_7_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_8 packet
 *
 * Send LSBs of TTL, RSF flags, change ECN behavior and options list
 * See RFC4996 page 82
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for compressed packet
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_rnd_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                             struct tcp_tmp_variables *const tmp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	const struct ip_hdr *const inner_ip_hdr = uncomp_pkt_hdrs->innermost_ip_hdr->ip;
	const size_t inner_ip_hdr_len = uncomp_pkt_hdrs->innermost_ip_hdr->tot_len;
	const struct tcphdr *const tcp = (struct tcphdr *) uncomp_pkt_hdrs->tcp;
	rnd_8_t *const rnd8 = (rnd_8_t *) rohc_data;
	uint32_t seq_num;
	size_t comp_opts_len;
	uint8_t ttl_hl;
	uint8_t msn;
	int ret;

	if(rohc_max_len < sizeof(rnd_8_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_8 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_8_t), rohc_max_len);
		goto error;
	}

	rnd8->discriminator = 0x16; /* '10110' */
	rnd8->rsf_flags = rsf_index_enc(tcp->rsf_flags);
	rnd8->list_present = 0; /* options are set later */
	rnd8->header_crc = crc;
	rohc_comp_debug(context, "CRC 0x%x", rnd8->header_crc);

	/* MSN */
	msn = tcp_context->msn & 0xf;
	rnd8->msn1 = (msn >> 3) & 0x01;
	rnd8->msn2 = msn & 0x07;

	rnd8->psh_flag = tcp->psh_flag;

	/* TTL/HL */
	assert(inner_ip_hdr_len >= 1);
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
		assert(inner_ip_ctxt->version == IPV4);
		ttl_hl = ipv4->ttl;
	}
	else
	{
		const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) inner_ip_hdr;
		assert(inner_ip_hdr->version == IPV6);
		assert(inner_ip_hdr_len >= sizeof(struct ipv6_hdr));
		assert(inner_ip_ctxt->version == IPV6);
		ttl_hl = ipv6->hl;
	}
	rnd8->ttl_hopl = ttl_hl & 0x7;
	rnd8->ecn_used = GET_REAL(tcp_context->ecn_used);

	/* sequence number */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0xffff;
	rnd8->seq_num = rohc_hton16(seq_num);
	rohc_comp_debug(context, "16 bits of sequence number = 0x%04x", seq_num);

	/* ACK number */
	rnd8->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);

	/* include the list of TCP options if the structure of the list changed
	 * or if some static options changed (irregular chain cannot transmit
	 * static options) */
	if(tmp->tcp_opts.do_list_struct_changed ||
	   tmp->tcp_opts.do_list_static_changed ||
	   tmp->tcp_opts.opt_ts_do_transmit_item)
	{
		/* the structure of the list of TCP options changed or at least one of
		 * the static option changed, compress them */
		bool no_item_needed;
		rnd8->list_present = 1;
		ret = c_tcp_code_tcp_opts_list_item(context, uncomp_pkt_hdrs,
		                                    ROHC_CHAIN_CO, &tcp_context->tcp_opts,
		                                    &tmp->tcp_opts, rnd8->options,
		                                    rohc_max_len - sizeof(rnd_8_t),
		                                    &no_item_needed);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to compress TCP options");
			goto error;
		}
		comp_opts_len = ret;
	}
	else
	{
		/* the structure of the list of TCP options didn't change */
		rohc_comp_debug(context, "compressed list of TCP options: list not present");
		rnd8->list_present = 0;
		comp_opts_len = 0;
	}

	return (sizeof(rnd_8_t) + comp_opts_len);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_1 packet
 *
 * Send LSBs of sequence number
 * See RFC4996 page 83
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param innermost_ip_id_delta  The offset between the innermost IP-ID and MSN
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_1(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_1_t *const seq1 = (seq_1_t *) rohc_data;
	uint32_t seq_num;

	assert(inner_ip_ctxt->version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_1_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_1 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_1_t), rohc_max_len);
		goto error;
	}

	seq1->discriminator = 0x0a; /* '1010' */
	seq1->ip_id = innermost_ip_id_delta & 0x0f;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq1->ip_id);
	seq_num = rohc_ntoh32(tcp->seq_num) & 0xffff;
	seq1->seq_num = rohc_hton16(seq_num);
	seq1->msn = tcp_context->msn & 0xf;
	seq1->psh_flag = tcp->psh_flag;
	seq1->header_crc = crc;

	return sizeof(seq_1_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_2 packet
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 83
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param innermost_ip_id_delta  The offset between the innermost IP-ID and MSN
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_2(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_2_t *const seq2 = (seq_2_t *) rohc_data;

	assert(inner_ip_ctxt->version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_2_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_2 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_2_t), rohc_max_len);
		goto error;
	}

	seq2->discriminator = 0x1a; /* '11010' */
	seq2->ip_id1 = (innermost_ip_id_delta >> 4) & 0x7;
	seq2->ip_id2 = innermost_ip_id_delta & 0xf;
	rohc_comp_debug(context, "7-bit IP-ID offset 0x%x%x", seq2->ip_id1, seq2->ip_id2);
	seq2->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	seq2->msn = tcp_context->msn & 0xf;
	seq2->psh_flag = tcp->psh_flag;
	seq2->header_crc = crc;

	return sizeof(seq_2_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_3 packet
 *
 * Send acknowledgment number LSBs
 * See RFC4996 page 83
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param innermost_ip_id_delta  The offset between the innermost IP-ID and MSN
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_3(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_3_t *const seq3 = (seq_3_t *) rohc_data;

	assert(inner_ip_ctxt->version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_3_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_3 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_3_t), rohc_max_len);
		goto error;
	}

	seq3->discriminator = 0x09; /* '1001' */
	seq3->ip_id = innermost_ip_id_delta & 0xf;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq3->ip_id);
	seq3->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq3->msn = tcp_context->msn & 0xf;
	seq3->psh_flag = tcp->psh_flag;
	seq3->header_crc = crc;

	return sizeof(seq_3_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_4 packet
 *
 * Send scaled acknowledgment number scaled
 * See RFC4996 page 84
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param innermost_ip_id_delta  The offset between the innermost IP-ID and MSN
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_4(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_4_t *const seq4 = (seq_4_t *) rohc_data;

	assert(inner_ip_ctxt->version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);
	assert(tcp_context->ack_stride != 0);

	if(rohc_max_len < sizeof(seq_4_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_4 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_4_t), rohc_max_len);
		goto error;
	}

	seq4->discriminator = 0x00; /* '0' */
	seq4->ack_num_scaled = tcp_context->ack_num_scaled & 0xf;
	seq4->ip_id = innermost_ip_id_delta & 0x7;
	rohc_comp_debug(context, "3-bit IP-ID offset 0x%x", seq4->ip_id);
	seq4->msn = tcp_context->msn & 0xf;
	seq4->psh_flag = tcp->psh_flag;
	seq4->header_crc = crc;

	return sizeof(seq_4_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_5 packet
 *
 * Send ACK and sequence number
 * See RFC4996 page 84
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param innermost_ip_id_delta  The offset between the innermost IP-ID and MSN
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_5(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_5_t *const seq5 = (seq_5_t *) rohc_data;
	uint32_t seq_num;

	assert(inner_ip_ctxt->version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_5_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_5 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_5_t), rohc_max_len);
		goto error;
	}

	seq5->discriminator = 0x08; /* '1000' */
	seq5->ip_id = innermost_ip_id_delta & 0xf;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq5->ip_id);
	seq5->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq_num = rohc_ntoh32(tcp->seq_num) & 0xffff;
	seq5->seq_num = rohc_hton16(seq_num);
	seq5->msn = tcp_context->msn & 0xf;
	seq5->psh_flag = tcp->psh_flag;
	seq5->header_crc = crc;

	return sizeof(seq_5_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_6 packet
 *
 * See RFC4996 page 84
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param innermost_ip_id_delta  The offset between the innermost IP-ID and MSN
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_6(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_6_t *const seq6 = (seq_6_t *) rohc_data;
	uint8_t seq_num_scaled;

	assert(inner_ip_ctxt->version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_6_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_6 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_6_t), rohc_max_len);
		goto error;
	}

	seq6->discriminator = 0x1b; /* '11011' */

	/* scaled sequence number */
	seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	seq6->seq_num_scaled1 = (seq_num_scaled >> 1) & 0x07;
	seq6->seq_num_scaled2 = seq_num_scaled & 0x01;

	/* IP-ID */
	seq6->ip_id = innermost_ip_id_delta & 0x7f;
	rohc_comp_debug(context, "7-bit IP-ID offset 0x%x", seq6->ip_id);
	seq6->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq6->msn = tcp_context->msn & 0xf;
	seq6->psh_flag = tcp->psh_flag;
	seq6->header_crc = crc;

	return sizeof(seq_6_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_7 packet
 *
 * Send ACK and window
 * See RFC4996 page 85
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param innermost_ip_id_delta  The offset between the innermost IP-ID and MSN
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_7(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_7_t *const seq7 = (seq_7_t *) rohc_data;
	uint16_t window;

	assert(inner_ip_ctxt->version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_7_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_7 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_7_t), rohc_max_len);
		goto error;
	}

	seq7->discriminator = 0x0c; /* '1100' */

	/* window */
	window = rohc_ntoh16(tcp->window) & 0x7fff;
	seq7->window1 = (window >> 11) & 0x0f;
	seq7->window2 = (window >> 3) & 0xff;
	seq7->window3 = window & 0x07;

	/* IP-ID */
	seq7->ip_id = innermost_ip_id_delta & 0x1f;
	rohc_comp_debug(context, "5-bit IP-ID offset 0x%x", seq7->ip_id);
	seq7->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq7->msn = tcp_context->msn & 0xf;
	seq7->psh_flag = tcp->psh_flag;
	seq7->header_crc = crc;

	return sizeof(seq_7_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_8 packet
 *
 * Send LSBs of TTL, RSF flags, change ECN behavior, and options list
 * See RFC4996 page 85
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for compressed packet
 * @param innermost_ip_id_delta  The offset between the innermost IP-ID and MSN
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                             struct tcp_tmp_variables *const tmp,
                             const uint16_t innermost_ip_id_delta,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	const struct ipv4_hdr *const ipv4 = uncomp_pkt_hdrs->innermost_ip_hdr->ipv4;
	const struct tcphdr *const tcp = (struct tcphdr *) uncomp_pkt_hdrs->tcp;
	seq_8_t *const seq8 = (seq_8_t *) rohc_data;
	size_t comp_opts_len;
	uint16_t ack_num;
	uint16_t seq_num;
	int ret;

	assert(inner_ip_ctxt->version == IPV4);
	assert(ipv4->version == IPV4);

	if(rohc_max_len < sizeof(seq_8_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_8 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_8_t), rohc_max_len);
		goto error;
	}

	seq8->discriminator = 0x0b; /* '1011' */

	/* IP-ID */
	seq8->ip_id = innermost_ip_id_delta & 0xf;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq8->ip_id);

	seq8->list_present = 0; /* options are set later */
	seq8->header_crc = crc;
	rohc_comp_debug(context, "CRC = 0x%x", seq8->header_crc);
	seq8->msn = tcp_context->msn & 0xf;
	seq8->psh_flag = tcp->psh_flag;

	/* TTL/HL */
	seq8->ttl_hopl = ipv4->ttl & 0x7;

	/* ecn_used */
	seq8->ecn_used = GET_REAL(tcp_context->ecn_used);

	/* ACK number */
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x7fff;
	seq8->ack_num1 = (ack_num >> 8) & 0x7f;
	seq8->ack_num2 = ack_num & 0xff;
	rohc_comp_debug(context, "ack_number = 0x%04x (0x%02x 0x%02x)",
	                ack_num, seq8->ack_num1, seq8->ack_num2);

	seq8->rsf_flags = rsf_index_enc(tcp->rsf_flags);

	/* sequence number */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0x3fff;
	seq8->seq_num1 = (seq_num >> 8) & 0x3f;
	seq8->seq_num2 = seq_num & 0xff;
	rohc_comp_debug(context, "seq_number = 0x%04x (0x%02x 0x%02x)",
	                seq_num, seq8->seq_num1, seq8->seq_num2);

	/* include the list of TCP options if the structure of the list changed
	 * or if some static options changed (irregular chain cannot transmit
	 * static options) */
	if(tmp->tcp_opts.do_list_struct_changed ||
	   tmp->tcp_opts.do_list_static_changed ||
	   tmp->tcp_opts.opt_ts_do_transmit_item)
	{
		/* the structure of the list of TCP options changed or at least one of
		 * the static option changed, compress them */
		bool no_item_needed;
		seq8->list_present = 1;
		ret = c_tcp_code_tcp_opts_list_item(context, uncomp_pkt_hdrs,
		                                    ROHC_CHAIN_CO, &tcp_context->tcp_opts,
		                                    &tmp->tcp_opts, seq8->options,
		                                    rohc_max_len - sizeof(seq_8_t),
		                                    &no_item_needed);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to compress TCP options");
			goto error;
		}
		comp_opts_len = ret;
	}
	else
	{
		/* the structure of the list of TCP options didn't change */
		rohc_comp_debug(context, "compressed list of TCP options: list not present");
		seq8->list_present = 0;
		comp_opts_len = 0;
	}

	return (sizeof(seq_8_t) + comp_opts_len);

error:
	return -1;
}


/**
 * @brief Build a TCP co_common packet
 *
 * @param context          The compression context
 * @param inner_ip_ctxt    The context of the innermost IP header
 * @param tcp_context      The specific TCP context
 * @param uncomp_pkt_hdrs  The uncompressed headers to encode
 * @param tmp              The temporary state for the compressed packet
 * @param crc              The CRC on the uncompressed headers
 * @param[out] rohc_data   The ROHC packet being built
 * @param rohc_max_len     The max remaining length in the ROHC buffer
 * @return                 true if the packet is successfully built,
 *                         false otherwise
 */
static int c_tcp_build_co_common(const struct rohc_comp_ctxt *const context,
                                 const ip_context_t *const inner_ip_ctxt,
                                 struct sc_tcp_context *const tcp_context,
                                 const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                 struct tcp_tmp_variables *const tmp,
                                 const uint8_t crc,
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	const struct tcphdr *const tcp = uncomp_pkt_hdrs->tcp;
	co_common_t *const co_common = (co_common_t *) rohc_data;
	uint8_t *co_common_opt = (uint8_t *) (co_common + 1); /* optional part */
	size_t co_common_opt_len = 0;
	size_t rohc_remain_len = rohc_max_len - sizeof(co_common_t);
	size_t encoded_seq_len;
	size_t encoded_ack_len;
	int indicator;
	int ret;

	if(rohc_max_len < sizeof(co_common_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the co_common header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(co_common_t), rohc_max_len);
		goto error;
	}

	rohc_comp_debug(context, "ttl_irreg_chain_flag = %d",
	                tmp->ttl_irreg_chain_flag);

	co_common->discriminator = 0x7D; // '1111101'
	co_common->ttl_hopl_outer_flag = tmp->ttl_irreg_chain_flag;

	rohc_comp_debug(context, "TCP ack_flag = %d, psh_flag = %d, rsf_flags = %d",
	                tcp->ack_flag, tcp->psh_flag, tcp->rsf_flags);
	// =:= irregular(1) [ 1 ];
	co_common->ack_flag = tcp->ack_flag;
	// =:= irregular(1) [ 1 ];
	co_common->psh_flag = tcp->psh_flag;
	// =:= rsf_index_enc [ 2 ];
	co_common->rsf_flags = rsf_index_enc(tcp->rsf_flags);
	// =:= lsb(4, 4) [ 4 ];
	co_common->msn = tcp_context->msn & 0xf;

	/* seq_number */
	ret = variable_length_32_enc(tmp->tcp_seq_num_unchanged, tmp->seq_num,
	                             &tcp_context->seq_wlsb,
	                             co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the encoded sequence "
		               "number");
		goto error;
	}
	co_common->seq_indicator = indicator;
	encoded_seq_len = ret;
	co_common_opt += encoded_seq_len;
	co_common_opt_len += encoded_seq_len;
	rohc_remain_len -= encoded_seq_len;
	rohc_comp_debug(context, "encode sequence number 0x%08x on %zu bytes with "
	                "indicator %d", tmp->seq_num, encoded_seq_len,
	                co_common->seq_indicator);

	/* ack_number */
	ret = variable_length_32_enc(tmp->tcp_ack_num_unchanged, tmp->ack_num,
	                             &tcp_context->ack_wlsb,
	                             co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the encoded ACK number");
		goto error;
	}
	co_common->ack_indicator = indicator;
	encoded_ack_len = ret;
	co_common_opt += encoded_ack_len;
	co_common_opt_len += encoded_ack_len;
	rohc_remain_len -= encoded_ack_len;
	rohc_comp_debug(context, "encode ACK number 0x%08x on %zu bytes with "
	                "indicator %d", tmp->ack_num, encoded_ack_len,
	                co_common->ack_indicator);

	/* ack_stride */
	{
		const bool is_ack_stride_static =
			tcp_is_ack_stride_static(tcp_context->ack_stride,
			                         tcp_context->ack_num_scaling_nr,
			                         oa_repetitions_nr);
		ret = c_static_or_irreg16(rohc_hton16(tcp_context->ack_stride),
		                          is_ack_stride_static,
		                          co_common_opt, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(ack_stride)");
			goto error;
		}
		co_common->ack_stride_indicator = indicator;
		co_common_opt += ret;
		co_common_opt_len += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "ack_stride_indicator = %d, ack_stride 0x%x on "
		                "%d bytes", co_common->ack_stride_indicator,
		                tcp_context->ack_stride, ret);
	}

	/* window */
	ret = c_static_or_irreg16(tcp->window, !tmp->tcp_window_changed,
	                          co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode static_or_irreg(window)");
		goto error;
	}
	co_common->window_indicator = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "window_indicator = %d, window = 0x%x on %d bytes",
	                co_common->window_indicator, rohc_ntoh16(tcp->window), ret);

	/* innermost IP-ID */
	if(uncomp_pkt_hdrs->innermost_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 =
			uncomp_pkt_hdrs->innermost_ip_hdr->ipv4;
		// =:= irregular(1) [ 1 ];
		rohc_comp_debug(context, "optional_ip_id_lsb(behavior = %d, IP-ID = 0x%04x, "
		                "IP-ID offset = 0x%04x)", inner_ip_ctxt->ip_id_behavior,
		                rohc_ntoh16(inner_ipv4->id), tmp->ip_id_delta);
		ret = c_optional_ip_id_lsb(inner_ip_ctxt->ip_id_behavior,
		                           inner_ipv4->id, tmp->ip_id_delta,
		                           &tcp_context->ip_id_wlsb, 3,
		                           co_common_opt, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode optional_ip_id_lsb(ip_id)");
			goto error;
		}
		co_common->ip_id_indicator = indicator;
		co_common_opt += ret;
		co_common_opt_len += ret;
		rohc_remain_len -= ret;
		// =:= ip_id_behavior_choice(true) [ 2 ];
		co_common->ip_id_behavior = inner_ip_ctxt->ip_id_behavior;
		rohc_comp_debug(context, "ip_id_indicator = %d, "
		                "ip_id_behavior = %d (innermost IP-ID encoded on %d bytes)",
		                co_common->ip_id_indicator, co_common->ip_id_behavior, ret);
	}
	else
	{
		// =:= irregular(1) [ 1 ];
		co_common->ip_id_indicator = 0;
		// =:= ip_id_behavior_choice(true) [ 2 ];
		co_common->ip_id_behavior = ROHC_IP_ID_BEHAVIOR_RAND;
		rohc_comp_debug(context, "ip_id_indicator = %d, "
		                "ip_id_behavior = %d (innermost IP-ID encoded on 0 byte)",
		                co_common->ip_id_indicator, co_common->ip_id_behavior);
	}

	// cf RFC3168 and RFC4996 page 20 :
	// =:= one_bit_choice [ 1 ];
	co_common->ecn_used = GET_REAL(tcp_context->ecn_used);
	rohc_comp_debug(context, "ecn_used = %d", GET_REAL(co_common->ecn_used));

	/* urg_flag */
	co_common->urg_flag = tcp->urg_flag;
	rohc_comp_debug(context, "urg_flag = %d", co_common->urg_flag);
	/* urg_ptr */
	ret = c_static_or_irreg16(tcp->urg_ptr, !tmp->tcp_urg_ptr_changed,
	                          co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode static_or_irreg(urg_ptr)");
		goto error;
	}
	co_common->urg_ptr_present = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "urg_ptr_present = %d (URG pointer encoded on %d bytes)",
	                co_common->urg_ptr_present, ret);

	if(uncomp_pkt_hdrs->innermost_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 =
			uncomp_pkt_hdrs->innermost_ip_hdr->ipv4;

		/* dscp_present =:= irregular(1) [ 1 ] */
		ret = dscp_encode(!tmp->dscp_changed, inner_ipv4->dscp,
		                  co_common_opt, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode dscp_encode(dscp)");
			goto error;
		}
		co_common->dscp_present = indicator;
		co_common_opt += ret;
		co_common_opt_len += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "dscp_present = %d (context = 0x%02x, "
		                "value = 0x%02x) => length = %d bytes",
		                co_common->dscp_present, inner_ip_ctxt->dscp,
		                inner_ipv4->dscp, ret);

		// =:= dont_fragment(version.UVALUE) [ 1 ];
		co_common->df = inner_ipv4->df;
	}
	else
	{
		const struct ipv6_hdr *const inner_ipv6 =
			uncomp_pkt_hdrs->innermost_ip_hdr->ipv6;
		const uint8_t dscp = ipv6_get_dscp(inner_ipv6);

		/* dscp_present =:= irregular(1) [ 1 ] */
		ret = dscp_encode(!tmp->dscp_changed, dscp, co_common_opt,
		                  rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode dscp_encode(dscp)");
			goto error;
		}
		co_common->dscp_present = indicator;
		co_common_opt += ret;
		co_common_opt_len += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "dscp_present = %d (context = 0x%02x, "
		                "value = 0x%02x) => length = %d bytes",
		                co_common->dscp_present, inner_ip_ctxt->dscp,
		                dscp, ret);

		// =:= dont_fragment(version.UVALUE) [ 1 ];
		co_common->df = 0;
	}
	rohc_comp_debug(context, "DF = %d", co_common->df);

	/* ttl_hopl */
	ret = c_static_or_irreg8(uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl,
	                         !tmp->ttl_hopl_changed,
	                         co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode static_or_irreg(ttl_hopl)");
		goto error;
	}
	rohc_comp_debug(context, "TTL/HL = 0x%02x -> 0x%02x", inner_ip_ctxt->ttl_hopl,
	                uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl);
	co_common->ttl_hopl_present = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "ttl_hopl_present = %d (TTL/HL encoded on %d bytes)",
	                co_common->ttl_hopl_present, ret);

	// =:= compressed_value(1, 0) [ 1 ];
	co_common->reserved = 0;

	/* include the list of TCP options if the structure of the list changed
	 * or if some static options changed (irregular chain cannot transmit
	 * static options) */
	if(tmp->tcp_opts.do_list_struct_changed ||
	   tmp->tcp_opts.do_list_static_changed ||
	   tmp->tcp_opts.opt_ts_do_transmit_item)
	{
		/* the structure of the list of TCP options changed or at least one of
		 * the static option changed, compress them */
		bool no_item_needed;
		co_common->list_present = 1;
		ret = c_tcp_code_tcp_opts_list_item(context, uncomp_pkt_hdrs,
		                                    ROHC_CHAIN_CO, &tcp_context->tcp_opts,
		                                    &tmp->tcp_opts,
		                                    co_common_opt, rohc_remain_len,
		                                    &no_item_needed);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to compress TCP options");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		co_common_opt += ret;
		rohc_remain_len -= ret;
#endif
		co_common_opt_len += ret;
		rohc_comp_debug(context, "compressed list of TCP options: %d-byte list "
		                "present", ret);
	}
	else
	{
		/* the structure of the list of TCP options didn't change */
		rohc_comp_debug(context, "compressed list of TCP options: list not present");
		co_common->list_present = 0;
	}

	// =:= crc7(THIS.UVALUE,THIS.ULENGTH) [ 7 ];
	co_common->header_crc = crc;
	rohc_comp_debug(context, "CRC = 0x%x", co_common->header_crc);

	return (sizeof(co_common_t) + co_common_opt_len);

error:
	return -1;
}


/**
 * @brief Detect changes between packet and context
 *
 * @param context          The compression context to compare
 * @param inner_ip_ctxt    The context of the innermost IP header
 * @param uncomp_pkt_hdrs  The uncompressed headers to encode
 * @param tmp              The temporary state for the compressed packet
 * @return                 true if changes were successfully detected,
 *                         false if a problem occurred
 */
static bool tcp_detect_changes(struct rohc_comp_ctxt *const context,
                               ip_context_t *const inner_ip_ctxt, /* TODO: const */
                               const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                               struct tcp_tmp_variables *const tmp)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct sc_tcp_context *const tcp_context = context->specific;
	size_t ip_hdr_pos;
	bool pkt_outer_dscp_changed;
	bool last_pkt_outer_dscp_changed;
	uint8_t pkt_ecn_vals;

	/* no IPv6 extension got its static or dynamic parts changed at the beginning */
	tmp->is_ipv6_exts_list_static_changed = false;
	tmp->is_ipv6_exts_list_dyn_changed = false;

	/* compute or find the new SN */
	tcp_context->msn = c_tcp_get_next_msn(context);
	rohc_comp_debug(context, "MSN = 0x%04x / %u", tcp_context->msn, tcp_context->msn);

	pkt_outer_dscp_changed = 0;
	last_pkt_outer_dscp_changed = false;
	pkt_ecn_vals = 0;
	tmp->ttl_irreg_chain_flag = 0;
	for(ip_hdr_pos = 0; ip_hdr_pos < uncomp_pkt_hdrs->ip_hdrs_nr; ip_hdr_pos++)
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		const bool is_innermost = !!((ip_hdr_pos + 1) == uncomp_pkt_hdrs->ip_hdrs_nr);
		const struct rohc_pkt_ip_hdr *const ip_hdr = &(uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos]);
		const uint8_t dscp = ip_hdr->dscp;
		const uint8_t ecn = ip_hdr->ecn;
		const uint8_t ttl_hl = ip_hdr->ttl_hl;

		rohc_comp_debug(context, "detect changes of IPv%d header #%zu",
		                ip_hdr->version, ip_hdr_pos + 1);

		/* IP DSCP */
		pkt_outer_dscp_changed =
			!!(pkt_outer_dscp_changed || last_pkt_outer_dscp_changed);
		last_pkt_outer_dscp_changed = !!(dscp != ip_context->dscp);
		rohc_comp_debug(context, "  DSCP did%s change: 0x%02x -> 0x%02x",
		                last_pkt_outer_dscp_changed ? "" : "n't",
		                ip_context->dscp, dscp);

		/* IP ECN */
		pkt_ecn_vals |= ecn;

		/* IP TTL/HL */
		if(!is_innermost && ttl_hl != ip_context->ttl_hopl)
		{
			tmp->ttl_irreg_chain_flag |= 1;
			rohc_comp_debug(context, "  TTL/HL did change: 0x%02x -> 0x%02x",
			                ip_context->ttl_hopl, ttl_hl);
		}

		/* IPv6 extension headers */
		if(ip_hdr->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) ip_hdr->ipv6;
			const uint8_t *const ipv6_payload = (const uint8_t *const) (ipv6 + 1);
			const size_t ipv6_payload_len = ip_hdr->tot_len - sizeof(struct ipv6_hdr);

			if(!tcp_detect_changes_ipv6_exts(context, ip_context, tmp, ipv6->nh,
			                                 ipv6_payload, ipv6_payload_len))
			{
				rohc_comp_warn(context, "failed to detect changes in IPv6 extension headers");
				goto error;
			}
		}

	}
	tmp->outer_ip_ttl_changed =
		(tmp->ttl_irreg_chain_flag != 0);
	tcp_field_descr_change(context, "one or more outer TTL/HL values",
	                       tmp->outer_ip_ttl_changed, 0);

	/* TCP ECN */
	pkt_ecn_vals |= uncomp_pkt_hdrs->tcp->ecn_flags;

	/* parse TCP options for changes */
	tcp_detect_options_changes(context, uncomp_pkt_hdrs,
	                           &tcp_context->tcp_opts, &tmp->tcp_opts);

	/* what value for ecn_used? */
	tmp->ecn_used_changed =
		tcp_detect_ecn_used_behavior(context, pkt_ecn_vals, pkt_outer_dscp_changed,
		                             uncomp_pkt_hdrs->tcp->res_flags);

	/* determine the IP-ID behavior of the innermost IPv4 header */
	if(uncomp_pkt_hdrs->innermost_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 =
			uncomp_pkt_hdrs->innermost_ip_hdr->ipv4;
		const uint16_t ip_id = rohc_ntoh16(inner_ipv4->id);

		rohc_comp_debug(context, "IP-ID behaved as %s",
		                rohc_ip_id_behavior_get_descr(inner_ip_ctxt->ip_id_behavior));
		rohc_comp_debug(context, "IP-ID = 0x%04x -> 0x%04x",
		                inner_ip_ctxt->last_ip_id, ip_id);

		if(context->num_sent_packets == 0)
		{
			/* first packet, be optimistic: choose sequential behavior */
			inner_ip_ctxt->ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
		}
		else
		{
			inner_ip_ctxt->ip_id_behavior =
				rohc_comp_detect_ip_id_behavior(inner_ip_ctxt->last_ip_id, ip_id, 1, 19);
		}
		rohc_comp_debug(context, "IP-ID now behaves as %s",
		                rohc_ip_id_behavior_get_descr(inner_ip_ctxt->ip_id_behavior));

		/* does innermost IP-ID behavior changed? */
		tmp->ip_id_behavior_changed =
			(inner_ip_ctxt->last_ip_id_behavior != inner_ip_ctxt->ip_id_behavior);
		tcp_field_descr_change(context, "IP-ID behavior",
		                       tmp->ip_id_behavior_changed, 0);

		/* compute the new innermost IP-ID / SN delta */
		if(inner_ip_ctxt->ip_id_behavior == ROHC_IP_ID_BEHAVIOR_SEQ_SWAP)
		{
			/* specific case of IP-ID delta for sequential swapped behavior */
			tmp->ip_id_delta = swab16(ip_id) - tcp_context->msn;
			rohc_comp_debug(context, "new outer IP-ID delta = 0x%x / %u (behavior = %d)",
			                tmp->ip_id_delta, tmp->ip_id_delta,
			                inner_ip_ctxt->ip_id_behavior);
		}
		else
		{
			/* compute delta the same way for sequential, zero or random: it is
			 * important to always compute the IP-ID delta and record it in W-LSB,
			 * so that the IP-ID deltas of next packets may be correctly encoded */
			tmp->ip_id_delta = ip_id - tcp_context->msn;
			rohc_comp_debug(context, "new outer IP-ID delta = 0x%x / %u (behavior = %d)",
			                tmp->ip_id_delta, tmp->ip_id_delta,
			                inner_ip_ctxt->ip_id_behavior);
		}

		tmp->ip_df_changed = !!(inner_ipv4->df != inner_ip_ctxt->df);
		tcp_field_descr_change(context, "DF", tmp->ip_df_changed, 0);

		tmp->dscp_changed = !!(inner_ipv4->dscp != inner_ip_ctxt->dscp);
		tcp_field_descr_change(context, "DSCP", tmp->dscp_changed, 0);
	}
	else /* IPv6 */
	{
		const struct ipv6_hdr *const inner_ipv6 =
			uncomp_pkt_hdrs->innermost_ip_hdr->ipv6;

		/* no IP-ID for IPv6 */
		tmp->ip_id_delta = 0;
		tmp->ip_id_behavior_changed = false;

		tmp->ip_df_changed = false; /* no DF for IPv6 */

		tmp->dscp_changed =
			!!(ipv6_get_dscp(inner_ipv6) != inner_ip_ctxt->dscp);
		tcp_field_descr_change(context, "DSCP", tmp->dscp_changed, 0);
	}

	/* innermost IPv4/IPv6 DSCP */
	if(tmp->dscp_changed)
	{
		rohc_comp_debug(context, "innermost IP DSCP changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		tcp_context->innermost_dscp_trans_nr = 0;
	}
	else if(tcp_context->innermost_dscp_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "innermost IP DSCP changed in last packets, "
		                "it shall be transmitted %u times more", oa_repetitions_nr -
		                tcp_context->innermost_dscp_trans_nr);
		tmp->dscp_changed = true;
	}

	/* encode innermost IPv4 TTL or IPv6 Hop Limit */
	if(uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl != inner_ip_ctxt->ttl_hopl)
	{
		rohc_comp_debug(context, "innermost IP TTL/HL changed (%u -> %u) "
		                "in current packet, it shall be transmitted %u times",
		                inner_ip_ctxt->ttl_hopl,
		                uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl, oa_repetitions_nr);
		tmp->ttl_hopl_changed = true;
		tcp_context->ttl_hopl_change_count = 0;
	}
	else if(tcp_context->ttl_hopl_change_count < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "innermost IP TTL/HL changed in last packets, "
		                "it shall be transmitted %u times more", oa_repetitions_nr -
		                tcp_context->ttl_hopl_change_count);
		tmp->ttl_hopl_changed = true;
	}
	else
	{
		tmp->ttl_hopl_changed = false;
	}

	/* compute how many bits are needed to send header fields */
	if(!tcp_detect_changes_tcp_hdr(context, uncomp_pkt_hdrs, tmp))
	{
		rohc_comp_warn(context, "failed to compute how many bits are needed to "
		               "transmit all changes in header fields");
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Detect changes about IPv6 extension headers between packet and context
 *
 * @param context        The compression context to compare
 * @param ip_context     The specific IP compression context
 * @param tmp            The temporary state for the compressed packet
 * @param protocol       The protocol type of the first extension header
 * @param exts           The beginning of the IPv6 extension headers
 * @param max_exts_len   The maximum length (in bytes) of the extension headers
 * @return               true if changes were successfully detected,
 *                       false if a problem occurred
 */
static bool tcp_detect_changes_ipv6_exts(struct rohc_comp_ctxt *const context,
                                         ip_context_t *const ip_context, /* TODO: const */
                                         struct tcp_tmp_variables *const tmp,
                                         uint8_t protocol,
                                         const uint8_t *const exts,
                                         const size_t max_exts_len)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint8_t *remain_data = exts;
	size_t remain_len = max_exts_len;
	size_t exts_nr;
	size_t ext_pos;

	exts_nr = 0;
	for(ext_pos = 0;
	    rohc_is_ipv6_opt(protocol) && ext_pos < ROHC_MAX_IP_EXT_HDRS;
	    ext_pos++)
	{
		ip_option_context_t *const opt_ctxt = &(ip_context->opts[ext_pos]);
		const struct ipv6_opt *const ext = (struct ipv6_opt *) remain_data;
		size_t ext_len;

		rohc_comp_debug(context, "  found IP extension header %u", protocol);

		if(remain_len < (sizeof(struct ipv6_opt) - 1))
		{
			rohc_comp_warn(context, "malformed IPv6 extension header: remaining "
			               "data too small for minimal IPv6 header");
			goto error;
		}
		ext_len = ipv6_opt_get_length(ext);
		if(remain_len < ext_len)
		{
			rohc_comp_warn(context, "malformed IPv6 extension header: remaining "
			               "data too small for IPv6 header");
			goto error;
		}

		switch(protocol)
		{
			case ROHC_IPPROTO_HOPOPTS: /* IPv6 Hop-by-Hop option */
			case ROHC_IPPROTO_ROUTING: /* IPv6 routing header */
			case ROHC_IPPROTO_DSTOPTS: /* IPv6 destination option */
				/* - for Hop-by-Hop and Destination options, static chain is required
				 *   only if option length changed
				 * - for Routing option, static chain is required if option length
				 *   changed or content changed */
				if(context->num_sent_packets == 0 ||
				   ext_pos >= ip_context->opts_nr)
				{
					rohc_comp_debug(context, "  IPv6 option %u is new", protocol);
					tmp->is_ipv6_exts_list_static_changed = true;

					/* record option in context */
					/* TODO: should not update context there */
					opt_ctxt->generic.option_length = ext_len;
					assert((ext_len - 2) <= IPV6_OPT_CTXT_LEN_MAX);
					memcpy(opt_ctxt->generic.data, ext->value, ext_len - 2);

				}
				else if(ext_len != opt_ctxt->generic.option_length)
				{
					rohc_comp_debug(context, "  IPv6 option %u changed of length "
					                "(%u -> %zu bytes)", protocol,
					                opt_ctxt->generic.option_length, ext_len);
					tmp->is_ipv6_exts_list_static_changed = true;

					/* record option in context */
					/* TODO: should not update context there */
					opt_ctxt->generic.option_length = ext_len;
					assert((ext_len - 2) <= IPV6_OPT_CTXT_LEN_MAX);
					memcpy(opt_ctxt->generic.data, ext->value, ext_len - 2);
				}
				else if(memcmp(ext->value, opt_ctxt->generic.data, ext_len - 2) != 0)
				{
					rohc_comp_debug(context, "  IPv6 option %u changed of content",
					                protocol);
					if(protocol == ROHC_IPPROTO_ROUTING)
					{
						tmp->is_ipv6_exts_list_static_changed = true;
					}
					else
					{
						tmp->is_ipv6_exts_list_dyn_changed = true;
					}

					/* record option in context */
					/* TODO: should not update context there */
					opt_ctxt->generic.option_length = ext_len;
					assert((ext_len - 2) <= IPV6_OPT_CTXT_LEN_MAX);
					memcpy(opt_ctxt->generic.data, ext->value, ext_len - 2);
				}
				else
				{
					rohc_comp_debug(context, "  IPv6 option %u did not change",
					                protocol);
				}
				break;
			case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
			case ROHC_IPPROTO_MINE: /* TODO: MINE not yet supported */
			case ROHC_IPPROTO_AH:   /* TODO: AH not yet supported */
			default:
				assert(0);
				break;
		}
		protocol = ext->next_header;
		remain_data += ext_len;
		remain_len -= ext_len;
		exts_nr++;
	}
	assert(!rohc_is_ipv6_opt(protocol));
	assert(exts_nr <= ROHC_MAX_IP_EXT_HDRS);

	/* more or less IP extension headers than previous packet? */
	if(context->num_sent_packets == 0)
	{
		rohc_comp_debug(context, "  IP extension headers not sent yet");
		tmp->is_ipv6_exts_list_static_changed = true;
	}
	else if(exts_nr < ip_context->opts_nr)
	{
		rohc_comp_debug(context, "  less IP extension headers (%zu) than "
		                "context (%u)", exts_nr, ip_context->opts_nr);
		tmp->is_ipv6_exts_list_static_changed = true;
	}
	else if(exts_nr > ip_context->opts_nr)
	{
		rohc_comp_debug(context, "  more IP extension headers (%zu+) than "
		                "context (%u)", exts_nr, ip_context->opts_nr);
		tmp->is_ipv6_exts_list_static_changed = true;
	}

	if(tmp->is_ipv6_exts_list_static_changed)
	{
		rohc_comp_debug(context, "  IPv6 extension headers changed too much, static "
		                "chain is required");
		tcp_context->ipv6_exts_list_static_trans_nr = 0;
	}
	else if(tcp_context->ipv6_exts_list_static_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "  IPv6 extension headers changed too much "
		                "in last packets, static chain is required");
		tmp->is_ipv6_exts_list_static_changed = true;
	}
	else if(tmp->is_ipv6_exts_list_dyn_changed)
	{
		rohc_comp_debug(context, "  IPv6 extension headers changed too much, dynamic "
		                "chain is required");
		tcp_context->ipv6_exts_list_dyn_trans_nr = 0;
	}
	else if(tcp_context->ipv6_exts_list_dyn_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "  IPv6 extension headers changed too much "
		                "in last packets, dynamic chain is required");
		tmp->is_ipv6_exts_list_dyn_changed = true;
	}
	else
	{
		rohc_comp_debug(context, "  IPv6 extension headers did not change too much, "
		                "neither static nor dynamic chain is required");
	}

	return true;

error:
	return false;
}


/**
 * @brief Determine the MSN value for the next packet
 *
 * Profile MSN is an internal increasing 16-bit number. See RFC 6846, §6.1.1.
 *
 * @param context     The compression context
 * @return            The MSN value for the next ROHC packet
 */
static uint16_t c_tcp_get_next_msn(const struct rohc_comp_ctxt *const context)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	return (tcp_context->msn + 1); /* wraparound on overflow is expected */
}


/**
 * @brief Decide the state that should be used for the next packet.
 *
 * The three states are:\n
 *  - Initialization and Refresh (IR),\n
 *  - First Order (FO),\n
 *  - Second Order (SO).
 *
 * @param context   The compression context
 * @param pkt_time  The time of packet arrival
 */
static void tcp_decide_state(struct rohc_comp_ctxt *const context,
                             struct rohc_ts pkt_time)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	const rohc_comp_state_t curr_state = context->state;
	rohc_comp_state_t next_state;

	assert(curr_state != ROHC_COMP_STATE_UNKNOWN);

	if(curr_state == ROHC_COMP_STATE_SO)
	{
		/* do not change state */
		rohc_comp_debug(context, "stay in SO state");
		next_state = ROHC_COMP_STATE_SO;
		/* TODO: handle NACK and STATIC-NACK */
	}
	else if(context->state_oa_repeat_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "not enough packets transmitted in current state "
		                "for the moment (%u/%u), so stay in current state",
		                context->state_oa_repeat_nr, oa_repetitions_nr);
		next_state = curr_state;
	}
	else
	{
		rohc_comp_debug(context, "enough packets transmitted in current state "
		                "(%u/%u), go to upper state", context->state_oa_repeat_nr,
		                oa_repetitions_nr);
		next_state = ROHC_COMP_STATE_SO;
	}

	rohc_comp_change_state(context, next_state);

	/* periodic context refreshes (RFC6846, §5.2.1.2) */
	if(context->mode == ROHC_U_MODE)
	{
		rohc_comp_periodic_down_transition(context, pkt_time);
	}
}


/**
 * @brief Encode uncompressed TCP fields with the corresponding encoding scheme
 *
 * @param context          The compression context
 * @param uncomp_pkt_hdrs  The uncompressed headers to encode
 * @param tmp              The temporary state for the compressed packet
 * @return                 true in case of success, false otherwise
 */
static bool tcp_detect_changes_tcp_hdr(struct rohc_comp_ctxt *const context,
                                       const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                       struct tcp_tmp_variables *const tmp)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct sc_tcp_context *const tcp_context = context->specific;
	const struct tcphdr *const tcp = uncomp_pkt_hdrs->tcp;

	tmp->seq_num = rohc_ntoh32(tcp->seq_num);
	tmp->ack_num = rohc_ntoh32(tcp->ack_num);

	rohc_comp_debug(context, "new TCP seq = 0x%08x, ack_seq = 0x%08x",
	                tmp->seq_num, tmp->ack_num);
	rohc_comp_debug(context, "old TCP seq = 0x%08x, ack_seq = 0x%08x",
	                tcp_context->seq_num, tcp_context->ack_num);
	rohc_comp_debug(context, "TCP begin = 0x%04x, res_flags = %d, "
	                "data offset = %d, rsf_flags = %d, ecn_flags = %d, "
	                "URG = %d, ACK = %d, PSH = %d",
	                *(uint16_t *)(((uint8_t *) tcp) + 12),
	                tcp->res_flags, tcp->data_offset, tcp->rsf_flags,
	                tcp->ecn_flags, tcp->urg_flag, tcp->ack_flag,
	                tcp->psh_flag);
	rohc_comp_debug(context, "TCP window = %d (0x%04x), check = 0x%x, "
	                "urg_ptr = %d", rohc_ntoh16(tcp->window),
	                rohc_ntoh16(tcp->window), rohc_ntoh16(tcp->checksum),
	                rohc_ntoh16(tcp->urg_ptr));

	tmp->tcp_ack_flag_changed =
		(tcp->ack_flag != tcp_context->ack_flag);
	tcp_field_descr_change(context, "ACK flag",
	                       tmp->tcp_ack_flag_changed, 0);
	tmp->tcp_urg_flag_present = (tcp->urg_flag != 0);
	tcp_field_descr_present(context, "URG flag",
	                        tmp->tcp_urg_flag_present);
	tmp->tcp_urg_flag_changed =
		(tcp->urg_flag != tcp_context->urg_flag);
	tcp_field_descr_change(context, "URG flag",
	                       tmp->tcp_urg_flag_changed, 0);
	tcp_field_descr_change(context, "ECN flag",
	                       tmp->ecn_used_changed,
	                       tcp_context->ecn_used_change_count);
	if(tcp->rsf_flags != 0)
	{
		rohc_comp_debug(context, "RSF flags is set in current packet");
	}

	/* how many bits are required to encode the new TCP window? */
	if(tcp->window != tcp_context->window_nbo)
	{
		tmp->tcp_window_changed = 1;
		tcp_context->tcp_window_change_count = 0;
	}
	else if(tcp_context->tcp_window_change_count < oa_repetitions_nr)
	{
		tmp->tcp_window_changed = 1;
	}
	else
	{
		tmp->tcp_window_changed = 0;
	}
	tcp_field_descr_change(context, "TCP window", tmp->tcp_window_changed,
	                       tcp_context->tcp_window_change_count);

	/* compute new scaled TCP sequence number */
	{
		const size_t seq_num_factor = uncomp_pkt_hdrs->payload_len;
		uint32_t seq_num_scaled;
		uint32_t seq_num_residue;

		c_field_scaling(&seq_num_scaled, &seq_num_residue, seq_num_factor,
		                tmp->seq_num);
		rohc_comp_debug(context, "seq_num = 0x%x, scaled = 0x%x, factor = %zu, "
		                "residue = 0x%x", tmp->seq_num, seq_num_scaled,
		                seq_num_factor, seq_num_residue);

		if(context->num_sent_packets == 0 ||
		   seq_num_factor == 0 ||
		   seq_num_factor != tcp_context->seq_num_factor ||
		   seq_num_residue != tcp_context->seq_num_residue)
		{
			/* sequence number is not scalable with same parameters any more */
			tcp_context->seq_num_scaling_nr = 0;
		}
		rohc_comp_debug(context, "unscaled sequence number was transmitted at "
		                "least %u / %u times since the scaling factor or "
		                "residue changed", tcp_context->seq_num_scaling_nr,
		                oa_repetitions_nr);

		/* TODO: should update context at the very end only */
		tcp_context->seq_num_scaled = seq_num_scaled;
		tcp_context->seq_num_residue = seq_num_residue;
		tcp_context->seq_num_factor = seq_num_factor;
	}

	/* compute new scaled TCP acknowledgment number */
	{
		const uint32_t ack_delta = tmp->ack_num - tcp_context->ack_num;
		uint16_t ack_stride = 0;
		uint32_t ack_num_scaled;
		uint32_t ack_num_residue;

		/* change ack_stride only if the ACK delta that was most used over the
		 * sliding window changed */
		rohc_comp_debug(context, "ACK delta with previous packet = 0x%04x", ack_delta);
		if(ack_delta == 0)
		{
			ack_stride = tcp_context->ack_stride;
		}
		else
		{
			size_t ack_stride_count = 0;
			size_t i;
			size_t j;

			/* TODO: should update context at the very end only */
			tcp_context->ack_deltas_width[tcp_context->ack_deltas_next] = ack_delta;
			tcp_context->ack_deltas_next = (tcp_context->ack_deltas_next + 1) % 20;

			for(i = 0; i < 20; i++)
			{
				const uint16_t val =
					tcp_context->ack_deltas_width[(tcp_context->ack_deltas_next + i) % 20];
				size_t val_count = 1;

				for(j = i + 1; j < 20; j++)
				{
					if(val == tcp_context->ack_deltas_width[(tcp_context->ack_deltas_next + j) % 20])
					{
						val_count++;
					}
				}

				if(val_count > ack_stride_count)
				{
					ack_stride = val;
					ack_stride_count = val_count;
					if(ack_stride_count > (20/2))
					{
						break;
					}
				}
			}
			rohc_comp_debug(context, "ack_stride 0x%04x was used %zu times in the "
			                "last 20 packets", ack_stride, ack_stride_count);
		}

		/* compute new scaled ACK number & residue */
		c_field_scaling(&ack_num_scaled, &ack_num_residue, ack_stride, tmp->ack_num);
		rohc_comp_debug(context, "ack_number = 0x%x, scaled = 0x%x, factor = %u, "
		                "residue = 0x%x", tmp->ack_num, ack_num_scaled,
		                ack_stride, ack_num_residue);

		if(context->num_sent_packets == 0)
		{
			/* no need to transmit the ack_stride until it becomes non-zero */
			tcp_context->ack_num_scaling_nr = oa_repetitions_nr;
		}
		else
		{
			if(ack_stride != tcp_context->ack_stride ||
			   ack_num_residue != tcp_context->ack_num_residue)
			{
				/* ACK number is not scalable with same parameters any more */
				tcp_context->ack_num_scaling_nr = 0;
			}
			rohc_comp_debug(context, "unscaled ACK number was transmitted at least "
			                "%u / %u times since the scaling factor or residue changed",
			                tcp_context->ack_num_scaling_nr, oa_repetitions_nr);
		}

		/* TODO: should update context at the very end only */
		tcp_context->ack_num_scaled = ack_num_scaled;
		tcp_context->ack_num_residue = ack_num_residue;
		tcp_context->ack_stride = ack_stride;
	}

	/* how many bits are required to encode the new ACK number? */
	tmp->tcp_seq_num_unchanged = (tmp->seq_num == tcp_context->seq_num);
	tcp_field_descr_change(context, "TCP sequence number", !tmp->tcp_seq_num_unchanged, 0);
	tmp->tcp_ack_num_unchanged = (tmp->ack_num == tcp_context->ack_num);
	tcp_field_descr_change(context, "TCP ACK number", !tmp->tcp_ack_num_unchanged, 0);
	tmp->tcp_urg_ptr_changed = (tcp->urg_ptr != tcp_context->urg_ptr_nbo);
	tcp_field_descr_change(context, "TCP URG pointer", tmp->tcp_urg_ptr_changed, 0);

	/* innermost IP-ID behavior that changes shall be transmitted several times */
	if(tmp->ip_id_behavior_changed)
	{
		rohc_comp_debug(context, "innermost IP-ID behavior changed in current "
		                "packet, it shall be transmitted %u times", oa_repetitions_nr);
		tcp_context->innermost_ip_id_behavior_trans_nr = 0;
	}
	else if(tcp_context->innermost_ip_id_behavior_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "innermost IP-ID behavior changed in last packets, "
		                "it shall be transmitted %u times more", oa_repetitions_nr -
		                tcp_context->innermost_ip_id_behavior_trans_nr);
		tmp->ip_id_behavior_changed = true;
	}

	/* TCP sequence number that changes shall be transmitted several times */
	if(!tmp->tcp_seq_num_unchanged)
	{
		rohc_comp_debug(context, "TCP sequence number changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		tcp_context->tcp_seq_num_trans_nr = 0;
	}
	else if(tcp_context->tcp_seq_num_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "TCP sequence number changed in last packets, "
		                "it shall be transmitted %u times more",
		                oa_repetitions_nr - tcp_context->tcp_seq_num_trans_nr);
		tmp->tcp_seq_num_unchanged = false;
	}

	/* TCP ACK number that changes shall be transmitted several times */
	if(!tmp->tcp_ack_num_unchanged)
	{
		rohc_comp_debug(context, "TCP ACK number changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		tcp_context->tcp_ack_num_trans_nr = 0;
	}
	else if(tcp_context->tcp_ack_num_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "TCP ACK number changed in last packets, "
		                "it shall be transmitted %u times more",
		                oa_repetitions_nr - tcp_context->tcp_ack_num_trans_nr);
		tmp->tcp_ack_num_unchanged = false;
	}

	/* TCP URG pointer that changes shall be transmitted several times */
	if(tmp->tcp_urg_ptr_changed)
	{
		rohc_comp_debug(context, "TCP URG pointer changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		tcp_context->tcp_urg_ptr_trans_nr = 0;
	}
	else if(tcp_context->tcp_urg_ptr_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "TCP URG pointer changed in last packets, "
		                "it shall be transmitted %u times more",
		                oa_repetitions_nr - tcp_context->tcp_urg_ptr_trans_nr);
		tmp->tcp_urg_ptr_changed = true;
	}

	return true;
}


/**
 * @brief Decide which packet to send when in the different states.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the innermost IP header
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for the compressed packet
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_DYN, ROHC_PACKET_TCP_RND_[1-8],
 *                              ROHC_PACKET_TCP_SEQ_[1-8] and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_packet(const struct rohc_comp_ctxt *const context,
                                       const ip_context_t *const ip_inner_context,
                                       const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                       const struct tcp_tmp_variables *const tmp)
{
	rohc_packet_t packet_type;

	switch(context->state)
	{
		case ROHC_COMP_STATE_IR: /* The Initialization and Refresh (IR) state */
			rohc_comp_debug(context, "code IR packet");
			packet_type = ROHC_PACKET_IR;
			break;
		case ROHC_COMP_STATE_CR: /* The Context Replication (CR) state */
			if(tmp->is_ipv6_exts_list_static_changed)
			{
				rohc_comp_debug(context, "code IR packet (IPv6 extension list changed)");
				packet_type = ROHC_PACKET_IR;
			}
			else
			{
				rohc_comp_debug(context, "code IR-CR packet");
				packet_type = ROHC_PACKET_IR_CR;
			}
			break;
		case ROHC_COMP_STATE_FO: /* The First Order (FO) state */
			packet_type = tcp_decide_FO_packet(context, ip_inner_context,
			                                   uncomp_pkt_hdrs, tmp);
			break;
		case ROHC_COMP_STATE_SO: /* The Second Order (SO) state */
			packet_type = tcp_decide_SO_packet(context, ip_inner_context,
			                                   uncomp_pkt_hdrs, tmp);
			break;
		case ROHC_COMP_STATE_UNKNOWN:
		default:
#if defined(NDEBUG) || defined(__KERNEL__) || defined(ENABLE_DEAD_CODE)
			packet_type = ROHC_PACKET_UNKNOWN;
#endif
			assert(0); /* should not happen */
			break;
	}

	return packet_type;
}


/**
 * @brief Decide which packet to send when in FO state.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the innermost IP header
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for the compressed packet
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_DYN, ROHC_PACKET_TCP_RND_8,
 *                              ROHC_PACKET_TCP_SEQ_8 and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                          const struct tcp_tmp_variables *const tmp)
{
	const bool crc7_at_least = true;
	return tcp_decide_FO_SO_packet(context, ip_inner_context, uncomp_pkt_hdrs,
	                               tmp, crc7_at_least);
}


/**
 * @brief Decide which packet to send when in SO state.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the inner IP header
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for the compressed packet
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_CR, ROHC_PACKET_IR_DYN,
 *                              ROHC_PACKET_TCP_RND_[1-8],
 *                              ROHC_PACKET_TCP_SEQ_[1-8] and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_SO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                          const struct tcp_tmp_variables *const tmp)
{
	const bool crc7_at_least = false;
	return tcp_decide_FO_SO_packet(context, ip_inner_context, uncomp_pkt_hdrs,
	                               tmp, crc7_at_least);
}


/**
 * @brief Decide which packet to send when in FO or SO state.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the inner IP header
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for the compressed packet
 * @param crc7_at_least     Whether packet types with CRC strictly smaller
 *                          than 8 bits are allowed or not
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_DYN, ROHC_PACKET_TCP_RND_[1-8],
 *                              ROHC_PACKET_TCP_SEQ_[1-8] and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_SO_packet(const struct rohc_comp_ctxt *const context,
                                             const ip_context_t *const ip_inner_context,
                                             const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                             const struct tcp_tmp_variables *const tmp,
                                             const bool crc7_at_least)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct sc_tcp_context *const tcp_context = context->specific;
	const struct tcphdr *const tcp = uncomp_pkt_hdrs->tcp;
	rohc_packet_t packet_type;

	if(tmp->is_ipv6_exts_list_static_changed)
	{
		rohc_comp_debug(context, "force packet IR because at least one IPv6 option "
		                "changed its static part");
		packet_type = ROHC_PACKET_IR;
	}
	else if(tmp->is_ipv6_exts_list_dyn_changed)
	{
		rohc_comp_debug(context, "force packet IR-DYN because at least one IPv6 option "
		                "changed its dynamic part");
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(!wlsb_is_kp_possible_16bits(&tcp_context->msn_wlsb, tcp_context->msn, 4,
	                                    ROHC_LSB_SHIFT_TCP_SN))
	{
		rohc_comp_debug(context, "force packet IR-DYN because the MSN changed "
		                "too much");
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(!rsf_index_enc_possible(tcp->rsf_flags))
	{
		rohc_comp_debug(context, "force packet IR-DYN because the RSF flags are "
		                "not compressible");
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(tmp->outer_ip_ttl_changed ||
	        tmp->ip_id_behavior_changed ||
	        tmp->ip_df_changed ||
	        tmp->dscp_changed ||
	        tmp->tcp_ack_flag_changed ||
	        tmp->tcp_urg_flag_present ||
	        tmp->tcp_urg_flag_changed ||
	        tmp->tcp_urg_ptr_changed ||
	        !tcp_is_ack_stride_static(tcp_context->ack_stride,
	                                  tcp_context->ack_num_scaling_nr,
	                                  oa_repetitions_nr))
	{
		TRACE_GOTO_CHOICE;
		packet_type = ROHC_PACKET_TCP_CO_COMMON;
	}
	else if(tmp->ecn_used_changed ||
	        tmp->ttl_hopl_changed)
	{
		/* use compressed header with a 7-bit CRC (rnd_8, seq_8 or common):
		 *  - use common if too many LSB of sequence number are required
		 *  - use common if too many LSB of sequence number are required
		 *  - use common if too many LSB of innermost TTL/Hop Limit are required
		 *  - use common if window changed */
		if(ip_inner_context->ip_id_behavior <= ROHC_IP_ID_BEHAVIOR_SEQ_SWAP &&
		   wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb, tmp->ip_id_delta, 4, 3) &&
		   wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 14, 8191) &&
		   wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 15, 8191) &&
		   wlsb_is_kp_possible_8bits(&tcp_context->ttl_hopl_wlsb,
		                             uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl,
		                             3, ROHC_LSB_SHIFT_TCP_TTL) &&
		   !tmp->tcp_window_changed)
		{
			/* ROHC_IP_ID_BEHAVIOR_SEQ or ROHC_IP_ID_BEHAVIOR_SEQ_SWAP */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else if(ip_inner_context->ip_id_behavior > ROHC_IP_ID_BEHAVIOR_SEQ_SWAP &&
		        wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 16, 65535) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 16, 16383) &&
		        wlsb_is_kp_possible_8bits(&tcp_context->ttl_hopl_wlsb,
		                                  uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl,
		                                  3, ROHC_LSB_SHIFT_TCP_TTL) &&
		        !tmp->tcp_window_changed)
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_8;
		}
		else
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(ip_inner_context->ip_id_behavior <= ROHC_IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		/* ROHC_IP_ID_BEHAVIOR_SEQ or ROHC_IP_ID_BEHAVIOR_SEQ_SWAP:
		 * co_common or seq_X packet types */
		packet_type = tcp_decide_FO_SO_packet_seq(context, uncomp_pkt_hdrs, tmp,
		                                          crc7_at_least);
	}
	else if(ip_inner_context->ip_id_behavior == ROHC_IP_ID_BEHAVIOR_RAND ||
	        ip_inner_context->ip_id_behavior == ROHC_IP_ID_BEHAVIOR_ZERO)
	{
		/* ROHC_IP_ID_BEHAVIOR_RAND or ROHC_IP_ID_BEHAVIOR_ZERO:
		 * co_common or rnd_X packet types */
		packet_type = tcp_decide_FO_SO_packet_rnd(context, uncomp_pkt_hdrs, tmp,
		                                          crc7_at_least);
	}
	else
	{
		rohc_comp_warn(context, "unexpected IP-ID behavior (%d)",
		               ip_inner_context->ip_id_behavior);
		assert(0);
		goto error;
	}

	rohc_comp_debug(context, "code %s packet",
	                rohc_get_packet_descr(packet_type));

	return packet_type;

error:
	return ROHC_PACKET_UNKNOWN;
}


/**
 * @brief Decide which seq packet to send when in FO or SO state.
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for the compressed packet
 * @param crc7_at_least     Whether packet types with CRC strictly smaller
 *                          than 8 bits are allowed or not
 * @return                  \li The packet type among ROHC_PACKET_TCP_SEQ_[1-8]
 *                              and ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
                                                 const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                 const struct tcp_tmp_variables *const tmp,
                                                 const bool crc7_at_least)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct sc_tcp_context *const tcp_context = context->specific;
	const struct tcphdr *const tcp = uncomp_pkt_hdrs->tcp;
	rohc_packet_t packet_type;

	if(tcp->rsf_flags == 0 &&
	   !tmp->tcp_opts.do_list_struct_changed &&
	   !tmp->tcp_opts.do_list_static_changed &&
	   !tmp->tcp_opts.opt_ts_do_transmit_item &&
	   !tmp->tcp_window_changed &&
	   (tcp->ack_flag == 0 || tmp->tcp_ack_num_unchanged) &&
	   !crc7_at_least &&
	   wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb,
	                              tmp->ip_id_delta, 7, 3) &&
	   tcp_context->seq_num_factor > 0 &&
	   tcp_context->seq_num_scaling_nr >= oa_repetitions_nr &&
	   wlsb_is_kp_possible_32bits(&tcp_context->seq_scaled_wlsb,
	                              tcp_context->seq_num_scaled, 4, 7))
	{
		/* seq_2 is possible */
		TRACE_GOTO_CHOICE;
		assert(uncomp_pkt_hdrs->payload_len > 0);
		packet_type = ROHC_PACKET_TCP_SEQ_2;
	}
	else if(tcp->rsf_flags != 0 ||
	        tmp->tcp_opts.do_list_struct_changed ||
	        tmp->tcp_opts.do_list_static_changed ||
	        tmp->tcp_opts.opt_ts_do_transmit_item)
	{
		/* seq_8 or co_common
		 *
		 * seq_8 can be used if:
		 *  - TCP window didn't change,
		 *  - at most 14 LSB of the TCP sequence number are required,
		 *  - at most 15 LSB of the TCP ACK number are required,
		 *  - at most 4 LSBs of IP-ID must be transmitted
		 * otherwise use co_common packet */
		if(wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb,
		                              tmp->ip_id_delta, 4, 3) &&
		   wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 14, 8191) &&
		   wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 15, 8191) &&
		   wlsb_is_kp_possible_8bits(&tcp_context->ttl_hopl_wlsb,
		                             uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl,
		                             3, ROHC_LSB_SHIFT_TCP_TTL) &&
		   !tmp->tcp_window_changed)
		{
			/* seq_8 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(tmp->tcp_window_changed)
	{
		/* seq_7 or co_common */
		if(!crc7_at_least &&
		   wlsb_is_kp_possible_16bits(&tcp_context->window_wlsb,
		                              rohc_ntoh16(tcp->window), 15, 16383) &&
		   wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb,
		                              tmp->ip_id_delta, 5, 3) &&
		   wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 16, 32767) &&
		   tmp->tcp_seq_num_unchanged)
		{
			/* seq_7 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_7;
		}
		else
		{
			/* seq_7 is not possible, seq_8 neither so fallback on co_common */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(tcp->ack_flag == 0 || tmp->tcp_ack_num_unchanged)
	{
		/* seq_2, seq_1 or co_common */
		if(!crc7_at_least &&
		   wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb,
		                              tmp->ip_id_delta, 7, 3) &&
		   tcp_context->seq_num_factor > 0 &&
		   tcp_context->seq_num_scaling_nr >= oa_repetitions_nr &&
		   wlsb_is_kp_possible_32bits(&tcp_context->seq_scaled_wlsb,
		                              tcp_context->seq_num_scaled, 4, 7))
		{
			/* seq_2 is possible */
			TRACE_GOTO_CHOICE;
			assert(uncomp_pkt_hdrs->payload_len > 0);
			packet_type = ROHC_PACKET_TCP_SEQ_2;
		}
		else if(!crc7_at_least &&
		        wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb,
		                                   tmp->ip_id_delta, 4, 3) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 16, 32767))
		{
			/* seq_1 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_1;
		}
		else if(wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb,
		                                   tmp->ip_id_delta, 4, 3) &&
		        true /* TODO: no more than 3 bits of TTL */ &&
		        wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 14, 8191) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 15, 8191))
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(tmp->tcp_seq_num_unchanged)
	{
		/* seq_4, seq_3, or co_common */
		if(!crc7_at_least &&
		   wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb,
		                              tmp->ip_id_delta, 3, 1) &&
		   tcp_is_ack_scaled_possible(tcp_context->ack_stride,
		                              tcp_context->ack_num_scaling_nr,
		                              oa_repetitions_nr) &&
		   wlsb_is_kp_possible_32bits(&tcp_context->ack_scaled_wlsb,
		                              tcp_context->ack_num_scaled, 4, 3))
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_4;
		}
		else if(!crc7_at_least &&
		        wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb,
		                                   tmp->ip_id_delta, 4, 3) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 16, 16383))
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_3;
		}
		else if(wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb,
		                                   tmp->ip_id_delta, 4, 3) &&
		        true /* TODO: no more than 3 bits of TTL */ &&
		        wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 14, 8191) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 15, 8191))
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(wlsb_is_kp_possible_16bits(&tcp_context->ip_id_wlsb,
	                                   tmp->ip_id_delta, 4, 3))
	{
		/* sequence and acknowledgment numbers changed:
		 * seq_6, seq_5, seq_8 or co_common */
		if(!crc7_at_least &&
		   tcp_context->seq_num_factor > 0 &&
		   tcp_context->seq_num_scaling_nr >= oa_repetitions_nr &&
		   wlsb_is_kp_possible_32bits(&tcp_context->seq_scaled_wlsb,
		                              tcp_context->seq_num_scaled, 4, 7) &&
		   wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 16, 16383))
		{
			TRACE_GOTO_CHOICE;
			assert(uncomp_pkt_hdrs->payload_len > 0);
			packet_type = ROHC_PACKET_TCP_SEQ_6;
		}
		else if(!crc7_at_least &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 16, 16383) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 16, 32767))
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_5;
		}
		else if(wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 14, 8191) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 15, 8191) &&
		        wlsb_is_kp_possible_8bits(&tcp_context->ttl_hopl_wlsb,
		                                  uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl,
		                                  3, ROHC_LSB_SHIFT_TCP_TTL) &&
		        !tmp->tcp_window_changed)
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else
	{
		TRACE_GOTO_CHOICE;
		packet_type = ROHC_PACKET_TCP_CO_COMMON;
	}

	/* IP-ID is sequential, so only co_common and seq_X packets are allowed */
	assert(packet_type == ROHC_PACKET_TCP_CO_COMMON ||
	       (packet_type >= ROHC_PACKET_TCP_SEQ_1 &&
	        packet_type <= ROHC_PACKET_TCP_SEQ_8));

	return packet_type;
}


/**
 * @brief Decide which rnd packet to send when in FO or SO state.
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for the compressed packet
 * @param crc7_at_least     Whether packet types with CRC strictly smaller
 *                          than 8 bits are allowed or not
 * @return                  \li The packet type among ROHC_PACKET_TCP_SEQ_[1-8]
 *                              and ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
                                                 const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                 const struct tcp_tmp_variables *const tmp,
                                                 const bool crc7_at_least)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct sc_tcp_context *const tcp_context = context->specific;
	const struct tcphdr *const tcp = uncomp_pkt_hdrs->tcp;
	rohc_packet_t packet_type;

	if(tcp->rsf_flags == 0 &&
	   !tmp->tcp_opts.do_list_struct_changed &&
	   !tmp->tcp_opts.do_list_static_changed &&
	   !tmp->tcp_opts.opt_ts_do_transmit_item &&
	   !tmp->tcp_window_changed &&
	   !crc7_at_least &&
	   tmp->tcp_ack_num_unchanged &&
	   uncomp_pkt_hdrs->payload_len > 0 &&
	   tcp_context->seq_num_factor > 0 &&
	   tcp_context->seq_num_scaling_nr >= oa_repetitions_nr &&
	   wlsb_is_kp_possible_32bits(&tcp_context->seq_scaled_wlsb,
	                              tcp_context->seq_num_scaled, 4, 7))
	{
		/* rnd_2 is possible */
		assert(uncomp_pkt_hdrs->payload_len > 0);
		TRACE_GOTO_CHOICE;
		packet_type = ROHC_PACKET_TCP_RND_2;
	}
	else if(tcp->rsf_flags != 0 ||
	        tmp->tcp_opts.do_list_struct_changed ||
	        tmp->tcp_opts.do_list_static_changed ||
	        tmp->tcp_opts.opt_ts_do_transmit_item)
	{
		if(!tmp->tcp_window_changed &&
		   wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 16, 65535) &&
		   wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 16, 16383))
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_8;
		}
		else
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else /* unchanged structure of the list of TCP options */
	{
		if(tmp->tcp_window_changed)
		{
			if(!crc7_at_least &&
			   tmp->tcp_seq_num_unchanged &&
			   wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 18, 65535))
			{
				/* rnd_7 is possible */
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_RND_7;
			}
			else
			{
				/* rnd_7 is not possible, rnd_8 neither so fallback on co_common */
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		}
		else if(!crc7_at_least &&
		        tmp->tcp_ack_num_unchanged &&
		        uncomp_pkt_hdrs->payload_len > 0 &&
		        tcp_context->seq_num_factor > 0 &&
		        tcp_context->seq_num_scaling_nr >= oa_repetitions_nr &&
		        wlsb_is_kp_possible_32bits(&tcp_context->seq_scaled_wlsb,
		                                   tcp_context->seq_num_scaled, 4, 7))
		{
			/* rnd_2 is possible */
			assert(uncomp_pkt_hdrs->payload_len > 0);
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_2;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        tcp_is_ack_scaled_possible(tcp_context->ack_stride,
		                                   tcp_context->ack_num_scaling_nr,
		                                   oa_repetitions_nr) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_scaled_wlsb,
		                                   tcp_context->ack_num_scaled, 4, 3) &&
		        tmp->tcp_seq_num_unchanged)
		{
			/* rnd_4 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_4;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        tmp->tcp_seq_num_unchanged &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 15, 8191))
		{
			/* rnd_3 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_3;
		}
		else if(!crc7_at_least &&
		        wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 18, 65535) &&
		        tmp->tcp_ack_num_unchanged)
		{
			/* rnd_1 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_1;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        tcp_context->seq_num_factor > 0 &&
		        tcp_context->seq_num_scaling_nr >= oa_repetitions_nr &&
		        wlsb_is_kp_possible_32bits(&tcp_context->seq_scaled_wlsb,
		                                   tcp_context->seq_num_scaled, 4, 7) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 16, 16383))
		{
			/* ACK number present */
			/* rnd_6 is possible */
			assert(uncomp_pkt_hdrs->payload_len > 0);
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_6;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 14, 8191) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 15, 8191))
		{
			/* ACK number present */
			/* rnd_5 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_5;
		}
		else if(/* !tmp->tcp_window_changed && */
		        wlsb_is_kp_possible_32bits(&tcp_context->seq_wlsb, tmp->seq_num, 16, 65535) &&
		        wlsb_is_kp_possible_32bits(&tcp_context->ack_wlsb, tmp->ack_num, 16, 16383))
		{
			/* fallback on rnd_8 */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_8;
		}
		else
		{
			/* rnd_8 is not possible, fallback on co_common */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	} /* end of case 'unchanged structure of the list of TCP options' */

	/* IP-ID is NOT sequential, so only co_common and rnd_X packets are allowed */
	assert(packet_type == ROHC_PACKET_TCP_CO_COMMON ||
	       (packet_type >= ROHC_PACKET_TCP_RND_1 &&
	        packet_type <= ROHC_PACKET_TCP_RND_8));

	return packet_type;
}


/**
 * @brief Detect the behavior of the IP/TCP ECN flags and TCP RES flags
 *
 * What value for ecn_used? The ecn_used controls the presence of IP ECN flags,
 * TCP ECN flags, but also TCP RES flags.
 *
 * @param[in,out] context         The compression context to compare
 * @param pkt_ecn_vals            The values of the IP/ECN flags in the current packet
 * @param pkt_outer_dscp_changed  Whether at least one DSCP changed in the current packet
 * @param pkt_res_val             The TCP RES flags in the current packet
 * @return                        Whether the ecn_used flag changed or not 
 */
static bool tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
                                         const uint8_t pkt_ecn_vals,
                                         const uint8_t pkt_outer_dscp_changed,
                                         const uint8_t pkt_res_val)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct sc_tcp_context *const tcp_context = context->specific;
	bool ecn_used_changed;

	const bool ecn_used_change_needed_by_outer_dscp =
		(pkt_outer_dscp_changed && !tcp_context->ecn_used);
	const bool tcp_res_flag_changed =
		(pkt_res_val != tcp_context->res_flags);
	const bool ecn_used_change_needed_by_res_flags =
		(tcp_res_flag_changed && !tcp_context->ecn_used);
	const bool ecn_used_change_needed_by_ecn_flags_unset =
		(pkt_ecn_vals == 0 && tcp_context->ecn_used);
	const bool ecn_used_change_needed_by_ecn_flags_set =
		(pkt_ecn_vals != 0 && !tcp_context->ecn_used);
	const bool ecn_used_change_needed =
		(ecn_used_change_needed_by_outer_dscp ||
		 ecn_used_change_needed_by_res_flags ||
		 ecn_used_change_needed_by_ecn_flags_unset ||
		 ecn_used_change_needed_by_ecn_flags_set);

	tcp_field_descr_change(context, "RES flags", tcp_res_flag_changed, 0);
	rohc_comp_debug(context, "ECN: context did%s use ECN",
	                tcp_context->ecn_used ? "" : "n't");
	rohc_comp_debug(context, "ECN: packet does%s use ECN",
	                pkt_ecn_vals != 0 ? "" : "n't");

	/* is a change of ecn_used value required? */
	if(ecn_used_change_needed)
	{
		/* a change of ecn_used value seems to be required */
		if(ecn_used_change_needed_by_ecn_flags_unset &&
		   tcp_context->ecn_used_zero_count < oa_repetitions_nr)
		{
			/* do not change ecn_used = 0 too quickly, wait for a few packets
			 * that do not need ecn_used = 1 to actually perform the change */
			rohc_comp_debug(context, "ECN: packet doesn't use ECN any more but "
			                "context does, wait for %u more packets without ECN "
			                "before changing the context ecn_used parameter",
			                oa_repetitions_nr - tcp_context->ecn_used_zero_count);
			ecn_used_changed = false;
			tcp_context->ecn_used_zero_count++;
		}
		else
		{
			rohc_comp_debug(context, "ECN: behavior changed");
			ecn_used_changed = true;
			tcp_context->ecn_used =
				!!(pkt_ecn_vals != 0 || tcp_res_flag_changed || pkt_outer_dscp_changed);
			tcp_context->ecn_used_change_count = 0;
			tcp_context->ecn_used_zero_count = 0;
		}
	}
	else if(tcp_context->ecn_used_change_count < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "ECN: behavior didn't change but changed a few "
		                "packet before");
		ecn_used_changed = true;
		tcp_context->ecn_used_change_count++;
		tcp_context->ecn_used_zero_count = 0;
	}
	else
	{
		rohc_comp_debug(context, "ECN: behavior didn't change");
		ecn_used_changed = false;
		tcp_context->ecn_used_zero_count = 0;
	}
	rohc_comp_debug(context, "ECN: context does%s use ECN",
	                tcp_context->ecn_used ? "" : "n't");

	return ecn_used_changed;
}


/**
 * @brief Print a debug trace for the field change
 *
 * @param context  The compression context
 * @param name     The name of the field
 * @param changed  Whether the field changed or not
 * @param nr_trans The number of times the field was transmitted since
 *                 the last change
 */
static void tcp_field_descr_change(const struct rohc_comp_ctxt *const context,
                                   const char *const name,
                                   const bool changed,
                                   const size_t nr_trans)
{
	if(!changed)
	{
		rohc_comp_debug(context, "%s did not change", name);
	}
	else if(nr_trans == 0)
	{
		rohc_comp_debug(context, "%s did change with the current packet", name);
	}
	else
	{
		rohc_comp_debug(context, "%s did change %zu packets before", name, nr_trans);
	}
}


/**
 * @brief Print a debug trace for the field presence
 *
 * @param context  The compression context
 * @param name     The name of the field
 * @param present  Whether the field is present or not
 */
static void tcp_field_descr_present(const struct rohc_comp_ctxt *const context,
                                    const char *const name,
                                    const bool present)
{
	rohc_comp_debug(context, "%s is%s present", name, present ? "" : " not");
}


/**
 * @brief Update the profile when feedback is received
 *
 * This function is one of the functions that must exist in one profile for
 * the framework to work.
 *
 * @param context            The compression context
 * @param feedback_type      The feedback type
 * @param packet             The whole feedback packet with CID bits
 * @param packet_len         The length of the whole feedback packet with CID bits
 * @param feedback_data      The feedback data without the CID bits
 * @param feedback_data_len  The length of the feedback data without the CID bits
 * @return                   true if the feedback was successfully handled,
 *                           false if the feedback could not be taken into account
 */
static bool c_tcp_feedback(struct rohc_comp_ctxt *const context,
                           const enum rohc_feedback_type feedback_type,
                           const uint8_t *const packet,
                           const size_t packet_len,
                           const uint8_t *const feedback_data,
                           const size_t feedback_data_len)
{
	if(feedback_type == ROHC_FEEDBACK_1)
	{
		const bool sn_not_valid = false;
		uint32_t sn_bits;
		size_t sn_bits_nr;

		rohc_comp_debug(context, "FEEDBACK-1 received");
		assert(feedback_data_len == 1);

		/* get the 8 LSB bits of the acknowledged SN */
		sn_bits = feedback_data[0] & 0xff;
		sn_bits_nr = 8;

		rohc_comp_debug(context, "ACK received (CID = %u, %zu-bit SN = 0x%02x)",
		                context->cid, sn_bits_nr, sn_bits);

		/* the compressor received a positive ACK */
		c_tcp_feedback_ack(context, sn_bits, sn_bits_nr, sn_not_valid);
	}
	else if(feedback_type == ROHC_FEEDBACK_2)
	{
		rohc_comp_debug(context, "FEEDBACK-2 received");

		if(!c_tcp_feedback_2(context, packet, packet_len, feedback_data,
		                     feedback_data_len))
		{
			rohc_comp_warn(context, "failed to handle FEEDBACK-2");
			goto error;
		}
	}
	else /* not FEEDBACK-1 nor FEEDBACK-2 */
	{
		rohc_comp_warn(context, "feedback type not implemented (%d)", feedback_type);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Update the profile when FEEDBACK-2 is received
 *
 * @param context            The compression context
 * @param packet             The whole feedback packet with CID bits
 * @param packet_len         The length of the whole feedback packet with CID bits
 * @param feedback_data      The feedback data without the CID bits
 * @param feedback_data_len  The length of the feedback data without the CID bits
 * @return                   true if the feedback was successfully handled,
 *                           false if the feedback could not be taken into account
 */
static bool c_tcp_feedback_2(struct rohc_comp_ctxt *const context,
                             const uint8_t *const packet,
                             const size_t packet_len,
                             const uint8_t *const feedback_data,
                             const size_t feedback_data_len)
{
	const uint8_t *remain_data = feedback_data;
	size_t remain_len = feedback_data_len;
	const struct rohc_feedback_2_rfc6846 *feedback2;

	size_t opts_present[ROHC_FEEDBACK_OPT_MAX] = { 0 };

	uint8_t crc_in_packet;
	size_t crc_pos_from_end;

	uint32_t sn_bits;
	size_t sn_bits_nr;

	/* retrieve acked SN */
	if(remain_len < sizeof(struct rohc_feedback_2_rfc6846))
	{
		rohc_comp_warn(context, "malformed FEEDBACK-2: packet too short for the "
		               "minimal %zu-byte header, only %zu bytes remaining",
		               sizeof(struct rohc_feedback_2_rfc6846), remain_len);
		goto error;
	}
	feedback2 = (const struct rohc_feedback_2_rfc6846 *) feedback_data;
	sn_bits = (feedback2->sn1 << 8) | feedback2->sn2;
	sn_bits_nr = 6 + 8;
	crc_in_packet = feedback2->crc;
	crc_pos_from_end = remain_len - 2;
	remain_data += 3;
	remain_len -= 3;

	/* parse FEEDBACK-2 options */
	if(!rohc_comp_feedback_parse_opts(context, packet, packet_len,
	                                  remain_data, remain_len,
	                                  opts_present, &sn_bits, &sn_bits_nr,
	                                  ROHC_FEEDBACK_WITH_CRC_BASE,
	                                  crc_in_packet, crc_pos_from_end))
	{
		rohc_comp_warn(context, "malformed FEEDBACK-2: failed to parse options");
		goto error;
	}

	/* change from U- to O-mode once feedback channel is established */
	rohc_comp_change_mode(context, ROHC_O_MODE);

	/* act according to the type of feedback */
	switch(feedback2->ack_type)
	{
		case ROHC_FEEDBACK_ACK:
		{
			const bool sn_not_valid = !!(opts_present[ROHC_FEEDBACK_OPT_SN_NOT_VALID] > 0);

			rohc_comp_debug(context, "ACK received (CID = %u, %zu-bit SN = 0x%x, "
			                "SN-not-valid = %d)", context->cid, sn_bits_nr, sn_bits,
			                GET_REAL(sn_not_valid));

			/* the compressor received a positive ACK */
			c_tcp_feedback_ack(context, sn_bits, sn_bits_nr, sn_not_valid);
			break;
		}
		case ROHC_FEEDBACK_NACK:
		{
			/* RFC3095 §5.4.1.1.1: NACKs, downward transition */
			rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			          "NACK received for CID %u", context->cid);
			/* the compressor transits back to the FO state */
			if(context->state == ROHC_COMP_STATE_SO)
			{
				rohc_comp_change_state(context, ROHC_COMP_STATE_FO);
			}
			/* TODO: use the SN field to determine the latest packet successfully
			 * decompressed and then determine what fields need to be updated */
			break;
		}
		case ROHC_FEEDBACK_STATIC_NACK:
		{
			/* RFC3095 §5.4.1.1.1: NACKs, downward transition */
			rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			          "STATIC-NACK received for CID %u", context->cid);
			/* the compressor transits back to the IR state */
			rohc_comp_change_state(context, ROHC_COMP_STATE_IR);
			/* TODO: use the SN field to determine the latest packet successfully
			 * decompressed and then determine what fields need to be updated */
			break;
		}
		case ROHC_FEEDBACK_RESERVED:
		{
			/* RFC3095 §5.7.6.1: reserved (MUST NOT be used for parseability) */
			rohc_comp_warn(context, "malformed FEEDBACK-2: reserved ACK type used");
			goto error;
		}
		default:
		{
			/* impossible value */
			rohc_comp_warn(context, "malformed FEEDBACK-2: unknown ACK type %u",
			               feedback2->ack_type);
			goto error;
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Perform the required actions after the reception of a positive ACK
 *
 * @param context       The compression context that received a positive ACK
 * @param sn_bits       The LSB bits of the acknowledged SN
 * @param sn_bits_nr    The number of LSB bits of the acknowledged SN
 * @param sn_not_valid  Whether the received SN may be considered as valid or not
 */
static void c_tcp_feedback_ack(struct rohc_comp_ctxt *const context,
                               const uint32_t sn_bits,
                               const size_t sn_bits_nr,
                               const bool sn_not_valid)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	/* the W-LSB encoding scheme as defined by function lsb() in RFC4997 uses a
	 * sliding window with a large limited maximum width ; once the feedback channel
	 * is established, positive ACKs may remove older values from the windows */
	if(!sn_not_valid)
	{
		size_t acked_nr;

		assert(sn_bits_nr <= 16);
		assert(sn_bits <= 0xffffU);

		/* ack TTL or Hop Limit */
		acked_nr = wlsb_ack(&tcp_context->ttl_hopl_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TTL or Hop Limit W-LSB", acked_nr);
		/* ack innermost IP-ID */
		acked_nr = wlsb_ack(&tcp_context->ip_id_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from innermost IP-ID W-LSB", acked_nr);
		/* ack TCP window */
		acked_nr = wlsb_ack(&tcp_context->window_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP window W-LSB", acked_nr);
		/* ack TCP (scaled) sequence number */
		acked_nr = wlsb_ack(&tcp_context->seq_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP sequence number W-LSB", acked_nr);
		acked_nr = wlsb_ack(&tcp_context->seq_scaled_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP scaled sequence number W-LSB", acked_nr);
		/* ack TCP (scaled) acknowledgment number */
		acked_nr = wlsb_ack(&tcp_context->ack_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP acknowledgment number W-LSB", acked_nr);
		acked_nr = wlsb_ack(&tcp_context->ack_scaled_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP scaled acknowledgment number W-LSB", acked_nr);
		/* ack TCP TS option */
		acked_nr = wlsb_ack(&tcp_context->tcp_opts.ts_req_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP TS request W-LSB", acked_nr);
		acked_nr = wlsb_ack(&tcp_context->tcp_opts.ts_reply_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP TS reply W-LSB", acked_nr);
		/* ack SN */
		acked_nr = wlsb_ack(&tcp_context->msn_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from SN W-LSB", acked_nr);
	}

	/* RFC 6846, §5.2.2.1:
	 *   The compressor MAY use acknowledgment feedback (ACKs) to move to a
	 *   higher compression state.
	 *   Upon reception of an ACK for a context-updating packet, the
	 *   compressor obtains confidence that the decompressor has received the
	 *   acknowledged packet and that it has observed changes in the packet
	 *   flow up to the acknowledged packet. */
	if(context->state != ROHC_COMP_STATE_SO && !sn_not_valid)
	{
		uint16_t sn_mask;
		if(sn_bits_nr < 16)
		{
			sn_mask = (1U << sn_bits_nr) - 1;
		}
		else
		{
			sn_mask = 0xffffU;
		}
		assert((sn_bits & sn_mask) == sn_bits);

		if(!wlsb_is_sn_present(&tcp_context->msn_wlsb,
		                       tcp_context->msn_of_last_ctxt_updating_pkt) ||
		   sn_bits == (tcp_context->msn_of_last_ctxt_updating_pkt & sn_mask))
		{
			/* decompressor acknowledged some SN, so some SNs were removed from the
			 * W-LSB windows; the SN of the last context-updating packet was part of
			 * the SNs that were acknowledged, so the compressor is 100% sure that
			 * the decompressor received the packet and updated its context in
			 * consequence, so the compressor may transit to a higher compression
			 * state immediately! */
			rohc_comp_debug(context, "FEEDBACK-2: positive ACK makes the compressor "
			                "transit to the SO state more quickly (context-updating "
			                "packet with SN %u was acknowledged by decompressor)",
			                tcp_context->msn_of_last_ctxt_updating_pkt);
			rohc_comp_change_state(context, ROHC_COMP_STATE_SO);
		}
		else
		{
			rohc_comp_debug(context, "FEEDBACK-2: positive ACK DOES NOT make the "
			                "compressor transit to the SO state more quickly "
			                "(context-updating packet with SN %u was NOT acknowledged "
			                "YET by decompressor)",
			                tcp_context->msn_of_last_ctxt_updating_pkt);
		}
	}
}


/**
 * @brief Define the compression part of the TCP profile as described
 *        in the RFC 3095.
 */
const struct rohc_comp_profile c_tcp_profile =
{
	.id             = ROHC_PROFILE_TCP, /* profile ID (see 8 in RFC 3095) */
	.create         = c_tcp_create_from_pkt,     /* profile handlers */
	.clone          = c_tcp_create_from_ctxt,
	.destroy        = c_tcp_destroy,
	.is_cr_possible = c_tcp_is_cr_possible,
	.encode         = c_tcp_encode,
	.feedback       = c_tcp_feedback,
};

