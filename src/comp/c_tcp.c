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
#include "net_pkt.h"
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
                                  const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static void c_tcp_destroy(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

static bool c_tcp_check_profile(const struct rohc_comp *const comp,
                                const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool c_tcp_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet,
                                size_t *const cr_score)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int c_tcp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));

static uint16_t c_tcp_get_next_msn(const struct rohc_comp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1)));

static bool tcp_detect_changes(struct rohc_comp_ctxt *const context,
                               const struct net_pkt *const uncomp_pkt,
                               ip_context_t **const ip_inner_context,
                               const struct tcphdr **const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static bool tcp_detect_changes_ipv6_exts(struct rohc_comp_ctxt *const context,
                                         ip_context_t *const ip_context,
                                         uint8_t *const protocol,
                                         const uint8_t *const exts,
                                         const size_t max_exts_len,
                                         size_t *const exts_nr,
                                         size_t *const exts_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 6, 7)));

static void tcp_decide_state(struct rohc_comp_ctxt *const context,
                             struct rohc_ts pkt_time)
	__attribute__((nonnull(1)));

static bool tcp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt,
                                     const struct tcphdr *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static bool tcp_encode_uncomp_ip_fields(struct rohc_comp_ctxt *const context,
                                        const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static bool tcp_encode_uncomp_tcp_fields(struct rohc_comp_ctxt *const context,
                                         const struct tcphdr *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static rohc_packet_t tcp_decide_packet(struct rohc_comp_ctxt *const context,
                                       const ip_context_t *const ip_inner_context,
                                       const struct tcphdr *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_FO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct tcphdr *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_SO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct tcphdr *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_FO_SO_packet(const struct rohc_comp_ctxt *const context,
                                             const ip_context_t *const ip_inner_context,
                                             const struct tcphdr *const tcp,
                                             const bool crc7_at_least)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
                                                 const struct tcphdr *const tcp,
                                                 const bool crc7_at_least)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
                                                 const struct tcphdr *const tcp,
                                                 const bool crc7_at_least)
	__attribute__((warn_unused_result, nonnull(1, 2)));

/* IR and CO packets */
static int code_IR_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *const ip,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6)));

static int code_CO_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *ip,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6)));
static int co_baseheader(struct rohc_comp_ctxt *const context,
                         struct sc_tcp_context *const tcp_context,
                         ip_context_t *const ip_inner_context,
                         const struct ip_hdr *const inner_ip_hdr,
                         const size_t inner_ip_hdr_len,
                         uint8_t *const rohc_pkt,
                         const size_t rohc_pkt_max_len,
                         const rohc_packet_t packet_type,
                         const struct tcphdr *const tcp,
                         const uint8_t crc)
	__attribute__((nonnull(1, 2, 3, 4, 6, 9), warn_unused_result));


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
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));


/*
 * Functions that build the seq_X packets
 */

static int c_tcp_build_seq_1(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_2(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_3(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_4(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_5(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_6(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_7(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_co_common(const struct rohc_comp_ctxt *const context,
                                 const ip_context_t *const inner_ip_ctxt,
                                 struct sc_tcp_context *const tcp_context,
                                 const struct ip_hdr *const inner_ip_hdr,
                                 const size_t inner_ip_hdr_len,
                                 const struct tcphdr *const tcp,
                                 const uint8_t crc,
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));



/*
 * Misc functions
 */

static void tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
                                         const uint8_t pkt_ecn_vals,
                                         const uint8_t pkt_outer_dscp_changed,
                                         const uint8_t pkt_res_val)
	__attribute__((nonnull(1)));

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
	const size_t wlsb_size = sizeof(struct c_wlsb);
	struct sc_tcp_context *tcp_ctxt;

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
	memcpy(&tcp_ctxt->msn_wlsb, &base_tcp_ctxt->msn_wlsb, wlsb_size);
	/* IP-ID offset */
	memcpy(&tcp_ctxt->ip_id_wlsb, &base_tcp_ctxt->ip_id_wlsb, wlsb_size);
	/* innermost IPv4 TTL or IPv6 Hop Limit */
	memcpy(&tcp_ctxt->ttl_hopl_wlsb, &base_tcp_ctxt->ttl_hopl_wlsb, wlsb_size);
	/* TCP window */
	memcpy(&tcp_ctxt->window_wlsb, &base_tcp_ctxt->window_wlsb, wlsb_size);
	/* TCP sequence number */
	memcpy(&tcp_ctxt->seq_wlsb, &base_tcp_ctxt->seq_wlsb, wlsb_size);
	memcpy(&tcp_ctxt->seq_scaled_wlsb, &base_tcp_ctxt->seq_scaled_wlsb, wlsb_size);
	/* TCP acknowledgment (ACK) number */
	memcpy(&tcp_ctxt->ack_wlsb, &base_tcp_ctxt->ack_wlsb, wlsb_size);
	memcpy(&tcp_ctxt->ack_scaled_wlsb, &base_tcp_ctxt->ack_scaled_wlsb, wlsb_size);

	/* init the Master Sequence Number to a random value */
	tcp_ctxt->msn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(ctxt, "MSN = 0x%04x / %u", tcp_ctxt->msn, tcp_ctxt->msn);

	/* TCP option Timestamp (request) */
	memcpy(&tcp_ctxt->tcp_opts.ts_req_wlsb, &base_tcp_ctxt->tcp_opts.ts_req_wlsb, wlsb_size);
	/* TCP option Timestamp (reply) */
	memcpy(&tcp_ctxt->tcp_opts.ts_reply_wlsb, &base_tcp_ctxt->tcp_opts.ts_reply_wlsb, wlsb_size);

	return true;

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
                                  const struct net_pkt *const packet)
{
	const struct rohc_comp *const comp = context->compressor;
	struct sc_tcp_context *tcp_context;
	const uint8_t *remain_data = packet->outer_ip.data;
	size_t remain_len = packet->outer_ip.size;
	const struct tcphdr *tcp;
	uint8_t proto;
	size_t i;

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
		ip_context->ctxt.vx.version = ip->version;

		switch(ip->version)
		{
			case IPV4:
			{
				const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

				assert(remain_len >= sizeof(struct ipv4_hdr));
				proto = ipv4->protocol;

				ip_context->ctxt.v4.last_ip_id = rohc_ntoh16(ipv4->id);
				rohc_comp_debug(context, "IP-ID 0x%04x", ip_context->ctxt.v4.last_ip_id);
				ip_context->ctxt.v4.last_ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
				ip_context->ctxt.v4.ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
				ip_context->ctxt.v4.protocol = proto;
				ip_context->ctxt.v4.dscp = ipv4->dscp;
				ip_context->ctxt.v4.df = ipv4->df;
				ip_context->ctxt.v4.ttl = ipv4->ttl;
				ip_context->ctxt.v4.src_addr = ipv4->saddr;
				ip_context->ctxt.v4.dst_addr = ipv4->daddr;

				remain_data += sizeof(struct ipv4_hdr);
				remain_len -= sizeof(struct ipv4_hdr);
				break;
			}
			case IPV6:
			{
				const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;

				assert(remain_len >= sizeof(struct ipv6_hdr));
				proto = ipv6->nh;

				ip_context->ctxt.v6.ip_id_behavior = ROHC_IP_ID_BEHAVIOR_RAND;
				ip_context->ctxt.v6.dscp = remain_data[1];
				ip_context->ctxt.v6.hopl = ipv6->hl;
				ip_context->ctxt.v6.flow_label = ipv6_get_flow_label(ipv6);
				memcpy(ip_context->ctxt.v6.src_addr, &ipv6->saddr,
				       sizeof(struct ipv6_addr));
				memcpy(ip_context->ctxt.v6.dest_addr, &ipv6->daddr,
				       sizeof(struct ipv6_addr));

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
				ip_context->ctxt.v6.next_header = proto;
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
	tcp_context->tcp_seq_num_change_count = 0;
	tcp_context->ttl_hopl_change_count = 0;
	tcp_context->tcp_window_change_count = 0;
	tcp_context->ecn_used = false;
	tcp_context->ecn_used_change_count = MAX_FO_COUNT;
	tcp_context->ecn_used_zero_count = 0;

	/* TCP header begins just after the IP headers */
	assert(remain_len >= sizeof(struct tcphdr));
	tcp = (struct tcphdr *) remain_data;
	memcpy(&(tcp_context->old_tcphdr), tcp, sizeof(struct tcphdr));

	/* MSN */
	wlsb_init(&tcp_context->msn_wlsb, 16, comp->wlsb_window_width, ROHC_LSB_SHIFT_TCP_SN);
	/* IP-ID offset */
	wlsb_init(&tcp_context->ip_id_wlsb, 16, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	/* innermost IPv4 TTL or IPv6 Hop Limit */
	wlsb_init(&tcp_context->ttl_hopl_wlsb, 8, comp->wlsb_window_width, ROHC_LSB_SHIFT_TCP_TTL);
	/* TCP window */
	wlsb_init(&tcp_context->window_wlsb, 16, comp->wlsb_window_width, ROHC_LSB_SHIFT_TCP_WINDOW);
	/* TCP sequence number */
	tcp_context->seq_num = rohc_ntoh32(tcp->seq_num);
	wlsb_init(&tcp_context->seq_wlsb, 32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	wlsb_init(&tcp_context->seq_scaled_wlsb, 32, comp->wlsb_window_width, 7);
	/* TCP acknowledgment (ACK) number */
	tcp_context->ack_num = rohc_ntoh32(tcp->ack_num);
	wlsb_init(&tcp_context->ack_wlsb, 32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	wlsb_init(&tcp_context->ack_scaled_wlsb, 32, comp->wlsb_window_width, 3);

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

	/* no TCP option Timestamp received yet */
	tcp_context->tcp_opts.is_timestamp_init = false;
	/* TCP option Timestamp (request) */
	wlsb_init(&tcp_context->tcp_opts.ts_req_wlsb, 32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	/* TCP option Timestamp (reply) */
	wlsb_init(&tcp_context->tcp_opts.ts_reply_wlsb, 32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);

	return true;

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

	free(tcp_context);
}


/**
 * @brief Check if the given packet corresponds to the TCP profile
 *
 * Conditions are:
 *  \li the transport protocol is TCP
 *  \li the version of the outer IP header is 4 or 6
 *  \li the outer IP header is not an IP fragment
 *  \li if there are at least 2 IP headers, the version of the inner IP header
 *      is 4 or 6
 *  \li if there are at least 2 IP headers, the inner IP header is not an IP
 *      fragment
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param comp    The ROHC compressor
 * @param packet  The packet to check
 * @return        Whether the IP packet corresponds to the profile:
 *                  \li true if the IP packet corresponds to the profile,
 *                  \li false if the IP packet does not correspond to
 *                      the profile
 */
static bool c_tcp_check_profile(const struct rohc_comp *const comp,
                                const struct net_pkt *const packet)
{
	/* TODO: should avoid code duplication by using net_pkt as
	 * rohc_comp_rfc3095_check_profile() does */
	const uint8_t *remain_data = packet->outer_ip.data;
	size_t remain_len = packet->outer_ip.size;
	size_t ip_hdrs_nr;
	uint8_t next_proto;
	const struct tcphdr *tcp_header;

	/* check that the the versions of IP headers are 4 or 6 and that IP headers
	 * are not IP fragments */
	ip_hdrs_nr = 0;
	do
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;

		/* check minimal length for IP version */
		if(remain_len < sizeof(struct ip_hdr))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "failed to determine the version of IP header #%zu",
			           ip_hdrs_nr + 1);
			goto bad_profile;
		}

		if(ip->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;
			const size_t ipv4_min_words_nr = sizeof(struct ipv4_hdr) / sizeof(uint32_t);

			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "found IPv4");
			if(remain_len < sizeof(struct ipv4_hdr))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "uncompressed packet too short for IP header #%zu",
				           ip_hdrs_nr + 1);
				goto bad_profile;
			}

			/* IPv4 options are not supported by the TCP profile */
			if(ipv4->ihl != ipv4_min_words_nr)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: "
				           "IP options are not accepted", ip_hdrs_nr + 1);
				goto bad_profile;
			}

			/* IPv4 total length shall be correct */
			if(rohc_ntoh16(ipv4->tot_len) != remain_len)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: total "
				           "length is %u while it shall be %zu", ip_hdrs_nr + 1,
				           rohc_ntoh16(ipv4->tot_len), remain_len);
				goto bad_profile;
			}

			/* check if the IPv4 header is a fragment */
			if(ipv4_is_fragment(ipv4))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is fragmented", ip_hdrs_nr + 1);
				goto bad_profile;
			}

			/* check if the checksum of the IPv4 header is correct */
			if((comp->features & ROHC_COMP_FEATURE_NO_IP_CHECKSUMS) == 0 &&
			   ip_fast_csum(remain_data, ipv4_min_words_nr) != 0)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not correct (bad checksum)",
				           ip_hdrs_nr + 1);
				goto bad_profile;
			}

			next_proto = ipv4->protocol;
			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			size_t ipv6_exts_len;

			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "found IPv6");
			if(remain_len < sizeof(struct ipv6_hdr))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "uncompressed packet too short for IP header #%zu",
				           ip_hdrs_nr + 1);
				goto bad_profile;
			}
			next_proto = ipv6->nh;
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* payload length shall be correct */
			if(rohc_ntoh16(ipv6->plen) != remain_len)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: payload "
				           "length is %u while it shall be %zu", ip_hdrs_nr + 1,
				           rohc_ntoh16(ipv6->plen), remain_len);
				goto bad_profile;
			}

			/* reject packets with malformed IPv6 extension headers or IPv6
			 * extension headers that are not compatible with the TCP profile */
			if(!rohc_comp_ipv6_exts_are_acceptable(comp, &next_proto,
			                                       remain_data, remain_len,
			                                       &ipv6_exts_len))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: "
				           "malformed or incompatible IPv6 extension headers "
				           "detected", ip_hdrs_nr + 1);
				goto bad_profile;
			}
			remain_data += ipv6_exts_len;
			remain_len -= ipv6_exts_len;
		}
		else
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported version %u for header #%zu",
			           ip->version, ip_hdrs_nr + 1);
			goto bad_profile;
		}
		ip_hdrs_nr++;
	}
	while(rohc_is_tunneling(next_proto) && ip_hdrs_nr < ROHC_MAX_IP_HDRS);

	/* profile cannot handle the packet if it bypasses internal limit of IP headers */
	if(rohc_is_tunneling(next_proto))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "too many IP headers for TCP profile (%u headers max)",
		           ROHC_MAX_IP_HDRS);
		goto bad_profile;
	}

	/* check that the transport protocol is TCP */
	if(next_proto != ROHC_IPPROTO_TCP)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "transport protocol is not TCP");
		goto bad_profile;
	}

	/* innermost IP payload shall be large enough for TCP header */
	if(remain_len < sizeof(struct tcphdr))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "innermost IP payload too small for minimal TCP header");
		goto bad_profile;
	}

	/* retrieve the TCP header */
	tcp_header = (const struct tcphdr *) remain_data;
	if(tcp_header->data_offset < 5)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "TCP data offset too small for minimal TCP header");
		goto bad_profile;
	}
	if(remain_len < (tcp_header->data_offset * sizeof(uint32_t)))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "TCP data too small for full TCP header with options");
		goto bad_profile;
	}

	/* reject packets with malformed TCP options or TCP options that are not
	 * compatible with the TCP profile */
	if(!rohc_comp_tcp_are_options_acceptable(comp, tcp_header->options,
	                                         tcp_header->data_offset))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "malformed or incompatible TCP options detected");
		goto bad_profile;
	}

	return true;

bad_profile:
	return false;
}


/**
 * @brief Check if the IP/TCP packet belongs to the context
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of all the IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of all the IP headers must match
 *    the ones in the context
 *  - the transport protocol must be TCP
 *  - the source and destination ports of the TCP header must match the ones
 *    in the context
 *  - IPv6 only: the Flow Label of the all IP headers must match the ones the
 *    context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context        The compression context
 * @param packet         The IP/TCP packet to check
 * @param[out] cr_score  The score of the context for Context Replication (CR)
 * @return               true if the IP/TCP packet belongs to the context
 *                       false if it does not belong to the context
 *
 * @todo TODO: the code that parses IP headers in IP/UDP/RTP profiles could
 *             probably be re-used (and maybe enhanced if needed)
 */
static bool c_tcp_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet,
                                size_t *const cr_score)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint8_t *remain_data = packet->outer_ip.data;
	size_t remain_len = packet->outer_ip.size;
	size_t ip_hdr_pos;
	uint8_t next_proto = ROHC_IPPROTO_IPIP;
	const struct tcphdr *tcp;
	bool at_least_one_ipv6_hl_changed = false;

	/* Context Replication is possible only if the chain of IP headers is
	 * unchanged on some aspects:
	 *  - same number and order of IP headers,
	 *  - IP versions,
	 *  - IP addresses */
	(*cr_score) = 0;

	/* parse the IP headers (lengths already checked while checking profile) */
	for(ip_hdr_pos = 0;
	    ip_hdr_pos < tcp_context->ip_contexts_nr && rohc_is_tunneling(next_proto);
	    ip_hdr_pos++)
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;
		const ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		size_t ip_ext_pos;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip->version);
		if(ip->version != ip_context->version)
		{
			rohc_comp_debug(context, "  not same IP version");
			goto bad_context;
		}

		if(ip->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv4_hdr));

			/* check source address */
			if(ipv4->saddr != ip_context->ctxt.v4.src_addr)
			{
				rohc_comp_debug(context, "  not same IPv4 source addresses");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv4 source addresses");

			/* check destination address */
			if(ipv4->daddr != ip_context->ctxt.v4.dst_addr)
			{
				rohc_comp_debug(context, "  not same IPv4 destination addresses");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv4 destination addresses");

			/* check transport protocol */
			next_proto = ipv4->protocol;
			if(next_proto != ip_context->ctxt.v4.protocol)
			{
				rohc_comp_debug(context, "  IPv4 not same protocol");
				goto bad_context;
			}
			rohc_comp_debug(context, "  IPv4 same protocol %d", next_proto);

			/* skip IPv4 header */
			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			/* check source address */
			if(memcmp(&ipv6->saddr, ip_context->ctxt.v6.src_addr,
			          sizeof(struct ipv6_addr)) != 0)
			{
				rohc_comp_debug(context, "  not same IPv6 source addresses");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv6 source addresses");

			/* check destination address */
			if(memcmp(&ipv6->daddr, ip_context->ctxt.v6.dest_addr,
			          sizeof(struct ipv6_addr)) != 0)
			{
				rohc_comp_debug(context, "  not same IPv6 destination addresses");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv6 destination addresses");

			/* check Flow Label */
			if(ipv6_get_flow_label(ipv6) != ip_context->ctxt.v6.flow_label)
			{
				rohc_comp_debug(context, "  not same IPv6 flow label");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv6 flow label");

			/* skip IPv6 base header */
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* find transport header/protocol, skip any IPv6 extension headers */
			next_proto = ipv6->nh;
			for(ip_ext_pos = 0; rohc_is_ipv6_opt(next_proto); ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				size_t opt_len;
				assert(remain_len >= sizeof(struct ipv6_opt));
				opt_len = ipv6_opt_get_length(ipv6_opt);
				remain_data += opt_len;
				remain_len -= opt_len;
				next_proto = ipv6_opt->next_header;
			}

			/* check transport header protocol */
			if(next_proto != ip_context->ctxt.v6.next_header)
			{
				rohc_comp_debug(context, "  IPv6 not same protocol %u", next_proto);
				goto bad_context;
			}
			rohc_comp_debug(context, "  IPv6 same protocol %u", next_proto);

			/* check whether IPv6 HL changed to avoid Context Replication
			 * (changes for IPv6 HL cannot be transmitted in IR-CR) */
			if(ipv6->hl != ip_context->ctxt.v6.hopl)
			{
				at_least_one_ipv6_hl_changed = true;
			}
		}
		else
		{
			rohc_comp_warn(context, "unsupported version %u for header #%zu",
			               ip->version, ip_hdr_pos + 1);
			assert(0);
			goto bad_context;
		}
	}

	if(ip_hdr_pos < tcp_context->ip_contexts_nr)
	{
		rohc_comp_debug(context, "  less IP headers than context");
		goto bad_context;
	}

	if(rohc_is_tunneling(next_proto))
	{
		rohc_comp_debug(context, "  more IP headers than context");
		goto bad_context;
	}

	/* the packet matches the context enough to use Context Replication */
	(*cr_score)++;

	assert(remain_len >= sizeof(struct tcphdr));
	tcp = (struct tcphdr *) remain_data;

	/* check TCP source port */
	if(tcp_context->old_tcphdr.src_port != tcp->src_port)
	{
		rohc_comp_debug(context, "  not same TCP source ports");
		goto bad_context_check_cr;
	}
	rohc_comp_debug(context, "  same TCP source ports");
	(*cr_score)++;

	/* check TCP destination port */
	if(tcp_context->old_tcphdr.dst_port != tcp->dst_port)
	{
		rohc_comp_debug(context, "  not same TCP destination ports");
		goto bad_context_check_cr;
	}
	rohc_comp_debug(context, "  same TCP destination ports");
	(*cr_score)++;

	return true;

bad_context_check_cr:
	/* Context Replication is not possible if the IPv6 HL changed in any
	 * of the IP headers: indeed the IR-CR cannot transmit the changes */
	if(at_least_one_ipv6_hl_changed)
	{
		(*cr_score) = 0;
	}
	/* Context Replication is not possible if TCP RSF flags are abnormal: indeed
	 * the IR-CR packet encodes TCP RSF flags with the rsf_index_enc() method
	 * that does not support combination of RST, SYN or FIN flags */
	if(!rsf_index_enc_possible(tcp->rsf_flags))
	{
		(*cr_score) = 0;
	}
bad_context:
	return false;
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
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 *
 * @todo TODO: the code that parses IP headers in IP/UDP/RTP profiles could
 *             probably be re-used (and maybe enhanced if needed)
 */
static int c_tcp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	ip_context_t *ip_inner_context;
	const struct tcphdr *tcp;
	int counter;
	size_t i;

	*packet_type = ROHC_PACKET_UNKNOWN;

	/* at the beginning, no item transmitted for the compressed list of TCP options */
	for(i = 0; i <= MAX_TCP_OPTION_INDEX; i++)
	{
		tcp_context->tcp_opts.tmp.is_list_item_present[i] = false;
	}

	/* detect changes between new uncompressed packet and context */
	if(!tcp_detect_changes(context, uncomp_pkt, &ip_inner_context, &tcp))
	{
		rohc_comp_warn(context, "failed to detect changes in uncompressed packet");
		goto error;
	}

	/* decide in which state to go */
	tcp_decide_state(context, uncomp_pkt->time);

	/* compute how many bits are needed to send header fields */
	if(!tcp_encode_uncomp_fields(context, uncomp_pkt, tcp))
	{
		rohc_comp_warn(context, "failed to compute how many bits are needed to "
		               "transmit all changes in header fields");
		goto error;
	}

	/* decide which packet to send */
	*packet_type = tcp_decide_packet(context, ip_inner_context, tcp);

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
		counter = code_CO_packet(context, &uncomp_pkt->outer_ip, rohc_pkt,
		                         rohc_pkt_max_len, *packet_type, payload_offset);
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

		counter = code_IR_packet(context, &uncomp_pkt->outer_ip, rohc_pkt,
		                         rohc_pkt_max_len, *packet_type, payload_offset);
		if(counter < 0)
		{
			rohc_comp_warn(context, "failed to build IR(-DYN) packet");
			goto error;
		}
	}
	rohc_comp_dump_buf(context, "current ROHC packet", rohc_pkt, counter);

	rohc_comp_debug(context, "payload_offset = %zu", *payload_offset);

	rohc_comp_debug(context, "update context:");

	/* update the context with the new numbers of IP extension headers */
	{
		size_t ip_hdr_pos;
		for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
		{
			rohc_comp_debug(context, "  update context of IP header #%zu:",
			                ip_hdr_pos + 1);
			tcp_context->ip_contexts[ip_hdr_pos].opts_nr =
				tcp_context->tmp.ip_exts_nr[ip_hdr_pos];
			rohc_comp_debug(context, "    %zu extension headers",
			                tcp_context->ip_contexts[ip_hdr_pos].opts_nr);
		}
	}

	/* update the context with the new TCP header */
	memcpy(&(tcp_context->old_tcphdr), tcp, sizeof(struct tcphdr));
	tcp_context->seq_num = rohc_ntoh32(tcp->seq_num);
	tcp_context->ack_num = rohc_ntoh32(tcp->ack_num);

	/* sequence number */
	c_add_wlsb(&tcp_context->seq_wlsb, tcp_context->msn, tcp_context->seq_num);
	if(tcp_context->seq_num_factor != 0)
	{
		c_add_wlsb(&tcp_context->seq_scaled_wlsb, tcp_context->msn,
		           tcp_context->seq_num_scaled);

		/* sequence number sent once more, count the number of transmissions to
		 * know when scaled sequence number is possible */
		if(tcp_context->seq_num_scaling_nr < ROHC_INIT_TS_STRIDE_MIN)
		{
			tcp_context->seq_num_scaling_nr++;
			rohc_comp_debug(context, "unscaled sequence number was transmitted "
			                "%zu / %u times since the scaling factor or residue "
			                "changed", tcp_context->seq_num_scaling_nr,
			                ROHC_INIT_TS_STRIDE_MIN);
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
		if(tcp_context->ack_num_scaling_nr < ROHC_INIT_TS_STRIDE_MIN)
		{
			tcp_context->ack_num_scaling_nr++;
			rohc_comp_debug(context, "unscaled ACK number was transmitted %zu / %u "
			                "times since the scaling factor or residue changed",
			                tcp_context->ack_num_scaling_nr, ROHC_INIT_TS_STRIDE_MIN);
		}
	}

	return counter;

error:
	return -1;
}


/**
 * @brief Encode an IP/TCP packet as IR, IR-CR or IR-DYN packet
 *
 * @param context           The compression context
 * @param ip                The outer IP header
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_IR_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *const ip,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
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
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the %zu-byte "
		               "ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_remain_len);
		goto error;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_hdr_len += ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %d byte(s)",
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
			ret = tcp_code_static_part(context, ip, rohc_remain_data, rohc_remain_len);
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
		ret = tcp_code_dyn_part(context, ip, rohc_remain_data,
		                        rohc_remain_len, payload_offset);
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
		if(!B)
		{
			rohc_remain_data[0] = 0x00;
			rohc_comp_debug(context, "B = %d (and CRC7 = 0x00 for computation) = 0x%02x",
			                GET_REAL(B), rohc_remain_data[0]);
			rohc_remain_data++;
			rohc_remain_len--;
			rohc_hdr_len++;
		}
		else
		{
			rohc_remain_data[0] = 0x80;
			rohc_comp_debug(context, "B = %d (and CRC7 = 0x00 for computation) = 0x%02x",
			                GET_REAL(B), rohc_remain_data[0]);
			rohc_remain_data++;
			rohc_remain_len--;
			rohc_hdr_len++;

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
				rohc_comp_debug(context, "small Base CID %zu encoded as 0x%02x",
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
					rohc_comp_warn(context, "failed to encode large base CID %zu: "
					               "maybe the %zu-byte ROHC buffer is too small",
					               context->cr_base_cid, rohc_remain_len);
					goto error;
				}
				assert(ret == 2 || ret == 3);
				rohc_remain_data += ret - 1;
				rohc_remain_len -= ret - 1;
				rohc_hdr_len += ret - 1;
				rohc_comp_debug(context, "large Base CID %zu encoded on %d byte(s)",
				                context->cr_base_cid, ret - 1);
			}
		}

		/* add replicate chain for IR-CR packet only */
		ret = tcp_code_replicate_chain(context, ip, rohc_remain_data,
		                               rohc_remain_len, payload_offset);
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
	                                       rohc_hdr_len, CRC_INIT_8,
	                                       context->compressor->crc_table_8);
	rohc_comp_debug(context, "CRC (header length = %zu, crc = 0x%x)",
	                rohc_hdr_len, rohc_pkt[crc_position]);

	/* TODO: compute CRC7 */

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
 * @param ip                The outer IP header
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       The type of ROHC packet to create
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_CO_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *ip,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	const uint8_t *remain_data = ip->data;
	size_t remain_len = ip->size;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	ip_context_t *inner_ip_ctxt = NULL;
	const struct ip_hdr *inner_ip_hdr = NULL;
	size_t inner_ip_hdr_len = 0;

	const struct tcphdr *tcp;
	size_t pos_1st_byte;
	size_t pos_2nd_byte;
	uint8_t save_first_byte;
	size_t payload_size = 0;
	uint8_t ip_inner_ecn = 0;
	uint8_t crc_computed;
	size_t ip_hdr_pos;
	int ret;

	rohc_comp_debug(context, "code CO packet (CID = %zu)", context->cid);

	/* parse the IP headers and their extension headers */
	rohc_comp_debug(context, "parse the %zu-byte IP packet", remain_len);
	assert(tcp_context->ip_contexts_nr > 0);
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const struct ip_hdr *const ip_hdr = (struct ip_hdr *) remain_data;
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		uint8_t protocol;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip_hdr->version);

		inner_ip_hdr = (struct ip_hdr *) remain_data;
		inner_ip_hdr_len = remain_len;
		inner_ip_ctxt = ip_context;

		if(ip_hdr->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;
			size_t ipv4_hdr_len;

			assert(remain_len >= sizeof(struct ipv4_hdr));

			protocol = ipv4->protocol;
			ip_inner_ecn = ipv4->ecn;
			ipv4_hdr_len = ipv4->ihl * sizeof(uint32_t);
			payload_size = rohc_ntoh16(ipv4->tot_len) - ipv4_hdr_len;

			/* skip IPv4 header */
			rohc_comp_debug(context, "skip %zu-byte IPv4 header with "
			                "Protocol 0x%02x", ipv4_hdr_len, protocol);
			remain_data += ipv4_hdr_len;
			remain_len -= ipv4_hdr_len;
		}
		else if(ip_hdr->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			size_t ip_ext_pos;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			protocol = ipv6->nh;
			ip_inner_ecn = ipv6->ecn;
			payload_size = rohc_ntoh16(ipv6->plen);

			/* skip IPv6 header */
			rohc_comp_debug(context, "skip %zu-byte IPv6 header with Next Header "
			                "0x%02x", sizeof(struct ipv6_hdr), protocol);
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* skip IPv6 extension headers */
			for(ip_ext_pos = 0; ip_ext_pos < ip_context->opts_nr; ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				const ip_option_context_t *const opt_ctxt =
					&(ip_context->opts[ip_ext_pos]);

				protocol = ipv6_opt->next_header;
				rohc_comp_debug(context, "skip %zu-byte IPv6 extension header "
				                "with Next Header 0x%02x",
				                opt_ctxt->generic.option_length, protocol);
				remain_data += opt_ctxt->generic.option_length;
				remain_len -= opt_ctxt->generic.option_length;
			}
		}
		else
		{
			rohc_comp_warn(context, "unexpected IP version %u", ip_hdr->version);
			assert(0);
			goto error;
		}
	}

	/* parse the TCP header */
	assert(remain_len >= sizeof(struct tcphdr));
	tcp = (struct tcphdr *) remain_data;
	{
		const size_t tcp_data_offset = tcp->data_offset << 2;

		assert(remain_len >= tcp_data_offset);
		assert(payload_size >= tcp_data_offset);
		payload_size -= tcp_data_offset;

		assert(((uint8_t *) tcp) >= ip->data);
		*payload_offset = ((uint8_t *) tcp) + tcp_data_offset - ip->data;
		rohc_comp_debug(context, "payload offset = %zu", *payload_offset);
		rohc_comp_debug(context, "payload size = %zu", payload_size);
	}

	/* we have just identified the IP and TCP headers (options included), so
	 * let's compute the CRC on uncompressed headers */
	if(packet_type == ROHC_PACKET_TCP_SEQ_8 ||
	   packet_type == ROHC_PACKET_TCP_RND_8 ||
	   packet_type == ROHC_PACKET_TCP_CO_COMMON)
	{
		crc_computed = crc_calculate(ROHC_CRC_TYPE_7, ip->data, *payload_offset,
		                             CRC_INIT_7, context->compressor->crc_table_7);
		rohc_comp_debug(context, "CRC-7 on %zu-byte uncompressed header = 0x%x",
		                *payload_offset, crc_computed);
	}
	else
	{
		crc_computed = crc_calculate(ROHC_CRC_TYPE_3, ip->data, *payload_offset,
		                             CRC_INIT_3, context->compressor->crc_table_3);
		rohc_comp_debug(context, "CRC-3 on %zu-byte uncompressed header = 0x%x",
		                *payload_offset, crc_computed);
	}

	/* write Add-CID or large CID bytes: 'pos_1st_byte' indicates the location
	 * where first header byte shall be written, 'pos_2nd_byte' indicates the
	 * location where the next header bytes shall be written */
	ret = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                      rohc_remain_data, rohc_remain_len, &pos_1st_byte);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the "
		               "%zu-byte ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_remain_len);
		goto error;
	}
	pos_2nd_byte = ret;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %d byte(s)",
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

	ret = co_baseheader(context, tcp_context,
	                    inner_ip_ctxt, inner_ip_hdr, inner_ip_hdr_len,
	                    rohc_remain_data, rohc_remain_len,
	                    packet_type, tcp, crc_computed);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the CO base header");
		goto error;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* add irregular chain */
	ret = tcp_code_irreg_chain(context, ip, ip_inner_ecn, tcp,
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
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @return                  The position in the rohc-packet-under-build buffer
 *                          -1 in case of problem
 */
static int co_baseheader(struct rohc_comp_ctxt *const context,
                         struct sc_tcp_context *const tcp_context,
                         ip_context_t *const inner_ip_ctxt,
                         const struct ip_hdr *const inner_ip_hdr,
                         const size_t inner_ip_hdr_len,
                         uint8_t *const rohc_pkt,
                         const size_t rohc_pkt_max_len,
                         const rohc_packet_t packet_type,
                         const struct tcphdr *const tcp,
                         const uint8_t crc)
{
	size_t rohc_hdr_len = 0;
	int ret;

	rohc_comp_debug(context, "code %s packet", rohc_get_packet_descr(packet_type));

	switch(packet_type)
	{
		case ROHC_PACKET_TCP_RND_1:
			ret = c_tcp_build_rnd_1(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_2:
			ret = c_tcp_build_rnd_2(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_3:
			ret = c_tcp_build_rnd_3(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_4:
			ret = c_tcp_build_rnd_4(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_5:
			ret = c_tcp_build_rnd_5(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_6:
			ret = c_tcp_build_rnd_6(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_7:
			ret = c_tcp_build_rnd_7(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_8:
			ret = c_tcp_build_rnd_8(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_1:
			ret = c_tcp_build_seq_1(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_2:
			ret = c_tcp_build_seq_2(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_3:
			ret = c_tcp_build_seq_3(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_4:
			ret = c_tcp_build_seq_4(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_5:
			ret = c_tcp_build_seq_5(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_6:
			ret = c_tcp_build_seq_6(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_7:
			ret = c_tcp_build_seq_7(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_8:
			ret = c_tcp_build_seq_8(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_CO_COMMON:
			ret = c_tcp_build_co_common(context, inner_ip_ctxt, tcp_context,
			                            inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
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
	assert(inner_ip_hdr_len >= 1);
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		inner_ip_ctxt->ctxt.v4.last_ip_id_behavior = inner_ip_ctxt->ctxt.v4.ip_id_behavior;
		inner_ip_ctxt->ctxt.v4.last_ip_id = rohc_ntoh16(inner_ipv4->id);
		inner_ip_ctxt->ctxt.v4.df = inner_ipv4->df;
		inner_ip_ctxt->ctxt.vx.dscp = inner_ipv4->dscp;
	}
	else
	{
		const struct ipv6_hdr *const inner_ipv6 = (struct ipv6_hdr *) inner_ip_hdr;
		inner_ip_ctxt->ctxt.vx.dscp = ipv6_get_dscp(inner_ipv6);
	}
	inner_ip_ctxt->ctxt.vx.ttl_hopl = tcp_context->tmp.ttl_hopl;

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
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_rnd_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
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
		assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
		ttl_hl = ipv4->ttl;
	}
	else
	{
		const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) inner_ip_hdr;
		assert(inner_ip_hdr->version == IPV6);
		assert(inner_ip_hdr_len >= sizeof(struct ipv6_hdr));
		assert(inner_ip_ctxt->ctxt.vx.version == IPV6);
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
	if(tcp_context->tcp_opts.tmp.do_list_struct_changed ||
	   tcp_context->tcp_opts.tmp.do_list_static_changed)
	{
		/* the structure of the list of TCP options changed or at least one of
		 * the static option changed, compress them */
		bool no_item_needed;
		rnd8->list_present = 1;
		ret = c_tcp_code_tcp_opts_list_item(context, tcp, tcp_context->msn,
		                                    ROHC_CHAIN_CO, &tcp_context->tcp_opts,
		                                    rnd8->options,
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
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_1_t *const seq1 = (seq_1_t *) rohc_data;
	uint32_t seq_num;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
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
	seq1->ip_id = tcp_context->tmp.ip_id_delta & 0x0f;
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
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_2_t *const seq2 = (seq_2_t *) rohc_data;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
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
	seq2->ip_id1 = (tcp_context->tmp.ip_id_delta >> 4) & 0x7;
	seq2->ip_id2 = tcp_context->tmp.ip_id_delta & 0xf;
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
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_3_t *const seq3 = (seq_3_t *) rohc_data;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
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
	seq3->ip_id = tcp_context->tmp.ip_id_delta & 0xf;
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
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_4_t *const seq4 = (seq_4_t *) rohc_data;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
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
	seq4->ip_id = tcp_context->tmp.ip_id_delta & 0x7;
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
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_5_t *const seq5 = (seq_5_t *) rohc_data;
	uint32_t seq_num;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
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
	seq5->ip_id = tcp_context->tmp.ip_id_delta & 0xf;
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
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_6_t *const seq6 = (seq_6_t *) rohc_data;
	uint8_t seq_num_scaled;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
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
	seq6->ip_id = tcp_context->tmp.ip_id_delta & 0x7f;
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
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_7_t *const seq7 = (seq_7_t *) rohc_data;
	uint16_t window;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
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
	seq7->ip_id = tcp_context->tmp.ip_id_delta & 0x1f;
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
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_8_t *const seq8 = (seq_8_t *) rohc_data;
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
	size_t comp_opts_len;
	uint16_t ack_num;
	uint16_t seq_num;
	int ret;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_8_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_8 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_8_t), rohc_max_len);
		goto error;
	}

	seq8->discriminator = 0x0b; /* '1011' */

	/* IP-ID */
	seq8->ip_id = tcp_context->tmp.ip_id_delta & 0xf;
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
	if(tcp_context->tcp_opts.tmp.do_list_struct_changed ||
	   tcp_context->tcp_opts.tmp.do_list_static_changed)
	{
		/* the structure of the list of TCP options changed or at least one of
		 * the static option changed, compress them */
		bool no_item_needed;
		seq8->list_present = 1;
		ret = c_tcp_code_tcp_opts_list_item(context, tcp, tcp_context->msn,
		                                    ROHC_CHAIN_CO, &tcp_context->tcp_opts,
		                                    seq8->options,
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
 * @param context             The compression context
 * @param inner_ip_ctxt       The specific IP  text
 * @param tcp_context         The specific TCP context
 * @param inner_ip_hdr        The innermost IP header
 * @param inner_ip_hdr_len    The length of the innermost IP header
 * @param tcp                 The TCP header to compress
 * @param crc                 The CRC on the uncompressed headers
 * @param[out] rohc_data      The ROHC packet being built
 * @param rohc_max_len        The max remaining length in the ROHC buffer
 * @return                    true if the packet is successfully built,
 *                            false otherwise
 */
static int c_tcp_build_co_common(const struct rohc_comp_ctxt *const context,
                                 const ip_context_t *const inner_ip_ctxt,
                                 struct sc_tcp_context *const tcp_context,
                                 const struct ip_hdr *const inner_ip_hdr,
                                 const size_t inner_ip_hdr_len,
                                 const struct tcphdr *const tcp,
                                 const uint8_t crc,
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len)
{
	co_common_t *const co_common = (co_common_t *) rohc_data;
	uint8_t *co_common_opt = (uint8_t *) (co_common + 1); /* optional part */
	size_t co_common_opt_len = 0;
	size_t rohc_remain_len = rohc_max_len - sizeof(co_common_t);
	const uint32_t seq_num_hbo = rohc_ntoh32(tcp->seq_num);
	const uint32_t ack_num_hbo = rohc_ntoh32(tcp->ack_num);
	size_t nr_seq_bits_16383; /* min bits required to encode TCP seqnum with p = 16383 */
	size_t nr_seq_bits_63; /* min bits required to encode TCP seqnum with p = 63 */
	size_t nr_ack_bits_63; /* min bits required to encode TCP ACK number with p = 63 */
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
	                tcp_context->tmp.ttl_irreg_chain_flag);

	co_common->discriminator = 0x7D; // '1111101'
	co_common->ttl_hopl_outer_flag = tcp_context->tmp.ttl_irreg_chain_flag;

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
	nr_seq_bits_16383 = wlsb_get_kp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 16383);
	rohc_comp_debug(context, "%zd bits are required to encode new sequence "
	                "number 0x%08x with p = 16383", nr_seq_bits_16383, seq_num_hbo);
	nr_seq_bits_63 = wlsb_get_kp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 63);
	rohc_comp_debug(context, "%zd bits are required to encode new sequence "
	                "number 0x%08x with p = 63", nr_seq_bits_63, seq_num_hbo);
	ret = variable_length_32_enc(rohc_ntoh32(tcp_context->old_tcphdr.seq_num),
	                             rohc_ntoh32(tcp->seq_num),
	                             nr_seq_bits_63, nr_seq_bits_16383,
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
	                "indicator %d", rohc_ntoh32(tcp->seq_num), encoded_seq_len,
	                co_common->seq_indicator);

	/* ack_number */
	nr_ack_bits_63 = wlsb_get_kp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 63);
	rohc_comp_debug(context, "%zd bits are required to encode new ACK "
	                "number 0x%08x with p = 63", nr_ack_bits_63, ack_num_hbo);
	ret = variable_length_32_enc(rohc_ntoh32(tcp_context->old_tcphdr.ack_num),
	                             rohc_ntoh32(tcp->ack_num),
	                             nr_ack_bits_63, tcp_context->tmp.nr_ack_bits_16383,
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
	                "indicator %d", rohc_ntoh32(tcp->ack_num), encoded_ack_len,
	                co_common->ack_indicator);

	/* ack_stride */
	{
		const bool is_ack_stride_static =
			tcp_is_ack_stride_static(tcp_context->ack_stride,
			                         tcp_context->ack_num_scaling_nr);
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
	ret = c_static_or_irreg16(tcp->window, !tcp_context->tmp.tcp_window_changed,
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
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		// =:= irregular(1) [ 1 ];
		rohc_comp_debug(context, "optional_ip_id_lsb(behavior = %d, IP-ID = 0x%04x, "
		                "IP-ID offset = 0x%04x, nr of bits required for WLSB encoding "
		                "= %zu)", inner_ip_ctxt->ctxt.v4.ip_id_behavior,
		                rohc_ntoh16(inner_ipv4->id), tcp_context->tmp.ip_id_delta,
		                tcp_context->tmp.nr_ip_id_bits_3);
		ret = c_optional_ip_id_lsb(inner_ip_ctxt->ctxt.v4.ip_id_behavior,
		                           inner_ipv4->id,
		                           tcp_context->tmp.ip_id_delta,
		                           tcp_context->tmp.nr_ip_id_bits_3,
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
		co_common->ip_id_behavior = inner_ip_ctxt->ctxt.v4.ip_id_behavior;
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
	ret = c_static_or_irreg16(tcp->urg_ptr,
	                          !!(tcp_context->old_tcphdr.urg_ptr == tcp->urg_ptr),
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

	assert(inner_ip_hdr_len >= 1);
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) inner_ip_hdr;

		/* dscp_present =:= irregular(1) [ 1 ] */
		ret = dscp_encode(inner_ip_ctxt->ctxt.vx.dscp, ipv4->dscp,
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
		                co_common->dscp_present, inner_ip_ctxt->ctxt.vx.dscp,
		                ipv4->dscp, ret);

		/* ttl_hopl */
		{
			const bool is_ttl_hopl_static =
				(inner_ip_ctxt->ctxt.vx.ttl_hopl == tcp_context->tmp.ttl_hopl);
			ret = c_static_or_irreg8(tcp_context->tmp.ttl_hopl, is_ttl_hopl_static,
			                         co_common_opt, rohc_remain_len, &indicator);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to encode static_or_irreg(ttl_hopl)");
				goto error;
			}
			rohc_comp_debug(context, "TTL = 0x%02x -> 0x%02x",
			                inner_ip_ctxt->ctxt.vx.ttl_hopl, tcp_context->tmp.ttl_hopl);
			co_common->ttl_hopl_present = indicator;
			co_common_opt += ret;
			co_common_opt_len += ret;
			rohc_remain_len -= ret;
			rohc_comp_debug(context, "ttl_hopl_present = %d (TTL encoded on %d bytes)",
			                co_common->ttl_hopl_present, ret);
		}

		// =:= dont_fragment(version.UVALUE) [ 1 ];
		co_common->df = ipv4->df;
	}
	else
	{
		const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) inner_ip_hdr;
		const uint8_t dscp = ipv6_get_dscp(ipv6);

		/* dscp_present =:= irregular(1) [ 1 ] */
		ret = dscp_encode(inner_ip_ctxt->ctxt.vx.dscp, dscp, co_common_opt,
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
		                co_common->dscp_present, inner_ip_ctxt->ctxt.vx.dscp,
		                dscp, ret);

		/* ttl_hopl */
		{
			const bool is_ttl_hopl_static =
				(inner_ip_ctxt->ctxt.vx.ttl_hopl == tcp_context->tmp.ttl_hopl);
			ret = c_static_or_irreg8(tcp_context->tmp.ttl_hopl, is_ttl_hopl_static,
			                         co_common_opt, rohc_remain_len, &indicator);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to encode static_or_irreg(ttl_hopl)");
				goto error;
			}
			rohc_comp_debug(context, "HOPL = 0x%02x -> 0x%02x",
			                inner_ip_ctxt->ctxt.vx.ttl_hopl, tcp_context->tmp.ttl_hopl);
			co_common->ttl_hopl_present = indicator;
			co_common_opt += ret;
			co_common_opt_len += ret;
			rohc_remain_len -= ret;
			rohc_comp_debug(context, "ttl_hopl_present = %d (HOPL encoded on %d bytes)",
			                co_common->ttl_hopl_present, ret);
		}

		// =:= dont_fragment(version.UVALUE) [ 1 ];
		co_common->df = 0;
	}
	rohc_comp_debug(context, "DF = %d", co_common->df);

	// =:= compressed_value(1, 0) [ 1 ];
	co_common->reserved = 0;

	/* include the list of TCP options if the structure of the list changed
	 * or if some static options changed (irregular chain cannot transmit
	 * static options) */
	if(tcp_context->tcp_opts.tmp.do_list_struct_changed ||
	   tcp_context->tcp_opts.tmp.do_list_static_changed)
	{
		/* the structure of the list of TCP options changed or at least one of
		 * the static option changed, compress them */
		bool no_item_needed;
		co_common->list_present = 1;
		ret = c_tcp_code_tcp_opts_list_item(context, tcp, tcp_context->msn,
		                                    ROHC_CHAIN_CO, &tcp_context->tcp_opts,
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
 * @param context             The compression context to compare
 * @param uncomp_pkt          The uncompressed packet to compare
 * @param[out] ip_inner_ctxt  The context of the inner IP header
 * @param[out] tcp            The TCP header found in uncompressed headers
 * @return                    true if changes were successfully detected,
 *                            false if a problem occurred
 */
static bool tcp_detect_changes(struct rohc_comp_ctxt *const context,
                               const struct net_pkt *const uncomp_pkt,
                               ip_context_t **const ip_inner_ctxt,
                               const struct tcphdr **const tcp)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint8_t *remain_data = uncomp_pkt->outer_ip.data;
	size_t remain_len = uncomp_pkt->outer_ip.size;

	const uint8_t *inner_ip_hdr = NULL;
	ip_version inner_ip_version = IP_UNKNOWN;

	size_t ip_hdrs_nr;
	size_t hdrs_len;
	uint8_t protocol;
	size_t opts_len;
	bool pkt_outer_dscp_changed;
	bool last_pkt_outer_dscp_changed;
	uint8_t pkt_ecn_vals;

	/* no IPv6 extension got its static or dynamic parts changed at the beginning */
	tcp_context->tmp.is_ipv6_exts_list_static_changed = false;
	tcp_context->tmp.is_ipv6_exts_list_dyn_changed = false;

	hdrs_len = 0;
	pkt_outer_dscp_changed = 0;
	last_pkt_outer_dscp_changed = false;
	pkt_ecn_vals = 0;
	ip_hdrs_nr = 0;
	do
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdrs_nr]);

		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d header #%zu",
		                ip->version, ip_hdrs_nr + 1);

		pkt_outer_dscp_changed =
			!!(pkt_outer_dscp_changed || last_pkt_outer_dscp_changed);
		inner_ip_hdr = remain_data;
		inner_ip_version = ip->version;
		*ip_inner_ctxt = ip_context;

		if(ip->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

			if(remain_len < sizeof(struct ipv4_hdr))
			{
				rohc_comp_warn(context, "not enough data for IPv4 header #%zu",
				               ip_hdrs_nr + 1);
				goto error;
			}

			protocol = ipv4->protocol;
			last_pkt_outer_dscp_changed = !!(ipv4->dscp != ip_context->ctxt.vx.dscp);
			pkt_ecn_vals |= ipv4->ecn;

			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
			hdrs_len += sizeof(struct ipv4_hdr);
		}
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			uint8_t dscp;
			size_t exts_nr;
			size_t exts_len;

			if(remain_len < sizeof(struct ipv6_hdr))
			{
				rohc_comp_warn(context, "not enough data for IPv6 header #%zu",
				               ip_hdrs_nr + 1);
				goto error;
			}

			protocol = ipv6->nh;
			dscp = (remain_data[1] >> 2) & 0x3f;
			last_pkt_outer_dscp_changed = !!(dscp != ip_context->ctxt.vx.dscp);
			pkt_ecn_vals |= remain_data[1] & 0x3;

			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);
			hdrs_len += sizeof(struct ipv6_hdr);

			if(!tcp_detect_changes_ipv6_exts(context, ip_context, &protocol,
			                                 remain_data, remain_len,
			                                 &exts_nr, &exts_len))
			{
				rohc_comp_warn(context, "failed to detect changes in IPv6 extension headers");
				goto error;
			}
			remain_data += exts_len;
			remain_len -= exts_len;
			tcp_context->tmp.ip_exts_nr[ip_hdrs_nr] = exts_nr;
			hdrs_len += exts_len;
		}
		else
		{
			rohc_comp_warn(context, "unknown IP header with version %u", ip->version);
			goto error;
		}
		rohc_comp_debug(context, "  DSCP did%s change",
		                last_pkt_outer_dscp_changed ? "" : "n't");

		ip_hdrs_nr++;
	}
	while(protocol != ROHC_IPPROTO_TCP && hdrs_len < uncomp_pkt->outer_ip.size);

	/* next header is the TCP header */
	if(remain_len < sizeof(struct tcphdr))
	{
		rohc_comp_warn(context, "not enough data for TCP header");
		goto error;
	}
	*tcp = (struct tcphdr *) remain_data;
	pkt_ecn_vals |= (*tcp)->ecn_flags;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += sizeof(struct tcphdr);
	remain_len -= sizeof(struct tcphdr);
#endif
	hdrs_len += sizeof(struct tcphdr);

	/* parse TCP options for changes */
	if(!tcp_detect_options_changes(context, *tcp, &tcp_context->tcp_opts, &opts_len))
	{
		rohc_comp_warn(context, "failed to detect changes in the uncompressed "
		               "TCP options");
		goto error;
	}
	rohc_comp_debug(context, "%zu bytes of TCP options successfully parsed",
	                opts_len);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += opts_len;
	remain_len -= opts_len;
#endif
	hdrs_len += opts_len;

	/* what value for ecn_used? */
	tcp_detect_ecn_used_behavior(context, pkt_ecn_vals, pkt_outer_dscp_changed,
	                             (*tcp)->res_flags);

	/* determine the IP-ID behavior of the innermost IPv4 header */
	if(inner_ip_version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4_hdr = (struct ipv4_hdr *) inner_ip_hdr;
		const uint16_t ip_id = rohc_ntoh16(inner_ipv4_hdr->id);

		rohc_comp_debug(context, "IP-ID behaved as %s",
		                rohc_ip_id_behavior_get_descr((*ip_inner_ctxt)->ctxt.v4.ip_id_behavior));
		rohc_comp_debug(context, "IP-ID = 0x%04x -> 0x%04x",
		                (*ip_inner_ctxt)->ctxt.v4.last_ip_id, ip_id);

		if(context->num_sent_packets == 0)
		{
			/* first packet, be optimistic: choose sequential behavior */
			(*ip_inner_ctxt)->ctxt.v4.ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
		}
		else
		{
			(*ip_inner_ctxt)->ctxt.v4.ip_id_behavior =
				rohc_comp_detect_ip_id_behavior((*ip_inner_ctxt)->ctxt.v4.last_ip_id, ip_id, 1, 19);
		}
		rohc_comp_debug(context, "IP-ID now behaves as %s",
		                rohc_ip_id_behavior_get_descr((*ip_inner_ctxt)->ctxt.v4.ip_id_behavior));
	}

	/* find the offset of the payload and its size */
	assert(uncomp_pkt->len >= hdrs_len);
	tcp_context->tmp.payload_len = uncomp_pkt->len - hdrs_len;
	rohc_comp_debug(context, "payload length = %zu bytes",
	                tcp_context->tmp.payload_len);

	/* compute or find the new SN */
	tcp_context->msn = c_tcp_get_next_msn(context);
	rohc_comp_debug(context, "MSN = 0x%04x / %u", tcp_context->msn, tcp_context->msn);

	return true;

error:
	return false;
}


/**
 * @brief Detect changes about IPv6 extension headers between packet and context
 *
 * @param context           The compression context to compare
 * @param ip_context        The specific IP compression context
 * @param[in,out] protocol  in: the protocol type of the first extension header
 *                          out: the protocol type of the transport header
 * @param exts              The beginning of the IPv6 extension headers
 * @param max_exts_len      The maximum length (in bytes) of the extension headers
 * @param[out] exts_nr      The number of IPv6 extension headers
 * @param[out] exts_len     The length (in bytes) of the IPv6 extension headers
 * @return                  true if changes were successfully detected,
 *                          false if a problem occurred
 */
static bool tcp_detect_changes_ipv6_exts(struct rohc_comp_ctxt *const context,
                                         ip_context_t *const ip_context,
                                         uint8_t *const protocol,
                                         const uint8_t *const exts,
                                         const size_t max_exts_len,
                                         size_t *const exts_nr,
                                         size_t *const exts_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint8_t *remain_data = exts;
	size_t remain_len = max_exts_len;
	size_t ext_pos;

	(*exts_nr) = 0;
	(*exts_len) = 0;

	for(ext_pos = 0;
	    rohc_is_ipv6_opt(*protocol) && ext_pos < ROHC_MAX_IP_EXT_HDRS;
	    ext_pos++)
	{
		ip_option_context_t *const opt_ctxt = &(ip_context->opts[ext_pos]);
		const struct ipv6_opt *const ext = (struct ipv6_opt *) remain_data;
		size_t ext_len;

		rohc_comp_debug(context, "  found IP extension header %u", *protocol);

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

		switch(*protocol)
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
					rohc_comp_debug(context, "  IPv6 option %u is new", *protocol);
					tcp_context->tmp.is_ipv6_exts_list_static_changed = true;

					/* record option in context */
					/* TODO: should not update context there */
					opt_ctxt->generic.option_length = ext_len;
					memcpy(opt_ctxt->generic.data, ext->value, ext_len - 2);

				}
				else if(ext_len != opt_ctxt->generic.option_length)
				{
					rohc_comp_debug(context, "  IPv6 option %u changed of length "
					                "(%zu -> %zu bytes)", *protocol,
					                opt_ctxt->generic.option_length, ext_len);
					tcp_context->tmp.is_ipv6_exts_list_static_changed = true;

					/* record option in context */
					/* TODO: should not update context there */
					opt_ctxt->generic.option_length = ext_len;
					memcpy(opt_ctxt->generic.data, ext->value, ext_len - 2);
				}
				else if(memcmp(ext->value, opt_ctxt->generic.data, ext_len - 2) != 0)
				{
					rohc_comp_debug(context, "  IPv6 option %u changed of content",
					                *protocol);
					if((*protocol) == ROHC_IPPROTO_ROUTING)
					{
						tcp_context->tmp.is_ipv6_exts_list_static_changed = true;
					}
					else
					{
						tcp_context->tmp.is_ipv6_exts_list_dyn_changed = true;
					}

					/* record option in context */
					/* TODO: should not update context there */
					opt_ctxt->generic.option_length = ext_len;
					memcpy(opt_ctxt->generic.data, ext->value, ext_len - 2);
				}
				else
				{
					rohc_comp_debug(context, "  IPv6 option %u did not change",
					                *protocol);
				}
				break;
			case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
			case ROHC_IPPROTO_MINE: /* TODO: MINE not yet supported */
			case ROHC_IPPROTO_AH:   /* TODO: AH not yet supported */
			default:
				assert(0);
				break;
		}
		(*protocol) = ext->next_header;

		remain_data += ext_len;
		remain_len -= ext_len;

		(*exts_nr)++;
		(*exts_len) += ext_len;
	}
	assert(!rohc_is_ipv6_opt(*protocol));
	assert((*exts_nr) <= ROHC_MAX_IP_EXT_HDRS);

	/* more or less IP extension headers than previous packet? */
	if(context->num_sent_packets == 0)
	{
		rohc_comp_debug(context, "  IP extension headers not sent yet");
		tcp_context->tmp.is_ipv6_exts_list_static_changed = true;
	}
	else if((*exts_nr) < ip_context->opts_nr)
	{
		rohc_comp_debug(context, "  less IP extension headers (%zu) than "
		                "context (%zu)", *exts_nr, ip_context->opts_nr);
		tcp_context->tmp.is_ipv6_exts_list_static_changed = true;
	}
	else if((*exts_nr) > ip_context->opts_nr)
	{
		rohc_comp_debug(context, "  more IP extension headers (%zu+) than "
		                "context (%zu)", *exts_nr, ip_context->opts_nr);
		tcp_context->tmp.is_ipv6_exts_list_static_changed = true;
	}

	if(tcp_context->tmp.is_ipv6_exts_list_static_changed)
	{
		rohc_comp_debug(context, "  IPv6 extension headers changed too much, static "
		                "chain is required");
	}
	else if(tcp_context->tmp.is_ipv6_exts_list_dyn_changed)
	{
		rohc_comp_debug(context, "  IPv6 extension headers changed too much, dynamic "
		                "chain is required");
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
	const rohc_comp_state_t curr_state = context->state;
	rohc_comp_state_t next_state;

	if(curr_state == ROHC_COMP_STATE_IR)
	{
		if(context->ir_count < MAX_IR_COUNT)
		{
			rohc_comp_debug(context, "no enough packets transmitted in IR state "
			                "for the moment (%zu/%d), so stay in IR state",
			                context->ir_count, MAX_IR_COUNT);
			next_state = ROHC_COMP_STATE_IR;
		}
		else
		{
			rohc_comp_debug(context, "enough packets transmitted in IR state (%zu/%u), "
			                "go to SO state", context->ir_count, MAX_IR_COUNT);
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_CR)
	{
		if(context->cr_count < MAX_CR_COUNT)
		{
			rohc_comp_debug(context, "no enough packets transmitted in CR state "
			                "for the moment (%zu/%d), so stay in CR state",
			                context->cr_count, MAX_CR_COUNT);
			next_state = ROHC_COMP_STATE_CR;
		}
		else
		{
			rohc_comp_debug(context, "enough packets transmitted in CR state (%zu/%u), "
			                "go to SO state", context->cr_count, MAX_CR_COUNT);
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_FO)
	{
		if(context->fo_count < MAX_FO_COUNT)
		{
			rohc_comp_debug(context, "no enough packets transmitted in FO state "
			                "for the moment (%zu/%u), so stay in FO state",
			                context->fo_count, MAX_FO_COUNT);
			next_state = ROHC_COMP_STATE_FO;
		}
		else
		{
			rohc_comp_debug(context, "enough packets transmitted in FO state (%zu/%u), "
			                "go to SO state", context->fo_count, MAX_FO_COUNT);
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_SO)
	{
		/* do not change state */
		rohc_comp_debug(context, "stay in SO state");
		next_state = ROHC_COMP_STATE_SO;
		/* TODO: handle NACK and STATIC-NACK */
	}
	else
	{
		rohc_comp_warn(context, "unexpected compressor state %d", curr_state);
		assert(0);
		return;
	}

	rohc_comp_change_state(context, next_state);

	/* periodic context refreshes (RFC6846, §5.2.1.2) */
	if(context->mode == ROHC_U_MODE)
	{
		rohc_comp_periodic_down_transition(context, pkt_time);
	}
}


/**
 * @brief Encode uncompressed fields with the corresponding encoding scheme
 *
 * @param context      The compression context
 * @param uncomp_pkt   The uncompressed packet to encode
 * @param tcp          The uncompressed TCP header to encode
 * @return             true in case of success,
 *                     false otherwise
 */
static bool tcp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt,
                                     const struct tcphdr *const tcp)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	/* how many bits are required to encode the new SN ? */
	tcp_context->tmp.nr_msn_bits =
		wlsb_get_k_16bits(&tcp_context->msn_wlsb, tcp_context->msn);
	rohc_comp_debug(context, "%zu bits are required to encode new MSN 0x%04x",
	                tcp_context->tmp.nr_msn_bits, tcp_context->msn);
	/* add the new MSN to the W-LSB encoding object */
	/* TODO: move this after successful packet compression */
	c_add_wlsb(&tcp_context->msn_wlsb, tcp_context->msn, tcp_context->msn);

	if(!tcp_encode_uncomp_ip_fields(context, uncomp_pkt))
	{
		rohc_comp_warn(context, "failed to encode the uncompressed fields "
		               "of the IP headers");
		goto error;
	}

	if(!tcp_encode_uncomp_tcp_fields(context, tcp))
	{
		rohc_comp_warn(context, "failed to encode the uncompressed fields "
		               "of the TCP header");
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Encode uncompressed IP fields with the corresponding encoding scheme
 *
 * @param context      The compression context
 * @param uncomp_pkt   The uncompressed packet to encode
 * @return             true in case of success,
 *                     false otherwise
 */
static bool tcp_encode_uncomp_ip_fields(struct rohc_comp_ctxt *const context,
                                        const struct net_pkt *const uncomp_pkt)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	const uint8_t *remain_data = uncomp_pkt->data;
	size_t remain_len = uncomp_pkt->len;

	const ip_context_t *inner_ip_ctxt = NULL;
	const uint8_t *inner_ip_hdr = NULL;
	ip_version inner_ip_version = IP_UNKNOWN;

	uint8_t protocol;
	size_t ip_hdr_pos;

	/* there is at least one IP header otherwise it won't be the IP/TCP profile */
	assert(tcp_context->ip_contexts_nr > 0);

	/* parse IP headers */
	tcp_context->tmp.ttl_irreg_chain_flag = 0;
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;
		const ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		const bool is_innermost = !!(ip_hdr_pos + 1 == tcp_context->ip_contexts_nr);
		uint8_t ttl_hopl;
		size_t ip_ext_pos;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip->version);

		inner_ip_ctxt = ip_context;
		inner_ip_hdr = remain_data;
		inner_ip_version = ip->version;

		if(ip->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;
			size_t ipv4_hdr_len;

			assert(remain_len >= sizeof(struct ipv4_hdr));
			ipv4_hdr_len = ipv4->ihl * sizeof(uint32_t);
			assert(remain_len >= ipv4_hdr_len);

			/* get the transport protocol */
			protocol = ipv4->protocol;

			/* irregular chain? */
			ttl_hopl = ipv4->ttl;
			if(!is_innermost && ttl_hopl != ip_context->ctxt.v4.ttl)
			{
				tcp_context->tmp.ttl_irreg_chain_flag |= 1;
				rohc_comp_debug(context, "last ttl_hopl = 0x%02x, ttl_hopl = "
				                "0x%02x, ttl_irreg_chain_flag = %d",
				                ip_context->ctxt.v4.ttl, ttl_hopl,
				                tcp_context->tmp.ttl_irreg_chain_flag);
			}

			/* skip IPv4 header */
			rohc_comp_debug(context, "skip %zu-byte IPv4 header with "
			                "Protocol 0x%02x", ipv4_hdr_len, protocol);
			remain_data += ipv4_hdr_len;
			remain_len -= ipv4_hdr_len;
		}
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			/* get the transport protocol */
			protocol = ipv6->nh;

			/* irregular chain? */
			ttl_hopl = ipv6->hl;
			if(!is_innermost && ttl_hopl != ip_context->ctxt.v6.hopl)
			{
				tcp_context->tmp.ttl_irreg_chain_flag |= 1;
				rohc_comp_debug(context, "last ttl_hopl = 0x%02x, ttl_hopl = "
				                "0x%02x, ttl_irreg_chain_flag = %d",
				                ip_context->ctxt.v6.hopl, ttl_hopl,
				                tcp_context->tmp.ttl_irreg_chain_flag);
			}

			/* skip IPv6 header */
			rohc_comp_debug(context, "skip %zd-byte IPv6 header with Next "
			                "Header 0x%02x", sizeof(struct ipv6_hdr), protocol);
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* skip IPv6 extension headers */
			for(ip_ext_pos = 0; rohc_is_ipv6_opt(protocol); ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				const size_t opt_len = ipv6_opt_get_length(ipv6_opt);
				rohc_comp_debug(context, "  skip %zu-byte IPv6 extension header "
				                "with Next Header 0x%02x", opt_len, protocol);
				remain_data += opt_len;
				remain_len -= opt_len;
				protocol = ipv6_opt->next_header;
			}
		}
		else
		{
			assert(0);
			goto error;
		}
	}

	tcp_context->tmp.outer_ip_ttl_changed =
		(tcp_context->tmp.ttl_irreg_chain_flag != 0);
	tcp_field_descr_change(context, "one or more outer TTL values",
	                       tcp_context->tmp.outer_ip_ttl_changed, 0);

	if(inner_ip_version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		const uint16_t ip_id = rohc_ntoh16(inner_ipv4->id);

		/* does IP-ID behavior changed? */
		tcp_context->tmp.ip_id_behavior_changed =
			(inner_ip_ctxt->ctxt.v4.last_ip_id_behavior != inner_ip_ctxt->ctxt.v4.ip_id_behavior);
		tcp_field_descr_change(context, "IP-ID behavior",
		                       tcp_context->tmp.ip_id_behavior_changed, 0);

		/* compute the new IP-ID / SN delta */
		if(inner_ip_ctxt->ctxt.v4.ip_id_behavior == ROHC_IP_ID_BEHAVIOR_SEQ_SWAP)
		{
			/* specific case of IP-ID delta for sequential swapped behavior */
			tcp_context->tmp.ip_id_delta = swab16(ip_id) - tcp_context->msn;
			rohc_comp_debug(context, "new outer IP-ID delta = 0x%x / %u (behavior = %d)",
			                tcp_context->tmp.ip_id_delta, tcp_context->tmp.ip_id_delta,
			                inner_ip_ctxt->ctxt.v4.ip_id_behavior);
		}
		else
		{
			/* compute delta the same way for sequential, zero or random: it is
			 * important to always compute the IP-ID delta and record it in W-LSB,
			 * so that the IP-ID deltas of next packets may be correctly encoded */
			tcp_context->tmp.ip_id_delta = ip_id - tcp_context->msn;
			rohc_comp_debug(context, "new outer IP-ID delta = 0x%x / %u (behavior = %d)",
			                tcp_context->tmp.ip_id_delta, tcp_context->tmp.ip_id_delta,
			                inner_ip_ctxt->ctxt.v4.ip_id_behavior);
		}

		/* how many bits are required to encode the new IP-ID / SN delta ? */
		if(inner_ip_ctxt->ctxt.v4.ip_id_behavior != ROHC_IP_ID_BEHAVIOR_SEQ &&
		   inner_ip_ctxt->ctxt.v4.ip_id_behavior != ROHC_IP_ID_BEHAVIOR_SEQ_SWAP)
		{
			/* send all bits if IP-ID behavior is not sequential */
			tcp_context->tmp.nr_ip_id_bits_3 = 16;
			tcp_context->tmp.nr_ip_id_bits_1 = 16;
			rohc_comp_debug(context, "force using 16 bits to encode new IP-ID delta "
			                "(non-sequential)");
		}
		else
		{
			/* send only required bits in FO or SO states */
			tcp_context->tmp.nr_ip_id_bits_3 =
				wlsb_get_kp_16bits(&tcp_context->ip_id_wlsb,
				                   tcp_context->tmp.ip_id_delta, 3);
			rohc_comp_debug(context, "%zu bits are required to encode new innermost "
			                "IP-ID delta 0x%04x with p = 3",
			                tcp_context->tmp.nr_ip_id_bits_3,
			                tcp_context->tmp.ip_id_delta);
			tcp_context->tmp.nr_ip_id_bits_1 =
				wlsb_get_kp_16bits(&tcp_context->ip_id_wlsb,
				                   tcp_context->tmp.ip_id_delta, 1);
			rohc_comp_debug(context, "%zu bits are required to encode new innermost "
			                "IP-ID delta 0x%04x with p = 1",
			                tcp_context->tmp.nr_ip_id_bits_1,
			                tcp_context->tmp.ip_id_delta);
		}
		/* add the new IP-ID / SN delta to the W-LSB encoding object */
		/* TODO: move this after successful packet compression */
		c_add_wlsb(&tcp_context->ip_id_wlsb, tcp_context->msn,
		           tcp_context->tmp.ip_id_delta);

		tcp_context->tmp.ip_df_changed =
			!!(inner_ipv4->df != inner_ip_ctxt->ctxt.v4.df);
		tcp_field_descr_change(context, "DF", tcp_context->tmp.ip_df_changed, 0);

		tcp_context->tmp.dscp_changed =
			!!(inner_ipv4->dscp != inner_ip_ctxt->ctxt.v4.dscp);
		tcp_field_descr_change(context, "DSCP", tcp_context->tmp.dscp_changed, 0);

		tcp_context->tmp.ttl_hopl = inner_ipv4->ttl;
	}
	else /* IPv6 */
	{
		const struct ipv6_hdr *const inner_ipv6 = (struct ipv6_hdr *) inner_ip_hdr;

		/* no IP-ID for IPv6 */
		tcp_context->tmp.ip_id_delta = 0;
		tcp_context->tmp.ip_id_behavior_changed = false;
		tcp_context->tmp.nr_ip_id_bits_3 = 0;
		tcp_context->tmp.nr_ip_id_bits_1 = 0;

		tcp_context->tmp.ip_df_changed = false; /* no DF for IPv6 */

		tcp_context->tmp.dscp_changed =
			!!(ipv6_get_dscp(inner_ipv6) != inner_ip_ctxt->ctxt.v6.dscp);
		tcp_field_descr_change(context, "DSCP", tcp_context->tmp.dscp_changed, 0);

		tcp_context->tmp.ttl_hopl = inner_ipv6->hl;
	}

	/* encode innermost IPv4 TTL or IPv6 Hop Limit */
	if(tcp_context->tmp.ttl_hopl != inner_ip_ctxt->ctxt.vx.ttl_hopl)
	{
		tcp_context->tmp.ttl_hopl_changed = true;
		tcp_context->ttl_hopl_change_count = 0;
	}
	else if(tcp_context->ttl_hopl_change_count < MAX_FO_COUNT)
	{
		tcp_context->tmp.ttl_hopl_changed = true;
		tcp_context->ttl_hopl_change_count++;
	}
	else
	{
		tcp_context->tmp.ttl_hopl_changed = false;
	}
	tcp_context->tmp.nr_ttl_hopl_bits =
		wlsb_get_k_8bits(&tcp_context->ttl_hopl_wlsb, tcp_context->tmp.ttl_hopl);
	rohc_comp_debug(context, "%zu bits are required to encode new innermost "
	                "TTL/Hop Limit 0x%02x with p = 3",
	                tcp_context->tmp.nr_ttl_hopl_bits,
	                tcp_context->tmp.ttl_hopl);
	/* add the new TTL/Hop Limit to the W-LSB encoding object */
	/* TODO: move this after successful packet compression */
	c_add_wlsb(&tcp_context->ttl_hopl_wlsb, tcp_context->msn,
	           tcp_context->tmp.ttl_hopl);

	return true;

error:
	return false;
}


/**
 * @brief Encode uncompressed TCP fields with the corresponding encoding scheme
 *
 * @param context  The compression context
 * @param tcp      The uncompressed TCP header to encode
 * @return         true in case of success, false otherwise
 */
static bool tcp_encode_uncomp_tcp_fields(struct rohc_comp_ctxt *const context,
                                         const struct tcphdr *const tcp)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint32_t seq_num_hbo = rohc_ntoh32(tcp->seq_num);
	const uint32_t ack_num_hbo = rohc_ntoh32(tcp->ack_num);

	rohc_comp_debug(context, "new TCP seq = 0x%08x, ack_seq = 0x%08x",
	                seq_num_hbo, ack_num_hbo);
	rohc_comp_debug(context, "old TCP seq = 0x%08x, ack_seq = 0x%08x",
	                rohc_ntoh32(tcp_context->old_tcphdr.seq_num),
	                rohc_ntoh32(tcp_context->old_tcphdr.ack_num));
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

	tcp_context->tmp.tcp_ack_flag_changed =
		(tcp->ack_flag != tcp_context->old_tcphdr.ack_flag);
	tcp_field_descr_change(context, "ACK flag",
	                       tcp_context->tmp.tcp_ack_flag_changed, 0);
	tcp_context->tmp.tcp_urg_flag_present = (tcp->urg_flag != 0);
	tcp_field_descr_present(context, "URG flag",
	                        tcp_context->tmp.tcp_urg_flag_present);
	tcp_context->tmp.tcp_urg_flag_changed =
		(tcp->urg_flag != tcp_context->old_tcphdr.urg_flag);
	tcp_field_descr_change(context, "URG flag",
	                       tcp_context->tmp.tcp_urg_flag_changed, 0);
	tcp_field_descr_change(context, "ECN flag",
	                       tcp_context->tmp.ecn_used_changed,
	                       tcp_context->ecn_used_change_count);
	if(tcp->rsf_flags != 0)
	{
		rohc_comp_debug(context, "RSF flags is set in current packet");
	}

	/* how many bits are required to encode the new TCP window? */
	if(tcp->window != tcp_context->old_tcphdr.window)
	{
		tcp_context->tmp.tcp_window_changed = true;
		tcp_context->tcp_window_change_count = 0;
	}
	else if(tcp_context->tcp_window_change_count < MAX_FO_COUNT)
	{
		tcp_context->tmp.tcp_window_changed = true;
		tcp_context->tcp_window_change_count++;
	}
	else
	{
		tcp_context->tmp.tcp_window_changed = false;
	}
	tcp_field_descr_change(context, "TCP window", tcp_context->tmp.tcp_window_changed,
	                       tcp_context->tcp_window_change_count);
	tcp_context->tmp.nr_window_bits_16383 =
		wlsb_get_kp_16bits(&tcp_context->window_wlsb, rohc_ntoh16(tcp->window),
		                   ROHC_LSB_SHIFT_TCP_WINDOW);
	rohc_comp_debug(context, "%zu bits are required to encode new TCP window "
	                "0x%04x with p = %d", tcp_context->tmp.nr_window_bits_16383,
	                rohc_ntoh16(tcp->window), ROHC_LSB_SHIFT_TCP_WINDOW);
	/* TODO: move this after successful packet compression */
	c_add_wlsb(&tcp_context->window_wlsb, tcp_context->msn, rohc_ntoh16(tcp->window));

	/* compute new scaled TCP sequence number */
	{
		const size_t seq_num_factor = tcp_context->tmp.payload_len;
		uint32_t seq_num_scaled;
		uint32_t seq_num_residue;

		c_field_scaling(&seq_num_scaled, &seq_num_residue, seq_num_factor,
		                seq_num_hbo);
		rohc_comp_debug(context, "seq_num = 0x%x, scaled = 0x%x, factor = %zu, "
		                "residue = 0x%x", seq_num_hbo, seq_num_scaled,
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
		                "least %zu / %u times since the scaling factor or "
		                "residue changed", tcp_context->seq_num_scaling_nr,
		                ROHC_INIT_TS_STRIDE_MIN);

		/* TODO: should update context at the very end only */
		tcp_context->seq_num_scaled = seq_num_scaled;
		tcp_context->seq_num_residue = seq_num_residue;
		tcp_context->seq_num_factor = seq_num_factor;
	}

	/* compute new scaled TCP acknowledgment number */
	{
		const uint32_t old_ack_num_hbo = rohc_ntoh32(tcp_context->old_tcphdr.ack_num);
		const uint32_t ack_delta = ack_num_hbo - old_ack_num_hbo;
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
		c_field_scaling(&ack_num_scaled, &ack_num_residue, ack_stride, ack_num_hbo);
		rohc_comp_debug(context, "ack_number = 0x%x, scaled = 0x%x, factor = %u, "
		                "residue = 0x%x", ack_num_hbo, ack_num_scaled,
		                ack_stride, ack_num_residue);

		if(context->num_sent_packets == 0)
		{
			/* no need to transmit the ack_stride until it becomes non-zero */
			tcp_context->ack_num_scaling_nr = ROHC_INIT_TS_STRIDE_MIN;
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
			                "%zu / %u times since the scaling factor or residue changed",
			                tcp_context->ack_num_scaling_nr, ROHC_INIT_TS_STRIDE_MIN);
		}

		/* TODO: should update context at the very end only */
		tcp_context->ack_num_scaled = ack_num_scaled;
		tcp_context->ack_num_residue = ack_num_residue;
		tcp_context->ack_stride = ack_stride;
	}

	/* how many bits are required to encode the new sequence number? */
	tcp_context->tmp.tcp_seq_num_changed =
		(tcp->seq_num != tcp_context->old_tcphdr.seq_num);
	if(tcp_context->seq_num_factor == 0 ||
	   tcp_context->seq_num_scaling_nr < ROHC_INIT_TS_STRIDE_MIN)
	{
		tcp_context->tmp.nr_seq_scaled_bits = 32;
	}
	else
	{
		tcp_context->tmp.nr_seq_scaled_bits =
			wlsb_get_k_32bits(&tcp_context->seq_scaled_wlsb, tcp_context->seq_num_scaled);
		rohc_comp_debug(context, "%zu bits are required to encode new scaled "
		                "sequence number 0x%08x", tcp_context->tmp.nr_seq_scaled_bits,
		                tcp_context->seq_num_scaled);
	}

	/* how many bits are required to encode the new ACK number? */
	tcp_context->tmp.tcp_ack_num_changed =
		(tcp->ack_num != tcp_context->old_tcphdr.ack_num);
	tcp_context->tmp.nr_ack_bits_16383 =
		wlsb_get_kp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 16383);
	rohc_comp_debug(context, "%zd bits are required to encode new ACK "
	                "number 0x%08x with p = 16383",
	                tcp_context->tmp.nr_ack_bits_16383, ack_num_hbo);
	if(!tcp_is_ack_scaled_possible(tcp_context->ack_stride,
	                               tcp_context->ack_num_scaling_nr))
	{
		tcp_context->tmp.nr_ack_scaled_bits = 32;
	}
	else
	{
		tcp_context->tmp.nr_ack_scaled_bits =
			wlsb_get_k_32bits(&tcp_context->ack_scaled_wlsb, tcp_context->ack_num_scaled);
		rohc_comp_debug(context, "%zu bits are required to encode new scaled "
		                "ACK number 0x%08x", tcp_context->tmp.nr_ack_scaled_bits,
		                tcp_context->ack_num_scaled);
	}

	/* how many bits are required to encode the new timestamp echo request and
	 * timestamp echo reply? */
	if(!tcp_context->tcp_opts.tmp.opt_ts_present)
	{
		/* no bit to send */
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_minus_1 = 0;
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x40000 = 0;
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x4000000 = 0;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_minus_1 = 0;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x40000 = 0;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x4000000 = 0;
		rohc_comp_debug(context, "no TS option: 0 bit required to encode the "
		                "new timestamp echo request/reply numbers");
	}
	else if(!tcp_context->tcp_opts.is_timestamp_init)
	{
		/* send all bits for the first occurrence of the TCP TS option */
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_minus_1 = 32;
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x40000 = 32;
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x4000000 = 32;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_minus_1 = 32;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x40000 = 32;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x4000000 = 32;
		rohc_comp_debug(context, "first occurrence of TCP TS option: force "
		                "using 32 bits to encode new timestamp echo "
		                "request/reply numbers");
	}
	else
	{
		/* send only required bits in FO or SO states */

		/* how many bits are required to encode the timestamp echo request
		 * with p = -1 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_minus_1 =
			wlsb_get_kp_32bits(&tcp_context->tcp_opts.ts_req_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_req,
			                   ROHC_LSB_SHIFT_TCP_TS_1B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo request 0x%08x with p = %d",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_minus_1,
		                tcp_context->tcp_opts.tmp.ts_req, ROHC_LSB_SHIFT_TCP_TS_1B);

		/* how many bits are required to encode the timestamp echo request
		 * with p = 0x40000 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x40000 =
			wlsb_get_kp_32bits(&tcp_context->tcp_opts.ts_req_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_req,
			                   ROHC_LSB_SHIFT_TCP_TS_3B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo request 0x%08x with p = 0x%x",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x40000,
		                tcp_context->tcp_opts.tmp.ts_req, ROHC_LSB_SHIFT_TCP_TS_3B);

		/* how many bits are required to encode the timestamp echo reply
		 * with p = 0x4000000 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x4000000 =
			wlsb_get_kp_32bits(&tcp_context->tcp_opts.ts_req_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_req,
			                   ROHC_LSB_SHIFT_TCP_TS_4B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo request 0x%08x with p = 0x%x",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x4000000,
		                tcp_context->tcp_opts.tmp.ts_req, ROHC_LSB_SHIFT_TCP_TS_4B);

		/* how many bits are required to encode the timestamp echo reply
		 * with p = -1 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_minus_1 =
			wlsb_get_kp_32bits(&tcp_context->tcp_opts.ts_reply_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_reply,
			                   ROHC_LSB_SHIFT_TCP_TS_1B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo reply 0x%08x with p = %d",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_minus_1,
		                tcp_context->tcp_opts.tmp.ts_reply, ROHC_LSB_SHIFT_TCP_TS_1B);

		/* how many bits are required to encode the timestamp echo reply
		 * with p = 0x40000 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x40000 =
			wlsb_get_kp_32bits(&tcp_context->tcp_opts.ts_reply_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_reply,
			                   ROHC_LSB_SHIFT_TCP_TS_3B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo reply 0x%08x with p = 0x%x",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x40000,
		                tcp_context->tcp_opts.tmp.ts_reply, ROHC_LSB_SHIFT_TCP_TS_3B);

		/* how many bits are required to encode the timestamp echo reply
		 * with p = 0x4000000 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x4000000 =
			wlsb_get_kp_32bits(&tcp_context->tcp_opts.ts_reply_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_reply,
			                   ROHC_LSB_SHIFT_TCP_TS_4B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo reply 0x%08x with p = 0x%x",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x4000000,
		                tcp_context->tcp_opts.tmp.ts_reply, ROHC_LSB_SHIFT_TCP_TS_4B);
	}

	return true;
}


/**
 * @brief Decide which packet to send when in the different states.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the inner IP header
 * @param tcp               The TCP header to compress
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_DYN, ROHC_PACKET_TCP_RND_[1-8],
 *                              ROHC_PACKET_TCP_SEQ_[1-8] and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_packet(struct rohc_comp_ctxt *const context,
                                       const ip_context_t *const ip_inner_context,
                                       const struct tcphdr *const tcp)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	rohc_packet_t packet_type;

	switch(context->state)
	{
		case ROHC_COMP_STATE_IR: /* The Initialization and Refresh (IR) state */
			rohc_comp_debug(context, "code IR packet");
			packet_type = ROHC_PACKET_IR;
			context->ir_count++;
			break;
		case ROHC_COMP_STATE_CR: /* The Context Replication (CR) state */
			if(tcp_context->tmp.is_ipv6_exts_list_static_changed)
			{
				rohc_comp_debug(context, "code IR packet (IPv6 extension list changed)");
				packet_type = ROHC_PACKET_IR;
			}
			else
			{
				rohc_comp_debug(context, "code IR-CR packet");
				packet_type = ROHC_PACKET_IR_CR;
			}
			context->cr_count++;
			break;
		case ROHC_COMP_STATE_FO: /* The First Order (FO) state */
			context->fo_count++;
			packet_type = tcp_decide_FO_packet(context, ip_inner_context, tcp);
			break;
		case ROHC_COMP_STATE_SO: /* The Second Order (SO) state */
			context->so_count++;
			packet_type = tcp_decide_SO_packet(context, ip_inner_context, tcp);
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
 * @param ip_inner_context  The context of the inner IP header
 * @param tcp               The TCP header to compress
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_DYN, ROHC_PACKET_TCP_RND_8,
 *                              ROHC_PACKET_TCP_SEQ_8 and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct tcphdr *const tcp)
{
	const bool crc7_at_least = true;
	return tcp_decide_FO_SO_packet(context, ip_inner_context, tcp, crc7_at_least);
}


/**
 * @brief Decide which packet to send when in SO state.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the inner IP header
 * @param tcp               The TCP header to compress
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_CR, ROHC_PACKET_IR_DYN,
 *                              ROHC_PACKET_TCP_RND_[1-8],
 *                              ROHC_PACKET_TCP_SEQ_[1-8] and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_SO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct tcphdr *const tcp)
{
	const bool crc7_at_least = false;
	return tcp_decide_FO_SO_packet(context, ip_inner_context, tcp, crc7_at_least);
}


/**
 * @brief Decide which packet to send when in FO or SO state.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the inner IP header
 * @param tcp               The TCP header to compress
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
                                             const struct tcphdr *const tcp,
                                             const bool crc7_at_least)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	rohc_packet_t packet_type;

	if(tcp_context->tmp.is_ipv6_exts_list_static_changed)
	{
		rohc_comp_debug(context, "force packet IR because at least one IPv6 option "
		                "changed its static part");
		packet_type = ROHC_PACKET_IR;
	}
	else if(tcp_context->tmp.is_ipv6_exts_list_dyn_changed)
	{
		rohc_comp_debug(context, "force packet IR-DYN because at least one IPv6 option "
		                "changed its dynamic part");
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if((tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_minus_1 > ROHC_SDVL_MAX_BITS_IN_2_BYTES &&
	         tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x40000 > ROHC_SDVL_MAX_BITS_IN_3_BYTES &&
	         tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x4000000 > ROHC_SDVL_MAX_BITS_IN_4_BYTES) ||
	        (tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_minus_1 > ROHC_SDVL_MAX_BITS_IN_2_BYTES &&
	         tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x40000 > ROHC_SDVL_MAX_BITS_IN_3_BYTES &&
	         tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x4000000 > ROHC_SDVL_MAX_BITS_IN_4_BYTES))
	{
		rohc_comp_debug(context, "force packet IR-DYN because the TCP TS option "
		                "changed too much");
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(tcp_context->tmp.nr_msn_bits > 4)
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
	else if(tcp_context->tmp.outer_ip_ttl_changed ||
	        tcp_context->tmp.ip_id_behavior_changed ||
	        tcp_context->tmp.ip_df_changed ||
	        tcp_context->tmp.dscp_changed ||
	        tcp_context->tmp.tcp_ack_flag_changed ||
	        tcp_context->tmp.tcp_urg_flag_present ||
	        tcp_context->tmp.tcp_urg_flag_changed ||
	        tcp_context->old_tcphdr.urg_ptr != tcp->urg_ptr ||
	        !tcp_is_ack_stride_static(tcp_context->ack_stride,
	                                  tcp_context->ack_num_scaling_nr))
	{
		TRACE_GOTO_CHOICE;
		packet_type = ROHC_PACKET_TCP_CO_COMMON;
	}
	else if(tcp_context->tmp.ecn_used_changed ||
	        tcp_context->tmp.ttl_hopl_changed)
	{
		const uint32_t seq_num_hbo = rohc_ntoh32(tcp->seq_num);
		const uint32_t ack_num_hbo = rohc_ntoh32(tcp->ack_num);
		size_t nr_seq_bits_65535; /* min bits required to encode TCP seqnum with p = 65535 */
		size_t nr_seq_bits_8191; /* min bits required to encode TCP seqnum with p = 8191 */
		size_t nr_ack_bits_8191; /* min bits required to encode TCP ACK number with p = 8191 */

		nr_seq_bits_65535 = wlsb_get_kp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 65535);
		rohc_comp_debug(context, "%zd bits are required to encode new sequence "
		                "number 0x%08x with p = 65535", nr_seq_bits_65535, seq_num_hbo);
		nr_seq_bits_8191 = wlsb_get_kp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 8191);
		rohc_comp_debug(context, "%zd bits are required to encode new sequence "
		                "number 0x%08x with p = 8191", nr_seq_bits_8191, seq_num_hbo);

		nr_ack_bits_8191 = wlsb_get_kp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 8191);
		rohc_comp_debug(context, "%zd bits are required to encode new ACK "
		                "number 0x%08x with p = 8191", nr_ack_bits_8191, ack_num_hbo);

		/* use compressed header with a 7-bit CRC (rnd_8, seq_8 or common):
		 *  - use common if too many LSB of sequence number are required
		 *  - use common if too many LSB of sequence number are required
		 *  - use common if too many LSB of innermost TTL/Hop Limit are required
		 *  - use common if window changed */
		if(ip_inner_context->ctxt.vx.ip_id_behavior <= ROHC_IP_ID_BEHAVIOR_SEQ_SWAP &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		   nr_seq_bits_8191 <= 14 &&
		   nr_ack_bits_8191 <= 15 &&
		   tcp_context->tmp.nr_ttl_hopl_bits <= 3 &&
		   !tcp_context->tmp.tcp_window_changed)
		{
			/* ROHC_IP_ID_BEHAVIOR_SEQ or ROHC_IP_ID_BEHAVIOR_SEQ_SWAP */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else if(ip_inner_context->ctxt.vx.ip_id_behavior > ROHC_IP_ID_BEHAVIOR_SEQ_SWAP &&
		        nr_seq_bits_65535 <= 16 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
		        tcp_context->tmp.nr_ttl_hopl_bits <= 3 &&
		        !tcp_context->tmp.tcp_window_changed)
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
	else if(ip_inner_context->ctxt.vx.ip_id_behavior <= ROHC_IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		/* ROHC_IP_ID_BEHAVIOR_SEQ or ROHC_IP_ID_BEHAVIOR_SEQ_SWAP:
		 * co_common or seq_X packet types */
		packet_type = tcp_decide_FO_SO_packet_seq(context, tcp, crc7_at_least);
	}
	else if(ip_inner_context->ctxt.vx.ip_id_behavior == ROHC_IP_ID_BEHAVIOR_RAND ||
	        ip_inner_context->ctxt.vx.ip_id_behavior == ROHC_IP_ID_BEHAVIOR_ZERO)
	{
		/* ROHC_IP_ID_BEHAVIOR_RAND or ROHC_IP_ID_BEHAVIOR_ZERO:
		 * co_common or rnd_X packet types */
		packet_type = tcp_decide_FO_SO_packet_rnd(context, tcp, crc7_at_least);
	}
	else
	{
		rohc_comp_warn(context, "unexpected IP-ID behavior (%d)",
		               ip_inner_context->ctxt.vx.ip_id_behavior);
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
 * @param tcp               The TCP header to compress
 * @param crc7_at_least     Whether packet types with CRC strictly smaller
 *                          than 8 bits are allowed or not
 * @return                  \li The packet type among ROHC_PACKET_TCP_SEQ_[1-8]
 *                              and ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
                                                 const struct tcphdr *const tcp,
                                                 const bool crc7_at_least)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint32_t seq_num_hbo = rohc_ntoh32(tcp->seq_num);
	const uint32_t ack_num_hbo = rohc_ntoh32(tcp->ack_num);
	size_t nr_seq_bits_32767; /* min bits required to encode TCP seqnum with p = 32767 */
	size_t nr_seq_bits_8191; /* min bits required to encode TCP seqnum with p = 8191 */
	size_t nr_ack_bits_8191; /* min bits required to encode TCP ACK number with p = 8191 */
	rohc_packet_t packet_type;

	nr_seq_bits_32767 = wlsb_get_kp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 32767);
	rohc_comp_debug(context, "%zd bits are required to encode new sequence "
	                "number 0x%08x with p = 32767", nr_seq_bits_32767, seq_num_hbo);
	nr_seq_bits_8191 = wlsb_get_kp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 8191);
	rohc_comp_debug(context, "%zd bits are required to encode new sequence "
	                "number 0x%08x with p = 8191", nr_seq_bits_8191, seq_num_hbo);

	nr_ack_bits_8191 = wlsb_get_kp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 8191);
	rohc_comp_debug(context, "%zd bits are required to encode new ACK "
	                "number 0x%08x with p = 8191", nr_ack_bits_8191, ack_num_hbo);

	if(tcp->rsf_flags != 0 ||
	   tcp_context->tcp_opts.tmp.do_list_struct_changed ||
	   tcp_context->tcp_opts.tmp.do_list_static_changed)
	{
		/* seq_8 or co_common
		 *
		 * seq_8 can be used if:
		 *  - TCP window didn't change,
		 *  - at most 14 LSB of the TCP sequence number are required,
		 *  - at most 15 LSB of the TCP ACK number are required,
		 *  - at most 4 LSBs of IP-ID must be transmitted
		 * otherwise use co_common packet */
		if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		   nr_seq_bits_8191 <= 14 &&
		   nr_ack_bits_8191 <= 15 &&
		   tcp_context->tmp.nr_ttl_hopl_bits <= 3 &&
		   !tcp_context->tmp.tcp_window_changed)
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
	else if(tcp_context->tmp.tcp_window_changed)
	{
		size_t nr_ack_bits_32767; /* min bits required to encode TCP ACK number with p = 32767 */

		nr_ack_bits_32767 = wlsb_get_kp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 32767);
		rohc_comp_debug(context, "%zd bits are required to encode new ACK "
		                "number 0x%08x with p = 32767", nr_ack_bits_32767, ack_num_hbo);

		/* seq_7 or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_window_bits_16383 <= 15 &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 5 &&
		   nr_ack_bits_32767 <= 16 &&
		   !tcp_context->tmp.tcp_seq_num_changed)
		{
			/* seq_7 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_7;
		}
		else
		{
			/* rnd_7 is not possible, rnd_8 neither so fallback on co_common */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(tcp->ack_flag == 0 || !tcp_context->tmp.tcp_ack_num_changed)
	{
		/* seq_2, seq_1 or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 7 &&
		   tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
		   tcp_context->tmp.nr_seq_scaled_bits <= 4)
		{
			/* seq_2 is possible */
			TRACE_GOTO_CHOICE;
			assert(tcp_context->tmp.payload_len > 0);
			packet_type = ROHC_PACKET_TCP_SEQ_2;
		}
		else if(!crc7_at_least &&
		        tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        nr_seq_bits_32767 <= 16)
		{
			/* seq_1 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_1;
		}
		else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        true /* TODO: no more than 3 bits of TTL */ &&
		        nr_ack_bits_8191 <= 15 &&
		        nr_seq_bits_8191 <= 14)
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
	else if(!tcp_context->tmp.tcp_seq_num_changed)
	{
		/* seq_4, seq_3, or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_ip_id_bits_1 <= 3 &&
		   tcp_is_ack_scaled_possible(tcp_context->ack_stride,
		                              tcp_context->ack_num_scaling_nr) &&
		   tcp_context->tmp.nr_ack_scaled_bits <= 4)
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_4;
		}
		else if(!crc7_at_least &&
		        tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16)
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_3;
		}
		else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        true /* TODO: no more than 3 bits of TTL */ &&
		        nr_ack_bits_8191 <= 15 &&
		        nr_seq_bits_8191 <= 14)
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
		/* sequence and acknowledgment numbers changed:
		 * seq_6, seq_5, seq_8 or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		   tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
		   tcp_context->tmp.nr_seq_scaled_bits <= 4 &&
		   tcp_context->tmp.nr_ack_bits_16383 <= 16)
		{
			TRACE_GOTO_CHOICE;
			assert(tcp_context->tmp.payload_len > 0);
			packet_type = ROHC_PACKET_TCP_SEQ_6;
		}
		else if(!crc7_at_least &&
		        tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
		        nr_seq_bits_32767 <= 16)
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_5;
		}
		else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        nr_seq_bits_8191 <= 14 &&
		        nr_ack_bits_8191 <= 15 &&
		        tcp_context->tmp.nr_ttl_hopl_bits <= 3 &&
		        !tcp_context->tmp.tcp_window_changed)
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
 * @param tcp               The TCP header to compress
 * @param crc7_at_least     Whether packet types with CRC strictly smaller
 *                          than 8 bits are allowed or not
 * @return                  \li The packet type among ROHC_PACKET_TCP_SEQ_[1-8]
 *                              and ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
                                                 const struct tcphdr *const tcp,
                                                 const bool crc7_at_least)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint32_t seq_num_hbo = rohc_ntoh32(tcp->seq_num);
	const uint32_t ack_num_hbo = rohc_ntoh32(tcp->ack_num);
	size_t nr_seq_bits_65535; /* min bits required to encode TCP seqnum with p = 65535 */
	size_t nr_seq_bits_8191; /* min bits required to encode TCP seqnum with p = 8191 */
	size_t nr_ack_bits_8191; /* min bits required to encode TCP ACK number with p = 8191 */
	rohc_packet_t packet_type;

	nr_seq_bits_65535 = wlsb_get_kp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 65535);
	rohc_comp_debug(context, "%zd bits are required to encode new sequence "
	                "number 0x%08x with p = 65535", nr_seq_bits_65535, seq_num_hbo);
	nr_seq_bits_8191 = wlsb_get_kp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 8191);
	rohc_comp_debug(context, "%zd bits are required to encode new sequence "
	                "number 0x%08x with p = 8191", nr_seq_bits_8191, seq_num_hbo);

	nr_ack_bits_8191 = wlsb_get_kp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 8191);
	rohc_comp_debug(context, "%zd bits are required to encode new ACK "
	                "number 0x%08x with p = 8191", nr_ack_bits_8191, ack_num_hbo);

	if(tcp->rsf_flags != 0 ||
	   tcp_context->tcp_opts.tmp.do_list_struct_changed ||
	   tcp_context->tcp_opts.tmp.do_list_static_changed)
	{
		if(!tcp_context->tmp.tcp_window_changed &&
		   nr_seq_bits_65535 <= 16 &&
		   tcp_context->tmp.nr_ack_bits_16383 <= 16)
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
		if(tcp_context->tmp.tcp_window_changed)
		{
			size_t nr_ack_bits_65535; /* min bits required to encode ACK number with p = 65535 */

			nr_ack_bits_65535 = wlsb_get_kp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 65535);
			rohc_comp_debug(context, "%zd bits are required to encode new ACK "
			                "number 0x%08x with p = 65535", nr_ack_bits_65535, ack_num_hbo);

			if(!crc7_at_least &&
			   !tcp_context->tmp.tcp_seq_num_changed &&
			   nr_ack_bits_65535 <= 18)
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
		        !tcp_context->tmp.tcp_ack_num_changed &&
		        tcp_context->tmp.payload_len > 0 &&
		        tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
		        tcp_context->tmp.nr_seq_scaled_bits <= 4)
		{
			/* rnd_2 is possible */
			assert(tcp_context->tmp.payload_len > 0);
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_2;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        tcp_is_ack_scaled_possible(tcp_context->ack_stride,
		                                   tcp_context->ack_num_scaling_nr) &&
		        tcp_context->tmp.nr_ack_scaled_bits <= 4 &&
		        !tcp_context->tmp.tcp_seq_num_changed)
		{
			/* rnd_4 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_4;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        !tcp_context->tmp.tcp_seq_num_changed &&
		        nr_ack_bits_8191 <= 15)
		{
			/* rnd_3 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_3;
		}
		else if(!crc7_at_least &&
		        nr_seq_bits_65535 <= 18 &&
		        !tcp_context->tmp.tcp_ack_num_changed)
		{
			/* rnd_1 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_1;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
		        tcp_context->tmp.nr_seq_scaled_bits <= 4 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16)
		{
			/* ACK number present */
			/* rnd_6 is possible */
			assert(tcp_context->tmp.payload_len > 0);
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_6;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        nr_seq_bits_8191 <= 14 &&
		        nr_ack_bits_8191 <= 15)
		{
			/* ACK number present */
			/* rnd_5 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_5;
		}
		else if(/* !tcp_context->tmp.tcp_window_changed && */
		        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
		        nr_seq_bits_65535 <= 16)
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
 */
static void tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
                                         const uint8_t pkt_ecn_vals,
                                         const uint8_t pkt_outer_dscp_changed,
                                         const uint8_t pkt_res_val)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	const bool ecn_used_change_needed_by_outer_dscp =
		(pkt_outer_dscp_changed && !tcp_context->ecn_used);
	const bool tcp_res_flag_changed =
		(pkt_res_val != tcp_context->old_tcphdr.res_flags);
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
		   tcp_context->ecn_used_zero_count < MAX_FO_COUNT)
		{
			/* do not change ecn_used = 0 too quickly, wait for a few packets
			 * that do not need ecn_used = 1 to actually perform the change */
			rohc_comp_debug(context, "ECN: packet doesn't use ECN any more but "
			                "context does, wait for %zu more packets without ECN "
			                "before changing the context ecn_used parameter",
			                MAX_FO_COUNT - tcp_context->ecn_used_zero_count);
			tcp_context->tmp.ecn_used_changed = false;
			tcp_context->ecn_used_zero_count++;
		}
		else
		{
			rohc_comp_debug(context, "ECN: behavior changed");
			tcp_context->tmp.ecn_used_changed = true;
			tcp_context->ecn_used =
				!!(pkt_ecn_vals != 0 || tcp_res_flag_changed || pkt_outer_dscp_changed);
			tcp_context->ecn_used_change_count = 0;
			tcp_context->ecn_used_zero_count = 0;
		}
	}
	else if(tcp_context->ecn_used_change_count < MAX_FO_COUNT)
	{
		rohc_comp_debug(context, "ECN: behavior didn't change but changed a few "
		                "packet before");
		tcp_context->tmp.ecn_used_changed = true;
		tcp_context->ecn_used_change_count++;
		tcp_context->ecn_used_zero_count = 0;
	}
	else
	{
		rohc_comp_debug(context, "ECN: behavior didn't change");
		tcp_context->tmp.ecn_used_changed = false;
		tcp_context->ecn_used_zero_count = 0;
	}
	rohc_comp_debug(context, "ECN: context does%s use ECN",
	                tcp_context->ecn_used ? "" : "n't");
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
	const uint8_t *remain_data = feedback_data;
	size_t remain_len = feedback_data_len;

	if(feedback_type == ROHC_FEEDBACK_1)
	{
		const bool sn_not_valid = false;
		uint32_t sn_bits;
		size_t sn_bits_nr;

		rohc_comp_debug(context, "FEEDBACK-1 received");
		assert(remain_len == 1);

		/* get the 8 LSB bits of the acknowledged SN */
		sn_bits = remain_data[0] & 0xff;
		sn_bits_nr = 8;

		rohc_comp_debug(context, "ACK received (CID = %zu, %zu-bit SN = 0x%02x)",
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

			rohc_comp_debug(context, "ACK received (CID = %zu, %zu-bit SN = 0x%x, "
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
			          "NACK received for CID %zu", context->cid);
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
			          "STATIC-NACK received for CID %zu", context->cid);
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
	.protocol       = ROHC_IPPROTO_TCP, /* IP protocol */
	.create         = c_tcp_create_from_pkt,     /* profile handlers */
	.clone          = c_tcp_create_from_ctxt,
	.destroy        = c_tcp_destroy,
	.check_profile  = c_tcp_check_profile,
	.check_context  = c_tcp_check_context,
	.encode         = c_tcp_encode,
	.feedback       = c_tcp_feedback,
};

