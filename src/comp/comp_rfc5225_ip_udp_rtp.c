/*
 * Copyright 2018 Viveris Technologies
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
 * @file   comp_rfc5225_ip_udp_rtp.c
 * @brief  ROHC compression context for the ROHCv2 IP/UDP/RTP profile
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Valentin Boutonné <vboutonne@toulouse.viveris.com>
 */

#include "rohc_comp_internals.h"
#include "rohc_traces.h"
#include "rohc_traces_internal.h"
#include "rohc_debug.h"
#include "rohc_bit_ops.h"
#include "protocols/ip_numbers.h"
#include "protocols/ip.h"
#include "protocols/rfc5225.h"
#include "schemes/cid.h"
#include "schemes/ipv6_exts.h"
#include "schemes/ip_ctxt.h"
#include "schemes/comp_wlsb.h"
#include "schemes/ip_id_offset.h"
#include "schemes/rfc4996.h" /* for c_optional_ip_id_lsb */
#include "crc.h"

#include <assert.h>


/**
 * @brief Define the RFC5225-specific temporary variables in the profile
 *        compression context
 */
struct comp_rfc5225_tmp_variables
{
	/** The offset between two consecutive MSN */
	int16_t msn_offset;

	/** Whether at least one of the DF fields changed */
	bool at_least_one_df_changed;
	/** Whether the behavior of at least one of the IP-ID fields changed */
	bool at_least_one_ip_id_behavior_changed;

	/** Whether at least one of the DF fields changed in all outer IP headers */
	bool outer_df_changed;
	/** Whether the behavior of at least one of the outer IP-ID fields changed */
	bool outer_ip_id_behavior_changed;
	/* Whether at least one TOS/TC or TTL/HL changed in all outer IP headers */
	bool outer_ip_flag;

	/** Whether the innermost DF field changed */
	bool innermost_df_changed;
	/** Whether the behavior of the innermost IP-ID field changed */
	bool innermost_ip_id_behavior_changed;
	/** Whether the innermost IP-ID offset changed */
	bool innermost_ip_id_offset_changed;
	/** Whether the innermost TOS/TC changed in the innermost IP header */
	bool innermost_tos_tc_changed;
	/** Whether the innermost TTL/HL changed in the innermost IP header */
	bool innermost_ttl_hopl_changed;
	/** Whether the innermost TOS/TC or TTL/HL changed in the innermost IP header */
	bool innermost_ip_flag;

	/** The new innermost IP-ID value */
	uint16_t innermost_ip_id;
	/** The new innermost IP-ID / SN delta (with bits swapped if necessary) */
	uint16_t innermost_ip_id_offset;

	/** The new innermost DF value */
	uint8_t innermost_df;
	/** The new innermost TTL/HL value */
	uint8_t innermost_ttl_hopl;
	/** The new innermost TOS/TC value */
	uint8_t innermost_tos_tc;

	/** Whether the UDP checksum is used or not */
	bool new_udp_checksum_used;
	/** Whether the fact that the UDP checksum is used or not changed */
	bool udp_checksum_used_changed;
};


/** Define the ROHCv2 IP/UDP/RTP part of the profile compression context */
struct rohc_comp_rfc5225_ip_udp_rtp_ctxt
{
	uint16_t msn;  /**< The Master Sequence Number (MSN) */
	struct c_wlsb msn_wlsb;    /**< The W-LSB encoding context for MSN */

	/** The MSN of the last packet that updated the context (used to determine
	 * if a positive ACK may cause a transition to a higher compression state) */
	uint16_t msn_of_last_ctxt_updating_pkt;

	/** The W-LSB encoding context for innermost IP-ID offset */
	struct c_wlsb innermost_ip_id_offset_wlsb;
	/** The innermost IP-ID / SN delta (with bits swapped if necessary) */
	uint16_t innermost_ip_id_offset;

	ip_context_t ip_contexts[ROHC_MAX_IP_HDRS];
	size_t ip_contexts_nr;

	/** The number of all DF transmissions since last change */
	uint8_t all_df_trans_nr;
	/** The number of innermost DF transmissions since last change */
	uint8_t innermost_df_trans_nr;
	/** The number of outer DF transmissions since last change */
	uint8_t outer_df_trans_nr;

	/** The number of all IP-ID behavior transmissions since last change */
	uint8_t all_ip_id_behavior_trans_nr;
	/** The number of innermost IP-ID behavior transmissions since last change */
	uint8_t innermost_ip_id_behavior_trans_nr;
	/** The number of innermost IP-ID offset transmissions since last change */
	uint8_t innermost_ip_id_offset_trans_nr;
	/** The number of outer IP-ID behavior transmissions since last change */
	uint8_t outer_ip_id_behavior_trans_nr;

	/** The number of innermost IP flag transmissions since last change */
	uint8_t innermost_ip_flag_trans_nr;
	/** The number of outer IP flag transmissions since last change */
	uint8_t outer_ip_flag_trans_nr;

	/** The number of innermost TOS/TC transmissions since last change */
	uint8_t innermost_tos_tc_trans_nr;

	/** The number of innermost TTL/HL transmissions since last change */
	uint8_t innermost_ttl_hopl_trans_nr;

	struct comp_rfc5225_tmp_variables tmp;

	/** The UDP Source port */
	uint16_t udp_sport;
	/** The UDP Destination port */
	uint16_t udp_dport;
	/** Whether the UDP checksum is used or not */
	bool udp_checksum_used;
	/** The number of 'UDP checksum used' transmissions since last change */
	uint8_t udp_checksum_used_trans_nr;

	/** The RTP SSRC field */
	uint32_t rtp_ssrc;
};


/*
 * Prototypes of private functions
 */

/* create/destroy context */
static bool rohc_comp_rfc5225_ip_udp_rtp_create(struct rohc_comp_ctxt *const context,
                                                const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static void rohc_comp_rfc5225_ip_udp_rtp_destroy(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

/* encode ROHCv2 IP/UDP/RTP packets */
static int rohc_comp_rfc5225_ip_udp_rtp_encode(struct rohc_comp_ctxt *const context,
                                               const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                               uint8_t *const rohc_pkt,
                                               const size_t rohc_pkt_max_len,
                                               rohc_packet_t *const packet_type)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static void rohc_comp_rfc5225_ip_udp_rtp_detect_changes(struct rohc_comp_ctxt *const context,
                                                        const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs)
	__attribute__((nonnull(1, 2)));
static void rohc_comp_rfc5225_ip_udp_rtp_detect_changes_ipv4(struct rohc_comp_ctxt *const ctxt,
                                                             ip_context_t *const ip_ctxt,
                                                             const struct ipv4_hdr *const ipv4,
                                                             const bool is_innermost)
	__attribute__((nonnull(1, 2, 3)));

static int rohc_comp_rfc5225_ip_udp_rtp_code_IR_pkt(const struct rohc_comp_ctxt *const ctxt,
                                                    const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                    uint8_t *const rohc_pkt,
                                                    const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int rohc_comp_rfc5225_ip_udp_rtp_code_co_repair_pkt(const struct rohc_comp_ctxt *const ctxt,
                                                           const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                           uint8_t *const rohc_pkt,
                                                           const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int rohc_comp_rfc5225_ip_udp_rtp_code_CO_pkt(const struct rohc_comp_ctxt *const context,
                                                    const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                    uint8_t *const rohc_pkt,
                                                    const size_t rohc_pkt_max_len,
                                                    const rohc_packet_t packet_type)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

/* static chain */
static int rohc_comp_rfc5225_ip_udp_rtp_static_chain(const struct rohc_comp_ctxt *const ctxt,
                                                     const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                     uint8_t *const rohc_pkt,
                                                     const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int rohc_comp_rfc5225_ip_udp_rtp_static_ipv4_part(const struct rohc_comp_ctxt *const ctxt,
                                                 const struct ipv4_hdr *const ipv4,
                                                 const bool is_innermost,
                                                 uint8_t *const rohc_data,
                                                 const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int rohc_comp_rfc5225_ip_udp_rtp_static_ipv6_part(const struct rohc_comp_ctxt *const ctxt,
                                                 const struct ipv6_hdr *const ipv6,
                                                 const bool is_innermost,
                                                 uint8_t *const rohc_data,
                                                 const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int rohc_comp_rfc5225_ip_udp_rtp_static_udp_part(const struct rohc_comp_ctxt *const ctxt,
                                                    const struct udphdr *const udp,
                                                    uint8_t *const rohc_data,
                                                    const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int rohc_comp_rfc5225_ip_udp_rtp_static_rtp_part(const struct rohc_comp_ctxt *const ctxt,
                                                    const struct rtphdr *const rtp,
                                                    uint8_t *const rohc_data,
                                                    const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

/* dynamic chain */
static int rohc_comp_rfc5225_ip_udp_rtp_dyn_chain(const struct rohc_comp_ctxt *const ctxt,
                                                  const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                  uint8_t *const rohc_pkt,
                                                  const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int rohc_comp_rfc5225_ip_udp_rtp_dyn_ipv4_part(const struct rohc_comp_ctxt *const ctxt,
                                                  const ip_context_t *const ip_ctxt,
                                                  const struct ipv4_hdr *const ipv4,
                                                  uint8_t *const rohc_data,
                                                  const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static int rohc_comp_rfc5225_ip_udp_rtp_dyn_ipv6_part(const struct rohc_comp_ctxt *const ctxt,
                                                  const ip_context_t *const ip_ctxt,
                                                  const struct ipv6_hdr *const ipv6,
                                                  uint8_t *const rohc_data,
                                                  const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static int rohc_comp_rfc5225_ip_udp_rtp_dyn_udp_part(const struct rohc_comp_ctxt *const ctxt,
                                                 const struct udphdr *const udp,
                                                 uint8_t *const rohc_data,
                                                 const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int rohc_comp_rfc5225_ip_udp_rtp_dyn_rtp_part(const struct rohc_comp_ctxt *const ctxt,
                                                 const struct rtphdr *const rtp,
                                                 uint8_t *const rohc_data,
                                                 const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

/* irregular chain */
static int rohc_comp_rfc5225_ip_udp_rtp_irreg_chain(const struct rohc_comp_ctxt *const ctxt,
                                                    const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                    uint8_t *const rohc_pkt,
                                                    const size_t rohc_pkt_max_len)
        __attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int rohc_comp_rfc5225_ip_udp_rtp_irreg_ipv4_part(const struct rohc_comp_ctxt *const ctxt,
                                                    const ip_context_t *const ip_ctxt,
                                                    const struct ipv4_hdr *const ipv4,
                                                    const bool is_innermost,
                                                    uint8_t *const rohc_data,
                                                    const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
static int rohc_comp_rfc5225_ip_udp_rtp_irreg_ipv6_part(const struct rohc_comp_ctxt *const ctxt,
                                                    const ip_context_t *const ip_ctxt,
                                                    const struct ipv6_hdr *const ipv6,
                                                    const bool is_innermost,
                                                    uint8_t *const rohc_data,
                                                    const size_t rohc_max_len)
        __attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
static int rohc_comp_rfc5225_ip_udp_rtp_irreg_udp_part(const struct rohc_comp_ctxt *const ctxt,
                                                   const struct udphdr *const udp,
                                                   uint8_t *const rohc_data,
                                                   const size_t rohc_max_len)
        __attribute__((warn_unused_result, nonnull(1, 2, 3)));

/* deliver feedbacks */
static bool rohc_comp_rfc5225_ip_udp_rtp_feedback(struct rohc_comp_ctxt *const ctxt,
                                              const enum rohc_feedback_type feedback_type,
                                              const uint8_t *const packet,
                                              const size_t packet_len,
                                              const uint8_t *const feedback_data,
                                              const size_t feedback_data_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 5)));
static bool rohc_comp_rfc5225_ip_udp_rtp_feedback_2(struct rohc_comp_ctxt *const ctxt,
                                                const uint8_t *const packet,
                                                const size_t packet_len,
                                                const uint8_t *const feedback_data,
                                                const size_t feedback_data_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static void rohc_comp_rfc5225_ip_udp_rtp_feedback_ack(struct rohc_comp_ctxt *const ctxt,
                                                  const uint32_t sn_bits,
                                                  const size_t sn_bits_nr,
                                                  const bool sn_not_valid)
	__attribute__((nonnull(1)));

/* decide packet */
static rohc_packet_t rohc_comp_rfc5225_ip_udp_rtp_decide_pkt(const struct rohc_comp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1)));

static rohc_packet_t rohc_comp_rfc5225_ip_udp_rtp_decide_FO_pkt(const struct rohc_comp_ctxt *const ctxt)
	__attribute__((warn_unused_result, nonnull(1)));

static rohc_packet_t rohc_comp_rfc5225_ip_udp_rtp_decide_SO_pkt(const struct rohc_comp_ctxt *const ctxt)
	__attribute__((warn_unused_result, nonnull(1)));

static rohc_packet_t rohc_comp_rfc5225_ip_udp_rtp_decide_FO_SO_pkt(const struct rohc_comp_ctxt *const ctxt,
                                                               const bool crc7_at_least)
	__attribute__((warn_unused_result, nonnull(1)));

static bool rohc_comp_rfc5225_is_msn_lsb_possible(const struct c_wlsb *const wlsb,
                                                  const uint16_t value,
                                                  const rohc_reordering_offset_t reorder_ratio,
                                                  const size_t k)
	__attribute__((warn_unused_result, nonnull(1)));

static bool rohc_comp_rfc5225_is_ipid_sequential(const rohc_ip_id_behavior_t behavior)
	__attribute__((warn_unused_result, const));

static bool rohc_comp_rfc5225_is_seq_ipid_inferred(const ip_context_t *const ip_ctxt,
                                                   const uint8_t ip_id_offset_trans_nr,
                                                   const uint8_t oa_repetitions_nr,
                                                   const uint16_t new_ip_id,
                                                   const int16_t msn_offset)
	__attribute__((warn_unused_result, nonnull(1)));

/*
 * Definitions of private functions
 */


/**
 * @brief Create a new ROHCv2 IP/UDP/RTP context and initialize it thanks
 *        to the given uncompressed packet
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context          The compression context
 * @param uncomp_pkt_hdrs  The uncompressed headers to initialize the new context
 * @return                 true if successful, false otherwise
 */
static bool rohc_comp_rfc5225_ip_udp_rtp_create(struct rohc_comp_ctxt *const context,
                                                const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs)
{
	const struct rohc_comp *const comp = context->compressor;
	struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *rfc5225_ctxt;
	size_t ip_hdr_pos;
	bool is_ok;

	assert(uncomp_pkt_hdrs->innermost_ip_hdr->next_proto == ROHC_IPPROTO_UDP);
	assert(uncomp_pkt_hdrs->udp != NULL);
	assert(uncomp_pkt_hdrs->rtp != NULL);

	/* create the ROHCv2 IP/UDP/RTP part of the profile context */
	rfc5225_ctxt = calloc(1, sizeof(struct rohc_comp_rfc5225_ip_udp_rtp_ctxt));
	if(rfc5225_ctxt == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the ROHCv2 IP/UDP/RTP part of the profile context");
		goto error;
	}
	context->specific = rfc5225_ctxt;

	/* create contexts for IP headers and their extensions */
	for(ip_hdr_pos = 0; ip_hdr_pos < uncomp_pkt_hdrs->ip_hdrs_nr; ip_hdr_pos++)
	{
		const struct rohc_pkt_ip_hdr *const pkt_ip_hdr =
			&(uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos]);
		ip_context_t *const ip_context = &(rfc5225_ctxt->ip_contexts[ip_hdr_pos]);

		ip_context->version = pkt_ip_hdr->version;
		ip_context->tos_tc = pkt_ip_hdr->tos_tc;
		ip_context->ttl_hopl = pkt_ip_hdr->ttl_hl;
		ip_context->next_header = pkt_ip_hdr->next_proto;

		if(pkt_ip_hdr->version == IPV4)
		{
			ip_context->last_ip_id = rohc_ntoh16(pkt_ip_hdr->ipv4->id);
			rohc_debug(comp, ROHC_TRACE_COMP, context->profile->id,
			           "IP-ID 0x%04x", ip_context->last_ip_id);
			ip_context->last_ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
			ip_context->ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
			ip_context->df = pkt_ip_hdr->ipv4->df;
			ip_context->saddr[0] = pkt_ip_hdr->ipv4->saddr;
			ip_context->daddr[0] = pkt_ip_hdr->ipv4->daddr;
		}
		else
		{
			/* IPv6 got no IP-ID, but for encoding the innermost IP-ID is
			 * considered bebaving randomly (see RFC5225 page 90):
			 * ENFORCE(ip_id_behavior_innermost.UVALUE == IP_ID_BEHAVIOR_RANDOM);
			 */
			ip_context->ip_id_behavior = ROHC_IP_ID_BEHAVIOR_RAND;
			ip_context->flow_label = ipv6_get_flow_label(pkt_ip_hdr->ipv6);
			memcpy(ip_context->saddr, &pkt_ip_hdr->ipv6->saddr, sizeof(struct ipv6_addr));
			memcpy(ip_context->daddr, &pkt_ip_hdr->ipv6->daddr, sizeof(struct ipv6_addr));

			/* TODO: handle IPv6 extension headers */
			assert(rohc_is_ipv6_opt(pkt_ip_hdr->ipv6->nh) == false);
		}
	}
	rfc5225_ctxt->ip_contexts_nr = uncomp_pkt_hdrs->ip_hdrs_nr;

	/* MSN */
	is_ok = wlsb_new(&rfc5225_ctxt->msn_wlsb, comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(comp, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for MSN");
		goto free_context;
	}

	/* innermost IP-ID offset */
	is_ok = wlsb_new(&rfc5225_ctxt->innermost_ip_id_offset_wlsb,
	                 comp->oa_repetitions_nr);
	if(!is_ok)
	{
		rohc_error(comp, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for IP-ID offset");
		goto free_wlsb_msn;
	}

	/* record the UDP source and destination ports in context */
	rfc5225_ctxt->udp_sport = rohc_ntoh16(uncomp_pkt_hdrs->udp->source);
	rfc5225_ctxt->udp_dport = rohc_ntoh16(uncomp_pkt_hdrs->udp->dest);

	/* record the RTP SSRC UDP in context */
	rfc5225_ctxt->rtp_ssrc = rohc_ntoh16(uncomp_pkt_hdrs->rtp->ssrc);
		
	/* init the Master Sequence Number with the RTP Sequence Number */
	rfc5225_ctxt->msn = rohc_ntoh16(uncomp_pkt_hdrs->rtp->sn);
	rohc_debug(comp, ROHC_TRACE_COMP, context->profile->id,
	           "MSN = 0x%04x / %u", rfc5225_ctxt->msn, rfc5225_ctxt->msn);

	return true;

free_wlsb_msn:
	wlsb_free(&rfc5225_ctxt->msn_wlsb);
free_context:
	free(rfc5225_ctxt);
error:
	return false;
}


/**
 * @brief Destroy the ROHCv2 IP/UDP/RTP context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The ROHCv2 IP/UDP/RTP compression context to destroy
 */
static void rohc_comp_rfc5225_ip_udp_rtp_destroy(struct rohc_comp_ctxt *const context)
{
	struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = context->specific;

	wlsb_free(&rfc5225_ctxt->innermost_ip_id_offset_wlsb);
	wlsb_free(&rfc5225_ctxt->msn_wlsb);
	free(rfc5225_ctxt);
}


/**
 * @brief Encode an uncompressed packet according to a pattern decided by
 *        several different factors
 *
 * 1. Decide state\n
 * 2. Decide which packet type to send.\n
 * 3. Code packet\n
 * 4. Update context\n
 * \n
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc5225_ip_udp_rtp_encode(struct rohc_comp_ctxt *const context,
                                               const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                               uint8_t *const rohc_pkt,
                                               const size_t rohc_pkt_max_len,
                                               rohc_packet_t *const packet_type)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = context->specific;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	size_t ip_hdr_pos;
	size_t rohc_len;
	int ret;

	*packet_type = ROHC_PACKET_UNKNOWN;

	/* STEP 0: detect changes between new uncompressed packet and context */
	rohc_comp_rfc5225_ip_udp_rtp_detect_changes(context, uncomp_pkt_hdrs);

	/* STEP 1: decide packet type */
	*packet_type = rohc_comp_rfc5225_ip_udp_rtp_decide_pkt(context);

	/* the outer_ip_flag may be set to 1 only for co_common */
	if(rfc5225_ctxt->tmp.outer_ip_flag && (*packet_type) != ROHC_PACKET_CO_COMMON)
	{
		rfc5225_ctxt->tmp.outer_ip_flag = false;
	}

	/* does the packet update the decompressor context? */
	if(rohc_packet_carry_crc_7_or_8(*packet_type))
	{
		rfc5225_ctxt->msn_of_last_ctxt_updating_pkt = rfc5225_ctxt->msn;
	}

	/* STEP 2: code packet */
	if((*packet_type) == ROHC_PACKET_IR)
	{
		ret = rohc_comp_rfc5225_ip_udp_rtp_code_IR_pkt(context, uncomp_pkt_hdrs,
		                                               rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to build IR packet");
			goto error;
		}
		rohc_len = ret;
	}
	else if((*packet_type) == ROHC_PACKET_CO_REPAIR)
	{
		ret = rohc_comp_rfc5225_ip_udp_rtp_code_co_repair_pkt(context, uncomp_pkt_hdrs,
		                                                      rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to build co_repair packet");
			goto error;
		}
		rohc_len = ret;
	}
	else /* other CO packets */
	{
		ret = rohc_comp_rfc5225_ip_udp_rtp_code_CO_pkt(context, uncomp_pkt_hdrs,
		                                               rohc_remain_data, rohc_remain_len,
		                                               *packet_type);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to build CO packet");
			goto error;
		}
		rohc_len = ret;
	}

	rohc_comp_dump_buf(context, "current ROHC packet", rohc_pkt, rohc_len);

	/* STEP 3: update context with new values (done at the very end to avoid
	 * wrongly updating the context in case of compression failure) */
	rohc_comp_debug(context, "update context:");
	/* add the new MSN to the W-LSB encoding object */
	c_add_wlsb(&rfc5225_ctxt->msn_wlsb, rfc5225_ctxt->msn, rfc5225_ctxt->msn);
	/* update context for all IP headers */
	for(ip_hdr_pos = 0; ip_hdr_pos < rfc5225_ctxt->ip_contexts_nr; ip_hdr_pos++)
	{
		ip_context_t *const ip_ctxt = &(rfc5225_ctxt->ip_contexts[ip_hdr_pos]);
		const struct rohc_pkt_ip_hdr *const ip_hdr =
			&(uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos]);

		ip_ctxt->tos_tc = ip_hdr->tos_tc;
		ip_ctxt->ttl_hopl = ip_hdr->ttl_hl;

		if(ip_hdr->version == IPV4)
		{
			ip_ctxt->last_ip_id_behavior = ip_ctxt->ip_id_behavior;
			ip_ctxt->last_ip_id = rohc_ntoh16(ip_hdr->ipv4->id);
			/* add the new IP-ID offset to the W-LSB encoding object */
			if((ip_hdr_pos + 1) == rfc5225_ctxt->ip_contexts_nr)
			{
				c_add_wlsb(&rfc5225_ctxt->innermost_ip_id_offset_wlsb, rfc5225_ctxt->msn,
				           rfc5225_ctxt->tmp.innermost_ip_id_offset);
				rfc5225_ctxt->innermost_ip_id_offset = rfc5225_ctxt->tmp.innermost_ip_id_offset;
			}
			ip_ctxt->df = ip_hdr->ipv4->df;
		}

		/* TODO: handle IPv6 extension headers */
	}
	/* update context for the UDP header */
	rfc5225_ctxt->udp_checksum_used = rfc5225_ctxt->tmp.new_udp_checksum_used;
	/* update transmission counters */
	if(rfc5225_ctxt->all_df_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->all_df_trans_nr++;
	}
	if(rfc5225_ctxt->innermost_df_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->innermost_df_trans_nr++;
	}
	if(rfc5225_ctxt->outer_df_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->outer_df_trans_nr++;
	}
	if(rfc5225_ctxt->all_ip_id_behavior_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->all_ip_id_behavior_trans_nr++;
	}
	if(rfc5225_ctxt->innermost_ip_id_behavior_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->innermost_ip_id_behavior_trans_nr++;
	}
	if(rfc5225_ctxt->innermost_ip_id_offset_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->innermost_ip_id_offset_trans_nr++;
	}
	if(rfc5225_ctxt->outer_ip_id_behavior_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->outer_ip_id_behavior_trans_nr++;
	}
	if(rfc5225_ctxt->innermost_ip_flag_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->innermost_ip_flag_trans_nr++;
	}
	if(rfc5225_ctxt->outer_ip_flag_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->outer_ip_flag_trans_nr++;
	}
	if(rfc5225_ctxt->innermost_tos_tc_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->innermost_tos_tc_trans_nr++;
	}
	if(rfc5225_ctxt->innermost_ttl_hopl_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->innermost_ttl_hopl_trans_nr++;
	}
	if(rfc5225_ctxt->udp_checksum_used_trans_nr < oa_repetitions_nr)
	{
		rfc5225_ctxt->udp_checksum_used_trans_nr++;
	}

	return rohc_len;

error:
	return -1;
}


/**
 * @brief Detect changes between packet and context
 *
 * @param context          The compression context to compare
 * @param uncomp_pkt_hdrs  The uncompressed headers to compare
 */
static void rohc_comp_rfc5225_ip_udp_rtp_detect_changes(struct rohc_comp_ctxt *const context,
                                                        const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = context->specific;
	ip_context_t *innermost_ip_ctxt = NULL;
	size_t ip_hdr_pos;

	/* detect changes in all the IP headers */
	rohc_comp_debug(context, "detect changes the IP packet");
	assert(rfc5225_ctxt->ip_contexts_nr > 0);
	rfc5225_ctxt->tmp.outer_df_changed = false;
	rfc5225_ctxt->tmp.outer_ip_id_behavior_changed = false;
	rfc5225_ctxt->tmp.outer_ip_flag = false;
	rfc5225_ctxt->tmp.innermost_df_changed = false;
	rfc5225_ctxt->tmp.innermost_ip_id_behavior_changed = false;
	rfc5225_ctxt->tmp.innermost_ip_id_offset_changed = false;
	rfc5225_ctxt->tmp.innermost_tos_tc_changed = false;
	rfc5225_ctxt->tmp.innermost_ttl_hopl_changed = false;
	rfc5225_ctxt->tmp.innermost_ip_flag = false;
	rfc5225_ctxt->tmp.at_least_one_df_changed = false;
	rfc5225_ctxt->tmp.at_least_one_ip_id_behavior_changed = false;
	for(ip_hdr_pos = 0; ip_hdr_pos < rfc5225_ctxt->ip_contexts_nr; ip_hdr_pos++)
	{
		ip_context_t *const ip_ctxt = &(rfc5225_ctxt->ip_contexts[ip_hdr_pos]);
		const bool is_innermost = !!(ip_hdr_pos == (rfc5225_ctxt->ip_contexts_nr - 1));
		const struct rohc_pkt_ip_hdr *const ip_hdr =
			&(uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos]);

		rohc_comp_debug(context, "  found %s IPv%d header",
		                is_innermost ? "innermost" : "outer", ip_hdr->version);

		/* TOS/HL or TTL/HL changed? */
		if(is_innermost)
		{
			/* innermost TOS/HL changed? */
			if(ip_ctxt->tos_tc != ip_hdr->tos_tc)
			{
				rohc_comp_debug(context, "    TOS/HL (0x%02x -> 0x%02x) changed",
				                ip_ctxt->tos_tc, ip_hdr->tos_tc);
				rfc5225_ctxt->tmp.innermost_tos_tc_changed = true;
				rfc5225_ctxt->tmp.innermost_ip_flag = true;
			}
			/* innermost TTL/HL changed? */
			if(ip_ctxt->ttl_hopl != ip_hdr->ttl_hl)
			{
				rohc_comp_debug(context, "    TTL/HL (%u -> %u) changed",
				                ip_ctxt->ttl_hopl, ip_hdr->ttl_hl);
				rfc5225_ctxt->tmp.innermost_ttl_hopl_changed = true;
				rfc5225_ctxt->tmp.innermost_ip_flag = true;
			}
			/* save the new values of innermost TOS/HL and TTL/HL to easily retrieve them
			 * during packet creation */
			rfc5225_ctxt->tmp.innermost_tos_tc = ip_hdr->tos_tc;
			rfc5225_ctxt->tmp.innermost_ttl_hopl = ip_hdr->ttl_hl;
		}
		else
		{
			if(ip_ctxt->tos_tc != ip_hdr->tos_tc ||
			   ip_ctxt->ttl_hopl != ip_hdr->ttl_hl)
			{
				rohc_comp_debug(context, "    TOS/HL (%02x -> %02x) or TTL/HL (%u -> %u) "
				                "changed", ip_ctxt->tos_tc, ip_hdr->tos_tc,
				                ip_ctxt->ttl_hopl, ip_hdr->ttl_hl);
				rfc5225_ctxt->tmp.outer_ip_flag = true;
			}
		}

		if(ip_hdr->version == IPV4)
		{
			/* detect changes in the IPv4 header */
			rohc_comp_rfc5225_ip_udp_rtp_detect_changes_ipv4(context, ip_ctxt,
			                                                 ip_hdr->ipv4, is_innermost);
		}
		else /* IPv6 */
		{
			/* save the new value of the innermost DF to easily retrieve them during
			 * packet creation */
			if(is_innermost)
			{
				rfc5225_ctxt->tmp.innermost_df = 0; /* no DF, dont_fragment() uses 0 */
			}

			/* TODO: handle IPv6 extension headers */
		}

		/* remember the innermost IP header */
		innermost_ip_ctxt = ip_ctxt;
	}

	/* detect changes in UDP header */
	rfc5225_ctxt->tmp.new_udp_checksum_used = !!(uncomp_pkt_hdrs->udp->check != 0);
	if(rfc5225_ctxt->tmp.new_udp_checksum_used != rfc5225_ctxt->udp_checksum_used)
	{
		rohc_comp_debug(context, "UDP checksum used changed (%d -> %d)",
		                rfc5225_ctxt->udp_checksum_used,
		                rfc5225_ctxt->tmp.new_udp_checksum_used);
		rfc5225_ctxt->tmp.udp_checksum_used_changed = true;
	}
	else
	{
		rfc5225_ctxt->tmp.udp_checksum_used_changed = false;
	}

	/* detect changes in RTP header */
	{
		const uint16_t old_msn = rfc5225_ctxt->msn;

		/* compute or find the new SN */
		rfc5225_ctxt->msn = rohc_ntoh16(uncomp_pkt_hdrs->rtp->sn);
		rohc_comp_debug(context, "MSN = 0x%04x / %u", rfc5225_ctxt->msn, rfc5225_ctxt->msn);
		/* compute the MSN offset */
		rfc5225_ctxt->tmp.msn_offset = rfc5225_ctxt->msn - old_msn;
		rohc_comp_debug(context, "MSN offset = %d (%u -> %u)",
		                rfc5225_ctxt->tmp.msn_offset, old_msn, rfc5225_ctxt->msn);
	}

	/* now that the MSN was updated with the new received IP/UDP/RTP packet,
	 * compute the new IP-ID / MSN offset for the innermost IP header */
	if(innermost_ip_ctxt->version == IPV4)
	{
		const uint16_t ip_id = rfc5225_ctxt->tmp.innermost_ip_id;
		const uint16_t last_ip_id = innermost_ip_ctxt->last_ip_id;
		const rohc_ip_id_behavior_t last_ip_id_behavior =
			innermost_ip_ctxt->ip_id_behavior;
		rohc_ip_id_behavior_t ip_id_behavior;

		rohc_comp_debug(context, "IP-ID behaved as %s",
		                rohc_ip_id_behavior_get_descr(last_ip_id_behavior));
		rohc_comp_debug(context, "IP-ID = 0x%04x -> 0x%04x", last_ip_id, ip_id);

		if(context->num_sent_packets == 0)
		{
			/* first packet, be optimistic: choose sequential behavior */
			ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
		}
		else
		{
			ip_id_behavior =
				rohc_comp_detect_ip_id_behavior(last_ip_id, ip_id,
				                                rfc5225_ctxt->tmp.msn_offset, 19);
		}
		/* TODO: avoid changing context here */
		innermost_ip_ctxt->ip_id_behavior = ip_id_behavior;
		rohc_comp_debug(context, "IP-ID now behaves as %s",
		                rohc_ip_id_behavior_get_descr(ip_id_behavior));
		if(last_ip_id_behavior != ip_id_behavior)
		{
			rfc5225_ctxt->tmp.at_least_one_ip_id_behavior_changed = true;
			rfc5225_ctxt->tmp.innermost_ip_id_behavior_changed = true;
		}

		if(innermost_ip_ctxt->ip_id_behavior == ROHC_IP_ID_BEHAVIOR_SEQ_SWAP)
		{
			/* specific case of IP-ID delta for sequential swapped behavior */
			rfc5225_ctxt->tmp.innermost_ip_id_offset =
				swab16(rfc5225_ctxt->tmp.innermost_ip_id) - rfc5225_ctxt->msn;
		}
		else
		{
			/* compute delta the same way for sequential, zero or random: it is
			 * important to always compute the IP-ID delta and record it in W-LSB,
			 * so that the IP-ID deltas of next packets may be correctly encoded */
			rfc5225_ctxt->tmp.innermost_ip_id_offset =
				rfc5225_ctxt->tmp.innermost_ip_id - rfc5225_ctxt->msn;
		}
		rohc_comp_debug(context, "new IP-ID offset = 0x%x / %u",
		                rfc5225_ctxt->tmp.innermost_ip_id_offset,
		                rfc5225_ctxt->tmp.innermost_ip_id_offset);

		rfc5225_ctxt->tmp.innermost_ip_id_offset_changed =
			!!(rfc5225_ctxt->innermost_ip_id_offset != rfc5225_ctxt->tmp.innermost_ip_id_offset);
	}

	/* any DF that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.at_least_one_df_changed)
	{
		rohc_comp_debug(context, "at least one DF changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->all_df_trans_nr = 0;
	}
	else if(rfc5225_ctxt->all_df_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "at least one DF changed in last packets, "
		                "it shall be transmitted %u times more",
		                oa_repetitions_nr - rfc5225_ctxt->all_df_trans_nr);
		rfc5225_ctxt->tmp.at_least_one_df_changed = true;
	}
	/* the innermost DF that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.innermost_df_changed)
	{
		rohc_comp_debug(context, "innermost DF changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->innermost_df_trans_nr = 0;
	}
	else if(rfc5225_ctxt->innermost_df_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "innermost DF changed in last packets, "
		                "it shall be transmitted %u times more",
		                oa_repetitions_nr - rfc5225_ctxt->innermost_df_trans_nr);
		rfc5225_ctxt->tmp.innermost_df_changed = true;
	}
	/* any outer DF that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.outer_df_changed)
	{
		rohc_comp_debug(context, "at least one outer DF changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->outer_df_trans_nr = 0;
	}
	else if(rfc5225_ctxt->outer_df_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "at least one outer DF changed in last packets, "
		                "it shall be transmitted %u times more",
		                oa_repetitions_nr - rfc5225_ctxt->outer_df_trans_nr);
		rfc5225_ctxt->tmp.outer_df_changed = true;
	}

	/* any IP-ID behavior that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.at_least_one_ip_id_behavior_changed)
	{
		rohc_comp_debug(context, "at least one IP-ID behavior changed in current "
		                "packet, it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->all_ip_id_behavior_trans_nr = 0;
	}
	else if(rfc5225_ctxt->all_ip_id_behavior_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "at least one IP-ID behavior changed in last "
		                "packets, it shall be transmitted %u times more",
		                oa_repetitions_nr - rfc5225_ctxt->all_ip_id_behavior_trans_nr);
		rfc5225_ctxt->tmp.at_least_one_ip_id_behavior_changed = true;
	}
	/* innermost IP-ID behavior that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.innermost_ip_id_behavior_changed)
	{
		rohc_comp_debug(context, "innermost IP-ID behavior changed in current "
		                "packet, it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->innermost_ip_id_behavior_trans_nr = 0;
	}
	else if(rfc5225_ctxt->innermost_ip_id_behavior_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "innermost IP-ID behavior changed in last packets, "
		                "it shall be transmitted %u times more", oa_repetitions_nr -
		                rfc5225_ctxt->innermost_ip_id_behavior_trans_nr);
		rfc5225_ctxt->tmp.innermost_ip_id_behavior_changed = true;
	}
	/* innermost IP-ID offset that changes shall be transmitted several times
	 * before being inferred */
	if(rfc5225_ctxt->tmp.innermost_ip_id_offset_changed)
	{
		rohc_comp_debug(context, "innermost IP-ID offset changed in current "
		                "packet, it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->innermost_ip_id_offset_trans_nr = 0;
	}
	else if(rfc5225_ctxt->innermost_ip_id_offset_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "innermost IP-ID offset changed in last packets, "
		                "it shall be transmitted %u times more", oa_repetitions_nr -
		                rfc5225_ctxt->innermost_ip_id_offset_trans_nr);
		rfc5225_ctxt->tmp.innermost_ip_id_offset_changed = true;
	}
	/* any outer IP-ID behavior that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.outer_ip_id_behavior_changed)
	{
		rohc_comp_debug(context, "at least one outer IP-ID behavior changed in "
		                "current packet, it shall be transmitted %u times",
		                oa_repetitions_nr);
		rfc5225_ctxt->outer_ip_id_behavior_trans_nr = 0;
	}
	else if(rfc5225_ctxt->outer_ip_id_behavior_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "at least one outer IP-ID behavior changed in "
		                "last packets, it shall be transmitted %u times more",
		                oa_repetitions_nr - rfc5225_ctxt->outer_ip_id_behavior_trans_nr);
		rfc5225_ctxt->tmp.outer_ip_id_behavior_changed = true;
	}

	/* innermost IP flag that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.innermost_ip_flag)
	{
		rohc_comp_debug(context, "innermost IP flag changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->innermost_ip_flag_trans_nr = 0;
	}
	else if(rfc5225_ctxt->innermost_ip_flag_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "innermost IP flag changed in last packets, "
		                "it shall be transmitted %u times more",
		                oa_repetitions_nr - rfc5225_ctxt->innermost_ip_flag_trans_nr);
		rfc5225_ctxt->tmp.innermost_ip_flag = true;
	}
	/* any outer IP-ID behavior that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.outer_ip_flag)
	{
		rohc_comp_debug(context, "at least one outer IP flag changed in current "
		                "packet, it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->outer_ip_flag_trans_nr = 0;
	}
	else if(rfc5225_ctxt->outer_ip_flag_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "at least one outer IP flag changed in last "
		                "packets, it shall be transmitted %u times more",
		                oa_repetitions_nr - rfc5225_ctxt->outer_ip_flag_trans_nr);
		rfc5225_ctxt->tmp.outer_ip_flag = true;
	}

	/* innermost TOS/TC that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.innermost_tos_tc_changed)
	{
		rohc_comp_debug(context, "innermost TOS/TC changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->innermost_tos_tc_trans_nr = 0;
	}
	else if(rfc5225_ctxt->innermost_tos_tc_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "innermost TOS/TC changed in last packets, "
		                "it shall be transmitted %u times more",
		                oa_repetitions_nr - rfc5225_ctxt->innermost_tos_tc_trans_nr);
		rfc5225_ctxt->tmp.innermost_tos_tc_changed = true;
	}

	/* innermost TTL/HL that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.innermost_ttl_hopl_changed)
	{
		rohc_comp_debug(context, "innermost TTL/HL changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->innermost_ttl_hopl_trans_nr = 0;
	}
	else if(rfc5225_ctxt->innermost_ttl_hopl_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "innermost TTL/HL changed in last packets, "
		                "it shall be transmitted %u times more",
		                oa_repetitions_nr - rfc5225_ctxt->innermost_ttl_hopl_trans_nr);
		rfc5225_ctxt->tmp.innermost_ttl_hopl_changed = true;
	}

	/* 'UDP checksum used' that changes shall be transmitted several times */
	if(rfc5225_ctxt->tmp.udp_checksum_used_changed)
	{
		rohc_comp_debug(context, "'UDP checksum used' changed in current packet, "
		                "it shall be transmitted %u times", oa_repetitions_nr);
		rfc5225_ctxt->udp_checksum_used_trans_nr = 0;
	}
	else if(rfc5225_ctxt->udp_checksum_used_trans_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "'UDP checksum used' changed in last packets, "
		                "it shall be transmitted %u times more",
		                oa_repetitions_nr - rfc5225_ctxt->udp_checksum_used_trans_nr);
		rfc5225_ctxt->tmp.udp_checksum_used_changed = true;
	}
}


/**
 * @brief Detect changes for the given IPv4 header between packet and context
 *
 * @param ctxt          The compression context
 * @param ip_ctxt       The IPv4 context to compare
 * @param ipv4          The IPv4 header to compare
 * @param is_innermost  Whether the IPv4 header is the innermost of all IP headers
 */
static void rohc_comp_rfc5225_ip_udp_rtp_detect_changes_ipv4(struct rohc_comp_ctxt *const ctxt,
                                                             ip_context_t *const ip_ctxt,
                                                             const struct ipv4_hdr *const ipv4,
                                                             const bool is_innermost)
{
	/* TODO: parameter ip_ctxt should be const */
	struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = ctxt->specific;

	/* IPv4 DF changed? */
	if(ip_ctxt->df != ipv4->df)
	{
		rohc_comp_debug(ctxt, "    DF (%u -> %u) changed", ip_ctxt->df, ipv4->df);
		rfc5225_ctxt->tmp.at_least_one_df_changed = true;
		if(is_innermost)
		{
			rfc5225_ctxt->tmp.innermost_df_changed = true;
		}
		else
		{
			rfc5225_ctxt->tmp.outer_df_changed = true;
		}
	}
	/* save the new value of the innermost DF to easily retrieve them during
	 * packet creation */
	if(is_innermost)
	{
		rfc5225_ctxt->tmp.innermost_df = ipv4->df;
	}

	/* determine the IP-ID behavior of the IPv4 header */
	if(!is_innermost)
	{
		const uint16_t ip_id = rohc_ntoh16(ipv4->id);
		const uint16_t last_ip_id = ip_ctxt->last_ip_id;
		const rohc_ip_id_behavior_t last_ip_id_behavior = ip_ctxt->ip_id_behavior;
		rohc_ip_id_behavior_t ip_id_behavior;

		rohc_comp_debug(ctxt, "IP-ID behaved as %s",
		                rohc_ip_id_behavior_get_descr(last_ip_id_behavior));
		rohc_comp_debug(ctxt, "IP-ID = 0x%04x -> 0x%04x", last_ip_id, ip_id);

		/* RFC5225 §6.3.3 reads:
		 *   ROHCv2 profiles MUST NOT assign a sequential behavior (network byte
		 *   order or byte-swapped) to any IP-ID but the one in the innermost IP
		 *   header when compressing more than one level of IP headers.  This is
		 *   because only the IP-ID of the innermost IP header is likely to have a
		 *   sufficiently close correlation with the MSN to compress it as a
		 *   sequentially changing field.  Therefore, a compressor MUST assign
		 *   either the constant zero IP-ID or the random IP-ID behavior to
		 *   tunneling headers.
		 */
		if(ip_id == 0)
		{
			ip_id_behavior = ROHC_IP_ID_BEHAVIOR_ZERO;
		}
		else
		{
			ip_id_behavior = ROHC_IP_ID_BEHAVIOR_RAND;
		}
		/* TODO: avoid changing context here */
		ip_ctxt->ip_id_behavior = ip_id_behavior;
		rohc_comp_debug(ctxt, "IP-ID now behaves as %s",
		                rohc_ip_id_behavior_get_descr(ip_id_behavior));
		if(last_ip_id_behavior != ip_id_behavior)
		{
			rfc5225_ctxt->tmp.at_least_one_ip_id_behavior_changed = true;
			rfc5225_ctxt->tmp.outer_ip_id_behavior_changed = true;
		}
	}
	else
	{
		rfc5225_ctxt->tmp.innermost_ip_id = rohc_ntoh16(ipv4->id);
	}
}


/**
 * @brief Update the profile when feedback is received
 *
 * This function is one of the functions that must exist in one profile for
 * the framework to work.
 *
 * @param ctxt               The compression context
 * @param feedback_type      The feedback type among ROHC_FEEDBACK_1 and ROHC_FEEDBACK_2
 * @param packet             The whole feedback packet with CID bits
 * @param packet_len         The length of the whole feedback packet with CID bits
 * @param feedback_data      The feedback data without the CID bits
 * @param feedback_data_len  The length of the feedback data without the CID bits
 * @return                   true if the feedback was successfully handled,
 *                           false if the feedback could not be taken into account
 */
static bool rohc_comp_rfc5225_ip_udp_rtp_feedback(struct rohc_comp_ctxt *const ctxt,
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

		rohc_comp_debug(ctxt, "FEEDBACK-1 received");
		assert(remain_len == 1);

		/* get the 8 LSB bits of the acknowledged SN */
		sn_bits = remain_data[0] & 0xff;
		sn_bits_nr = 8;

		rohc_comp_debug(ctxt, "ACK received (CID = %u, %zu-bit SN = 0x%02x)",
		                ctxt->cid, sn_bits_nr, sn_bits);

		/* the compressor received a positive ACK */
		rohc_comp_rfc5225_ip_udp_rtp_feedback_ack(ctxt, sn_bits, sn_bits_nr, sn_not_valid);
	}
	else if(feedback_type == ROHC_FEEDBACK_2)
	{
		rohc_comp_debug(ctxt, "FEEDBACK-2 received");

		if(!rohc_comp_rfc5225_ip_udp_rtp_feedback_2(ctxt, packet, packet_len,
		                                        feedback_data, feedback_data_len))
		{
			rohc_comp_warn(ctxt, "failed to handle FEEDBACK-2");
			goto error;
		}
	}
	else /* not FEEDBACK-1 nor FEEDBACK-2 */
	{
		rohc_comp_warn(ctxt, "feedback type not implemented (%d)", feedback_type);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Update the profile when FEEDBACK-2 is received
 *
 * @param ctxt               The compression context
 * @param packet             The whole feedback packet with CID bits
 * @param packet_len         The length of the whole feedback packet with CID bits
 * @param feedback_data      The feedback data without the CID bits
 * @param feedback_data_len  The length of the feedback data without the CID bits
 * @return                   true if the feedback was successfully handled,
 *                           false if the feedback could not be taken into account
 */
static bool rohc_comp_rfc5225_ip_udp_rtp_feedback_2(struct rohc_comp_ctxt *const ctxt,
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

	/* retrieve acked MSN */
	if(remain_len < sizeof(struct rohc_feedback_2_rfc6846))
	{
		rohc_comp_warn(ctxt, "malformed FEEDBACK-2: packet too short for the "
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
	if(!rohc_comp_feedback_parse_opts(ctxt, packet, packet_len,
	                                  remain_data, remain_len,
	                                  opts_present, &sn_bits, &sn_bits_nr,
	                                  ROHC_FEEDBACK_WITH_CRC_BASE,
	                                  crc_in_packet, crc_pos_from_end))
	{
		rohc_comp_warn(ctxt, "malformed FEEDBACK-2: failed to parse options");
		goto error;
	}

	/* change from U- to O-mode once feedback channel is established */
	rohc_comp_change_mode(ctxt, ROHC_O_MODE);

	/* act according to the type of feedback */
	switch(feedback2->ack_type)
	{
		case ROHC_FEEDBACK_ACK:
		{
			const bool sn_not_valid =
				!!(opts_present[ROHC_FEEDBACK_OPT_ACKNUMBER_NOT_VALID] > 0);

			rohc_comp_debug(ctxt, "ACK received (CID = %u, %zu-bit SN = 0x%x, "
			                "ACKNUMBER-NOT-VALID = %d)", ctxt->cid, sn_bits_nr,
			                sn_bits, GET_REAL(sn_not_valid));

			/* the compressor received a positive ACK */
			rohc_comp_rfc5225_ip_udp_rtp_feedback_ack(ctxt, sn_bits, sn_bits_nr,
			                                      sn_not_valid);
			break;
		}
		case ROHC_FEEDBACK_NACK:
		{
			/* RFC5225 §5.2.1: NACKs, downward transition */
			rohc_info(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
			          "NACK received for CID %u", ctxt->cid);
			/* the compressor transits back to the FO state */
			if(ctxt->state == ROHC_COMP_STATE_SO)
			{
				rohc_comp_change_state(ctxt, ROHC_COMP_STATE_FO);
			}
			/* TODO: use the SN field to determine the latest packet successfully
			 * decompressed and then determine what fields need to be updated */
			break;
		}
		case ROHC_FEEDBACK_STATIC_NACK:
		{
			/* RFC5225 §5.2.1: STATIC-NACKs, downward transition */
			rohc_info(ctxt->compressor, ROHC_TRACE_COMP, ctxt->profile->id,
			          "STATIC-NACK received for CID %u", ctxt->cid);
			/* the compressor transits back to the IR state */
			rohc_comp_change_state(ctxt, ROHC_COMP_STATE_IR);
			/* TODO: use the SN field to determine the latest packet successfully
			 * decompressed and then determine what fields need to be updated */
			break;
		}
		case ROHC_FEEDBACK_RESERVED:
		{
			/* RFC5225 §6.9.1: reserved (MUST NOT be used for parseability) */
			rohc_comp_warn(ctxt, "malformed FEEDBACK-2: reserved ACK type used");
			goto error;
		}
		default:
		{
			/* impossible value */
			rohc_comp_warn(ctxt, "malformed FEEDBACK-2: unknown ACK type %u",
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
 * @param ctxt          The compression context that received a positive ACK
 * @param sn_bits       The LSB bits of the acknowledged SN
 * @param sn_bits_nr    The number of LSB bits of the acknowledged SN
 * @param sn_not_valid  Whether the received SN may be considered as valid or not
 */
static void rohc_comp_rfc5225_ip_udp_rtp_feedback_ack(struct rohc_comp_ctxt *const ctxt,
                                                  const uint32_t sn_bits,
                                                  const size_t sn_bits_nr,
                                                  const bool sn_not_valid)
{
	struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = ctxt->specific;

	/* the W-LSB encoding scheme as defined by function lsb() in RFC4997 uses a
	 * sliding window with a large limited maximum width ; once the feedback channel
	 * is established, positive ACKs may remove older values from the windows */
	if(!sn_not_valid)
	{
		size_t acked_nr;

		assert(sn_bits_nr <= 16);
		assert(sn_bits <= 0xffffU);

		/* ack innermost IP-ID */
		acked_nr = wlsb_ack(&rfc5225_ctxt->innermost_ip_id_offset_wlsb,
		                    sn_bits, sn_bits_nr);
		rohc_comp_debug(ctxt, "FEEDBACK-2: positive ACK removed %zu values "
		                "from innermost IP-ID W-LSB", acked_nr);
		/* ack MSN */
		acked_nr = wlsb_ack(&rfc5225_ctxt->msn_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(ctxt, "FEEDBACK-2: positive ACK removed %zu values "
		                "from MSN W-LSB", acked_nr);
	}

	/* RFC 6846, §5.2.2.1:
	 *   The compressor MAY use acknowledgment feedback (ACKs) to move to a
	 *   higher compression state.
	 *   Upon reception of an ACK for a context-updating packet, the
	 *   compressor obtains confidence that the decompressor has received the
	 *   acknowledged packet and that it has observed changes in the packet
	 *   flow up to the acknowledged packet. */
	if(ctxt->state != ROHC_COMP_STATE_SO && !sn_not_valid)
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

		if(!wlsb_is_sn_present(&rfc5225_ctxt->msn_wlsb,
		                       rfc5225_ctxt->msn_of_last_ctxt_updating_pkt) ||
		   sn_bits == (rfc5225_ctxt->msn_of_last_ctxt_updating_pkt & sn_mask))
		{
			/* decompressor acknowledged some SN, so some SNs were removed from the
			 * W-LSB windows; the SN of the last context-updating packet was part of
			 * the SNs that were acknowledged, so the compressor is 100% sure that
			 * the decompressor received the packet and updated its context in
			 * consequence, so the compressor may transit to a higher compression
			 * state immediately! */
			rohc_comp_debug(ctxt, "FEEDBACK-2: positive ACK makes the compressor "
			                "transit to the SO state more quickly (context-updating "
			                "packet with SN %u was acknowledged by decompressor)",
			                rfc5225_ctxt->msn_of_last_ctxt_updating_pkt);
			rohc_comp_change_state(ctxt, ROHC_COMP_STATE_SO);
		}
		else
		{
			rohc_comp_debug(ctxt, "FEEDBACK-2: positive ACK DOES NOT make the "
			                "compressor transit to the SO state more quickly "
			                "(context-updating packet with SN %u was NOT acknowledged "
			                "YET by decompressor)",
			                rfc5225_ctxt->msn_of_last_ctxt_updating_pkt);
		}
	}
}


/**
 * @brief Decide which packet to send when in the different states
 *
 * @param context           The compression context
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_PT_0_CRC3,
 *                              ROHC_PACKET_NORTP_PT_0_CRC7,
 *                              ROHC_PACKET_NORTP_PT_1_SEQ_ID, or
 *                              ROHC_PACKET_NORTP_PT_2_SEQ_ID
 *                              in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t rohc_comp_rfc5225_ip_udp_rtp_decide_pkt(const struct rohc_comp_ctxt *const context)
{
	rohc_packet_t packet_type;

#ifndef __clang_analyzer__ /* TODO: silent warning since packet_type forced to IR */
	switch(context->state)
	{
		case ROHC_COMP_STATE_IR: /* The Initialization and Refresh (IR) state */
			rohc_comp_debug(context, "code IR packet");
			packet_type = ROHC_PACKET_IR;
			break;
		case ROHC_COMP_STATE_FO:
			packet_type = rohc_comp_rfc5225_ip_udp_rtp_decide_FO_pkt(context);
			break;
		case ROHC_COMP_STATE_SO:
			packet_type = rohc_comp_rfc5225_ip_udp_rtp_decide_SO_pkt(context);
			break;
		case ROHC_COMP_STATE_UNKNOWN:
		default:
#if defined(NDEBUG) || defined(__KERNEL__) || defined(ENABLE_DEAD_CODE)
			packet_type = ROHC_PACKET_UNKNOWN;
#endif
			assert(0); /* should not happen */
			break;
	}
#endif

	/* TODO: handle non-IR packets */
	rohc_comp_debug(context, "force IR packet");
	packet_type = ROHC_PACKET_IR;

	return packet_type;
}


/**
 * @brief Decide which packet to send when in FO state
 *
 * @param ctxt  The compression context
 * @return      \li The packet type among ROHC_PACKET_IR,
 *                  ROHC_PACKET_CO_REPAIR,
 *                  ROHC_PACKET_CO_COMMON,
 *                  ROHC_PACKET_NORTP_PT_0_CRC7, or
 *                  ROHC_PACKET_NORTP_PT_2_SEQ_ID
 *                  in case of success
 *              \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t rohc_comp_rfc5225_ip_udp_rtp_decide_FO_pkt(const struct rohc_comp_ctxt *const ctxt)
{
	const bool crc7_at_least = true;
	const rohc_packet_t packet_type =
		rohc_comp_rfc5225_ip_udp_rtp_decide_FO_SO_pkt(ctxt, crc7_at_least);

	assert(packet_type != ROHC_PACKET_PT_0_CRC3);
	assert(packet_type != ROHC_PACKET_NORTP_PT_1_SEQ_ID);

	return packet_type;
}


/**
 * @brief Decide which packet to send when in SO state
 *
 * @param ctxt  The compression context
 * @return      \li The packet type among ROHC_PACKET_IR,
 *                  ROHC_PACKET_CO_REPAIR,
 *                  ROHC_PACKET_CO_COMMON,
 *                  ROHC_PACKET_PT_0_CRC3,
 *                  ROHC_PACKET_NORTP_PT_0_CRC7,
 *                  ROHC_PACKET_NORTP_PT_1_SEQ_ID, or
 *                  ROHC_PACKET_NORTP_PT_2_SEQ_ID
 *                  in case of success
 *              \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t rohc_comp_rfc5225_ip_udp_rtp_decide_SO_pkt(const struct rohc_comp_ctxt *const ctxt)
{
	const bool crc7_at_least = false;
	return rohc_comp_rfc5225_ip_udp_rtp_decide_FO_SO_pkt(ctxt, crc7_at_least);
}


/**
 * @brief Decide which packet to send when in FO or SO state
 *
 * @param ctxt           The compression context
 * @param crc7_at_least  Whether packet types with CRC strictly smaller
 *                       than 7 bits are allowed or not
 * @return               \li The packet type among ROHC_PACKET_IR,
 *                           ROHC_PACKET_CO_REPAIR,
 *                           ROHC_PACKET_CO_COMMON,
 *                           ROHC_PACKET_PT_0_CRC3,
 *                           ROHC_PACKET_NORTP_PT_0_CRC7,
 *                           ROHC_PACKET_NORTP_PT_1_SEQ_ID, or
 *                           ROHC_PACKET_NORTP_PT_2_SEQ_ID
 *                           in case of success
 *                       \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t rohc_comp_rfc5225_ip_udp_rtp_decide_FO_SO_pkt(const struct rohc_comp_ctxt *const ctxt,
                                                               const bool crc7_at_least)
{
	struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = ctxt->specific;
	const int16_t msn_offset = rfc5225_ctxt->tmp.msn_offset;
	const uint8_t oa_repetitions_nr = ctxt->compressor->oa_repetitions_nr;
	const rohc_reordering_offset_t reorder_ratio = ctxt->compressor->reorder_ratio;
	const ip_context_t *const innermost_ip_ctxt =
		&(rfc5225_ctxt->ip_contexts[rfc5225_ctxt->ip_contexts_nr - 1]);
	const uint16_t innermost_ip_id = rfc5225_ctxt->tmp.innermost_ip_id;
	const uint8_t innermost_ip_id_offset_trans_nr =
		rfc5225_ctxt->innermost_ip_id_offset_trans_nr;
	const rohc_ip_id_behavior_t innermost_ip_id_behavior =
		innermost_ip_ctxt->ip_id_behavior;
	rohc_packet_t packet_type;

	/* use co_repair if 'UDP checksum used' changed */
	if(rfc5225_ctxt->tmp.udp_checksum_used_changed)
	{
		rohc_comp_debug(ctxt, "code co_repair packet because 'UDP checksum used' "
		                "changed");
		packet_type = ROHC_PACKET_CO_REPAIR;
	}
	/* use pt_0_crc3 only if:
	 *  - CRC-3 is enough to protect the compression
	 *  - 4 MSN bits are enough
	 *  - the innermost IP-ID is either:
	 *     - random (transmitted in irregular chain),
	 *     - zero (not transmitted at all),
	 *     - sequential and inferred from MSN (and not transmitted at all).
	 *  - the TOS/TC fields of all IP headers shall not be changing
	 *  - the behavior of the innermost IP-ID shall not be changing
	 */
	else if(!crc7_at_least &&
	        rohc_comp_rfc5225_is_msn_lsb_possible(&rfc5225_ctxt->msn_wlsb,
	                                              rfc5225_ctxt->msn, reorder_ratio, 4) &&
	        (!rohc_comp_rfc5225_is_ipid_sequential(innermost_ip_id_behavior) ||
	         rohc_comp_rfc5225_is_seq_ipid_inferred(innermost_ip_ctxt,
	                                                innermost_ip_id_offset_trans_nr,
	                                                oa_repetitions_nr,
	                                                innermost_ip_id, msn_offset)) &&
	        !rfc5225_ctxt->tmp.outer_ip_flag &&
	        !rfc5225_ctxt->tmp.innermost_ip_flag &&
	        !rfc5225_ctxt->tmp.at_least_one_df_changed &&
	        !rfc5225_ctxt->tmp.at_least_one_ip_id_behavior_changed)
	{
		rohc_comp_debug(ctxt, "code pt_0_crc3 packet");
		packet_type = ROHC_PACKET_PT_0_CRC3;
	}
	/* use pt_0_crc7 only if:
	 *  - 6 MSN bits are enough
	 *  - the innermost IP-ID is either:
	 *     - random (transmitted in irregular chain),
	 *     - zero (not transmitted at all),
	 *     - sequential and inferred from MSN (and not transmitted at all).
	 *  - the TOS/TC fields of all IP headers shall not be changing
	 *  - the behavior of the innermost IP-ID shall not be changing
	 */
	else if(rohc_comp_rfc5225_is_msn_lsb_possible(&rfc5225_ctxt->msn_wlsb,
	                                              rfc5225_ctxt->msn,
	                                              reorder_ratio, 6) &&
	        (!rohc_comp_rfc5225_is_ipid_sequential(innermost_ip_id_behavior) ||
	         rohc_comp_rfc5225_is_seq_ipid_inferred(innermost_ip_ctxt,
	                                                innermost_ip_id_offset_trans_nr,
	                                                oa_repetitions_nr,
	                                                innermost_ip_id, msn_offset)) &&
	        !rfc5225_ctxt->tmp.outer_ip_flag &&
	        !rfc5225_ctxt->tmp.innermost_ip_flag &&
	        !rfc5225_ctxt->tmp.at_least_one_df_changed &&
	        !rfc5225_ctxt->tmp.at_least_one_ip_id_behavior_changed)
	{
		rohc_comp_debug(ctxt, "code pt_0_crc7 packet");
		packet_type = ROHC_PACKET_NORTP_PT_0_CRC7;
	}
	/* use pt_1_seq_id only if:
	 *  - CRC-3 is enough to protect the compression
	 *  - 6 MSN bits are enough
	 *  - innermost IP-ID is sequential (swapped or not)
	 *  - 4 innermost IP-ID / SN offset bits are enough
	 *  - the TOS/TC fields of all IP headers shall not be changing
	 *  - the behavior of the innermost IP-ID shall not be changing
	 */
	else if(!crc7_at_least &&
	        rohc_comp_rfc5225_is_msn_lsb_possible(&rfc5225_ctxt->msn_wlsb,
	                                              rfc5225_ctxt->msn,
	                                              reorder_ratio, 6) &&
	        rohc_comp_rfc5225_is_ipid_sequential(innermost_ip_id_behavior) &&
	        wlsb_is_kp_possible_16bits(&rfc5225_ctxt->innermost_ip_id_offset_wlsb,
	                                   rfc5225_ctxt->tmp.innermost_ip_id_offset, 4,
	                                   rohc_interval_get_rfc5225_id_id_p(4)) &&
	        !rfc5225_ctxt->tmp.outer_ip_flag &&
	        !rfc5225_ctxt->tmp.innermost_ip_flag &&
	        !rfc5225_ctxt->tmp.at_least_one_df_changed &&
	        !rfc5225_ctxt->tmp.at_least_one_ip_id_behavior_changed)
	{
		assert(innermost_ip_ctxt->version == IPV4);
		rohc_comp_debug(ctxt, "code pt_1_seq_id packet");
		packet_type = ROHC_PACKET_NORTP_PT_1_SEQ_ID;
	}
	/* use pt_2_seq_id only if:
	 *  - innermost IP-ID is sequential (swapped or not)
	 *  - 6 innermost IP-ID / SN offset bits are enough
	 *  - 8 MSN bits are enough
	 *  - the TOS/TC fields of all IP headers shall not be changing
	 *  - the behavior of the innermost IP-ID shall not be changing
	 */
	else if(rohc_comp_rfc5225_is_ipid_sequential(innermost_ip_id_behavior) &&
	        wlsb_is_kp_possible_16bits(&rfc5225_ctxt->innermost_ip_id_offset_wlsb,
	                                   rfc5225_ctxt->tmp.innermost_ip_id_offset, 6,
	                                   rohc_interval_get_rfc5225_id_id_p(6)) &&
	        rohc_comp_rfc5225_is_msn_lsb_possible(&rfc5225_ctxt->msn_wlsb,
	                                              rfc5225_ctxt->msn,
	                                              reorder_ratio, 8) &&
	        !rfc5225_ctxt->tmp.outer_ip_flag &&
	        !rfc5225_ctxt->tmp.innermost_ip_flag &&
	        !rfc5225_ctxt->tmp.at_least_one_df_changed &&
	        !rfc5225_ctxt->tmp.at_least_one_ip_id_behavior_changed)
	{
		rohc_comp_debug(ctxt, "code pt_2_seq_id packet");
		packet_type = ROHC_PACKET_NORTP_PT_2_SEQ_ID;
	}
	/* use co_common only if:
	 *  - 8 MSN bits are enough
	 *  - the DF fields of all outer IP headers shall not be changing
	 *  - the behavior of the outer IP-IDs shall not be changing
	 */
	else if(rohc_comp_rfc5225_is_msn_lsb_possible(&rfc5225_ctxt->msn_wlsb,
	                                              rfc5225_ctxt->msn,
	                                              reorder_ratio, 8) &&
	        !rfc5225_ctxt->tmp.outer_df_changed &&
	        !rfc5225_ctxt->tmp.outer_ip_id_behavior_changed)
	{
		rohc_comp_debug(ctxt, "code co_common packet");
		packet_type = ROHC_PACKET_CO_COMMON;
	}
	else /* fallback on co_repair packet */
	{
		/* the co_repair packet is enough to transmit all the dynamic changes ;
		 * if there were static changes, the context would have been reset by
		 * the stream classifier */
		rohc_comp_debug(ctxt, "code co_repair packet");
		packet_type = ROHC_PACKET_CO_REPAIR;
	}

	return packet_type;
}


/**
 * @brief Define according to computed shift parameter if msn_lsb() is possible
 *
 * @param wlsb           The W-LSB object
 * @param value          The value to encode using the LSB algorithm
 * @param reorder_ratio  The reordering ratio
 * @param k              The number of bits for encoding
 * @return               true if msn_lsb is possible or not
 */
static bool rohc_comp_rfc5225_is_msn_lsb_possible(const struct c_wlsb *const wlsb,
                                                  const uint16_t value,
                                                  const rohc_reordering_offset_t reorder_ratio,
                                                  const size_t k)
{
	/* compute p according to reorder ratio  */
	rohc_lsb_shift_t p_computed = rohc_interval_get_rfc5225_msn_p(k, reorder_ratio);

	return wlsb_is_kp_possible_16bits(wlsb, value, k, p_computed);
}


/**
 * @brief Whether the given IP-ID is sequential (swapped or not)
 *
 * @param behavior  The IP-ID behavior
 * @return          true if the given IP-ID behavior is sequential or sequential
 *                  swapped, false otherwise
 */
static bool rohc_comp_rfc5225_is_ipid_sequential(const rohc_ip_id_behavior_t behavior)
{
	return (behavior == ROHC_IP_ID_BEHAVIOR_SEQ ||
	        behavior == ROHC_IP_ID_BEHAVIOR_SEQ_SWAP);
}


/**
 * @brief Whether the given IP-ID is inferred from SN
 *
 * The given IP-ID is inferred from SN if:
 *  - the IP header is IPv4,
 *  - the IP-ID / SN offset was transmitted enough times to gain confidence
 *    that the decompressor received the value,
 *  - the IP-ID behavior is sequential or sequential swapped,
 *  - the new IP-ID value increases from the last IP-ID by the same delta as the MSN.
 *
 * @param ip_ctxt                The context for the given IP header
 * @param ip_id_offset_trans_nr  The number of IP-ID offset transmissions
 * @param oa_repetitions_nr      The number of repetitions for Optimistic Approach
 * @param new_ip_id              The new value of the IP-ID
 * @param msn_offset             The offset between the previous and current MSN
 * @return                       true if the given IP-ID is sequential and
 *                               inferred from MSN, false otherwise
 */
static bool rohc_comp_rfc5225_is_seq_ipid_inferred(const ip_context_t *const ip_ctxt,
                                                   const uint8_t ip_id_offset_trans_nr,
                                                   const uint8_t oa_repetitions_nr,
                                                   const uint16_t new_ip_id,
                                                   const int16_t msn_offset)
{
	bool is_inferred;

	if(ip_ctxt->version != IPV4)
	{
		is_inferred = false;
	}
	else if(ip_id_offset_trans_nr < oa_repetitions_nr)
	{
		is_inferred = false;
	}
	else if(ip_ctxt->ip_id_behavior == ROHC_IP_ID_BEHAVIOR_SEQ)
	{
		is_inferred = (new_ip_id == (ip_ctxt->last_ip_id + msn_offset));
	}
	else if(ip_ctxt->ip_id_behavior == ROHC_IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		is_inferred =
			(swab16(new_ip_id) == (swab16(ip_ctxt->last_ip_id) + msn_offset));
	}
	else
	{
		is_inferred = false;
	}

	return is_inferred;
}

/**
 * @brief Encode an IP packet as IR packet
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc5225_ip_udp_rtp_code_IR_pkt(const struct rohc_comp_ctxt *context,
                                                    const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                    uint8_t *const rohc_pkt,
                                                    const size_t rohc_pkt_max_len)
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
	rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR;
	rohc_comp_debug(context, "packet type = 0x%02x", rohc_pkt[first_position]);

	/* enough room for profile ID and CRC? */
	if(rohc_remain_len < 2)
	{
		rohc_comp_warn(context, "ROHC buffer too small for IR packet: "
		               "2 bytes required for profile ID and CRC, but only "
		               "%zu bytes available", rohc_remain_len);
		goto error;
	}

	/* profile ID */
	rohc_comp_debug(context, "profile ID = 0x%02x", context->profile->id & 0xff);
	rohc_remain_data[0] = context->profile->id & 0xff;
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

	/* add static chain */
	ret = rohc_comp_rfc5225_ip_udp_rtp_static_chain(context, uncomp_pkt_hdrs,
	                                                rohc_remain_data,
	                                                rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the static chain of the IR packet");
		goto error;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_hdr_len += ret;
	rohc_comp_dump_buf(context, "current ROHC packet (with static part)",
	                   rohc_pkt, rohc_hdr_len);

	/* add dynamic chain */
	ret = rohc_comp_rfc5225_ip_udp_rtp_dyn_chain(context, uncomp_pkt_hdrs,
	                                             rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the dynamic chain of the IR packet");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
#endif
	rohc_hdr_len += ret;
	rohc_comp_dump_buf(context, "current ROHC packet (with dynamic part)",
	                   rohc_pkt, rohc_hdr_len);

	/* IR header was successfully built, compute the CRC */
	rohc_pkt[crc_position] = crc_calculate(ROHC_CRC_TYPE_8, rohc_pkt,
	                                       rohc_hdr_len, CRC_INIT_8);
	rohc_comp_debug(context, "CRC (header length = %zu, crc = 0x%x)",
	                rohc_hdr_len, rohc_pkt[crc_position]);

	rohc_comp_debug(context, "IR packet, length %zu", rohc_hdr_len);
	rohc_comp_dump_buf(context, "current ROHC packet", rohc_pkt, rohc_hdr_len);

	return rohc_hdr_len;

error:
	return -1;
}


/**
 * @brief Encode an IP packet as co_repair packet
 *
 * \verbatim

        0   1   2   3   4   5   6   7
       --- --- --- --- --- --- --- ---
      :         Add-CID octet         : if for small CIDs and CID 1-15
      +---+---+---+---+---+---+---+---+
      | 1   1   1   1   1   0   1   1 | discriminator
      +---+---+---+---+---+---+---+---+
      :                               :
      /   0, 1, or 2 octets of CID    / 1-2 octets if large CIDs
      :                               :
      +---+---+---+---+---+---+---+---+
      |r1 |         CRC-7             |
      +---+---+---+---+---+---+---+---+
      |        r2         |   CRC-3   |
      +---+---+---+---+---+---+---+---+
      |                               |
      /         Dynamic chain         / variable length
      |                               |
       - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc5225_ip_udp_rtp_code_co_repair_pkt(const struct rohc_comp_ctxt *context,
                                                           const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                           uint8_t *const rohc_pkt,
                                                           const size_t rohc_pkt_max_len)
{
	const struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = context->specific;
	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;
	size_t first_position;
	size_t rohc_hdr_len = 0;
	int ret;

	/* Add-CID or large CID:
	 *  - discriminator will be placed at 'first_position'
	 *  - CRC-7 will start at 'counter'
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

	/* discriminator */
	rohc_pkt[first_position] = ROHC_PACKET_TYPE_CO_REPAIR;
	rohc_comp_debug(context, "discriminator = 0x%02x", rohc_pkt[first_position]);

	/* enough room for CRC-7 and CRC-3? */
	if(rohc_remain_len < sizeof(co_repair_crc_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for co_repair packet: "
		               "%zu bytes required for CRC-7 and CRC-2, but only %zu "
		               "bytes available", sizeof(co_repair_crc_t), rohc_remain_len);
		goto error;
	}

	/* CRC-7 over uncompressed headers and CRC-3 over control fields */
	{
		co_repair_crc_t *const co_repair_crc = (co_repair_crc_t *) rohc_remain_data;
		uint8_t ip_id_behaviors[ROHC_MAX_IP_HDRS];
		size_t ip_id_behaviors_nr;
		size_t ip_hdr_pos;

		/* reserved field must be 0 */
		co_repair_crc->r1 = 0;
		/* CRC-7 over uncompressed headers */
		co_repair_crc->header_crc =
			crc_calculate(ROHC_CRC_TYPE_7, uncomp_pkt_hdrs->all_hdrs,
			              uncomp_pkt_hdrs->all_hdrs_len, CRC_INIT_7);
		rohc_comp_debug(context, "CRC-7 on %u-byte uncompressed header = 0x%x",
		                uncomp_pkt_hdrs->all_hdrs_len, co_repair_crc->header_crc);

		/* reserved field must be 0 */
		co_repair_crc->r2 = 0;
		/* CRC-3 over control fields */
		ip_id_behaviors_nr = 0;
		for(ip_hdr_pos = 0; ip_hdr_pos < rfc5225_ctxt->ip_contexts_nr; ip_hdr_pos++)
		{
			/* only IP-ID behavior of IPv4 headers are part of the CRC, see
			 * errata 2703 of RFC5225 for reasons to exclude IPv6 headers:
			 * https://www.rfc-editor.org/errata_search.php?rfc=5225&eid=2703 */
			if(rfc5225_ctxt->ip_contexts[ip_hdr_pos].version == IPV4)
			{
				ip_id_behaviors[ip_id_behaviors_nr] =
					rfc5225_ctxt->ip_contexts[ip_hdr_pos].ip_id_behavior;
				rohc_comp_debug(context, "IP-ID behavior #%zu of IPv4 header #%zu "
				                "= 0x%02x", ip_id_behaviors_nr + 1, ip_hdr_pos + 1,
				                ip_id_behaviors[ip_id_behaviors_nr]);
				ip_id_behaviors_nr++;
			}
		}
		co_repair_crc->ctrl_crc =
			compute_crc_ctrl_fields(context->profile->id,
			                        context->compressor->reorder_ratio,
			                        rfc5225_ctxt->msn,
			                        ip_id_behaviors, ip_id_behaviors_nr);
		rohc_comp_debug(context, "CRC-3 on control fields = 0x%x "
		                "(reorder_ratio = 0x%02x, MSN = 0x%04x, %zu IP-ID behaviors)",
		                co_repair_crc->ctrl_crc, context->compressor->reorder_ratio,
		                rfc5225_ctxt->msn, ip_id_behaviors_nr);

		/* skip CRCs */
		rohc_remain_data += sizeof(co_repair_crc_t);
		rohc_remain_len -= sizeof(co_repair_crc_t);
		rohc_hdr_len += sizeof(co_repair_crc_t);
	}

	/* add dynamic chain */
	ret = rohc_comp_rfc5225_ip_udp_rtp_dyn_chain(context, uncomp_pkt_hdrs,
	                                             rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the dynamic chain of the "
		               "co_repair packet");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
#endif
	rohc_hdr_len += ret;
	rohc_comp_dump_buf(context, "current ROHC packet (with dynamic part)",
	                   rohc_pkt, rohc_hdr_len);

	/* co_repair header was successfully built */
	rohc_comp_debug(context, "co_repair packet, length %zu", rohc_hdr_len);
	rohc_comp_dump_buf(context, "current ROHC packet", rohc_pkt, rohc_hdr_len);

	return rohc_hdr_len;

error:
	return -1;
}


/**
 * @brief Encode an IP packet as CO packet
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       The type of ROHC packet to create
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc5225_ip_udp_rtp_code_CO_pkt(const struct rohc_comp_ctxt *const context,
                                                    const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                    uint8_t *const rohc_pkt,
                                                    const size_t rohc_pkt_max_len,
                                                    const rohc_packet_t packet_type)
{
	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;
	uint8_t crc_computed;
	uint8_t save_first_byte;
	size_t pos_1st_byte;
#ifndef __clang_analyzer__ /* TODO: silent warning caused by missing packet types */
	size_t pos_2nd_byte;
#endif
	int ret;

	/* let's compute the CRC on uncompressed headers */
	if(packet_type == ROHC_PACKET_PT_0_CRC3 ||
	   packet_type == ROHC_PACKET_NORTP_PT_1_SEQ_ID)
	{
		crc_computed =
			crc_calculate(ROHC_CRC_TYPE_3, uncomp_pkt_hdrs->all_hdrs,
			              uncomp_pkt_hdrs->all_hdrs_len, CRC_INIT_3);
		rohc_comp_debug(context, "CRC-3 on %u-byte uncompressed header = 0x%x",
		                uncomp_pkt_hdrs->all_hdrs_len, crc_computed);
	}
	else
	{
		crc_computed =
			crc_calculate(ROHC_CRC_TYPE_7, uncomp_pkt_hdrs->all_hdrs,
			              uncomp_pkt_hdrs->all_hdrs_len, CRC_INIT_7);
		rohc_comp_debug(context, "CRC-7 on %u-byte uncompressed header = 0x%x",
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
#ifndef __clang_analyzer__ /* TODO: silent warning caused by missing packet types */
	pos_2nd_byte = ret;
#endif
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
#ifndef __clang_analyzer__ /* TODO: silent warning caused by missing packet types */
	save_first_byte = rohc_remain_data[-1];
#endif
	rohc_remain_data--;
	rohc_remain_len++;

	if(packet_type == ROHC_PACKET_UNKNOWN)
	{
		rohc_comp_warn(context, "failed to find the packet type to encode");
		goto error;
	}
	else
	{
		rohc_comp_warn(context, "packet type %d '%s' not supported by profile",
		               packet_type, rohc_get_packet_descr(packet_type));
		assert(0);
		goto error;
	}

	/* add the irregular chain at the very end of the CO header */
	ret = rohc_comp_rfc5225_ip_udp_rtp_irreg_chain(context, uncomp_pkt_hdrs,
	                                               rohc_remain_data,
	                                               rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the irregular chain of the CO packet");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

#ifndef __clang_analyzer__ /* TODO: silent warning caused by missing packet types */
	/* end of workaround: restore the saved octet */
	if(context->compressor->medium.cid_type != ROHC_SMALL_CID)
	{
		rohc_pkt[pos_1st_byte] = rohc_pkt[pos_2nd_byte - 1];
		rohc_pkt[pos_2nd_byte - 1] = save_first_byte;
	}
#endif

	rohc_comp_dump_buf(context, "CO packet", rohc_pkt,
	                   rohc_pkt_max_len - rohc_remain_len);

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Code the static chain of an ROHCv2 IP/UDP/RTP IR packet
 *
 * @param ctxt              The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc5225_ip_udp_rtp_static_chain(const struct rohc_comp_ctxt *const ctxt,
                                                     const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                     uint8_t *const rohc_pkt,
                                                     const size_t rohc_pkt_max_len)
{
	const struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = ctxt->specific;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	size_t ip_hdr_pos;
	int ret;

	/* add IP parts of static chain */
	for(ip_hdr_pos = 0; ip_hdr_pos < rfc5225_ctxt->ip_contexts_nr; ip_hdr_pos++)
	{
		const bool is_innermost = !!(ip_hdr_pos + 1 == rfc5225_ctxt->ip_contexts_nr);
		const struct rohc_pkt_ip_hdr *const ip_hdr =
			&(uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos]);

		rohc_comp_debug(ctxt, "found IPv%d", ip_hdr->version);

		if(ip_hdr->version == IPV4)
		{
			ret = rohc_comp_rfc5225_ip_udp_rtp_static_ipv4_part(ctxt, ip_hdr->ipv4, is_innermost,
			                                                rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(ctxt, "failed to build the IPv4 base header part "
				               "of the static chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
		}
		else /* IPv6 */
		{
			ret = rohc_comp_rfc5225_ip_udp_rtp_static_ipv6_part(ctxt, ip_hdr->ipv6, is_innermost,
			                                                rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(ctxt, "failed to build the IPv6 base header part "
				               "of the static chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			/* TODO: handle IPv6 extension headers */
		}
	}

	/* add UDP part to static chain */
	ret = rohc_comp_rfc5225_ip_udp_rtp_static_udp_part(ctxt, uncomp_pkt_hdrs->udp,
	                                                   rohc_remain_data,
	                                                   rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(ctxt, "failed to build the UDP header part of static chain");
		goto error;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* add RTP part to static chain */
	ret = rohc_comp_rfc5225_ip_udp_rtp_static_rtp_part(ctxt, uncomp_pkt_hdrs->rtp,
	                                                   rohc_remain_data,
	                                                   rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(ctxt, "failed to build the RTP header part of static chain");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the static part of the IPv4 header
 *
 * @param ctxt            The compression context
 * @param ipv4            The IPv4 header
 * @param is_innermost    Whether the IPv4 header is the innermost IP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_static_ipv4_part(const struct rohc_comp_ctxt *const ctxt,
                                                     const struct ipv4_hdr *const ipv4,
                                                     const bool is_innermost,
                                                     uint8_t *const rohc_data,
                                                     const size_t rohc_max_len)
{
	ipv4_static_t *const ipv4_static = (ipv4_static_t *) rohc_data;
	const size_t ipv4_static_len = sizeof(ipv4_static_t);

	if(rohc_max_len < ipv4_static_len)
	{
		rohc_comp_warn(ctxt, "ROHC buffer too small for the IPv4 static part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv4_static_len, rohc_max_len);
		goto error;
	}

	ipv4_static->version_flag = 0;
	ipv4_static->innermost_ip = GET_REAL(is_innermost);
	ipv4_static->reserved = 0;
	ipv4_static->protocol = ipv4->protocol;
	rohc_comp_debug(ctxt, "IPv4 protocol = %u", ipv4_static->protocol);
	ipv4_static->src_addr = ipv4->saddr;
	ipv4_static->dst_addr = ipv4->daddr;

	rohc_comp_dump_buf(ctxt, "IPv4 static part", rohc_data, ipv4_static_len);

	return ipv4_static_len;

error:
	return -1;
}


/**
 * @brief Build the static part of the IPv6 header
 *
 * @param ctxt            The compression context
 * @param ipv6            The IPv6 header
 * @param is_innermost    Whether the IPv6 header is the innermost IP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_static_ipv6_part(const struct rohc_comp_ctxt *const ctxt,
                                                     const struct ipv6_hdr *const ipv6,
                                                     const bool is_innermost,
                                                     uint8_t *const rohc_data,
                                                     const size_t rohc_max_len)
{
	size_t ipv6_static_len;

	if(ipv6->flow1 == 0 && ipv6->flow2 == 0)
	{
		ipv6_static_nofl_t *const ipv6_static = (ipv6_static_nofl_t *) rohc_data;

		ipv6_static_len = sizeof(ipv6_static_nofl_t);
		if(rohc_max_len < ipv6_static_len)
		{
			rohc_comp_warn(ctxt, "ROHC buffer too small for the IPv6 static part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv6_static_len, rohc_max_len);
			goto error;
		}

		ipv6_static->version_flag = 1;
		ipv6_static->innermost_ip = GET_REAL(is_innermost);
		ipv6_static->reserved1 = 0;
		ipv6_static->flow_label_enc_discriminator = 0;
		ipv6_static->reserved2 = 0;
		ipv6_static->next_header = ipv6->nh;
		memcpy(ipv6_static->src_addr, &ipv6->saddr, sizeof(struct ipv6_addr));
		memcpy(ipv6_static->dst_addr, &ipv6->daddr, sizeof(struct ipv6_addr));
	}
	else
	{
		ipv6_static_fl_t *const ipv6_static = (ipv6_static_fl_t *) rohc_data;

		ipv6_static_len = sizeof(ipv6_static_fl_t);
		if(rohc_max_len < ipv6_static_len)
		{
			rohc_comp_warn(ctxt, "ROHC buffer too small for the IPv6 static part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv6_static_len, rohc_max_len);
			goto error;
		}

		ipv6_static->version_flag = 1;
		ipv6_static->innermost_ip = GET_REAL(is_innermost);
		ipv6_static->reserved = 0;
		ipv6_static->flow_label_enc_discriminator = 1;
		ipv6_static->flow_label_msb = ipv6->flow1;
		ipv6_static->flow_label_lsb = ipv6->flow2;
		ipv6_static->next_header = ipv6->nh;
		memcpy(ipv6_static->src_addr, &ipv6->saddr, sizeof(struct ipv6_addr));
		memcpy(ipv6_static->dst_addr, &ipv6->daddr, sizeof(struct ipv6_addr));
	}
	rohc_comp_debug(ctxt, "IPv6 next header = %u", ipv6->nh);

	rohc_comp_dump_buf(ctxt, "IPv6 static part", rohc_data, ipv6_static_len);

	return ipv6_static_len;

error:
	return -1;
}


/**
 * @brief Build the static part of the UDP header
 *
 * @param ctxt            The compression context
 * @param udp             The UDP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_static_udp_part(const struct rohc_comp_ctxt *const ctxt,
                                                    const struct udphdr *const udp,
                                                    uint8_t *const rohc_data,
                                                    const size_t rohc_max_len)
{
	udp_static_t *const udp_static = (udp_static_t *) rohc_data;
	const size_t udp_static_len = sizeof(udp_static_t);

	if(rohc_max_len < udp_static_len)
	{
		rohc_comp_warn(ctxt, "ROHC buffer too small for the UDP static part: "
		               "%zu bytes required, but only %zu bytes available",
		               udp_static_len, rohc_max_len);
		goto error;
	}

	udp_static->src_port = udp->source;
	udp_static->dst_port = udp->dest;

	rohc_comp_dump_buf(ctxt, "UDP static part", rohc_data, udp_static_len);

	return udp_static_len;

error:
	return -1;
}


/**
 * @brief Build the static part of the RTP header
 *
 * @param ctxt            The compression context
 * @param rtp             The RTP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_static_rtp_part(const struct rohc_comp_ctxt *const ctxt,
                                                    const struct rtphdr *const rtp,
                                                    uint8_t *const rohc_data,
                                                    const size_t rohc_max_len)
{
	rtp_static_t *const rtp_static = (rtp_static_t *) rohc_data;
	const size_t rtp_static_len = sizeof(rtp_static_t);

	if(rohc_max_len < rtp_static_len)
	{
		rohc_comp_warn(ctxt, "ROHC buffer too small for the RTP static part: "
		               "%zu bytes required, but only %zu bytes available",
		               rtp_static_len, rohc_max_len);
		goto error;
	}

	rtp_static->ssrc = rtp->ssrc;

	rohc_comp_dump_buf(ctxt, "RTP static part", rohc_data, rtp_static_len);

	return rtp_static_len;

error:
	return -1;
}


/**
 * @brief Code the dynamic chain of a ROHCv2 IP/UDP/RTP IR packet
 *
 * @param ctxt              The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc5225_ip_udp_rtp_dyn_chain(const struct rohc_comp_ctxt *const ctxt,
                                                  const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                  uint8_t *const rohc_pkt,
                                                  const size_t rohc_pkt_max_len)
{
	struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = ctxt->specific;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	size_t ip_hdr_pos;
	int ret;

	/* there is at least one IP header otherwise it won't be the IP/UDP/RTP profile */
	assert(rfc5225_ctxt->ip_contexts_nr > 0);

	/* add dynamic part for all IP headers */
	for(ip_hdr_pos = 0; ip_hdr_pos < rfc5225_ctxt->ip_contexts_nr; ip_hdr_pos++)
	{
		const ip_context_t *const ip_ctxt = &(rfc5225_ctxt->ip_contexts[ip_hdr_pos]);
		const struct rohc_pkt_ip_hdr *const ip_hdr =
			&(uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos]);

		rohc_comp_debug(ctxt, "found IPv%d", ip_hdr->version);

		if(ip_hdr->version == IPV4)
		{
			ret = rohc_comp_rfc5225_ip_udp_rtp_dyn_ipv4_part(ctxt, ip_ctxt, ip_hdr->ipv4,
			                                             rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(ctxt, "failed to build the IPv4 base header part "
				               "of the dynamic chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
		}
		else /* IPv6 */
		{
			ret = rohc_comp_rfc5225_ip_udp_rtp_dyn_ipv6_part(ctxt, ip_ctxt, ip_hdr->ipv6,
			                                             rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(ctxt, "failed to build the IPv6 base header part "
				               "of the dynamic chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			/* TODO: handle IPv6 extension headers */
		}
	}

	/* add UDP part to dynamic chain */
	ret = rohc_comp_rfc5225_ip_udp_rtp_dyn_udp_part(ctxt, uncomp_pkt_hdrs->udp,
	                                                rohc_remain_data,
	                                                rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(ctxt, "failed to build the UDP header part of dynamic chain");
		goto error;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* add RTP part to dynamic chain */
	ret = rohc_comp_rfc5225_ip_udp_rtp_dyn_rtp_part(ctxt, uncomp_pkt_hdrs->rtp,
	                                                rohc_remain_data,
	                                                rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(ctxt, "failed to build the RTP header part of dynamic chain");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the IPv4 header
 *
 * @param ctxt            The compression context
 * @param ip_ctxt         The specific IP compression context
 * @param ipv4            The IPv4 header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_dyn_ipv4_part(const struct rohc_comp_ctxt *const ctxt,
                                                  const ip_context_t *const ip_ctxt,
                                                  const struct ipv4_hdr *const ipv4,
                                                  uint8_t *const rohc_data,
                                                  const size_t rohc_max_len)
{
	ipv4_regular_dynamic_noipid_t *const ipv4_dynamic =
		(ipv4_regular_dynamic_noipid_t *) rohc_data;
	size_t ipv4_dyn_len = sizeof(ipv4_regular_dynamic_noipid_t);

	assert(ip_ctxt->version == IPV4);

	if(rohc_max_len < ipv4_dyn_len)
	{
		rohc_comp_warn(ctxt, "ROHC buffer too small for the IPv4 dynamic part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv4_dyn_len, rohc_max_len);
		goto error;
	}

	ipv4_dynamic->reserved = 0;
	ipv4_dynamic->df = ipv4->df;
	ipv4_dynamic->ip_id_behavior = ip_ctxt->ip_id_behavior;
	ipv4_dynamic->tos_tc = ipv4->tos;
	ipv4_dynamic->ttl_hopl = ipv4->ttl;

	/* IP-ID */
	if(ipv4_dynamic->ip_id_behavior == ROHC_IP_ID_BEHAVIOR_ZERO)
	{
		rohc_comp_debug(ctxt, "ip_id_behavior = %d", ipv4_dynamic->ip_id_behavior);
	}
	else
	{
		ipv4_regular_dynamic_ipid_t *const ipv4_dynamic_ipid =
			(ipv4_regular_dynamic_ipid_t *) rohc_data;
		ipv4_dyn_len = sizeof(ipv4_regular_dynamic_ipid_t);

		if(rohc_max_len < ipv4_dyn_len)
		{
			rohc_comp_warn(ctxt, "ROHC buffer too small for the IPv4 dynamic part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv4_dyn_len, rohc_max_len);
			goto error;
		}

		ipv4_dynamic_ipid->ip_id = ipv4->id;
		rohc_comp_debug(ctxt, "ip_id_behavior = %d, IP-ID = 0x%04x",
		                ipv4_dynamic->ip_id_behavior, rohc_ntoh16(ipv4->id));
	}

	rohc_comp_dump_buf(ctxt, "IPv4 dynamic part", rohc_data, ipv4_dyn_len);

	return ipv4_dyn_len;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the IPv6 header
 *
 * @param ctxt            The compression context
 * @param ip_ctxt         The specific IP compression context
 * @param ipv6            The IPv6 header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_dyn_ipv6_part(const struct rohc_comp_ctxt *const ctxt,
                                                  const ip_context_t *const ip_ctxt,
                                                  const struct ipv6_hdr *const ipv6,
                                                  uint8_t *const rohc_data,
                                                  const size_t rohc_max_len)
{
	ipv6_regular_dynamic_t *const ipv6_dynamic =
		(ipv6_regular_dynamic_t *) rohc_data;
	size_t ipv6_dyn_len = sizeof(ipv6_regular_dynamic_t);
	const uint8_t tc = ipv6_get_tc(ipv6);

	assert(ip_ctxt->version == IPV6);

	if(rohc_max_len < ipv6_dyn_len)
	{
		rohc_comp_warn(ctxt, "ROHC buffer too small for the IPv6 dynamic part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv6_dyn_len, rohc_max_len);
		goto error;
	}

	ipv6_dynamic->tos_tc = tc;
	ipv6_dynamic->ttl_hopl = ipv6->hl;

	rohc_comp_dump_buf(ctxt, "IP dynamic part", rohc_data, ipv6_dyn_len);

	return ipv6_dyn_len;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the UDP header
 *
 * @param ctxt            The compression context
 * @param udp             The UDP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_dyn_udp_part(const struct rohc_comp_ctxt *const ctxt,
                                                 const struct udphdr *const udp,
                                                 uint8_t *const rohc_data,
                                                 const size_t rohc_max_len)
{
	udp_regular_dynamic_t *const udp_dynamic = (udp_regular_dynamic_t *) rohc_data;
	const size_t udp_dynamic_len = sizeof(udp_regular_dynamic_t);

	if(rohc_max_len < udp_dynamic_len)
	{
		rohc_comp_warn(ctxt, "ROHC buffer too small for the UDP dynamic part: "
		               "%zu bytes required, but only %zu bytes available",
		               udp_dynamic_len, rohc_max_len);
		goto error;
	}

	udp_dynamic->checksum = udp->check;

	rohc_comp_dump_buf(ctxt, "UDP dynamic part", rohc_data, udp_dynamic_len);

	return udp_dynamic_len;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the RTP header
 *
 * @param ctxt            The compression context
 * @param rtp             The RTP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_dyn_rtp_part(const struct rohc_comp_ctxt *const ctxt,
                                                 const struct rtphdr *const rtp,
                                                 uint8_t *const rohc_data,
                                                 const size_t rohc_max_len)
{
	struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = ctxt->specific;
	rtp_dynamic_t *const rtp_dynamic = (rtp_dynamic_t *) rohc_data;
	const size_t rtp_dynamic_len = sizeof(rtp_dynamic_t);

	if(rohc_max_len < rtp_dynamic_len)
	{
		rohc_comp_warn(ctxt, "ROHC buffer too small for the RTP dynamic part: "
		               "%zu bytes required, but only %zu bytes available",
		               rtp_dynamic_len, rohc_max_len);
		goto error;
	}

	rtp_dynamic->reserved = 0;
	rtp_dynamic->reorder_ratio = ctxt->compressor->reorder_ratio;
	rtp_dynamic->list_present = 0; /* TODO: handle RTP CSRC list */
	rtp_dynamic->tss_indicator = 0; /* TODO: handle RTP ts_stride */
	rtp_dynamic->tis_indicator = 0; /* TODO: handle RTP time_stride */
	rtp_dynamic->pad_bit = rtp->padding;
	rtp_dynamic->extension = rtp->extension;
	rtp_dynamic->marker = rtp->m;
	rtp_dynamic->payload_type = rtp->pt;
	rtp_dynamic->sequence_number = rohc_hton16(rfc5225_ctxt->msn);
	rtp_dynamic->timestamp = rtp->timestamp;
	/* TODO: handle optional RTP ts_stride */
	/* TODO: handle optional RTP time_stride */
	/* TODO: handle optional RTP CSRC list */

	rohc_comp_dump_buf(ctxt, "RTP dynamic part", rohc_data, rtp_dynamic_len);

	return rtp_dynamic_len;

error:
	return -1;
}


/**
 * @brief Code the irregular chain of a ROHCv2 IP/UDP/RTP IR packet
 *
 * @param ctxt              The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc5225_ip_udp_rtp_irreg_chain(const struct rohc_comp_ctxt *const ctxt,
                                                    const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                                    uint8_t *const rohc_pkt,
                                                    const size_t rohc_pkt_max_len)
{
	const struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = ctxt->specific;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	size_t ip_hdr_pos;
	int ret;

	/* there is at least one IP header otherwise it won't be the IP/UDP/RTP profile */
	assert(rfc5225_ctxt->ip_contexts_nr > 0);

	/* add dynamic part for all IP headers */
	for(ip_hdr_pos = 0; ip_hdr_pos < rfc5225_ctxt->ip_contexts_nr; ip_hdr_pos++)
	{
		const ip_context_t *const ip_ctxt = &(rfc5225_ctxt->ip_contexts[ip_hdr_pos]);
		const bool is_innermost = !!(ip_hdr_pos + 1 == rfc5225_ctxt->ip_contexts_nr);
		const struct rohc_pkt_ip_hdr *const ip_hdr =
			&(uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos]);

		rohc_comp_debug(ctxt, "found IPv%d", ip_hdr->version);

		if(ip_hdr->version == IPV4)
		{
			ret = rohc_comp_rfc5225_ip_udp_rtp_irreg_ipv4_part(ctxt, ip_ctxt, ip_hdr->ipv4, is_innermost,
			                                               rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(ctxt, "failed to build the IPv4 base header part "
				               "of the irregular chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
		}
		else /* IPv6 */
		{
			ret = rohc_comp_rfc5225_ip_udp_rtp_irreg_ipv6_part(ctxt, ip_ctxt, ip_hdr->ipv6, is_innermost,
			                                               rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(ctxt, "failed to build the IPv6 base header part "
				               "of the irregular chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			/* TODO: handle IPv6 extension headers */
		}
	}

	/* add UDP part to the irregular chain */
	ret = rohc_comp_rfc5225_ip_udp_rtp_irreg_udp_part(ctxt, uncomp_pkt_hdrs->udp,
	                                                  rohc_remain_data,
	                                                  rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(ctxt, "failed to build the UDP header part of irregular chain");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

	/* RTP part in irregular chain is empty */

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the irregular part of the IPv4 header
 *
 * @param ctxt            The compression context
 * @param ip_ctxt         The specific IP compression context
 * @param ipv4            The IPv4 header
 * @param is_innermost    true if the IP header is the innermost of the packet,
 *                        false otherwise
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_irreg_ipv4_part(const struct rohc_comp_ctxt *const ctxt,
                                                    const ip_context_t *const ip_ctxt,
                                                    const struct ipv4_hdr *const ipv4,
                                                    const bool is_innermost,
                                                    uint8_t *const rohc_data,
                                                    const size_t rohc_max_len)
{
	const struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = ctxt->specific;
	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;
	size_t ipv4_irreg_len = 0;

	assert(ip_ctxt->version == IPV4);

	/* IP ID if random */
	if(ip_ctxt->ip_id_behavior == ROHC_IP_ID_BEHAVIOR_RAND)
	{
		if(rohc_remain_len < sizeof(uint16_t))
		{
			rohc_comp_warn(ctxt, "ROHC buffer too small for the IPv4 header "
			               "irregular part: %zu bytes required for random IP-ID, "
			               "but only %zu bytes available", sizeof(uint16_t),
			               rohc_remain_len);
			goto error;
		}
		memcpy(rohc_remain_data, &ipv4->id, sizeof(uint16_t));
		rohc_remain_data += sizeof(uint16_t);
		rohc_remain_len -= sizeof(uint16_t);
		ipv4_irreg_len += sizeof(uint16_t);
		rohc_comp_debug(ctxt, "random IP-ID 0x%04x", rohc_ntoh16(ipv4->id));
	}

	/* TOS and TTL for outer IP headers */
	if(!is_innermost && rfc5225_ctxt->tmp.outer_ip_flag)
	{
		const size_t tos_ttl_req_len = 2;

		if(rohc_remain_len < tos_ttl_req_len)
		{
			rohc_comp_warn(ctxt, "ROHC buffer too small for the IPv4 header "
			               "irregular part: %zu bytes required for TOS and TTL, "
			               "but only %zu bytes available", tos_ttl_req_len,
			               rohc_remain_len);
			goto error;
		}
		rohc_remain_data[0] = ipv4->tos;
		rohc_remain_data[1] = ipv4->ttl;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += tos_ttl_req_len;
		rohc_remain_len -= tos_ttl_req_len;
#endif
		ipv4_irreg_len += tos_ttl_req_len;
	}

	rohc_comp_dump_buf(ctxt, "IPv4 irregular part", rohc_data, ipv4_irreg_len);

	return ipv4_irreg_len;

error:
	return -1;
}


/**
 * @brief Build the irregular part of the IPv6 header
 *
 * @param ctxt            The compression context
 * @param ip_ctxt         The specific IP compression context
 * @param ipv6            The IPv6 header
 * @param is_innermost    true if the IP header is the innermost of the packet,
 *                        false otherwise
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_irreg_ipv6_part(const struct rohc_comp_ctxt *const ctxt,
                                                    const ip_context_t *const ip_ctxt,
                                                    const struct ipv6_hdr *const ipv6,
                                                    const bool is_innermost,
                                                    uint8_t *const rohc_data,
                                                    const size_t rohc_max_len)
{
	const struct rohc_comp_rfc5225_ip_udp_rtp_ctxt *const rfc5225_ctxt = ctxt->specific;
	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;
	size_t ipv6_irreg_len = 0;

	assert(ip_ctxt->version == IPV6);

	/* TOS and TTL for outer IP headers */
	if(!is_innermost && rfc5225_ctxt->tmp.outer_ip_flag)
	{
		const size_t tc_hl_req_len = 2;

		if(rohc_remain_len < tc_hl_req_len)
		{
			rohc_comp_warn(ctxt, "ROHC buffer too small for the IPv6 header "
			               "irregular part: %zu bytes required for TC and HL, "
			               "but only %zu bytes available", tc_hl_req_len,
			               rohc_remain_len);
			goto error;
		}
		rohc_remain_data[0] = ipv6_get_tc(ipv6);
		rohc_remain_data[1] = ipv6->hl;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += tc_hl_req_len;
		rohc_remain_len -= tc_hl_req_len;
#endif
		ipv6_irreg_len += tc_hl_req_len;
	}

	rohc_comp_dump_buf(ctxt, "IPv6 irregular part", rohc_data, ipv6_irreg_len);

	return ipv6_irreg_len;

error:
	return -1;
}


/**
 * @brief Build the irregular part of the UDP header
 *
 * @param ctxt            The compression context
 * @param udp             The UDP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int rohc_comp_rfc5225_ip_udp_rtp_irreg_udp_part(const struct rohc_comp_ctxt *const ctxt,
                                                   const struct udphdr *const udp,
                                                   uint8_t *const rohc_data,
                                                   const size_t rohc_max_len)
{
	size_t udp_irreg_len;

	if(udp->check == 0)
	{
		udp_irreg_len = 0;
	}
	else
	{
		udp_with_checksum_irregular_t *const udp_irreg =
			(udp_with_checksum_irregular_t *) rohc_data;

		udp_irreg_len = sizeof(udp_with_checksum_irregular_t);
		if(rohc_max_len < udp_irreg_len)
		{
			rohc_comp_warn(ctxt, "ROHC buffer too small for the UDP irregular part: "
			               "%zu bytes required, but only %zu bytes available",
			               udp_irreg_len, rohc_max_len);
			goto error;
		}

		udp_irreg->checksum = udp->check;
	}

	rohc_comp_dump_buf(ctxt, "UDP irregular part", rohc_data, udp_irreg_len);

	return udp_irreg_len;

error:
	return -1;
}

/**
 * @brief Define the compression part of the ROHCv2 IP/UDP/RTP profile as described
 *        in the RFC 5225
 */
const struct rohc_comp_profile rohc_comp_rfc5225_ip_udp_rtp_profile =
{
	.id             = ROHCv2_PROFILE_IP_UDP_RTP, /* profile ID (RFC5225, ROHCv2 IP/UDP/RTP) */
	.create         = rohc_comp_rfc5225_ip_udp_rtp_create,     /* profile handlers */
	.clone          = NULL,
	.destroy        = rohc_comp_rfc5225_ip_udp_rtp_destroy,
	.encode         = rohc_comp_rfc5225_ip_udp_rtp_encode,
	.feedback       = rohc_comp_rfc5225_ip_udp_rtp_feedback,
};

