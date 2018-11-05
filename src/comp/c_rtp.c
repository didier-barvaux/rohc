/*
 * Copyright 2007,2008 CNES
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2009,2010,2012,2013,2014 Viveris Technologies
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
 * @file c_rtp.c
 * @brief ROHC compression context for the RTP profile.
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "c_rtp.h"
#include "c_udp.h"
#include "rohc_traces_internal.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "sdvl.h"
#include "crc.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>


/*
 * Constants and macros
 */


/*
 * Private function prototypes.
 */

static bool c_rtp_create(struct rohc_comp_ctxt *const context,
                         const struct rohc_buf *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static void c_rtp_destroy(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

static int c_rtp_encode(struct rohc_comp_ctxt *const context,
                        const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                        const struct rohc_buf *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 6)));

static void rtp_decide_state(struct rohc_comp_ctxt *const context);

static rohc_packet_t c_rtp_decide_FO_packet(const struct rohc_comp_ctxt *const context);
static rohc_packet_t c_rtp_decide_SO_packet(const struct rohc_comp_ctxt *const context);
static rohc_ext_t c_rtp_decide_extension(const struct rohc_comp_ctxt *const context,
                                         const rohc_packet_t packet_type)
	__attribute__((warn_unused_result, nonnull(1)));

static uint32_t c_rtp_get_next_sn(const struct rohc_comp_ctxt *const context,
                                  const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool rtp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static size_t rtp_code_static_rtp_part(const struct rohc_comp_ctxt *const context,
                                       const uint8_t *const next_header,
                                       uint8_t *const dest,
                                       const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static size_t rtp_code_dynamic_rtp_part(const struct rohc_comp_ctxt *const context,
                                        const uint8_t *const next_header,
                                        uint8_t *const dest,
                                        const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int rtp_changed_rtp_dynamic(const struct rohc_comp_ctxt *const context,
                                   const struct udphdr *const udp,
                                   const struct rtphdr *const rtp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));


/**
 * @brief Create a new RTP context and initialize it thanks to the given
 *        IP/UDP/RTP packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The IP/UDP/RTP packet given to initialize the new context
 * @return         true if successful, false otherwise
 */
static bool c_rtp_create(struct rohc_comp_ctxt *const context,
                         const struct rohc_buf *const packet)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_rtp_context *rtp_context;
	const struct udphdr *udp;
	const struct rtphdr *rtp;
	struct net_pkt ip_pkt;

	assert(context->profile != NULL);

	/* parse the uncompressed packet */
	net_pkt_parse(&ip_pkt, *packet, context->compressor->trace_callback,
	              context->compressor->trace_callback_priv, ROHC_TRACE_COMP);

	/* create and initialize the generic part of the profile context */
	if(!rohc_comp_rfc3095_create(context, &ip_pkt))
	{
		rohc_comp_warn(context, "generic context creation failed");
		goto quit;
	}
	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	/* check that transport protocol is UDP, and application protocol is RTP */
	assert(ip_pkt.transport->proto == ROHC_IPPROTO_UDP);
	assert(ip_pkt.transport->data != NULL);
	udp = (struct udphdr *) ip_pkt.transport->data;
	rtp = (struct rtphdr *) (udp + 1);

	/* initialize SN with the SN found in the RTP header */
	rfc3095_ctxt->sn = (uint32_t) rohc_ntoh16(rtp->sn);
	assert(rfc3095_ctxt->sn <= 0xffff);
	rohc_comp_debug(context, "initialize context(SN) = hdr(SN) of first "
	                "packet = %u", rfc3095_ctxt->sn);

	/* create the RTP part of the profile context */
	rtp_context = malloc(sizeof(struct sc_rtp_context));
	if(rtp_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the RTP part of the profile context");
		goto clean;
	}
	rfc3095_ctxt->specific = rtp_context;

	/* initialize the RTP part of the profile context */
	rtp_context->udp_checksum_change_count = 0;
	memcpy(&rtp_context->old_udp, udp, sizeof(struct udphdr));
	rtp_context->rtp_version_change_count = 0;
	rtp_context->rtp_pt_change_count = 0;
	rtp_context->rtp_padding_change_count = 0;
	rtp_context->rtp_extension_change_count = 0;
	memcpy(&rtp_context->old_rtp, rtp, sizeof(struct rtphdr));
	if(!c_create_sc(&rtp_context->ts_sc,
	                context->compressor->oa_repetitions_nr,
	                context->compressor->trace_callback,
	                context->compressor->trace_callback_priv))
	{
		rohc_comp_warn(context, "cannot create scaled RTP Timestamp encoding");
		goto clean;
	}

	/* init the RTP-specific temporary variables */
	rtp_context->tmp.send_rtp_dynamic = -1;
	rtp_context->tmp.ts_send = 0;
	/* do not transmit any RTP TimeStamp (TS) bit by default */
	rtp_context->tmp.nr_ts_bits = 0;
	/* RTP Marker (M) bit is not set by default */
	rtp_context->tmp.is_marker_bit_set = false;
	rtp_context->tmp.rtp_pt_changed = 0;
	rtp_context->tmp.padding_bit_changed = false;
	rtp_context->tmp.extension_bit_changed = false;

	/* init the RTP-specific variables and functions */
	rfc3095_ctxt->next_header_len = sizeof(struct udphdr) + sizeof(struct rtphdr);
	rfc3095_ctxt->encode_uncomp_fields = rtp_encode_uncomp_fields;
	rfc3095_ctxt->decide_state = rtp_decide_state;
	rfc3095_ctxt->decide_FO_packet = c_rtp_decide_FO_packet;
	rfc3095_ctxt->decide_SO_packet = c_rtp_decide_SO_packet;
	rfc3095_ctxt->decide_extension = c_rtp_decide_extension;
	rfc3095_ctxt->init_at_IR = NULL;
	rfc3095_ctxt->get_next_sn = c_rtp_get_next_sn;
	rfc3095_ctxt->code_static_part = rtp_code_static_rtp_part;
	rfc3095_ctxt->code_dynamic_part = rtp_code_dynamic_rtp_part;
	rfc3095_ctxt->code_ir_remainder = NULL;
	rfc3095_ctxt->code_UO_packet_head = NULL;
	rfc3095_ctxt->code_uo_remainder = udp_code_uo_remainder;
	rfc3095_ctxt->compute_crc_static = rtp_compute_crc_static;
	rfc3095_ctxt->compute_crc_dynamic = rtp_compute_crc_dynamic;

	return true;

clean:
	rohc_comp_rfc3095_destroy(context);
quit:
	return false;
}


/**
 * @brief Destroy the RTP context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The RTP compression context to destroy
 */
static void c_rtp_destroy(struct rohc_comp_ctxt *const context)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	struct sc_rtp_context *const rtp_context = rfc3095_ctxt->specific;

	c_destroy_sc(&rtp_context->ts_sc);
	rohc_comp_rfc3095_destroy(context);
}


/**
 * @brief Decide which packet to send when in First Order (FO) state.
 *
 * Packets that can be used are the IR-DYN and UO-2 packets.
 *
 * @see decide_packet
 *
 * @param context The compression context
 * @return        The packet type among:
 *                 - ROHC_PACKET_UOR_2_RTP
 *                 - ROHC_PACKET_UOR_2_TS
 *                 - ROHC_PACKET_UOR_2_ID
 *                 - ROHC_PACKET_IR_DYN
 */
static rohc_packet_t c_rtp_decide_FO_packet(const struct rohc_comp_ctxt *const context)
{
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	const struct sc_rtp_context *const rtp_context =
		(struct sc_rtp_context *) rfc3095_ctxt->specific;
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	const size_t nr_of_ip_hdr = rfc3095_ctxt->ip_hdr_nr;
	rohc_packet_t packet;

	if(rtp_context->udp_checksum_change_count < oa_repetitions_nr)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because UDP checksum "
		                "behavior changed");
	}
	else if(rtp_context->rtp_version_change_count < oa_repetitions_nr)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because RTP Version "
		                "changed");
	}
	else if((rfc3095_ctxt->outer_ip_flags.version == IPV4 &&
	         rfc3095_ctxt->outer_ip_flags.info.v4.sid_count < oa_repetitions_nr) ||
	        (nr_of_ip_hdr > 1 &&
	         rfc3095_ctxt->inner_ip_flags.version == IPV4 &&
	         rfc3095_ctxt->inner_ip_flags.info.v4.sid_count < oa_repetitions_nr))
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because at least one "
		                "SID flag changed");
	}
	else if(nr_of_ip_hdr == 1 && rfc3095_ctxt->tmp.send_dynamic > 2)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %d > 2 dynamic "
		                "fields changed with a single IP header",
		                rfc3095_ctxt->tmp.send_dynamic);
	}
	else if(nr_of_ip_hdr > 1 && rfc3095_ctxt->tmp.send_dynamic > 4)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %d > 4 dynamic "
		                "fields changed with double IP headers",
		                rfc3095_ctxt->tmp.send_dynamic);
	}
	else if(rfc3095_ctxt->tmp.sn_6bits_possible || rfc3095_ctxt->tmp.sn_14bits_possible)
	{
		/* UOR-2* packets can be used only if SN stand on <= 14 bits (6 bits
		 * in base header + 8 bits in extension 3): determine which UOR-2*
		 * packet to choose */

		/* how many IP headers are IPv4 headers with non-random IP-IDs */
		const size_t nr_ipv4_non_rnd = get_nr_ipv4_non_rnd(rfc3095_ctxt);
		const size_t nr_ipv4_non_rnd_with_bits = get_nr_ipv4_non_rnd_with_bits(rfc3095_ctxt);

		rohc_comp_debug(context, "choose one UOR-2-* packet because less than 14 "
		                "SN bits must be transmitted");

		/* what UOR-2* packet do we choose? */
		/* TODO: the 3 next if/else could be merged with the ones from
		 * c_rtp_decide_SO_packet */
		if(nr_ipv4_non_rnd == 0)
		{
			packet = ROHC_PACKET_UOR_2_RTP;
			rohc_comp_debug(context, "choose packet UOR-2-RTP because neither "
			                "of the %zd IP header(s) are IPv4 with non-random "
			                "IP-ID", nr_of_ip_hdr);
		}
		else if(nr_ipv4_non_rnd_with_bits >= 1 &&
		        sdvl_can_length_be_encoded(rtp_context->tmp.nr_ts_bits))
		{
			packet = ROHC_PACKET_UOR_2_ID;
			rohc_comp_debug(context, "choose packet UOR-2-ID because at least "
			                "one of the %zd IP header(s) is IPv4 with "
			                "non-random IP-ID with at least 1 bit of IP-ID to "
			                "transmit, and ( TS bits are deducible from SN, or "
			                "TS bits can be SDVL-encoded", nr_of_ip_hdr);
		}
		else
		{
			packet = ROHC_PACKET_UOR_2_TS;
			rohc_comp_debug(context, "choose packet UOR-2-TS because at least "
			                "one of the %zd IP header(s) is IPv4 with non-random "
			                "IP-ID", nr_of_ip_hdr);
		}
	}
	else
	{
		/* UOR-2* packets can not be used, use IR-DYN instead */
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because more than 14 SN "
		                "bits must be transmitted");
	}

	return packet;
}


/**
 * @brief Decide which packet to send when in Second Order (SO) state.
 *
 * Packets that can be used are the UO-0, UO-1 and UO-2 (with or without
 * extensions) packets.
 *
 * @see decide_packet
 *
 * @param context The compression context
 * @return        The packet type among:
 *                 - ROHC_PACKET_UO_0
 *                 - ROHC_PACKET_UO_1_RTP
 *                 - ROHC_PACKET_UO_1_TS
 *                 - ROHC_PACKET_UO_1_ID
 *                 - ROHC_PACKET_UOR_2_RTP
 *                 - ROHC_PACKET_UOR_2_TS
 *                 - ROHC_PACKET_UOR_2_ID
 *                 - ROHC_PACKET_IR_DYN
 */
static rohc_packet_t c_rtp_decide_SO_packet(const struct rohc_comp_ctxt *const context)
{
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	const struct sc_rtp_context *const rtp_context =
		(struct sc_rtp_context *) rfc3095_ctxt->specific;
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	const size_t nr_of_ip_hdr = rfc3095_ctxt->ip_hdr_nr;
	rohc_packet_t packet;
	unsigned int nr_ipv4_non_rnd;
	unsigned int nr_ipv4_non_rnd_with_bits;
	bool innermost_ip_id_changed;
	bool innermost_ip_id_3bits_possible;
	bool innermost_ip_id_5bits_possible;
	bool innermost_ip_id_8bits_possible;
	bool innermost_ip_id_11bits_possible;
	bool outermost_ip_id_changed;
	bool outermost_ip_id_11bits_possible;
	bool is_outer_ipv4_non_rnd;
	int is_rnd;
	int is_ip_v4;
	bool is_ts_deducible;
	bool is_ts_scaled;

	is_rnd = rfc3095_ctxt->outer_ip_flags.info.v4.rnd;
	is_ip_v4 = (rfc3095_ctxt->outer_ip_flags.version == IPV4);
	is_outer_ipv4_non_rnd = (is_ip_v4 && !is_rnd);

	is_ts_deducible = rohc_ts_sc_is_deducible(&rtp_context->ts_sc);
	is_ts_scaled = (rtp_context->ts_sc.state == SEND_SCALED);

	rohc_comp_debug(context, "is_ts_deducible = %d, is_ts_scaled = %d, "
	                "Marker bit = %d, nr_of_ip_hdr = %zd, rnd = %d",
	                !!is_ts_deducible, !!is_ts_scaled,
	                !!rtp_context->tmp.is_marker_bit_set, nr_of_ip_hdr, is_rnd);

	/* sanity check */
	if(rfc3095_ctxt->outer_ip_flags.version == IPV4)
	{
		assert(rfc3095_ctxt->outer_ip_flags.info.v4.sid_count >= oa_repetitions_nr);
		assert(rfc3095_ctxt->outer_ip_flags.info.v4.rnd_count >= oa_repetitions_nr);
		assert(rfc3095_ctxt->outer_ip_flags.info.v4.nbo_count >= oa_repetitions_nr);
	}
	if(nr_of_ip_hdr > 1 && rfc3095_ctxt->inner_ip_flags.version == IPV4)
	{
		assert(rfc3095_ctxt->inner_ip_flags.info.v4.sid_count >= oa_repetitions_nr);
		assert(rfc3095_ctxt->inner_ip_flags.info.v4.rnd_count >= oa_repetitions_nr);
		assert(rfc3095_ctxt->inner_ip_flags.info.v4.nbo_count >= oa_repetitions_nr);
	}
	assert(rfc3095_ctxt->tmp.send_dynamic == 0);
	assert(rtp_context->tmp.send_rtp_dynamic == 0);
	/* RTP Padding bit is a STATIC field, not allowed to change in SO state */
	assert(!rtp_context->tmp.padding_bit_changed);
	/* RTP eXtension bit is STATIC field, not allowed to change in SO state */
	assert(!rtp_context->tmp.extension_bit_changed);

	/* find out how many IP headers are IPv4 headers with non-random IP-IDs */
	nr_ipv4_non_rnd = 0;
	nr_ipv4_non_rnd_with_bits = 0;
	if(is_outer_ipv4_non_rnd)
	{
		nr_ipv4_non_rnd++;
		if(rfc3095_ctxt->tmp.ip_id_changed)
		{
			nr_ipv4_non_rnd_with_bits++;
		}
	}
	if(nr_of_ip_hdr >= 1)
	{
		const int is_ip2_v4 = (rfc3095_ctxt->inner_ip_flags.version == IPV4);
		const int is_rnd2 = rfc3095_ctxt->inner_ip_flags.info.v4.rnd;
		const bool is_inner_ipv4_non_rnd = (is_ip2_v4 && !is_rnd2);

		if(is_inner_ipv4_non_rnd)
		{
			nr_ipv4_non_rnd++;
			if(rfc3095_ctxt->tmp.ip_id2_changed)
			{
				nr_ipv4_non_rnd_with_bits++;
			}
		}
	}
	rohc_comp_debug(context, "nr_ipv4_non_rnd = %u, nr_ipv4_non_rnd_with_bits = %u",
	                nr_ipv4_non_rnd, nr_ipv4_non_rnd_with_bits);

	/* determine the number of IP-ID bits and the IP-ID offset of the
	 * innermost IPv4 header with non-random IP-ID */
	rohc_get_ipid_bits(context,
	                   &innermost_ip_id_changed,
	                   &innermost_ip_id_3bits_possible,
	                   &innermost_ip_id_5bits_possible,
	                   &innermost_ip_id_8bits_possible,
	                   &innermost_ip_id_11bits_possible,
	                   &outermost_ip_id_changed,
	                   &outermost_ip_id_11bits_possible);

	/* what packet type do we choose? */
	if(rtp_context->udp_checksum_change_count < oa_repetitions_nr)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because UDP checksum "
		                "behavior changed");
	}
	else if(rtp_context->rtp_version_change_count < oa_repetitions_nr)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because RTP Version "
		                "changed");
	}
	else if(rfc3095_ctxt->tmp.sn_4bits_possible &&
	        nr_ipv4_non_rnd_with_bits == 0 &&
	        is_ts_scaled &&
	        (is_ts_deducible || rtp_context->tmp.nr_ts_bits == 0) &&
	        !rtp_context->tmp.is_marker_bit_set)
	{
		packet = ROHC_PACKET_UO_0;
		rohc_comp_debug(context, "choose packet UO-0 because less than 4 SN bits "
		                "must be transmitted, neither of the %zd IP header(s) "
		                "are IPv4 with non-random IP-ID with some IP-ID bits "
		                "to transmit, ( no TS bit must be transmitted, "
		                "or TS bits are deducible from SN ), and RTP M bit is "
		                "not set", nr_of_ip_hdr);
	}
	else if(rfc3095_ctxt->tmp.sn_4bits_possible &&
	        nr_ipv4_non_rnd == 0 &&
	        is_ts_scaled && rtp_context->tmp.nr_ts_bits <= 6)
	{
		packet = ROHC_PACKET_UO_1_RTP;
		rohc_comp_debug(context, "choose packet UO-1-RTP because neither of "
		                "the %zd IP header(s) are 'IPv4 with non-random IP-ID', "
		                "less than 4 SN bits must be transmitted, and "
		                "%zu <= 6 TS bits must be transmitted", nr_of_ip_hdr,
		                rtp_context->tmp.nr_ts_bits);
	}
	else if(rfc3095_ctxt->tmp.sn_4bits_possible &&
	        nr_ipv4_non_rnd_with_bits == 1 && innermost_ip_id_5bits_possible &&
	        is_ts_scaled &&
	        (is_ts_deducible || rtp_context->tmp.nr_ts_bits == 0) &&
	        !rtp_context->tmp.is_marker_bit_set)
	{
		/* UO-1-ID without extension */
		packet = ROHC_PACKET_UO_1_ID;
		rohc_comp_debug(context, "choose packet UO-1-ID because only one of the "
		                "%zd IP header(s) is IPv4 with non-random IP-ID with "
		                "<= 5 IP-ID bits to transmit, less than 4 SN bits "
		                "must be transmitted, ( no TS bit must be transmitted, "
		                "or TS bits are deducible from SN ), and RTP M bit is not "
		                "set", nr_of_ip_hdr);
	}
	else if(rfc3095_ctxt->tmp.sn_4bits_possible &&
	        nr_ipv4_non_rnd_with_bits == 0 &&
	        is_ts_scaled && rtp_context->tmp.nr_ts_bits <= 5)
	{
		packet = ROHC_PACKET_UO_1_TS;
		rohc_comp_debug(context, "choose packet UO-1-TS because neither of the "
		                "%zd IP header(s) are IPv4 with non-random IP-ID with "
		                "some IP-ID bits to to transmit for that IP header, "
		                "less than 4 SN bits must be transmitted, and "
		                "%zu <= 6 TS bits must be transmitted", nr_of_ip_hdr,
		                rtp_context->tmp.nr_ts_bits);
	}
	else if((rfc3095_ctxt->tmp.sn_4bits_possible || rfc3095_ctxt->tmp.sn_12bits_possible) &&
	        nr_ipv4_non_rnd_with_bits >= 1 &&
	        sdvl_can_length_be_encoded(rtp_context->tmp.nr_ts_bits))
	{
		/* UO-1-ID packet with extension can be used only if SN stand on
		 * <= 12 bits (4 bits in base header + 8 bits in extension 3) */

		packet = ROHC_PACKET_UO_1_ID;
		rohc_comp_debug(context, "choose packet UO-1-ID because at least "
		                "one of the %zd IP header(s) is IPv4 with "
		                "non-random IP-ID with at least 1 bit of IP-ID to "
		                "transmit, less than 12 SN bits must be transmitted, "
		                "and %zu TS bits can be SDVL-encoded", nr_of_ip_hdr,
		                rtp_context->tmp.nr_ts_bits);
	}
	else if(rfc3095_ctxt->tmp.sn_6bits_possible || rfc3095_ctxt->tmp.sn_14bits_possible)
	{
		/* UOR-2* packets can be used only if SN stand on <= 14 bits (6 bits
		 * in base header + 8 bits in extension 3): determine which UOR-2*
		 * packet to choose */

		/* what UOR-2* packet do we choose? */
		/* TODO: the 3 next if/else could be merged with the ones from
		 * c_rtp_decide_FO_packet */
		if(nr_ipv4_non_rnd == 0)
		{
			packet = ROHC_PACKET_UOR_2_RTP;
			rohc_comp_debug(context, "choose packet UOR-2-RTP because neither "
			                "of the %zd IP header(s) are IPv4 with non-random "
			                "IP-ID", nr_of_ip_hdr);
		}
		else if(nr_ipv4_non_rnd_with_bits >= 1 &&
		        sdvl_can_length_be_encoded(rtp_context->tmp.nr_ts_bits))
		{
			packet = ROHC_PACKET_UOR_2_ID;
			rohc_comp_debug(context, "choose packet UOR-2-ID because at least "
			                "one of the %zd IP header(s) is IPv4 with non-random "
			                "IP-ID with at least 1 bit of IP-ID to transmit, "
			                "and %zu TS bits can be SDVL-encoded", nr_of_ip_hdr,
			                rtp_context->tmp.nr_ts_bits);
		}
		else
		{
			packet = ROHC_PACKET_UOR_2_TS;
			rohc_comp_debug(context, "choose packet UOR-2-TS because at least "
			                "one of the %zd IP header(s) is IPv4 with "
			                "non-random IP-ID", nr_of_ip_hdr);
		}
	}
	else
	{
		/* UOR-2* packets can not be used, use IR-DYN instead */
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because more than 14 SN "
		                "bits must be transmitted");
	}

	return packet;
}


/**
 * @brief Decide what extension shall be used in the UO-1-ID/UOR-2 packet
 *
 * Extensions 0, 1 & 2 are IPv4 only because of the IP-ID.
 *
 * @param context      The compression context
 * @param packet_type  The type of ROHC packet that is created
 * @return             The extension code among ROHC_EXT_NO, ROHC_EXT_0,
 *                     ROHC_EXT_1 and ROHC_EXT_3 if successful,
 *                     ROHC_EXT_UNKNOWN otherwise
 */
static rohc_ext_t c_rtp_decide_extension(const struct rohc_comp_ctxt *const context,
                                         const rohc_packet_t packet_type)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_rtp_context *rtp_context;
	rohc_ext_t ext;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	rtp_context = (struct sc_rtp_context *) rfc3095_ctxt->specific;

	/* force extension type 3 if at least one RTP dynamic field changed
	 *                     OR if TS cannot be transmitted scaled */
	if(rtp_context->tmp.send_rtp_dynamic > 0)
	{
		rohc_comp_debug(context, "force EXT-3 because at least one RTP dynamic "
		                "field changed");
		ext = ROHC_EXT_3;
	}
	else if(rtp_context->ts_sc.state != SEND_SCALED)
	{
		rohc_comp_debug(context, "force EXT-3 because TS cannot be transmitted "
		                "scaled");
		ext = ROHC_EXT_3;
	}
	else
	{
		/* fallback on the algorithm shared by all IP-based profiles */
		ext = decide_extension(context, packet_type);
	}

	return ext;
}


/**
 * @brief Encode an IP/UDP/RTP packet according to a pattern decided by several
 *        different factors.
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int c_rtp_encode(struct rohc_comp_ctxt *const context,
                        const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                        const struct rohc_buf *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	struct sc_rtp_context *const rtp_context = rfc3095_ctxt->specific;
	const struct udphdr *udp;
	const struct rtphdr *rtp;
	struct net_pkt ip_pkt;
	int size;

	/* parse the uncompressed packet */
	net_pkt_parse(&ip_pkt, *uncomp_pkt, context->compressor->trace_callback,
	              context->compressor->trace_callback_priv, ROHC_TRACE_COMP);

	/* retrieve the UDP and RTP headers */
	assert(ip_pkt.transport->data != NULL);
	udp = (struct udphdr *) ip_pkt.transport->data;
	rtp = (struct rtphdr *) (udp + 1);

	/* how many UDP/RTP fields changed? */
	rtp_context->tmp.send_rtp_dynamic = rtp_changed_rtp_dynamic(context, udp, rtp);

	/* encode the IP packet */
	size = rohc_comp_rfc3095_encode(context, uncomp_pkt_hdrs, uncomp_pkt,
	                                rohc_pkt, rohc_pkt_max_len, packet_type);
	if(size < 0)
	{
		goto quit;
	}

	/* update the context with the new UDP/RTP headers */
	if((*packet_type) == ROHC_PACKET_IR ||
	   (*packet_type) == ROHC_PACKET_IR_DYN)
	{
		memcpy(&rtp_context->old_udp, udp, sizeof(struct udphdr));
		memcpy(&rtp_context->old_rtp, rtp, sizeof(struct rtphdr));
	}
	else
	{
		if(rtp_context->tmp.padding_bit_changed)
		{
			rtp_context->old_rtp.padding = rtp->padding;
		}
		if(rtp_context->tmp.extension_bit_changed)
		{
			rtp_context->old_rtp.extension = rtp->extension;
		}
		if(rtp_context->tmp.rtp_pt_changed)
		{
			rtp_context->old_rtp.pt = rtp->pt;
		}
	}

quit:
	return size;
}


/**
 * @brief Decide the state that should be used for the next packet compressed
 *        with the ROHC RTP profile.
 *
 * The three states are:
 *  - Initialization and Refresh (IR),
 *  - First Order (FO),
 *  - Second Order (SO).
 *
 * @param context The compression context
 */
static void rtp_decide_state(struct rohc_comp_ctxt *const context)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_rtp_context *rtp_context;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	rtp_context = (struct sc_rtp_context *) rfc3095_ctxt->specific;

	if(rtp_context->tmp.send_rtp_dynamic)
	{
		if(context->state == ROHC_COMP_STATE_IR)
		{
			rohc_comp_debug(context, "%d RTP dynamic fields changed, stay in "
			                "IR state", rtp_context->tmp.send_rtp_dynamic);
		}
		else
		{
			rohc_comp_debug(context, "%d RTP dynamic fields changed, go in FO "
			                "state", rtp_context->tmp.send_rtp_dynamic);
			rohc_comp_change_state(context, ROHC_COMP_STATE_FO);
		}
	}
	else
	{
		/* generic function used by the IP-only, UDP and UDP-Lite profiles */
		rohc_comp_rfc3095_decide_state(context);
	}

	/* force initializing TS, TS_STRIDE and TS_SCALED again after
	 * transition back to IR */
	if(context->state == ROHC_COMP_STATE_IR &&
	   rtp_context->ts_sc.state > INIT_STRIDE)
	{
		rtp_context->ts_sc.state = INIT_STRIDE;
		rtp_context->ts_sc.nr_init_stride_packets = 0;
	}
}


/**
 * @brief Determine the SN value for the next packet
 *
 * Profile SN is the 16-bit RTP SN.
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @return            The SN
 */
static uint32_t c_rtp_get_next_sn(const struct rohc_comp_ctxt *const context __attribute__((unused)),
                                  const struct net_pkt *const uncomp_pkt)
{
	const struct udphdr *const udp = (struct udphdr *) uncomp_pkt->transport->data;
	const struct rtphdr *const rtp = (struct rtphdr *) (udp + 1);
	uint32_t next_sn;

	next_sn = (uint32_t) rohc_ntoh16(rtp->sn);

	assert(next_sn <= 0xffff);
	return next_sn;
}


/**
 * @brief Encode uncompressed RTP fields
 *
 * Handle the RTP TS field.
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @return            true in case of success, false otherwise
 */
static bool rtp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	struct sc_rtp_context *const rtp_context = rfc3095_ctxt->specific;
	struct udphdr *udp;
	struct rtphdr *rtp;

	assert(uncomp_pkt->transport->data != NULL);
	udp = (struct udphdr *) uncomp_pkt->transport->data;
	rtp = (struct rtphdr *) (udp + 1);

	/* add new TS value to context */
	assert(rfc3095_ctxt->sn <= 0xffff);
	c_add_ts(&rtp_context->ts_sc, rohc_ntoh32(rtp->timestamp), rfc3095_ctxt->sn);

	/* determine the number of TS bits to send wrt compression state */
	if(rtp_context->ts_sc.state == INIT_TS ||
	   rtp_context->ts_sc.state == INIT_STRIDE)
	{
		/* state INIT_TS: TS_STRIDE cannot be computed yet (first packet or TS
		 *                is constant), so send TS only
		 * state INIT_STRIDE: TS and TS_STRIDE will be send
		 */
		rtp_context->tmp.ts_send = get_ts_unscaled(&rtp_context->ts_sc);
		rtp_context->tmp.nr_ts_bits = nb_bits_unscaled(&rtp_context->ts_sc);

		/* save the new unscaled value */
		assert(rfc3095_ctxt->sn <= 0xffff);
		add_unscaled(&rtp_context->ts_sc, rfc3095_ctxt->sn);
		rohc_comp_debug(context, "unscaled TS = %u on %zu bits",
		                rtp_context->tmp.ts_send, rtp_context->tmp.nr_ts_bits);
	}
	else /* SEND_SCALED */
	{
		/* TS_SCALED value will be send */
		rtp_context->tmp.ts_send = get_ts_scaled(&rtp_context->ts_sc);
		rtp_context->tmp.nr_ts_bits = nb_bits_scaled(&rtp_context->ts_sc);

		/* save the new unscaled and TS_SCALED values */
		assert(rfc3095_ctxt->sn <= 0xffff);
		add_unscaled(&rtp_context->ts_sc, rfc3095_ctxt->sn);
		add_scaled(&rtp_context->ts_sc, rfc3095_ctxt->sn);
		rohc_comp_debug(context, "TS_SCALED = %u on %zu bits",
		                rtp_context->tmp.ts_send, rtp_context->tmp.nr_ts_bits);
	}

	rohc_comp_debug(context, "%s%zu bits are required to encode new TS",
	                (rohc_ts_sc_is_deducible(&rtp_context->ts_sc) ?
	                 "0 (TS is deducible from SN bits) or " : ""),
	                rtp_context->tmp.nr_ts_bits);

	return true;
}


/**
 * @brief Build the static part of the UDP/RTP headers.
 *
 * \verbatim

 Static part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /          Source Port          /   2 octets
    +---+---+---+---+---+---+---+---+
 2  /       Destination Port        /   2 octets
    +---+---+---+---+---+---+---+---+

 Static part of RTP header (5.7.7.6):

    +---+---+---+---+---+---+---+---+
 3  /             SSRC              /   4 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 1 & 2 are done by the udp_code_static_udp_part() function. Part 3 is
 * done by this function.
 *
 * @param context     The compression context
 * @param next_header The UDP/RTP headers
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 *
 * @see udp_code_static_udp_part
 */
static size_t rtp_code_static_rtp_part(const struct rohc_comp_ctxt *const context,
                                       const uint8_t *const next_header,
                                       uint8_t *const dest,
                                       const size_t counter)
{
	const struct udphdr *const udp = (struct udphdr *) next_header;
	const struct rtphdr *const rtp = (struct rtphdr *) (udp + 1);
	size_t counter2;
	size_t nr_written = 0;

	/* parts 1 & 2 */
	counter2 = udp_code_static_udp_part(context, next_header, dest, counter);

	/* part 3 */
	rohc_comp_debug(context, "RTP SSRC = 0x%x", rtp->ssrc);
	memcpy(&dest[counter2 + nr_written], &rtp->ssrc, 4);
	nr_written += 4;

	return counter2 + nr_written;
}


/**
 * @brief Build the dynamic part of the UDP/RTP headers.
 *
 * \verbatim

 Dynamic part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /           Checksum            /   2 octets
    +---+---+---+---+---+---+---+---+

 Dynamic part of RTP header (5.7.7.6):

    +---+---+---+---+---+---+---+---+
 2  |  V=2  | P | RX|      CC       |  (RX is NOT the RTP X bit)
    +---+---+---+---+---+---+---+---+
 3  | M |            PT             |
    +---+---+---+---+---+---+---+---+
 4  /      RTP Sequence Number      /  2 octets
    +---+---+---+---+---+---+---+---+
 5  /   RTP Timestamp (absolute)    /  4 octets
    +---+---+---+---+---+---+---+---+
 6  /      Generic CSRC list        /  variable length
    +---+---+---+---+---+---+---+---+
 7  : Reserved  | X |  Mode |TIS|TSS:  if RX = 1
    +---+---+---+---+---+---+---+---+
 8  :         TS_Stride             :  1-4 octets, if TSS = 1
    +---+---+---+---+---+---+---+---+
 9  :         Time_Stride           :  1-4 octets, if TIS = 1
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 6 & 9 are not supported yet. The TIS flag in part 7 is not supported.
 *
 * @param context     The compression context
 * @param next_header The UDP/RTP headers
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static size_t rtp_code_dynamic_rtp_part(const struct rohc_comp_ctxt *const context,
                                        const uint8_t *const next_header,
                                        uint8_t *const dest,
                                        const size_t counter)
{
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	struct sc_rtp_context *const rtp_context =
		(struct sc_rtp_context *) rfc3095_ctxt->specific;
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	const struct udphdr *const udp = (struct udphdr *) next_header;
	const struct rtphdr *const rtp = (struct rtphdr *) (udp + 1);
	uint8_t byte;
	unsigned int rx_byte = 0;
	size_t nr_written;

	/* part 1 */
	rohc_comp_debug(context, "UDP checksum = 0x%04x", udp->check);
	memcpy(&dest[counter], &udp->check, 2);
	nr_written = 2;
	rtp_context->udp_checksum_change_count++;

	/* part 2 */
	byte = 0;
	if(rtp_context->ts_sc.state == INIT_STRIDE ||
	   rtp_context->tmp.extension_bit_changed ||
	   rtp_context->rtp_extension_change_count < oa_repetitions_nr)
	{
		/* send TS_STRIDE and/or the eXtension (X) bit */
		rx_byte = 1;
		byte |= 1 << 4;
	}
	byte |= (rtp->version & 0x03) << 6;
	byte |= (rtp->padding & 0x01) << 5;
	byte |= rtp->cc & 0x0f;
	dest[counter + nr_written] = byte;
	rohc_comp_debug(context, "(V = %u, P = %u, RX = %u, CC = 0x%x) = 0x%02x",
	                rtp->version & 0x03, rtp->padding & 0x01, rx_byte,
	                rtp->cc & 0x0f, dest[counter + nr_written]);
	nr_written++;
	rtp_context->rtp_version_change_count++;
	rtp_context->rtp_padding_change_count++;

	/* part 3 */
	byte = 0;
	byte |= (rtp->m & 0x01) << 7;
	byte |= rtp->pt & 0x7f;
	dest[counter + nr_written] = byte;
	rohc_comp_debug(context, "(M = %u, PT = 0x%02x) = 0x%02x", rtp->m & 0x01,
	                rtp->pt & 0x7f, dest[counter + nr_written]);
	nr_written++;
	rtp_context->rtp_pt_change_count++;

	/* part 4 */
	memcpy(&dest[counter + nr_written], &rtp->sn, 2);
	rohc_comp_debug(context, "SN = 0x%02x 0x%02x", dest[counter + nr_written],
	                dest[counter + nr_written + 1]);
	nr_written += 2;

	/* part 5 */
	memcpy(&dest[counter + nr_written], &rtp->timestamp, 4);
	rohc_comp_debug(context, "TS = 0x%02x 0x%02x 0x%02x 0x%02x",
	                dest[counter + nr_written], dest[counter + nr_written + 1],
	                dest[counter + nr_written + 2],
	                dest[counter + nr_written + 3]);
	nr_written += 4;

	/* part 6 not supported yet  but the field is mandatory,
	   so add a zero byte */
	dest[counter + nr_written] = 0x00;
	rohc_comp_debug(context, "Generic CSRC list not supported yet, put a 0x00 byte");
	nr_written++;

	/* parts 7, 8 & 9 */
	if(rx_byte)
	{
		int tis;
		int tss;

		/* part 7 */
		tis = 0; /* TIS flag not supported yet */
		tss = (rtp_context->ts_sc.state == INIT_STRIDE);

		byte = 0;
		byte |= (rtp->extension & 0x01) << 4;
		byte |= (context->mode & 0x03) << 2;
#if 0 /* TODO: handle TIS */
		byte |= (tis & 0x01) << 1;
#endif
		byte |= tss & 0x01;
		dest[counter + nr_written] = byte;
		rohc_comp_debug(context, "(X = %u, Mode = %u, TIS = %u, TSS = %u) = 0x%02x",
		                rtp->extension & 0x01, context->mode & 0x03, tis & 0x01,
		                tss & 0x01, dest[counter + nr_written]);
		nr_written++;
		rtp_context->rtp_extension_change_count++;

		/* part 8 */
		if(tss)
		{
			uint32_t ts_stride;
			size_t ts_stride_sdvl_len;

			/* get the TS_STRIDE to send in packet */
			ts_stride = get_ts_stride(&rtp_context->ts_sc);

			/* encode TS_STRIDE in SDVL and write it to packet */
			if(!sdvl_encode_full(dest + counter + nr_written, 4U /* TODO */,
			                     &ts_stride_sdvl_len, ts_stride))
			{
				rohc_comp_warn(context, "failed to SDVL-encode TS_STRIDE %u",
				               ts_stride);
				/* TODO: should handle error gracefully */
				assert(0);
			}
			rohc_comp_debug(context, "send TS_STRIDE = 0x%08x encoded with SDVL "
			                "on %zu bytes", ts_stride, ts_stride_sdvl_len);

			/* skip the bytes used to encode TS_STRIDE in SDVL */
			nr_written += ts_stride_sdvl_len;

			/* do we transmit the scaled RTP Timestamp (TS) in the next packet ? */
			rtp_context->ts_sc.nr_init_stride_packets++;
			if(rtp_context->ts_sc.nr_init_stride_packets >= oa_repetitions_nr)
			{
				rohc_comp_debug(context, "TS_STRIDE transmitted at least %u "
				                "times, so change from state INIT_STRIDE to "
				                "SEND_SCALED", oa_repetitions_nr);
				rtp_context->ts_sc.state = SEND_SCALED;
			}
			else
			{
				rohc_comp_debug(context, "TS_STRIDE transmitted only %zd times, "
				                "so stay in state INIT_STRIDE (at least %u times "
				                "are required to change to state SEND_SCALED)",
				                rtp_context->ts_sc.nr_init_stride_packets,
				                oa_repetitions_nr);
			}
		}

		/* part 9 not supported yet */
	}

	return counter + nr_written;
}


/**
 * @brief Check if the dynamic part of the UDP/RTP headers changed.
 *
 * @param context The compression context
 * @param udp     The UDP header
 * @param rtp     The RTP header
 * @return        The number of UDP/RTP fields that changed
 */
static int rtp_changed_rtp_dynamic(const struct rohc_comp_ctxt *const context,
                                   const struct udphdr *const udp,
                                   const struct rtphdr *const rtp)
{
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	struct sc_rtp_context *const rtp_context =
		(struct sc_rtp_context *) rfc3095_ctxt->specific;
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	int fields = 0;

	rohc_comp_debug(context, "find changes in RTP dynamic fields");

	/* check UDP checksum field */
	if((udp->check != 0 && rtp_context->old_udp.check == 0) ||
	   (udp->check == 0 && rtp_context->old_udp.check != 0) ||
	   (rtp_context->udp_checksum_change_count < oa_repetitions_nr))
	{
		if((udp->check != 0 && rtp_context->old_udp.check == 0) ||
		   (udp->check == 0 && rtp_context->old_udp.check != 0))
		{
			rohc_comp_debug(context, "UDP checksum field changed");
			rtp_context->udp_checksum_change_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "UDP checksum field did not change but "
			                "changed in the last few packets");
		}

		/* do not count the UDP checksum change as other RTP dynamic fields
		 * because it requires a specific behaviour (IR or IR-DYN packet
		 * required). */
	}

	/* check RTP Version field */
	if(rtp->version != rtp_context->old_rtp.version ||
	   rtp_context->rtp_version_change_count < oa_repetitions_nr)
	{
		if(rtp->version != rtp_context->old_rtp.version)
		{
			rohc_comp_debug(context, "RTP Version field changed (%u -> %u)",
			                rtp_context->old_rtp.version, rtp->version);
			rtp_context->rtp_version_change_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "RTP Payload Type (PT) field did not "
			                "change but changed in the last few packets");
		}

		/* do not count the RTP Version change as other RTP dynamic fields
		 * because it requires a specific behaviour (IR or IR-DYN packet
		 * required). */
	}

	/* check RTP CSRC Counter and CSRC field */
	if(rtp->cc != rtp_context->old_rtp.cc)
	{
		rohc_comp_debug(context, "RTP CC field changed (0x%x -> 0x%x)",
		                rtp_context->old_rtp.cc, rtp->cc);
		fields += 2;
	}

	/* check SSRC field */
	if(rtp->ssrc != rtp_context->old_rtp.ssrc)
	{
		rohc_comp_debug(context, "RTP SSRC field changed (0x%08x -> 0x%08x)",
		                rtp_context->old_rtp.ssrc, rtp->ssrc);
		fields++;
	}

	/* check RTP Marker field: remember its value but do not count it
	 * as a changed field since it is not stored in the context */
	if(rtp->m != 0)
	{
		rohc_comp_debug(context, "RTP Marker (M) bit is set");
		rtp_context->tmp.is_marker_bit_set = true;
	}
	else
	{
		rtp_context->tmp.is_marker_bit_set = false;
	}

	/* check RTP Padding field */
	if(rtp->padding != rtp_context->old_rtp.padding ||
	   rtp_context->rtp_padding_change_count < oa_repetitions_nr)
	{
		if(rtp->padding != rtp_context->old_rtp.padding)
		{
			rohc_comp_debug(context, "RTP Padding (P) bit changed (0x%x -> 0x%x)",
			                rtp_context->old_rtp.padding, rtp->padding);
			rtp_context->tmp.padding_bit_changed = true;
			rtp_context->rtp_padding_change_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "RTP Padding (P) bit did not change but "
			                "changed in the last few packets");
			rtp_context->tmp.padding_bit_changed = false;
		}

		fields++;
	}
	else
	{
		rtp_context->tmp.padding_bit_changed = false;
	}

	/* check RTP eXtension (X) field */
	if(rtp->extension != rtp_context->old_rtp.extension ||
	   rtp_context->rtp_extension_change_count < oa_repetitions_nr)
	{
		if(rtp->extension != rtp_context->old_rtp.extension)
		{
			rohc_comp_debug(context, "RTP eXtension (X) bit changed (0x%x -> "
			                "0x%x)", rtp_context->old_rtp.extension,
			                rtp->extension);
			rtp_context->tmp.extension_bit_changed = true;
			rtp_context->rtp_extension_change_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "RTP eXtension (X) bit did not change but "
			                "changed in the last few packets");
			rtp_context->tmp.extension_bit_changed = false;
		}

		fields++;
	}
	else
	{
		rtp_context->tmp.extension_bit_changed = false;
	}

	/* check RTP Payload Type field */
	if(rtp->pt != rtp_context->old_rtp.pt ||
	   rtp_context->rtp_pt_change_count < oa_repetitions_nr)
	{
		if(rtp->pt != rtp_context->old_rtp.pt)
		{
			rohc_comp_debug(context, "RTP Payload Type (PT) field changed "
			                "(0x%x -> 0x%x)", rtp_context->old_rtp.pt, rtp->pt);
			rtp_context->tmp.rtp_pt_changed = 1;
			rtp_context->rtp_pt_change_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "RTP Payload Type (PT) field did not "
			                "change but changed in the last few packets");
			rtp_context->tmp.rtp_pt_changed = 0;
		}

		fields++;
	}
	else
	{
		rtp_context->tmp.rtp_pt_changed = 0;
	}

	rohc_comp_debug(context, "%d RTP dynamic fields changed", fields);

	return fields;
}


/**
 * @brief Define the compression part of the RTP profile as described
 *        in the RFC 3095.
 */
const struct rohc_comp_profile c_rtp_profile =
{
	.id             = ROHC_PROFILE_RTP, /* profile ID */
	.create         = c_rtp_create,     /* profile handlers */
	.destroy        = c_rtp_destroy,
	.encode         = c_rtp_encode,
	.feedback       = rohc_comp_rfc3095_feedback,
};

