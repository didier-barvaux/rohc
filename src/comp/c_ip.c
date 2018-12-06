/*
 * Copyright 2012,2013,2014 Didier Barvaux
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
 * @file c_ip.c
 * @brief ROHC compression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "c_ip.h"
#include "rohc_traces_internal.h"
#include "rohc_utils.h"

#include <string.h>
#include <assert.h>


/*
 * Prototypes of private functions
 */

static bool rohc_ip_ctxt_create(struct rohc_comp_ctxt *const context,
                                const struct rohc_buf *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool max_6_bits_of_innermost_nonrnd_ipv4_id_required(const struct rohc_comp_rfc3095_ctxt *const ctxt)
	__attribute__((warn_unused_result, nonnull(1)));


/*
 * Definitions of public functions
 */

/**
 * @brief Create a new context and initialize it thanks to the given IP packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The IP packet given to initialize the new context
 * @return         true if successful, false otherwise
 */
static bool rohc_ip_ctxt_create(struct rohc_comp_ctxt *const context,
                                const struct rohc_buf *const packet)
{
	const struct rohc_comp *const comp = context->compressor;
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct net_pkt ip_pkt;

	/* parse the uncompressed packet */
	net_pkt_parse(&ip_pkt, *packet, context->compressor->trace_callback,
	              context->compressor->trace_callback_priv, ROHC_TRACE_COMP);

	/* call the generic function for all IP-based profiles */
	if(!rohc_comp_rfc3095_create(context, &ip_pkt))
	{
		rohc_comp_warn(context, "generic context creation failed");
		goto error;
	}
	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	/* initialize SN to a random value (RFC 3095, 5.11.1) */
	rfc3095_ctxt->sn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "initialize context(SN) = random() = %u",
	                rfc3095_ctxt->sn);

	/* init the IP-only-specific variables and functions */
	rfc3095_ctxt->decide_FO_packet = c_ip_decide_FO_packet;
	rfc3095_ctxt->decide_SO_packet = c_ip_decide_SO_packet;
	rfc3095_ctxt->decide_extension = decide_extension;
	rfc3095_ctxt->get_next_sn = c_ip_get_next_sn;
	rfc3095_ctxt->code_ir_remainder = c_ip_code_ir_remainder;

	return true;

error:
	return false;
}


/**
 * @brief Decide which packet to send when in First Order (FO) state.
 *
 * Packets that can be used are the IR-DYN and UO-2 packets.
 *
 * @see decide_packet
 *
 * @param context The compression context
 * @return        The packet type among ROHC_PACKET_IR_DYN and ROHC_PACKET_UOR_2
 */
rohc_packet_t c_ip_decide_FO_packet(const struct rohc_comp_ctxt *const context)
{
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(const struct rohc_comp_rfc3095_ctxt *const) context->specific;
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	rohc_packet_t packet;

	if(does_at_least_one_sid_change(rfc3095_ctxt, oa_repetitions_nr))
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because at least one "
		                "SID flag changed");
	}
	else if(rfc3095_ctxt->ip_hdr_nr == 1 && rfc3095_ctxt->tmp.send_dynamic > 2)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %d > 2 dynamic "
		                "fields changed with a single IP header",
		                rfc3095_ctxt->tmp.send_dynamic);
	}
	else if(rfc3095_ctxt->ip_hdr_nr > 1 && rfc3095_ctxt->tmp.send_dynamic > 4)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %d > 4 dynamic "
		                "fields changed with double IP header",
		                rfc3095_ctxt->tmp.send_dynamic);
	}
	else if(rfc3095_ctxt->tmp.sn_5bits_possible ||
	        rfc3095_ctxt->tmp.sn_13bits_possible)
	{
		/* UOR-2 packet can be used only if SN stand on <= 13 bits (5 bits in
		   base header + 8 bits in extension 3) */
		packet = ROHC_PACKET_UOR_2;
		rohc_comp_debug(context, "choose packet UOR-2 because <= 13 SN bits "
		                "must be transmitted");
	}
	else
	{
		/* UOR-2 packet can not be used, use IR-DYN instead */
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because > 13 SN bits "
		                "must be transmitted");
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
 * @return        The packet type among ROHC_PACKET_UO_0, ROHC_PACKET_UO_1 and
 *                ROHC_PACKET_UOR_2
 */
rohc_packet_t c_ip_decide_SO_packet(const struct rohc_comp_ctxt *const context)
{
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	bool some_ip_id_bits_required = false;
	rohc_packet_t packet;
	size_t ip_hdr_pos;

	for(ip_hdr_pos = 0; ip_hdr_pos < rfc3095_ctxt->ip_hdr_nr; ip_hdr_pos++)
	{
		const struct ip_header_info *const ip_ctxt =
			&(rfc3095_ctxt->ip_ctxts[ip_hdr_pos]);
		const struct rohc_rfc3095_tmp_ip_hdr *const tmp_vars_ip =
			&(rfc3095_ctxt->tmp.ip_hdrs[ip_hdr_pos]);

		if(ip_ctxt->version == IPV4)
		{
			/* SID, RND and NBO flags shall be established for all IPv4 headers */
			assert(ip_ctxt->info.v4.sid_count >= oa_repetitions_nr);
			assert(ip_ctxt->info.v4.rnd_count >= oa_repetitions_nr);
			assert(ip_ctxt->info.v4.nbo_count >= oa_repetitions_nr);

			/* are some IP-ID bits required for the IP header? */
			if(ip_ctxt->info.v4.rnd == 0 && tmp_vars_ip->ip_id_changed)
			{
				some_ip_id_bits_required = true;
			}
		}
	}

	/* what is the smallest possible packet type? */
	if(rfc3095_ctxt->tmp.sn_4bits_possible && !some_ip_id_bits_required)
	{
		packet = ROHC_PACKET_UO_0;
		rohc_comp_debug(context, "choose packet UO-0 to transmit <= 4 SN bits, and "
		                "no IP-ID bits");
	}
	else if(rfc3095_ctxt->tmp.sn_5bits_possible &&
	        max_6_bits_of_innermost_nonrnd_ipv4_id_required(rfc3095_ctxt))
	{
		packet = ROHC_PACKET_UO_1; /* IPv4 only for outer header */
		rohc_comp_debug(context, "choose packet UO-1 to transmit <= 5 SN bits, "
		                "<= 6 IP-ID bits of innermost IPv4 header with RND=0, and "
		                "0 IP-ID bits of the other outer IPv4 headers");
	}
	else if(rfc3095_ctxt->tmp.sn_5bits_possible ||
	        rfc3095_ctxt->tmp.sn_13bits_possible)
	{
		/* UOR-2 packet can be used only if SN stand on <= 13 bits (5 bits in
		   base header + 8 bits in extension 3) */
		packet = ROHC_PACKET_UOR_2;
		rohc_comp_debug(context, "choose packet UOR-2 to transmit <= 13 SN bits");
	}
	else
	{
		/* UOR-2 packet can not be used, use IR-DYN instead */
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN to transmit > 13 SN bits");
	}

	return packet;
}


/**
 * @brief Determine the SN value for the next packet
 *
 * Profile SN is an internal increasing 16-bit number.
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @return            The SN
 */
uint32_t c_ip_get_next_sn(const struct rohc_comp_ctxt *const context,
                          const struct net_pkt *const uncomp_pkt __attribute__((unused)))
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	uint32_t next_sn;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	if(rfc3095_ctxt->sn == 0xffff)
	{
		next_sn = 0;
	}
	else
	{
		next_sn = rfc3095_ctxt->sn + 1;
	}

	assert(next_sn <= 0xffff);
	return next_sn;
}


/**
 * @brief Code the remainder header for the IR or IR-DYN packets
 *
 * \verbatim

 Remainder of IR/IR-DYN packet (5.7.7.1):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 1  |             SN                |  2 octets if not RTP
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context       The compression context
 * @param dest          The ROHC packet being coded
 * @param dest_max_len  The maximum length (in bytes) of the ROHC packet
 * @param counter       The current position in the ROHC buffer
 * @return              The new position in ROHC buffer in case of success,
 *                      -1 in case of failure
 */
int c_ip_code_ir_remainder(const struct rohc_comp_ctxt *const context,
                           uint8_t *const dest,
                           const size_t dest_max_len,
                           const size_t counter)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	uint16_t sn;

	/* part 1 */
	if((counter + 2) > dest_max_len)
	{
		rohc_comp_warn(context, "ROHC packet too small (%zu bytes max) for the "
		               "2-byte SN in the IR remainder at %zu bytes of the "
		               "beginning of the packet", dest_max_len, counter);
		goto error;
	}
	sn = rfc3095_ctxt->sn & 0xffff;
	sn = rohc_hton16(sn);
	memcpy(&dest[counter], &sn, sizeof(uint16_t));
	rohc_comp_debug(context, "SN = %u -> 0x%02x%02x", rfc3095_ctxt->sn,
	                dest[counter], dest[counter + 1]);

	return counter + 2;

error:
	return -1;
}


/**
 * @brief May the inner IP header transmit the required non-random IP-ID bits?
 *
 * @param ctxt  The generic decompression context
 * @return      true if the required IP-ID bits may be transmitted,
 *              false otherwise
 */
static bool max_6_bits_of_innermost_nonrnd_ipv4_id_required(const struct rohc_comp_rfc3095_ctxt *const ctxt)
{
	bool is_possible;

	if(ctxt->ip_hdr_nr == 1)
	{
		is_possible = (ctxt->ip_ctxts[0].version == IPV4 &&
		               ctxt->ip_ctxts[0].info.v4.rnd != 1 &&
		               ctxt->tmp.ip_hdrs[0].ip_id_6bits_possible);
	}
	else if(ctxt->ip_ctxts[1].version == IPV4 &&
	        ctxt->ip_ctxts[1].info.v4.rnd != 1)
	{
		const bool no_1st_hdr_bits = (ctxt->ip_ctxts[0].version != IPV4 ||
		                              ctxt->ip_ctxts[0].info.v4.rnd == 1 ||
		                              !ctxt->tmp.ip_hdrs[0].ip_id_changed);
		is_possible = (ctxt->tmp.ip_hdrs[1].ip_id_6bits_possible && no_1st_hdr_bits);
	}
	else if(ctxt->ip_ctxts[0].version == IPV4 &&
	        ctxt->ip_ctxts[0].info.v4.rnd != 1)
	{
		is_possible = ctxt->tmp.ip_hdrs[1].ip_id_6bits_possible;
	}
	else
	{
		/* UO-1 is possible even if there is no IPv4 header with RND=0 (the
		 * decompressor shall then ignore the IP-ID bits transmitted), but
		 * there is no gain sending one UO-1 packet with useless bits */
		is_possible = false;
	}

	return is_possible;
}


/**
 * @brief Define the compression part of the IP-only profile as described
 *        in the RFC 3843.
 */
const struct rohc_comp_profile c_ip_profile =
{
	.id             = ROHC_PROFILE_IP,     /* profile ID (see 5 in RFC 3843) */
	.create         = rohc_ip_ctxt_create, /* profile handlers */
	.destroy        = rohc_comp_rfc3095_destroy,
	.encode         = rohc_comp_rfc3095_encode,
	.feedback       = rohc_comp_rfc3095_feedback,
};

