/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2009,2010,2012,2013,2014 Viveris Technologies
 *
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
 * @file c_ip.c
 * @brief ROHC compression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "c_ip.h"
#include "rohc_traces_internal.h"
#include "rohc_utils.h"

#ifndef __KERNEL__
#	include <string.h>
#endif
#include <assert.h>


/*
 * Prototypes of private functions
 */

static bool rohc_ip_ctxt_create(struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));


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
                                const struct net_pkt *const packet)
{
	const struct rohc_comp *const comp = context->compressor;
	struct c_generic_context *g_context;

	assert(context != NULL);
	assert(context->profile != NULL);
	assert(packet != NULL);

	/* call the generic function for all IP-based profiles */
	if(!c_generic_create(context, ROHC_LSB_SHIFT_SN, packet))
	{
		rohc_comp_warn(context, "generic context creation failed");
		goto error;
	}
	g_context = (struct c_generic_context *) context->specific;

	/* initialize SN to a random value (RFC 3095, 5.11.1) */
	g_context->sn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "initialize context(SN) = random() = %u",
	                g_context->sn);

	/* init the IP-only-specific variables and functions */
	g_context->decide_FO_packet = c_ip_decide_FO_packet;
	g_context->decide_SO_packet = c_ip_decide_SO_packet;
	g_context->decide_extension = decide_extension;
	g_context->get_next_sn = c_ip_get_next_sn;
	g_context->code_ir_remainder = c_ip_code_ir_remainder;

	return true;

error:
	return false;
}


/**
 * @brief Check if an IP packet belongs to the context.
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of the two IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match the
 *    ones in the context
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones in
 *    the context
 *  - the transport protocol must match the one in the context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The IP packet to check
 * @return         true if the IP packet belongs to the context
 *                 false if it does not belong to the context
 */
bool c_ip_check_context(const struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const packet)
{
	struct c_generic_context *g_context;
	struct ip_header_info *outer_ip_flags;
	struct ip_header_info *inner_ip_flags;
	ip_version version;
	bool same_src;
	bool same_dest;
	bool same_src2;
	bool same_dest2;

	g_context = (struct c_generic_context *) context->specific;
	outer_ip_flags = &g_context->outer_ip_flags;
	inner_ip_flags = &g_context->inner_ip_flags;

	/* check the IP version of the first header */
	version = ip_get_version(&packet->outer_ip);
	if(version != outer_ip_flags->version)
	{
		goto bad_context;
	}

	/* compare the addresses of the first header */
	if(version == IPV4)
	{
		same_src = outer_ip_flags->info.v4.old_ip.saddr == ipv4_get_saddr(&packet->outer_ip);
		same_dest = outer_ip_flags->info.v4.old_ip.daddr == ipv4_get_daddr(&packet->outer_ip);
	}
	else /* IPV6 */
	{
		same_src = IPV6_ADDR_CMP(&outer_ip_flags->info.v6.old_ip.ip6_src,
		                         ipv6_get_saddr(&packet->outer_ip));
		same_dest = IPV6_ADDR_CMP(&outer_ip_flags->info.v6.old_ip.ip6_dst,
		                          ipv6_get_daddr(&packet->outer_ip));
	}

	if(!same_src || !same_dest)
	{
		goto bad_context;
	}

	/* compare the Flow Label of the first header if IPv6 */
	if(version == IPV6 && ipv6_get_flow_label(&packet->outer_ip) !=
	   IPV6_GET_FLOW_LABEL(outer_ip_flags->info.v6.old_ip))
	{
		goto bad_context;
	}

	/* check the second IP header */
	if(packet->ip_hdr_nr == 1)
	{
		/* no second IP header: check if the context used not to have a
		 * second header */
		if(g_context->ip_hdr_nr > 1)
		{
			goto bad_context;
		}
	}
	else
	{
		/* second header: check if the context used to have a second IP header */
		if(g_context->ip_hdr_nr == 1)
		{
			goto bad_context;
		}

		/* check the IP version of the second header */
		version = ip_get_version(&packet->inner_ip);
		if(version != inner_ip_flags->version)
		{
			goto bad_context;
		}

		/* compare the addresses of the second header */
		if(version == IPV4)
		{
			same_src2 = inner_ip_flags->info.v4.old_ip.saddr == ipv4_get_saddr(&packet->inner_ip);
			same_dest2 = inner_ip_flags->info.v4.old_ip.daddr == ipv4_get_daddr(&packet->inner_ip);
		}
		else /* IPV6 */
		{
			same_src2 = IPV6_ADDR_CMP(&inner_ip_flags->info.v6.old_ip.ip6_src,
			                          ipv6_get_saddr(&packet->inner_ip));
			same_dest2 = IPV6_ADDR_CMP(&inner_ip_flags->info.v6.old_ip.ip6_dst,
			                           ipv6_get_daddr(&packet->inner_ip));
		}

		if(!same_src2 || !same_dest2)
		{
			goto bad_context;
		}

		/* compare the Flow Label of the second header if IPv6 */
		if(version == IPV6 && ipv6_get_flow_label(&packet->inner_ip) !=
		   IPV6_GET_FLOW_LABEL(inner_ip_flags->info.v6.old_ip))
		{
			goto bad_context;
		}
	}

	/* check the transport protocol */
	if(packet->transport->proto != g_context->next_header_proto)
	{
		goto bad_context;
	}

	return true;

bad_context:
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
rohc_packet_t c_ip_decide_FO_packet(const struct rohc_comp_ctxt *context)
{
	struct c_generic_context *g_context;
	rohc_packet_t packet;

	g_context = (struct c_generic_context *) context->specific;

	if((g_context->outer_ip_flags.version == IPV4 &&
	    g_context->outer_ip_flags.info.v4.sid_count < MAX_FO_COUNT) ||
	   (g_context->ip_hdr_nr > 1 &&
	    g_context->inner_ip_flags.version == IPV4 &&
	    g_context->inner_ip_flags.info.v4.sid_count < MAX_FO_COUNT))
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because at least one "
		                "SID flag changed");
	}
	else if(g_context->tmp.send_static && g_context->tmp.nr_sn_bits <= 13)
	{
		packet = ROHC_PACKET_UOR_2;
		rohc_comp_debug(context, "choose packet UOR-2 because at least one "
		                "static field changed");
	}
	else if(g_context->ip_hdr_nr == 1 && g_context->tmp.send_dynamic > 2)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %d > 2 dynamic "
		                "fields changed with a single IP header",
		                g_context->tmp.send_dynamic);
	}
	else if(g_context->ip_hdr_nr > 1 && g_context->tmp.send_dynamic > 4)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %d > 4 dynamic "
		                "fields changed with double IP header",
		                g_context->tmp.send_dynamic);
	}
	else if(g_context->tmp.nr_sn_bits <= 13)
	{
		/* UOR-2 packet can be used only if SN stand on <= 13 bits (5 bits in
		   base header + 8 bits in extension 3) */
		packet = ROHC_PACKET_UOR_2;
		rohc_comp_debug(context, "choose packet UOR-2 because %zd <= 13 SN "
		                "bits must be transmitted", g_context->tmp.nr_sn_bits);
	}
	else
	{
		/* UOR-2 packet can not be used, use IR-DYN instead */
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %zd > 13 SN "
		                "bits must be transmitted", g_context->tmp.nr_sn_bits);
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
rohc_packet_t c_ip_decide_SO_packet(const struct rohc_comp_ctxt *context)
{
	struct c_generic_context *g_context;
	int nr_of_ip_hdr;
	size_t nr_sn_bits;
	size_t nr_ip_id_bits;
	rohc_packet_t packet;
	int is_rnd;
	int is_ip_v4;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->ip_hdr_nr;
	nr_sn_bits = g_context->tmp.nr_sn_bits;
	nr_ip_id_bits = g_context->tmp.nr_ip_id_bits;
	is_rnd = g_context->outer_ip_flags.info.v4.rnd;
	is_ip_v4 = g_context->outer_ip_flags.version == IPV4;

	rohc_comp_debug(context, "nr_ip_bits = %zd, nr_sn_bits = %zd, "
	                "nr_of_ip_hdr = %d, rnd = %d", nr_ip_id_bits, nr_sn_bits,
	                nr_of_ip_hdr, is_rnd);

	if(nr_of_ip_hdr == 1) /* single IP header */
	{
		if(g_context->outer_ip_flags.version == IPV4)
		{
			assert(g_context->outer_ip_flags.info.v4.sid_count >= MAX_FO_COUNT);
			assert(g_context->outer_ip_flags.info.v4.rnd_count >= MAX_FO_COUNT);
			assert(g_context->outer_ip_flags.info.v4.nbo_count >= MAX_FO_COUNT);
		}

		if(nr_sn_bits <= 4 &&
		   (!is_ip_v4 || (is_ip_v4 && (is_rnd == 1 || nr_ip_id_bits == 0))))
		{
			packet = ROHC_PACKET_UO_0;
			rohc_comp_debug(context, "choose packet UO-0 because %zd <= 4 SN "
			                "bits must be transmitted, and the single IP header "
			                "is either 'non-IPv4' or 'IPv4 with random IP-ID' "
			                "or 'IPv4 with non-random IP-ID but 0 IP-ID bit to "
			                "transmit'", nr_sn_bits);
		}
		else if(nr_sn_bits <= 5 &&
		        is_ip_v4 && is_rnd != 1 && nr_ip_id_bits <= 6)
		{
			packet = ROHC_PACKET_UO_1; /* IPv4 only */
			rohc_comp_debug(context, "choose packet UO-1 because %zd <= 5 SN "
			                "bits must be transmitted, and the single IP header "
			                "is 'IPv4 with non-random IP-ID but %zd <= 6 IP-ID "
			                "bits to transmit'", nr_sn_bits, nr_ip_id_bits);
		}
		else if(nr_sn_bits <= 13)
		{
			/* UOR-2 packet can be used only if SN stand on <= 13 bits (5 bits in
			   base header + 8 bits in extension 3) */
			packet = ROHC_PACKET_UOR_2;
			rohc_comp_debug(context, "choose packet UOR-2 because %zd <= 13 SN "
			                "bits must be transmitted", nr_sn_bits);
		}
		else
		{
			/* UOR-2 packet can not be used, use IR-DYN instead */
			packet = ROHC_PACKET_IR_DYN;
			rohc_comp_debug(context, "choose packet IR-DYN because %zd > 13 SN "
			                "bits must be be transmitted", nr_sn_bits);
		}
	}
	else /* double IP headers */
	{
		const int is_ip2_v4 = (g_context->inner_ip_flags.version == IPV4);
		const int is_rnd2 = g_context->inner_ip_flags.info.v4.rnd;
		const size_t nr_ip_id_bits2 = g_context->tmp.nr_ip_id_bits2;

		if(g_context->outer_ip_flags.version == IPV4)
		{
			assert(g_context->outer_ip_flags.info.v4.sid_count >= MAX_FO_COUNT);
			assert(g_context->outer_ip_flags.info.v4.rnd_count >= MAX_FO_COUNT);
			assert(g_context->outer_ip_flags.info.v4.nbo_count >= MAX_FO_COUNT);
		}
		if(g_context->inner_ip_flags.version == IPV4)
		{
			assert(g_context->inner_ip_flags.info.v4.sid_count >= MAX_FO_COUNT);
			assert(g_context->inner_ip_flags.info.v4.rnd_count >= MAX_FO_COUNT);
			assert(g_context->inner_ip_flags.info.v4.nbo_count >= MAX_FO_COUNT);
		}

		if(nr_sn_bits <= 4 &&
		   (!is_ip_v4 || (is_ip_v4 && (is_rnd == 1 || nr_ip_id_bits == 0))) &&
		   (!is_ip2_v4 || (is_ip2_v4 && (is_rnd2 == 1 || nr_ip_id_bits2 == 0))))
		{
			packet = ROHC_PACKET_UO_0;
			rohc_comp_debug(context, "choose packet UO-0");
		}
		else if(nr_sn_bits <= 5 && (is_ip_v4 && nr_ip_id_bits <= 6) &&
		        (!is_ip2_v4 || (is_ip2_v4 && (is_rnd2 == 1 || nr_ip_id_bits2 == 0))))
		{
			packet = ROHC_PACKET_UO_1; /* IPv4 only for outer header */
			rohc_comp_debug(context, "choose packet UO-1");
		}
		else if(nr_sn_bits <= 13)
		{
			/* UOR-2 packet can be used only if SN stand on <= 13 bits (5 bits in
			   base header + 8 bits in extension 3) */
			packet = ROHC_PACKET_UOR_2;
			rohc_comp_debug(context, "choose packet UOR-2 because %zd <= 13 SN "
			                "bits must be transmitted", nr_sn_bits);
		}
		else
		{
			/* UOR-2 packet can not be used, use IR-DYN instead */
			packet = ROHC_PACKET_IR_DYN;
			rohc_comp_debug(context, "choose packet IR-DYN because %zd > 13 SN "
			                "bits must be transmitted", nr_sn_bits);
		}
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
	struct c_generic_context *g_context;
	uint32_t next_sn;

	g_context = (struct c_generic_context *) context->specific;

	if(g_context->sn == 0xffff)
	{
		next_sn = 0;
	}
	else
	{
		next_sn = g_context->sn + 1;
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
                           unsigned char *const dest,
                           const size_t dest_max_len,
                           const size_t counter)
{
	struct c_generic_context *g_context;
	uint16_t sn;

	assert(context != NULL);
	assert(context->specific != NULL);
	assert(dest != NULL);

	g_context = (struct c_generic_context *) context->specific;

	/* part 1 */
	if((counter + 2) > dest_max_len)
	{
		rohc_comp_warn(context, "ROHC packet too small (%zu bytes max) for the "
		               "2-byte SN in the IR remainder at %zu bytes of the "
		               "beginning of the packet", dest_max_len, counter);
		goto error;
	}
	sn = g_context->sn & 0xffff;
	sn = rohc_hton16(sn);
	memcpy(&dest[counter], &sn, sizeof(uint16_t));
	rohc_comp_debug(context, "SN = %u -> 0x%02x%02x", g_context->sn,
	                dest[counter], dest[counter + 1]);

	return counter + 2;

error:
	return -1;
}


/**
 * @brief Define the compression part of the IP-only profile as described
 *        in the RFC 3843.
 */
const struct rohc_comp_profile c_ip_profile =
{
	.id             = ROHC_PROFILE_IP,     /* profile ID (see 5 in RFC 3843) */
	.protocol       = 0,                   /* IP protocol */
	.create         = rohc_ip_ctxt_create, /* profile handlers */
	.destroy        = c_generic_destroy,
	.check_profile  = c_generic_check_profile,
	.check_context  = c_ip_check_context,
	.encode         = c_generic_encode,
	.reinit_context = c_generic_reinit_context,
	.feedback       = c_generic_feedback,
	.use_udp_port   = c_generic_use_udp_port,
};

