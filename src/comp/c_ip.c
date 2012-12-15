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
 * @file c_ip.c
 * @brief ROHC compression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#include "c_ip.h"
#include "rohc_traces_internal.h"
#include "rohc_utils.h"

#include <string.h>
#include <assert.h>


/**
 * @brief Create a new context and initialize it thanks to the given IP packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP packet given to initialize the new context
 * @return        1 if successful, 0 otherwise
 */
static int rohc_ip_ctxt_create(struct c_context *const context,
                               const struct ip_packet *ip)
{
	const struct rohc_comp *const comp = context->compressor;
	struct c_generic_context *g_context;
	unsigned int ip_proto;

	assert(context != NULL);
	assert(context->profile != NULL);
	assert(ip != NULL);

	/* call the generic function for all IP-based profiles */
	if(!c_generic_create(context, ROHC_LSB_SHIFT_SN, ip))
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "generic context creation failed\n");
		goto error;
	}
	g_context = (struct c_generic_context *) context->specific;

	/* initialize SN to a random value (RFC 3095, 5.11.1) */
	g_context->sn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "initialize context(SN) = random() = %u\n",
	                g_context->sn);

	/* initialize the next header protocol (used later to match the best
	 * IP-only context) */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		struct ip_packet ip2;

		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "cannot create the inner IP header\n");
			goto destroy_generic_context;
		}

		/* get the transport protocol */
		ip_proto = ip_get_protocol(&ip2);
	}

	/* init the IP-only-specific variables and functions */
	g_context->next_header_proto = ip_proto;
	g_context->decide_FO_packet = c_ip_decide_FO_packet;
	g_context->decide_SO_packet = c_ip_decide_SO_packet;
	g_context->decide_extension = decide_extension;
	g_context->get_next_sn = c_ip_get_next_sn;
	g_context->code_ir_remainder = c_ip_code_ir_remainder;

	return 1;

destroy_generic_context:
	c_generic_destroy(context);
error:
	return 0;
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
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones the
 *    context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP packet to check
 * @return        1 if the IP packet belongs to the context,
 *                0 if it does not belong to the context and
 *                -1 if the profile cannot compress it or an error occurs
 */
int c_ip_check_context(const struct c_context *context,
                       const struct ip_packet *ip)
{
	struct c_generic_context *g_context;
	struct ip_header_info *ip_flags;
	struct ip_header_info *ip2_flags;
	struct ip_packet ip2;
	ip_version version;
	unsigned int ip_proto;
	int same_src;
	int same_dest;
	int same_src2;
	int same_dest2;

	g_context = (struct c_generic_context *) context->specific;
	ip_flags = &g_context->ip_flags;
	ip2_flags = &g_context->ip2_flags;

	/* check the IP version of the first header */
	version = ip_get_version(ip);
	if(version != ip_flags->version)
	{
		goto bad_context;
	}

	/* compare the addresses of the first header */
	if(version == IPV4)
	{
		same_src = ip_flags->info.v4.old_ip.saddr == ipv4_get_saddr(ip);
		same_dest = ip_flags->info.v4.old_ip.daddr == ipv4_get_daddr(ip);
	}
	else /* IPV6 */
	{
		same_src = IPV6_ADDR_CMP(&ip_flags->info.v6.old_ip.ip6_src,
		                         ipv6_get_saddr(ip));
		same_dest = IPV6_ADDR_CMP(&ip_flags->info.v6.old_ip.ip6_dst,
		                          ipv6_get_daddr(ip));
	}

	if(!same_src || !same_dest)
	{
		goto bad_context;
	}

	/* compare the Flow Label of the first header if IPv6 */
	if(version == IPV6 && ipv6_get_flow_label(ip) !=
	   IPV6_GET_FLOW_LABEL(ip_flags->info.v6.old_ip))
	{
		goto bad_context;
	}

	/* check the second IP header */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		/* check if the context used to have a second IP header */
		if(!g_context->is_ip2_initialized)
		{
			goto bad_context;
		}

		/* get the second IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "cannot create the inner IP header\n");
			goto error;
		}

		/* check the IP version of the second header */
		version = ip_get_version(&ip2);
		if(version != ip2_flags->version)
		{
			goto bad_context;
		}

		/* compare the addresses of the second header */
		if(version == IPV4)
		{
			same_src2 = ip2_flags->info.v4.old_ip.saddr == ipv4_get_saddr(&ip2);
			same_dest2 = ip2_flags->info.v4.old_ip.daddr == ipv4_get_daddr(&ip2);
		}
		else /* IPV6 */
		{
			same_src2 = IPV6_ADDR_CMP(&ip2_flags->info.v6.old_ip.ip6_src,
			                          ipv6_get_saddr(&ip2));
			same_dest2 = IPV6_ADDR_CMP(&ip2_flags->info.v6.old_ip.ip6_dst,
			                           ipv6_get_daddr(&ip2));
		}

		if(!same_src2 || !same_dest2)
		{
			goto bad_context;
		}

		/* compare the Flow Label of the second header if IPv6 */
		if(version == IPV6 && ipv6_get_flow_label(&ip2) !=
		   IPV6_GET_FLOW_LABEL(ip2_flags->info.v6.old_ip))
		{
			goto bad_context;
		}

		/* get the transport protocol */
		ip_proto = ip_get_protocol(&ip2);
	}
	else /* no second IP header */
	{
		/* check if the context used not to have a second header */
		if(g_context->is_ip2_initialized)
		{
			goto bad_context;
		}
	}

	/* check the transport protocol */
	if(ip_proto != g_context->next_header_proto)
	{
		goto bad_context;
	}

	return 1;

bad_context:
	return 0;
error:
	return -1;
}


/**
 * @brief Decide which packet to send when in First Order (FO) state.
 *
 * Packets that can be used are the IR-DYN and UO-2 packets.
 *
 * @see decide_packet
 *
 * @param context The compression context
 * @return        The packet type among PACKET_IR_DYN and PACKET_UOR_2
 */
rohc_packet_t c_ip_decide_FO_packet(const struct c_context *context)
{
	struct c_generic_context *g_context;
	rohc_packet_t packet;

	g_context = (struct c_generic_context *) context->specific;

	if((g_context->ip_flags.version == IPV4 &&
	    g_context->ip_flags.info.v4.sid_count < MAX_FO_COUNT) ||
	   (g_context->tmp.nr_of_ip_hdr > 1 &&
	    g_context->ip2_flags.version == IPV4 &&
	    g_context->ip2_flags.info.v4.sid_count < MAX_FO_COUNT))
	{
		packet = PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because at least one "
		                "SID flag changed\n");
	}
	else if(g_context->tmp.send_static && g_context->tmp.nr_sn_bits <= 13)
	{
		packet = PACKET_UOR_2;
		rohc_comp_debug(context, "choose packet UOR-2 because at least one "
		                "static field changed\n");
	}
	else if(g_context->tmp.nr_of_ip_hdr == 1 && g_context->tmp.send_dynamic > 2)
	{
		packet = PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %d > 2 dynamic "
		                "fields changed with a single IP header\n",
		                g_context->tmp.send_dynamic);
	}
	else if(g_context->tmp.nr_of_ip_hdr > 1 && g_context->tmp.send_dynamic > 4)
	{
		packet = PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %d > 4 dynamic "
		                "fields changed with double IP header\n",
		                g_context->tmp.send_dynamic);
	}
	else if(g_context->tmp.nr_sn_bits <= 13)
	{
		/* UOR-2 packet can be used only if SN stand on <= 13 bits (5 bits in
		   base header + 8 bits in extension 3) */
		packet = PACKET_UOR_2;
		rohc_comp_debug(context, "choose packet UOR-2 because %zd <= 13 SN "
		                "bits must be transmitted\n", g_context->tmp.nr_sn_bits);
	}
	else
	{
		/* UOR-2 packet can not be used, use IR-DYN instead */
		packet = PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %zd > 13 SN "
		                "bits must be transmitted\n", g_context->tmp.nr_sn_bits);
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
 * @return        The packet type among PACKET_UO_0, PACKET_UO_1 and
 *                PACKET_UOR_2
 */
rohc_packet_t c_ip_decide_SO_packet(const struct c_context *context)
{
	struct c_generic_context *g_context;
	int nr_of_ip_hdr;
	size_t nr_sn_bits;
	size_t nr_ip_id_bits;
	rohc_packet_t packet;
	int is_rnd;
	int is_ip_v4;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp.nr_of_ip_hdr;
	nr_sn_bits = g_context->tmp.nr_sn_bits;
	nr_ip_id_bits = g_context->tmp.nr_ip_id_bits;
	is_rnd = g_context->ip_flags.info.v4.rnd;
	is_ip_v4 = g_context->ip_flags.version == IPV4;

	rohc_comp_debug(context, "nr_ip_bits = %zd, nr_sn_bits = %zd, "
	                "nr_of_ip_hdr = %d, rnd = %d\n", nr_ip_id_bits, nr_sn_bits,
	                nr_of_ip_hdr, is_rnd);

	if(nr_of_ip_hdr == 1) /* single IP header */
	{
		if(g_context->ip_flags.version == IPV4)
		{
			assert(g_context->ip_flags.info.v4.sid_count >= MAX_FO_COUNT);
		}

		if(nr_sn_bits <= 4 &&
		   (!is_ip_v4 || (is_ip_v4 && (is_rnd == 1 || nr_ip_id_bits == 0))))
		{
			packet = PACKET_UO_0;
			rohc_comp_debug(context, "choose packet UO-0 because %zd <= 4 SN "
			                "bits must be transmitted, and the single IP header "
			                "is either 'non-IPv4' or 'IPv4 with random IP-ID' "
			                "or 'IPv4 with non-random IP-ID but 0 IP-ID bit to "
			                "transmit'\n", nr_sn_bits);
		}
		else if(nr_sn_bits <= 5 &&
		        is_ip_v4 && is_rnd != 1 && nr_ip_id_bits <= 6)
		{
			packet = PACKET_UO_1; /* IPv4 only */
			rohc_comp_debug(context, "choose packet UO-1 because %zd <= 5 SN "
			                "bits must be transmitted, and the single IP header "
			                "is 'IPv4 with non-random IP-ID but %zd <= 6 IP-ID "
			                "bits to transmit'\n", nr_sn_bits, nr_ip_id_bits);
		}
		else if(nr_sn_bits <= 13)
		{
			/* UOR-2 packet can be used only if SN stand on <= 13 bits (5 bits in
			   base header + 8 bits in extension 3) */
			packet = PACKET_UOR_2;
			rohc_comp_debug(context, "choose packet UOR-2 because %zd <= 13 SN "
			                "bits must be transmitted\n", nr_sn_bits);
		}
		else
		{
			/* UOR-2 packet can not be used, use IR-DYN instead */
			packet = PACKET_IR_DYN;
			rohc_comp_debug(context, "choose packet IR-DYN because %zd > 13 SN "
			                "bits must be be transmitted\n", nr_sn_bits);
		}
	}
	else /* double IP headers */
	{
		const int is_ip2_v4 = (g_context->ip2_flags.version == IPV4);
		const int is_rnd2 = g_context->ip2_flags.info.v4.rnd;
		const size_t nr_ip_id_bits2 = g_context->tmp.nr_ip_id_bits2;

		if(g_context->ip_flags.version == IPV4)
		{
			assert(g_context->ip_flags.info.v4.sid_count >= MAX_FO_COUNT);
		}
		if(g_context->ip2_flags.version == IPV4)
		{
			assert(g_context->ip2_flags.info.v4.sid_count >= MAX_FO_COUNT);
		}

		if(nr_sn_bits <= 4 &&
		   (!is_ip_v4 || (is_ip_v4 && (is_rnd == 1 || nr_ip_id_bits == 0))) &&
		   (!is_ip2_v4 || (is_ip2_v4 && (is_rnd2 == 1 || nr_ip_id_bits2 == 0))))
		{
			packet = PACKET_UO_0;
			rohc_comp_debug(context, "choose packet UO-0\n");
		}
		else if(nr_sn_bits <= 5 && (is_ip_v4 && nr_ip_id_bits <= 6) &&
		        (!is_ip2_v4 || (is_ip2_v4 && (is_rnd2 == 1 || nr_ip_id_bits2 == 0))))
		{
			packet = PACKET_UO_1; /* IPv4 only for outer header */
			rohc_comp_debug(context, "choose packet UO-1\n");
		}
		else if(nr_sn_bits <= 13)
		{
			/* UOR-2 packet can be used only if SN stand on <= 13 bits (5 bits in
			   base header + 8 bits in extension 3) */
			packet = PACKET_UOR_2;
			rohc_comp_debug(context, "choose packet UOR-2 because %zd <= 13 SN "
			                "bits must be transmitted\n", nr_sn_bits);
		}
		else
		{
			/* UOR-2 packet can not be used, use IR-DYN instead */
			packet = PACKET_IR_DYN;
			rohc_comp_debug(context, "choose packet IR-DYN because %zd > 13 SN "
			                "bits must be transmitted\n", nr_sn_bits);
		}
	}

	return packet;
}


/**
 * @brief Determine the SN value for the next packet
 *
 * Profile SN is an internal increasing 16-bit number.
 *
 * @param context   The compression context
 * @param outer_ip  The outer IP header
 * @param inner_ip  The inner IP header if it exists, NULL otherwise
 * @return          The SN
 */
uint32_t c_ip_get_next_sn(const struct c_context *context,
                          const struct ip_packet *outer_ip,
                          const struct ip_packet *inner_ip)
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
 * @param context  The compression context
 * @param dest     The rohc-packet-under-build buffer
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer
 */
int c_ip_code_ir_remainder(const struct c_context *context,
	                        unsigned char *const dest,
	                        int counter)
{
	struct c_generic_context *g_context;
	uint16_t sn;

	assert(context != NULL);
	assert(context->specific != NULL);
	assert(dest != NULL);

	g_context = (struct c_generic_context *) context->specific;

	/* part 1 */
	sn = g_context->sn & 0xffff;
	sn = htons(sn);
	memcpy(&dest[counter], &sn, sizeof(uint16_t));
	counter += 2;
	rohc_comp_debug(context, "SN = %u -> 0x%02x%02x\n", g_context->sn,
	                dest[counter - 2], dest[counter - 1]);

	return counter;
}


/**
 * @brief Define the compression part of the IP-only profile as described
 *        in the RFC 3843.
 */
struct c_profile c_ip_profile =
{
	0,                  /* IP protocol */
	ROHC_PROFILE_IP,    /* profile ID (see 5 in RFC 3843) */
	"IP / Compressor",  /* profile description */
	rohc_ip_ctxt_create,
	c_generic_destroy,
	c_generic_check_profile,
	c_ip_check_context,
	c_generic_encode,
	c_generic_reinit_context,
	c_generic_feedback,
	c_generic_use_udp_port,
};

