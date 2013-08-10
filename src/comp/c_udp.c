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
 * @file c_udp.c
 * @brief ROHC compression context for the UDP profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#include "c_udp.h"
#include "c_ip.h"
#include "rohc_traces_internal.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "crc.h"
#include "c_generic.h"
#include "protocols/udp.h"

#include <stdlib.h>
#ifndef __KERNEL__
#	include <string.h>
#endif
#include <assert.h>


/**
 * @brief Define the UDP-specific temporary variables in the profile
 *        compression context.
 *
 * This object must be used by the UDP-specific decompression context
 * sc_udp_context.
 *
 * @see sc_udp_context
 */
struct udp_tmp_vars
{
	/** The number of UDP fields that changed in the UDP header */
	int send_udp_dynamic;
};


/**
 * @brief Define the UDP part of the profile decompression context.
 *
 * This object must be used with the generic part of the decompression
 * context c_generic_context.
 *
 * @see c_generic_context
 */
struct sc_udp_context
{
	/** @brief The number of times the checksum field was added to the
	 *         compressed header */
	int udp_checksum_change_count;

	/** The previous UDP header */
	struct udphdr old_udp;

	/** @brief UDP-specific temporary variables that are used during one single
	 *         compression of packet */
	struct udp_tmp_vars tmp;
};


/*
 * Private function prototypes.
 */

static int c_udp_create(struct c_context *const context,
                        const struct ip_packet *ip);

static void udp_decide_state(struct c_context *const context);

static int c_udp_encode(struct c_context *const context,
                        const struct ip_packet *ip,
                        const size_t packet_size,
                        unsigned char *const dest,
                        const size_t dest_size,
                        rohc_packet_t *const packet_type,
                        int *const payload_offset);

static int udp_code_dynamic_udp_part(const struct c_context *context,
                                     const unsigned char *next_header,
                                     unsigned char *const dest,
                                     int counter);

static int udp_changed_udp_dynamic(const struct c_context *context,
                                   const struct udphdr *udp);


/**
 * @brief Create a new UDP context and initialize it thanks to the given IP/UDP
 *        packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/UDP packet given to initialize the new context
 * @return        1 if successful, 0 otherwise
 */
static int c_udp_create(struct c_context *const context,
                        const struct ip_packet *ip)
{
	const struct rohc_comp *const comp = context->compressor;
	struct c_generic_context *g_context;
	struct sc_udp_context *udp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	unsigned int ip_proto;

	assert(context != NULL);
	assert(context->profile != NULL);
	assert(ip != NULL);

	/* create and initialize the generic part of the profile context */
	if(!c_generic_create(context, ROHC_LSB_SHIFT_SN, ip))
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "generic context creation failed\n");
		goto quit;
	}
	g_context = (struct c_generic_context *) context->specific;

	/* initialize SN to a random value (RFC 3095, 5.11.1) */
	g_context->sn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "initialize context(SN) = random() = %u\n",
	                g_context->sn);

	/* check if packet is IP/UDP or IP/IP/UDP */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "cannot create the inner IP header\n");
			goto clean;
		}

		/* two IP headers, the last IP header is the second one */
		last_ip_header = &ip2;

		/* get the transport protocol */
		ip_proto = ip_get_protocol(last_ip_header);
	}
	else
	{
		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	if(ip_proto != ROHC_IPPROTO_UDP)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "next header is not UDP (%d), cannot use this profile\n",
		             ip_proto);
		goto clean;
	}

	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);

	/* create the UDP part of the profile context */
	udp_context = malloc(sizeof(struct sc_udp_context));
	if(udp_context == NULL)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "no memory for the UDP part of the profile context\n");
		goto clean;
	}
	g_context->specific = udp_context;

	/* initialize the UDP part of the profile context */
	udp_context->udp_checksum_change_count = 0;
	memcpy(&udp_context->old_udp, udp, sizeof(struct udphdr));

	/* init the UDP-specific temporary variables */
	udp_context->tmp.send_udp_dynamic = -1;

	/* init the UDP-specific variables and functions */
	g_context->next_header_proto = ROHC_IPPROTO_UDP;
	g_context->next_header_len = sizeof(struct udphdr);
	g_context->decide_state = udp_decide_state;
	g_context->decide_FO_packet = c_ip_decide_FO_packet;
	g_context->decide_SO_packet = c_ip_decide_SO_packet;
	g_context->decide_extension = decide_extension;
	g_context->init_at_IR = NULL;
	g_context->get_next_sn = c_ip_get_next_sn;
	g_context->code_static_part = udp_code_static_udp_part;
	g_context->code_dynamic_part = udp_code_dynamic_udp_part;
	g_context->code_ir_remainder = c_ip_code_ir_remainder;
	g_context->code_UO_packet_head = NULL;
	g_context->code_uo_remainder = udp_code_uo_remainder;
	g_context->compute_crc_static = udp_compute_crc_static;
	g_context->compute_crc_dynamic = udp_compute_crc_dynamic;

	return 1;

clean:
	c_generic_destroy(context);
quit:
	return 0;
}


/**
 * @brief Check if the given packet corresponds to the UDP profile
 *
 * Conditions are:
 *  \li the transport protocol is UDP
 *  \li the version of the outer IP header is 4 or 6
 *  \li the outer IP header is not an IP fragment
 *  \li if there are at least 2 IP headers, the version of the inner IP header
 *      is 4 or 6
 *  \li if there are at least 2 IP headers, the inner IP header is not an IP
 *      fragment
 *  \li the inner IP payload is at least 8-byte long for UDP header
 *  \li the UDP Length field and the UDP payload match
 *
 * @see c_generic_check_profile
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param comp      The ROHC compressor
 * @param outer_ip  The outer IP header of the IP packet to check
 * @param inner_ip  Two possible cases:
 *                    \li The inner IP header of the IP packet to check if the IP
 *                        packet contains at least 2 IP headers,
 *                    \li NULL if the IP packet to check contains only one IP header
 * @param protocol  The transport protocol carried by the IP packet:
 *                    \li the protocol carried by the outer IP header if there
 *                        is only one IP header,
 *                    \li the protocol carried by the inner IP header if there
 *                        are at least two IP headers.
 * @param ctxt_key  The key to help finding the context associated with packet
 * @return          Whether the IP packet corresponds to the profile:
 *                    \li true if the IP packet corresponds to the profile,
 *                    \li false if the IP packet does not correspond to
 *                        the profile
 */
bool c_udp_check_profile(const struct rohc_comp *const comp,
                         const struct ip_packet *const outer_ip,
                         const struct ip_packet *const inner_ip,
                         const uint8_t protocol,
                         rohc_ctxt_key_t *const ctxt_key)
{
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp_header;
	unsigned int ip_payload_size;
	bool ip_check;

	assert(comp != NULL);
	assert(outer_ip != NULL);
	assert(ctxt_key != NULL);

	/* check that the transport protocol is UDP */
	if(protocol != ROHC_IPPROTO_UDP)
	{
		goto bad_profile;
	}

	/* check that the the versions of outer and inner IP headers are 4 or 6
	   and that outer and inner IP headers are not IP fragments */
	ip_check = c_generic_check_profile(comp, outer_ip, inner_ip, protocol,
	                                   ctxt_key);
	if(!ip_check)
	{
		goto bad_profile;
	}

	/* determine the last IP header */
	if(inner_ip != NULL)
	{
		/* two IP headers, the last IP header is the inner IP header */
		last_ip_header = inner_ip;
	}
	else
	{
		/* only one IP header, last IP header is the outer IP header */
		last_ip_header = outer_ip;
	}

	/* IP payload shall be large enough for UDP header */
	ip_payload_size = ip_get_plen(last_ip_header);
	if(ip_payload_size < sizeof(struct udphdr))
	{
		goto bad_profile;
	}

	/* retrieve the UDP header */
	udp_header = (const struct udphdr *) ip_get_next_layer(last_ip_header);
	if(ip_payload_size != rohc_ntoh16(udp_header->len))
	{
		goto bad_profile;
	}
	*ctxt_key ^= udp_header->source;
	*ctxt_key ^= udp_header->dest;

	return true;

bad_profile:
	return false;
}


/**
 * @brief Check if the IP/UDP packet belongs to the context
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of the two IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match the
 *    ones in the context
 *  - the transport protocol must be UDP
 *  - the source and destination ports of the UDP header must match the ones in
 *    the context
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones the
 *    context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/UDP packet to check
 * @return        true if the IP/UDP packet belongs to the context
 *                false if it does not belong to the context
 */
bool c_udp_check_context(const struct c_context *context,
                         const struct ip_packet *ip)
{
	struct c_generic_context *g_context;
	struct sc_udp_context *udp_context;
	struct ip_header_info *ip_flags;
	struct ip_header_info *ip2_flags;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	ip_version version;
	unsigned int ip_proto;
	bool is_ip_same;
	bool is_ip2_same;
	bool is_udp_same;

	g_context = (struct c_generic_context *) context->specific;
	udp_context = (struct sc_udp_context *) g_context->specific;
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
		is_ip_same = ip_flags->info.v4.old_ip.saddr == ipv4_get_saddr(ip) &&
		             ip_flags->info.v4.old_ip.daddr == ipv4_get_daddr(ip);
	}
	else /* IPV6 */
	{
		is_ip_same =
			IPV6_ADDR_CMP(&ip_flags->info.v6.old_ip.ip6_src, ipv6_get_saddr(ip)) &&
			IPV6_ADDR_CMP(&ip_flags->info.v6.old_ip.ip6_dst, ipv6_get_daddr(ip));
	}

	if(!is_ip_same)
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
			goto bad_context;
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
			is_ip2_same = ip2_flags->info.v4.old_ip.saddr == ipv4_get_saddr(&ip2) &&
			              ip2_flags->info.v4.old_ip.daddr == ipv4_get_daddr(&ip2);
		}
		else /* IPV6 */
		{
			is_ip2_same = IPV6_ADDR_CMP(&ip2_flags->info.v6.old_ip.ip6_src,
			                            ipv6_get_saddr(&ip2)) &&
			              IPV6_ADDR_CMP(&ip2_flags->info.v6.old_ip.ip6_dst,
			                            ipv6_get_daddr(&ip2));
		}

		if(!is_ip2_same)
		{
			goto bad_context;
		}

		/* compare the Flow Label of the second header if IPv6 */
		if(version == IPV6 && ipv6_get_flow_label(&ip2) !=
		   IPV6_GET_FLOW_LABEL(ip2_flags->info.v6.old_ip))
		{
			goto bad_context;
		}

		/* get the last IP header */
		last_ip_header = &ip2;

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

		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	/* check the transport protocol */
	if(ip_proto != ROHC_IPPROTO_UDP)
	{
		goto bad_context;
	}

	/* check UDP ports */
	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);
	is_udp_same = udp_context->old_udp.source == udp->source &&
	              udp_context->old_udp.dest == udp->dest;

	return is_udp_same;

bad_context:
	return false;
}


/**
 * @brief Encode an IP/UDP packet according to a pattern decided by several
 *        different factors.
 *
 * @param context        The compression context
 * @param ip             The IP packet to encode
 * @param packet_size    The length of the IP packet to encode
 * @param dest           The rohc-packet-under-build buffer
 * @param dest_size      The length of the rohc-packet-under-build buffer
 * @param packet_type    OUT: The type of ROHC packet that is created
 * @param payload_offset The offset for the payload in the IP packet
 * @return               The length of the created ROHC packet
 *                       or -1 in case of failure
 */
static int c_udp_encode(struct c_context *const context,
                        const struct ip_packet *ip,
                        const size_t packet_size,
                        unsigned char *const dest,
                        const size_t dest_size,
                        rohc_packet_t *const packet_type,
                        int *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_udp_context *udp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	unsigned int ip_proto;
	size_t ip_hdrs_len;
	int size;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	udp_context = (struct sc_udp_context *) g_context->specific;

	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "cannot create the inner IP header\n");
			return -1;
		}
		last_ip_header = &ip2;

		/* get the transport protocol */
		ip_proto = ip_get_protocol(last_ip_header);
	}
	else
	{
		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	if(ip_proto != ROHC_IPPROTO_UDP)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "packet is not an UDP packet\n");
		return -1;
	}
	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);

	/* check that UDP length is correct (we have to discard all packets with
	 * wrong UDP length fields, otherwise the ROHC decompressor will compute
	 * a different UDP length on its side) */
	ip_hdrs_len = ((unsigned char *) udp) - ip->data;
	if(rohc_ntoh16(udp->len) != (packet_size - ip_hdrs_len))
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "wrong UDP Length field in UDP header: %u found while "
		             "%zd expected\n", rohc_ntoh16(udp->len),
		             packet_size - ip_hdrs_len);
		return -1;
	}

	/* how many UDP fields changed? */
	udp_context->tmp.send_udp_dynamic = udp_changed_udp_dynamic(context, udp);

	/* encode the IP packet */
	size = c_generic_encode(context, ip, packet_size, dest, dest_size,
	                        packet_type, payload_offset);
	if(size < 0)
	{
		goto quit;
	}

	/* update the context with the new UDP header */
	if(g_context->tmp.packet_type == PACKET_IR ||
	   g_context->tmp.packet_type == PACKET_IR_DYN)
	{
		memcpy(&udp_context->old_udp, udp, sizeof(struct udphdr));
	}

quit:
	return size;
}


/**
 * @brief Decide the state that should be used for the next packet compressed
 *        with the ROHC UDP profile.
 *
 * The three states are:
 *  - Initialization and Refresh (IR),
 *  - First Order (FO),
 *  - Second Order (SO).
 *
 * @param context The compression context
 */
static void udp_decide_state(struct c_context *const context)
{
	struct c_generic_context *g_context;
	struct sc_udp_context *udp_context;

	g_context = (struct c_generic_context *) context->specific;
	udp_context = (struct sc_udp_context *) g_context->specific;

	if(udp_context->tmp.send_udp_dynamic)
	{
		rohc_comp_debug(context, "go back to IR state because UDP checksum "
		                "behaviour changed in the last few packets\n");
		change_state(context, IR);
	}
	else
	{
		/* generic function used by the IP-only, UDP and UDP-Lite profiles */
		decide_state(context);
	}
}


/**
 * @brief Build UDP-related fields in the tail of the UO packets.
 *
 * \verbatim

     --- --- --- --- --- --- --- ---
    :                               :
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The UDP header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
int udp_code_uo_remainder(const struct c_context *context,
                          const unsigned char *next_header,
                          unsigned char *const dest,
                          int counter)
{
	const struct udphdr *udp = (struct udphdr *) next_header;

	/* part 13 */
	if(udp->check != 0)
	{
		rohc_comp_debug(context, "UDP checksum = 0x%x\n", udp->check);
		memcpy(&dest[counter], &udp->check, 2);
		counter += 2;
	}

	return counter;
}


/**
 * @brief Build the static part of the UDP header.
 *
 * \verbatim

 Static part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /          Source Port          /   2 octets
    +---+---+---+---+---+---+---+---+
 2  /       Destination Port        /   2 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The UDP header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
int udp_code_static_udp_part(const struct c_context *context,
                             const unsigned char *next_header,
                             unsigned char *const dest,
                             int counter)
{
	const struct udphdr *udp = (struct udphdr *) next_header;

	/* part 1 */
	rohc_comp_debug(context, "UDP source port = 0x%x\n", udp->source);
	memcpy(&dest[counter], &udp->source, 2);
	counter += 2;

	/* part 2 */
	rohc_comp_debug(context, "UDP dest port = 0x%x\n", udp->dest);
	memcpy(&dest[counter], &udp->dest, 2);
	counter += 2;

	return counter;
}


/**
 * @brief Build the dynamic part of the UDP header.
 *
 * \verbatim

 Dynamic part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /           Checksum            /   2 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The UDP header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static int udp_code_dynamic_udp_part(const struct c_context *context,
                                     const unsigned char *next_header,
                                     unsigned char *const dest,
                                     int counter)
{
	struct c_generic_context *g_context;
	struct sc_udp_context *udp_context;
	const struct udphdr *udp;

	g_context = (struct c_generic_context *) context->specific;
	udp_context = (struct sc_udp_context *) g_context->specific;

	udp = (struct udphdr *) next_header;

	/* part 1 */
	rohc_comp_debug(context, "UDP checksum = 0x%x\n", udp->check);
	memcpy(&dest[counter], &udp->check, 2);
	counter += 2;
	udp_context->udp_checksum_change_count++;

	return counter;
}


/**
 * @brief Check if the dynamic part of the UDP header changed.
 *
 * @param context The compression context
 * @param udp     The UDP header
 * @return        The number of UDP fields that changed
 */
static int udp_changed_udp_dynamic(const struct c_context *context,
                                   const struct udphdr *udp)
{
	const struct c_generic_context *g_context;
	struct sc_udp_context *udp_context;

	g_context = (struct c_generic_context *) context->specific;
	udp_context = (struct sc_udp_context *) g_context->specific;

	if((udp->check != 0 && udp_context->old_udp.check == 0) ||
	   (udp->check == 0 && udp_context->old_udp.check != 0) ||
	   (udp_context->udp_checksum_change_count < MAX_IR_COUNT))
	{
		if((udp->check != 0 && udp_context->old_udp.check == 0) ||
		   (udp->check == 0 && udp_context->old_udp.check != 0))
		{
			udp_context->udp_checksum_change_count = 0;
		}
		return 1;
	}
	else
	{
		return 0;
	}
}


/**
 * @brief Define the compression part of the UDP profile as described
 *        in the RFC 3095.
 */
struct c_profile c_udp_profile =
{
	ROHC_IPPROTO_UDP,    /* IP protocol */
	ROHC_PROFILE_UDP,    /* profile ID (see 8 in RFC 3095) */
	"UDP / Compressor",  /* profile description */
	c_udp_create,        /* profile handlers */
	c_generic_destroy,
	c_udp_check_profile,
	c_udp_check_context,
	c_udp_encode,
	c_generic_reinit_context,
	c_generic_feedback,
	c_generic_use_udp_port,
};

