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
 * @file c_udp_lite.h
 * @brief ROHC compression context for the UDP-Lite profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#include "c_udp_lite.h"
#include "c_udp.h"
#include "c_ip.h"
#include "rohc_traces_internal.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "crc.h"
#include "c_generic.h"
#include "protocols/udp_lite.h"

#include <stdlib.h>
#ifndef __KERNEL__
#	include <string.h>
#endif
#include <assert.h>


/// @brief The maximal number of times the checksum coverage dit not change
///        or may be inferred
#define MAX_LITE_COUNT 2


/**
 * @brief Define the UDP-Lite-specific temporary variables in the profile
 *        compression context.
 *
 * This object must be used by the UDP-specific compression context
 * sc_udp_lite_context.
 *
 * @see sc_udp_lite_context
 */
struct udp_lite_tmp_vars
{
	/// The size of the UDP-Lite packet (header + payload)
	int udp_size;
};


/**
 * @brief Define the UDP-Lite part of the profile compression context.
 *
 * This object must be used with the generic part of the compression
 * context c_generic_context.
 *
 * @see c_generic_context
 */
struct sc_udp_lite_context
{
	/// Whether the Coverage Field is Present or not
	int cfp;
	/// Whether the Coverage Field is Inferred or not
	int cfi;

	/// The F and K bits in the CCE packet (see appendix B in the RFC 4019)
	unsigned char FK;

	/// The number of times the checksum coverage field did not change
	int coverage_equal_count;
	/// The number of times the checksum coverage field may be inferred
	int coverage_inferred_count;
	/// Temporary variables related to the checksum coverage field
	int tmp_coverage;

	/// The number of CCE() packets sent by the compressor
	int sent_cce_only_count;
	/// The number of CCE(ON) packets sent by the compressor
	int sent_cce_on_count;
	/// The number of CCE(OFF) packets sent by the compressor
	int sent_cce_off_count;

	/// The previous UDP-Lite header
	struct udphdr old_udp_lite;

	/// @brief UDP-Lite-specific temporary variables that are used during one
	///        single compression of packet
	struct udp_lite_tmp_vars tmp;
};



/*
 * Private function prototypes.
 */

static bool c_udp_lite_create(struct c_context *const context,
                              const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool c_udp_lite_check_profile(const struct rohc_comp *const comp,
                                     const struct ip_packet *const outer_ip,
                                     const struct ip_packet *const inner_ip,
                                     const uint8_t protocol,
                                     rohc_ctxt_key_t *const ctxt_key)
		__attribute__((warn_unused_result, nonnull(1, 2, 5)));

static bool c_udp_lite_check_context(const struct c_context *const context,
                                     const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int c_udp_lite_encode(struct c_context *const context,
                             const struct ip_packet *ip,
                             const size_t packet_size,
                             unsigned char *const dest,
                             const size_t dest_size,
                             rohc_packet_t *const packet_type,
                             int *const payload_offset);

static size_t udp_lite_code_dynamic_udplite_part(const struct c_context *const context,
                                                 const unsigned char *const next_header,
                                                 unsigned char *const dest,
                                                 const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static size_t udp_lite_build_cce_packet(const struct c_context *const context,
                                        const unsigned char *const next_header,
                                        unsigned char *const dest,
                                        size_t counter,
                                        size_t *const first_position)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static bool udp_lite_send_cce_packet(const struct c_context *const context,
                                     const struct udphdr *const udp_lite)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static size_t udp_lite_code_uo_remainder(const struct c_context *const context,
                                         const unsigned char *const next_header,
                                         unsigned char *const dest,
                                         const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static void udp_lite_init_cc(const struct c_context *context,
                             const unsigned char *next_header);



/**
 * @brief Create a new UDP-Lite context and initialize it thanks to the given
 *        IP/UDP-Lite packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/UDP-Lite packet given to initialize the new context
 * @return        true if successful, false otherwise
 */
static bool c_udp_lite_create(struct c_context *const context,
                              const struct ip_packet *const ip)
{
	const struct rohc_comp *const comp = context->compressor;
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp_lite;
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

	/* check if packet is IP/UDP-Lite or IP/IP/UDP-Lite */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "cannot create the inner IP header\n");
			goto quit;
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

	if(ip_proto != ROHC_IPPROTO_UDPLITE)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "next header is not UDP-Lite (%d), cannot use this "
		             "profile\n", ip_proto);
		goto clean;
	}

	udp_lite = (struct udphdr *) ip_get_next_layer(last_ip_header);

	/* create the UDP-Lite part of the profile context */
	udp_lite_context = malloc(sizeof(struct sc_udp_lite_context));
	if(udp_lite_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the UDP-Lite part of the profile context\n");
		goto clean;
	}
	g_context->specific = udp_lite_context;

	/* initialize the UDP-Lite part of the profile context */
	udp_lite_context->cfp = 0;
	udp_lite_context->cfi = 0;
	udp_lite_context->FK = 0;
	udp_lite_context->coverage_equal_count = 0;
	udp_lite_context->coverage_inferred_count = 0;
	udp_lite_context->sent_cce_only_count = 0;
	udp_lite_context->sent_cce_on_count = MAX_IR_COUNT;
	udp_lite_context->sent_cce_off_count = MAX_IR_COUNT;
	memcpy(&udp_lite_context->old_udp_lite, udp_lite, sizeof(struct udphdr));

	/* init the UDP-Lite-specific temporary variables */
	udp_lite_context->tmp.udp_size = -1;

	/* init the UDP-Lite-specific variables and functions */
	g_context->next_header_proto = ROHC_IPPROTO_UDPLITE;
	g_context->next_header_len = sizeof(struct udphdr);
	g_context->decide_state = decide_state;
	g_context->decide_FO_packet = c_ip_decide_FO_packet;
	g_context->decide_SO_packet = c_ip_decide_SO_packet;
	g_context->decide_extension = decide_extension;
	g_context->init_at_IR = udp_lite_init_cc;
	g_context->get_next_sn = c_ip_get_next_sn;
	g_context->code_static_part = udp_code_static_udp_part; /* same as UDP */
	g_context->code_dynamic_part = udp_lite_code_dynamic_udplite_part;
	g_context->code_ir_remainder = c_ip_code_ir_remainder;
	g_context->code_UO_packet_head = udp_lite_build_cce_packet;
	g_context->code_uo_remainder = udp_lite_code_uo_remainder;
	g_context->compute_crc_static = udp_compute_crc_static;
	g_context->compute_crc_dynamic = udp_compute_crc_dynamic;

	return true;

clean:
	c_generic_destroy(context);
quit:
	return false;
}


/**
 * @brief Check if the given packet corresponds to the UDP-Lite profile
 *
 * Conditions are:
 *  \li the transport protocol is UDP-Lite
 *  \li the version of the outer IP header is 4 or 6
 *  \li the outer IP header is not an IP fragment
 *  \li if there are at least 2 IP headers, the version of the inner IP header
 *      is 4 or 6
 *  \li if there are at least 2 IP headers, the inner IP header is not an IP
 *      fragment
 *
 * @see c_generic_check_profile
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param comp      The ROHC compressor
 * @param outer_ip  The outer IP header of the IP packet to check
 * @param inner_ip  \li The inner IP header of the IP packet to check if the IP
 *                      packet contains at least 2 IP headers,
 *                  \li NULL if the IP packet to check contains only one IP header
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
static bool c_udp_lite_check_profile(const struct rohc_comp *const comp,
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

	/* check that the transport protocol is UDP-Lite */
	if(protocol != ROHC_IPPROTO_UDPLITE)
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

	/* retrieve the UDP-Lite header */
	udp_header = (const struct udphdr *) ip_get_next_layer(last_ip_header);
	*ctxt_key ^= udp_header->source;
	*ctxt_key ^= udp_header->dest;

	return true;

bad_profile:
	return false;
}


/**
 * @brief Check if the IP/UDP-Lite packet belongs to the context
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of the two IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match the
 *    ones in the context
 *  - the transport protocol must be UDP-Lite
 *  - the source and destination ports of the UDP-Lite header must match the
 *    ones in the context
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones the
 *    context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/UDP-Lite packet to check
 * @return        true if the IP/UDP-Lite packet belongs to the context,
 *                false if it does not belong to the context
 */
static bool c_udp_lite_check_context(const struct c_context *const context,
                                     const struct ip_packet *const ip)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	struct ip_header_info *ip_flags;
	struct ip_header_info *ip2_flags;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp_lite;
	ip_version version;
	unsigned int ip_proto;
	bool is_ip_same;
	bool is_ip2_same;
	bool is_udp_lite_same;

	g_context = (struct c_generic_context *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;
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
	if(ip_proto != ROHC_IPPROTO_UDPLITE)
	{
		goto bad_context;
	}

	/* check UDP-Lite ports */
	udp_lite = (struct udphdr *) ip_get_next_layer(last_ip_header);
	is_udp_lite_same =
		udp_lite_context->old_udp_lite.source == udp_lite->source &&
		udp_lite_context->old_udp_lite.dest == udp_lite->dest;

	return is_udp_lite_same;

bad_context:
	return false;
}


/**
 * @brief Encode an IP/UDP-lite packet according to a pattern decided by several
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
static int c_udp_lite_encode(struct c_context *const context,
                             const struct ip_packet *ip,
                             const size_t packet_size,
                             unsigned char *const dest,
                             const size_t dest_size,
                             rohc_packet_t *const packet_type,
                             int *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp_lite;
	unsigned int ip_proto;
	int size;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;
	udp_lite_context->tmp.udp_size = packet_size - ip_get_hdrlen(ip);

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

		/* update the UDP-Lite payload size */
		udp_lite_context->tmp.udp_size -= ip_get_hdrlen(last_ip_header);
	}
	else
	{
		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	if(ip_proto != ROHC_IPPROTO_UDPLITE)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "packet is not an UDP-Lite packet\n");
		return -1;
	}
	udp_lite = (struct udphdr *) ip_get_next_layer(last_ip_header);

	/* encode the IP packet */
	size = c_generic_encode(context, ip, packet_size, dest, dest_size,
	                        packet_type, payload_offset);
	if(size < 0)
	{
		goto quit;
	}

	/* update the context with the new UDP-Lite header */
	if(g_context->tmp.packet_type == PACKET_IR ||
	   g_context->tmp.packet_type == PACKET_IR_DYN)
	{
		memcpy(&udp_lite_context->old_udp_lite, udp_lite, sizeof(struct udphdr));
	}

quit:
	return size;
}


/**
 * @brief Build the Checksum Coverage Extension (CCE) packet.
 *
 * The Checksum Coverage Extension is located at the very start of the UO
 * packet (part 2 in the following figure).
 *
 * \verbatim

     0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :  If for small CIDs and CID 1 - 15
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   0   F | K |  Outer packet type identifier
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /   0, 1, or 2 octets of CID    /  1 - 2 octets if large CIDs
    :                               :
    +---+---+---+---+---+---+---+---+
    :                               :
 4  /   UO-0, UO-1 or UO-2 packet   /
    :                               :
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 1, 3 and 4 are coded by the generic code_UO0_packet, code_UO1_packet
 * and code_UO2_packet functions. These functions call the code_UO_packet_head
 * function which in case of UDP-Lite profile is the udp_lite_build_cce_packet
 * function.
 *
 * When the udp_lite_build_cce_packet is called, the parameter first_position
 * points on the part 2 and the parameter counter points on the beginning of
 * the part 4.
 *
 * @param context        The compression context
 * @param next_header    The UDP header
 * @param dest           The rohc-packet-under-build buffer
 * @param counter        The current position in the rohc-packet-under-build buffer
 * @param first_position The position to place the first byte of packet
 * @return               The new position in the rohc-packet-under-build buffer
 */
static size_t udp_lite_build_cce_packet(const struct c_context *const context,
                                        const unsigned char *const next_header,
                                        unsigned char *const dest,
                                        const size_t counter,
                                        size_t *const first_position)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	const struct udphdr *const udp_lite = (struct udphdr *) next_header;
	size_t nr_written = 0;
	bool send_cce_packet;

	g_context = (struct c_generic_context *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;


	/* do we need to add the CCE packet? */
	send_cce_packet = udp_lite_send_cce_packet(context, udp_lite);
	if(send_cce_packet)
	{
		rohc_comp_debug(context, "adding CCE\n");

		/* part 2 */
		dest[*first_position] = (0xf8 | udp_lite_context->FK);

		/* now first_position must point on the first byte of the part 4
		 * and counter must point on the second byte of the part 4 */
		*first_position = counter;
		nr_written++;
	}
	else
	{
		rohc_comp_debug(context, "CCE not needed\n");
	}

	return counter + nr_written;
}


/**
 * @brief Build UDP-Lite-related fields in the tail of the UO packets.
 *
 * \verbatim

     --- --- --- --- --- --- --- ---
    :                               :  2 octets,
 1  +  UDP-Lite Checksum Coverage   +  if context(CFP) = 1 or
    :                               :  if packet type = CCE
     --- --- --- --- --- --- --- ---
    :                               :
 2  +       UDP-Lite Checksum       +  2 octets
    :                               :
     --- --- --- --- --- --- --- ---

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The UDP-Lite header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static size_t udp_lite_code_uo_remainder(const struct c_context *const context,
                                         const unsigned char *const next_header,
                                         unsigned char *const dest,
                                         const size_t counter)
{
	const struct c_generic_context *g_context;
	const struct sc_udp_lite_context *udp_lite_context;
	const struct udphdr *const udp_lite = (struct udphdr *) next_header;
	size_t nr_written = 0;

	g_context = (struct c_generic_context *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;

	/* part 1 */
	if(udp_lite_context->cfp == 1 ||
	   udp_lite_send_cce_packet(context, udp_lite))
	{
		rohc_comp_debug(context, "UDP-Lite checksum coverage = 0x%04x\n",
		                rohc_ntoh16(udp_lite->len));
		memcpy(&dest[counter + nr_written], &udp_lite->len, 2);
		nr_written += 2;
	}

	/* part 2 */
	rohc_comp_debug(context, "UDP-Lite checksum = 0x%04x\n",
	                rohc_ntoh16(udp_lite->check));
	memcpy(&dest[counter + nr_written], &udp_lite->check, 2);
	nr_written += 2;

	return counter + nr_written;
}


/**
 * @brief Build the dynamic part of the UDP-Lite header.
 *
 * \verbatim

 Dynamic part of UDP-Lite header (5.2.1 of RFC 4019):

    +---+---+---+---+---+---+---+---+
 1  /       Checksum Coverage       /   2 octets
    +---+---+---+---+---+---+---+---+
 2  /           Checksum            /   2 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The UDP-Lite header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static size_t udp_lite_code_dynamic_udplite_part(const struct c_context *const context,
                                                 const unsigned char *const next_header,
                                                 unsigned char *const dest,
                                                 const size_t counter)
{
	const struct udphdr *const udp_lite = (struct udphdr *) next_header;
	size_t nr_written = 0;

	/* part 1 */
	rohc_comp_debug(context, "UDP-Lite checksum coverage = 0x%04x\n",
	                rohc_ntoh16(udp_lite->len));
	memcpy(&dest[counter + nr_written], &udp_lite->len, 2);
	nr_written += 2;

	/* part 2 */
	rohc_comp_debug(context, "UDP-Lite checksum = 0x%04x\n",
	                rohc_ntoh16(udp_lite->check));
	memcpy(&dest[counter + nr_written], &udp_lite->check, 2);
	nr_written += 2;

	return counter + nr_written;
}


/**
 * @brief Initialize checksum coverage in the compression context with the given
 *        UDP-Lite header.
 *
 * @param context     The compression context
 * @param next_header The UDP-Lite header
 */
static void udp_lite_init_cc(const struct c_context *context,
                             const unsigned char *next_header)
{
	const struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	const struct udphdr *udp_lite;
	int packet_length;

	g_context = (struct c_generic_context *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;

	packet_length = udp_lite_context->tmp.udp_size;
	udp_lite = (struct udphdr *) next_header;

	if(g_context->ir_count == 1)
	{
		udp_lite_context->cfp = 0;
		udp_lite_context->cfi = 1;
	}

	rohc_comp_debug(context, "CFP = %d, CFI = %d (ir_count = %d)\n",
	                udp_lite_context->cfp, udp_lite_context->cfi,
	                g_context->ir_count);

	udp_lite_context->cfp =
		(rohc_ntoh16(udp_lite->len) != packet_length) || udp_lite_context->cfp;
	udp_lite_context->cfi =
		(rohc_ntoh16(udp_lite->len) == packet_length) && udp_lite_context->cfi;

	rohc_comp_debug(context, "packet_length = %d\n", packet_length);
	rohc_comp_debug(context, "udp_lite length = %d\n",
	                rohc_ntoh16(udp_lite->len));
	rohc_comp_debug(context, "CFP = %d, CFI = %d\n", udp_lite_context->cfp,
	                udp_lite_context->cfi);

	udp_lite_context->tmp_coverage = udp_lite->len;
	memcpy(&udp_lite_context->old_udp_lite, udp_lite, sizeof(struct udphdr));
}


/**
 * @brief Check whether a Checksum Coverage Extension (CCE) packet must be sent
 *        or not in order to compress the given UDP-Lite header.
 *
 * The function also updates the FK variable stored in the UDP-Lite context.
 *
 * @param context   The compression context
 * @param udp_lite  The UDP-Lite header
 * @return          true if a CCE packet must be sent, false if not
 */
static bool udp_lite_send_cce_packet(const struct c_context *const context,
                                     const struct udphdr *const udp_lite)
{
	const struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	int is_coverage_inferred;
	int is_coverage_same;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;

	rohc_comp_debug(context, "CFP = %d, CFI = %d\n", udp_lite_context->cfp,
	                udp_lite_context->cfi);

	/* may the checksum coverage be inferred from UDP-Lite length ? */
	is_coverage_inferred =
		(rohc_ntoh16(udp_lite->len) == udp_lite_context->tmp.udp_size);

	/* is the checksum coverage unchanged since last packet ? */
	if(udp_lite_context->sent_cce_only_count > 0)
	{
		is_coverage_same = (udp_lite_context->tmp_coverage == udp_lite->len);
	}
	else
	{
		is_coverage_same = (udp_lite_context->old_udp_lite.len == udp_lite->len);
	}

	udp_lite_context->tmp_coverage = udp_lite->len;

	if(is_coverage_same)
	{
		udp_lite_context->coverage_equal_count++;
		if(is_coverage_inferred)
		{
			udp_lite_context->coverage_inferred_count++;
		}
	}
	else
	{
		udp_lite_context->coverage_equal_count = 0;
		if(is_coverage_inferred)
		{
			udp_lite_context->coverage_inferred_count++;
		}
		else
		{
			udp_lite_context->coverage_inferred_count = 0;
		}
	}

	if(udp_lite_context->cfp == 0 && udp_lite_context->cfi == 1)
	{
		if(!is_coverage_inferred)
		{
			if(udp_lite_context->sent_cce_only_count < MAX_IR_COUNT)
			{
				udp_lite_context->sent_cce_only_count++;
				udp_lite_context->FK = 0x01;
				return true;
			}
			else if(udp_lite_context->coverage_equal_count > MAX_LITE_COUNT)
			{
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 0;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->FK = 0x03;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
			else
			{
				udp_lite_context->cfp = 1;
				udp_lite_context->cfi = 0;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_on_count = 1;
				udp_lite_context->FK = 0x02;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
		}
	}
	else if(udp_lite_context->cfp == 0 && udp_lite_context->cfi == 0)
	{
		if(is_coverage_inferred || (!is_coverage_inferred && !is_coverage_same))
		{
			if(udp_lite_context->sent_cce_only_count < MAX_IR_COUNT)
			{
				udp_lite_context->sent_cce_only_count++;
				udp_lite_context->FK = 0x01;
				return true;
			}
			else if(udp_lite_context->coverage_inferred_count > MAX_LITE_COUNT)
			{
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 1;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->FK = 0x03;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
			else
			{
				udp_lite_context->cfp = 1;
				udp_lite_context->cfi = 0;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_on_count = 1;
				udp_lite_context->FK = 0x02;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
		}
	}
	else if(udp_lite_context->cfp == 1)
	{
		if(is_coverage_inferred || (is_coverage_inferred && is_coverage_same))
		{
			if(udp_lite_context->coverage_equal_count > MAX_LITE_COUNT)
			{
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 0;
				udp_lite_context->FK = 0x03;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
			else if(udp_lite_context->coverage_inferred_count > MAX_LITE_COUNT)
			{
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 1;
				udp_lite_context->FK = 0x03;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
		}
	}

	if(udp_lite_context->sent_cce_off_count < MAX_IR_COUNT)
	{
		udp_lite_context->sent_cce_off_count++;
		udp_lite_context->sent_cce_only_count = 0;
		udp_lite_context->FK = 0x03;
		memcpy(&udp_lite_context->old_udp_lite, udp_lite, sizeof(struct udphdr));
		return true;
	}
	else if(udp_lite_context->sent_cce_on_count < MAX_IR_COUNT)
	{
		udp_lite_context->sent_cce_on_count++;
		udp_lite_context->sent_cce_only_count = 0;
		udp_lite_context->FK = 0x02;
		memcpy(&udp_lite_context->old_udp_lite, udp_lite, sizeof(struct udphdr));
		return true;
	}

	udp_lite_context->sent_cce_only_count = 0;

	return false;
}


/**
 * @brief Define the compression part of the UDP-Lite profile as described
 *        in the RFC 4019.
 */
struct c_profile c_udp_lite_profile =
{
	ROHC_IPPROTO_UDPLITE,     /* IP protocol */
	ROHC_PROFILE_UDPLITE,     /* profile ID (see 7 in RFC 4019) */
	"UDP-Lite / Compressor",  /* profile description */
	c_udp_lite_create,        /* profile handlers */
	c_generic_destroy,
	c_udp_lite_check_profile,
	c_udp_lite_check_context,
	c_udp_lite_encode,
	c_generic_reinit_context,
	c_generic_feedback,
	c_generic_use_udp_port,
};

