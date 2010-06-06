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
 * @author The hackers from ROHC for Linux
 */

#include "c_udp.h"
#include "rohc_traces.h"
#include "rohc_packets.h"
#include "crc.h"


/*
 * Private function prototypes.
 */

int udp_code_dynamic_udp_part(const struct c_context *context,
                              const unsigned char *next_header,
                              unsigned char *const dest,
                              int counter);

int udp_changed_udp_dynamic(const struct c_context *context,
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
int c_udp_create(struct c_context *const context, const struct ip_packet *ip)
{
	struct c_generic_context *g_context;
	struct sc_udp_context *udp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	unsigned int ip_proto;

	/* create and initialize the generic part of the profile context */
	if(!c_generic_create(context, ip))
	{
		rohc_debugf(0, "generic context creation failed\n");
		goto quit;
	}
	g_context = (struct c_generic_context *) context->specific;

	/* check if packet is IP/UDP or IP/IP/UDP */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
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

	if(ip_proto != IPPROTO_UDP)
	{
		rohc_debugf(0, "next header is not UDP (%d), cannot use this profile\n",
		            ip_proto);
		goto clean;
	}

	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);

	/* create the UDP part of the profile context */
	udp_context = malloc(sizeof(struct sc_udp_context));
	if(udp_context == NULL)
	{
	  rohc_debugf(0, "no memory for the UDP part of the profile context\n");
	  goto clean;
	}
	g_context->specific = udp_context;

	/* initialize the UDP part of the profile context */
	udp_context->udp_checksum_change_count = 0;
	udp_context->old_udp = *udp;

	/* init the UDP-specific temporary variables */
	udp_context->tmp_variables.send_udp_dynamic = -1;

	/* init the UDP-specific variables and functions */
	g_context->next_header_proto = IPPROTO_UDP;
	g_context->next_header_len = sizeof(struct udphdr);
	g_context->decide_state = udp_decide_state;
	g_context->init_at_IR = NULL;
	g_context->code_static_part = udp_code_static_udp_part;
	g_context->code_dynamic_part = udp_code_dynamic_udp_part;
	g_context->code_UO_packet_head = NULL;
	g_context->code_UO_packet_tail = udp_code_UO_packet_tail;
	g_context->compute_crc_static = udp_compute_crc_static;
	g_context->compute_crc_dynamic = udp_compute_crc_dynamic;

	return 1;

clean:
	c_generic_destroy(context);
quit:
	return 0;
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
 * @return        1 if the IP/UDP packet belongs to the context,
 *                0 if it does not belong to the context and
 *                -1 if the profile cannot compress it or an error occurs
 */
int c_udp_check_context(const struct c_context *context,
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
	int is_ip_same;
	int is_ip2_same;
	int is_udp_same;

	g_context = (struct c_generic_context *) context->specific;
	udp_context = (struct sc_udp_context *) g_context->specific;
	ip_flags = &g_context->ip_flags;
	ip2_flags = &g_context->ip2_flags;

	/* check the IP version of the first header */
	version = ip_get_version(ip);
	if(version != ip_flags->version)
		goto bad_context;

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
		goto bad_context;

	/* compare the Flow Label of the first header if IPv6 */
	if(version == IPV6 && ipv6_get_flow_label(ip) !=
	   IPV6_GET_FLOW_LABEL(ip_flags->info.v6.old_ip))
		goto bad_context;

	/* check the second IP header */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
	{
		/* check if the context used to have a second IP header */
		if(!g_context->is_ip2_initialized)
			goto bad_context;

		/* get the second IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			goto error;
		}

		/* check the IP version of the second header */
		version = ip_get_version(&ip2);
		if(version != ip2_flags->version)
			goto bad_context;

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
			goto bad_context;

		/* compare the Flow Label of the second header if IPv6 */
		if(version == IPV6 && ipv6_get_flow_label(&ip2) !=
		   IPV6_GET_FLOW_LABEL(ip2_flags->info.v6.old_ip))
			goto bad_context;

		/* get the last IP header */
		last_ip_header = &ip2;

		/* get the transport protocol */
		ip_proto = ip_get_protocol(&ip2);
	}
	else /* no second IP header */
	{
		/* check if the context used not to have a second header */
		if(g_context->is_ip2_initialized)
			goto bad_context;

		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	/* check the transport protocol */
	if(ip_proto != IPPROTO_UDP)
		goto bad_context;
	
	/* check UDP ports */
	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);
	is_udp_same = udp_context->old_udp.source == udp->source &&
	              udp_context->old_udp.dest == udp->dest;

	return is_udp_same;

bad_context:
	return 0;
error:
	return -1;
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
 * @param payload_offset The offset for the payload in the IP packet
 * @return               The length of the created ROHC packet
 *                       or -1 in case of failure
 */
int c_udp_encode(struct c_context *const context,
                 const struct ip_packet *ip,
                 const int packet_size,
                 unsigned char *const dest,
                 const int dest_size,
                 int *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_udp_context *udp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	unsigned int ip_proto;
	int size;

	g_context = (struct c_generic_context *) context->specific;
	if(g_context == NULL)
	{
		rohc_debugf(0, "generic context not valid\n");
		return -1;
	}

	udp_context = (struct sc_udp_context *) g_context->specific;
	if(udp_context == NULL)
	{
		rohc_debugf(0, "UDP context not valid\n");
		return -1;
	}

	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
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

	if(ip_proto != IPPROTO_UDP)
	{
		rohc_debugf(0, "packet is not an UDP packet\n");
		return -1;
	}
	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);

	/* how many UDP fields changed? */
	udp_context->tmp_variables.send_udp_dynamic = udp_changed_udp_dynamic(context, udp);

	/* encode the IP packet */
	size = c_generic_encode(context, ip, packet_size, dest, dest_size, payload_offset);
	if(size < 0)
		goto quit;

	/* update the context with the new UDP header */
	if(g_context->tmp_variables.packet_type == PACKET_IR ||
	   g_context->tmp_variables.packet_type == PACKET_IR_DYN)
		udp_context->old_udp = *udp;

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
void udp_decide_state(struct c_context *const context)
{
	struct c_generic_context *g_context;
	struct sc_udp_context *udp_context;

	g_context = (struct c_generic_context *) context->specific;
	udp_context = (struct sc_udp_context *) g_context->specific;

	if(udp_context->tmp_variables.send_udp_dynamic)
		change_state(context, IR);
	else
		/* generic function used by the IP-only, UDP and UDP-Lite profiles */
		decide_state(context);
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
int udp_code_UO_packet_tail(const struct c_context *context,
                            const unsigned char *next_header,
                            unsigned char *const dest,
                            int counter)
{
	const struct udphdr *udp = (struct udphdr *) next_header;

	/* part 13 */
	if(udp->check != 0)
	{
		rohc_debugf(3, "UDP checksum = 0x%x\n", udp->check);
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
	rohc_debugf(3, "UDP source port = 0x%x\n", udp->source);
	memcpy(&dest[counter], &udp->source, 2);
	counter += 2;

	/* part 2 */
	rohc_debugf(3, "UDP dest port = 0x%x\n", udp->dest);
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
int udp_code_dynamic_udp_part(const struct c_context *context,
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
	rohc_debugf(3, "UDP checksum = 0x%x\n", udp->check);
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
int udp_changed_udp_dynamic(const struct c_context *context,
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
			udp_context->udp_checksum_change_count = 0;
		return 1;
	}
	else
		return 0;
}


/**
 * @brief Define the compression part of the UDP profile as described
 *        in the RFC 3095.
 */
struct c_profile c_udp_profile =
{
	IPPROTO_UDP,         /* IP protocol */
	NULL,                /* list of UDP ports, not relevant for UDP */
	ROHC_PROFILE_UDP,    /* profile ID (see 8 in RFC 3095) */
	"UDP / Compressor",  /* profile description */
	c_udp_create,        /* profile handlers */
	c_generic_destroy,
	c_udp_check_context,
	c_udp_encode,
	c_generic_feedback,
};

