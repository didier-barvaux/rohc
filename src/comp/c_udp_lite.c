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
 * @author The hackers from ROHC for Linux
 */

#include "c_udp_lite.h"
#include "rohc_traces.h"
#include "rohc_packets.h"


/*
 * Private function prototypes.
 */

int udp_lite_code_dynamic_udp_lite_part(struct c_context *context,
                                        const unsigned char *next_header,
                                        unsigned char *dest,
                                        int counter);

int udp_lite_build_cce_packet(struct c_context *context,
                              const unsigned char *next_header,
                              unsigned char *dest,
                              int counter,
                              int *first_position);

int udp_lite_send_cce_packet(struct c_context *context,
                             const struct udphdr *udp_lite);

int udp_lite_code_UO_packet_tail(struct c_context *context,
                                 const unsigned char *next_header,
                                 unsigned char *dest,
                                 int counter);

void udp_lite_init_cc(struct c_context *context,
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
 * @return        1 if successful, 0 otherwise
 */
int c_udp_lite_create(struct c_context *context, const struct ip_packet ip)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	struct udphdr *udp_lite;
	struct ip_packet last_ip_header;
	unsigned int ip_proto;

	/* create and initialize the generic part of the profile context */
	if(!c_generic_create(context, ip))
	{
		rohc_debugf(0, "generic context creation failed\n");
		goto quit;
	}
	g_context = (struct c_generic_context *) context->specific;

	/* check if packet is IP/UDP-Lite or IP/IP/UDP-Lite */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
	{
		/* get the last IP header */
  		if(!ip_get_inner_packet(ip, &last_ip_header))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			goto quit;
		}

		/* get the transport protocol */
		ip_proto = ip_get_protocol(last_ip_header);
	}
	else
	{
		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}
		
	if(ip_proto != IPPROTO_UDPLITE)
	{
		rohc_debugf(0, "next header is not UDP-Lite (%d), cannot use this "
		            "profile\n", ip_proto);
		goto clean;
	}
	
	udp_lite = (struct udphdr *) ip_get_next_layer(&last_ip_header);

	/* create the UDP-Lite part of the profile context */
	udp_lite_context = malloc(sizeof(struct sc_udp_lite_context));
	if(udp_lite_context == NULL)
	{
	  rohc_debugf(0, "no memory for the UDP-Lite part of the profile context\n");
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
	udp_lite_context->old_udp_lite = *udp_lite;

	/* init the UDP-Lite-specific temporary variables */
	udp_lite_context->tmp_variables.udp_size = -1;

	/* init the UDP-Lite-specific variables and functions */
	g_context->next_header_proto = IPPROTO_UDPLITE;
	g_context->next_header_len = sizeof(struct udphdr);
	g_context->decide_state = decide_state;
	g_context->init_at_IR = udp_lite_init_cc;
	g_context->code_static_part = udp_code_static_udp_part; /* same as UDP */
	g_context->code_dynamic_part = udp_lite_code_dynamic_udp_lite_part;
	g_context->code_UO_packet_head = udp_lite_build_cce_packet;
	g_context->code_UO_packet_tail = udp_lite_code_UO_packet_tail;
	g_context->compute_crc_static = udp_compute_crc_static;
	g_context->compute_crc_dynamic = udp_compute_crc_dynamic;

	return 1;

clean:
	c_generic_destroy(context);
quit:
	return 0;
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
 * @return        1 if the IP/UDP-Lite packet belongs to the context,
 *                0 if it does not belong to the context and
 *                -1 if the profile cannot compress it or an error occurs
 */
int c_udp_lite_check_context(struct c_context *context, struct ip_packet ip)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	struct ip_header_info *ip_flags;
	struct ip_header_info *ip2_flags;
	struct ip_packet ip2, last_ip_header;
	struct udphdr *udp_lite;
	ip_version version;
	unsigned int ip_proto;
	int is_ip_same;
	int is_ip2_same;
	int is_udp_lite_same;

	g_context = (struct c_generic_context *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;
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
			IPV6_ADDR_CMP(&ip_flags->info.v6.old_ip.ip6_src, ipv6_get_saddr(&ip)) &&
			IPV6_ADDR_CMP(&ip_flags->info.v6.old_ip.ip6_dst, ipv6_get_daddr(&ip));
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
		version = ip_get_version(ip2);
		if(version != ip2_flags->version)
			goto bad_context;

		/* compare the addresses of the second header */
		if(version == IPV4)
		{
			is_ip2_same = ip2_flags->info.v4.old_ip.saddr == ipv4_get_saddr(ip2) &&
			              ip2_flags->info.v4.old_ip.daddr == ipv4_get_daddr(ip2);
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
		if(version == IPV6 && ipv6_get_flow_label(ip2) !=
		   IPV6_GET_FLOW_LABEL(ip2_flags->info.v6.old_ip))
			goto bad_context;

		/* get the last IP header */
		last_ip_header = ip2;

		/* get the transport protocol */
		ip_proto = ip_get_protocol(ip2);
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
	if(ip_proto != IPPROTO_UDPLITE)
		goto bad_context;
	
	/* check UDP-Lite ports */
	udp_lite = (struct udphdr *) ip_get_next_layer(&last_ip_header);
	is_udp_lite_same =
		udp_lite_context->old_udp_lite.source == udp_lite->source &&
		udp_lite_context->old_udp_lite.dest == udp_lite->dest;

	return is_udp_lite_same;

bad_context:
	return 0;
error:
	return -1;
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
 * @param payload_offset The offset for the payload in the IP packet
 * @return               The length of the created ROHC packet
 *                       or -1 in case of failure
 */
int c_udp_lite_encode(struct c_context *context,
                      const struct ip_packet ip,
                      int packet_size,
                      unsigned char *dest,
                      int dest_size,
                      int *payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	struct ip_packet last_ip_header;
	struct udphdr *udp_lite;
	unsigned int ip_proto;
	int size;

	g_context = (struct c_generic_context *) context->specific;
	if(g_context == NULL)
	{
		rohc_debugf(0, "generic context not valid\n");
		return -1;
	}

	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;
	if(udp_lite_context == NULL)
	{
		rohc_debugf(0, "UDP-Lite context not valid\n");
		return -1;
	}

	udp_lite_context->tmp_variables.udp_size = packet_size - ip_get_hdrlen(ip);

	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &last_ip_header))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			return -1;
		}

		/* get the transport protocol */
		ip_proto = ip_get_protocol(last_ip_header);
		
		/* update the UDP-Lite payload size */
		udp_lite_context->tmp_variables.udp_size -= ip_get_hdrlen(last_ip_header);
	}
	else
	{
		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	if(ip_proto != IPPROTO_UDPLITE)
	{
		rohc_debugf(0, "packet is not an UDP-Lite packet\n");
		return -1;
	}
	udp_lite = (struct udphdr *) ip_get_next_layer(&last_ip_header);

	/* encode the IP packet */
	size = c_generic_encode(context, ip, packet_size, dest, dest_size, payload_offset);
	if(size < 0)
		goto quit;

	/* update the context with the new UDP-Lite header */
	if(g_context->tmp_variables.packet_type == PACKET_IR ||
	   g_context->tmp_variables.packet_type == PACKET_IR_DYN)
		udp_lite_context->old_udp_lite = *udp_lite;

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
int udp_lite_build_cce_packet(struct c_context *context,
                              const unsigned char *next_header,
                              unsigned char *dest,
                              int counter,
                              int *first_position)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	struct udphdr *udp_lite;
	int send_cce_packet;

	g_context = (struct c_generic_context *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;
	
	udp_lite = (struct udphdr *) next_header;

	/* do we need to add the CCE packet? */
	send_cce_packet = udp_lite_send_cce_packet(context, udp_lite);
	if(send_cce_packet)
	{
		rohc_debugf(2, "Adding CCE\n");
		
		/* part 2 */
		dest[*first_position] = (0xf8 | udp_lite_context->FK);

		/* now first_position must point on the first byte of the part 4
		 * and counter must point on the second byte of the part 4 */
		*first_position = counter;
		counter++;
	}
	else
		rohc_debugf(2, "CCE not needed\n");

	return counter;
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
int udp_lite_code_UO_packet_tail(struct c_context *context,
                                 const unsigned char *next_header,
                                 unsigned char *dest,
                                 int counter)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	struct udphdr *udp_lite;

	g_context = (struct c_generic_context *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;
	
	udp_lite = (struct udphdr *) next_header;

	/* part 1 */
	if(udp_lite_context->cfp == 1 ||
	   udp_lite_send_cce_packet(context, udp_lite))
	{
		rohc_debugf(3, "UDP-Lite checksum coverage = 0x%04x\n",
		            ntohs(udp_lite->len));
		memcpy(&dest[counter], &udp_lite->len, 2);
		counter += 2;
	}

	/* part 2 */
	rohc_debugf(3, "UDP-Lite checksum = 0x%04x\n", ntohs(udp_lite->check));
	memcpy(&dest[counter], &udp_lite->check, 2);
	counter += 2;

	return counter;
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
int udp_lite_code_dynamic_udp_lite_part(struct c_context *context,
                                        const unsigned char *next_header,
                                        unsigned char *dest,
                                        int counter)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	struct udphdr *udp_lite;

	g_context = (struct c_generic_context *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;

	udp_lite = (struct udphdr *) next_header;

	/* part 1 */
	rohc_debugf(3, "UDP-Lite checksum coverage = 0x%04x\n",
	            ntohs(udp_lite->len));
	memcpy(&dest[counter], &udp_lite->len, 2);
	counter += 2;

	/* part 2 */
	rohc_debugf(3, "UDP-Lite checksum = 0x%04x\n", ntohs(udp_lite->check));
	memcpy(&dest[counter], &udp_lite->check, 2);
	counter += 2;

	return counter;
}


/**
 * @brief Initialize checksum coverage in the compression context with the given
 *        UDP-Lite header.
 *
 * @param context     The compression context
 * @param next_header The UDP-Lite header
 */
void udp_lite_init_cc(struct c_context *context,
                      const unsigned char *next_header)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	struct udphdr *udp_lite;
	int packet_length;
	
	g_context = (struct c_generic_context *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;

	packet_length = udp_lite_context->tmp_variables.udp_size;
	udp_lite = (struct udphdr *) next_header;

	if(g_context->ir_count == 1)
	{
		udp_lite_context->cfp = 0;
		udp_lite_context->cfi = 1;
	}

	rohc_debugf(2, "CFP = %d, CFI = %d (ir_count = %d)\n", udp_lite_context->cfp,
	            udp_lite_context->cfi, g_context->ir_count);

	udp_lite_context->cfp = (ntohs(udp_lite->len) != packet_length) || udp_lite_context->cfp;
	udp_lite_context->cfi = (ntohs(udp_lite->len) == packet_length) && udp_lite_context->cfi;
	
	rohc_debugf(2, "packet_length = %d\n", packet_length);
	rohc_debugf(2, "udp_lite length = %d\n", ntohs(udp_lite->len));
	rohc_debugf(2, "CFP = %d, CFI = %d\n", udp_lite_context->cfp,
	            udp_lite_context->cfi);

	udp_lite_context->tmp_coverage = udp_lite->len;
	udp_lite_context->old_udp_lite = *udp_lite;
}


/**
 * @brief Check whether a Checksum Coverage Extension (CCE) packet must be sent
 *        or not in order to compress the given UDP-Lite header.
 *
 * The function also updates the FK variable stored in the UDP-Lite context.
 *
 * @param context  The compression context
 * @param udp_lite The UDP-Lite header
 * @return         1 if a CCE packet must be sent, 0 if not
 */
int udp_lite_send_cce_packet(struct c_context *context,
                             const struct udphdr *udp_lite)
{
	struct c_generic_context *g_context;
	struct sc_udp_lite_context *udp_lite_context;
	int is_coverage_inferred;
	int is_coverage_same;
	
	g_context = (struct c_generic_context *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) g_context->specific;

	rohc_debugf(2, "CFP = %d, CFI = %d\n", udp_lite_context->cfp,
	            udp_lite_context->cfi);

	/* may the checksum coverage be inferred from UDP-Lite length ? */
	is_coverage_inferred =
		(ntohs(udp_lite->len) == udp_lite_context->tmp_variables.udp_size);

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
				return 1;
			}
			else if(udp_lite_context->coverage_equal_count > MAX_LITE_COUNT)
			{
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 0;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->FK = 0x03;
				udp_lite_context->old_udp_lite = *udp_lite;
				return 1;
			}
			else
			{
				udp_lite_context->cfp = 1;
				udp_lite_context->cfi = 0;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_on_count = 1;
				udp_lite_context->FK = 0x02;
				udp_lite_context->old_udp_lite = *udp_lite;
				return 1;
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
				return 1;
			}
			else if(udp_lite_context->coverage_inferred_count > MAX_LITE_COUNT)
			{
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 1;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->FK = 0x03;
				udp_lite_context->old_udp_lite = *udp_lite;
				return 1;
			}
			else
			{
				udp_lite_context->cfp = 1;
				udp_lite_context->cfi = 0;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_on_count = 1;
				udp_lite_context->FK = 0x02;
				udp_lite_context->old_udp_lite = *udp_lite;
				return 1;
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
				udp_lite_context->old_udp_lite = *udp_lite;
				return 1;
			}
			else if(udp_lite_context->coverage_inferred_count > MAX_LITE_COUNT)
			{
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 1;
				udp_lite_context->FK = 0x03;
				udp_lite_context->old_udp_lite = *udp_lite;
				return 1;
			}
		}
	}

	if(udp_lite_context->sent_cce_off_count < MAX_IR_COUNT)
	{
		udp_lite_context->sent_cce_off_count++;
		udp_lite_context->sent_cce_only_count = 0;
		udp_lite_context->FK = 0x03;
		udp_lite_context->old_udp_lite = *udp_lite;
		return 1;
	}
	else if(udp_lite_context->sent_cce_on_count < MAX_IR_COUNT)
	{
		udp_lite_context->sent_cce_on_count++;
		udp_lite_context->sent_cce_only_count = 0;
		udp_lite_context->FK = 0x02;
		udp_lite_context->old_udp_lite = *udp_lite;
		return 1;
	}

	udp_lite_context->sent_cce_only_count = 0;

	return 0;
}


/**
 * @brief Define the compression part of the UDP-Lite profile as described
 *        in the RFC 4019.
 */
struct c_profile c_udp_lite_profile =
{
	IPPROTO_UDPLITE,          /* IP protocol */
	NULL,                     /* list of UDP ports, not relevant for UDP-Lite */
	ROHC_PROFILE_UDPLITE,     /* profile ID (see 7 in RFC 4019) */
	"1.0b",                   /* profile version */
	"UDP-Lite / Compressor",  /* profile description */
	c_udp_lite_create,        /* profile handlers */
	c_generic_destroy,
	c_udp_lite_check_context,
	c_udp_lite_encode,
	c_generic_feedback,
};

