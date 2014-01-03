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
 * @file   common/net_pkt.c
 * @brief  Network packet (may contains several IP headers)
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "net_pkt.h"

#include "protocols/ip_numbers.h"
#include "rohc_traces_internal.h"


/**
 * @brief Parse a network packet
 *
 * @param[out] packet     The parsed packet
 * @param data            The data to parse
 * @param data_len        The length of the data to parse
 * @param trace_callback  The function to call for printing traces
 * @param trace_entity    The entity that emits the traces
 * @return                true if the packet was successfully parsed,
 *                        false if a problem occurred (a malformed packet is
 *                        not considered as an error)
 */
bool net_pkt_parse(struct net_pkt *const packet,
                   const uint8_t *const data,
                   const size_t data_len,
                   rohc_trace_callback_t trace_callback,
                   rohc_trace_entity_t trace_entity)
{
	packet->data = data;
	packet->len = data_len;
	packet->ip_hdr_nr = 0;
	packet->key = 0;

	/* traces */
	packet->trace_callback = trace_callback;

	/* create the outer IP packet from raw data */
	if(!ip_create(&packet->outer_ip, data, data_len))
	{
		rohc_warning(packet, trace_entity, ROHC_PROFILE_GENERAL,
		             "cannot create the outer IP header\n");
		goto error;
	}
	packet->ip_hdr_nr++;
	rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
	           "outer IP header: %u bytes\n", ip_get_totlen(&packet->outer_ip));
	rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
	           "outer IP header: version %d\n", ip_get_version(&packet->outer_ip));
	if(packet->outer_ip.nh.data != NULL)
	{
		rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
		           "outer IP header: next header is of type %d\n",
		           packet->outer_ip.nh.proto);
		if(packet->outer_ip.nl.data != NULL)
		{
			rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
			           "outer IP header: next layer is of type %d\n",
			           packet->outer_ip.nl.proto);
		}
	}

	/* build the hash key for the packet */
	if(ip_get_version(&packet->outer_ip) == IPV4)
	{
		packet->key ^= ipv4_get_saddr(&packet->outer_ip);
		packet->key ^= ipv4_get_daddr(&packet->outer_ip);
	}
	else if(ip_get_version(&packet->outer_ip) == IPV6)
	{
		const struct ipv6_addr *const saddr = ipv6_get_saddr(&packet->outer_ip);
		const struct ipv6_addr *const daddr = ipv6_get_daddr(&packet->outer_ip);
		packet->key ^= saddr->addr.u32[0];
		packet->key ^= saddr->addr.u32[1];
		packet->key ^= saddr->addr.u32[2];
		packet->key ^= saddr->addr.u32[3];
		packet->key ^= daddr->addr.u32[0];
		packet->key ^= daddr->addr.u32[1];
		packet->key ^= daddr->addr.u32[2];
		packet->key ^= daddr->addr.u32[3];
	}

	/* get the transport protocol */
	packet->transport = &packet->outer_ip.nl;

	/* is there any inner IP header? */
	if(packet->transport->proto == ROHC_IPPROTO_IPIP ||
	   packet->transport->proto == ROHC_IPPROTO_IPV6)
	{
		/* create the second IP header */
		if(!ip_get_inner_packet(&packet->outer_ip, &packet->inner_ip))
		{
			rohc_warning(packet, trace_entity, ROHC_PROFILE_GENERAL,
			             "cannot create the inner IP header\n");
			goto error;
		}
		packet->ip_hdr_nr++;
		rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
		           "inner IP header: %u bytes\n", ip_get_totlen(&packet->inner_ip));
		rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
		           "inner IP header: version %d\n", ip_get_version(&packet->inner_ip));
		if(packet->inner_ip.nh.data != NULL)
		{
			rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
			           "inner IP header: next header is of type %d\n",
			           packet->inner_ip.nh.proto);
			if(packet->inner_ip.nl.data != NULL)
			{
				rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
				           "inner IP header: next layer is of type %d\n",
				           packet->inner_ip.nl.proto);
			}
		}

		/* get the transport protocol */
		packet->transport = &packet->inner_ip.nl;
	}

	return true;

error:
	return false;
}


/**
 * @brief Get the offset of the IP payload in the given packet
 *
 * The payload begins after the innermost IP header (and its extension headers).
 *
 * @param packet  The packet to get the payload offset for
 * @return        The payload offset (in bytes)
 */
size_t net_pkt_get_payload_offset(const struct net_pkt *const packet)
{
	size_t payload_offset;

	/* outer IP header (and its extension headers) if any */
	payload_offset = ip_get_hdrlen(&packet->outer_ip) +
	                 ip_get_total_extension_size(&packet->outer_ip);

	/* inner IP header (and its extension headers) if any */
	if(packet->ip_hdr_nr > 1)
	{
		payload_offset += ip_get_hdrlen(&packet->inner_ip) +
		                  ip_get_total_extension_size(&packet->inner_ip);
	}

	/* the length of the transport header depends on the compression profile */

	return payload_offset;
}

