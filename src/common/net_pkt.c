/*
 * Copyright 2014 Didier Barvaux
 * Copyright 2014 Viveris Technologies
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
 * @param[out] packet    The parsed packet
 * @param data           The data to parse
 * @param trace_cb       The function to call for printing traces
 * @param trace_cb_priv  An optional private context, may be NULL
 * @param trace_entity   The entity that emits the traces
 */
void net_pkt_parse(struct net_pkt *const packet,
                   const struct rohc_buf data,
                   rohc_trace_callback2_t trace_cb,
                   void *const trace_cb_priv,
                   rohc_trace_entity_t trace_entity)
{
	packet->time = data.time;
	packet->data = rohc_buf_data(data);
	packet->len = data.len;
	packet->ip_hdr_nr = 0;

	/* traces */
	packet->trace_callback = trace_cb;
	packet->trace_callback_priv = trace_cb_priv;

	/* create the outer IP packet from raw data */
	ip_create(&packet->outer_ip, rohc_buf_data(data), data.len);
	packet->ip_hdr_nr++;
	rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
	           "outer IP header: %u bytes", ip_get_totlen(&packet->outer_ip));
	rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
	           "outer IP header: version %d", ip_get_version(&packet->outer_ip));
	if(packet->outer_ip.nh.data != NULL)
	{
		rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
		           "outer IP header: next header is of type %d",
		           packet->outer_ip.nh.proto);
		if(packet->outer_ip.nl.data != NULL)
		{
			rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
			           "outer IP header: next layer is of type %d",
			           packet->outer_ip.nl.proto);
		}
	}

	/* get the transport protocol */
	packet->transport = &packet->outer_ip.nl;

	/* is there any inner IP header? */
	if(rohc_is_tunneling(packet->transport->proto))
	{
		/* create the second IP header */
		ip_get_inner_packet(&packet->outer_ip, &packet->inner_ip);
		packet->ip_hdr_nr++;
		rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
		           "inner IP header: %u bytes", ip_get_totlen(&packet->inner_ip));
		rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
		           "inner IP header: version %d", ip_get_version(&packet->inner_ip));
		if(packet->inner_ip.nh.data != NULL)
		{
			rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
			           "inner IP header: next header is of type %d",
			           packet->inner_ip.nh.proto);
			if(packet->inner_ip.nl.data != NULL)
			{
				rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
				           "inner IP header: next layer is of type %d",
				           packet->inner_ip.nl.proto);
			}
		}

		/* get the transport protocol */
		packet->transport = &packet->inner_ip.nl;
	}
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

