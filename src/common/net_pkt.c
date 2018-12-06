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
	ip_create(&packet->ip_hdrs[packet->ip_hdr_nr], rohc_buf_data(data), data.len);
	rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
	           "IP header #%zu:", packet->ip_hdr_nr + 1);
	rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
	           "  %u bytes", ip_get_totlen(&packet->ip_hdrs[packet->ip_hdr_nr]));
	rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
	           "  version %d", ip_get_version(&packet->ip_hdrs[packet->ip_hdr_nr]));
	if(packet->ip_hdrs[packet->ip_hdr_nr].nh.data != NULL)
	{
		rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
		           "  next header is of type %d",
		           packet->ip_hdrs[packet->ip_hdr_nr].nh.proto);
		if(packet->ip_hdrs[packet->ip_hdr_nr].nl.data != NULL)
		{
			rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
			           "  next layer is of type %d",
			           packet->ip_hdrs[packet->ip_hdr_nr].nl.proto);
		}
	}

	/* get the transport protocol */
	packet->transport = &packet->ip_hdrs[packet->ip_hdr_nr].nl;
	packet->ip_hdr_nr++;

	/* is there any inner IP header? */
	if(rohc_is_tunneling(packet->transport->proto))
	{
		/* create the second IP header */
		ip_get_inner_packet(&packet->ip_hdrs[0], &packet->ip_hdrs[packet->ip_hdr_nr]);
		rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
		           "IP header #%zu:", packet->ip_hdr_nr + 1);
		rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
		           "  %u bytes", ip_get_totlen(&packet->ip_hdrs[packet->ip_hdr_nr]));
		rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
		           "  version %d", ip_get_version(&packet->ip_hdrs[packet->ip_hdr_nr]));
		if(packet->ip_hdrs[packet->ip_hdr_nr].nh.data != NULL)
		{
			rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
			           "  next header is of type %d",
			           packet->ip_hdrs[packet->ip_hdr_nr].nh.proto);
			if(packet->ip_hdrs[packet->ip_hdr_nr].nl.data != NULL)
			{
				rohc_debug(packet, trace_entity, ROHC_PROFILE_GENERAL,
				           "  next layer is of type %d",
				           packet->ip_hdrs[packet->ip_hdr_nr].nl.proto);
			}
		}

		/* get the transport protocol */
		packet->transport = &packet->ip_hdrs[packet->ip_hdr_nr].nl;
		packet->ip_hdr_nr++;
	}
}

