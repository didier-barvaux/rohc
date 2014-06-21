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
 * @file   common/net_pkt.h
 * @brief  Network packet (may contains several IP headers)
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMMON_NET_PKT_H
#define ROHC_COMMON_NET_PKT_H

#include "rohc_buf.h"
#include "ip.h"
#include "rohc_traces.h"

#include "dllexport.h"

#include "config.h" /* for ROHC_ENABLE_DEPRECATED_API */


/** The key to help identify (not quaranted unique) a compression context */
typedef uint32_t rohc_ctxt_key_t;


/** One network packet */
struct net_pkt
{
	const uint8_t *data;         /**< The packet data */
	size_t len;                  /**< The length (in bytes) of the packet data */

	size_t ip_hdr_nr;            /**< The number of IP headers */
	struct ip_packet outer_ip;   /**< The outer IP header */
	struct ip_packet inner_ip;   /**< The inner IP header if any */

	struct net_hdr *transport;   /**< The transport layer of the packet if any */

	rohc_ctxt_key_t key;         /**< The hash key of the packet */

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	/** The old callback function used to manage traces */
	rohc_trace_callback_t trace_callback;
#endif
	/** The new callback function used to manage traces */
	rohc_trace_callback2_t trace_callback2;
	/** The private context of the callback function used to manage traces */
	void *trace_callback_priv;
};


bool ROHC_EXPORT net_pkt_parse(struct net_pkt *const packet,
                               const struct rohc_buf data,
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
                               rohc_trace_callback_t trace_cb,
#endif
                               rohc_trace_callback2_t trace_cb2,
                               void *const trace_cb_priv,
                               rohc_trace_entity_t trace_entity)
	__attribute__((warn_unused_result, nonnull(1)));

size_t ROHC_EXPORT net_pkt_get_payload_offset(const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1)));

#endif

