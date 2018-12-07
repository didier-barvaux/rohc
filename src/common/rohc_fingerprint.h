/*
 * Copyright 2018 Didier Barvaux
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
 * @file   rohc_fingerprint.h
 * @brief  The unique fingerprint of one compression context or uncompressed packet
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_PROTOCOLS_FINGERPRINT_H
#define ROHC_PROTOCOLS_FINGERPRINT_H

#include "protocols/ip.h"
#include "protocols/ipv6.h"
#include "rohc_profiles.h"

#include <stdint.h>

#ifdef __KERNEL__
#  include <endian.h>
#else
#  include "config.h" /* for WORDS_BIGENDIAN */
#endif


/**
 * @brief The unique fingerprint of one IP header
 */
struct rohc_fingerprint_ip
{
	uint32_t version:4;
	uint32_t next_proto:8;
	uint32_t flow_label:20;
	struct ipv6_addr saddr;
	struct ipv6_addr daddr;
} __attribute__((packed));


/**
 * @brief The part of the unique fingerprint for Context Replication
 */
struct rohc_fingerprint_base
{
	rohc_profile_t profile_id;

	uint8_t ip_hdrs_nr; /**< The number of IP headers */
	struct rohc_fingerprint_ip ip_hdrs[ROHC_MAX_IP_HDRS];
} __attribute__((packed));


/**
 * @brief The unique fingerprint of one compression context or uncompressed packet
 */
struct rohc_fingerprint
{
	struct rohc_fingerprint_base base;

	union
	{
		struct
		{
			uint16_t src_port;
			uint16_t dst_port;
		} __attribute__((packed));
		uint32_t esp_spi;
	};

	uint32_t rtp_ssrc;

} __attribute__((packed));

#endif

