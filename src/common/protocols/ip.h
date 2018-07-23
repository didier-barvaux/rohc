/*
 * Copyright 2015 Didier Barvaux
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
 * @file   protocols/ip.h
 * @brief  Defines the common IPv4/v6 header
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_PROTOCOLS_IP_H
#define ROHC_PROTOCOLS_IP_H

#include <stdint.h>

#ifdef __KERNEL__
#  include <endian.h>
#else
#  include "config.h" /* for WORDS_BIGENDIAN */
#endif


/**
 * @brief The maximum number of IP headers supported
 *
 * Used by the ROHCv1 TCP and ROHCv2 profiles. Not used by the other ROHCv1
 * profiles.
 *
 * The limit value was chosen arbitrarily. It should handle most real-life case
 * without hurting performances nor memory footprint.
 */
#define ROHC_MAX_IP_HDRS  2U


/**
 * @brief The maximum number of IP headers supported
 *
 * Used by the ROHCv1 profiles, except the TCP profile.
 *
 * The limit value was not chosen arbitrarily, those profiles only support
 * 2 levels of IP headers.
 */
#define ROHC_MAX_IP_HDRS_RFC3095  2U


/**
 * @brief The maximum number of IP extension headers supported
 *
 * Used by the ROHCv1 TCP and ROHCv2 profiles. Not used by the other ROHCv1
 * profiles.
 *
 * The limit value was chosen arbitrarily. It should handle most real-life case
 * without hurting performances nor memory footprint.
 */
#define ROHC_MAX_IP_EXT_HDRS    3U


/** The common IPv4/v6 header */
struct ip_hdr
{
#if WORDS_BIGENDIAN == 1
	uint8_t version:4;    /**< The IP version */
	uint8_t reserved:4;   /**< That field depends on IP version */
#else
	uint8_t reserved:4;
	uint8_t version:4;
#endif
} __attribute__((packed));


#endif

