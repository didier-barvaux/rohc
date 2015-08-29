/*
 * Copyright 2012 Didier Barvaux
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
 * @file   udp.h
 * @brief  Defines the UDP header
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * This file mimics the udphdr struct defined by netinet/udp.h from the GNU C
 * library. It is defined here to be portable on all platforms, even the
 * platforms that miss the declarations or got different declarations, such as
 * Microsoft Windows or FreeBSD. The udphdr struct being trivial, the original
 * copyrights and licenses are not kept to simplify the library license.
 */

#ifndef ROHC_PROTOCOLS_UDP_H
#define ROHC_PROTOCOLS_UDP_H

#include <stdint.h>


/** The UDP header */
struct udphdr
{
	uint16_t source; /**< The source port of the UDP header */
	uint16_t dest;   /**< The destination port of the UDP header */
	uint16_t len;    /**< The length (in bytes) of the UDP packet (header + payload) */
	uint16_t check;  /**< The checksum over of the UDP header + pseudo IP header */
} __attribute__((packed));

#endif

