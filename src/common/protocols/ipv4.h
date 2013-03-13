/* Copyright (C) 1991-1993,1995-2000,2009,2010 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/**
 * @file   ipv4.h
 * @brief  Defines the IPv4 header
 * @author Free Software Foundation, Inc
 *
 * This file contains a part of netinet/ip.h from the GNU C library. It is
 * copied here to be portable on all platforms, even the platforms that miss
 * the declarations or got different declarations, such as Microsoft Windows
 * or FreeBSD.
 */

#ifndef ROHC_PROTOCOLS_IPV4_H
#define ROHC_PROTOCOLS_IPV4_H

#include <stdint.h>

#ifdef __KERNEL__
#	include <endian.h>
#else
#	include "config.h" /* for WORDS_BIGENDIAN */
#endif


/**
 * @brief The IPv4 header
 */
struct ipv4_hdr
{
#if WORDS_BIGENDIAN == 1
	uint8_t version:4;
	uint8_t ihl:4;
#else
	uint8_t ihl:4;
	uint8_t version:4;
#endif
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
	/* The options start here. */
} __attribute__((packed));

#endif
