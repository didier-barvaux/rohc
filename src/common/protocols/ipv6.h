/* Copyright (C) 1991-1997, 2001, 2003, 2006 Free Software Foundation, Inc.
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
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA.  */

/**
 * @file   ipv6.h
 * @brief  Defines the IPv6 header
 * @author Free Software Foundation, Inc
 *
 * This file contains a part of netinet/ip6.h from the GNU C library. It is
 * copied here to be portable on all platforms, even the platforms that miss
 * the declarations or got different declarations, such as Microsoft Windows
 * or FreeBSD.
 */

#ifndef ROHC_PROTOCOLS_IPV6_H
#define ROHC_PROTOCOLS_IPV6_H

#include <stdint.h>


/**
 * @brief The IPv6 address
 */
struct ipv6_addr
{
	union
	{
		uint8_t u8[16];
		uint16_t u16[8];
		uint32_t u32[4];
	} addr;
} __attribute__((packed));


/**
 * @brief The IPv6 header
 */
struct ipv6_hdr
{
	union
	{
		struct ip6_hdrctl
		{
			uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
			                            20 bits flow-ID */
			uint16_t ip6_un1_plen;   /* payload length */
			uint8_t ip6_un1_nxt;     /* next header */
			uint8_t ip6_un1_hlim;    /* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
	} ip6_ctlun;
	struct ipv6_addr ip6_src;     /* source address */
	struct ipv6_addr ip6_dst;     /* destination address */
} __attribute__((packed));

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim


/** The IPv6 option header */
struct ipv6_opt
{
	uint8_t next_header;
	uint8_t length;
	uint8_t value[1];
} __attribute__((packed));


#endif

