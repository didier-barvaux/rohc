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
 * @file   netinet_ip.h
 * @brief  Defines the IPv4 header for platforms that miss one
 * @author Free Software Foundation, Inc
 *
 * This file contains a part of netinet/ip.h from the GNU C library. It is
 * used on platforms that miss the definition of struct iphdr, eg. Microsoft
 * Windows.
 */

#ifndef __NETINET_IP_H
#define __NETINET_IP_H 1

#include <stdint.h>

#include "config.h" /* for WORDS_BIGENDIAN + u_int*_t */


/* IPv4 header */
struct iphdr
  {
#if WORDS_BIGENDIAN == 1
    unsigned int version:4;
    unsigned int ihl:4;
#else
    unsigned int ihl:4;
    unsigned int version:4;
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };

#endif
