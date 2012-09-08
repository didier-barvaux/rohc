/* Copyright (C) 1991-2001, 2003, 2004, 2006, 2007, 2008
   Free Software Foundation, Inc.
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
 * @file   netinet_in.h
 * @brief  Defines INET functions for platforms that miss one
 * @author Free Software Foundation, Inc
 *
 * This file contains a part of netinet/in.h from the GNU C library. It is
 * used on platforms that miss the definition of ntohl, htonl, ntohs, htons,
 * struct in6_addr, and some standard well-defined IP protocols.
 */

#ifndef	_NETINET_IN_H
#define	_NETINET_IN_H	1

#include <stdint.h>

#include "config.h" /* for HAVE_[HN]TO[NH][SL] + HAVE_WINSOCK2_H */


/* find ntohl definition */
#if HAVE_NTOHL == 1
#elif HAVE_WINSOCK2_H == 1
#  include <winsock2.h>
#else
#  error "we do not have a definition of the ntohl() function"
#endif

/* find htonl definition */
#if HAVE_HTONL == 1
#elif HAVE_WINSOCK2_H == 1
#  include <winsock2.h>
#else
#  error "we do not have a definition of the htonl() function"
#endif

/* find ntohs definition */
#if HAVE_NTOHS == 1
#elif HAVE_WINSOCK2_H == 1
#  include <winsock2.h>
#else
#  error "we do not have a definition of the ntohs() function"
#endif

/* find htons definition */
#if HAVE_HTONS == 1
#elif HAVE_WINSOCK2_H == 1
#  include <winsock2.h>
#else
#  error "we do not have a definition of the htons() function"
#endif


/* IPv6 address */
struct in6_addr
{
	union
	{
		uint8_t __u6_addr8[16];
		uint16_t __u6_addr16[8];
		uint32_t __u6_addr32[4];
	} __in6_u;
#define s6_addr		__in6_u.__u6_addr8
#define s6_addr16		__in6_u.__u6_addr16
#define s6_addr32		__in6_u.__u6_addr32
  };


/*
 * Some standard well-defined IP protocols
 */

/* IP */
#ifdef IPPROTO_IP
#elif HAVE_WINSOCK2_H == 1
#  include <winsock2.h>
#else
#  error "we do not have a definition of IPPROTO_IP"
#endif

/* IPIP tunnels */
#ifndef IPPROTO_IPIP
#  define IPPROTO_IPIP  4
#endif


#endif	/* netinet/in.h */
