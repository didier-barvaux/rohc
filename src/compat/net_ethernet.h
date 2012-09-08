/* Copyright (C) 1997, 1999, 2001, 2008 Free Software Foundation, Inc.
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

/* Based on the FreeBSD version of this file. Curiously, that file
   lacks a copyright in the header. */

/**
 * @file   net_ethernet.h
 * @brief  Defines the Ethernet header for platforms that miss one
 * @author Free Software Foundation, Inc
 *
 * This file contains a part of net/ethernet.h from the GNU C library. It is
 * used on platforms that miss the definition of struct ether_header, eg.
 * Microsoft Windows.
 */

#ifndef __NET_ETHERNET_H
#define __NET_ETHERNET_H 1

#include <stdint.h>

/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14

/** The length (in bytes) of the Ethernet address */
#define ETH_ALEN  6

/** The 10Mb/s ethernet header */
struct ether_header
{
	u_int8_t  ether_dhost[ETH_ALEN]; /**< destination eth addr */
	u_int8_t  ether_shost[ETH_ALEN]; /**< source ether addr */
	u_int16_t ether_type;            /**< packet type ID field */
} __attribute__ ((__packed__));

#endif	/* net/ethernet.h */
