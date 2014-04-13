/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file   test.h
 * @brief  Common definitions for test applications
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_TEST__H
#define ROHC_TEST__H

#include <stdint.h>

/// The maximal size for the ROHC packets
#define MAX_ROHC_SIZE  (5 * 1024)

/// The length of the Linux Cooked Sockets header
#define LINUX_COOKED_HDR_LEN  16U

/// The length of the BSD loopback encapsulation
#define BSD_LOOPBACK_HDR_LEN  4U

/// The minimum Ethernet length (in bytes)
#define ETHER_FRAME_MIN_LEN  60U

/** The length (in bytes) of the Ethernet address */
#define ETH_ALEN  6U

/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14U

/** The 10Mb/s ethernet header */
struct ether_header
{
	uint8_t  ether_dhost[ETH_ALEN]; /**< destination eth addr */
	uint8_t  ether_shost[ETH_ALEN]; /**< source ether addr */
	uint16_t ether_type;            /**< packet type ID field */
} __attribute__ ((__packed__));


/** A simple maximum macro */
#define max(x, y) \
	(((x) > (y)) ? (x) : (y))

/** A simple minimum macro */
#define min(x, y) \
	(((x) < (y)) ? (x) : (y))


#endif

