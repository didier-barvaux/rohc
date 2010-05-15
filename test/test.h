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
 */

#ifndef TEST__H
#define TEST__H

/// The maximal size for the ROHC packets
#define MAX_ROHC_SIZE	(5 * 1024)

/// The length of the Linux Cooked Sockets header
#define LINUX_COOKED_HDR_LEN  16

/// The minimum Ethernet length (in bytes)
#define ETHER_FRAME_MIN_LEN 60


/** A simple maximum macro */
#define max(x, y) \
	(((x) > (y)) ? (x) : (y))

/** A simple minimum macro */
#define min(x, y) \
	(((x) < (y)) ? (x) : (y))


#endif

