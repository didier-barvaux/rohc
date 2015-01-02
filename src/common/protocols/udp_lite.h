/*
 * Copyright 2012 Didier Barvaux
 * Copyright 2007,2009,2010 Viveris Technologies
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
 * @file udp_lite.h
 * @brief Define the UDP-Lite protocol.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_PROTOCOLS_UDP_LITE_H
#define ROHC_PROTOCOLS_UDP_LITE_H

#include "protocols/udp.h"

typedef enum /* TODO: doxygen */
{
	ROHC_PACKET_CCE       = 0,
	ROHC_PACKET_CCE_ON    = 1,
	ROHC_PACKET_CCE_OFF   = 2,
	ROHC_PACKET_CCE_OTHER = 3,
} rohc_packet_cce_t;

#endif

