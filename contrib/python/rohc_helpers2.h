/*
 * Copyright 2016 Didier Barvaux
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
 * @file    rohc_helpers2.h
 * @brief   Helpers for the python binding of the ROHC library
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_HELPERS2_H
#define ROHC_HELPERS2_H


#define RTP_PORTS_MAX_NR 10U
static unsigned int rtp_ports[RTP_PORTS_MAX_NR] = { 0 };


/**
 * @brief Add new UDP port for RTP streams
 *
 * @param new_port  The UDP port to add
 * @return          true if port was successfully added,
 *                  false if the list of ports is full
 */
bool rohc_comp_add_rtp_port(const unsigned int new_port)
{
	size_t i;

	/* find the first free slot in the list and record the new port there */
	for(i = 0; i < RTP_PORTS_MAX_NR; i++)
	{
		if(rtp_ports[i] == 0)
		{
			rtp_ports[i] = new_port;
			return true;
		}
	}

	/* list is full */
	return false;
}


#endif /* ROHC_HELPERS2_H */

