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
 * @file c_ip.h
 * @brief ROHC compression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef C_IP_H
#define C_IP_H

#include <netinet/ip.h>
#include "c_generic.h"

/*
 * Function prototypes.
 */

int c_ip_check_context(const struct c_context *context,
                       const const struct ip_packet *ip);

rohc_packet_t c_ip_decide_FO_packet(const struct c_context *context);
rohc_packet_t c_ip_decide_SO_packet(const struct c_context *context);

uint16_t c_ip_get_next_sn(const struct c_context *context,
                          const struct ip_packet *outer_ip,
                          const struct ip_packet *inner_ip);

#endif

