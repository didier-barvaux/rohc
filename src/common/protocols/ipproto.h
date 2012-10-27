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
 * @file ipproto.h
 * @brief Description of IP protocole number.
 * @author FWX <rohc_team@dialine.fr>
 */
extern u_int8_t ipproto_specifications[];

#ifndef IPPROTO_MIME
#define IPPROTO_MIME 55  // see RFC2004
#endif

#define IPV4_TUNNELING  0x01
#define IPV6_TUNNELING  0x02
#define IP_TUNNELING    (IPV4_TUNNELING|IPV6_TUNNELING)
#define IPV6_OPTION     0x04

