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
 * @file ip_id.h
 * @brief IP-ID decompression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef IP_ID_H
#define IP_ID_H

#include "wlsb.h"


/**
 * @brief Defines a IP-ID object to help computing the IP-ID value
 *        from an IP-ID offset
 */
struct d_ip_id_decode
{
	int id_ref; ///< The reference IP-ID
	int sn_ref; ///< The reference Sequence Number (SN)
};


/*
 * Function prototypes.
 */

void d_ip_id_init(struct d_ip_id_decode *s, int id_ref, int sn_ref);

int d_ip_id_decode(struct d_ip_id_decode *s, int m, int length, int sn);

void d_ip_id_update(struct d_ip_id_decode *s, int id_ref, int sn_ref);


#endif

