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
 * @file ip_id.c
 * @brief IP-ID decompression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#include "ip_id.h"


/**
 * @brief Initialize an IP-ID object
 *
 * @param s      The IP-ID object to initialize
 * @param id_ref The IP-ID reference
 * @param sn_ref The reference Sequence Number (SN)
 */
void d_ip_id_init(struct d_ip_id_decode *s, int id_ref, int sn_ref)
{
	s->id_ref = id_ref;
	s->sn_ref = sn_ref;
}


/**
 * @brief Decode the IP-ID offset in a ROHC packet and compute the associated
 *        IP-ID
 *
 * @param s  The IP-ID object
 * @param m  The IP-ID offset
 * @param k  The number of bits used to code the IP-ID offset
 * @param sn The SN of the ROHC packet that contains the IP-ID offset
 * @return   The computed IP-ID
 */
int d_ip_id_decode(struct d_ip_id_decode *s, int m, int k, int sn)
{
	int offset_ref = (s->id_ref - s->sn_ref) % 65536;
	int min;
	int max;
	int tmp;
	int mask = ((1 << k) - 1);

	f(offset_ref, k, 0, &min, &max);
	
	tmp = min;
	m &= mask;

	while(tmp <= max && (tmp & mask) != m)
	{
		tmp++;
	}

	if((tmp & mask) != m)
	{
		tmp = -1;
	}
	else
	{
		tmp = (sn + tmp) & 0xffff;
	}

	return tmp;
}


/**
 * @brief Update the reference values for the IP-ID and the SN
 *
 * @param s      The IP-ID object
 * @param id_ref The new IP-ID reference
 * @param sn_ref The new SN reference
 */
void d_ip_id_update(struct d_ip_id_decode *s, int id_ref, int sn_ref)
{
	s->id_ref = id_ref;
	s->sn_ref = sn_ref;
}

