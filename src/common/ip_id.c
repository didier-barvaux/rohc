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
#include "interval.h" /* for the f() function */

#include <stdlib.h> /* for abs(3) */
#include <assert.h>


/**
 * @brief Initialize an IP-ID object
 *
 * @param ip_id  The IP-ID object to initialize
 * @param id_ref The IP-ID reference
 * @param sn_ref The reference Sequence Number (SN)
 */
void d_ip_id_init(struct d_ip_id_decode *const ip_id,
                  const uint16_t id_ref,
                  const uint16_t sn_ref)
{
	ip_id->id_ref = id_ref;
	ip_id->sn_ref = sn_ref;
}


/**
 * @brief Decode the IP-ID offset in a ROHC packet and compute the associated
 *        IP-ID
 *
 * @param ip_id    The IP-ID object
 * @param m        The IP-ID offset
 * @param k        The number of bits used to code the IP-ID offset
 * @param sn       The SN of the ROHC packet that contains the IP-ID offset
 * @param decoded  OUT: The computed IP-ID
 * @return         1 in case of success, 0 otherwise
 */
int d_ip_id_decode(const struct d_ip_id_decode *const ip_id,
                   const uint16_t m,
                   const size_t k,
                   const uint16_t sn,
                   uint16_t *const decoded)
{
	uint16_t offset_ref;
	uint32_t min;
	uint32_t max;
	uint32_t try;
	uint32_t mask;
	int is_success;

	assert(ip_id != NULL);
	assert(k <= 16);

	/* compute the offset between reference IP-ID and reference SN
	 * (overflow over 16 bits is expected if SN > IP-ID) */
	offset_ref = ip_id->id_ref - ip_id->sn_ref;

	/* compute the mask for k bits (handle integer overflow) */
	if(k == 16)
	{
		mask = 0xffff;
	}
	else
	{
		mask = ((1 << k) - 1);
	}

	/* determine the interval in which the decoded value should be present */
	f(offset_ref, k, 0, &min, &max);

	/* search the value that matches the k lower bits of the value m to decode:
	   try all values from the interval starting from the smallest one */
	for(try = min; try <= max; try++)
	{
		if((try & mask) == (m & mask))
		{
			/* corresponding value found */
			break;
		}
	}

	if((try & mask) == (m & mask))
	{
		*decoded = (sn + ((uint16_t) (try & 0xffff))) & 0xffff;
		is_success = 1;
	}
	else
	{
		is_success = 0;
	}

	return is_success;
}


/**
 * @brief Update the reference values for the IP-ID and the SN
 *
 * @param ip_id  The IP-ID object
 * @param id_ref The new IP-ID reference
 * @param sn_ref The new SN reference
 */
void d_ip_id_update(struct d_ip_id_decode *const ip_id,
                    const uint16_t id_ref,
                    const uint16_t sn_ref)
{
	ip_id->id_ref = id_ref;
	ip_id->sn_ref = sn_ref;
}

