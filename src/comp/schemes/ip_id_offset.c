/*
 * Copyright 2015 Didier Barvaux
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
 * @file   src/comp/schemes/ip_id_offset.c
 * @brief  Offset IP-ID encoding
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "ip_id_offset.h"
#include "ip.h"


/**
 * @brief Whether the new IP-ID is increasing
 *
 * The new IP-ID is considered as increasing if the new value is greater by a
 * small delta then the previous IP-ID. Wraparound shall be taken into
 * account.
 *
 * @param old_id  The IP-ID of the previous IPv4 header
 * @param new_id  The IP-ID of the current IPv4 header
 * @return        Whether the IP-ID is increasing
 */
bool is_ip_id_increasing(const uint16_t old_id, const uint16_t new_id)
{
	/* The maximal delta accepted between two consecutive IPv4 ID so that it
	 * can be considered as increasing */
	const uint16_t max_id_delta = 2;
	bool is_increasing;

	/* the new IP-ID is increasing if it belongs to:
	 *  - interval ]old_id ; old_id + IPID_MAX_DELTA[ (no wraparound)
	 *  - intervals ]old_id ; 0xffff] or
	 *    [0 ; (old_id + IPID_MAX_DELTA) % 0xffff[ (wraparound) */
	if(new_id > old_id && (new_id - old_id) < max_id_delta)
	{
		is_increasing = true;
	}
	else if(old_id > (0xffff - max_id_delta) &&
	        (new_id > old_id || new_id < (max_id_delta - (0xffff - old_id))))
	{
		is_increasing = true;
	}
	else
	{
		is_increasing = false;
	}

	return is_increasing;
}


/**
 * @brief Detect the behavior of the IPv4 Identification field
 *
 * @param last_ip_id  The IP-ID value of the previous packet (in HBO)
 * @param new_ip_id   The IP-ID value of the current packet (in HBO)
 * @return            The IP-ID behavior among: ROHC_IP_ID_BEHAVIOR_SEQ,
 *                    ROHC_IP_ID_BEHAVIOR_SEQ_SWAP, ROHC_IP_ID_BEHAVIOR_ZERO, or
 *                    ROHC_IP_ID_BEHAVIOR_RAND
 */
rohc_ip_id_behavior_t rohc_comp_detect_ip_id_behavior(const uint16_t last_ip_id,
                                                      const uint16_t new_ip_id)
{
	rohc_ip_id_behavior_t behavior;

	if(is_ip_id_increasing(last_ip_id, new_ip_id))
	{
		behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
	}
	else
	{
		const uint16_t swapped_last_ip_id = swab16(last_ip_id);
		const uint16_t swapped_new_ip_id = swab16(new_ip_id);

		if(is_ip_id_increasing(swapped_last_ip_id, swapped_new_ip_id))
		{
			behavior = ROHC_IP_ID_BEHAVIOR_SEQ_SWAP;
		}
		else if(new_ip_id == 0)
		{
			behavior = ROHC_IP_ID_BEHAVIOR_ZERO;
		}
		else
		{
			behavior = ROHC_IP_ID_BEHAVIOR_RAND;
		}
	}

	return behavior;
}

