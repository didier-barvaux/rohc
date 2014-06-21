/*
 * Copyright 2013 Didier Barvaux
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
 * @file   rohc_add_cid.c
 * @brief  Functions related to ROHC add-CID
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_add_cid.h"
#include "rohc_bit_ops.h"


/**
 * @brief The magic bits to find out whether a ROHC packet starts with an
 *        add-CID byte or not
 */
#define ROHC_ADD_CID  0xe


/**
 * @brief Check whether a ROHC packet starts with an add-CID byte or not
 *
 * @param data The ROHC packet with a possible add-CID byte
 * @return     Whether the ROHC packet starts with an add-CID byte or not
 */
bool rohc_add_cid_is_present(const uint8_t *const data)
{
	return (GET_BIT_4_7(data) == ROHC_ADD_CID);
}


/**
 * @brief Decode the add-CID byte of a ROHC packet (if the add-CID byte is
 *        present)
 *
 * @param data The ROHC packet with a possible add-CID byte
 * @return     0 if no add-CID byte is present, the CID value otherwise
 */
uint8_t rohc_add_cid_decode(const uint8_t *const data)
{
	uint8_t cid;

	if(rohc_add_cid_is_present(data))
	{
		cid = GET_BIT_0_3(data);
	}
	else
	{
		cid = 0;
	}

	return cid;
}

