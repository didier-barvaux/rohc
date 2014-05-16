/*
 * Copyright 2011,2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010 Viveris Technologies
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

/**
 * @file   ip_id_offset.c
 * @brief  Offset IP-ID decoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "ip_id_offset.h"
#include "wlsb.h"

#include <stdlib.h>
#include <assert.h>


/*
 * Private structures
 */

/**
 * @brief Defines a IP-ID object to help computing the IP-ID value
 *        from an IP-ID offset
 */
struct ip_id_offset_decode
{
	/** The LSB context for decoding IP-ID offset */
	struct rohc_lsb_decode *lsb;
};


/*
 * Public functions
 */


/**
 * @brief Create a new Offset IP-ID decoding context
 *
 * See 4.5.5 in the RFC 3095 for details about Offset IP-ID encoding.
 *
 * @return  The new Offset IP-ID decoding context in case of success,
 *          NULL otherwise
 */
struct ip_id_offset_decode * ip_id_offset_new(void)
{
	struct ip_id_offset_decode *ipid;

	ipid = malloc(sizeof(struct ip_id_offset_decode));
	if(ipid == NULL)
	{
		goto error;
	}

	ipid->lsb = rohc_lsb_new(ROHC_LSB_SHIFT_IP_ID, 16);
	if(ipid->lsb == NULL)
	{
		goto destroy_ipid;
	}

	return ipid;

destroy_ipid:
	free(ipid);
error:
	return NULL;
}


/**
 * @brief Destroy a given Offset IP-ID decoding context
 *
 * See 4.5.5 in the RFC 3095 for details about Offset IP-ID encoding.
 *
 * @param ipid  The Offset IP-ID decoding context to destroy
 */
void ip_id_offset_free(struct ip_id_offset_decode *const ipid)
{
	assert(ipid != NULL);
	rohc_lsb_free(ipid->lsb);
	free(ipid);
}


/**
 * @brief Decode the given IP-ID offset
 *
 * @param ipid     The Offset IP-ID object
 * @param m        The IP-ID offset to decode
 * @param k        The number of bits used to code the IP-ID offset
 * @param sn       The SN of the ROHC packet that contains the IP-ID offset
 * @param decoded  OUT: The computed IP-ID
 * @return         true in case of success, false otherwise
 */
bool ip_id_offset_decode(const struct ip_id_offset_decode *const ipid,
                         const uint16_t m,
                         const size_t k,
                         const uint32_t sn,
                         uint16_t *const decoded)
{
	uint32_t offset_decoded;
	bool is_success;

	is_success = rohc_lsb_decode(ipid->lsb, ROHC_LSB_REF_0, 0, m, k,
	                             ROHC_LSB_SHIFT_IP_ID, &offset_decoded);
	if(is_success)
	{
		/* add the decoded offset with SN, taking care of overflow */
		*decoded = (uint16_t) ((sn + offset_decoded) & 0xffff);
	}

	return is_success;
}


/**
 * @brief Update the reference values for the IP-ID and the SN
 *
 * @param ipid    The Offset IP-ID decoding object
 * @param id_ref  The new IP-ID reference
 * @param sn_ref  The new SN reference
 */
void ip_id_offset_set_ref(struct ip_id_offset_decode *const ipid,
                          const uint16_t id_ref,
                          const uint32_t sn_ref)
{
	uint16_t offset_ref;

	/* compute the offset between reference IP-ID and reference SN
	 * (overflow over 16 bits is expected if SN > IP-ID) */
	offset_ref = id_ref - sn_ref;

	rohc_lsb_set_ref(ipid->lsb, offset_ref, false);
}

