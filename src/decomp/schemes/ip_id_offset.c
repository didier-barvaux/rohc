/*
 * Copyright 2011,2012,2013 Didier Barvaux
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
 * @file   decomp/schemes/ip_id_offset.c
 * @brief  Offset IP-ID decoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "ip_id_offset.h"

#include <stdlib.h>
#include <assert.h>


/*
 * Public functions
 */


/**
 * @brief Create a new Offset IP-ID decoding context
 *
 * See 4.5.5 in the RFC 3095 for details about Offset IP-ID encoding.
 *
 * @param[in,out] ipid  The Offset IP-ID decoding context to init
 */
void ip_id_offset_init(struct ip_id_offset_decode *const ipid)
{
	rohc_lsb_init(&ipid->lsb, 16);
}


/**
 * @brief Decode the given IP-ID offset
 *
 * @param ipid     The Offset IP-ID object
 * @param ref_type The reference value to use to decode
 *                 (used for context repair upon CRC failure)
 * @param m        The IP-ID offset to decode
 * @param k        The number of bits used to code the IP-ID offset
 * @param sn       The SN of the ROHC packet that contains the IP-ID offset
 * @param decoded  OUT: The computed IP-ID
 * @return         true in case of success, false otherwise
 */
bool ip_id_offset_decode(const struct ip_id_offset_decode *const ipid,
                         const rohc_lsb_ref_t ref_type,
                         const uint16_t m,
                         const size_t k,
                         const uint32_t sn,
                         uint16_t *const decoded)
{
	uint32_t offset_decoded;
	bool is_success;

	/* RFC4815 §8.2:
	 *   When RND=0 but no IP-ID bits are sent in the compressed header, the
	 *   SN offset for IP-ID stays unchanged, meaning that Offset_m equals
	 *   Offset_ref, as described in Section 4.5.5.  This is further expressed
	 *   in a slightly different way (with the same meaning) in Section 5.7,
	 *   where it is said that "default-slope(IP-ID offset) = 0", meaning, if
	 *   no bits are sent for IP-ID, its SN offset slope defaults to 0.
	 */
	if(k == 0)
	{
		offset_decoded = rohc_lsb_get_ref(&ipid->lsb, ref_type);
		is_success = true;
	}
	else
	{
		/* decode IP-ID / SN offset from the received bits */
		is_success = rohc_lsb_decode(&ipid->lsb, ref_type, 0, m, k,
		                             ROHC_LSB_SHIFT_IP_ID, &offset_decoded);
	}

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
 * @param ipid              The Offset IP-ID decoding object
 * @param id_ref            The new IP-ID reference
 * @param sn_ref            The new SN reference
 * @param keep_ref_minus_1  Keep ref -1 unchanged (used for SN context repair
 *                          after CRC failure, see RFC3095 §5.3.2.2.5)
 */
void ip_id_offset_set_ref(struct ip_id_offset_decode *const ipid,
                          const uint16_t id_ref,
                          const uint32_t sn_ref,
                          const bool keep_ref_minus_1)
{
	uint16_t offset_ref;

	/* compute the offset between reference IP-ID and reference SN
	 * (overflow over 16 bits is expected if SN > IP-ID) */
	offset_ref = id_ref - sn_ref;

	rohc_lsb_set_ref(&ipid->lsb, offset_ref, keep_ref_minus_1);
}

