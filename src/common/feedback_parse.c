/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2013 Viveris Technologies
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
 * @file   feedback_parse.c
 * @brief  Function to parse ROHC feedback
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "feedback_parse.h"

#include "rohc_bit_ops.h"


/** The magic bits to find out whether a ROHC packet is a feedback packet */
#define D_FEEDBACK       (0xf0 >> 3)


/**
 * @brief Find out whether a ROHC packet is a Feedback packet or not
 *
 * @param byte  The first byte of ROHC packet to analyze
 * @return      Whether the ROHC packet is a Feedback packet or not
 */
bool rohc_packet_is_feedback(const uint8_t byte)
{
	return (GET_BIT_3_7(&byte) == D_FEEDBACK);
}


/**
 * @brief Find out the lengths of the feedback header and data
 *
 * See 5.2.2 in the RFC 3095 for details.
 *
 * @param rohc_data               The ROHC data to get feedback lengths from
 * @param[out] feedback_hdr_len   The length of the feedback header (in bytes)
 * @param[out] feedback_data_len  The length of the feedback data (in bytes)
 * @return                        true if feedback parsing was successful,
 *                                false if feedback is malformed
 */
bool rohc_feedback_get_size(const struct rohc_buf rohc_data,
                            size_t *const feedback_hdr_len,
                            size_t *const feedback_data_len)
{
	uint8_t code;

	/* extract the code field */
	if(rohc_data.len < 1)
	{
		goto error;
	}
	code = GET_BIT_0_2(rohc_buf_data(rohc_data));

	/* code:
	 *  - 1-7 indicates the size of the feedback data field in octets,
	 *  - 0 indicates that a size field is present just after the code field */
	if(code != 0)
	{
		*feedback_hdr_len = 1; /* no size field is present */
		*feedback_data_len = code;
	}
	else
	{
		/* extract the size octet */
		if(rohc_data.len < 1)
		{
			goto error;
		}
		*feedback_hdr_len = 2; /* a size field is present */
		*feedback_data_len = GET_BIT_0_7(rohc_buf_data_at(rohc_data, 1));
	}

	return true;

error:
	return false;
}

