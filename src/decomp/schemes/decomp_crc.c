/*
 * Copyright 2012,2013,2014,2015 Didier Barvaux
 * Copyright 2013,2014 Viveris Technologies
 * Copyright 2012 WBX
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
 * @file   decomp_crc.c
 * @brief  ROHC decompression checks for CRC
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "decomp_crc.h"


/**
 * @brief Check whether the CRC on uncompressed header is correct or not
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param uncomp_hdrs  The uncompressed headers
 * @param crc_pkt      The CRC over uncompressed headers extracted from packet
 * @return             true if the CRC is correct, false otherwise
 */
bool rohc_decomp_check_uncomp_crc(const struct rohc_decomp *const decomp,
                                  const struct rohc_decomp_ctxt *const context,
                                  struct rohc_buf *const uncomp_hdrs,
                                  const struct rohc_decomp_crc_one *const crc_pkt)
{
	const uint8_t *crc_table;
	uint8_t crc_computed;

	/* determine the initial value and the pre-computed table for the CRC */
	switch(crc_pkt->type)
	{
		case ROHC_CRC_TYPE_3:
			crc_computed = CRC_INIT_3;
			crc_table = decomp->crc_table_3;
			break;
		case ROHC_CRC_TYPE_7:
			crc_computed = CRC_INIT_7;
			crc_table = decomp->crc_table_7;
			break;
		case ROHC_CRC_TYPE_8:
			rohc_decomp_warn(context, "unexpected CRC type %d", crc_pkt->type);
			assert(0);
			goto error;
		case ROHC_CRC_TYPE_NONE:
		default:
			rohc_decomp_warn(context, "unknown CRC type %d", crc_pkt->type);
			assert(0);
			goto error;
	}

	/* compute the CRC from built uncompressed headers */
	crc_computed =
		crc_calculate(crc_pkt->type, rohc_buf_data(*uncomp_hdrs), uncomp_hdrs->len,
		              crc_computed, crc_table);
	rohc_decomp_debug(context, "CRC-%d on uncompressed header = 0x%x",
	                  crc_pkt->type, crc_computed);

	/* does the computed CRC match the one in packet? */
	if(crc_computed != crc_pkt->bits)
	{
		rohc_decomp_warn(context, "CRC failure (computed = 0x%02x, packet = "
		                 "0x%02x)", crc_computed, crc_pkt->bits);
		goto error;
	}

	/* computed CRC matches the one in packet */
	return true;

error:
	return false;
}

