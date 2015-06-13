/*
 * Copyright 2012,2013,2014 Didier Barvaux
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
 * @file   decomp/schemes/tcp_ts.h
 * @brief  Handle decoding of TCP TimeStamp (TS) option
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "tcp_ts.h"

#include "rohc_utils.h"

#ifndef __KERNEL__
#  include <string.h>
#endif


/**
 * @brief Parse the LSBs bits of one of the TS echo request/reply fields
 *
 * See RFC4996 page 65
 *
 * @param context        The decompression context
 * @param data           The data to decode
 * @param data_len       The length of the data to decode
 * @param[out] ts_field  The information of TS option field extracted from packet
 * @return               The number of data bytes parsed,
 *                       -1 if data is malformed
 */
int d_tcp_ts_lsb_parse(const struct rohc_decomp_ctxt *const context,
                       const uint8_t *const data,
                       const size_t data_len,
                       struct rohc_lsb_field32 *const ts_field)
{
	const uint8_t *remain_data;
	size_t remain_len;

	remain_data = data;
	remain_len = data_len;

	if(remain_len < 1)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
		             "packet too short for TS LSB: only %zu bytes available "
		             "while at least 1 byte required", remain_len);
		goto error;
	}

	if((remain_data[0] & 0x80) == 0)
	{
		/* discriminator '0' */
		rohc_decomp_debug(context, "TCP TS option: TS field is 1-byte long");
		ts_field->bits = remain_data[0];
		ts_field->bits_nr = 7;
		ts_field->p = ROHC_LSB_SHIFT_TCP_TS_1B;
		remain_len--;
	}
	else if((remain_data[0] & 0x40) == 0)
	{
		/* discriminator '10' */
		rohc_decomp_debug(context, "TCP TS option: TS field is 2-byte long");
		if(remain_len < 2)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for TS LSB: only %zu bytes available "
			             "while at least 2 bytes required", remain_len);
			goto error;
		}
		ts_field->bits = (remain_data[0] & 0x3f) << 8;
		ts_field->bits |= remain_data[1];
		ts_field->bits_nr = 14;
		ts_field->p = ROHC_LSB_SHIFT_TCP_TS_2B;
		remain_len -= 2;
	}
	else if((remain_data[0] & 0x20) == 0)
	{
		/* discriminator '110' */
		rohc_decomp_debug(context, "TCP TS option: TS field is 3-byte long");
		if(remain_len < 3)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for TS LSB: only %zu bytes available "
			             "while at least 3 bytes required", remain_len);
			goto error;
		}
		ts_field->bits = (remain_data[0] & 0x1f) << 16;
		ts_field->bits |= remain_data[1] << 8;
		ts_field->bits |= remain_data[2];
		ts_field->bits_nr = 21;
		ts_field->p = ROHC_LSB_SHIFT_TCP_TS_3B;
		remain_len -= 3;
	}
	else
	{
		/* discriminator '111' */
		rohc_decomp_debug(context, "TCP TS option: TS field is 4-byte long");
		if(remain_len < 4)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for TS LSB: only %zu bytes available "
			             "while at least 4 bytes required", remain_len);
			goto error;
		}
		ts_field->bits = (remain_data[0] & 0x1f) << 24;
		ts_field->bits |= remain_data[1] << 16;
		ts_field->bits |= remain_data[2] << 8;
		ts_field->bits |= remain_data[3];
		ts_field->bits_nr = 29;
		ts_field->p = ROHC_LSB_SHIFT_TCP_TS_4B;
		remain_len -= 4;
	}

	return (data_len - remain_len);

error:
	return -1;
}

