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
 * @brief Calculate the size of TimeStamp compressed TCP option
 *
 * @param context      The decompression context
 * @param rohc_data    The remaining ROHC data
 * @param rohc_length  The length (in bytes) of the remaining ROHC data
 * @return             The length (in bytes) of the compressed TCP option,
 *                     -1 in case of problem
 */
int d_tcp_ts_lsb_size(const struct rohc_decomp_ctxt *const context,
                      const uint8_t *const rohc_data,
                      const size_t rohc_length)
{
	size_t lsb_len;

	/* enough data for the discriminator byte? */
	if(rohc_length < 1)
	{
		rohc_decomp_warn(context, "remaining ROHC data too small (%zu bytes) "
		                 "for the LSB-encoded TCP TimeStamp value", rohc_length);
		goto error;
	}

	if(rohc_data[0] & 0x80)
	{
		if(rohc_data[0] & 0x40)
		{
			if(rohc_data[0] & 0x20)
			{
				/* discriminator '111' */
				lsb_len = 4;
			}
			else
			{
				/* iscriminator '110' */
				lsb_len = 3;
			}
		}
		else
		{
			/* discriminator '10' */
			lsb_len = 2;
		}
	}
	else
	{
		/* discriminator '0' */
		lsb_len = 1;
	}

	/* enough data for the full LSB field? */
	if(rohc_length < lsb_len)
	{
		rohc_decomp_warn(context, "remaining ROHC data too small (%zu bytes) "
		                 "for the %zu-byte LSB-encoded TCP TimeStamp value",
		                 rohc_length, lsb_len);
		goto error;
	}

	return lsb_len;

error:
	return -1;
}


/**
 * @brief Decompress the LSBs bits of TimeStamp TCP option
 *
 * See RFC4996 page 65
 *
 * @param context    The decompression context
 * @param lsb        The LSB decoding context
 * @param data       The data to decode
 * @param data_len   The length of the data to decode
 * @param timestamp  Pointer to the uncompressed value
 * @return           The number of data bytes parsed,
 *                   -1 if data is malformed
 */
int d_tcp_ts_lsb_decode(const struct rohc_decomp_ctxt *const context,
                        const struct rohc_lsb_decode *const lsb,
                        const uint8_t *const data,
                        const size_t data_len,
                        uint32_t *const timestamp)
{
	uint32_t ts_bits;
	size_t ts_bits_nr;
	rohc_lsb_shift_t p;
	bool decode_ok;
	uint32_t decoded;
	uint32_t decoded_nbo;
	const uint8_t *remain_data;
	size_t remain_len;

	assert(context != NULL);
	assert(lsb != NULL);
	assert(data != NULL);
	assert(timestamp != NULL);

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
		ts_bits = remain_data[0];
		ts_bits_nr = 7;
		p = -1;
		remain_len--;
	}
	else if((remain_data[0] & 0x40) == 0)
	{
		/* discriminator '10' */
		if(remain_len < 2)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for TS LSB: only %zu bytes available "
			             "while at least 2 bytes required", remain_len);
			goto error;
		}
		ts_bits = (remain_data[0] & 0x3f) << 8;
		ts_bits |= remain_data[1];
		ts_bits_nr = 14;
		p = -1;
		remain_len -= 2;
	}
	else if((remain_data[0] & 0x20) == 0)
	{
		/* discriminator '110' */
		if(remain_len < 3)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for TS LSB: only %zu bytes available "
			             "while at least 3 bytes required", remain_len);
			goto error;
		}
		ts_bits = (remain_data[0] & 0x1f) << 16;
		ts_bits |= remain_data[1] << 8;
		ts_bits |= remain_data[2];
		ts_bits_nr = 21;
		p = 0x40000;
		remain_len -= 3;
	}
	else
	{
		/* discriminator '111' */
		if(remain_len < 4)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for TS LSB: only %zu bytes available "
			             "while at least 4 bytes required", remain_len);
			goto error;
		}
		ts_bits = (remain_data[0] & 0x1f) << 24;
		ts_bits |= remain_data[1] << 16;
		ts_bits |= remain_data[2] << 8;
		ts_bits |= remain_data[3];
		ts_bits_nr = 29;
		p = 0x40000;
		remain_len -= 4;
	}

	decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, ts_bits, ts_bits_nr, p,
	                            &decoded);
	if(!decode_ok)
	{
		rohc_decomp_warn(context, "failed to decode %zu timestamp bits 0x%x "
		                 "with p = %u", ts_bits_nr, ts_bits, p);
		goto error;
	}
	rohc_decomp_debug(context, "decoded timestamp = 0x%08x (%zu bits 0x%x "
	                  "with ref 0x%08x and p = %d)", decoded, ts_bits_nr,
	                  ts_bits, rohc_lsb_get_ref(lsb, ROHC_LSB_REF_0), p);

	decoded_nbo = rohc_hton32(decoded);
	memcpy(timestamp, &decoded_nbo, sizeof(uint32_t));

	return (data_len - remain_len);

error:
	return -1;
}

