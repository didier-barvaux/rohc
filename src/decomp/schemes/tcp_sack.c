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
 * @file   tcp_sack.c
 * @brief  Decompression scheme for the TCP SACK option
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "tcp_sack.h"

#include "rohc_utils.h"

static int d_tcp_sack_block_size(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const rohc_data,
                                 const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int d_tcp_sack_field_size(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const rohc_data,
                                 const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int d_tcp_sack_block(const struct rohc_decomp_ctxt *const context,
                            const uint8_t *const data,
                            const size_t data_len,
                            sack_block_t *const sack_block)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int d_tcp_sack_pure_lsb(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const data,
                               const size_t data_len,
                               uint32_t *const field)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));


/**
 * @brief Compute the size of the SACK TCP option
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context      The decompression context
 * @param rohc_data    The remaining ROHC data to parse
 * @param rohc_length  The length (in bytes) of the remaining ROHC data
 * @param uncomp_len   The length (in bytes) of the uncompressed TCP option
 * @return             The size (in bytes) of the compressed value,
 *                     -1 in case of problem
 */
int d_tcp_sack_size(const struct rohc_decomp_ctxt *const context,
                    const uint8_t *const rohc_data,
                    const size_t rohc_length,
                    uint16_t *const uncomp_len)
{
	const uint8_t *remain_data;
	size_t remain_len;
	uint8_t discriminator;
	size_t size = 0;
	size_t i;

	assert(context != NULL);
	assert(rohc_data != NULL);
	assert(uncomp_len != NULL);

	remain_data = rohc_data;
	remain_len = rohc_length;

	/* parse discriminator */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "remaining ROHC data too small (%zu bytes) "
		                 "for the discriminator of the compressed TCP SACK "
		                 "option", remain_len);
		goto error;
	}
	discriminator = remain_data[0];
	remain_data++;
	remain_len--;
	size++;
	if(discriminator > 4)
	{
		rohc_decomp_warn(context, "invalid discriminator value (%d)",
		                 discriminator);
		goto error;
	}

	for(i = 0; i < discriminator; i++)
	{
		const int block_len = d_tcp_sack_block_size(context, remain_data, remain_len);
		if(block_len < 0)
		{
			rohc_decomp_warn(context, "failed to determine the length of SACK "
			                 "block #%zu", i + 1);
			goto error;
		}
		remain_data += block_len;
		remain_len -= block_len;
		size += block_len;
	}

	rohc_decomp_debug(context, "TCP SACK option is compressed on %zu bytes",
	                  size);

	return size;

error:
	return -1;
}


/**
 * @brief Parse the SACK TCP option
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context        The decompression context
 * @param data           The ROHC data to parse
 * @param data_len       The length of the ROHC data to parse
 * @param[out] opt_sack  The information of SACK option extracted from the packet
 * @return               The number of ROHC bytes parsed,
 *                       -1 if packet is malformed
 */
int d_tcp_sack_parse(const struct rohc_decomp_ctxt *const context,
                     const uint8_t *const data,
                     const size_t data_len,
                     struct d_tcp_opt_sack *const opt_sack)
{
	const uint8_t *remain_data;
	size_t remain_data_len;
	uint8_t discriminator;
	int i;

	rohc_decomp_debug(context, "parse SACK option");

	remain_data = data;
	remain_data_len = data_len;

	/* parse discriminator */
	if(remain_data_len < 1)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
		             "packet too short for the discriminator of the TCP SACK "
		             "option: only %zu bytes available while at least 1 byte "
		             "required", remain_data_len);
		goto error;
	}
	discriminator = remain_data[0];
	remain_data++;
	remain_data_len--;
	if(discriminator > TCP_SACK_BLOCKS_MAX_NR)
	{
		rohc_decomp_warn(context, "invalid discriminator value (%d)",
		                 discriminator);
		goto error;
	}

	/* parse up to 4 SACK blocks */
	for(i = 0; i < discriminator; i++)
	{
		const int ret = d_tcp_sack_block(context, remain_data, remain_data_len,
		                                 &(opt_sack->blocks[i]));
		if(ret < 0)
		{
			rohc_decomp_warn(context, "failed to parse block #%d of SACK "
			                 "option", i + 1);
			goto error;
		}
		remain_data += ret;
		remain_data_len -= ret;
		rohc_decomp_debug(context, "block #%d of SACK option: start bits = 0x%08x, "
		                  "end bits = 0x%08x", i + 1, opt_sack->blocks[i].block_start,
		                  opt_sack->blocks[i].block_end);
	}
	opt_sack->blocks_nr = discriminator;

	return (data_len - remain_data_len);

error:
	return -1;
}


/**
 * @brief Calculate the size of the compressed SACK block
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context      The decompression context
 * @param rohc_data    The remaining ROHC data to parse
 * @param rohc_length  The length (in bytes) of the remaining ROHC data
 * @return             The size (in bytes) of the compressed value,
 *                     -1 in case of problem
 */
static int d_tcp_sack_block_size(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const rohc_data,
                                 const size_t rohc_length)
{
	const uint8_t *remain_data = rohc_data;
	size_t remain_len = rohc_length;
	size_t size = 0;
	int ret;

	/* parse block start */
	ret = d_tcp_sack_field_size(context, remain_data, remain_len);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to parse the TCP SACK block start");
		goto error;
	}
	remain_data += ret;
	remain_len -= ret;
	size += ret;

	/* parse block end */
	ret = d_tcp_sack_field_size(context, remain_data, remain_len);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to parse the TCP SACK block end");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += ret;
	remain_len -= ret;
#endif
	size += ret;

	return size;

error:
	return -1;
}

/**
 * @brief Calculate the size of the compressed SACK field value
 *
 * See RFC6846 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context      The decompression context
 * @param rohc_data    The remaining ROHC data to parse
 * @param rohc_length  The length (in bytes) of the remaining ROHC data
 * @return             The size (in bytes) of the compressed value,
 *                     -1 in case of problem
 */
static int d_tcp_sack_field_size(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const rohc_data,
                                 const size_t rohc_length)
{
	size_t block_len;

	/* enough data for discriminator? */
	if(rohc_length < 1)
	{
		rohc_decomp_warn(context, "remaining ROHC data too small (%zu bytes) "
		                 "for the discriminator of SACK block_start or SACK "
		                 "block_end", rohc_length);
		goto error;
	}

	if((rohc_data[0] & 0x80) == 0)
	{
		/* discriminator '0' */
		block_len = 2;
	}
	else if((rohc_data[0] & 0x40) == 0)
	{
		/* discriminator '10' */
		block_len = 3;
	}
	else if((rohc_data[0] & 0x20) == 0)
	{
		/* discriminator '110' */
		block_len = 4;
	}
	else if(rohc_data[0] == 0xff)
	{
		/* discriminator '11111111' */
		block_len = 5;
	}
	else
	{
		rohc_decomp_warn(context, "invalid discriminator (%u) for the SACK "
		                 "block_start or SACK block_end", rohc_data[0]);
		block_len = -1;
	}

	/* enough data for the whole compressed data? */
	if(rohc_length < block_len)
	{
		rohc_decomp_warn(context, "remaining ROHC data too small (%zu bytes) "
		                 "for the %zu-byte SACK block_start or SACK block_end",
		                 rohc_length, block_len);
		goto error;
	}

	return block_len;

error:
	return -1;
}


/**
 * @brief Parse a SACK block of the TCP SACK option
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context          The decompression context
 * @param data             The data to parse
 * @param data_len         The length of the data to parse
 * @param[out] sack_block  The SACK block bits extracted from ROHC packet
 * @return                 The number of data bytes parsed,
 *                         -1 if data is malformed
 */
static int d_tcp_sack_block(const struct rohc_decomp_ctxt *const context,
                            const uint8_t *const data,
                            const size_t data_len,
                            sack_block_t *const sack_block)
{
	const uint8_t *remain_data = data;
	size_t remain_len = data_len;
	int ret;

	/* parse block start */
	ret = d_tcp_sack_pure_lsb(context, remain_data, remain_len,
	                          &sack_block->block_start);
	if(ret < 0)
	{
		goto error;
	}
	remain_data += ret;
	remain_len -= ret;

	/* parse block end */
	ret = d_tcp_sack_pure_lsb(context, remain_data, remain_len,
	                          &sack_block->block_end);
	if(ret < 0)
	{
		goto error;
	}
	remain_data += ret;
	remain_len -= ret;

	return (data_len - remain_len);

error:
	return -1;
}


/**
 * @brief Parse a SACK field of a SACK block of the TCP SACK option
 *
 * See RFC6846 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context          The decompression context
 * @param data             The ROHC data to parse
 * @param data_len         The length of the ROHC data to parse
 * @param[out] sack_field  The uncompressed SACK field
 * @return                 The number of data bytes parsed,
 *                         -1 if data is malformed
 */
static int d_tcp_sack_pure_lsb(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const data,
                               const size_t data_len,
                               uint32_t *const sack_field)
{
	const uint8_t *remain_data = data;
	size_t remain_len = data_len;

	if(remain_len < 2)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
		             "packet too short for the discriminator of the TCP pure "
		             "field: only %zu bytes available while at least 2 bytes "
		             "required", remain_len);
		goto error;
	}

	if((remain_data[0] & 0x80) == 0)
	{
		/* discriminator '0' */
		rohc_decomp_debug(context, "SACK block is 2-byte long");
		(*sack_field) = *(remain_data++) << 8;
		(*sack_field) |= *(remain_data++);
		remain_len -= 2;
	}
	else if((remain_data[0] & 0x40) == 0)
	{
		/* discriminator '10' */
		rohc_decomp_debug(context, "SACK block is 3-byte long");
		if(remain_len < 3)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for the discriminator of the TCP pure "
			             "field: only %zu bytes available while at least 3 bytes "
			             "required", remain_len);
			goto error;
		}
		(*sack_field) = *(remain_data++) & 0x3f;
		(*sack_field) <<= 8;
		(*sack_field) |= *(remain_data++);
		(*sack_field) <<= 8;
		(*sack_field) |= *(remain_data++);
		remain_len -= 3;
	}
	else if((remain_data[0] & 0x20) == 0)
	{
		/* discriminator '110' */
		rohc_decomp_debug(context, "SACK block is 4-byte long");
		if(remain_len < 4)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for the discriminator of the TCP pure "
			             "field: only %zu bytes available while at least 4 bytes "
			             "required", remain_len);
			goto error;
		}
		(*sack_field) = *(remain_data++) & 0x1f;
		(*sack_field) <<= 8;
		(*sack_field) |= *(remain_data++);
		(*sack_field) <<= 8;
		(*sack_field) |= *(remain_data++);
		(*sack_field) <<= 8;
		(*sack_field) |= *(remain_data++);
		remain_len -= 4;
	}
	else if(remain_data[0] == 0xff)
	{
		/* discriminator '11111111' */
		rohc_decomp_debug(context, "SACK block is 5-byte long");
		if(remain_len < 5)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for the discriminator of the TCP pure "
			             "field: only %zu bytes available while at least 5 bytes "
			             "required", remain_len);
			goto error;
		}
		remain_data++; /* skip discriminator */
		(*sack_field) = *(remain_data++);
		(*sack_field) <<= 8;
		(*sack_field) |= *(remain_data++);
		(*sack_field) <<= 8;
		(*sack_field) |= *(remain_data++);
		(*sack_field) <<= 8;
		(*sack_field) |= *(remain_data++);
		remain_len -= 5;
	}
	else
	{
		rohc_decomp_warn(context, "malformed SACK block: unexpected "
		                 "discriminator 0x%02x", remain_data[0]);
		goto error;
	}

	return (data_len - remain_len);

error:
	return -1;
}

