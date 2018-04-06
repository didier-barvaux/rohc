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
 * @file   /comp/schemes/tcp_sack.c
 * @brief  Handle encoding of TCP Selective ACKnowledgement (SACK) option
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "tcp_sack.h"

#include "rohc_utils.h"


static int c_tcp_sack_code_block(const struct rohc_comp_ctxt *const context,
                                 const uint32_t reference,
                                 const sack_block_t *const sack_block,
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 4)));

static int c_tcp_sack_code_pure_lsb(const struct rohc_comp_ctxt *const context,
                                    const uint32_t base,
                                    const uint32_t field,
                                    uint8_t *const rohc_data,
                                    const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 4)));


/**
 * @brief Compress one TCP Selective ACKnowledgement (SACK) option
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context         The compression context
 * @param ack_value       The ack value
 * @param sack_blocks     The SACK blocks to compress
 * @param length          The length of the SACK blocks
 * @param is_unchanged    Whether the SACK option is unchanged or not
 *                        (only for irregular chain, use false for list item)
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
int c_tcp_opt_sack_code(const struct rohc_comp_ctxt *const context,
                        const uint32_t ack_value,
                        const sack_block_t *const sack_blocks,
                        const uint8_t length,
                        const bool is_unchanged,
                        uint8_t *const rohc_data,
                        const size_t rohc_max_len)
{
	uint8_t * rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;
	const sack_block_t *block;
	size_t blocks_nr;
	size_t i;
	int ret;

	rohc_comp_debug(context, "%schanged TCP option SACK (reference ACK = 0x%08x)",
	                (is_unchanged ? "un" : ""), ack_value);
	rohc_comp_dump_buf(context, "TCP option SACK", (uint8_t *) sack_blocks, length);

	if(rohc_max_len < 1)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP option SACK "
		               "part: 1 byte required, but only %zu bytes available",
		               rohc_max_len);
		goto error;
	}

	/* the irregular chain supports a special encoding for unchanged option */
	if(is_unchanged)
	{
		rohc_remain_data[0] = 0x00;
		rohc_remain_data++;
		rohc_remain_len--;
	}
	else
	{
		uint32_t reference;

		/* determine the number of SACK blocks
		 * (integer division checked by \ref c_tcp_check_profile ) */
		blocks_nr = length / sizeof(sack_block_t);
		rohc_remain_data[0] = blocks_nr;
		rohc_remain_data++;
		rohc_remain_len--;

		/* compress every SACK block, one by one:
		 *  - first block uses ACK as reference
		 *  - next block uses current block end as reference */
		for(i = 0, reference = ack_value, block = sack_blocks;
		    i < blocks_nr;
		    i++, reference = rohc_ntoh32(block->block_end), block++)
		{
			rohc_comp_debug(context, "block of SACK option: reference = 0x%08x, "
			                "start = 0x%08x, end = 0x%08x", reference,
			                rohc_ntoh32(block->block_start),
			                rohc_ntoh32(block->block_end));
			ret = c_tcp_sack_code_block(context, reference, block,
			                            rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to encode SACK block #%zu", i + 1);
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
		}
	}

	return (rohc_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Compress one SACK block
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context         The compression context
 * @param reference       The reference value
 * @param sack_block      The SACK block to compress
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_sack_code_block(const struct rohc_comp_ctxt *const context,
                                 const uint32_t reference,
                                 const sack_block_t *const sack_block,
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len)
{
	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;
	int ret;

	rohc_comp_debug(context, "reference = 0x%x, block_start = 0x%x, block_end "
	                "= 0x%x", reference, rohc_ntoh32(sack_block->block_start),
	                rohc_ntoh32(sack_block->block_end));

	/* block_start =:= sack_var_length_enc(reference) */
	ret = c_tcp_sack_code_pure_lsb(context, reference,
	                               rohc_ntoh32(sack_block->block_start),
	                               rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode the SACK block start");
		goto error;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* block_end =:= sack_var_length_enc(block_start) */
	ret = c_tcp_sack_code_pure_lsb(context, rohc_ntoh32(sack_block->block_start),
	                               rohc_ntoh32(sack_block->block_end),
	                               rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode the SACK block end");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

	return (rohc_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Compress one SACK field value
 *
 * See RFC6846 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context         The compression context
 * @param base            The base value
 * @param field           The value to compress
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_sack_code_pure_lsb(const struct rohc_comp_ctxt *const context,
                                    const uint32_t base,
                                    const uint32_t field,
                                    uint8_t *const rohc_data,
                                    const size_t rohc_max_len)
{
	/* if base can be >= field, overflow is expected */
	const uint32_t sack_field = field - base;
	size_t len;

	if(sack_field < 0x8000)
	{
		/* 2 bytes with discriminator '0' */
		len = 2;
		if(rohc_max_len < len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the SACK pure LSB: "
			               "%zu bytes required, but only %zu bytes available",
			               len, rohc_max_len);
			goto error;
		}
		rohc_data[0] = (sack_field >> 8) & 0x7f;
		rohc_data[1] = sack_field & 0xff;
	}
	else if(sack_field < 0x400000)
	{
		/* 3 bytes with discriminator '10' */
		len = 3;
		if(rohc_max_len < len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the SACK pure LSB: "
			               "%zu bytes required, but only %zu bytes available",
			               len, rohc_max_len);
			goto error;
		}
		rohc_data[0] = 0x80 | ((sack_field >> 16) & 0x3f);
		rohc_data[1] = (sack_field >> 8) & 0xff;
		rohc_data[2] = sack_field & 0xff;
	}
	else if(sack_field < 0x20000000)
	{
		/* 4 bytes with discriminator '110' */
		len = 4;
		if(rohc_max_len < len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the SACK pure LSB: "
			               "%zu bytes required, but only %zu bytes available",
			               len, rohc_max_len);
			goto error;
		}
		rohc_data[0] = 0xc0 | ((sack_field >> 24) & 0x1f);
		rohc_data[1] = (sack_field >> 16) & 0xff;
		rohc_data[2] = (sack_field >> 8) & 0xff;
		rohc_data[3] = sack_field & 0xff;
	}
	else
	{
		/* 5 bytes with discriminator '11111111' */
		len = 5;
		if(rohc_max_len < len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the SACK pure LSB: "
			               "%zu bytes required, but only %zu bytes available",
			               len, rohc_max_len);
			goto error;
		}
		rohc_data[0] = 0xff;
		rohc_data[1] = (sack_field >> 24) & 0xff;
		rohc_data[2] = (sack_field >> 16) & 0xff;
		rohc_data[3] = (sack_field >> 8) & 0xff;
		rohc_data[4] = sack_field & 0xff;
	}

	rohc_comp_debug(context, "sack_field = 0x%x (0x%x - 0x%x) encoded on %zu "
	                "bytes (discriminator included)", sack_field, field,
	                base, len);

	return len;

error:
	return -1;
}

