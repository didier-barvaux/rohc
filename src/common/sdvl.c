/*
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file sdvl.c
 * @brief Self-Describing Variable-Length (SDVL) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#include "sdvl.h"
#include "rohc_bit_ops.h"
#include "rohc_traces.h"

#include <assert.h>


/**
 * @brief Find out how many bytes are needed to represent the value using
 *        Self-Describing Variable-Length (SDVL) encoding
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param value  The value to encode
 * @param length The length of the value to encode
 *               (0 to let the SDVL encoding find the length itself)
 * @return       The size needed to represent the SDVL-encoded value
 */
size_t c_bytesSdvl(uint32_t value, size_t length)
{
	size_t size;

	if(length == 0)
	{
		/* value length is unknown, find the length ourselves, then
		 * find the length for SDVL-encoding */
		if(value <= 127)
			size = 1;
		else if(value <= 16383)
			size = 2;
		else if(value <= 2097151)
			size = 3;
		else if(value <= 536870911)
			size = 4;
		else
		{
			rohc_debugf(0, "value %d is too large for SDVL-encoding\n", value);
			size = 5;
		}
	}
	else
	{
		/* value length is known, find the length for SDVL-encoding */
		if(length <= MAX_BITS_IN_1_BYTE_SDVL)
			size = 1;
		else if(length <= MAX_BITS_IN_2_BYTE_SDVL)
			size = 2;
		else if(length <= MAX_BITS_IN_3_BYTE_SDVL)
			size = 3;
		else if(length <= MAX_BITS_IN_4_BYTE_SDVL)
			size = 4;
		else
		{
			rohc_debugf(0, "value %d on %d bits is too large for SDVL-encoding\n",
			            value, length);
			size = 5;
		}
	}

	return size;
}


/**
 * @brief Encode a value using Self-Describing Variable-Length (SDVL) encoding
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param dest   The destination to write the SDVL-encoded to
 * @param value  The value to encode
 * @param length The length of the value to encode
 *               (0 to let the SDVL encoding find the length itself)
 * @return       1 if SDVL encoding is successful, 0 in case of failure
 *               (failure may be due to a value greater than 2^29)
 */
int c_encodeSdvl(unsigned char *dest, uint32_t value, size_t length)
{
	size_t size;

	/* check destination buffer validity */
	assert(dest != NULL);

	/* find out the number of bytes needed to represent the SDVL-encoded value */
	size = c_bytesSdvl(value, length);
	assert(size > 0 && size <= 5);
	if(size > 4)
	{
		/* number of bytes needed is too large (value must be < 2^29) */
		goto error;
	}

	/* encode the value according to the number of available bytes */
	switch(size)
	{
		case 4:
			/* 7 = bit pattern 111 */
			*dest++ = ((7 << 5) | ((value >> 24) & 0x1f)) & 0xff;
			*dest++ = (value >> 16) & 0xff;
			*dest++ = (value >> 8) & 0xff;
			*dest = value & 0xff;
			break;

		case 3:
			/* 6 = bit pattern 110 */
			*dest++ = ((6 << 5) | ((value >> 16) & 0x1f)) & 0xff;
			*dest++ = (value >> 8) & 0xff;
			*dest = value & 0xff;
			break;

		case 2:
			/* 2 = bit pattern 10 */
			*dest++ = ((2 << 6) | ((value >> 8) & 0x3f)) & 0xff;
			*dest = value & 0xff;
			break;

		case 1:
			/* bit pattern 0 */
			*dest = value & 0x7f;
			break;

		default:
			rohc_debugf(0, "invalid length (%zd) for SDVL encoding\n", size);
			assert(0);
			break;
	}

	return 1;

error:
	return 0;
}


/**
 * @brief Find out a size of the Self-Describing Variable-Length (SDVL) value
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param data The SDVL data to analyze
 * @return     The size of the SDVL value (possible values are 1-4)
 */
int d_sdvalue_size(const unsigned char *data)
{
	int size;
	
	if(!GET_BIT_7(data)) /* bit == 0 */
		size = 1;
	else if(GET_BIT_6_7(data) == (0x8 >> 2)) /* bits == 0b10 */
		size = 2;
	else if(GET_BIT_5_7(data) == (0xc >> 1)) /* bits == 0b110 */
		size = 3;
	else if(GET_BIT_5_7(data) == (0xe >> 1)) /* bits == 0b111 */
		size = 4;
	else
	{
		size = -1;
		rohc_debugf(0, "Bad SDVL data, this should not append\n");
	}

	return size;
}


/**
 * @brief Decode a Self-Describing Variable-Length (SDVL) value
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param data The SDVL data to decode
 * @return     The decoded value
 */
int d_sdvalue_decode(const unsigned char *data)
{
	int value;

	if(!GET_BIT_7(data)) /* bit == 0 */
		value = GET_BIT_0_6(data);
	else if(GET_BIT_6_7(data) == (0x8 >> 2)) /* bits == 0b10 */
		value = (GET_BIT_0_5(data) << 8 | GET_BIT_0_7(data + 1));
	else if(GET_BIT_5_7(data) == (0xc >> 1)) /* bits == 0b110 */
		value = (GET_BIT_0_4(data) << 16 |
		         GET_BIT_0_7(data + 1) << 8 |
		         GET_BIT_0_7(data + 2)); 
	else if(GET_BIT_5_7(data) == (0xe >> 1)) /* bits == 0b111 */
		value = (GET_BIT_0_4(data) << 24 |
		         GET_BIT_0_7(data + 1) << 16 |
		         GET_BIT_0_7(data + 2) << 8 |
		         GET_BIT_0_7(data + 3));
	else
		value = -1; /* should not happen */

	return value;
}

