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


/** The maximum values that can be SDVL-encoded in 1, 2, 3 and 4 bytes */
typedef enum
{
	/** Maximum value in 1 SDVL-encoded byte */
	ROHC_SDVL_MAX_VALUE_IN_1_BYTE = ((1 << ROHC_SDVL_MAX_BITS_IN_1_BYTE) - 1),
	/** Maximum value in 2 SDVL-encoded byte */
	ROHC_SDVL_MAX_VALUE_IN_2_BYTES = ((1 << ROHC_SDVL_MAX_BITS_IN_2_BYTES) - 1),
	/** Maximum value in 3 SDVL-encoded byte */
	ROHC_SDVL_MAX_VALUE_IN_3_BYTES = ((1 << ROHC_SDVL_MAX_BITS_IN_3_BYTES) - 1),
	/** Maximum value in 4 SDVL-encoded byte */
	ROHC_SDVL_MAX_VALUE_IN_4_BYTES = ((1 << ROHC_SDVL_MAX_BITS_IN_4_BYTES) - 1),
} rohc_sdvl_max_value_t;


/**
 * @brief Can the given value be encoded with SDVL?
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param value  The value to encode
 * @return       Whether the value can be encoded with SDVL or not
 */
bool sdvl_can_value_be_encoded(uint32_t value)
{
	return (value <= ROHC_SDVL_MAX_VALUE_IN_4_BYTES);
}


/**
 * @brief Is the given length (in bits) compatible with SDVL?
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param bits_nr  The length (in bits) of the value to encode
 * @return         Whether the value can be encoded with SDVL or not
 */
bool sdvl_can_length_be_encoded(size_t bits_nr)
{
	return (bits_nr <= ROHC_SDVL_MAX_BITS_IN_4_BYTES);
}


/**
 * @brief Find out how many SDVL bits are needed to represent a value
 *
 * The number of bits already encoded in another field may be specified.
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param nr_min_required  The minimum required number of bits to encode
 * @param nr_encoded       The number of bits already encoded in another field
 * @return                 The number of bits needed to encode the value
 */
size_t sdvl_get_min_len(const size_t nr_min_required,
                        const size_t nr_encoded)
{
	size_t nr_needed;

	if(nr_min_required <= nr_encoded)
	{
		nr_needed = 0;
	}
	else
	{
		const size_t remaining = nr_min_required - nr_encoded;

		if(remaining <= ROHC_SDVL_MAX_BITS_IN_1_BYTE)
		{
			nr_needed = ROHC_SDVL_MAX_BITS_IN_1_BYTE;
		}
		else if(remaining <= ROHC_SDVL_MAX_BITS_IN_2_BYTES)
		{
			nr_needed = ROHC_SDVL_MAX_BITS_IN_2_BYTES;
		}
		else if(remaining <= ROHC_SDVL_MAX_BITS_IN_3_BYTES)
		{
			nr_needed = ROHC_SDVL_MAX_BITS_IN_3_BYTES;
		}
		else
		{
			nr_needed = ROHC_SDVL_MAX_BITS_IN_4_BYTES;
		}
	}

	return nr_needed;
}


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
		if(value <= ROHC_SDVL_MAX_VALUE_IN_1_BYTE)
		{
			size = 1;
		}
		else if(value <= ROHC_SDVL_MAX_VALUE_IN_2_BYTES)
		{
			size = 2;
		}
		else if(value <= ROHC_SDVL_MAX_VALUE_IN_3_BYTES)
		{
			size = 3;
		}
		else if(value <= ROHC_SDVL_MAX_VALUE_IN_4_BYTES)
		{
			size = 4;
		}
		else
		{
			rohc_debugf(0, "value %d is too large for SDVL-encoding\n", value);
			size = 5;
		}
	}
	else
	{
		/* value length is known, find the length for SDVL-encoding */
		if(length <= ROHC_SDVL_MAX_BITS_IN_1_BYTE)
		{
			size = 1;
		}
		else if(length <= ROHC_SDVL_MAX_BITS_IN_2_BYTES)
		{
			size = 2;
		}
		else if(length <= ROHC_SDVL_MAX_BITS_IN_3_BYTES)
		{
			size = 3;
		}
		else if(length <= ROHC_SDVL_MAX_BITS_IN_4_BYTES)
		{
			size = 4;
		}
		else
		{
			rohc_debugf(0, "value %d on %zd bits is too large for SDVL-encoding\n",
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
	{
		size = 1;
	}
	else if(GET_BIT_6_7(data) == (0x8 >> 2)) /* bits == 0b10 */
	{
		size = 2;
	}
	else if(GET_BIT_5_7(data) == (0xc >> 1)) /* bits == 0b110 */
	{
		size = 3;
	}
	else if(GET_BIT_5_7(data) == (0xe >> 1)) /* bits == 0b111 */
	{
		size = 4;
	}
	else
	{
		size = -1;
		rohc_debugf(0, "Bad SDVL data, this should not happen\n");
	}

	return size;
}


/**
 * @brief Decode a Self-Describing Variable-Length (SDVL) value
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param data     The SDVL data to decode
 * @param length   The maximum data length available (in bytes)
 * @param value    OUT: The decoded value
 * @param bits_nr  OUT: The number of useful bits
 * @return         The number of bytes used by the SDVL field
 */
size_t sdvl_decode(const unsigned char *data,
                   const size_t length,
                   uint32_t *const value,
                   size_t *const bits_nr)
{
	size_t sdvl_len;

	assert(data != NULL);
	assert(value != NULL);
	assert(bits_nr != NULL);

	if(length < 1)
	{
		rohc_debugf(0, "packet too small to decode SDVL field (len = %zd)\n",
		            length);
		goto error;
	}

	if(!GET_BIT_7(data)) /* bit == 0 */
	{
		*value = GET_BIT_0_6(data);
		*bits_nr = ROHC_SDVL_MAX_BITS_IN_1_BYTE;
		sdvl_len = 1;
	}
	else if(GET_BIT_6_7(data) == (0x8 >> 2)) /* bits == 0b10 */
	{
		if(length < 2)
		{
			rohc_debugf(0, "packet too small to decode SDVL field (len = %zd)\n",
			            length);
			goto error;
		}
		*value = (GET_BIT_0_5(data) << 8 | GET_BIT_0_7(data + 1));
		*bits_nr = ROHC_SDVL_MAX_BITS_IN_2_BYTES;
		sdvl_len = 2;
	}
	else if(GET_BIT_5_7(data) == (0xc >> 1)) /* bits == 0b110 */
	{
		if(length < 3)
		{
			rohc_debugf(0, "packet too small to decode SDVL field (len = %zd)\n",
			            length);
			goto error;
		}
		*value = (GET_BIT_0_4(data) << 16 |
		          GET_BIT_0_7(data + 1) << 8 |
		          GET_BIT_0_7(data + 2));
		*bits_nr = ROHC_SDVL_MAX_BITS_IN_3_BYTES;
		sdvl_len = 3;
	}
	else if(GET_BIT_5_7(data) == (0xe >> 1)) /* bits == 0b111 */
	{
		if(length < 4)
		{
			rohc_debugf(0, "packet too small to decode SDVL field (len = %zd)\n",
			            length);
			goto error;
		}
		*value = (GET_BIT_0_4(data) << 24 |
		          GET_BIT_0_7(data + 1) << 16 |
		          GET_BIT_0_7(data + 2) << 8 |
		          GET_BIT_0_7(data + 3));
		*bits_nr = ROHC_SDVL_MAX_BITS_IN_4_BYTES;
		sdvl_len = 4;
	}
	else
	{
		rohc_debugf(0, "bad SDVL-encoded field length (0x%02x)\n", data[0]);
		goto error;
	}

	return sdvl_len;

error:
	return 0;
}

