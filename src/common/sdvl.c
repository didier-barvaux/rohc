/**
 * @file sdvl.c
 * @brief Self-Describing Variable-Length (SDVL) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#include "sdvl.h"
#include "rohc_traces.h"


/**
 * @brief Find out how many bytes are needed to represent the value using
 *        Self-Describing Variable-Length (SDVL) encoding
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param value  The value to encode
 * @param length The length of the value to encode (-1 to let the SDVL encoding
 *               find the length itself)
 * @return       The size needed to represent the SDVL-encoded value
 */
int c_bytesSdvl(int value, int length)
{
	int size;

	if(length < 0)
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
			size = 5;
	}
	else
	{
		/* value length is known, find the length for SDVL-encoding */
		if(length <= 7)
			size = 1;
		else if(length <= 14)
			size = 2;
		else if(length <= 21)
			size = 3;
		else if(length <= 29)
			size = 4;
		else
			size = 5;
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
 * @return       Whether the SDVL encoding is successful or not (failure may be
 *               due to a value greater than 2^29)
 */
boolean c_encodeSdvl(unsigned char *dest, int value, int length)
{
	boolean status = ROHC_FALSE;
	int size;

	/* check destination buffer validity */
	if(dest == NULL)
		goto quit;

	/* find out the number of bytes needed to represent
	 * the SDVL-encoded value */
	size = c_bytesSdvl(value, length);

	/* check if the number of bytes needed is not too large (must be < 2^29) */
	if(size > 4 )
		goto quit;

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
	}

	status = ROHC_TRUE;

quit:
	return status;
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

