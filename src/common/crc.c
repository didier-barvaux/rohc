/**
 * @file crc.c
 * @brief ROHC CRC routines
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include "crc.h"


unsigned char crc_table_8[256];
unsigned char crc_table_7[256];
unsigned char crc_table_6[256];
unsigned char crc_table_3[256];
unsigned char crc_table_2[256];


/**
 * @brief Get the polynom for the CRC type.
 *
 * @param type The CRC type
 * @return     The polynom for the requested CRC type
 */
int crc_get_polynom(int type)
{
	int polynom;

	switch(type)
	{
		case CRC_TYPE_2:
			polynom = 0x3;
			break;
		case CRC_TYPE_3:
			polynom = 0x6;
			break;
		case CRC_TYPE_6:
			polynom = 0x30;
			break;
		case CRC_TYPE_7:
			polynom = 0x79;
			break;
		case CRC_TYPE_8:
			polynom = 0xe0;
			break;
		default:
			polynom = 0;
			break;
	}

	return polynom;
}


/**
 * @brief Initialize a table given a 256 bytes table and the polynom to use
 *
 * @param table The 256 bytes table
 * @param poly  The polynom
 */
void crc_init_table(unsigned char *table, unsigned char poly)
{
	unsigned char crc;
	int i, j;

	for(i = 0; i < 256; i++)
	{
		crc = i;

		for(j = 0; j < 8; j++)
		{
			if(crc & 1)
				crc = (crc >> 1) ^ poly;
			else
				crc = crc >> 1;
		}

		table[i] = crc;
	}
}


/**
 * @brief Optimized CRC-8 calculation using a table
 *
 * @param buf  The data to compute the CRC for
 * @param size The size of the data
 * @return     The CRC byte
 */
inline unsigned char crc_calc_8(unsigned char *buf, int size)
{
	int i;
	unsigned char crc = 0xff;

	for(i = 0; i < size; i++)
		crc = crc_table_8[buf[i] ^ crc];

	return crc;
}


/**
 * @brief Optimized CRC-7 calculation using a table
 *
 * @param buf  The data to compute the CRC for
 * @param size The size of the data
 * @return     The CRC byte
 */
inline unsigned char crc_calc_7(unsigned char *buf, int size)
{
	int i;
	unsigned char crc = 0x7f;

	for(i = 0; i < size; i++)
		crc = crc_table_7[buf[i] ^ (crc & 127)];

	return crc;
}

/**
 * @brief Optimized CRC-6 calculation using a table
 *
 * @param buf  The data to compute the CRC for
 * @param size The size of the data
 * @return     The CRC byte
 */
inline unsigned char crc_calc_6(unsigned char *buf, int size)
{
	int i;
	unsigned char crc = 0x3f;

	for(i = 0; i < size; i++)
		crc = crc_table_6[buf[i] ^ (crc & 63)];

	return crc;
}

/**
 * @brief Optimized CRC-3 calculation using a table
 *
 * @param buf  The data to compute the CRC for
 * @param size The size of the data
 * @return     The CRC byte
 */
inline unsigned char crc_calc_3(unsigned char *buf, int size)
{
	int i;
	unsigned char crc = 0x7;

	for(i = 0; i < size; i++)
		crc = crc_table_3[buf[i] ^ (crc & 7)];

	return crc;
}

/**
 * @brief Optimized CRC-2 calculation using a table
 *
 * @param buf  The data to compute the CRC for
 * @param size The size of the data
 * @return     The CRC byte
 */
inline unsigned char crc_calc_2(unsigned char *buf, int size)
{
	int i;
	unsigned char crc = 0x3;

	for(i = 0; i < size; i++)
		crc = crc_table_2[buf[i] ^ (crc & 3)];

	return crc;
}

/**
 * @brief Calculate the checksum for the given data.
 *
 * @param type   The CRC type (CRC_TYPE_2, CRC_TYPE_3, CRC_TYPE_6, CRC_TYPE_7 or CRC_TYPE_8)
 * @param data   The data to calculate the checksum on
 * @param length The length of the data
 * @return       The checksum
 */
unsigned int crc_calculate(int type, unsigned char *data, int length)
{
	unsigned int crc;

	switch(type)
	{
		case CRC_TYPE_8:
			crc = crc_calc_8(data, length);
			break;
		case CRC_TYPE_7:
			crc = crc_calc_7(data, length);
			break;
		case CRC_TYPE_6:
			crc = crc_calc_6(data, length);
			break;
		case CRC_TYPE_3:
			crc = crc_calc_3(data, length);
			break;
		case CRC_TYPE_2:
			crc = crc_calc_2(data, length);
			break;
		default:
			crc = 0;
			break;
	}

	return crc;
}

