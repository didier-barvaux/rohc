/**
 * @file crc.h
 * @brief ROHC CRC routines
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef CRC_H
#define CRC_H


/// The CRC-3 type
#define CRC_TYPE_3 1
/// The CRC-7 type
#define CRC_TYPE_7 2
/// The CRC-8 type
#define CRC_TYPE_8 3


/// Table to enable fast CRC-8 computation
extern unsigned char crc_table_8[256];
/// Table to enable fast CRC-7 computation
extern unsigned char crc_table_7[256];
/// Table to enable fast CRC-3 computation
extern unsigned char crc_table_3[256];


/*
 * Function prototypes.
 */

unsigned int crc_calculate(int type, unsigned char *data, int length);

int crc_get_polynom(int type);

void crc_init_table(unsigned char *table, unsigned char polynum);


#endif

