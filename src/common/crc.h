/**
 * @file crc.h
 * @brief ROHC CRC routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef CRC_H
#define CRC_H

/// The CRC-2 type
#define CRC_TYPE_2 1
/// The CRC-3 type
#define CRC_TYPE_3 2
/// The CRC-6 type
#define CRC_TYPE_6 3
/// The CRC-7 type
#define CRC_TYPE_7 4
/// The CRC-8 type
#define CRC_TYPE_8 5


/// Table to enable fast CRC-8 computation
extern unsigned char crc_table_8[256];
/// Table to enable fast CRC-7 computation
extern unsigned char crc_table_7[256];
/// Table to enable fast CRC-6 computation
extern unsigned char crc_table_6[256];
/// Table to enable fast CRC-3 computation
extern unsigned char crc_table_3[256];
/// Table to enable fast CRC-2 computation
extern unsigned char crc_table_2[256];


/*
 * Function prototypes.
 */

unsigned int crc_calculate(int type, unsigned char *data, int length);

int crc_get_polynom(int type);

void crc_init_table(unsigned char *table, unsigned char polynum);


#endif

