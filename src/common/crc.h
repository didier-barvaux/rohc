/**
 * @file crc.h
 * @brief ROHC CRC routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef CRC_H
#define CRC_H

#include "ip.h"

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

/// The CRC-2 initial value
#define CRC_INIT_2 0x3
/// The CRC-3 initial value
#define CRC_INIT_3 0x7
/// The CRC-6 initial value
#define CRC_INIT_6 0x3f
/// The CRC-7 initial value
#define CRC_INIT_7 0x7f
/// The CRC-8 initial value
#define CRC_INIT_8 0xff


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

unsigned int crc_calculate(int type,
                           unsigned char *data,
                           int length,
                           unsigned int init_val);

int crc_get_polynom(int type);

void crc_init_table(unsigned char *table, unsigned char polynum);

unsigned int compute_crc_static(const unsigned char *ip,
                                const unsigned char *ip2,
                                const unsigned char *next_header,
                                unsigned int crc_type,
                                unsigned int init_val);
unsigned int compute_crc_dynamic(const unsigned char *ip,
                                 const unsigned char *ip2,
                                 const unsigned char *next_header,
                                 unsigned int crc_type,
                                 unsigned int init_val);

unsigned int udp_compute_crc_static(const unsigned char *ip,
                                    const unsigned char *ip2,
                                    const unsigned char *next_header,
                                    unsigned int crc_type,
                                    unsigned int init_val);
unsigned int udp_compute_crc_dynamic(const unsigned char *ip,
                                     const unsigned char *ip2,
                                     const unsigned char *next_header,
                                     unsigned int crc_type,
                                     unsigned int init_val);


unsigned int rtp_compute_crc_static(const unsigned char *ip,
                                    const unsigned char *ip2,
                                    const unsigned char *next_header,
                                    unsigned int crc_type,
                                    unsigned int init_val);
unsigned int rtp_compute_crc_dynamic(const unsigned char *ip,
                                     const unsigned char *ip2,
                                     const unsigned char *next_header,
                                     unsigned int crc_type,
                                     unsigned int init_val);

unsigned int ipv6_ext_compute_crc_static(const unsigned char *ip,
                                         unsigned int crc_type,
                                         unsigned int init_val);
unsigned int ipv6_ext_compute_crc_dynamic(const unsigned char *ip,
                                          unsigned int crc_type,
                                          unsigned int init_val);

#endif

