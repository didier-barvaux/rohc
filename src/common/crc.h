/*
 * Copyright 2007,2008 CNES
 * Copyright 2011,2012,2013,2018 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2009,2010 Thales Communications
 * Copyright 2007,2009,2010,2012,2013,2018 Viveris Technologies
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
 * @file crc.h
 * @brief ROHC CRC routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author FWX <rohc_team@dialine.fr>
 */

#ifndef ROHC_COMMON_CRC_H
#define ROHC_COMMON_CRC_H

#include "crcany.h"
#include "ip.h"
#include "protocols/uncomp_pkt_hdrs.h"

#include <rohc/rohc.h> /* for rohc_profile_t */

#include <stdbool.h>

/// The CRC-3 initial value
#define CRC_INIT_3 0x7
/// The CRC-7 initial value
#define CRC_INIT_7 0x7f
/// The CRC-8 initial value
#define CRC_INIT_8 0xff

/** The FCS-32 initial value */
#define CRC_INIT_FCS32 0xffffffff
/** The length (in bytes) of the FCS-32 CRC */
#define CRC_FCS32_LEN  4U

/** The different types of CRC used to protect ROHC headers */
typedef enum
{
	ROHC_CRC_TYPE_NONE = 0,  /**< No CRC selected */
	ROHC_CRC_TYPE_3 = 3,     /**< The CRC-3 type */
	ROHC_CRC_TYPE_7 = 7,     /**< The CRC-7 type */
	ROHC_CRC_TYPE_8 = 8,     /**< The CRC-8 type */
} rohc_crc_type_t;


/** The table to enable fast CRC-7 computation */
static const uint8_t crc_table_7[256] =
{
	0x00, 0x40, 0x73, 0x33, 0x15, 0x55, 0x66, 0x26,
	0x2a, 0x6a, 0x59, 0x19, 0x3f, 0x7f, 0x4c, 0x0c,
	0x54, 0x14, 0x27, 0x67, 0x41, 0x01, 0x32, 0x72,
	0x7e, 0x3e, 0x0d, 0x4d, 0x6b, 0x2b, 0x18, 0x58,
	0x5b, 0x1b, 0x28, 0x68, 0x4e, 0x0e, 0x3d, 0x7d,
	0x71, 0x31, 0x02, 0x42, 0x64, 0x24, 0x17, 0x57,
	0x0f, 0x4f, 0x7c, 0x3c, 0x1a, 0x5a, 0x69, 0x29,
	0x25, 0x65, 0x56, 0x16, 0x30, 0x70, 0x43, 0x03,
	0x45, 0x05, 0x36, 0x76, 0x50, 0x10, 0x23, 0x63,
	0x6f, 0x2f, 0x1c, 0x5c, 0x7a, 0x3a, 0x09, 0x49,
	0x11, 0x51, 0x62, 0x22, 0x04, 0x44, 0x77, 0x37,
	0x3b, 0x7b, 0x48, 0x08, 0x2e, 0x6e, 0x5d, 0x1d,
	0x1e, 0x5e, 0x6d, 0x2d, 0x0b, 0x4b, 0x78, 0x38,
	0x34, 0x74, 0x47, 0x07, 0x21, 0x61, 0x52, 0x12,
	0x4a, 0x0a, 0x39, 0x79, 0x5f, 0x1f, 0x2c, 0x6c,
	0x60, 0x20, 0x13, 0x53, 0x75, 0x35, 0x06, 0x46,
	0x79, 0x39, 0x0a, 0x4a, 0x6c, 0x2c, 0x1f, 0x5f,
	0x53, 0x13, 0x20, 0x60, 0x46, 0x06, 0x35, 0x75,
	0x2d, 0x6d, 0x5e, 0x1e, 0x38, 0x78, 0x4b, 0x0b,
	0x07, 0x47, 0x74, 0x34, 0x12, 0x52, 0x61, 0x21,
	0x22, 0x62, 0x51, 0x11, 0x37, 0x77, 0x44, 0x04,
	0x08, 0x48, 0x7b, 0x3b, 0x1d, 0x5d, 0x6e, 0x2e,
	0x76, 0x36, 0x05, 0x45, 0x63, 0x23, 0x10, 0x50,
	0x5c, 0x1c, 0x2f, 0x6f, 0x49, 0x09, 0x3a, 0x7a,
	0x3c, 0x7c, 0x4f, 0x0f, 0x29, 0x69, 0x5a, 0x1a,
	0x16, 0x56, 0x65, 0x25, 0x03, 0x43, 0x70, 0x30,
	0x68, 0x28, 0x1b, 0x5b, 0x7d, 0x3d, 0x0e, 0x4e,
	0x42, 0x02, 0x31, 0x71, 0x57, 0x17, 0x24, 0x64,
	0x67, 0x27, 0x14, 0x54, 0x72, 0x32, 0x01, 0x41,
	0x4d, 0x0d, 0x3e, 0x7e, 0x58, 0x18, 0x2b, 0x6b,
	0x33, 0x73, 0x40, 0x00, 0x26, 0x66, 0x55, 0x15,
	0x19, 0x59, 0x6a, 0x2a, 0x0c, 0x4c, 0x7f, 0x3f,
};


/** The table to enable fast CRC-8 computation */
static const uint8_t crc_table_8[256] =
{
	0x00, 0x91, 0xe3, 0x72, 0x07, 0x96, 0xe4, 0x75,
	0x0e, 0x9f, 0xed, 0x7c, 0x09, 0x98, 0xea, 0x7b,
	0x1c, 0x8d, 0xff, 0x6e, 0x1b, 0x8a, 0xf8, 0x69,
	0x12, 0x83, 0xf1, 0x60, 0x15, 0x84, 0xf6, 0x67,
	0x38, 0xa9, 0xdb, 0x4a, 0x3f, 0xae, 0xdc, 0x4d,
	0x36, 0xa7, 0xd5, 0x44, 0x31, 0xa0, 0xd2, 0x43,
	0x24, 0xb5, 0xc7, 0x56, 0x23, 0xb2, 0xc0, 0x51,
	0x2a, 0xbb, 0xc9, 0x58, 0x2d, 0xbc, 0xce, 0x5f,
	0x70, 0xe1, 0x93, 0x02, 0x77, 0xe6, 0x94, 0x05,
	0x7e, 0xef, 0x9d, 0x0c, 0x79, 0xe8, 0x9a, 0x0b,
	0x6c, 0xfd, 0x8f, 0x1e, 0x6b, 0xfa, 0x88, 0x19,
	0x62, 0xf3, 0x81, 0x10, 0x65, 0xf4, 0x86, 0x17,
	0x48, 0xd9, 0xab, 0x3a, 0x4f, 0xde, 0xac, 0x3d,
	0x46, 0xd7, 0xa5, 0x34, 0x41, 0xd0, 0xa2, 0x33,
	0x54, 0xc5, 0xb7, 0x26, 0x53, 0xc2, 0xb0, 0x21,
	0x5a, 0xcb, 0xb9, 0x28, 0x5d, 0xcc, 0xbe, 0x2f,
	0xe0, 0x71, 0x03, 0x92, 0xe7, 0x76, 0x04, 0x95,
	0xee, 0x7f, 0x0d, 0x9c, 0xe9, 0x78, 0x0a, 0x9b,
	0xfc, 0x6d, 0x1f, 0x8e, 0xfb, 0x6a, 0x18, 0x89,
	0xf2, 0x63, 0x11, 0x80, 0xf5, 0x64, 0x16, 0x87,
	0xd8, 0x49, 0x3b, 0xaa, 0xdf, 0x4e, 0x3c, 0xad,
	0xd6, 0x47, 0x35, 0xa4, 0xd1, 0x40, 0x32, 0xa3,
	0xc4, 0x55, 0x27, 0xb6, 0xc3, 0x52, 0x20, 0xb1,
	0xca, 0x5b, 0x29, 0xb8, 0xcd, 0x5c, 0x2e, 0xbf,
	0x90, 0x01, 0x73, 0xe2, 0x97, 0x06, 0x74, 0xe5,
	0x9e, 0x0f, 0x7d, 0xec, 0x99, 0x08, 0x7a, 0xeb,
	0x8c, 0x1d, 0x6f, 0xfe, 0x8b, 0x1a, 0x68, 0xf9,
	0x82, 0x13, 0x61, 0xf0, 0x85, 0x14, 0x66, 0xf7,
	0xa8, 0x39, 0x4b, 0xda, 0xaf, 0x3e, 0x4c, 0xdd,
	0xa6, 0x37, 0x45, 0xd4, 0xa1, 0x30, 0x42, 0xd3,
	0xb4, 0x25, 0x57, 0xc6, 0xb3, 0x22, 0x50, 0xc1,
	0xba, 0x2b, 0x59, 0xc8, 0xbd, 0x2c, 0x5e, 0xcf,
};



/*
 * Function prototypes.
 */

uint32_t crc_calc_fcs32(const uint8_t *const data,
                        const size_t length,
                        const uint32_t init_val)
	__attribute__((nonnull(1), warn_unused_result, pure));

uint8_t ip_compute_crc_static(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                              const rohc_crc_type_t crc_type,
                              const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result));
uint8_t ip_compute_crc_dynamic(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result));

static inline
uint8_t udp_compute_crc_static(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result));
static inline
uint8_t udp_compute_crc_dynamic(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result));

static inline
uint8_t esp_compute_crc_static(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result));
static inline
uint8_t esp_compute_crc_dynamic(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result));

static inline
uint8_t rtp_compute_crc_static(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result));
static inline
uint8_t rtp_compute_crc_dynamic(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result));

uint8_t compute_crc_ctrl_fields(const rohc_profile_t profile_id,
                                const uint8_t reorder_ratio,
                                const uint16_t msn,
                                const uint8_t ip_id_behaviors[],
                                const size_t ip_id_behaviors_nr)
	__attribute__((warn_unused_result));

static inline
uint8_t crc_calculate(const rohc_crc_type_t crc_type,
                      const uint8_t *const data,
                      const size_t length,
                      const uint8_t init_val)
	__attribute__((nonnull(2), warn_unused_result));

static inline uint8_t crc_calc_8(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result, pure));
static inline uint8_t crc_calc_7(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result, pure));
static inline uint8_t crc_calc_3(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val)
	__attribute__((nonnull(1), warn_unused_result, pure));


/**
 * @brief Calculate the checksum for the given data.
 *
 * @param crc_type   The CRC type
 * @param data       The data to calculate the checksum on
 * @param length     The length of the data
 * @param init_val   The initial CRC value
 * @return           The checksum
 */
static inline
uint8_t crc_calculate(const rohc_crc_type_t crc_type,
                      const uint8_t *const data,
                      const size_t length,
                      const uint8_t init_val)
{
	uint8_t crc;

	/* call the function that corresponds to the CRC type */
	switch(crc_type)
	{
		case ROHC_CRC_TYPE_8:
			crc = crc_calc_8(data, length, init_val);
			break;
		case ROHC_CRC_TYPE_7:
			crc = crc_calc_7(data, length, init_val);
			break;
		case ROHC_CRC_TYPE_3:
			crc = crc_calc_3(data, length, init_val);
			break;
		case ROHC_CRC_TYPE_NONE:
		default:
			crc = 0;
			break;
	}

	return crc;
}


/**
 * @brief Optimized CRC-8 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @return           The CRC byte
 */
static inline uint8_t crc_calc_8(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val)
{
	uint8_t crc = init_val;
	size_t i;

	for(i = 0; i < size; i++)
	{
		crc = crc_table_8[buf[i] ^ crc];
	}

	return crc;
}


/**
 * @brief Optimized CRC-7 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @return           The CRC byte
 */
static inline uint8_t crc_calc_7(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val)
{
	uint8_t crc = init_val;
	size_t i;

	for(i = 0; i < size; i++)
	{
		crc = crc_table_7[buf[i] ^ (crc & 127)];
	}

	return crc;
}


/**
 * @brief Optimized CRC-3 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @return           The CRC byte
 */
static inline uint8_t crc_calc_3(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val)
{
	return crc3rohc_word(init_val, buf, size);
}


/**
 * @brief Compute the CRC-STATIC part of an UDP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1-4 in original UDP header
 *
 * @param uncomp_pkt_hdrs  The uncompressed headers to compute CRC for
 * @param crc_type         The type of CRC
 * @param init_val         The initial CRC value
 * @return                 The computed CRC
 */
static inline
uint8_t udp_compute_crc_static(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val)
{
	uint8_t crc = init_val;

	/* compute the CRC-STATIC value for IP and IP2 headers */
	crc = ip_compute_crc_static(uncomp_pkt_hdrs, crc_type, crc);

	/* bytes 1-4 (Source Port, Destination Port) */
	crc = crc_calculate(crc_type, (uint8_t *)(&uncomp_pkt_hdrs->udp->source), 4, crc);

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of an UDP header
 *
 * Concerned fields are:
 *   - bytes 5-6, 7-8 in original UDP header
 *
 * @param uncomp_pkt_hdrs  The uncompressed headers to compute CRC for
 * @param crc_type         The type of CRC
 * @param init_val         The initial CRC value
 * @return                 The computed CRC
 */
static inline
uint8_t udp_compute_crc_dynamic(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val)
{
	uint8_t crc = init_val;

	/* compute the CRC-DYNAMIC value for IP and IP2 headers */
	crc = ip_compute_crc_dynamic(uncomp_pkt_hdrs, crc_type, crc);

	/* bytes 5-8 (Length, Checksum) */
	crc = crc_calculate(crc_type, (uint8_t *)(&uncomp_pkt_hdrs->udp->len), 4, crc);

	return crc;
}


/**
 * @brief Compute the CRC-STATIC part of an ESP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1-4 in original ESP header
 *
 * @param uncomp_pkt_hdrs  The uncompressed headers to compute CRC for
 * @param crc_type         The type of CRC
 * @param init_val         The initial CRC value
 * @return                 The computed CRC
 */
static inline
uint8_t esp_compute_crc_static(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val)
{
	uint8_t crc = init_val;

	/* compute the CRC-STATIC value for IP and IP2 headers */
	crc = ip_compute_crc_static(uncomp_pkt_hdrs, crc_type, crc);

	/* bytes 1-4 (Security parameters index) */
	crc = crc_calculate(crc_type, (uint8_t *)(&uncomp_pkt_hdrs->esp->spi), 4, crc);

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of an ESP header
 *
 * Concerned fields are:
 *   - bytes 5-8 in original ESP header
 *
 * @param uncomp_pkt_hdrs  The uncompressed headers to compute CRC for
 * @param crc_type         The type of CRC
 * @param init_val         The initial CRC value
 * @return                 The computed CRC
 */
static inline
uint8_t esp_compute_crc_dynamic(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val)
{
	uint8_t crc = init_val;

	/* compute the CRC-DYNAMIC value for IP and IP2 headers */
	crc = ip_compute_crc_dynamic(uncomp_pkt_hdrs, crc_type, crc);

	/* bytes 5-8 (Sequence number) */
	crc = crc_calculate(crc_type, (uint8_t *)(&uncomp_pkt_hdrs->esp->sn), 4, crc);

	return crc;
}


/**
 * @brief Compute the CRC-STATIC part of a RTP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1, 9-12 (and CSRC list) in original RTP header
 *
 * @param uncomp_pkt_hdrs  The uncompressed headers to compute CRC for
 * @param crc_type         The type of CRC
 * @param init_val         The initial CRC value
 * @return                 The computed CRC
 */
static inline
uint8_t rtp_compute_crc_static(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val)
{
	uint8_t crc = init_val;

	/* compute the CRC-STATIC value for IP, IP2 and UDP headers */
	crc = udp_compute_crc_static(uncomp_pkt_hdrs, crc_type, crc);

	/* byte 1 (Version, P, X, CC) */
	crc = crc_calculate(crc_type, (uint8_t *)uncomp_pkt_hdrs->rtp, 1, crc);

	/* bytes 9-12 (SSRC identifier) */
	crc = crc_calculate(crc_type, (uint8_t *)(&uncomp_pkt_hdrs->rtp->ssrc), 4, crc);

	/* TODO: CSRC identifiers */

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of a RTP header
 *
 * Concerned fields are:
 *   - bytes 2, 3-4, 5-8 in original RTP header
 *
 * @param uncomp_pkt_hdrs  The uncompressed headers to compute CRC for
 * @param crc_type         The type of CRC
 * @param init_val         The initial CRC value
 * @return                 The computed CRC
 */
static inline
uint8_t rtp_compute_crc_dynamic(const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val)
{
	uint8_t crc = init_val;

	/* compute the CRC-DYNAMIC value for IP, IP2 and UDP headers */
	crc = udp_compute_crc_dynamic(uncomp_pkt_hdrs, crc_type, crc);

	/* bytes 2-8 (Marker, Payload Type, Sequence Number, Timestamp) */
	crc = crc_calculate(crc_type, ((uint8_t *) uncomp_pkt_hdrs->rtp) + 1, 7, crc);

	return crc;
}

#endif

