/*
 * Copyright 2007,2008 CNES
 * Copyright 2011,2012,2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2009,2010 Thales Communications
 * Copyright 2007,2009,2010,2012,2013 Viveris Technologies
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

#include "ip.h"
#include "protocols/udp.h"
#include "protocols/rtp.h"
#include "protocols/esp.h"
#include "protocols/tcp.h"

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


/*
 * Function prototypes.
 */

void rohc_crc_init_table(uint8_t *const table,
                         const rohc_crc_type_t crc_type)
	__attribute__((nonnull(1)));

uint8_t crc_calculate(const rohc_crc_type_t crc_type,
                      const uint8_t *const data,
                      const size_t length,
                      const uint8_t init_val,
                      const uint8_t *const crc_table)
	__attribute__((nonnull(2, 5), warn_unused_result));

uint32_t crc_calc_fcs32(const uint8_t *const data,
                        const size_t length,
                        const uint32_t init_val)
	__attribute__((nonnull(1), warn_unused_result, pure));

uint8_t compute_crc_static(const uint8_t *const outer_ip,
                           const uint8_t *const inner_ip,
                           const uint8_t *const next_header,
                           const rohc_crc_type_t crc_type,
                           const uint8_t init_val,
                           const uint8_t *const crc_table)
	__attribute__((nonnull(1, 6), warn_unused_result));
uint8_t compute_crc_dynamic(const uint8_t *const outer_ip,
                            const uint8_t *const inner_ip,
                            const uint8_t *const next_header,
                            const rohc_crc_type_t crc_type,
                            const uint8_t init_val,
                            const uint8_t *const crc_table)
	__attribute__((nonnull(1, 6), warn_unused_result));

static inline
uint8_t udp_compute_crc_static(const uint8_t *const outer_ip,
                               const uint8_t *const inner_ip,
                               const uint8_t *const next_header,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val,
                               const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));
static inline
uint8_t udp_compute_crc_dynamic(const uint8_t *const outer_ip,
                                const uint8_t *const inner_ip,
                                const uint8_t *const next_header,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val,
                                const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));

static inline
uint8_t esp_compute_crc_static(const uint8_t *const outer_ip,
                               const uint8_t *const inner_ip,
                               const uint8_t *const next_header,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val,
                               const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));
static inline
uint8_t esp_compute_crc_dynamic(const uint8_t *const outer_ip,
                                const uint8_t *const inner_ip,
                                const uint8_t *const next_header,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val,
                                const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));

static inline
uint8_t rtp_compute_crc_static(const uint8_t *const outer_ip,
                               const uint8_t *const inner_ip,
                               const uint8_t *const next_header,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val,
                               const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));
static inline
uint8_t rtp_compute_crc_dynamic(const uint8_t *const outer_ip,
                                const uint8_t *const inner_ip,
                                const uint8_t *const next_header,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val,
                                const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));

uint8_t compute_crc_ctrl_fields(const rohc_profile_t profile_id,
                                const uint8_t *const crc_table,
                                const uint8_t reorder_ratio,
                                const uint16_t msn,
                                const uint8_t ip_id_behaviors[],
                                const size_t ip_id_behaviors_nr)
	__attribute__((nonnull(2), warn_unused_result));


/**
 * @brief Compute the CRC-STATIC part of an UDP or UDP-Lite header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1-4 in original UDP header
 *
 * @param outer_ip    The outer IP packet
 * @param inner_ip    The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
static inline
uint8_t udp_compute_crc_static(const uint8_t *const outer_ip,
                               const uint8_t *const inner_ip,
                               const uint8_t *const next_header,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val,
                               const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	const struct udphdr *udp;

	/* compute the CRC-STATIC value for IP and IP2 headers */
	crc = compute_crc_static(outer_ip, inner_ip, next_header,
	                         crc_type, crc, crc_table);

	/* get the start of UDP header */
	udp = (struct udphdr *) next_header;

	/* bytes 1-4 (Source Port, Destination Port) */
	crc = crc_calculate(crc_type, (uint8_t *)(&udp->source), 4,
	                    crc, crc_table);

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of an UDP or UDP-Lite header
 *
 * Concerned fields are:
 *   - bytes 5-6, 7-8 in original UDP header
 *
 * @param outer_ip    The outer IP packet
 * @param inner_ip    The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
static inline
uint8_t udp_compute_crc_dynamic(const uint8_t *const outer_ip,
                                const uint8_t *const inner_ip,
                                const uint8_t *const next_header,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val,
                                const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	const struct udphdr *udp;

	/* compute the CRC-DYNAMIC value for IP and IP2 headers */
	crc = compute_crc_dynamic(outer_ip, inner_ip, next_header,
	                          crc_type, crc, crc_table);

	/* get the start of UDP header */
	udp = (struct udphdr *) next_header;

	/* bytes 5-8 (Length, Checksum) */
	crc = crc_calculate(crc_type, (uint8_t *)(&udp->len), 4,
	                    crc, crc_table);

	return crc;
}


/**
 * @brief Compute the CRC-STATIC part of an ESP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1-4 in original ESP header
 *
 * @param outer_ip    The outer IP packet
 * @param inner_ip    The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
static inline
uint8_t esp_compute_crc_static(const uint8_t *const outer_ip,
                               const uint8_t *const inner_ip,
                               const uint8_t *const next_header,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val,
                               const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	const struct esphdr *esp;

	/* compute the CRC-STATIC value for IP and IP2 headers */
	crc = compute_crc_static(outer_ip, inner_ip, next_header,
	                         crc_type, crc, crc_table);

	/* get the start of ESP header */
	esp = (struct esphdr *) next_header;

	/* bytes 1-4 (Security parameters index) */
	crc = crc_calculate(crc_type, (uint8_t *)(&esp->spi), 4,
	                    crc, crc_table);

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of an ESP header
 *
 * Concerned fields are:
 *   - bytes 5-8 in original ESP header
 *
 * @param outer_ip    The outer IP packet
 * @param inner_ip    The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
static inline
uint8_t esp_compute_crc_dynamic(const uint8_t *const outer_ip,
                                const uint8_t *const inner_ip,
                                const uint8_t *const next_header,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val,
                                const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	const struct esphdr *esp;

	/* compute the CRC-DYNAMIC value for IP and IP2 headers */
	crc = compute_crc_dynamic(outer_ip, inner_ip, next_header,
	                          crc_type, crc, crc_table);

	/* get the start of ESP header */
	esp = (struct esphdr *) next_header;

	/* bytes 5-8 (Sequence number) */
	crc = crc_calculate(crc_type, (uint8_t *)(&esp->sn), 4,
	                    crc, crc_table);

	return crc;
}


/**
 * @brief Compute the CRC-STATIC part of a RTP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1, 9-12 (and CSRC list) in original RTP header
 *
 * @param outer_ip    The outer IP packet
 * @param inner_ip    The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
static inline
uint8_t rtp_compute_crc_static(const uint8_t *const outer_ip,
                               const uint8_t *const inner_ip,
                               const uint8_t *const next_header,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val,
                               const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	const struct rtphdr *rtp;

	/* compute the CRC-STATIC value for IP, IP2 and UDP headers */
	crc = udp_compute_crc_static(outer_ip, inner_ip, next_header,
	                             crc_type, crc, crc_table);

	/* get the start of RTP header */
	rtp = (struct rtphdr *) (next_header + sizeof(struct udphdr));

	/* byte 1 (Version, P, X, CC) */
	crc = crc_calculate(crc_type, (uint8_t *)rtp, 1, crc, crc_table);

	/* bytes 9-12 (SSRC identifier) */
	crc = crc_calculate(crc_type, (uint8_t *)(&rtp->ssrc), 4,
	                    crc, crc_table);

	/* TODO: CSRC identifiers */

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of a RTP header
 *
 * Concerned fields are:
 *   - bytes 2, 3-4, 5-8 in original RTP header
 *
 * @param outer_ip    The outer IP packet
 * @param inner_ip    The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
static inline
uint8_t rtp_compute_crc_dynamic(const uint8_t *const outer_ip,
                                const uint8_t *const inner_ip,
                                const uint8_t *const next_header,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val,
                                const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	const struct rtphdr *rtp;

	/* compute the CRC-DYNAMIC value for IP, IP2 and UDP headers */
	crc = udp_compute_crc_dynamic(outer_ip, inner_ip, next_header,
	                              crc_type, crc, crc_table);

	/* get the start of RTP header */
	rtp = (struct rtphdr *) (next_header + sizeof(struct udphdr));

	/* bytes 2-8 (Marker, Payload Type, Sequence Number, Timestamp) */
	crc = crc_calculate(crc_type, ((uint8_t *) rtp) + 1, 7,
	                    crc, crc_table);

	return crc;
}



#endif

