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

#ifdef __KERNEL__
#  include <linux/types.h>
#else
#  include <stdbool.h>
#endif

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

bool rohc_crc_init_table(uint8_t *const table,
                         const rohc_crc_type_t crc_type)
	__attribute__((nonnull(1), warn_unused_result));

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

uint8_t udp_compute_crc_static(const uint8_t *const outer_ip,
                               const uint8_t *const inner_ip,
                               const uint8_t *const next_header,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val,
                               const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));
uint8_t udp_compute_crc_dynamic(const uint8_t *const outer_ip,
                                const uint8_t *const inner_ip,
                                const uint8_t *const next_header,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val,
                                const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));

uint8_t esp_compute_crc_static(const uint8_t *const outer_ip,
                               const uint8_t *const inner_ip,
                               const uint8_t *const next_header,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val,
                               const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));
uint8_t esp_compute_crc_dynamic(const uint8_t *const outer_ip,
                                const uint8_t *const inner_ip,
                                const uint8_t *const next_header,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val,
                                const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));

uint8_t rtp_compute_crc_static(const uint8_t *const outer_ip,
                               const uint8_t *const inner_ip,
                               const uint8_t *const next_header,
                               const rohc_crc_type_t crc_type,
                               const uint8_t init_val,
                               const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));
uint8_t rtp_compute_crc_dynamic(const uint8_t *const outer_ip,
                                const uint8_t *const inner_ip,
                                const uint8_t *const next_header,
                                const rohc_crc_type_t crc_type,
                                const uint8_t init_val,
                                const uint8_t *const crc_table)
	__attribute__((nonnull(1, 3, 6), warn_unused_result));

#endif

