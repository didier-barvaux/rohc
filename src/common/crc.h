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
 * @file crc.h
 * @brief ROHC CRC routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 * @author Didier Barvaux <didier@barvaux.org>
 * @author FWX <rohc_team@dialine.fr>
 */

#ifndef CRC_H
#define CRC_H

#include "ip.h"
#include "dllexport.h"

#include <stdbool.h>

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


/** The different types of CRC used to protect ROHC headers */
typedef enum
{
	ROHC_CRC_TYPE_NONE = 0,  /**< No CRC selected */
	ROHC_CRC_TYPE_2 = 2,     /**< The CRC-2 type */
	ROHC_CRC_TYPE_3 = 3,     /**< The CRC-3 type */
	ROHC_CRC_TYPE_6 = 6,     /**< The CRC-6 type */
	ROHC_CRC_TYPE_7 = 7,     /**< The CRC-7 type */
	ROHC_CRC_TYPE_8 = 8,     /**< The CRC-8 type */
} rohc_crc_type_t;


/*
 * Function prototypes.
 */

bool ROHC_EXPORT rohc_crc_init_table(unsigned char *const table,
                                     const rohc_crc_type_t crc_type)
	__attribute__((nonnull(1), warn_unused_result));

unsigned int ROHC_EXPORT crc_calculate(const rohc_crc_type_t crc_type,
                                       const unsigned char *const data,
                                       const int length,
                                       const unsigned int init_val,
                                       const unsigned char *const crc_table)
	__attribute__((nonnull(2, 5)));

unsigned int ROHC_EXPORT compute_crc_static(const unsigned char *const ip,
                                            const unsigned char *const ip2,
                                            const unsigned char *const next_header,
                                            const rohc_crc_type_t crc_type,
                                            const unsigned int init_val,
                                            const unsigned char *const crc_table)
	__attribute__((nonnull(1, 6)));
unsigned int ROHC_EXPORT compute_crc_dynamic(const unsigned char *const ip,
                                             const unsigned char *const ip2,
                                             const unsigned char *const next_header,
                                             const rohc_crc_type_t crc_type,
                                             const unsigned int init_val,
                                             const unsigned char *const crc_table)
	__attribute__((nonnull(1, 6)));

unsigned int ROHC_EXPORT udp_compute_crc_static(const unsigned char *const ip,
                                                const unsigned char *const ip2,
                                                const unsigned char *const next_header,
                                                const rohc_crc_type_t crc_type,
                                                const unsigned int init_val,
                                                const unsigned char *const crc_table)
	__attribute__((nonnull(1, 3, 6)));
unsigned int ROHC_EXPORT udp_compute_crc_dynamic(const unsigned char *const ip,
                                                 const unsigned char *const ip2,
                                                 const unsigned char *const next_header,
                                                 const rohc_crc_type_t crc_type,
                                                 const unsigned int init_val,
                                                 const unsigned char *const crc_table)
	__attribute__((nonnull(1, 3, 6)));

unsigned int ROHC_EXPORT esp_compute_crc_static(const unsigned char *const ip,
                                                const unsigned char *const ip2,
                                                const unsigned char *const next_header,
                                                const rohc_crc_type_t crc_type,
                                                const unsigned int init_val,
                                                const unsigned char *const crc_table)
	__attribute__((nonnull(1, 3, 6)));
unsigned int ROHC_EXPORT esp_compute_crc_dynamic(const unsigned char *const ip,
                                                 const unsigned char *const ip2,
                                                 const unsigned char *const next_header,
                                                 const rohc_crc_type_t crc_type,
                                                 const unsigned int init_val,
                                                 const unsigned char *const crc_table)
	__attribute__((nonnull(1, 3, 6)));

unsigned int ROHC_EXPORT rtp_compute_crc_static(const unsigned char *const ip,
                                                const unsigned char *const ip2,
                                                const unsigned char *const next_header,
                                                const rohc_crc_type_t crc_type,
                                                const unsigned int init_val,
                                                const unsigned char *const crc_table)
	__attribute__((nonnull(1, 3, 6)));
unsigned int ROHC_EXPORT rtp_compute_crc_dynamic(const unsigned char *const ip,
                                                 const unsigned char *const ip2,
                                                 const unsigned char *const next_header,
                                                 const rohc_crc_type_t crc_type,
                                                 const unsigned int init_val,
                                                 const unsigned char *const crc_table)
	__attribute__((nonnull(1, 3, 6)));

#endif

