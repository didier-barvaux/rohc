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
 * @file decode.h
 * @brief ROHC packet related routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#ifndef DECODE_H
#define DECODE_H

#include "dllexport.h"

#include <stddef.h>
#include <stdint.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif


/// The magic bits to find out whether a field is a segment field or not
#define D_SEGMENT        (0xfe >> 1)
/// The magic byte to find out whether a field is a padding field or not
#define D_PADDING        0xe0

/// The magic bits to find out whether a ROHC packet is a Feedback packet or not
#define D_FEEDBACK       (0xf0 >> 3)
/// The magic bits to find out whether a ROHC packet is an IR packet or not
#define D_IR_PACKET      (0xfc >> 1)
/// The magic byte to find out whether a ROHC packet is an IR-DYN packet or not
#define D_IR_DYN_PACKET  0xf8

/// @brief The magic bits to find out whether a ROHC packet starts with an
///        add-CID byte or not
#define D_ADD_CID        0xe


/*
 * Function prototypes.
 */

bool ROHC_EXPORT d_is_segment(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));
bool ROHC_EXPORT d_is_padding(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));

bool ROHC_EXPORT d_is_feedback(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));
size_t ROHC_EXPORT d_feedback_size(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));
size_t ROHC_EXPORT d_feedback_headersize(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));

bool ROHC_EXPORT d_is_ir(const uint8_t *const data, const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));
bool ROHC_EXPORT d_is_irdyn(const uint8_t *const data, const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));

bool ROHC_EXPORT d_is_uo0(const uint8_t *const data, const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));

bool ROHC_EXPORT d_is_uo1(const uint8_t *const data, const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));
bool ROHC_EXPORT d_is_uo1_ts(const uint8_t *const data, const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));

bool ROHC_EXPORT d_is_uor2(const uint8_t *const data, const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));
bool ROHC_EXPORT d_is_uor2_ts(const uint8_t *const data,
                              const size_t data_len,
                              const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1), pure));

bool ROHC_EXPORT d_is_add_cid(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));
uint8_t ROHC_EXPORT d_decode_add_cid(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));


#endif

