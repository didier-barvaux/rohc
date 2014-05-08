/*
 * Copyright 2011,2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010,2013 Viveris Technologies
 *
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
 * @file   rohc_decomp_detect_packet.h
 * @brief  Functions related to packet detection
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_DETECT_PACKET_H
#define ROHC_DECOMP_DETECT_PACKET_H

#include "dllexport.h"

#include <stddef.h>
#include <stdint.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif


/*
 * Function prototypes.
 */

/* ROHC segment */
bool ROHC_EXPORT rohc_decomp_packet_is_segment(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));
bool ROHC_EXPORT rohc_decomp_packet_is_padding(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));

/* ROHC feedback */
bool ROHC_EXPORT rohc_decomp_packet_is_feedback(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));

/* IR packet */
bool ROHC_EXPORT rohc_decomp_packet_is_ir(const uint8_t *const data,
                                          const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));

/* IR-DYN packet */
bool ROHC_EXPORT rohc_decomp_packet_is_irdyn(const uint8_t *const data,
                                             const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));

/* UO-0 packet */
bool ROHC_EXPORT rohc_decomp_packet_is_uo0(const uint8_t *const data,
                                           const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));

/* UO-1* packets */
bool ROHC_EXPORT rohc_decomp_packet_is_uo1(const uint8_t *const data,
                                           const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));
bool ROHC_EXPORT rohc_decomp_packet_is_uo1_ts(const uint8_t *const data,
                                              const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));

/* UOR-2* packets */
bool ROHC_EXPORT rohc_decomp_packet_is_uor2(const uint8_t *const data,
                                            const size_t len)
	__attribute__((warn_unused_result, nonnull(1), pure));
bool ROHC_EXPORT rohc_decomp_packet_is_uor2_ts(const uint8_t *const data,
                                               const size_t data_len,
                                               const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1), pure));

#endif

