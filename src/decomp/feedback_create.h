/*
 * Copyright 2011,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012 Viveris Technologies
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
 * @file   feedback_create.h
 * @brief  Functions to create ROHC feedback
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_FEEDBACK_CREATE_H
#define ROHC_DECOMP_FEEDBACK_CREATE_H

#include <rohc/rohc.h>
#include <rohc/rohc_buf.h>
#include <feedback.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>


/// The maximum length (in bytes) of the feedback data
#define FEEDBACK_DATA_MAX_LEN  30


/**
 * @brief Defines a ROHC feedback.
 */
struct d_feedback
{
	/// The type of feedback (1 for FEEDBACK-1 and 2 for FEEDBACK-2)
	enum rohc_feedback_ack_type type;
	/// The feedback data
	uint8_t data[FEEDBACK_DATA_MAX_LEN];
	/// The size of feedback data
	int size;
};


/*
 * Prototypes of public functions.
 */

bool rohc_decomp_feedback_size(const struct rohc_buf rohc_data,
                               size_t *const feedback_hdr_len,
                               size_t *const feedback_data_len)
	__attribute__((warn_unused_result, nonnull(2, 3)));

void f_feedback1(const uint32_t sn_bits, struct d_feedback *const feedback)
	__attribute__((nonnull(2)));

bool f_feedback2(const rohc_profile_t profile_id,
                 const enum rohc_feedback_ack_type ack_type,
                 const rohc_mode_t mode,
                 const uint32_t sn_bits,
                 const size_t sn_bits_nr,
                 struct d_feedback *const feedback)
	__attribute__((warn_unused_result, nonnull(6)));

bool f_add_option(struct d_feedback *const feedback,
                  const enum rohc_feedback_opt opt_type,
                  const uint8_t *const data,
                  const size_t data_len)
	__attribute__((warn_unused_result, nonnull(1)));

uint8_t * f_wrap_feedback(struct d_feedback *feedback,
                          const uint16_t cid,
                          const rohc_cid_type_t cid_type,
                          const rohc_feedback_crc_t protect_with_crc,
                          const uint8_t *const crc_table,
                          size_t *const final_size)
	__attribute__((warn_unused_result, nonnull(1, 5, 6)));


#endif

