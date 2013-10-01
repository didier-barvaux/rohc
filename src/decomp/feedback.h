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
 * @file feedback.h
 * @brief ROHC feedback routines.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#ifndef ROHC_DECOMP_FEEDBACK_H
#define ROHC_DECOMP_FEEDBACK_H

#include "rohc.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "dllexport.h"


/**
 * @brief The different feedback options
 */
typedef enum
{
	ROHC_FEEDBACK_OPT_CRC          = 1, /**< FEEDBACK-2 CRC option */
	ROHC_FEEDBACK_OPT_REJECT       = 2, /**< FEEDBACK-2 Reject option */
	ROHC_FEEDBACK_OPT_SN_NOT_VALID = 3, /**< FEEDBACK-2 SN-not-valid option */
	ROHC_FEEDBACK_OPT_SN           = 4, /**< FEEDBACK-2 SN option */
	ROHC_FEEDBACK_OPT_CLOCK        = 5, /**< FEEDBACK-2 Clock option */
	ROHC_FEEDBACK_OPT_JITTER       = 6, /**< FEEDBACK-2 Jitter option */
	ROHC_FEEDBACK_OPT_LOSS         = 7, /**< FEEDBACK-2 Loss option */

} rohc_feedback_opt_t;


/**
 * @brief The different types of feedback acknowledgements
 */
typedef enum
{
	ROHC_ACK_TYPE_ACK         = 0, /**< positive ACKnowledgement (ACK) */
	ROHC_ACK_TYPE_NACK        = 1, /**< Negative ACKnowledgement (NACK) */
	ROHC_ACK_TYPE_STATIC_NACK = 2, /**< static Negative ACK (STATIC-NACK) */

} rohc_ack_type_t;


/**
 * @brief Whether the feedback is protected by a CRC or not
 */
typedef enum
{
	ROHC_FEEDBACK_NO_CRC   = false, /**< No CRC option protects the feedback */
	ROHC_FEEDBACK_WITH_CRC = true,  /**< A CRC option protects the feedback */

} rohc_feedback_crc_t;


/// The maximum length (in bytes) of the feedback data
#define FEEDBACK_DATA_MAX_LEN  30


/**
 * @brief Defines a ROHC feedback.
 */
struct d_feedback
{
	/// The type of feedback (1 for FEEDBACK-1 and 2 for FEEDBACK-2)
	int type;
	/// The feedback data
	uint8_t data[FEEDBACK_DATA_MAX_LEN];
	/// The size of feedback data
	int size;
};


/*
 * Prototypes of public functions.
 */

size_t ROHC_EXPORT rohc_decomp_feedback_size(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));

size_t ROHC_EXPORT rohc_decomp_feedback_headersize(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));

void f_feedback1(const uint32_t sn, struct d_feedback *const feedback)
	__attribute__((nonnull(2)));

bool f_feedback2(const rohc_ack_type_t ack_type,
                 const rohc_mode_t mode,
                 const uint32_t sn,
                 struct d_feedback *const feedback)
	__attribute__((warn_unused_result, nonnull(4)));

bool f_add_option(struct d_feedback *const feedback,
                  const rohc_feedback_opt_t opt_type,
                  const unsigned char *const data,
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

