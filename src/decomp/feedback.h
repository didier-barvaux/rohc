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

#ifndef FEEDBACK_H
#define FEEDBACK_H

#include "rohc.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>


/// CRC option for the FEEDBACK-2 packet
#define OPT_TYPE_CRC           1
/// Reject option for the FEEDBACK-2 packet
#define OPT_TYPE_REJECT        2
/// SN-not-valid option for the FEEDBACK-2 packet
#define OPT_TYPE_SN_NOT_VALID  3
/// SN option for the FEEDBACK-2 packet
#define OPT_TYPE_SN            4
/// Clock option for the FEEDBACK-2 packet (not used)
#define OPT_TYPE_CLOCK         5
/// Jitter option for the FEEDBACK-2 packet (not used)
#define OPT_TYPE_JITTER        6
/// Loss option for the FEEDBACK-2 packet
#define OPT_TYPE_LOSS          7


/// Feedback ACK
#define ACKTYPE_ACK          0
/// Feedback Negative ACK
#define ACKTYPE_NACK         1
/// Feedback Satic Negative ACK
#define ACKTYPE_STATIC_NACK  2


/// Do not add a CRC option in Feedback packet
#define NO_CRC    false
/// Do add a CRC option in Feedback packet
#define WITH_CRC  true


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
	char data[FEEDBACK_DATA_MAX_LEN];
	/// The size of feedback data
	int size;
};


/*
 * Prototypes of public functions.
 */

void f_feedback1(const uint32_t sn, struct d_feedback *const feedback)
	__attribute__((nonnull(2)));

bool f_feedback2(const int acktype,
                 const rohc_mode mode,
                 const uint32_t sn,
                 struct d_feedback *const feedback)
	__attribute__((warn_unused_result, nonnull(4)));

bool f_add_option(struct d_feedback *const feedback,
                  const uint8_t opt_type,
                  const unsigned char *const data,
                  const size_t data_len)
	__attribute__((warn_unused_result, nonnull(1)));

uint8_t * f_wrap_feedback(struct d_feedback *feedback,
                          const uint16_t cid,
                          const rohc_cid_type_t cid_type,
                          const bool with_crc,
                          const uint8_t *const crc_table,
                          size_t *const final_size)
	__attribute__((warn_unused_result, nonnull(1, 5, 6)));


#endif

