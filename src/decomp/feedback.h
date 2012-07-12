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
 * @author The hackers from ROHC for Linux
 */

#ifndef FEEDBACK_H
#define FEEDBACK_H

#include <string.h>

#include "sdvl.h"
#include "crc.h"


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
#define NO_CRC    0
/// Do add a CRC option in Feedback packet
#define WITH_CRC  1


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

int f_feedback1(int sn, struct d_feedback *feedback);

int f_feedback2(int acktype, int mode, uint32_t sn, struct d_feedback *feedback);

int f_add_option(struct d_feedback *feedback,
                 const uint8_t opt_type,
                 const unsigned char *data,
                 const size_t data_len);

unsigned char * f_wrap_feedback(struct d_feedback *feedback, int cid,
                                int largecidUsed, int with_crc,
                                unsigned char *crc_table,
                                int *final_size);


#endif

