/**
 * @file feedback.h
 * @brief ROHC feedback routines.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
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


/**
 * @brief Defines a ROHC feedback.
 */
struct d_feedback
{
	/// The type of feedback (1 for FEEDBACK-1 and 2 for FEEDBACK-2)
	int type;
	/// The feedback data
	char data[30];
	/// The size of feedback data
	int size;
};


/*
 * Prototypes of public functions.
 */

int f_feedback1(int sn, struct d_feedback *feedback);

void f_feedback2(int acktype, int mode, int sn, struct d_feedback *feedback);

int f_add_option(struct d_feedback *feedback, int opt_type,
                  unsigned char *data);

unsigned char * f_wrap_feedback(struct d_feedback *feedback, int cid,
                                int largecidUsed, int with_crc,
                                int *final_size);


#endif

