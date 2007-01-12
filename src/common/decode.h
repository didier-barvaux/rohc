/**
 * @file decode.h
 * @brief ROHC packet related routines
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef DECODE_H
#define DECODE_H

#include "rohc.h"


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

int d_is_segment(const unsigned char *);
int d_is_padding(const unsigned char *);

int d_is_feedback(const unsigned char *);
int d_feedback_size(const unsigned char *);
int d_feedback_headersize(const unsigned char *);

int d_is_ir(const unsigned char *);
int d_is_irdyn(const unsigned char *);

int d_is_add_cid(const unsigned char *);
int d_decode_add_cid(const unsigned char *);


#endif

