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

