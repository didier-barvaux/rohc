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
 * @file sdvl.h
 * @brief Self-Describing Variable-Length (SDVL) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef SDVL_H
#define SDVL_H

/*
 * Constants related to fields length for SDVL-encoding
 */

/** Maximum number of bits in 1 SDVL-encoded byte */
#define MAX_BITS_IN_1_BYTE_SDVL 7
/** Maximum number of bits in 2 SDVL-encoded byte */
#define MAX_BITS_IN_2_BYTE_SDVL 14
/** Maximum number of bits in 3 SDVL-encoded byte */
#define MAX_BITS_IN_3_BYTE_SDVL 21
/** Maximum number of bits in 4 SDVL-encoded byte */
#define MAX_BITS_IN_4_BYTE_SDVL 29

/*
 * Function prototypes.
 */

int c_bytesSdvl(int value, int length);

int c_encodeSdvl(unsigned char *dest, int value, int length);

int d_sdvalue_size(const unsigned char *data);

int d_sdvalue_decode(const unsigned char *data);


#endif

