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

#include "dllexport.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


/*
 * Constants related to fields length for SDVL-encoding
 */

/** The maximum numbers of bits that can be SDVL-encoded in 1, 2, 3
 *  and 4 bytes */
typedef enum
{
	/** Maximum number of bits in 1 SDVL-encoded byte */
	ROHC_SDVL_MAX_BITS_IN_1_BYTE = 7U,
	/** Maximum number of bits in 2 SDVL-encoded byte */
	ROHC_SDVL_MAX_BITS_IN_2_BYTES = 14U,
	/** Maximum number of bits in 3 SDVL-encoded byte */
	ROHC_SDVL_MAX_BITS_IN_3_BYTES = 21U,
	/** Maximum number of bits in 4 SDVL-encoded byte */
	ROHC_SDVL_MAX_BITS_IN_4_BYTES = 29U,
} rohc_sdvl_max_bits_t;


/*
 * Function prototypes.
 */

bool ROHC_EXPORT sdvl_can_value_be_encoded(uint32_t value);
bool ROHC_EXPORT sdvl_can_length_be_encoded(size_t bits_nr);

size_t ROHC_EXPORT sdvl_get_min_len(const size_t nr_min_required,
                                    const size_t nr_encoded);

size_t ROHC_EXPORT c_bytesSdvl(uint32_t value, size_t length);

int ROHC_EXPORT c_encodeSdvl(unsigned char *dest,
                             uint32_t value,
                             size_t length);

int ROHC_EXPORT d_sdvalue_size(const unsigned char *data);

size_t ROHC_EXPORT sdvl_decode(const unsigned char *data,
                               const size_t length,
                               uint32_t *const value,
                               size_t *const bits_nr);

#endif

