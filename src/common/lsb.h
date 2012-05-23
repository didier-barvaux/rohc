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
 * @file lsb.h
 * @brief Least Significant Bits (LSB) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef LSB_H
#define LSB_H

#include "interval.h" /* for rohc_lsb_shift_t */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


/* The definition of the Least Significant Bits decoding object is private */
struct d_lsb_decode;


/*
 * Function prototypes
 */

struct d_lsb_decode *const rohc_lsb_new(const rohc_lsb_shift_t p);
void rohc_lsb_free(struct d_lsb_decode *const lsb)
	__attribute__((nonnull(1)));

bool d_lsb_decode32(const struct d_lsb_decode *const lsb,
                    const uint32_t m,
                    const size_t k,
                    uint32_t *const decoded);
bool d_lsb_decode16(const struct d_lsb_decode *const lsb,
                    const uint16_t m,
                    const size_t k,
                    uint16_t *const decoded);

void d_lsb_update(struct d_lsb_decode *const lsb, const uint32_t v_ref_d);

uint32_t d_get_lsb_ref(struct d_lsb_decode *const lsb);

#endif

