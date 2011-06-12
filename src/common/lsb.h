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

#include <stdlib.h>
#include <stdint.h>


/**
 * @brief Least Significant Bits decoding object
 */
struct d_lsb_decode
{
	/// The current reference value
	uint32_t v_ref_d;
	/// The previous reference value
	uint32_t old_v_ref_d;
	/// The p shift parameter (see 4.5.1 in the RFC 3095)
	short p;
};


/*
 * Function prototypes
 */

void d_lsb_init(struct d_lsb_decode *const lsb,
                const uint32_t v_ref_d,
                const short p);

int d_lsb_decode32(const struct d_lsb_decode *const lsb,
                   const uint32_t m,
                   const size_t k,
                   uint32_t *const decoded);
int d_lsb_decode16(const struct d_lsb_decode *const lsb,
                   const uint16_t m,
                   const size_t k,
                   uint16_t *const decoded);

void d_lsb_update(struct d_lsb_decode *const lsb, const uint32_t v_ref_d);

void d_lsb_sync_ref(struct d_lsb_decode *const lsb);

uint32_t d_get_lsb_ref(struct d_lsb_decode *const lsb);
uint32_t d_get_lsb_old_ref(struct d_lsb_decode *const lsb);

#endif

