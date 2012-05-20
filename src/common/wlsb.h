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
 * @file wlsb.h
 * @brief Window-based Least Significant Bits (W-LSB) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author David Moreau from TAS
 * @author The hackers from ROHC for Linux
 */

#ifndef WLSB_H
#define WLSB_H

#include "interval.h" /* for rohc_lsb_shift_t */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


/// Default window width for W-LSB encoding
#define C_WINDOW_WIDTH 4


/**
 * @brief Defines a W-LSB window entry
 */
struct c_window
{
	uint16_t sn;     /**< The Sequence Number (SN) associated with the entry
	                      (used to acknowledge the entry) */
	uint32_t value;  /**< The value stored in the window entry */
	bool is_used;    /**< Whether the window entry is used or not */
};


/**
 * @brief Defines a W-LSB encoding object
 */
struct c_wlsb
{
	/// @brief The window in which numerous previous values of the encoded value
	///        are stored to help recreate the value
	struct c_window *window;
	/// The width of the window
	size_t window_width;

	/// A pointer on the oldest entry in the window (change on acknowledgement)
	size_t oldest;
	/// A pointer on the current entry in the window  (change on add and ack)
	size_t next;

	/// The maximal number of bits for representing the value
	size_t bits;
	/// Shift parameter (see 4.5.2 in the RFC 3095)
	rohc_lsb_shift_t p;
};


/*
 * Public function prototypes:
 */

struct c_wlsb * c_create_wlsb(const size_t bits,
                              const size_t window_width,
                              const rohc_lsb_shift_t p);
void c_destroy_wlsb(struct c_wlsb *s);

void c_add_wlsb(struct c_wlsb *const wlsb,
                const uint16_t sn,
                const uint32_t value);

bool wlsb_get_k_16bits(const struct c_wlsb *const wlsb,
                       const uint16_t value,
                       size_t *const bits_nr);
bool wlsb_get_k_32bits(const struct c_wlsb *const wlsb,
                       const uint32_t value,
                       size_t *const bits_nr);

void c_ack_sn_wlsb(struct c_wlsb *s, int sn);

int c_sum_wlsb(struct c_wlsb *s);
int c_mean_wlsb(struct c_wlsb *s);

#endif

