/*
 * Copyright 2011,2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010 Viveris Technologies
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file   schemes/comp_wlsb.h
 * @brief  Window-based Least Significant Bits (W-LSB) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author David Moreau from TAS
 */

#ifndef ROHC_COMP_SCHEMES_WLSB_H
#define ROHC_COMP_SCHEMES_WLSB_H

#include "interval.h" /* for rohc_lsb_shift_t */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


/*
 * Public structures and types
 */

/**
 * @brief One W-LSB window entry
 */
struct c_window
{
	uint32_t sn;     /**< The Sequence Number (SN) associated with the entry
	                      (used to acknowledge the entry) */
	uint32_t value;  /**< The value stored in the window entry */
	bool used;       /**< Whether the window entry is used or not */
	uint8_t unused[7];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct c_window, sn) % 8) == 0,
               "sn in c_window should be aligned on 8 bytes");
_Static_assert((offsetof(struct c_window, value) % 4) == 0,
               "value in c_window should be aligned on 4 bytes");
_Static_assert((sizeof(struct c_window) % 8) == 0,
               "c_window length should be multiple of 8 bytes");
#endif


/**
 * @brief One W-LSB encoding object
 */
struct c_wlsb
{
	/** The window in which previous values of the encoded value are stored */
	struct c_window *window;

	/** The width of the window */
	uint8_t window_width; /* TODO: R-mode needs a non-fixed window width */

	/** A pointer on the oldest entry in the window (change on acknowledgement) */
	uint8_t oldest;
	/** A pointer on the current entry in the window  (change on add and ack) */
	uint8_t next;

	/** The count of entries in the window */
	uint8_t count;

	/** The maximal number of bits for representing the value */
	uint8_t bits;
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct c_wlsb, window) % 8) == 0,
               "window in c_wlsb should be aligned on 8 bytes");
_Static_assert((sizeof(struct c_wlsb) % 8) == 0,
               "c_wlsb length should be multiple of 8 bytes");
#endif



/*
 * Public function prototypes:
 */

bool wlsb_new(struct c_wlsb *const wlsb,
              const size_t bits,
              const size_t window_width)
	__attribute__((warn_unused_result, nonnull(1)));
bool wlsb_copy(struct c_wlsb *const dst,
               const struct c_wlsb *const src)
	__attribute__((warn_unused_result, nonnull(1, 2)));
void wlsb_free(struct c_wlsb *const wlsb)
	__attribute__((nonnull(1)));

void c_add_wlsb(struct c_wlsb *const wlsb,
                const uint32_t sn,
                const uint32_t value)
	__attribute__((nonnull(1)));

bool wlsb_is_kp_possible_8bits(const struct c_wlsb *const wlsb,
                               const uint8_t value,
                               const size_t k,
                               const rohc_lsb_shift_t p)
	__attribute__((warn_unused_result, nonnull(1)));

bool wlsb_is_kp_possible_16bits(const struct c_wlsb *const wlsb,
                                const uint16_t value,
                                const size_t k,
                                const rohc_lsb_shift_t p)
	__attribute__((warn_unused_result, nonnull(1)));

bool wlsb_is_kp_possible_32bits(const struct c_wlsb *const wlsb,
                                const uint32_t value,
                                const size_t k,
                                const rohc_lsb_shift_t p)
	__attribute__((warn_unused_result, nonnull(1)));

size_t wlsb_ack(struct c_wlsb *const wlsb,
                const uint32_t sn_bits,
                const size_t sn_bits_nr)
	__attribute__((warn_unused_result, nonnull(1)));

bool wlsb_is_sn_present(struct c_wlsb *const wlsb, const uint32_t sn)
	__attribute__((warn_unused_result, nonnull(1)));

#endif

