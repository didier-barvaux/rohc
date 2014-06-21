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
 * @file   src/comp/schemes/wlsb.h
 * @brief  Window-based Least Significant Bits (W-LSB) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author David Moreau from TAS
 */

#ifndef ROHC_COMP_SCHEMES_WLSB_H
#define ROHC_COMP_SCHEMES_WLSB_H

#include "interval.h" /* for rohc_lsb_shift_t */
#include "dllexport.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


/* The definition of the W-LSB encoding object is private */
struct c_wlsb;


/*
 * Public function prototypes:
 */

struct c_wlsb * ROHC_EXPORT c_create_wlsb(const size_t bits,
                                          const size_t window_width,
                                          const rohc_lsb_shift_t p)
	__attribute__((warn_unused_result));
void ROHC_EXPORT c_destroy_wlsb(struct c_wlsb *s);

void ROHC_EXPORT c_add_wlsb(struct c_wlsb *const wlsb,
                            const uint32_t sn,
                            const uint32_t value);

bool ROHC_EXPORT wlsb_get_k_16bits(const struct c_wlsb *const wlsb,
                                   const uint16_t value,
                                   size_t *const bits_nr)
	__attribute__((warn_unused_result, nonnull(1, 3)));
bool ROHC_EXPORT wlsb_get_k_32bits(const struct c_wlsb *const wlsb,
                                   const uint32_t value,
                                   size_t *const bits_nr)
	__attribute__((warn_unused_result, nonnull(1, 3)));
bool ROHC_EXPORT wlsb_get_kp_32bits(const struct c_wlsb *const wlsb,
                                    const uint32_t value,
                                    const rohc_lsb_shift_t p,
                                    size_t *const bits_nr)
	__attribute__((warn_unused_result, nonnull(1, 4)));

void ROHC_EXPORT c_ack_sn_wlsb(struct c_wlsb *const s, const uint32_t sn)
	__attribute__((nonnull(1)));

#endif

