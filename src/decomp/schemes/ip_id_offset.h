/*
 * Copyright 2012,2013 Didier Barvaux
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
 * @file   decomp/schemes/ip_id_offset.h
 * @brief  Offset IP-ID decoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_IP_ID_OFFSET_H
#define ROHC_DECOMP_IP_ID_OFFSET_H

#include "decomp_wlsb.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>


/*
 * Public structures
 */

/**
 * @brief Defines a IP-ID object to help computing the IP-ID value
 *        from an IP-ID offset
 */
struct ip_id_offset_decode
{
	/** The LSB context for decoding IP-ID offset */
	struct rohc_lsb_decode lsb;
};


/*
 * Function prototypes.
 */

void ip_id_offset_init(struct ip_id_offset_decode *const ipid)
	__attribute__((nonnull(1)));

bool ip_id_offset_decode(const struct ip_id_offset_decode *const ipid,
                         const rohc_lsb_ref_t ref_type,
                         const uint16_t m,
                         const size_t k,
                         const uint32_t sn,
                         uint16_t *const decoded)
	__attribute__((nonnull(1, 6), warn_unused_result));

void ip_id_offset_set_ref(struct ip_id_offset_decode *const ipid,
                          const uint16_t id_ref,
                          const uint32_t sn_ref,
                          const bool keep_ref_minus_1)
	__attribute__((nonnull(1)));

#endif

