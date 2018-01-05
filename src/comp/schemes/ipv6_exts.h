/*
 * Copyright 2018 Viveris Technologies
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
 * @file   comp/schemes/ipv6_exts.h
 * @brief  Compression schemes for IPv6 extension headers
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMP_SCHEMES_IPV6_EXTS_H
#define ROHC_COMP_SCHEMES_IPV6_EXTS_H

#include "rohc_comp_internals.h"

#include <stdint.h>
#include <stdbool.h>


/*
 * Prototypes of functions that may used by other ROHC modules
 */

bool rohc_comp_ipv6_exts_are_acceptable(const struct rohc_comp *const comp,
                                        uint8_t *const next_proto,
                                        const uint8_t *const exts,
                                        const size_t max_exts_len,
                                        size_t *const exts_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));


#endif

