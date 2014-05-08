/*
 * Copyright 2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 *
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
 * @file   decomp/schemes/list_ipv6.h
 * @brief  ROHC list decompression of IPv6 extension headers
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_LIST_IPV6_H
#define ROHC_DECOMP_LIST_IPV6_H

#include "decomp/schemes/list.h"


void ROHC_EXPORT rohc_decomp_list_ipv6_new(struct list_decomp *const decomp,
                                           rohc_trace_callback_t trace_callback,
                                           const int profile_id)
	__attribute__((nonnull(1)));

void ROHC_EXPORT rohc_decomp_list_ipv6_free(struct list_decomp *const decomp)
	__attribute__((nonnull(1)));

#endif

