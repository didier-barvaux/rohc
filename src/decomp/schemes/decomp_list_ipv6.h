/*
 * Copyright 2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
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
 * @file   schemes/decomp_list_ipv6.h
 * @brief  ROHC list decompression of IPv6 extension headers
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_LIST_IPV6_H
#define ROHC_DECOMP_LIST_IPV6_H

#include "schemes/decomp_list.h"

void rohc_decomp_list_ipv6_init(struct list_decomp *const decomp,
                                rohc_trace_callback2_t trace_cb,
                                void *const trace_cb_priv,
                                const int profile_id)
	__attribute__((nonnull(1)));

#endif

