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
 * @file   schemes/comp_list_ipv6.h
 * @brief  ROHC list compression of IPv6 extension headers
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_COMP_LIST_IPV6_H
#define ROHC_COMP_LIST_IPV6_H

#include "schemes/comp_list.h"


void rohc_comp_list_ipv6_new(struct list_comp *const comp,
                             const size_t list_trans_nr,
                             rohc_trace_callback2_t trace_cb,
                             void *const trace_cb_priv,
                             const int profile_id)
	__attribute__((nonnull(1)));

void rohc_comp_list_ipv6_free(struct list_comp *const comp)
	__attribute__((nonnull(1)));

#endif

