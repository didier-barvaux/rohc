/*
 * Copyright 2012,2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2009,2010,2012 Viveris Technologies
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
 * @file d_udp.h
 * @brief ROHC decompression context for the UDP profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_UDP_H
#define ROHC_DECOMP_UDP_H

#include "d_generic.h"

int udp_parse_static_udp(const struct rohc_decomp_ctxt *const context,
                         const unsigned char *packet,
                         size_t length,
                         struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

void udp_update_context(const struct rohc_decomp_ctxt *context,
                        const struct rohc_decoded_values decoded)
	__attribute__((nonnull(1)));

#endif

