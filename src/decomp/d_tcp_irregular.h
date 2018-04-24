/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2013,2014 Viveris Technologies
 * Copyright 2012 WBX
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
 * @file   d_tcp_irregular.c
 * @brief  Handle the irregular chain of the TCP decompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_DECOMP_TCP_IRREGULAR_H
#define ROHC_DECOMP_TCP_IRREGULAR_H

#include "rohc_decomp_internals.h"
#include "d_tcp_defines.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

bool tcp_parse_irreg_chain(const struct rohc_decomp_ctxt *const context,
                           const uint8_t *const rohc_packet,
                           const size_t rohc_length,
                           const rohc_ip_id_behavior_t innermost_ip_id_behavior,
                           struct rohc_tcp_extr_bits *const bits,
                           size_t *const parsed_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6)));

#endif /* ROHC_DECOMP_TCP_IRREGULAR_H */

