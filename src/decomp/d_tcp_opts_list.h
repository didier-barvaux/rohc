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
 * @file   d_tcp_opts_list.h
 * @brief  Handle the list of TCP options for the TCP decompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_DECOMP_TCP_OPTS_LIST_H
#define ROHC_DECOMP_TCP_OPTS_LIST_H

#include "rohc_decomp_internals.h"
#include "d_tcp_defines.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

int d_tcp_parse_tcp_opts_list_item(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *const rohc_packet,
                                   const size_t rohc_length,
                                   const bool is_dynamic_chain,
                                   struct d_tcp_opts_ctxt *const tcp_opts)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));

int d_tcp_parse_tcp_opts_irreg(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const rohc_packet,
                               const size_t rohc_length,
                               struct d_tcp_opts_ctxt *const tcp_opts)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

bool d_tcp_build_tcp_opts(const struct rohc_decomp_ctxt *const context,
                          const struct rohc_tcp_decoded_values *const decoded,
                          struct rohc_buf *const uncomp_packet,
                          size_t *const opts_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

#endif /* ROHC_DECOMP_TCP_OPTS_LIST_H */

