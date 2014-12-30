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
 * @file   decomp/schemes/tcp_ts.h
 * @brief  Handle decoding of TCP TimeStamp (TS) option
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_SCHEMES_TCP_TS_H
#define ROHC_DECOMP_SCHEMES_TCP_TS_H

#include "rohc_decomp_internals.h"
#include "decomp_wlsb.h"

#include <stdlib.h>
#include <stdint.h>

/** The context to parse and decode the TCP TimeStamp (TS) option */
struct d_tcp_opt_ts
{
	struct rohc_lsb_field32 req;  /**< The context for the TS request field */
	struct rohc_lsb_field32 rep;  /**< The context for the TS reply field */
	size_t uncomp_opt_offset;     /**< The uncompressed TS option */
};

int d_tcp_ts_lsb_size(const struct rohc_decomp_ctxt *const context,
                      const uint8_t *const rohc_data,
                      const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2)));

int d_tcp_ts_parse(const struct rohc_decomp_ctxt *const context,
                   const uint8_t *const data,
                   const size_t data_len,
                   struct d_tcp_opt_ts *const opt_ts)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

#endif /* ROHC_DECOMP_SCHEMES_TCP_TS_H */

