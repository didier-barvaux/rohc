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
 * @file   decomp/schemes/rfc4996.h
 * @brief  Library of decoding methods from RFC4997 and RFC4996
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_SCHEMES_TCP_SACK_H
#define ROHC_DECOMP_SCHEMES_TCP_SACK_H

#include "rohc_decomp_internals.h"

#include <stdlib.h>
#include <stdint.h>

int d_tcp_sack_size(const struct rohc_decomp_ctxt *const context,
                    const uint8_t *const rohc_data,
                    const size_t rohc_length,
                    uint16_t *const uncomp_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

int d_tcp_sack_decode(const struct rohc_decomp_ctxt *const context,
                      const uint8_t *const data,
                      const size_t data_len,
                      uint8_t *const tcp_opts,
                      size_t *const tcp_opts_len,
                      const size_t tcp_opts_max_len,
                      const uint32_t ack_value)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

#endif /* ROHC_DECOMP_SCHEMES_TCP_SACK_H */

