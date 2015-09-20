/*
 * Copyright 2015 Didier Barvaux
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
 * @file   /comp/schemes/tcp_sack.h
 * @brief  Handle encoding of TCP Selective ACKnowledgement (SACK) option
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_COMP_SCHEMES_TCP_SACK_H
#define ROHC_COMP_SCHEMES_TCP_SACK_H

#include "rohc_comp_internals.h"
#include "protocols/tcp.h" /* for sack_block_t */

#include <stddef.h>
#include <stdint.h>

int c_tcp_opt_sack_code(const struct rohc_comp_ctxt *const context,
                        const uint32_t ack_value,
                        const sack_block_t *const sack_blocks,
                        const uint8_t length,
                        const bool is_unchanged,
                        uint8_t *const rohc_data,
                        const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 6)));

#endif /* ROHC_COMP_SCHEMES_TCP_SACK_H */

