/*
 * Copyright 2013 Didier Barvaux
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
 * @file   rohc_add_cid.h
 * @brief  Functions related to ROHC add-CID
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_ADD_CID_H
#define ROHC_ADD_CID_H

#include <stddef.h>
#include <stdint.h>
#ifdef __KERNEL__
#  include <linux/types.h>
#else
#  include <stdbool.h>
#endif

/*
 * Function prototypes
 */

bool rohc_add_cid_is_present(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));

uint8_t rohc_add_cid_decode(const uint8_t *const data)
	__attribute__((warn_unused_result, nonnull(1), pure));

#endif

