/*
 * Copyright 2012,2013,2014,2015 Didier Barvaux
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
 * @file   decomp_crc.h
 * @brief  ROHC decompression checks for CRC
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_DECOMP_SCHEMES_CRC_H
#define ROHC_DECOMP_SCHEMES_CRC_H

#include "rohc_decomp_internals.h"

#include <stdbool.h>


bool rohc_decomp_check_uncomp_crc(const struct rohc_decomp *const decomp,
                                  const struct rohc_decomp_ctxt *const context,
                                  struct rohc_buf *const uncomp_hdrs,
                                  const struct rohc_decomp_crc_one *const crc_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

#endif

