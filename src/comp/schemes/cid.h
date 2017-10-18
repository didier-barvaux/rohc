/*
 * Copyright 2010,2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010 Viveris Technologies
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
 * @file cid.h
 * @brief Context ID (CID) routines.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMP_SCHEMES_CID_H
#define ROHC_COMP_SCHEMES_CID_H

#include "rohc.h"

#include <stdlib.h>
#include <stdint.h>


/*
 * Prototypes of functions that may used by other ROHC modules
 */

int code_cid_values(const rohc_cid_type_t cid_type,
                    const rohc_cid_t cid,
                    uint8_t *const dest,
                    const size_t dest_size,
                    size_t *const first_position)
	__attribute__((warn_unused_result, nonnull(3, 5)));


#endif

