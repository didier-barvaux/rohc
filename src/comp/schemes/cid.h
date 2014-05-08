/*
 * Copyright 2010,2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010 Viveris Technologies
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file cid.h
 * @brief Context ID (CID) routines.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMP_SCHEMES_CID_H
#define ROHC_COMP_SCHEMES_CID_H

#include "rohc.h"
#include "dllexport.h"

#include <stdlib.h>


/*
 * Prototypes of functions that may used by other ROHC modules
 */

size_t ROHC_EXPORT code_cid_values(const rohc_cid_type_t cid_type,
                                   const int cid,
                                   unsigned char *const dest,
                                   const size_t dest_size,
                                   size_t *const first_position)
	__attribute__((warn_unused_result, nonnull(3, 5)));


#endif

