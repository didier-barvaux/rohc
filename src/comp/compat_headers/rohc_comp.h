/*
 * Copyright 2013 Didier Barvaux
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

#ifndef ROHC_COMPAT_COMP_H
#define ROHC_COMPAT_COMP_H

/* The rohc_comp.h header was deprecated. All of the public headers of the
 * ROHC library were moved to the rohc/ subdirectory.
 *
 * A stub rohc_comp.h file (this file) was installed to keep compatibility for
 * developers of applications using the ROHC library, but they should migrate
 * as soon as possible. Removal is planned for 2.0.0.
 */
#warning "please do not include rohc_comp.h, include rohc/rohc_comp.h instead"

#include <rohc/rohc_comp.h>

#endif

