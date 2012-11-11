/*
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
 * @file    rohc_decomp_internals.h
 * @brief   Internal structures for ROHC decompression
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_INTERNALS_H
#define ROHC_DECOMP_INTERNALS_H


/*
 * Constants and macros
 */

/** Print a debug trace for the given decompression context */
#define rohc_decomp_debug(context, format, ...) \
	rohc_debug((context)->decompressor, ROHC_TRACE_DECOMP, \
	           (context)->profile->id, \
	           format, ##__VA_ARGS__)

#endif

