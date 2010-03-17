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
 * @file rohc.c
 * @brief ROHC common definitions and routines 
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Emmanuelle Pechereau <epechereau@toulouse.viveris.com>
 */

#include "rohc.h"
#include "config.h" /* for VERSION definition */


/**
 * @defgroup rohc_common ROHC compressor/decompressor common API
 */


/**
 * @brief Get the version of the ROHC library
 *
 * @return the version of the library
 *
 * @ingroup rohc_common
 */
char *rohc_version(void)
{
	return VERSION;
}

