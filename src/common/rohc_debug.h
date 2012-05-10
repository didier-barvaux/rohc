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
 * @file   rohc_debug.h
 * @brief  ROHC debug utils
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DEBUG_H
#define ROHC_DEBUG_H

/*
 * Includes
 */

#include <stdlib.h> /* for free(3) */
#include "config.h" /* for ROHC_DEBUG_LEVEL definition */


/*
 * Debug macros
 */

#if ROHC_DEBUG_LEVEL > 0

/** Free a pointer plus set it to NULL to avoid hidden bugs */
#define zfree(pointer) \
	do { \
		free(pointer); \
		pointer = NULL; \
	} while(0)

#else /* not ROHC_DEBUG */

#define zfree(pointer) \
	do { \
		free(pointer); \
	} while(0)

#endif


#endif

