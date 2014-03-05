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
 * @file rohc_common.c
 * @brief ROHC common definitions and routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Emmanuelle Pechereau <epechereau@toulouse.viveris.com>
 */

#include "rohc.h"
#include "config.h" /* for VERSION definition */

#include <assert.h>


/**
 * @defgroup rohc  The ROHC compressor/decompressor common API
 *
 * The common API of the ROHC library allows a program to print the version of
 * the ROHC library, or retrieve the description of ROHC modes and packets. No
 * initialization is required.
 */


/**
 * @brief Get the version of the ROHC library
 *
 * Get the version of the ROHC library
 *
 * @return the version of the library
 *
 * @ingroup rohc
 *
 * \par Example:
 * @snippet print_rohc_version.c get ROHC version
 */
char * rohc_version(void)
{
	return VERSION PACKAGE_REVNO;
}


/**
 * @brief Give a description for the given ROHC mode
 *
 * Give a description for the given ROHC mode.
 *
 * The descriptions are not part of the API. They may change between
 * releases without any warning. Do NOT use them for other means that
 * providing to users a textual description of modes used by the
 * library. If unsure, ask on the mailing list.
 *
 * @param mode  The ROHC mode to get a description for
 * @return      A string that describes the given ROHC mode
 *
 * @ingroup rohc
 */
const char * rohc_get_mode_descr(const rohc_mode_t mode)
{
	switch(mode)
	{
		case ROHC_U_MODE:
			return "U-mode";
		case ROHC_O_MODE:
			return "O-mode";
		case ROHC_R_MODE:
			return "R-mode";
		default:
			assert(0);
#ifdef __KERNEL__
			return "no description";
#endif
	}
}


/**
 * @brief Give a description for the given ROHC profile
 *
 * Give a description for the given ROHC compression/decompression profile.
 *
 * The descriptions are not part of the API. They may change between
 * releases without any warning. Do NOT use them for other means that
 * providing to users a textual description of profiles used by the
 * library. If unsure, ask on the mailing list.
 *
 * @param profile  The ROHC profile to get a description for
 * @return         A string that describes the given ROHC profile
 *
 * @ingroup rohc
 */
const char * rohc_get_profile_descr(const rohc_profile_t profile)
{
	switch(profile)
	{
		case ROHC_PROFILE_UNCOMPRESSED:
			return "Uncompressed";
		case ROHC_PROFILE_RTP:
			return "IP/UDP/RTP";
		case ROHC_PROFILE_UDP:
			return "IP/UDP";
		case ROHC_PROFILE_ESP:
			return "IP/ESP";
		case ROHC_PROFILE_IP:
			return "IP-only";
		case ROHC_PROFILE_TCP:
			return "IP/TCP";
		case ROHC_PROFILE_UDPLITE:
			return "IP/UDP-Lite";
		default:
			assert(0);
#ifdef __KERNEL__
			return "no description";
#endif
	}
}

