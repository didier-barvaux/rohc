/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2017,2018 Viveris Technologies
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
 * @file   rohc_profiles.c
 * @brief  ROHC common definitions and routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Emmanuelle Pechereau <epechereau@toulouse.viveris.com>
 * @author Valentin Boutonné <vboutonne@toulouse.viveris.com>
 */

#include "rohc_profiles.h"


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
			return "ROHCv1 Uncompressed";
		case ROHC_PROFILE_RTP:
			return "ROHCv1 IP/UDP/RTP";
		case ROHC_PROFILE_UDP:
			return "ROHCv1 IP/UDP";
		case ROHC_PROFILE_ESP:
			return "ROHCv1 IP/ESP";
		case ROHC_PROFILE_IP:
			return "ROHCv1 IP-only";
		case ROHC_PROFILE_RTP_LLA:
			return "ROHCv1 IP/UDP/RTP (LLA)";
		case ROHC_PROFILE_TCP:
			return "ROHCv1 IP/TCP";
		case ROHC_PROFILE_UDPLITE_RTP:
			return "ROHCv1 IP/UDP-Lite/RTP";
		case ROHC_PROFILE_UDPLITE:
			return "ROHCv1 IP/UDP-Lite";
		case ROHCv2_PROFILE_IP_UDP_RTP:
			return "ROHCv2 IP/UDP/RTP";
		case ROHCv2_PROFILE_IP_UDP:
			return "ROHCv2 IP/UDP";
		case ROHCv2_PROFILE_IP_ESP:
			return "ROHCv2 IP/ESP";
		case ROHCv2_PROFILE_IP:
			return "ROHCv2 IP";
		case ROHCv2_PROFILE_IP_UDPLITE_RTP:
			return "ROHCv2 IP/UDP-Lite/RTP";
		case ROHCv2_PROFILE_IP_UDPLITE:
			return "ROHCv2 IP/UDP-Lite";

		case ROHC_PROFILE_MAX:
		default:
			return "no description";
	}
}


/**
 * @brief Is the given profile one ROHCv1 profile?
 *
 * @param profile  The profile ID to check for
 * @return         true if profile is one ROHCv1 profile,
 *                 false if profile is one ROHCv2 profile
 *
 * @ingroup rohc
 */
bool rohc_profile_is_rohcv1(const rohc_profile_t profile)
{
	return ((profile & 0xff00) == 0x0000);
}


/**
 * @brief Is the given profile one ROHCv2 profile?
 *
 * @param profile  The profile ID to check for
 * @return         true if profile is one ROHCv2 profile,
 *                 false if profile is one ROHCv1 profile
 *
 * @ingroup rohc
 */
bool rohc_profile_is_rohcv2(const rohc_profile_t profile)
{
	return ((profile & 0xff00) == 0x0100);
}


/**
 * @brief Get the other version of the given profile
 *
 * @param profile  The profile ID for which to get the other version
 * @return         The ROHCv1 profile if the given one is ROHCv2,
 *                 the ROHCv2 profile if the given one is ROHCv1,
 *                 ROHC_PROFILE_MAX otherwise
 *
 * @ingroup rohc
 */
rohc_profile_t rohc_profile_get_other_version(const rohc_profile_t profile)
{
	rohc_profile_t other_version_profile;

	if(rohc_profile_is_rohcv1(profile))
	{
		other_version_profile = profile + 0x0100;
	}
	else if(rohc_profile_is_rohcv2(profile))
	{
		other_version_profile = profile - 0x0100;
	}
	else
	{
		other_version_profile = ROHC_PROFILE_MAX;
	}

	return other_version_profile;
}

