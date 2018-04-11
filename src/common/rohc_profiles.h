/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2017,2018 Viveris Technologies
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
 * @file   rohc_profiles.h
 * @brief  Definition of ROHC profiles
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Valentin Boutonné <vboutonne@toulouse.viveris.com>
 */

#ifndef ROHC_PROFILES_H
#define ROHC_PROFILES_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __KERNEL__
#  include <linux/types.h>
#else
#  include <stdbool.h>
#endif

/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
#  define ROHC_EXPORT __declspec(dllexport)
#else
#  define ROHC_EXPORT
#endif


/*
 * ROHC profiles numbers allocated by the IANA (see 8 in the RFC 3095):
 */

/** The maximum major number for the supported ROHC profile IDs */
#define ROHC_PROFILE_ID_MAJOR_MAX  0x01U

/** The maximum minor number for the supported ROHC profile IDs */
#define ROHC_PROFILE_ID_MINOR_MAX  0x08U

/**
 * @brief The different ROHC compression/decompression profiles
 *
 * The ROHC profiles numbers are allocated by the IANA:
 *  - see  §8 in the RFC 3095 (ROHCv1)
 *  - see  §5 in the RFC 3843 (ROHCv1 IP-only)
 *  - see  §7 in the RFC 4019 (ROHCv1 UDP-Lite)
 *  - see §11 in the RFC 6846 (ROHCv1 TCP)
 *  - see  §8 in the RFC 5252 (ROHCv2)
 *
 * If you add a new compression/decompression profile, please also add the
 * corresponding textual description in \ref rohc_get_profile_descr.
 *
 * @ingroup rohc
 *
 * @see rohc_get_profile_descr
 */
typedef enum
{
	/** The ROHCv1 Uncompressed profile (RFC 3095, section 5.10) */
	ROHC_PROFILE_UNCOMPRESSED     = 0x0000,
/** Alias for ROHCv1 Uncompressed profile */
#define ROHCv1_PROFILE_UNCOMPRESSED   ROHC_PROFILE_UNCOMPRESSED
	/** The ROHCv1 RTP profile (RFC 3095, section 8) */
	ROHC_PROFILE_RTP              = 0x0001,
/** Alias for ROHCv1 IP/UDP/RTP profile */
#define ROHCv1_PROFILE_IP_UDP_RTP     ROHC_PROFILE_RTP
	/** The ROHCv1 UDP profile (RFC 3095, section 5.11) */
	ROHC_PROFILE_UDP              = 0x0002,
/** Alias for ROHCv1 IP/UDP profile */
#define ROHCv1_PROFILE_IP_UDP         ROHC_PROFILE_UDP
	/** The ROHCv1 ESP profile (RFC 3095, section 5.12) */
	ROHC_PROFILE_ESP              = 0x0003,
/** Alias for ROHCv1 IP/ESP profile */
#define ROHCv1_PROFILE_IP_ESP         ROHC_PROFILE_ESP
	/** The ROHCv1 IP-only profile (RFC 3843, section 5) */
	ROHC_PROFILE_IP               = 0x0004,
/** Alias for ROHCv1 IP-only profile */
#define ROHCv1_PROFILE_IP             ROHC_PROFILE_IP
	/** The ROHCv1 IP/UDP/RTP Link-Layer Assisted Profile (LLA) profile
	 *  (RFC 4362, section 6) */
	ROHC_PROFILE_RTP_LLA          = 0x0005,
/** Alias for ROHCv1 IP/UDP/RTP LLA profile */
#define ROHCv1_PROFILE_IP_UDP_RTP_LLA ROHC_PROFILE_RTP_LLA
	/** The ROHCv1 TCP profile (RFC 4996) */
	ROHC_PROFILE_TCP              = 0x0006,
/** Alias for ROHCv1 IP/TCP profile */
#define ROHCv1_PROFILE_IP_TCP         ROHC_PROFILE_TCP
	/** The ROHCv1 UDP-Lite/RTP profile (RFC 4019, section 7) */
	ROHC_PROFILE_UDPLITE_RTP      = 0x0007,
/** Alias for ROHCv1 IP/UDP-Lite/RTP profile */
#define ROHCv1_PROFILE_IP_UDPLITE_RTP ROHC_PROFILE_UDPLITE_RTP
	/** The ROHCv1 UDP-Lite profile (RFC 4019, section 7) */
	ROHC_PROFILE_UDPLITE          = 0x0008,
/** Alias for ROHCv1 IP/UDP-Lite profile */
#define ROHCv1_PROFILE_IP_UDPLITE     ROHC_PROFILE_UDPLITE

	/** The ROHCv2 RTP/UDP/IP profile */
	ROHCv2_PROFILE_IP_UDP_RTP     = 0x0101,
	/** The ROHCv2 UDP/IP profile */
	ROHCv2_PROFILE_IP_UDP         = 0x0102,
	/** The ROHCv2 ESP/IP profile */
	ROHCv2_PROFILE_IP_ESP         = 0x0103,
	/** The ROHCv2 IP-only profile */
	ROHCv2_PROFILE_IP             = 0x0104,
	/** The ROHCv2 IP/UDP-Lite/RTP profile */
	ROHCv2_PROFILE_IP_UDPLITE_RTP = 0x0107,
	/** The ROHCv2 IP/UDP-Lite profile */
	ROHCv2_PROFILE_IP_UDPLITE     = 0x0108,

	ROHC_PROFILE_MAX              = 0x0109,

} rohc_profile_t;


/*
 * Prototypes of public functions
 */

const char * ROHC_EXPORT rohc_get_profile_descr(const rohc_profile_t profile)
	__attribute__((warn_unused_result, const));

bool ROHC_EXPORT rohc_profile_is_rohcv1(const rohc_profile_t profile)
	__attribute__((warn_unused_result, const));

bool ROHC_EXPORT rohc_profile_is_rohcv2(const rohc_profile_t profile)
	__attribute__((warn_unused_result, const));

rohc_profile_t rohc_profile_get_other_version(const rohc_profile_t profile)
	__attribute__((warn_unused_result, const));

#undef ROHC_EXPORT /* do not pollute outside this header */

#ifdef __cplusplus
}
#endif

#endif /* ROHC_PROFILES_H */

