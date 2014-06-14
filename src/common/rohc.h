/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012 Viveris Technologies
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

/**
 * @file rohc.h
 * @brief ROHC common definitions and routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_H
#define ROHC_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
#ifndef __KERNEL__
#  include <inttypes.h>
#endif


/** Macro that handles deprecated declarations gracefully */
#if defined __GNUC__ && \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5))
	/* __attribute__((deprecated(msg))) is supported by GCC 4.5 and later */
	#define ROHC_DEPRECATED(msg) __attribute__((deprecated(msg)))
#elif defined __GNUC__ && \
      (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1))
	/* __attribute__((deprecated)) is supported by GCC 3.1 and later */
	#define ROHC_DEPRECATED(msg) __attribute__((deprecated))
#else
	/* no support */
	#define ROHC_DEPRECATED(msg)
#endif


/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
	#define ROHC_EXPORT __declspec(dllexport)
#else
	#define ROHC_EXPORT 
#endif



/**
 * @brief The Ethertype assigned to the ROHC protocol by the IEEE
 *
 * @see http://standards.ieee.org/regauth/ethertype/eth.txt
 *
 * @ingroup rohc
 */
#define ROHC_ETHERTYPE  0x22f1


/*
 * Below are some return codes:
 */

/**
 * @brief Return code: the action was performed without problem
 * @ingroup rohc
 */
#define ROHC_OK                     1

/**
 * @brief Return code: the action failed because no context is defined
 * @ingroup rohc
 */
#define ROHC_ERROR_NO_CONTEXT      -1

/**
 * @brief Return code: the action failed due to an unattended or malformed packet
 * @ingroup rohc
 */
#define ROHC_ERROR_PACKET_FAILED   -2

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
/**
 * @brief Return code: the action failed because the packet only contains feedback info
 * @ingroup rohc
 * @deprecated please do not use this constant anymore,
 *             use rohc_compress4() instead
 */
#define ROHC_FEEDBACK_ONLY         -3
#endif /* !ROHC_ENABLE_DEPRECATED_API */

/**
 * @brief Return code: the action failed due to a CRC failure
 * @ingroup rohc
 */
#define ROHC_ERROR_CRC             -4

/**
 * @brief Return code: the action encountered a problem
 * @ingroup rohc
 */
#define ROHC_ERROR                 -5

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
/// Return code: the packet needs to be parsed again
#define ROHC_NEED_REPARSE          -6
#endif /* !ROHC_ENABLE_DEPRECATED_API */

/**
 * @brief Return code: the action succeeded but packet needs to be segmented
 * @ingroup rohc
 */
#define ROHC_NEED_SEGMENT          -7

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
/**
 * @brief Return code: the action succeeded but packet is a non-final segment
 * @ingroup rohc
 * @deprecated please do not use this constant anymore,
 *             use rohc_compress4() instead
 */
#define ROHC_NON_FINAL_SEGMENT     -8
#endif /* !ROHC_ENABLE_DEPRECATED_API */


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief ROHC operation modes (see 4.4 in the RFC 3095)
 *
 * If you add a new operation mode, please also add the corresponding textual
 * description in \ref rohc_get_mode_descr.
 *
 * @deprecated do not use this type anymore, use \ref rohc_mode_t instead
 *
 * @ingroup rohc
 *
 * @see rohc_mode_t
 */
typedef enum
{
	/// The Unidirectional mode (U-mode)
	U_MODE = 1,
	/// The Bidirectional Optimistic mode (O-mode)
	O_MODE = 2,
	/// The Bidirectional Reliable mode (R-mode)
	R_MODE = 3,
} rohc_mode
	ROHC_DEPRECATED("please do not use this type anymore, "
	                "use rohc_mode_t instead");

#endif /* !ROHC_ENABLE_DEPRECATED_API) */

/**
 * @brief ROHC operation modes
 *
 * The different ROHC operation modes as defined in section 4.4 of RFC 3095.
 *
 * If you add a new operation mode, please also add the corresponding textual
 * description in \ref rohc_get_mode_descr.
 *
 * @ingroup rohc
 *
 * @see rohc_get_mode_descr
 */
typedef enum
{
	/** The Unidirectional mode (U-mode) */
	ROHC_U_MODE = 1,
	/** The Bidirectional Optimistic mode (O-mode) */
	ROHC_O_MODE = 2,
	/** The Bidirectional Reliable mode (R-mode) */
	ROHC_R_MODE = 3,

} rohc_mode_t;


/**
 * @brief The maximum value for large CIDs
 *
 * @ingroup rohc
 *
 * @see rohc_comp_new
 * @see rohc_c_set_max_cid
 * @see rohc_decomp_set_max_cid
 */
#define ROHC_LARGE_CID_MAX  ((1 << 14) - 1) /* 2^14 - 1 = 16383 */

/**
 * @brief The maximum value for small CIDs
 *
 * @ingroup rohc
 *
 * @see rohc_comp_new
 * @see rohc_c_set_max_cid
 * @see rohc_decomp_set_max_cid
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \snippet simple_rohc_program.c create ROHC compressor
 */
#define ROHC_SMALL_CID_MAX  15


/**
 * @brief The different types of Context IDs (CID)
 *
 * The different types of Context IDs (CID) a ROHC compressor or a ROHC
 * decompressor may use.
 *
 * Possible values are:
 *  \li \ref ROHC_LARGE_CID : large CID means that a ROHC compressor or a ROHC
 *      decompressor may identify contexts with IDs in the range
 *      [0, \ref ROHC_LARGE_CID_MAX ], ie. it may uniquely identify at
 *      most \e ROHC_LARGE_CID_MAX + 1 streams.
 *  \li \ref ROHC_SMALL_CID : small CID means that a ROHC compressor or a ROHC
 *      decompressor may identify contexts with IDs in the range
 *      [0, \ref ROHC_SMALL_CID_MAX ], ie. it may uniquely identify at
 *      most \e ROHC_SMALL_CID_MAX + 1 streams.
 *
 * In short, you choose the CID type in function of the number of simultaneous
 * streams you have to compress efficiently.
 *
 * @see ROHC_SMALL_CID_MAX ROHC_LARGE_CID_MAX
 *
 * @ingroup rohc
 */
typedef enum
{
	/**
	 * @brief The context uses large CID
	 *
	 * CID values shall be in the range [0, \ref ROHC_LARGE_CID_MAX].
	 */
	ROHC_LARGE_CID,
	/**
	 * @brief The context uses small CID
	 *
	 * CID value shall be in the range [0, \ref ROHC_SMALL_CID_MAX].
	 */
	ROHC_SMALL_CID,

} rohc_cid_type_t;


/** A ROHC Context ID (CID) */
typedef size_t rohc_cid_t;


/*
 * ROHC profiles numbers allocated by the IANA (see 8 in the RFC 3095):
 */

/**
 * @brief The different ROHC compression/decompression profiles
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
	/** The ROHC Uncompressed profile (RFC 3095, section 5.10) */
	ROHC_PROFILE_UNCOMPRESSED = 0x0000,
	/** The ROHC RTP profile (RFC 3095, section 8) */
	ROHC_PROFILE_RTP          = 0x0001,
	/** The ROHC UDP profile (RFC 3095, section 5.11) */
	ROHC_PROFILE_UDP          = 0x0002,
	/** The ROHC ESP profile (RFC 3095, section 5.12) */
	ROHC_PROFILE_ESP          = 0x0003,
	/** The ROHC IP-only profile (RFC 3843, section 5) */
	ROHC_PROFILE_IP           = 0x0004,
	/** The ROHC TCP profile (RFC 4996) */
	ROHC_PROFILE_TCP          = 0x0006,
	/** The ROHC UDP-Lite profile (RFC 4019, section 7) */
	ROHC_PROFILE_UDPLITE      = 0x0008,

} rohc_profile_t;


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/*
 * The different CRC types and tables for ROHC compression/decompression
 *
 * TODO API: remove these public constants since a private enum was created
 */

/** The CRC-2 type (deprecated) */
#define CRC_TYPE_2 1
/** The CRC-3 type (deprecated) */
#define CRC_TYPE_3 2
/** The CRC-6 type (deprecated) */
#define CRC_TYPE_6 3
/** The CRC-7 type (deprecated) */
#define CRC_TYPE_7 4
/** The CRC-8 type (deprecated) */
#define CRC_TYPE_8 5


/* TODO API: remove these variables once compatibility is not needed anymore */

/** The table to enable fast CRC-2 computation
 * @deprecated please do not use this variable anymore */
extern unsigned char ROHC_EXPORT crc_table_2[256]
	ROHC_DEPRECATED("please do not use this variable anymore, simply drop it");

/** The table to enable fast CRC-3 computation
 * @deprecated please do not use this variable anymore */
extern unsigned char ROHC_EXPORT crc_table_3[256]
	ROHC_DEPRECATED("please do not use this variable anymore, simply drop it");

/** The table to enable fast CRC-6 computation
 * @deprecated please do not use this variable anymore */
extern unsigned char ROHC_EXPORT crc_table_6[256]
	ROHC_DEPRECATED("please do not use this variable anymore, simply drop it");

/** The table to enable fast CRC-7 computation
 * @deprecated please do not use this variable anymore */
extern unsigned char ROHC_EXPORT crc_table_7[256]
	ROHC_DEPRECATED("please do not use this variable anymore, simply drop it");

/** The table to enable fast CRC-8 computation
 * @deprecated please do not use this variable anymore */
extern unsigned char ROHC_EXPORT crc_table_8[256]
	ROHC_DEPRECATED("please do not use this variable anymore, simply drop it");

#endif /* !ROHC_ENABLE_DEPRECATED_API) */


/*
 * Prototypes of public up-to-date functions
 */

char * ROHC_EXPORT rohc_version(void);

const char * ROHC_EXPORT rohc_get_mode_descr(const rohc_mode_t mode);

const char * ROHC_EXPORT rohc_get_profile_descr(const rohc_profile_t profile)
	__attribute__((warn_unused_result));


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/*
 * Prototypes of public deprecated functions
 *
 * TODO API: remove this function once compatibility is not needed anymore
 */

int ROHC_EXPORT crc_get_polynom(int type)
	ROHC_DEPRECATED("please do not use this function anymore, simply drop it");

void ROHC_EXPORT crc_init_table(unsigned char *table, unsigned char polynum)
	ROHC_DEPRECATED("please do not use this function anymore, simply drop it");

#endif /* !ROHC_ENABLE_DEPRECATED_API) */


#undef ROHC_EXPORT /* do not pollute outside this header */

#ifdef __cplusplus
}
#endif

#endif /* ROHC_H */

