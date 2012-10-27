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
 * @file rohc.h
 * @brief ROHC common definitions and routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#ifndef ROHC_H
#define ROHC_H

/**
 * \mainpage
 *
 * <h2>Introduction</h2>
 * <p>The <a href="http://rohc-lib.org/" title="Official website">ROHC library</a>
 * provides an easy and robust way for applications to reduce their bandwidth
 * usage on network links with limited capacity.  Headers of network packets are
 * compressed with the ROHC protocol and algorithms.</p>
 * <p><a href="http://rohc-lib.org/wiki/doku.php?id=rohc-protocol"
 * title="An introduction to the ROHC protocol">RObust Header Compression
 * (ROHC)</a> is a set of standards defined by the <a href="http://www.ietf.org/"
 * title="The IETF website">IETF</a>. The ROHC library is a free, opensource and
 * efficient implementation of them. The list of features implemented is available
 * on a separate page: \ref features</p>
 * <ul>
 *   <li>Official website: <a href="http://rohc-lib.org/">
 *                          http://rohc-lib.org/</a></li>
 *   <li>Project page on Launchpad: <a href="http://rohc-lib.org/">
 *                          http://rohc-lib.org/</a></li>
 *   <li>Mailing list: <a href="mailto:rohc@lists.launchpad.net">
 *                      rohc@lists.launchpad.net</a></li>
 *   <li>Mailing list archives: <a href="http://lists.launchpad.net/rohc/">
 *                               http://lists.launchpad.net/rohc/</a></li>
 *   <li>Bugtracker: <a href="http://bugs.launchpad.net/rohc">
 *                    http://bugs.launchpad.net/rohc</a></li>
 * </ul>
 *
 * <h2>License</h2>
 * <p>The project is licensed under GPL2+.
 * See the <a href="http://bazaar.launchpad.net/%7Edidier-barvaux/rohc/main/annotate/head%3A/COPYING">COPYING</a>
 * and <a href="http://bazaar.launchpad.net/%7Edidier-barvaux/rohc/main/annotate/head%3A/AUTHORS">AUTHORS</a>
 * files for more details.</p>
 *
 * <h2>Libraries</h2>
 * <p>
 * The sources are in the src subdirectory. The sources are separated into
 * three libraries:
 *  <ul>
 *   <li>a library that contains the routines used for both the compression
 *       and the decompression processes</li>
 *   <li>a library that handles the compression process</li>
 *   <li>a library that handles the decompression process</li>
 *  </ul>
 * </p>
 * <p>See the <a href="http://bazaar.launchpad.net/%7Edidier-barvaux/rohc/main/annotate/head%3A/INSTALL"> INSTALL file</a>
 * to learn to build the libraries.</p>
 *
 * <h2>API documentation</h2>
 * <p>The APIs for ROHC common, compression and decompression are available on
 * separate pages:
 *  <ul>
 *    <li>\ref rohc_common</li>
 *    <li>\ref rohc_comp</li>
 *    <li>\ref rohc_decomp</li>
 *  </ul>
 * </p>
 *
 * <h2>Tests</h2>
 * <p>
 * Several tests may be run to check the library behaviour. See the
 * <a href="http://bazaar.launchpad.net/%7Edidier-barvaux/rohc/main/annotate/head%3A/INSTALL">INSTALL file</a> to learn how to use these tools.
 * </p>
 *
 * <h2>References</h2>
 * <dl style="padding-bottom: 1em;">
 *  <dt><a href="http://tools.ietf.org/html/rfc3095">RFC&nbsp;3095</a></dt>
 *  <dd>ROHC: Framework and four profiles: RTP, UDP, ESP, and uncompressed.</dd>
 *  <dt><a href="http://tools.ietf.org/html/rfc3096">RFC&nbsp;3096</a></dt>
 *  <dd>Requirements for robust IP/UDP/RTP header compression.</dd>
 *  <dt><a href="http://tools.ietf.org/html/rfc3843">RFC&nbsp;3843</a></dt>
 *  <dd>ROHC: A Compression Profile for IP.</dd>
 *  <dt><a href="http://tools.ietf.org/html/rfc4019">RFC&nbsp;4019</a></dt>
 *  <dd>ROHC: Profiles for User Datagram Protocol (UDP) Lite.</dd>
 *  <dt><a href="http://rohc-lib.org/">ROHC library</a></dt>
 *  <dd>The Open Source ROHC library described by the documentation you are
 *      currently reading.</dd>
 *  <dt><a href="http://rohc.sourceforge.net/">ROHC Linux</a></dt>
 *  <dd>A GPL-licensed implementation of ROHC over PPP for the 2.4 Linux kernel.
 *      The ROHC library started as a fork of this project.</dd>
 * </dl>
 */


/**
 * \page features Library features
 *
 * <p>See the <a href="http://rohc-lib.org/wiki/doku.php?id=library-compliance-rfcs">dedicated Wiki page for more details</a>.</p>
 */


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
 */
#define ROHC_ETHERTYPE  0x22f1


/*
 * Below are some return codes:
 */

/// Return code: the action done without problem
#define ROHC_OK                     1
/// Return code: the action can not proceed because no context is defined
#define ROHC_ERROR_NO_CONTEXT      -1
/// Return code: the action failed due to an unattended or malformed packet
#define ROHC_ERROR_PACKET_FAILED   -2
/// Return code: the action failed because the packet only contains feedback info
#define ROHC_FEEDBACK_ONLY         -3
/// Return code: the action failed due to a CRC failure
#define ROHC_ERROR_CRC             -4
/// Return code: the action encountered a problem
#define ROHC_ERROR                 -5
/// Return code: the packet needs to be parsed again
#define ROHC_NEED_REPARSE          -6


/**
 * @brief ROHC operation modes (see 4.4 in the RFC 3095)
 *
 * If you add a new operation mode, please also add the corresponding textual
 * description in \ref rohc_get_mode_descr.
 */
typedef enum
{
	/// The Unidirectional mode (U-mode)
	U_MODE = 1,
	/// The Bidirectional Optimistic mode (O-mode)
	O_MODE = 2,
	/// The Bidirectional Reliable mode (R-mode)
	R_MODE = 3,
} rohc_mode;


/** The maximum value for large CIDs */
#define ROHC_LARGE_CID_MAX  ((1 << 14) - 1) /* 2^14 - 1 = 16383 */
/** The maximum value for small CIDs */
#define ROHC_SMALL_CID_MAX  15


/**
 * @brief The different types of Context IDs (CID) a stream/context may use
 *
 * Possible values are: \ref ROHC_LARGE_CID, \ref ROHC_SMALL_CID.
 *
 * Small CID means CID in the \f$[0-ROHC\_SMALL\_CID\_MAX]\f$ interval.
 *
 * Large CID means CID in the \f$[0-ROHC\_LARGE\_CID\_MAX]\f$ interval.
 *
 * @see ROHC_SMALL_CID_MAX ROHC_LARGE_CID_MAX
 */
typedef enum
{
	/**
	 * @brief The context uses large CID
	 *
	 * Value in the \f$[0-ROHC\_LARGE\_CID\_MAX]\f$ interval.
	 */
	ROHC_LARGE_CID,
	/**
	 * @brief The context uses small CID
	 *
	 * Value in the \f$[0-ROHC\_SMALL\_CID\_MAX]\f$ interval.
	 */
	ROHC_SMALL_CID,
} rohc_cid_type_t;


/**
 * @brief ROHC medium (CID characteristics).
 */
struct medium
{
	/** The CID type: large or small */
	rohc_cid_type_t cid_type;

	/// The maximum CID value
	int max_cid;
};


/*
 * ROHC profiles numbers allocated by the IANA (see 8 in the RFC 3095):
 */

/// The number allocated for the ROHC Uncompressed profile (RFC 3095, 5.10)
#define ROHC_PROFILE_UNCOMPRESSED  0x0000
/// The number allocated for the ROHC RTP profile (RFC 3095, 8)
#define ROHC_PROFILE_RTP           0x0001
/// The number allocated for the ROHC UDP profile (RFC 3095, 5.11)
#define ROHC_PROFILE_UDP           0x0002
/// The number allocated for the ROHC ESP profile (RFC 3095, 5.12)
#define ROHC_PROFILE_ESP           0x0003
/// The number allocated for the ROHC IP-only profile (see 5 in the RFC 3843)
#define ROHC_PROFILE_IP            0x0004
/// The number allocated for the ROHC TCP profile (see the RFC 4996)
#define ROHC_PROFILE_TCP           0x0006  // FWX2
/// The number allocated for the ROHC UDP-Lite profile (see 7 in the RFC 4019)
#define ROHC_PROFILE_UDPLITE       0x0008


/*
 * The limits for the compressor states changes:
 */

/// @brief The maximal number of packets sent in > IR states (= FO and SO
///        states) before changing back the state to IR (periodic refreshes)
#define CHANGE_TO_IR_COUNT  1700

/// @brief The maximal number of packets sent in > FO states (= SO state)
///        before changing back the state to FO (periodic refreshes)
#define CHANGE_TO_FO_COUNT  700

/// @brief Defines the minimal number of packets that must be sent while
///        in IR state before being able to switch to the FO state
#define MAX_IR_COUNT  3

/// @brief Defines the minimal number of packets that must be sent while
///        in FO state before being able to switch to the SO state
#define MAX_FO_COUNT  3

/// @brief Defines the minimal number of packets that must be sent while in
///        INIT_STRIDE state before being able to switch to the SEND_SCALED
///        state
#define ROHC_INIT_TS_STRIDE_MIN  3U


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


/*
 * Prototypes of public up-to-date functions
 */

char * ROHC_EXPORT rohc_version(void);

const char * ROHC_EXPORT rohc_get_mode_descr(const rohc_mode mode);


/*
 * Prototypes of public deprecated functions
 *
 * TODO API: remove this function once compatibility is not needed anymore
 */

int ROHC_EXPORT crc_get_polynom(int type)
	ROHC_DEPRECATED("please do not use this function anymore, simply drop it");

void ROHC_EXPORT crc_init_table(unsigned char *table, unsigned char polynum)
	ROHC_DEPRECATED("please do not use this function anymore, simply drop it");


#undef ROHC_EXPORT /* do not pollute outside this header */

#endif

