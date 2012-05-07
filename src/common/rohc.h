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
 *
 * <h2>Introduction</h2>
 * 
 * <p>The ROHC library provides an easy and robust way for applications to
 * reduce their bandwidth usage on network links with limited capacity.
 * Headers of network packets are compressed with the ROHC protocol and
 * algorithms.</p>
 *
 * <p>RObust Header Compression (ROHC) is a set of standards defined by the
 * <a href="http://www.ietf.org/">IETF</a>. The ROHC library is a free,
 * opensource and efficient implementation of them. The list of features
 * implemented is available on a separate page: \ref features</p>
 *
 * <ul>
 *   <li>Official website: <a href="http://rohc-lib.org/">
 *                          http://rohc-lib.org/</a></li>
 *   <li>Project page on Launchpad: <a href="http://launchpad.net/rohc">
 *                          http://launchpad.net/rohc</a></li>
 *   <li>Mailing list: <a href="mailto:rohc@lists.launchpad.net">
 *                      rohc@lists.launchpad.net</a></li>
 *   <li>Mailing list archives: <a href="http://lists.launchpad.net/rohc/">
 *                               http://lists.launchpad.net/rohc/</a></li>
 *   <li>Bugtracker: <a href="http://bugs.launchpad.net/rohc">
 *                    http://bugs.launchpad.net/rohc</a></li>
 * </ul>
 *
 *
 * <h2>License</h2>
 * 
 * <p>The project is licensed under GPL2+.
 * See the <a href="http://bazaar.launchpad.net/%7Edidier-barvaux/rohc/main/annotate/head%3A/COPYING">COPYING</a>
 * and <a href="http://bazaar.launchpad.net/%7Edidier-barvaux/rohc/main/annotate/head%3A/AUTHORS">AUTHORS</a>
 * files for more details.</p>
 * 
 *
 * <h2>Libraries</h2>
 * 
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
 * 
 * <p>See the <a href="http://bazaar.launchpad.net/%7Edidier-barvaux/rohc/main/annotate/head%3A/INSTALL"> INSTALL file</a>
 * to learn to build the libraries.</p>
 *
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
 *
 * <h2>Non-regression tests</h2>
 * 
 * <p>
 * The test subdirectory contains several test applications. See the <a href="http://bazaar.launchpad.net/%7Edidier-barvaux/rohc/main/annotate/head%3A/INSTALL">INSTALL file</a> to learn how to use these tools.
 * </p>
 * 
 *
 * <h2>References</h2>
 * 
 * <table style="border-collapse: collapse; border: solid thin black;">
 *  <tr>
 *   <td>RFC 3095</td>
 *   <td>
 *    <p>
 *     RObust Header Compression (ROHC): Framework and four profiles: RTP,
 *     UDP, ESP, and uncompressed.<br>
 *      <a href="http://www.ietf.org/rfc/rfc3095.txt">
 *       http://www.ietf.org/rfc/rfc3095.txt</a>
 *    </p>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>RFC 3096</td>
 *   <td>
 *    <p>
 *     Requirements for robust IP/UDP/RTP header compression.<br>
 *      <a href="http://www.ietf.org/rfc/rfc3096.txt">
 *       http://www.ietf.org/rfc/rfc3096.txt</a>
 *    </p>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>RFC 3828</td>
 *   <td>
 *    <p>
 *     The Lightweight User Datagram Protocol (UDP-Lite).<br>
 *     <a href="http://www.ietf.org/rfc/rfc3828.txt">
 *     http://www.ietf.org/rfc/rfc3828.txt</a>
 *    </p>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>RFC 3843
 *   <td>
 *    <p>
 *     RObust Header Compression (ROHC): A Compression Profile for IP.<br>
 *     <a href="http://www.ietf.org/rfc/rfc3843.txt">
 *     http://www.ietf.org/rfc/rfc3843.txt</a>
 *    </p>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>RFC 4019</td>
 *   <td>
 *    <p>
 *     RObust Header Compression (ROHC): Profiles for User Datagram Protocol
 *     (UDP) Lite.<br>
 *     <a href="http://www.ietf.org/rfc/rfc4019.txt">
 *     http://www.ietf.org/rfc/rfc4019.txt</a>
 *    </p>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>ROHC library</td>
 *   <td>
 *    <p>
 *     The Open Source ROHC library described by the documentation you are
 *     currently reading.<br>
 *     <a href="http://launchpad.net/rohc">http://launchpad.net/rohc</a>
 *    </p>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>ROHC Linux</td>
 *   <td>
 *    <p>
 *     A GPL-licensed implementation of ROHC over PPP for the 2.4 Linux
 *     kernel. The ROHC library is mainly based on this software.<br>
 *     <a href="http://rohc.sourceforge.net/">http://rohc.sourceforge.net/</a>
 *    </p>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>UDP-Lite</td>
 *   <td>
 *    <p>
 *     An UDP-Lite implementation for the Linux kernel.<br>
 *     <a href="http://www.erg.abdn.ac.uk/users/gerrit/udp-lite/">
 *     http://www.erg.abdn.ac.uk/users/gerrit/udp-lite/</a>
 *    </p>
 *   </td>
 *  </tr>
 * </table>
 */


/**
 * \page features Library features
 *
 * <p>Unsupported features are in <span style="color: red;">red</span>.</p>
 * <p>Limitations are in <span style="color: orange;">orange</span>.</p>
 *
 * <p>See the <a href="https://answers.launchpad.net/rohc/+faq/1806">FAQ about compliance with IETF RFCs</a> for additional details.</p>
 *
 * <h2>Main features</h2>
 *
 * <ul>
 *  <li>ROHC compression</li>
 *  <li>ROHC decompression</li>
 *  <li>ROHC channels: small and large Channel IDs (CIDs)</li>
 *  <li>
 *    ROHC modes:
 *    <ul>
 *     <li>Unidirectional mode (U-mode)</li>
 *     <li>Bidirectional Optimistic mode (O-mode)</li>
 *     <li style="color: red;">Bidirectional Reliable mode (R-mode)</li>
 *    </ul>
 *  </li>
 *  <li>
 *   ROHC states:
 *   <ul>
 *    <li>Initialization & Refresh (IR)</li>
 *    <li>First Order (FO)</li>
 *    <li>Second Order (SO)</li>
 *   </ul>
 *  </li>
 *  <li>
 *   Feedback:
 *   <ul>
 *    <li>Feedback packets</li>
 *    <li>Piggy-backed feedbacks</li>
 *    <li>Negative ACKs</li>
 *   </ul>
 *  </li>
 *  <li>
 *   ROHC packets:
 *   <ul>
 *    <li>Feedback packets (RFC 3095, §5.2.1 and §5.2.2)</li>
 *    <li>
 *     IR packet (RFC 3095, §5.2.3)
 *     <ul>
 *      <li style="color: orange;">Optional dynamic part is always sent</li>
 *     </ul>
 *    </li>
 *    <li>IR-DYN packet (RFC 3095, §5.2.3)</li>
 *    <li>
 *     Packet type 0 (RFC 3095, §5.7.1)
 *     <ul>
 *      <li>UO-0</li>
 *      <li style="color: red;">R-0</li>
 *      <li style="color: red;">R-0-CRC</li>
 *     </ul>
 *    </li>
 *    <li style="color: red;">
 *     Packet type 1 for R-mode (RFC 3095, §5.7.2)
 *     <ul>
 *      <li style="color: red;">R-1</li>
 *      <li style="color: red;">R-1-TS</li>
 *      <li style="color: red;">R-1-ID</li>
 *     </ul>
 *    </li>
 *    <li>
 *     Packet type 1 for U/O-mode (RFC 3095, §5.7.3)
 *     <ul>
 *      <li>UO-1</li>
 *      <li>UO-1-ID</li>
 *      <li>UO-1-TS</li>
 *     </ul>
 *    </li>
 *    <li>
 *     Packet type 2 (RFC 3095, §5.7.4)
 *     <ul>
 *      <li>UOR-2</li>
 *     </ul>
 *    </li>
 *   </ul>
 *  </li>
 *  <li>Actions upon CRC failure (RFC 3095, §5.3.2.2.3, §5.3.2.2.4 and §5.3.2.2.5)</li>
 * </ul>
 *
 * <h2>ROHC profiles</h2>
 *
 * <ul>
 *  <li>Uncompressed (0x0000)</li>
 *  <li>RTP (0x0001)</li>
 *  <li>UDP (0x0002)</li>
 *  <li style="color: red;">ESP (0x0003)</li>
 *  <li>IP-only (0x0004)</li>
 *  <li style="color: red;">TCP (0x0006)</li>
 *  <li>UDP-Light (0x0008)</li>
 * </ul>
 *
 * <h2>Features shared by all supported profiles</h2>
 *
 * <ul>
 *  <li>Compression of up to two IPv4/IPv6 headers</li>
 *  <li style="color: red;">Compressed IPv4 Header Extension List (RFC 3095, §5.8.4.1 & §5.8.5.1)</li>
 *  <li>Compressed IPv6 Header Extension List (RFC 3095, §5.8.4.1 & §5.8.5.1)</li>
 *  <li>Authentication Header (AH) Compression (RFC 3095, §5.8.4.2)</li>
 *  <li style="color: red;">Encapsulating Security Payload Header (ESP) Compression (RFC 3095, §5.8.4.3)</li>
 *  <li style="color: red;">GRE Header Compression (RFC 3095, §5.8.4.4)</li>
 *  <li>Forced context reinitialization controled by the user</li>
 *  <li>Fixed sizes parameters in order to specify the size of ROHC packets</li>
 *  <li style="color: red;">Optional Reverse decompression (RFC 3095, §6.1)</li>
 *  <li style="color: red;">ROHC segmentation (RFC 3095, §5.2.5)</li>
 * </ul>
 *
 * <h2>Profile-specific features</h2>
 *
 * <table style="border-collapse: collapse; border: solid thin black;">
 *  <tr>
 *   <td>Uncompressed</td>
 *   <td>
 *    &nbsp;
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>RTP</td>
 *   <td>
 *    <ul>
 *     <li style="color: red;">Compressed CSRC List (RFC 3095, §5.8.5.2)</li>
 *     <li style="color: red;">Timer-based compression of RTP Timestamp (RFC 3095, §4.5.4)</li>
 *    </ul>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>UDP</td>
 *   <td>
 *    &nbsp;
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>IP-only</td>
 *   <td>
 *    <ul>
 *     <li style="color: red;">more than 2 IPv4/IPv6 headers</li>
 *    </ul>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>UDP-Lite</td>
 *   <td>
 *    <ul>
 *     <li>Checksum Coverage (CC) compression</li>
 *    </ul>
 *   </td>
 *  </tr>
 * </table>
 *
 * <h2>Encoding methods</h2>
 *
 * <ul>
 *  <li>Least Significant Bits (LSB) encoding (RFC 3095, §4.5.1)</li>
 *  <li>Window-based LSB (W-LSB) encoding (RFC 3095, §4.5.2)</li>
 *  <li>Scaled RTP Timestamp encoding (RFC 3095, §4.5.3)</li>
 *  <li style="color: red;">Timer-based compression of RTP Timestamp (RFC 3095, §4.5.4)</li>
 *  <li>Offset IP-ID encoding (RFC 3095, §4.5.5)</li>
 *  <li>Self-describing variable-length (SDVL) values (RFC 3095, §4.5.6)</li>
 *  <li>
 *   Encoded values across several fields in compressed headers (RFC 3095, §4.5.7)
 *   <ul>
 *    <li style="color: orange;">Not fully respected: if more bits than stricly necessary are available, more bits are sent</li>
 *   </ul>
 *  </li>
 * </ul>
 *
 * <h2>Non-standard ROHC enhancements</h2>
 *
 * <ul>
 *  <li>
 *   Use of encapsulation padding for sending larger packets</li>
 *   <ul>
 *    <li style="color: orange;">Padding not used with Compressed IPv6 Header Extension List</li>
 *   </ul>
 *  </li>
 *  <li>Optional simplification of UOR-2-TS / UOR-2-ID packets to help distinguish them at decompressor</li>
 * </ul>
 */


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
 * Possible values are: ROHC_LARGE_CID, ROHC_SMALL_CID.
 * Small CID means CID in the \f$[0-ROHC_SMALL_CID_MAX]\f$ interval.
 * Large CID means CID in the \f$[0-ROHC_LARGE_CID_MAX]\f$ interval.
 */
typedef enum
{
	/**
	 * @brief The context uses large CID
	 * Value in the \f$[0-ROHC_LARGE_CID_MAX]\f$ interval.
	 */
	ROHC_LARGE_CID,
	/**
	 * @brief The context uses small CID
	 * Value in the \f$[0-ROHC_SMALL_CID_MAX]\f$ interval.
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

/// The number allocated for the ROHC Uncompressed profile
#define ROHC_PROFILE_UNCOMPRESSED  0x0000
/// The number allocated for the ROHC RTP profile
#define ROHC_PROFILE_RTP           0x0001
/// The number allocated for the ROHC UDP profile
#define ROHC_PROFILE_UDP           0x0002
/// The number allocated for the ROHC IP-only profile (see 5 in the RFC 3843)
#define ROHC_PROFILE_IP            0x0004
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
 * TODO API: define constants as private and move in crc.h or even crc.c
 * TODO API: use an enum instead of constants
 */

/** The CRC-2 type */
#define CRC_TYPE_2 1
/** The CRC-3 type */
#define CRC_TYPE_3 2
/** The CRC-6 type */
#define CRC_TYPE_6 3
/** The CRC-7 type */
#define CRC_TYPE_7 4
/** The CRC-8 type */
#define CRC_TYPE_8 5


/* TODO API: remove these variables once compatibility is not needed anymore */

/** The table to enable fast CRC-2 computation
 * @deprecated please do not use this variable anymore */
extern unsigned char crc_table_2[256]
	__attribute__((deprecated));

/** The table to enable fast CRC-3 computation
 * @deprecated please do not use this variable anymore */
extern unsigned char crc_table_3[256]
	__attribute__((deprecated));

/** The table to enable fast CRC-6 computation
 * @deprecated please do not use this variable anymore */
extern unsigned char crc_table_6[256]
	__attribute__((deprecated));

/** The table to enable fast CRC-7 computation
 * @deprecated please do not use this variable anymore */
extern unsigned char crc_table_7[256]
	__attribute__((deprecated));

/** The table to enable fast CRC-8 computation
 * @deprecated please do not use this variable anymore */
extern unsigned char crc_table_8[256]
	__attribute__((deprecated));


/*
 * Prototypes of public up-to-date functions
 */

char * rohc_version(void);

const char * rohc_get_mode_descr(const rohc_mode mode);


/*
 * Prototypes of public deprecated functions
 */

/* TODO API: define as private and move in crc.h */
int crc_get_polynom(int type)
	__attribute__((deprecated));

/* TODO API: define as private and move in crc.h */
void crc_init_table(unsigned char *table, unsigned char polynum)
	__attribute__((deprecated));

#endif

