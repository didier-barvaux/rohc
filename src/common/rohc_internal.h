/*
 * Copyright 2013 Didier Barvaux
 * Copyright 2017 Viveris Technologies
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
 * @file rohc_internal.h
 * @brief ROHC private common definitions and routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_INTERNAL_H
#define ROHC_INTERNAL_H

#include <stdint.h>

/**
 * \mainpage
 *
 * <h2>Introduction</h2>
 * <p>The <a href="https://rohc-lib.org/" title="Official website">ROHC library</a>
 * provides an easy and robust way for applications to reduce their bandwidth
 * usage on network links with limited capacity.  Headers of network packets are
 * compressed with the ROHC protocol and algorithms.</p>
 * <p><a href="https://rohc-lib.org/support/wiki/doku.php?id=rohc-protocol"
 * title="An introduction to the ROHC protocol">RObust Header Compression
 * (ROHC)</a> is a set of standards defined by the <a href="http://www.ietf.org/"
 * title="The IETF website">IETF</a>. The ROHC library is a free, opensource and
 * efficient implementation of them.
 * <a href="https://rohc-lib.org/support/wiki/doku.php?id=library-compliance-rfcs">Many
 * features</a>are implemented.</p>
 * <ul>
 *   <li><a href="https://rohc-lib.org/">Official website</a></li>
 *   <li><a href="https://github.com/didier-barvaux/rohc">Project page on
 *          GitHub</a></li>
 *   <li><a href="https://launchpad.net/rohc">Project page on Launchpad</a></li>
 *   <li><a href="mailto:rohc@lists.launchpad.net">Mailing list:
 *          rohc@lists.launchpad.net</a></li>
 *   <li><a href="https://lists.launchpad.net/rohc/">Mailing list archives</a></li>
 *   <li><a href="https://bugs.launchpad.net/rohc">Bugtracker</a></li>
 * </ul>
 *
 * <h2>License</h2>
 * <p>The project is licensed under LGPL2.1+.
 * See the <a href="https://github.com/didier-barvaux/rohc/blob/master/COPYING">COPYING</a>
 * and <a href="https://github.com/didier-barvaux/rohc/blob/master/AUTHORS.md">AUTHORS.md</a>
 * files for more details.</p>
 *
 * <h2>Library</h2>
 * <p>
 * The sources are in the src subdirectory. The sources are separated into
 * three sub-directories:
 *  <ul>
 *   <li>the common/ sub-directory contains the routines used for both the
 *       compression and the decompression processes,</li>
 *   <li>the comp/ sub-directory handles the compression process,</li>
 *   <li>the decomp/ sub-directory handles the decompression process.</li>
 *  </ul>
 * </p>
 * <p>See the <a href="https://github.com/didier-barvaux/rohc/blob/master/INSTALL.md">INSTALL.md file</a>
 * to learn to build the libraries. See also the <a href="https://rohc-lib.org/support/wiki/">Wiki
 * of the project</a>.</p>
 *
 * <h2>API documentation, tutorials and examples</h2>
 * <p>The APIs for ROHC common, compression and decompression parts are available on
 * separate pages:
 *  <ul>
 *    <li>\ref rohc</li>
 *    <li>\ref rohc_comp</li>
 *    <li>\ref rohc_decomp</li>
 *  </ul>
 * </p>
 * <p><a href="https://rohc-lib.org/presentation/getting-started/">Some</a>
 * <a href="https://rohc-lib.org/support/wiki/doku.php?id=library-first-application">tutorials</a>
 * are available on the website and wiki.</p>
 * <p><a href="https://github.com/didier-barvaux/rohc/tree/master/examples">Some examples</a>
 * are available in the examples/ sub-directory in the sources.</p>
 *
 * <h2>Tests</h2>
 * <p>
 * Several tests may be run to check the library behaviour. See the
 * <a href="https://github.com/didier-barvaux/rohc/blob/master/INSTALL.md">INSTALL.md file</a>
 * to learn how to use these tools.</p>
 *
 * <h2>References</h2>
 * <dl style="padding-bottom: 1em;">
 *  <dt><a href="https://tools.ietf.org/html/rfc3095">RFC&nbsp;3095</a></dt>
 *  <dd>ROHC: Framework and four profiles: RTP, UDP, ESP, and uncompressed.</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc3096">RFC&nbsp;3096</a></dt>
 *  <dd>Requirements for robust IP/UDP/RTP header compression.</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc3241">RFC&nbsp;3241</a></dt>
 *  <dd>ROHC over PPP</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc3242">RFC&nbsp;3242</a></dt>
 *  <dd>ROHC: A Link-Layer Assisted Profile for IP/UDP/RTP</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc3243">RFC&nbsp;3243</a></dt>
 *  <dd>ROHC: Requirements and Assumptions for 0-byte IP/UDP/RTP Compression</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc3408">RFC&nbsp;3408</a></dt>
 *  <dd>ROHC: Zero-byte Support for R-mode in Extended Link-Layer Assisted ROHC Profile</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc3409">RFC&nbsp;3409</a></dt>
 *  <dd>ROHC: Lower Layer Guidelines for Robust RTP/UDP/IP Header Compression</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc3759">RFC&nbsp;3759</a></dt>
 *  <dd>ROHC: Terminology and Channel Mapping Examples</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc3816">RFC&nbsp;3816</a></dt>
 *  <dd>ROHC: Definitions of Managed Objects (SNMP MIB) for ROHC</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc3828">RFC&nbsp;3828</a></dt>
 *  <dd>The Lightweight User Datagram Protocol (UDP-Lite)</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc3843">RFC&nbsp;3843</a></dt>
 *  <dd>ROHC: A Compression Profile for IP.</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc4019">RFC&nbsp;4019</a></dt>
 *  <dd>ROHC: Profiles for User Datagram Protocol (UDP) Lite.</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc4163">RFC&nbsp;4163</a></dt>
 *  <dd>ROHC: Requirements on TCP/IP Header Compression</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc4224">RFC&nbsp;4224</a></dt>
 *  <dd>ROHC over Channels That Can Reorder Packets</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc4362">RFC&nbsp;4362</a></dt>
 *  <dd>ROHC: A Link-Layer Assisted Profile for IP/UDP/RTP</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc4995">RFC&nbsp;4995</a></dt>
 *  <dd>The RObust Header Compression (ROHC) Framework</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc4996">RFC&nbsp;4996</a></dt>
 *  <dd>ROHC: A Profile for TCP/IP (ROHC-TCP)</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc4997">RFC&nbsp;4997</a></dt>
 *  <dd>Formal Notation for RObust Header Compression (ROHC-FN)</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc5225">RFC&nbsp;5225</a></dt>
 *  <dd>ROHCv2: Profiles for RTP, UDP, IP, ESP and UDP-Lite</dt>
 *  <dt><a href="https://tools.ietf.org/html/rfc5795">RFC&nbsp;5795</a></dt>
 *  <dd>The RObust Header Compression (ROHC) Framework</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc5856">RFC&nbsp;5856</a></dt>
 *  <dd>ROHC: Integration of ROHC over IPsec Security Associations</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc5857">RFC&nbsp;5857</a></dt>
 *  <dd>ROHC: IKEv2 Extensions to Support ROHC over IPsec</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc5858">RFC&nbsp;5858</a></dt>
 *  <dd>ROHC: IPsec Extensions to Support ROHC over IPsec</dd>
 *  <dt><a href="https://tools.ietf.org/html/rfc6846">RFC&nbsp;6846</a></dt>
 *  <dd>ROHC: A Profile for TCP/IP (ROHC-TCP)</dd>
 *  <dt><a href="https://rohc-lib.org/">ROHC library</a></dt>
 *  <dd>The Open Source ROHC library described by the documentation you are
 *      currently reading.</dd>
 *  <dt><a href="http://rohc.sourceforge.net/">ROHC Linux</a></dt>
 *  <dd>A GPL-licensed implementation of ROHC over PPP for the 2.4 Linux kernel.
 *      The ROHC library started as a fork of this project.</dd>
 * </dl>
 */


#include "rohc.h"


/** The maximal value for MRRU */
#define ROHC_MAX_MRRU 65535


/**
 * @brief The padding field defined by the ROHC protocol
 *
 * See RFC 3095, §5.2:
 * \verbatim

   Padding Octet

     0   1   2   3   4   5   6   7
   +---+---+---+---+---+---+---+---+
   | 1   1   1   0   0   0   0   0 |
   +---+---+---+---+---+---+---+---+

\endverbatim
 */
#define ROHC_PADDING_BYTE  0xe0


/**
 * @brief A number of bits required or retrieved
 */
typedef uint8_t bits_nr_t;


/**
 * @brief ROHC medium (CID characteristics)
 */
struct rohc_medium
{
	/** The CID type: large or small */
	rohc_cid_type_t cid_type;

	/// The maximum CID value
	rohc_cid_t max_cid;
};


/**
 * @brief The different chains used by the ROHCv1 TCP and ROHCv2 profiles
 */
typedef enum
{
	ROHC_CHAIN_STATIC    = 0,  /**< The TCP static chain */
	ROHC_CHAIN_DYNAMIC   = 1,  /**< The TCP dynamic chain */
	ROHC_CHAIN_REPLICATE = 2,  /**< The TCP replicate chain */
	ROHC_CHAIN_IRREGULAR = 3,  /**< The TCP irregular chain */
	ROHC_CHAIN_CO        = 4,  /**< Not a chain, but in CO packet */

} rohc_chain_t;


/** The different IP-ID behaviors */
typedef enum
{
	ROHC_IP_ID_BEHAVIOR_SEQ       = 0, /**< IP-ID increases */
	ROHC_IP_ID_BEHAVIOR_SEQ_SWAP  = 1, /**< IP-ID increases in little endian */
	ROHC_IP_ID_BEHAVIOR_RAND      = 2, /**< IP-ID is random */
	ROHC_IP_ID_BEHAVIOR_ZERO      = 3, /**< IP-ID is constant zero */
} rohc_ip_id_behavior_t;



/************************************************************************
 * Helper functions                                                     *
 ************************************************************************/

static inline char * rohc_ip_id_behavior_get_descr(const rohc_ip_id_behavior_t behavior)
	__attribute__((warn_unused_result, const));


/**
 * @brief Get a string that describes the given IP-ID behavior
 *
 * @param behavior  The type of the option to get a description for
 * @return          The description of the option
 */
static inline char * rohc_ip_id_behavior_get_descr(const rohc_ip_id_behavior_t behavior)
{
	switch(behavior)
	{
		case ROHC_IP_ID_BEHAVIOR_SEQ:
			return "sequential";
		case ROHC_IP_ID_BEHAVIOR_SEQ_SWAP:
			return "sequential swapped";
		case ROHC_IP_ID_BEHAVIOR_RAND:
			return "random";
		case ROHC_IP_ID_BEHAVIOR_ZERO:
			return "constant zero";
		default:
			return "unknown IP-ID behavior";
	}
}


#endif

