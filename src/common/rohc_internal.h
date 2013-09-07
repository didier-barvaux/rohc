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
 * @file rohc_internal.h
 * @brief ROHC private common definitions and routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#ifndef ROHC_INTERNAL_H
#define ROHC_INTERNAL_H

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
 *   <li>Project page on Launchpad: <a href="https://launchpad.net/rohc">
 *                          https://launchpad.net/rohc</a></li>
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

#include "rohc.h"


/**
 * @brief ROHC medium (CID characteristics)
 */
struct medium
{
	/** The CID type: large or small */
	rohc_cid_type_t cid_type;

	/// The maximum CID value
	int max_cid;
};


#endif

