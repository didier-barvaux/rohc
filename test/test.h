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
 * @file test.h
 * @brief ROHC test program
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <net/ethernet.h>
#include <math.h>

/* include for the PCAP library */
#include <pcap.h>

/* ROHC includes */
#include "rohc.h"
#include "rohc_comp.h"
#include "rohc_decomp.h"


/// The program version
#define TEST_VERSION  	"ROHC test application, version 0.1\n"

/// The program usage
#define TEST_USAGE \
"ROHC test application: test the ROHC library with a flow of IP packets\n\n\
usage: test [-h] [-v] [-o output_file] [-c cmp_file] flow\n\
  -v              print version information and exit\n\
  -h              print this usage and exit\n\
  -o output_file  save the generated ROHC packets in output_file (PCAP format)\n\
  -c cmp_file     compare the generated ROHC packets with the ROHC packets\n\
                  stored in cmp_file (PCAP format)\n\
  flow            flow of Ethernet frames to compress (PCAP format)\n"


/// The maximal size for the ROHC packets
#define MAX_ROHC_SIZE	(5 * 1024)

/// The length of the Linux Cooked Sockets header
#define LINUX_COOKED_HDR_LEN  16

