/**
 * @file test.h
 * @brief ROHC test program
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <net/ethernet.h>

/* include for the PCAP library */
#include <pcap.h>

/* ROHC includes */
#include "rohc.h"
#include "rohc_comp.h"
#include "rohc_decomp.h"


/// The program version
#define VERSION  	"ROHC test application, version 0.1\n"

/// The program usage
#define USAGE \
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


/// A simple maximum macro
#define max(x, y) \
	(((x) > (y)) ? (x) : (y))


/*
 * Function prototypes:
 */

void test_comp_and_decomp(char *src_filename,
                          char *ofilename,
                          char *cmp_filename);

