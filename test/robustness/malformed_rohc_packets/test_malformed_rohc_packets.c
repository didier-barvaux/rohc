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
 * @file   test_malformed_rohc_packets.c
 * @brief  Test the decompression of malformed ROHC packets
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "config.h" /* for HAVE_*_H */
#include "test.h"

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

/* include for the PCAP library */
#if HAVE_PCAP_PCAP_H == 1
#  include <pcap/pcap.h>
#elif HAVE_PCAP_H == 1
#  include <pcap.h>
#else
#  error "pcap.h header not found, did you specified --enable-rohc-tests \
for ./configure ? If yes, check configure output and config.log"
#endif

/* ROHC includes */
#include <rohc.h>
#include <rohc_decomp.h>


/* prototypes of private functions */
static void usage(void);
static int test_decomp(const char *const filename);


/**
 * @brief Main function for the ROHC test program
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure,
 *              \li 77 in case test is skipped
 */
int main(int argc, char *argv[])
{
	char *filename = NULL;
	int status = 1;
	int args_used;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 1)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc -= args_used, argv += args_used)
	{
		args_used = 1;

		if(!strcmp(*argv, "-h"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(filename == NULL)
		{
			/* get the name of the file that contains the packets to
			 * decompress */
			filename = argv[0];
		}
		else
		{
			/* do not accept more than one filename without option name */
			usage();
			goto error;
		}
	}

	/* the source filename is mandatory */
	if(filename == NULL)
	{
		usage();
		goto error;
	}

	/* test ROHC decompression with the packets from the file */
	status = test_decomp(filename);

error:
	return status;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	fprintf(stderr,
	        "ROHC decompression tool: test the ROHC library with a flow\n"
	        "                         of malformed ROHC packets\n"
	        "\n"
	        "usage: test_malformed_rohc_packets FLOW\n");
}


/**
 * @brief Test the ROHC library with a flow of ROHC packets
 *
 * @param filename  The name of the PCAP file that contains the ROHC packets
 * @return          0 in case of success,
 *                  1 in case of failure
 */
static int test_decomp(const char *const filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;
	struct pcap_pkthdr header;
	unsigned char *packet;
	struct rohc_decomp *decomp;
	unsigned int counter;
	int status = 1;

	/* open the source dump file */
	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "failed to open the source pcap file: %s\n", errbuf);
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type = pcap_datalink(handle);
	if(link_layer_type != DLT_EN10MB &&
	   link_layer_type != DLT_LINUX_SLL &&
	   link_layer_type != DLT_RAW)
	{
		fprintf(stderr, "link layer type %d not supported in source dump (supported = "
		       "%d, %d, %d)\n", link_layer_type, DLT_EN10MB, DLT_LINUX_SLL,
		       DLT_RAW);
		goto close_input;
	}

	if(link_layer_type == DLT_EN10MB)
	{
		link_len = ETHER_HDR_LEN;
	}
	else if(link_layer_type == DLT_LINUX_SLL)
	{
		link_len = LINUX_COOKED_HDR_LEN;
	}
	else /* DLT_RAW */
	{
		link_len = 0;
	}

	/* create the decompressor */
	decomp = rohc_alloc_decompressor(NULL);
	if(decomp == NULL)
	{
		fprintf(stderr, "cannot create the decompressor\n");
		goto close_input;
	}

	/* set CID type and MAX_CID for decompressor 1 */
	if(!rohc_decomp_set_cid_type(decomp, ROHC_SMALL_CID))
	{
		fprintf(stderr, "failed to set CID type to small CIDs for "
		        "decompressor\n");
		goto destroy_decomp;
	}
	if(!rohc_decomp_set_max_cid(decomp, ROHC_SMALL_CID_MAX))
	{
		fprintf(stderr, "failed to set MAX_CID to %d for "
		        "decompressor\n", ROHC_SMALL_CID_MAX);
		goto destroy_decomp;
	}

	/* for each packet in the dump */
	counter = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		unsigned char *rohc_packet;
		int rohc_size;
		static unsigned char ip_packet[MAX_ROHC_SIZE];
		int ip_size;

		counter++;

		/* check Ethernet frame length */
		if(header.len < link_len || header.len != header.caplen)
		{
			fprintf(stderr, "bad PCAP packet (len = %d, caplen = %d)\n",
			       header.len, header.caplen);
			goto destroy_decomp;
		}

		rohc_packet = packet + link_len;
		rohc_size = header.len - link_len;

		fprintf(stderr, "decompress malformed packet #%u:\n", counter);

		/* decompress the ROHC packet */
		ip_size = rohc_decompress(decomp,
		                          rohc_packet, rohc_size,
		                          ip_packet, MAX_ROHC_SIZE);
		if(ip_size > 0)
		{
			fprintf(stderr, "unexpected successful decompression\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\texpected decompression failure\n");
	}

	status = 0;

destroy_decomp:
	rohc_free_decompressor(decomp);
close_input:
	pcap_close(handle);
error:
	return status;
}

