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
 * @file   test_context_reuse.c
 * @brief  Check that contexts are re-used correctly
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application compresses IP packets from a source PCAP file with a single
 * compression context. It then decompresses them. All (de)compression must
 * succeed.
 */

#include "test.h"
#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#if HAVE_NET_ETHERNET_H == 1
#  include <net/ethernet.h>
#else
#  include "net_ethernet.h" /* use an internal definition for compatibility */
#endif
#if HAVE_NETINET_IP_H == 1
#  include <netinet/ip.h>
#else
#  include <netinet_ip.h>  /* use an internal definition for compatibility */
#endif
#if HAVE_NETINET_IP6_H == 1
#  include <netinet/ip6.h>
#else
#  include <netinet_ip6.h>  /* use an internal definition for compatibility */
#endif
#include <errno.h>
#include <assert.h>
#include <time.h> /* for time(2) */

/* include for the PCAP library */
#include <pcap/pcap.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(const char *filename);
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));


/**
 * @brief Check that the compression of the IP packets read in the capture
 *        are possible with only one single context.
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	char *filename = NULL;
	int args_read;
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 1)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc -= args_read, argv += args_read)
	{
		if(!strcmp(*argv, "-h"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(filename == NULL)
		{
			/* get the name of the file that contains the packets to decompress */
			filename = argv[0];
			args_read = 1;
		}
		else
		{
			/* do not accept more than two arguments without option name */
			usage();
			goto error;
		}
	}

	/* the source filename and the ACK type are mandatory */
	if(filename == NULL)
	{
		usage();
		goto error;
	}

	/* test ROHC compression with the packets from the file */
	status = test_comp_and_decomp(filename);

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that contexts are re-used as expected\n"
	        "\n"
	        "usage: test_context_reuse [OPTIONS] FLOW\n"
	        "\n"
	        "with:\n"
	        "  FLOW         The flow of Ethernet frames to compress\n"
	        "               (in PCAP format)\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with a flow of IP packets that shall
 *        re-use the same context
 *
 * @param filename             The name of the PCAP file that contains the
 *                             IP packets
 * @return                     0 in case of success,
 *                             1 in case of failure
 */
static int test_comp_and_decomp(const char *filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_comp *comp;
	struct rohc_decomp *decomp;

	struct pcap_pkthdr header;
	unsigned char *packet;
	unsigned int counter;

	int is_failure = 1;

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
		fprintf(stderr, "link layer type %d not supported in source dump "
		        "(supported = %d, %d, %d)\n", link_layer_type,
		        DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW);
		goto close_input;
	}

	/* determine the length of the link layer header */
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

	/* initialize the random generator */
	srand(time(NULL));

	/* create the ROHC compressor with small CID */
	comp = rohc_alloc_compressor(0 /* only one context */, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto close_input;
	}
	rohc_activate_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(comp, ROHC_PROFILE_UDP);
	rohc_activate_profile(comp, ROHC_PROFILE_IP);
	rohc_activate_profile(comp, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(comp, ROHC_PROFILE_RTP);
	rohc_activate_profile(comp, ROHC_PROFILE_ESP);
	rohc_c_set_large_cid(comp, 0);

	/* set the callback for random numbers */
	if(!rohc_comp_set_random_cb(comp, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto destroy_comp;
	}

	/* create the ROHC decompressor in bi-directional mode */
	decomp = rohc_alloc_decompressor(comp);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* for each packet in the dump */
	counter = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		unsigned char *ip_packet;
		int ip_size;
		static unsigned char rohc_packet[MAX_ROHC_SIZE];
		int rohc_size;
		static unsigned char decomp_packet[MAX_ROHC_SIZE];
		int decomp_size;

		counter++;

		fprintf(stderr, "packet #%u:\n", counter);

		/* check the length of the link layer header/frame */
		if(header.len <= link_len || header.len != header.caplen)
		{
			fprintf(stderr, "\ttruncated packet in capture (len = %d, "
			        "caplen = %d)\n", header.len, header.caplen);
			goto destroy_decomp;
		}

		/* skip the link layer header */
		ip_packet = packet + link_len;
		ip_size = header.len - link_len;

		/* check for padding after the IP packet in the Ethernet payload */
		if(link_len == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
		{
			int version;
			int tot_len;

			version = (ip_packet[0] >> 4) & 0x0f;

			if(version == 4)
			{
				struct iphdr *ip = (struct iphdr *) ip_packet;
				tot_len = ntohs(ip->tot_len);
			}
			else
			{
				struct ip6_hdr *ip = (struct ip6_hdr *) ip_packet;
				tot_len = sizeof(struct ip6_hdr) + ntohs(ip->ip6_plen);
			}

			if(tot_len < ip_size)
			{
				fprintf(stderr, "the Ethernet frame has %d bytes of padding "
				        "after the %d byte IP packet!\n", ip_size - tot_len,
				        tot_len);
				ip_size = tot_len;
			}
		}

		/* compress the IP packet */
		rohc_size = rohc_compress(comp, ip_packet, ip_size,
		                          rohc_packet, MAX_ROHC_SIZE);
		if(rohc_size <= 0)
		{
			fprintf(stderr, "\tfailed to compress IP packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tcompression is successful\n");

		/* decompress the ROHC packet with the ROHC decompressor */
		decomp_size = rohc_decompress(decomp,
		                              rohc_packet, rohc_size,
		                              decomp_packet, MAX_ROHC_SIZE);
		if(decomp_size <= 0)
		{
			fprintf(stderr, "\tfailed to decompress ROHC packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tdecompression is successful\n");
	}

	/* everything went fine */
	is_failure = 0;

destroy_decomp:
	rohc_free_decompressor(decomp);
destroy_comp:
	rohc_free_compressor(comp);
close_input:
	pcap_close(handle);
error:
	return is_failure;
}


/**
 * @brief Generate a random number
 *
 * @param comp          The ROHC compressor
 * @param user_context  Should always be NULL
 * @return              A random number
 */
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
{
	assert(comp != NULL);
	assert(user_context == NULL);
	return rand();
}

