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
 * @file   test_lost_packet.c
 * @brief  Check that lost ROHC packets are handled correctly
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application compresses IP packets from a source PCAP file, then
 * decompresses them after losing one of them. All IP packets should be
 * correctly compressed. All generated ROHC packets should be correctly
 * decompressed except the lost one.
 */

#include "test.h"
#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif
#include <errno.h>
#include <assert.h>
#include <stdarg.h>

/* includes for network headers */
#include <protocols/ipv4.h>
#include <protocols/ipv6.h>

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
#include <rohc_comp.h>
#include <rohc_decomp.h>


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(const char *const filename,
                                const bool do_repair,
                                const unsigned int first_packet_to_lose,
                                const unsigned int last_packet_to_lose,
                                const unsigned int last_packet_in_error);
static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));


/**
 * @brief Check that lost ROHC packets are handled correctly
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
	char *first_packet_to_lose_param = NULL;
	char *last_packet_to_lose_param = NULL;
	char *last_packet_in_error_param = NULL;
	int first_packet_to_lose;
	int last_packet_to_lose;
	int last_packet_in_error;
	bool do_repair = false;
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 2)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc--, argv++)
	{
		if(!strcmp(*argv, "-h"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(!strcmp(*argv, "--repair"))
		{
			do_repair = true;
		}
		else if(filename == NULL)
		{
			/* get the name of the file that contains the packets to
			 * compress/decompress */
			filename = argv[0];
		}
		else if(first_packet_to_lose_param == NULL)
		{
			/* get the first ROHC packet to lose */
			first_packet_to_lose_param = argv[0];
		}
		else if(last_packet_to_lose_param == NULL)
		{
			/* get the last ROHC packet to lose */
			last_packet_to_lose_param = argv[0];
		}
		else if(last_packet_in_error_param == NULL)
		{
			/* get the last ROHC packet that will fail to decompress */
			last_packet_in_error_param = argv[0];
		}
		else
		{
			/* do not accept more than two arguments without option name */
			usage();
			goto error;
		}
	}

	/* check mandatory parameters */
	if(filename == NULL ||
	   first_packet_to_lose_param == NULL ||
	   last_packet_to_lose_param == NULL ||
	   last_packet_in_error_param == NULL)
	{
		usage();
		goto error;
	}

	/* parse the first packet to lose */
	first_packet_to_lose = atoi(first_packet_to_lose_param);
	if(first_packet_to_lose <= 0)
	{
		fprintf(stderr, "bad number for the first packet to lose '%s'\n\n",
		        first_packet_to_lose_param);
		usage();
		goto error;
	}

	/* parse the last packet to lose */
	last_packet_to_lose = atoi(last_packet_to_lose_param);
	if(last_packet_to_lose <= 0)
	{
		fprintf(stderr, "bad number for the last packet to lose '%s'\n\n",
		        last_packet_to_lose_param);
		usage();
		goto error;
	}

	/* parse the last packet to will failed to decompress */
	last_packet_in_error = atoi(last_packet_in_error_param);
	if(last_packet_in_error <= 0)
	{
		fprintf(stderr, "bad number for the last packet that will fail to "
		        "decompress '%s'\n\n", last_packet_in_error_param);
		usage();
		goto error;
	}

	/* init the random system with a constant value for the test to be fully
	   reproductible */
	srand(5);

	/* test ROHC compression/decompression with the packets from the file */
	status = test_comp_and_decomp(filename, do_repair, first_packet_to_lose,
	                              last_packet_to_lose, last_packet_in_error);

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that lost ROHC packets are correctly handled\n"
	        "\n"
	        "usage: test_lost_packet [OPTIONS] FLOW FIRST_PACKET_NUM \\\n"
	        "                        LAST_PACKET_NUM LAST_PACKET_ERROR\n"
	        "\n"
	        "with:\n"
	        "  FLOW               The flow of Ethernet frames to (de)compress\n"
	        "                     (in PCAP format)\n"
	        "  FIRST_PACKET_NUM   The first packet # to lose\n"
	        "  LAST_PACKET_NUM    The last packet # to lose\n"
	        "  LAST_PACKET_ERROR  The last packet # that will fail to decompress\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n"
	        "  --repair     Repair packet/context\n");
}


/**
 * @brief Test the ROHC library with a flow of IP packets going through one
 *        compressor then one decompressor
 *
 * @param filename              The name of the PCAP file that contains the
 *                              IP packets
 * @param do_repair             Repair the packet/context
 * @param first_packet_to_lose  The first packet # to lost
 * @param last_packet_to_lose   The last packet # to lost
 * @param last_packet_in_error  The last packet # that will fail to decompress
 * @return                      0 in case of success,
 *                              1 in case of failure
 */
static int test_comp_and_decomp(const char *const filename,
                                const bool do_repair,
                                const unsigned int first_packet_to_lose,
                                const unsigned int last_packet_to_lose,
                                const unsigned int last_packet_in_error)
{
	struct timespec arrival_time = { .tv_sec = 4242, .tv_nsec = 4242 };

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_comp *comp;
	struct rohc_decomp *decomp;

	struct pcap_pkthdr header;
	unsigned char *packet;
	unsigned int counter;

#define NB_RTP_PORTS 5
	unsigned int rtp_ports[NB_RTP_PORTS] =
		{ 1234, 36780, 33238, 5020, 5002 };
	int i;

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
	   link_layer_type != DLT_RAW &&
	   link_layer_type != DLT_NULL)
	{
		fprintf(stderr, "link layer type %d not supported in source dump "
		        "(supported = %d, %d, %d, %d)\n", link_layer_type,
		        DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW, DLT_NULL);
		goto close_input;
	}

	/* determine the length of the link layer header */
	if(link_layer_type == DLT_EN10MB)
		link_len = ETHER_HDR_LEN;
	else if(link_layer_type == DLT_LINUX_SLL)
		link_len = LINUX_COOKED_HDR_LEN;
	else if(link_layer_type == DLT_NULL)
		link_len = BSD_LOOPBACK_HDR_LEN;
	else /* DLT_RAW */
		link_len = 0;

	/* create the ROHC compressor with small CID */
	comp = rohc_alloc_compressor(ROHC_SMALL_CID_MAX, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto close_input;
	}

	/* set the callback for traces on compressor */
	if(!rohc_comp_set_traces_cb(comp, print_rohc_traces))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "compressor\n");
		goto destroy_comp;
	}

	/* enable profiles */
	if(!rohc_comp_enable_profiles(comp, ROHC_PROFILE_UNCOMPRESSED,
	                              ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                              ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                              ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles\n");
		goto destroy_comp;
	}
	rohc_c_set_large_cid(comp, 0);

	/* set the callback for random numbers on compressor A */
	if(!rohc_comp_set_random_cb(comp, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto destroy_comp;
	}

	if(!do_repair)
	{
		/* set the default timeouts for periodic refreshes of contexts */
		if(!rohc_comp_set_periodic_refreshes(comp, 121, 120))
		{
			fprintf(stderr, "failed to set timeouts for periodic refreshes\n");
			goto destroy_comp;
		}
	}

	/* reset list of RTP ports */
	if(!rohc_comp_reset_rtp_ports(comp))
	{
		fprintf(stderr, "failed to reset list of RTP ports\n");
		goto destroy_comp;
	}

	/* add some ports to the list of RTP ports */
	for(i = 0; i < NB_RTP_PORTS; i++)
	{
		if(!rohc_comp_add_rtp_port(comp, rtp_ports[i]))
		{
			fprintf(stderr, "failed to enable RTP port %u\n", rtp_ports[i]);
			goto destroy_comp;
		}
	}

	/* create the ROHC decompressor in unidirectional mode */
	decomp = rohc_alloc_decompressor(NULL);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb(decomp, print_rohc_traces))
	{
		fprintf(stderr, "cannot set trace callback for decompressor\n");
		goto destroy_decomp;
	}

	/* enable decompression profiles */
	if(!rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_UNCOMPRESSED,
	                                ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                                ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                                ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the decompression profiles\n");
		goto destroy_decomp;
	}

	if(do_repair)
	{
		/* enable some features: CRC repair */
		if(!rohc_decomp_set_features(decomp, ROHC_DECOMP_FEATURE_CRC_REPAIR))
		{
			fprintf(stderr, "failed to enabled CRC repair\n");
			goto destroy_decomp;
		}
	}

	/* for each packet in the dump */
	counter = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		unsigned char *ip_packet;
		size_t ip_size;
		static unsigned char rohc_packet[MAX_ROHC_SIZE];
		size_t rohc_size;
		static unsigned char decomp_packet[MAX_ROHC_SIZE];
		size_t decomp_size;
		int ret;

		counter++;
		arrival_time.tv_nsec += 20 * 1e6; /* 20ms between consecutive packets */

		/* avoid overflow of tv_nsec */
		arrival_time.tv_sec += arrival_time.tv_nsec / (unsigned long) 1e9;
		arrival_time.tv_nsec %= (unsigned long) 1e9;

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
			uint8_t version;
			uint16_t tot_len;

			/* get IP version */
			version = (ip_packet[0] >> 4) & 0x0f;

			/* get IP total length depending on IP version */
			if(version == 4)
			{
				const struct ipv4_hdr *const ip = (struct ipv4_hdr *) ip_packet;
				tot_len = ntohs(ip->tot_len);
			}
			else
			{
				const struct ipv6_hdr *const ip = (struct ipv6_hdr *) ip_packet;
				tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->ip6_plen);
			}

			/* determine if there is Ethernet padding after IP packet */
			if(tot_len < ip_size)
			{
				/* there is Ethernet padding, ignore these bits because there are
				 * not part of the IP packet */
				ip_size = tot_len;
			}
		}
		fprintf(stderr, "\tpacket is valid\n");

		/* compress the IP packet with the ROHC compressor */
		ret = rohc_compress3(comp, arrival_time, ip_packet, ip_size,
		                     rohc_packet, MAX_ROHC_SIZE, &rohc_size);
		if(ret != ROHC_OK)
		{
			fprintf(stderr, "\tfailed to compress IP packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tcompression is successful\n");

		/* is it the packet to lose? */
		if(counter >= first_packet_to_lose && counter <= last_packet_to_lose)
		{
			fprintf(stderr, "\tvoluntary lose packet #%d\n", counter);
			continue;
		}

		/* decompress the generated ROHC packet with the ROHC decompressor */
		ret = rohc_decompress2(decomp, arrival_time, rohc_packet, rohc_size,
		                       decomp_packet, MAX_ROHC_SIZE, &decomp_size);
		if(ret != ROHC_OK)
		{
			if(counter > last_packet_to_lose && counter <= last_packet_in_error)
			{
				/* failure is expected */
				fprintf(stderr, "\texpected failure to decompress generated "
				        "ROHC packet\n");
			}
			else
			{
				/* failure is NOT expected */
				fprintf(stderr, "\tunexpected failure to decompress generated "
				        "ROHC packet\n");
				goto destroy_decomp;
			}
		}
		else
		{
			if(counter > last_packet_to_lose && counter <= last_packet_in_error)
			{
				fprintf(stderr, "\tunexpected successful decompression\n");
				goto destroy_decomp;
			}
			else
			{
				/* success is expected for the non-lost packets */
				fprintf(stderr, "\texpected successful decompression\n");
			}
		}
	}

	/* everything went fine */
	fprintf(stderr, "all non-lost packets were successfully decompressed\n");
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
 * @brief Callback to print traces of the ROHC library
 *
 * @param level    The priority level of the trace
 * @param entity   The entity that emitted the trace among:
 *                  \li ROHC_TRACE_COMP
 *                  \li ROHC_TRACE_DECOMP
 * @param profile  The ID of the ROHC compression/decompression profile
 *                 the trace is related to
 * @param format   The format string of the trace
 */
static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
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

