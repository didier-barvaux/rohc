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
 * @file    test_rtp_ports.c
 * @brief   Test the RTP ports management
 * @author  Julien Bernard <julien.bernard@toulouse.viveris.com>
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "test.h"

#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif
#include <stdarg.h>
#include <assert.h>

/* include for the PCAP library */
#if HAVE_PCAP_PCAP_H == 1
#  include <pcap/pcap.h>
#elif HAVE_PCAP_H == 1
#  include <pcap.h>
#else
#  error "pcap.h header not found, did you specified --enable-rohc-tests \
for ./configure ? If yes, check configure output and config.log"
#endif

/* includes for network headers */
#include <protocols/ipv4.h>
#include <protocols/ipv6.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>


/** The number of UDP ports associated to RTP profile for the test */
#define NB_RTP_PORTS 4


/*
 * Function prototypes
 */

static void usage(void);

static int test_rtp_ports(const char *check_type,
                          const char *stream_file);

static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));

static int compress_and_check(struct rohc_comp *comp,
                              struct pcap_pkthdr header,
                              unsigned char *packet,
                              size_t link_len,
                              int packet_counter,
                              int success_expected,
                              int profile_expected);
static int check_profile(struct rohc_comp *comp,
                         unsigned int profile);


/** Whether the application runs in verbose mode or not */
static int is_verbose;


/**
 * @brief Check the RTP ports management
 *
 * @param argc  The number of program arguments
 * @param argv  The program arguments
 * @return      The unix return code: 0 if OK, 1 otherwise
 */
int main(int argc, char *argv[])
{
	char *check_type = NULL;
	char *stream_file = NULL;
	int is_failure = 1;
	int ret;

	/* parse the arguments, print the help message in case of failure */
	if(argc == 1)
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
		else if(!strcmp(*argv, "--verbose"))
		{
			/* enable verbose mode */
			is_verbose = 1;
		}
		else if(check_type == NULL)
		{
			/* get the type of check */
			check_type = argv[0];
		}
		else if(stream_file == NULL)
		{
			/* get the name of the file that contains the packets to
			 * compress/decompress */
			stream_file = argv[0];
		}
		else
		{
			/* do not accept more than one filename without option name */
			usage();
			goto error;
		}
	}

	/* the type of check and source filename are mandatory */
	if(check_type == NULL || stream_file == NULL)
	{
		fprintf(stderr, "type of check and stream file are mandatory\n");
		usage();
		goto error;
	}

	/* run the test and check its result */
	printf("run test...\n");
	ret = test_rtp_ports(check_type, stream_file);
	if(ret != 0)
	{
		fprintf(stderr, "test failed\n");
		goto error;
	}
	printf("test is successful\n");

	/* everything went fine */
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Print usage of the test program
 */
static void usage(void)
{
	fprintf(stderr,
	        "Test program for the RTP ports management\n"
	        "\n"
	        "usage: test_rtp_ports CHECK_TYPE STREAM [verbose]\n"
	        "\n"
	        "with:\n"
	        "  CHECK_TYPE  the type of check to run:\n"
	        "               - test context deletion\n"
	        "               - test profile usage after port deletion\n"
	        "  STREAM      a stream of IP packet to compress (PCAP format)\n"
	        "\n"
	        "options:\n"
	        "  -h                      Print this usage and exit\n"
	        "  --verbose               Run in verbose mode\n");
}


/**
 * @brief Test that the RTP ports are handled by the library as expected
 *
 * @param check_type  The type of check to run
 * @param stream_file The name of the PCAP file that contains the input stream
 * @return            0 in case of success, 1 otherwise
 */
static int test_rtp_ports(const char *check_type,
                          const char *stream_file)
{
	unsigned int rtp_ports[NB_RTP_PORTS] = { 1234, 1232, 1235, 1236 };
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct rohc_comp *comp;
	struct pcap_pkthdr header;
	int link_layer_type;
	size_t link_len;
	unsigned char *packet;
	int counter;
	int expected_profile;
	int success_expected;
	int is_failure = 1;
	int ret;
	unsigned int i;

	/* open the source capture */
	handle = pcap_open_offline(stream_file, errbuf);
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
	                              ROHC_PROFILE_ESP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles");
		goto destroy_comp;
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

	/* remove one of the RTP port to check there is no problem removing port */
	assert(NB_RTP_PORTS >= 2);
	if(!rohc_comp_remove_rtp_port(comp, rtp_ports[NB_RTP_PORTS - 2]))
	{
		fprintf(stderr, "failed to remove RTP port %u\n",
		        rtp_ports[NB_RTP_PORTS - 2]);
		goto destroy_comp;
	}

	/* compress the first packet of the RTP stream, RTP profile is expected */
	counter = 1;
	packet = (unsigned char *) pcap_next(handle, &header);
	expected_profile = ROHC_PROFILE_RTP;
	success_expected = 1;
	ret = compress_and_check(comp, header, packet, link_len,
	                         counter, success_expected,
	                         expected_profile);
	if(ret != 0)
	{
		fprintf(stderr, "test on packet #%d failed\n", counter);
		goto destroy_comp;
	}
	counter++;

	/* remove one RTP port */
	assert(NB_RTP_PORTS > 0);
	if(!rohc_comp_remove_rtp_port(comp, rtp_ports[0]))
	{
		fprintf(stderr, "failed to remove RTP port %u\n", rtp_ports[0]);
		goto destroy_comp;
	}

	if(strcmp(check_type, "context") == 0)
	{
		rohc_comp_last_packet_info2_t last_info;

		/* get last information from ROHC context */
		last_info.version_major = 0;
		last_info.version_minor = 0;
		if(!rohc_comp_get_last_packet_info2(comp, &last_info))
		{
			fprintf(stderr, "failed to get last packet information\n");
			goto destroy_comp;
		}

		/* check if the context using the RTP port is still used */
		if(last_info.context_used)
		{
			fprintf(stderr, "the context was not disabled when the port was "
			        "removed\n");
			goto destroy_comp;
		}
	}
	else
	{
		/* compress the following packets in the stream and check that
		   there are compressed with the UDP profile since the RTP port
		   was removed from the list */
		while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
		{
			/* compress the packet */
			fprintf(stderr, "compress packet #%d\n", counter);
			expected_profile = ROHC_PROFILE_UDP;
			success_expected = 1;
			ret = compress_and_check(comp, header, packet, link_len,
			                         counter, success_expected,
			                         expected_profile);
			if(ret != 0)
			{
				fprintf(stderr, "test on packet #%d failed\n", counter);
				goto destroy_comp;
			}
			counter++;
			fprintf(stderr, "\n");
		}
	}

	/* everything went fine */
	is_failure = 0;

destroy_comp:
	rohc_free_compressor(comp);
close_input:
	pcap_close(handle);
error:
	return is_failure;
}


/**
 * @brief Compress a packet with the given compressor and check its validity
 *        with the given callback
 *
 * @param comp              The compressor to use to compress the packet
 * @param header            The PCAP header for the packet
 * @param packet            The packet to compress (link layer included)
 * @param link_len          The length of the link layer header before IP data
 * @param packet_counter    The number of the packet in the stream (for debug
 *                          purpose only)
 * @param success_expected  Whether the compression shall be successful or not
 * @param profile_expected  The profile expected
 * @return                  0 in case of success, 1 otherwise
 */
static int compress_and_check(struct rohc_comp *comp,
                              struct pcap_pkthdr header,
                              unsigned char *packet,
                              size_t link_len,
                              int packet_counter,
                              int success_expected,
                              int profile_expected)
{
	unsigned char *ip_packet;
	size_t ip_size;
	static unsigned char rohc_packet[MAX_ROHC_SIZE];
	size_t rohc_size;
	int is_failure = 1;
	int ret;

	/* check packet */
	if(packet == NULL)
	{
		fprintf(stderr, "packet #%d: packet does not exist in capture\n",
		        packet_counter);
		goto error;
	}

	/* check Ethernet frame length */
	if(header.len <= link_len || header.len != header.caplen)
	{
		fprintf(stderr, "packet #%d: bad PCAP packet (len = %d, caplen = %d)\n",
		        packet_counter, header.len, header.caplen);
		goto error;
	}

	/* skip the link layer header */
	ip_packet = packet + link_len;
	ip_size = header.len - link_len;

	/* check for padding after the IP packet in the Ethernet payload */
	if(link_len == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
	{
		uint8_t ip_version;
		uint16_t tot_len;

		/* get IP version */
		ip_version = (ip_packet[0] >> 4) & 0x0f;

		/* get IP total length depending on IP version */
		if(ip_version == 4)
		{
			struct ipv4_hdr *ip = (struct ipv4_hdr *) ip_packet;
			tot_len = ntohs(ip->tot_len);
		}
		else
		{
			struct ipv6_hdr *ip = (struct ipv6_hdr *) ip_packet;
			tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->ip6_plen);
		}

		/* update the length of the IP packet if padding is present */
		if(tot_len < ip_size)
		{
			fprintf(stderr, "packet #%d: the Ethernet frame has %zd bytes "
			        "of padding after the %u-byte IP packet!\n",
			        packet_counter, ip_size - tot_len, tot_len);
			ip_size = tot_len;
		}
	}

	ret = rohc_compress2(comp, ip_packet, ip_size,
	                     rohc_packet, MAX_ROHC_SIZE, &rohc_size);

	/* check the compression result against expected one */
	if(success_expected && ret != ROHC_OK)
	{
		fprintf(stderr, "packet #%d: failed to compress one %zd-byte IP packet\n",
		        packet_counter, ip_size);
		goto error;
	}
	else if(!success_expected && ret != ROHC_ERROR)
	{
		fprintf(stderr, "packet #%d: compress successfully one %zd-byte IP packet "
		        "while it should have failed\n", packet_counter, ip_size);
		goto error;
	}

	/** Check the profile */
	ret = check_profile(comp, profile_expected);
	if(ret != 0)
	{
		fprintf(stderr, "packet #%d: the profile is not as expected\n",
				packet_counter);
		goto error;
	}

	/* everything went fine */
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Check if the packet was compressed with the expected profile
 *
 * @param comp    The ROHC compressor
 * @param profile The expected profile
 * @return        1 in case of failure, 0 otherwise
 */
static int check_profile(struct rohc_comp *comp,
                         unsigned int profile)
{
	rohc_comp_last_packet_info2_t info;

	/** Get last information from ROHC context */
	info.version_major = 0;
	info.version_minor = 0;
	if(!rohc_comp_get_last_packet_info2(comp, &info))
	{
		fprintf(stderr, "Error while getting last packet information\n");
		return 1;
	}

	/* check if the profiles match */
	if(info.profile_id != profile)
	{
		fprintf(stderr, "profile %d was used instead of %d\n",
		        info.profile_id, profile);
		return 1;
	}

	return 0;
}


/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param level    The priority level of the trace
 * @param entity   The entity that emitted the trace among:
 *                  \li ROHC_TRACE_COMPRESSOR
 *                  \li ROHC_TRACE_DECOMPRESSOR
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

	if(is_verbose)
	{
		va_start(args, format);
		vfprintf(stdout, format, args);
		va_end(args);
	}
}

