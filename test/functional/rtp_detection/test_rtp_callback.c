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
 * @file    test_rtp_callback.c
 * @brief   Test the RTP detection callback
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


/*
 * Function prototypes
 */

static void usage(void);

static int test_rtp_callback(const char *const do_detect,
                             const char *const stream_file);

static bool callback_detect(const unsigned char *const ip,
                            const unsigned char *const udp,
                            const unsigned char *payload,
                            const unsigned int payload_size,
                            void *const rtp_private);
static bool callback_ignore(const unsigned char *const ip,
                            const unsigned char *const udp,
                            const unsigned char *const payload,
                            const unsigned int payload_size,
                            void *const rtp_private);

static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format, ...)
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
 * @brief Check the RTP detection callback
 *
 * @param argc  The number of program arguments
 * @param argv  The program arguments
 * @return      The unix return code: 0 if OK, 1 otherwise
 */
int main(int argc, char *argv[])
{
	char *do_detect = NULL;
	char *stream_file = NULL;
	int is_failure = 1;
	int ret;

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
		else if(do_detect == NULL)
		{
			/* get the type of check */
			do_detect = argv[0];
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
	if(do_detect == NULL || stream_file == NULL)
	{
		fprintf(stderr, "type of check and stream file are mandatory\n");
		usage();
		goto error;
	}

	/* run the test and check its result */
	printf("run test...\n");
	ret = test_rtp_callback(do_detect, stream_file);
	if(ret != 0)
	{
		fprintf(stderr, "test failed\n");
		goto error;
	}

	/* everything went fine */
	printf("test is successful\n");
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
	        "Test program for the RTP detection callback\n"
	        "\n"
	        "usage: test_rtp_callback [OPTIONS] DETECT STREAM\n"
	        "\n"
	        "with:\n"
	        "  DETECT  whether the RTP stream should be detected or not\n"
	        "  STREAM  a stream of IP packet to compress (PCAP format)\n"
	        "\n"
	        "options:\n"
	        "  -h                      Print this usage and exit\n"
	        "  --verbose               Run in verbose mode\n");
}


/**
 * @brief Test that RTP detection callback is handled as expected
 *
 * @param do_detect   Whether the RTP stream should be detected or not
 * @param stream_file The name of the PCAP file that contains the input stream
 * @return            0 in case of success, 1 otherwise
 */
static int test_rtp_callback(const char *const do_detect,
                             const char *const stream_file)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
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
	                              ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles\n");
		goto destroy_comp;
	}

	/* reset list of RTP ports */
	if(!rohc_comp_reset_rtp_ports(comp))
	{
		fprintf(stderr, "failed to reset list of RTP ports\n");
		goto destroy_comp;
	}

	/* enable the RTP detection callback */
	if(strcmp(do_detect, "detect") == 0)
	{
		if(!rohc_comp_set_rtp_detection_cb(comp, callback_detect, NULL))
		{
			fprintf(stderr, "failed to set RTP detection callback\n");
			goto destroy_comp;
		}

		expected_profile = ROHC_PROFILE_RTP;
	}
	else
	{
		/* add the RTP port to the list,
		 * if the callback is activated it should not have any effect */
		if(!rohc_comp_add_rtp_port(comp, 1234))
		{
			fprintf(stderr, "failed to add RTP port\n");
			goto destroy_comp;
		}

		if(!rohc_comp_set_rtp_detection_cb(comp, callback_ignore, NULL))
		{
			fprintf(stderr, "failed to set RTP detection callback\n");
			goto destroy_comp;
		}

		expected_profile = ROHC_PROFILE_UDP;
	}

	/* compress the first packet of the RTP stream, RTP profile is expected */
	counter = 1;
	packet = (unsigned char *) pcap_next(handle, &header);
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
	const struct timespec arrival_time = { .tv_sec = 0, .tv_nsec = 0 };
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
			fprintf(stderr, "packet #%d: the Ethernet frame has %zu bytes "
			        "of padding after the %u-byte IP packet!\n",
			        packet_counter, ip_size - tot_len, tot_len);
			ip_size = tot_len;
		}
	}

	ret = rohc_compress3(comp, arrival_time, ip_packet, ip_size,
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
 * @brief The RTP detection callback which does detect RTP stream
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @return             true if the packet is an RTP packet, false otherwise
 */
static bool callback_detect(const unsigned char *const ip,
                            const unsigned char *const udp,
                            const unsigned char *const payload,
                            const unsigned int payload_size,
                            void *const rtp_private)
{
	uint16_t udp_dport;
	uint32_t rtp_ssrc;
	bool is_rtp = false;

	/* check UDP destination port */
	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));
	if(ntohs(udp_dport) != 1234)
	{
		fprintf(stderr, "RTP packet not detected (wrong UDP port)\n");
		goto not_rtp;
	}

	/* check minimal RTP header length */
	if(payload_size < 12)
	{
		fprintf(stderr, "RTP packet not detected (UDP payload too short)\n");
		goto not_rtp;
	}

	/* check RTP SSRC field */
	memcpy(&rtp_ssrc, payload + 8, sizeof(uint32_t));
	if(ntohl(rtp_ssrc) != 0x0d1ba521)
	{
		fprintf(stderr, "RTP packet not detected (wrong RTP SSRC)\n");
		goto not_rtp;
	}

	/* we think that the UDP packet is a RTP packet */
	fprintf(stderr, "RTP packet detected\n");
	is_rtp = true;

not_rtp:
	return is_rtp;
}


/**
 * @brief The RTP detection callback which do not detect RTP stream
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @return             true if the packet is an RTP packet, false otherwise
 */
static bool callback_ignore(const unsigned char *const ip,
                            const unsigned char *const udp,
                            const unsigned char *const payload,
                            const unsigned int payload_size,
                            void *const rtp_private)
{
	return false;
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
		fprintf(stderr, "failed to get last packet information\n");
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

