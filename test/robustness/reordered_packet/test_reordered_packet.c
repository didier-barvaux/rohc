/*
 * Copyright 2012,2013,2014,2015 Didier Barvaux
 * Copyright 2012 Viveris Technologies
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
 * @file   test_reordered_packet.c
 * @brief  Check that moderate reordered ROHC packets are handled correctly
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application compresses IP packets from a source PCAP file, then
 * decompresses them but reorder one of them between compressor and decompressor.
 * All IP packets should be correctly compressed. All generated ROHC packets
 * should be correctly decompressed except the reordered one and the one
 * following the reordered one because of context repair.
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
                                const unsigned int packet_to_reorder);
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 5, 6), nonnull(5)));
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));
static bool rohc_comp_rtp_cb(const unsigned char *const ip,
                             const unsigned char *const udp,
                             const unsigned char *const payload,
                             const unsigned int payload_size,
                             void *const rtp_private)
	__attribute__((warn_unused_result));


/**
 * @brief Check that moderate reordered ROHC packets are handled correctly
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
	char *packet_to_reorder_param = NULL;
	int packet_to_reorder;
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 2)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc--, argv++)
	{
		if(!strcmp(*argv, "-h") || !strcmp(*argv, "--help"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(filename == NULL)
		{
			/* get the name of the file that contains the packets to
			 * compress/decompress */
			filename = argv[0];
		}
		else if(packet_to_reorder_param == NULL)
		{
			/* get the ROHC packet to reorder */
			packet_to_reorder_param = argv[0];
		}
		else
		{
			/* do not accept more than two arguments without option name */
			usage();
			goto error;
		}
	}

	/* check mandatory parameters */
	if(filename == NULL || packet_to_reorder_param == NULL)
	{
		usage();
		goto error;
	}

	/* parse the packet to reorder */
	packet_to_reorder = atoi(packet_to_reorder_param);
	if(packet_to_reorder <= 0)
	{
		fprintf(stderr, "bad number for the packet to reorder '%s'\n\n",
		        packet_to_reorder_param);
		usage();
		goto error;
	}

	/* init the random system with a constant value for the test to be fully
	   reproductible */
	srand(5);

	/* test ROHC compression/decompression with the packets from the file */
	status = test_comp_and_decomp(filename, packet_to_reorder);

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that moderate reordered ROHC packets are correctly handled\n"
	        "\n"
	        "usage: test_reordered_packet [OPTIONS] FLOW PACKET_NUM\n"
	        "\n"
	        "with:\n"
	        "  FLOW         The flow of Ethernet frames to (de)compress\n"
	        "               (in PCAP format)\n"
	        "  PACKET_NUM   The firpacket # to reorder\n"
	        "\n"
	        "options:\n"
	        "  -h, --help   Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with a flow of IP packets going through one
 *        compressor then one decompressor
 *
 * @param filename           The name of the PCAP file that contains the
 *                           IP packets
 * @param packet_to_reorder  The first packet # to reorder
 * @return                   0 in case of success,
 *                           1 in case of failure
 */
static int test_comp_and_decomp(const char *const filename,
                                const unsigned int packet_to_reorder)
{
	struct rohc_ts arrival_time = { .sec = 4242, .nsec = 4242 };

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_comp *comp;
	struct rohc_decomp *decomp;

	struct pcap_pkthdr header;
	unsigned char *packet;
	unsigned int counter;

	uint8_t late_rohc_buffer[MAX_ROHC_SIZE];
	struct rohc_buf late_rohc_packet =
		rohc_buf_init_empty(late_rohc_buffer, MAX_ROHC_SIZE);

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
	{
		link_len = ETHER_HDR_LEN;
	}
	else if(link_layer_type == DLT_LINUX_SLL)
	{
		link_len = LINUX_COOKED_HDR_LEN;
	}
	else if(link_layer_type == DLT_NULL)
	{
		link_len = BSD_LOOPBACK_HDR_LEN;
	}
	else /* DLT_RAW */
	{
		link_len = 0;
	}

	/* create the ROHC compressor with small CID */
	comp = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                      gen_random_num, NULL);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto close_input;
	}

	/* set the callback for traces on compressor */
	if(!rohc_comp_set_traces_cb2(comp, print_rohc_traces, NULL))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "compressor\n");
		goto destroy_comp;
	}

	/* enable profiles */
	if(!rohc_comp_enable_profiles(comp, ROHC_PROFILE_UNCOMPRESSED,
	                              ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                              ROHC_PROFILE_RTP, ROHC_PROFILE_ESP,
	                              ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles\n");
		goto destroy_comp;
	}

	/* set UDP ports dedicated to RTP traffic */
	if(!rohc_comp_set_rtp_detection_cb(comp, rohc_comp_rtp_cb, NULL))
	{
		fprintf(stderr, "failed to set the callback RTP detection\n");
		goto destroy_comp;
	}

	/* create the ROHC decompressor in unidirectional mode */
	decomp = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_U_MODE);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb2(decomp, print_rohc_traces, NULL))
	{
		fprintf(stderr, "cannot set trace callback for decompressor\n");
		goto destroy_decomp;
	}

	/* enable decompression profiles */
	if(!rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_UNCOMPRESSED,
	                                ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                                ROHC_PROFILE_RTP, ROHC_PROFILE_ESP,
	                                ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the decompression profiles\n");
		goto destroy_decomp;
	}

	/* enable some features: CRC repair */
	if(!rohc_decomp_set_features(decomp, ROHC_DECOMP_FEATURE_CRC_REPAIR))
	{
		fprintf(stderr, "failed to enabled CRC repair\n");
		goto destroy_decomp;
	}

	/* for each packet in the dump */
	counter = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		struct rohc_buf ip_packet =
			rohc_buf_init_full(packet, header.caplen, arrival_time);
		uint8_t rohc_buffer[MAX_ROHC_SIZE];
		struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, MAX_ROHC_SIZE);
		uint8_t decomp_buffer[MAX_ROHC_SIZE];
		struct rohc_buf decomp_packet =
			rohc_buf_init_empty(decomp_buffer, MAX_ROHC_SIZE);
		rohc_status_t status;

		counter++;
		arrival_time.nsec += 20 * 1e6; /* 20ms between consecutive packets */

		/* avoid overflow of tv_nsec */
		arrival_time.sec += arrival_time.nsec / (unsigned long) 1e9;
		arrival_time.nsec %= (unsigned long) 1e9;

		ip_packet.time.sec = arrival_time.sec;
		ip_packet.time.nsec = arrival_time.nsec;

		fprintf(stderr, "packet #%u:\n", counter);

		/* check the length of the link layer header/frame */
		if(header.len <= link_len || header.len != header.caplen)
		{
			fprintf(stderr, "\ttruncated packet in capture (len = %u, "
			        "caplen = %u)\n", header.len, header.caplen);
			goto destroy_decomp;
		}

		/* skip the link layer header */
		rohc_buf_pull(&ip_packet, link_len);

		/* check for padding after the IP packet in the Ethernet payload */
		if(link_len == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
		{
			uint8_t version;
			uint16_t tot_len;

			/* get IP version */
			version = (rohc_buf_byte(ip_packet) >> 4) & 0x0f;

			/* get IP total length depending on IP version */
			if(version == 4)
			{
				const struct ipv4_hdr *const ip =
					(struct ipv4_hdr *) rohc_buf_data(ip_packet);
				tot_len = ntohs(ip->tot_len);
			}
			else
			{
				const struct ipv6_hdr *const ip =
					(struct ipv6_hdr *) rohc_buf_data(ip_packet);
				tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->plen);
			}

			/* determine if there is Ethernet padding after IP packet */
			if(tot_len < ip_packet.len)
			{
				/* there is Ethernet padding, ignore these bits because there are
				 * not part of the IP packet */
				ip_packet.len = tot_len;
			}
		}
		fprintf(stderr, "\tpacket is valid\n");

		/* compress the IP packet with the ROHC compressor */
		if(counter != packet_to_reorder)
		{
			status = rohc_compress4(comp, ip_packet, &rohc_packet);
		}
		else
		{
			status = rohc_compress4(comp, ip_packet, &late_rohc_packet);
		}
		if(status != ROHC_STATUS_OK)
		{
			fprintf(stderr, "\tfailed to compress IP packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tcompression is successful\n");

		/* is it the packet to reorder? */
		if(counter == packet_to_reorder)
		{
			fprintf(stderr, "\tvoluntary reorder packet #%u\n", counter);
			continue;
		}

		rohc_packet.time.sec = arrival_time.sec;
		rohc_packet.time.nsec = arrival_time.nsec;

		/* decompress the generated ROHC packet with the ROHC decompressor */
		status = rohc_decompress3(decomp, rohc_packet, &decomp_packet,
		                          NULL, NULL);
		if(counter > packet_to_reorder + 1 && counter < packet_to_reorder + 1 + 2)
		{
			/* reordered packet and the next one shall fail */
			if(status == ROHC_STATUS_OK)
			{
				/* success is NOT expected */
				fprintf(stderr, "\tunexpected success to decompress reordered "
				        "ROHC packet or the next one\n");
				goto destroy_decomp;
			}
			else
			{
				/* failure is expected for the reordered packet or the next one */
				fprintf(stderr, "\texpected failure of decompression\n");
			}
		}
		else
		{
			/* non-reordered packets shall succeed */
			if(status != ROHC_STATUS_OK)
			{
				/* failure is NOT expected */
				fprintf(stderr, "\tunexpected failure to decompress generated "
				        "ROHC packet\n");
				goto destroy_decomp;
			}
			else
			{
				/* success is expected for the non-reordered packets */
				fprintf(stderr, "\texpected successful decompression\n");
			}
		}

		/* decompress the reordered packet if needed */
		if(counter == packet_to_reorder + 1)
		{
			rohc_buf_reset(&decomp_packet);
			status = rohc_decompress3(decomp, late_rohc_packet, &decomp_packet,
			                          NULL, NULL);
			/* reordered packet and the next one shall fail */
			if(status == ROHC_STATUS_OK)
			{
				/* success is NOT expected */
				fprintf(stderr, "\tunexpected success to decompress reordered "
				        "ROHC packet or the next one\n");
				goto destroy_decomp;
			}
			else
			{
				/* failure is expected for the reordered packet or the next one */
				fprintf(stderr, "\texpected failure of decompression\n");
			}
		}
	}

	/* everything went fine */
	fprintf(stderr, "all packets were successfully decompressed except the "
	        "reordered one and the next one\n");
	is_failure = 0;

destroy_decomp:
	rohc_decomp_free(decomp);
destroy_comp:
	rohc_comp_free(comp);
close_input:
	pcap_close(handle);
error:
	return is_failure;
}


/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param priv_ctxt  An optional private context, may be NULL
 * @param level      The priority level of the trace
 * @param entity     The entity that emitted the trace among:
 *                    \li ROHC_TRACE_COMP
 *                    \li ROHC_TRACE_DECOMP
 * @param profile    The ID of the ROHC compression/decompression profile
 *                   the trace is related to
 * @param format     The format string of the trace
 */
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
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


/**
 * @brief The RTP detection callback
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @param rtp_private  An optional private context
 * @return             true if the packet is an RTP packet, false otherwise
 */
static bool rohc_comp_rtp_cb(const unsigned char *const ip __attribute__((unused)),
                             const unsigned char *const udp,
                             const unsigned char *const payload __attribute__((unused)),
                             const unsigned int payload_size __attribute__((unused)),
                             void *const rtp_private __attribute__((unused)))
{
	const size_t default_rtp_ports_nr = 5;
	unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002 };
	uint16_t udp_dport;
	bool is_rtp = false;
	size_t i;

	if(udp == NULL)
	{
		return false;
	}

	/* get the UDP destination port */
	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));

	/* is the UDP destination port in the list of ports reserved for RTP
	 * traffic by default (for compatibility reasons) */
	for(i = 0; i < default_rtp_ports_nr; i++)
	{
		if(ntohs(udp_dport) == default_rtp_ports[i])
		{
			is_rtp = true;
			break;
		}
	}

	return is_rtp;
}

