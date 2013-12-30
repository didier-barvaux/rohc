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
 * @file   test_rtp_uor2_disambiguation.c
 * @brief  Check that RTP UO-1* / UOR-2* disambiguation algorithm is correct
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application compresses IP packets from a source PCAP file, then
 * decompresses them. The last packet shall be compressed/decompressed as
 * the expected packet type.
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
#include <stdarg.h>
#include <assert.h>

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
                                const rohc_packet_t expected_packet);
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
 * @brief Check that RTP UO-1* / UOR-2* disambiguation algorithm is correct
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
	char *packet_type = NULL;
	rohc_packet_t expected_packet;
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
		else if(filename == NULL)
		{
			/* get the name of the file that contains the packets to
			 * compress/decompress */
			filename = argv[0];
		}
		else if(packet_type == NULL)
		{
			/* get the expected type of the last packet */
			packet_type = argv[0];
		}
		else
		{
			/* do not accept more than two arguments without option name */
			usage();
			goto error;
		}
	}

	/* check mandatory parameters */
	if(filename == NULL || packet_type == NULL)
	{
		usage();
		goto error;
	}

	/* parse the packet type */
	if(strlen(packet_type) == 6 && strcmp(packet_type, "uo1rtp") == 0)
	{
		expected_packet = ROHC_PACKET_UO_1_RTP;
	}
	else if(strlen(packet_type) == 5 && strcmp(packet_type, "uo1ts") == 0)
	{
		expected_packet = ROHC_PACKET_UO_1_TS;
	}
	else if(strlen(packet_type) == 5 && strcmp(packet_type, "uo1id") == 0)
	{
		expected_packet = ROHC_PACKET_UO_1_ID;
	}
	else if(strlen(packet_type) == 7 && strcmp(packet_type, "uor2rtp") == 0)
	{
		expected_packet = ROHC_PACKET_UOR_2_RTP;
	}
	else if(strlen(packet_type) == 6 && strcmp(packet_type, "uor2ts") == 0)
	{
		expected_packet = ROHC_PACKET_UOR_2_TS;
	}
	else if(strlen(packet_type) == 6 && strcmp(packet_type, "uor2id") == 0)
	{
		expected_packet = ROHC_PACKET_UOR_2_ID;
	}
	else
	{
		fprintf(stderr, "unknown packet type '%s'\n\n", packet_type);
		usage();
		goto error;
	}

	/* init the random system with a constant value for the test to be fully
	   reproductible */
	srand(5);

	/* test ROHC compression/decompression with the packets from the file */
	status = test_comp_and_decomp(filename, expected_packet);

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that RTP UO-1* / UOR-2* disambiguation algorithm is correct\n"
	        "\n"
	        "usage: test_rtp_uo_disambiguation [OPTIONS] FLOW PACKET_TYPE\n"
	        "\n"
	        "with:\n"
	        "  FLOW         The flow of Ethernet frames to compress/decompress\n"
	        "               (in PCAP format)\n"
	        "  PACKET_TYPE  The packet type expected for the last packet\n"
	        "               among: uo1rtp, uo1ts, uo1ts, uor2rtp, uor2ts and uor2ts\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with a flow of IP packets going through one
 *        compressor then one decompressor
 *
 * @param filename          The name of the PCAP file that contains the
 *                          IP packets
 * @param expected_packet   The type of ROHC packet expected at the end of the
 *                          source capture
 * @return                  0 in case of success,
 *                          1 in case of failure
 */
static int test_comp_and_decomp(const char *const filename,
                                const rohc_packet_t expected_packet)
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

	rohc_packet_t pkt_type_comp = ROHC_PACKET_UNKNOWN;
	rohc_packet_t pkt_type_decomp = ROHC_PACKET_UNKNOWN;

#define NB_RTP_PORTS 5
	const unsigned int rtp_ports[NB_RTP_PORTS] =
		{ 1234, 36780, 33238, 5020, 5002 };

	unsigned int i;
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

	/* create the ROHC compressor with small CID */
	comp = rohc_comp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX);
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

	/* reduce uncompressed transmissions for list compression to ease test */
	if(!rohc_comp_set_list_trans_nr(comp, 2U))
	{
		fprintf(stderr, "failed to reduce uncompressed transmissions for list "
		        "compression\n");
		goto destroy_comp;
	}

	/* enable profiles */
	if(!rohc_comp_enable_profiles(comp, ROHC_PROFILE_RTP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles\n");
		goto destroy_comp;
	}

	/* set the callback for random numbers on compressor */
	if(!rohc_comp_set_random_cb(comp, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto destroy_comp;
	}

	/* reset list of RTP ports for compressor */
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
	decomp = rohc_decomp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                         ROHC_U_MODE, NULL);
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
	if(!rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_RTP, -1))
	{
		fprintf(stderr, "failed to enable the decompression profiles\n");
		goto destroy_decomp;
	}

	/* for each packet in the dump */
	counter = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		const struct rohc_timestamp arrival_time = { .sec = 0, .nsec = 0 };
		unsigned char *ip_packet;
		size_t ip_size;
		static unsigned char rohc_packet[MAX_ROHC_SIZE];
		size_t rohc_size;
		rohc_comp_last_packet_info2_t comp_packet_info;
		rohc_decomp_last_packet_info_t decomp_packet_info;
		static unsigned char decomp_packet[MAX_ROHC_SIZE];
		size_t decomp_size;
		int ret;

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
			uint8_t version;
			uint16_t tot_len;

			/* get IP version */
			version = (ip_packet[0] >> 4) & 0x0f;

			/* get IP total length depending on IP version */
			if(version == 4)
			{
				struct ipv4_hdr *ip = (struct ipv4_hdr *) ip_packet;
				tot_len = ntohs(ip->tot_len);
			}
			else
			{
				struct ipv6_hdr *ip = (struct ipv6_hdr *) ip_packet;
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

		/* get packet statistics to retrieve the packet type */
		comp_packet_info.version_major = 0;
		comp_packet_info.version_minor = 0;
		if(!rohc_comp_get_last_packet_info2(comp, &comp_packet_info))
		{
			fprintf(stderr, "\tfailed to get statistics on packet to damage\n");
			goto destroy_decomp;
		}
		pkt_type_comp = comp_packet_info.packet_type;
		fprintf(stderr, "\tROHC packet is of type '%s' (%d)\n",
		        rohc_get_packet_descr(pkt_type_comp), pkt_type_comp);

		/* decompress the generated ROHC packet with the ROHC decompressor */
		ret = rohc_decompress2(decomp, arrival_time, rohc_packet, rohc_size,
		                       decomp_packet, MAX_ROHC_SIZE, &decomp_size);
		if(ret != ROHC_OK)
		{
			fprintf(stderr, "\tunexpected failure to decompress generated "
			        "ROHC packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tdecompression is successful\n");

		/* retrieve the packet type */
		decomp_packet_info.version_major = 0;
		decomp_packet_info.version_minor = 1;
		if(!rohc_decomp_get_last_packet_info(decomp, &decomp_packet_info))
		{
			fprintf(stderr, "\tfailed to get decompression info\n");
			goto destroy_decomp;
		}
		pkt_type_decomp = decomp_packet_info.packet_type;
	}

	/* last compressed packet must be of the expected type */
	if(pkt_type_comp != expected_packet)
	{
		fprintf(stderr, "last packet was compressed as '%s' (%u) "
		        "while '%s' (%u) was expected\n",
		        rohc_get_packet_descr(pkt_type_comp), pkt_type_comp,
		        rohc_get_packet_descr(expected_packet), expected_packet);
		goto destroy_decomp;
	}

	/* last decompressed packet must be of the expected type */
	if(pkt_type_decomp != expected_packet)
	{
		fprintf(stderr, "last packet was decompressed as '%s' (%u) "
		        "while '%s' (%u) was expected\n",
		        rohc_get_packet_descr(pkt_type_decomp), pkt_type_decomp,
		        rohc_get_packet_descr(expected_packet), expected_packet);
		goto destroy_decomp;
	}

	/* everything went fine */
	fprintf(stderr, "all packets were successfully compressed/decompressed\n");
	fprintf(stderr, "last packet was compressed/decompressed with the "
	        "expected packet type\n");
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

