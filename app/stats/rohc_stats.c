/*
 * Copyright 2010,2012,2013,2014 Didier Barvaux
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
 * @file   rohc_stats.c
 * @brief  ROHC statistics program
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The program takes a flow of IP packets as input (in the PCAP format) and
 * generate some ROHC compression statistics with them.
 */

#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif
#include <assert.h>
#include <time.h> /* for time(2) */
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
#include <rohc_packets.h>
#include <rohc_comp.h>


/** The maximal size for the ROHC packets */
#define MAX_ROHC_SIZE  (5 * 1024)

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16U

/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14U

/** The minimum Ethernet length (in bytes) */
#define ETHER_FRAME_MIN_LEN  60U


/* prototypes of private functions */
static void usage(void);
static int generate_comp_stats_all(const rohc_cid_type_t cid_type,
                                   const unsigned int max_contexts,
                                   const char *filename);
static int generate_comp_stats_one(struct rohc_comp *comp,
                                   const unsigned long num_packet,
                                   const struct pcap_pkthdr header,
                                   const unsigned char *packet,
                                   const int link_len);
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
 * @brief Main function for the ROHC statistics program
 *
 * @param argc  The number of program arguments
 * @param argv  The program arguments
 * @return      The unix return code:
 *               \li 0 in case of success,
 *               \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	char *cid_type_name = NULL;
	char *source_filename = NULL;
	int status = 1;
	int max_contexts = ROHC_SMALL_CID_MAX + 1;
	size_t max_possible_contexts = ROHC_SMALL_CID_MAX + 1;
	rohc_cid_type_t cid_type = ROHC_SMALL_CID;
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

		if(!strcmp(*argv, "-h") || !strcmp(*argv, "--help"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(!strcmp(*argv, "-v") || !strcmp(*argv, "--version"))
		{
			/* print version */
			printf("rohc_stats version %s\n", rohc_version());
			goto error;
		}
		else if(!strcmp(*argv, "--max-contexts"))
		{
			/* get the maximum number of contexts the test should use */
			max_contexts = atoi(argv[1]);
			args_used++;
		}
		else if(cid_type_name == NULL)
		{
			/* get the type of CID to use within the ROHC library */
			cid_type_name = argv[0];

			if(!strcmp(cid_type_name, "smallcid"))
			{
				cid_type = ROHC_SMALL_CID;
				max_possible_contexts = ROHC_SMALL_CID_MAX + 1;
			}
			else if(!strcmp(cid_type_name, "largecid"))
			{
				cid_type = ROHC_LARGE_CID;
				max_possible_contexts = ROHC_LARGE_CID_MAX + 1;
			}
			else
			{
				fprintf(stderr, "invalid CID type '%s', only 'smallcid' and "
				        "'largecid' expected\n", cid_type_name);
				usage();
				goto error;
			}
		}
		else if(source_filename == NULL)
		{
			/* get the name of the file that contains the packets to compress */
			source_filename = argv[0];
		}
		else
		{
			/* do not accept more than one filename without option name */
			usage();
			goto error;
		}
	}

	/* check CID type */
	if(cid_type_name == NULL)
	{
		fprintf(stderr, "parameter CID_TYPE is mandatory\n");
		usage();
		goto error;
	}

	/* the maximum number of ROHC contexts should be valid wrt CID type */
	if(max_contexts < 1 || max_contexts > max_possible_contexts)
	{
		fprintf(stderr, "the maximum number of ROHC contexts should be "
		        "between 1 and %zu\n\n", max_possible_contexts);
		usage();
		goto error;
	}

	/* the source filename is mandatory */
	if(source_filename == NULL)
	{
		fprintf(stderr, "source filename is mandatory\n");
		usage();
		goto error;
	}

	/* generate ROHC compression statistics with the packets from the file */
	status = generate_comp_stats_all(cid_type, max_contexts, source_filename);

error:
	return status;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	printf("The ROHC stats tool generates statistics about ROHC compression\n"
	       "\n"
	       "The rohc_stats tool outputs statistics in CSV format with the\n"
	       "following tab-separated fields:\n\n"
	       "  * keyword 'STAT'\n\n"
	       "  * packet number\n\n"
	       "  * context mode (numeric ID)\n\n"
	       "  * context mode (string, no whitespace)\n\n"
	       "  * context state (numeric ID)\n\n"
	       "  * context state (string, no whitespace)\n\n"
	       "  * packet type (numeric ID)\n\n"
	       "  * packet type (string, no whitespace)\n\n"
	       "  * uncompressed packet size (bytes)\n\n"
	       "  * uncompressed header size (bytes)\n\n"
	       "  * compressed packet size (bytes)\n\n"
	       "  * compressed header size (bytes)\n\n"
	       "\n"
	       "The shell script rohc_stats.sh could be used to generate a HTML\n"
	       "report.\n"
	       "\n"
	       "Usage: rohc_stats [OPTIONS] CID_TYPE FLOW\n"
	       "\n"
	       "Options:\n"
	       "  -v, --version           Print version information and exit\n"
	       "  -h, --help              Print this usage and exit\n"
	       "      --max-contexts NUM  The maximum number of ROHC contexts to\n"
	       "                          simultaneously use during the test\n"
	       "\n"
	       "With:\n"
	       "  CID_TYPE                The type of CID to use among 'smallcid'\n"
	       "                          and 'largecid'\n"
	       "  FLOW                    The flow of Ethernet frames to compress\n"
	       "                          (in PCAP format)\n"
	       "\n"
	       "Examples:\n"
	       "  rohc_stats smallcid /tmp/rtp.pcap   Generate statistics\n"
	       "  rohc_stats largecid ~/lan.pcap      Generate statistics\n"
	       "\n"
	       "Report bugs to <" PACKAGE_BUGREPORT ">.\n");
}


/**
 * @brief Generate ROHC compression statistics with a flow of IP packets
 *
 * @param cid_type       The type of CIDs the compressor shall use
 * @param max_contexts   The maximum number of ROHC contexts to use
 * @param filename       The name of the PCAP file that contains the IP packets
 * @return               0 in case of success,
 *                       1 in case of failure
 */
static int generate_comp_stats_all(const rohc_cid_type_t cid_type,
                                   const unsigned int max_contexts,
                                   const char *filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_comp *comp;

	unsigned long num_packet;
	struct pcap_pkthdr header;
	unsigned char *packet;

	int is_failure = 1;

	/* open the source PCAP file */
	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "failed to open the source pcap file: %s\n", errbuf);
		goto error;
	}

	/* link layer in the source PCAP file must be Ethernet */
	link_layer_type = pcap_datalink(handle);
	if(link_layer_type != DLT_EN10MB &&
	   link_layer_type != DLT_LINUX_SLL &&
	   link_layer_type != DLT_RAW)
	{
		fprintf(stderr, "link layer type %d not supported in source PCAP file "
		        "(supported = %d, %d, %d)\n", link_layer_type, DLT_EN10MB,
		        DLT_LINUX_SLL, DLT_RAW);
		goto close_input;
	}

	/* determine the size of the link layer header */
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

	/* create the ROHC compressor */
	comp = rohc_comp_new2(cid_type, max_contexts - 1, gen_random_num, NULL);
	if(comp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC compressor\n");
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
	                              ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                              ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles\n");
		goto destroy_comp;
	}

	/* set UDP ports dedicated to RTP traffic */
	if(!rohc_comp_set_rtp_detection_cb(comp, rohc_comp_rtp_cb, NULL))
	{
		goto destroy_comp;
	}

	/* output the statistics columns names */
	printf("STAT\t"
	       "\"packet number\"\t"
	       "\"context mode\"\t"
	       "\"context mode (string)\"\t"
	       "\"context state\"\t"
	       "\"context state (string)\"\t"
	       "\"packet type\"\t"
	       "\"packet type (string)\"\t"
	       "\"uncompressed packet size (bytes)\"\t"
	       "\"uncompressed header size (bytes)\"\t"
	       "\"compressed packet size (bytes)\"\t"
	       "\"compressed header size (bytes)\"\n");
	fflush(stdout);

	/* for each packet extracted from the PCAP file */
	num_packet = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		int ret;

		num_packet++;

		/* compress the packet and generate statistics */
		ret = generate_comp_stats_one(comp, num_packet, header, packet, link_len);
		if(ret != 0)
		{
			fprintf(stderr, "packet %lu: failed to compress or generate stats "
			        "for packet\n", num_packet);
			goto destroy_comp;
		}
	}

	/* everything went fine */
	is_failure = 0;

destroy_comp:
	rohc_comp_free(comp);
close_input:
	pcap_close(handle);
error:
	return is_failure;
}


/**
 * @brief Compress and decompress one uncompressed IP packet with the given
 *        compressor and decompressor
 *
 * @param comp        The compressor to use to compress the IP packet
 * @param num_packet  A number affected to the IP packet to compress
 * @param header      The PCAP header for the packet
 * @param packet      The packet to compress (link layer included)
 * @param link_len    The length of the link layer header before IP data
 * @return            0 in case of success,
 *                    1 in case of failure
 */
static int generate_comp_stats_one(struct rohc_comp *comp,
                                   const unsigned long num_packet,
                                   const struct pcap_pkthdr header,
                                   const unsigned char *packet,
                                   const int link_len)
{
	struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
	struct rohc_buf ip_packet =
		rohc_buf_init_full((unsigned char *) packet, header.caplen, arrival_time);
	uint8_t rohc_buffer[MAX_ROHC_SIZE];
	struct rohc_buf rohc_packet =
		rohc_buf_init_empty(rohc_buffer, MAX_ROHC_SIZE);
	rohc_comp_last_packet_info2_t last_packet_info;
	rohc_status_t status;

	/* check frame length */
	if(header.len <= link_len || header.len != header.caplen)
	{
		fprintf(stderr, "packet #%lu: bad PCAP packet (len = %d, caplen = %d)\n",
		        num_packet, header.len, header.caplen);
		goto error;
	}

	/* skip the link layer header */
	rohc_buf_pull(&ip_packet, link_len);

	/* check for padding after the IP packet in the Ethernet payload */
	if(link_len == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
	{
		uint8_t version;
		uint16_t tot_len;

		version = (rohc_buf_byte(ip_packet) >> 4) & 0x0f;
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
			tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->ip6_plen);
		}

		if(tot_len < ip_packet.len)
		{
			/* the Ethernet frame has some bytes of padding after the IP packet */
			ip_packet.len = tot_len;
		}
	}

	/* compress the IP packet */
	status = rohc_compress4(comp, ip_packet, &rohc_packet);
	if(status != ROHC_STATUS_OK)
	{
		fprintf(stderr, "packet #%lu: compression failed\n", num_packet);
		goto error;
	}

	/* get some statistics about the last compressed packet */
	last_packet_info.version_major = 0;
	last_packet_info.version_minor = 0;
	if(!rohc_comp_get_last_packet_info2(comp, &last_packet_info))
	{
		fprintf(stderr, "packet #%lu: cannot get stats about the last compressed "
		        "packet\n", num_packet);
		goto error;
	}

	/* output some statistics about the last compressed packet */
	printf("STAT\t%lu\t%d\t%s\t%d\t%s\t%d\t%s\t%lu\t%lu\t%lu\t%lu\n",
	       num_packet,
	       last_packet_info.context_mode,
	       rohc_get_mode_descr(last_packet_info.context_mode),
	       last_packet_info.context_state,
	       rohc_comp_get_state_descr(last_packet_info.context_state),
	       last_packet_info.packet_type,
	       rohc_get_packet_descr(last_packet_info.packet_type),
	       last_packet_info.total_last_uncomp_size,
	       last_packet_info.header_last_uncomp_size,
	       last_packet_info.total_last_comp_size,
	       last_packet_info.header_last_comp_size);
	fflush(stdout);

	return 0;

error:
	return 1;
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
static void print_rohc_traces(void *const priv_ctxt __attribute__((unused)),
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
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

