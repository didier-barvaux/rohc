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
 * @file   rohc_gen_stream.c
 * @brief  Generate an (un)compressed stream for performance testing
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "config.h" /* for HAVE_*_H and PACKAGE_BUGREPORT */

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
#include <ip.h> /* for IPv4 checksum */
#include <protocols/ipv4.h>
#include <protocols/udp.h>
#include <protocols/rtp.h>

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
#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>



/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14


/* prototypes of private functions */
static void usage(void);
static bool build_stream(const char *const filename,
                         const char *const stream_type,
                         const unsigned long max_packets,
                         const int use_large_cid,
                         const size_t wlsb_width,
                         const unsigned int max_contexts)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));

static int gen_false_random_num(const struct rohc_comp *const comp,
                                void *const user_context)
	__attribute__((nonnull(1)));


/** Whether the application runs in verbose mode or not */
static int is_verbose;


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
	char *stream_type = NULL;
	unsigned long max_packets = 0;
	char *filename = NULL;
	char *cid_type = NULL;
	int max_contexts = ROHC_SMALL_CID_MAX + 1;
	int wlsb_width = 4;
	int is_failure = 1;
	int use_large_cid;
	int args_used;

	/* set to quiet mode by default */
	is_verbose = 0;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 1)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc -= args_used, argv += args_used)
	{
		args_used = 1;

		if(!strcmp(*argv, "-v") || !strcmp(*argv, "--version"))
		{
			/* print version */
			printf("rohc_gen_stream version %s\n", rohc_version());
			goto error;
		}
		else if(!strcmp(*argv, "-h") || !strcmp(*argv, "--help"))
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
		else if(!strcmp(*argv, "--cid-type"))
		{
			/* get the type of CID to use within the ROHC library */
			cid_type = argv[1];
			args_used++;
		}
		else if(!strcmp(*argv, "--max-contexts"))
		{
			/* get the maximum number of contexts the test should use */
			max_contexts = atoi(argv[1]);
			args_used++;
		}
		else if(!strcmp(*argv, "--wlsb-width"))
		{
			/* get the width of the WLSB window the test should use */
			wlsb_width = atoi(argv[1]);
			args_used++;
		}
		else if(stream_type == NULL)
		{
			/* get the type of the stream to perform */
			stream_type = argv[0];
		}
		else if(max_packets == 0)
		{
			/* get the number of packets to put in stream */
			max_packets = atoi(argv[0]);
		}
		else if(filename == NULL)
		{
			/* get the name of the output file */
			filename = argv[0];
		}
		else
		{
			/* do not accept more than 3 arguments without option name */
			usage();
			goto error;
		}
	}

	/* check CID type */
	if(cid_type == NULL || !strcmp(cid_type, "smallcid"))
	{
		use_large_cid = 0;

		/* the maximum number of ROHC contexts should be valid */
		if(max_contexts < 1 || max_contexts > (ROHC_SMALL_CID_MAX + 1))
		{
			fprintf(stderr, "the maximum number of ROHC contexts should be "
			        "between 1 and %u\n\n", ROHC_SMALL_CID_MAX + 1);
			usage();
			goto error;
		}
	}
	else if(!strcmp(cid_type, "largecid"))
	{
		use_large_cid = 1;

		/* the maximum number of ROHC contexts should be valid */
		if(max_contexts < 1 || max_contexts > (ROHC_LARGE_CID_MAX + 1))
		{
			fprintf(stderr, "the maximum number of ROHC contexts should be "
			        "between 1 and %u\n\n", ROHC_LARGE_CID_MAX + 1);
			usage();
			goto error;
		}
	}
	else
	{
		fprintf(stderr, "invalid CID type '%s', only 'smallcid' and 'largecid' "
		        "expected\n", cid_type);
		goto error;
	}

	/* check WLSB width */
	if(wlsb_width <= 0 || (wlsb_width & (wlsb_width - 1)) != 0)
	{
		fprintf(stderr, "invalid WLSB width %d: should be a positive power of "
		        "two\n", wlsb_width);
		goto error;
	}

	/* the stream type is mandatory */
	if(stream_type == NULL)
	{
		fprintf(stderr, "missing stream type: uncomp or comp\n");
		usage();
		goto error;
	}
	if(strcmp(stream_type, "uncomp") != 0 &&
	   strcmp(stream_type, "comp") != 0)
	{
		fprintf(stderr, "unexpected stream type: uncomp or comp supported\n");
		usage();
		goto error;
	}

	/* the output filename is mandatory */
	if(filename == NULL)
	{
		fprintf(stderr, "missing output filename\n");
		usage();
		goto error;
	}

	/* test ROHC compression/decompression with the packets from the file */
	if(!build_stream(filename, stream_type, max_packets,
	                 use_large_cid, wlsb_width, max_contexts))
	{
		fprintf(stderr, "failed to build stream\n");
		goto error;
	}

	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	printf("Generate an (un)compressed stream for performance testing\n"
	       "\n"
	       "Usage: rohc_gen_stream [General options]\n"
	       "   or: rohc_gen_stream uncomp MAX OUTPUT\n"
	       "   or: rohc_gen_stream [Compression options] comp MAX OUTPUT\n"
	       "\n"
	       "Options:\n"
	       "General options:\n"
	       "  -h, --help              Print this usage and exit\n"
	       "  -v, --version           Print the application version and exit\n"
	       "Compression options:\n"
	       "      --cid-type TYPE     The type of CID to use among 'smallcid'\n"
	       "                          and 'largecid'\n"
	       "      --max-contexts NUM  The maximum number of ROHC contexts to\n"
	       "                          simultaneously use during the test\n"
	       "      --wlsb-width NUM    The width of the WLSB window to use\n"
	       "Mandatory parameters:\n"
	       "  MAX                     The number of packets to generate\n"
	       "  OUTPUT                  The name of the output file with the\n"
	       "                          generated stream (in PCAP format)\n"
	       "\n"
	       "Examples:\n"
	       "  rohc_gen_stream uncomp 1000 rtp.pcap  Generate 1000 RTP packets\n"
	       "                                        in file rtp.pcap\n"
	       "  rohc_gen_stream comp 500 rohc.pcap    Generate 500 RTP packets,\n"
	       "                                        compress them, then store\n"
	       "                                        them in file rohc.pcap\n"
	       "\n"
	       "Report bugs to <" PACKAGE_BUGREPORT ">.\n");
}


/**
 * @brief Build an (un)compressed stream
 *
 * @param filename       The name of the PCAP file to output the stream
 * @param stream_type    The type of stream to generate: uncomp or comp
 * @param max_packets    The number of packets to generate
 * @param use_large_cid  Whether the compressor shall use large CIDs
 * @param max_contexts   The maximum number of ROHC contexts to use
 * @param wlsb_width     The width of the WLSB window to use
 * @return               true in case of success,
 *                       false in case of failure
 */
static bool build_stream(const char *const filename,
                         const char *const stream_type,
                         const unsigned long max_packets,
                         const int use_large_cid,
                         const size_t wlsb_width,
                         const unsigned int max_contexts)
{
	const rohc_cid_type_t cid_type =
		(use_large_cid ? ROHC_LARGE_CID : ROHC_SMALL_CID);
	bool is_success = false;
	int ret;

	pcap_t *pcap;
	pcap_dumper_t *dumper;

	unsigned long counter;

	struct rohc_comp *comp = NULL;

	printf("generate %lu %s packets in '%s'...\n", max_packets, stream_type,
	       filename);

	/* create a PCAP context for output */
	pcap = pcap_open_dead(DLT_EN10MB, 0 /* infinite snaplen */);
	if(pcap == NULL)
	{
		fprintf(stderr, "failed to create a pcap context\n");
		goto error;
	}

	/* open the PCAP dump file */
	dumper = pcap_dump_open(pcap, filename);
	if(dumper == NULL)
	{
		fprintf(stderr, "failed to open dump file\n");
		goto close_pcap;
	}

	if(strcmp(stream_type, "comp") == 0)
	{
#define NB_RTP_PORTS 1
		const unsigned int rtp_ports[NB_RTP_PORTS] = { 1234 };
		int i;

		/* create the compressor */
		comp = rohc_comp_new(cid_type, max_contexts - 1);
		if(comp == NULL)
		{
			fprintf(stderr, "cannot create the compressor\n");
			goto close_dumper;
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

		/* set the callback for random numbers on compressor */
		if(!rohc_comp_set_random_cb(comp, gen_false_random_num, NULL))
		{
			fprintf(stderr, "failed to set the callback for random numbers on "
			        "compressor\n");
			goto destroy_comp;
		}

		/* set the WLSB window width on compressor */
		if(!rohc_comp_set_wlsb_window_width(comp, wlsb_width))
		{
			fprintf(stderr, "failed to set the WLSB window width on compressor\n");
			goto destroy_comp;
		}

		/* reset list of RTP ports for compressor */
		if(!rohc_comp_reset_rtp_ports(comp))
		{
			fprintf(stderr, "failed to reset list of RTP ports for compressor\n");
			goto destroy_comp;
		}

		/* add some ports to the list of RTP ports */
		for(i = 0; i < NB_RTP_PORTS; i++)
		{
			if(!rohc_comp_add_rtp_port(comp, rtp_ports[i]))
			{
				fprintf(stderr, "failed to enable RTP port %u for compressor\n",
				        rtp_ports[i]);
				goto destroy_comp;
			}
		}
	}

	/* build the stream, and save it in the PCAP dump */
	for(counter = 1; counter <= max_packets; counter++)
	{
		const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
		const size_t payload_len = 20;
		const size_t packet_len = sizeof(struct ipv4_hdr) +
		                          sizeof(struct udphdr) +
		                          sizeof(struct rtphdr) +
		                          payload_len;
		size_t packet_offset = 0;
		uint8_t packet[ETHER_HDR_LEN + packet_len];

		const size_t rohc_max_len = packet_len * 2;
		uint8_t output[ETHER_HDR_LEN + rohc_max_len];
		uint8_t *const rohc_packet = output + ETHER_HDR_LEN;
		size_t rohc_len;

		struct pcap_pkthdr header = { .ts = { .tv_sec = 0, .tv_usec = 0 } };
		struct ipv4_hdr *ipv4;
		struct udphdr *udp;
		struct rtphdr *rtp;

		/* build IPv4 header */
		packet_offset += ETHER_HDR_LEN;
		ipv4 = (struct ipv4_hdr *) (packet + packet_offset);
		ipv4->version = 4;
		ipv4->ihl = 5;
		ipv4->tos = 0;
		ipv4->tot_len = htons(packet_len);
		ipv4->id = htons(42 + counter);
		ipv4->frag_off = 0;
		ipv4->ttl = 64;
		ipv4->protocol = IPPROTO_UDP;
		ipv4->check = 0;
		ipv4->saddr = htonl(0xc0a80001);
		ipv4->daddr = htonl(0xc0a80002);
		ipv4->check = ip_fast_csum((uint8_t *) ipv4, ipv4->ihl);

		/* build UDP header */
		packet_offset += sizeof(struct ipv4_hdr);
		udp = (struct udphdr *) (packet + packet_offset);
		udp->source = htons(1234);
		udp->dest = htons(1234);
		udp->len = htons(packet_len - sizeof(struct ipv4_hdr));
		udp->check = 0; /* UDP checksum disabled */

		/* build RTP header */
		packet_offset += sizeof(struct udphdr);
		rtp = (struct rtphdr *) (packet + packet_offset);
		rtp->version = 2;
		rtp->padding = 0;
		rtp->extension = 0;
		rtp->cc = 0;
		rtp->m = 0;
		rtp->pt = 0x72; /* speex */
		rtp->sn = htons(counter);
		rtp->timestamp = htonl(500000 + counter * 160);
		rtp->ssrc = htonl(0x42424242);

		/* build RTP payload */
		packet_offset += sizeof(struct rtphdr);
		for(size_t i = 0; i < payload_len; i++)
		{
			packet[packet_offset + i] = i % 0xff;
		}

		if(strcmp(stream_type, "comp") == 0)
		{
			/* compress packet */
			ret = rohc_compress3(comp, arrival_time,
			                     (unsigned char *) ipv4, packet_len,
			                     rohc_packet, rohc_max_len, &rohc_len);
			if(ret != ROHC_OK)
			{
				fprintf(stderr, "failed to compress packet #%lu\n", counter);
				goto destroy_comp;
			}

			/* build Linux cooked header */
			memset(output, 0, ETHER_HDR_LEN);
			output[ETHER_HDR_LEN - 2] = ROHC_ETHERTYPE & 0xff;
			output[ETHER_HDR_LEN - 1] = (ROHC_ETHERTYPE >> 8) & 0xff;

			/* write the packet in the PCAP dump */
			header.caplen = ETHER_HDR_LEN + rohc_len,
			header.len = ETHER_HDR_LEN + rohc_len,
			pcap_dump((u_char *) dumper, &header, output);
		}
		else
		{
			/* build Linux cooked header */
			memset(packet, 0, ETHER_HDR_LEN);
			packet[ETHER_HDR_LEN - 2] = 0x08;
			packet[ETHER_HDR_LEN - 1] = 0x00;

			/* write the packet in the PCAP dump */
			header.caplen = ETHER_HDR_LEN + packet_len,
			header.len = ETHER_HDR_LEN + packet_len,
			pcap_dump((u_char *) dumper, &header, packet);
		}
	}

	is_success = true;

destroy_comp:
	if(comp != NULL)
	{
		rohc_comp_free(comp);
	}
close_dumper:
	pcap_dump_close(dumper);
close_pcap:
	pcap_close(pcap);
error:
	return is_success;
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
                              const rohc_trace_entity_t entity __attribute__((unused)),
                              const int profile __attribute__((unused)),
                              const char *const format,
                              ...)
{
	const char *level_descrs[] =
	{
		[ROHC_TRACE_DEBUG]   = "DEBUG",
		[ROHC_TRACE_INFO]    = "INFO",
		[ROHC_TRACE_WARNING] = "WARNING",
		[ROHC_TRACE_ERROR]   = "ERROR"
	};

	if(level >= ROHC_TRACE_WARNING || is_verbose)
	{
		va_list args;
		fprintf(stdout, "[%s] ", level_descrs[level]);
		va_start(args, format);
		vfprintf(stdout, format, args);
		va_end(args);
	}
}


/**
 * @brief Generate a false random number for testing the ROHC library
 *
 * @param comp          The ROHC compressor
 * @param user_context  Should always be NULL
 * @return              Always 0
 */
static int gen_false_random_num(const struct rohc_comp *const comp,
                                void *const user_context)
{
	assert(comp != NULL);
	assert(user_context == NULL);
	return 0;
}

