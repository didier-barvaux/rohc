/*
 * Copyright 2010,2012,2013,2014 Didier Barvaux
 * Copyright 2010,2012,2013 Viveris Technologies
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
 * @file    test_performance.c
 * @brief   ROHC perf program
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author  Didier Barvaux <didier@barvaux.org>
 *
 * Introduction
 * ------------
 *
 * The program takes a flow of packets as input (in the PCAP format) and
 * tests the performance of the ROHC (de)compression library with them.
 *
 * Details
 * -------
 *
 * The program defines one (de)compressor and sends the flow of packets
 * through it. The time elapsed during the (de)compression of every packet
 * is determined. See the figure below.
 *
 *                            +----------------+
 *                            |                |
 *   IP / ROHC packets  ----> | (de)compressor | ---->  ROHC / IP packets
 *                        ^   |                |   ^
 *                        |   +----------------+   |
 *                        |                        |
 *                        |------------------------|
 *                               elapsed time
 *
 * Checks
 * ------
 *
 * The program checks for the status of the (de)compression process.
 *
 * Output
 * ------
 *
 * The program outputs the time elapsed for (de)compression all packets, the
 * number of (de)compressed packets and the average elapsed time per packet.
 */

#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <unistd.h>
#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
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
#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>


/** The application version */
#define APP_VERSION "ROHC performance test application, version 0.1"

/** The maximal size for the ROHC packets */
#define MAX_ROHC_SIZE  (5 * 1024)

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16U

/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14U

/** The minimum Ethernet length (in bytes) */
#define ETHER_FRAME_MIN_LEN  60U


static void usage(void);

static int test_compression_perfs(const bool is_verbose,
                                  char *filename,
                                  const rohc_cid_type_t cid_type,
                                  const size_t wlsb_width,
                                  const unsigned int max_contexts,
                                  unsigned long *packet_count);
static int time_compress_packet(struct rohc_comp *comp,
                                unsigned long num_packet,
                                struct pcap_pkthdr header,
                                unsigned char *packet,
                                size_t link_len);

static int test_decompression_perfs(const bool is_verbose,
                                    char *filename,
                                    const rohc_cid_type_t cid_type,
                                    const unsigned int max_contexts,
                                    unsigned long *packet_count);
static int time_decompress_packet(struct rohc_decomp *decomp,
                                  unsigned long num_packet,
                                  struct pcap_pkthdr header,
                                  unsigned char *packet,
                                  size_t link_len,
                                  const struct rohc_ts arrival_time);

static void print_rohc_traces(void *const is_verbose__,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 5, 6), nonnull(5)));

static int gen_false_random_num(const struct rohc_comp *const comp,
                                void *const user_context)
	__attribute__((nonnull(1)));

static bool rohc_comp_rtp_cb(const unsigned char *const ip,
                             const unsigned char *const udp,
                             const unsigned char *const payload,
                             const unsigned int payload_size,
                             void *const rtp_private)
	__attribute__((warn_unused_result));



/**
 * @brief Main function for the ROHC performance test program
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code: 0 in case of success, 1 in case of error,
 *             77 in case test is skipped
 */
int main(int argc, char *argv[])
{
	int max_contexts = ROHC_SMALL_CID_MAX + 1;
	char *cid_type_name = NULL;
	int wlsb_width = 4;
	char *test_type = NULL; /* the name of the test to perform */
	char *filename = NULL; /* the name of the PCAP capture used as input */
	rohc_cid_type_t cid_type;
	unsigned long packet_count = 0;
	bool is_verbose = false; /* set to quiet mode by default */
	int status = 1;
	int ret;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 2)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc--, argv++)
	{
		if(!strcmp(*argv, "-v") || !strcmp(*argv, "--version"))
		{
			/* print version */
			printf("rohc_test_perf version %s\n", rohc_version());
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
			is_verbose = true;
		}
		else if(!strcmp(*argv, "--max-contexts"))
		{
			/* get the maximum number of contexts the test should use */
			max_contexts = atoi(argv[1]);
			argv++;
			argc--;
		}
		else if(!strcmp(*argv, "--wlsb-width"))
		{
			/* get the width of the WLSB window the test should use */
			wlsb_width = atoi(argv[1]);
			argv++;
			argc--;
		}
		else if(test_type == 0)
		{
			/* get the name of the test */
			test_type = argv[0];
		}
		else if(cid_type_name == NULL)
		{
			/* get the type of CID to use within the ROHC library */
			cid_type_name = argv[0];
		}
		else if(filename == NULL)
		{
			/* get the name of the file that contains the IP packets
			   to compress */
			filename = argv[0];
		}
		else
		{
			/* do not accept more than one filename without option name */
			usage();
			goto error;
		}
	}

	/* the test type and source filename are mandatory */
	if(test_type == NULL || cid_type_name == NULL || filename == NULL)
	{
		usage();
		goto error;
	}

	/* check WLSB width */
	if(wlsb_width <= 0 || (wlsb_width & (wlsb_width - 1)) != 0)
	{
		fprintf(stderr, "invalid WLSB width %d: should be a positive power of "
		        "two\n", wlsb_width);
		goto error;
	}

	/* check CID type */
	if(!strcmp(cid_type_name, "smallcid"))
	{
		cid_type = ROHC_SMALL_CID;

		/* the maximum number of ROHC contexts should be valid */
		if(max_contexts < 1 || max_contexts > (ROHC_SMALL_CID_MAX + 1))
		{
			fprintf(stderr, "the maximum number of ROHC contexts should be "
			        "between 1 and %u\n\n", ROHC_SMALL_CID_MAX + 1);
			usage();
			goto error;
		}
	}
	else if(!strcmp(cid_type_name, "largecid"))
	{
		cid_type = ROHC_LARGE_CID;

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
		        "expected\n", cid_type_name);
		usage();
		goto error;
	}

	if(strcmp(test_type, "comp") == 0)
	{
		/* test ROHC compression with the packets from the capture */
		ret = test_compression_perfs(is_verbose, filename, cid_type, wlsb_width,
		                             max_contexts, &packet_count);
	}
	else if(strcmp(test_type, "decomp") == 0)
	{
		/* test ROHC decompression with the packets from the capture */
		ret = test_decompression_perfs(is_verbose, filename, cid_type,
		                               max_contexts, &packet_count);
	}
	else
	{
		fprintf(stderr, "unexpected test type '%s'\n", test_type);
		goto error;
	}

	/* check test status */
	if(ret != 0)
	{
		fprintf(stderr, "performance test failed, see above error(s)\n");
		goto error;
	}

	/* print performance statistics */
	fprintf(stderr, "%scompression: %lu packets\n",
	        (strcmp(test_type, "comp") == 0 ? "" : "de"), packet_count);

	/* everything went fine */
	status = 0;

error:
	return status;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	printf(
		"Test the performance of the ROHC library.\n"
		"\n"
		"Usage: rohc_test_performance [General options]\n"
		"   or: rohc_test_performance [ROHC options] ACTION CID_TYPE FLOW\n"
		"\n"
		"Options:\n"
		"Mandatory parameters:\n"
		"  ACTION            Run a compression test with 'comp' or a\n"
		"                    decompression test with 'decomp'\n"
		"  CID_TYPE          Run a small CID test with 'smallcid' or a\n"
		"                    large CID test with 'largecid'\n"
		"  FLOW              A flow of Ethernet frames to (de)compress\n"
		"                    (in PCAP format)\n"
		"General options:\n"
		"  -h, --help              Print application usage and exit\n"
		"  -v, --version           Print version information and exit\n"
		"ROHC options:\n"
		"      --verbose           Tell the application to be more verbose\n"
		"      --wlsb-width NUM    The width of the WLSB window to use\n"
		"      --max-contexts NUM  The maximum number of ROHC contexts to\n"
		"                          simultaneously use during the test\n"
		"\n"
		"Examples:\n"
		"  rohc_test_performance comp smallcid voip.pcap     test compression performances with small CIDs on the given VoIP stream\n"
		"  rohc_test_performance decomp largecid a.pcap      test decompression performances with large CIDs on the given stream\n"
		"\n"
		"Report bugs to <" PACKAGE_BUGREPORT ">.\n");
}


/**
 * @brief Test the compression performance of the ROHC library
 *        with a flow of IP packets
 *
 * @param is_verbose    Whether the test is run in verbose mode or not
 * @param filename      The name of the PCAP file that contains the IP packets
 * @param cid_type      The type of CIDs the compressor shall use
 * @param wlsb_width    The width of the WLSB window to use
 * @param max_contexts  The maximum number of ROHC contexts to use
 * @param packet_count  OUT: the number of compressed packets, undefined if
 *                      compression failed
 * @return              0 in case of success, 1 otherwise
 */
static int test_compression_perfs(const bool is_verbose,
                                  char *filename,
                                  const rohc_cid_type_t cid_type,
                                  const size_t wlsb_width,
                                  const unsigned int max_contexts,
                                  unsigned long *packet_count)
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int link_layer_type;
	size_t link_len;
	struct pcap_pkthdr header;
	unsigned char *packet;
	struct rohc_comp *comp;
	int is_failure = 1;
	int ret;

	assert(max_contexts > 0);

	/* open the PCAP file that contains the stream */
	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "failed to open the pcap file: %s\n", errbuf);
		goto exit;
	}

	/* link layer in the capture must be Ethernet */
	link_layer_type = pcap_datalink(handle);
	if(link_layer_type != DLT_EN10MB &&
	   link_layer_type != DLT_LINUX_SLL &&
	   link_layer_type != DLT_RAW)
	{
		fprintf(stderr, "link layer type %d not supported in capture "
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

	/* create ROHC compressor */
	comp = rohc_comp_new2(cid_type, max_contexts - 1, gen_false_random_num, NULL);
	if(comp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC compressor\n");
		goto close_input;
	}

	/* set the callback for traces */
	if(!rohc_comp_set_traces_cb2(comp, print_rohc_traces, (void *) &is_verbose))
	{
		fprintf(stderr, "failed to set the callback for traces\n");
		goto free_compresssor;
	}

	/* activate all the compression profiles */
	if(!rohc_comp_enable_profiles(comp, ROHC_PROFILE_UNCOMPRESSED,
	                              ROHC_PROFILE_RTP, ROHC_PROFILE_UDP,
	                              ROHC_PROFILE_IP, ROHC_PROFILE_UDPLITE,
	                              ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles\n");
		goto free_compresssor;
	}

	/* set the WLSB window width on compressor */
	if(!rohc_comp_set_wlsb_window_width(comp, wlsb_width))
	{
		fprintf(stderr, "failed to set the WLSB window width on compressor\n");
		goto free_compresssor;
	}

	/* set UDP ports dedicated to RTP traffic */
	if(!rohc_comp_set_rtp_detection_cb(comp, rohc_comp_rtp_cb, NULL))
	{
		fprintf(stderr, "failed to set the RTP detection callback on compressor\n");
		goto free_compresssor;
	}

	fflush(stderr);

	/* for each packet in the dump */
	*packet_count = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		(*packet_count)++;
		if((*packet_count) != 0 && ((*packet_count) % 100000) == 0)
		{
			fprintf(stderr, "compression: packet #%lu\r", *packet_count);
			fflush(stderr);
		}

		/* compress the IP packet */
		ret = time_compress_packet(comp, *packet_count,
		                           header, packet, link_len);
		if(ret != 0)
		{
			fprintf(stderr, "packet %lu: performance test failed\n",
			        *packet_count);
			goto free_compresssor;
		}
	}

	/* everything went fine */
	is_failure = 0;

free_compresssor:
	rohc_comp_free(comp);
close_input:
	pcap_close(handle);
exit:
	return is_failure;
}


/**
 * @brief Determine the time required to compress the given IP packet
 *        with the given compressor
 *
 * @param comp          The compressor to use to compress the IP packet
 * @param num_packet    A number affected to the IP packet to compress
 *                      (traces only)
 * @param header        The PCAP header for the packet
 * @param packet        The packet to compress (link layer included)
 * @param link_len      The length of the link layer header before IP data
 * @return              0 if compression is successful, 1 otherwise
 */
static int time_compress_packet(struct rohc_comp *comp,
                                unsigned long num_packet,
                                struct pcap_pkthdr header,
                                unsigned char *packet,
                                size_t link_len)
{
	/* the buffer that will contain the initial uncompressed packet */
	const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
	struct rohc_buf ip_packet =
		rohc_buf_init_full(packet, header.caplen, arrival_time);

	/* the buffer that will contain the compressed ROHC packet */
	uint8_t rohc_buffer[MAX_ROHC_SIZE];
	struct rohc_buf rohc_packet =
		rohc_buf_init_empty(rohc_buffer, MAX_ROHC_SIZE);

	int is_failure = 1;
	rohc_status_t status;

	/* check Ethernet frame length */
	if(header.len <= link_len || header.len != header.caplen)
	{
		fprintf(stderr, "packet %lu: bad PCAP packet (len = %u, caplen = %u)\n",
		        num_packet, header.len, header.caplen);
		goto error;
	}

	/* skip the link layer header */
	rohc_buf_pull(&ip_packet, link_len);

	/* check for padding after the IP packet in the Ethernet payload */
	if(link_len == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
	{
		uint8_t ip_version;
		uint16_t tot_len;

		/* determine the total length of the IP packet */
		ip_version = (rohc_buf_byte(ip_packet) >> 4) & 0x0f;
		if(ip_version == 4) /* IPv4 */
		{
			struct ipv4_hdr *ip;

			ip = (struct ipv4_hdr *) rohc_buf_data(ip_packet);
			tot_len = ntohs(ip->tot_len);
		}
		else if(ip_version == 6) /* IPv6 */
		{
			struct ipv6_hdr *ip;

			ip = (struct ipv6_hdr *) rohc_buf_data(ip_packet);
			tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->plen);
		}
		else /* unknown IP version */
		{
			fprintf(stderr, "packet %lu: bad IP version (0x%x) "
			        "in packet\n", num_packet, ip_version);
			goto error;
		}

		/* update the length of the IP packet if padding is present */
		if(tot_len < ip_packet.len)
		{
			fprintf(stderr, "packet %lu: the Ethernet frame has %zd "
			        "bytes of padding after the %u-byte IP packet!\n",
			        num_packet, ip_packet.len - tot_len, tot_len);
			ip_packet.len = tot_len;
		}
	}

	/* compress the packet */
	status = rohc_compress4(comp, ip_packet, &rohc_packet);
	if(status != ROHC_STATUS_OK)
	{
		fprintf(stderr, "packet %lu: compression failed\n", num_packet);
		goto error;
	}

	/* everything went fine */
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Test the decompression performance of the ROHC library
 *        with a flow of IP packets
 *
 * @param is_verbose    Whether the test is run in verbose mode or not
 * @param filename      The name of the PCAP file that contains the ROHC packets
 * @param cid_type      The type of CIDs the decompressor shall use
 * @param max_contexts  The maximum number of ROHC contexts to use
 * @param packet_count  OUT: the number of decompressed packets, undefined if
 *                      decompression failed
 * @return              0 in case of success, 1 otherwise
 */
static int test_decompression_perfs(const bool is_verbose,
                                    char *filename,
                                    const rohc_cid_type_t cid_type,
                                    const unsigned int max_contexts,
                                    unsigned long *packet_count)
{
	const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int link_layer_type;
	size_t link_len;
	struct pcap_pkthdr header;
	unsigned char *packet;
	struct rohc_decomp *decomp;
	int is_failure = 1;
	int ret;

	assert(max_contexts > 0);

	/* open the PCAP file that contains the stream */
	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "failed to open the pcap file: %s\n", errbuf);
		goto exit;
	}

	/* link layer in the capture must be Ethernet */
	link_layer_type = pcap_datalink(handle);
	if(link_layer_type != DLT_EN10MB &&
	   link_layer_type != DLT_LINUX_SLL &&
	   link_layer_type != DLT_RAW)
	{
		fprintf(stderr, "link layer type %d not supported in capture "
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

	/* create ROHC decompressor */
	decomp = rohc_decomp_new2(cid_type, max_contexts - 1, ROHC_U_MODE);
	if(decomp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC decompressor\n");
		goto close_input;
	}

	/* set trace callback for decompressor in verbose mode */
	if(!rohc_decomp_set_traces_cb2(decomp, print_rohc_traces, (void *) &is_verbose))
	{
		fprintf(stderr, "cannot set trace callback for decompressor\n");
		goto free_decompressor;
	}

	/* activate all the decompression profiles */
	if(!rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_UNCOMPRESSED,
	                                ROHC_PROFILE_RTP, ROHC_PROFILE_UDP,
	                                ROHC_PROFILE_IP, ROHC_PROFILE_UDPLITE,
	                                ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the decompression profiles\n");
		goto free_decompressor;
	}

	fflush(stderr);

	/* for each packet in the dump */
	*packet_count = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		(*packet_count)++;
		if((*packet_count) != 0 && ((*packet_count) % 100000) == 0)
		{
			fprintf(stderr, "decompression: packet #%lu\r", *packet_count);
			fflush(stderr);
		}

		/* decompress the ROHC packet */
		ret = time_decompress_packet(decomp, *packet_count,
		                             header, packet, link_len, arrival_time);
		if(ret != 0)
		{
			fprintf(stderr, "packet %lu: performance test failed\n",
			        *packet_count);
			goto free_decompressor;
		}
	}

	/* everything went fine */
	is_failure = 0;

free_decompressor:
	rohc_decomp_free(decomp);
close_input:
	pcap_close(handle);
exit:
	return is_failure;
}


/**
 * @brief Determine the time required to decompress the given ROHC packet
 *        with the given decompressor
 *
 * @param decomp        The decompressor to use to decompress the ROHC packet
 * @param num_packet    A number affected to the ROHC packet to decompress
 *                      (traces only)
 * @param header        The PCAP header for the packet
 * @param packet        The packet to decompress (link layer included)
 * @param link_len      The length of the link layer header before ROHC data
 * @return              0 if decompression is successful, 1 otherwise
 */
static int time_decompress_packet(struct rohc_decomp *decomp,
                                  unsigned long num_packet,
                                  struct pcap_pkthdr header,
                                  unsigned char *packet,
                                  size_t link_len,
                                  const struct rohc_ts arrival_time)
{
	/* the buffer that will contain the compressed ROHC packet */
	struct rohc_buf rohc_packet =
		rohc_buf_init_full(packet, header.caplen, arrival_time);

	/* the buffer that will contain the uncompressed packet */
	uint8_t ip_buffer[MAX_ROHC_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, MAX_ROHC_SIZE);

	int is_failure = 1;
	rohc_status_t status;

	/* check Ethernet frame length */
	if(header.len <= link_len || header.len != header.caplen)
	{
		fprintf(stderr, "packet %lu: bad PCAP packet (len = %u, caplen = %u)\n",
		        num_packet, header.len, header.caplen);
		goto error;
	}

	/* skip the link layer header */
	rohc_buf_pull(&rohc_packet, link_len);

	/* decompress the packet */
	status = rohc_decompress3(decomp, rohc_packet, &ip_packet, NULL, NULL);
	if(status != ROHC_STATUS_OK)
	{
		fprintf(stderr, "packet %lu: decompression failed\n", num_packet);
		goto error;
	}

	/* everything went fine */
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Print traces emitted by the ROHC library in verbose mode
 *
 * @param is_verbose__  Whether the test run in verbose mode or not
 * @param level         The priority level of the trace
 * @param entity        The entity that emitted the trace among:
 *                      \li ROHC_TRACE_COMP
 *                      \li ROHC_TRACE_DECOMP
 * @param profile       The ID of the ROHC compression/decompression profile
 *                      the trace is related to
 * @param format        The format string of the trace
 */
static void print_rohc_traces(void *const is_verbose__,
                              const rohc_trace_level_t level __attribute__((unused)),
                              const rohc_trace_entity_t entity __attribute__((unused)),
                              const int profile __attribute__((unused)),
                              const char *const format,
                              ...)
{
	const bool *const is_verbose = (bool *) is_verbose__;

	if(*is_verbose)
	{
		va_list args;
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	}
}


/**
 * @brief Generate a false random number for testing the ROHC library
 *
 * We want to test the performances of the ROHC library, not the performances
 * of a random generator, so disable it.
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

