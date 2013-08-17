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

#include "test.h"

#include "config.h" /* for HAVE_*_H and SCHED_SETSCHEDULER_PARAMS */

/* system includes */
#if HAVE_SCHED_H == 1
#  include <sched.h>
#endif
#if HAVE_SYS_MMAN_H == 1
#  include <sys/mman.h>
#endif
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
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>


/** The application version */
#define APP_VERSION "ROHC performance test application, version 0.1"

/** The maximal size for the ROHC packets */
#define MAX_ROHC_SIZE  (5 * 1024)

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

/** The minimum Ethernet length (in bytes) */
#define ETHER_FRAME_MIN_LEN  60

/** Whether the application runs in verbose mode or not */
static int is_verbose;

static void usage(void);

static int tune_env_for_perfs(void);

static int test_compression_perfs(char *filename,
                                  const int use_large_cid,
                                  const size_t wlsb_width,
                                  const unsigned int max_contexts,
                                  unsigned long *packet_count,
                                  unsigned long *overflows,
                                  unsigned long long *time_elapsed);
static int time_compress_packet(struct rohc_comp *comp,
                                unsigned long num_packet,
                                struct pcap_pkthdr header,
                                unsigned char *packet,
                                size_t link_len,
                                unsigned long long *time_elapsed);

static int test_decompression_perfs(char *filename,
                                    const int use_large_cid,
                                    const unsigned int max_contexts,
                                    unsigned long *packet_count,
                                    unsigned long *overflows,
                                    unsigned long long *time_elapsed);
static int time_decompress_packet(struct rohc_decomp *decomp,
                                  unsigned long num_packet,
                                  struct pcap_pkthdr header,
                                  unsigned char *packet,
                                  size_t link_len,
                                  const struct timespec arrival_time,
                                  unsigned long long *time_elapsed);

static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));

static int gen_false_random_num(const struct rohc_comp *const comp,
                                void *const user_context)
	__attribute__((nonnull(1)));



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
	char *cid_type = NULL;
	int wlsb_width = 4;
	char *test_type = NULL; /* the name of the test to perform */
	char *filename = NULL; /* the name of the PCAP capture used as input */
	bool use_large_cid;
	unsigned long packet_count = 0;
	unsigned long overflows = 0;
	unsigned long long time_elapsed = 0;
	int ret;
	unsigned long average;
	int i;
	int status = 1;

	/* set to quiet mode by default */
	is_verbose = 0;

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
			fprintf(stderr, APP_VERSION "\n");
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
		else if(cid_type == NULL)
		{
			/* get the type of CID to use within the ROHC library */
			cid_type = argv[0];
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
	if(test_type == NULL || filename == NULL)
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
	if(!strcmp(cid_type, "smallcid"))
	{
		use_large_cid = false;

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
		use_large_cid = true;

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
		usage();
		goto error;
	}

	/* tune environment for performance
	   (realtime priority, disable swapping...) */
	ret = tune_env_for_perfs();
	if(ret != 0)
	{
		fprintf(stderr, "failed to tune environment for performance\n");
		goto error;
	}

	if(strcmp(test_type, "compression") == 0)
	{
		/* test ROHC compression with the packets from the capture */
		ret = test_compression_perfs(filename, use_large_cid, wlsb_width, max_contexts,
		                             &packet_count, &overflows, &time_elapsed);
	}
	else if(strcmp(test_type, "decompression") == 0)
	{
		/* test ROHC decompression with the packets from the capture */
		ret = test_decompression_perfs(filename, use_large_cid, max_contexts,
		                               &packet_count, &overflows, &time_elapsed);
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
	fprintf(stderr, "total time elapsed               =  %lu * %lu + %lu ns\n",
	        0xffffffffUL, overflows, (unsigned long) time_elapsed);
	fprintf(stderr, "total number of packets          =  %lu packets\n",
	        packet_count);
	if(packet_count != 0)
	{
		average = time_elapsed / packet_count;
		for(i = 0; i < overflows; i++)
		{
			average += 0xffffffffUL / packet_count;
		}
	}
	else
	{
		average = 0;
	}
	fprintf(stderr, "average elapsed time per packet  =  %lu ns/packet\n",
	        average);

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
	fprintf(stderr,
		"ROHC performance test: test the performance of the ROHC library\n"
		"                       with a flow of IP packets\n"
		"\n"
		"usage: test_performance [-h|--help] [-v|--version] [de]compression (small|large)cid flow\n"
		"\n"
		"  --version               Print version information and exit\n"
		"  -v\n"
		"  --verbose               Tell the application to be more verbose\n"
		"  --help                  Print application usage and exit\n"
		"  -h\n"
		"  --wlsb-width NUM        The width of the WLSB window to use\n"
		"  --max-contexts NUM      The maximum number of ROHC contexts to\n"
		"                          simultaneously use during the test\n"
		"\n"
		"  flow  flow of Ethernet frames to (de)compress (PCAP format)\n");
}


/**
 * @brief Tune environment for performance
 *
 * Set high realtime priority.
 * Disable swapping.
 * Initialize CPU tics to nanoseconds coefficient.
 *
 * @return              0 in case of success, 1 otherwise
 */
static int tune_env_for_perfs(void)
{
#if HAVE_SCHED_H == 1 && SCHED_SETSCHEDULER_PARAMS == 3
	struct sched_param param;
#endif
#if HAVE_SCHED_H == 1 || HAVE_SYS_MMAN_H == 1
	int ret;
#endif

#if HAVE_SCHED_H == 1 && SCHED_SETSCHEDULER_PARAMS > 0
	/* set the process to realtime priority */
#if SCHED_SETSCHEDULER_PARAMS == 3
	memset(&param, 0, sizeof(struct sched_param));
	param.sched_priority = sched_get_priority_max(SCHED_FIFO);
	if(param.sched_priority == -1)
	{
		fprintf(stderr, "failed to get maximum scheduler priority: "
		        "%s (%d)\n", strerror(errno), errno);
		goto error;
	}
	ret = sched_setscheduler(0, SCHED_FIFO, &param);
#else /* SCHED_SETSCHEDULER_PARAMS != 3 */
	ret = sched_setscheduler(0, SCHED_FIFO);
#endif
	if(ret != 0)
	{
		fprintf(stderr, "failed to set high scheduler priority: %s (%d)\n",
		        strerror(errno), errno);
		goto error;
	}
#else
	fprintf(stderr, "do not set maximum scheduler priority: not implemented "
	        "for the platform yet\n");
#endif

#if HAVE_SYS_MMAN_H == 1
	/* avoid swapping */
	ret = mlockall(MCL_CURRENT | MCL_FUTURE);
	if(ret != 0)
	{
		fprintf(stderr, "failed to disable swapping: %s (%d)\n",
		        strerror(errno), errno);
		goto error;
	}
#else
	fprintf(stderr, "do not lock memory to avoid swapping: not implemented "
	        "for the platform yet\n");
#endif

	return 0;

#if HAVE_SCHED_H == 1 || HAVE_SYS_MMAN_H == 1
error:
	return 1;
#endif
}


/**
 * @brief Test the compression performance of the ROHC library
 *        with a flow of IP packets
 *
 * @param filename      The name of the PCAP file that contains the IP packets
 * @param use_large_cid Whether the compressor shall use large CIDs
 * @param wlsb_width    The width of the WLSB window to use
 * @param max_contexts  The maximum number of ROHC contexts to use
 * @param packet_count  OUT: the number of compressed packets, undefined if
 *                      compression failed
 * @param time_elapsed  OUT: the time elapsed for compression (in nanoseconds),
 *                      unchanged if compression failed
 * @return              0 in case of success, 1 otherwise
 */
static int test_compression_perfs(char *filename,
                                  const int use_large_cid,
                                  const size_t wlsb_width,
                                  const unsigned int max_contexts,
                                  unsigned long *packet_count,
                                  unsigned long *overflows,
                                  unsigned long long *time_elapsed)
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int link_layer_type;
	size_t link_len;
	struct pcap_pkthdr header;
	unsigned char *packet;
	struct rohc_comp *comp;
	int is_failure = 1;
	unsigned int i;
	int ret;

#define NB_RTP_PORTS 5
	const unsigned int rtp_ports[NB_RTP_PORTS] =
		{ 1234, 36780, 33238, 5020, 5002 };

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
	comp = rohc_alloc_compressor(max_contexts - 1, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC compressor\n");
		goto close_input;
	}

	/* set the callback for traces */
	if(!rohc_comp_set_traces_cb(comp, print_rohc_traces))
	{
		fprintf(stderr, "failed to set the callback for traces\n");
		goto free_compresssor;
	}

	/* set the callback for random numbers */
	if(!rohc_comp_set_random_cb(comp, gen_false_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
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
	rohc_c_set_large_cid(comp, use_large_cid);

	/* set the WLSB window width on compressor */
	if(!rohc_comp_set_wlsb_window_width(comp, wlsb_width))
	{
		fprintf(stderr, "failed to set the WLSB window width on compressor\n");
		goto free_compresssor;
	}

	/* reset list of RTP ports */
	if(!rohc_comp_reset_rtp_ports(comp))
	{
		fprintf(stderr, "failed to reset list of RTP ports\n");
		goto free_compresssor;
	}

	/* add some ports to the list of RTP ports */
	for(i = 0; i < NB_RTP_PORTS; i++)
	{
		if(!rohc_comp_add_rtp_port(comp, rtp_ports[i]))
		{
			fprintf(stderr, "failed to enable RTP port %u\n", rtp_ports[i]);
			goto free_compresssor;
		}
	}

	fflush(stderr);

	/* for each packet in the dump */
	*packet_count = 0;
	*time_elapsed = 0;
	*overflows = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		unsigned long long packet_time_elapsed = 0;

		(*packet_count)++;
		if((*packet_count) != 0 && ((*packet_count) % 50000) == 0)
		{
			fprintf(stderr, "packet #%lu\n", *packet_count);
			fflush(stderr);
		}

		/* compress the IP packet */
		ret = time_compress_packet(comp, *packet_count,
		                           header, packet, link_len,
		                           &packet_time_elapsed);
		if(ret != 0)
		{
			fprintf(stderr, "packet %lu: performance test failed\n",
			        *packet_count);
			goto free_compresssor;
		}

		if((*time_elapsed) > (0xffffffff - packet_time_elapsed))
		{
			(*overflows)++;
			packet_time_elapsed -= 0xffffffff - (*time_elapsed);
			*time_elapsed = packet_time_elapsed;
		}
		else
		{
			*time_elapsed += packet_time_elapsed;
		}
	}

	/* everything went fine */
	is_failure = 0;

free_compresssor:
	rohc_free_compressor(comp);
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
 * @param time_elapsed  OUT: the time elapsed for compression (in nanoseconds),
 *                      unchanged if compression failed
 * @return              0 if compression is successful, 1 otherwise
 */
static int time_compress_packet(struct rohc_comp *comp,
                                unsigned long num_packet,
                                struct pcap_pkthdr header,
                                unsigned char *packet,
                                size_t link_len,
                                unsigned long long *time_elapsed)
{
	const struct timespec arrival_time = { .tv_sec = 0, .tv_nsec = 0 };
	unsigned char *ip_packet;
	size_t ip_size;
	static unsigned char rohc_packet[MAX_ROHC_SIZE];
	size_t rohc_size;
	struct timespec start_tics;
	struct timespec end_tics;
	int is_failure = 1;
	int ret;

	/* check Ethernet frame length */
	if(header.len <= link_len || header.len != header.caplen)
	{
		fprintf(stderr, "packet %lu: bad PCAP packet "
		        "(len = %d, caplen = %d)\n",
		        num_packet, header.len, header.caplen);
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

		/* determine the total length of the IP packet */
		ip_version = (ip_packet[0] >> 4) & 0x0f;
		if(ip_version == 4) /* IPv4 */
		{
			struct ipv4_hdr *ip;

			ip = (struct ipv4_hdr *) ip_packet;
			tot_len = ntohs(ip->tot_len);
		}
		else if(ip_version == 6) /* IPv6 */
		{
			struct ipv6_hdr *ip;

			ip = (struct ipv6_hdr *) ip_packet;
			tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->ip6_plen);
		}
		else /* unknown IP version */
		{
			fprintf(stderr, "packet %lu: bad IP version (0x%x) "
			        "in packet\n", num_packet, ip_version);
			goto error;
		}

		/* update the length of the IP packet if padding is present */
		if(tot_len < ip_size)
		{
			fprintf(stderr, "packet %lu: the Ethernet frame has %zd "
			        "bytes of padding after the %u-byte IP packet!\n",
			        num_packet, ip_size - tot_len, tot_len);
			ip_size = tot_len;
		}
	}

	/* get CPU tics before compression */
	assert(clock_gettime(CLOCK_MONOTONIC_RAW, &start_tics) == 0);

	/* compress the packet */
	ret = rohc_compress3(comp, arrival_time, ip_packet, ip_size,
	                     rohc_packet, MAX_ROHC_SIZE, &rohc_size);

	/* get CPU tics after compression */
	assert(clock_gettime(CLOCK_MONOTONIC_RAW, &end_tics) == 0);

	/* stop performance test if compression failed */
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "packet %lu: compression failed\n", num_packet);
		goto error;
	}

	/* compute the time elapsed during the compression process */
	*time_elapsed = (end_tics.tv_sec - start_tics.tv_sec) * 1e9 +
	                end_tics.tv_nsec - start_tics.tv_nsec;

	/* everything went fine */
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Test the decompression performance of the ROHC library
 *        with a flow of IP packets
 *
 * @param filename      The name of the PCAP file that contains the ROHC packets
 * @param use_large_cid Whether the decompressor shall use large CIDs
 * @param max_contexts  The maximum number of ROHC contexts to use
 * @param packet_count  OUT: the number of decompressed packets, undefined if
 *                      decompression failed
 * @param time_elapsed  OUT: the time elapsed for decompression (in nanoseconds),
 *                      unchanged if decompression failed
 * @return              0 in case of success, 1 otherwise
 */
static int test_decompression_perfs(char *filename,
                                    const int use_large_cid,
                                    const unsigned int max_contexts,
                                    unsigned long *packet_count,
                                    unsigned long *overflows,
                                    unsigned long long *time_elapsed)
{
	const struct timespec arrival_time = { .tv_sec = 0, .tv_nsec = 0 };
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
	decomp = rohc_alloc_decompressor(NULL);
	if(decomp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC decompressor\n");
		goto close_input;
	}

	/* set trace callback for decompressor in verbose mode */
	if(!rohc_decomp_set_traces_cb(decomp, print_rohc_traces))
	{
		fprintf(stderr, "cannot set trace callback for decompressor\n");
		goto free_decompressor;
	}

	/* set CID type and MAX_CID for decompressor 1 */
	if(use_large_cid)
	{
		if(!rohc_decomp_set_cid_type(decomp, ROHC_LARGE_CID))
		{
			fprintf(stderr, "failed to set CID type to large CIDs for "
			        "decompressor\n");
			goto free_decompressor;
		}
		if(!rohc_decomp_set_max_cid(decomp, max_contexts - 1))
		{
			fprintf(stderr, "failed to set MAX_CID to %d for decompressor\n",
			        ROHC_LARGE_CID_MAX);
			goto free_decompressor;
		}
	}
	else
	{
		if(!rohc_decomp_set_cid_type(decomp, ROHC_SMALL_CID))
		{
			fprintf(stderr, "failed to set CID type to small CIDs for "
			        "decompressor\n");
			goto free_decompressor;
		}
		if(!rohc_decomp_set_max_cid(decomp, max_contexts - 1))
		{
			fprintf(stderr, "failed to set MAX_CID to %d for decompressor\n",
			        ROHC_SMALL_CID_MAX);
			goto free_decompressor;
		}
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
	*time_elapsed = 0;
	*overflows = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		unsigned long long packet_time_elapsed = 0;

		(*packet_count)++;
		if((*packet_count) != 0 && ((*packet_count) % 50000) == 0)
		{
			fprintf(stderr, "packet #%lu\n", *packet_count);
			fflush(stderr);
		}

		/* decompress the ROHC packet */
		ret = time_decompress_packet(decomp, *packet_count,
		                             header, packet, link_len, arrival_time,
		                             &packet_time_elapsed);
		if(ret != 0)
		{
			fprintf(stderr, "packet %lu: performance test failed\n",
			        *packet_count);
			goto free_decompressor;
		}

		if((*time_elapsed) > (0xffffffff - packet_time_elapsed))
		{
			(*overflows)++;
			packet_time_elapsed -= 0xffffffff - (*time_elapsed);
			*time_elapsed = packet_time_elapsed;
		}
		else
		{
			*time_elapsed += packet_time_elapsed;
		}
	}

	/* everything went fine */
	is_failure = 0;

free_decompressor:
	rohc_free_decompressor(decomp);
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
 * @param time_elapsed  OUT: the time elapsed for decompression (in nanoseconds),
 *                      unchanged if decompression failed
 * @return              0 if decompression is successful, 1 otherwise
 */
static int time_decompress_packet(struct rohc_decomp *decomp,
                                  unsigned long num_packet,
                                  struct pcap_pkthdr header,
                                  unsigned char *packet,
                                  size_t link_len,
                                  const struct timespec arrival_time,
                                  unsigned long long *time_elapsed)
{
	unsigned char *rohc_packet;
	unsigned int rohc_size;
	static unsigned char ip_packet[MAX_ROHC_SIZE];
	size_t ip_size;
	struct timespec start_tics;
	struct timespec end_tics;
	int is_failure = 1;
	int ret;

	/* check Ethernet frame length */
	if(header.len <= link_len || header.len != header.caplen)
	{
		fprintf(stderr, "packet %lu: bad PCAP packet "
		        "(len = %d, caplen = %d)\n",
		        num_packet, header.len, header.caplen);
		goto error;
	}

	/* skip the link layer header */
	rohc_packet = packet + link_len;
	rohc_size = header.len - link_len;

	/* get CPU tics before compression */
	assert(clock_gettime(CLOCK_MONOTONIC_RAW, &start_tics) == 0);

	/* decompress the packet */
	ret = rohc_decompress2(decomp, arrival_time, rohc_packet, rohc_size,
	                       ip_packet, MAX_ROHC_SIZE, &ip_size);

	/* get CPU tics after compression */
	assert(clock_gettime(CLOCK_MONOTONIC_RAW, &end_tics) == 0);

	/* stop performance test if decompression failed */
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "packet %lu: decompression failed\n", num_packet);
		goto error;
	}

	/* compute the time elapsed during the decompression process */
	*time_elapsed = (end_tics.tv_sec - start_tics.tv_sec) * 1e9 +
	                end_tics.tv_nsec - start_tics.tv_nsec;

	/* everything went fine */
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Print traces emitted by the ROHC library in verbose mode
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
	if(is_verbose)
	{
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

