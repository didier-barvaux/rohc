/*
 * Copyright 2010,2012,2013,2014 Didier Barvaux
 * Copyright 2012,2017 Viveris Technologies
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
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h> /* for INT_MAX */

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
#include <rohc_decomp.h>


/** The device MTU */
#define DEV_MTU  0xffffU

/** The maximal size for the ROHC packets */
#define MAX_ROHC_SIZE  (DEV_MTU + 100U)

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16U

/** The length (in bytes) of the Ethernet address */
#define ETH_ALEN  6U

/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14U

/** The minimum Ethernet length (in bytes) */
#define ETHER_FRAME_MIN_LEN  60U

/** The 10Mb/s ethernet header */
struct ether_header
{
	uint8_t ether_dhost[ETH_ALEN];  /**< destination eth addr */
	uint8_t ether_shost[ETH_ALEN];  /**< source ether addr */
	uint16_t ether_type;            /**< packet type ID field */
} __attribute__((__packed__));

/** The Ethertype for the 802.1q protocol (VLAN) */
#define ETHERTYPE_8021Q   0x8100U
/** The Ethertype for the 802.1ad protocol */
#define ETHERTYPE_8021AD  0x88a8U

/** The VLAN header */
struct vlan_hdr
{
	uint16_t vid;  /**< The PCP, DEI and VID fields */
	uint16_t type; /**< The Ethertype of the next header */
} __attribute__((packed));


/** Whether the application runs in verbose mode or not */
static enum
{
	VERBOSITY_NONE,
	VERBOSITY_NORMAL,
	VERBOSITY_FULL
} verbosity = VERBOSITY_NORMAL;


/* prototypes of private functions */
static void usage(void);

static int generate_dummy_stats_all(const char *source,
                                    const size_t max_pkts_nr)
	__attribute__((warn_unused_result, nonnull(1)));
static int generate_dummy_stats_one(const unsigned long num_packet,
                                    const struct pcap_pkthdr header,
                                    const unsigned char *packet,
                                    size_t link_len)
	__attribute__((warn_unused_result, nonnull(3)));

static int generate_comp_stats_all(const rohc_cid_type_t cid_type,
                                   const unsigned int max_contexts,
                                   const char *source,
                                   const size_t max_pkts_nr)
	__attribute__((warn_unused_result, nonnull(3)));
static int generate_comp_stats_one(struct rohc_comp *comp,
                                   const unsigned long num_packet,
                                   const struct pcap_pkthdr header,
                                   const unsigned char *packet,
                                   size_t link_len)
	__attribute__((warn_unused_result, nonnull(1, 4)));

static int generate_decomp_stats_all(const rohc_cid_type_t cid_type,
                                     const unsigned int max_contexts,
                                     const char *source,
                                     const size_t max_pkts_nr)
	__attribute__((warn_unused_result, nonnull(3)));
static int generate_decomp_stats_one(struct rohc_decomp *const decomp,
                                     const unsigned long num_packet,
                                     const struct pcap_pkthdr header,
                                     const unsigned char *packet,
                                     size_t link_len)
	__attribute__((warn_unused_result, nonnull(1, 4)));

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

static bool detect_vlan_hdrs(const struct rohc_buf *const frame,
                             size_t *const link_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));


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
	char *test_type = NULL; /* the name of the test to perform */
	char *cid_type_name = NULL;
	char *source_descr = NULL;
	int status = 1;
	int max_contexts = ROHC_SMALL_CID_MAX + 1;
	int max_pkts_nr = 0; /* 0 means all PCAP file or infinite for live capture */
	size_t max_possible_contexts = ROHC_SMALL_CID_MAX + 1;
	rohc_cid_type_t cid_type = ROHC_SMALL_CID;
	int args_used;

	/* set to normal mode by default */
	verbosity = VERBOSITY_NORMAL;

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
		else if(!strcmp(*argv, "--verbose"))
		{
			/* be more verbose */
			verbosity = VERBOSITY_FULL;
		}
		else if(!strcmp(*argv, "--quiet"))
		{
			/* be more quiet */
			verbosity = VERBOSITY_NONE;
		}
		else if(!strcmp(*argv, "--max-contexts"))
		{
			/* get the maximum number of contexts the test should use */
			if(argc <= 1)
			{
				fprintf(stderr, "missing mandatory --max-contexts parameter\n");
				usage();
				goto error;
			}
			max_contexts = atoi(argv[1]);
			args_used++;
		}
		else if(!strcmp(*argv, "--max-pkts-nr"))
		{
			/* get the maximum number of packets the test should (de)compress */
			if(argc <= 1)
			{
				fprintf(stderr, "missing mandatory --max-pkts-nr parameter\n");
				usage();
				goto error;
			}
			max_pkts_nr = atoi(argv[1]);
			args_used++;
		}
		else if(test_type == NULL)
		{
			/* get the name of the test */
			test_type = argv[0];
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
		else if(source_descr == NULL)
		{
			/* get the source of packets: either the name of the file that contains
			 * the packets to compress, or the name of the network device to
			 * live capture packets from */
			source_descr = argv[0];
		}
		else
		{
			/* do not accept more than one filename without option name */
			usage();
			goto error;
		}
	}

	/* check test type */
	if(test_type == NULL)
	{
		fprintf(stderr, "parameter TEST_TYPE is mandatory\n");
		usage();
		goto error;
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

	/* handling a negative number of packets is not possible (0 is a value
	 * meaning all the packets found in the PCAP file, or infinite for live
	 * mode) */
	if(max_pkts_nr < 0)
	{
		fprintf(stderr, "the maximum number of packets should be "
		        "between 0 and %d\n\n", INT_MAX);
		usage();
		goto error;
	}

	/* the source is mandatory */
	if(source_descr == NULL)
	{
		fprintf(stderr, "source is mandatory\n");
		usage();
		goto error;
	}

	/* generate ROHC (de)compression statistics with the packets from the source */
	if(strcmp(test_type, "dummy") == 0)
	{
		/* do nothing with the packets from the capture to estimate program overhead */
		status = generate_dummy_stats_all(source_descr, max_pkts_nr);
	}
	else if(strcmp(test_type, "comp") == 0)
	{
		/* test ROHC compression with the packets from the capture */
		status = generate_comp_stats_all(cid_type, max_contexts, source_descr,
		                                 max_pkts_nr);
	}
	else if(strcmp(test_type, "decomp") == 0)
	{
		/* test ROHC decompression with the packets from the capture */
		status = generate_decomp_stats_all(cid_type, max_contexts, source_descr,
		                                   max_pkts_nr);
	}
	else
	{
		fprintf(stderr, "unexpected test type '%s'\n", test_type);
		goto error;
	}

error:
	return status;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	printf("The ROHC stats tool generates statistics about ROHC (de)compression\n"
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
	       "Usage: rohc_stats [OPTIONS] ACTION CID_TYPE SOURCE\n"
	       "\n"
	       "Options:\n"
	       "  -v, --version           Print version information and exit\n"
	       "  -h, --help              Print this usage and exit\n"
	       "      --verbose           Be more verbose\n"
	       "      --quiet             Tell the application to be even less verbose\n"
	       "      --max-contexts NUM  The maximum number of ROHC contexts to\n"
	       "                          simultaneously use during the test\n"
	       "      --max-pkts-nr NUM   The maximum number of packets to (de)compress\n"
	       "                          (0 means all packets from file or infinite for\n"
	       "                           network device)\n"
	       "\n"
	       "With:\n"
	       "  ACTION    Run a dummy test with 'dummy',\n"
	       "            a compression test with 'comp', or\n"
	       "            a decompression test with 'decomp'\n"
	       "  CID_TYPE  The type of CID to use among 'smallcid'\n"
	       "            and 'largecid'\n"
	       "  SOURCE    The source of of Ethernet frames to compress, ie:\n"
	       "              - the name of a file in PCAP format\n"
	       "              - the name of a network device\n"
	       "\n"
	       "Examples:\n"
	       "  rohc_stats comp smallcid /tmp/rtp.pcap  Generate statistics from a file\n"
	       "  rohc_stats decomp largecid ~/lan.pcap   Generate statistics from a file\n"
	       "  rohc_stats comp largecid eth0           Generate statistics from Ethernet device 'eth0'\n"
	       "\n"
	       "Report bugs to <" PACKAGE_BUGREPORT ">.\n");
}


/**
 * @brief Generate dummy statistics with a flow of IP packets
 *
 * @param source         The source of IP packets
 * @param max_pkts_nr    The maximum number of packets to compress
 * @return               0 in case of success,
 *                       1 in case of failure
 */
static int generate_dummy_stats_all(const char *source,
                                    const size_t max_pkts_nr)
{
	struct stat source_stat;
	int ret;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	unsigned long num_packet;
	struct pcap_pkthdr header;
	unsigned char *packet;

	int is_failure = 1;

	/* open the source */
	ret = stat(source, &source_stat);
	if(ret != 0 && errno != ENOENT)
	{
		fprintf(stderr, "failed to get information for file '%s': %s (%d)\n",
		        source, strerror(errno), errno);
		goto error;
	}
	else if(ret != 0 && errno == ENOENT)
	{
		/* open the network device */
		handle = pcap_open_live(source, DEV_MTU, 0, 0, errbuf);
		if(handle == NULL)
		{
			fprintf(stderr, "failed to open network device '%s': %s",
			        source, errbuf);
			goto error;
		}
	}
	else
	{
		/* open the source PCAP file */
		handle = pcap_open_offline(source, errbuf);
		if(handle == NULL)
		{
			fprintf(stderr, "failed to open the source pcap file: %s\n", errbuf);
			goto error;
		}
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

	/* output the statistics columns names */
	if(verbosity != VERBOSITY_NONE)
	{
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
	}

	/* for each packet extracted from the PCAP file or live capture,
	 * up to max_pkts_nr packets */
	num_packet = 0;
	while((max_pkts_nr == 0 || num_packet < max_pkts_nr) &&
	      (packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		num_packet++;

		/* do nothing with the packet and generate statistics */
		ret = generate_dummy_stats_one(num_packet, header, packet, link_len);
		if(ret != 0)
		{
			fprintf(stderr, "packet %lu: failed to generate stats for packet\n",
			        num_packet);
			goto close_input;
		}
	}

	/* everything went fine */
	is_failure = 0;

close_input:
	pcap_close(handle);
error:
	return is_failure;
}


/**
 * @brief Generate dummy statistics for one single IP packet
 *
 * @param num_packet  A number affected to the IP packet to compress
 * @param header      The PCAP header for the packet
 * @param packet      The packet to compress (link layer included)
 * @param link_len    The length of the link layer header before IP data
 * @return            0 in case of success,
 *                    1 in case of failure
 */
static int generate_dummy_stats_one(const unsigned long num_packet,
                                    const struct pcap_pkthdr header,
                                    const unsigned char *packet,
                                    size_t link_len)
{
	struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
	struct rohc_buf ip_packet =
		rohc_buf_init_full((unsigned char *) packet, header.caplen, arrival_time);

	/* check frame length */
	if(header.len <= link_len || header.len != header.caplen)
	{
		fprintf(stderr, "packet #%lu: bad PCAP packet (len = %u, caplen = %u)\n",
		        num_packet, header.len, header.caplen);
		goto error;
	}

	/* skip the link layer header (including VLAN headers) */
	if(!detect_vlan_hdrs(&ip_packet, &link_len))
	{
		fprintf(stderr, "packet #%lu: malformed VLAN header\n", num_packet);
		goto error;
	}
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
			tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->plen);
		}

		if(tot_len < ip_packet.len)
		{
			/* the Ethernet frame has some bytes of padding after the IP packet */
			ip_packet.len = tot_len;
		}
	}

	if(verbosity != VERBOSITY_NONE)
	{
		/* output some statistics about the last compressed packet */
		printf("STAT\t%lu\t0\tunknown\t0\tunknown\t14\tunknown\t%zu\t0\t%zu\t0\n",
		       num_packet, ip_packet.len, ip_packet.len);
		fflush(stdout);
	}

	return 0;

error:
	return 1;
}


/**
 * @brief Generate ROHC compression statistics with a flow of IP packets
 *
 * @param cid_type       The type of CIDs the compressor shall use
 * @param max_contexts   The maximum number of ROHC contexts to use
 * @param source         The source of IP packets
 * @param max_pkts_nr    The maximum number of packets to compress
 * @return               0 in case of success,
 *                       1 in case of failure
 */
static int generate_comp_stats_all(const rohc_cid_type_t cid_type,
                                   const unsigned int max_contexts,
                                   const char *source,
                                   const size_t max_pkts_nr)
{
	struct stat source_stat;
	int ret;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_comp *comp;

	unsigned long num_packet;
	struct pcap_pkthdr header;
	unsigned char *packet;

	int is_failure = 1;

	/* open the source */
	ret = stat(source, &source_stat);
	if(ret != 0 && errno != ENOENT)
	{
		fprintf(stderr, "failed to get information for file '%s': %s (%d)\n",
		        source, strerror(errno), errno);
		goto error;
	}
	else if(ret != 0 && errno == ENOENT)
	{
		/* open the network device */
		handle = pcap_open_live(source, DEV_MTU, 0, 0, errbuf);
		if(handle == NULL)
		{
			fprintf(stderr, "failed to open network device '%s': %s",
			        source, errbuf);
			goto error;
		}
	}
	else
	{
		/* open the source PCAP file */
		handle = pcap_open_offline(source, errbuf);
		if(handle == NULL)
		{
			fprintf(stderr, "failed to open the source pcap file: %s\n", errbuf);
			goto error;
		}
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

	/* enable traces in verbose mode */
	if(verbosity == VERBOSITY_FULL)
	{
		/* set the callback for traces on compressor */
		if(!rohc_comp_set_traces_cb2(comp, print_rohc_traces, NULL))
		{
			fprintf(stderr, "failed to set the callback for traces on "
			        "compressor\n");
			goto destroy_comp;
		}
	}

	/* enable periodic refreshes based on inter-packet delay */
	if(!rohc_comp_set_features(comp, ROHC_COMP_FEATURE_TIME_BASED_REFRESHES))
	{
		fprintf(stderr, "failed to enable periodic refreshes of contexts based "
		        "on inter-packet delay\n");
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
		goto destroy_comp;
	}

	/* output the statistics columns names */
	if(verbosity != VERBOSITY_NONE)
	{
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
	}

	/* for each packet extracted from the PCAP file or live capture,
	 * up to max_pkts_nr packets */
	num_packet = 0;
	while((max_pkts_nr == 0 || num_packet < max_pkts_nr) &&
	      (packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
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
 * @brief Generate ROHC compression statistics for one single IP packet
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
                                   size_t link_len)
{
	const struct rohc_ts arrival_time = {
		.sec = header.ts.tv_sec,
		.nsec = header.ts.tv_usec * 1000
	};
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
		fprintf(stderr, "packet #%lu: bad PCAP packet (len = %u, caplen = %u)\n",
		        num_packet, header.len, header.caplen);
		goto error;
	}

	/* skip the link layer header (including VLAN headers) */
	if(!detect_vlan_hdrs(&ip_packet, &link_len))
	{
		fprintf(stderr, "packet #%lu: malformed VLAN header\n", num_packet);
		goto error;
	}
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
			tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->plen);
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

	if(verbosity != VERBOSITY_NONE)
	{
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
	}

	return 0;

error:
	return 1;
}


/**
 * @brief Generate ROHC decompression statistics with a flow of ROHC packets
 *
 * @param cid_type       The type of CIDs the compressor shall use
 * @param max_contexts   The maximum number of ROHC contexts to use
 * @param source         The source of ROHC packets
 * @param max_pkts_nr    The maximum number of packets to decompress
 * @return               0 in case of success,
 *                       1 in case of failure
 */
static int generate_decomp_stats_all(const rohc_cid_type_t cid_type,
                                     const unsigned int max_contexts,
                                     const char *source,
                                     const size_t max_pkts_nr)
{
	struct stat source_stat;
	int ret;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_decomp *decomp;

	unsigned long num_packet;
	struct pcap_pkthdr header;
	unsigned char *packet;

	int is_failure = 1;

	/* open the source */
	ret = stat(source, &source_stat);
	if(ret != 0 && errno != ENOENT)
	{
		fprintf(stderr, "failed to get information for file '%s': %s (%d)\n",
		        source, strerror(errno), errno);
		goto error;
	}
	else if(ret != 0 && errno == ENOENT)
	{
		/* open the network device */
		handle = pcap_open_live(source, DEV_MTU, 0, 0, errbuf);
		if(handle == NULL)
		{
			fprintf(stderr, "failed to open network device '%s': %s",
			        source, errbuf);
			goto error;
		}
	}
	else
	{
		/* open the source PCAP file */
		handle = pcap_open_offline(source, errbuf);
		if(handle == NULL)
		{
			fprintf(stderr, "failed to open the source pcap file: %s\n", errbuf);
			goto error;
		}
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

	/* create the ROHC decompressor */
	decomp = rohc_decomp_new2(cid_type, max_contexts - 1, ROHC_U_MODE);
	if(decomp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC decompressor\n");
		goto close_input;
	}

	/* enable traces in verbose mode */
	if(verbosity == VERBOSITY_FULL)
	{
		/* set the callback for traces on decompressor */
		if(!rohc_decomp_set_traces_cb2(decomp, print_rohc_traces, NULL))
		{
			fprintf(stderr, "failed to set the callback for traces on "
			        "decompressor\n");
			goto destroy_decomp;
		}

		/* enable packet dump only in verbose mode */
		if(!rohc_decomp_set_features(decomp, ROHC_DECOMP_FEATURE_DUMP_PACKETS))
		{
			fprintf(stderr, "failed to enable packet dumps\n");
			goto destroy_decomp;
		}
	}

	/* enable profiles */
	if(!rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_UNCOMPRESSED,
	                                ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                                ROHC_PROFILE_RTP, ROHC_PROFILE_ESP,
	                                ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the decompression profiles\n");
		goto destroy_decomp;
	}

	/* output the statistics columns names */
	if(verbosity != VERBOSITY_NONE)
	{
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
	}

	/* for each packet extracted from the PCAP file or live capture,
	 * up to max_pkts_nr packets */
	num_packet = 0;
	while((max_pkts_nr == 0 || num_packet < max_pkts_nr) &&
	      (packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		num_packet++;

		/* decompress the packet and generate statistics */
		ret = generate_decomp_stats_one(decomp, num_packet, header, packet, link_len);
		if(ret != 0)
		{
			fprintf(stderr, "packet %lu: failed to decompress or generate stats "
			        "for packet\n", num_packet);
			goto destroy_decomp;
		}
	}

	/* everything went fine */
	is_failure = 0;

destroy_decomp:
	rohc_decomp_free(decomp);
close_input:
	pcap_close(handle);
error:
	return is_failure;
}


/**
 * @brief Generate ROHC decompression statistics for one single IP packet
 *
 * @param comp        The compressor to use to compress the ROHC packet
 * @param num_packet  A number affected to the ROHC packet to compress
 * @param header      The PCAP header for the packet
 * @param packet      The packet to compress (link layer included)
 * @param link_len    The length of the link layer header before ROHC data
 * @return            0 in case of success,
 *                    1 in case of failure
 */
static int generate_decomp_stats_one(struct rohc_decomp *const decomp,
                                     const unsigned long num_packet,
                                     const struct pcap_pkthdr header,
                                     const unsigned char *packet,
                                     size_t link_len)
{
	const struct rohc_ts arrival_time = {
		.sec = header.ts.tv_sec,
		.nsec = header.ts.tv_usec * 1000
	};
	struct rohc_buf rohc_packet =
		rohc_buf_init_full((unsigned char *) packet, header.caplen, arrival_time);
	uint8_t ip_buffer[MAX_ROHC_SIZE];
	struct rohc_buf ip_packet =
		rohc_buf_init_empty(ip_buffer, MAX_ROHC_SIZE);
	rohc_decomp_last_packet_info_t last_packet_info;
	rohc_status_t status;

	/* check frame length */
	if(header.len <= link_len || header.len != header.caplen)
	{
		fprintf(stderr, "packet #%lu: bad PCAP packet (len = %u, caplen = %u)\n",
		        num_packet, header.len, header.caplen);
		goto error;
	}

	/* skip the link layer header (including VLAN headers) */
	if(!detect_vlan_hdrs(&rohc_packet, &link_len))
	{
		fprintf(stderr, "packet #%lu: malformed VLAN header\n", num_packet);
		goto error;
	}
	rohc_buf_pull(&rohc_packet, link_len);

	/* decompress the IP packet */
	status = rohc_decompress3(decomp, rohc_packet, &ip_packet, NULL, NULL);
	if(status != ROHC_STATUS_OK)
	{
		fprintf(stderr, "packet #%lu: compression failed\n", num_packet);
		goto error;
	}

	if(verbosity != VERBOSITY_NONE)
	{
		/* get some statistics about the last decompressed packet */
		last_packet_info.version_major = 0;
		last_packet_info.version_minor = 2;
		if(!rohc_decomp_get_last_packet_info(decomp, &last_packet_info))
		{
			fprintf(stderr, "packet #%lu: cannot get stats about the last "
			        "decompressed packet\n", num_packet);
			goto error;
		}

		/* output some statistics about the last decompressed packet */
		printf("STAT\t%lu\t%d\t%s\t%d\t%s\t%d\t%s\t%lu\t%lu\t%lu\t%lu\n",
		       num_packet,
		       last_packet_info.context_mode,
		       rohc_get_mode_descr(last_packet_info.context_mode),
		       last_packet_info.context_state,
		       rohc_decomp_get_state_descr(last_packet_info.context_state),
		       last_packet_info.packet_type,
		       rohc_get_packet_descr(last_packet_info.packet_type),
		       last_packet_info.total_last_uncomp_size,
		       last_packet_info.header_last_uncomp_size,
		       last_packet_info.total_last_comp_size,
		       last_packet_info.header_last_comp_size);
		fflush(stdout);
	}

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


/**
 * @brief Detect 802.1q and 802.1ad headers
 *
 * @param frame             The frame in which VLAN headers shall be detected
 * @param[in,out] link_len  in: the length of the link layer identified yet
 *                          out: the length of the link layer including VLAN headers
 * @return                  false if VLAN are malformed, true otherwise
 */
static bool detect_vlan_hdrs(const struct rohc_buf *const frame,
                             size_t *const link_len)
{
	if((*link_len) == ETHER_HDR_LEN)
	{
		const struct ether_header *const eth_header =
			(struct ether_header *) rohc_buf_data(*frame);
		uint16_t proto_type = ntohs(eth_header->ether_type);

		/* skip all 802.1q or 802.1ad headers */
		while(proto_type == ETHERTYPE_8021Q || proto_type == ETHERTYPE_8021AD)
		{
			if(verbosity == VERBOSITY_FULL)
			{
				fprintf(stderr, "found one 802.1q or 802.1ad header\n");
			}

			/* check min length */
			if(frame->len < (*link_len) + sizeof(struct vlan_hdr))
			{
				fprintf(stderr, "truncated %zu-byte 802.1q or 802.1ad frame\n",
				        frame->len);
				goto error;
			}

			/* detect next header */
			const struct vlan_hdr *const vlan_hdr =
				(struct vlan_hdr *) rohc_buf_data_at(*frame, (*link_len));
			proto_type = ntohs(vlan_hdr->type);

			/* skip VLAN header */
			(*link_len) += sizeof(struct vlan_hdr);
		}
	}

	return true;

error:
	return false;
}

