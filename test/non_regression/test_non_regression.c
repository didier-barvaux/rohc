/*
 * Copyright 2010,2011,2012,2013,2014,2017 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2014,2017 Viveris Technologies
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
 * @file   test_non_regression.c
 * @brief  ROHC non-regression test program
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 *
 * Introduction
 * ------------
 *
 * The program takes a flow of IP packets as input (in the PCAP format) and
 * tests the ROHC compression/decompression library with them. The program
 * also tests the feedback mechanism.
 *
 * Details
 * -------
 *
 * The program defines two compressor/decompressor pairs and sends the flow
 * of IP packet through Compressor 1 and Decompressor 1 (flow A) and through
 * Compressor 2 and Decompressor 2 (flow B). See the figure below.
 *
 * The feedback for flow A is sent by Decompressor 1 to Compressor 1 via
 * Compressor 2 and Decompressor 2. The feedback for flow  B is sent by
 * Decompressor 2 to Compressor 2 via Compressor 1 and Decompressor 1.
 *
 *          +-- IP packets                             IP packets <--+
 *          |   flow A (input)                    flow A (output)    |
 *          |                                                        |
 *          |    +----------------+    ROHC    +----------------+    |
 *          +--> |                |            |                | ---+
 *               |  Compressor 1  | ---------> | Decompressor 1 |
 *          +--> |                |            |                | ---+
 *          |    +----------------+            +----------------+    |
 * feedback |                                                        | feedback
 * flow B   |                                                        | flow A
 *          |    +----------------+     ROHC   +----------------+    |
 *          +--- |                |            |                | <--+
 *               | Decompressor 2 | <--------- |  Compressor 2  |
 *          +--- |                |            |                | <--+
 *          |    +----------------+            +----------------+    |
 *          |                                                        |
 *          +--> IP packets                             IP packets --+
 *               flow B (output)                    flow B (input)
 *
 * Checks
 * ------
 *
 * The program checks for the status of the compression and decompression
 * processes. The program also compares input IP packets from flow A (resp.
 * flow B) with output IP packets from flow A (resp. flow B).
 *
 * The program optionally compares the ROHC packets generated with the ones
 * given as input to the program.
 *
 * Output
 * ------
 *
 * The program outputs XML containing the compression/decompression/comparison
 * status of every packets of flow A and flow B on stdout. It also outputs the
 * log of the different processes (startup, compression, decompression,
 * comparison and shutdown).
 *
 * The program optionally outputs the ROHC packets in a PCAP packet.
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
#include <protocols/udp.h>

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

/** The maximum number of source PCAP dump files */
#define SRC_FILENAMES_MAX_NR  2U

/** The Ethertype for the 802.1q protocol (VLAN) */
#define ETHERTYPE_8021Q   0x8100U
/** The Ethertype for the 802.1ad protocol */
#define ETHERTYPE_8021AD  0x88a8U

/** print text on console if not in quiet mode */
#define trace(format, ...) \
	do { \
		if(verbosity != VERBOSITY_NONE) { \
			printf(format, ##__VA_ARGS__); \
		} \
	} while(0)

/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(const rohc_cid_type_t cid_type,
                                const size_t oa_repetitions,
                                const size_t max_contexts,
                                const size_t proto_version,
                                const size_t padding_up_to,
                                const bool no_comparison,
                                const bool ignore_malformed,
                                const char *const src_filenames[],
                                const size_t src_filenames_nr,
                                char *ofilename,
                                char *cmp_filename,
                                const char *rohc_size_ofilename);
static int compress_decompress(struct rohc_comp *comp,
                               struct rohc_decomp *decomp,
                               struct rohc_comp *const comp_associated,
                               int num_comp,
                               int num_packet,
                               struct pcap_pkthdr header,
                               const uint8_t *const packet,
                               int link_len_src,
                               const size_t padding_up_to,
                               const bool no_comparison,
                               const bool ignore_malformed,
                               pcap_dumper_t *dumper,
                               unsigned char *cmp_packet,
                               int cmp_size,
                               int link_len_cmp,
                               FILE *size_output_file,
                               const struct rohc_buf feedback_send_by_me,
                               struct rohc_buf *const feedback_send_by_other);

static struct rohc_comp * create_compressor(const rohc_cid_type_t cid_type,
                                            const size_t oa_repetitions,
                                            const size_t max_contexts,
                                            const size_t proto_version)
	__attribute__((warn_unused_result));
static struct rohc_decomp * create_decompressor(const rohc_cid_type_t cid_type,
                                                const size_t max_contexts,
                                                const size_t proto_version)
	__attribute__((warn_unused_result));

static void print_rohc_traces(void *const priv_ctxt,
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

static pcap_t * open_pcap_file(const char *const descr,
                               const char *const filename,
                               size_t *const link_len)
	__attribute__((nonnull(1, 2, 3), warn_unused_result));
static bool get_next_packet(pcap_t **const pcap_handle,
                            const char *const src_filenames[],
                            const size_t src_filenames_nr,
                            size_t *const src_filenames_id,
                            struct pcap_pkthdr *const header,
                            size_t *const link_len,
                            const uint8_t **const packet)
	__attribute__((nonnull(1, 2, 4, 5, 6, 7), warn_unused_result));

static void show_rohc_stats(struct rohc_comp *comp1, struct rohc_decomp *decomp1,
                            struct rohc_comp *comp2, struct rohc_decomp *decomp2);
static bool show_rohc_comp_stats(const struct rohc_comp *const comp,
                                 const size_t instance)
	__attribute__((nonnull(1), warn_unused_result));
static void show_rohc_comp_profile(const struct rohc_comp *const comp,
                                   const rohc_profile_t profile)
	__attribute__((nonnull(1)));
static bool show_rohc_decomp_stats(const struct rohc_decomp *const decomp,
                                   const size_t instance)
	__attribute__((nonnull(1), warn_unused_result));
static void show_rohc_decomp_profile(const struct rohc_decomp *const decomp,
                                     const rohc_profile_t profile)
	__attribute__((nonnull(1)));

static int compare_packets(unsigned char *pkt1, int pkt1_size,
                           unsigned char *pkt2, int pkt2_size);


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

/** The number of warnings emitted by the ROHC library */
static size_t nr_rohc_warnings = 0;

/** The stats about packet sizes */
static size_t nr_pkts_per_size[MAX_ROHC_SIZE + 1] = { 0 };

/** The initial Master Sequence Number (MSN) to use, helpful for interop debug */
static int initial_msn = 1;

/** Whether a lossy link is emulated or not? */
static bool loss_enabled = false;
/** How large is a burst (in number of packets) */
static int burst_pkts_nr = 0;
/** What packet is not lost in the burst */
static int pkt_not_lost = 0;
/** Number of compressors */
#define NUM_COMP 2
/** Loss state per compressor and per context */
static size_t rcvd_pkts_nr_per_burst[NUM_COMP][ROHC_SMALL_CID_MAX + 1] = { { 0 } };


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
	char *cid_type_name = NULL;
	char *rohc_size_ofilename = NULL;
	size_t src_filenames_nr = 0;
	char *src_filenames[SRC_FILENAMES_MAX_NR] = { NULL };
	char *ofilename = NULL;
	char *cmp_filename = NULL;
	int max_contexts = ROHC_SMALL_CID_MAX + 1;
	int oa_repetitions = 4;
	int padding_up_to = 0;
	int proto_version = 1; /* ROHC protocol version, v1 by default */
	bool no_comparison = false;
	bool ignore_malformed = false;
	bool assert_on_error = false;
	bool print_stats = false;
	int status = 1;
	rohc_cid_type_t cid_type;
	int args_used;

	/* set to quiet mode by default */
	verbosity = VERBOSITY_NORMAL;
	/* no ROHC warning at the beginning */
	nr_rohc_warnings = 0;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 1)
	{
		usage();
		goto error;
	}


	for(argc--, argv++; argc > 0; argc -= args_used, argv += args_used)
	{
		args_used = 1;

		if(!strcmp(*argv, "-v"))
		{
			/* print version */
			printf("ROHC non-regression test application, version %s\n",
			       rohc_version());
			goto error;
		}
		else if(!strcmp(*argv, "-h"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(!strcmp(*argv, "--verbose"))
		{
			/* enable verbose mode */
			verbosity = VERBOSITY_FULL;
		}
		else if(!strcmp(*argv, "--quiet"))
		{
			/* enable quiet mode */
			verbosity = VERBOSITY_NONE;
		}
		else if(!strcmp(*argv, "-o"))
		{
			/* get the name of the file to store the ROHC packets */
			if(argc <= 1)
			{
				fprintf(stderr, "option -o takes one argument\n\n");
				usage();
				goto error;
			}
			ofilename = argv[1];
			args_used++;
		}
		else if(!strcmp(*argv, "-c"))
		{
			/* get the name of the file where the ROHC packets used for comparison
			 * are stored */
			if(argc <= 1)
			{
				fprintf(stderr, "option -c takes one argument\n\n");
				usage();
				goto error;
			}
			cmp_filename = argv[1];
			args_used++;
		}
		else if(!strcmp(*argv, "--no-comparison"))
		{
			/* do not exit with error code if comparison is not possible */
			no_comparison = true;
		}
		else if(!strcmp(*argv, "--ignore-malformed"))
		{
			/* do not exit with error code if malformed packets are found */
			ignore_malformed = true;
		}
		else if(!strcmp(*argv, "--assert-on-error"))
		{
			/* assert on the first encountered error */
			assert_on_error = true;
		}
		else if(!strcmp(*argv, "--rohc-size-output"))
		{
			/* get the name of the file to store the sizes of every ROHC packets */
			if(argc <= 1)
			{
				fprintf(stderr, "option --rohc-size-output takes one argument\n\n");
				usage();
				goto error;
			}
			rohc_size_ofilename = argv[1];
			args_used++;
		}
		else if(!strcmp(*argv, "--max-contexts"))
		{
			/* get the maximum number of contexts the test should use */
			if(argc <= 1)
			{
				fprintf(stderr, "option --max-contexts takes one argument\n\n");
				usage();
				goto error;
			}
			max_contexts = atoi(argv[1]);
			args_used++;
		}
		else if(!strcmp(*argv, "--loss-ratio"))
		{
			/* get the number of packets to loss */
			if(argc <= 2)
			{
				fprintf(stderr, "missing mandatory --loss-ratio parameters\n");
				usage();
				goto error;
			}
			pkt_not_lost = atoi(argv[1]);
			burst_pkts_nr = atoi(argv[2]);
			loss_enabled = true;
			args_used += 2;
		}
		else if(!strcmp(*argv, "--optimistic-approach"))
		{
			/* get the number of repetitions for the Optimistic Approach */
			if(argc <= 1)
			{
				fprintf(stderr, "option --optimistic-approach takes one argument\n\n");
				usage();
				goto error;
			}
			oa_repetitions = atoi(argv[1]);
			args_used++;
		}
		else if(!strcmp(*argv, "--padding-up-to"))
		{
			/* get the amount of padding that the test should add */
			if(argc <= 1)
			{
				fprintf(stderr, "option --padding-up-to takes one argument\n\n");
				usage();
				goto error;
			}
			padding_up_to = atoi(argv[1]);
			args_used++;
		}
		else if(!strcmp(*argv, "--print-stats"))
		{
			/* print some stats at the very end of the test */
			print_stats = true;
		}
		else if(!strcmp(*argv, "--rohc-version"))
		{
			/* get the ROHC version to use */
			if(argc <= 1)
			{
				fprintf(stderr, "option --rohc-version takes one argument\n\n");
				usage();
				goto error;
			}
			proto_version = atoi(argv[1]);
			args_used++;
		}
		else if(!strcmp(*argv, "--initial-msn"))
		{
			/* get the initial Master Sequence Number (MSN) */
			if(argc <= 1)
			{
				fprintf(stderr, "option --initial-msn takes one argument\n\n");
				usage();
				goto error;
			}
			initial_msn = atoi(argv[1]);
			args_used++;
		}
		else if(cid_type_name == NULL)
		{
			/* get the type of CID to use within the ROHC library */
			cid_type_name = argv[0];
		}
		else if(src_filenames[0] == NULL)
		{
			/* get the name of the file that contains the packets to
			 * compress/decompress */
			src_filenames[src_filenames_nr] = argv[0];
			src_filenames_nr++;
		}
		else if(src_filenames[1] == NULL)
		{
			/* get the name of the file that contains the packets to
			 * compress/decompress */
			src_filenames[src_filenames_nr] = argv[0];
			src_filenames_nr++;
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
		fprintf(stderr, "CID_TYPE is a mandatory parameter\n\n");
		usage();
		goto error;
	}
	else if(!strcmp(cid_type_name, "smallcid"))
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
		goto error;
	}

	/* check the number of repetitions for Optimistic Approach */
	if(oa_repetitions <= 0 || oa_repetitions >= UINT8_MAX)
	{
		fprintf(stderr, "invalid number of Optimistic Approach repetitions %d: "
		        "should be in range ]0;%u]\n", oa_repetitions,
		        (unsigned int) UINT8_MAX);
		goto error;
	}

	/* check padding */
	if(padding_up_to < 0)
	{
		fprintf(stderr, "invalid padding amount %d: should be a positive number "
		        "or 0\n", padding_up_to);
		goto error;
	}

	if(proto_version != 1 && proto_version != 2)
	{
		fprintf(stderr, "invalid ROHC version '%d': specify 1 for ROHCv1 and "
		        "2 for ROHCv2\n", proto_version);
		goto error;
	}

	/* at least one source filename is mandatory */
	if(src_filenames[0] == NULL)
	{
		fprintf(stderr, "FLOW is a mandatory parameter\n\n");
		usage();
		goto error;
	}

	/* test ROHC compression/decompression with the packets from the file */
	status = test_comp_and_decomp(cid_type, oa_repetitions, max_contexts, proto_version,
	                              padding_up_to, no_comparison, ignore_malformed,
	                              (const char *const *) src_filenames, src_filenames_nr,
	                              ofilename, cmp_filename,
	                              rohc_size_ofilename);

	trace("=== number of warnings/errors emitted by the library: %zu\n",
	      nr_rohc_warnings);
	if(nr_rohc_warnings > 0)
	{
		status = 1;
	}

	trace("=== exit test with code %d\n", status);

	if(assert_on_error)
	{
		assert(status == 0 || status == 77);
	}

	/* print stats about packet sizes */
	if(print_stats)
	{
		size_t i;
		for(i = 0; i <= 1600; i++)
		{
			size_t j;
			printf("%zu ", i);
			for(j = 0; j < nr_pkts_per_size[i] / 100; j++)
			{
				printf("*");
			}
			printf(" %zu\n", nr_pkts_per_size[i]);
		}
	}

error:
	return status;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	fprintf(stderr,
	        "ROHC non-regression tool: test the ROHC library with a flow\n"
	        "                          of IP packets\n"
	        "\n"
	        "usage: test_non_regression [OPTIONS] CID_TYPE FLOW [FLOW]\n"
	        "\n"
	        "with:\n"
	        "  CID_TYPE                The type of CID to use among 'smallcid'\n"
	        "                          and 'largecid'\n"
	        "  FLOW                    The flow of Ethernet frames to compress\n"
	        "                          (in PCAP format)\n"
	        "\n"
	        "options:\n"
	        "  -v                         Print version information and exit\n"
	        "  -h                         Print this usage and exit\n"
	        "  -o FILE                    Save the generated ROHC packets in FILE\n"
	        "                             (PCAP format)\n"
	        "  -c FILE                    Compare the generated ROHC packets with the\n"
	        "                             ROHC packets stored in FILE (PCAP format)\n"
	        "  --rohc-size-output FILE    Save the sizes of ROHC packets in FILE\n"
	        "  --max-contexts NUM         The maximum number of ROHC contexts to\n"
	        "                             simultaneously use during the test\n"
	        "  --optimistic-approach NUM  The nr of Optimistic Approach repetitions\n"
	        "  --rohc-version NUM         The ROHC version to use: 1 for ROHCv1\n"
	        "                             and 2 for ROHCv2\n"
	        "  --print-stats              Print some stats at the end of test\n"
	        "  --no-comparison            Is comparison with ROHC reference optional for test\n"
	        "  --ignore-malformed         Ignore malformed packets for test\n"
	        "  --assert-on-error          Stop the test after the very first encountered error\n"
	        "  --initial-msn NUM          The initial Master Sequence Number (MSN) for debug\n"
	        "  --verbose                  Run the test in verbose mode\n"
	        "  --quiet                    Run the test in silent mode\n");
}


/**
 * @brief Print statistics about the compressors and decompressors used during
 *        the test
 *
 * @param comp1   The first compressor
 * @param decomp1 The decompressor that receives data from the first compressor
 * @param comp2 The second compressor
 * @param decomp2 The decompressor that receives data from the second compressor
 */
static void show_rohc_stats(struct rohc_comp *comp1, struct rohc_decomp *decomp1,
                            struct rohc_comp *comp2, struct rohc_decomp *decomp2)
{
	/* print compressor statistics */
	if(!show_rohc_comp_stats(comp1, 1))
	{
		fprintf(stderr, "failed to print statistics for compressor 1\n");
		goto error;
	}
	if(!show_rohc_comp_stats(comp2, 2))
	{
		fprintf(stderr, "failed to print statistics for compressor 1\n");
		goto error;
	}

	/* print decompressor statistics */
	if(!show_rohc_decomp_stats(decomp1, 1))
	{
		fprintf(stderr, "failed to print statistics for decompressor 1\n");
		goto error;
	}
	if(!show_rohc_decomp_stats(decomp2, 2))
	{
		fprintf(stderr, "failed to print statistics for decompressor 1\n");
		goto error;
	}

error:
	return;
}


/**
 * @brief Print statistics about the given compressor
 *
 * @param comp      The compressor to print statistics for
 * @param instance  The instance number
 * @return          true if statistics were printed, false if a problem occurred
 */
static bool show_rohc_comp_stats(const struct rohc_comp *const comp,
                                 const size_t instance)
{
	rohc_comp_general_info_t general_info;
	unsigned long percent;
	size_t max_cid;
	size_t mrru;
	rohc_cid_type_t cid_type;

	assert(comp != NULL);

	/* general information */
	general_info.version_major = 0;
	general_info.version_minor = 0;
	if(!rohc_comp_get_general_info(comp, &general_info))
	{
		fprintf(stderr, "failed to get general information for compressor\n");
		goto error;
	}
	trace("=== compressor #%zu\n", instance);
	trace("===\tcreator: %s\n", PACKAGE_NAME " (" PACKAGE_URL ")");
	trace("===\tversion: %s\n", rohc_version());

	/* configuration */
	trace("===\tconfiguration:\n");
	if(!rohc_comp_get_cid_type(comp, &cid_type))
	{
		fprintf(stderr, "failed to get CID type for compressor\n");
		goto error;
	}
	trace("===\t\tcid_type: %s\n", cid_type == ROHC_LARGE_CID ? "large" : "small");
	if(!rohc_comp_get_max_cid(comp, &max_cid))
	{
		fprintf(stderr, "failed to get MAX_CID for compressor\n");
		goto error;
	}
	trace("===\t\tmax_cid:  %zu\n", max_cid);
//! [get compressor MRRU]
	/* retrieve current compressor MRRU */
	if(!rohc_comp_get_mrru(comp, &mrru))
	{
		fprintf(stderr, "failed to get MRRU for compressor\n");
		goto error;
	}
//! [get compressor MRRU]
	trace("===\t\tmrru:     %zu\n", mrru);

	/* profiles */
	trace("===\tprofiles:\n");
	show_rohc_comp_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
	show_rohc_comp_profile(comp, ROHC_PROFILE_RTP);
	show_rohc_comp_profile(comp, ROHC_PROFILE_UDP);
	show_rohc_comp_profile(comp, ROHC_PROFILE_ESP);
	show_rohc_comp_profile(comp, ROHC_PROFILE_IP);
	show_rohc_comp_profile(comp, ROHC_PROFILE_TCP);
	show_rohc_comp_profile(comp, ROHC_PROFILE_UDPLITE);

	/* statistics */
	trace("===\tstatistics:\n");
	trace("===\t\tflows:             %zu\n", general_info.contexts_nr);
	trace("===\t\tpackets:           %lu\n", general_info.packets_nr);
	if(general_info.uncomp_bytes_nr != 0)
	{
		percent = (100 * general_info.comp_bytes_nr) /
		          general_info.uncomp_bytes_nr;
	}
	else
	{
		percent = 0;
	}
	trace("===\t\tcompression_ratio: %lu%%\n", percent);
	trace("\n");

	return true;

error:
	return false;
}


/**
 * @brief Print details about a compression profile
 *
 * @param comp     The compressor to print statistics for
 * @param profile  The compression profile to print details for
 */
static void show_rohc_comp_profile(const struct rohc_comp *const comp,
                                   const rohc_profile_t profile)
{
	trace("===\t\t%s profile: %s (%d)\n",
	      rohc_comp_profile_enabled(comp, profile) ? "enabled " : "disabled",
	      rohc_get_profile_descr(profile), profile);
}


/**
 * @brief Print statistics about the given decompressor
 *
 * @param decomp    The decompressor to print statistics for
 * @param instance  The instance number
 * @return          true if statistics were printed, false if a problem occurred
 */
static bool show_rohc_decomp_stats(const struct rohc_decomp *const decomp,
                                   const size_t instance)
{
	rohc_decomp_general_info_t general_info;
	unsigned long percent;
	size_t max_cid;
	size_t mrru;
	rohc_cid_type_t cid_type;

	assert(decomp != NULL);

	/* general information */
	general_info.version_major = 0;
	general_info.version_minor = 1;
	if(!rohc_decomp_get_general_info(decomp, &general_info))
	{
		fprintf(stderr, "failed to get general information for decompressor\n");
		goto error;
	}

	trace("=== decompressor #%zu\n", instance);
	trace("===\tcreator: %s\n", PACKAGE_NAME " (" PACKAGE_URL ")");
	trace("===\tversion: %s\n", rohc_version());

	/* configuration */
	trace("===\tconfiguration:\n");
	if(!rohc_decomp_get_cid_type(decomp, &cid_type))
	{
		fprintf(stderr, "failed to get CID type for decompressor\n");
		goto error;
	}
	trace("===\t\tcid_type: %s\n", cid_type == ROHC_LARGE_CID ? "large" : "small");
	if(!rohc_decomp_get_max_cid(decomp, &max_cid))
	{
		fprintf(stderr, "failed to get MAX_CID for decompressor\n");
		goto error;
	}
	trace("===\t\tmax_cid:  %zu\n", max_cid);
//! [get decompressor MRRU]
	/* retrieve current decompressor MRRU */
	if(!rohc_decomp_get_mrru(decomp, &mrru))
	{
		fprintf(stderr, "failed to get MRRU for decompressor\n");
		goto error;
	}
//! [get decompressor MRRU]
	trace("===\t\tmrru:     %zu\n", mrru);

	/* profiles */
	trace("===\tprofiles:\n");
	show_rohc_decomp_profile(decomp, ROHC_PROFILE_UNCOMPRESSED);
	show_rohc_decomp_profile(decomp, ROHC_PROFILE_RTP);
	show_rohc_decomp_profile(decomp, ROHC_PROFILE_UDP);
	show_rohc_decomp_profile(decomp, ROHC_PROFILE_ESP);
	show_rohc_decomp_profile(decomp, ROHC_PROFILE_IP);
	show_rohc_decomp_profile(decomp, ROHC_PROFILE_TCP);
	show_rohc_decomp_profile(decomp, ROHC_PROFILE_UDPLITE);

	/* statistics */
	trace("===\tstatistics:\n");
	trace("===\t\tflows:               %zu\n", general_info.contexts_nr);
	trace("===\t\tpackets:             %lu\n", general_info.packets_nr);
	if(general_info.comp_bytes_nr != 0)
	{
		percent = (100 * general_info.uncomp_bytes_nr) /
		          general_info.comp_bytes_nr;
	}
	else
	{
		percent = 0;
	}
	trace("===\t\tdecompression_ratio: %lu%%\n", percent);
	trace("\n");

	return true;

error:
	return false;
}


/**
 * @brief Print details about a decompression profile
 *
 * @param decomp   The decompressor to print statistics for
 * @param profile  The decompression profile to print details for
 */
static void show_rohc_decomp_profile(const struct rohc_decomp *const decomp,
                                     const rohc_profile_t profile)
{
	trace("===\t\t%s profile: %s (%d)\n",
	      rohc_decomp_profile_enabled(decomp, profile) ? "enabled " : "disabled",
	      rohc_get_profile_descr(profile), profile);
}


/**
 * @brief Compress and decompress one uncompressed IP packet with the given
 *        compressor and decompressor
 *
 * @param comp             The compressor to use to compress the IP packet
 * @param decomp           The decompressor to use to decompress the IP packet
 * @param comp_associated  The same-side compressor associated to the
 *                         decompressor, this is the destination of feedback
 *                         received from the decompressor
 * @param num_comp         The ID of the compressor/decompressor
 * @param num_packet       A number affected to the IP packet to compress/decompress
 * @param header           The PCAP header for the packet
 * @param packet           The packet to compress/decompress (link layer included)
 * @param link_len_src     The length of the link layer header before IP data
 * @param padding_up_to    The amount of padding to use
 * @param no_comparison    Whether to handle comparison as fatal for test or not
 * @param ignore_malformed Whether to handle malformed packets as fatal for test
 * @param dumper           The PCAP output dump file
 * @param cmp_packet       The ROHC packet for comparison purpose
 * @param cmp_size         The size of the ROHC packet used for comparison
 *                         purpose
 * @param link_len_cmp     The length of the link layer header before ROHC data
 * @param size_output_file The name of the text file to output the sizes of
 *                         the ROHC packets
 * @return                 1 if the process is successful
 *                         0 if the decompressed packet doesn't match the
 *                         original one
 *                         -1 if an error occurs while compressing
 *                         -2 if an error occurs while decompressing
 *                         -3 if the link layer is not Ethernet
 */
static int compress_decompress(struct rohc_comp *comp,
                               struct rohc_decomp *decomp,
                               struct rohc_comp *const comp_associated,
                               int num_comp,
                               int num_packet,
                               struct pcap_pkthdr header,
                               const uint8_t *const packet,
                               int link_len_src,
                               const size_t padding_up_to,
                               const bool no_comparison,
                               const bool ignore_malformed,
                               pcap_dumper_t *dumper,
                               unsigned char *cmp_packet,
                               int cmp_size,
                               int link_len_cmp,
                               FILE *size_output_file,
                               const struct rohc_buf feedback_send_by_me,
                               struct rohc_buf *const feedback_send_by_other)
{
	/* the layer 2 header */
	size_t l2_hdr_max_len = max(ETHER_HDR_LEN, LINUX_COOKED_HDR_LEN);
	bool is_vlan_present = false;

	/* the buffer that will contain the initial uncompressed packet */
	const struct rohc_ts arrival_time = {
		.sec = header.ts.tv_sec,
		.nsec = header.ts.tv_usec * 1000
	};
	struct rohc_buf ip_packet =
		rohc_buf_init_full((uint8_t *) packet, header.caplen, arrival_time);

	/* the buffer that will contain the compressed ROHC packet */
	uint8_t rohc_buffer[l2_hdr_max_len + MAX_ROHC_SIZE];
	struct rohc_buf rohc_packet =
		rohc_buf_init_empty(rohc_buffer, l2_hdr_max_len + MAX_ROHC_SIZE);

	/* the buffer that will contain the uncompressed packet */
	uint8_t decomp_buffer[MAX_ROHC_SIZE];
	struct rohc_buf decomp_packet =
		rohc_buf_init_empty(decomp_buffer, MAX_ROHC_SIZE);

	/* the buffer that will contain the feedback data received by the
	 * decompressor from the remote peer for the same-side associated ROHC
	 * compressor through the feedback channel */
	uint8_t rcvd_feedback_buffer[MAX_ROHC_SIZE];
	struct rohc_buf rcvd_feedback =
		rohc_buf_init_empty(rcvd_feedback_buffer, MAX_ROHC_SIZE);

	int status = 1;
	rohc_status_t ret;

	trace("=== compressor/decompressor #%d, packet #%d:\n", num_comp, num_packet);
	trace("=== arrival time %ld seconds %ld us\n", header.ts.tv_sec, header.ts.tv_usec);

	/* check Ethernet frame length */
	if(header.len < link_len_src || header.len != header.caplen)
	{
		trace("bad PCAP packet (len = %u, caplen = %u)\n", header.len,
		      header.caplen);
		status = -3;
		goto exit;
	}

	/* copy the layer 2 header before the ROHC packet, then skip it */
	if(link_len_src == ETHER_HDR_LEN)
	{
		const struct ether_header *const eth_header =
			(struct ether_header *) rohc_buf_data(ip_packet);
		uint16_t proto_type = ntohs(eth_header->ether_type);

		/* skip all 802.1q or 802.1ad headers */
		while(proto_type == ETHERTYPE_8021Q || proto_type == ETHERTYPE_8021AD)
		{
			trace("found one 802.1q or 802.1ad header\n");
			is_vlan_present = true;

			/* check min length */
			if(header.len < link_len_src + sizeof(struct vlan_hdr))
			{
				trace("truncated %u-byte 802.1q or 802.1ad frame\n", header.len);
				status = -3;
				goto exit;
			}

			/* detect next header */
			const struct vlan_hdr *const vlan_hdr =
				(struct vlan_hdr *) rohc_buf_data_at(ip_packet, link_len_src);
			proto_type = ntohs(vlan_hdr->type);

			/* skip VLAN header */
			link_len_src += sizeof(struct vlan_hdr);
		}
	}
	rohc_buf_append(&rohc_packet, packet, link_len_src);
	rohc_buf_pull(&ip_packet, link_len_src);
	rohc_buf_pull(&rohc_packet, link_len_src);

	/* check for padding after the IP packet in the Ethernet payload */
	if(link_len_src == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
	{
		int version;
		size_t tot_len;

		version = (rohc_buf_byte(ip_packet) >> 4) & 0x0f;

		if(version == 4)
		{
			struct ipv4_hdr *ip = (struct ipv4_hdr *) rohc_buf_data(ip_packet);
			tot_len = ntohs(ip->tot_len);
			if(tot_len < sizeof(struct ipv4_hdr))
			{
				trace("malformed IPv4 packet: IPv4 total length is %zu bytes, "
				      "but it should be at least %zu bytes", tot_len,
				      sizeof(struct ipv4_hdr));
				status = -3;
				goto exit;
			}
		}
		else
		{
			struct ipv6_hdr *ip = (struct ipv6_hdr *) rohc_buf_data(ip_packet);
			tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->plen);
		}

		if(tot_len < ip_packet.len)
		{
			trace("The Ethernet frame has %zu bytes of padding after the "
			      "%zu byte IP packet!\n", ip_packet.len - tot_len, tot_len);
			ip_packet.len = tot_len;
		}
	}

	/* fix IPv4 packets with non-standard-compliant 0xffff checksums instead
	 * of 0x0000 (Windows Vista seems to be faulty for the latter), to avoid
	 * false comparison failures after decompression) */
	if(((rohc_buf_byte(ip_packet) >> 4) & 0x0f) == 4 &&
	   ip_packet.len >= sizeof(struct ipv4_hdr) &&
	   rohc_buf_byte_at(ip_packet, 10) == 0xff &&
	   rohc_buf_byte_at(ip_packet, 11) == 0xff)
	{
		trace("fix IPv4 packet with 0xffff IP checksum\n");
		rohc_buf_byte_at(ip_packet, 10) = 0x00;
		rohc_buf_byte_at(ip_packet, 11) = 0x00;
	}

	/* make room for future ROHC padding */
	rohc_packet.len += padding_up_to;
	rohc_buf_pull(&rohc_packet, padding_up_to);

	/* copy the feedback data that needs to be piggybacked along the ROHC
	 * packet */
	trace("=== ROHC piggybacked feedback: start\n");
	if(feedback_send_by_me.len > rohc_buf_avail_len(rohc_packet))
	{
		trace("ROHC buffer is too small for %zu bytes of feedback data\n",
		      feedback_send_by_me.len);
		trace("=== ROHC piggybacked feedback: failure\n");
		status = -1;
		goto exit;
	}
	trace("copy %zu bytes of feedback data before ROHC packet\n",
	      feedback_send_by_me.len);
	rohc_buf_append_buf(&rohc_packet, feedback_send_by_me);
	rohc_buf_pull(&rohc_packet, feedback_send_by_me.len); /* skip feedback */
	trace("=== ROHC piggybacked feedback: success\n");

	/* compress the IP packet into a ROHC packet */
	trace("=== ROHC compression: start\n");
	ret = rohc_compress4(comp, ip_packet, &rohc_packet);
	if(ret != ROHC_STATUS_OK)
	{
		trace("=== ROHC compression: failure\n");
		status = -1;
		goto exit;
	}
	trace("=== ROHC compression: success\n");

	/* unhide feedback data */
	rohc_buf_push(&rohc_packet, feedback_send_by_me.len);

	/* pad the ROHC packet up to 100 bytes */
	trace("=== ROHC padding: start\n");
	ret = rohc_comp_pad(comp, &rohc_packet, padding_up_to);
	if(ret != ROHC_STATUS_OK)
	{
		trace("=== ROHC padding: failure\n");
		status = -1;
		goto exit;
	}
	trace("=== ROHC padding: success\n");

	/* output the ROHC packet to the PCAP dump file if asked */
	if(dumper != NULL)
	{
		header.len = link_len_src + rohc_packet.len;
		header.caplen = header.len;
		if(link_len_src != 0)
		{
			/* prepend the link layer header */
			rohc_buf_prepend(&rohc_packet, packet, link_len_src);
			if(is_vlan_present) /* Ethernet and VLAN */
			{
				struct vlan_hdr *const vlan_hdr = (struct vlan_hdr *)
					rohc_buf_data_at(rohc_packet, link_len_src - sizeof(struct vlan_hdr));
				vlan_hdr->type = htons(ROHC_ETHERTYPE); /* ROHC Ethertype */
			}
			else if(link_len_src == ETHER_HDR_LEN) /* Ethernet only */
			{
				struct ether_header *const eth_header =
					(struct ether_header *) rohc_buf_data(rohc_packet);
				eth_header->ether_type = htons(ROHC_ETHERTYPE); /* ROHC Ethertype */
			}
			else if(link_len_src == LINUX_COOKED_HDR_LEN) /* Linux Cooked Sockets only */
			{
				rohc_buf_byte_at(rohc_packet, LINUX_COOKED_HDR_LEN - 2) =
					ROHC_ETHERTYPE & 0xff;
				rohc_buf_byte_at(rohc_packet, LINUX_COOKED_HDR_LEN - 1) =
					(ROHC_ETHERTYPE >> 8) & 0xff;
			}
		}
		pcap_dump((u_char *) dumper, &header, rohc_buf_data(rohc_packet));
		/* skip the link layer header again */
		rohc_buf_pull(&rohc_packet, link_len_src);
	}

	/* output the size of the ROHC packet to the output file if asked */
	rohc_cid_t last_cid;
	{
		rohc_comp_last_packet_info2_t last_packet_info;

		/* get some statistics about the last compressed packet */
		last_packet_info.version_major = 0;
		last_packet_info.version_minor = 0;
		if(!rohc_comp_get_last_packet_info2(comp, &last_packet_info))
		{
			trace("failed to get statistics\n");
			status = -1;
			goto exit;
		}
		nr_pkts_per_size[last_packet_info.header_last_comp_size]++;
		last_cid = last_packet_info.context_id;

		if(size_output_file != NULL)
		{
			fprintf(size_output_file, "compressor_num = %d\tpacket_num = %d\t"
			        "rohc_size = %zu\tpacket_type = %d\n", num_comp, num_packet,
			        rohc_packet.len, last_packet_info.packet_type);
		}
	}

	/* compare the ROHC packets with the ones given by the user if asked */
	trace("=== ROHC comparison: start\n");
	if(!no_comparison && cmp_packet != NULL && cmp_size > link_len_cmp)
	{
		if(!compare_packets(cmp_packet + link_len_cmp, cmp_size - link_len_cmp,
		                    rohc_buf_data(rohc_packet), rohc_packet.len))
		{
			trace("=== ROHC comparison: failure\n");
			status = 0;
		}
		else
		{
			trace("=== ROHC comparison: success\n");
		}
	}
	else
	{
		trace("=== ROHC comparison: no reference available (run with the -c option)\n");
		if(!no_comparison)
		{
			status = 0;
		}
	}

	/* decompress the ROHC packet if it is not lost during transmission */
	rcvd_pkts_nr_per_burst[num_comp - 1][last_cid]++;
	if(loss_enabled && rcvd_pkts_nr_per_burst[num_comp - 1][last_cid] != pkt_not_lost)
	{
		trace("=== ROHC decompression: packet %zu/%d was lost during "
		      "transmission\n", rcvd_pkts_nr_per_burst[num_comp - 1][last_cid],
		      burst_pkts_nr);
	}
	else
{
		trace("=== ROHC decompression: packet %zu/%d received\n",
		      rcvd_pkts_nr_per_burst[num_comp - 1][last_cid], burst_pkts_nr);

	/* decompress the ROHC packet */
	trace("=== ROHC decompression: start\n");
	ret = rohc_decompress3(decomp, rohc_packet, &decomp_packet,
	                       &rcvd_feedback, feedback_send_by_other);
	if(ret != ROHC_STATUS_OK)
	{
		size_t i;

		trace("=== ROHC decompression: failure\n");
		trace("=== original %zu-byte non-compressed packet:\n", ip_packet.len);
		for(i = 0; i < ip_packet.len; i++)
		{
			if(i > 0 && (i % 16) == 0)
			{
				trace("\n");
			}
			else if(i > 0 && (i % 8) == 0)
			{
				trace("  ");
			}
			trace("%02x ", rohc_buf_byte_at(ip_packet, i));
		}
		trace("\n");
		status = -2;
		goto exit;
	}
	trace("=== ROHC decompression: success\n");

	/* compare the decompressed packet with the original one */
	trace("=== IP comparison: start\n");
	if(!compare_packets(rohc_buf_data(ip_packet), ip_packet.len,
	                    rohc_buf_data(decomp_packet), decomp_packet.len))
	{
		trace("=== IP comparison: failure\n");
		status = 0;
		goto exit;
	}
	else
	{
		trace("=== IP comparison: success\n");
	}

	/* deliver any received feedback data to the associated compressor: the
	 * compressor will take it into account and update the mode/state of the
	 * related compression contexts in consequence */
	trace("=== deliver received feedback to compressor: start\n");
	if(!rohc_comp_deliver_feedback2(comp_associated, rcvd_feedback))
	{
		trace("=== deliver received feedback to compressor: failure\n");
		status = -2;
		goto exit;
	}
	else
	{
		trace("=== deliver received feedback to compressor: success\n");
	}
}
	if(rcvd_pkts_nr_per_burst[num_comp - 1][last_cid] >= burst_pkts_nr)
	{
		trace("=== ROHC decompression: last packet for that burst\n");
		rcvd_pkts_nr_per_burst[num_comp - 1][last_cid] = 0;
	}

exit:
	trace("\n");
	return status;
}


/**
 * @brief Test the ROHC library with a flow of IP packets going through
 *        two compressor/decompressor pairs
 *
 * @param cid_type             The type of CIDs the compressor shall use
 * @param oa_repetitions       The nr of repetitions for the Optimistic Approach
 * @param max_contexts         The maximum number of ROHC contexts to use
 * @param proto_version        The version of the ROHC protocol to use: v1 or v2
 * @param padding_up_to        The amount of padding to use
 * @param no_comparison        Whether to handle comparison as fatal for test or not
 * @param ignore_malformed     Whether to handle malformed packets as fatal for test
 * @param src_filenames        The names of the PCAP files that contain the
 *                             IP packets
 * @param ofilename            The name of the PCAP file to output the ROHC
 *                             packets
 * @param cmp_filename         The name of the PCAP file that contains the
 *                             ROHC packets used for comparison
 * @param rohc_size_ofilename  The name of the text file to output the sizes
 *                             of the ROHC packets
 * @return                     0 in case of success,
 *                             1 in case of failure,
 *                             77 if test is skipped
 */
static int test_comp_and_decomp(const rohc_cid_type_t cid_type,
                                const size_t oa_repetitions,
                                const size_t max_contexts,
                                const size_t proto_version,
                                const size_t padding_up_to,
                                const bool no_comparison,
                                const bool ignore_malformed,
                                const char *const src_filenames[],
                                const size_t src_filenames_nr,
                                char *ofilename,
                                char *cmp_filename,
                                const char *rohc_size_ofilename)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	size_t src_filenames_id = 0;
	pcap_t *handle;
	pcap_t *cmp_handle;
	pcap_dumper_t *dumper;
	size_t link_len_src = 0;
	size_t link_len_cmp = 0;
	struct pcap_pkthdr header;
	struct pcap_pkthdr cmp_header;

	FILE *rohc_size_output_file;

	const uint8_t *packet;
	unsigned char *cmp_packet;

	int counter;

	struct rohc_comp *comp1;
	struct rohc_comp *comp2;

	struct rohc_decomp *decomp1;
	struct rohc_decomp *decomp2;

	/* the buffer that will contain the feedback packet of #1 */
	uint8_t feedback1_buffer[MAX_ROHC_SIZE];
	struct rohc_buf feedback1_data =
		rohc_buf_init_empty(feedback1_buffer, MAX_ROHC_SIZE);
	/* the buffer that will contain the feedback packet of #2 */
	uint8_t feedback2_buffer[MAX_ROHC_SIZE];
	struct rohc_buf feedback2_data =
		rohc_buf_init_empty(feedback2_buffer, MAX_ROHC_SIZE);

	int ret;
	int nb_bad = 0, nb_ok = 0, err_comp = 0, err_decomp = 0, nb_ref = 0;
	int status = 1;

	trace("=== initialization:\n");

	/* open the source dump file */
	handle = open_pcap_file("source", src_filenames[0], &link_len_src);
	if(handle == NULL)
	{
		status = 77; /* skip test */
		goto error;
	}

	/* open the network dump file for ROHC storage if asked */
	if(ofilename != NULL)
	{
		dumper = pcap_dump_open(handle, ofilename);
		if(dumper == NULL)
		{
			trace("failed to open dump file '%s': %s\n", ofilename, errbuf);
			status = 77; /* skip test */
			goto close_input;
		}
	}
	else
	{
		dumper = NULL;
	}

	/* open the ROHC comparison dump file if asked */
	if(cmp_filename != NULL)
	{
		cmp_handle = open_pcap_file("comparison", cmp_filename, &link_len_cmp);
		if(cmp_handle == NULL)
		{
			status = 77; /* skip test */
			goto close_output;
		}
	}
	else
	{
		cmp_handle = NULL;
	}

	/* open the file in which to write the sizes of the ROHC packets if asked */
	if(rohc_size_ofilename != NULL)
	{
		rohc_size_output_file = fopen(rohc_size_ofilename, "w+");
		if(rohc_size_output_file == NULL)
		{
			trace("failed to open file '%s' to output the sizes of ROHC packets: "
			      "%s (%d)\n", rohc_size_ofilename, strerror(errno), errno);
			status = 77; /* skip test */
			goto close_comparison;
		}
	}
	else
	{
		rohc_size_output_file = NULL;
	}

	/* create the compressor 1 */
	comp1 = create_compressor(cid_type, oa_repetitions, max_contexts, proto_version);
	if(comp1 == NULL)
	{
		trace("failed to create the compressor 1\n");
		goto close_output_size;
	}

	/* create the compressor 2 */
	comp2 = create_compressor(cid_type, oa_repetitions, max_contexts, proto_version);
	if(comp2 == NULL)
	{
		trace("failed to create the compressor 2\n");
		goto destroy_comp1;
	}

	/* create the decompressor 1 */
	decomp1 = create_decompressor(cid_type, max_contexts, proto_version);
	if(decomp1 == NULL)
	{
		trace("failed to create the decompressor 1\n");
		goto destroy_comp2;
	}

	/* create the decompressor 2 */
	decomp2 = create_decompressor(cid_type, max_contexts, proto_version);
	if(decomp2 == NULL)
	{
		trace("failed to create the decompressor 2\n");
		goto destroy_decomp1;
	}

	trace("\n");

	/* for each packet in the dump */
	counter = 0;
	while(get_next_packet(&handle, src_filenames, src_filenames_nr,
	                      &src_filenames_id, &header, &link_len_src, &packet))
	{
		counter++;

		/* get next ROHC packet from the comparison dump file if asked */
		if(cmp_handle != NULL)
		{
			cmp_packet = (unsigned char *) pcap_next(cmp_handle, &cmp_header);
		}
		else
		{
			cmp_packet = NULL;
			cmp_header.caplen = 0;
		}

		/* compress & decompress from compressor 1 to decompressor 1 */
		ret = compress_decompress(comp1, decomp1, comp2, 1, counter,
		                          header, packet, link_len_src,
		                          padding_up_to, no_comparison, ignore_malformed,
		                          dumper,
		                          cmp_packet, cmp_header.caplen, link_len_cmp,
		                          rohc_size_output_file,
		                          feedback2_data, &feedback1_data);
		if(ret == -1)
		{
			err_comp++;
			break;
		}
		else if(ret == -2)
		{
			err_decomp++;
			break;
		}
		else if(ret == 0)
		{
			nb_ref++;
		}
		else if(ret == 1)
		{
			nb_ok++;
		}
		else
		{
			nb_bad++;
		}
		/* reset feedback for comp/decomp #2 since it was just piggybacked */
		rohc_buf_reset(&feedback2_data);

		/* get next ROHC packet from the comparison dump file if asked */
		if(cmp_handle != NULL)
		{
			cmp_packet = (unsigned char *) pcap_next(cmp_handle, &cmp_header);
		}
		else
		{
			cmp_packet = NULL;
			cmp_header.caplen = 0;
		}

		/* compress & decompress from compressor 2 to decompressor 2 */
		ret = compress_decompress(comp2, decomp2, comp1, 2, counter,
		                          header, packet, link_len_src,
		                          padding_up_to, no_comparison, ignore_malformed,
		                          dumper,
		                          cmp_packet, cmp_header.caplen, link_len_cmp,
		                          rohc_size_output_file,
		                          feedback1_data, &feedback2_data);
		if(ret == -1)
		{
			err_comp++;
			break;
		}
		else if(ret == -2)
		{
			err_decomp++;
			break;
		}
		else if(ret == 0)
		{
			nb_ref++;
		}
		else if(ret == 1)
		{
			nb_ok++;
		}
		else
		{
			nb_bad++;
		}
		/* reset feedback for comp/decomp #1 since it was just piggybacked */
		rohc_buf_reset(&feedback1_data);
	}

	/* show the compression/decompression results */
	trace("=== summary:\n");
	trace("===\tprocessed:            %d\n", 2 * counter);
	trace("===\tmalformed:            %d\n", nb_bad);
	trace("===\tcompression_failed:   %d\n", err_comp);
	trace("===\tdecompression_failed: %d\n", err_decomp);
	trace("===\tmatches:              %d\n", nb_ok);
	trace("\n");

	/* show some info/stats about the compressors and decompressors */
	show_rohc_stats(comp1, decomp1, comp2, decomp2);
	trace("\n");

	/* destroy the compressors and decompressors */
	trace("=== shutdown:\n");
	if(err_comp == 0 && err_decomp == 0 &&
	   (ignore_malformed || nb_bad == 0) && nb_ref == 0 &&
	   (nb_ok + nb_bad) == (counter * 2))
	{
		/* test is successful */
		status = 0;
	}

	rohc_decomp_free(decomp2);
destroy_decomp1:
	rohc_decomp_free(decomp1);
destroy_comp2:
	rohc_comp_free(comp2);
destroy_comp1:
	rohc_comp_free(comp1);
close_output_size:
	if(rohc_size_output_file != NULL)
	{
		fclose(rohc_size_output_file);
	}
close_comparison:
	if(cmp_handle != NULL)
	{
		pcap_close(cmp_handle);
	}
close_output:
	if(dumper != NULL)
	{
		pcap_dump_close(dumper);
	}
close_input:
	if(handle != NULL)
	{
		pcap_close(handle);
	}
error:
	return status;
}


/**
 * @brief Create and configure a ROHC compressor
 *
 * @param cid_type        The type of CIDs the compressor shall use
 * @param max_contexts    The maximum number of ROHC contexts to use
 * @param oa_repetitions  The number of repetitions for the Optimistic Approach
 * @param proto_version   The version of the ROHC protocol to use: v1 or v2
 * @return                The new ROHC compressor
 */
static struct rohc_comp * create_compressor(const rohc_cid_type_t cid_type,
                                            const size_t oa_repetitions,
                                            const size_t max_contexts,
                                            const size_t proto_version)
{
	struct rohc_comp *comp;

	/* create the compressor */
	comp = rohc_comp_new2(cid_type, max_contexts - 1,
	                      gen_false_random_num, NULL);
	if(comp == NULL)
	{
		trace("failed to create compressor\n");
		goto error;
	}

	/* enable traces and packet dump in verbose mode */
	if(verbosity == VERBOSITY_FULL)
	{
		/* set the callback for traces */
		if(!rohc_comp_set_traces_cb2(comp, print_rohc_traces, NULL))
		{
			trace("failed to set the callback for traces\n");
			goto destroy_comp;
		}

		/* enable packet dump only in verbose mode */
		if(!rohc_comp_set_features(comp, ROHC_COMP_FEATURE_DUMP_PACKETS))
		{
			trace("failed to enable packet dumps");
			goto destroy_comp;
		}
	}

	/* enable profiles */
	if(proto_version == 1)
	{
		/* enable ROHCv1 profiles */
		if(!rohc_comp_enable_profiles(comp,
		                              ROHCv1_PROFILE_UNCOMPRESSED,
		                              ROHCv1_PROFILE_IP_UDP_RTP,
		                              ROHCv1_PROFILE_IP_UDP,
		                              ROHCv1_PROFILE_IP_ESP,
		                              ROHCv1_PROFILE_IP,
		                              ROHCv1_PROFILE_IP_TCP,
		                              ROHCv1_PROFILE_IP_UDPLITE,
		                              -1))
		{
			trace("failed to enable the compression profiles\n");
			goto destroy_comp;
		}
	}
	else
	{
		/* enable ROHCv2 profiles */
		if(!rohc_comp_enable_profiles(comp,
		                              ROHCv1_PROFILE_UNCOMPRESSED,
		                              ROHCv1_PROFILE_IP_TCP,
		                              ROHCv2_PROFILE_IP_UDP_RTP,
		                              ROHCv2_PROFILE_IP_UDP,
		                              ROHCv2_PROFILE_IP_ESP,
		                              ROHCv2_PROFILE_IP,
#if 0
		                              ROHCv2_PROFILE_IP_UDPLITE_RTP,
		                              ROHCv2_PROFILE_IP_UDPLITE,
#endif
		                              -1))
		{
			trace("failed to enable the compression profiles\n");
			goto destroy_comp;
		}
	}

	/* set the number of repetitions for Optimistic Approach */
	if(!rohc_comp_set_optimistic_approach(comp, oa_repetitions))
	{
		trace("failed to set the Optimistic Approach repetitions\n");
		goto destroy_comp;
	}

	/* set UDP ports dedicated to RTP traffic */
	if(!rohc_comp_set_rtp_detection_cb(comp, rohc_comp_rtp_cb, NULL))
	{
		fprintf(stderr, "failed to set the callback RTP detection\n");
		goto destroy_comp;
	}

	return comp;

destroy_comp:
	rohc_comp_free(comp);
error:
	return NULL;
}


/**
 * @brief Create and configure a ROHC decompressor
 *
 * @param cid_type      The type of CIDs the compressor shall use
 * @param max_contexts  The maximum number of ROHC contexts to use
 * @param proto_version The version of the ROHC protocol to use: v1 or v2
 * @return              The new ROHC decompressor
 */
static struct rohc_decomp * create_decompressor(const rohc_cid_type_t cid_type,
                                                const size_t max_contexts,
                                                const size_t proto_version)
{
	struct rohc_decomp *decomp;

	/* create the decompressor */
	decomp = rohc_decomp_new2(cid_type, max_contexts - 1, ROHC_O_MODE);
	if(decomp == NULL)
	{
		trace("failed to create decompressor\n");
		goto error;
	}

	/* enable traces and packet dump in verbose mode */
	if(verbosity == VERBOSITY_FULL)
	{
		/* set the callback for traces */
		if(!rohc_decomp_set_traces_cb2(decomp, print_rohc_traces, NULL))
		{
			trace("failed to set trace callback\n");
			goto destroy_decomp;
		}

		/* enable packet dump only in verbose mode */
		if(!rohc_decomp_set_features(decomp, ROHC_DECOMP_FEATURE_DUMP_PACKETS))
		{
			trace("failed to enable packet dumps");
			goto destroy_decomp;
		}
	}

	/* enable decompression profiles */
	if(proto_version == 1)
	{
		/* enable ROHCv1 profiles */
		if(!rohc_decomp_enable_profiles(decomp,
		                                ROHCv1_PROFILE_UNCOMPRESSED,
		                                ROHCv1_PROFILE_IP_UDP_RTP,
		                                ROHCv1_PROFILE_IP_UDP,
		                                ROHCv1_PROFILE_IP_ESP,
		                                ROHCv1_PROFILE_IP,
		                                ROHCv1_PROFILE_IP_TCP,
		                                ROHCv1_PROFILE_IP_UDPLITE,
		                                -1))
		{
			trace("failed to enable the decompression profiles\n");
			goto destroy_decomp;
		}
	}
	else
	{
		/* enable ROHCv2 profiles */
		if(!rohc_decomp_enable_profiles(decomp,
		                                ROHCv1_PROFILE_UNCOMPRESSED,
		                                ROHCv1_PROFILE_IP_TCP,
		                                ROHCv2_PROFILE_IP_UDP_RTP,
		                                ROHCv2_PROFILE_IP_UDP,
		                                ROHCv2_PROFILE_IP_ESP,
		                                ROHCv2_PROFILE_IP,
#if 0
		                                ROHCv2_PROFILE_IP_UDPLITE_RTP,
		                                ROHCv2_PROFILE_IP_UDPLITE,
#endif
		                                -1))
		{
			trace("failed to enable the decompression profiles\n");
			goto destroy_decomp;
		}
	}

	return decomp;

destroy_decomp:
	rohc_decomp_free(decomp);
error:
	return NULL;
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
	if(level >= ROHC_TRACE_WARNING || verbosity == VERBOSITY_FULL)
	{
		va_list args;
		fprintf(stdout, "[%s] ", trace_level_descrs[level]);
		va_start(args, format);
		vfprintf(stdout, format, args);
		va_end(args);

		if(level >= ROHC_TRACE_WARNING)
		{
			nr_rohc_warnings++;
		}
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
	return initial_msn - 1;
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
	const size_t default_rtp_ports_nr = 6;
	unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002, 5006 };
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
 * @brief Open a PCAP dump file
 *
 * @param descr          A description for the PCAP dump to open
 * @param filename       The file name of the PCAP dump file to open
 * @param[out] link_len  The length of the link layer detected in the PCAP dump
 *                       in case of success
 * @return               The handle on the opened PCAP dump file in case of success,
 *                       NULL in case of error
 */
static pcap_t * open_pcap_file(const char *const descr,
                               const char *const filename,
                               size_t *const link_len)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int link_layer_type;
	pcap_t *handle;

	/* open the source dump file */
	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL)
	{
		trace("failed to open the %s pcap file: %s\n", descr, errbuf);
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type = pcap_datalink(handle);
	if(link_layer_type != DLT_EN10MB &&
	   link_layer_type != DLT_LINUX_SLL &&
	   link_layer_type != DLT_RAW &&
	   link_layer_type != DLT_NULL)
	{
		trace("link layer type %d not supported in %s dump (supported = "
		      "%d, %d, %d, %d)\n", link_layer_type, descr, DLT_EN10MB,
		      DLT_LINUX_SLL, DLT_RAW, DLT_NULL);
		goto close_input;
	}

	if(link_layer_type == DLT_EN10MB)
	{
		*link_len = ETHER_HDR_LEN;
	}
	else if(link_layer_type == DLT_LINUX_SLL)
	{
		*link_len = LINUX_COOKED_HDR_LEN;
	}
	else if(link_layer_type == DLT_NULL)
	{
		*link_len = BSD_LOOPBACK_HDR_LEN;
	}
	else /* DLT_RAW */
	{
		*link_len = 0;
	}

	return handle;

close_input:
	pcap_close(handle);
error:
	return NULL;
}


/**
 * @brief Get the next packet from source captures
 *
 */
static bool get_next_packet(pcap_t **const pcap_handle,
                            const char *const src_filenames[],
                            const size_t src_filenames_nr,
                            size_t *const src_filenames_id,
                            struct pcap_pkthdr *const header,
                            size_t *const link_len,
                            const uint8_t **const packet)
{
	assert((*pcap_handle) != NULL);

	/* get the next packet in the current PCAP dump */
	*packet = (const uint8_t *) pcap_next(*pcap_handle, header);

	/* if there is no more packet in the current PCAP dump file, try next one */
	if((*packet) == NULL)
	{
		/* close current PCAP dump file */
		pcap_close(*pcap_handle);
		*pcap_handle = NULL;

		/* is there another PCAP dump file? */
		(*src_filenames_id)++;
		if((*src_filenames_id) >= src_filenames_nr)
		{
			goto no_more_packet;
		}

		/* open next PCAP dump file */
		*pcap_handle = open_pcap_file("source", src_filenames[*src_filenames_id],
		                              link_len);
		if((*pcap_handle) == NULL)
		{
			goto error;
		}

		/* get the next packet in the current PCAP dump */
		*packet = (const uint8_t *) pcap_next(*pcap_handle, header);
		if((*packet) == NULL)
		{
			goto no_more_packet;
		}
	}

	return true;

no_more_packet:
error:
	return false;
}


/**
 * @brief Compare two network packets and print differences if any
 *
 * @param pkt1      The first packet
 * @param pkt1_size The size of the first packet
 * @param pkt2      The second packet
 * @param pkt2_size The size of the second packet
 * @return          Whether the packets are equal or not
 */
static int compare_packets(unsigned char *pkt1, int pkt1_size,
                           unsigned char *pkt2, int pkt2_size)
{
	int valid = 1;
	int min_size;
	int i;
	int j;
	int k;
	char str1[4][7];
	char str2[4][7];
	char sep1;
	char sep2;

	/* do not compare more than the shortest of the 2 packets */
	min_size = min(pkt1_size, pkt2_size);

	/* do not compare more than 180 bytes to avoid huge output */
	min_size = min(180, min_size);

	/* if packets are equal, do not print the packets */
	if(pkt1_size == pkt2_size && memcmp(pkt1, pkt2, pkt1_size) == 0)
	{
		goto skip;
	}

	/* packets are different */
	valid = 0;

	trace("------------------------------ Compare ------------------------------\n");
	trace("--------- reference ----------         ----------- new --------------\n");

	if(pkt1_size != pkt2_size)
	{
		trace("packets have different sizes (%d != %d), compare only the %d "
		      "first bytes\n", pkt1_size, pkt2_size, min_size);
	}

	j = 0;
	for(i = 0; i < min_size; i++)
	{
		if(pkt1[i] != pkt2[i])
		{
			sep1 = '#';
			sep2 = '#';
		}
		else
		{
			sep1 = '[';
			sep2 = ']';
		}

		sprintf(str1[j], "%c0x%.2x%c", sep1, pkt1[i], sep2);
		sprintf(str2[j], "%c0x%.2x%c", sep1, pkt2[i], sep2);

		/* make the output human readable */
		if(j >= 3 || (i + 1) >= min_size)
		{
			for(k = 0; k < 4; k++)
			{
				if(k < (j + 1))
				{
					trace("%s  ", str1[k]);
				}
				else /* fill the line with blanks if nothing to print */
				{
					trace("        ");
				}
			}

			trace("       ");

			for(k = 0; k < (j + 1); k++)
			{
				trace("%s  ", str2[k]);
			}

			trace("\n");

			j = 0;
		}
		else
		{
			j++;
		}
	}

	trace("----------------------- packets are different -----------------------\n");

skip:
	return valid;
}

