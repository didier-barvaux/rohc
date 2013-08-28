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
 * @file   sniffer.c
 * @brief  ROHC sniffer program
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * Objectives:
 *   Easily test the library on a network without affecting it.
 *   Gather compression statistics on a network without affecting it.
 *
 * How it works:
 *   The program sniffs IP packets from a given network interface, and tests
 *   the ROHC library with them. The packets are compressed, then decompressed,
 *   and finally compared with the original IP packets.
 *
 * Statistics:
 *   Some statistics are gathered during the tests. There are printed on the
 *   console. More stats should be added. A better way to export them remains to
 *   be added too.
 *
 * Post-mortem bug analysis:
 *   The program stops (assertion) if compression/decompression/comparison
 *   fails. The last library traces are recorded and printed in case of error.
 *   The last packets are recorded in PCAP files, one per context. This is
 *   also a good idea to run the program with core enabled. Many elements are
 *   thus available to reproduce and fix the discovered problems.
 */

#include "test.h"

#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <netinet/in.h>
#include <math.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>

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



/** Return the smaller value from the two */
#define min(x, y)  (((x) < (y)) ? (x) : (y))
/** Return the greater value from the two */
#define max(x, y)  (((x) > (y)) ? (x) : (y))

/** The device MTU (TODO: should not be hardcoded) */
#define DEV_MTU 1518

/** The maximal size for the ROHC packets */
#define MAX_ROHC_SIZE  (5 * 1024)

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

/** The minimum Ethernet length (in bytes) */
#define ETHER_FRAME_MIN_LEN  60


/** Some statistics collected by the sniffer */
struct sniffer_stats
{
	/** The size of one unit */
	unsigned long comp_unit_size;

	/** Cumulative number of units before ROHC compression */
	unsigned long comp_pre_nr_units;
	/** Cumulative number of bytes before ROHC compression */
	unsigned long comp_pre_nr_bytes;

	/** Cumulative number of units after ROHC compression */
	unsigned long comp_post_nr_units;
	/** Cumulative number of bytes after ROHC compression */
	unsigned long comp_post_nr_bytes;

	/** Cumulative number of packets per ROHC profile */
	unsigned long comp_nr_pkts_per_profile[ROHC_PROFILE_UDPLITE + 1];
	/** Cumulative number of packets per ROHC mode */
	unsigned long comp_nr_pkts_per_mode[R_MODE + 1];
	/** Cumulative number of packets per state */
	unsigned long comp_nr_pkts_per_state[SO + 1];
	/** Cumulative number of packets per packet type */
	unsigned long comp_nr_pkts_per_pkt_type[PACKET_UNKNOWN];
	/** Cumulative number of times a context is reused (first time included) */
	unsigned long comp_nr_reused_cid;

	/** Cumulative number of packets */
	unsigned long total_packets;
	/** Cumulative number of bad packets */
	unsigned long bad_packets;

	/** Cumulative number of (possible) lost packets */
	unsigned long nr_lost_packets;
	/** Cumulative number of (possible) loss bursts */
	unsigned long nr_loss_bursts;
	/** Maximum length of (possible) loss bursts */
	unsigned long max_loss_burst_len;
	/** Minimum length of (possible) loss bursts */
	unsigned long min_loss_burst_len;

	/** Cumulative number of (possible) mis-ordered packets */
	unsigned long nr_misordered_packets;
	/** Cumulative number of (possible) duplicated packets */
	unsigned long nr_duplicated_packets;
};


/* prototypes of private functions */

static void usage(void);
static void sniffer_interrupt(int signal);
static void sniffer_print_stats(int signal);

static bool sniff(const int use_large_cid,
                  const unsigned int max_contexts,
                  const int enabled_profiles[],
                  const char *const device_name)
	__attribute__((nonnull(4)));
static int compress_decompress(struct rohc_comp *comp,
                               struct rohc_decomp *decomp,
                               struct pcap_pkthdr header,
                               unsigned char *packet,
                               size_t link_len_src,
                               bool use_large_cid,
                               pcap_t *handle,
                               pcap_dumper_t *dumpers[],
                               unsigned int *const cid,
                               struct sniffer_stats *stats);

static int compare_packets(const unsigned char *const pkt1,
                           const size_t pkt1_size,
                           const unsigned char *const pkt2,
                           const size_t pkt2_size);

static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));
static int gen_false_random_num(const struct rohc_comp *const comp,
                                void *const user_context)
	__attribute__((nonnull(1)));
static bool rtp_detect_cb(const unsigned char *const ip,
                          const unsigned char *const udp,
                          const unsigned char *const payload,
                          const unsigned int payload_size,
                          void *const rtp_private)
	__attribute__((nonnull(1, 2, 3), warn_unused_result));


static inline uint16_t from32to16(uint32_t x);
static inline uint16_t ip_fast_csum(unsigned char *iph, size_t ihl);


/** Whether the application shall stop or not */
static bool stop_program;

/** Some statistics collected by the sniffer */
static struct sniffer_stats stats;

/** Whether the application runs in verbose mode or not */
static bool is_verbose;

/** The maximum number of traces to keep */
#define MAX_LAST_TRACES  5000
/** The maximum length of a trace */
#define MAX_TRACE_LEN  300

/** The ring buffer for the last traces */
static char last_traces[MAX_LAST_TRACES][MAX_LAST_TRACES + 1];
/** The index of the first trace */
static int last_traces_first;
/** The index of the last trace */
static int last_traces_last;


/**
 * @brief Main function for the ROHC sniffer application
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	int enabled_profiles[ROHC_PROFILE_UDPLITE + 1];
	char *cid_type = NULL;
	char *device_name = NULL;
	int max_contexts = ROHC_SMALL_CID_MAX + 1;
	int use_large_cid;
	int args_used;
	int i;

	/* by default, we don't stop */
	stop_program = false;

	/* reset stats */
	memset(&stats, 0, sizeof(struct sniffer_stats));
	stats.comp_unit_size = 1;

	/* set to quiet mode by default */
	is_verbose = false;

	/* enable all ROHC profiles by default */
	enabled_profiles[ROHC_PROFILE_UNCOMPRESSED] = 1;
	enabled_profiles[ROHC_PROFILE_RTP] = 1;
	enabled_profiles[ROHC_PROFILE_UDP] = 1;
	enabled_profiles[ROHC_PROFILE_ESP] = 1;
	enabled_profiles[ROHC_PROFILE_IP] = 1;
	enabled_profiles[0x0005] = -1;
	enabled_profiles[ROHC_PROFILE_TCP] = 1;
	enabled_profiles[ROHC_PROFILE_UDPLITE] = 1;

	/* no traces at the moment */
	for(i = 0; i < MAX_LAST_TRACES; i++)
	{
		last_traces[i][0] = '\0';
	}
	last_traces_first = -1;
	last_traces_last = -1;

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
			printf("ROHC sniffer program, based on library version %s\n",
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
			is_verbose = true;
		}
		else if(!strcmp(*argv, "--max-contexts"))
		{
			/* get the maximum number of contexts the test should use */
			max_contexts = atoi(argv[1]);
			args_used++;
		}
		else if(!strcmp(*argv, "--disable"))
		{
			/* disable the given ROHC profile */
			const int rohc_profile = atoi(argv[1]);
			if(rohc_profile >= ROHC_PROFILE_UNCOMPRESSED &&
			   rohc_profile <= ROHC_PROFILE_UDPLITE)
			{
				enabled_profiles[rohc_profile] = 0;
				fprintf(stderr, "disable ROHC profile 0x%04x\n", rohc_profile);
			}
			args_used++;
		}
		else if(cid_type == NULL)
		{
			/* get the type of CID to use within the ROHC library */
			cid_type = argv[0];
		}
		else if(device_name == NULL)
		{
			/* get the device on which we will capture packets to compress,
			 * then decompress */
			device_name = argv[0];
		}
		else
		{
			/* do not accept more than one filename without option name */
			usage();
			goto error;
		}
	}

	/* check CID type */
	if(!strcmp(cid_type, "smallcid"))
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
		fprintf(stderr, "invalid CID type '%s', only 'smallcid' and "
		        "'largecid' expected\n", cid_type);
		goto error;
	}

	/* the source filename is mandatory */
	if(device_name == NULL)
	{
		usage();
		goto error;
	}

	/* set signal handlers */
	signal(SIGINT, sniffer_interrupt);
	signal(SIGTERM, sniffer_interrupt);
	signal(SIGSEGV, sniffer_interrupt);
	signal(SIGABRT, sniffer_interrupt);
	signal(SIGUSR1, sniffer_print_stats);

	/* test ROHC compression/decompression with the packets from the file */
	if(!sniff(use_large_cid, max_contexts, enabled_profiles, device_name))
	{
		goto error;
	}

	return 0;

error:
	return 1;
}


/**
 * @brief Print usage of the sniffer test application
 */
static void usage(void)
{
	printf("ROHC sniffer tool: test the ROHC library with sniffed traffic\n"
	       "\n"
	       "usage: rohc_sniffer [OPTIONS] CID_TYPE DEVICE\n"
	       "\n"
	       "with:\n"
	       "  CID_TYPE            The type of CID to use among 'smallcid'\n"
	       "                      and 'largecid'\n"
	       "  DEVICE              The name of the network device to use\n"
	       "\n"
	       "options:\n"
	       "  -v                  Print version information and exit\n"
	       "  -h                  Print this usage and exit\n"
	       "  --max-contexts NUM  The maximum number of ROHC contexts to\n"
	       "                      simultaneously use during the test\n"
	       "  --disable PROFILE   A ROHC profile to disable\n"
	       "                      (may be specified several times)\n"
	       "  --verbose           Make the test more verbose\n");
}


/**
 * @brief Handle UNIX signals that interrupt the program
 *
 * @param signal  The received signal
 */
static void sniffer_interrupt(int signal)
{
	/* end the program with next captured packet */
	fprintf(stderr, "signal %d catched\n", signal);
	fflush(stderr);
	stop_program = true;

	/* for SIGSEGV/SIGABRT, print the last debug traces,
	 * then kill the program */
	if(signal == SIGSEGV || signal == SIGABRT)
	{
		const char *logfilename = "./sniffer.log";
		FILE *logfile;
		int ret;
		int i;

		logfile = fopen(logfilename, "w");
		if(logfile == NULL)
		{
			fprintf(stderr, "failed to create '%s' file: %s (%d)\n",
			        logfilename, strerror(errno), errno);
			fflush(stderr);
			raise(SIGKILL);
		}

		fprintf(logfile, "a problem occurred at packet #%lu\n\n",
		        stats.total_packets);

		if(last_traces_first == -1 || last_traces_last == -1)
		{
			fprintf(stderr, "no trace to record\n");
			fflush(stderr);
			raise(SIGKILL);
		}

		if(last_traces_first <= last_traces_last)
		{
			fprintf(stderr, "record the last %d traces...\n",
			        last_traces_last - last_traces_first);
			for(i = last_traces_first; i <= last_traces_last; i++)
			{
				fprintf(logfile, "%s", last_traces[i]);
			}
		}
		else
		{
			fprintf(stderr, "record the last %d traces...\n",
			        MAX_LAST_TRACES - last_traces_first + last_traces_last);
			for(i = last_traces_first;
			    i <= MAX_LAST_TRACES + last_traces_last;
			    i++)
			{
				fprintf(logfile, "%s", last_traces[i % MAX_LAST_TRACES]);
			}
		}

		ret = fclose(logfile);
		if(ret != 0)
		{
			fprintf(stderr, "failed to close log file '%s': %s (%d)\n",
			        logfilename, strerror(errno), errno);
		}

		fflush(stderr);
		if(signal == SIGSEGV)
		{
			struct sigaction action;
			memset(&action, 0, sizeof(struct sigaction));
			action.sa_handler = SIG_DFL;
			sigaction(SIGSEGV, &action, NULL);
			raise(signal);
		}
	}
}


/**
 * @brief Compute a percentage
 *
 * @param value  The value to compute percentage from
 * @param total  The total to compute percentage from
 * @return       The percentage
 */
static unsigned long long percent(const unsigned long value,
                                  const unsigned long total)
{
	unsigned long long percent;

	if(total == 0)
	{
		percent = 0;
	}
	else
	{
		percent = value;
		percent *= 100;
		percent /= total;
	}

	return percent;
}


/**
 * @brief Handle UNIX signals that print statistics
 *
 * @param signal  The received signal
 */
static void sniffer_print_stats(int signal)
{
	unsigned long total;
	int i;

	/* general */
	printf("general:\n");
	printf("\ttotal packets: %lu packets\n", stats.total_packets);
	printf("\tbad packets: %lu packets (%llu%%)\n", stats.bad_packets,
	       percent(stats.bad_packets, stats.total_packets));
	printf("\tloss (estim.):\n");
	printf("\t\t%lu packets among %lu bursts (%llu%%)\n", stats.nr_lost_packets,
	       stats.nr_loss_bursts,
	       percent(stats.nr_lost_packets, stats.total_packets));
	printf("\t\tpackets per burst: max %lu, avg %lu, min %lu\n",
	       stats.max_loss_burst_len, (stats.nr_loss_bursts != 0 ?
	       stats.nr_lost_packets / stats.nr_loss_bursts : 0),
	       stats.min_loss_burst_len);
	printf("\tmis-ordered packets (estim.): %lu packets (%llu%%)\n",
	       stats.nr_misordered_packets,
	       percent(stats.nr_misordered_packets, stats.total_packets));
	printf("\tduplicated packets (estim.): %lu packets (%llu%%)\n",
	       stats.nr_duplicated_packets,
	       percent(stats.nr_duplicated_packets, stats.total_packets));

	/* compression gain */
	printf("compression gain:\n");
	if(stats.comp_unit_size == 1)
	{
		printf("\tpre-compress: %lu bytes\n", stats.comp_pre_nr_bytes);
	}
	else
	{
		printf("\tpre-compress: %lu %s\n", stats.comp_pre_nr_units,
		       stats.comp_unit_size == 1000 ? "KB" :
		       (stats.comp_unit_size == 1000*1000 ? "MB" :
		        (stats.comp_unit_size == 1000*1000*1000 ? "GB" : "?")));
	}
	if(stats.comp_unit_size == 1)
	{
		printf("\tpost-compress: %lu bytes\n", stats.comp_post_nr_bytes);
	}
	else
	{
		printf("\tpost-compress: %lu %s\n", stats.comp_post_nr_units,
		       stats.comp_unit_size == 1000 ? "KB" :
		       (stats.comp_unit_size == 1000*1000 ? "MB" :
		        (stats.comp_unit_size == 1000*1000*1000 ? "GB" : "?")));
	}
	if(stats.comp_unit_size == 1)
	{
		printf("\tcompress ratio: %llu%% of total, ie. %llu%% of gain\n",
		       percent(stats.comp_post_nr_bytes, stats.comp_pre_nr_bytes),
		       100 - percent(stats.comp_post_nr_bytes, stats.comp_pre_nr_bytes));
	}
	else
	{
		printf("\tcompress ratio: %llu%% of total, ie. %llu%% of gain\n",
		       percent(stats.comp_post_nr_units, stats.comp_pre_nr_units),
		       100 - percent(stats.comp_post_nr_units, stats.comp_pre_nr_units));
	}
	printf("\tused and re-used contexts: %lu\n", stats.comp_nr_reused_cid);

	/* packets per profile */
	total = stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UNCOMPRESSED] +
	        stats.comp_nr_pkts_per_profile[ROHC_PROFILE_RTP] +
	        stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDP] +
	        stats.comp_nr_pkts_per_profile[ROHC_PROFILE_IP] +
	        stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDPLITE];
	printf("packets per profile:\n");
	printf("\tUncompressed profile: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UNCOMPRESSED],
	       percent(stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UNCOMPRESSED],
	               total));
	printf("\tIP/UDP/RTP profile: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_profile[ROHC_PROFILE_RTP],
	       percent(stats.comp_nr_pkts_per_profile[ROHC_PROFILE_RTP], total));
	printf("\tIP/UDP profile: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDP],
	       percent(stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDP], total));
	printf("\tIP-only profile: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_profile[ROHC_PROFILE_IP],
	       percent(stats.comp_nr_pkts_per_profile[ROHC_PROFILE_IP], total));
	printf("\tIP/UDP-Lite profile: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDPLITE],
	       percent(stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDPLITE], total));

	/* packets per mode */
	total = stats.comp_nr_pkts_per_mode[U_MODE] +
	        stats.comp_nr_pkts_per_mode[O_MODE] +
	        stats.comp_nr_pkts_per_mode[R_MODE];
	printf("packets per mode:\n");
	printf("\tU-mode: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_mode[U_MODE],
	       percent(stats.comp_nr_pkts_per_mode[U_MODE], total));
	printf("\tO-mode: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_mode[O_MODE],
	       percent(stats.comp_nr_pkts_per_mode[O_MODE], total));
	printf("\tR-mode: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_mode[R_MODE],
	       percent(stats.comp_nr_pkts_per_mode[R_MODE], total));

	/* packets per state */
	total = stats.comp_nr_pkts_per_state[IR] +
	        stats.comp_nr_pkts_per_state[FO] +
	        stats.comp_nr_pkts_per_state[SO];
	printf("packets per state:\n");
	printf("\tIR state: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_state[IR],
	       percent(stats.comp_nr_pkts_per_state[IR], total));
	printf("\tFO state: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_state[FO],
	       percent(stats.comp_nr_pkts_per_state[FO], total));
	printf("\tSO state: %lu packets (%llu%%)\n",
	       stats.comp_nr_pkts_per_state[SO],
	       percent(stats.comp_nr_pkts_per_state[SO], total));

	/* packets per packet type */
	printf("packets per packet type:\n");
	total = 0;
	for(i = PACKET_IR; i < PACKET_UNKNOWN; i++)
	{
		total += stats.comp_nr_pkts_per_pkt_type[i];
	}
	for(i = PACKET_IR; i < PACKET_UNKNOWN; i++)
	{
		printf("\tpacket type %s: %lu packets (%llu%%)\n",
		       rohc_get_packet_descr(i),
		       stats.comp_nr_pkts_per_pkt_type[i],
		       percent(stats.comp_nr_pkts_per_pkt_type[i], total));
	}
}


/**
 * @brief Test the ROHC library with a sniffed flow of IP packets going
 *        through one compressor/decompressor pair
 *
 * @param use_large_cid        Whether the compressor shall use large CIDs
 * @param max_contexts         The maximum number of ROHC contexts to use
 * @param enabled_profiles     The ROHC profiles to enable
 * @param device_name          The name of the network device
 * @return                     Whether the sniffer setup was OK
 */
static bool sniff(const int use_large_cid,
                  const unsigned int max_contexts,
                  const int enabled_profiles[],
                  const char *const device_name)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type_src;
	int link_len_src;
	struct pcap_pkthdr header;
	unsigned char *packet;

	struct rohc_comp *comp;
	struct rohc_decomp *decomp;

	pcap_dumper_t *dumpers[max_contexts];

	int ret;
	int i;

	/* statistics */
	unsigned int nb_ok = 0;
	unsigned int nb_bad = 0;
	unsigned int nb_internal_err = 0;
	unsigned int err_comp = 0;
	unsigned int err_decomp = 0;
	unsigned int nb_ref = 0;

	/* init status */
	bool status = false;

	assert(device_name != NULL);

	/* open the network device */
	handle = pcap_open_live(device_name, DEV_MTU, 0, 0, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "failed to open network device '%s': %s\n",
		       device_name, errbuf);
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type_src = pcap_datalink(handle);
	if(link_layer_type_src != DLT_EN10MB &&
	   link_layer_type_src != DLT_LINUX_SLL &&
	   link_layer_type_src != DLT_RAW)
	{
		fprintf(stderr, "link layer type %d not supported in source dump "
		        "(supported = %d, %d, %d)\n", link_layer_type_src, DLT_EN10MB,
		        DLT_LINUX_SLL, DLT_RAW);
		goto close_input;
	}

	if(link_layer_type_src == DLT_EN10MB)
	{
		link_len_src = ETHER_HDR_LEN;
	}
	else if(link_layer_type_src == DLT_LINUX_SLL)
	{
		link_len_src = LINUX_COOKED_HDR_LEN;
	}
	else /* DLT_RAW */
	{
		link_len_src = 0;
	}

	/* create the ROHC compressor */
	comp = rohc_alloc_compressor(ROHC_SMALL_CID_MAX, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto close_input;
	}

	/* set the callback for traces on compressor */
	if(!rohc_comp_set_traces_cb(comp, print_rohc_traces))
	{
		fprintf(stderr, "failed to set trace callback for compressor\n");
		goto destroy_comp;
	}

	/* enable the compression profiles */
	for(i = ROHC_PROFILE_UNCOMPRESSED; i <= ROHC_PROFILE_UDPLITE; i++)
	{
		if(enabled_profiles[i] == 1 && !rohc_comp_enable_profile(comp, i))
		{
			fprintf(stderr, "failed to enable compression profile 0x%04x\n", i);
			goto destroy_comp;
		}
		else if(enabled_profiles[i] == 0 && !rohc_comp_disable_profile(comp, i))
		{
			fprintf(stderr, "failed to disable compression profile 0x%04x\n", i);
			goto destroy_comp;
		}
	}

	/* configure SMALL_CID / LARGE_CID and MAX_CID */
	rohc_c_set_large_cid(comp, use_large_cid);
	rohc_c_set_max_cid(comp, max_contexts - 1);

	/* set the callback for random numbers on compressor */
	if(!rohc_comp_set_random_cb(comp, gen_false_random_num, NULL))
	{
		fprintf(stderr, "failed to set the random numbers callback for "
		        "compressor\n");
		goto destroy_comp;
	}

	/* reset list of RTP ports for compressor */
	if(!rohc_comp_reset_rtp_ports(comp))
	{
		fprintf(stderr, "failed to reset list of RTP ports for compressor\n");
		goto destroy_comp;
	}

	/* set the callback for RTP stream detection */
	if(!rohc_comp_set_rtp_detection_cb(comp, rtp_detect_cb, NULL))
	{
		fprintf(stderr, "failed to set the RTP stream detection callback for "
		        "compressor\n");
		goto destroy_comp;
	}

	/* create the decompressor (bi-directional mode) */
	decomp = rohc_alloc_decompressor(comp);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the decompressor\n");
		goto destroy_comp;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb(decomp, print_rohc_traces))
	{
		printf("cannot set trace callback for decompressor\n");
		goto destroy_decomp;
	}

	/* set CID type and MAX_CID for decompressor */
	if(use_large_cid)
	{
		if(!rohc_decomp_set_cid_type(decomp, ROHC_LARGE_CID))
		{
			fprintf(stderr, "failed to set CID type to large CIDs for "
			        "decompressor\n");
			goto destroy_decomp;
		}
		if(!rohc_decomp_set_max_cid(decomp, ROHC_LARGE_CID_MAX))
		{
			fprintf(stderr, "failed to set MAX_CID to %d for decompressor\n",
			        ROHC_LARGE_CID_MAX);
			goto destroy_decomp;
		}
	}
	else
	{
		if(!rohc_decomp_set_cid_type(decomp, ROHC_SMALL_CID))
		{
			fprintf(stderr, "failed to set CID type to small CIDs for "
			        "decompressor\n");
			goto destroy_decomp;
		}
		if(!rohc_decomp_set_max_cid(decomp, ROHC_SMALL_CID_MAX))
		{
			fprintf(stderr, "failed to set MAX_CID to %d for decompressor\n",
			        ROHC_SMALL_CID_MAX);
			goto destroy_decomp;
		}
	}

	/* enable the decompression profiles */
	for(i = ROHC_PROFILE_UNCOMPRESSED; i <= ROHC_PROFILE_UDPLITE; i++)
	{
		if(enabled_profiles[i] == 1 && !rohc_decomp_enable_profile(decomp, i))
		{
			fprintf(stderr, "failed to enable decompression profile 0x%04x\n", i);
			goto destroy_decomp;
		}
		else if(enabled_profiles[i] == 0 &&
		        !rohc_decomp_disable_profile(decomp, i))
		{
			fprintf(stderr, "failed to disable decompression profile 0x%04x\n", i);
			goto destroy_decomp;
		}
	}

	/* reset the PCAP dumpers (used to save sniffed packets in several PCAP
	 * files, one per Context ID) */
	bzero(dumpers, sizeof(pcap_dumper_t *) * max_contexts);

	/* for each sniffed packet */
	stats.total_packets = 0;
	while(!stop_program)
	{
		unsigned int cid = 0;

		/* try to capture a packet */
		packet = (unsigned char *) pcap_next(handle, &header);
		if(packet == NULL)
		{
			/* no packet captured, re-try */
			continue;
		}

		stats.total_packets++;

		if(stats.total_packets == 1 || (stats.total_packets % 100) == 0)
		{
			if(stats.total_packets > 1)
			{
				printf("\r");
			}
			printf("packet #%lu", stats.total_packets);
			fflush(stdout);
		}

		/* compress & decompress from compressor to decompressor */
		ret = compress_decompress(comp, decomp, header, packet,
		                          link_len_src, use_large_cid,
		                          handle, dumpers, &cid, &stats);
		if(ret == -1)
		{
			err_comp++;
		}
		else if(ret == -2)
		{
			err_decomp++;
		}
		else if(ret == 0)
		{
			nb_ref++;
		}
		else if(ret == 1)
		{
			nb_ok++;
		}
		else if(ret == -3)
		{
			nb_bad++;
			stats.bad_packets++;
		}
		else
		{
			nb_internal_err++;
		}

		/* in case of problem (ignore bad packets), just die! */
		if(ret != 1 && ret != -3)
		{
			fprintf(stderr, "packet #%lu, CID %u: stats OK, ERR(COMP), "
			        "ERR(DECOMP), ERR(REF), ERR(BAD), ERR(INTERNAL)\t="
			        "\t%u\t%u\t%u\t%u\t%u\t%u\n",
			        stats.total_packets, cid, nb_ok, err_comp, err_decomp,
			        nb_ref, nb_bad, nb_internal_err);

			/* last debug traces are recorded in SIGABRT handler */
			assert(0);
		}
	}

	if(stop_program)
	{
		printf("program stopped by signal\n");
	}

	status = true;

	/* close PCAP dumpers */
	for(i = 0; i < max_contexts; i++)
	{
		if(dumpers[i] != NULL)
		{
			printf("close dump file for context with ID %d\n", i);
			pcap_dump_close(dumpers[i]);
		}
	}

destroy_decomp:
	rohc_free_decompressor(decomp);
destroy_comp:
	rohc_free_compressor(comp);
close_input:
	pcap_close(handle);
error:
	return status;
}


/**
 * @brief Compress and decompress one uncompressed IP packet with the given
 *        compressor and decompressor
 *
 * @param comp           The compressor to use to compress the IP packet
 * @param decomp         The decompressor to use to decompress the IP packet
 * @param header         The PCAP header for the packet
 * @param packet         The packet to compress/decompress (link layer included)
 * @param link_len_src   The length of the link layer header before IP data
 * @param use_large_cid  Whether use large CID or not
 * @param handle         The PCAP handler that sniffed the packet
 * @param dumpers        The PCAP dumpers, one per context
 * @param cid            OUT: the CID used for the last packet
 * @param stats          IN/OUT: The sniffer stats
 * @return               1 if the process is successful
 *                       0 if the decompressed packet doesn't match the
 *                         original one
 *                       -1 if an error occurs while compressing
 *                       -2 if an error occurs while decompressing
 *                       -3 if the link layer is not Ethernet
 *                       -4 if (de)compression info cannot be retrieved
 */
static int compress_decompress(struct rohc_comp *comp,
                               struct rohc_decomp *decomp,
                               struct pcap_pkthdr header,
                               unsigned char *packet,
                               size_t link_len_src,
                               bool use_large_cid,
                               pcap_t *handle,
                               pcap_dumper_t *dumpers[],
                               unsigned int *const cid,
                               struct sniffer_stats *stats)
{
	const struct timespec arrival_time = { .tv_sec = 0, .tv_nsec = 0 };
	unsigned char *ip_packet;
	size_t ip_size;
	static unsigned char output_packet[max(ETHER_HDR_LEN, LINUX_COOKED_HDR_LEN) + MAX_ROHC_SIZE];
	unsigned char *rohc_packet;
	size_t rohc_size;
	rohc_comp_last_packet_info2_t comp_last_packet_info;
	rohc_decomp_last_packet_info_t decomp_last_packet_info;
	static unsigned char decomp_packet[MAX_ROHC_SIZE];
	size_t decomp_size;
	unsigned long possible_unit;
	int ret;

	/* check Ethernet frame length */
	if(header.len <= link_len_src || header.len != header.caplen)
	{
		if(is_verbose)
		{
			fprintf(stderr, "bad PCAP packet (len = %d, caplen = %d)\n",
			        header.len, header.caplen);
		}
		ret = -3;
		goto error;
	}

	ip_packet = packet + link_len_src;
	ip_size = header.len - link_len_src;
	rohc_packet = output_packet + link_len_src;

	/* check for padding after the IP packet in the Ethernet payload */
	if(link_len_src == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
	{
		int version;
		uint16_t tot_len;

		version = (ip_packet[0] >> 4) & 0x0f;

		if(version == 4)
		{
			memcpy(&tot_len, ip_packet + 2, sizeof(uint16_t));
			tot_len = ntohs(tot_len);
		}
		else
		{
			const size_t ipv6_header_len = 40;
			memcpy(&tot_len, ip_packet + 4, sizeof(uint16_t));
			tot_len = ipv6_header_len + ntohs(tot_len);
		}

		if(tot_len < ip_size)
		{
			if(is_verbose)
			{
				fprintf(stderr, "the Ethernet frame has %zd bytes of padding "
				        "after the %u byte IP packet!\n", ip_size - tot_len,
				        tot_len);
			}
			ip_size = tot_len;
		}
	}

	/* discard IPv4 packets with wrong checksums and fix IPv4 packets with
	 * non-standard-compliant 0xffff checksums instead of 0x0000 (Windows
	 * Vista seems to be faulty for the latter), to avoid false comparison
	 * failures after decompression) */
	if(((ip_packet[0] >> 4) & 0x0f) == 4 && ip_size >= 20)
	{
		if(ip_fast_csum(ip_packet, (ip_packet[0] & 0x0f)) != 0)
		{
			fprintf(stderr, "discard IPv4 packet with bad IP checksum\n");
			goto ignore;
		}

		if(ip_packet[10] == 0xff && ip_packet[11] == 0xff)
		{
			ip_packet[10] = 0x00;
			ip_packet[11] = 0x00;
		}
	}

	/* compress the IP packet */
	ret = rohc_compress3(comp, arrival_time, ip_packet, ip_size,
	                     rohc_packet, MAX_ROHC_SIZE, &rohc_size);
	if(ret != ROHC_OK)
	{
		pcap_dumper_t *dumper;

		fprintf(stderr, "compression failed\n");
		ret = -1;

		/* open the new dumper */
		dumper = pcap_dump_open(handle, "./dump_stream_default.pcap");
		if(dumper == NULL)
		{
			fprintf(stderr, "failed to open new dump file '%s'\n",
			        "./dump_stream_default.pcap");
			assert(0);
			goto error;
		}

		/* dump the IP packet */
		fprintf(stderr, "dump packet in file '%s'\n",
		        "./dump_stream_default.pcap");
		pcap_dump((u_char *) dumper, &header, packet);

		fprintf(stderr, "close dump file\n");
		pcap_dump_close(dumper);

		goto error;
	}

	/* get some statistics about the last compressed packet */
	comp_last_packet_info.version_major = 0;
	comp_last_packet_info.version_minor = 0;
	if(!rohc_comp_get_last_packet_info2(comp, &comp_last_packet_info))
	{
		fprintf(stderr, "failed to get compression info\n");
		ret = -4;
		goto error;
	}
	stats->comp_pre_nr_bytes += ip_size;
	stats->comp_post_nr_bytes += rohc_size;
	possible_unit = stats->comp_unit_size;
	if(stats->comp_unit_size == 1)
	{
		if(stats->comp_pre_nr_bytes >= (100 * 1000) &&
		   stats->comp_post_nr_bytes >= (100 * 1000))
		{
			possible_unit = 1000;
		}
	}
	else
	{
		if(stats->comp_pre_nr_units >= (100 * 1000) &&
		   stats->comp_post_nr_units >= (100 * 1000))
		{
			possible_unit = stats->comp_unit_size * 1000;
		}
	}
	if(possible_unit != stats->comp_unit_size)
	{
		if(stats->comp_unit_size == 1)
		{
			stats->comp_pre_nr_units =
				stats->comp_pre_nr_bytes / 1000;
			stats->comp_pre_nr_bytes %= 1000;
			stats->comp_post_nr_units =
				stats->comp_post_nr_bytes / 1000;
			stats->comp_post_nr_bytes %= 1000;
		}
		else
		{
			unsigned long rest;
			rest = stats->comp_pre_nr_units % 1000;
			stats->comp_pre_nr_units /= 1000;
			stats->comp_pre_nr_bytes += rest * possible_unit;
			rest = stats->comp_post_nr_units % 1000;
			stats->comp_post_nr_units /= 1000;
			stats->comp_post_nr_bytes += rest * possible_unit;
		}
		stats->comp_unit_size = possible_unit;
	}
	else
	{
		if(stats->comp_unit_size > 1)
		{
			stats->comp_pre_nr_units +=
				stats->comp_pre_nr_bytes / stats->comp_unit_size;
			stats->comp_pre_nr_bytes %= stats->comp_unit_size;
			stats->comp_post_nr_units +=
				stats->comp_post_nr_bytes / stats->comp_unit_size;
			stats->comp_post_nr_bytes %= stats->comp_unit_size;
		}
	}
	stats->comp_nr_pkts_per_profile[comp_last_packet_info.profile_id]++;
	stats->comp_nr_pkts_per_mode[comp_last_packet_info.context_mode]++;
	stats->comp_nr_pkts_per_state[comp_last_packet_info.context_state]++;
	stats->comp_nr_pkts_per_pkt_type[comp_last_packet_info.packet_type]++;
	if(comp_last_packet_info.is_context_init)
	{
		stats->comp_nr_reused_cid++;
	}

	/* open a new dumper if none exists or the stream changed */
	if(comp_last_packet_info.is_context_init)
	{
		char dump_filename[1024];

		snprintf(dump_filename, 1024, "./dump_stream_cid_%u.pcap",
		         comp_last_packet_info.context_id);
		/* TODO: check result */

		/* close the previous dumper and remove its file if one was opened */
		if(dumpers[comp_last_packet_info.context_id] != NULL)
		{
			if(is_verbose)
			{
				printf("replace dump file '%s' for context with ID %u\n",
				       dump_filename, comp_last_packet_info.context_id);
			}
			pcap_dump_close(dumpers[comp_last_packet_info.context_id]);
			unlink(dump_filename);
			/* TODO: check result */
		}

		/* open the new dumper */
		dumpers[comp_last_packet_info.context_id] =
			pcap_dump_open(handle, dump_filename);
		if(dumpers[comp_last_packet_info.context_id] == NULL)
		{
			fprintf(stderr, "failed to open new dump file '%s' for context "
			        "with ID %u\n", dump_filename,
			        comp_last_packet_info.context_id);
			assert(0);
			goto error;
		}
	}

	/* dump the IP packet */
	pcap_dump((u_char *) dumpers[comp_last_packet_info.context_id],
	          &header, packet);

	/* record the CID */
	*cid = comp_last_packet_info.context_id;

	/* decompress the ROHC packet */
	ret = rohc_decompress2(decomp, arrival_time, rohc_packet, rohc_size,
	                       decomp_packet, MAX_ROHC_SIZE, &decomp_size);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "decompression failed\n");
		ret = -2;
		goto error;
	}

	/* get some statistics about the last decompressed packet */
	decomp_last_packet_info.version_major = 0;
	decomp_last_packet_info.version_minor = 0;
	if(!rohc_decomp_get_last_packet_info(decomp, &decomp_last_packet_info))
	{
		fprintf(stderr, "failed to get decompression info\n");
		ret = -4;
		goto error;
	}
	stats->nr_lost_packets += decomp_last_packet_info.nr_lost_packets;
	if(decomp_last_packet_info.nr_lost_packets > 0)
	{
		stats->nr_loss_bursts++;
		if(decomp_last_packet_info.nr_lost_packets > stats->max_loss_burst_len)
		{
			stats->max_loss_burst_len = decomp_last_packet_info.nr_lost_packets;
		}
		if(decomp_last_packet_info.nr_lost_packets < stats->min_loss_burst_len ||
		   stats->min_loss_burst_len == 0)
		{
			stats->min_loss_burst_len = decomp_last_packet_info.nr_lost_packets;
		}
	}
	stats->nr_misordered_packets += decomp_last_packet_info.nr_misordered_packets;
	if(decomp_last_packet_info.is_duplicated)
	{
		stats->nr_duplicated_packets++;
	}

	/* compare the decompressed packet with the original one */
	if(!compare_packets(ip_packet, ip_size, decomp_packet, decomp_size))
	{
		fprintf(stderr, "comparison with original packet failed\n");
		ret = 0;
	}
	else
	{
		/* comparison is OK */
		ret = 1;
	}

error:
	return ret;

ignore:
	return 1;
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
static int compare_packets(const unsigned char *const pkt1,
                           const size_t pkt1_size,
                           const unsigned char *const pkt2,
                           const size_t pkt2_size)
{
	int valid = 1;
	size_t min_size;
	int i, j, k;
	char str1[4][7], str2[4][7];
	char sep1, sep2;

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

	printf("------------------------------ Compare ------------------------------\n");
	printf("--------- reference ----------         ----------- new --------------\n");

	if(pkt1_size != pkt2_size)
	{
		printf("packets have different sizes (%zd != %zd), compare only the %zd "
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
					printf("%s  ", str1[k]);
				}
				else /* fill the line with blanks if nothing to print */
				{
					printf("        ");
				}
			}

			printf("      ");

			for(k = 0; k < (j + 1); k++)
			{
				printf("%s  ", str2[k]);
			}

			printf("\n");

			j = 0;
		}
		else
		{
			j++;
		}
	}

	printf("----------------------- packets are different -----------------------\n");

skip:
	return valid;
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
                              const char *format, ...)
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

	if(last_traces_last == -1)
	{
		last_traces_last = 0;
	}
	else
	{
		last_traces_last = (last_traces_last + 1) % MAX_LAST_TRACES;
	}
	{
		va_list args;
		va_start(args, format);
		vsnprintf(last_traces[last_traces_last], MAX_TRACE_LEN + 1, format, args);
		/* TODO: check return code */
		last_traces[last_traces_last][MAX_TRACE_LEN] = '\0';
		va_end(args);
	}
	if(last_traces_first == -1)
	{
		last_traces_first = 0;
	}
	else if(last_traces_first == last_traces_last)
	{
		last_traces_first = (last_traces_first + 1) % MAX_LAST_TRACES;
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


/**
 * @brief The detection callback which do detect RTP stream
 *
 * @param ip           The inner ip packet
 * @param udp          The udp header of the packet
 * @param payload      The payload of the packet
 * @param payload_size The size of the payload (in bytes)
 * @return             1 if the packet is an RTP packet, 0 otherwise
 */
static bool rtp_detect_cb(const unsigned char *const ip,
                          const unsigned char *const udp,
                          const unsigned char *const payload,
                          const unsigned int payload_size,
                          void *const rtp_private)
{
	const uint16_t max_well_known_port = 1024;
	const uint16_t sip_port = 5060;
	uint16_t udp_sport;
	uint16_t udp_dport;
	uint16_t udp_len;
	uint8_t rtp_pt;
	bool is_rtp = false;

	assert(ip != NULL);
	assert(udp != NULL);
	assert(payload != NULL);
	assert(rtp_private == NULL);

	/* retrieve UDP source and destination ports and UDP length */
	memcpy(&udp_sport, udp, sizeof(uint16_t));
	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));
	memcpy(&udp_len, udp + 4, sizeof(uint16_t));

	/* RTP streams do not use well known ports */
	if(ntohs(udp_sport) <= max_well_known_port ||
	   ntohs(udp_dport) <= max_well_known_port)
	{
		goto not_rtp;
	}

	/* SIP (UDP/5060) is not RTP */
	if(ntohs(udp_sport) == sip_port && ntohs(udp_dport) == sip_port)
	{
		goto not_rtp;
	}

	/* the UDP destination port of RTP packet is even (the RTCP destination
	 * port are RTP destination port + 1, so it is odd) */
	if((ntohs(udp_sport) % 2) != 0 || (ntohs(udp_dport) % 2) != 0)
	{
		goto not_rtp;
	}

	/* UDP Length shall not be too large */
	if(ntohs(udp_len) > 200)
	{
		goto not_rtp;
	}

	/* UDP payload shall at least contain the smallest RTP header */
	if(payload_size < 12)
	{
		goto not_rtp;
	}

	/* RTP version bits shall be 2 */
	if(((payload[0] >> 6) & 0x3) != 0x2)
	{
		goto not_rtp;
	}

	/* RTP payload type shall be GSM (0x03), ITU-T G.723 (0x04),
	 * ITU-T G.729 (0x12), dynamic RTP type 97 (0x61),
	 * telephony-event (0x65), Speex (0x72),
	 * or dynamic RTP type 125 (0x7d) */
	rtp_pt = payload[1] & 0x7f;
	if (rtp_pt != 0x03 && rtp_pt != 0x04 && rtp_pt != 0x12 &&
	    rtp_pt != 0x61 && rtp_pt != 0x65 && rtp_pt != 0x72 &&
	    rtp_pt != 0x7d)
	{
		goto not_rtp;
	}

	/* we think that the UDP packet is a RTP packet */
	is_rtp = true;

not_rtp:
	return is_rtp;
}


static inline uint16_t from32to16(uint32_t x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

/**
 *  This is a version of ip_compute_csum() optimized for IP headers,
 *  which always checksum on 4 octet boundaries.
 */
static inline uint16_t ip_fast_csum(unsigned char *iph, size_t ihl)
{
	const unsigned char *buff = iph;
	size_t len = ihl * 4;
	bool odd;
	size_t count;
	uint32_t result = 0;

	if(len <= 0)
	{
		goto out;
	}
	odd = 1 & (uintptr_t) buff;
	if(odd)
	{
#ifdef __LITTLE_ENDIAN
		result = *buff;
#else
		result += (*buff << 8);
#endif
		len--;
		buff++;
	}
	count = len >> 1; /* nr of 16-bit words.. */
	if(count)
	{
		if(2 & (uintptr_t) buff)
		{
			result += *(uint16_t *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1; /* nr of 32-bit words.. */
		if(count)
		{
			uint32_t carry = 0;
			do
			{
				uint32_t word = *(uint32_t *) buff;
				count--;
				buff += sizeof(uint32_t);
				result += carry;
				result += word;
				carry = (word > result);
			}
			while(count);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if(len & 2)
		{
			result += *(uint16_t *) buff;
			buff += 2;
		}
	}
	if(len & 1)
	{
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	}
	result = from32to16(result);
	if(odd)
	{
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
out:
	return ~result;
}


