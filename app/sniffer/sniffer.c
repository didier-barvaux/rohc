/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2012,2013 Viveris Technologies
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

#include "config.h" /* for HAVE_*_H and PACKAGE_BUGREPORT */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <math.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>

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
#include <rohc/rohc_decomp.h>



/** Return the smaller value from the two */
#define min(x, y)  (((x) < (y)) ? (x) : (y))
/** Return the greater value from the two */
#define max(x, y)  (((x) > (y)) ? (x) : (y))

/** The device MTU (TODO: should not be hardcoded) */
#define DEV_MTU 1518U

/** The maximal size for the ROHC packets */
#define MAX_ROHC_SIZE  (5 * 1024)

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16U

/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14U

/** The minimum Ethernet length (in bytes) */
#define ETHER_FRAME_MIN_LEN  60U


/** Some statistics collected by the sniffer */
struct sniffer_stats_t
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
	unsigned long comp_nr_pkts_per_mode[ROHC_R_MODE + 1];
	/** Cumulative number of packets per state */
	unsigned long comp_nr_pkts_per_state[ROHC_COMP_STATE_SO + 1];
	/** Cumulative number of packets per packet type */
	unsigned long comp_nr_pkts_per_pkt_type[ROHC_PACKET_TCP_SEQ_8 + 1];
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
static void sniffer_interrupt(int signum);
static void sniffer_print_stats(int signum);

static bool sniff(const rohc_cid_type_t cid_type,
                  const size_t max_contexts,
                  const int enabled_profiles[],
                  const char *const device_name)
	__attribute__((warn_unused_result, nonnull(4)));
static int compress_decompress(struct rohc_comp *comp,
                               struct rohc_decomp *decomp,
                               struct pcap_pkthdr header,
                               unsigned char *packet,
                               size_t link_len_src,
                               pcap_t *handle,
                               pcap_dumper_t *dumpers[],
                               struct rohc_buf *const feedback_send,
                               unsigned int *const cid,
                               struct sniffer_stats_t *stats);

static int compare_packets(const struct rohc_buf pkt1,
                           const struct rohc_buf pkt2)
	__attribute__((warn_unused_result));
static size_t get_tcp_opt_padding(const struct rohc_buf packet)
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
static bool rtp_detect_cb(const unsigned char *const ip,
                          const unsigned char *const udp,
                          const unsigned char *const payload,
                          const unsigned int payload_size,
                          void *const rtp_private)
	__attribute__((nonnull(1, 2, 3), warn_unused_result));


/** Whether the application shall stop or not */
static bool stop_program;

/** Some statistics collected by the sniffer */
static struct sniffer_stats_t sniffer_stats;

/** Whether the application runs in daemon mode or not */
static bool is_daemon;

/** Whether the application runs in verbose mode or not */
static bool is_verbose;

/** Whether the application prints stats at regular interval of time or not */
static bool do_print_stat;

/** The PCAP dumpers */
static pcap_dumper_t *sniffer_dumpers[ROHC_LARGE_CID_MAX + 1] = { 0 };

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

/** Whether to print traces on stderr or not */
static bool do_print_stderr = true;

/** Print a trace in syslog and eventually on stderr */
#define SNIFFER_LOG(prio, format, ...) \
	do \
	{ \
		if(do_print_stderr) \
		{ \
			fprintf(stderr, format "\n", ##__VA_ARGS__); \
			fflush(stderr); \
		} \
		syslog(prio, format, ##__VA_ARGS__); \
	} while(0)


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
	const int do_change_dir = 1;
	const int do_close_fds = 1;
	int enabled_profiles[ROHC_PROFILE_UDPLITE + 1];
	char *pidfilename = NULL;
	char *cid_type_name = NULL;
	char *device_name = NULL;
	int max_contexts = ROHC_SMALL_CID_MAX + 1;
	rohc_cid_type_t cid_type;
	int args_used;
	int ret;
	int i;

	/* by default, we don't stop */
	stop_program = false;

	/* reset stats */
	memset(&sniffer_stats, 0, sizeof(struct sniffer_stats_t));
	sniffer_stats.comp_unit_size = 1;

	/* set to quiet mode by default */
	is_verbose = false;
	/* disable stat printing by default */
	do_print_stat = false;
	/* disable daemon mode by default */
	is_daemon = false;

	/* enable all ROHC profiles by default */
	enabled_profiles[ROHC_PROFILE_UNCOMPRESSED] = 1;
	enabled_profiles[ROHC_PROFILE_RTP] = 1;
	enabled_profiles[ROHC_PROFILE_UDP] = 1;
	enabled_profiles[ROHC_PROFILE_ESP] = 1;
	enabled_profiles[ROHC_PROFILE_IP] = 1;
	enabled_profiles[0x0005] = -1;
	enabled_profiles[ROHC_PROFILE_TCP] = 1;
	enabled_profiles[0x0007] = -1;
	enabled_profiles[ROHC_PROFILE_UDPLITE] = 1;

	/* no traces at the moment */
	for(i = 0; i < MAX_LAST_TRACES; i++)
	{
		last_traces[i][0] = '\0';
	}
	last_traces_first = -1;
	last_traces_last = -1;

	/* traces go to syslog */
	openlog("rohc_sniffer", LOG_PID, LOG_USER);

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
			printf("rohc_sniffer version %s\n", rohc_version());
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
		else if(!strcmp(*argv, "--stat"))
		{
			/* enable stat mode */
			do_print_stat = true;
		}
		else if(!strcmp(*argv, "--daemon") || !strcmp(*argv, "-d"))
		{
			/* enable daemon mode */
			is_daemon = true;
		}
		else if(!strcmp(*argv, "-p") || !strcmp(*argv, "--pidfile"))
		{
			/* get the name of the pidfile */
			pidfilename = argv[1];
			args_used++;
		}
		else if(!strcmp(*argv, "-m") || !strcmp(*argv, "--max-contexts"))
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
				SNIFFER_LOG(LOG_INFO, "disable ROHC profile 0x%04x", rohc_profile);
			}
			args_used++;
		}
		else if(cid_type_name == NULL)
		{
			/* get the type of CID to use within the ROHC library */
			cid_type_name = argv[0];
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
	if(!strcmp(cid_type_name, "smallcid"))
	{
		cid_type = ROHC_SMALL_CID;

		/* the maximum number of ROHC contexts should be valid */
		if(max_contexts < 1 || max_contexts > (ROHC_SMALL_CID_MAX + 1))
		{
			SNIFFER_LOG(LOG_WARNING, "the maximum number of ROHC contexts "
			            "should be between 1 and %u", ROHC_SMALL_CID_MAX + 1);
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
			SNIFFER_LOG(LOG_WARNING, "the maximum number of ROHC contexts "
			            "should be between 1 and %u", ROHC_LARGE_CID_MAX + 1);
			usage();
			goto error;
		}
	}
	else
	{
		SNIFFER_LOG(LOG_WARNING, "invalid CID type '%s', only 'smallcid' and "
		            "'largecid' expected", cid_type_name);
		goto error;
	}

	/* the source filename is mandatory */
	if(device_name == NULL)
	{
		SNIFFER_LOG(LOG_WARNING, "device name is mandatory");
		usage();
		goto error;
	}

	/* --pidfile cannot be used in foreground mode */
	if(pidfilename != NULL && !is_daemon)
	{
		SNIFFER_LOG(LOG_WARNING, "option --pidfile cannot be used without "
		            "option --daemon");
		usage();
		goto error;
	}

	/* run in daemon mode if asked */
	if(is_daemon)
	{
		const char dirname[] = "/var/tmp/rohc_sniffer/";

		ret = daemon(do_change_dir, do_close_fds);
		if(ret != 0)
		{
			SNIFFER_LOG(LOG_WARNING, "failed to run in background: %s (%d)",
			            strerror(errno), errno);
			goto error;
		}

		/* in daemon mode, do not write on stderr anymore, only syslog */
		do_print_stderr = false;

		/* create temporary directory for captures */
		ret = mkdir(dirname, 0700);
		if(ret != 0 && errno != EEXIST)
		{
			SNIFFER_LOG(LOG_WARNING, "failed to create directory '%s': %s (%d)",
			            dirname, strerror(errno), errno);
			goto error;
		}

		/* enter the temporary directory */
		ret = chdir(dirname);
		if(ret != 0)
		{
			SNIFFER_LOG(LOG_WARNING, "failed to enter directory '%s': %s (%d)",
			            dirname, strerror(errno), errno);
			goto error;
		}

		if(pidfilename != NULL)
		{
			FILE *pidfile;

			pidfile = fopen(pidfilename, "w");
			if(pidfile == NULL)
			{
				SNIFFER_LOG(LOG_WARNING, "failed to open PID file '%s': %s (%d)",
				            pidfilename, strerror(errno), errno);
				goto error;
			}
			ret = fprintf(pidfile, "%d\n", getpid());
			if(ret <= 0)
			{
				SNIFFER_LOG(LOG_WARNING, "failed to write PID in file '%s': "
				            "%s (%d)", pidfilename, strerror(errno), errno);
				ret = fclose(pidfile);
				if(ret != 0)
				{
					SNIFFER_LOG(LOG_WARNING, "failed to close PID file '%s': "
					            "%s (%d)", pidfilename, strerror(errno), errno);
				}
				goto error;
			}
			ret = fclose(pidfile);
			if(ret != 0)
			{
				SNIFFER_LOG(LOG_WARNING, "failed to close PID file '%s': %s (%d)",
				            pidfilename, strerror(errno), errno);
				goto error;
			}
		}
	}

	SNIFFER_LOG(LOG_INFO, "starting ROHC sniffer");

	/* set signal handlers */
	signal(SIGINT, sniffer_interrupt);
	signal(SIGTERM, sniffer_interrupt);
	signal(SIGSEGV, sniffer_interrupt);
	signal(SIGABRT, sniffer_interrupt);
	signal(SIGUSR1, sniffer_print_stats);
	{
		struct sigaction action;
		memset(&action, 0, sizeof(struct sigaction));
		action.sa_handler = SIG_IGN;
		sigaction(SIGHUP, &action, NULL);
	}

	/* test ROHC compression/decompression with the packets from the file */
	if(!sniff(cid_type, max_contexts, enabled_profiles, device_name))
	{
		goto error;
	}

	if(pidfilename != NULL)
	{
		ret = unlink(pidfilename);
		if(ret != 0)
		{
			SNIFFER_LOG(LOG_WARNING, "failed to remove PID file '%s': %s (%d)",
			            pidfilename, strerror(errno), errno);
			goto error;
		}
	}
	closelog();
	return 0;

error:
	if(pidfilename != NULL)
	{
		ret = unlink(pidfilename);
		if(ret != 0)
		{
			SNIFFER_LOG(LOG_WARNING, "failed to remove PID file '%s': %s (%d)",
			            pidfilename, strerror(errno), errno);
		}
	}
	closelog();
	return 1;
}


/**
 * @brief Print usage of the sniffer test application
 */
static void usage(void)
{
	printf("The ROHC sniffer tests the ROHC library with sniffed traffic\n"
	       "\n"
	       "You need to be root (or to have POSIX capability CAP_NET_ADMIN)\n"
	       "to run the ROHC sniffer.\n"
	       "\n"
	       "Usage: rohc_sniffer [OPTIONS] CID_TYPE DEVICE\n"
	       "\n"
	       "Options:\n"
	       "  CID_TYPE                The type of CID to use among 'smallcid'\n"
	       "                          and 'largecid'\n"
	       "  DEVICE                  The name of the network device to use\n"
	       "  -v, --version           Print version information and exit\n"
	       "  -h, --help              Print this usage and exit\n"
	       "  -d, --daemon            Run in background, trace in syslog\n"
	       "  -p, --pidfile FILE      Write daemon PID in the given file\n"
	       "  -m, --max-contexts NUM  The maximum number of ROHC contexts to\n"
	       "                          simultaneously use during the test\n"
	       "      --disable PROFILE   A ROHC profile to disable\n"
	       "                          (may be specified several times)\n"
	       "      --verbose           Make the test more verbose\n"
	       "      --stat              Print statistics at regular interval of time\n"
	       "\n"
	       "Examples:\n"
	       "  rohc_sniffer smallcid eth0          compress traffic from eth0\n"
	       "                                      with small CIDs\n"
	       "  rohc_sniffer -m 450 largecid wlan0  compress traffic from\n"
	       "                                      wlan0 with large CIDs, no\n"
	       "                                      more than 450 streams\n"
	       "\n"
	       "Report bugs to <" PACKAGE_BUGREPORT ">.\n");
}


/**
 * @brief Handle UNIX signals that interrupt the program
 *
 * @param signum  The received signal
 */
static void sniffer_interrupt(int signum)
{
	/* end the program with next captured packet */
	SNIFFER_LOG(LOG_NOTICE, "signal %d catched", signum);
	stop_program = true;

	/* for SIGSEGV/SIGABRT, close the PCAP dumps, print the last debug traces,
	 * then kill the program */
	if(signum == SIGSEGV || signum == SIGABRT)
	{
		int i;

		if(signum == SIGSEGV)
		{
			SNIFFER_LOG(LOG_WARNING, "a segfault occurred at packet #%lu",
			            sniffer_stats.total_packets);
		}
		else
		{
			SNIFFER_LOG(LOG_WARNING, "an assertion failed at packet #%lu",
			            sniffer_stats.total_packets);
		}

		/* close PCAP dumpers */
		for(i = 0; i <= ROHC_LARGE_CID_MAX; i++)
		{
			if(sniffer_dumpers[i] != NULL)
			{
				SNIFFER_LOG(LOG_INFO, "close dump file for context with ID %u", i);
				pcap_dump_close(sniffer_dumpers[i]);
			}
		}

		/* print last debug traces */
		if(last_traces_first == -1 || last_traces_last == -1)
		{
			SNIFFER_LOG(LOG_NOTICE, "no trace to print");
			raise(SIGKILL);
		}

		if(last_traces_first <= last_traces_last)
		{
			SNIFFER_LOG(LOG_NOTICE, "print the last %d traces...",
			            last_traces_last - last_traces_first);
			for(i = last_traces_first; i <= last_traces_last; i++)
			{
				SNIFFER_LOG(LOG_WARNING, "%s", last_traces[i]);
			}
		}
		else
		{
			SNIFFER_LOG(LOG_NOTICE, "print the last %d traces...",
			            MAX_LAST_TRACES - last_traces_first + last_traces_last);
			for(i = last_traces_first;
			    i <= MAX_LAST_TRACES + last_traces_last;
			    i++)
			{
				SNIFFER_LOG(LOG_WARNING, "%s", last_traces[i % MAX_LAST_TRACES]);
			}
		}
		SNIFFER_LOG(LOG_NOTICE, "all last traces printed, you can analyze "
		            "the problem, have a nice day!");

		if(signum == SIGSEGV)
		{
			struct sigaction action;
			memset(&action, 0, sizeof(struct sigaction));
			action.sa_handler = SIG_DFL;
			sigaction(SIGSEGV, &action, NULL);
			raise(signum);
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
static unsigned long long compute_percent(const unsigned long value,
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
 * @param signum  The received signal
 */
static void sniffer_print_stats(int signum __attribute__((unused)))
{
	unsigned long total;
	int i;

	SNIFFER_LOG(LOG_INFO, "dump ROHC sniffer statistics...");

	/* general */
	SNIFFER_LOG(LOG_INFO, "general:");
	SNIFFER_LOG(LOG_INFO, "  total packets: %lu packets",
	            sniffer_stats.total_packets);
	SNIFFER_LOG(LOG_INFO, "  bad packets: %lu packets (%llu%%)",
	            sniffer_stats.bad_packets,
	            compute_percent(sniffer_stats.bad_packets, sniffer_stats.total_packets));
	SNIFFER_LOG(LOG_INFO, "  loss (estim.):");
	SNIFFER_LOG(LOG_INFO, "    %lu packets among %lu bursts (%llu%%)",
	            sniffer_stats.nr_lost_packets, sniffer_stats.nr_loss_bursts,
	            compute_percent(sniffer_stats.nr_lost_packets, sniffer_stats.total_packets));
	SNIFFER_LOG(LOG_INFO, "    packets per burst: max %lu, avg %lu, min %lu",
	            sniffer_stats.max_loss_burst_len, (sniffer_stats.nr_loss_bursts != 0 ?
	            sniffer_stats.nr_lost_packets / sniffer_stats.nr_loss_bursts : 0),
	            sniffer_stats.min_loss_burst_len);
	SNIFFER_LOG(LOG_INFO, "  mis-ordered packets (estim.): %lu packets "
	            "(%llu%%)", sniffer_stats.nr_misordered_packets,
	            compute_percent(sniffer_stats.nr_misordered_packets, sniffer_stats.total_packets));
	SNIFFER_LOG(LOG_INFO, "  duplicated packets (estim.): %lu packets "
	            "(%llu%%)", sniffer_stats.nr_duplicated_packets,
	            compute_percent(sniffer_stats.nr_duplicated_packets, sniffer_stats.total_packets));

	/* compression gain */
	SNIFFER_LOG(LOG_INFO, "compression gain:");
	if(sniffer_stats.comp_unit_size == 1)
	{
		SNIFFER_LOG(LOG_INFO, "  pre-compress: %lu bytes",
		            sniffer_stats.comp_pre_nr_bytes);
	}
	else
	{
		SNIFFER_LOG(LOG_INFO, "  pre-compress: %lu %s",
		            sniffer_stats.comp_pre_nr_units,
		            sniffer_stats.comp_unit_size == 1000 ? "KB" :
		            (sniffer_stats.comp_unit_size == 1000*1000 ? "MB" :
		             (sniffer_stats.comp_unit_size == 1000*1000*1000 ? "GB" : "?")));
	}
	if(sniffer_stats.comp_unit_size == 1)
	{
		SNIFFER_LOG(LOG_INFO, "  post-compress: %lu bytes",
		            sniffer_stats.comp_post_nr_bytes);
	}
	else
	{
		SNIFFER_LOG(LOG_INFO, "  post-compress: %lu %s",
		            sniffer_stats.comp_post_nr_units,
		            sniffer_stats.comp_unit_size == 1000 ? "KB" :
		            (sniffer_stats.comp_unit_size == 1000*1000 ? "MB" :
		             (sniffer_stats.comp_unit_size == 1000*1000*1000 ? "GB" : "?")));
	}
	if(sniffer_stats.comp_unit_size == 1)
	{
		SNIFFER_LOG(LOG_INFO, "  compress ratio: %llu%% of total, ie. %llu%% "
		            "of gain",
		            compute_percent(sniffer_stats.comp_post_nr_bytes, sniffer_stats.comp_pre_nr_bytes),
		            100 - compute_percent(sniffer_stats.comp_post_nr_bytes, sniffer_stats.comp_pre_nr_bytes));
	}
	else
	{
		SNIFFER_LOG(LOG_INFO, "  compress ratio: %llu%% of total, ie. %llu%% "
		            "of gain",
		            compute_percent(sniffer_stats.comp_post_nr_units, sniffer_stats.comp_pre_nr_units),
		            100 - compute_percent(sniffer_stats.comp_post_nr_units, sniffer_stats.comp_pre_nr_units));
	}
	SNIFFER_LOG(LOG_INFO, "  used and re-used contexts: %lu",
	            sniffer_stats.comp_nr_reused_cid);

	/* packets per profile */
	total = sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UNCOMPRESSED] +
	        sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_RTP] +
	        sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDP] +
	        sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_IP] +
	        sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_TCP] +
	        sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDPLITE];
	SNIFFER_LOG(LOG_INFO, "packets per profile:");
	SNIFFER_LOG(LOG_INFO, "  Uncompressed profile: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UNCOMPRESSED],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UNCOMPRESSED],
	                    total));
	SNIFFER_LOG(LOG_INFO, "  IP/UDP/RTP profile: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_RTP],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_RTP], total));
	SNIFFER_LOG(LOG_INFO, "  IP/UDP profile: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDP],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDP], total));
	SNIFFER_LOG(LOG_INFO, "  IP-only profile: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_IP],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_IP], total));
	SNIFFER_LOG(LOG_INFO, "  IP/TCP profile: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_TCP],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_TCP], total));
	SNIFFER_LOG(LOG_INFO, "  IP/UDP-Lite profile: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDPLITE],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_profile[ROHC_PROFILE_UDPLITE], total));

	/* packets per mode */
	total = sniffer_stats.comp_nr_pkts_per_mode[ROHC_U_MODE] +
	        sniffer_stats.comp_nr_pkts_per_mode[ROHC_O_MODE] +
	        sniffer_stats.comp_nr_pkts_per_mode[ROHC_R_MODE];
	SNIFFER_LOG(LOG_INFO, "packets per mode:");
	SNIFFER_LOG(LOG_INFO, "  U-mode: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_mode[ROHC_U_MODE],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_mode[ROHC_U_MODE], total));
	SNIFFER_LOG(LOG_INFO, "  O-mode: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_mode[ROHC_O_MODE],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_mode[ROHC_O_MODE], total));
	SNIFFER_LOG(LOG_INFO, "  R-mode: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_mode[ROHC_R_MODE],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_mode[ROHC_R_MODE], total));

	/* packets per state */
	total = sniffer_stats.comp_nr_pkts_per_state[ROHC_COMP_STATE_IR] +
	        sniffer_stats.comp_nr_pkts_per_state[ROHC_COMP_STATE_FO] +
	        sniffer_stats.comp_nr_pkts_per_state[ROHC_COMP_STATE_SO];
	SNIFFER_LOG(LOG_INFO, "packets per state:");
	SNIFFER_LOG(LOG_INFO, "  IR state: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_state[ROHC_COMP_STATE_IR],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_state[ROHC_COMP_STATE_IR], total));
	SNIFFER_LOG(LOG_INFO, "  FO state: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_state[ROHC_COMP_STATE_FO],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_state[ROHC_COMP_STATE_FO], total));
	SNIFFER_LOG(LOG_INFO, "  SO state: %lu packets (%llu%%)",
	            sniffer_stats.comp_nr_pkts_per_state[ROHC_COMP_STATE_SO],
	            compute_percent(sniffer_stats.comp_nr_pkts_per_state[ROHC_COMP_STATE_SO], total));

	/* packets per packet type */
	SNIFFER_LOG(LOG_INFO, "packets per packet type:");
	total = 0;
	for(i = ROHC_PACKET_IR; i <= ROHC_PACKET_TCP_SEQ_8; i++)
	{
		total += sniffer_stats.comp_nr_pkts_per_pkt_type[i];
	}
	for(i = ROHC_PACKET_IR; i <= ROHC_PACKET_TCP_SEQ_8; i++)
	{
		if(i != ROHC_PACKET_UNKNOWN &&
		   strcmp(rohc_get_packet_descr(i), "no description") != 0)
		{
			SNIFFER_LOG(LOG_INFO, "  packet type %s: %lu packets (%llu%%)",
			            rohc_get_packet_descr(i),
			            sniffer_stats.comp_nr_pkts_per_pkt_type[i],
			            compute_percent(sniffer_stats.comp_nr_pkts_per_pkt_type[i], total));
		}
	}

	SNIFFER_LOG(LOG_INFO, "all ROHC sniffer statistics dumped");
}


/**
 * @brief Test the ROHC library with a sniffed flow of IP packets going
 *        through one compressor/decompressor pair
 *
 * @param cid_type          The type of CIDs that the compressor shall use
 * @param max_contexts      The maximum number of ROHC contexts to use
 * @param enabled_profiles  The ROHC profiles to enable
 * @param device_name       The name of the network device
 * @return                  Whether the sniffer setup was OK
 */
static bool sniff(const rohc_cid_type_t cid_type,
                  const size_t max_contexts,
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

	uint8_t feedback_send_buffer[MAX_ROHC_SIZE];
	struct rohc_buf feedback_send =
		rohc_buf_init_empty(feedback_send_buffer, MAX_ROHC_SIZE);

	int ret;
	unsigned int i;

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
		SNIFFER_LOG(LOG_WARNING, "failed to open network device '%s': %s",
		            device_name, errbuf);
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type_src = pcap_datalink(handle);
	if(link_layer_type_src != DLT_EN10MB &&
	   link_layer_type_src != DLT_LINUX_SLL &&
	   link_layer_type_src != DLT_RAW)
	{
		SNIFFER_LOG(LOG_WARNING, "link layer type %d not supported in source "
		            "dump (supported = %d, %d, %d)", link_layer_type_src,
		            DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW);
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
	comp = rohc_comp_new2(cid_type, max_contexts - 1, gen_false_random_num, NULL);
	if(comp == NULL)
	{
		SNIFFER_LOG(LOG_WARNING, "failed to create the ROHC compressor");
		goto close_input;
	}

	/* set the callback for traces on compressor */
	if(!rohc_comp_set_traces_cb2(comp, print_rohc_traces, NULL))
	{
		SNIFFER_LOG(LOG_WARNING, "failed to set the trace callback for the "
		            "compressor");
		goto destroy_comp;
	}

	/* enable the compression profiles */
	for(i = ROHC_PROFILE_UNCOMPRESSED; i <= ROHC_PROFILE_UDPLITE; i++)
	{
		if(enabled_profiles[i] == 1 && !rohc_comp_enable_profile(comp, i))
		{
			SNIFFER_LOG(LOG_WARNING, "failed to enable compression profile "
			            "0x%04x", i);
			goto destroy_comp;
		}
		else if(enabled_profiles[i] == 0 && !rohc_comp_disable_profile(comp, i))
		{
			SNIFFER_LOG(LOG_WARNING, "failed to disable compression profile "
			            "0x%04x", i);
			goto destroy_comp;
		}
	}

	/* set the callback for RTP stream detection */
	if(!rohc_comp_set_rtp_detection_cb(comp, rtp_detect_cb, NULL))
	{
		SNIFFER_LOG(LOG_WARNING, "failed to set the RTP stream detection "
		            "callback for compressor");
		goto destroy_comp;
	}

	/* create the decompressor (bi-directional mode) */
	decomp = rohc_decomp_new2(cid_type, max_contexts - 1, ROHC_O_MODE);
	if(decomp == NULL)
	{
		SNIFFER_LOG(LOG_WARNING, "failed to create the decompressor");
		goto destroy_comp;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb2(decomp, print_rohc_traces, NULL))
	{
		SNIFFER_LOG(LOG_WARNING, "failed to set trace callback for "
		            "decompressor");
		goto destroy_decomp;
	}

	/* enable the decompression profiles */
	for(i = ROHC_PROFILE_UNCOMPRESSED; i <= ROHC_PROFILE_UDPLITE; i++)
	{
		if(enabled_profiles[i] == 1 && !rohc_decomp_enable_profile(decomp, i))
		{
			SNIFFER_LOG(LOG_WARNING, "failed to enable decompression profile "
			            "0x%04x", i);
			goto destroy_decomp;
		}
		else if(enabled_profiles[i] == 0 &&
		        !rohc_decomp_disable_profile(decomp, i))
		{
			SNIFFER_LOG(LOG_WARNING, "failed to disable decompression profile "
			            "0x%04x", i);
			goto destroy_decomp;
		}
	}

	/* reset the PCAP dumpers (used to save sniffed packets in several PCAP
	 * files, one per Context ID) */
	bzero(sniffer_dumpers, sizeof(pcap_dumper_t *) * max_contexts);

	SNIFFER_LOG(LOG_INFO, "ROHC sniffer successfully started");
	SNIFFER_LOG(LOG_INFO, "start processing captured packets");

	/* for each sniffed packet */
	sniffer_stats.total_packets = 0;
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

		sniffer_stats.total_packets++;

		if(!is_daemon &&
		   (sniffer_stats.total_packets == 1 || (sniffer_stats.total_packets % 100) == 0))
		{
			if(sniffer_stats.total_packets > 1)
			{
				printf("\r");
			}
			printf("packet #%lu", sniffer_stats.total_packets);
			fflush(stdout);

			if(do_print_stat && (sniffer_stats.total_packets % 1000) == 0)
			{
				printf("\n\n");
				fprintf(stderr, "================================================\n");
				sniffer_print_stats(SIGUSR1);
				fprintf(stderr, "================================================\n");
				fprintf(stderr, "\n");
				fflush(stderr);
			}
		}

		/* compress & decompress from compressor to decompressor */
		ret = compress_decompress(comp, decomp, header, packet,
		                          link_len_src, handle, sniffer_dumpers,
		                          &feedback_send, &cid, &sniffer_stats);
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
			sniffer_stats.bad_packets++;
		}
		else
		{
			nb_internal_err++;
		}

		/* in case of problem (ignore bad packets), just die! */
		if(ret != 1 && ret != -3)
		{
			SNIFFER_LOG(LOG_WARNING, "packet #%lu, CID %u: stats OK, ERR(COMP), "
			            "ERR(DECOMP), ERR(REF), ERR(BAD), ERR(INTERNAL)  =  "
			            "%u  %u  %u  %u  %u  %u", sniffer_stats.total_packets,
			            cid, nb_ok, err_comp, err_decomp, nb_ref, nb_bad,
			            nb_internal_err);

			/* last debug traces are recorded in SIGABRT handler */
			assert(0);
		}
	}

	if(stop_program)
	{
		SNIFFER_LOG(LOG_INFO, "program stopped by signal");
	}

	status = true;

	/* close PCAP dumpers */
	for(i = 0; i < max_contexts; i++)
	{
		if(sniffer_dumpers[i] != NULL)
		{
			SNIFFER_LOG(LOG_INFO, "close dump file for context with ID %u", i);
			pcap_dump_close(sniffer_dumpers[i]);
		}
	}

destroy_decomp:
	rohc_decomp_free(decomp);
destroy_comp:
	rohc_comp_free(comp);
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
                               pcap_t *handle,
                               pcap_dumper_t *dumpers[],
                               struct rohc_buf *const feedback_send,
                               unsigned int *const cid,
                               struct sniffer_stats_t *stats)
{
	const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
	struct rohc_buf ip_packet =
		rohc_buf_init_full(packet, header.caplen, arrival_time);

	const size_t output_packet_max_len =
		max(ETHER_HDR_LEN, LINUX_COOKED_HDR_LEN) + MAX_ROHC_SIZE;
	uint8_t output_packet[output_packet_max_len];
	struct rohc_buf rohc_packet =
		rohc_buf_init_empty(output_packet, output_packet_max_len);

	uint8_t decomp_buffer[MAX_ROHC_SIZE];
	struct rohc_buf decomp_packet =
		rohc_buf_init_empty(decomp_buffer, MAX_ROHC_SIZE);

	uint8_t rcvd_feedback_buffer[MAX_ROHC_SIZE];
	struct rohc_buf rcvd_feedback =
		rohc_buf_init_empty(rcvd_feedback_buffer, MAX_ROHC_SIZE);

	rohc_comp_last_packet_info2_t comp_last_packet_info;
	rohc_decomp_last_packet_info_t decomp_last_packet_info;
	unsigned long possible_unit;
	rohc_status_t status;
	int ret;

	/* check Ethernet frame length */
	if(header.len <= link_len_src || header.len != header.caplen)
	{
		if(is_verbose)
		{
			SNIFFER_LOG(LOG_WARNING, "bad PCAP packet (full len = %d, capture "
			            "len = %d)", header.len, header.caplen);
		}
		ret = -3;
		goto error;
	}

	/* skip the link layer header */
	rohc_buf_pull(&ip_packet, link_len_src);
	rohc_packet.len += link_len_src;
	rohc_buf_pull(&rohc_packet, link_len_src);

	/* check for padding after the IP packet in the Ethernet payload */
	if(link_len_src == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
	{
		int version;
		uint16_t tot_len;

		version = (rohc_buf_byte(ip_packet) >> 4) & 0x0f;
		if(version == 4)
		{
			memcpy(&tot_len, rohc_buf_data_at(ip_packet, 2), sizeof(uint16_t));
			tot_len = ntohs(tot_len);
		}
		else
		{
			const size_t ipv6_header_len = 40;
			memcpy(&tot_len, rohc_buf_data_at(ip_packet, 4), sizeof(uint16_t));
			tot_len = ipv6_header_len + ntohs(tot_len);
		}

		if(tot_len < ip_packet.len)
		{
			if(is_verbose)
			{
				SNIFFER_LOG(LOG_INFO, "the Ethernet frame has %zd bytes of "
				            "padding after the %u byte IP packet!",
				            ip_packet.len - tot_len, tot_len);
			}
			ip_packet.len = tot_len;
		}
	}

	/* fix IPv4 packets with non-standard-compliant 0xffff checksums instead
	 * of 0x0000 (Windows Vista seems to be faulty for the latter), to avoid
	 * false comparison failures after decompression */
	if(((rohc_buf_byte_at(ip_packet, 0) >> 4) & 0x0f) == 4 &&
	   ip_packet.len >= 20 &&
	   rohc_buf_byte_at(ip_packet, 10) == 0xff &&
	   rohc_buf_byte_at(ip_packet, 11) == 0xff)
	{
		rohc_buf_byte_at(ip_packet, 10) = 0x00;
		rohc_buf_byte_at(ip_packet, 11) = 0x00;
	}

	/* piggyback the feedback */
	rohc_buf_append_buf(&rohc_packet, *feedback_send);
	rohc_buf_pull(&rohc_packet, feedback_send->len);

	/* compress the IP packet */
	status = rohc_compress4(comp, ip_packet, &rohc_packet);
	if(status != ROHC_STATUS_OK)
	{
		pcap_dumper_t *dumper;

		SNIFFER_LOG(LOG_WARNING, "compression failed");
		ret = -1;
		rohc_buf_push(&ip_packet, link_len_src);

		/* open the new dumper */
		dumper = pcap_dump_open(handle, "./dump_stream_default.pcap");
		if(dumper == NULL)
		{
			SNIFFER_LOG(LOG_WARNING, "failed to open new dump file '%s'",
			            "./dump_stream_default.pcap");
			assert(0);
			goto error;
		}

		/* dump the IP packet */
		SNIFFER_LOG(LOG_INFO, "dump packet in file '%s'",
		            "./dump_stream_default.pcap");
		pcap_dump((u_char *) dumper, &header, packet);

		SNIFFER_LOG(LOG_INFO, "close dump file");
		pcap_dump_close(dumper);

		goto error;
	}

	/* get some statistics about the last compressed packet */
	comp_last_packet_info.version_major = 0;
	comp_last_packet_info.version_minor = 0;
	if(!rohc_comp_get_last_packet_info2(comp, &comp_last_packet_info))
	{
		SNIFFER_LOG(LOG_WARNING, "failed to get compression info");
		ret = -4;
		goto error;
	}
	stats->comp_pre_nr_bytes += ip_packet.len;
	stats->comp_post_nr_bytes += rohc_packet.len;
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
				SNIFFER_LOG(LOG_INFO, "replace dump file '%s' for context with "
				            "ID %u", dump_filename,
				            comp_last_packet_info.context_id);
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
			SNIFFER_LOG(LOG_WARNING, "failed to open new dump file '%s' for "
			            "context with ID %u", dump_filename,
			            comp_last_packet_info.context_id);
			assert(0);
			goto error;
		}
	}

	/* dump the IP packet */
	rohc_buf_push(&ip_packet, link_len_src);
	pcap_dump((u_char *) dumpers[comp_last_packet_info.context_id],
	          &header, packet);
	rohc_buf_pull(&ip_packet, link_len_src);

	/* record the CID */
	*cid = comp_last_packet_info.context_id;

	/* reset the feedback buffer */
	feedback_send->data -= feedback_send->offset;
	feedback_send->len = 0;

	/* decompress the ROHC packet */
	status = rohc_decompress3(decomp, rohc_packet, &decomp_packet,
	                          &rcvd_feedback, feedback_send);
	if(status != ROHC_STATUS_OK)
	{
		SNIFFER_LOG(LOG_WARNING, "decompression failed");
		ret = -2;
		goto error;
	}

	/* get some statistics about the last decompressed packet */
	decomp_last_packet_info.version_major = 0;
	decomp_last_packet_info.version_minor = 0;
	if(!rohc_decomp_get_last_packet_info(decomp, &decomp_last_packet_info))
	{
		SNIFFER_LOG(LOG_WARNING, "failed to get decompression info");
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

	/* deliver any received feedback data to the associated compressor */
	if(!rohc_comp_deliver_feedback2(comp, rcvd_feedback))
	{
		SNIFFER_LOG(LOG_WARNING, "failed to deliver feedback");
		ret = -4;
		goto error;
	}

	/* compare the decompressed packet with the original one */
	if(!compare_packets(ip_packet, decomp_packet))
	{
		SNIFFER_LOG(LOG_WARNING, "comparison with original packet failed");
		ret = 0;
	}
	else
	{
		/* comparison is OK */
		ret = 1;
	}

error:
	return ret;
}


/**
 * @brief Compare two network packets and print differences if any
 *
 * @param pkt1      The first packet
 * @param pkt2      The second packet
 * @return          Whether the packets are equal or not
 */
static int compare_packets(const struct rohc_buf pkt1,
                           const struct rohc_buf pkt2)
{
	int valid = 1;
	size_t min_size;
	size_t i, j, k;
	char str1[4][7], str2[4][7];
	char sep1, sep2;
	size_t tcp_padding_bytes;

	/* do not compare more than the shortest of the 2 packets */
	min_size = min(pkt1.len, pkt2.len);

	/* do not compare more than 180 bytes to avoid huge output */
	min_size = min(180, min_size);

	/* if packets are equal, do not print the packets */
	if(pkt1.len == pkt2.len &&
	   memcmp(rohc_buf_data(pkt1), rohc_buf_data(pkt2), pkt1.len) == 0)
	{
		goto skip;
	}
	/* packets seem different, double check for extra padding of TCP options:
	 * packets with extra padding at the end of TCP options cannot be compared */
	tcp_padding_bytes = get_tcp_opt_padding(pkt1);
	if(tcp_padding_bytes >= 4)
	{
		fprintf(stderr, "unexpected padding at the end of TCP options: "
		        "%zu EOL bytes\n", tcp_padding_bytes);
		goto skip;
	}

	/* packets are different */
	valid = 0;

	SNIFFER_LOG(LOG_WARNING, "------------------------------ Compare ------------------------------");
	SNIFFER_LOG(LOG_WARNING, "--------- reference ----------         ----------- new --------------");

	if(pkt1.len != pkt2.len)
	{
		SNIFFER_LOG(LOG_WARNING, "packets have different sizes (%zd != %zd), "
		            "compare only the %zd first bytes",
		            pkt1.len, pkt2.len, min_size);
	}

	j = 0;
	for(i = 0; i < min_size; i++)
	{
		if(rohc_buf_byte_at(pkt1, i) != rohc_buf_byte_at(pkt2, i))
		{
			sep1 = '#';
			sep2 = '#';
		}
		else
		{
			sep1 = '[';
			sep2 = ']';
		}

		sprintf(str1[j], "%c0x%.2x%c", sep1, rohc_buf_byte_at(pkt1, i), sep2);
		sprintf(str2[j], "%c0x%.2x%c", sep1, rohc_buf_byte_at(pkt2, i), sep2);

		/* make the output human readable */
		if(j >= 3 || (i + 1) >= min_size)
		{
			for(k = 0; k < 4; k++)
			{
				if(k < (j + 1))
				{
					SNIFFER_LOG(LOG_WARNING, "%s  ", str1[k]);
				}
				else /* fill the line with blanks if nothing to print */
				{
					SNIFFER_LOG(LOG_WARNING, "        ");
				}
			}

			SNIFFER_LOG(LOG_WARNING, "      ");

			for(k = 0; k < (j + 1); k++)
			{
				SNIFFER_LOG(LOG_WARNING, "%s  ", str2[k]);
			}

			j = 0;
		}
		else
		{
			j++;
		}
	}

	SNIFFER_LOG(LOG_WARNING, "----------------------- packets are different -----------------------");

skip:
	return valid;
}


/**
 * @brief How many bytes of padding the packet got after TCP options?
 *
 * TCP options shall be padded to be aligned on 32-bit boundaries, ie. add
 * 0 to 3 bytes of padding 0x00. Some TCP stacks however adds extra padding
 * (4 bytes of example). This stops us to compare original and decompressed
 * packet, since the ROHC decompressor will only add the minimal number of
 * padding bytes.
 *
 * @param packet  The packet to check for padding
 * @return        The number of padding bytes found after TCP options
 */
static size_t get_tcp_opt_padding(const struct rohc_buf packet)
{
	struct tcphdr *tcp;
	size_t opt_len;
	size_t nr_eol_found = 0;
	size_t ip_len;
	size_t i;

	/* check IP version */
	if(packet.len < 1)
	{
		goto too_short;
	}
	if((rohc_buf_byte(packet) & 0xf0) == 0x40)
	{
		/* IPv4 */
		struct iphdr *ip = (struct iphdr *) rohc_buf_data(packet);
		ip_len = ip->ihl * 4;
		if(packet.len <= ip_len || ip->protocol != 6)
		{
			goto not_tcp;
		}
	}
	else if((rohc_buf_byte(packet) & 0xf0) == 0x60)
	{
		/* IPv6 */
		struct ip6_hdr *ip = (struct ip6_hdr *) rohc_buf_data(packet);
		ip_len = sizeof(struct ip6_hdr);
		if(packet.len <= ip_len || ip->ip6_nxt != 6)
		{
			goto not_tcp;
		}
	}
	else
	{
		goto not_ip;
	}

	/* enough room for IP and TCP base header? */
	if(packet.len < (ip_len + sizeof(struct tcphdr)))
	{
		goto malformed;
	}

	/* enough room for TCP options? */
	tcp = (struct tcphdr *) rohc_buf_data_at(packet, ip_len);
	if(packet.len < (ip_len + tcp->doff * 4))
	{
		goto malformed;
	}

	/* parse TCP options, count padding bytes */
	nr_eol_found = 0;
	for(i = ip_len + sizeof(struct tcphdr);
	    i < (ip_len + tcp->doff * 4);
	    i += opt_len)
	{
		switch(rohc_buf_byte_at(packet, i))
		{
			case 0x01: /* NOP */
				opt_len = 1;
				break;
			case 0x00: /* EOL */
				opt_len = 1;
				nr_eol_found++;
				break;
			default: /* long option TLV */
				if(packet.len <= (i + 1))
				{
					goto malformed;
				}
				opt_len = rohc_buf_byte_at(packet, i + 1);
				if(packet.len <= (i + opt_len))
				{
					goto malformed;
				}
				break;
		}
	}

	return nr_eol_found;

not_ip:
not_tcp:
malformed:
too_short:
	return 0;
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
                              const rohc_trace_entity_t entity __attribute__((unused)),
                              const int profile __attribute__((unused)),
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
		if(is_verbose)
		{
			fprintf(stdout, "[%s] ", level_descrs[level]);
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
		}
		if(is_daemon)
		{
			va_start(args, format);
			vsyslog(LOG_DEBUG, format, args);
			va_end(args);
		}
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
		last_traces[last_traces_last][MAX_TRACE_LEN] = '\0';
		/* TODO: check return code */
		va_end(args);
		/* remove the final \n if present */
		if(strlen(last_traces[last_traces_last]) >= 1 &&
		   last_traces[last_traces_last][strlen(last_traces[last_traces_last]) - 1] == '\n')
		{
			last_traces[last_traces_last][strlen(last_traces[last_traces_last]) - 1] = '\0';
		}
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
	if((ntohs(udp_dport) % 2) != 0)
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

