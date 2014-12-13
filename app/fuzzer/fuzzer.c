/*
 * Copyright 2013,2014 Didier Barvaux
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
 * @file   fuzzer.c
 * @brief  ROHC fuzzer program
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * Stress test the ROHC decompressor to discover bugs.
 */

#include "config.h" /* for PACKAGE_BUGREPORT */

/* system includes */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>

/* ROHC includes */
#include <rohc/rohc.h>
#include <rohc/rohc_decomp.h>


/** The maximum size of IP and ROHC packets */
#define PACKET_MAX_SIZE 2048


/* prototypes of private functions */
static void usage(void);
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 5, 6), nonnull(5)));

static unsigned long compute_eta(const struct timespec ts_begin,
                                 const unsigned long max_iter,
                                 const unsigned long cur_iter)
	__attribute__((warn_unused_result));
static void print_time(const char *const descr, const unsigned long sec)
	__attribute__((nonnull(1)));
static bool now(struct timespec *const now)
	__attribute__((warn_unused_result, nonnull(1)));


/** The maximum number of traces to keep */
#define MAX_LAST_TRACES  5000
/** The maximum length of a trace */
#define MAX_TRACE_LEN  300

/** The ring buffer for the last traces */
static char last_traces[MAX_LAST_TRACES][MAX_TRACE_LEN + 1];
/** The index of the first trace */
static int last_traces_first;
/** The index of the last trace */
static int last_traces_last;


/**
 * @brief Main function for the ROHC fuzzer application
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	unsigned int rand_seed;
	struct rohc_decomp *decomp;
	const unsigned long max_iter = 2000000000;
	unsigned long cur_iter;
	size_t i;

	struct timespec ts_begin;

	/* no traces at the moment */
	for(i = 0; i < MAX_LAST_TRACES; i++)
	{
		last_traces[i][0] = '\0';
	}
	last_traces_first = -1;
	last_traces_last = -1;

	/* parse arguments and check consistency */
	if(argc != 2 && argc != 3)
	{
		fprintf(stderr, "wrong number of arguments\n");
		usage();
		goto error;
	}
	else if(strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0)
	{
		/* print version */
		printf("rohc_fuzzer version %s\n", rohc_version());
		goto error;
	}
	else if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
	{
		/* print help */
		usage();
		goto error;
	}
	else if(strcmp(argv[1], "play") == 0)
	{
		/* 'play' command: no additional argument allowed */
		if(argc != 2)
		{
			fprintf(stderr, "play command does not take any argument\n");
			usage();
			goto error;
		}

		/* 'play' command: choose a random seed */
		rand_seed = time(NULL);
	}
	else if(strcmp(argv[1], "replay") == 0)
	{
		if(argc != 3)
		{
			fprintf(stderr, "replay command takes one argument\n");
			usage();
			goto error;
		}

		/* 'replay' command: take random seed given as argument */
		rand_seed = atoi(argv[2]);
	}
	else
	{
		fprintf(stderr, "unrecognized command '%s'\n", argv[1]);
		usage();
		goto error;
	}

	printf("start fuzzing session with random seed %u\n", rand_seed);
	printf("you can use the replay command and the above random seed to run\n"
	       "the same fuzzing session again\n\n");
	srand(rand_seed);

	/* create ROHC decompressor */
	decomp = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_U_MODE);
	assert(decomp != NULL);

	/* set the callback for traces on ROHC decompressor */
	assert(rohc_decomp_set_traces_cb2(decomp, print_rohc_traces, NULL));

	/* activate all the decompression profiles */
	assert(rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_UNCOMPRESSED,
	                                   ROHC_PROFILE_RTP, ROHC_PROFILE_UDP,
	                                   ROHC_PROFILE_IP, ROHC_PROFILE_UDPLITE,
	                                   ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1));

	/* get timestamp at the beginning of the test */
	assert(now(&ts_begin));

	/* decompress many random packets in a row */
	for(cur_iter = 1; cur_iter <= max_iter; cur_iter++)
	{
		uint8_t rohc_buffer[PACKET_MAX_SIZE];
		struct rohc_buf rohc_packet =
			rohc_buf_init_empty(rohc_buffer, PACKET_MAX_SIZE);
		uint8_t ip_buffer[PACKET_MAX_SIZE];
		struct rohc_buf ip_packet =
			rohc_buf_init_empty(ip_buffer, PACKET_MAX_SIZE);
		int ret __attribute__((unused));

		/* print progress from time to time */
		if(cur_iter == 1 || (cur_iter % 10000) == 0)
		{
			if(cur_iter > 1)
			{
				printf("\r");
			}
			printf("iteration %lu / %lu", cur_iter, max_iter);
			if(cur_iter > 1)
			{
				print_time("  ETA", compute_eta(ts_begin, max_iter, cur_iter));
			}
			fflush(stdout);
		}

		/* create one crazy ROHC packet */
		rohc_packet.len = rand() % PACKET_MAX_SIZE;
		for(i = 0; i < rohc_packet.len; i++)
		{
			rohc_buf_byte_at(rohc_packet, i) = rand() % 0xff;
		}

		/* decompress the crazy ROHC packet */
		ret = rohc_decompress3(decomp, rohc_packet, &ip_packet, NULL, NULL);
		/* do not check for result, only robustness is checked */
	}

	printf("\nTEST OK\n");

	rohc_decomp_free(decomp);
	return 0;

error:
	return 1;
}


/**
 * @brief Print usage of the fuzzer application
 */
static void usage(void)
{
	printf("The ROHC fuzzer tests the ROHC library robustness\n"
	       "\n"
	       "Usage: rohc_fuzzer OPTIONS\n"
	       "   or: rohc_fuzzer play\n"
	       "   or: rohc_fuzzer replay SEED\n"
	       "\n"
	       "Options:\n"
	       "  -v, --version          Print version information and exit\n"
	       "  -h, --help             Print this usage and exit\n"
	       "\n"
	       "Examples:\n"
	       "  rohc_fuzzer play       Run a test\n"
	       "  rohc_fuzzer replay 5   Run a specific test (to reproduce bugs)\n"
	       "\n"
	       "Report bugs to <" PACKAGE_BUGREPORT ">.\n");
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
                              const char *format, ...)
{
	va_list args;
	int ret;

	if(last_traces_last == -1)
	{
		last_traces_last = 0;
	}
	else
	{
		last_traces_last = (last_traces_last + 1) % MAX_LAST_TRACES;
	}

	va_start(args, format);
	ret = vsnprintf(last_traces[last_traces_last], MAX_TRACE_LEN + 1,
	                format, args);
	last_traces[last_traces_last][MAX_TRACE_LEN] = '\0';
	va_end(args);

	if(last_traces_first == -1)
	{
		last_traces_first = 0;
	}
	else if(last_traces_first == last_traces_last)
	{
		last_traces_first = (last_traces_first + 1) % MAX_LAST_TRACES;
	}

	/* if trace was truncated, mention it */
	if(ret > MAX_TRACE_LEN)
	{
		print_rohc_traces(priv_ctxt, level, entity, profile,
		                  "previous trace truncated\n");
	}
}


/**
 * @brief Compute the Estimed Time for Arrival (ETA), ie. the end of the test
 *
 * @param ts_begin  The timestamp at the beginning of the test
 *                  (in seconds and nanoseconds)
 * @param max_iter  The number of iterations that need to be performed
 * @param cur_iter  The number of iterations done so far
 * @return          The ETA in seconds
 */
static unsigned long compute_eta(const struct timespec ts_begin,
                                 const unsigned long max_iter,
                                 const unsigned long cur_iter)
{
	struct timespec ts_now;

	assert(now(&ts_now));

	const uint64_t interval_ns = (ts_now.tv_sec - ts_begin.tv_sec) * 1e9 +
	                             ts_now.tv_nsec - ts_begin.tv_nsec;
	const unsigned long nr_done_10000 = cur_iter / 10000UL;
	const uint64_t nr_ns_for_10000 = interval_ns / nr_done_10000;
	const unsigned long nr_remain_10000 = ((max_iter - cur_iter) / 10000UL);
	const uint64_t eta_ns = nr_remain_10000 * nr_ns_for_10000;
	const unsigned long eta_s = eta_ns / 1e9;

	return eta_s;
}


/**
 * @brief Pretty print the given timestamp
 *
 * @param ts  The timestamp to print (in seconds)
 */
static void print_time(const char *const descr, const unsigned long sec)
{
	const unsigned long min = sec / 60;
	const unsigned long sec_reminder = sec % 60;
	const unsigned long hour = min / 60;
	const unsigned long min_reminder = min % 60;

	printf("%s %2luh %2lum %2lus", descr, hour, min_reminder, sec_reminder);
}


/**
 * @brief Retrieve the current timestamp
 *
 * @param[out] now  The current timestamp in seconds and nanoseconds
 */
static bool now(struct timespec *const now)
{
	if(clock_gettime(CLOCK_MONOTONIC_RAW, now) != 0)
	{
		fprintf(stderr, "failed to retrieve current timestamp: %s (%d)\n",
		        strerror(errno), errno);
		return false;
	}
	return true;
}

