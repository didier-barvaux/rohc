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
 * @file   test_feedback_ring.c
 * @brief  Check that the feedback ring works as expected
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application transmits feedbacks to a compressor that have to transmit them.
 */

#include "test.h"

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <time.h> /* for time(2) */
#include <string.h>
#include <stdarg.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>


/* prototypes of private functions */
static void usage(void);
static int test_feedback_ring(void);

static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));

static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));


/** Whether the application runs in verbose mode or not */
static int is_verbose;


/**
 * @brief Check that the feedback ring works as expected
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	int args_used;
	int status = 1;

	/* set to quiet mode by default */
	is_verbose = 0;

	/* parse program arguments, print the help message in case of failure */
	if(argc != 1 && argc != 2)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc -= args_used, argv += args_used)
	{
		args_used = 1;

		if(!strcmp(*argv, "--verbose"))
		{
			/* enable verbose mode */
			is_verbose = 1;
		}
		else
		{
			/* unknown option */
			usage();
			goto error;
		}
	}

	/* test feedback ring */
	status = test_feedback_ring();

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that the feedback ring works as expected\n"
	        "\n"
	        "usage: test_feedback_ring [OPTIONS]\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n"
	        "  --verbose    Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library by sending many feedbacks
 *
 * @return                     0 in case of success,
 *                             1 in case of failure
 */
static int test_feedback_ring(void)
{
	struct rohc_comp *comp;

#define FEEDBACK_SIZE  8
#define BUFFER_SIZE    ((FEEDBACK_SIZE + 2 /* for header */) * 2)
	unsigned char feedback_data[BUFFER_SIZE] = { 0 };

	int feedback_nr;
	int feedback_output_size;

	int is_failure = 1;

	/* initialize the random generator */
	srand(time(NULL));

	/* create the ROHC compressor with small CID */
	comp = rohc_alloc_compressor(ROHC_SMALL_CID_MAX, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto error;
	}

	/* set the callback for traces on compressor */
	if(!rohc_comp_set_traces_cb(comp, print_rohc_traces))
	{
		fprintf(stderr, "failed to set trace callback for compressor\n");
		goto destroy_comp;
	}

	/* enable profiles */
	rohc_activate_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(comp, ROHC_PROFILE_UDP);
	rohc_activate_profile(comp, ROHC_PROFILE_IP);
	rohc_activate_profile(comp, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(comp, ROHC_PROFILE_RTP);
	rohc_activate_profile(comp, ROHC_PROFILE_ESP);
	rohc_activate_profile(comp, ROHC_PROFILE_TCP);

	/* set the callback for random numbers */
	if(!rohc_comp_set_random_cb(comp, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto destroy_comp;
	}


	/*
	 * Test #1: fill the ring buffer, then flush it, last add more data in
	 *          ring buffer, the last step shall succeed
	 */

	printf("test #1: piggyback feedbacks\n");
	for(feedback_nr = 0; feedback_nr < 1000; feedback_nr++)
	{
		if(!rohc_comp_piggyback_feedback(comp, feedback_data, FEEDBACK_SIZE))
		{
			fprintf(stderr, "failed to piggyback the feedback\n");
			goto destroy_comp;
		}
	}

	printf("test #1: flush feedbacks\n");
	do
	{
		/* get as many as feedbacks as possible */
		feedback_output_size = rohc_feedback_flush(comp, feedback_data,
		                                           BUFFER_SIZE);

		/* feedbacks should be transmitted here (and succeed) */

		/* remove the locked feedbacks once there were transmitted */
		if(!rohc_feedback_remove_locked(comp))
		{
			fprintf(stderr, "failed to remove locked feedbacks\n");
			goto destroy_comp;
		}

	} while(feedback_output_size > 0);

	printf("test #1: piggyback one feedback more\n");
	if(!rohc_comp_piggyback_feedback(comp, feedback_data, FEEDBACK_SIZE))
	{
		fprintf(stderr, "failed to piggyback the feedback\n");
		goto destroy_comp;
	}


	/*
	 * Test #2: fill the ring buffer (one feedback already in), then flush it
	 *          (but emulate sending failure), last add more data in ring
	 *          ring buffer, the last step shall fail
	 */

	printf("test #2: piggyback feedbacks\n");
	for(feedback_nr = 1; feedback_nr < 1000; feedback_nr++)
	{
		if(!rohc_comp_piggyback_feedback(comp, feedback_data, FEEDBACK_SIZE))
		{
			fprintf(stderr, "failed to piggyback the feedback\n");
			goto destroy_comp;
		}
	}

	printf("test #2: flush feedbacks\n");
	/* get as many as feedbacks as possible */
	feedback_output_size = rohc_feedback_flush(comp, feedback_data,
	                                           BUFFER_SIZE);

	/* feedbacks should be transmitted here (and fail) */

	/* unlock the locked feedbacks since transmission failed */
	if(!rohc_feedback_unlock(comp))
	{
		fprintf(stderr, "failed to unlock feedbacks\n");
		goto error;
	}

	printf("test #2: piggyback one feedback more\n");
	if(rohc_comp_piggyback_feedback(comp, feedback_data, FEEDBACK_SIZE))
	{
		fprintf(stderr, "unexpected success to piggyback the feedback\n");
		goto destroy_comp;
	}


	/* everything went fine */
	is_failure = 0;

destroy_comp:
	rohc_free_compressor(comp);
error:
	return is_failure;
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
}

