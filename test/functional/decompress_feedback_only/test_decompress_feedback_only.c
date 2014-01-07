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
 * @file   test_decompress_feedback_only.c
 * @brief  Check that FEEDBACK-2 packets are generated as expected
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application decompresses ROHC feedback-only packets successfully.
 */

#include "test.h"

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h> /* for time(2) */
#include <stdarg.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_decomp.h>


/* prototypes of private functions */
static void usage(void);
static int test_decomp(const unsigned char *const rohc_feedback,
                       const size_t rohc_feedback_len);
static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));


/**
 * @brief Check that the decompression of the ROHC feedback-only packets is
 *        successful.
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	int args_read = 1;

	/* a ROHC feedback-only packet */
	const unsigned char rohc_feedback[] = { 0xf4, 0x20, 0x00, 0x11, 0xe9 };
	const size_t rohc_feedback_len = 5;

	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 0)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc -= args_read, argv += args_read)
	{
		if(!strcmp(*argv, "-h"))
		{
			/* print help */
			usage();
			goto error;
		}
		else
		{
			/* do not accept more than two arguments without option name */
			usage();
			goto error;
		}
	}

	/* test ROHC feedback-only decompression */
	status = test_decomp(rohc_feedback, rohc_feedback_len);

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that feedback-only packets are decompressed as expected\n"
	        "\n"
	        "usage: test_decompress_feedback_only [OPTIONS]\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with the given ROHC feedback packet
 *
 * @param rohc_feedback      The ROHC feedback data
 * @param rohc_feedback_len  The length (in bytes) of the ROHC feedback
 * @return                   0 in case of success,
 *                           1 in case of failure
 */
static int test_decomp(const unsigned char *const rohc_feedback,
                       const size_t rohc_feedback_len)
{
	const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };

	struct rohc_comp *comp;
	struct rohc_decomp *decomp;

	unsigned char ip_packet[MAX_ROHC_SIZE];
	size_t ip_size;

#define NB_RTP_PORTS 5
	const unsigned int rtp_ports[NB_RTP_PORTS] =
		{ 1234, 36780, 33238, 5020, 5002 };

	unsigned int i;
	int is_failure = 1;
	int ret;

	/* create the ROHC compressor with small CID */
	comp = rohc_comp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto error;
	}

	/* set the callback for traces on compressor */
	if(!rohc_comp_set_traces_cb(comp, print_rohc_traces))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "compressor\n");
		goto destroy_comp;
	}

	/* initialize the random generator */
	srand(time(NULL));

	/* set the callback for random numbers */
	if(!rohc_comp_set_random_cb(comp, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto destroy_comp;
	}

	/* reset list of RTP ports for compressor */
	if(!rohc_comp_reset_rtp_ports(comp))
	{
		fprintf(stderr, "failed to reset list of RTP ports\n");
		goto destroy_comp;
	}

	/* add some ports to the list of RTP ports */
	for(i = 0; i < NB_RTP_PORTS; i++)
	{
		if(!rohc_comp_add_rtp_port(comp, rtp_ports[i]))
		{
			fprintf(stderr, "failed to enable RTP port %u\n", rtp_ports[i]);
			goto destroy_comp;
		}
	}

	/* create the ROHC decompressor in bi-directional mode */
	decomp = rohc_decomp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                         ROHC_O_MODE, comp);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb(decomp, print_rohc_traces))
	{
		fprintf(stderr, "cannot set trace callback for decompressor\n");
		goto destroy_decomp;
	}

	/* decompress the ROHC feedback with the ROHC decompressor */
	ret = rohc_decompress2(decomp, arrival_time,
	                       (unsigned char *) rohc_feedback, rohc_feedback_len,
	                       ip_packet, MAX_ROHC_SIZE, &ip_size);
	if(ret != ROHC_FEEDBACK_ONLY)
	{
		fprintf(stderr, "failed to decompress ROHC feedback\n");
		goto destroy_decomp;
	}
	fprintf(stderr, "decompression is successful\n");

	/* everything went fine */
	is_failure = 0;

destroy_decomp:
	rohc_decomp_free(decomp);
destroy_comp:
	rohc_comp_free(comp);
error:
	return is_failure;
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
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stdout, format, args);
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

