/*
 * Copyright 2011,2012,2013,2014 Didier Barvaux
 * Copyright 2012 Viveris Technologies
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

/**
 * @file   test_decompress_feedback_only.c
 * @brief  Check that decompression of ROHC feedback-only packets is fine
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application shall decompress ROHC feedback-only packets successfully.
 */

#include "test.h"

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_decomp.h>


/* prototypes of private functions */
static void usage(void);
static int test_decomp(const struct rohc_buf rohc_feedback)
	__attribute__((warn_unused_result));
static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));


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
	/* a ROHC feedback-only packet */
	const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
	uint8_t rohc_feedback_data[] = { 0xf4, 0x20, 0x00, 0x11, 0xe9 };
	const size_t rohc_feedback_len = 5;
	const struct rohc_buf rohc_feedback =
		rohc_buf_init_full(rohc_feedback_data, rohc_feedback_len, arrival_time);

	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc != 1)
	{
		usage();
		goto error;
	}

	/* test ROHC feedback-only decompression */
	status = test_decomp(rohc_feedback);

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
 * @param rohc_feedback  The ROHC feedback data
 * @return               0 in case of success,
 *                       1 in case of failure
 */
static int test_decomp(const struct rohc_buf rohc_feedback)
{
	struct rohc_decomp *decomp;

	uint8_t ip_buffer[MAX_ROHC_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, MAX_ROHC_SIZE);

	uint8_t feedback_buffer[MAX_ROHC_SIZE];
	struct rohc_buf feedback_packet =
		rohc_buf_init_empty(feedback_buffer, MAX_ROHC_SIZE);

	int is_failure = 1;
	int ret;

	/* create the ROHC decompressor in bi-directional mode */
	decomp = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_O_MODE);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto error;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb(decomp, print_rohc_traces))
	{
		fprintf(stderr, "cannot set trace callback for decompressor\n");
		goto destroy_decomp;
	}

	/* decompress the ROHC feedback with the ROHC decompressor */
	ret = rohc_decompress3(decomp, rohc_feedback, &ip_packet,
	                       &feedback_packet, NULL);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to decompress ROHC feedback\n");
		goto destroy_decomp;
	}
	if(!rohc_buf_is_empty(ip_packet))
	{
		fprintf(stderr, "ROHC packet was not a feedback-only packet\n");
	}
	if(rohc_buf_is_empty(feedback_packet))
	{
		fprintf(stderr, "ROHC packet contained no feedback data\n");
	}
	fprintf(stderr, "decompression is successful\n");

	/* everything went fine */
	is_failure = 0;

destroy_decomp:
	rohc_decomp_free(decomp);
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

