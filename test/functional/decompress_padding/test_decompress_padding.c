/*
 * Copyright 2014 Didier Barvaux
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
 * @file   test_decompress_padding.c
 * @brief  Check that padded ROHC packets are decompressed as expected
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application shall decompress ROHC padded packets successfully.
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
static int test_decomp(const struct rohc_buf rohc_pkt)
	__attribute__((warn_unused_result));
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 5, 6), nonnull(5)));


/**
 * @brief Check that the decompression of the ROHC padded packets is
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
	const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };

	/* a ROHC IR packet with 1-byte padding prepended */
	uint8_t rohc_ir_padded1[] = {
		0xe0, 0xfc, 0x00, 0xb7, 0x55, 0x00, 0x00, 0x54,
		0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x83, 0x52,
		0xc0, 0xa8, 0x13, 0x01, 0xc0, 0xa8, 0x13, 0x05,
		0x08, 0x00, 0xe9, 0xc2, 0x9b, 0x42, 0x00, 0x01,
		0x66, 0x15, 0xa6, 0x45, 0x77, 0x9b, 0x04, 0x00,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 };
	const size_t rohc_ir_padded1_len = 11 * 8;
	const struct rohc_buf rohc_ir_padded1_pkt =
		rohc_buf_init_full(rohc_ir_padded1, rohc_ir_padded1_len, arrival_time);

	/* a ROHC feedback-only packet with 1-byte padding prepended */
	uint8_t rohc_feedback_padded1[] = { 0xe0, 0xf4, 0x20, 0x00, 0x11, 0xe9 };
	const size_t rohc_feedback_padded1_len = 6;
	const struct rohc_buf rohc_feedback_padded1_pkt =
		rohc_buf_init_full(rohc_feedback_padded1, rohc_feedback_padded1_len,
		                   arrival_time);

	/* a ROHC feedback-only packet with 2-byte padding prepended */
	uint8_t rohc_feedback_padded2[] = {
		0xe0, 0xe0, 0xf4, 0x20, 0x00, 0x11, 0xe9 };
	const size_t rohc_feedback_padded2_len = 7;
	const struct rohc_buf rohc_feedback_padded2_pkt =
		rohc_buf_init_full(rohc_feedback_padded2, rohc_feedback_padded2_len,
		                   arrival_time);

	/* a ROHC IR packet with 1-byte padding prepended and feedback data */
	uint8_t rohc_ir_feedback_padded1[] = {
		0xe0, 0xf4, 0x20, 0x00, 0x11, 0xe9,
		0xfc, 0x00, 0xb7, 0x55, 0x00, 0x00, 0x54,
		0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x83, 0x52,
		0xc0, 0xa8, 0x13, 0x01, 0xc0, 0xa8, 0x13, 0x05,
		0x08, 0x00, 0xe9, 0xc2, 0x9b, 0x42, 0x00, 0x01,
		0x66, 0x15, 0xa6, 0x45, 0x77, 0x9b, 0x04, 0x00,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 };
	const size_t rohc_ir_feedback_padded1_len = 11 * 8 + 5;
	const struct rohc_buf rohc_ir_feedback_padded1_pkt =
		rohc_buf_init_full(rohc_ir_feedback_padded1,
		                   rohc_ir_feedback_padded1_len,
		                   arrival_time);

	/* a ROHC padding-only packet */
	uint8_t rohc_padding_only[] = { 0xe0, 0xe0, 0xe0, 0xe0, 0xe0, 0xe0 };
	const size_t rohc_padding_only_len = 6;
	const struct rohc_buf rohc_padding_only_pkt =
		rohc_buf_init_full(rohc_padding_only, rohc_padding_only_len,
		                   arrival_time);

	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc != 1)
	{
		usage();
		goto error;
	}

	/* ROHC packets with padding bytes and followed by feedback and/or header
	 * shall be successfully decompressed */
	fprintf(stderr, "decompress rohc_ir_padded1\n");
	status = test_decomp(rohc_ir_padded1_pkt);
	assert(status == 0);
	fprintf(stderr, "decompress rohc_feedback_padded1\n");
	status = test_decomp(rohc_feedback_padded1_pkt);
	assert(status == 0);
	fprintf(stderr, "decompress rohc_feedback_padded2\n");
	status = test_decomp(rohc_feedback_padded2_pkt);
	assert(status == 0);
	fprintf(stderr, "decompress rohc_ir_feedback_padded1\n");
	status = test_decomp(rohc_ir_feedback_padded1_pkt);
	assert(status == 0);

	/* ROHC packet with only padding bytes is not allowed. RFC 3095 reads:
	 *   Padding is any number (zero or more) of padding octets.  Either of
	 *   Feedback or Header must be present. */
	fprintf(stderr, "decompress rohc_padding_only\n");
	status = test_decomp(rohc_padding_only_pkt);
	assert(status != 0);

	/* everything went fine */
	status = 0;

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that ROHC padded packets are decompressed as expected\n"
	        "\n"
	        "usage: test_decompress_padding [OPTIONS]\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with the given ROHC padded packet
 *
 * @param rohc_pkt      The ROHC packet
 * @return              0 in case of success,
 *                      1 in case of failure
 */
static int test_decomp(const struct rohc_buf rohc_pkt)
{
	struct rohc_decomp *decomp;

	uint8_t ip_buffer[MAX_ROHC_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, MAX_ROHC_SIZE);

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
	if(!rohc_decomp_set_traces_cb2(decomp, print_rohc_traces, NULL))
	{
		fprintf(stderr, "cannot set trace callback for decompressor\n");
		goto destroy_decomp;
	}

	/* enable all profiles */
	if(!rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_UNCOMPRESSED,
	                                ROHC_PROFILE_IP, ROHC_PROFILE_UDP,
	                                ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                                ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "cannot enable all decompression profiles\n");
		goto destroy_decomp;
	}

	/* decompress the ROHC packet with the ROHC decompressor */
	ret = rohc_decompress3(decomp, rohc_pkt, &ip_packet, NULL, NULL);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to decompress ROHC packet\n");
		goto destroy_decomp;
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
	vfprintf(stdout, format, args);
	va_end(args);
}

