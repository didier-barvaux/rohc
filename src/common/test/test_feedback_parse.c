/*
 * Copyright 2015 Didier Barvaux
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
 * @file    test_feedback_parse.c
 * @brief   Test the parsing of feedback packets
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "feedback_parse.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>


/** Print trace on stdout only in verbose mode */
#define trace(is_verbose, format, ...) \
	do { \
		if(is_verbose) { \
			printf(format, ##__VA_ARGS__); \
		} \
	} while(0)

/** Improved assert() */
#define CHECK(condition) \
	do { \
		trace(verbose, "test '%s'\n", #condition); \
		fflush(stdout); \
		assert(condition); \
	} while(0)


/**
 * @brief Test the parsing of feedback packets
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
	bool verbose; /* whether to run in verbose mode or not */
	int is_failure = 1; /* test fails by default */

	/* do we run in verbose mode ? */
	if(argc == 1)
	{
		/* no argument, run in silent mode */
		verbose = false;
	}
	else if(argc == 2 && strcmp(argv[1], "verbose") == 0)
	{
		/* run in verbose mode */
		verbose = true;
	}
	else
	{
		/* invalid usage */
		printf("test the parsing of feedback packet\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* rohc_packet_is_feedback() */
	CHECK(rohc_packet_is_feedback(0x00) == false);
	CHECK(rohc_packet_is_feedback(0xf0 - 0x01) == false);
	CHECK(rohc_packet_is_feedback(0xf0 + 0x00) == true);
	CHECK(rohc_packet_is_feedback(0xf0 + 0x01) == true);
	CHECK(rohc_packet_is_feedback(0xf0 + 0x02) == true);
	CHECK(rohc_packet_is_feedback(0xf0 + 0x03) == true);
	CHECK(rohc_packet_is_feedback(0xf0 + 0x04) == true);
	CHECK(rohc_packet_is_feedback(0xf0 + 0x05) == true);
	CHECK(rohc_packet_is_feedback(0xf0 + 0x06) == true);
	CHECK(rohc_packet_is_feedback(0xf0 + 0x07) == true);
	CHECK(rohc_packet_is_feedback(0xf0 + 0x08) == false);
	CHECK(rohc_packet_is_feedback(0xff) == false);

	/* rohc_feedback_get_size() */
	{
#define feedback_max_len 10U
		uint8_t buf[feedback_max_len];
		struct rohc_buf feedback = rohc_buf_init_empty(buf, feedback_max_len);
		size_t feedback_hdr_len = 0xff;
		size_t feedback_data_len = 0xff;

		const uint8_t feedback_0[] = { 0xf0, 0x08, 0xbe, 0xef, 0xfe, 0xed, 0xbe, 0xef, 0xfe, 0xed };
		const uint8_t feedback_1[] = { 0xf1, 0x00 };
		const uint8_t feedback_2[] = { 0xf2, 0x00, 0x00 };
		const uint8_t feedback_3[] = { 0xf3, 0x00, 0x00, 0x00 };
		const uint8_t feedback_4[] = { 0xf4, 0x00, 0x00, 0x00, 0x00 };
		const uint8_t feedback_5[] = { 0xf5, 0x00, 0x00, 0x00, 0x00, 0x00 };
		const uint8_t feedback_6[] = { 0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		const uint8_t feedback_7[] = { 0xf7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		rohc_buf_reset(&feedback);
		CHECK(rohc_feedback_get_size(feedback, &feedback_hdr_len, &feedback_data_len) == false);

		rohc_buf_reset(&feedback);
		rohc_buf_append(&feedback, feedback_0, 10);
		CHECK(rohc_feedback_get_size(feedback, &feedback_hdr_len, &feedback_data_len));
		CHECK(feedback_hdr_len == 2);
		CHECK(feedback_data_len == 8);

		rohc_buf_reset(&feedback);
		rohc_buf_append(&feedback, feedback_1, 2);
		CHECK(rohc_feedback_get_size(feedback, &feedback_hdr_len, &feedback_data_len));
		CHECK(feedback_hdr_len == 1);
		CHECK(feedback_data_len == 1);

		rohc_buf_reset(&feedback);
		rohc_buf_append(&feedback, feedback_2, 3);
		CHECK(rohc_feedback_get_size(feedback, &feedback_hdr_len, &feedback_data_len));
		CHECK(feedback_hdr_len == 1);
		CHECK(feedback_data_len == 2);

		rohc_buf_reset(&feedback);
		rohc_buf_append(&feedback, feedback_3, 4);
		CHECK(rohc_feedback_get_size(feedback, &feedback_hdr_len, &feedback_data_len));
		CHECK(feedback_hdr_len == 1);
		CHECK(feedback_data_len == 3);

		rohc_buf_reset(&feedback);
		rohc_buf_append(&feedback, feedback_4, 5);
		CHECK(rohc_feedback_get_size(feedback, &feedback_hdr_len, &feedback_data_len));
		CHECK(feedback_hdr_len == 1);
		CHECK(feedback_data_len == 4);

		rohc_buf_reset(&feedback);
		rohc_buf_append(&feedback, feedback_5, 6);
		CHECK(rohc_feedback_get_size(feedback, &feedback_hdr_len, &feedback_data_len));
		CHECK(feedback_hdr_len == 1);
		CHECK(feedback_data_len == 5);

		rohc_buf_reset(&feedback);
		rohc_buf_append(&feedback, feedback_6, 7);
		CHECK(rohc_feedback_get_size(feedback, &feedback_hdr_len, &feedback_data_len));
		CHECK(feedback_hdr_len == 1);
		CHECK(feedback_data_len == 6);

		rohc_buf_reset(&feedback);
		rohc_buf_append(&feedback, feedback_7, 8);
		CHECK(rohc_feedback_get_size(feedback, &feedback_hdr_len, &feedback_data_len));
		CHECK(feedback_hdr_len == 1);
		CHECK(feedback_data_len == 7);
	}

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}

