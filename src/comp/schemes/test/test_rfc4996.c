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
 * @file   test_rfc4996_encoding.c
 * @brief  Tests for RFC4996 encoding methods
 * @author Didier Barvaux <didier@barvaux.org>
 */


#include <stdint.h>

#include "rfc4996.h"
#include "comp_wlsb.h"

#include "config.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif



/** The width of the W-LSB sliding window */
#define ROHC_WLSB_WINDOW_WIDTH  4U

/** Print trace on stdout only in verbose mode */
#define trace(is_verbose, format, ...) \
	do { \
		if(is_verbose) { \
			printf(format, ##__VA_ARGS__); \
		} \
	} while(0)

static bool run_test_variable_length_32_enc(const bool be_verbose);



/**
 * @brief Test RFC4996 encoding methods
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
		printf("test the RFC4996 encoding methods\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* test variable_length_32_enc(flag) method */
	trace(verbose, "test variable_length_32_enc(flag) method\n");
	if(!run_test_variable_length_32_enc(verbose))
	{
		fprintf(stderr, "test failed\n");
		goto error;
	}

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Run the variable_length_32_enc(flag) test
 *
 * @param be_verbose  Whether to print traces or not
 * @return            true if test succeeds, false otherwise
 */
static bool run_test_variable_length_32_enc(const bool be_verbose)
{
	const size_t comp_max_len = sizeof(uint32_t);
	uint8_t comp_data[comp_max_len];
	struct c_wlsb *wlsb;
	uint32_t old_value;
	bool is_success = false;
	size_t i;

	const struct
	{
		uint32_t uncomp_value;
		size_t expected_len;
		int expected_indicator;
	}
	inputs[] = { /* works with width = 4 */
		{ 0,              0, 0 },
		{ 1,              1, 1 },
		{ 2,              1, 1 },
		{ 3,              1, 1 },
		{ 4,              1, 1 },
		{ 0xff,           2, 2 },
		{ 0xff + 1,       2, 2 },
		{ 0xff + 2,       2, 2 },
		{ 0xff + 3,       2, 2 },
		{ 0xff + 4,       1, 1 },
		{ 0xffff,         4, 3 },
		{ 0xffff + 1,     4, 3 },
		{ 0xffff + 2,     4, 3 },
		{ 0xffff + 3,     4, 3 },
		{ 0xffff + 4,     1, 1 },
		{ 0xfffff,        4, 3 },
		{ 0xfffff + 1,    4, 3 },
		{ 0xfffff + 2,    4, 3 },
		{ 0xfffff + 3,    4, 3 },
		{ 0xfffff + 4,    1, 1 },
		{ 0xffffff,       4, 3 },
		{ 0xffffff + 1,   4, 3 },
		{ 0xffffff + 2,   4, 3 },
		{ 0xffffff + 3,   4, 3 },
		{ 0xffffff + 4,   1, 1 },
		{ 0xfffffff,      4, 3 },
		{ 0xfffffff + 1,  4, 3 },
		{ 0xfffffff + 2,  4, 3 },
		{ 0xfffffff + 3,  4, 3 },
		{ 0xfffffff + 4,  1, 1 },
		{ 0xffffffff,     4, 3 },
		{ 0xffffffff + 1, 4, 3 },
		{ 0xffffffff + 2, 4, 3 },
		{ 0xffffffff + 3, 4, 3 },
		{ 0xffffffff + 4, 1, 1 },
		{ 0,              0, 4 }  /* stopper */
	};

	/* create the W-LSB context */
	wlsb = c_create_wlsb(32, ROHC_WLSB_WINDOW_WIDTH, ROHC_LSB_SHIFT_VAR);
	if(wlsb == NULL)
	{
		trace(be_verbose, "failed to create W-LSB context\n");
		goto error;
	}
	/* init the W-LSB context with several values */
	c_add_wlsb(wlsb, 0, 0);
	c_add_wlsb(wlsb, 1, 0);
	c_add_wlsb(wlsb, 2, 0);
	c_add_wlsb(wlsb, 3, 0);

	i = 0;
	old_value = 0;
	while(inputs[i].expected_indicator <= 3)
	{
		int indicator;
		size_t comp_len;
		size_t nr_bits_16383;
		size_t nr_bits_63;

		/* detect how many bits are required for the value */
		nr_bits_16383 = wlsb_get_kp_32bits(wlsb, inputs[i].uncomp_value, 16383);
		nr_bits_63 = wlsb_get_kp_32bits(wlsb, inputs[i].uncomp_value, 63);

		/* compress the value */
		trace(be_verbose, "\tvariable_length_32_enc(value = 0x%08x)\n",
		      inputs[i].uncomp_value);
		comp_len = variable_length_32_enc(old_value, inputs[i].uncomp_value,
		                                  nr_bits_63, nr_bits_16383,
		                                  comp_data, comp_max_len, &indicator);
		printf("\t\tindicator %d\n", indicator);
		printf("\t\tencoded length %zu\n", comp_len);

		/* check that returned indicator is as expected */
		if(indicator != inputs[i].expected_indicator)
		{
			fprintf(stderr, "variable_length_32_enc(value = 0x%08x) returned %d "
			        "as indicator while %d expected\n", inputs[i].uncomp_value,
			        indicator, inputs[i].expected_indicator);
			goto free_wlsb;
		}

		/* check that written data is as expected */
		if(comp_len != inputs[i].expected_len)
		{
			fprintf(stderr, "variable_length_32_enc(value = 0x%08x) wrote one "
			        "%zd-byte compressed value while one %zd-byte value was "
			        "expected\n", inputs[i].uncomp_value, comp_len,
			        inputs[i].expected_len);
			goto free_wlsb;
		}

		c_add_wlsb(wlsb, i + 4, inputs[i].uncomp_value);
		old_value = inputs[i].uncomp_value;

		i++;
	}

	is_success = true;

free_wlsb:
	c_destroy_wlsb(wlsb);
error:
	return is_success;
}

