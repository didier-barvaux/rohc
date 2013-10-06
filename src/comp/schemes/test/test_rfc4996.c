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
 * @file   test_rfc4996_encoding.c
 * @brief  Tests for RFC4996 encoding methods
 * @author Didier Barvaux <didier@barvaux.org>
 */


#include <stdint.h>

#include "rfc4996.h"

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
	uint8_t compressed_data[sizeof(uint32_t)];
	size_t i;
	int ret;

	const struct
	{
		uint32_t uncomp_value;
		size_t expected_len;
		unsigned int expected_indicator;
	}
	inputs[] = {
		{ htonl(0),          0, 0 },
		{ htonl(1),          1, 1 },
		{ htonl(0xff),       1, 1 },
		{ htonl(0xff + 1),   2, 2 },
		{ htonl(0xffff),     2, 2 },
		{ htonl(0xffff + 1), 4, 3 },
		{ htonl(0xfffff),    4, 3 },
		{ htonl(0xffffff),   4, 3 },
		{ htonl(0xfffffff),  4, 3 },
		{ htonl(0xffffffff), 4, 3 },
		{ 0,                 0, 4 }  /* stopper */
	};

	i = 0;
	while(inputs[i].expected_indicator <= 3)
	{
		int indicator;
		size_t comp_len;

		/* compress the value */
		trace(be_verbose, "\tvariable_length_32_enc(value = 0x%08x)\n",
		      inputs[i].uncomp_value);
		ret = variable_length_32_enc(inputs[i].uncomp_value, compressed_data,
		                             &indicator);
		if(ret < 0)
		{
			fprintf(stderr, "variable_length_32_enc(value = 0x%08x) failed\n",
			        inputs[i].uncomp_value);
			goto error;
		}
		comp_len = ret;

		/* check that returned indicator is as expected */
		if(indicator != inputs[i].expected_indicator)
		{
			fprintf(stderr, "variable_length_32_enc(value = 0x%08x) returned %u "
			        "as indicator while %u expected\n", inputs[i].uncomp_value,
			        indicator, inputs[i].expected_indicator);
			goto error;
		}

		/* check that written data is as expected */
		if(comp_len != inputs[i].expected_len)
		{
			fprintf(stderr, "variable_length_32_enc(value = 0x%08x) wrote one "
			        "%zd-byte compressed value while one %zd-byte value was "
			        "expected\n", inputs[i].uncomp_value, comp_len,
			        inputs[i].expected_len);
			goto error;
		}

		i++;
	}

	return true;

error:
	return false;
}

