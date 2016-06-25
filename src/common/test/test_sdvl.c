/*
 * Copyright 2016 Didier Barvaux
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
 * @file    test_sdvl.c
 * @brief   Test the SDVL compression scheme
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "sdvl.h"

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
 * @brief Test the SDVL compression scheme
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
		printf("test the SDVL compression scheme\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* sdvl_can_value_be_encoded() */
	CHECK(sdvl_can_value_be_encoded(0U) == true);
	CHECK(sdvl_can_value_be_encoded(1U) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 5) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 6) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 7) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 12) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 13) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 14) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 19) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 20) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 21) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 27) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 28) == true);
	CHECK(sdvl_can_value_be_encoded(1U << 29) == false);
	CHECK(sdvl_can_value_be_encoded(1U << 30) == false);
	CHECK(sdvl_can_value_be_encoded(1U << 31) == false);
	CHECK(sdvl_can_value_be_encoded(UINT32_MAX) == false);

	/* sdvl_can_length_be_encoded() */
	CHECK(sdvl_can_length_be_encoded(0) == true);
	CHECK(sdvl_can_length_be_encoded(1) == true);
	CHECK(sdvl_can_length_be_encoded(6) == true);
	CHECK(sdvl_can_length_be_encoded(7) == true);
	CHECK(sdvl_can_length_be_encoded(8) == true);
	CHECK(sdvl_can_length_be_encoded(13) == true);
	CHECK(sdvl_can_length_be_encoded(14) == true);
	CHECK(sdvl_can_length_be_encoded(15) == true);
	CHECK(sdvl_can_length_be_encoded(20) == true);
	CHECK(sdvl_can_length_be_encoded(21) == true);
	CHECK(sdvl_can_length_be_encoded(22) == true);
	CHECK(sdvl_can_length_be_encoded(28) == true);
	CHECK(sdvl_can_length_be_encoded(29) == true);
	CHECK(sdvl_can_length_be_encoded(30) == false);
	CHECK(sdvl_can_length_be_encoded(31) == false);
	CHECK(sdvl_can_length_be_encoded(32) == false);

	/* sdvl_get_min_len() */
	CHECK(sdvl_get_min_len(0, 0) == 0);
	CHECK(sdvl_get_min_len(1, 0) == 7);
	CHECK(sdvl_get_min_len(6, 0) == 7);
	CHECK(sdvl_get_min_len(7, 0) == 7);
	CHECK(sdvl_get_min_len(8, 0) == 14);
	CHECK(sdvl_get_min_len(13, 0) == 14);
	CHECK(sdvl_get_min_len(14, 0) == 14);
	CHECK(sdvl_get_min_len(15, 0) == 21);
	CHECK(sdvl_get_min_len(20, 0) == 21);
	CHECK(sdvl_get_min_len(21, 0) == 21);
	CHECK(sdvl_get_min_len(22, 0) == 29);
	CHECK(sdvl_get_min_len(28, 0) == 29);
	CHECK(sdvl_get_min_len(29, 0) == 29);
	CHECK(sdvl_get_min_len(0, 1) == 0);
	CHECK(sdvl_get_min_len(1, 1) == 0);
	CHECK(sdvl_get_min_len(6, 1) == 7);
	CHECK(sdvl_get_min_len(7, 1) == 7);
	CHECK(sdvl_get_min_len(8, 1) == 7);
	CHECK(sdvl_get_min_len(13, 1) == 14);
	CHECK(sdvl_get_min_len(14, 1) == 14);
	CHECK(sdvl_get_min_len(15, 1) == 14);
	CHECK(sdvl_get_min_len(20, 1) == 21);
	CHECK(sdvl_get_min_len(21, 1) == 21);
	CHECK(sdvl_get_min_len(22, 1) == 21);
	CHECK(sdvl_get_min_len(28, 1) == 29);
	CHECK(sdvl_get_min_len(29, 1) == 29);
	CHECK(sdvl_get_min_len(0, 21) == 0);
	CHECK(sdvl_get_min_len(1, 21) == 0);
	CHECK(sdvl_get_min_len(6, 21) == 0);
	CHECK(sdvl_get_min_len(7, 21) == 0);
	CHECK(sdvl_get_min_len(8, 21) == 0);
	CHECK(sdvl_get_min_len(13, 21) == 0);
	CHECK(sdvl_get_min_len(14, 21) == 0);
	CHECK(sdvl_get_min_len(15, 21) == 0);
	CHECK(sdvl_get_min_len(20, 21) == 0);
	CHECK(sdvl_get_min_len(21, 21) == 0);
	CHECK(sdvl_get_min_len(22, 21) == 7);
	CHECK(sdvl_get_min_len(28, 21) == 7);
	CHECK(sdvl_get_min_len(29, 21) == 14);
	CHECK(sdvl_get_min_len(0, 32) == 0);
	CHECK(sdvl_get_min_len(1, 32) == 0);
	CHECK(sdvl_get_min_len(6, 32) == 0);
	CHECK(sdvl_get_min_len(7, 32) == 0);
	CHECK(sdvl_get_min_len(8, 32) == 0);
	CHECK(sdvl_get_min_len(13, 32) == 0);
	CHECK(sdvl_get_min_len(14, 32) == 0);
	CHECK(sdvl_get_min_len(15, 32) == 0);
	CHECK(sdvl_get_min_len(20, 32) == 0);
	CHECK(sdvl_get_min_len(21, 32) == 0);
	CHECK(sdvl_get_min_len(22, 32) == 0);
	CHECK(sdvl_get_min_len(28, 32) == 0);
	CHECK(sdvl_get_min_len(29, 32) == 0);

	/* sdvl_get_encoded_len() */
	CHECK(sdvl_get_encoded_len(0U) == 1);
	CHECK(sdvl_get_encoded_len(1U) == 1);
	CHECK(sdvl_get_encoded_len(1U << 5) == 1);
	CHECK(sdvl_get_encoded_len(1U << 6) == 1);
	CHECK(sdvl_get_encoded_len(1U << 7) == 2);
	CHECK(sdvl_get_encoded_len(1U << 12) == 2);
	CHECK(sdvl_get_encoded_len(1U << 13) == 2);
	CHECK(sdvl_get_encoded_len(1U << 14) == 3);
	CHECK(sdvl_get_encoded_len(1U << 19) == 3);
	CHECK(sdvl_get_encoded_len(1U << 20) == 3);
	CHECK(sdvl_get_encoded_len(1U << 21) == 4);
	CHECK(sdvl_get_encoded_len(1U << 27) == 4);
	CHECK(sdvl_get_encoded_len(1U << 28) == 4);
	CHECK(sdvl_get_encoded_len(1U << 29) == 5);
	CHECK(sdvl_get_encoded_len(1U << 30) == 5);
	CHECK(sdvl_get_encoded_len(1U << 31) == 5);

	/* sdvl_encode() / sdvl_encode_full() / sdvl_decode() */
	{
		const uint32_t values[] =  { 1, 6, 7,  8, 13, 14, 15, 20, 21, 22, 28, 29, 30, 31, 32 };
		const size_t values_nr = sizeof(values) / sizeof(uint32_t);
		const size_t exp_bytes[] = { 1, 1, 1,  2,  2,  2,  3,  3,  3,  4,  4,  4,  5,  5,  5 };
		const size_t exp_bytes_nr = sizeof(exp_bytes) / sizeof(size_t);
		const size_t exp_bits[] =  { 7, 7, 7, 14, 14, 14, 21, 21, 21, 29, 29, 29, 32, 32, 32 };
		const size_t exp_bits_nr = sizeof(exp_bits) / sizeof(size_t);
		size_t sdvl_bytes_max_nr;

		CHECK(values_nr == exp_bytes_nr);
		CHECK(values_nr == exp_bits_nr);

		for(sdvl_bytes_max_nr = 0; sdvl_bytes_max_nr <= 4; sdvl_bytes_max_nr++)
		{
			size_t i;

			for(i = 0; i < values_nr; i++)
			{
				const uint32_t value = (values[i] == 32 ? UINT32_MAX : ((1U << values[i]) - 1U));
				uint8_t sdvl_bytes[sdvl_bytes_max_nr];
				size_t sdvl_bytes_nr;
				uint32_t decoded_value;
				size_t useful_bits_nr;

				/* sdvl_encode_full() */
				const bool exp_status = (exp_bytes[i] <= 4 && exp_bytes[i] <= sdvl_bytes_max_nr);
				CHECK(sdvl_encode_full(sdvl_bytes, sdvl_bytes_max_nr, &sdvl_bytes_nr,
				                       value) == exp_status);
				if(exp_status)
				{
					printf("sdvl_encode_full(%u) = ", value);
					for(size_t j = 0; j < sdvl_bytes_nr; j++)
					{
						printf("0x%02x ", sdvl_bytes[j]);
					}
					printf("\n");
					CHECK(sdvl_bytes_nr == exp_bytes[i]);

					/* sdvl_decode() */
					for(size_t j = 0; j <= sdvl_bytes_nr; j++)
					{
						const size_t exp_result = (j < sdvl_bytes_nr ? 0 : exp_bytes[i]);
						CHECK(sdvl_decode(sdvl_bytes, j, &decoded_value,
						                  &useful_bits_nr) == exp_result);
						if(exp_result > 0)
						{
							CHECK(decoded_value == value);
							CHECK(useful_bits_nr == exp_bits[i]);
						}
					}
				}

				/* sdvl_encode() */
				{
					uint8_t sdvl_bytes2[sdvl_bytes_max_nr];
					size_t sdvl_bytes2_nr;
					CHECK(sdvl_encode(sdvl_bytes2, sdvl_bytes_max_nr, &sdvl_bytes2_nr,
					                  value, exp_bits[i]) == exp_status);
					if(exp_status)
					{
						printf("sdvl_encode(%u) = ", value);
						for(size_t j = 0; j < sdvl_bytes_nr; j++)
						{
							printf("0x%02x ", sdvl_bytes[j]);
						}
						printf("\n");
						CHECK(sdvl_bytes2_nr == sdvl_bytes_nr);
						CHECK(memcmp(sdvl_bytes2, sdvl_bytes, sdvl_bytes2_nr) == 0);
					}
				}
			}
		}
	}

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}

