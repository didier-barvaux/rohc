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
 * @file    /comp/comp/schemes/test/test_tcp_ts_opt.c
 * @brief   Test TCP TS option encoding
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "tcp_ts.h"

#include <setjmp.h>
#include <stddef.h>
#include <stdarg.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "config.h" /* for HAVE_CMOCKA_RUN(_GROUP)?_TESTS */


/** Test \ref c_tcp_ts_lsb_code */
static void test_tcp_ts_opt(void **state __attribute__((unused)))
{
	struct rohc_comp comp = { .trace_callback = NULL };
	struct rohc_comp_profile profile = { .id = ROHC_PROFILE_TCP };
	struct rohc_comp_ctxt context = { .compressor = &comp, .profile = &profile };

	uint32_t ts;

	const size_t encoded_max_len = 4;
	uint8_t rohc_data[encoded_max_len];
	size_t rohc_len;

	bool is_ok;

	/* get a random value for TimeStamp (TS) */
	ts = rand() & UINT32_MAX;

	/* 1 byte with prefix '0' */
	is_ok = c_tcp_ts_lsb_code(&context, ts, 0, 0, 0, rohc_data, 0, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 0, 0, 0, rohc_data, 1, &rohc_len);
	assert_true(is_ok == true);
	assert_true(rohc_len == 1);
	assert_true((rohc_data[0] & 0x80) == 0);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 1, 0, 0, rohc_data, 1, &rohc_len);
	assert_true(is_ok == true);
	assert_true(rohc_len == 1);
	assert_true((rohc_data[0] & 0x80) == 0);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 7, 0, 0, rohc_data, 1, &rohc_len);
	assert_true(is_ok == true);
	assert_true(rohc_len == 1);
	assert_true((rohc_data[0] & 0x80) == 0);

	/* 2 bytes with prefix '10' */
	is_ok = c_tcp_ts_lsb_code(&context, ts, 8, 0, 0, rohc_data, 0, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 8, 0, 0, rohc_data, 1, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 8, 0, 0, rohc_data, 2, &rohc_len);
	assert_true(is_ok == true);
	assert_true(rohc_len == 2);
	assert_true((rohc_data[0] & 0xc0) == 0x80);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 14, 0, 0, rohc_data, 2, &rohc_len);
	assert_true(is_ok == true);
	assert_true(rohc_len == 2);
	assert_true((rohc_data[0] & 0xc0) == 0x80);

	/* 3 bytes with prefix '110' */
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 0, 0, rohc_data, 0, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 0, 0, rohc_data, 1, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 0, 0, rohc_data, 2, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 0, 0, rohc_data, 3, &rohc_len);
	assert_true(is_ok == true);
	assert_true(rohc_len == 3);
	assert_true((rohc_data[0] & 0xe0) == 0xc0);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 21, 0, rohc_data, 3, &rohc_len);
	assert_true(is_ok == true);
	assert_true(rohc_len == 3);
	assert_true((rohc_data[0] & 0xe0) == 0xc0);

	/* 4 bytes with prefix '111' */
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 22, 0, rohc_data, 0, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 22, 0, rohc_data, 1, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 22, 0, rohc_data, 2, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 22, 0, rohc_data, 3, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 22, 0, rohc_data, 4, &rohc_len);
	assert_true(is_ok == true);
	assert_true(rohc_len == 4);
	assert_true((rohc_data[0] & 0xe0) == 0xe0);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 22, 29, rohc_data, 4, &rohc_len);
	assert_true(is_ok == true);
	assert_true(rohc_len == 4);
	assert_true((rohc_data[0] & 0xe0) == 0xe0);

	/* more than 29 bits of TS */
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 22, 30, rohc_data, 4, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 22, 31, rohc_data, 4, &rohc_len);
	assert_true(is_ok == false);
	is_ok = c_tcp_ts_lsb_code(&context, ts, 15, 22, 32, rohc_data, 4, &rohc_len);
	assert_true(is_ok == false);
}


/**
 * @brief Test TCP TS option decoding
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
	srand(time(NULL));

#if defined(HAVE_CMOCKA_RUN_GROUP_TESTS) && HAVE_CMOCKA_RUN_GROUP_TESTS == 1
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_tcp_ts_opt),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
#elif defined(HAVE_CMOCKA_RUN_TESTS) && HAVE_CMOCKA_RUN_TESTS == 1
	const UnitTest tests[] = {
		unit_test(test_tcp_ts_opt),
	};
	return run_tests(tests);
#else
#  error "no function found to run cmocka tests"
#endif
}

