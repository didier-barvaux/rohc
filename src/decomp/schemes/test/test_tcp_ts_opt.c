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
 * @file    test_tcp_ts_opt.c
 * @brief   Test TCP TS option decoding
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "tcp_ts.h"

#include <setjmp.h>
#include <stddef.h>
#include <stdarg.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>

#include "config.h" /* for HAVE_CMOCKA_RUN(_GROUP)?_TESTS */


/** Test \ref test_tcp_ts_opt */
static void test_tcp_ts_opt(void **state)
{
	struct rohc_decomp decomp = { .trace_callback = NULL };
	struct rohc_decomp_profile profile = { .id = ROHC_PROFILE_TCP };
	struct rohc_decomp_ctxt context = { .decompressor = &decomp, .profile = &profile };
	struct rohc_lsb_field32 lsb32;
	uint32_t val;
	size_t i;
	int ret;

	/* 1-byte long with prefix '0' */
	for(val = 0; val < 0x80; val++)
	{
		const uint8_t data[1] = {
			val
		};

		printf("decode 1-byte value 0x%08x...\n", val);

		/* too short for 1-byte long */
		ret = d_tcp_ts_lsb_parse(&context, data, 0, &lsb32);
		assert_true(ret == -1);

		/* 1-byte long with 7 LSB bits */
		ret = d_tcp_ts_lsb_parse(&context, data, 1, &lsb32);
		assert_true(ret == 1);
		assert_true(lsb32.bits == val);
		assert_true(lsb32.bits_nr == 7);
		assert_true(lsb32.p == ROHC_LSB_SHIFT_TCP_TS_1B);
	}

	/* 2-byte long with prefix '10' */
	for(val = 0; val < 0x4000; val++)
	{
		const uint8_t data[2] = {
			0x80 | ((val >> 8) & 0xff),
			val & 0xff
		};

		printf("decode 2-byte value 0x%08x...\n", val);

		/* too short for 2-byte long */
		ret = d_tcp_ts_lsb_parse(&context, data, 1, &lsb32);
		assert_true(ret == -1);

		/* 2-byte long with 14 LSB bits */
		ret = d_tcp_ts_lsb_parse(&context, data, 2, &lsb32);
		assert_true(ret == 2);
		assert_true(lsb32.bits == val);
		assert_true(lsb32.bits_nr == 14);
		assert_true(lsb32.p == ROHC_LSB_SHIFT_TCP_TS_1B);
	}

	/* 3-byte long with prefix '110' */
	const uint32_t vals_3_byte[] = { 0, 0x200000 / 2, 0x200000 - 1 };
	for(i = 0; i < sizeof(vals_3_byte) / sizeof(uint32_t); i++)
	{
		val = vals_3_byte[i];
		const uint8_t data[3] = {
			0xc0 | ((val >> 16) & 0xff),
			(val >> 8) & 0xff,
			val & 0xff
		};

		printf("decode 3-byte value 0x%08x...\n", val);

		/* too short for 3-byte long */
		ret = d_tcp_ts_lsb_parse(&context, data, 1, &lsb32);
		assert_true(ret == -1);
		ret = d_tcp_ts_lsb_parse(&context, data, 2, &lsb32);
		assert_true(ret == -1);

		/* 3-byte long with 21 LSB bits */
		ret = d_tcp_ts_lsb_parse(&context, data, 3, &lsb32);
		assert_true(ret == 3);
		assert_true(lsb32.bits == val);
		assert_true(lsb32.bits_nr == 21);
		assert_true(lsb32.p == ROHC_LSB_SHIFT_TCP_TS_3B);
	}

	/* 4-byte long with prefix '111' */
	const uint32_t vals_4_byte[] = { 0, 0x20000000 / 2, 0x20000000 - 1 };
	for(i = 0; i < sizeof(vals_4_byte) / sizeof(uint32_t); i++)
	{
		val = vals_4_byte[i];
		const uint8_t data[4] = {
			0xe0 | ((val >> 24) & 0xff),
			(val >> 16) & 0xff,
			(val >> 8) & 0xff,
			val & 0xff
		};

		printf("decode 4-byte value 0x%08x...\n", val);

		/* too short for 4-byte long */
		ret = d_tcp_ts_lsb_parse(&context, data, 1, &lsb32);
		assert_true(ret == -1);
		ret = d_tcp_ts_lsb_parse(&context, data, 2, &lsb32);
		assert_true(ret == -1);
		ret = d_tcp_ts_lsb_parse(&context, data, 3, &lsb32);
		assert_true(ret == -1);

		/* 4-byte long with 29 LSB bits */
		ret = d_tcp_ts_lsb_parse(&context, data, 4, &lsb32);
		assert_true(ret == 4);
		assert_true(lsb32.bits == val);
		assert_true(lsb32.bits_nr == 29);
		assert_true(lsb32.p == ROHC_LSB_SHIFT_TCP_TS_4B);
	}
}


/**
 * @brief Test TCP TS option decoding
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
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

