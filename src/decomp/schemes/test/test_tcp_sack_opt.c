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
 * @file    test_tcp_sack_opt.c
 * @brief   Test TCP SACK option decoding
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "tcp_sack.h"

#include <setjmp.h>
#include <stddef.h>
#include <stdarg.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>

#include "config.h" /* for HAVE_CMOCKA_RUN(_GROUP)?_TESTS */


#define lsb_15(val) \
	((((val) & 0x7fff) >> 8) & 0x7f), \
	(((val) & 0x7fff) & 0xff)

#define lsb_22(val) \
	(0x80 | ((((val) & 0x3fffff) >> 16) & 0x3f)), \
	((((val) & 0x3fffff) >> 8) & 0xff), \
	(((val) & 0x3fffff) & 0xff)

#define lsb_29(val) \
	(0xc0 | ((((val) & 0x1fffffff) >> 16) & 0x1f)), \
	((((val) & 0x1fffffff) >> 16) & 0xff), \
	((((val) & 0x1fffffff) >> 8) & 0xff), \
	(((val) & 0x1fffffff) & 0xff)

#define lsb_32(val) \
	0xff, \
	(((val) >> 24) & 0xff), \
	(((val) >> 16) & 0xff), \
	(((val) >> 8) & 0xff), \
	((val) & 0xff)


void test_tcp_sack_opt_1_block(const uint32_t val)
{
	struct rohc_decomp decomp = { .trace_callback = NULL };
	struct rohc_decomp_profile profile = { .id = ROHC_PROFILE_TCP };
	struct rohc_decomp_ctxt context = { .decompressor = &decomp, .profile = &profile };
	struct d_tcp_opt_sack sack;
	const uint8_t data[] = {
		0x01,                    /* discriminator */
		lsb_15(val),             /* block 1 */
		lsb_15(val + 1),
	};
	size_t i;
	int ret;

	/* too short */
	for(i = 0; i < 5; i++)
	{
		ret = d_tcp_sack_parse(&context, data, i, &sack);
		assert_true(ret == -1);
	}

	/* correct length */
	ret = d_tcp_sack_parse(&context, data, 5, &sack);
	assert_true(ret == 5);
	assert_true(sack.blocks_nr == 1);
	assert_true(sack.blocks[0].block_start == val);
	assert_true(sack.blocks[0].block_end == (val + 1));
}


void test_tcp_sack_opt_2_blocks(const uint32_t val)
{
	struct rohc_decomp decomp = { .trace_callback = NULL };
	struct rohc_decomp_profile profile = { .id = ROHC_PROFILE_TCP };
	struct rohc_decomp_ctxt context = { .decompressor = &decomp, .profile = &profile };
	struct d_tcp_opt_sack sack;
	const uint8_t data[] = {
		0x02,                    /* discriminator */
		lsb_15(val),             /* block 1 */
		lsb_15(val + 1),
		lsb_22(val + 2),         /* block 2 */
		lsb_22(val + 3),
	};
	size_t i;
	int ret;

	/* too short */
	for(i = 0; i < 11; i++)
	{
		ret = d_tcp_sack_parse(&context, data, i, &sack);
		assert_true(ret == -1);
	}

	/* correct length */
	ret = d_tcp_sack_parse(&context, data, 11, &sack);
	assert_true(ret == 11);
	assert_true(sack.blocks_nr == 2);
	assert_true(sack.blocks[0].block_start == (val & 0x7fff));
	assert_true(sack.blocks[0].block_end == ((val + 1) & 0x7fff));
	assert_true(sack.blocks[1].block_start == (val + 2));
	assert_true(sack.blocks[1].block_end == (val + 3));
}


void test_tcp_sack_opt_3_blocks(const uint32_t val)
{
	struct rohc_decomp decomp = { .trace_callback = NULL };
	struct rohc_decomp_profile profile = { .id = ROHC_PROFILE_TCP };
	struct rohc_decomp_ctxt context = { .decompressor = &decomp, .profile = &profile };
	struct d_tcp_opt_sack sack;
	const uint8_t data[] = {
		0x03,                    /* discriminator */
		lsb_15(val),             /* block 1 */
		lsb_15(val + 1),
		lsb_22(val + 2),         /* block 2 */
		lsb_22(val + 3),
		lsb_29(val + 4),         /* block 3 */
		lsb_29(val + 5),
	};
	size_t i;
	int ret;

	/* too short */
	for(i = 0; i < 19; i++)
	{
		ret = d_tcp_sack_parse(&context, data, i, &sack);
		assert_true(ret == -1);
	}

	/* correct length */
	ret = d_tcp_sack_parse(&context, data, 19, &sack);
	assert_true(ret == 19);
	assert_true(sack.blocks_nr == 3);
	assert_true(sack.blocks[0].block_start == (val & 0x7fff));
	assert_true(sack.blocks[0].block_end == ((val + 1) & 0x7fff));
	assert_true(sack.blocks[1].block_start == ((val + 2) & 0x3fffff));
	assert_true(sack.blocks[1].block_end == ((val + 3) & 0x3fffff));
	assert_true(sack.blocks[2].block_start == (val + 4));
	assert_true(sack.blocks[2].block_end == (val + 5));
}


void test_tcp_sack_opt_4_blocks(const uint32_t val)
{
	struct rohc_decomp decomp = { .trace_callback = NULL };
	struct rohc_decomp_profile profile = { .id = ROHC_PROFILE_TCP };
	struct rohc_decomp_ctxt context = { .decompressor = &decomp, .profile = &profile };
	struct d_tcp_opt_sack sack;
	const uint8_t data[] = {
		0x04,                    /* discriminator */
		lsb_15(val),             /* block 1 */
		lsb_15(val + 1),
		lsb_22(val + 2),         /* block 2 */
		lsb_22(val + 3),
		lsb_29(val + 4),         /* block 3 */
		lsb_29(val + 5),
		lsb_32(val + 6),         /* block 4 */
		lsb_32(val + 7),
	};
	size_t i;
	int ret;

	/* too short */
	for(i = 0; i < 29; i++)
	{
		ret = d_tcp_sack_parse(&context, data, i, &sack);
		assert_true(ret == -1);
	}

	/* correct length */
	ret = d_tcp_sack_parse(&context, data, 29, &sack);
	assert_true(ret == 29);
	assert_true(sack.blocks_nr == 4);
	assert_true(sack.blocks[0].block_start == (val & 0x7fff));
	assert_true(sack.blocks[0].block_end == ((val + 1) & 0x7fff));
	assert_true(sack.blocks[1].block_start == ((val + 2) & 0x3fffff));
	assert_true(sack.blocks[1].block_end == ((val + 3) & 0x3fffff));
	assert_true(sack.blocks[2].block_start == ((val + 4) & 0x1fffffff));
	assert_true(sack.blocks[2].block_end == ((val + 5) & 0x1fffffff));
	assert_true(sack.blocks[3].block_start == (val + 6));
	assert_true(sack.blocks[3].block_end == (val + 7));
}


void test_tcp_sack_opt_4_blocks_bad_sack(const uint32_t val)
{
	struct rohc_decomp decomp = { .trace_callback = NULL };
	struct rohc_decomp_profile profile = { .id = ROHC_PROFILE_TCP };
	struct rohc_decomp_ctxt context = { .decompressor = &decomp, .profile = &profile };
	struct d_tcp_opt_sack sack;
	const uint8_t data[] = {
		0x04,                    /* discriminator */
		lsb_15(val),             /* block 1 */
		lsb_15(val + 1),
		lsb_22(val + 2),         /* block 2 */
		lsb_22(val + 3),
		lsb_29(val + 4),         /* block 3 */
		lsb_29(val + 5),
		0xf0,                    /* malformed block 4 */
		0xff,
	};
	int ret;

	ret = d_tcp_sack_parse(&context, data, 21, &sack);
	assert_true(ret == -1);
}


void test_tcp_sack_opt_5_blocks(const uint32_t val)
{
	struct rohc_decomp decomp = { .trace_callback = NULL };
	struct rohc_decomp_profile profile = { .id = ROHC_PROFILE_TCP };
	struct rohc_decomp_ctxt context = { .decompressor = &decomp, .profile = &profile };
	struct d_tcp_opt_sack sack;
	const uint8_t data[] = {
		0x05,                    /* discriminator */
		lsb_15(val),             /* block 1 */
		lsb_15(val + 1),
		lsb_22(val + 2),         /* block 2 */
		lsb_22(val + 3),
		lsb_29(val + 4),         /* block 3 */
		lsb_29(val + 5),
		lsb_32(val + 6),         /* block 4 */
		lsb_32(val + 7),
		lsb_15(val + 8),             /* invalid block 5 */
		lsb_15(val + 9),
	};
	int ret;

	ret = d_tcp_sack_parse(&context, data, 33, &sack);
	assert_true(ret == -1);
}


void test_tcp_sack_opt_0_block(const uint32_t val)
{
	struct rohc_decomp decomp = { .trace_callback = NULL };
	struct rohc_decomp_profile profile = { .id = ROHC_PROFILE_TCP };
	struct rohc_decomp_ctxt context = { .decompressor = &decomp, .profile = &profile };
	struct d_tcp_opt_sack sack;
	const uint8_t previous_data[] = {
		0x01,                    /* discriminator */
		lsb_15(val),             /* block 1 */
		lsb_15(val + 1),
	};
	const uint8_t data[] = {
		0x00,                    /* discriminator */
	};
	int ret;

	/* decode previous data */
	ret = d_tcp_sack_parse(&context, previous_data, 5, &sack);
	assert_true(ret == 5);
	assert_true(sack.blocks_nr == 1);
	assert_true(sack.blocks[0].block_start == val);
	assert_true(sack.blocks[0].block_end == (val + 1));

	/* decode new unchanged data (too short) */
	ret = d_tcp_sack_parse(&context, data, 0, &sack);
	assert_true(ret == -1);

	/* decode new unchanged data (correct length) */
	ret = d_tcp_sack_parse(&context, data, 1, &sack);
	assert_true(ret == 1);
	assert_true(sack.blocks_nr == 0);
}


/** Test \ref test_tcp_sack_opt */
static void test_tcp_sack_opt(void **state)
{
	/* 1-block */
	printf("test 1-block SACK...\n");
	test_tcp_sack_opt_1_block(0);
	test_tcp_sack_opt_1_block(0x7fff - 1);

	/* 2-block */
	printf("test 2-block SACK...\n");
	test_tcp_sack_opt_2_blocks(0);
	test_tcp_sack_opt_2_blocks(0x3fffff - 3);

	/* 3-block */
	printf("test 3-block SACK...\n");
	test_tcp_sack_opt_3_blocks(0);
	test_tcp_sack_opt_3_blocks(0x1fffffff - 5);

	/* 4-block */
	printf("test 4-block SACK...\n");
	test_tcp_sack_opt_4_blocks(0);
	test_tcp_sack_opt_4_blocks(0xffffffff - 7);

	/* 4-block with malformed SACK */
	printf("test 4-block with malformed SACK...\n");
	test_tcp_sack_opt_4_blocks_bad_sack(0);
	test_tcp_sack_opt_4_blocks_bad_sack(0xffffffff - 7);

	/* malformed 5-block */
	printf("test malformed 5-block SACK...\n");
	test_tcp_sack_opt_5_blocks(0);
	test_tcp_sack_opt_5_blocks(0xffffffff - 9);

	/* unchanged 0-block (for irregular chain only) */
	printf("test unchanged 0-block SACK...\n");
	test_tcp_sack_opt_0_block(0);
	test_tcp_sack_opt_0_block(0x7fff - 1);
}


/**
 * @brief Test TCP SACK option decoding
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
#if defined(HAVE_CMOCKA_RUN_GROUP_TESTS) && HAVE_CMOCKA_RUN_GROUP_TESTS == 1
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_tcp_sack_opt),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
#elif defined(HAVE_CMOCKA_RUN_TESTS) && HAVE_CMOCKA_RUN_TESTS == 1
	const UnitTest tests[] = {
		unit_test(test_tcp_sack_opt),
	};
	return run_tests(tests);
#else
#  error "no function found to run cmocka tests"
#endif
}

