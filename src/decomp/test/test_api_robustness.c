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
 * @file    test_api_robustness.c
 * @brief   Test the robustness of the decompression API
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_decomp.h"

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
 * @brief Test the robustness of the decompression API
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
	struct rohc_comp *comp; /* used for some tests */
	struct rohc_decomp *decomp;
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
		printf("test the robustness of the decompression API\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* rohc_decomp_new() */
	CHECK(rohc_decomp_new(-1, ROHC_SMALL_CID_MAX, ROHC_U_MODE, NULL) == NULL);
	CHECK(rohc_decomp_new(ROHC_SMALL_CID + 1, ROHC_SMALL_CID_MAX, ROHC_U_MODE, NULL) == NULL);
	decomp = rohc_decomp_new(ROHC_SMALL_CID, 0, ROHC_U_MODE, NULL);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	decomp = rohc_decomp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_U_MODE, NULL);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	CHECK(rohc_decomp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX + 1, ROHC_U_MODE, NULL) == NULL);
	decomp = rohc_decomp_new(ROHC_LARGE_CID, 0, ROHC_U_MODE, NULL);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	decomp = rohc_decomp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_U_MODE, NULL);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	CHECK(rohc_decomp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX + 1, ROHC_U_MODE, NULL) == NULL);
	decomp = rohc_decomp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_U_MODE, NULL);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);

	decomp = rohc_decomp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_U_MODE, NULL);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	comp = rohc_comp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX);
	CHECK(comp != NULL);
	decomp = rohc_decomp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_U_MODE, comp);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	CHECK(rohc_decomp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_O_MODE, NULL) == NULL);
	decomp = rohc_decomp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_O_MODE, comp);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	CHECK(rohc_decomp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_R_MODE, NULL) == NULL);
	CHECK(rohc_decomp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_R_MODE, comp) == NULL);

	decomp = rohc_decomp_new(ROHC_LARGE_CID, ROHC_SMALL_CID_MAX, ROHC_O_MODE, comp);
	CHECK(decomp != NULL);

	/* rohc_decomp_set_traces_cb() */
	{
		rohc_trace_callback_t fct = (rohc_trace_callback_t) NULL;
		CHECK(rohc_decomp_set_traces_cb(NULL, fct) == false);
		CHECK(rohc_decomp_set_traces_cb(decomp, fct) == true);
	}

	/* rohc_decomp_enable_profile() */
	CHECK(rohc_decomp_enable_profile(NULL, ROHC_PROFILE_IP) == false);
	CHECK(rohc_decomp_enable_profile(decomp, ROHC_PROFILE_GENERAL) == false);
	CHECK(rohc_decomp_enable_profile(decomp, ROHC_PROFILE_IP) == true);

	/* rohc_decomp_disable_profile() */
	CHECK(rohc_decomp_disable_profile(NULL, ROHC_PROFILE_IP) == false);
	CHECK(rohc_decomp_disable_profile(decomp, ROHC_PROFILE_GENERAL) == false);
	CHECK(rohc_decomp_disable_profile(decomp, ROHC_PROFILE_IP) == true);

	/* rohc_decomp_enable_profiles() */
	CHECK(rohc_decomp_enable_profiles(NULL, ROHC_PROFILE_IP, -1) == false);
	CHECK(rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_GENERAL, -1) == false);
	CHECK(rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_IP, -1) == true);
	CHECK(rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_IP, ROHC_PROFILE_UDP,
	                                  ROHC_PROFILE_RTP, -1) == true);

	/* rohc_decomp_disable_profiles() */
	CHECK(rohc_decomp_disable_profiles(NULL, ROHC_PROFILE_IP, -1) == false);
	CHECK(rohc_decomp_disable_profiles(decomp, ROHC_PROFILE_GENERAL, -1) == false);
	CHECK(rohc_decomp_disable_profiles(decomp, ROHC_PROFILE_UDP, -1) == true);
	CHECK(rohc_decomp_disable_profiles(decomp, ROHC_PROFILE_UDP,
	                                   ROHC_PROFILE_RTP, -1) == true);


	/* rohc_decomp_set_mrru() */
	CHECK(rohc_decomp_set_mrru(NULL, 10) == false);
	CHECK(rohc_decomp_set_mrru(decomp, 65535 + 1) == false);
	CHECK(rohc_decomp_set_mrru(decomp, 0) == true);
	CHECK(rohc_decomp_set_mrru(decomp, 65535) == true);

	/* rohc_decomp_get_mrru() */
	{
		size_t mrru;
		CHECK(rohc_decomp_get_mrru(NULL, &mrru) == false);
		CHECK(rohc_decomp_get_mrru(decomp, NULL) == false);
		CHECK(rohc_decomp_get_mrru(decomp, &mrru) == true);
		CHECK(mrru == 65535);
	}

	/* rohc_decomp_get_max_cid() */
	{
		size_t max_cid;
		CHECK(rohc_decomp_get_max_cid(NULL, &max_cid) == false);
		CHECK(rohc_decomp_get_max_cid(decomp, NULL) == false);
		CHECK(rohc_decomp_get_max_cid(decomp, &max_cid) == true);
		CHECK(max_cid == ROHC_SMALL_CID_MAX);
	}

	/* rohc_decomp_get_cid_type() */
	{
		rohc_cid_type_t cid_type;
		CHECK(rohc_decomp_get_cid_type(NULL, &cid_type) == false);
		CHECK(rohc_decomp_get_cid_type(decomp, NULL) == false);
		CHECK(rohc_decomp_get_cid_type(decomp, &cid_type) == true);
		CHECK(cid_type == ROHC_LARGE_CID);
	}

	/* rohc_decompress2() */
	{
		const struct timespec time = { .tv_sec = 0, .tv_nsec = 0 };
		unsigned char buf1[1];
		unsigned char buf2[100];
		unsigned char buf[] =
		{
			0xfd, 0x00, 0x04, 0xce,  0x40, 0x01, 0xc0, 0xa8,
			0x13, 0x01, 0xc0, 0xa8,  0x13, 0x05, 0x00, 0x40,
			0x00, 0x00, 0xa0, 0x00,  0x00, 0x01, 0x08, 0x00,
			0xe9, 0xc2, 0x9b, 0x42,  0x00, 0x01, 0x66, 0x15,
			0xa6, 0x45, 0x77, 0x9b,  0x04, 0x00, 0x08, 0x09,
			0x0a, 0x0b, 0x0c, 0x0d,  0x0e, 0x0f, 0x10, 0x11,
			0x12, 0x13, 0x14, 0x15,  0x16, 0x17, 0x18, 0x19,
			0x1a, 0x1b, 0x1c, 0x1d,  0x1e, 0x1f, 0x20, 0x21,
			0x22, 0x23, 0x24, 0x25,  0x26, 0x27, 0x28, 0x29,
			0x2a, 0x2b, 0x2c, 0x2d,  0x2e, 0x2f, 0x30, 0x31,
			0x32, 0x33, 0x34, 0x35,  0x36, 0x37
		};
		size_t len;
		CHECK(rohc_decompress2(NULL, time, buf1, 1, buf2, 1, &len) == ROHC_ERROR);
		CHECK(rohc_decompress2(decomp, time, NULL, 1, buf2, 1, &len) == ROHC_ERROR);
		CHECK(rohc_decompress2(decomp, time, buf1, 0, buf2, 1, &len) == ROHC_ERROR);
		CHECK(rohc_decompress2(decomp, time, buf1, 1, NULL, 1, &len) == ROHC_ERROR);
		CHECK(rohc_decompress2(decomp, time, buf1, 1, buf2, 0, &len) == ROHC_ERROR);
		CHECK(rohc_decompress2(decomp, time, buf1, 1, buf2, 1, NULL) == ROHC_ERROR);
		CHECK(rohc_decompress2(decomp, time, buf, sizeof(buf), buf2, sizeof(buf2), &len) == ROHC_OK);
	}

	/* rohc_decomp_get_last_packet_info() */
	{
		rohc_decomp_last_packet_info_t info;
		memset(&info, 0, sizeof(rohc_decomp_last_packet_info_t));
		CHECK(rohc_decomp_get_last_packet_info(NULL, &info) == false);
		CHECK(rohc_decomp_get_last_packet_info(decomp, NULL) == false);
		info.version_major = 0xffff;
		CHECK(rohc_decomp_get_last_packet_info(decomp, &info) == false);
		info.version_major = 0;
		info.version_minor = 0xffff;
		CHECK(rohc_decomp_get_last_packet_info(decomp, &info) == false);
		info.version_minor = 0;
		CHECK(rohc_decomp_get_last_packet_info(decomp, &info) == true);
	}

	/* rohc_decomp_get_state_descr() */
	CHECK(strcmp(rohc_decomp_get_state_descr(NO_CONTEXT), "No Context") == 0);
	CHECK(strcmp(rohc_decomp_get_state_descr(STATIC_CONTEXT), "Static Context") == 0);
	CHECK(strcmp(rohc_decomp_get_state_descr(FULL_CONTEXT), "Full Context") == 0);
	CHECK(strcmp(rohc_decomp_get_state_descr(0xffff), "no description") == 0);

	/* rohc_decomp_free() */
	rohc_decomp_free(NULL);
	rohc_decomp_free(decomp);

	/* free compressor used for tests */
	rohc_comp_free(comp);

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}

