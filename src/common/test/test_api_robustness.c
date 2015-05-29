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
 * @file    test_api_robustness.c
 * @brief   Test the robustness of the common API
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "rohc.h"
#include "rohc_packets.h"

#include "config.h" /* for VERSION and PACKAGE_REVNO */

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
 * @brief Test the robustness of the common API
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
		printf("test the robustness of the common API\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* rohc_version() */
	CHECK(strcmp(rohc_version(), "") != 0);
	CHECK(strcmp(rohc_version(), VERSION PACKAGE_REVNO) == 0);

	/* rohc_strerror() */
	{
		const char unknown[] = "no description";

		CHECK(strcmp(rohc_strerror(ROHC_STATUS_OK), "") != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_OK), unknown) != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_SEGMENT), "") != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_SEGMENT), unknown) != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_MALFORMED), "") != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_MALFORMED), unknown) != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_NO_CONTEXT), "") != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_NO_CONTEXT), unknown) != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_BAD_CRC), "") != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_BAD_CRC), unknown) != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_OUTPUT_TOO_SMALL), "") != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_OUTPUT_TOO_SMALL), unknown) != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_ERROR), "") != 0);
		CHECK(strcmp(rohc_strerror(ROHC_STATUS_ERROR), unknown) != 0);

		CHECK(strcmp(rohc_strerror(ROHC_STATUS_ERROR + 1), unknown) == 0);
	}

	/* rohc_get_mode_descr() */
	{
		const char unknown[] = "no description";

		CHECK(strcmp(rohc_get_mode_descr(ROHC_U_MODE), "") != 0);
		CHECK(strcmp(rohc_get_mode_descr(ROHC_U_MODE), unknown) != 0);
		CHECK(strcmp(rohc_get_mode_descr(ROHC_O_MODE), "") != 0);
		CHECK(strcmp(rohc_get_mode_descr(ROHC_O_MODE), unknown) != 0);
		CHECK(strcmp(rohc_get_mode_descr(ROHC_R_MODE), "") != 0);
		CHECK(strcmp(rohc_get_mode_descr(ROHC_R_MODE), unknown) != 0);
		CHECK(strcmp(rohc_get_mode_descr(ROHC_R_MODE + 1), unknown) == 0);
	}

	/* rohc_get_profile_descr() */
	{
		const char unknown[] = "no description";

		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UNCOMPRESSED), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UNCOMPRESSED), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_RTP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_RTP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UDP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UDP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_ESP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_ESP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_IP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_IP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_TCP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_TCP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UDPLITE), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UDPLITE), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UDPLITE + 1), unknown) == 0);
	}

	/* rohc_get_packet_descr() */
	{
		const char unknown[] = "unknown ROHC packet";

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_IR), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_IR), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_IR_DYN), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_IR_DYN), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UO_0), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UO_0), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UO_1), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UO_1), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UO_1_ID), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UO_1_ID), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UO_1_TS), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UO_1_TS), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UO_1_RTP), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UO_1_RTP), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UOR_2), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UOR_2), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UOR_2_RTP), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UOR_2_RTP), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UOR_2_ID), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UOR_2_ID), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UOR_2_TS), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UOR_2_TS), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_NORMAL), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_NORMAL), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_CO_COMMON), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_CO_COMMON), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_1), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_1), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_2), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_2), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_3), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_3), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_4), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_4), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_5), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_5), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_6), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_6), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_7), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_7), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_8), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_RND_8), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_1), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_1), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_2), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_2), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_3), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_3), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_4), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_4), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_5), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_5), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_6), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_6), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_7), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_7), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_8), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_8), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_TCP_SEQ_8 + 1), unknown) == 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_UNKNOWN), unknown) == 0);
	}

	/* rohc_get_ext_descr() */
	{
		const char unknown[] = "unknown ROHC extension";

		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_0), "") != 0);
		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_0), unknown) != 0);
		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_1), "") != 0);
		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_1), unknown) != 0);
		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_2), "") != 0);
		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_2), unknown) != 0);
		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_3), "") != 0);
		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_3), unknown) != 0);
		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_NONE), "") != 0);
		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_NONE), unknown) != 0);

		CHECK(strcmp(rohc_get_ext_descr(ROHC_EXT_NONE + 1), unknown) == 0);
	}

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}

