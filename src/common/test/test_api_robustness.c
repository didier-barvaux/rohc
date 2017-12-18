/*
 * Copyright 2015,2016 Didier Barvaux
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
#include "rohc_internal.h"
#include <rohc/rohc_buf.h>
#include "rohc_packets.h"
#include "protocols/ip_numbers.h"
#include "protocols/tcp.h"
#include "protocols/rfc6846.h"

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

		CHECK(strcmp(rohc_get_mode_descr(ROHC_UNKNOWN_MODE), unknown) == 0);
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
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_RTP_LLA), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_RTP_LLA), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_TCP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_TCP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UDPLITE_RTP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UDPLITE_RTP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UDPLITE), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHC_PROFILE_UDPLITE), unknown) != 0);

		/* test ROHCv1 profiles */
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_UNCOMPRESSED), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_UNCOMPRESSED), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_UDP_RTP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_UDP_RTP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_UDP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_UDP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_ESP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_ESP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_UDP_RTP_LLA), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_UDP_RTP_LLA), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_TCP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_TCP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_UDPLITE_RTP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_UDPLITE_RTP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_UDPLITE), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv1_PROFILE_IP_UDPLITE), unknown) != 0);

		/* test ROHCv2 profiles */
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_UDP_RTP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_UDP_RTP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_UDP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_UDP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_ESP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_ESP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_UDPLITE_RTP), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_UDPLITE_RTP), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_UDPLITE), "") != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_UDPLITE), unknown) != 0);
		CHECK(strcmp(rohc_get_profile_descr(ROHCv2_PROFILE_IP_UDPLITE + 1), unknown) == 0);
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

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_IR_CR), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_IR_CR), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_CO_COMMON), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_CO_COMMON), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_CO_REPAIR), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_CO_REPAIR), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_PT_0_CRC3), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_PT_0_CRC3), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_NORTP_PT_0_CRC7), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_NORTP_PT_0_CRC7), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_NORTP_PT_1_SEQ_ID), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_NORTP_PT_1_SEQ_ID), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_NORTP_PT_2_SEQ_ID), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_NORTP_PT_2_SEQ_ID), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_0_CRC7), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_0_CRC7), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_1_RND), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_1_RND), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_1_SEQ_ID), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_1_SEQ_ID), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_1_SEQ_TS), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_1_SEQ_TS), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_2_RND), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_2_RND), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_2_SEQ_ID), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_2_SEQ_ID), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_2_SEQ_TS), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_2_SEQ_TS), unknown) != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_2_SEQ_BOTH), "") != 0);
		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_RTP_PT_2_SEQ_BOTH), unknown) != 0);

		CHECK(strcmp(rohc_get_packet_descr(ROHC_PACKET_MAX), unknown) == 0);
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

	/* rohc_get_packet_type() */
	{
		const char *const packet_type_names[ROHC_PACKET_MAX] = {
			"ir", "irdyn",
			"uo0", "uo1",
			"uo1id", "uo1ts", "uo1rtp",
			"uor2", "uor2rtp", "uor2id", "uor2ts",
			"xxx", "xxx",
			"uncomp-normal",
			"unknown",
			"tcp-co-common",
			"tcp-rnd-1", "tcp-rnd-2", "tcp-rnd-3", "tcp-rnd-4",
			"tcp-rnd-5", "tcp-rnd-6", "tcp-rnd-7", "tcp-rnd-8",
			"tcp-seq-1", "tcp-seq-2", "tcp-seq-3", "tcp-seq-4",
			"tcp-seq-5", "tcp-seq-6", "tcp-seq-7", "tcp-seq-8",
			"ir-cr",
			"co-repair", "pt-0-crc3",
			"nortp-pt-0-crc7", "nortp-pt-1-seq-id", "nortp-pt-2-seq-id",
			"rtp-pt-0-crc7",
			"rtp-pt-1-rnd", "rtp-pt-1-seq-id", "rtp-pt-1-seq-ts",
			"rtp-pt-2-rnd", "rtp-pt-2-seq-id", "rtp-pt-2-seq-ts", "rtp-pt-2-seq-both",
		};
		rohc_packet_t packet_type;

		for(packet_type = ROHC_PACKET_IR;
		    packet_type < ROHC_PACKET_MAX;
		    packet_type++)
		{
			if(packet_type != 11 && packet_type != 12)
			{
				CHECK(rohc_get_packet_type(packet_type_names[packet_type]) == packet_type);
			}
		}
	}

	/* not a public API, but best place to test: rohc_get_ip_proto_descr() */
	{
		const char unknown[] = "unknown IP protocol";

		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_HOPOPTS), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_HOPOPTS), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_IPIP), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_IPIP), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_TCP), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_TCP), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_UDP), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_UDP), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_IPV6), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_IPV6), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_ROUTING), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_ROUTING), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_FRAGMENT), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_FRAGMENT), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_GRE), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_GRE), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_ESP), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_ESP), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_AH), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_AH), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_MINE), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_MINE), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_DSTOPTS), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_DSTOPTS), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_MOBILITY), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_MOBILITY), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_UDPLITE), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_UDPLITE), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_HIP), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_HIP), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_SHIM), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_SHIM), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_RESERVED1), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_RESERVED1), unknown) != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_RESERVED2), "") != 0);
		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_RESERVED2), unknown) != 0);

		CHECK(strcmp(rohc_get_ip_proto_descr(ROHC_IPPROTO_MAX), unknown) == 0);
	}

	/* not a public API, but best place to test: rohc_ip_id_behavior_get_descr() */
	{
		const char unknown[] = "unknown IP-ID behavior";

		CHECK(strcmp(rohc_ip_id_behavior_get_descr(ROHC_IP_ID_BEHAVIOR_SEQ), "") != 0);
		CHECK(strcmp(rohc_ip_id_behavior_get_descr(ROHC_IP_ID_BEHAVIOR_SEQ), unknown) != 0);
		CHECK(strcmp(rohc_ip_id_behavior_get_descr(ROHC_IP_ID_BEHAVIOR_SEQ_SWAP), "") != 0);
		CHECK(strcmp(rohc_ip_id_behavior_get_descr(ROHC_IP_ID_BEHAVIOR_SEQ_SWAP), unknown) != 0);
		CHECK(strcmp(rohc_ip_id_behavior_get_descr(ROHC_IP_ID_BEHAVIOR_RAND), "") != 0);
		CHECK(strcmp(rohc_ip_id_behavior_get_descr(ROHC_IP_ID_BEHAVIOR_RAND), unknown) != 0);
		CHECK(strcmp(rohc_ip_id_behavior_get_descr(ROHC_IP_ID_BEHAVIOR_ZERO), "") != 0);
		CHECK(strcmp(rohc_ip_id_behavior_get_descr(ROHC_IP_ID_BEHAVIOR_ZERO), unknown) != 0);

		CHECK(strcmp(rohc_ip_id_behavior_get_descr(ROHC_IP_ID_BEHAVIOR_ZERO + 1), unknown) == 0);
	}

	/* not a public API, but best place to test: tcp_opt_get_descr() */
	{
		CHECK(strcmp(tcp_opt_get_descr(TCP_OPT_EOL), "EOL") == 0);
		CHECK(strcmp(tcp_opt_get_descr(TCP_OPT_NOP), "NOP") == 0);
		CHECK(strcmp(tcp_opt_get_descr(TCP_OPT_MSS), "MSS") == 0);
		CHECK(strcmp(tcp_opt_get_descr(TCP_OPT_WS), "Window Scale") == 0);
		CHECK(strcmp(tcp_opt_get_descr(TCP_OPT_SACK_PERM), "SACK permitted") == 0);
		CHECK(strcmp(tcp_opt_get_descr(TCP_OPT_SACK), "SACK") == 0);
		CHECK(strcmp(tcp_opt_get_descr(TCP_OPT_TS), "Timestamp") == 0);
		CHECK(strcmp(tcp_opt_get_descr(TCP_OPT_MAX), "generic") == 0);
	}

	/* rohc_buf_*() */
	{
		const struct rohc_ts time2 = { .sec = 1, .nsec = 2 };
		const size_t buf1_max_len = 300;
		uint8_t buf1[buf1_max_len];
		const size_t buf2_max_len = 300;
		const size_t buf2_len = 100;
		uint8_t buf2[buf2_max_len];

		memset(buf1, 0, buf1_max_len);
		memset(buf2, 0, buf2_max_len);

		/* rohc_buf_init_empty() */
		struct rohc_buf rbuf1 = rohc_buf_init_empty(buf1, buf1_max_len);
		CHECK(rbuf1.time.sec == 0);
		CHECK(rbuf1.time.nsec == 0);
		CHECK(rbuf1.data == buf1);
		CHECK(rbuf1.max_len == buf1_max_len);
		CHECK(rbuf1.offset == 0);
		CHECK(rbuf1.len == 0);

		/* rohc_buf_init_full() */
		memset(buf2, 2, buf2_len);
		struct rohc_buf rbuf2 = rohc_buf_init_full(buf2, buf2_max_len, time2);
		CHECK(rbuf2.time.sec == 1);
		CHECK(rbuf2.time.nsec == 2);
		CHECK(rbuf2.data == buf2);
		CHECK(rbuf2.max_len == buf2_max_len);
		CHECK(rbuf2.offset == 0);
		CHECK(rbuf2.len == buf2_max_len);
		rbuf2.len = buf2_len;
		CHECK(rbuf2.len == buf2_len);

		/* rohc_buf_byte_at() */
		CHECK(rohc_buf_byte_at(rbuf1, 0) == 0);
		CHECK(rohc_buf_byte_at(rbuf1, rbuf1.max_len - 1) == 0);
		CHECK(rohc_buf_byte_at(rbuf2, 0) == 2);
		CHECK(rohc_buf_byte_at(rbuf2, rbuf2.len - 1) == 2);
		CHECK(rohc_buf_byte_at(rbuf2, rbuf2.len) == 0);
		CHECK(rohc_buf_byte_at(rbuf2, rbuf2.max_len - 1) == 0);

		/* rohc_buf_byte() */
		CHECK(rohc_buf_byte(rbuf1) == rohc_buf_byte_at(rbuf1, 0));
		CHECK(rohc_buf_byte(rbuf2) == rohc_buf_byte_at(rbuf2, 0));

		/* rohc_buf_data_at() */
		CHECK(rohc_buf_data_at(rbuf1, 0) == buf1);
		CHECK(rohc_buf_data_at(rbuf1, rbuf1.max_len - 1) == (buf1 + buf1_max_len - 1));
		CHECK(rohc_buf_data_at(rbuf2, 0) == buf2);
		CHECK(rohc_buf_data_at(rbuf2, rbuf2.len - 1) == (buf2 + buf2_len - 1));
		CHECK(rohc_buf_data_at(rbuf2, rbuf2.len) == (buf2 + buf2_len));
		CHECK(rohc_buf_data_at(rbuf2, rbuf2.max_len - 1) == (buf2 + buf1_max_len - 1));

		/* rohc_buf_data() */
		CHECK(rohc_buf_data(rbuf1) == rohc_buf_data_at(rbuf1, 0));
		CHECK(rohc_buf_data(rbuf2) == rohc_buf_data_at(rbuf2, 0));

		/* rohc_buf_is_malformed() */
		CHECK(rohc_buf_is_malformed(rbuf1) == false);
		rbuf1.len = rbuf1.max_len + 1;
		CHECK(rohc_buf_is_malformed(rbuf1) == true);
		rbuf1.len = 0;
		CHECK(rohc_buf_is_malformed(rbuf1) == false);
		CHECK(rohc_buf_is_malformed(rbuf2) == false);
		{
			const size_t buf3_max_len = 3;
			uint8_t buf3[buf3_max_len];
			struct rohc_buf rbuf3 = rohc_buf_init_full(buf3, buf3_max_len, time2);
			CHECK(rohc_buf_is_malformed(rbuf3) == false);
			rbuf3.data = NULL;
			CHECK(rohc_buf_is_malformed(rbuf3) == true);
			rbuf3.data = buf3;
			CHECK(rohc_buf_is_malformed(rbuf3) == false);
			rbuf3.max_len = 0;
			CHECK(rohc_buf_is_malformed(rbuf3) == true);
			rbuf3.max_len = buf3_max_len;
			CHECK(rohc_buf_is_malformed(rbuf3) == false);
			rbuf3.offset = 2;
			rbuf3.len = 2;
			CHECK(rohc_buf_is_malformed(rbuf3) == true);
			rbuf3.offset = 2;
			rbuf3.len = 1;
			CHECK(rohc_buf_is_malformed(rbuf3) == false);
			rbuf3.data = NULL;
			rbuf3.max_len = 0;
			rbuf3.offset = 2;
			rbuf3.len = 2;
			CHECK(rohc_buf_is_malformed(rbuf3) == true);
		}

		/* rohc_buf_is_empty() */
		CHECK(rohc_buf_is_empty(rbuf1) == true);
		CHECK(rohc_buf_is_empty(rbuf2) == false);

		/* rohc_buf_pull() / rohc_buf_push() / rohc_buf_avail_len() */
		rohc_buf_pull(&rbuf2, 1);
		CHECK(rbuf2.len == (buf2_len - 1));
		CHECK(rohc_buf_avail_len(rbuf2) == (buf2_max_len - 1));
		CHECK(rohc_buf_data(rbuf2) == (buf2 + 1));
		rohc_buf_pull(&rbuf2, buf2_len - 1);
		CHECK(rbuf2.len == 0);
		CHECK(rohc_buf_avail_len(rbuf2) == (buf2_max_len - buf2_len));
		CHECK(rohc_buf_data(rbuf2) == (buf2 + buf2_len));
		rohc_buf_push(&rbuf2, buf2_len);
		CHECK(rbuf2.len == buf2_len);
		CHECK(rohc_buf_avail_len(rbuf2) == buf2_max_len);
		CHECK(rohc_buf_data(rbuf2) == buf2);

		/* rohc_buf_prepend() */
		const uint8_t data[] = { 1, 2, 3, 4, 5 };
		const size_t data_len = sizeof(data) / sizeof(uint8_t);
		rohc_buf_pull(&rbuf2, data_len);
		CHECK(rbuf2.len == (buf2_len - data_len));
		rohc_buf_prepend(&rbuf2, data, data_len);
		CHECK(rbuf2.len == buf2_len);
		CHECK(memcmp(rohc_buf_data(rbuf2), data, data_len) == 0);
		CHECK(rohc_buf_byte_at(rbuf2, data_len) == 2);

		/* rohc_buf_append() */
		rohc_buf_append(&rbuf2, data, data_len);
		CHECK(rbuf2.len == (buf2_len + data_len));
		CHECK(memcmp(rohc_buf_data(rbuf2), data, data_len) == 0);
		CHECK(rohc_buf_byte_at(rbuf2, data_len) == 2);
		CHECK(rohc_buf_byte_at(rbuf2, buf2_len - 1) == 2);
		CHECK(memcmp(rohc_buf_data_at(rbuf2, buf2_len), data, data_len) == 0);

		/* rohc_buf_append_buf() */
		const struct rohc_buf rdata = rohc_buf_init_full((uint8_t *) data, data_len, time2);
		rohc_buf_append_buf(&rbuf2, rdata);
		CHECK(rbuf2.len == (buf2_len + data_len * 2));
		CHECK(memcmp(rohc_buf_data(rbuf2), data, data_len) == 0);
		CHECK(rohc_buf_byte_at(rbuf2, data_len) == 2);
		CHECK(rohc_buf_byte_at(rbuf2, buf2_len - 1) == 2);
		CHECK(memcmp(rohc_buf_data_at(rbuf2, buf2_len), data, data_len) == 0);
		CHECK(memcmp(rohc_buf_data_at(rbuf2, buf2_len + data_len), data, data_len) == 0);

		/* rohc_buf_reset() */
		rohc_buf_reset(&rbuf1);
		CHECK(rohc_buf_is_empty(rbuf1) == true);
		rohc_buf_reset(&rbuf2);
		CHECK(rohc_buf_is_empty(rbuf2) == true);
	}

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}

