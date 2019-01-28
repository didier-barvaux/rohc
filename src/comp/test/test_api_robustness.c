/*
 * Copyright 2013,2014 Didier Barvaux
 * Copyright 2013 Friedrich
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
 * @brief   Test the robustness of the compression API
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_comp.h"

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


static int random_cb(const struct rohc_comp *const comp,
                     void *const user_context)
	__attribute__((warn_unused_result));


/**
 * @brief Test the robustness of the compression API
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
	struct rohc_comp *comp;
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
		printf("test the robustness of the compression API\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* rohc_comp_new2() */
	CHECK(rohc_comp_new2(-1, ROHC_SMALL_CID_MAX, random_cb, NULL) == NULL);
	CHECK(rohc_comp_new2(ROHC_SMALL_CID + 1, ROHC_SMALL_CID_MAX,
	                     random_cb, NULL) == NULL);
	comp = rohc_comp_new2(ROHC_SMALL_CID, 0, random_cb, NULL);
	CHECK(comp != NULL);
	rohc_comp_free(comp);
	comp = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                      random_cb, NULL);
	CHECK(comp != NULL);
	rohc_comp_free(comp);
	CHECK(rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX + 1,
	                     random_cb, NULL) == NULL);
	comp = rohc_comp_new2(ROHC_LARGE_CID, 0, random_cb, NULL);
	CHECK(comp != NULL);
	rohc_comp_free(comp);
	comp = rohc_comp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX,
	                      random_cb, NULL);
	CHECK(comp != NULL);
	rohc_comp_free(comp);
	CHECK(rohc_comp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX + 1,
	                     random_cb, NULL) == NULL);
	CHECK(rohc_comp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX,
	                     NULL, NULL) == NULL);
	comp = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                      random_cb, NULL);
	CHECK(comp != NULL);

	/* rohc_comp_set_traces_cb2() */
	{
		rohc_trace_callback2_t fct = (rohc_trace_callback2_t) NULL;
		CHECK(rohc_comp_set_traces_cb2(NULL, fct, NULL) == false);
		CHECK(rohc_comp_set_traces_cb2(comp, fct, NULL) == true);
		CHECK(rohc_comp_set_traces_cb2(comp, fct, comp) == true);
	}

	/* rohc_comp_profile_enabled() */
	CHECK(rohc_comp_profile_enabled(NULL, ROHC_PROFILE_IP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_GENERAL) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_UNCOMPRESSED) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_RTP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_UDP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_ESP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_IP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_TCP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_UDPLITE) == false);

	/* ROHCv2 rohc_comp_profile_enabled() */
	CHECK(rohc_comp_profile_enabled(comp, ROHCv2_PROFILE_IP_UDP_RTP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHCv2_PROFILE_IP_UDP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHCv2_PROFILE_IP_ESP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHCv2_PROFILE_IP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHCv2_PROFILE_IP_UDPLITE_RTP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHCv2_PROFILE_IP_UDPLITE) == false);

	/* rohc_comp_enable_profile() */
	CHECK(rohc_comp_enable_profile(NULL, ROHC_PROFILE_IP) == false);
	CHECK(rohc_comp_enable_profile(comp, ROHC_PROFILE_GENERAL) == false);
	CHECK(rohc_comp_enable_profile(comp, ROHC_PROFILE_IP) == true);

	/* ROHCv2 rohc_comp_enable_profile() */
	/* ROHCv1_PROFILE_IP already enabled so ROHCv2_PROFILE_IP can't be activated */
	CHECK(rohc_comp_enable_profile(comp, ROHCv2_PROFILE_IP) == false);
	CHECK(rohc_comp_enable_profile(comp, ROHCv2_PROFILE_IP_UDP) == true);
	/* ROHCv2_PROFILE_IP_UDP enabled so ROHC_PROFILE_UDP can't be enabled */
	CHECK(rohc_comp_enable_profile(comp, ROHC_PROFILE_UDP) == false);
	CHECK(rohc_comp_enable_profile(comp, ROHCv2_PROFILE_IP_ESP) == true);
#if 0
	CHECK(rohc_comp_enable_profile(comp, ROHCv2_PROFILE_IP_UDPLITE_RTP) == true);
	CHECK(rohc_comp_enable_profile(comp, ROHCv2_PROFILE_IP_UDPLITE) == true);
	CHECK(rohc_comp_enable_profile(comp, ROHCv2_PROFILE_IP_UDP_RTP) == true);
#endif

	/* rohc_comp_disable_profile() */
	CHECK(rohc_comp_disable_profile(NULL, ROHC_PROFILE_IP) == false);
	CHECK(rohc_comp_disable_profile(comp, ROHC_PROFILE_GENERAL) == false);
	CHECK(rohc_comp_disable_profile(comp, ROHC_PROFILE_IP) == true);

	/* ROHCv2 rohc_comp_disable_profile() */
	CHECK(rohc_comp_disable_profile(comp, ROHCv2_PROFILE_IP) == true);
	CHECK(rohc_comp_disable_profile(comp, ROHCv2_PROFILE_IP_UDP) == true);
	CHECK(rohc_comp_disable_profile(comp, ROHCv2_PROFILE_IP_ESP) == true);
#if 0
	CHECK(rohc_comp_disable_profile(comp, ROHCv2_PROFILE_IP_UDPLITE_RTP) == true);
	CHECK(rohc_comp_disable_profile(comp, ROHCv2_PROFILE_IP_UDPLITE) == true);
	CHECK(rohc_comp_disable_profile(comp, ROHCv2_PROFILE_IP_UDP_RTP) == true);
#endif

	/* rohc_comp_enable_profiles() */
	CHECK(rohc_comp_enable_profiles(NULL, ROHC_PROFILE_IP, -1) == false);
	CHECK(rohc_comp_enable_profiles(comp, ROHC_PROFILE_GENERAL, -1) == false);
	CHECK(rohc_comp_enable_profiles(comp, ROHC_PROFILE_IP, -1) == true);
	CHECK(rohc_comp_enable_profiles(comp, ROHC_PROFILE_IP,
	                                ROHC_PROFILE_RTP, -1) == true);

	/* ROHCv2 rohc_comp_enable_profiles() */
	CHECK(rohc_comp_enable_profiles(comp, ROHCv2_PROFILE_IP_ESP,
	                                ROHCv2_PROFILE_IP_UDP, -1) == true);

	/* rohc_comp_disable_profiles() */
	CHECK(rohc_comp_disable_profiles(NULL, ROHC_PROFILE_IP, -1) == false);
	CHECK(rohc_comp_disable_profiles(comp, ROHC_PROFILE_GENERAL, -1) == false);
	CHECK(rohc_comp_disable_profiles(comp, ROHC_PROFILE_UDP, -1) == true);
	CHECK(rohc_comp_disable_profiles(comp, ROHC_PROFILE_UDP,
	                                 ROHC_PROFILE_RTP, -1) == true);

	/* ROHCv2 rohc_comp_disable_profiles() */
	CHECK(rohc_comp_disable_profiles(comp, ROHCv2_PROFILE_IP_ESP,
	                                 ROHCv2_PROFILE_IP_UDP, -1) == true);

	/* rohc_comp_profile_enabled() */
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_UNCOMPRESSED) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_RTP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_UDP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_ESP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_IP) == true);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_TCP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_UDPLITE) == false);

	/* ROHCv2 rohc_comp_profile_enabled() */
	CHECK(rohc_comp_profile_enabled(comp, ROHCv2_PROFILE_IP_ESP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHCv2_PROFILE_IP_UDPLITE) == false);

	/* rohc_comp_get_segment2() */
	{
		uint8_t buf1[1];
		struct rohc_buf pkt1 = rohc_buf_init_empty(buf1, 1);
		CHECK(rohc_comp_get_segment2(NULL, &pkt1) == ROHC_STATUS_ERROR);
		CHECK(rohc_comp_get_segment2(comp, NULL) == ROHC_STATUS_ERROR);
		pkt1.max_len = 0;
		pkt1.offset = 0;
		pkt1.len = 0;
		CHECK(rohc_comp_get_segment2(comp, &pkt1) == ROHC_STATUS_ERROR);
		pkt1.max_len = 1;
		pkt1.offset = 0;
		pkt1.len = 0;
		CHECK(rohc_comp_get_segment2(comp, &pkt1) == ROHC_STATUS_ERROR);
		pkt1.max_len = 2;
		pkt1.offset = 0;
		pkt1.len = 0;
		CHECK(rohc_comp_get_segment2(comp, &pkt1) == ROHC_STATUS_ERROR);
	}

	/* rohc_comp_force_contexts_reinit() */
	CHECK(rohc_comp_force_contexts_reinit(NULL) == false);
	CHECK(rohc_comp_force_contexts_reinit(comp) == true);

	/* rohc_comp_set_optimistic_approach() */
	CHECK(rohc_comp_set_optimistic_approach(NULL, 16) == false);
	CHECK(rohc_comp_set_optimistic_approach(comp, 0) == false);
	CHECK(rohc_comp_set_optimistic_approach(comp, 256) == false);
	CHECK(rohc_comp_set_optimistic_approach(comp, 255) == true);
	CHECK(rohc_comp_set_optimistic_approach(comp, 64) == true);
	CHECK(rohc_comp_set_optimistic_approach(comp, 16) == true);

	/* rohc_comp_set_periodic_refreshes() */
	CHECK(rohc_comp_set_periodic_refreshes(NULL, 1700, 700) == false);
	CHECK(rohc_comp_set_periodic_refreshes(comp, 0, 700) == false);
	CHECK(rohc_comp_set_periodic_refreshes(comp, 1700, 0) == false);
	CHECK(rohc_comp_set_periodic_refreshes(comp, 5, 10) == false);
	CHECK(rohc_comp_set_periodic_refreshes(comp, 10, 5) == true);

	/* rohc_comp_set_periodic_refreshes_time() */
	CHECK(rohc_comp_set_periodic_refreshes_time(NULL, 1000, 500) == false);
	CHECK(rohc_comp_set_periodic_refreshes_time(comp, 0, 500) == false);
	CHECK(rohc_comp_set_periodic_refreshes_time(comp, 1000, 0) == false);
	CHECK(rohc_comp_set_periodic_refreshes_time(comp, 5, 10) == false);
	CHECK(rohc_comp_set_periodic_refreshes_time(comp, 10, 5) == true);

	/* rohc_comp_set_rtp_detection_cb() */
	{
		rohc_rtp_detection_callback_t fct =
			(rohc_rtp_detection_callback_t) NULL;
		CHECK(rohc_comp_set_rtp_detection_cb(NULL, fct, NULL) == false);
		CHECK(rohc_comp_set_rtp_detection_cb(comp, fct, NULL) == true);
	}

	/* rohc_comp_set_mrru() */
	CHECK(rohc_comp_set_mrru(NULL, 10) == false);
	CHECK(rohc_comp_set_mrru(comp, 65535 + 1) == false);
	CHECK(rohc_comp_enable_profile(comp, ROHCv2_PROFILE_IP_UDP) == true);
	CHECK(rohc_comp_set_mrru(comp, 0) == true);
	CHECK(rohc_comp_set_mrru(comp, 65535) == false);
	CHECK(rohc_comp_disable_profile(comp, ROHCv2_PROFILE_IP_UDP) == true);
	CHECK(rohc_comp_set_mrru(comp, 0) == true);
	CHECK(rohc_comp_set_mrru(comp, 65535) == true);
	CHECK(rohc_comp_enable_profile(comp, ROHCv2_PROFILE_IP_UDP) == false);

	/* rohc_comp_get_mrru() */
	{
		size_t mrru;
		CHECK(rohc_comp_get_mrru(NULL, &mrru) == false);
		CHECK(rohc_comp_get_mrru(comp, NULL) == false);
		CHECK(rohc_comp_get_mrru(comp, &mrru) == true);
		CHECK(mrru == 65535);
	}
	/* disable MRRU for next tests */
	CHECK(rohc_comp_set_mrru(comp, 0) == true);

	/* rohc_comp_get_max_cid() */
	{
		size_t max_cid;
		CHECK(rohc_comp_get_max_cid(NULL, &max_cid) == false);
		CHECK(rohc_comp_get_max_cid(comp, NULL) == false);
		CHECK(rohc_comp_get_max_cid(comp, &max_cid) == true);
		CHECK(max_cid == ROHC_SMALL_CID_MAX);
	}

	/* rohc_comp_get_cid_type() */
	{
		rohc_cid_type_t cid_type;
		CHECK(rohc_comp_get_cid_type(NULL, &cid_type) == false);
		CHECK(rohc_comp_get_cid_type(comp, NULL) == false);
		CHECK(rohc_comp_get_cid_type(comp, &cid_type) == true);
		CHECK(cid_type == ROHC_SMALL_CID);
	}

	/* rohc_comp_get_last_packet_info2() before any compressed packet */
	{
		rohc_comp_last_packet_info2_t info;
		memset(&info, 0, sizeof(rohc_comp_last_packet_info2_t));
		info.version_major = 0;
		info.version_minor = 0;
		CHECK(rohc_comp_get_last_packet_info2(comp, &info) == false);
	}

	/* rohc_compress4() */
	{
		const struct rohc_ts ts = { .sec = 0, .nsec = 0 };
		uint8_t buf1[1] = { 0x00 };
		struct rohc_buf pkt1 = rohc_buf_init_full(buf1, 1, ts);
		uint8_t buf2[100];
		struct rohc_buf pkt2 = rohc_buf_init_empty(buf2, 100);
		uint8_t buf[] =
		{
			0x45, 0x00, 0x00, 0x54,  0x00, 0x00, 0x40, 0x00,
			0x40, 0x01, 0x93, 0x52,  0xc0, 0xa8, 0x13, 0x01,
			0xc0, 0xa8, 0x13, 0x05,  0x08, 0x00, 0xe9, 0xc2,
			0x9b, 0x42, 0x00, 0x01,  0x66, 0x15, 0xa6, 0x45,
			0x77, 0x9b, 0x04, 0x00,  0x08, 0x09, 0x0a, 0x0b,
			0x0c, 0x0d, 0x0e, 0x0f,  0x10, 0x11, 0x12, 0x13,
			0x14, 0x15, 0x16, 0x17,  0x18, 0x19, 0x1a, 0x1b,
			0x1c, 0x1d, 0x1e, 0x1f,  0x20, 0x21, 0x22, 0x23,
			0x24, 0x25, 0x26, 0x27,  0x28, 0x29, 0x2a, 0x2b,
			0x2c, 0x2d, 0x2e, 0x2f,  0x30, 0x31, 0x32, 0x33,
			0x34, 0x35, 0x36, 0x37
		};
		struct rohc_buf pkt = rohc_buf_init_full(buf, sizeof(buf), ts);
		CHECK(rohc_compress4(NULL, pkt1, &pkt2) == ROHC_STATUS_ERROR);
		pkt1.len = 0;
		CHECK(rohc_compress4(comp, pkt1, &pkt2) == ROHC_STATUS_ERROR);
		pkt1.len = 1;
		CHECK(rohc_compress4(comp, pkt1, NULL) == ROHC_STATUS_ERROR);
		pkt2.max_len = 0;
		pkt2.offset = 0;
		pkt2.len = 0;
		CHECK(rohc_compress4(comp, pkt1, &pkt2) == ROHC_STATUS_ERROR);
		for(size_t i = 0; i <= pkt.len; i++)
		{
			pkt2.max_len = i;
			pkt2.offset = 0;
			pkt2.len = 0;
			CHECK(rohc_compress4(comp, pkt, &pkt2) == ROHC_STATUS_ERROR);
		}
		pkt2.max_len = pkt.len + 1;
		pkt2.offset = 0;
		pkt2.len = 0;
		CHECK(rohc_compress4(comp, pkt, &pkt2) == ROHC_STATUS_OK);
	}

	/* rohc_comp_get_last_packet_info2() */
	{
		rohc_comp_last_packet_info2_t info;
		memset(&info, 0, sizeof(rohc_comp_last_packet_info2_t));
		CHECK(rohc_comp_get_last_packet_info2(NULL, &info) == false);
		CHECK(rohc_comp_get_last_packet_info2(comp, NULL) == false);
		info.version_major = 0xffff;
		CHECK(rohc_comp_get_last_packet_info2(comp, &info) == false);
		info.version_major = 0;
		info.version_minor = 0xffff;
		CHECK(rohc_comp_get_last_packet_info2(comp, &info) == false);
		info.version_minor = 0;
		CHECK(rohc_comp_get_last_packet_info2(comp, &info) == true);
	}

	/* rohc_comp_get_general_info() */
	{
		rohc_comp_general_info_t info;
		memset(&info, 0, sizeof(rohc_comp_general_info_t));
		CHECK(rohc_comp_get_general_info(NULL, &info) == false);
		CHECK(rohc_comp_get_general_info(comp, NULL) == false);
		info.version_major = 0xffff;
		CHECK(rohc_comp_get_general_info(comp, &info) == false);
		info.version_major = 0;
		info.version_minor = 0xffff;
		CHECK(rohc_comp_get_general_info(comp, &info) == false);
		info.version_minor = 0;
		CHECK(rohc_comp_get_general_info(comp, &info) == true);
	}

	/* rohc_comp_get_state_descr() */
	CHECK(strcmp(rohc_comp_get_state_descr(ROHC_COMP_STATE_IR), "IR") == 0);
	CHECK(strcmp(rohc_comp_get_state_descr(ROHC_COMP_STATE_FO), "FO") == 0);
	CHECK(strcmp(rohc_comp_get_state_descr(ROHC_COMP_STATE_SO), "SO") == 0);
	CHECK(strcmp(rohc_comp_get_state_descr(ROHC_COMP_STATE_CR), "CR") == 0);
	CHECK(strcmp(rohc_comp_get_state_descr(ROHC_COMP_STATE_CR + 1), "no description") == 0);

	/* rohc_comp_force_contexts_reinit() with some contexts init'ed */
	CHECK(rohc_comp_force_contexts_reinit(comp) == true);

	/* rohc_comp_set_features */
	CHECK(rohc_comp_set_features(comp, ROHC_COMP_FEATURE_COMPAT_1_6_x) == false);
	CHECK(rohc_comp_set_features(comp, ROHC_COMP_FEATURE_NO_IP_CHECKSUMS) == true);
	CHECK(rohc_comp_set_features(comp, ROHC_COMP_FEATURE_DUMP_PACKETS) == true);
	CHECK(rohc_comp_set_features(comp, ROHC_COMP_FEATURE_TIME_BASED_REFRESHES) == true);
	CHECK(rohc_comp_set_features(comp, ROHC_COMP_FEATURE_NONE) == true);

	/* rohc_comp_deliver_feedback2() */
	{
		const struct rohc_ts ts = { .sec = 0, .nsec = 0 };
		uint8_t buf[] = { 0xf4, 0x20, 0x01, 0x11, 0x39 };
		struct rohc_buf pkt = rohc_buf_init_full(buf, 5, ts);

		CHECK(rohc_comp_deliver_feedback2(NULL, pkt) == false);
		pkt.len = 0; CHECK(rohc_comp_deliver_feedback2(comp, pkt) == true);
		pkt.len = 1; CHECK(rohc_comp_deliver_feedback2(comp, pkt) == false);
		pkt.len = 2; CHECK(rohc_comp_deliver_feedback2(comp, pkt) == false);
		pkt.len = 3; CHECK(rohc_comp_deliver_feedback2(comp, pkt) == false);
		pkt.len = 4; CHECK(rohc_comp_deliver_feedback2(comp, pkt) == false);
		pkt.len = 5; CHECK(rohc_comp_deliver_feedback2(comp, pkt) == true);
	}

	/* several functions with some packets already compressed */
	{
		rohc_trace_callback2_t fct = (rohc_trace_callback2_t) NULL;
		CHECK(rohc_comp_set_traces_cb2(comp, fct, comp) == false);

		CHECK(rohc_comp_set_optimistic_approach(comp, 16) == false);

		CHECK(rohc_comp_set_periodic_refreshes(comp, 10, 5) == false);
	}

	/* rohc_comp_free() */
	rohc_comp_free(NULL);
	rohc_comp_free(comp);

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Fake random callback: always send 0
 *
 * @param comp          The compressor
 * @param user_context  Private data
 * @return              Always 0
 */
static int random_cb(const struct rohc_comp *const comp __attribute__((unused)),
                     void *const user_context __attribute__((unused)))
{
	return 0; /* fake */
}

