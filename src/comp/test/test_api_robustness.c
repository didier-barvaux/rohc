/*
 * Copyright 2013,2014 Didier Barvaux
 * Copyright 2013 Friedrich
 *
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

	/* rohc_comp_new() */
	CHECK(rohc_comp_new(-1, ROHC_SMALL_CID_MAX) == NULL);
	CHECK(rohc_comp_new(ROHC_SMALL_CID + 1, ROHC_SMALL_CID_MAX) == NULL);
	comp = rohc_comp_new(ROHC_SMALL_CID, 0);
	CHECK(comp != NULL);
	rohc_comp_free(comp);
	comp = rohc_comp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX);
	CHECK(comp != NULL);
	rohc_comp_free(comp);
	CHECK(rohc_comp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX + 1) == NULL);
	comp = rohc_comp_new(ROHC_LARGE_CID, 0);
	CHECK(comp != NULL);
	rohc_comp_free(comp);
	comp = rohc_comp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX);
	CHECK(comp != NULL);
	rohc_comp_free(comp);
	CHECK(rohc_comp_new(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX + 1) == NULL);
	comp = rohc_comp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX);
	CHECK(comp != NULL);

	/* rohc_comp_set_traces_cb() */
	{
		rohc_trace_callback_t fct = (rohc_trace_callback_t) NULL;
		CHECK(rohc_comp_set_traces_cb(NULL, fct) == false);
		CHECK(rohc_comp_set_traces_cb(comp, fct) == true);
	}

	/* rohc_comp_set_random_cb() */
	{
		rohc_comp_random_cb_t fct = (rohc_comp_random_cb_t) NULL;
		CHECK(rohc_comp_set_random_cb(NULL, fct, NULL) == false);
		CHECK(rohc_comp_set_random_cb(comp, fct, NULL) == false);
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

	/* rohc_comp_enable_profile() */
	CHECK(rohc_comp_enable_profile(NULL, ROHC_PROFILE_IP) == false);
	CHECK(rohc_comp_enable_profile(comp, ROHC_PROFILE_GENERAL) == false);
	CHECK(rohc_comp_enable_profile(comp, ROHC_PROFILE_IP) == true);

	/* rohc_comp_disable_profile() */
	CHECK(rohc_comp_disable_profile(NULL, ROHC_PROFILE_IP) == false);
	CHECK(rohc_comp_disable_profile(comp, ROHC_PROFILE_GENERAL) == false);
	CHECK(rohc_comp_disable_profile(comp, ROHC_PROFILE_IP) == true);

	/* rohc_comp_enable_profiles() */
	CHECK(rohc_comp_enable_profiles(NULL, ROHC_PROFILE_IP, -1) == false);
	CHECK(rohc_comp_enable_profiles(comp, ROHC_PROFILE_GENERAL, -1) == false);
	CHECK(rohc_comp_enable_profiles(comp, ROHC_PROFILE_IP, -1) == true);
	CHECK(rohc_comp_enable_profiles(comp, ROHC_PROFILE_IP, ROHC_PROFILE_UDP,
	                                ROHC_PROFILE_RTP, -1) == true);

	/* rohc_comp_disable_profiles() */
	CHECK(rohc_comp_disable_profiles(NULL, ROHC_PROFILE_IP, -1) == false);
	CHECK(rohc_comp_disable_profiles(comp, ROHC_PROFILE_GENERAL, -1) == false);
	CHECK(rohc_comp_disable_profiles(comp, ROHC_PROFILE_UDP, -1) == true);
	CHECK(rohc_comp_disable_profiles(comp, ROHC_PROFILE_UDP,
	                                 ROHC_PROFILE_RTP, -1) == true);

	/* rohc_comp_profile_enabled() */
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_UNCOMPRESSED) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_RTP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_UDP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_ESP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_IP) == true);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_TCP) == false);
	CHECK(rohc_comp_profile_enabled(comp, ROHC_PROFILE_UDPLITE) == false);

	/* rohc_comp_get_segment() */
	{
		unsigned char buf1[1];
		size_t len;
		CHECK(rohc_comp_get_segment(NULL, buf1, 1, &len) == ROHC_ERROR);
		CHECK(rohc_comp_get_segment(comp, NULL, 1, &len) == ROHC_ERROR);
		CHECK(rohc_comp_get_segment(comp, buf1, 0, &len) == ROHC_ERROR);
		CHECK(rohc_comp_get_segment(comp, buf1, 1, NULL) == ROHC_ERROR);
	}

	/* rohc_comp_force_contexts_reinit() */
	CHECK(rohc_comp_force_contexts_reinit(NULL) == false);
	CHECK(rohc_comp_force_contexts_reinit(comp) == true);

	/* rohc_comp_set_wlsb_window_width() */
	CHECK(rohc_comp_set_wlsb_window_width(NULL, 16) == false);
	CHECK(rohc_comp_set_wlsb_window_width(comp, 0) == false);
	CHECK(rohc_comp_set_wlsb_window_width(comp, 15) == false);
	CHECK(rohc_comp_set_wlsb_window_width(comp, 16) == true);

	/* rohc_comp_set_periodic_refreshes() */
	CHECK(rohc_comp_set_periodic_refreshes(NULL, 1700, 700) == false);
	CHECK(rohc_comp_set_periodic_refreshes(comp, 0, 700) == false);
	CHECK(rohc_comp_set_periodic_refreshes(comp, 1700, 0) == false);
	CHECK(rohc_comp_set_periodic_refreshes(comp, 5, 10) == false);
	CHECK(rohc_comp_set_periodic_refreshes(comp, 5, 10) == false);

	/* rohc_comp_set_list_trans_nr() */
	CHECK(rohc_comp_set_list_trans_nr(NULL, 5) == false);
	CHECK(rohc_comp_set_list_trans_nr(comp, 0) == false);
	CHECK(rohc_comp_set_list_trans_nr(comp, 1) == true);
	CHECK(rohc_comp_set_list_trans_nr(comp, 5) == true);

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
	CHECK(rohc_comp_set_mrru(comp, 0) == true);
	CHECK(rohc_comp_set_mrru(comp, 65535) == true);

	/* rohc_comp_get_mrru() */
	{
		size_t mrru;
		CHECK(rohc_comp_get_mrru(NULL, &mrru) == false);
		CHECK(rohc_comp_get_mrru(comp, NULL) == false);
		CHECK(rohc_comp_get_mrru(comp, &mrru) == true);
		CHECK(mrru == 65535);
	}

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

	/* rohc_comp_add_rtp_port() */
	CHECK(rohc_comp_add_rtp_port(NULL, 1) == false);
	CHECK(rohc_comp_add_rtp_port(comp, 0) == false);
	CHECK(rohc_comp_add_rtp_port(comp, 0xffff + 1) == false);
	CHECK(rohc_comp_add_rtp_port(comp, 1) == true);
	CHECK(rohc_comp_add_rtp_port(comp, 1) == false); /* not twice in list */
	for(int i = 2; i <= 15; i++)
	{
		CHECK(rohc_comp_add_rtp_port(comp, i) == true);
	}
	CHECK(rohc_comp_add_rtp_port(comp, 16) == false);

	/* rohc_comp_remove_rtp_port() */
	CHECK(rohc_comp_remove_rtp_port(NULL, 1) == false);
	CHECK(rohc_comp_remove_rtp_port(comp, 0) == false);
	CHECK(rohc_comp_remove_rtp_port(comp, 0xffff + 1) == false);
	CHECK(rohc_comp_remove_rtp_port(comp, 16) == false); /* not in list */
	CHECK(rohc_comp_remove_rtp_port(comp, 15) == true); /* remove last */
	CHECK(rohc_comp_remove_rtp_port(comp, 16) == false); /* not in list (2) */
	for(int i = 1; i < 15; i++)
	{
		CHECK(rohc_comp_remove_rtp_port(comp, i) == true);
	}
	CHECK(rohc_comp_remove_rtp_port(comp, 16) == false); /* empty list */

	/* rohc_comp_reset_rtp_ports() */
	CHECK(rohc_comp_reset_rtp_ports(NULL) == false);
	CHECK(rohc_comp_reset_rtp_ports(comp) == true);

	/* rohc_comp_piggyback_feedback() */
	{
		unsigned char buf[1];
		CHECK(rohc_comp_piggyback_feedback(NULL, buf, 1) == false);
		CHECK(rohc_comp_piggyback_feedback(comp, NULL, 1) == false);
		CHECK(rohc_comp_piggyback_feedback(comp, buf, 0) == false);
		for(int i = 0; i < 1000; i++)
		{
			CHECK(rohc_comp_piggyback_feedback(comp, buf, 1) == true);
		}
		CHECK(rohc_comp_piggyback_feedback(comp, buf, 1) == false); /* full */
	}

	/* rohc_feedback_flush() */
	{
		const size_t buflen = 2;
		unsigned char buf[buflen];
		CHECK(rohc_feedback_flush(NULL, buf, buflen) == 0);
		CHECK(rohc_feedback_flush(comp, NULL, buflen) == 0);
		CHECK(rohc_feedback_flush(comp, buf, 0) == 0);
		for(int i = 0; i < 1000; i++)
		{
			CHECK(rohc_feedback_flush(comp, buf, buflen) > 0);
		}
		CHECK(rohc_feedback_flush(comp, buf, buflen) == 0); /* empty */
	}

	/* rohc_compress3() */
	{
		const struct rohc_ts ts = { .sec = 0, .nsec = 0 };
		unsigned char buf1[1];
		unsigned char buf2[100];
		unsigned char buf[] =
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
		size_t len;
		CHECK(rohc_compress3(NULL, ts, buf1, 1, buf2, 1, &len) == ROHC_ERROR);
		CHECK(rohc_compress3(comp, ts, NULL, 1, buf2, 1, &len) == ROHC_ERROR);
		CHECK(rohc_compress3(comp, ts, buf1, 0, buf2, 1, &len) == ROHC_ERROR);
		CHECK(rohc_compress3(comp, ts, buf1, 1, NULL, 1, &len) == ROHC_ERROR);
		CHECK(rohc_compress3(comp, ts, buf1, 1, buf2, 0, &len) == ROHC_ERROR);
		CHECK(rohc_compress3(comp, ts, buf1, 1, buf2, 1, NULL) == ROHC_ERROR);
		CHECK(rohc_compress3(comp, ts, buf, sizeof(buf), buf2, sizeof(buf2), &len) == ROHC_OK);
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

	/* rohc_comp_force_contexts_reinit() with some contexts init'ed */
	CHECK(rohc_comp_force_contexts_reinit(comp) == true);

	/* rohc_feedback_remove_locked() */
	CHECK(rohc_feedback_remove_locked(NULL) == false);
	CHECK(rohc_feedback_remove_locked(comp) == true);

	/* rohc_feedback_avail_bytes() */
	{
		const size_t buflen = 12;
		unsigned char buf[buflen];
		unsigned char buf1[1];
		unsigned char buf2[8];
		CHECK(rohc_feedback_avail_bytes(NULL) == 0);
		CHECK(rohc_feedback_avail_bytes(comp) == 0);
		CHECK(rohc_comp_piggyback_feedback(comp, buf1, 1) == true);
		CHECK(rohc_feedback_avail_bytes(comp) == 2);
		CHECK(rohc_comp_piggyback_feedback(comp, buf2, 8) == true);
		CHECK(rohc_feedback_avail_bytes(comp) == 12);
		CHECK(rohc_feedback_flush(comp, buf, buflen) == 12);
		CHECK(rohc_feedback_avail_bytes(comp) == 0);
	}

	/* rohc_feedback_unlock() */
	CHECK(rohc_feedback_unlock(NULL) == false);
	CHECK(rohc_feedback_unlock(comp) == true);
	CHECK(rohc_feedback_avail_bytes(comp) == 12);

	/* rohc_comp_deliver_feedback() */
	{
		const unsigned char buf[] = { 0x00, 0x01, 0x02, 0x03 };

		CHECK(rohc_comp_deliver_feedback(NULL, buf, 4) == true);
		CHECK(rohc_comp_deliver_feedback(comp, NULL, 4) == false);
		CHECK(rohc_comp_deliver_feedback(comp, buf, -1) == false);
		CHECK(rohc_comp_deliver_feedback(comp, buf, 4) == true);
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

