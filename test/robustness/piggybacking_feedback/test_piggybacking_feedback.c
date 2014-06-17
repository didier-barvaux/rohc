/*
 * Copyright 2011,2012,2013,2014 Didier Barvaux
 * Copyright 2012 Viveris Technologies
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

/**
 * @file   test_piggybacking_feedback.c
 * @brief  Check that the ROHC compressor handles correctly feedbacks being
 *         piggybacked when a compression error occurs
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application creates 2 compressors/decompressors pairs A and B. The
 * decompressor A is associated with the compressor B. The decompressor B is
 * associated with the compressor A. Each pair therefore provides a feedback
 * channel for the other pair.
 *
 * The application compresses one IP packet then decompresses it with the
 * compressor/decompressor pair A. Decompressor A generates a feedback and
 * provides it to the compressor B.
 *
 * The application then compresses the same IP packet with the compressor B.
 * It adds the feedback from decompressor A to the compressed packet in the
 * process. As the output buffer is too small, the compression fails. However
 * feedback data shall not be lost, it shall be transmitted with next compressed
 * packet.
 *
 * The application compresses again the same IP packet with the compressor B
 * with a larger output buffer. Compression is successful. Feedback data shall
 * be part of the generated ROHC packet.
 *
 * The ROHC packet is then decompressed by decompressor B. Decompressor B parses
 * the feedback data and delivers it to compressor A. It makes compressor A
 * change for O-Mode.
 *
 * At the end of the test, compressor A shall be in O-Mode. If not, feedback
 * data was somehow lost because of the compression failure at compressor B.
 */

#include "test.h"
#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif
#include <errno.h>
#include <assert.h>
#include <time.h> /* for time(2) */
#include <stdarg.h>

/* includes for network headers */
#include <protocols/ipv4.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(void);
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 5, 6), nonnull(5)));
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));
static bool rohc_comp_rtp_cb(const unsigned char *const ip,
                             const unsigned char *const udp,
                             const unsigned char *const payload,
                             const unsigned int payload_size,
                             void *const rtp_private)
	__attribute__((warn_unused_result));


/**
 * @brief Check that the ROHC compressor handles correctly feedbacks being
 *        piggybacked when a compression error occurs
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc != 1)
	{
		usage();
		goto error;
	}

	/* test ROHC feedback handling */
	status = test_comp_and_decomp();

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that the ROHC compressor handles correctly feedbacks being\n"
	        "piggybacked when a compression error occurs\n"
	        "\n"
	        "usage: test_piggybacking_feedback [OPTIONS]\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the way the ROHC library handles feedbacks being piggybacked
 *        when a compression error occurs
 *
 * @return  0 in case of success,
 *          1 in case of failure
 */
static int test_comp_and_decomp(void)
{
	/* compressors and decompressors used during the test */
	struct rohc_comp *compA;
	struct rohc_decomp *decompA;
	struct rohc_comp *compB;
	struct rohc_decomp *decompB;

	/* original IP packet, ROHC packet and decompressed IP packet */
	struct ipv4_hdr *ip_header;
	uint8_t ip_buffer[MAX_ROHC_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, MAX_ROHC_SIZE);
	uint8_t rohc_buffer[MAX_ROHC_SIZE];
	struct rohc_buf rohc_packet =
		rohc_buf_init_empty(rohc_buffer, MAX_ROHC_SIZE);
	uint8_t decomp_buffer[MAX_ROHC_SIZE];
	struct rohc_buf decomp_packet =
		rohc_buf_init_empty(decomp_buffer, MAX_ROHC_SIZE);

	/* feedback data */
	uint8_t rcvd_feedback_buffer[MAX_ROHC_SIZE];
	struct rohc_buf rcvd_feedback =
		rohc_buf_init_empty(rcvd_feedback_buffer, MAX_ROHC_SIZE);
	uint8_t feedback_send_buffer[MAX_ROHC_SIZE];
	struct rohc_buf feedback_send =
		rohc_buf_init_empty(feedback_send_buffer, MAX_ROHC_SIZE);

	/* information about the last compressed packet */
	rohc_comp_last_packet_info2_t last_packet_info;

	int is_failure = 1;
	int ret;

/** The payload for the fake IP packet */
#define FAKE_PAYLOAD "hello, ROHC world!"

	/* initialize the random generator */
	srand(time(NULL));

	/* create the ROHC compressor A with small CID */
	compA = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                       gen_random_num, NULL);
	if(compA == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor A\n");
		goto error;
	}

	/* set the callback for traces on compressor A */
	if(!rohc_comp_set_traces_cb2(compA, print_rohc_traces, NULL))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "compressor A\n");
		goto destroy_compA;
	}

	/* enable profiles for compressor A */
	if(!rohc_comp_enable_profiles(compA, ROHC_PROFILE_UNCOMPRESSED,
	                              ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                              ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                              ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the profiles on compressor A\n");
		goto destroy_compA;
	}

	/* set UDP ports dedicated to RTP traffic */
	if(!rohc_comp_set_rtp_detection_cb(compA, rohc_comp_rtp_cb, NULL))
	{
		fprintf(stderr, "failed to set the callback RTP detection\n");
		goto destroy_compA;
	}

	/* create the ROHC compressor B with small CID */
	compB = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                       gen_random_num, NULL);
	if(compB == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor B\n");
		goto destroy_compA;
	}

	/* set the callback for traces on compressor B */
	if(!rohc_comp_set_traces_cb2(compB, print_rohc_traces, NULL))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "compressor B\n");
		goto destroy_compB;
	}

	/* enable profiles for compressor B */
	if(!rohc_comp_enable_profiles(compB, ROHC_PROFILE_UNCOMPRESSED,
	                              ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                              ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                              ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the profiles on compressor B\n");
		goto destroy_compB;
	}

	/* set UDP ports dedicated to RTP traffic */
	if(!rohc_comp_set_rtp_detection_cb(compB, rohc_comp_rtp_cb, NULL))
	{
		fprintf(stderr, "failed to set the callback RTP detection\n");
		goto destroy_compB;
	}

	/* create the ROHC decompressor A with associated compressor B for its
	 * feedback channel */
	decompA = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_O_MODE);
	if(decompA == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor A\n");
		goto destroy_compB;
	}

	/* set the callback for traces on decompressor A */
	if(!rohc_decomp_set_traces_cb2(decompA, print_rohc_traces, NULL))
	{
		fprintf(stderr, "cannot set trace callback for decompressor A\n");
		goto destroy_decompA;
	}

	/* enable decompression profiles on decompressor A */
	if(!rohc_decomp_enable_profiles(decompA, ROHC_PROFILE_UNCOMPRESSED,
	                                ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                                ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                                ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the profiles on decompressor A\n");
		goto destroy_decompA;
	}

	/* create the ROHC decompressor B with associated compressor A for its
	 * feedback channel */
	decompB = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_O_MODE);
	if(decompB == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor B\n");
		goto destroy_decompA;
	}

	/* set the callback for traces on decompressor B */
	if(!rohc_decomp_set_traces_cb2(decompB, print_rohc_traces, NULL))
	{
		fprintf(stderr, "cannot set trace callback for decompressor B\n");
		goto destroy_decompB;
	}

	/* enable decompression profiles on decompressor B */
	if(!rohc_decomp_enable_profiles(decompB, ROHC_PROFILE_UNCOMPRESSED,
	                                ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                                ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                                ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the profiles on decompressor B\n");
		goto destroy_decompB;
	}

	/* create a fake IP packet for the purpose of the test*/
	ip_packet.len = sizeof(struct ipv4_hdr) + strlen(FAKE_PAYLOAD);
	ip_header = (struct ipv4_hdr *) rohc_buf_data(ip_packet);
	ip_header->version = 4; /* we create an IPv4 header */
	ip_header->ihl = 5; /* minimal IPv4 header length (in 32-bit words) */
	ip_header->tos = 0;
	ip_header->tot_len = htons(ip_packet.len);
	ip_header->id = 0;
	ip_header->frag_off = 0;
	ip_header->ttl = 1;
	ip_header->protocol = 134; /* unassigned number according to /etc/protocols */
	ip_header->check = htons(0xa93f); /* IP checksum */
	ip_header->saddr = htonl(0x01020304);
	ip_header->daddr = htonl(0x05060708);
	memcpy(rohc_buf_data_at(ip_packet, ip_header->ihl * 4), FAKE_PAYLOAD,
	       strlen(FAKE_PAYLOAD));
	fprintf(stderr, "IP packet successfully built\n");

	/* compress the IP packet with the ROHC compressor A */
	ret = rohc_compress4(compA, ip_packet, &rohc_packet);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to compress IP packet with compressor A\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "compression with compressor A is successful\n");

	/* decompress the generated ROHC packet with the ROHC decompressor A:
	 * feedback data shall be delivered to compressor B */
	ret = rohc_decompress3(decompA, rohc_packet, &decomp_packet,
	                       &rcvd_feedback, &feedback_send);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to decompress ROHC packet with decompressor A\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "decompression with decompressor A is successful\n");
	rohc_packet.len = 0; /* ROHC packet was correctly decompressed */
	decomp_packet.len = 0; /* drop the decompressed packet */

	/* no feedback expected to be received */
	assert(rcvd_feedback.len == 0);
	/* some feedback expected to be ready to be sent */
	fprintf(stderr, "%zu-byte feedback to be sent\n", feedback_send.len);
	assert(feedback_send.len > 0);

	/* piggyback the feedback to send along the ROHC packet that compressor B
	 * is going to generate */
	rohc_buf_append_buf(&rohc_packet, feedback_send);
	rohc_buf_pull(&rohc_packet, feedback_send.len);

	/* fail to compress the IP packet with the ROHC compressor B: compressor B
	 * shall not change the piggybacked feedback data */
	rohc_packet.max_len = feedback_send.len + 1; /* cause compression error */
	ret = rohc_compress4(compB, ip_packet, &rohc_packet);
	if(ret == ROHC_OK)
	{
		fprintf(stderr, "succeeded to compress IP packet with compressor B\n");
		feedback_send.len = 0; /* feedback was correctly piggybacked */
		goto destroy_decompB;
	}
	fprintf(stderr, "compression with compressor B failed as expected\n");
	rohc_packet.max_len = MAX_ROHC_SIZE; /* revert */

	/* compress the IP packet with the ROHC compressor B: feedback data
	 * shall be piggybacked */
	ret = rohc_compress4(compB, ip_packet, &rohc_packet);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to compress IP packet with compressor B\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "compression with compressor B is successful\n");

	/* feedback was correctly piggybacked */
	rohc_buf_push(&rohc_packet, feedback_send.len);
	feedback_send.len = 0;

	/* decompress the generated ROHC packet with the ROHC decompressor B:
	 * feedback data shall be received for compressor A */
	ret = rohc_decompress3(decompB, rohc_packet, &decomp_packet,
	                       &rcvd_feedback, &feedback_send);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to decompress ROHC packet with decompressor B\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "decompression with decompressor B is successful\n");
	rohc_packet.len = 0; /* ROHC packet was correctly decompressed */

	/* some feedback expected to be received */
	assert(rcvd_feedback.len > 0);

	/* deliver the received feedback data to compressor A */
	if(!rohc_comp_deliver_feedback2(compA, rcvd_feedback))
	{
		fprintf(stderr, "failed to deliver the received feedback data to "
		        "compressor A\n");
		goto destroy_decompB;
	}

	/* get packet statistics and remember the context mode */
	last_packet_info.version_major = 0;
	last_packet_info.version_minor = 0;
	if(!rohc_comp_get_last_packet_info2(compA, &last_packet_info))
	{
		fprintf(stderr, "failed to get statistics on packet\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "context mode = %s\n",
	        rohc_get_mode_descr(last_packet_info.context_mode));

	/* compression context shall now be in O-Mode because of the received
	 * feedback */
	if(last_packet_info.context_mode != ROHC_O_MODE)
	{
		fprintf(stderr, "compression context is not in O-Mode as expected\n");
		goto destroy_decompB;
	}

	/* everything went fine */
	fprintf(stderr, "compression context is in O-Mode as expected\n");
	is_failure = 0;

destroy_decompB:
	rohc_decomp_free(decompB);
destroy_decompA:
	rohc_decomp_free(decompA);
destroy_compB:
	rohc_comp_free(compB);
destroy_compA:
	rohc_comp_free(compA);
error:
	return is_failure;
}


/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param priv_ctxt  An optional private context, may be NULL
 * @param level      The priority level of the trace
 * @param entity     The entity that emitted the trace among:
 *                    \li ROHC_TRACE_COMP
 *                    \li ROHC_TRACE_DECOMP
 * @param profile    The ID of the ROHC compression/decompression profile
 *                   the trace is related to
 * @param format     The format string of the trace
 */
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
{
	const char *level_descrs[] =
	{
		[ROHC_TRACE_DEBUG]   = "DEBUG",
		[ROHC_TRACE_INFO]    = "INFO",
		[ROHC_TRACE_WARNING] = "WARNING",
		[ROHC_TRACE_ERROR]   = "ERROR"
	};
	va_list args;

	fprintf(stdout, "[%s] ", level_descrs[level]);
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
}


/**
 * @brief Generate a random number
 *
 * @param comp          The ROHC compressor
 * @param user_context  Should always be NULL
 * @return              A random number
 */
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
{
	assert(comp != NULL);
	assert(user_context == NULL);
	return rand();
}


/**
 * @brief The RTP detection callback
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @param rtp_private  An optional private context
 * @return             true if the packet is an RTP packet, false otherwise
 */
static bool rohc_comp_rtp_cb(const unsigned char *const ip __attribute__((unused)),
                             const unsigned char *const udp,
                             const unsigned char *const payload __attribute__((unused)),
                             const unsigned int payload_size __attribute__((unused)),
                             void *const rtp_private __attribute__((unused)))
{
	const size_t default_rtp_ports_nr = 5;
	unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002 };
	uint16_t udp_dport;
	bool is_rtp = false;
	size_t i;

	if(udp == NULL)
	{
		return false;
	}

	/* get the UDP destination port */
	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));

	/* is the UDP destination port in the list of ports reserved for RTP
	 * traffic by default (for compatibility reasons) */
	for(i = 0; i < default_rtp_ports_nr; i++)
	{
		if(ntohs(udp_dport) == default_rtp_ports[i])
		{
			is_rtp = true;
			break;
		}
	}

	return is_rtp;
}

