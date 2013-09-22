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
static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));


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
	if(argc <= 0)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc--, argv++)
	{
		if(!strcmp(*argv, "-h"))
		{
			/* print help */
			usage();
			goto error;
		}
		else
		{
			/* unknown argument */
			usage();
			goto error;
		}
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
	const struct rohc_timestamp arrival_time = { .sec = 0, .nsec = 0 };

	/* compressors and decompressors used during the test */
	struct rohc_comp *compA;
	struct rohc_decomp *decompA;
	struct rohc_comp *compB;
	struct rohc_decomp *decompB;

	/* original IP packet, ROHC packet and decompressed IP packet */
	struct ipv4_hdr *ip_header;
	unsigned char ip_packet[MAX_ROHC_SIZE];
	size_t ip_size;
	static unsigned char rohc_packet[MAX_ROHC_SIZE];
	size_t rohc_size;
	static unsigned char decomp_packet[MAX_ROHC_SIZE];
	size_t decomp_size;

	/* information about the last compressed packet */
	rohc_comp_last_packet_info2_t last_packet_info;

#define NB_RTP_PORTS 5
	const unsigned int rtp_ports[NB_RTP_PORTS] =
		{ 1234, 36780, 33238, 5020, 5002 };

	unsigned int i;
	int is_failure = 1;
	int ret;

/** The payload for the fake IP packet */
#define FAKE_PAYLOAD "hello, ROHC world!"

	/* initialize the random generator */
	srand(time(NULL));

	/* create the ROHC compressor A with small CID */
	compA = rohc_comp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX);
	if(compA == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor A\n");
		goto error;
	}

	/* set the callback for traces on compressor A */
	if(!rohc_comp_set_traces_cb(compA, print_rohc_traces))
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

	/* set the callback for random numbers on compressor A */
	if(!rohc_comp_set_random_cb(compA, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers on "
		        "compressor A\n");
		goto destroy_compA;
	}

	/* reset list of RTP ports on compressor A */
	if(!rohc_comp_reset_rtp_ports(compA))
	{
		fprintf(stderr, "failed to reset list of RTP ports on compressor A\n");
		goto destroy_compA;
	}

	/* add some ports to the list of RTP ports on compressor A */
	for(i = 0; i < NB_RTP_PORTS; i++)
	{
		if(!rohc_comp_add_rtp_port(compA, rtp_ports[i]))
		{
			fprintf(stderr, "failed to enable RTP port %u on compressor A\n",
			        rtp_ports[i]);
			goto destroy_compA;
		}
	}

	/* create the ROHC compressor B with small CID */
	compB = rohc_comp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX);
	if(compB == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor B\n");
		goto destroy_compA;
	}

	/* set the callback for traces on compressor B */
	if(!rohc_comp_set_traces_cb(compB, print_rohc_traces))
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

	/* set the callback for random numbers on compressor B */
	if(!rohc_comp_set_random_cb(compB, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers on "
		        "compressor B\n");
		goto destroy_compB;
	}

	/* reset list of RTP ports on compressor B */
	if(!rohc_comp_reset_rtp_ports(compB))
	{
		fprintf(stderr, "failed to reset list of RTP ports on compressor B\n");
		goto destroy_compB;
	}

	/* add some ports to the list of RTP ports on compressor B */
	for(i = 0; i < NB_RTP_PORTS; i++)
	{
		if(!rohc_comp_add_rtp_port(compB, rtp_ports[i]))
		{
			fprintf(stderr, "failed to enable RTP port %u on compressor B\n",
			        rtp_ports[i]);
			goto destroy_compB;
		}
	}

	/* create the ROHC decompressor A with associated compressor B for its
	 * feedback channel */
	decompA = rohc_decomp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                          ROHC_O_MODE, compB);
	if(decompA == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor A\n");
		goto destroy_compB;
	}

	/* set the callback for traces on decompressor A */
	if(!rohc_decomp_set_traces_cb(decompA, print_rohc_traces))
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
	decompB = rohc_decomp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                          ROHC_O_MODE, compA);
	if(decompB == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor B\n");
		goto destroy_decompA;
	}

	/* set the callback for traces on decompressor B */
	if(!rohc_decomp_set_traces_cb(decompB, print_rohc_traces))
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
	ip_header = (struct ipv4_hdr *) ip_packet;
	ip_header->version = 4; /* we create an IPv4 header */
	ip_header->ihl = 5; /* minimal IPv4 header length (in 32-bit words) */
	ip_header->tos = 0;
	ip_size = ip_header->ihl * 4 + strlen(FAKE_PAYLOAD);
	ip_header->tot_len = htons(ip_size);
	ip_header->id = 0;
	ip_header->frag_off = 0;
	ip_header->ttl = 1;
	ip_header->protocol = 134; /* unassigned number according to /etc/protocols */
	ip_header->check = 0; /* set to 0 for checksum computation */
	ip_header->saddr = htonl(0x01020304);
	ip_header->daddr = htonl(0x05060708);
	ip_header->check = 0xbeef; /* fake IP checksum */
	memcpy(ip_packet + ip_header->ihl * 4, FAKE_PAYLOAD, strlen(FAKE_PAYLOAD));
	fprintf(stderr, "IP packet successfully built\n");

	/* compress the IP packet with the ROHC compressor A */
	ret = rohc_compress3(compA, arrival_time, ip_packet, ip_size,
	                     rohc_packet, MAX_ROHC_SIZE, &rohc_size);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to compress IP packet with compressor A\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "compression with compressor A is successful\n");

	/* decompress the generated ROHC packet with the ROHC decompressor A:
	 * feedback data shall be delivered to compressor B */
	ret = rohc_decompress2(decompA, arrival_time, rohc_packet, rohc_size,
	                       decomp_packet, MAX_ROHC_SIZE, &decomp_size);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to decompress ROHC packet with decompressor A\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "decompression with decompressor A is successful\n");

	/* fail to compress the IP packet with the ROHC compressor B: compressor B
	 * shall try to put in the ROHC packet the feedback data delivered by
	 * decompressor A but it shall not lose feedback data when the compression
	 * fails */
	ret = rohc_compress3(compB, arrival_time, ip_packet, ip_size,
	                     rohc_packet, 1, &rohc_size);
	if(ret == ROHC_OK)
	{
		fprintf(stderr, "succeeded to compress IP packet with compressor B\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "compression with compressor B failed as expected\n");

	/* compress the IP packet with the ROHC compressor B: feedback data
	 * delivered by decompressor A shall be piggybacked */
	ret = rohc_compress3(compB, arrival_time, ip_packet, ip_size,
	                     rohc_packet, MAX_ROHC_SIZE, &rohc_size);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to compress IP packet with compressor B\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "compression with compressor B is successful\n");

	/* decompress the generated ROHC packet with the ROHC decompressor B:
	 * feedback data shall be delivered to compressor A */
	ret = rohc_decompress2(decompB, arrival_time, rohc_packet, rohc_size,
	                       decomp_packet, MAX_ROHC_SIZE, &decomp_size);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to decompress ROHC packet with decompressor B\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "decompression with decompressor B is successful\n");

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
 * @param level    The priority level of the trace
 * @param entity   The entity that emitted the trace among:
 *                  \li ROHC_TRACE_COMP
 *                  \li ROHC_TRACE_DECOMP
 * @param profile  The ID of the ROHC compression/decompression profile
 *                 the trace is related to
 * @param format   The format string of the trace
 */
static void print_rohc_traces(const rohc_trace_level_t level,
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

