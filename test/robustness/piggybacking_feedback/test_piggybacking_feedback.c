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

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <errno.h>
#include <assert.h>
#include <time.h> /* for time(2) */

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(void);
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
static int test_comp_and_decomp()
{
	/* compressors and decompressors used during the test */
	struct rohc_comp *compA;
	struct rohc_decomp *decompA;
	struct rohc_comp *compB;
	struct rohc_decomp *decompB;

	/* original IP packet, ROHC packet and decompressed IP packet */
	struct iphdr *ip_header;
	unsigned char ip_packet[MAX_ROHC_SIZE];
	int ip_size;
	static unsigned char rohc_packet[MAX_ROHC_SIZE];
	int rohc_size;
	static unsigned char decomp_packet[MAX_ROHC_SIZE];
	int decomp_size;

	/* information about the last compressed packet */
	rohc_comp_last_packet_info_t last_packet_info;

	int ret;
	int is_failure = 1;

/** The payload for the fake IP packet */
#define FAKE_PAYLOAD "hello, ROHC world!"

	/* initialize the random generator */
	srand(time(NULL));

	/* create the ROHC compressor with MAX_CID = 15 (small CID) */
	/* create the ROHC compressor A with MAX_CID = 15 (small CID) */
	compA = rohc_alloc_compressor(15, 0, 0, 0);
	if(compA == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor A\n");
		goto error;
	}
	rohc_c_set_large_cid(compA, 0);
	rohc_activate_profile(compA, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(compA, ROHC_PROFILE_UDP);
	rohc_activate_profile(compA, ROHC_PROFILE_IP);
	rohc_activate_profile(compA, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(compA, ROHC_PROFILE_RTP);

	/* set the callback for random numbers on compressor A */
	if(!rohc_comp_set_random_cb(compA, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers on "
		        "compressor A\n");
		goto destroy_compA;
	}

	/* create the ROHC compressor B with MAX_CID = 15 (small CID) */
	compB = rohc_alloc_compressor(15, 0, 0, 0);
	if(compB == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor B\n");
		goto destroy_compA;
	}
	rohc_c_set_large_cid(compB, 0);
	rohc_activate_profile(compB, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(compB, ROHC_PROFILE_UDP);
	rohc_activate_profile(compB, ROHC_PROFILE_IP);
	rohc_activate_profile(compB, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(compB, ROHC_PROFILE_RTP);

	/* set the callback for random numbers on compressor B */
	if(!rohc_comp_set_random_cb(compB, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers on "
		        "compressor B\n");
		goto destroy_compB;
	}

	/* create the ROHC decompressor A with associated compressor B for its
	 * feedback channel */
	decompA = rohc_alloc_decompressor(compB);
	if(decompA == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor A\n");
		goto destroy_compB;
	}

	/* create the ROHC decompressor B with associated compressor A for its
	 * feedback channel */
	decompB = rohc_alloc_decompressor(compA);
	if(decompB == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor B\n");
		goto destroy_decompA;
	}

	/* create a fake IP packet for the purpose of the test*/
	ip_header = (struct iphdr *) ip_packet;
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
	rohc_size = rohc_compress(compA, ip_packet, ip_size,
	                          rohc_packet, MAX_ROHC_SIZE);
	if(rohc_size <= 0)
	{
		fprintf(stderr, "failed to compress IP packet with compressor A\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "compression with compressor A is successful\n");

	/* decompress the generated ROHC packet with the ROHC decompressor A:
	 * feedback data shall be delivered to compressor B */
	decomp_size = rohc_decompress(decompA, rohc_packet, rohc_size,
	                              decomp_packet, MAX_ROHC_SIZE);
	if(decomp_size <= 0)
	{
		fprintf(stderr, "failed to decompress ROHC packet with decompressor A\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "decompression with decompressor A is successful\n");

	/* fail to compress the IP packet with the ROHC compressor B: compressor B
	 * shall try to put in the ROHC packet the feedback data delivered by
	 * decompressor A but it shall not lose feedback data when the compression
	 * fails */
	rohc_size = rohc_compress(compB, ip_packet, ip_size,
	                          rohc_packet, 5);
	if(rohc_size > 0)
	{
		fprintf(stderr, "succeeded to compress IP packet with compressor B\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "compression with compressor B failed as expected\n");

	/* compress the IP packet with the ROHC compressor B: feedback data
	 * delivered by decompressor A shall be piggybacked */
	rohc_size = rohc_compress(compB, ip_packet, ip_size,
	                          rohc_packet, MAX_ROHC_SIZE);
	if(rohc_size <= 0)
	{
		fprintf(stderr, "failed to compress IP packet with compressor B\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "compression with compressor B is successful\n");

	/* decompress the generated ROHC packet with the ROHC decompressor B:
	 * feedback data shall be delivered to compressor A */
	decomp_size = rohc_decompress(decompB, rohc_packet, rohc_size,
	                              decomp_packet, MAX_ROHC_SIZE);
	if(decomp_size <= 0)
	{
		fprintf(stderr, "failed to decompress ROHC packet with decompressor B\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "decompression with decompressor B is successful\n");

	/* get packet statistics and remember the context mode */
	ret = rohc_comp_get_last_packet_info(compA, &last_packet_info);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "failed to get statistics on packet\n");
		goto destroy_decompB;
	}
	fprintf(stderr, "context mode = ");
	switch(last_packet_info.context_mode)
	{
		case U_MODE:
			fprintf(stderr, "U-Mode\n");
			break;
		case O_MODE:
			fprintf(stderr, "O-Mode\n");
			break;
		case R_MODE:
			fprintf(stderr, "R-Mode\n");
			break;
		default:
			/* could not happen */
			fprintf(stderr, "unknown context mode %d\n",
			        last_packet_info.context_mode);
			assert(0);
			goto destroy_decompB;
	}

	/* compression context shall now be in O-Mode because of the received
	 * feedback */
	if(last_packet_info.context_mode != O_MODE)
	{
		fprintf(stderr, "compression context is not in O-Mode as expected\n");
		goto destroy_decompB;
	}

	/* everything went fine */
	fprintf(stderr, "compression context is in O-Mode as expected\n");
	is_failure = 0;

destroy_decompB:
	rohc_free_decompressor(decompB);
destroy_decompA:
	rohc_free_decompressor(decompA);
destroy_compB:
	rohc_free_compressor(compB);
destroy_compA:
	rohc_free_compressor(compA);
error:
	return is_failure;
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

