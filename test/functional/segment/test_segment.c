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
 * @file   test_segment.c
 * @brief  Check that ROHC segments are handled as expected
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application compresses ROHC packets, doing segmentation if needed.
 */

#include "test.h"
#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif
#include <errno.h>
#include <assert.h>
#include <stdarg.h>

/* includes for network headers */
#include <protocols/ipv4.h>
#include <protocols/ipv6.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(const size_t ip_packet_len,
                                const size_t mrru,
                                const bool is_comp_expected_ok,
                                const size_t expected_segments_nr);
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
 * @brief Check that the decompression of the ROHC packets read in the capture
 *        generates a FEEDBACK-2 packet of the expected type with the expected
 *        feedback options.
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	int args_read;
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 0)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc -= args_read, argv += args_read)
	{
		if(!strcmp(*argv, "-h"))
		{
			/* print help */
			usage();
			goto error;
		}
		else
		{
			/* do not accept any argument without option name */
			usage();
			goto error;
		}
	}

	/* test ROHC segments with small packet (wrt output buffer) and large MRRU
	 * => no segmentation needed */
	status = test_comp_and_decomp(100, MAX_ROHC_SIZE * 2, true, 0);
	if(status != 0)
	{
		goto error;
	}

	/* test ROHC segments with large packet (wrt output buffer) and large MRRU,
	 * => segmentation needed */
	status |= test_comp_and_decomp(MAX_ROHC_SIZE, MAX_ROHC_SIZE * 2, true, 2);
	if(status != 0)
	{
		goto error;
	}

	/* test ROHC segments with large packet (wrt output buffer) and MRRU = 0,
	 * ie. segments disabled => segmentation needed but impossible */
	status |= test_comp_and_decomp(MAX_ROHC_SIZE, 0, false, 0);
	if(status != 0)
	{
		goto error;
	}

	/* test ROHC segments with very large packet (wrt output buffer) and large
	 * MRRU => segmentation needed, more than 2 segments expected */
	status |= test_comp_and_decomp(MAX_ROHC_SIZE * 2, MAX_ROHC_SIZE * 3, true, 3);
	if(status != 0)
	{
		goto error;
	}

	/* test ROHC segments with very large packet (wrt output buffer) and large
	 * MRRU (but not large enough) => segmentation needed, but MRRU forbids it */
	status |= test_comp_and_decomp(MAX_ROHC_SIZE * 2, MAX_ROHC_SIZE, false, 0);
	if(status != 0)
	{
		goto error;
	}

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that ROHC segments are handled as expected\n"
	        "\n"
	        "usage: test_segment [OPTIONS]\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with one IP packet of given length and the
 *        given MRRU
 *
 * @param ip_packet_len         The size of the IP packet to generate for the
 *                              test
 * @param mrru                  The MRRU for the test
 * @param is_comp_expected_ok   Whether compression is expected to be
 *                              successful or not?
 * @parma expected_segments_nr  The number of ROHC segments that we expect
 *                              for the test
 * @return                      0 in case of success,
 *                              1 in case of failure
 */
static int test_comp_and_decomp(const size_t ip_packet_len,
                                const size_t mrru,
                                const bool is_comp_expected_ok,
                                const size_t expected_segments_nr)
{
	struct rohc_comp *comp;
	struct rohc_decomp *decomp;

	struct ipv4_hdr *ip_header;
	unsigned char ip_packet[MAX_ROHC_SIZE * 3];

	unsigned char rohc_packet[MAX_ROHC_SIZE];
	size_t rohc_packet_len;

	unsigned char uncomp_packet[MAX_ROHC_SIZE * 3];
	int uncomp_packet_len;

	size_t segments_nr;

	int is_failure = 1;
	size_t i;
	int ret;

	fprintf(stderr, "test ROHC segments with %zd-byte IP packet and "
	        "MMRU = %zd bytes\n", ip_packet_len, mrru);

	/* check that buffer for IP packet is large enough */
	if(ip_packet_len > MAX_ROHC_SIZE * 3)
	{
		fprintf(stderr, "size requested for IP packet is too large\n");
		goto error;
	}

	/* initialize the random generator with the same number to ease debugging */
	srand(4 /* chosen by fair dice roll, guaranteed to be random */);

	/* create the ROHC compressor with small CID */
	comp = rohc_alloc_compressor(ROHC_SMALL_CID_MAX, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto error;
	}

	/* set the callback for traces on compressor */
	if(!rohc_comp_set_traces_cb(comp, print_rohc_traces))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "compressor\n");
		goto destroy_comp;
	}

	/* enable profiles */
	if(!rohc_comp_enable_profiles(comp, ROHC_PROFILE_UNCOMPRESSED,
	                              ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                              ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                              ROHC_PROFILE_ESP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles");
		goto destroy_comp;
	}

	/* set the callback for random numbers */
	if(!rohc_comp_set_random_cb(comp, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto destroy_comp;
	}

	/* set the MRRU at compressor */
	if(!rohc_comp_set_mrru(comp, mrru))
	{
		fprintf(stderr, "failed to set the MRRU at compressor\n");
		goto destroy_comp;
	}

	/* create the ROHC decompressor in uni-directional mode */
	decomp = rohc_alloc_decompressor(NULL);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb(decomp, print_rohc_traces))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "decompressor\n");
		goto destroy_decomp;
	}

	/* set the MRRU at decompressor */
	if(!rohc_decomp_set_mrru(decomp, mrru))
	{
		fprintf(stderr, "failed to set the MRRU at decompressor\n");
		goto destroy_decomp;
	}

	/* generate the IP packet of the given length */
	ip_header = (struct ipv4_hdr *) ip_packet;
	ip_header->version = 4; /* we create an IPv4 header */
	ip_header->ihl = 5; /* minimal IPv4 header length (in 32-bit words) */
	ip_header->tos = 0;
	ip_header->tot_len = htons(ip_packet_len);
	ip_header->id = 0;
	ip_header->frag_off = 0;
	ip_header->ttl = 1;
	ip_header->protocol = 134; /* unassigned number according to /etc/protocols */
	ip_header->check = 0; /* set to 0 for checksum computation */
	ip_header->saddr = htonl(0x01020304);
	ip_header->daddr = htonl(0x05060708);
	if(ip_packet_len == 100)
	{
		ip_header->check = htons(0xa901);
	}
	else if(ip_packet_len == MAX_ROHC_SIZE)
	{
		ip_header->check = htons(0x9565);
	}
	else if(ip_packet_len == MAX_ROHC_SIZE * 2)
	{
		ip_header->check = htons(0x8165);
	}
	else
	{
		/* compute the IP checksum for your test length */
		assert(0);
	}
	for(i = sizeof(struct ipv4_hdr); i < ip_packet_len; i++)
	{
		ip_packet[i] = i & 0xff;
	}

	/* compress the IP packet */
	segments_nr = 0;
	ret = rohc_compress2(comp,
	                     ip_packet, ip_packet_len,
	                     rohc_packet, MAX_ROHC_SIZE, &rohc_packet_len);
	if(ret == ROHC_NEED_SEGMENT)
	{
		fprintf(stderr, "\tROHC segments are required to compress the IP "
		        "packet\n");

		/* get the segments */
		while((ret = rohc_comp_get_segment(comp, rohc_packet, MAX_ROHC_SIZE,
		                                   &rohc_packet_len)) == ROHC_NEED_SEGMENT)
		{
			fprintf(stderr, "\t%zd-byte ROHC segment generated\n",
			        rohc_packet_len);
			segments_nr++;

			/* decompress segment */
			uncomp_packet_len = rohc_decompress(decomp,
			                                    rohc_packet, rohc_packet_len,
			                                    uncomp_packet, MAX_ROHC_SIZE * 3);
			if(uncomp_packet_len != ROHC_NON_FINAL_SEGMENT)
			{
				fprintf(stderr, "\tfailed to decompress ROHC segment packet\n");
				goto destroy_decomp;
			}
		}
		if(ret != ROHC_OK)
		{
			fprintf(stderr, "failed to generate ROHC segment (ret = %d)\n", ret);
			goto destroy_decomp;
		}
		fprintf(stderr, "\t%zd-byte final ROHC segment generated\n",
		        rohc_packet_len);
		segments_nr++;

		/* decompress last segment */
		uncomp_packet_len = rohc_decompress(decomp,
		                                    rohc_packet, rohc_packet_len,
		                                    uncomp_packet, MAX_ROHC_SIZE * 3);
		if(uncomp_packet_len <= 0)
		{
			fprintf(stderr, "\tfailed to decompress ROHC segments\n");
			goto destroy_decomp;
		}
	}
	else if(ret != ROHC_OK)
	{
		if(is_comp_expected_ok)
		{
			fprintf(stderr, "\tfailed to compress ROHC packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\texpected failure to compress packet\n");
		uncomp_packet_len = 0; /* decompression not possible */
	}
	else if(!is_comp_expected_ok)
	{
		fprintf(stderr, "\tunexpected success to compress packet\n");
		goto destroy_decomp;
	}
	else
	{
		fprintf(stderr, "\t%zd-byte ROHC packet generated\n", rohc_packet_len);

		/* decompress ROHC packet */
		uncomp_packet_len = rohc_decompress(decomp,
		                                    rohc_packet, rohc_packet_len,
		                                    uncomp_packet, MAX_ROHC_SIZE * 3);
		if(uncomp_packet_len <= 0)
		{
			fprintf(stderr, "\tfailed to decompress ROHC packet\n");
			goto destroy_decomp;
		}
	}

	/* check the number of generated segments */
	if(expected_segments_nr != segments_nr)
	{
		fprintf(stderr, "\tunexpected number of segment(s): %zd segment(s) generated "
		        "while %zd expected\n", segments_nr, expected_segments_nr);
		goto destroy_decomp;
	}
	fprintf(stderr, "\t%zd segment(s) generated as expected\n", segments_nr);

	/* check that decompressed packet matches the original IP packet */
	if(is_comp_expected_ok)
	{
		if(ip_packet_len != uncomp_packet_len)
		{
			fprintf(stderr, "\t%d-byte decompressed packet does not match original "
			        "%zd-byte IP packet: different lengths\n", uncomp_packet_len,
			        ip_packet_len);
			goto destroy_decomp;
		}
		if(memcmp(ip_packet, uncomp_packet, ip_packet_len) != 0)
		{
			fprintf(stderr, "\t%d-byte decompressed packet does not match original "
			        "%zd-byte IP packet\n", uncomp_packet_len, ip_packet_len);
			goto destroy_decomp;
		}
		fprintf(stderr, "\tdecompressed ROHC packet/segments match the original "
		        "IP packet\n");
	}

	/* everything went fine */
	fprintf(stderr, "\n");
	is_failure = 0;

destroy_decomp:
	rohc_free_decompressor(decomp);
destroy_comp:
	rohc_free_compressor(comp);
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
	va_list args;

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

