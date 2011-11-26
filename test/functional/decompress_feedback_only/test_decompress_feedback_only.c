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
 * @file   test_decompress_feedback_only.c
 * @brief  Check that FEEDBACK-2 packets are generated as expected
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application decompresses ROHC feedback-only packets successfully.
 */

#include "test.h"

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <errno.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_decomp.h>


/* prototypes of private functions */
static void usage(void);
static int test_decomp(const unsigned char *const rohc_feedback,
                       const size_t rohc_feedback_len);


/**
 * @brief Check that the decompression of the ROHC feedback-only packets is
 *        successful.
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	int args_read = 1;

	/* a ROHC feedback-only packet */
	const unsigned char rohc_feedback[] = { 0xf4, 0x20, 0x00, 0x11, 0xe9 };
	const size_t rohc_feedback_len = 5;

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
			/* do not accept more than two arguments without option name */
			usage();
			goto error;
		}
	}

	/* test ROHC feedback-only decompression */
	status = test_decomp(rohc_feedback, rohc_feedback_len);

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that feedback-only packets are decompressed as expected\n"
	        "\n"
	        "usage: test_decompress_feedback_only [OPTIONS]\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with the given ROHC feedback packet
 *
 * @param rohc_feedback      The ROHC feedback data
 * @param rohc_feedback_len  The length (in bytes) of the ROHC feedback
 * @return                   0 in case of success,
 *                           1 in case of failure
 */
static int test_decomp(const unsigned char *const rohc_feedback,
                       const size_t rohc_feedback_len)
{
	struct rohc_comp *comp;
	struct rohc_decomp *decomp;

	unsigned char ip_packet[MAX_ROHC_SIZE];
	int ip_size;

	int is_failure = 1;

	/* create the ROHC compressor with MAX_CID = 15 (small CID) */
	comp = rohc_alloc_compressor(15, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto error;
	}

	/* create the ROHC decompressor in bi-directional mode */
	decomp = rohc_alloc_decompressor(comp);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* decompress the ROHC feedback with the ROHC decompressor */
	ip_size = rohc_decompress(decomp,
	                          (unsigned char *) rohc_feedback,
	                          rohc_feedback_len,
	                          ip_packet, MAX_ROHC_SIZE);
	if(ip_size <= 0 && ip_size != ROHC_FEEDBACK_ONLY)
	{
		fprintf(stderr, "failed to decompress ROHC feedback\n");
		goto destroy_decomp;
	}
	fprintf(stderr, "decompression is successful\n");

	/* everything went fine */
	is_failure = 0;

destroy_decomp:
	rohc_free_decompressor(decomp);
destroy_comp:
	rohc_free_compressor(comp);
error:
	return is_failure;
}

