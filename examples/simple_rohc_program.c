/*
 * Copyright 2011,2012,2013,2014 Didier Barvaux
 * Copyright 2010,2012 Viveris Technologies
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
 * @file     simple_rohc_program.c
 * @brief    A simple program that uses the compression part of the ROHC library
 * @author   Didier Barvaux <didier@barvaux.org>
 *
 * This simple program was first published on the mailing list dedicated to the
 * ROHC library. Ask your questions about this example there.
 *
 * Mailing list subscription:     http://launchpad.net/~rohc/+join
 * Mailing list public archives:  http://lists.launchpad.net/rohc/
 */

/**
 * @example simple_rohc_program.c
 *
 * How to compress one IP packet into one ROHC packet.
 */

/* system includes */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "config.h" /* for HAVE_*_H definitions */

#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for htons() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for htons() on Linux */
#endif

/* includes required to use the compression part of the ROHC library */
#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>


/** The size (in bytes) of the buffers used in the program */
#define BUFFER_SIZE 2048

/** The payload for the fake IP packet */
#define FAKE_PAYLOAD "hello, ROHC world!"


static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context);



/**
 * @brief The main entry point for the simple ROHC program
 *
 * @param argc  The number of arguments given to the program
 * @param argv  The table of arguments given to the program
 * @return      0 in case of success, 1 otherwise
 */
int main(int argc, char **argv)
{
//! [define ROHC compressor]
	struct rohc_comp *compressor;           /* the ROHC compressor */
//! [define ROHC compressor]
//! [define IP and ROHC packets]
	/* the buffer that will contain the IPv4 packet to compress */
	unsigned char ip_buffer[BUFFER_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);
	/* the buffer that will contain the resulting ROHC packet */
	unsigned char rohc_buffer[BUFFER_SIZE];
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);
//! [define IP and ROHC packets]
	unsigned int seed;
	size_t i;
	rohc_status_t status;

	/* initialize the random generator */
	seed = time(NULL);
	srand(seed);

	/* Create a ROHC compressor with small CIDs and the largest MAX_CID
	 * possible for small CIDs */
	printf("\ncreate the ROHC compressor\n");
//! [create ROHC compressor]
	compressor = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                            gen_random_num, NULL);
	if(compressor == NULL)
	{
		fprintf(stderr, "failed create the ROHC compressor\n");
		goto error;
	}
//! [create ROHC compressor]

	/* Enable the compression profiles you need */
	printf("\nenable several ROHC compression profiles\n");
//! [enable ROHC compression profile]
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_UNCOMPRESSED))
	{
		fprintf(stderr, "failed to enable the Uncompressed profile\n");
		goto release_compressor;
	}
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_IP))
	{
		fprintf(stderr, "failed to enable the IP-only profile\n");
		goto release_compressor;
	}
//! [enable ROHC compression profile]
//! [enable ROHC compression profiles]
	if(!rohc_comp_enable_profiles(compressor, ROHC_PROFILE_UDP,
	                              ROHC_PROFILE_UDPLITE, -1))
	{
		fprintf(stderr, "failed to enable the IP/UDP and IP/UDP-Lite "
		        "profiles\n");
		goto release_compressor;
	}
//! [enable ROHC compression profiles]


	/* create a fake IP packet for the purpose of this simple program */
	printf("\nbuild a fake IP packet\n");
	rohc_buf_byte_at(ip_packet, 0) = 4 << 4; /* IP version 4 */
	rohc_buf_byte_at(ip_packet, 0) |= 5; /* IHL: min. IPv4 header length
	                                        (in 32-bit words) */
	rohc_buf_byte_at(ip_packet, 1) = 0; /* TOS */
	ip_packet.len = 5 * 4 + strlen(FAKE_PAYLOAD);
	rohc_buf_byte_at(ip_packet, 2) = (ip_packet.len >> 8) & 0xff; /* Total Length */
	rohc_buf_byte_at(ip_packet, 3) = ip_packet.len & 0xff;
	rohc_buf_byte_at(ip_packet, 4) = 0; /* IP-ID */
	rohc_buf_byte_at(ip_packet, 5) = 0;
	rohc_buf_byte_at(ip_packet, 6) = 0; /* Fragment Offset and IP flags */
	rohc_buf_byte_at(ip_packet, 7) = 0;
	rohc_buf_byte_at(ip_packet, 8) = 1; /* TTL */
	rohc_buf_byte_at(ip_packet, 9) = 134; /* Protocol: unassigned number */
	rohc_buf_byte_at(ip_packet, 10) = 0xa9; /* IP Checksum */
	rohc_buf_byte_at(ip_packet, 11) = 0x3f;
	rohc_buf_byte_at(ip_packet, 12) = 0x01; /* Source address */
	rohc_buf_byte_at(ip_packet, 13) = 0x02;
	rohc_buf_byte_at(ip_packet, 14) = 0x03;
	rohc_buf_byte_at(ip_packet, 15) = 0x04;
	rohc_buf_byte_at(ip_packet, 16) = 0x05; /* Destination address */
	rohc_buf_byte_at(ip_packet, 17) = 0x06;
	rohc_buf_byte_at(ip_packet, 18) = 0x07;
	rohc_buf_byte_at(ip_packet, 19) = 0x08;

	/* copy the payload just after the IP header */
	memcpy(rohc_buf_data_at(ip_packet, 5 * 4), FAKE_PAYLOAD, strlen(FAKE_PAYLOAD));

	/* dump the newly-created IP packet on terminal */
	for(i = 0; i < ip_packet.len; i++)
	{
		printf("0x%02x ", rohc_buf_byte_at(ip_packet, i));
		if(i != 0 && ((i + 1) % 8) == 0)
		{
			printf("\n");
		}
	}
	if(i != 0 && ((i + 1) % 8) != 0) /* be sure to go to the line */
	{
		printf("\n");
	}


	/* Now, compress this fake IP packet */
	printf("\ncompress the fake IP packet\n");
//! [compress IP packet #1]
	status = rohc_compress4(compressor, ip_packet, &rohc_packet);
//! [compress IP packet #1]
//! [compress IP packet #2]
	if(status == ROHC_STATUS_SEGMENT)
	{
		/* success: compression succeeded, but resulting ROHC packet was too
		 * large for the Maximum Reconstructed Reception Unit (MRRU) configured
		 * with \ref rohc_comp_set_mrru, the rohc_packet buffer contains the
		 * first ROHC segment and \ref rohc_comp_get_segment can be used to
		 * retrieve the next ones. */
//! [compress IP packet #2]
//! [compress IP packet #3]
	}
	else if(status == ROHC_STATUS_OK)
	{
		/* success: compression succeeded, and resulting ROHC packet fits the
		 * Maximum Reconstructed Reception Unit (MRRU) configured with
		 * \ref rohc_comp_set_mrru, the rohc_packet buffer contains the
		 * rohc_packet_len bytes of the ROHC packet */
//! [compress IP packet #3]

		/* dump the ROHC packet on terminal */
		printf("\nROHC packet resulting from the ROHC compression:\n");
		for(i = 0; i < rohc_packet.len; i++)
		{
			printf("0x%02x ", rohc_buf_byte_at(rohc_packet, i));
			if(i != 0 && ((i + 1) % 8) == 0)
			{
				printf("\n");
			}
		}
		if(i != 0 && ((i + 1) % 8) != 0) /* be sure to go to the line */
		{
			printf("\n");
		}
//! [compress IP packet #4]
	}
	else
	{
		/* compressor failed to compress the IP packet */
//! [compress IP packet #4]
		fprintf(stderr, "compression of fake IP packet failed\n");
		goto release_compressor;
//! [compress IP packet #5]
	}
//! [compress IP packet #5]



	/* Release the ROHC compressor when you do not need it anymore */
	printf("\n\ndestroy the ROHC decompressor\n");
//! [destroy ROHC compressor]
	rohc_comp_free(compressor);
//! [destroy ROHC compressor]


	printf("\nThe program ended successfully. The ROHC packet is larger than the "
	       "IP packet (39 bytes versus 38 bytes). This is expected since we only "
	       "compress one packet in this simple example. Keep in mind that ROHC "
	       "is designed to compress streams of packets not one single packet.\n\n");

	return 0;

release_compressor:
	rohc_comp_free(compressor);
error:
	fprintf(stderr, "an error occurred during program execution, "
	        "abort program\n");
	return 1;
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
	return rand();
}

