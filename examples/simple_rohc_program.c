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
#include <rohc.h>
#include <rohc_comp.h>


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
	const struct timespec arrival_time = { .tv_sec = 0, .tv_nsec = 0 };

	struct rohc_comp *compressor;           /* the ROHC compressor */
	unsigned char ip_packet[BUFFER_SIZE];   /* the buffer that will contain
	                                           the IPv4 packet to compress */
	size_t ip_packet_len;                   /* the length (in bytes) of the
	                                           IPv4 packet */
	unsigned char rohc_packet[BUFFER_SIZE]; /* the buffer that will contain
	                                           the resulting ROHC packet */
	size_t rohc_packet_len;                 /* the length (in bytes) of the
	                                           resulting ROHC packet */
	unsigned int seed;
	size_t i;
	int ret;

	/* initialize the random generator */
	seed = time(NULL);
	srand(seed);

	/* Create a ROHC compressor with small CIDs, no jamming and no adaptation
	 * to encapsulation frames.
	 *
	 * See http://rohc-lib.org/doc/latest/group__rohc__comp.html#ga721fd34fc0cd9e1d789b693eb6bb6485
	 * for details about rohc_alloc_compressor in the API documentation.
	 */
	printf("\ncreate the ROHC compressor\n");
	compressor = rohc_alloc_compressor(ROHC_SMALL_CID_MAX, 0, 0, 0);
	if(compressor == NULL)
	{
		fprintf(stderr, "failed create the ROHC compressor\n");
		goto error;
	}

	/* set the callback for random numbers */
	if(!rohc_comp_set_random_cb(compressor, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto release_compressor;
	}

	/* Enable the compression profiles you need (comment or uncomment some lines).
	 *
	 * See http://rohc-lib.org/doc/latest/group__rohc__comp.html#ga1a444eb91681521f726712a60a4df867
	 * for details about rohc_activate_profile in the API documentation.
	 */
	printf("\nenable several ROHC compression profiles\n");
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_UNCOMPRESSED))
	{
		fprintf(stderr, "failed to enable the Uncompressed profile\n");
		goto release_compressor;
	}
#if 0
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_RTP))
	{
		fprintf(stderr, "failed to enable the IP/UDP/RTP profile\n");
		goto release_compressor;
	}
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_UDP))
	{
		fprintf(stderr, "failed to enable the IP/UDP profile\n");
		goto release_compressor;
	}
#endif
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_IP))
	{
		fprintf(stderr, "failed to enable the IP-only profile\n");
		goto release_compressor;
	}
#if 0
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_UDPLITE))
	{
		fprintf(stderr, "failed to enable the IP/UDP-Lite profile\n");
		goto release_compressor;
	}
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_ESP))
	{
		fprintf(stderr, "failed to enable the IP/ESP profile\n");
		goto release_compressor;
	}
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_TCP))
	{
		fprintf(stderr, "failed to enable the IP/TCP profile\n");
		goto release_compressor;
	}
#endif


	/* create a fake IP packet for the purpose of this simple program */
	printf("\nbuild a fake IP packet\n");
	ip_packet[0] = 4 << 4; /* IP version 4 */
	ip_packet[0] |= 5; /* IHL: minimal IPv4 header length (in 32-bit words) */
	ip_packet[1] = 0; /* TOS */
	ip_packet_len = 5 * 4 + strlen(FAKE_PAYLOAD);
	ip_packet[2] = (ip_packet_len >> 8) & 0xff; /* Total Length */
	ip_packet[3] = ip_packet_len & 0xff;
	ip_packet[4] = 0; /* IP-ID */
	ip_packet[5] = 0;
	ip_packet[6] = 0; /* Fragment Offset and IP flags */
	ip_packet[7] = 0;
	ip_packet[8] = 1; /* TTL */
	ip_packet[9] = 134; /* Protocol: unassigned number */
	ip_packet[10] = 0xbe; /* fake Checksum */
	ip_packet[11] = 0xef;
	ip_packet[12] = 0x01; /* Source address */
	ip_packet[13] = 0x02;
	ip_packet[14] = 0x03;
	ip_packet[15] = 0x04;
	ip_packet[16] = 0x05; /* Destination address */
	ip_packet[17] = 0x06;
	ip_packet[18] = 0x07;
	ip_packet[19] = 0x08;

	/* copy the payload just after the IP header */
	memcpy(ip_packet + 5 * 4, FAKE_PAYLOAD, strlen(FAKE_PAYLOAD));

	/* dump the newly-created IP packet on terminal */
	for(i = 0; i < ip_packet_len; i++)
	{
		printf("0x%02x ", ip_packet[i]);
		if(i != 0 && ((i + 1) % 8) == 0)
		{
			printf("\n");
		}
	}
	if(i != 0 && ((i + 1) % 8) != 0) /* be sure to go to the line */
	{
		printf("\n");
	}


	/* Now, compress this fake IP packet.
	 *
	 * See http://rohc-lib.org/doc/latest/group__rohc__comp.html#ga99be8242b7bc4f442f4519461a99726b
	 * for details about rohc_compress in the API documentation.
	 */
	printf("\ncompress the fake IP packet\n");
	ret = rohc_compress3(compressor, arrival_time, ip_packet, ip_packet_len,
	                     rohc_packet, BUFFER_SIZE, &rohc_packet_len);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "compression of fake IP packet failed\n");
		goto release_compressor;
	}


	/* dump the ROHC packet on terminal */
	printf("\nROHC packet resulting from the ROHC compression:\n");
	for(i = 0; i < rohc_packet_len; i++)
	{
		printf("0x%02x ", rohc_packet[i]);
		if(i != 0 && ((i + 1) % 8) == 0)
		{
			printf("\n");
		}
	}
	if(i != 0 && ((i + 1) % 8) != 0) /* be sure to go to the line */
	{
		printf("\n");
	}


	/* Release the ROHC compressor when you do not need it anymore.
	 *
	 * See http://rohc-lib.org/doc/latest/group__rohc__comp.html#ga736ea1760d7af54ad903c29765df5bd3
	 * for details about rohc_free_compressor in the API documentation.
	 */
	printf("\n\ndestroy the ROHC decompressor\n");
	rohc_free_compressor(compressor);


	printf("\nThe program ended successfully. The ROHC packet is larger than the "
	       "IP packet (39 bytes versus 38 bytes). This is expected since we only "
	       "compress one packet in this simple example. Keep in mind that ROHC "
	       "is designed to compress streams of packets not one single packet.\n\n");

	return 0;

release_compressor:
	rohc_free_compressor(compressor);
error:
	fprintf(stderr, "an error occured during program execution, "
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

