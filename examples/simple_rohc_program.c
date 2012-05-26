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

/* includes required to create a fake IP packet */
#include <netinet/ip.h>
#include <string.h>

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
	struct rohc_comp *compressor;           /* the ROHC compressor */
	unsigned char ip_packet[BUFFER_SIZE];   /* the buffer that will contain
	                                           the IPv4 packet to compress */
	unsigned int ip_packet_len;             /* the length (in bytes) of the
	                                           IPv4 packet */
	struct iphdr *ip_header;                /* the header of the IPv4 packet */
	unsigned char rohc_packet[BUFFER_SIZE]; /* the buffer that will contain
	                                           the resulting ROHC packet */
	int rohc_packet_len;                    /* the length (in bytes) of the
	                                           resulting ROHC packet */
	unsigned int seed;
	unsigned int i;

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
	rohc_activate_profile(compressor, ROHC_PROFILE_UNCOMPRESSED);
	//rohc_activate_profile(compressor, ROHC_PROFILE_UDP);
	rohc_activate_profile(compressor, ROHC_PROFILE_IP);
	//rohc_activate_profile(compressor, ROHC_PROFILE_UDPLITE);
	//rohc_activate_profile(compressor, ROHC_PROFILE_RTP);


	/* create a fake IP packet for the purpose of this simple program */
	printf("\nbuild a fake IP packet\n");
	ip_header = (struct iphdr *) ip_packet;
	ip_header->version = 4; /* we create an IPv4 header */
	ip_header->ihl = 5; /* minimal IPv4 header length (in 32-bit words) */
	ip_header->tos = 0;
	ip_packet_len = ip_header->ihl * 4 + strlen(FAKE_PAYLOAD);
	ip_header->tot_len = htons(ip_packet_len);
	ip_header->id = 0;
	ip_header->frag_off = 0;
	ip_header->ttl = 1;
	ip_header->protocol = 134; /* unassigned number according to /etc/protocols */
	ip_header->check = 0; /* set to 0 for checksum computation */
	ip_header->saddr = htonl(0x01020304);
	ip_header->daddr = htonl(0x05060708);

	/* header is now built, put a fake IP checksum for this example */
	ip_header->check = 0xbeef;

	/* copy the payload just after the IP header */
	memcpy(ip_packet + ip_header->ihl * 4, FAKE_PAYLOAD, strlen(FAKE_PAYLOAD));

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
	rohc_packet_len = rohc_compress(compressor,
	                                ip_packet, ip_packet_len,
	                                rohc_packet, BUFFER_SIZE);
	if(rohc_packet_len <= 0)
	{
		fprintf(stderr, "compression of fake IP packet failed\n");
		goto release_compressor;
	}


	/* dump the ROHC packet on terminal */
	printf("\nROHC packet resulting from the ROHC compression:\n");
	for(i = 0; i < ((unsigned int) rohc_packet_len); i++)
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

