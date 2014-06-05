/*
 * Copyright 2013,2014 Didier Barvaux
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
 * @file     example_rohc_decomp.c
 * @brief    A program that uses the decompression part of the ROHC library
 * @author   Didier Barvaux <didier@barvaux.org>
 */

/**
 * @example example_rohc_decomp.c
 *
 * How to decompress one ROHC packet into one IP packet.
 */

/* system includes */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

/* includes required to use the decompression part of the ROHC library */
#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>


/** The size (in bytes) of the buffers used in the program */
#define BUFFER_SIZE 2048

/** The payload for the fake IP packet */
#define FAKE_PAYLOAD "hello, ROHC world!"


/* dump the given network packet on standard output */
static void dump_packet(const struct rohc_buf packet);


/**
 * @brief The main entry point for the program
 *
 * @param argc  The number of arguments given to the program
 * @param argv  The table of arguments given to the program
 * @return      0 in case of success, 1 otherwise
 */
int main(int argc, char **argv)
{
//! [define ROHC decompressor]
	struct rohc_decomp *decompressor;       /* the ROHC decompressor */
//! [define ROHC decompressor]

//! [define IP and ROHC packets]
	/* the buffer that will contain the ROHC packet to decompress */
	unsigned char rohc_buffer[BUFFER_SIZE];
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);
	/* the buffer that will contain the resulting IP packet */
	unsigned char ip_buffer[BUFFER_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);
	/* we do not want to handle feedback in this simple example */
	struct rohc_buf *rcvd_feedback = NULL;
	struct rohc_buf *feedback_send = NULL;
//! [define IP and ROHC packets]

	size_t i;
	int ret;

//! [create ROHC decompressor #1]
	/* Create a ROHC decompressor to operate:
	 *  - with large CIDs,
	 *  - with the maximum of 5 streams (MAX_CID = 4),
	 *  - in Unidirectional mode (U-mode),
	 *  - with no feedback channel.
	 */
//! [create ROHC decompressor #1]
	printf("\ncreate the ROHC decompressor\n");
//! [create ROHC decompressor #2]
	decompressor = rohc_decomp_new(ROHC_LARGE_CID, 4, ROHC_U_MODE, NULL);
	if(decompressor == NULL)
	{
		fprintf(stderr, "failed create the ROHC decompressor\n");
		goto error;
	}
//! [create ROHC decompressor #2]

	/* Enable the decompression profiles you need */
	printf("\nenable several ROHC decompression profiles\n");
//! [enable ROHC decompression profile]
	if(!rohc_decomp_enable_profile(decompressor, ROHC_PROFILE_UNCOMPRESSED))
	{
		fprintf(stderr, "failed to enable the Uncompressed profile\n");
		goto release_decompressor;
	}
	if(!rohc_decomp_enable_profile(decompressor, ROHC_PROFILE_IP))
	{
		fprintf(stderr, "failed to enable the IP-only profile\n");
		goto release_decompressor;
	}
//! [enable ROHC decompression profile]
//! [enable ROHC decompression profiles]
	if(!rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDP,
	                                ROHC_PROFILE_UDPLITE, -1))
	{
		fprintf(stderr, "failed to enable the IP/UDP and IP/UDP-Lite "
		        "profiles\n");
		goto release_decompressor;
	}
//! [enable ROHC decompression profiles]


	/* create a fake ROHC packet for the purpose of this program */
	printf("\nbuild a fake ROHC packet\n");
	rohc_packet.len = 0;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0xfd;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x00;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x04;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0xf7;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x40;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x02;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0xc0;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0xa8;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x13;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x01;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0xc0;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0xa8;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x13;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x05;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x00;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x40;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x00;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x00;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0xa0;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x00;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x00;
	rohc_buf_byte_at(rohc_packet, rohc_packet.len++) = 0x01;

	/* copy the payload just after the IP header */
	memcpy(rohc_buf_data_at(rohc_packet, rohc_packet.len), FAKE_PAYLOAD,
	       strlen(FAKE_PAYLOAD));
	rohc_packet.len += strlen(FAKE_PAYLOAD);

	/* dump the newly-created ROHC packet on terminal */
	for(i = 0; i < rohc_packet.len; i++)
	{
		printf("0x%02x ", rohc_buf_byte_at(rohc_packet,i));
		if(i != 0 && ((i + 1) % 8) == 0)
		{
			printf("\n");
		}
	}
	if(i != 0 && ((i + 1) % 8) != 0) /* be sure to go to the line */
	{
		printf("\n");
	}


	/* Now, decompress this fake ROHC packet */
	printf("\ndecompress the fake ROHC packet\n");
//! [decompress ROHC packet #1]
	ret = rohc_decompress3(decompressor, rohc_packet, &ip_packet,
	                       rcvd_feedback, feedback_send);
//! [decompress ROHC packet #1]
	printf("\n");
//! [decompress ROHC packet #2]
	if(ret == ROHC_OK)
	{
		/* decompression is successful */
		if(!rohc_buf_is_empty(ip_packet))
		{
			/* ip_packet.len bytes of decompressed IP data available in
			 * ip_packet: dump the IP packet on the standard output */
			printf("IP packet resulting from the ROHC decompression:\n");
			dump_packet(ip_packet);
		}
		else
		{
			/* no IP packet was decompressed because of ROHC segmentation or
			 * feedback-only packet:
			 *  - the ROHC packet was a non-final segment, so at least another
			 *    ROHC segment is required to be able to decompress the full
			 *    ROHC packet
			 *  - the ROHC packet was a feedback-only packet, it contained only
			 *    feedback information, so there was nothing to decompress */
			printf("no IP packet decompressed");
		}
	}
	else
	{
		/* failure: decompressor failed to decompress the ROHC packet */
		fprintf(stderr, "decompression of fake ROHC packet failed\n");
//! [decompress ROHC packet #2]
		goto release_decompressor;
//! [decompress ROHC packet #3]
	}
//! [decompress ROHC packet #3]


	/* Release the ROHC decompressor when you do not need it anymore */
	printf("\n\ndestroy the ROHC decompressor\n");
//! [destroy ROHC decompressor]
	rohc_decomp_free(decompressor);
//! [destroy ROHC decompressor]


	printf("\nThe program ended successfully.\n");

	return 0;

release_decompressor:
	rohc_decomp_free(decompressor);
error:
	fprintf(stderr, "an error occured during program execution, "
	        "abort program\n");
	return 1;
}


/**
 * @brief Dump the given network packet on standard output
 *
 * @param packet  The packet to dump
 */
static void dump_packet(const struct rohc_buf packet)
{
	size_t i;

	for(i = 0; i < packet.len; i++)
	{
		printf("0x%02x ", rohc_buf_byte_at(packet, i));
		if(i != 0 && ((i + 1) % 8) == 0)
		{
			printf("\n");
		}
	}
	if(i != 0 && ((i + 1) % 8) != 0) /* be sure to go to the line */
	{
		printf("\n");
	}
}

