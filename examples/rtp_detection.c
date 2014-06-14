/*
 * Copyright 2014 Viveris Technologies
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
 * @file     rtp_detection.c
 * @brief    A simple program that uses the RTP detection capabilities of the
 *           ROHC library
 * @author   Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author   Didier Barvaux <didier@barvaux.org>
 */

/**
 * @example rtp_detection.c
 *
 * How to compress one IP/UDP/RTP packet with the ROHC RTP profile. The example
 * performs this twice: once with a list of UDP ports, then with a user-defined
 * callback.
 */

/* system includes */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>

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


static struct rohc_comp * create_compressor(void)
	__attribute__((warn_unused_result));

static void create_packet(struct rohc_buf *const packet);

static bool compress_with_rtp_ports(struct rohc_comp *const compressor,
                                    const struct rohc_buf packet)
	__attribute__((warn_unused_result, nonnull(1)));

static bool compress_with_callback(struct rohc_comp *const compressor,
                                   const struct rohc_buf packet)
	__attribute__((warn_unused_result, nonnull(1)));

/* user-defined function callbacks for the ROHC library */
static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((warn_unused_result));
static bool rtp_detect(const unsigned char *const ip,
                       const unsigned char *const udp,
                       const unsigned char *payload,
                       const unsigned int payload_size,
                       void *const rtp_private)
	__attribute__((warn_unused_result));



/**
 * @brief The main entry point for the RTP detection program
 *
 * @param argc  The number of arguments given to the program
 * @param argv  The table of arguments given to the program
 * @return      0 in case of success, 1 otherwise
 */
int main(int argc, char **argv)
{
	struct rohc_comp *compressor;  /* the ROHC compressor */

	/* the buffer that will contain the IPv4 packet to compress */
	uint8_t ip_buffer[BUFFER_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);

//! [define random callback 1]
	unsigned int seed;

	/* initialize the random generator */
	seed = time(NULL);
	srand(seed);
//! [define random callback 1]

	/* create a ROHC compressor with small CIDs and the largest MAX_CID
	 * possible for small CIDs */
	printf("\ncreate the ROHC compressor\n");
	compressor = create_compressor();
	if(compressor == NULL)
	{
		fprintf(stderr, "failed create the ROHC compressor\n");
		goto error;
	}

	/* create a fake IP packet for the purpose of this example program */
	printf("\nbuild a fake IP/UDP/RTP packet\n");
	create_packet(&ip_packet);

	/* compress the RTP packet with a list of UDP ports to detect the RTP
	 * packets */
	if(!compress_with_rtp_ports(compressor, ip_packet))
	{
		fprintf(stderr, "compression with detection by UDP ports failed\n");
		goto release_compressor;
	}

	/* now, let's do the same with a user-defined callback to detect the
	 * RTP packets */
	if(!compress_with_callback(compressor, ip_packet))
	{
		fprintf(stderr, "compression with detection by UDP ports failed\n");
		goto release_compressor;
	}

	/* release the ROHC compressor when you do not need it anymore */
	printf("\n\ndestroy the ROHC decompressor\n");
	rohc_comp_free(compressor);

	return 0;

release_compressor:
	rohc_comp_free(compressor);
error:
	fprintf(stderr, "an error occured during program execution, "
	        "abort program\n");
	return 1;
}


/**
 * @brief Create and configure one ROHC compressor
 *
 * @return  The created and configured ROHC compressor
 */
static struct rohc_comp * create_compressor(void)
{
	struct rohc_comp *compressor;

	/* create the ROHC compressor */
	compressor = rohc_comp_new(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX);
	if(compressor == NULL)
	{
		fprintf(stderr, "failed create the ROHC compressor\n");
		goto error;
	}

	/* set the callback for traces on compressor */
//! [set compression traces callback]
	if(!rohc_comp_set_traces_cb(compressor, print_rohc_traces))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "compressor\n");
		goto release_compressor;
	}
//! [set compression traces callback]

//! [set random callback]
	/* set the callback for random numbers */
	if(!rohc_comp_set_random_cb(compressor, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto release_compressor;
	}
//! [set random callback]

	/* enable the RTP compression profile */
	printf("\nenable the ROHC RTP compression profile\n");
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_RTP))
	{
		fprintf(stderr, "failed to enable the IP/UDP/RTP profile\n");
		goto release_compressor;
	}

	return compressor;

release_compressor:
	rohc_comp_free(compressor);
error:
	return NULL;
}


/**
 * @brief Create a fake IP/UDP/RTP packet for testing purposes
 *
 * @param packet  The IP/UDP/RTP packet
 */
static void create_packet(struct rohc_buf *const packet)
{
	packet->len = 5 * 4 + 8 + 12 + strlen(FAKE_PAYLOAD);

	/* IPv4 header */
	rohc_buf_byte_at(*packet, 0) = 4 << 4; /* IP version 4 */
	rohc_buf_byte_at(*packet, 0) |= 5; /* IHL: minimal IPv4 header length (in 32-bit words) */
	rohc_buf_byte_at(*packet, 1) = 0; /* TOS */
	rohc_buf_byte_at(*packet, 2) = (packet->len >> 8) & 0xff; /* Total Length */
	rohc_buf_byte_at(*packet, 3) = packet->len & 0xff;
	rohc_buf_byte_at(*packet, 4) = 0; /* IP-ID */
	rohc_buf_byte_at(*packet, 5) = 0;
	rohc_buf_byte_at(*packet, 6) = 0; /* Fragment Offset and IP flags */
	rohc_buf_byte_at(*packet, 7) = 0;
	rohc_buf_byte_at(*packet, 8) = 1; /* TTL */
	rohc_buf_byte_at(*packet, 9) = 17; /* Protocol: UDP */
	rohc_buf_byte_at(*packet, 10) = 0xa9; /* fake Checksum */
	rohc_buf_byte_at(*packet, 11) = 0xa0;
	rohc_buf_byte_at(*packet, 12) = 0x01; /* Source address */
	rohc_buf_byte_at(*packet, 13) = 0x02;
	rohc_buf_byte_at(*packet, 14) = 0x03;
	rohc_buf_byte_at(*packet, 15) = 0x04;
	rohc_buf_byte_at(*packet, 16) = 0x05; /* Destination address */
	rohc_buf_byte_at(*packet, 17) = 0x06;
	rohc_buf_byte_at(*packet, 18) = 0x07;
	rohc_buf_byte_at(*packet, 19) = 0x08;

	/* UDP header */
	rohc_buf_byte_at(*packet, 20) = 0x42; /* source port */
	rohc_buf_byte_at(*packet, 21) = 0x42;
	rohc_buf_byte_at(*packet, 22) = 0x27; /* destination port = 10042 */
	rohc_buf_byte_at(*packet, 23) = 0x3a;
	rohc_buf_byte_at(*packet, 24) = 0x00; /* UDP length */
	rohc_buf_byte_at(*packet, 25) = 8 + 12 + strlen(FAKE_PAYLOAD);
	rohc_buf_byte_at(*packet, 26) = 0x00; /* UDP checksum = 0 */
	rohc_buf_byte_at(*packet, 27) = 0x00;

	/* RTP header */
	rohc_buf_byte_at(*packet, 28) = 0x80;
	rohc_buf_byte_at(*packet, 29) = 0x00;
	rohc_buf_byte_at(*packet, 30) = 0x00;
	rohc_buf_byte_at(*packet, 31) = 0x2d;
	rohc_buf_byte_at(*packet, 32) = 0x00;
	rohc_buf_byte_at(*packet, 33) = 0x00;
	rohc_buf_byte_at(*packet, 34) = 0x01;
	rohc_buf_byte_at(*packet, 35) = 0x2c;
	rohc_buf_byte_at(*packet, 36) = 0x00;
	rohc_buf_byte_at(*packet, 37) = 0x00;
	rohc_buf_byte_at(*packet, 38) = 0x00;
	rohc_buf_byte_at(*packet, 39) = 0x00;

	/* copy the payload just after the IP/UDP/RTP headers */
	memcpy(rohc_buf_data_at(*packet, 40), FAKE_PAYLOAD, strlen(FAKE_PAYLOAD));
}


/**
 * @brief Compress one IP/UDP/RTP packet (detection with UDP ports)
 *
 * @param compressor     The ROHC compressor
 * @param uncomp_packet  The IP/UDP/RTP packet to compress
 * @return               true if the compression is successful,
 *                       false if the compression failed
 */
static bool compress_with_rtp_ports(struct rohc_comp *const compressor,
                                    const struct rohc_buf uncomp_packet)
{
	uint8_t rohc_buffer[BUFFER_SIZE];
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);
	int ret;

	/* reset list of UDP ports dedicated to RTP streams */
	printf("\nreset the list of UDP ports dedicated to RTP streams\n");
//! [reset RTP ports]
	if(!rohc_comp_reset_rtp_ports(compressor))
	{
		fprintf(stderr, "failed to reset list of RTP ports\n");
		goto error;
	}
//! [reset RTP ports]

	/* add UDP ports 1234 and 10042 to the list of RTP ports */
	printf("\nadd ports 1234 and 10042 to the list of UDP ports dedicated "
	       "to RTP streams\n");
//! [add RTP port]
	if(!rohc_comp_add_rtp_port(compressor, 1234))
	{
		fprintf(stderr, "failed to enable RTP port 1234\n");
		goto error;
	}
	if(!rohc_comp_add_rtp_port(compressor, 10042))
	{
		fprintf(stderr, "failed to enable RTP port 10042\n");
		goto error;
	}
//! [add RTP port]

	/* remove UDP port 1234 (for example purposes) */
	printf("\nremove port 1234 from the list of UDP ports dedicated "
	       "to RTP streams\n");
//! [remove RTP port]
	if(!rohc_comp_remove_rtp_port(compressor, 1234))
	{
		fprintf(stderr, "failed to remove RTP port 1234\n");
		goto error;
	}
//! [remove RTP port]

	/* now, compress this fake IP/UDP/RTP packet with the RTP profile */
	printf("\ncompress the fake IP/UDP/RTP packet\n");
	ret = rohc_compress4(compressor, uncomp_packet, &rohc_packet);
	if(ret == ROHC_NEED_SEGMENT)
	{
		fprintf(stderr, "unexpected ROHC segment\n");
		goto error;
	}
	else if(ret == ROHC_OK)
	{
		printf("\nIP/UDP/RTP packet successfully compressed\n");
	}
	else
	{
		/* compressor failed to compress the IP packet */
		fprintf(stderr, "compression of fake IP/UDP/RTP packet failed\n");
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Compress one IP/UDP/RTP packet (detection with callback)
 *
 * @param compressor     The ROHC compressor
 * @param uncomp_packet  The IP/UDP/RTP packet to compress
 * @return               true if the compression is successful,
 *                       false if the compression failed
 */
static bool compress_with_callback(struct rohc_comp *const compressor,
                                   const struct rohc_buf uncomp_packet)
{
	uint8_t rohc_buffer[BUFFER_SIZE];
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);
	int ret;

	/* reset the list of UDP ports dedicated to RTP streams */
	printf("\nreset the list of UDP ports dedicated to RTP streams\n");
	if(!rohc_comp_reset_rtp_ports(compressor))
	{
		fprintf(stderr, "failed to reset list of RTP ports\n");
		goto error;
	}

	/* define the user-defined function that the ROHC compressor shall
	 * call for every UDP packet in order to detect RTP packets */
	printf("\ndefine the RTP detection callback\n");
//! [set RTP detection callback]
	if(!rohc_comp_set_rtp_detection_cb(compressor, rtp_detect, NULL))
	{
		fprintf(stderr, "failed to set RTP detection callback\n");
		goto error;
	}
//! [set RTP detection callback]

	/* then, compress the fake IP/UDP/RTP packet with the RTP profile */
	printf("\ncompress the fake IP/UDP/RTP packet\n");
	ret = rohc_compress4(compressor, uncomp_packet, &rohc_packet);
	if(ret == ROHC_NEED_SEGMENT)
	{
		fprintf(stderr, "unexpected ROHC segment\n");
		goto error;
	}
	else if(ret == ROHC_OK)
	{
		printf("\nIP/UDP/RTP packet successfully compressed\n");
	}
	else
	{
		/* compressor failed to compress the IP packet */
		fprintf(stderr, "compression of fake IP/UDP/RTP packet failed\n");
		goto error;
	}

	return true;

error:
	return false;
}


//! [define random callback 2]
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
//! [define random callback 2]


//! [define compression traces callback]
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
//! [define compression traces callback]


//! [define RTP detection callback]
/**
 * @brief The RTP detection callback which does detect RTP stream
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @return             true if the packet is an RTP packet, false otherwise
 */
static bool rtp_detect(const unsigned char *const ip,
                       const unsigned char *const udp,
                       const unsigned char *const payload,
                       const unsigned int payload_size,
                       void *const rtp_private)
{
	uint16_t udp_dport;
	bool is_rtp;

	/* check UDP destination port */
	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));
	if(ntohs(udp_dport) == 10042)
	{
		/* we think that the UDP packet is a RTP packet */
		fprintf(stderr, "RTP packet detected (expected UDP port)\n");
		is_rtp = true;
	}
	else
	{
		/* we think that the UDP packet is not a RTP packet */
		fprintf(stderr, "RTP packet not detected (wrong UDP port)\n");
		is_rtp = false;
	}

	return is_rtp;
}
//! [define RTP detection callback]

