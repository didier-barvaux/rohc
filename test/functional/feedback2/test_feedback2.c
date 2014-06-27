/*
 * Copyright 2011,2012,2013,2014 Didier Barvaux
 * Copyright 2012 Viveris Technologies
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
 * @file   test_feedback2.c
 * @brief  Check that FEEDBACK-2 packets are generated as expected
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application decompresses ROHC packets from a source PCAP file and checks
 * that every decompressed packet generates a FEEDBACK-2 packet of the expected
 * type with the expected feedback options.
 */

#include "test.h"

#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h> /* for time(2) */
#include <stdarg.h>
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h>
#endif
#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h>
#endif
#if HAVE_SYS_TYPES_H == 1
#  include <sys/types.h>
#endif

/* include for the PCAP library */
#if HAVE_PCAP_PCAP_H == 1
#  include <pcap/pcap.h>
#elif HAVE_PCAP_H == 1
#  include <pcap.h>
#else
#  error "pcap.h header not found, did you specified --enable-rohc-tests \
for ./configure ? If yes, check configure output and config.log"
#endif

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>
#include <rohc_packets.h>


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(const char *filename,
                                const rohc_cid_type_t cid_type,
                                const char *expected_type,
                                char **expected_options,
                                const unsigned short expected_options_nr);
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
	char *filename = NULL;
	char *cid_type_name = NULL;
	char *ack_type = NULL;
	char **ack_options = NULL;
	unsigned short ack_options_nr = 0;
	rohc_cid_type_t cid_type;
	int args_read;
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 3)
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
		else if(filename == NULL)
		{
			/* get the name of the file that contains the packets to decompress */
			filename = argv[0];
			args_read = 1;
		}
		else if(cid_type_name == NULL)
		{
			/* get the CID type to use to decompress ROHC packets */
			cid_type_name = argv[0];
			args_read = 1;
		}
		else if(ack_type == NULL)
		{
			/* get the expected type of FEEDBACK-2 packet */
			ack_type = argv[0];
			args_read = 1;
		}
		else if(ack_options == NULL)
		{
			/* get the ACK options (possibly none) */
			ack_options = argv;
			ack_options_nr = argc;
			args_read = argc;
		}
		else
		{
			/* do not accept more than two arguments without option name */
			usage();
			goto error;
		}
	}

	/* the source filename, the CID type and the ACK type are mandatory */
	if(filename == NULL || cid_type_name == NULL || ack_type == NULL)
	{
		usage();
		goto error;
	}

	/* determine if we use small or large CIDs */
	if(strcmp(cid_type_name, "smallcid") == 0)
	{
		cid_type = ROHC_SMALL_CID;
	}
	else if(strcmp(cid_type_name, "largecid") == 0)
	{
		cid_type = ROHC_LARGE_CID;
	}
	else
	{
		fprintf(stderr, "unknown CID type '%s'\n", cid_type_name);
		goto error;
	}

	/* test ROHC decompression with the packets from the file */
	status = test_comp_and_decomp(filename, cid_type, ack_type,
	                              ack_options, ack_options_nr);

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that FEEDBACK-2 packets are generated as expected\n"
	        "\n"
	        "usage: test_feedback2 [OPTIONS] FLOW CID_TYPE ACK_TYPE ACK_OPTIONS\n"
	        "\n"
	        "with:\n"
	        "  FLOW         The flow of Ethernet frames to compress\n"
	        "               (in PCAP format)\n"
	        "  CID_TYPE     The CID type among 'largecid' and 'smallcid'\n"
	        "  ACK_TYPE     The type of FEEDBACK-2 expected among:\n"
	        "               ack\n"
	        "  ACK_OPTIONS  The FEEDBACK-2 options expected among:\n"
	        "               sn\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with a flow of ROHC packets that shall
 *        generate FEEDBACK-2 packets as expected
 *
 * @param filename             The name of the PCAP file that contains the
 *                             ROHC packets
 * @param cid_type             The type of CID to use
 * @param expected_type        The type of acknowledgement that shall be
 *                             generated during the decompression of every
 *                             packet of the source capture
 * @param expected_options     The list of acknowledgement options that shall
 *                             be generated during the decompression of every
 *                             packet of the source capture
 * @param expected_options_nr  The size of the list of acknowledgement options
 * @return                     0 in case of success,
 *                             1 in case of failure
 */
static int test_comp_and_decomp(const char *filename,
                                const rohc_cid_type_t cid_type,
                                const char *expected_type,
                                char **expected_options,
                                const unsigned short expected_options_nr)
{
	const rohc_cid_t max_cid =
		(cid_type == ROHC_SMALL_CID ? ROHC_SMALL_CID_MAX : ROHC_LARGE_CID_MAX);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_comp *comp; /* compressor required only to generate feedback */
	struct rohc_decomp *decomp;

	struct pcap_pkthdr header;
	unsigned char *packet;
	unsigned int counter;

	int is_failure = 1;

	/* open the source dump file */
	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "failed to open the source pcap file: %s\n", errbuf);
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type = pcap_datalink(handle);
	if(link_layer_type != DLT_EN10MB &&
	   link_layer_type != DLT_LINUX_SLL &&
	   link_layer_type != DLT_RAW)
	{
		fprintf(stderr, "link layer type %d not supported in source dump "
		        "(supported = %d, %d, %d)\n", link_layer_type,
		        DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW);
		goto close_input;
	}

	/* determine the length of the link layer header */
	if(link_layer_type == DLT_EN10MB)
	{
		link_len = ETHER_HDR_LEN;
	}
	else if(link_layer_type == DLT_LINUX_SLL)
	{
		link_len = LINUX_COOKED_HDR_LEN;
	}
	else /* DLT_RAW */
	{
		link_len = 0;
	}

	/* initialize the random generator */
	srand(time(NULL));

	/* create the ROHC compressor with small CID */
	comp = rohc_comp_new2(cid_type, max_cid, gen_random_num, NULL);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto close_input;
	}

	/* set the callback for traces on compressor */
	if(!rohc_comp_set_traces_cb2(comp, print_rohc_traces, NULL))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "compressor\n");
		goto destroy_comp;
	}

	/* enable profiles */
	if(!rohc_comp_enable_profiles(comp, ROHC_PROFILE_UNCOMPRESSED,
	                              ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                              ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                              ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles\n");
		goto destroy_comp;
	}

	/* set UDP ports dedicated to RTP traffic */
	if(!rohc_comp_set_rtp_detection_cb(comp, rohc_comp_rtp_cb, NULL))
	{
		fprintf(stderr, "failed to set the callback RTP detection\n");
		goto destroy_comp;
	}


	/* create the ROHC decompressor in bi-directional mode */
	decomp = rohc_decomp_new2(cid_type, max_cid, ROHC_O_MODE);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb2(decomp, print_rohc_traces, NULL))
	{
		fprintf(stderr, "cannot set trace callback for decompressor\n");
		goto destroy_decomp;
	}

	/* enable decompression profiles */
	if(!rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_UNCOMPRESSED,
	                                ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                                ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                                ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the decompression profiles\n");
		goto destroy_decomp;
	}

	/* for each packet in the dump */
	counter = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
		struct rohc_buf rohc_packet =
			rohc_buf_init_full(packet, header.caplen, arrival_time);

		uint8_t ip_buffer[MAX_ROHC_SIZE];
		struct rohc_buf ip_packet =
			rohc_buf_init_empty(ip_buffer, MAX_ROHC_SIZE);

		uint8_t feedback_buf[MAX_ROHC_SIZE];
		struct rohc_buf feedback_send =
			rohc_buf_init_empty(feedback_buf, MAX_ROHC_SIZE);

		uint8_t feedback_code;
		uint8_t feedback_full_len;
		uint8_t feedback_data_len;
		uint8_t feedback_type;

		uint16_t sn;
		unsigned int i;
		unsigned int opt_len;
		unsigned int expected_opt_pos;
		rohc_status_t status;

		counter++;

		fprintf(stderr, "packet #%u:\n", counter);

		/* check the length of the link layer header/frame */
		if(header.len <= link_len || header.len != header.caplen)
		{
			fprintf(stderr, "\ttruncated packet in capture (len = %d, "
			        "caplen = %d)\n", header.len, header.caplen);
			goto destroy_decomp;
		}

		/* skip the link layer header */
		rohc_buf_pull(&rohc_packet, link_len);

		/* decompress the ROHC packet with the ROHC decompressor */
		status = rohc_decompress3(decomp, rohc_packet, &ip_packet,
		                          NULL, &feedback_send);
		if(status != ROHC_STATUS_OK)
		{
			fprintf(stderr, "\tfailed to decompress ROHC packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tdecompression is successful\n");

		/* the decompressor should have generated one feedback */
		if(rohc_buf_is_empty(feedback_send))
		{
			fprintf(stderr, "\tno feedback generated while one was expected\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\t%zu-byte feedback generated\n", feedback_send.len);

		/* feedback header starts with 0b11110 */
		if((rohc_buf_byte(feedback_send) & 0xf8) != 0xf0)
		{
			fprintf(stderr, "\tfeedback should start with the bits 0b11110\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tmagic number 0b11110 found\n");

		feedback_code = rohc_buf_byte(feedback_send) & 0x07;
		if(feedback_code > 0)
		{
			feedback_data_len = feedback_code;
			feedback_full_len = 1 + feedback_data_len;
		}
		else
		{
			fprintf(stderr, "\tadditional Size octet found\n");
			if(feedback_send.len < 2)
			{
				fprintf(stderr, "\tfeedback is not large enough for the Size "
				        "octet\n");
				goto destroy_decomp;
			}
			feedback_data_len = rohc_buf_byte_at(feedback_send, 1);
			feedback_full_len = 1 + 1 + feedback_data_len;
		}
		if(feedback_full_len != feedback_send.len)
		{
			fprintf(stderr, "\tadditional data found at the end of feedback\n");
			goto destroy_decomp;
		}
		rohc_buf_pull(&feedback_send, feedback_full_len - feedback_data_len);

		/* if feedback length is 2 bytes (1-byte header + 1-byte feedback), the
		 * feedback is a FEEDBACK-1 */
		if(feedback_send.len == 2)
		{
			fprintf(stderr, "\tFEEDBACK-2 should be at least 2 byte long\n");
			goto destroy_decomp;
		}

		/* is there a Add-CID octet? */
		if(cid_type == ROHC_LARGE_CID)
		{
			size_t sdvl_size;

			/* determine the size of the SDVL-encoded large CID */
			if((rohc_buf_byte(feedback_send) & 0x80) == 0)
			{
				sdvl_size = 1;
			}
			else if(((rohc_buf_byte(feedback_send) & 0xc0) >> 6) == (0x8 >> 2))
			{
				sdvl_size = 2;
			}
			else if(((rohc_buf_byte(feedback_send) & 0xe0) >> 5) == (0xc >> 1))
			{
				sdvl_size = 3;
			}
			else if(((rohc_buf_byte(feedback_send) & 0xe0) >> 5) == (0xe >> 1))
			{
				sdvl_size = 4;
			}
			else
			{
				fprintf(stderr, "\tinvalid SDVL-encoded value for large CID\n");
				goto destroy_decomp;
			}

			fprintf(stderr, "\tlarge CID found\n");
			rohc_buf_pull(&feedback_send, sdvl_size);
		}
		else
		{
			if(((rohc_buf_byte(feedback_send) & 0xc0) >> 6) == 3)
			{
				/* skip Add-CID */
				fprintf(stderr, "\tAdd-CID found\n");
				rohc_buf_pull(&feedback_send, 1);
			}
		}

		/* check feedback type */
		feedback_type = (rohc_buf_byte(feedback_send) & 0xc0) >> 6;
		switch(feedback_type)
		{
			case 0:
				/* ACK */
				if(strcmp(expected_type, "ack") != 0)
				{
					fprintf(stderr, "\tfeedback type %u found, while type %s "
					        "expected\n", feedback_type, expected_type);
					goto destroy_decomp;
				}
				break;
			case 1:
				/* NACK */
				if(strcmp(expected_type, "nack") != 0)
				{
					fprintf(stderr, "\tfeedback type %u found, while type %s "
					        "expected\n", feedback_type, expected_type);
					goto destroy_decomp;
				}
				break;
			case 2:
				/* STATIC-NACK */
				if(strcmp(expected_type, "staticnack") != 0)
				{
					fprintf(stderr, "\tfeedback type %u found, while type %s "
					        "expected\n", feedback_type, expected_type);
					goto destroy_decomp;
				}
				break;
			default:
				fprintf(stderr, "\tunknown feedback type %u found, while type %s "
				        "expected\n", feedback_type, expected_type);
				goto destroy_decomp;
		}
		fprintf(stderr, "\tFEEDBACK-2 is a %s feedback as expected\n",
		        expected_type);

		sn = ((rohc_buf_byte(feedback_send) & 0x0f) << 8) +
		     (rohc_buf_byte_at(feedback_send, 1) & 0xff);
		fprintf(stderr, "\tSN (or a part of it) = 0x%04x\n", sn);
		rohc_buf_pull(&feedback_send, 2);

		/* parse every feedback options found in the packet */
		expected_opt_pos = 0;
		for(i = 0; i < feedback_send.len; i += opt_len)
		{
			/* is another feedback option expected? */
			if(expected_opt_pos >= expected_options_nr)
			{
				fprintf(stderr, "\tmore options in packet than expected\n");
				goto destroy_decomp;
			}

			/* get option length (1 byte of header + variable data) */
			opt_len = 1 + (rohc_buf_byte_at(feedback_send, i) & 0x0f);

			/* check option type */
			switch((rohc_buf_byte_at(feedback_send, i) & 0xf0) >> 4)
			{
				case 1:
					/* CRC */
					if(strcmp(expected_options[expected_opt_pos], "crc") != 0)
					{
						fprintf(stderr, "\tCRC option found, while %s option "
						        "expected\n", expected_options[expected_opt_pos]);
						goto destroy_decomp;
					}
					fprintf(stderr, "\t%u-byte CRC option found\n", opt_len);
					expected_opt_pos++;
					break;
				case 2:
					/* REJECT */
					if(strcmp(expected_options[expected_opt_pos], "reject") != 0)
					{
						fprintf(stderr, "\tREJECT option found, while %s option "
						        "expected\n", expected_options[expected_opt_pos]);
						goto destroy_decomp;
					}
					fprintf(stderr, "\t%u-byte REJECT option found\n", opt_len);
					expected_opt_pos++;
					break;
				case 3:
					/* SN-NOT-VALID */
					if(strcmp(expected_options[expected_opt_pos], "snnotvalid") != 0)
					{
						fprintf(stderr, "\tSN-NOT-VALID option found, while %s option "
						        "expected\n", expected_options[expected_opt_pos]);
						goto destroy_decomp;
					}
					fprintf(stderr, "\t%u-byte SN-NOT-VALID option found\n", opt_len);
					expected_opt_pos++;
					break;
				case 4:
					/* SN */
					if(strcmp(expected_options[expected_opt_pos], "sn") != 0)
					{
						fprintf(stderr, "\tSN option found, while %s option "
						        "expected\n", expected_options[expected_opt_pos]);
						goto destroy_decomp;
					}
					fprintf(stderr, "\t%u-byte SN option found\n", opt_len);
					expected_opt_pos++;
					break;
				case 5:
					/* CLOCK */
					if(strcmp(expected_options[expected_opt_pos], "clock") != 0)
					{
						fprintf(stderr, "\tCLOCK option found, while %s option "
						        "expected\n", expected_options[expected_opt_pos]);
						goto destroy_decomp;
					}
					fprintf(stderr, "\t%u-byte CLOCK option found\n", opt_len);
					expected_opt_pos++;
					break;
				case 6:
					/* JITTER */
					if(strcmp(expected_options[expected_opt_pos], "jitter") != 0)
					{
						fprintf(stderr, "\tJITTER option found, while %s option "
						        "expected\n", expected_options[expected_opt_pos]);
						goto destroy_decomp;
					}
					fprintf(stderr, "\t%u-byte JITTER option found\n", opt_len);
					expected_opt_pos++;
					break;
				case 7:
					/* LOSS */
					if(strcmp(expected_options[expected_opt_pos], "loss") != 0)
					{
						fprintf(stderr, "\tLOSS option found, while %s option "
						        "expected\n", expected_options[expected_opt_pos]);
						goto destroy_decomp;
					}
					fprintf(stderr, "\t%u-byte LOSS option found\n", opt_len);
					expected_opt_pos++;
					break;
				default:
					/* unknown option: RFC 3095 says to ignore unknown options */
					fprintf(stderr, "\tIgnore unknown %u-byte option of type %u\n",
					        opt_len, (rohc_buf_byte_at(feedback_send, i) & 0xf0) >> 4);
					break;
			}
		}

		feedback_send.data -= feedback_send.offset;
		feedback_send.len = 0;
	}

	/* everything went fine */
	is_failure = 0;

destroy_decomp:
	rohc_decomp_free(decomp);
destroy_comp:
	rohc_comp_free(comp);
close_input:
	pcap_close(handle);
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
static void print_rohc_traces(void *const priv_ctxt __attribute__((unused)),
                              const rohc_trace_level_t level,
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

