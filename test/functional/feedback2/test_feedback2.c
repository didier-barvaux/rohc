/*
 * Copyright 2011,2012,2013,2014 Didier Barvaux
 * Copyright 2012 Viveris Technologies
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h> /* for time(2) */
#include <stdarg.h>

#include "config.h" /* for HAVE_*_H */

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
#include <rohc_comp_internals.h> /* to gain access to feedbacks in struct rohc_comp */
#include <sdvl.h> /* to gain access to d_sdvalue_size() */


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(const char *filename,
                                const rohc_cid_type_t cid_type,
                                const char *expected_type,
                                char **expected_options,
                                const unsigned short expected_options_nr);
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

#define NB_RTP_PORTS 5
	const unsigned int rtp_ports[NB_RTP_PORTS] =
		{ 1234, 36780, 33238, 5020, 5002 };

	int is_failure = 1;
	unsigned int i;

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
	comp = rohc_comp_new(cid_type, max_cid);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto close_input;
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
	                              ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles\n");
		goto destroy_comp;
	}

	/* set the callback for random numbers */
	if(!rohc_comp_set_random_cb(comp, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto destroy_comp;
	}

	/* reset list of RTP ports for compressor */
	if(!rohc_comp_reset_rtp_ports(comp))
	{
		fprintf(stderr, "failed to reset list of RTP ports\n");
		goto destroy_comp;
	}

	/* add some ports to the list of RTP ports */
	for(i = 0; i < NB_RTP_PORTS; i++)
	{
		if(!rohc_comp_add_rtp_port(comp, rtp_ports[i]))
		{
			fprintf(stderr, "failed to enable RTP port %u\n", rtp_ports[i]);
			goto destroy_comp;
		}
	}


	/* create the ROHC decompressor in bi-directional mode */
	decomp = rohc_decomp_new(cid_type, max_cid, ROHC_O_MODE, comp);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb(decomp, print_rohc_traces))
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
		unsigned char *rohc_packet;
		size_t rohc_size;
		static unsigned char ip_packet[MAX_ROHC_SIZE];
		size_t ip_size;

		unsigned char *feedback_data;
		size_t feedback_size;
		unsigned int feedback_type;
		unsigned int feedback_data_pos = 0;
		uint16_t sn;
		unsigned int i;
		unsigned int opt_len;
		unsigned int expected_opt_pos;
		int ret;

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
		rohc_packet = packet + link_len;
		rohc_size = header.len - link_len;

		/* decompress the ROHC packet with the ROHC decompressor */
		ret = rohc_decompress2(decomp, arrival_time, rohc_packet, rohc_size,
		                       ip_packet, MAX_ROHC_SIZE, &ip_size);
		if(ret != ROHC_OK)
		{
			fprintf(stderr, "\tfailed to decompress ROHC packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tdecompression is successful\n");

		if(comp->feedbacks_first == 0 &&
		   comp->feedbacks[comp->feedbacks_first].length == 0)
		{
			fprintf(stderr, "\tno feedback generated while one was expected\n");
			goto destroy_decomp;
		}

		/* retrieve feedback data */
		feedback_data = comp->feedbacks[comp->feedbacks_first].data;
		feedback_size = comp->feedbacks[comp->feedbacks_first].length;
		fprintf(stderr, "\t%zd-byte feedback generated\n", feedback_size);

		/* if feedback length is one octet, the feedback is a FEEDBACK-1 */
		if(feedback_size < 2)
		{
			fprintf(stderr, "\tFEEDBACK-2 should be at least 2 byte long\n");
			goto destroy_decomp;
		}

		/* is there a Add-CID octet? */
		if(cid_type == ROHC_LARGE_CID)
		{
			size_t sdvl_size;
			uint32_t cid;
			size_t cid_bits_nr;

			/* determine the size of the SDVL-encoded large CID */
			sdvl_size = sdvl_decode(feedback_data, feedback_size,
			                        &cid, &cid_bits_nr);
			if(sdvl_size <= 0 || sdvl_size > 4)
			{
				fprintf(stderr, "\tinvalid SDVL-encoded value for large CID\n");
				goto destroy_decomp;
			}

			fprintf(stderr, "\tlarge CID found\n");
			feedback_data_pos += sdvl_size;
		}
		else
		{
			if(((feedback_data[0] & 0xc0) >> 6) == 3)
			{
				/* skip Add-CID */
				fprintf(stderr, "\tAdd-CID found\n");
				feedback_data_pos++;
			}
		}

		/* check feedback type */
		feedback_type = (feedback_data[feedback_data_pos] & 0xc0) >> 6;
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

		sn = ((feedback_data[feedback_data_pos] & 0x0f) << 8) +
		     (feedback_data[feedback_data_pos + 1] & 0xff);
		fprintf(stderr, "\tSN (or a part of it) = 0x%04x\n", sn);

		/* parse every feedback options found in the packet */
		expected_opt_pos = 0;
		for(i = feedback_data_pos + 2; i < feedback_size; i += opt_len)
		{
			/* is another feedback option expected? */
			if(expected_opt_pos >= expected_options_nr)
			{
				fprintf(stderr, "\tmore options in packet than expected\n");
				goto destroy_decomp;
			}

			/* get option length (1 byte of header + variable data) */
			opt_len = 1 + (feedback_data[i] & 0x0f);

			/* check option type */
			switch((feedback_data[i] & 0xf0) >> 4)
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
					        opt_len, (feedback_data[i] & 0xf0) >> 4);
					break;
			}
		}

		free(comp->feedbacks[comp->feedbacks_first].data);
		comp->feedbacks[comp->feedbacks_first].length = 0;
		comp->feedbacks[comp->feedbacks_first].is_locked = false;
		comp->feedbacks_first = 0;
		comp->feedbacks_first_unlocked = 0;
		comp->feedbacks_next = 0;
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

