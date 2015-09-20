/*
 * Copyright 2013 Didier Barvaux
 * Copyright 2013 Viveris Technologies
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
 * @file   test_non_regression_kernel.c
 * @brief  ROHC non-regression test program for Linux kernel
 * @author Thales Communications
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 *
 * Introduction
 * ------------
 *
 * The program takes a flow of IP packets as input (in the PCAP format) and
 * tests the ROHC compression/decompression library with them. The program
 * also tests the feedback mechanism.
 *
 * Details
 * -------
 *
 * The program defines two compressor/decompressor pairs and sends the flow
 * of IP packet through Compressor 1 and Decompressor 1 (flow A) and through
 * Compressor 2 and Decompressor 2 (flow B). See the figure below.
 *
 * The feedback for flow A is sent by Decompressor 1 to Compressor 1 via
 * Compressor 2 and Decompressor 2. The feedback for flow  B is sent by
 * Decompressor 2 to Compressor 2 via Compressor 1 and Decompressor 1.
 *
 *          +-- IP packets                             IP packets <--+
 *          |   flow A (input)                    flow A (output)    |
 *          |                                                        |
 *          |    +----------------+    ROHC    +----------------+    |
 *          +--> |                |            |                | ---+
 *               |  Compressor 1  | ---------> | Decompressor 1 |
 *          +--> |                |            |                | ---+
 *          |    +----------------+            +----------------+    |
 * feedback |                                                        | feedback
 * flow B   |                                                        | flow A
 *          |    +----------------+     ROHC   +----------------+    |
 *          +--- |                |            |                | <--+
 *               | Decompressor 2 | <--------- |  Compressor 2  |
 *          +--- |                |            |                | <--+
 *          |    +----------------+            +----------------+    |
 *          |                                                        |
 *          +--> IP packets                             IP packets --+
 *               flow B (output)                    flow B (input)
 *
 * The compressors and decompressors are located in Linux kernel. The test
 * program exchanges IP and ROHC packets with the Linux kernel through dedicated
 * files in /proc:
 *   - /proc/rohc_comp1_in is for sending IP packets to compressor 1
 *   - /proc/rohc_comp1_out is for receiving ROHC packets from compressor 1
 *   - /proc/rohc_comp2_in is for sending IP packets to compressor 2
 *   - /proc/rohc_comp2_out is for receiving ROHC packets from compressor 2
 *   - /proc/rohc_decomp1_in is for sending IP packets to decompressor 1
 *   - /proc/rohc_decomp1_out is for receiving ROHC packets from decompressor 1
 *   - /proc/rohc_decomp2_in is for sending IP packets to decompressor 2
 *   - /proc/rohc_decomp2_out is for receiving ROHC packets from decompressor 2
 *
 * Checks
 * ------
 *
 * The program checks for the status of the compression and decompression
 * processes. The program also compares input IP packets from flow A (resp.
 * flow B) with output IP packets from flow A (resp. flow B).
 *
 * The program optionally compares the ROHC packets generated with the ones
 * given as input to the program.
 *
 */

#include "test.h"
#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>

/* includes for network headers */
#include <protocols/ipv4.h>
#include <protocols/ipv6.h>

/* include for the PCAP library */
#if HAVE_PCAP_PCAP_H == 1
#  include <pcap/pcap.h>
#elif HAVE_PCAP_H == 1
#  include <pcap.h>
#else
#  error "pcap.h header not found, did you specified --enable-rohc-tests \
for ./configure ? If yes, check configure output and config.log"
#endif


/** The different possible test results */
typedef enum
{
	TEST_SUCCESS = 0,    /**< Process is successful */
	TEST_ERROR_COMP,     /**< Error during compression */
	TEST_MISMATCH_ROHC,  /**< Compressed packet doesn't match reference */
	TEST_ERROR_DECOMP,   /**< Error during decompression */
	TEST_MISMATCH_IP,    /**< Decompressed packet doesn't match original one */
	TEST_ERROR_MISC,     /**< Miscellaneous error */
	TEST_RESULT_MAX      /**< The maximum number of test results */
} test_result_t;


/** The information related to a PCAP capture */
typedef struct
{
	pcap_t *handle;      /**< The handle on the PCAP capture */
	size_t link_length;  /**< The length (in bytes) of the link layer
	                          in the PCAP capture */
} pcap_capture_t;


/** Couples of /proc interfaces */
typedef struct
{
	/** The file to write IP packets on to compressor */
	FILE *proc_comp_in;
	/** The file to read ROHC packets from compressor */
	FILE *proc_comp_out;

	/** The file to write ROHC packets on to decompressor */
	FILE *proc_decomp_in;
	/** The file to read IP packets from decompressor */
	FILE *proc_decomp_out;

} rohc_proc_couple_t;


/** All the information that the test requires */
typedef struct
{
	int do_use_large_cid;      /**< Whether we test large or small CID */

	pcap_capture_t input;      /**< The PCAP capture for input IP stream */
	pcap_capture_t compare;    /**< The PCAP capture for reference ROHC stream */

	/** Two couples of ROHC decompressors/decompressors */
	rohc_proc_couple_t couples[2];

} test_context_t;


/* prototypes of private functions */

static void usage(void);

static int test_run(const char *input_filename,
                    const char *compare_filename);

static int test_init(const char *input_filename,
                     const char *compare_filename,
                     test_context_t *context);
static void test_release(test_context_t context);

static test_result_t test_run_one_step(test_context_t context,
                                       int couple_index,
                                       int num_packet,
                                       struct pcap_pkthdr header,
                                       unsigned char *packet,
                                       struct pcap_pkthdr cmp_header,
                                       unsigned char *cmp_packet);

static int compare_packets(unsigned char *pkt1, int pkt1_size,
                           unsigned char *pkt2, int pkt2_size);



/**
 * @brief Main function for the ROHC test program
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	char *input_filename = NULL;
	char *compare_filename = NULL;
	int status = 1;
	int args_used;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 1)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc -= args_used, argv += args_used)
	{
		args_used = 1;

		if(!strcmp(*argv, "-h") || !strcmp(*argv, "--help"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(!strcmp(*argv, "-c"))
		{
			/* get the name of the file where the ROHC packets used for comparison
			 * are stored */
			compare_filename = argv[1];
			args_used++;
		}
		else if(input_filename == NULL)
		{
			/* get the name of the file that contains the packets to
			 * compress/decompress */
			input_filename = argv[0];
		}
		else
		{
			/* do not accept more than one filename without option name */
			usage();
			goto error;
		}
	}

	/* the source filename is mandatory */
	if(input_filename == NULL)
	{
		usage();
		goto error;
	}

	/* run the test */
	status = test_run(input_filename, compare_filename);
	if(status != 0)
	{
		fprintf(stderr, "\n\nTEST FAILED\n");
	}
	else
	{
		fprintf(stderr, "\n\nTEST SUCCEEDED\n");
	}

error:
	return status;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	fprintf(stderr,
	        "ROHC test application: test the Linux kernel ROHC library "
	        "                       with a flow of IP packets\n"
	        "\n"
	        "usage: test [OPTIONS] [-c cmp_file] FLOW\n"
	        "\n"
	        "parameters:\n"
	        "  -c CMP_FILE     compare the generated ROHC packets with the ROHC packets\n"
	        "                  stored in CMP_FILE (PCAP format)\n"
	        "  FLOW            flow of Ethernet frames to compress (PCAP format)\n"
	        "\n"
	        "options:\n"
	        "  --help          print application usage and exit\n"
	        "  -h\n");
}


/**
 * @brief Test the ROHC library with a flow of IP packets going through
 *        two compressor/decompressor pairs
 *
 * @param input_filename    The name of the PCAP file that contains
 *                          the IP packets
 * @param compare_filename  The name of the PCAP file that contains
 *                          the ROHC packets used for comparison
 * @return                  0 in case of success, 1 otherwise
 */
static int test_run(const char *input_filename,
                    const char *compare_filename)
{
	test_context_t context;
	struct pcap_pkthdr header;
	unsigned char *packet;
	unsigned long results[TEST_RESULT_MAX];
	int status = 1;
	unsigned long counter;
	int ret;

	/* reset counters of return codes */
	memset(results, 0, sizeof(unsigned long) * TEST_RESULT_MAX);

	/* initialize test */
	ret = test_init(input_filename, compare_filename, &context);
	if(ret != 0)
	{
		goto error;
	}

	/* for each packet in the input capture */
	counter = 0;
	while((packet = (unsigned char *) pcap_next(context.input.handle, &header)) != NULL)
	{
		unsigned char *compare_packet;
		struct pcap_pkthdr compare_header =
			{ .ts = { .tv_sec = 0, .tv_usec = 0 }, .caplen = 0, .len = 0 };
		counter++;

		/* get next ROHC packet from the comparison dump file if asked */
		if(context.compare.handle != NULL)
		{
			compare_packet = (unsigned char *)
				pcap_next(context.compare.handle, &compare_header);
		}
		else
		{
			compare_packet = NULL;
		}

		/* compress & decompress with ROHC couple #1 */
		ret = test_run_one_step(context, 0, counter, header, packet,
		                        compare_header, compare_packet);
		assert(ret >= TEST_SUCCESS);
		assert(ret < TEST_RESULT_MAX);
		results[ret]++;

		/* get next ROHC packet from the comparison dump file if asked */
		if(context.compare.handle != NULL)
		{
			compare_packet = (unsigned char *)
				pcap_next(context.compare.handle, &compare_header);
		}
		else
		{
			compare_packet = NULL;
		}

		/* compress & decompress with ROHC couple #2 */
		ret = test_run_one_step(context, 1, counter, header, packet,
		                        compare_header, compare_packet);
		assert(ret >= TEST_SUCCESS);
		assert(ret < TEST_RESULT_MAX);
		results[ret]++;
	}

	/* show the compression/decompression results */
	fprintf(stderr, "\n\n");
	fprintf(stderr, "total packets = %lu\n", 2 * counter);
	fprintf(stderr, "success = %lu\n", results[TEST_SUCCESS]);
	fprintf(stderr, "compression failures = %lu\n", results[TEST_ERROR_COMP]);
	fprintf(stderr, "ROHC mismatches = %lu\n", results[TEST_MISMATCH_ROHC]);
	fprintf(stderr, "decompression failures = %lu\n", results[TEST_ERROR_DECOMP]);
	fprintf(stderr, "IP mismatches = %lu\n", results[TEST_MISMATCH_IP]);
	fprintf(stderr, "misc failures = %lu\n", results[TEST_ERROR_MISC]);

	if(compare_filename != NULL &&
	   results[TEST_SUCCESS] == (2 * counter) &&
	   results[TEST_MISMATCH_ROHC] == 0 &&
	   results[TEST_ERROR_COMP] == 0 &&
	   results[TEST_ERROR_DECOMP] == 0 &&
	   results[TEST_MISMATCH_IP] == 0 &&
	   results[TEST_ERROR_MISC] == 0)
	{
		/* everything went fine + output disabled + comparison enabled */
		fprintf(stderr, "\n\nall success/error counters are as expected\n");
		status = 0;
	}

	test_release(context);

error:
	return status;
}


/**
 * @brief Initialize the test resources
 *
 * @param input_filename     The filename of the IP stream to use for testing
 * @param compare_filename   The name of the PCAP file that contains
 *                           the ROHC packets used for comparison
 * @param context            OUT: the test context initialized by the function
 * @return                   0 in case of success, 1 otherwise
 */
static int test_init(const char *input_filename,
                     const char *compare_filename,
                     test_context_t *context)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int link_layer_type;
	int i;

	memset(context, 0, sizeof(test_context_t));

	/* open the PCAP file that contains the input stream */
	context->input.handle = pcap_open_offline(input_filename, errbuf);
	if(context->input.handle == NULL)
	{
		fprintf(stderr, "failed to open the pcap file: %s\n", errbuf);
		goto error;
	}

	/* link layer in the capture must be Ethernet */
	link_layer_type = pcap_datalink(context->input.handle);
	if(link_layer_type != DLT_EN10MB &&
	   link_layer_type != DLT_LINUX_SLL &&
	   link_layer_type != DLT_RAW)
	{
		fprintf(stderr, "link layer type %d not supported in capture "
		        "(supported = %d, %d, %d)\n", link_layer_type,
		        DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW);
		goto close_pcap_input;
	}

	if(link_layer_type == DLT_EN10MB)
	{
		context->input.link_length = ETHER_HDR_LEN;
	}
	else if(link_layer_type == DLT_LINUX_SLL)
	{
		context->input.link_length = LINUX_COOKED_HDR_LEN;
	}
	else /* DLT_RAW */
	{
		context->input.link_length = 0;
	}

	/* if asked, open the PCAP file that contains the ROHC packets that the
	   test application must compare with the ROHC packets it generates */
	if(compare_filename != NULL)
	{
		context->compare.handle = pcap_open_offline(compare_filename, errbuf);
		if(context->compare.handle == NULL)
		{
			fprintf(stderr, "failed to open the pcap file: %s\n", errbuf);
			goto close_pcap_input;
		}

		/* link layer in the capture must be Ethernet */
		link_layer_type = pcap_datalink(context->compare.handle);
		if(link_layer_type != DLT_EN10MB &&
		   link_layer_type != DLT_LINUX_SLL &&
		   link_layer_type != DLT_RAW)
		{
			fprintf(stderr, "link layer type %d not supported in capture "
			        "(supported = %d, %d, %d)\n", link_layer_type,
			        DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW);
			goto close_pcap_compare;
		}

		if(link_layer_type == DLT_EN10MB)
		{
			context->compare.link_length = ETHER_HDR_LEN;
		}
		else if(link_layer_type == DLT_LINUX_SLL)
		{
			context->compare.link_length = LINUX_COOKED_HDR_LEN;
		}
		else /* DLT_RAW */
		{
			context->compare.link_length = 0;
		}
	}
	else
	{
		context->compare.handle = NULL;
		context->compare.link_length = 0;
	}

	/* open the /proc files for the 2 couples of ROHC compressors/decompressors */
	for(i = 0; i < 2; i++)
	{
		char proc_comp_in_name[100];
		char proc_comp_out_name[100];
		char proc_decomp_in_name[100];
		char proc_decomp_out_name[100];

		sprintf(proc_comp_in_name, "/proc/rohc_comp%d_in", i + 1);
		sprintf(proc_comp_out_name, "/proc/rohc_comp%d_out", i + 1);
		sprintf(proc_decomp_in_name, "/proc/rohc_decomp%d_in", i + 1);
		sprintf(proc_decomp_out_name, "/proc/rohc_decomp%d_out", i + 1);

		/* open the input file for IP packets to compress */
		context->couples[i].proc_comp_in = fopen(proc_comp_in_name, "w");
		if(context->couples[i].proc_comp_in == NULL)
		{
			fprintf(stderr, "failed to open %s: %s (%d)\n", proc_comp_in_name,
			        strerror(errno), errno);
			goto close_proc;
		}

		/* open the output file for compressed ROHC packets */
		context->couples[i].proc_comp_out = fopen(proc_comp_out_name, "r");
		if(context->couples[i].proc_comp_out == NULL)
		{
			fprintf(stderr, "failed to open %s: %s (%d)\n", proc_comp_out_name,
			        strerror(errno), errno);
			goto close_proc;
		}

		/* open the input file for ROHC packets to decompress */
		context->couples[i].proc_decomp_in = fopen(proc_decomp_in_name, "w");
		if(context->couples[i].proc_decomp_in == NULL)
		{
			fprintf(stderr, "failed to open %s: %s (%d)\n", proc_decomp_in_name,
			        strerror(errno), errno);
			goto close_proc;
		}

		/* open the output file for decompressed IP packets */
		context->couples[i].proc_decomp_out = fopen(proc_decomp_out_name, "r");
		if(context->couples[i].proc_decomp_out == NULL)
		{
			fprintf(stderr, "failed to open %s: %s (%d)\n", proc_decomp_out_name,
			        strerror(errno), errno);
			goto close_proc;
		}
	}

	/* everything went fine */
	return 0;

close_proc:
	for(i = 0; i < 2; i++)
	{
		if(context->couples[i].proc_comp_in != NULL)
		{
			fclose(context->couples[i].proc_comp_in);
		}
		if(context->couples[i].proc_comp_out != NULL)
		{
			fclose(context->couples[i].proc_comp_out);
		}
		if(context->couples[i].proc_decomp_in != NULL)
		{
			fclose(context->couples[i].proc_decomp_in);
		}
		if(context->couples[i].proc_decomp_out != NULL)
		{
			fclose(context->couples[i].proc_decomp_out);
		}
	}
close_pcap_compare:
	if(context->compare.handle != NULL)
	{
		pcap_close(context->compare.handle);
	}
close_pcap_input:
	pcap_close(context->input.handle);
error:
	return 1;
}


/**
 * @brief Release the test resources
 *
 * @param context  The context that contains all the test resources
 */
static void test_release(test_context_t context)
{
	int i;

	for(i = 0; i < 2; i++)
	{
		fclose(context.couples[i].proc_comp_in);
		fclose(context.couples[i].proc_comp_out);
		fclose(context.couples[i].proc_decomp_in);
		fclose(context.couples[i].proc_decomp_out);
	}

	pcap_close(context.input.handle);
	if(context.compare.handle != NULL)
	{
		pcap_close(context.compare.handle);
	}
}


/**
 * @brief Compress and decompress one uncompressed IP packet with the given
 *        compressor and decompressor
 *
 * @param context       The context that contains all the test resources
 * @param couple_index  The index of the ROHC compressor/decompressor couple
 *                      to use
 * @param num_packet    A number affected to the IP packet to compress for debug
 *                      purpose
 * @param header        The PCAP header of the packet to compress
 * @param packet        The packet to compress (link layer included)
 * @param cmp_header    The PCAP header of the reference ROHC packet for
 *                      comparison purpose
 * @param cmp_packet    The reference ROHC packet for comparison purpose
 * @return              Possible return values:
 *                        \li TEST_SUCCESS if the process is successful
 *                        \li TEST_ERROR_COMP an error occurs while compressing
 *                        \li TEST_MISMATCH_ROHC if the generated ROHC packet
 *                            doesn't match the one of reference
 *                        \li TEST_ERROR_DECOMP if an error occurs while
 *                            decompressing
 *                        \li TEST_MISMATCH_IP if the decompressed IP packet
 *                            doesn't match the original IP packet
 *                        \li if a miscellaneous error appends
 */
static test_result_t test_run_one_step(test_context_t context,
                                       int couple_index,
                                       int num_packet,
                                       struct pcap_pkthdr header,
                                       unsigned char *packet,
                                       struct pcap_pkthdr cmp_header,
                                       unsigned char *cmp_packet)
{
	uint16_t packet_size;

	/* original uncompressed IP packet to compress */
	unsigned char *ip_packet;
	int ip_size;

	/* compressed ROHC packet generated from original IP packet */
	static unsigned char rohc_packet[MAX_ROHC_SIZE];
	int rohc_size;

	/* uncompressed IP packet generated from ROHC packet */
	static unsigned char decomp_packet[MAX_ROHC_SIZE];
	int decomp_size;

	int result = TEST_SUCCESS;
	int ret;

	fprintf(stderr, "\n\nPACKET %d ON ROHC COUPLE %d\n",
	        num_packet, couple_index + 1);

	/* check Ethernet frame length */
	if(header.len <= context.input.link_length ||
	   header.len != header.caplen)
	{
		result = TEST_ERROR_MISC;
		goto error;
	}

	/* skip the link layer header */
	ip_packet = packet + context.input.link_length;
	ip_size = header.len - context.input.link_length;

	/* check for padding after the IP packet in the Ethernet payload */
	if(context.input.link_length == ETHER_HDR_LEN &&
	   header.len == ETHER_FRAME_MIN_LEN)
	{
		uint8_t ip_version;
		uint16_t tot_len;

		/* determine the total length of the IP packet */
		ip_version = (ip_packet[0] >> 4) & 0x0f;
		if(ip_version == 4) /* IPv4 */
		{
			const struct ipv4_hdr *ip = (struct ipv4_hdr *) ip_packet;
			tot_len = ntohs(ip->tot_len);
		}
		else if(ip_version == 6) /* IPv6 */
		{
			const struct ipv6_hdr *ip = (struct ipv6_hdr *) ip_packet;
			tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->plen);
		}
		else /* unknown IP version */
		{
			fprintf(stderr, "bad IP version (0x%x) in packet\n", ip_version);
			goto error;
		}

		/* update the length of the IP packet if padding is present */
		if(tot_len < ip_size)
		{
			fprintf(stderr, "Ethernet frame has %u bytes of padding after "
			        "the %u-byte IP packet!\n", ip_size - tot_len, tot_len);
			ip_size = tot_len;
		}
	}

	/* ask the kernel to compress the IP packet
	   (send the size of 2 bytes, then the IP data) */
	fprintf(stderr, "send a %d-byte IP packet to kernel\n", ip_size);
	packet_size = ip_size;
	ret = fwrite(&packet_size, sizeof(uint16_t), 1,
	             context.couples[couple_index].proc_comp_in);
	if(ret != 1)
	{
		fprintf(stderr, "failed to send the size of the IP packet to kernel "
		        "(code = %d)\n", ret);
		result = TEST_ERROR_COMP;
		goto error_comp;
	}
	ret = fwrite(ip_packet, sizeof(unsigned char), ip_size,
	             context.couples[couple_index].proc_comp_in);
	if(ret != ip_size)
	{
		fprintf(stderr, "failed to send a %d-byte IP packet to kernel "
		        "(code = %d)\n", ip_size, ret);
		result = TEST_ERROR_COMP;
		goto error_comp;
	}
	fflush(context.couples[couple_index].proc_comp_in);

	/* ask the kernel for the ROHC packet it generated */
	fprintf(stderr, "receive a ROHC packet from kernel\n");
	rohc_size = fread(rohc_packet, sizeof(unsigned char), MAX_ROHC_SIZE,
	                  context.couples[couple_index].proc_comp_out);
	if(rohc_size <= 0)
	{
		fprintf(stderr, "failed to receive a ROHC packet from kernel\n");
		result = TEST_ERROR_COMP;
		goto error_comp;
	}

	if(context.compare.handle != NULL)
	{
		/* does the reference packet exist in capture ? */
		if(cmp_packet == NULL)
		{
			fprintf(stderr, "ROHC reference packet is missing in PCAP file\n");
			result = TEST_MISMATCH_ROHC;
			goto mismatch_rohc;
		}

		/* is reference packet OK ? */
		if(cmp_header.len <= context.compare.link_length ||
		   cmp_header.len != cmp_header.caplen)
		{
			fprintf(stderr, "ROHC reference packet is too short in PCAP file\n");
			result = TEST_MISMATCH_ROHC;
			goto mismatch_rohc;
		}

		/* compare reference and generated ROHC packets */
		if(!compare_packets(cmp_packet + context.compare.link_length,
		                    cmp_header.len - context.compare.link_length,
		                    rohc_packet, rohc_size))
		{
			result = TEST_MISMATCH_ROHC;
		}
		else
		{
			fprintf(stderr, "ROHC packets are equal\n");
		}
	}
	else
	{
		fprintf(stderr, "no ROHC packets given for reference, "
		        "cannot compare (run with the -c option)\n");
	}

	/* ask the kernel to decompress the ROHC packet
	   (send the size of 2 bytes, then the ROHC data) */
	fprintf(stderr, "send a %d-byte ROHC packet to kernel\n", rohc_size);
	packet_size = rohc_size;
	ret = fwrite(&packet_size, sizeof(uint16_t), 1,
	             context.couples[couple_index].proc_decomp_in);
	if(ret != 1)
	{
		fprintf(stderr, "failed to send the size of the ROHC packet to kernel "
		        "(code = %d)\n", ret);
		result = TEST_ERROR_DECOMP;
		goto error_decomp;
	}
	ret = fwrite(rohc_packet, sizeof(unsigned char), rohc_size,
	             context.couples[couple_index].proc_decomp_in);
	if(ret != rohc_size)
	{
		fprintf(stderr, "failed to send a %d-byte ROHC packet to kernel\n", rohc_size);
		result = TEST_ERROR_DECOMP;
		goto error_decomp;
	}
	fflush(context.couples[couple_index].proc_decomp_in);

	/* ask the kernel for the decompressed IP packet it generated */
	fprintf(stderr, "receive a decompressed IP packet from kernel\n");
	decomp_size = fread(decomp_packet, sizeof(unsigned char), MAX_ROHC_SIZE,
	                    context.couples[couple_index].proc_decomp_out);
	if(decomp_size <= 0)
	{
		fprintf(stderr, "failed to receive a decompressed IP packet from kernel\n");
		result = TEST_ERROR_DECOMP;
		goto error_decomp;
	}

	/* compare the decompressed packet with the original one */
	if(!compare_packets(ip_packet, ip_size, decomp_packet, decomp_size))
	{
		result = TEST_MISMATCH_IP;
		goto mismatch_ip;
	}
	fprintf(stderr, "decompressed IP packets are equal\n");

	return result;

error:
	fprintf(stderr, "bad PCAP packet (len = %u, caplen = %u)\n",
	        header.len, header.caplen);
error_comp:
	fprintf(stderr, "Compression failed, cannot compare the packets!\n");
mismatch_rohc:
	fprintf(stderr, "ROHC comparison failed, cannot decompress the packets!\n");
error_decomp:
	fprintf(stderr, "Decompression failed, cannot compare the packets!\n");
mismatch_ip:
	return result;
}


/**
 * @brief Compare two network packets and print differences if any
 *
 * @param pkt1      The first packet
 * @param pkt1_size The size of the first packet
 * @param pkt2      The second packet
 * @param pkt2_size The size of the second packet
 * @return          Whether the packets are equal or not
 */
static int compare_packets(unsigned char *pkt1, int pkt1_size,
                           unsigned char *pkt2, int pkt2_size)
{
	int valid = 1;
	int min_size;
	int i, j, k;
	char str1[4][7], str2[4][7];
	char sep1, sep2;

	/* do not compare more than the shortest of the 2 packets */
	min_size = min(pkt1_size, pkt2_size);

	/* do not compare more than 180 bytes to avoid huge output */
	min_size = min(180, min_size);

	/* if packets are equal, do not print the packets */
	if(pkt1_size == pkt2_size && memcmp(pkt1, pkt2, pkt1_size) == 0)
	{
		goto skip;
	}

	/* packets are different */
	valid = 0;

	fprintf(stderr, "------------------------------ Compare ------------------------------\n");

	if(pkt1_size != pkt2_size)
	{
		fprintf(stderr, "packets have different sizes (%d != %d), compare only the %d "
		        "first bytes\n", pkt1_size, pkt2_size, min_size);
	}

	j = 0;
	for(i = 0; i < min_size; i++)
	{
		if(pkt1[i] != pkt2[i])
		{
			sep1 = '#';
			sep2 = '#';
		}
		else
		{
			sep1 = '[';
			sep2 = ']';
		}

		sprintf(str1[j], "%c0x%.2x%c", sep1, pkt1[i], sep2);
		sprintf(str2[j], "%c0x%.2x%c", sep1, pkt2[i], sep2);

		/* make the output human readable */
		if(j >= 3 || (i + 1) >= min_size)
		{
			for(k = 0; k < 4; k++)
			{
				if(k < (j + 1))
				{
					fprintf(stderr, "%s  ", str1[k]);
				}
				else /* fill the line with blanks if nothing to print */
				{
					fprintf(stderr, "        ");
				}
			}

			fprintf(stderr, "      ");

			for(k = 0; k < (j + 1); k++)
			{
				fprintf(stderr, "%s  ", str2[k]);
			}

			fprintf(stderr, "\n");

			j = 0;
		}
		else
		{
			j++;
		}
	}

	fprintf(stderr, "----------------------- packets are different -----------------------\n");

skip:
	return valid;
}

