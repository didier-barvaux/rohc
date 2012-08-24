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
 * @file   generate_statistics.c
 * @brief  ROHC statistics program
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The program takes a flow of IP packets as input (in the PCAP format) and
 * generate some ROHC compression statistics with them.
 */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <assert.h>
#include <time.h> /* for time(2) */

/* include for the PCAP library */
#include <pcap.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_packets.h>
#include <rohc_comp.h>


/** The maximal size for the ROHC packets */
#define MAX_ROHC_SIZE  (5 * 1024)

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

/** The minimum Ethernet length (in bytes) */
#define ETHER_FRAME_MIN_LEN 60


/* prototypes of private functions */
static void usage(void);
static int generate_comp_stats_all(const int use_large_cid,
                                   const unsigned int max_contexts,
                                   const char *filename);
static int generate_comp_stats_one(struct rohc_comp *comp,
                                   const unsigned long num_packet,
                                   const struct pcap_pkthdr header,
                                   const unsigned char *packet,
                                   const int link_len);
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));


/**
 * @brief Main function for the ROHC statistics program
 *
 * @param argc  The number of program arguments
 * @param argv  The program arguments
 * @return      The unix return code:
 *               \li 0 in case of success,
 *               \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	char *cid_type = NULL;
	char *source_filename = NULL;
	int status = 1;
	int max_contexts = ROHC_SMALL_CID_MAX + 1;
	int use_large_cid;
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

		if(!strcmp(*argv, "-h"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(!strcmp(*argv, "--max-contexts"))
		{
			/* get the maximum number of contexts the test should use */
			max_contexts = atoi(argv[1]);
			args_used++;
		}
		else if(cid_type == NULL)
		{
			/* get the type of CID to use within the ROHC library */
			cid_type = argv[0];
		}
		else if(source_filename == NULL)
		{
			/* get the name of the file that contains the packets to compress */
			source_filename = argv[0];
		}
		else
		{
			/* do not accept more than one filename without option name */
			usage();
			goto error;
		}
	}

	/* check CID type */
	if(!strcmp(cid_type, "smallcid"))
	{
		use_large_cid = 0;

		/* the maximum number of ROHC contexts should be valid */
		if(max_contexts < 1 || max_contexts > (ROHC_SMALL_CID_MAX + 1))
		{
			fprintf(stderr, "the maximum number of ROHC contexts should be "
			        "between 1 and %u\n\n", ROHC_SMALL_CID_MAX + 1);
			usage();
			goto error;
		}
	}
	else if(!strcmp(cid_type, "largecid"))
	{
		use_large_cid = 1;

		/* the maximum number of ROHC contexts should be valid */
		if(max_contexts < 1 || max_contexts > (ROHC_LARGE_CID_MAX + 1))
		{
			fprintf(stderr, "the maximum number of ROHC contexts should be "
			        "between 1 and %u\n\n", ROHC_LARGE_CID_MAX + 1);
			usage();
			goto error;
		}
	}
	else
	{
		fprintf(stderr, "invalid CID type '%s', only 'smallcid' and 'largecid' "
		        "expected\n", cid_type);
		usage();
		goto error;
	}

	/* the source filename is mandatory */
	if(source_filename == NULL)
	{
		fprintf(stderr, "source filename is mandatory\n");
		usage();
		goto error;
	}

	/* generate ROHC compression statistics with the packets from the file */
	status = generate_comp_stats_all(use_large_cid, max_contexts, source_filename);

error:
	return status;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	fprintf(stderr,
	        "ROHC statistics tool: generate ROHC compression statistics\n"
	        "with a flow of IP packets\n"
	        "\n"
	        "usage: generate_statistics [OPTIONS] CID_TYPE FLOW\n"
	        "\n"
	        "with:\n"
	        "  CID_TYPE                The type of CID to use among 'smallcid'\n"
	        "                          and 'largecid'\n"
	        "  FLOW                    The flow of Ethernet frames to compress\n"
	        "                          (in PCAP format)\n"
	        "\n"
	        "options:\n"
	        "  -h                      Print this usage and exit\n"
	        "  --max-contexts NUM      The maximum number of ROHC contexts to\n"
	        "                          simultaneously use during the test\n");
}


/**
 * @brief Generate ROHC compression statistics with a flow of IP packets
 *
 * @param use_large_cid  Whether the compressor shall use large CIDs
 * @param max_contexts   The maximum number of ROHC contexts to use
 * @param filename       The name of the PCAP file that contains the IP packets
 * @return               0 in case of success,
 *                       1 in case of failure
 */
static int generate_comp_stats_all(const int use_large_cid,
                                   const unsigned int max_contexts,
                                   const char *filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_comp *comp;

	unsigned long num_packet;
	struct pcap_pkthdr header;
	unsigned char *packet;

	int is_failure = 1;

	/* open the source PCAP file */
	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "failed to open the source pcap file: %s\n", errbuf);
		goto error;
	}

	/* link layer in the source PCAP file must be Ethernet */
	link_layer_type = pcap_datalink(handle);
	if(link_layer_type != DLT_EN10MB &&
	   link_layer_type != DLT_LINUX_SLL &&
	   link_layer_type != DLT_RAW)
	{
		fprintf(stderr, "link layer type %d not supported in source PCAP file "
		        "(supported = %d, %d, %d)\n", link_layer_type, DLT_EN10MB,
		        DLT_LINUX_SLL, DLT_RAW);
		goto close_input;
	}

	/* determine the size of the link layer header */
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

	/* create the ROHC compressor */
	comp = rohc_alloc_compressor(max_contexts - 1, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC compressor\n");
		goto close_input;
	}
	rohc_activate_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(comp, ROHC_PROFILE_UDP);
	rohc_activate_profile(comp, ROHC_PROFILE_IP);
	rohc_activate_profile(comp, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(comp, ROHC_PROFILE_RTP);
	rohc_activate_profile(comp, ROHC_PROFILE_ESP);
	rohc_c_set_large_cid(comp, use_large_cid);

	/* set the callback for random numbers */
	if(!rohc_comp_set_random_cb(comp, gen_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto destroy_comp;
	}

	/* output the statistics columns names */
	printf("STAT\t"
	       "\"packet number\"\t"
	       "\"context mode\"\t"
	       "\"context mode (string)\"\t"
	       "\"context state\"\t"
	       "\"context state (string)\"\t"
	       "\"packet type\"\t"
	       "\"packet type (string)\"\t"
	       "\"uncompressed packet size (bytes)\"\t"
	       "\"uncompressed header size (bytes)\"\t"
	       "\"compressed packet size (bytes)\"\t"
	       "\"compressed header size (bytes)\"\n");
	fflush(stdout);

	/* for each packet extracted from the PCAP file */
	num_packet = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		int ret;

		num_packet++;

		/* compress the packet and generate statistics */
		ret = generate_comp_stats_one(comp, num_packet, header, packet, link_len);
		if(ret != 0)
		{
			fprintf(stderr, "packet %lu: failed to compress or generate stats "
			        "for packet\n", num_packet);
			goto destroy_comp;
		}
	}

	/* everything went fine */
	is_failure = 0;

destroy_comp:
	rohc_free_compressor(comp);
close_input:
	pcap_close(handle);
error:
	return is_failure;
}


/**
 * @brief Compress and decompress one uncompressed IP packet with the given
 *        compressor and decompressor
 *
 * @param comp        The compressor to use to compress the IP packet
 * @param num_packet  A number affected to the IP packet to compress
 * @param header      The PCAP header for the packet
 * @param packet      The packet to compress (link layer included)
 * @param link_len    The length of the link layer header before IP data
 * @return            0 in case of success,
 *                    1 in case of failure
 */
static int generate_comp_stats_one(struct rohc_comp *comp,
                                   const unsigned long num_packet,
                                   const struct pcap_pkthdr header,
                                   const unsigned char *packet,
                                   const int link_len)
{
	const unsigned char *ip_packet;
	int ip_size;
	static unsigned char rohc_packet[MAX_ROHC_SIZE];
	int rohc_size;
	rohc_comp_last_packet_info_t last_packet_info;
	int ret;

	/* check frame length */
	if(header.len <= link_len || header.len != header.caplen)
	{
		fprintf(stderr, "packet #%lu: bad PCAP packet (len = %d, caplen = %d)\n",
		        num_packet, header.len, header.caplen);
		goto error;
	}

	/* skip the link layer header */
	ip_packet = packet + link_len;
	ip_size = header.len - link_len;

	/* check for padding after the IP packet in the Ethernet payload */
	if(link_len == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
	{
		int version;
		int tot_len;

		version = (ip_packet[0] >> 4) & 0x0f;

		if(version == 4)
		{
			struct iphdr *ip = (struct iphdr *) ip_packet;
			tot_len = ntohs(ip->tot_len);
		}
		else
		{
			struct ip6_hdr *ip = (struct ip6_hdr *) ip_packet;
			tot_len = sizeof(struct ip6_hdr) + ntohs(ip->ip6_plen);
		}

		if(tot_len < ip_size)
		{
			/* the Ethernet frame has some bytes of padding after the IP packet */
			ip_size = tot_len;
		}
	}

	/* compress the IP packet */
	rohc_size = rohc_compress(comp, (unsigned char *) ip_packet, ip_size,
	                          rohc_packet, MAX_ROHC_SIZE);
	if(rohc_size <= 0)
	{
		fprintf(stderr, "packet #%lu: compression failed\n", num_packet);
		goto error;
	}

	/* get some statistics about the last compressed packet */
	ret = rohc_comp_get_last_packet_info(comp, &last_packet_info);
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "packet #%lu: cannot get stats about the last compressed "
		        "packet\n", num_packet);
		goto error;
	}

	/* output some statistics about the last compressed packet */
	printf("STAT\t%lu\t%d\t%s\t%d\t%s\t%d\t%s\t%lu\t%lu\t%lu\t%lu\n",
	       num_packet,
	       last_packet_info.context_mode,
	       rohc_get_mode_descr(last_packet_info.context_mode),
	       last_packet_info.context_state,
	       rohc_comp_get_state_descr(last_packet_info.context_state),
	       last_packet_info.packet_type,
	       rohc_get_packet_descr(last_packet_info.packet_type),
	       last_packet_info.total_last_uncomp_size,
	       last_packet_info.header_last_uncomp_size,
	       last_packet_info.total_last_comp_size,
	       last_packet_info.header_last_comp_size);
	fflush(stdout);

	return 0;

error:
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
	assert(comp != NULL);
	assert(user_context == NULL);
	return rand();
}

