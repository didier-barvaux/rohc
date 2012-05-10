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
 * @file   test_empty_payload.c
 * @brief  Check that IP/ROHC packets with empty payloads are correctly
 *         compressed/decompressed
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application compresses IP packets from a source PCAP file, check that
 * the last compressed packet is of the expected type (IR, IR-DYN...) and
 * decompresses all the generated ROHC packets. All IP packets should be
 * correctly compressed. All generated ROHC packets should be correctly
 * decompressed.
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

/* include for the PCAP library */
#include <pcap.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>
#include <rohc_packets.h>


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(const char *filename,
                                const unsigned int profile_id,
                                const rohc_packet_t expected_packet);


/**
 * @brief Check that IP/ROHC packets with empty payloads are correctly
 *        compressed/decompressed
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
	char *profile_name = NULL;
	unsigned int profile_id;
	char *packet_type = NULL;
	rohc_packet_t expected_packet;
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 3)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc--, argv++)
	{
		if(!strcmp(*argv, "-h"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(filename == NULL)
		{
			/* get the name of the file that contains the packets to
			 * compress/decompress */
			filename = argv[0];
		}
		else if(profile_name == NULL)
		{
			/* get the name of the profile to enable ('auto' means all) */
			profile_name = argv[0];
		}
		else if(packet_type == NULL)
		{
			/* get the expected type of the last packet of the capture */
			packet_type = argv[0];
		}
		else
		{
			/* do not accept more than two arguments without option name */
			usage();
			goto error;
		}
	}

	/* the source filename, the profile name and the packet type are mandatory */
	if(filename == NULL || profile_name == NULL || packet_type == NULL)
	{
		usage();
		goto error;
	}

	/* parse the profile name */
	if(strcmp(profile_name, "uncompressedprofile") == 0)
	{
		profile_id = ROHC_PROFILE_UNCOMPRESSED;
	}
	else if(strcmp(profile_name, "iponlyprofile") == 0)
	{
		profile_id = ROHC_PROFILE_IP;
	}
	else if(strcmp(profile_name, "udpprofile") == 0)
	{
		profile_id = ROHC_PROFILE_UDP;
	}
	else if(strcmp(profile_name, "udpliteprofile") == 0)
	{
		profile_id = ROHC_PROFILE_UDPLITE;
	}
	else if(strcmp(profile_name, "rtpprofile") == 0)
	{
		profile_id = ROHC_PROFILE_RTP;
	}
	else if(strcmp(profile_name, "auto") == 0)
	{
		profile_id = 0xFFFF;
	}
	else
	{
		fprintf(stderr, "unknown profile '%s'\n", profile_name);
		usage();
		goto error;
	}

	/* parse the packet type */
	if(strcmp(packet_type, "ir") == 0)
	{
		expected_packet = PACKET_IR;
	}
	else if(strcmp(packet_type, "irdyn") == 0)
	{
		expected_packet = PACKET_IR_DYN;
	}
	else if(strcmp(packet_type, "uo0") == 0)
	{
		expected_packet = PACKET_UO_0;
	}
	else if(strcmp(packet_type, "uo1") == 0)
	{
		expected_packet = PACKET_UO_1_TS;
	}
	else if(strcmp(packet_type, "uor2") == 0)
	{
		expected_packet = PACKET_UOR_2_TS;
	}
	else
	{
		fprintf(stderr, "unknown packet type '%s'\n", packet_type);
		usage();
		goto error;
	}

	/* test ROHC compression/decompression with the packets from the file */
	status = test_comp_and_decomp(filename, profile_id, expected_packet);

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that IP/ROHC packets with empty payloads are correctly\n"
	        "compressed/decompressed\n"
	        "\n"
	        "usage: test_empty_payload [OPTIONS] FLOW PACKET_TYPE\n"
	        "\n"
	        "with:\n"
	        "  FLOW          The flow of Ethernet frames to compress\n"
	        "                (in PCAP format)\n"
	        "  PROFILE_NAME  The name of the profile to enable ('auto' means all)\n"
	        "  PACKET_TYPE   The packet type expected for the last packet\n"
	        "                among: ir, irdyn, uo0, uo1, uor2\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with a flow of IP packets with empty payload
 *        going through one compressor then one decompressor
 *
 * @param filename         The name of the PCAP file that contains the
 *                         IP packets
 * @param profile_id       The profile to compress packets with
 *                         (0xFFFF means all)
 * @param expected_packet  The type of ROHC packet expected at the end of the
 *                         source capture
 * @return                 0 in case of success,
 *                         1 in case of failure
 */
static int test_comp_and_decomp(const char *filename,
                                const unsigned int profile_id,
                                const rohc_packet_t expected_packet)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_comp *comp;
	struct rohc_decomp *decomp;
	rohc_packet_t last_packet_type = PACKET_UNKNOWN;

	struct pcap_pkthdr header;
	unsigned char *packet;
	unsigned int counter;

	int ret;
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

	/* create the ROHC compressor with MAX_CID = 15 (small CID) */
	comp = rohc_alloc_compressor(15, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto close_input;
	}
	rohc_c_set_large_cid(comp, 0);

	/* enable the requested profile(s) */
	if(profile_id != 0xFFFF)
	{
		fprintf(stderr, "enable only the compression profile %u\n", profile_id);
		rohc_activate_profile(comp, profile_id);
	}
	else
	{
		fprintf(stderr, "enable all compression profiles\n");
		rohc_activate_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
		rohc_activate_profile(comp, ROHC_PROFILE_UDP);
		rohc_activate_profile(comp, ROHC_PROFILE_IP);
		rohc_activate_profile(comp, ROHC_PROFILE_UDPLITE);
		rohc_activate_profile(comp, ROHC_PROFILE_RTP);
	}

	/* create the ROHC decompressor in unidirectional mode */
	decomp = rohc_alloc_decompressor(NULL);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* for each packet in the dump */
	counter = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		rohc_comp_last_packet_info_t last_packet_info;
		unsigned char *ip_packet;
		int ip_size;
		static unsigned char rohc_packet[MAX_ROHC_SIZE];
		int rohc_size;
		static unsigned char decomp_packet[MAX_ROHC_SIZE];
		int decomp_size;

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
		ip_packet = packet + link_len;
		ip_size = header.len - link_len;

		/* check for padding after the IP packet in the Ethernet payload */
		if(link_len == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
		{
			uint8_t version;
			uint16_t tot_len;

			/* get IP version */
			version = (ip_packet[0] >> 4) & 0x0f;

			/* get IP total length depending on IP version */
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

			/* determine if there is Ethernet padding after IP packet */
			if(tot_len < ip_size)
			{
				/* there is Ethernet padding, ignore these bits because there are
				 * not part of the IP packet */
				ip_size = tot_len;
			}
		}
		fprintf(stderr, "\tpacket is valid\n");

		/* compress the IP packet with the ROHC compressor */
		rohc_size = rohc_compress(comp, ip_packet, ip_size,
		                          rohc_packet, MAX_ROHC_SIZE);
		if(rohc_size <= 0)
		{
			fprintf(stderr, "\tfailed to compress IP packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tcompression is successful\n");

		/* get packet statistics and remember the packet type */
		ret = rohc_comp_get_last_packet_info(comp, &last_packet_info);
		if(ret != ROHC_OK)
		{
			fprintf(stderr, "\tfailed to get statistics on packet\n");
			goto destroy_decomp;
		}
		last_packet_type = last_packet_info.packet_type;
		fprintf(stderr, "\tROHC packet of type %d generated\n", last_packet_type);

		/* decompress the generated ROHC packet with the ROHC decompressor */
		decomp_size = rohc_decompress(decomp, rohc_packet, rohc_size,
		                              decomp_packet, MAX_ROHC_SIZE);
		if(decomp_size <= 0)
		{
			fprintf(stderr, "\tfailed to decompress generated ROHC packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tdecompression is successful\n");
	}

	/* is the last packet of the expected type? */
	if(last_packet_type != expected_packet)
	{
		fprintf(stderr, "last generated ROHC packet is not as expected: "
		        "packet type %d generated while %d expected\n", last_packet_type,
		        expected_packet);
		goto destroy_decomp;
	}

	/* everything went fine */
	fprintf(stderr, "last generated ROHC packet is of type %d as expected\n",
	        expected_packet);
	is_failure = 0;

destroy_decomp:
	rohc_free_decompressor(decomp);
destroy_comp:
	rohc_free_compressor(comp);
close_input:
	pcap_close(handle);
error:
	return is_failure;
}

