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
 * @file   test_damaged_packet.c
 * @brief  Check that damaged ROHC packets are handled correctly
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application compresses IP packets from a source PCAP file, then
 * decompresses them after damaging one of them. All IP packets should be
 * correctly compressed. All generated ROHC packets should be correctly
 * decompressed except the damaged one.
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
#include <assert.h>

/* include for the PCAP library */
#include <pcap.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(const char *const filename,
                                const unsigned int packet_to_damage,
                                const rohc_packet_t expected_packet);


/**
 * @brief Check that damaged ROHC packets are handled correctly
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
	char *packet_to_damage_param = NULL;
	int packet_to_damage;
	char *packet_type = NULL;
	rohc_packet_t expected_packet;
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 2)
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
		else if(packet_to_damage_param == NULL)
		{
			/* get the ROHC packet to damage */
			packet_to_damage_param = argv[0];
		}
		else if(packet_type == NULL)
		{
			/* get the expected type of the packet to damage */
			packet_type = argv[0];
		}
		else
		{
			/* do not accept more than two arguments without option name */
			usage();
			goto error;
		}
	}

	/* check mandatory parameters */
	if(filename == NULL || packet_to_damage_param == NULL || packet_type == NULL)
	{
		usage();
		goto error;
	}

	/* parse the packet to damage */
	packet_to_damage = atoi(packet_to_damage_param);
	if(packet_to_damage <= 0)
	{
		fprintf(stderr, "bad number for the package to damage '%s'\n\n",
		        packet_to_damage_param);
		usage();
		goto error;
	}

	/* parse the packet type */
	if(strlen(packet_type) == 2 && strcmp(packet_type, "ir") == 0)
	{
		expected_packet = PACKET_IR;
	}
	else if(strlen(packet_type) == 5 && strcmp(packet_type, "irdyn") == 0)
	{
		expected_packet = PACKET_IR_DYN;
	}
	else if(strlen(packet_type) == 3 && strcmp(packet_type, "uo0") == 0)
	{
		expected_packet = PACKET_UO_0;
	}
	else if(strlen(packet_type) == 3 && strcmp(packet_type, "uo1") == 0)
	{
		expected_packet = PACKET_UO_1_ID;
	}
	else if(strlen(packet_type) == 4 && strcmp(packet_type, "uor2") == 0)
	{
		expected_packet = PACKET_UOR_2_TS;
	}
	else
	{
		fprintf(stderr, "unknown packet type '%s'\n\n", packet_type);
		usage();
		goto error;
	}

	/* init the CRC tables */
	crc_init_table(crc_table_3, crc_get_polynom(CRC_TYPE_3));
	crc_init_table(crc_table_7, crc_get_polynom(CRC_TYPE_7));
	crc_init_table(crc_table_8, crc_get_polynom(CRC_TYPE_8));

	/* init the random system with a constant value for the test to be fully
	   reproductible */
	srand(5);

	/* test ROHC compression/decompression with the packets from the file */
	status = test_comp_and_decomp(filename, packet_to_damage, expected_packet);

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that damaged ROHC packets are correctly handled\n"
	        "\n"
	        "usage: test_damaged_packet [OPTIONS] FLOW PACKET_NUM PACKET_TYPE\n"
	        "\n"
	        "with:\n"
	        "  FLOW         The flow of Ethernet frames to compress/decompress\n"
	        "               (in PCAP format)\n"
	        "  PACKET_NUM   The packet # to damage\n"
	        "  PACKET_TYPE  The packet type expected for the last packet\n"
	        "               among: ir, irdyn, uo0, uo1, uor2\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with a flow of IP packets going through one
 *        compressor then one decompressor
 *
 * @param filename          The name of the PCAP file that contains the
 *                          IP packets
 * @param packet_to_damage  The packet # to damage
 * @param expected_packet   The type of ROHC packet expected at the end of the
 *                          source capture
 * @return                  0 in case of success,
 *                          1 in case of failure
 */
static int test_comp_and_decomp(const char *const filename,
                                const unsigned int packet_to_damage,
                                const rohc_packet_t expected_packet)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_comp *comp;
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
		link_len = ETHER_HDR_LEN;
	else if(link_layer_type == DLT_LINUX_SLL)
		link_len = LINUX_COOKED_HDR_LEN;
	else /* DLT_RAW */
		link_len = 0;

	/* create the ROHC compressor with MAX_CID = 15 (small CID) */
	comp = rohc_alloc_compressor(15, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto close_input;
	}
	rohc_activate_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(comp, ROHC_PROFILE_UDP);
	rohc_activate_profile(comp, ROHC_PROFILE_IP);
	rohc_activate_profile(comp, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(comp, ROHC_PROFILE_RTP);
	rohc_c_set_large_cid(comp, 0);

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
		unsigned char *ip_packet;
		int ip_size;
		static unsigned char rohc_packet[MAX_ROHC_SIZE];
		int rohc_size;
		rohc_comp_last_packet_info_t packet_info;
		int ret;
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

		/* get packet statistics to retrieve the packet type */
		ret = rohc_comp_get_last_packet_info(comp, &packet_info);
		if(ret != ROHC_OK)
		{
			fprintf(stderr, "\tfailed to get statistics on packet to damage\n");
			goto destroy_decomp;
		}

		/* is it the packet to damage? */
		if(counter == packet_to_damage)
		{
			unsigned char old_byte;

			/* check packet type of the packet to damage */
			if(packet_info.packet_type != expected_packet)
			{
				fprintf(stderr, "\tROHC packet #%u is of type %d while type %d was "
				        "expected\n", packet_to_damage, packet_info.packet_type,
				        expected_packet);
				goto destroy_decomp;
			}
			fprintf(stderr, "\tROHC packet #%u is of type %d as expected\n",
			        packet_to_damage, expected_packet);

			/* damage the packet (randomly modify its last byte) */
			assert(rohc_size >= 1);
			old_byte = rohc_packet[rohc_size - 1];
			rohc_packet[rohc_size - 1] ^= rand() & 0xff;
			fprintf(stderr, "\tvoluntary damage packet (change byte #%d from 0x%02x "
			        "to 0x%02x)\n", rohc_size, old_byte, rohc_packet[rohc_size - 1]);
		}
		else
		{
			fprintf(stderr, "\tROHC packet is of type %d\n", packet_info.packet_type);
		}

		/* decompress the generated ROHC packet with the ROHC decompressor */
		decomp_size = rohc_decompress(decomp, rohc_packet, rohc_size,
		                              decomp_packet, MAX_ROHC_SIZE);
		if(decomp_size <= 0)
		{
			if(counter != packet_to_damage)
			{
				/* failure is NOT expected for the non-damaged packets */
				fprintf(stderr, "\tunexpected failure to decompress generated ROHC "
				        "packet\n");
				goto destroy_decomp;
			}
			else
			{
				/* failure is expected for the damaged packet */
				fprintf(stderr, "\texpected failure to decompress generated ROHC "
				        "packet\n");
			}
		}
		else
		{
			if(counter != packet_to_damage)
			{
				/* success is expected for the non-damaged packets */
				fprintf(stderr, "\texpected successful decompression\n");
			}
			else
			{
				/* success is NOT expected for the damaged packet */
				fprintf(stderr, "\tunexpected successful decompression\n");
				goto destroy_decomp;
			}
		}
	}

	/* everything went fine */
	fprintf(stderr, "all non-damaged packets were successfully decompressed\n");
	fprintf(stderr, "all damaged packets failed to be decompressed as expected\n");
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

