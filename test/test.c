/**
 * @file test.c
 * @brief ROHC test program
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author David Moreau from TAS
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
 * Output
 * ------
 *
 * The program outputs XML containing the compression/decompression/comparison
 * status of every packets of flow A and flow B on stdout. It also outputs the
 * log of the different processes (startup, compression, decompression,
 * comparison and shutdown).
 *
 * The program optionally outputs the ROHC packets in a PCAP packet.
 */

#include "test.h"


/**
 * @brief Main function for the ROHC test program
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code
 */
int main(int argc, char *argv[])
{
	char *src_filename = NULL;
	char *ofilename = NULL;
	char *cmp_filename = NULL;
	int failure = 1;
	int args_used;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 1)
	{
		printf(USAGE);
		goto quit;
	}

	for(argc--, argv++; argc > 0; argc -= args_used, argv += args_used)
	{
		args_used = 1;

		if(!strcmp(*argv, "-v"))
		{
			/* print version */
			printf(VERSION);
			goto quit;
		}
		else if(!strcmp(*argv, "-h"))
		{
			/* print help */
			printf(USAGE);
			goto quit;
		}
		else if(!strcmp(*argv, "-o"))
		{
			/* get the name of the file to store the ROHC packets */
			ofilename = argv[1];
			args_used++;
		}
		else if(!strcmp(*argv, "-c"))
		{
			/* get the name of the file where the ROHC packets used for comparison
			 * are stored */
			cmp_filename = argv[1];
			args_used++;
		}
		else if(src_filename == NULL)
		{
			/* get the name of the file that contains the packets to
			 * compress/decompress */
			src_filename = argv[0];
		}
		else
		{
			/* do not accept more than one filename without option name */
			printf(USAGE);
			goto quit;
		}
	}

	/* the source filename is mandatory */
	if(src_filename == NULL)
	{
		printf(USAGE);
		goto quit;
	}

	/* init the CRC tables */
	crc_init_table(crc_table_3, crc_get_polynom(CRC_TYPE_3));
	crc_init_table(crc_table_7, crc_get_polynom(CRC_TYPE_7));
	crc_init_table(crc_table_8, crc_get_polynom(CRC_TYPE_8));

	/* test ROHC compression/decompression with the packets from the file */
	test_comp_and_decomp(src_filename, ofilename, cmp_filename);

	failure = 0;

quit:
	return failure;
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
int compare_packets(unsigned char *pkt1, int pkt1_size,
                    unsigned char *pkt2, int pkt2_size)
{
	int valid = 1;
	int min_size;
	int i, j, k;
	char str1[4][7], str2[4][7];
	char sep1, sep2;

	min_size = pkt1_size > pkt2_size ? pkt2_size : pkt1_size;
	
	/* if packets are equal, do not print the packets */
	if(pkt1_size == pkt2_size && memcmp(pkt1, pkt2, pkt1_size) == 0)
		goto skip;

	/* packets are different */
	valid = 0;

	printf("------------------------------ Compare ------------------------------\n");
	
	if(pkt1_size != pkt2_size)
		printf("packets have different sizes (%d != %d), compare only the %d "
		       "first bytes\n", pkt1_size, pkt2_size, min_size);

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
					printf("%s  ", str1[k]);
				else /* fill the line with blanks if nothing to print */
					printf("        ");
			}

			printf("      ");

			for(k = 0; k < (j + 1); k++)
				printf("%s  ", str2[k]);

			printf("\n");

			j = 0;
		}
		else
			j++;
	}

	printf("----------------------- packets are different -----------------------\n");

skip:
	return valid;
}


/**
 * @brief Print statistics about the compressors and decompressors used during
 *        the test
 *
 * @param comp1   The first compressor
 * @param decomp1 The decompressor that receives data from the first compressor
 * @param comp2 The second compressor
 * @param decomp2 The decompressor that receives data from the second compressor
 */
void show_rohc_stats(struct rohc_comp *comp1, struct rohc_decomp *decomp1,
                     struct rohc_comp *comp2, struct rohc_decomp *decomp2)
{
	char buffer[80000];
	int len;
	unsigned int indent = 2;

	buffer[0] = '\0';

	/* compute compressor statistics */
	len = rohc_c_statistics(comp1, indent, buffer);
	len = rohc_c_statistics(comp2, indent, buffer);

	/* compute decompressor statistics */
	len = rohc_d_statistics(decomp1, indent, buffer);
	len = rohc_d_statistics(decomp2, indent, buffer);

	/* print statistics */
	printf("%s", buffer);
}


/**
 * @brief Compress and decompress one uncompressed IP packet with the given
 *        compressor and decompressor
 *
 * @param comp          The compressor to use to compress the IP packet
 * @param decomp        The decompressor to use to decompress the IP packet
 * @param num_comp      The ID of the compressor/decompressor
 * @param num_packet    A number affected to the IP packet to compress/decompress
 * @param header        The PCAP header for the packet
 * @param packet        The packet to compress/decompress (link layer included)
 * @param link_len_src  The length of the link layer header before IP data
 * @param dumper        The PCAP output dump file
 * @param cmp_packet    The ROHC packet for comparison purpose
 * @param cmp_size      The size of the ROHC packet used for comparison purpose
 * @param link_len_cmp  The length of the link layer header before ROHC data
 * @return              1 if the process is successful
 *                      0 if the decompressed packet doesn't match the original
 *                      one
 *                      -1 if an error occurs while compressing
 *                      -2 if an error occurs while decompressing
 *                      -3 if the link layer is not Ethernet
 */
int compress_decompress(struct rohc_comp *comp,
                        struct rohc_decomp *decomp,
                        int num_comp,
                        int num_packet,
                        struct pcap_pkthdr header,
                        unsigned char *packet,
                        int link_len_src,
                        pcap_dumper_t *dumper,
                        unsigned char *cmp_packet,
                        int cmp_size,
                        int link_len_cmp)
{
	unsigned char *ip_packet;
	int ip_size;
	static unsigned char output_packet[max(ETHER_HDR_LEN, LINUX_COOKED_HDR_LEN) + MAX_ROHC_SIZE];
	unsigned char *rohc_packet;
	int rohc_size;
	static unsigned char decomp_packet[MAX_ROHC_SIZE];
	int decomp_size;
	struct ether_header *eth_header;
	int ret = 1;

	printf("\t<packet id=\"%d\" comp=\"%d\">\n", num_packet, num_comp);

	/* check Ethernet frame length */
	if(header.len <= link_len_src || header.len != header.caplen)
	{
		printf("\t\t<compression>\n");
		printf("\t\t\t<log>\n");
		printf("bad PCAP packet (len = %d, caplen = %d)\n", header.len, header.caplen);
		printf("\t\t\t</log>\n");
		printf("\t\t\t<status>failed</status>\n");
		printf("\t\t</compression>\n");
		printf("\n");
		printf("\t\t<decompression>\n");
		printf("\t\t\t<log>\n");
		printf("Compression failed, cannot decompress the ROHC packet!\n");
		printf("\t\t\t</log>\n");
		printf("\t\t\t<status>failed</status>\n");
		printf("\t\t</decompression>\n");
		printf("\n");
		printf("\t\t<comparison>\n");
		printf("\t\t\t<log>\n");
		printf("Compression failed, cannot compare the packets!\n");
		printf("\t\t\t</log>\n");
		printf("\t\t\t<status>failed</status>\n");
		printf("\t\t</comparison>\n");

		ret = -3;
		goto exit;
	}

	ip_packet = packet + link_len_src;
	ip_size = header.len - link_len_src;
	rohc_packet = output_packet + link_len_src;

	/* check for padding after the IP packet in the Ethernet payload */
	if(link_len_src == ETHER_HDR_LEN &&
	   header.len == 60 /* min Ethernet length */ )
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
			printf("The Ethernet frame has %d bytes of padding after the "
			       "%d byte IP packet!\n", ip_size - tot_len, tot_len);
			ip_size = tot_len;
		}
	}

	/* compress the IP packet */
	printf("\t\t<compression>\n");
	printf("\t\t\t<log>\n");
	rohc_size = rohc_compress(comp, ip_packet, ip_size,
	                          rohc_packet, MAX_ROHC_SIZE);
	printf("\t\t\t</log>\n");

	if(rohc_size <= 0)
	{
		printf("\t\t\t<status>failed</status>\n");
		printf("\t\t</compression>\n");
		printf("\n");
		printf("\t\t<rohc_comparison>\n");
		printf("\t\t\t<log>\n");
		printf("Compression failed, cannot compare the packets!\n");
		printf("\t\t\t</log>\n");
		printf("\t\t\t<status>failed</status>\n");
		printf("\t\t</rohc_comparison>\n");
		printf("\n");
		printf("\t\t<decompression>\n");
		printf("\t\t\t<log>\n");
		printf("Compression failed, cannot decompress the ROHC packet!\n");
		printf("\t\t\t</log>\n");
		printf("\t\t\t<status>failed</status>\n");
		printf("\t\t</decompression>\n");
		printf("\n");
		printf("\t\t<ip_comparison>\n");
		printf("\t\t\t<log>\n");
		printf("Compression failed, cannot compare the packets!\n");
		printf("\t\t\t</log>\n");
		printf("\t\t\t<status>failed</status>\n");
		printf("\t\t</ip_comparison>\n");

		ret = -1;
		goto exit;
	}

	printf("\t\t\t<status>ok</status>\n");
	printf("\t\t</compression>\n\n");

	/* output the ROHC packet to the PCAP dump file if asked */
	if(dumper != NULL)
	{
		header.len = link_len_src + rohc_size;
		header.caplen = header.len;
		if(link_len_src != 0)
		{
			memcpy(output_packet, packet, link_len_src); /* add the link layer header */
			if(link_len_src == ETHER_HDR_LEN) /* Ethernet only */
			{
				eth_header = (struct ether_header *) output_packet;
				eth_header->ether_type = 0x162f; /* unused Ethernet ID ? */
			}
			else if(link_len_src == LINUX_COOKED_HDR_LEN) /* Linux Cooked Sockets only */
			{
				output_packet[LINUX_COOKED_HDR_LEN - 2] = 0x16;
				output_packet[LINUX_COOKED_HDR_LEN - 1] = 0x2f;
			}
		}
		pcap_dump((u_char *) dumper, &header, output_packet);
	}
	
	/* compare the ROHC packets with the ones given by the user if asked */
	printf("\t\t<rohc_comparison>\n");
	printf("\t\t\t<log>\n");
	if(cmp_packet != NULL && cmp_size > link_len_cmp)
	{
		if(!compare_packets(cmp_packet + link_len_cmp, cmp_size - link_len_cmp,
		                    rohc_packet, rohc_size))
		{
			printf("\t\t\t</log>\n");
			printf("\t\t\t<status>failed</status>\n");
			ret = 0;
		}
		else
		{
			printf("Packets are equal\n");
			printf("\t\t\t</log>\n");
			printf("\t\t\t<status>ok</status>\n");
		}
	}
	else
	{
		printf("No ROHC packets given for reference, cannot compare (run with the -c option)\n");
		printf("\t\t\t</log>\n");
		printf("\t\t\t<status>failed</status>\n");
		ret = 0;
	}
	printf("\t\t</rohc_comparison>\n\n");

	/* decompress the ROHC packet */
	printf("\t\t<decompression>\n");
	printf("\t\t\t<log>\n");
	decomp_size = rohc_decompress(decomp, rohc_packet, rohc_size, decomp_packet, MAX_ROHC_SIZE);
	printf("\t\t\t</log>\n");
	
	if(decomp_size <= 0)
	{
		printf("\t\t\t<status>failed</status>\n");
		printf("\t\t</decompression>\n");
		printf("\n");
		printf("\t\t<ip_comparison>\n");
		printf("\t\t\t<log>\n");
		printf("Decompression failed, cannot compare the packets!\n");
		printf("\t\t\t</log>\n");
		printf("\t\t\t<status>failed</status>\n");
		printf("\t\t</ip_comparison>\n");

		ret = -2;
		goto exit;
	}

	printf("\t\t\t<status>ok</status>\n");
	printf("\t\t</decompression>\n\n");

	/* compare the decompressed packet with the original one */
	printf("\t\t<ip_comparison>\n");
	printf("\t\t\t<log>\n");
	if(!compare_packets(ip_packet, ip_size, decomp_packet, decomp_size))
	{
		printf("\t\t\t</log>\n");
		printf("\t\t\t<status>failed</status>\n");
		ret = 0;
	}
	else
	{
		printf("Packets are equal\n");
		printf("\t\t\t</log>\n");
		printf("\t\t\t<status>ok</status>\n");
	}
	printf("\t\t</ip_comparison>\n");

exit:
	printf("\t</packet>\n\n");
	return ret;
}


/**
 * @brief Test the ROHC library with a flow of IP packets going through
 *        two compressor/decompressor pairs
 *
 * @param src_filename  The name of the PCAP file that contains the IP packets
 * @param ofilename     The name of the PCAP file to output the ROHC packets
 * @param cmp_filename  The name of the PCAP file that contains the ROHC
 *                      packets used for comparison
 */
void test_comp_and_decomp(char *src_filename,
                          char *ofilename,
                          char *cmp_filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	pcap_t *cmp_handle;
	pcap_dumper_t *dumper;
	int link_layer_type_src, link_layer_type_cmp;
	int link_len_src, link_len_cmp = 0;
	struct pcap_pkthdr header;
	struct pcap_pkthdr cmp_header;

	unsigned char *packet;
	unsigned char *cmp_packet;

	int counter;

	struct rohc_comp *comp1;
	struct rohc_comp *comp2;

	struct rohc_decomp * decomp1;
	struct rohc_decomp * decomp2;

	int ret;
	int nb_bad = 0, nb_ok = 0, err_comp = 0, err_decomp = 0;

	printf("<?xml version=\"1.0\" encoding=\"ISO-8859-15\"?>\n");
	printf("<test>\n");
	printf("\t<startup>\n");
	printf("\t\t<log>\n");

	/* open the source dump file */
	handle = pcap_open_offline(src_filename, errbuf);
	if(handle == NULL)
	{
		printf("failed to open the source pcap file: %s\n", errbuf);
		printf("\t\t</log>\n");
		printf("\t\t<status>failed</status>\n");
		printf("\t</startup>\n\n");
		goto exit;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type_src = pcap_datalink(handle);
	if(link_layer_type_src != DLT_EN10MB &&
	   link_layer_type_src != DLT_LINUX_SLL &&
	   link_layer_type_src != DLT_RAW)
	{
		printf("link layer type %d not supported in source dump (supported = "
		       "%d, %d, %d)\n", link_layer_type_src, DLT_EN10MB, DLT_LINUX_SLL,
		       DLT_RAW);
		printf("\t\t</log>\n");
		printf("\t\t<status>failed</status>\n");
		printf("\t</startup>\n\n");
		goto close_input;
	}

	if(link_layer_type_src == DLT_EN10MB)
		link_len_src = ETHER_HDR_LEN;
	else if(link_layer_type_src == DLT_LINUX_SLL)
		link_len_src = LINUX_COOKED_HDR_LEN;
	else /* DLT_RAW */
		link_len_src = 0;

	/* open the network dump file for ROHC storage if asked */
	if(ofilename != NULL)
	{
		dumper = pcap_dump_open(handle, ofilename);
		if(dumper == NULL)
		{
			printf("failed to open dump file: %s\n", errbuf);
			printf("\t\t</log>\n");
			printf("\t\t<status>failed</status>\n");
			printf("\t</startup>\n\n");
			goto close_input;
		}
	}
	else
		dumper = NULL;

	/* open the ROHC comparison dump file if asked */
	if(cmp_filename != NULL)
	{
		cmp_handle = pcap_open_offline(cmp_filename, errbuf);
		if(cmp_handle == NULL)
		{
			printf("failed to open the comparison pcap file: %s\n", errbuf);
			printf("\t\t</log>\n");
			printf("\t\t<status>failed</status>\n");
			printf("\t</startup>\n\n");
			goto close_output;
		}

		/* link layer in the rohc_comparison dump must be Ethernet */
		link_layer_type_cmp = pcap_datalink(cmp_handle);
		if(link_layer_type_cmp != DLT_EN10MB &&
		   link_layer_type_cmp != DLT_LINUX_SLL &&
		   link_layer_type_cmp != DLT_RAW)
		{
			printf("link layer type %d not supported in comparision dump "
			       "(supported = %d, %d, %d)\n", link_layer_type_cmp, DLT_EN10MB,
			       DLT_LINUX_SLL, DLT_RAW);
			printf("\t\t</log>\n");
			printf("\t\t<status>failed</status>\n");
			printf("\t</startup>\n\n");
			goto close_comparison;
		}

		if(link_layer_type_cmp == DLT_EN10MB)
			link_len_cmp = ETHER_HDR_LEN;
		else if(link_layer_type_cmp == DLT_LINUX_SLL)
			link_len_cmp = LINUX_COOKED_HDR_LEN;
		else /* DLT_RAW */
			link_len_cmp = 0;
	}
	else
		cmp_handle = NULL;

	/* create the compressor 1 */
	comp1 = rohc_alloc_compressor(15);
	if(comp1 == NULL)
	{
		printf("cannot create the compressor 1\n");
		printf("\t\t</log>\n");
		printf("\t\t<status>failed</status>\n");
		printf("\t</startup>\n\n");
		goto close_comparison;
	}
	rohc_activate_profile(comp1, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(comp1, ROHC_PROFILE_UDP);
	rohc_activate_profile(comp1, ROHC_PROFILE_IP);
	rohc_activate_profile(comp1, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(comp1, ROHC_PROFILE_RTP);

	/* create the compressor 2 */
	comp2 = rohc_alloc_compressor(15);
	if(comp2 == NULL)
	{
		printf("cannot create the compressor 2\n");
		printf("\t\t</log>\n");
		printf("\t\t<status>failed</status>\n");
		printf("\t</startup>\n\n");
		printf("\t<shutdown>\n");
		printf("\t\t<log>\n");
		goto destroy_comp1;
	}
	rohc_activate_profile(comp2, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(comp2, ROHC_PROFILE_UDP);
	rohc_activate_profile(comp2, ROHC_PROFILE_IP);
	rohc_activate_profile(comp2, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(comp2, ROHC_PROFILE_RTP);

	/* create the decompressor 1 */
	decomp1 = rohc_alloc_decompressor(comp2);
	if(decomp1 == NULL)
	{
		printf("cannot create the decompressor 1\n");
		printf("\t\t</log>\n");
		printf("\t\t<status>failed</status>\n");
		printf("\t</startup>\n\n");
		printf("\t<shutdown>\n");
		printf("\t\t<log>\n");
		goto destroy_comp2;
	}

	/* create the decompressor 2 */
	decomp2 = rohc_alloc_decompressor(comp1);
	if(decomp2 == NULL)
	{
		printf("cannot create the decompressor 2\n");
		printf("\t\t</log>\n");
		printf("\t\t<status>failed</status>\n");
		printf("\t</startup>\n\n");
		printf("\t<shutdown>\n");
		printf("\t\t<log>\n");
		goto destroy_decomp1;
	}
	
	printf("\t\t</log>\n");
	printf("\t\t<status>ok</status>\n");
	printf("\t</startup>\n\n");

	/* for each packet in the dump */
	counter = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		counter++;

		/* get next ROHC packet from the comparison dump file if asked */
		if(cmp_handle != NULL)
			cmp_packet = (unsigned char *) pcap_next(cmp_handle, &cmp_header);
		else
			cmp_packet = NULL;

		/* compress & decompress from 1 to 2 */
		ret = compress_decompress(comp1, decomp2, 1, counter, header, packet,
		                          link_len_src, dumper, cmp_packet,
		                          cmp_header.caplen, link_len_cmp);
		if(ret == -1)
			err_comp++;
		else if(ret == -2)
			err_decomp++;
		else if(ret == 1)
			nb_ok++;
		else if(ret == -3)
			nb_bad++;

		/* get next ROHC packet from the comparison dump file if asked */
		if(cmp_handle != NULL)
			cmp_packet = (unsigned char *) pcap_next(cmp_handle, &cmp_header);
		else
			cmp_packet = NULL;

		/* compress & decompress from 2 to 1 */
		ret = compress_decompress(comp2, decomp1, 2, counter, header, packet,
		                          link_len_src, dumper, cmp_packet,
		                          cmp_header.caplen, link_len_cmp);
		if(ret == -1)
			err_comp++;
		else if(ret == -2)
			err_decomp++;
		else if(ret == 1)
			nb_ok++;
		else if(ret == -3)
			nb_bad++;
	}

	/* show the compression/decompression results */
	printf("\t<summary>\n");
	printf("\t\t<packets_processed>%d</packets_processed>\n", 2 * counter);
	printf("\t\t<compression_failed>%d</compression_failed>\n",  nb_bad + err_comp);
	printf("\t\t<decompression_failed>%d</decompression_failed>\n", err_decomp);
	printf("\t\t<matches>%d</matches>\n", nb_ok);
	printf("\t</summary>\n\n");

	/* show some info/stats about the compressors and decompressors */
	printf("\t<infos>\n");
	show_rohc_stats(comp1, decomp1, comp2, decomp2);
	printf("\t</infos>\n\n");
	
	/* destroy the compressors and decompressors */
	printf("\t<shutdown>\n");
	printf("\t\t<log>\n\n");

	rohc_free_decompressor(decomp2);
destroy_decomp1:
	rohc_free_decompressor(decomp1);
destroy_comp2:
	rohc_free_compressor(comp2);
destroy_comp1:
	rohc_free_compressor(comp1);
	printf("\t\t</log>\n");
	printf("\t\t<status>ok</status>\n");
	printf("\t</shutdown>\n\n");
close_comparison:
	if(cmp_handle != NULL)
		pcap_close(cmp_handle);
close_output:
	if(dumper != NULL)
		pcap_dump_close(dumper);
close_input:
	pcap_close(handle);
exit:
	printf("</test>\n");
}

