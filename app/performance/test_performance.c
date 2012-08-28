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
 * @file    test_performance.c
 * @brief   ROHC perf program
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 *
 * Introduction
 * ------------
 *
 * The program takes a flow of IP packets as input (in the PCAP format) and
 * tests the performance of the ROHC compression library with them.
 *
 * Details
 * -------
 *
 * The program defines one compressor and sends the flow of IP packet through
 * it. The time elapsed during the compression of every packet is determined.
 * See the figure below.
 *
 *                     +--------------+
 *                     |              |
 *   IP packets  ----> |  Compressor  | ---->  ROHC packets
 *                 ^   |              |   ^
 *                 |   +--------------+   |
 *                 |                      |
 *                 |----------------------|
 *                       elapsed time
 *
 * Checks
 * ------
 *
 * The program checks for the status of the compression process.
 *
 * Output
 * ------
 *
 * The program outputs the time elapsed for compression all packets, the number
 * of compressed packets and the average elapsed time per packet.
 */

/* system includes */
#include <sched.h>
#include <sys/mman.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

/* include for the PCAP library */
#include <pcap/pcap.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>


/** The application version */
#define APP_VERSION "ROHC performance test application, version 0.1"

/** Get the current number of CPU tics */
#define GET_CPU_TICS(cpu_tics_64bits) \
	__asm__ __volatile__ ("rdtsc" : "=A" (cpu_tics_64bits))

/**
 * @brief Give the number of nanoseconds elapsed between 2 given
 *        measures of CPU tics
 */
#define TICS_2_NSEC(coef_ns, end, start) \
	((unsigned long long)(((end) - (start)) * (coef_ns)))

/** The maximal size for the ROHC packets */
#define MAX_ROHC_SIZE  (5 * 1024)

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

/** The minimum Ethernet length (in bytes) */
#define ETHER_FRAME_MIN_LEN  60


static void usage(void);

#if __i386__

static int tune_env_for_perfs(double *coef_nanosec);

static int test_compression_perfs(char *filename,
                                  double coef_nanosec,
                                  unsigned long *packet_count,
                                  unsigned long *overflows,
                                  unsigned long long *time_elapsed);

static int time_compress_packet(struct rohc_comp *comp,
                                unsigned long num_packet,
                                struct pcap_pkthdr header,
                                unsigned char *packet,
                                size_t link_len,
                                double coef_nanosec,
                                unsigned long long *time_elapsed);

static int gen_false_random_num(const struct rohc_comp *const comp,
                                void *const user_context)
	__attribute__((nonnull(1)));

#endif /* __i386__ */


/**
 * @brief Main function for the ROHC performance test program
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code: 0 in case of success, 1 in case of error,
 *             77 in case test is skipped
 */
int main(int argc, char *argv[])
{
	char *filename = NULL; /* the name of the PCAP capture used as input */
#if __i386__
	unsigned long packet_count = 0;
	unsigned long overflows = 0;
	unsigned long long time_elapsed = 0;
	double coef_nanosec; /* coefficient to convert from CPU tics to ns */
	int ret;
	unsigned long average;
	int i;
#endif
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 1)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc--, argv++)
	{
		if(!strcmp(*argv, "-v") || !strcmp(*argv, "--version"))
		{
			/* print version */
			fprintf(stderr, APP_VERSION "\n");
			goto error;
		}
		else if(!strcmp(*argv, "-h") || !strcmp(*argv, "--help"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(filename == NULL)
		{
			/* get the name of the file that contains the IP packets
			   to compress */
			filename = argv[0];
		}
		else
		{
			/* do not accept more than one filename without option name */
			usage();
			goto error;
		}
	}

	/* the source filename is mandatory */
	if(filename == NULL)
	{
		usage();
		goto error;
	}

#if !__i386__
	/* skip test because the test uses x86 ASM */
	status = 77;
#else
	/* tune environment for performance
	   (realtime priority, disable swapping...) */
	ret = tune_env_for_perfs(&coef_nanosec);
	if(ret != 0)
	{
		fprintf(stderr, "failed to tune environment for performance\n");
		goto error;
	}

	/* test ROHC compression with the packets from the capture */
	ret = test_compression_perfs(filename, coef_nanosec,
	                             &packet_count, &overflows, &time_elapsed);
	if(ret != 0)
	{
		fprintf(stderr, "performance test failed, see above error(s)\n");
		goto release_rohc_lib;
	}

	/* print performance statistics */
	fprintf(stderr, "total time elapsed               =  %lu * %lu + %lu ns\n",
	        0xffffffffUL, overflows, (unsigned long) time_elapsed);
	fprintf(stderr, "total number of packets          =  %lu packets\n",
	        packet_count);
	average = time_elapsed / packet_count;
	for(i = 0; i < overflows; i++)
	{
		average += 0xffffffffUL / packet_count;
	}
	fprintf(stderr, "average elapsed time per packet  =  %lu ns/packet\n",
	        average);

	/* everything went fine */
	status = 0;

release_rohc_lib:
#endif
error:
	return status;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	fprintf(stderr,
	        "ROHC performance test: test the performance of the ROHC library\n"
	        "                       with a flow of IP packets\n\n"
	        "usage: test_performance [-h|--help] [-v|--version] flow\n"
	        "  --version        print version information and exit\n"
	        "  -v\n"
	        "  --help           print application usage and exit\n"
	        "  -h\n"
	        "  flow  flow of Ethernet frames to compress (PCAP format)\n");
}


#if __i386__

/**
 * @brief Tune environment for performance
 *
 * Set high realtime priority.
 * Disable swapping.
 * Initialize CPU tics to nanoseconds coefficient.
 *
 * @param coef_nanosec  OUT: the CPU tics to nanoseconds coefficient
 * @return              0 in case of success, 1 otherwise
 */
static int tune_env_for_perfs(double *coef_nanosec)
{
	struct sched_param param;
	unsigned long long tics1;
	unsigned long long tics2;
	unsigned int i;
	int ret;

	/* set the process to realtime priority */
	bzero(&param, sizeof(struct sched_param));
	param.sched_priority = sched_get_priority_max(SCHED_FIFO);
	if(param.sched_priority == -1)
	{
		fprintf(stderr, "failed to get maximum scheduler priority: "
		        "%s (%d)\n", strerror(errno), errno);
		goto error;
	}
	ret = sched_setscheduler(0, SCHED_FIFO, &param);
	if(ret != 0)
	{
		fprintf(stderr, "failed to set high scheduler priority: %s (%d)\n",
		        strerror(errno), errno);
		goto error;
	}

	/* avoid swapping */
	ret = mlockall(MCL_CURRENT | MCL_FUTURE);
	if(ret != 0)
	{
		fprintf(stderr, "failed to disable swapping: %s (%d)\n",
		        strerror(errno), errno);
		goto error;
	}

	/* determine CPU tics to nanoseconds coefficient */
	*coef_nanosec = 0;
	for(i = 0; i < 10; i++)
	{
		GET_CPU_TICS(tics1);
		sleep(1);
		GET_CPU_TICS(tics2);
		*coef_nanosec += 1.e9 / (tics2 - tics1);
	}
	*coef_nanosec /= 10;
	fprintf(stderr, "CPU frequency estimated to %.6f GHz\n",
	        1. / (*coef_nanosec));

	return 0;

error:
	return 1;
}


/**
 * @brief Test the compression performance of the ROHC library
 *        with a flow of IP packets
 *
 * @param filename      The name of the PCAP file that contains the IP packets
 * @param coef_nanosec  The coefficient to convert from CPU tics to nanoseconds
 * @param packet_count  OUT: the number of compressed packets, undefined if
 *                      compression failed
 * @param time_elapsed  OUT: the time elapsed for compression (in nanoseconds),
 *                      unchanged if compression failed
 * @return              0 in case of success, 1 otherwise
 */
static int test_compression_perfs(char *filename,
                                  double coef_nanosec,
                                  unsigned long *packet_count,
                                  unsigned long *overflows,
                                  unsigned long long *time_elapsed)
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int link_layer_type;
	size_t link_len;
	struct pcap_pkthdr header;
	unsigned char *packet;
	struct rohc_comp *comp;
	int is_failure = 1;
	int ret;

	/* open the PCAP file that contains the stream */
	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "failed to open the pcap file: %s\n", errbuf);
		goto exit;
	}

	/* link layer in the capture must be Ethernet */
	link_layer_type = pcap_datalink(handle);
	if(link_layer_type != DLT_EN10MB &&
	   link_layer_type != DLT_LINUX_SLL &&
	   link_layer_type != DLT_RAW)
	{
		fprintf(stderr, "link layer type %d not supported in capture "
		        "(supported = %d, %d, %d)\n", link_layer_type,
		        DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW);
		goto close_input;
	}

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

	/* create ROHC compressor */
	comp = rohc_alloc_compressor(ROHC_SMALL_CID_MAX, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC compressor\n");
		goto close_input;
	}

	/* set the callback for random numbers */
	if(!rohc_comp_set_random_cb(comp, gen_false_random_num, NULL))
	{
		fprintf(stderr, "failed to set the callback for random numbers\n");
		goto free_compresssor;
	}

	/* activate all the compression profiles */
	rohc_activate_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(comp, ROHC_PROFILE_RTP);
	rohc_activate_profile(comp, ROHC_PROFILE_UDP);
	rohc_activate_profile(comp, ROHC_PROFILE_IP);
	rohc_activate_profile(comp, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(comp, ROHC_PROFILE_ESP);

	/* for each packet in the dump */
	*packet_count = 0;
	*time_elapsed = 0;
	*overflows = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		unsigned long long packet_time_elapsed = 0;

		(*packet_count)++;

		/* compress the IP packet */
		ret = time_compress_packet(comp, *packet_count,
		                           header, packet, link_len,
		                           coef_nanosec, &packet_time_elapsed);
		if(ret != 0)
		{
			fprintf(stderr, "packet %lu: performance test failed\n",
			        *packet_count);
			goto free_compresssor;
		}

		if((*time_elapsed) > (0xffffffff - packet_time_elapsed))
		{
			(*overflows)++;
			packet_time_elapsed -= 0xffffffff - (*time_elapsed);
			*time_elapsed = packet_time_elapsed;
		}
		else
		{
			*time_elapsed += packet_time_elapsed;
		}
	}

	/* everything went fine */
	is_failure = 0;

free_compresssor:
	rohc_free_compressor(comp);
close_input:
	pcap_close(handle);
exit:
	return is_failure;
}


/**
 * @brief Determine the time required to compress the given IP packet
 *        with the given compressor
 *
 * @param comp          The compressor to use to compress the IP packet
 * @param num_packet    A number affected to the IP packet to compress (traces only)
 * @param header        The PCAP header for the packet
 * @param packet        The packet to compress (link layer included)
 * @param link_len      The length of the link layer header before IP data
 * @param coef_nanosec  The coefficient to convert from CPU tics to nanoseconds
 * @param time_elapsed  OUT: the time elapsed for compression (in nanoseconds),
 *                      unchanged if compression failed
 * @return              0 if compression is successful, 1 otherwise
 */
static int time_compress_packet(struct rohc_comp *comp,
                                unsigned long num_packet,
                                struct pcap_pkthdr header,
                                unsigned char *packet,
                                size_t link_len,
                                double coef_nanosec,
                                unsigned long long *time_elapsed)
{
	unsigned char *ip_packet;
	unsigned int ip_size;
	static unsigned char rohc_packet[MAX_ROHC_SIZE];
	int rohc_size;
	unsigned long long start_tics;
	unsigned long long end_tics;
	int is_failure = 1;

	/* check Ethernet frame length */
	if(header.len <= link_len || header.len != header.caplen)
	{
		fprintf(stderr, "packet %lu: bad PCAP packet "
		        "(len = %d, caplen = %d)\n",
		        num_packet, header.len, header.caplen);
		goto error;
	}

	/* skip the link layer header */
	ip_packet = packet + link_len;
	ip_size = header.len - link_len;

	/* check for padding after the IP packet in the Ethernet payload */
	if(link_len == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
	{
		uint8_t ip_version;
		uint16_t tot_len;

		/* determine the total length of the IP packet */
		ip_version = (ip_packet[0] >> 4) & 0x0f;
		if(ip_version == 4) /* IPv4 */
		{
			struct iphdr *ip;

			ip = (struct iphdr *) ip_packet;
			tot_len = ntohs(ip->tot_len);
		}
		else if(ip_version == 6) /* IPv6 */
		{
			struct ip6_hdr *ip;

			ip = (struct ip6_hdr *) ip_packet;
			tot_len = sizeof(struct ip6_hdr) + ntohs(ip->ip6_plen);
		}
		else /* unknown IP version */
		{
			fprintf(stderr, "packet %lu: bad IP version (0x%x) "
			        "in packet\n", num_packet, ip_version);
			goto error;
		}

		/* update the length of the IP packet if padding is present */
		if(tot_len < ip_size)
		{
			fprintf(stderr, "packet %lu: the Ethernet frame has %u "
			        "bytes of padding after the %u-byte IP packet!\n",
			        num_packet, ip_size - tot_len, tot_len);
			ip_size = tot_len;
		}
	}

	/* get CPU tics before compression */
	GET_CPU_TICS(start_tics);

	/* compress the packet */
	rohc_size = rohc_compress(comp, ip_packet, ip_size,
	                          rohc_packet, MAX_ROHC_SIZE);

	/* get CPU tics after compression */
	GET_CPU_TICS(end_tics);

	/* stop performance test if compression failed */
	if(rohc_size <= 0)
	{
		fprintf(stderr, "packet %lu: compression failed\n", num_packet);
		goto error;
	}

	/* compute the time elapsed during the compression process */
	*time_elapsed = TICS_2_NSEC(coef_nanosec, end_tics, start_tics);

	/* everything went fine */
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Generate a false random number for testing the ROHC library
 *
 * We want to test the performances of the ROHC library, not the performances
 * of a random generator, so disable it.
 *
 * @param comp          The ROHC compressor
 * @param user_context  Should always be NULL
 * @return              Always 0
 */
static int gen_false_random_num(const struct rohc_comp *const comp,
                                void *const user_context)
{
	assert(comp != NULL);
	assert(user_context == NULL);
	return 0;
}

#endif /* __i386__ */
