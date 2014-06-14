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
 * @file   rtp_fuzzer.c
 * @brief  ROHC fuzzer program for RTP compression/decompression
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * Stress test the ROHC compressor and decompressor to discover bugs related
 * to the RTP profile.
 */

/* system includes */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>

/* includes for network headers */
#include <ip.h> /* for IPv4 checksum */
#include <protocols/ipv4.h>
#include <protocols/udp.h>
#include <protocols/rtp.h>

/* ROHC includes */
#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>


/** The maximum size of IP and ROHC packets */
#define PACKET_MAX_SIZE 2048


/* prototypes of private functions */
static void usage(void);
static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));
static int gen_false_random_num(const struct rohc_comp *const comp,
                                void *const user_context)
	__attribute__((nonnull(1)));
static bool rtp_detect_cb(const unsigned char *const ip,
                          const unsigned char *const udp,
                          const unsigned char *const payload,
                          const unsigned int payload_size,
                          void *const rtp_private)
	__attribute__((nonnull(1, 2, 3), warn_unused_result));
static unsigned int add_sometimes(const size_t period, const unsigned int max)
	__attribute__((warn_unused_result));
static void fuzzer_interrupt(int signal);


/** The maximum number of traces to keep */
#define MAX_LAST_TRACES  5000
/** The maximum length of a trace */
#define MAX_TRACE_LEN  300

/** The ring buffer for the last traces */
static char last_traces[MAX_LAST_TRACES][MAX_TRACE_LEN + 1];
/** The index of the first trace */
static int last_traces_first;
/** The index of the last trace */
static int last_traces_last;


/**
 * @brief Main function for the ROHC fuzzer application
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	unsigned int rand_seed;
	struct rohc_comp *comp;
	struct rohc_decomp *decomp;
	const unsigned long max_iter = 2000000000;
	unsigned long cur_iter;
	int i;

	/* no traces at the moment */
	for(i = 0; i < MAX_LAST_TRACES; i++)
	{
		last_traces[i][0] = '\0';
	}
	last_traces_first = -1;
	last_traces_last = -1;

	/* parse arguments and check consistency */
	if(argc != 2 && argc != 3)
	{
		fprintf(stderr, "wrong number of arguments\n");
		usage();
		goto error;
	}
	else if(strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0)
	{
		/* print version */
		printf("rohc_rtp_fuzzer version %s\n", rohc_version());
		goto quit;
	}
	else if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
	{
		/* print help */
		usage();
		goto quit;
	}
	else if(strcmp(argv[1], "play") == 0)
	{
		/* 'play' command: no additional argument allowed */
		if(argc != 2)
		{
			fprintf(stderr, "play command does not take any argument\n");
			usage();
			goto error;
		}

		/* 'play' command: choose a random seed */
		rand_seed = time(NULL);
	}
	else if(strcmp(argv[1], "replay") == 0)
	{
		if(argc != 3)
		{
			fprintf(stderr, "replay command takes one argument\n");
			usage();
			goto error;
		}

		/* 'replay' command: take random seed given as argument */
		rand_seed = atoi(argv[2]);
	}
	else
	{
		fprintf(stderr, "unrecognized command '%s'\n", argv[1]);
		usage();
		goto error;
	}

	/* set signal handlers */
	signal(SIGINT, fuzzer_interrupt);
	signal(SIGTERM, fuzzer_interrupt);
	signal(SIGSEGV, fuzzer_interrupt);
	signal(SIGABRT, fuzzer_interrupt);

	printf("start fuzzing session with random seed %u\n", rand_seed);
	printf("you can use the replay command and the above random seed to run\n"
	       "the same fuzzing session again\n\n");
	srand(rand_seed);

	/* create the ROHC compressor (large CID, MAX_CID = 450) */
	comp = rohc_comp_new(ROHC_LARGE_CID, 450);
	assert(comp != NULL);
	/* set the callback for traces on compressor */
	assert(rohc_comp_set_traces_cb(comp, print_rohc_traces));
	/* enable the compression profiles */
	assert(rohc_comp_enable_profile(comp, ROHC_PROFILE_RTP));
	/* set the WLSB window width on compressor */
	assert(rohc_comp_set_wlsb_window_width(comp, 4));
	/* set the callback for random numbers on compressor */
	assert(rohc_comp_set_random_cb(comp, gen_false_random_num, NULL));
	/* set the callback for RTP stream detection */
	assert(rohc_comp_set_rtp_detection_cb(comp, rtp_detect_cb, NULL));

	/* create the ROHC decompressor
	 * (large CID, MAX_CID = 450, U-mode) */
	decomp = rohc_decomp_new2(ROHC_LARGE_CID, 450, ROHC_U_MODE);
	assert(decomp != NULL);
	/* set the callback for traces on ROHC decompressor */
	assert(rohc_decomp_set_traces_cb(decomp, print_rohc_traces));
	/* activate all the decompression profiles */
	assert(rohc_decomp_enable_profile(decomp, ROHC_PROFILE_RTP));

	/* decompress many random packets in a row */
	for(cur_iter = 1; cur_iter <= max_iter; cur_iter++)
	{
		const size_t payload_len = 20;

		uint8_t rohc_buffer[PACKET_MAX_SIZE];
		struct rohc_buf rohc_packet =
			rohc_buf_init_empty(rohc_buffer, PACKET_MAX_SIZE);

		uint8_t ip_buffer[PACKET_MAX_SIZE];
		struct rohc_buf ip_packet =
			rohc_buf_init_empty(ip_buffer, PACKET_MAX_SIZE);

		struct ipv4_hdr *ipv4;
		struct udphdr *udp;
		struct rtphdr *rtp;

		uint8_t ip_buffer2[PACKET_MAX_SIZE];
		struct rohc_buf ip_packet2 =
			rohc_buf_init_empty(ip_buffer2, PACKET_MAX_SIZE);

		int ret;

		/* print progress from time to time */
		if(cur_iter == 1 || (cur_iter % 10000) == 0)
		{
			if(cur_iter > 1)
			{
				printf("\r");
			}
			printf("iteration %lu / %lu", cur_iter, max_iter);
			fflush(stdout);
		}

		/* create one IP/UDP/RTP packet */
		ip_packet.len = sizeof(struct ipv4_hdr) + sizeof(struct udphdr) +
		                sizeof(struct rtphdr) + payload_len;
		/* build IPv4 header */
		ipv4 = (struct ipv4_hdr *) rohc_buf_data(ip_packet);
		ipv4->version = 4;
		ipv4->ihl = 5;
		ipv4->tos = 0 + add_sometimes(10000, 3);
		ipv4->tot_len = htons(ip_packet.len);
		ipv4->id = htons(42 + cur_iter + add_sometimes(10, 100));
		ipv4->frag_off = 0;
		ipv4->ttl = 64 + add_sometimes(10000, 5);
		ipv4->protocol = IPPROTO_UDP;
		ipv4->check = 0;
		ipv4->saddr = htonl(0xc0a80001 + add_sometimes(20, 100));
		ipv4->daddr = htonl(0xc0a80002 + add_sometimes(25, 200));
		ipv4->check = ip_fast_csum((uint8_t *) ipv4, ipv4->ihl);

		/* build UDP header */
		udp = (struct udphdr *) (rohc_buf_data(ip_packet) +
		                         sizeof(struct ipv4_hdr));
		udp->source = htons(1234 + add_sometimes(10, 10000) / 2 * 2);
		udp->dest = htons(1234 + add_sometimes(15, 20000) / 2 * 2);
		udp->len = htons(ip_packet.len - sizeof(struct ipv4_hdr));
		udp->check = 0; /* UDP checksum disabled */

		/* build RTP header */
		rtp = (struct rtphdr *) (rohc_buf_data(ip_packet) +
		                         sizeof(struct ipv4_hdr) +
		                         sizeof(struct udphdr));
		rtp->version = 2;
		rtp->padding = 0;
		rtp->extension = 0;
		rtp->cc = 0;
		rtp->m = 0 + add_sometimes(5000, 1);
		rtp->pt = 0x72 + add_sometimes(10000000, 30);
		rtp->sn = htons(cur_iter + add_sometimes(1000000, 30));
		rtp->timestamp = htonl(500000 + add_sometimes(50000000, 30) +
		                       (cur_iter + add_sometimes(5000000, 10)) * 160);
		rtp->ssrc = htonl(0x42424242 + add_sometimes(100, 0x2894729));

		/* compress the IP/UDP/RTP packet */
		ret = rohc_compress4(comp, ip_packet, &rohc_packet);
		if(ret != ROHC_OK)
		{
			fprintf(stderr, "\nfailed to compress packet\n");
			assert(0);
			goto clean;
		}

		/* decompress the ROHC packet */
		ret = rohc_decompress3(decomp, rohc_packet, &ip_packet2, NULL, NULL);
		if(ret != ROHC_OK)
		{
			fprintf(stderr, "\nfailed to decompress packet\n");
			assert(0);
			goto clean;
		}

		/* compare IP packets */
		if(ip_packet.len != ip_packet2.len ||
		   memcmp(rohc_buf_data(ip_packet), rohc_buf_data(ip_packet2),
		          ip_packet.len) != 0)
		{
			fprintf(stderr, "\ndecompressed IP packet does not match original "
			        "IP packet\n");
			assert(0);
			goto clean;
		}
	}

	printf("\nTEST OK\n");

	rohc_decomp_free(decomp);
	rohc_comp_free(comp);
	return 0;

clean:
	rohc_decomp_free(decomp);
	rohc_comp_free(comp);
error:
	printf("\nTEST FAIL\n");
quit:
	return 1;
}


/**
 * @brief Print usage of the fuzzer application
 */
static void usage(void)
{
	printf("The ROHC RTP fuzzer tests the ROHC library robustness against RTP traffic\n"
	       "\n"
	       "Usage: rohc_rtp_fuzzer OPTIONS\n"
	       "   or: rohc_rtp_fuzzer play\n"
	       "   or: rohc_rtp_fuzzer replay SEED\n"
	       "\n"
	       "Options:\n"
	       "  -v, --version             Print version information and exit\n"
	       "  -h, --help                Print this usage and exit\n"
	       "\n"
	       "Examples:\n"
	       "  rohc_rtp_fuzzer play      Run a test\n"
	       "  rohc_rtp_fuzzer replay 5  Run a specific test (to reproduce bugs)\n"
	       "\n"
	       "Report bugs to <" PACKAGE_BUGREPORT ">.\n");
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
                              const char *format, ...)
{
	va_list args;
	int ret;

	if(last_traces_last == -1)
	{
		last_traces_last = 0;
	}
	else
	{
		last_traces_last = (last_traces_last + 1) % MAX_LAST_TRACES;
	}

	va_start(args, format);
	ret = vsnprintf(last_traces[last_traces_last], MAX_TRACE_LEN + 1,
	                format, args);
	last_traces[last_traces_last][MAX_TRACE_LEN] = '\0';
	va_end(args);

	if(last_traces_first == -1)
	{
		last_traces_first = 0;
	}
	else if(last_traces_first == last_traces_last)
	{
		last_traces_first = (last_traces_first + 1) % MAX_LAST_TRACES;
	}

	/* if trace was truncated, mention it */
	if(ret > MAX_TRACE_LEN)
	{
		print_rohc_traces(level, entity, profile, "previous trace truncated\n");
	}
}


/**
 * @brief Generate a false random number for testing the ROHC library
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


/**
 * @brief The detection callback which do detect RTP stream
 *
 * @param ip           The inner ip packet
 * @param udp          The udp header of the packet
 * @param payload      The payload of the packet
 * @param payload_size The size of the payload (in bytes)
 * @return             1 if the packet is an RTP packet, 0 otherwise
 */
static bool rtp_detect_cb(const unsigned char *const ip,
                          const unsigned char *const udp,
                          const unsigned char *const payload,
                          const unsigned int payload_size,
                          void *const rtp_private)
{
	const uint16_t max_well_known_port = 1024;
	const uint16_t sip_port = 5060;
	uint16_t udp_sport;
	uint16_t udp_dport;
	uint16_t udp_len;
	bool is_rtp = false;

	assert(ip != NULL);
	assert(udp != NULL);
	assert(payload != NULL);
	assert(rtp_private == NULL);

	/* retrieve UDP source and destination ports and UDP length */
	memcpy(&udp_sport, udp, sizeof(uint16_t));
	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));
	memcpy(&udp_len, udp + 4, sizeof(uint16_t));

	/* RTP streams do not use well known ports */
	if(ntohs(udp_sport) <= max_well_known_port ||
	   ntohs(udp_dport) <= max_well_known_port)
	{
		goto not_rtp;
	}

	/* SIP (UDP/5060) is not RTP */
	if(ntohs(udp_sport) == sip_port && ntohs(udp_dport) == sip_port)
	{
		goto not_rtp;
	}

	/* the UDP destination port of RTP packet is even (the RTCP destination
	 * port are RTP destination port + 1, so it is odd) */
	if((ntohs(udp_sport) % 2) != 0 || (ntohs(udp_dport) % 2) != 0)
	{
		goto not_rtp;
	}

	/* UDP Length shall not be too large */
	if(ntohs(udp_len) > 200)
	{
		goto not_rtp;
	}

	/* UDP payload shall at least contain the smallest RTP header */
	if(payload_size < 12)
	{
		goto not_rtp;
	}

	/* RTP version bits shall be 2 */
	if(((payload[0] >> 6) & 0x3) != 0x2)
	{
		goto not_rtp;
	}

	/* we think that the UDP packet is a RTP packet */
	is_rtp = true;

not_rtp:
	return is_rtp;
}


/**
 * @brief Add a random value at a random period
 *
 * @param period  The period at which to add the random value
 * @param max     The maximum random value to add
 * @return        The random value to add or 0
 */
static unsigned int add_sometimes(const size_t period, const unsigned int max)
{
	unsigned int value;

	if((rand() % period) == 0)
	{
		/* add something */
		value = rand() % (max + 1);
	}
	else
	{
		/* add nothing */
		value = 0;
	}

	return value;
}


/**
 * @brief Handle UNIX signals that interrupt the program
 *
 * @param signal  The received signal
 */
static void fuzzer_interrupt(int signal)
{
	/* end the program with next captured packet */
	fprintf(stderr, "signal %d catched\n", signal);
	fflush(stderr);

	/* for SIGSEGV/SIGABRT, print the last debug traces,
	 * then kill the program */
	if(signal == SIGSEGV || signal == SIGABRT)
	{
		const char *logfilename = "./rtp_fuzzer.log";
		FILE *logfile;
		int ret;
		int i;

		logfile = fopen(logfilename, "w");
		if(logfile == NULL)
		{
			fprintf(stderr, "failed to create '%s' file: %s (%d)\n",
			        logfilename, strerror(errno), errno);
			fflush(stderr);
			raise(SIGKILL);
		}

		fprintf(logfile, "a problem occurred\n\n");

		if(last_traces_first == -1 || last_traces_last == -1)
		{
			fprintf(stderr, "no trace to record\n");
			fflush(stderr);
			raise(SIGKILL);
		}

		if(last_traces_first <= last_traces_last)
		{
			fprintf(stderr, "record the last %d traces...\n",
			        last_traces_last - last_traces_first);
			for(i = last_traces_first; i <= last_traces_last; i++)
			{
				fprintf(logfile, "%s", last_traces[i]);
			}
		}
		else
		{
			fprintf(stderr, "record the last %d traces...\n",
			        MAX_LAST_TRACES - last_traces_first + last_traces_last);
			for(i = last_traces_first;
			    i <= MAX_LAST_TRACES + last_traces_last;
			    i++)
			{
				fprintf(logfile, "%s", last_traces[i % MAX_LAST_TRACES]);
			}
		}

		ret = fclose(logfile);
		if(ret != 0)
		{
			fprintf(stderr, "failed to close log file '%s': %s (%d)\n",
			        logfilename, strerror(errno), errno);
		}

		fflush(stderr);
		if(signal == SIGSEGV)
		{
			struct sigaction action;
			memset(&action, 0, sizeof(struct sigaction));
			action.sa_handler = SIG_DFL;
			sigaction(SIGSEGV, &action, NULL);
			raise(signal);
		}
	}
}

