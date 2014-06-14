/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012 Viveris Technologies
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
 * @file tunnel.c
 * @brief ROHC tunnel
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Raman Gupta <ramangupta16@gmail.com>
 *
 *
 * Description
 * -----------
 *
 * THIS PROGRAM IS DEPRECATED. IT WAS CREATED FOR TESTING PURPOSES. THE SNIFFER
 * AND FUZZER TOOLS REPLACE IT FOR TESTING. THE IP/ROHC TUNNEL REPLACES IT AS
 * TUNNELING SOLUTION THAT MAY BE USED IN PRODUCTION.
 *
 * The program creates a ROHC tunnel over UDP (resp. Ethernet). A ROHC tunnel
 * compresses the IP packets it receives from a virtual network interface and
 * decompresses the ROHC packets it receives from one UDP (resp. Ethernet)
 * flow.
 *
 *               +-----------+                          +------------------+
 * IP packets    |  Virtual  |     +--------------+     |                  |
 * sent by   --> | interface | --> |  Compressor  | --> |                  |
 * the host      |   (TUN)   |     +--------------+     |   ROHC packets   |
 *               |           |                          |     over UDP     |
 * IP packets    |           |     +--------------+     | (resp. Ethernet) |
 * received  <-- |           | <-- | Decompressor | <-- |       flow       |
 * from the      |           |     +--------------+     |                  |
 * tunnel        +-----------+                          +------------------+
 *
 * The program outputs messages from the tunnel application on stderr and
 * messages from the ROHC library on stdout. It outputs compression statistics
 * on file descriptor 3 and decompression statistics on file descriptor 4.
 *
 * The tunnel can emulate a lossy medium with a given error rate.
 * Unidirectional mode can be forced (no feedback channel).
 *
 *
 * Usage
 * -----
 *
 * Run the rohctunnel without any argument to see what arguments the
 * application accepts.
 *
 *
 * Basic example with UDP
 * ----------------------
 *
 * Type as root on machine A:
 *
 *  # rohctunnel rohc0 udp remote 192.168.0.20 local 192.168.0.21 port 5000
 *  # ip link set rohc0 up
 *  # ip -4 addr add 10.0.0.1/24 dev rohc0
 *  # ip -6 addr add 2001:eeee::1/64 dev rohc0
 *
 * Type as root on machine B:
 *
 *  # rohctunnel rohc0 udp remote 192.168.0.21 local 192.168.0.20 port 5000
 *  # ip link set rohc0 up
 *  # ip -4 addr add 10.0.0.2/24 dev rohc0
 *  # ip -6 addr add 2001:eeee::2/64 dev rohc0
 *
 * Then, on machine B:
 *
 *  $ ping 10.0.0.1
 *  $ ping6 2001:eeee::1
 *
 *
 * Basic example with Ethernet
 * ---------------------------
 *
 * Type as root on machine A:
 *
 *  # rohctunnel rohc0 ethernet remote 08:00:27:E1:1E:E6 local eth0
 *  # ip link set rohc0 up
 *  # ip -4 addr add 10.0.0.1/24 dev rohc0
 *  # ip -6 addr add 2001:eeee::1/64 dev rohc0
 *
 * Type as root on machine B:
 *
 *  # rohctunnel rohc0 ethernet remote 08:00:27:0F:D9:8D local eth0
 *  # ip link set rohc0 up
 *  # ip -4 addr add 10.0.0.2/24 dev rohc0
 *  # ip -6 addr add 2001:eeee::2/64 dev rohc0
 *
 * Then, on machine B:
 *
 *  $ ping 10.0.0.1
 *  $ ping6 2001:eeee::1
 */


#include "config.h" /* for HAVE_LINUX_IF_TUN_H and PACKAGE_BUGREPORT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <math.h> /* for HUGE_VAL */
#include <time.h> /* for time(2) */
#include <sys/time.h> /* for gettimeofday(2) */
#include <assert.h>

/* TUN includes */
#if HAVE_LINUX_IF_TUN_H == 1
#  include <linux/if_tun.h>
#else
#  error "No TUN/TAP support for non-Linux platforms yet"
#endif
#include <net/if.h> /* for IFNAMSIZ */
#include <fcntl.h>
#include <sys/ioctl.h>

/* UDP includes */
#include <sys/socket.h>
#include <arpa/inet.h>

/* Ethernet includes */
#include <netpacket/packet.h>

/* ROHC includes */
#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>



/*
 * Macros & definitions:
 */

/// Return the greater value from the two
#define max(x, y)  (((x) > (y)) ? (x) : (y))

/// The maximal size of data that can be received on the virtual interface
#define TUNTAP_BUFSIZE 1518

/// The maximal size of a ROHC packet
#define MAX_ROHC_SIZE	(5 * 1024)

/// Enable debug ?
#define DEBUG 0

/// Stop on compression/decompression failure
#define STOP_ON_FAILURE 0

/** The print format for one Ethernet MAC address */
#define MAC_ADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

/** The arguments for the print format for one Ethernet MAC address */
#define MAC_ADDR(mac) \
	(mac)[0], (mac)[1], (mac)[2], \
	(mac)[3], (mac)[4], (mac)[5]

/** The different types of tunnels */
typedef enum
{
	ROHC_TUNNEL_UDP = 0,
	ROHC_TUNNEL_ETHERNET = 1,
} rohc_tunnel_t;

/** The parameters of the tunnel wrt to its type */
struct rohc_tunnel
{
	rohc_tunnel_t type;

	union
	{
		/* UDP */
		struct
		{
			struct in_addr raddr;
			struct in_addr laddr;
			int port;
		} udp;

		/* Ethernet */
		struct
		{
			uint8_t raddr[ETH_ALEN];
			char *itf_name;
			unsigned int itf_index;
		} ethernet;

	} params;


#define FEEDBACK_SEND_MAX_LEN 500
	uint8_t feedback_send_buf[FEEDBACK_SEND_MAX_LEN];
	struct rohc_buf feedback_send;
};


/*
 * Function prototypes:
 */

int tun_create(char *name);
int read_from_tun(const int fd, struct rohc_buf *const packet);
int write_to_tun(int fd, struct rohc_buf packet);

int udp_create(struct in_addr laddr, int port);
int read_from_udp(int sock, struct rohc_buf *const packet);
int write_to_udp(int sock,
                 struct in_addr raddr,
                 int port,
                 struct rohc_buf packet);

static int raw_create(const unsigned int itf_index);
static int read_from_raw(const int sock, struct rohc_buf *const packet);
static int write_to_raw(const int sock,
                        const uint8_t raddr[ETH_ALEN],
                        const unsigned int itf_index,
                        struct rohc_buf packet);

int tun2wan(struct rohc_comp *comp,
            int from, int to,
            const struct rohc_tunnel *const tunnel,
            int error, double ber, double pe2, double p2);
int wan2tun(struct rohc_tunnel *const tunnel,
            struct rohc_decomp *const decomp,
            const int from,
            const int to,
            struct rohc_comp *const comp);
int flush_feedback(const int to,
                   struct rohc_tunnel *const tunnel);

void dump_packet(const char *const descr, const struct rohc_buf packet);
double get_probability(char *arg, int *error);
int is_timeout(struct timeval first,
               struct timeval second,
               unsigned int max);

static void print_rohc_traces(const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));

static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));


/*
 * Main functions:
 */


/// Whether the application should continue to live or not
int alive;


/**
 * @brief Catch the INT, TERM and KILL signals to properly shutdown the tunnel
 *
 * @param sig  The signal catched: SIGINT, SIGTERM or SIGKILL
 */
void sighandler(int sig)
{
	fprintf(stderr, "signal %d received, terminate the process\n", sig);
	alive = 0;
}


/**
 * @brief Display the application usage
 */
void usage(void)
{
	printf("The ROHC tunnel creates one ROHC-over-UDP or ROHC-over-Ethernet\n\
tunnel\n\
\n\
You need to be root (or to have POSIX capability CAP_NET_ADMIN) to create\n\
ROHC tunnels.\n\
\n\
THIS PROGRAM IS DEPRECATED. IT WAS CREATED FOR TESTING PURPOSES. THE SNIFFER\n\
AND FUZZER TOOLS REPLACE IT FOR TESTING. THE IP/ROHC TUNNEL REPLACES IT AS\n\
TUNNELING SOLUTION THAT MAY BE USED IN PRODUCTION.\n\
\n\
Usage: rohctunnel version\n\
   or: rohctunnel help\n\
   or: rohctunnel TUNNEL [ERROR] [DIR]\n\
\n\
Options:\n\
  TUNNEL := NAME TYPE PARAMS    The tunnel definition\n\
  NAME   := STRING              The name of the tunnel\n\
  TYPE   := { udp | ethernet }  The type of the tunnel\n\
\n\
Tunnel parameters if TYPE = udp:\n\
  PARAMS := REMOTE LOCAL PORT  Additional parameters for UDP\n\
  REMOTE := remote IPV4        The IP address of the remote host\n\
  LOCAL  := local IPV4         The IP address of the local host\n\
  PORT   := port PORTN         The UDP port to use (local and remote)\n\
\n\
Tunnel parameters if TYPE = ethernet:\n\
  PARAMS := REMOTE LOCAL    Additional parameters for Ethernet\n\
  REMOTE := remote MAC      The Ethernet MAC address of the remote host\n\
  LOCAL  := local ITF       The local interface to use, eg. eth0\n\
\n\
Error model (none if not specified):\n\
  ERROR  := error { none | uniform RATE | burst PE2 P2 }\n\
  RATE   := FLOAT             The BER (binary error rate) to emulate\n\
  PE2    := FLOAT             The probability to be in error state\n\
  P2     := FLOAT             The probability to stay in error state\n\
\n\
Direction (bidirectional if not specified):\n\
  DIR    := dir { bidirectional | unidirectional }\n\
\n\
Miscellaneous:\n\
  STRING := [a-zA-Z0-9]               A sequence of letters and numbers\n\
  IPV4   := NUM.NUM.NUM.NUM           An IPv4 address\n\
  MAC    := HEX:HEX:HEX:HEX:HEX:HEX   A MAC address\n\
  PORTN  := [1,65535]                 An UDP port\n\
  ITF    := STRING                    A network interface, eg. eth0\n\
  NUM    := [0,255]                   A part of an IPv4 address\n\
  HEX    := [0x00,0xff]               A part of a MAC address\n\
\n\
Examples:\n\
  # rohctunnel rohc0 udp remote 192.168.0.20 local 192.168.0.21 port 5000                                        ROHC-over-UDP tunnel with ROHC O-mode\n\
  # rohctunnel rohc0 udp remote 192.168.0.20 local 192.168.0.21 port 5000 dir unidirectional                     ROHC-over-UDP tunnel with ROHC U-mode\n\
  # rohctunnel rohc0 udp remote 192.168.0.20 local 192.168.0.21 port 5000 error uniform 1e-5 dir bidirectional   ROHC-over-UDP tunnel with ROHC O-mode and uniform BER\n\
  # rohctunnel rohc0 udp remote 192.168.0.20 local 192.168.0.21 port 5000 error burst 1e-5 2e-5                  ROHC-over-UDP tunnel with ROHC O-mode and bursty BER\n\
  # rohctunnel rohc0 ethernet remote 01:02:03:04:05:06 local eth1                                                ROHC-over-Ethernet tunnel with ROHC O-mode\n\
  # rohctunnel rohc0 ethernet remote 01:02:03:04:05:06 local eth1 error burst 1e-5 2e-5                          ROHC-over-Ethernet tunnel with ROHC O-mode and bursty BER\n\
\n\
Report bugs to <" PACKAGE_BUGREPORT ">.\n");
}


/**
 * @brief Display the application version
 */
void version(void)
{
	printf("rohctunnel version %s\n", rohc_version());
}


/// The file descriptor where to write the compression statistics
FILE *stats_comp;
/// The file descriptor where to write the decompression statistics
FILE *stats_decomp;
/// The sequence number for the UDP tunnel (used to discover lost packets)
unsigned int seq;


/**
 * @brief Setup a ROHC over UDP tunnel
 *
 * @param argc  The number of arguments given on the command line
 * @param argv  The arguments given on the command line
 * @return      0 in case of success, > 0 otherwise
 */
int main(int argc, char *argv[])
{
	int failure = 0;

	/* general */
	char *tun_name;
	struct rohc_tunnel tunnel;

	/* error model */
	int error_model;
	int conv_error;
	double ber = 0;
	double pe2 = 0;
	double p2 = 0;

	/* ROHC mode */
	rohc_mode_t mode;

	size_t arg_count;

	unsigned long seed;
	int ret;

	int tun;
	int wan;

	fd_set readfds;
	struct timespec timeout;
	sigset_t sigmask;

	struct timeval last;
	struct timeval now;

	struct rohc_comp *comp;
	struct rohc_decomp *decomp;


	/*
	 * Parse arguments:
	 */

	fprintf(stderr, "\n");
	fprintf(stderr, "=== The ROHC over UDP tunnel is deprecated.\n");
	fprintf(stderr, "=== Run with --help or see man page for more details.\n");
	fprintf(stderr, "\n");

	/* check the number of arguments:
	 *   rohctunnel version            -> 2 arguments
	 *   rohctunnel help               -> 2 arguments
	 *   UDP:
	 *     rohctunnel TUNNEL           -> 9 arguments
	 *     rohctunnel TUNNEL ERROR     -> 11-13 arguments
	 *     rohctunnel TUNNEL DIR       -> 11 arguments
	 *     rohctunnel TUNNEL ERROR DIR -> 13-15 arguments
	 *   Ethernet:
	 *     rohctunnel TUNNEL           -> 7 arguments
	 *     rohctunnel TUNNEL ERROR     -> 9-11 arguments
	 *     rohctunnel TUNNEL DIR       -> 9 arguments
	 *     rohctunnel TUNNEL ERROR DIR -> 11-13 arguments

	 */
	if(argc != 2 && argc != 7 && argc != 9 && (argc < 9 || argc > 15))
	{
		usage();
		goto quit;
	}

	/* is the first argument 'version' or 'help' ? */
	if(strcmp(argv[1], "version") == 0)
	{
		version();
		goto quit;
	}
	else if(strcmp(argv[1], "help") == 0)
	{
		usage();
		goto quit;
	}

	/* first argument is not 'version' or 'help', so we have a tunnel request */
	if(argc < 7)
	{
		usage();
		goto quit;
	}

	/* get the tunnel name */
	if(strlen(argv[1]) <= 0 || strlen(argv[1]) >= IFNAMSIZ)
	{
		fprintf(stderr, "bad tunnel interface name '%s': too long\n",
		        argv[1]);
		goto quit;
	}
	tun_name = argv[1];
	if(if_nametoindex(tun_name) > 0)
	{
		fprintf(stderr, "tunnel interface '%s' already exists\n", tun_name);
		goto quit;
	}

	/* get the type of tunnel: UDP or Ethernet */
	if(strcmp(argv[2], "udp") == 0)
	{
		tunnel.type = ROHC_TUNNEL_UDP;
		arg_count = 9;
	}
	else if(strcmp(argv[2], "ethernet") == 0)
	{
		tunnel.type = ROHC_TUNNEL_ETHERNET;
		arg_count = 7;
	}
	else
	{
		fprintf(stderr, "unknown tunnel type '%s'\n", argv[2]);
		usage();
		goto quit;
	}

	/* get the remote IP address */
	if(strcmp(argv[3], "remote") != 0)
	{
		fprintf(stderr, "keyword '%s' found instead of 'remote'\n", argv[3]);
		usage();
		goto quit;
	}
	if(tunnel.type == ROHC_TUNNEL_UDP)
	{
		if(!inet_aton(argv[4], &tunnel.params.udp.raddr))
		{
			fprintf(stderr, "bad remote IP address: %s\n", argv[4]);
			goto quit;
		}
	}
	else /* ROHC_TUNNEL_ETHERNET */
	{
		unsigned int mac_addr[ETH_ALEN];
		int i;

		ret = sscanf(argv[4], MAC_ADDR_FMT,
		             mac_addr, mac_addr + 1, mac_addr + 2,
		             mac_addr + 3, mac_addr + 4, mac_addr + 5);
		if(ret != ETH_ALEN)
		{
			fprintf(stderr, "bad remote Ethernet MAC address: %s\n", argv[4]);
			goto quit;
		}
		for(i = 0; i < ETH_ALEN; i++)
		{
			tunnel.params.ethernet.raddr[i] = mac_addr[i] & 0xff;
		}
	}

	/* get the local informations (IP address or interface) */
	if(strcmp(argv[5], "local") != 0)
	{
		fprintf(stderr, "keyword '%s' found instead of 'local'\n", argv[5]);
		usage();
		goto quit;
	}
	if(tunnel.type == ROHC_TUNNEL_UDP)
	{
		if(!inet_aton(argv[6], &tunnel.params.udp.laddr))
		{
			fprintf(stderr, "bad local IP address: %s\n", argv[6]);
			goto quit;
		}
	}
	else /* ROHC_TUNNEL_ETHERNET */
	{
		if(strlen(argv[6]) <= 0 || strlen(argv[6]) >= IFNAMSIZ)
		{
			fprintf(stderr, "bad local interface name '%s': too long\n",
			        argv[6]);
			goto quit;
		}
		tunnel.params.ethernet.itf_name = argv[6];
		tunnel.params.ethernet.itf_index =
			if_nametoindex(tunnel.params.ethernet.itf_name);
		if(tunnel.params.ethernet.itf_index == 0)
		{
			fprintf(stderr, "bad local interface '%s': %s (%d)\n",
			        tunnel.params.ethernet.itf_name, strerror(errno), errno);
			goto quit;
		}
	}

	/* get the UDP port */
	if(tunnel.type == ROHC_TUNNEL_UDP)
	{
		if(strcmp(argv[7], "port") != 0)
		{
			fprintf(stderr, "keyword '%s' found instead of 'port'\n", argv[7]);
			usage();
			goto quit;
		}
		tunnel.params.udp.port = atoi(argv[8]);
		if(tunnel.params.udp.port <= 0 || tunnel.params.udp.port >= 0xffff)
		{
			fprintf(stderr, "bad UDP port: %s\n", argv[8]);
			goto quit;
		}
	}

	/* get the error model and its parameters if present */
	if(((size_t) argc) > arg_count && strcmp(argv[arg_count], "error") == 0)
	{
		arg_count++;
		if(((size_t) argc) <= arg_count)
		{
			fprintf(stderr, "the error keyword requires an argument: "
			        "none, uniform or burst\n");
			goto quit;
		}

		if(strcmp(argv[arg_count], "none") == 0)
		{
			/* no error model */
			fprintf(stderr, "do not emulate lossy medium\n");
			error_model = 0;
			arg_count++;
		}
		else if(strcmp(argv[arg_count], "uniform") == 0)
		{
			/* uniform error model */
			error_model = 1;
			arg_count++;

			/* check if parameters are present */
			if(((size_t) argc) <= arg_count)
			{
				usage();
				goto quit;
			}

			/* get the RATE value */
			ber = get_probability(argv[arg_count], &conv_error);
			if(conv_error != 0)
			{
				fprintf(stderr, "cannot read the RATE parameter\n");
				goto quit;
			}
			arg_count++;

			fprintf(stderr, "emulate lossy medium with %e errors/bit "
			                "= 1 error every %lu bytes\n",
			        ber, (unsigned long) (1 / (ber * 8)));
		}
		else if(strcmp(argv[arg_count], "burst") == 0)
		{
			/* non-uniform/burst error model */
			error_model = 2;
			arg_count++;

			/* check if parameters are present */
			if(((size_t) argc) < (arg_count + 2))
			{
				usage();
				goto quit;
			}

			/* get the PE2 probability */
			pe2 = get_probability(argv[arg_count], &conv_error);
			if(conv_error != 0)
			{
				fprintf(stderr, "cannot read the PE2 parameter\n");
				goto quit;
			}
			arg_count++;

			/* get the P2 probability */
			p2 = get_probability(argv[arg_count], &conv_error);
			if(conv_error != 0)
			{
				fprintf(stderr, "cannot read the P2 parameter\n");
				goto quit;
			}
			arg_count++;

			fprintf(stderr, "emulate lossy medium with PE2 = %e and P2 = %e\n",
			        pe2, p2);
		}
		else
		{
			fprintf(stderr, "bad error model: %s\n", argv[arg_count]);
			goto quit;
		}
	}
	else
	{
		/* no error model */
		fprintf(stderr, "do not emulate lossy medium (default)\n");
		error_model = 0;
	}

	/* get the direction mode if present */
	if(((size_t) argc) > arg_count && strcmp(argv[arg_count], "dir") == 0)
	{
		arg_count++;
		if(((size_t) argc) <= arg_count)
		{
			fprintf(stderr, "the dir keyword requires an argument: "
			        "unidirectional or bidirectional\n");
			goto quit;
		}

		if(strcmp(argv[arg_count], "unidirectional") == 0)
		{
			fprintf(stderr, "force unidirectional mode\n");
			mode = ROHC_U_MODE;
		}
		else if(strcmp(argv[arg_count], "bidirectional") == 0)
		{
			fprintf(stderr, "force bidirectional mode\n");
			mode = ROHC_O_MODE;
		}
		else
		{
			fprintf(stderr, "bad direction mode: %s\n", argv[arg_count]);
			goto quit;
		}
	}
	else
	{
		fprintf(stderr, "force bidirectional mode (default)\n");
		mode = ROHC_O_MODE;
	}


	/*
	 * Network interface part:
	 */

	/* init the context that will store the feedbacks while waiting for them
	 * to be sent (alone or piggybacked) */
	tunnel.feedback_send.time.sec = 0;
	tunnel.feedback_send.time.nsec = 0;
	tunnel.feedback_send.data = tunnel.feedback_send_buf;
	tunnel.feedback_send.max_len = FEEDBACK_SEND_MAX_LEN;
	tunnel.feedback_send.offset = 3;
	tunnel.feedback_send.len = 0;

	/* create virtual network interface */
	tun = tun_create(tun_name);
	if(tun < 0)
	{
		fprintf(stderr, "%s creation failed, be sure to start rohctunnel "
		        "as root\n", tun_name);
		failure = 1;
		goto quit;
	}
	fprintf(stderr, "%s created, fd %d\n", tun_name, tun);

	/* create an UDP/ethernet socket */
	if(tunnel.type == ROHC_TUNNEL_UDP)
	{
		wan = udp_create(tunnel.params.udp.laddr, tunnel.params.udp.port);
		if(wan < 0)
		{
			fprintf(stderr, "UDP socket creation on port %d failed\n",
			        tunnel.params.udp.port);
			failure = 1;
			goto close_tun;
		}
		fprintf(stderr, "UDP socket created on port %d, fd %d\n",
		        tunnel.params.udp.port, wan);
	}
	else /* ROHC_TUNNEL_ETHERNET */
	{
		wan = raw_create(tunnel.params.ethernet.itf_index);
		if(wan < 0)
		{
			fprintf(stderr, "Ethernet socket creation failed\n");
			failure = 1;
			goto close_tun;
		}
		fprintf(stderr, "Ethernet socket created, fd %d\n", wan);
	}


	/*
	 * ROHC part:
	 */

	/* initialize the random generator */
	seed = time(NULL);
	srand(seed);

	/* create the compressor and activate profiles */
	comp = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, gen_random_num, NULL);
	if(comp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC compressor\n");
		goto close_wan;
	}

	/* set trace callback for compressor */
	if(!rohc_comp_set_traces_cb(comp, print_rohc_traces))
	{
		fprintf(stderr, "cannot set trace callback for the compressor\n");
		goto destroy_comp;
	}

	/* enable the compression profiles
	 * (the IP/TCP profile is not ready enough to be enabled) */
	if(!rohc_comp_enable_profiles(comp, ROHC_PROFILE_UNCOMPRESSED,
	                              ROHC_PROFILE_RTP, ROHC_PROFILE_UDP,
	                              ROHC_PROFILE_IP, ROHC_PROFILE_UDPLITE,
	                              ROHC_PROFILE_ESP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles\n");
		goto destroy_comp;
	}

	/* create the decompressor (associate it with the compressor) */
	decomp = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, mode);
	if(decomp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* set trace callback for decompressor */
	if(!rohc_decomp_set_traces_cb(decomp, print_rohc_traces))
	{
		fprintf(stderr, "cannot set trace callback for the decompressor\n");
		goto destroy_decomp;
	}


	/*
	 * Main program:
	 */

	/* write the compression stats to fd 3 */
	stats_comp = fdopen(3, "a");
	if(stats_comp == NULL)
	{
		fprintf(stderr, "cannot open fd 3 for compression stats: %s (%d)\n",
		        strerror(errno), errno);
		goto destroy_decomp;
	}

	/* write the decompression stats to fd 4 */
	stats_decomp = fdopen(4, "a");
	if(stats_decomp == NULL)
	{
		fprintf(stderr, "cannot open fd 4 for decompresion stats: %s (%d)\n",
		        strerror(errno), errno);
		goto close_stats_comp;
	}

	/* init the tunnel sequence number */
	seq = 0;

	/* catch signals to properly shutdown the bridge */
	alive = 1;
	signal(SIGKILL, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGINT, sighandler);

	/* poll network interfaces each second */
	timeout.tv_sec = 1;
	timeout.tv_nsec = 0;

	/* mask signals during interface polling */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGKILL);
	sigaddset(&sigmask, SIGTERM);
	sigaddset(&sigmask, SIGINT);

	/* initialize the last time we sent a packet */
	gettimeofday(&last, NULL);

	/* tunnel each packet from the UDP socket to the virtual interface
	 * and from the virtual interface to the UDP socket */
	do
	{
		/* poll the read sockets/file descriptors */
		FD_ZERO(&readfds);
		FD_SET(tun, &readfds);
		FD_SET(wan, &readfds);

		ret = pselect(max(tun, wan) + 1, &readfds, NULL, NULL,
		              &timeout, &sigmask);
		if(ret < 0)
		{
			fprintf(stderr, "pselect failed: %s (%d)\n", strerror(errno), errno);
			failure = 1;
			alive = 0;
		}
		else if(ret > 0)
		{
			/* bridge from TUN to WAN (UDP or Ethernet) */
			if(FD_ISSET(tun, &readfds))
			{
				failure = tun2wan(comp, tun, wan, &tunnel,
				                  error_model, ber, pe2, p2);
				gettimeofday(&last, NULL);
#if STOP_ON_FAILURE
				if(failure)
					alive = 0;
#endif
			}

			/* bridge from WAN (UDP or Ethernet) to TUN */
			if(
#if STOP_ON_FAILURE
			   !failure &&
#endif
			   FD_ISSET(wan, &readfds))
			{
				failure = wan2tun(&tunnel, decomp, wan, tun,
				                  mode == ROHC_U_MODE ? NULL : comp);
#if STOP_ON_FAILURE
				if(failure)
					alive = 0;
#endif
			}
		}

		/* flush feedback data if nothing is sent in the tunnel for a moment */
		gettimeofday(&now, NULL);
		if(now.tv_sec > last.tv_sec + 1)
		{
			failure = flush_feedback(wan, &tunnel);
			last = now;
#if STOP_ON_FAILURE
			if(failure)
				alive = 0;
#endif
		}
	}
	while(alive);


	/*
	 * Cleaning:
	 */

	fclose(stats_decomp);
close_stats_comp:
	fclose(stats_comp);
destroy_decomp:
	rohc_decomp_free(decomp);
destroy_comp:
	rohc_comp_free(comp);
close_wan:
	close(wan);
close_tun:
	close(tun);
quit:
	return failure;
}



/*
 * TUN interface:
 */


/**
 * @brief Create a virtual network interface of type TUN
 *
 * @param name  The name of the TUN interface to create
 * @return      An opened file descriptor on the TUN interface in case of
 *              success, a negative value otherwise
 */
int tun_create(char *name)
{
	struct ifreq ifr;
	int fd, err;

	/* open a file descriptor on the kernel interface */
	if((fd = open("/dev/net/tun", O_RDWR)) < 0)
	{
		fprintf(stderr, "failed to open /dev/net/tun: %s (%d)\n",
		        strerror(errno), errno);
		return fd;
	}

	/* flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *        IFF_NO_PI - Do not provide packet information */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_flags = IFF_TUN;

	/* create the TUN interface */
	if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
	{
		fprintf(stderr, "failed to ioctl(TUNSETIFF) on /dev/net/tun: %s (%d)\n",
		        strerror(errno), errno);
		close(fd);
		return err;
	}

	return fd;
}


/**
 * @brief Read data from the TUN interface
 *
 * Data read by this function contains a 4-byte header that gives the protocol
 * of the data.
 *
 *   +-----+-----+-----+-----+
 *   |  0  |  0  |  Protocol |
 *   +-----+-----+-----+-----+
 *
 * Protocol = 0x0800 for IPv4
 *            0x86dd for IPv6
 *
 * @param fd      The TUN file descriptor to read data from
 * @param packet  The buffer where to store the data
 * @param length  OUT: the length of the data
 * @return        0 in case of success, a non-null value otherwise
 */
int read_from_tun(const int fd, struct rohc_buf *const packet)
{
	int ret;

	ret = read(fd, rohc_buf_data(*packet), rohc_buf_avail_len(*packet));
	if(ret < 0 || ((unsigned int) ret) > rohc_buf_avail_len(*packet))
	{
		fprintf(stderr, "read failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}
	else if(ret < 4)
	{
		fprintf(stderr, "read failed: packet is smaller than the TUN header\n");
		goto error;
	}
	packet->len += ret;

#if DEBUG
	fprintf(stderr, "read %u bytes on fd %d\n", ret, fd);
#endif

	return 0;

error:
	return 1;
}


/**
 * @brief Write data to the TUN interface
 *
 * Data written to the TUN interface must contain a 4-byte header that gives
 * the protocol of the data. See the read_from_tun function for details.
 *
 * @param fd      The TUN file descriptor to write data to
 * @param packet  The packet to write to the TUN interface (header included)
 * @return        0 in case of success, a non-null value otherwise
 */
int write_to_tun(int fd, struct rohc_buf packet)
{
	int ret;

	ret = write(fd, rohc_buf_data(packet), packet.len);
	if(ret < 0)
	{
		fprintf(stderr, "write failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

#if DEBUG
	fprintf(stderr, "%zu bytes written on fd %d\n", packet.len, fd);
#endif

	return 0;

error:
	return 1;
}



/*
 * UDP socket:
 */


/**
 * @brief Create an UDP socket
 *
 * @param laddr  The local address to bind the socket to
 * @param port   The UDP port to bind the socket to
 * @return       An opened socket descriptor on the UDP socket in case of
 *               success, a negative value otherwise
 */
int udp_create(struct in_addr laddr, int port)
{
	int sock;
	int len;
	int ret;
	struct sockaddr_in addr;

	/* create an UDP socket */
   sock = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);
	if(sock < 0)
	{
		fprintf(stderr, "cannot create the UDP socket: %s (%d)\n",
		        strerror(errno), errno);
		goto quit;
	}

	/* try to reuse the socket */
	len = 1;
	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &len, sizeof(len));
	if(ret < 0)
	{
		fprintf(stderr, "cannot reuse the UDP socket\n");
		goto close;
	}

	/* bind the socket on given port */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = laddr;
	addr.sin_port = htons(port);

	ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
	if(ret < 0)
	{
		fprintf(stderr, "cannot bind to UDP socket: %s (%d)\n",
		        strerror(errno), errno);
		goto close;
	}

	return sock;

close:
	close(sock);
quit:
	return -1;
}


/**
 * @brief Read data from the UDP socket
 *
 * @param sock    The UDP socket descriptor to read data from
 * @param packet  The packet to read
 * @return        0 in case of success, a non-null value otherwise
 */
int read_from_udp(int sock, struct rohc_buf *const packet)
{
	struct sockaddr_in addr;
	socklen_t addr_len;
	int ret;

	addr_len = sizeof(struct sockaddr_in);
	memset(&addr, 0, addr_len);

	/* read data from the UDP socket */
	ret = recvfrom(sock, rohc_buf_data(*packet), rohc_buf_avail_len(*packet),
	               0, (struct sockaddr *) &addr, &addr_len);

	if(ret < 0 || ((unsigned int) ret) > rohc_buf_avail_len(*packet))
	{
		fprintf(stderr, "recvfrom failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}
	else if(ret < 2)
	{
		fprintf(stderr, "recvfrom failed: packet too small for UDP header\n");
		goto error;
	}
	packet->len += ret;

#if DEBUG
	fprintf(stderr, "read one %zu-byte ROHC packet on UDP socket %d\n",
	        packet->len - 2, sock);
#endif

	return 0;

error:
	return 1;
}


/**
 * @brief Write data to the UDP socket
 *
 * All UDP packets contain a sequence number that identify the UDP packet. It
 * helps discovering lost packets (for statistical purposes). The buffer that
 * contains the ROHC packet must have 2 bytes of free space at the beginning.
 * This allows the write_to_udp function to add the 2-byte sequence number in
 * the UDP packet without allocating new memory.
 *
 * @param sock    The UDP socket descriptor to write data to
 * @param raddr   The remote address of the tunnel (ie. the address where to
 *                send the UDP datagrams)
 * @param port    The remote UDP port where to send the UDP data
 * @param packet  The packet to write to the UDP socket
 * @return        0 in case of success, a non-null value otherwise
 */
int write_to_udp(int sock,
                 struct in_addr raddr,
                 int port,
                 struct rohc_buf packet)
{
	struct sockaddr_in addr;
	int ret;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = raddr.s_addr;
	addr.sin_port = htons(port);

	/* write the tunnel sequence number at the beginning of packet */
	rohc_buf_shift(&packet, 2);
	rohc_buf_byte_at(packet, 0) = (htons(seq) >> 8) & 0xff;
	rohc_buf_byte_at(packet, 1) = htons(seq) & 0xff;

	/* send the data on the UDP socket */
	ret = sendto(sock, rohc_buf_data(packet), packet.len, 0,
	             (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
	if(ret < 0)
	{
		fprintf(stderr, "sendto failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

#if DEBUG
	fprintf(stderr, "%zu bytes written on socket %d\n", packet.len, sock);
#endif

	return 0;

error:
	return 1;
}



/*
 * RAW socket:
 */


/**
 * @brief Create a RAW socket
 *
 * @param itf_index  The index of the local interface to bind the socket to
 * @return           An opened socket descriptor on the RAW socket in case of
 *                   success, a negative value otherwise
 */
static int raw_create(const unsigned int itf_index)
{
	struct sockaddr_ll addr;
	int sock;
	int ret;

	/* create a RAW socket */
	sock = socket(AF_PACKET, SOCK_DGRAM, htons(ROHC_ETHERTYPE));
	if(sock < 0)
	{
		fprintf(stderr, "cannot create the RAW socket: %s (%d)\n",
		        strerror(errno), errno);
		goto quit;
	}

	/* bind the socket on given interface for ROHC */
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ROHC_ETHERTYPE);
	addr.sll_ifindex = itf_index;

	ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
	if(ret < 0)
	{
		fprintf(stderr, "cannot bind to RAW socket to interface %u: %s (%d)\n",
		        itf_index, strerror(errno), errno);
		goto close;
	}

	return sock;

close:
	close(sock);
quit:
	return -1;
}


/**
 * @brief Read data from the RAW socket
 *
 * @param sock    The RAW socket descriptor to read data from
 * @param packet  The packet to read
 * @return        0 in case of success, a non-null value otherwise
 */
static int read_from_raw(const int sock, struct rohc_buf *const packet)
{
	struct sockaddr_ll addr;
	socklen_t addr_len;
	int ret;

	addr_len = sizeof(struct sockaddr_ll);
	memset(&addr, 0, addr_len);

	/* read data from the UDP socket */
	ret = recvfrom(sock, rohc_buf_data(*packet), rohc_buf_avail_len(*packet),
	               0, (struct sockaddr *) &addr, &addr_len);
	if(ret < 0 || ((unsigned int) ret) > rohc_buf_avail_len(*packet))
	{
		fprintf(stderr, "recvfrom failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}
	else if(ret < 3)
	{
		fprintf(stderr, "recvfrom failed: packet too small for RAW header\n");
		goto error;
	}
	packet->len += ret;

#if DEBUG
	fprintf(stderr, "read one %zu-byte ROHC packet on RAW socket %d\n",
	        packet->len - 3, sock);
#endif

	return 0;

error:
	return 1;
}


/**
 * @brief Write data to the RAW socket
 *
 * All Ethernet frames contain a sequence number that identify the Ethernet
 * frame. It helps discovering lost packets (for statistical purposes).
 *
 * All Ethernet frames contain also the length of the ROHC packet on 1 byte.
 *
 * The buffer that contains the ROHC packet must have 3 bytes of free space at
 * the beginning. This allows the write_to_raw function to add the 2-byte
 * sequence number and the 1-byte ROHC length in the Ethernet frame without
 * allocating new memory.
 *
 * @param sock       The RAW socket descriptor to write data to
 * @param raddr      The remote address of the tunnel (ie. the address where
 *                   to send the Ethernet datagrams)
 * @param itf_index  The index of the local interface on which to write
 * @param packet     The packet to write to the RAW socket
 * @return           0 in case of success, a non-null value otherwise
 */
static int write_to_raw(const int sock,
                        const uint8_t raddr[ETH_ALEN],
                        const unsigned int itf_index,
                        struct rohc_buf packet)
{
	struct sockaddr_ll addr;
	int ret;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ROHC_ETHERTYPE);
	addr.sll_ifindex = itf_index;
	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, raddr, ETH_ALEN);

	/* write the tunnel sequence number at the beginning of packet */
	rohc_buf_shift(&packet, 3);
	if(packet.len <= 3 || packet.len > 255)
	{
		fprintf(stderr, "write_to_raw: bad length %zu\n", packet.len);
		goto error;
	}
	rohc_buf_byte_at(packet, 0) = (htons(seq) >> 8) & 0xff;
	rohc_buf_byte_at(packet, 1) = htons(seq) & 0xff;

	/* Current ROHC packet length. Since for Ethernet min payload is 46 and
	 * any excess bytes after payload are padded. It is very much possible
	 * that current ROHC packet length is less than 46 bytes, so the length is
	 * conveyed in the third byte */
	rohc_buf_byte_at(packet, 2) = packet.len - 3;

	/* send the data on the UDP socket */
	ret = sendto(sock, rohc_buf_data(packet), packet.len, 0,
	             (struct sockaddr *) &addr, sizeof(struct sockaddr_ll));
	if(ret < 0)
	{
		fprintf(stderr, "sendto failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

#if DEBUG
	fprintf(stderr, "%zu bytes written on socket %d\n", packet.len, sock);
#endif

	return 0;

error:
	return 1;
}



/*
 * Forwarding between the TUN interface and the WAN socket
 */


/**
 * @brief Forward IP packets received on the TUN interface to the WAN socket
 *
 * The function compresses the IP packets thanks to the ROHC library before
 * sending them on the WAN socket.
 *
 * @param comp   The ROHC compressor
 * @param from   The TUN file descriptor to read from
 * @param to     The WAN socket descriptor to write to
 * @param tunnel The type and parameters of the tunnel
 * @param error  Type of error emulation (0 = none, 1 = uniform,
 *               2 = non-uniform/burst)
 * @param ber    The BER (Binary Error Rate) to emulate (value used on first
 *               call only if error model is uniform)
 * @param pe2    The probability to be in error state (value used on first
 *               call only if error model is non-uniform)
 * @param p2     The probability to stay in error state (value used on first
 *               call only if error model is non-uniform)
 * @return       0 in case of success, a non-null value otherwise
 */
int tun2wan(struct rohc_comp *comp,
            int from, int to,
            const struct rohc_tunnel *const tunnel,
            int error, double ber, double pe2, double p2)
{
	/* the buffer that will contain the uncompressed packet */
	static unsigned char uncomp_buffer[TUNTAP_BUFSIZE];
	struct rohc_buf uncomp_packet =
		rohc_buf_init_empty(uncomp_buffer, TUNTAP_BUFSIZE);

	/* the buffer that will contain the compressed ROHC packet */
	static unsigned char rohc_buffer[3 + MAX_ROHC_SIZE];
	struct rohc_buf rohc_packet =
		rohc_buf_init_empty(rohc_buffer, 3 + MAX_ROHC_SIZE);

	bool is_segment = false;
	int ret;

	/* error emulation */
	static unsigned int dropped = 0;
	int to_drop = 0;

	/* uniform model */
	static unsigned long nb_bytes = 0;
	static unsigned long bytes_without_error = 0;

	/* non-uniform error model */
	static int is_state_drop = 0;
	static float p1 = 0;
	static struct timeval last;
	struct timeval now;

	/* statistics output */
	rohc_comp_last_packet_info2_t last_packet_info;

	/* init the error model variables */
	if(error > 0)
	{
		/* init uniform error model variables */
		if(error == 1 && bytes_without_error == 0)
		{
			// find out the number of bytes without an error
			bytes_without_error = (unsigned long) (1 / (ber * 8));
		}

		/* init non-uniform error model variables */
		if(error == 2 && p1 == 0)
		{
			/* init of the random generator */
			gettimeofday(&last, NULL);
			srand(last.tv_sec);

			/* init the probability to stay in non-error state */
			p1 = (p2 - 1) / (1 - pe2) + 2 - p2;
		}
	}

#if DEBUG
	fprintf(stderr, "\n");
#endif

	/* read the IP packet from the virtual interface */
	ret = read_from_tun(from, &uncomp_packet);
	if(ret != 0)
	{
		fprintf(stderr, "read_from_tun failed\n");
		goto error;
	}

	/* skip the TUN header */
	rohc_buf_shift(&uncomp_packet, 4);

	/* skip the tunnel header */
	rohc_packet.len += 3;
	rohc_buf_shift(&rohc_packet, 3);

	/* increment the tunnel sequence number */
	seq++;

	/* compress the IP packet */
#if DEBUG
	fprintf(stderr, "compress packet #%u (%zd bytes)\n", seq, packet_len);
#endif
	ret = rohc_compress4(comp, uncomp_packet, &rohc_packet);
	if(ret == ROHC_NEED_SEGMENT)
	{
		is_segment = true;
	}
	else if(ret != ROHC_OK)
	{
		fprintf(stderr, "compression of packet #%u failed\n", seq);
		dump_packet("IP packet", uncomp_packet);
		goto error;
	}

	/* emulate lossy medium if asked to do so */
	if(error == 1) /* uniform error model */
	{
		if(nb_bytes + rohc_packet.len >= bytes_without_error)
		{
			to_drop = 1;
			dropped++;
			fprintf(stderr, "error inserted, ROHC packet #%u dropped\n", seq);
			nb_bytes = rohc_packet.len - (bytes_without_error - nb_bytes);
		}

		nb_bytes += rohc_packet.len;
	}
	else if(error == 2) /* non-uniform/burst error model */
	{
		/* reset to normal state if too much time between two packets */
		gettimeofday(&now, NULL);
		if(is_state_drop && is_timeout(last, now, 2))
		{
			fprintf(stderr, "go back to normal state (too much time between "
			        "packets #%u and #%u)\n", seq - 1, seq);
			is_state_drop = 0;
		}
		last = now;

		/* do we change state ? */
		int r = rand() % 1000;
		if(!is_state_drop)
			is_state_drop = (r > (int) (p1 * 1000));
		else
			is_state_drop = (r <= (int) (p2 * 1000));

		if(is_state_drop)
		{
			to_drop = 1;
			dropped++;
			fprintf(stderr, "error inserted, ROHC packet #%u dropped\n", seq);
		}
	}

	/* write the ROHC packet in the UDP/Ethernet tunnel if not dropped */
	if(!to_drop)
	{
		if(is_segment)
		{
			/* retrieve and transmit all remaining ROHC segments */
			while((ret = rohc_comp_get_segment2(comp, &rohc_packet)) != ROHC_NEED_SEGMENT)
			{
				/* write the ROHC segment in the tunnel */
				if(tunnel->type == ROHC_TUNNEL_UDP)
				{
					ret = write_to_udp(to, tunnel->params.udp.raddr,
					                   tunnel->params.udp.port, rohc_packet);
				}
				else /* ROHC_TUNNEL_ETHERNET */
				{
					ret = write_to_raw(to, tunnel->params.ethernet.raddr,
					                   tunnel->params.ethernet.itf_index,
					                   rohc_packet);
				}
				if(ret != 0)
				{
					fprintf(stderr, "write_to_udp(segment) failed\n");
					goto error;
				}
			}
		}
		else
		{
			/* write the ROHC packet in the tunnel */
			if(tunnel->type == ROHC_TUNNEL_UDP)
			{
				ret = write_to_udp(to, tunnel->params.udp.raddr,
				                   tunnel->params.udp.port, rohc_packet);
			}
			else /* ROHC_TUNNEL_ETHERNET */
			{
				ret = write_to_raw(to, tunnel->params.ethernet.raddr,
				                   tunnel->params.ethernet.itf_index,
				                   rohc_packet);
			}
			if(ret != 0)
			{
				fprintf(stderr, "failed to write data on tunnel\n");
				goto error;
			}
		}
	}

	/* print packet statistics */
	last_packet_info.version_major = 0;
	last_packet_info.version_minor = 0;
	if(!rohc_comp_get_last_packet_info2(comp, &last_packet_info))
	{
		fprintf(stderr, "cannot display stats about the last compressed packet\n");
		goto error;
	}
	fprintf(stats_comp, "%d\t%s\t%s\t%lu\t%lu\t%lu\t%lu\t%u\n",
	        seq,
	        rohc_get_mode_descr(last_packet_info.context_mode),
	        rohc_comp_get_state_descr(last_packet_info.context_state),
	        last_packet_info.total_last_uncomp_size,
	        last_packet_info.header_last_uncomp_size,
	        last_packet_info.total_last_comp_size,
	        last_packet_info.header_last_comp_size,
	        dropped);
	fflush(stats_comp);

	return 0;

error:
	return 1;
}


/*
 * @brief Print packet statistics for decompressor
 *
 * @param seq           The tunnel sequence number
 * @param lost_packets  The number of lost packets
 * @param failed_decomp The number of decompression failures
 */
void print_decomp_stats(unsigned int seq,
                        unsigned long lost_packets,
                        unsigned long failed_decomp)
{
	fprintf(stats_decomp, "%u\t%lu\t%lu\t%lu\n", seq,
	        lost_packets + failed_decomp, lost_packets, failed_decomp);
	fflush(stats_decomp);
}


/**
 * @brief Forward ROHC packets received on the WAN socket to the TUN interface
 *
 * The function decompresses the ROHC packets thanks to the ROHC library before
 * sending them on the TUN interface.
 *
 * @param tunnel       The tunnel context
 * @param decomp       The ROHC decompressor
 * @param from         The WAN socket descriptor to read from
 * @param to           The TUN file descriptor to write to
 * @param comp         The same-site associated ROHC compressor if any,
 *                     NULL if running in unidirectional mode
 * @return             0 in case of success, a non-null value otherwise
 */
int wan2tun(struct rohc_tunnel *const tunnel,
            struct rohc_decomp *const decomp,
            const int from,
            const int to,
            struct rohc_comp *const comp)
{
	static unsigned char buffer[3 + TUNTAP_BUFSIZE];
	struct rohc_buf packet = rohc_buf_init_empty(buffer, 3 + TUNTAP_BUFSIZE);

	static unsigned char decomp_buffer[TUNTAP_BUFSIZE + 4];
	struct rohc_buf decomp_packet =
		rohc_buf_init_empty(decomp_buffer, TUNTAP_BUFSIZE + 4);

	const size_t feedback_rcvd_max_len = 500;
	uint8_t feedback_rcvd_buf[feedback_rcvd_max_len];
	struct rohc_buf feedback_rcvd =
		rohc_buf_init_empty(feedback_rcvd_buf, feedback_rcvd_max_len);

	int ret;
	static unsigned int max_seq = 0;
	unsigned int new_seq;
	static unsigned long lost_packets = 0;
	static unsigned long failed_decomp = 0;

#if DEBUG
	fprintf(stderr, "\n");
#endif

	/* read the sequence number + ROHC packet from the tunnel */
	if(tunnel->type == ROHC_TUNNEL_UDP)
	{
		ret = read_from_udp(from, &packet);
	}
	else /* ROHC_TUNNEL_ETHERNET */
	{
		ret = read_from_raw(from, &packet);
	}
	if(ret != 0)
	{
		fprintf(stderr, "failed to read data from tunnel\n");
		goto error;
	}

	if((tunnel->type == ROHC_TUNNEL_UDP && packet.len <= 2) ||
	   (tunnel->type == ROHC_TUNNEL_ETHERNET && packet.len <= 3))
	{
		fprintf(stderr, "packet received from WAN is too short\n");
		goto quit;
	}

	/* find out if some ROHC packets were lost between compressor and
	 * decompressor (use the tunnel sequence number) */
	new_seq = ntohs((rohc_buf_byte(packet) << 8) +
	                rohc_buf_byte_at(packet, 1));
	if(new_seq < max_seq)
	{
		/* some packets were reordered, the packet was wrongly
		 * considered as lost */
		fprintf(stderr, "ROHC packet with seq = %u received after seq = %u\n",
		        new_seq, max_seq);
		lost_packets--;
	}
	else if(new_seq > max_seq + 1)
	{
		/* there is a gap between sequence numbers, some packets were lost */
		fprintf(stderr, "ROHC packet(s) probably lost between "
		        "seq = %u and seq = %u\n", max_seq, new_seq);
		lost_packets += new_seq - (max_seq + 1);
	}
	else if(new_seq == max_seq)
	{
		/* should not happen */
		fprintf(stderr, "ROHC packet #%u duplicated\n", new_seq);
	}

	if(new_seq > max_seq)
	{
		/* update max sequence numbers */
		max_seq = new_seq;
	}

	/* current ROHC packet length. Since for Ethernet min payload is 46 bytes
	 * and it is possible that current ROHC packet length is not that much, so
	 * the current length is extracted from the third byte */
	if(tunnel->type == ROHC_TUNNEL_UDP)
	{
		rohc_buf_shift(&packet, 2);
	}
	else /* ROHC_TUNNEL_ETHERNET */
	{
		uint8_t rohc_pkt_len = rohc_buf_byte_at(packet, 2);
		if(rohc_pkt_len > (packet.len - 3))
		{
			fprintf(stderr, "malformed Ethernet frame: length at byte #3 is "
			        "greater thant the full Ethernet frame\n");
			goto error;
		}
		rohc_buf_shift(&packet, 3);
		packet.len = rohc_pkt_len;
	}

	/* skip the TUN header */
	decomp_packet.len += 4;
	rohc_buf_shift(&decomp_packet, 4);

	/* decompress the ROHC packet */
#if DEBUG
	fprintf(stderr, "decompress ROHC packet #%u (%u bytes)\n",
	        new_seq, packet.len);
#endif
	ret = rohc_decompress3(decomp, packet, &decomp_packet,
	                       &feedback_rcvd, &(tunnel->feedback_send));
	if(ret != ROHC_OK)
	{
		fprintf(stderr, "decompression of packet #%u failed\n", new_seq);
		dump_packet("ROHC packet", packet);
		failed_decomp++;
		goto drop;
	}

	/* give received feedback to the same-side associated compressor */
	if(feedback_rcvd.len > 0 && comp != NULL)
	{
		if(!rohc_comp_deliver_feedback2(comp, feedback_rcvd))
		{
			fprintf(stderr, "failed to deliver the received feedback to the "
			        "same-site associated ROHC compressor\n");
		}
	}

	/* build the TUN header */
	rohc_buf_shift(&decomp_packet, -4);
	rohc_buf_byte_at(decomp_packet, 0) = 0;
	rohc_buf_byte_at(decomp_packet, 1) = 0;
	switch((rohc_buf_byte_at(decomp_packet, 4) >> 4) & 0x0f)
	{
		case 4: /* IPv4 */
			rohc_buf_byte_at(decomp_packet, 2) = 0x08;
			rohc_buf_byte_at(decomp_packet, 3) = 0x00;
			break;
		case 6: /* IPv6 */
			rohc_buf_byte_at(decomp_packet, 2) = 0x86;
			rohc_buf_byte_at(decomp_packet, 3) = 0xdd;
			break;
		default:
			fprintf(stderr, "bad IP version (%d)\n",
			        (rohc_buf_byte_at(decomp_packet, 4) >> 4) & 0x0f);
			dump_packet("ROHC packet", packet);
			rohc_buf_shift(&decomp_packet, 4);
			dump_packet("Decompressed packet", decomp_packet);
			goto drop;
	}

	/* write the IP packet on the virtual interface */
	ret = write_to_tun(to, decomp_packet);
	if(ret != 0)
	{
		fprintf(stderr, "write_to_tun failed\n");
		goto drop;
	}

	/* print packet statistics */
	print_decomp_stats(new_seq, lost_packets, failed_decomp);

quit:
	return 0;

drop:
	/* print packet statistics */
	print_decomp_stats(new_seq, lost_packets, failed_decomp);
error:
	return 1;
}



/*
 * Feedback flushing to the WAN socket
 */


/**
 * @brief Flush feedback packets stored at the compressor to the WAN socket
 *
 * @param comp   The ROHC compressor
 * @param to     The WAN socket descriptor to write to
 * @param tunnel The type and parameters of the tunnel
 * @return       0 in case of success, a non-null value otherwise
 */
int flush_feedback(const int to,
                   struct rohc_tunnel *const tunnel)
{
	int ret;

#if DEBUG
	fprintf(stderr, "flush %zu bytes of feedback data\n",
	        tunnel->feedback_send.len);
#endif
	if(tunnel->feedback_send.len > 0)
	{
		/* increment the tunnel sequence number */
		seq++;

		/* write the ROHC packet in the tunnel */
		if(tunnel->type == ROHC_TUNNEL_UDP)
		{
			rohc_buf_shift(&(tunnel->feedback_send), -2);
			ret = write_to_udp(to, tunnel->params.udp.raddr,
			                   tunnel->params.udp.port,
			                   tunnel->feedback_send);
		}
		else
		{
			rohc_buf_shift(&(tunnel->feedback_send), -3);
			ret = write_to_raw(to, tunnel->params.ethernet.raddr,
			                   tunnel->params.ethernet.itf_index,
			                   tunnel->feedback_send);
		}
		if(ret != 0)
		{
			fprintf(stderr, "failed to write data on tunnel\n");
			goto error;
		}
	}

	return 0;

error:
	return 1;
}



/*
 * Miscellaneous functions:
 */


/**
 * @brief Display the content of a IP or ROHC packet
 *
 * This function is used for debugging purposes.
 *
 * @param descr   A string that describes the packet
 * @param packet  The packet to display
 */
void dump_packet(const char *const descr, const struct rohc_buf packet)
{
	size_t i;

	fprintf(stderr, "-------------------------------\n");
	fprintf(stderr, "%s (%zd bytes):\n", descr, packet.len);
	for(i = 0; i < packet.len; i++)
	{
		if(i > 0 && (i % 16) == 0)
			fprintf(stderr, "\n");
		else if(i > 0 && (i % 8) == 0)
			fprintf(stderr, "\t");

		fprintf(stderr, "%.2x ", rohc_buf_byte_at(packet, i));
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "-------------------------------\n");
}


/**
 * @brief Get a probability number from the command line
 *
 * If error = 1, the return value is undetermined.
 *
 * @param arg    The argument from the command line
 * @param error  OUT: whether the conversion failed or not
 * @return       The probability
 */
double get_probability(char *arg, int *error)
{
	double proba;
	char *endptr;
	
	/* set error by default */
	*error = 1;

	/* convert from string to double */
	proba = strtod(arg, &endptr);

	/* check for conversion error */
	if(proba == 0 && endptr == arg)
	{
		if(errno == ERANGE)
			fprintf(stderr, "probability out of range (underflow): %s (%d)\n",
			        strerror(errno), errno);
		else
			fprintf(stderr, "bad probability value\n");
		goto quit;
	}

	/* check for overflow */
	if(proba == HUGE_VAL)
	{
		fprintf(stderr, "probability out of range (overflow): %s (%d)\n",
		        strerror(errno), errno);
		goto quit;
	}

	/* check probability value */
	if(proba < 0 || proba > 1)
	{
		fprintf(stderr, "probability must not be negative nor greater than 1\n");
		goto quit;
	}

	/* everything is fine */
	*error = 0;

quit:
	return proba;
}

/**
 * @brief Whether timeout is reached or not ?
 *
 * Timeout is reached if the differences between the two dates
 * is greater than the amount of time given as third parameter.
 *
 * @param first   The first date
 * @param second  The second date
 * @param max     The maximal amount of time between the two dates
 *                in seconds
 * @return        Whether timeout is reached or not ?
 */
int is_timeout(struct timeval first,
               struct timeval second,
               unsigned int max)
{
	unsigned int delta_sec;
	int is_timeout;

	delta_sec = second.tv_sec - first.tv_sec;

	if(delta_sec > max)
		is_timeout = 1;
	else if(delta_sec == max)
	{
		if(second.tv_usec > first.tv_usec)
			is_timeout = 1;
		else
			is_timeout = 0;
	}
	else
		is_timeout = 0;

	return is_timeout;
}


/**
 * @brief Print traces emitted by the ROHC library
 *
 * @param level    The priority level of the trace
 * @param entity   The entity that emitted the trace among:
 *                  \li ROHC_TRACE_COMP
 *                  \li ROHC_TRACE_DECOMP
 * @param profile  The ID of the ROHC compression/decompression profile
 *                 the trace is related to
 * @param format   The format string of the trace
 */
static void print_rohc_traces(const rohc_trace_level_t level __attribute__((unused)),
                              const rohc_trace_entity_t entity __attribute__((unused)),
                              const int profile __attribute__((unused)),
                              const char *const format,
                              ...)
{
	va_list args;
	va_start(args, format);
	vprintf(format, args);
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

