/**
 * @file tunnel.c
 * @brief ROHC tunnel
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 *
 * Description
 * -----------
 *
 * The program creates a ROHC tunnel over UDP. A ROHC tunnel compresses the IP
 * packets it receives from a virtual network interface and decompresses the
 * ROHC packets it receives from one UDP flow.
 *
 *               +-----------+                          +----------+
 * IP packets    |  Virtual  |     +--------------+     |          |
 * sent by   --> | interface | --> |  Compressor  | --> |   ROHC   |
 * the host      |   (TUN)   |     +--------------+     |  packets |
 *               |           |                          |   over   |
 * IP packets    |           |     +--------------+     | UDP flow |
 * received  <-- |           | <-- | Decompressor | <-- |          |
 * from the      |           |     +--------------+     |          |
 * tunnel        +-----------+                          +----------+
 *
 * The program outputs messages from the tunnel application on stderr and
 * messages from the ROHC library on stdout. It outputs compression statistics
 * on file descriptor 3 and decompression statistics on file descriptor 4.
 *
 * The tunnel can emulate a lossy medium with a given error rate. Unidirectional
 * mode can be forced (no feedback channel).
 *
 * Usage
 * -----
 *
 * Run the rohctunnel without any argument to see what arguments the application
 * accepts.
 *
 * Basic example
 * -------------
 *
 * Type as root on machine A:
 *
 *  # rohctunnel rohc0 remote 192.168.0.20 local 192.168.0.21 port 5000
 *  # ip link set rohc0 up
 *  # ip -4 addr add 10.0.0.1/24 dev rohc0
 *  # ip -6 addr add 2001:eeee::1/64 dev rohc0
 *
 * Type as root on machine B:
 *
 *  # rohctunnel rohc0 remote 192.168.0.21 local 192.168.0.20 port 5000
 *  # ip link set rohc0 up
 *  # ip -4 addr add 10.0.0.2/24 dev rohc0
 *  # ip -6 addr add 2001:eeee::2/64 dev rohc0
 *
 * Then, on machine B:
 *
 *  $ ping 10.0.0.1
 *  $ ping6 2001:eeee::1
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <signal.h>
#include <errno.h>
#include <math.h> /* for HUGE_VAL */

/* TUN includes */
#include <net/if.h> /* for IFNAMSIZ */
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>

/* UDP includes */
#include <sys/socket.h>
#include <arpa/inet.h>

/* ROHC includes */
#include "rohc.h"
#include "rohc_comp.h"
#include "rohc_decomp.h"



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


/*
 * Function prototypes:
 */

int tun_create(char *name);
int read_from_tun(int fd, unsigned char *buffer, unsigned int *length);
int write_to_tun(int fd, unsigned char *buffer, unsigned int length);

int udp_create(struct in_addr laddr, int port);
int read_from_udp(int sock, unsigned char *buffer, unsigned int *length);
int write_to_udp(int sock, struct in_addr raddr, int port,
                 unsigned char *packet, unsigned int length);

int tun2udp(struct rohc_comp *comp,
            int from, int to,
            struct in_addr raddr, int port,
            int error, double ber, double pe2, double p2);
int udp2tun(struct rohc_decomp *decomp, int from, int to);
int flush_feedback(struct rohc_comp *comp,
                   int to, struct in_addr raddr, int port);

void dump_packet(char *descr, unsigned char *packet, unsigned int length);
double get_probability(char *arg, int *error);
int is_timeout(struct timeval first,
               struct timeval second,
               unsigned int max);



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
	printf("ROHC tunnel: make a ROHC over UDP tunnel\n\n\
usage: rohctunnel NAME remote RADDR local LADDR port PORT [error MODEL PARAMS [dir DIR]]\n\
  NAME    the name of the tunnel\n\
  RADDR   the IP address of the remote host\n\
  LADDR   the IP address of the local host\n\
  PORT    the UDP port to use (local and remote)\n\
  MODEL   the error model to apply (none, uniform, burst)\n\
  PARAMS  the error model parameters:\n\
            none     no extra parameter\n\
            uniform  RATE = the BER (binary error rate) to emulate\n\
            burst    PE2  = the probability to be in error state\n\
                     P2   = the probability to stay in error state\n\
  DIR     unidirectional or bidirectional mode (default is bidirectional)\n\n\
example: rohctunnel rohc0 remote 192.168.0.20 local 192.168.0.21 port 5000 error uniform 1e-5 dir bidirectional\n");
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

	char *tun_name;
	struct in_addr raddr;
	struct in_addr laddr;
	int port;
	int error_model;
	int conv_error;
	double ber = 0;
	double pe2 = 0;
	double p2 = 0;
	int arg_count;
	int is_umode;

	int ret;

	int tun, udp;

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

	if(argc != 8 &&
	   argc < 10 && argc > 14)
	{
		usage();
		goto quit;
	}

	/* get the tunnel name */
	tun_name = argv[1];

	/* get the remote IP address */
	if(strcmp(argv[2], "remote") != 0)
	{
		usage();
		goto quit;
	}
	if(!inet_aton(argv[3], &raddr))
	{
		fprintf(stderr, "bad remote IP address: %s\n", argv[3]);
		goto quit;
	}


	/* get the local IP address */
	if(strcmp(argv[4], "local") != 0)
	{
		usage();
		goto quit;
	}
	if(!inet_aton(argv[5], &laddr))
	{
		fprintf(stderr, "bad local IP address: %s\n", argv[5]);
		goto quit;
	}

	/* get the device name */
	if(strcmp(argv[6], "port") != 0)
	{
		usage();
		goto quit;
	}
	port = atoi(argv[7]);
	if(port <= 0 || port >= 0xffff)
	{
		fprintf(stderr, "bad port: %s\n", argv[7]);
		goto quit;
	}

	/* get the error model and its parameters if present */
	if(argc >= 10)
	{
		if(strcmp(argv[8], "error") != 0)
		{
			usage();
			goto quit;
		}

		arg_count = 9;

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
			if(argc < arg_count + 1)
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
			if(argc < arg_count + 2)
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
		error_model = 0;
		arg_count = 8;
	}

	/* get the direction mode if present */
	if(argc >= arg_count + 2)
	{
		if(strcmp(argv[arg_count], "dir") != 0)
		{
			usage();
			goto quit;
		}
		arg_count++;

		if(strcmp(argv[arg_count], "unidirectional") == 0)
			is_umode = 1;
		else if(strcmp(argv[arg_count], "bidirectional") == 0)
			is_umode = 0;
		else
		{
			fprintf(stderr, "bad direction mode: %s\n", argv[arg_count]);
			goto quit;
		}

		if(is_umode)
			fprintf(stderr, "force unidirectional mode\n");
	}
	else
		is_umode = 0;


	/*
	 * Network interface part:
	 */

	/* create virtual network interface */
	tun = tun_create(tun_name);
	if(tun < 0)
	{
		fprintf(stderr, "%s creation failed\n", tun_name);
		failure = 1;
		goto quit;
	}
	fprintf(stderr, "%s created, fd %d\n", tun_name, tun);

	/* create an UDP socket */
	udp = udp_create(laddr, port);
	if(udp < 0)
	{
		fprintf(stderr, "UDP socket creation on port %d failed\n",
		        port);
		failure = 1;
		goto close_tun;
	}
	fprintf(stderr, "UDP socket created on port %d, fd %d\n",
	        port, udp);


	/*
	 * ROHC part:
	 */

	/* init the CRC tables for ROHC compression/decompression */
	crc_init_table(crc_table_3, crc_get_polynom(CRC_TYPE_3));
	crc_init_table(crc_table_7, crc_get_polynom(CRC_TYPE_7));
	crc_init_table(crc_table_8, crc_get_polynom(CRC_TYPE_8));

	/* create the compressor and activate profiles */
	comp = rohc_alloc_compressor(15, 0, 0, 0);
	if(comp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC compressor\n");
		goto close_udp;
	}
	rohc_activate_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(comp, ROHC_PROFILE_UDP);
	rohc_activate_profile(comp, ROHC_PROFILE_IP);
	rohc_activate_profile(comp, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(comp, ROHC_PROFILE_RTP);

	/* create the decompressor (associate it with the compressor) */
	decomp = rohc_alloc_decompressor(is_umode ? NULL : comp);
	if(decomp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC decompressor\n");
		goto destroy_comp;
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
		FD_SET(udp, &readfds);

		ret = pselect(max(tun, udp) + 1, &readfds, NULL, NULL, &timeout, &sigmask);
		if(ret < 0)
		{
			fprintf(stderr, "pselect failed: %s (%d)\n", strerror(errno), errno);
			failure = 1;
			alive = 0;
		}
		else if(ret > 0)
		{
			/* bridge from TUN to UDP */
			if(FD_ISSET(tun, &readfds))
			{
				failure = tun2udp(comp, tun, udp, raddr, port,
				                  error_model, ber, pe2, p2);
				gettimeofday(&last, NULL);
#if STOP_ON_FAILURE
				if(failure)
					alive = 0;
#endif
			}

			/* bridge from UDP to TUN */
			if(
#if STOP_ON_FAILURE
			   !failure &&
#endif
			   FD_ISSET(udp, &readfds))
			{
				failure = udp2tun(decomp, udp, tun);
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
			failure = flush_feedback(comp, udp, raddr, port);
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
	rohc_free_decompressor(decomp);
destroy_comp:
	rohc_free_compressor(comp);
close_udp:
	close(udp);
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
		return fd;

	/* flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *        IFF_NO_PI - Do not provide packet information */
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_flags = IFF_TUN;

	/* create the TUN interface */
	if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
	{
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
 * @param buffer  The buffer where to store the data
 * @param length  OUT: the length of the data
 * @return        0 in case of success, a non-null value otherwise
 */
int read_from_tun(int fd, unsigned char *buffer, unsigned int *length)
{
	int ret;

	ret = read(fd, buffer, *length);

	if(ret < 0 || ret > *length)
	{
		fprintf(stderr, "read failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

	*length = ret;

#if DEBUG
	fprintf(stderr, "read %u bytes on fd %d\n", ret, fd);
#endif

	return 0;

error:
	*length = 0;
	return 1;
}


/**
 * @brief Write data to the TUN interface
 *
 * Data written to the TUN interface must contain a 4-byte header that gives
 * the protocol of the data. See the read_from_tun function for details.
 *
 * @param fd      The TUN file descriptor to write data to
 * @param buffer  The packet to write to the TUN interface (header included)
 * @param length  The length of the packet (header included)
 * @return        0 in case of success, a non-null value otherwise
 */
int write_to_tun(int fd, unsigned char *packet, unsigned int length)
{
	int ret;

	ret = write(fd, packet, length);
	if(ret < 0)
	{
		fprintf(stderr, "write failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

#if DEBUG
	fprintf(stderr, "%u bytes written on fd %d\n", length, fd);
#endif

	return 0;

error:
	return 1;
}



/*
 * Raw socket:
 */


/**
 * @brief Create an UDP socket
 *
 * @param laddr  The local address to bind the socket to
 * @param port   The UDP port to bind the socket to
 * @return       An opened socket descriptor on the TUN interface in case of
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
		fprintf(stderr, "cannot create the UDP socket\n");
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
	bzero(&addr, sizeof(addr));
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
 * @param buffer  The buffer where to store the data
 * @param length  OUT: the length of the data
 * @return        0 in case of success, a non-null value otherwise
 */
int read_from_udp(int sock, unsigned char *buffer, unsigned int *length)
{
	struct sockaddr_in addr;
	socklen_t addr_len;
	int ret;

	addr_len = sizeof(struct sockaddr_in);
	bzero(&addr, addr_len);

	/* read data from the UDP socket */
	ret = recvfrom(sock, buffer, *length, 0, (struct sockaddr *) &addr,
	               &addr_len);

	if(ret < 0 || ret > *length)
	{
		fprintf(stderr, "recvfrom failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

	if(ret == 0)
		goto quit;

	*length = ret;

#if DEBUG
	fprintf(stderr, "read one %u-byte ROHC packet on UDP sock %d\n",
	        *length - 2, sock);
#endif

quit:
	return 0;

error:
	*length = 0;
	return 1;
}


/**
 * @brief Write data to the UDP socket
 *
 * All UDP packets contain a sequence number that identify the UDP packet. It
 * helps discovering lost packets (for statistical purposes). The buffer that
 * contains the ROHC packet must have 2 bytes of free space at the beginning.
 * This allows the write_to_udp function to add the 2-bytes sequence number in
 * the UDP packet without allocating new memory.
 *
 * @param sock    The UDP socket descriptor to write data to
 * @param raddr   The remote address of the tunnel (ie. the address where to
 *                send the UDP datagrams)
 * @param port    The remote UDP port  where to send the UDP data
 * @param buffer  The packet to write to the UDP socket
 * @param length  The length of the packet
 * @return        0 in case of success, a non-null value otherwise
 */
int write_to_udp(int sock, struct in_addr raddr, int port,
                 unsigned char *packet, unsigned int length)
{
	struct sockaddr_in addr;
	int ret;

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = raddr.s_addr;
	addr.sin_port = htons(port);

	/* write the tunnel sequence number at the beginning of packet */
	packet[0] = (htons(seq) >> 8) & 0xff;
	packet[1] = htons(seq) & 0xff;

	/* send the data on the UDP socket */
	ret = sendto(sock, packet, length, 0, (struct sockaddr *) &addr,
	             sizeof(struct sockaddr_in));
	if(ret < 0)
	{
		fprintf(stderr, "sendto failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

#if DEBUG
	fprintf(stderr, "%u bytes written on socket %d\n", length, sock);
#endif

	return 0;

error:
	return 1;
}



/*
 * Forwarding between the TUN interface and the UDP socket
 */


/**
 * @brief Forward IP packets received on the TUN interface to the UDP socket
 *
 * The function compresses the IP packets thanks to the ROHC library before
 * sending them on the UDP socket.
 *
 * @param comp   The ROHC compressor
 * @param from   The TUN file descriptor to read from
 * @param to     The UDP socket descriptor to write to
 * @param raddr  The remote address of the tunnel
 * @param port   The remote port of the tunnel
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
int tun2udp(struct rohc_comp *comp,
            int from, int to,
            struct in_addr raddr, int port,
            int error, double ber, double pe2, double p2)
{
	static unsigned char buffer[TUNTAP_BUFSIZE];
	static unsigned char rohc_packet[2 + MAX_ROHC_SIZE];
	unsigned int buffer_len = TUNTAP_BUFSIZE;
	unsigned char *packet;
	unsigned int packet_len;
	int rohc_size;
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
	static char *modes[] = { "error", "U-mode", "O-mode", "R-mode" };
	static char *states[] = { "error", "IR", "FO", "SO" };

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
	ret = read_from_tun(from, buffer, &buffer_len);
	if(ret != 0)
	{
		fprintf(stderr, "read_from_tun failed\n");
		goto error;
	}

	if(buffer_len == 0)
		goto quit;

	packet = &buffer[4];
	packet_len = buffer_len - 4;

	/* increment the tunnel sequence number */
	seq++;

	/* compress the IP packet */
#if DEBUG
	fprintf(stderr, "compress packet #%u (%u bytes)\n", seq, packet_len);
#endif
	rohc_size = rohc_compress(comp, packet, packet_len,
	                          rohc_packet + 2, MAX_ROHC_SIZE);
	if(rohc_size <= 0)
	{
		fprintf(stderr, "compression of packet #%u failed\n", seq);
		dump_packet("IP packet", packet, packet_len);
		goto error;
	}

	/* emulate lossy medium if asked to do so */
	if(error == 1) /* uniform error model */
	{
		if(nb_bytes + rohc_size >= bytes_without_error)
		{
			to_drop = 1;
			dropped++;
			fprintf(stderr, "error inserted, ROHC packet #%u dropped\n", seq);
			nb_bytes = rohc_size - (bytes_without_error - nb_bytes);
		}
		
		nb_bytes += rohc_size;
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

	/* write the ROHC packet in the UDP tunnel if not dropped */
	if(!to_drop)
	{
		ret = write_to_udp(to, raddr, port, rohc_packet, 2 + rohc_size);
		if(ret != 0)
		{
			fprintf(stderr, "write_to_udp failed\n");
			goto error;
		}
	}

	/* print packet statistics */
	if(comp->last_context == NULL)
	{
		fprintf(stderr, "cannot display stats (last context == NULL)\n");
		goto error;
	}
	if(comp->last_context->mode <= 0 ||
	   comp->last_context->mode > 3)
	{
		fprintf(stderr, "invalid mode\n");
		goto error;
	}
	if(comp->last_context->state <= 0 ||
	   comp->last_context->state > 3)
	{
		fprintf(stderr, "invalid state\n");
		goto error;
	}
	fprintf(stats_comp, "%d\t%s\t%s\t%d\t%d\t%d\t%d\t%u\n",
	        seq,
	        modes[comp->last_context->mode],
	        states[comp->last_context->state],
	        comp->last_context->total_last_uncompressed_size,
	        comp->last_context->header_last_uncompressed_size,
	        comp->last_context->total_last_compressed_size,
	        comp->last_context->header_last_compressed_size,
	        dropped);
	fflush(stats_comp);

quit:
	return 0;

error:
	return 1;
}


/*
 * @brief Print packet statistics for decompressor
 *
 * @param decomp        The ROHC decompressor
 * @param seq           The tunnel sequence number
 * @param lost_packets  The number of lost packets
 * @return              0 in case of success, 1 otherwise
 */
int print_decomp_stats(struct rohc_decomp *decomp,
                       unsigned int seq,
                       unsigned int lost_packets)
{
	if(decomp->last_context == NULL)
	{
		fprintf(stderr, "cannot display stats (last context == NULL)\n");
		goto error;
	}

	fprintf(stats_decomp, "%u\t%d\t%u\t%d\n", seq,
	        lost_packets + decomp->last_context->num_decomp_failures,
	        lost_packets, decomp->last_context->num_decomp_failures);
	fflush(stats_decomp);

	return 0;

error:
	return 1;
}


/**
 * @brief Forward ROHC packets received on the UDP socket to the TUN interface
 *
 * The function decompresses the ROHC packets thanks to the ROHC library before
 * sending them on the TUN interface.
 *
 * @param decomp  The ROHC decompressor
 * @param from    The UDP socket descriptor to read from
 * @param to      The TUN file descriptor to write to
 * @return        0 in case of success, a non-null value otherwise
 */
int udp2tun(struct rohc_decomp *decomp, int from, int to)
{
	static unsigned char packet[2 + MAX_ROHC_SIZE];
	static unsigned char decomp_packet[MAX_ROHC_SIZE + 4];
	unsigned int packet_len = TUNTAP_BUFSIZE;
	int decomp_size;
	int ret;
	static unsigned int max_seq = 0;
	unsigned int new_seq;
	static unsigned long lost_packets = 0;

#if DEBUG
	fprintf(stderr, "\n");
#endif

	/* read the sequence number + ROHC packet from the UDP tunnel */
	ret = read_from_udp(from, packet, &packet_len);
	if(ret != 0)
	{
		fprintf(stderr, "read_from_udp failed\n");
		goto error;
	}

	if(packet_len <= 2)
		goto quit;

	/* find out if some ROHC packets were lost between compressor and
	 * decompressor (use the tunnel sequence number) */
	new_seq = ntohs((packet[0] << 8) + packet[1]);

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
		/* should not append */
		fprintf(stderr, "ROHC packet #%u duplicated\n", new_seq);
	}
	
	if(new_seq > max_seq)
	{
		/* update max sequence numbers */
		max_seq = new_seq;
	}

	/* decompress the ROHC packet */
#if DEBUG
	fprintf(stderr, "decompress ROHC packet #%u (%u bytes)\n",
	        new_seq, packet_len - 2);
#endif
	decomp_size = rohc_decompress(decomp, packet + 2, packet_len - 2,
	                              &decomp_packet[4], MAX_ROHC_SIZE);
	if(decomp_size <= 0)
	{
		if(decomp_size == ROHC_FEEDBACK_ONLY)
		{
			/* no stats for feedback-only packets */
			goto quit;
		}
		else
		{
			fprintf(stderr, "decompression of packet #%u failed\n", new_seq);
			dump_packet("ROHC packet", packet + 2, packet_len - 2);
			goto drop;
		}
	}

	/* build the TUN header */
	decomp_packet[0] = 0;
	decomp_packet[1] = 0;
	switch((decomp_packet[4] >> 4) & 0x0f)
	{
		case 4: /* IPv4 */
			decomp_packet[2] = 0x08;
			decomp_packet[3] = 0x00;
			break;
		case 6: /* IPv6 */
			decomp_packet[2] = 0x86;
			decomp_packet[3] = 0xdd;
			break;
		default:
			fprintf(stderr, "bad IP version (%d)\n",
			        (decomp_packet[4] >> 4) & 0x0f);
			dump_packet("ROHC packet", packet, packet_len);
			dump_packet("Decompressed packet", &decomp_packet[4], decomp_size);
			goto drop;
	}
	
	/* write the IP packet on the virtual interface */
	ret = write_to_tun(to, decomp_packet, decomp_size + 4);
	if(ret != 0)
	{
		fprintf(stderr, "write_to_tun failed\n");
		goto drop;
	}

	/* print packet statistics */
	ret = print_decomp_stats(decomp, new_seq, lost_packets);
	if(ret != 0)
	{
		fprintf(stderr, "cannot display stats (print_decomp_stats failed)\n");
		goto drop;
	}

quit:
	return 0;

drop:
	/* print packet statistics */
	ret = print_decomp_stats(decomp, new_seq, lost_packets);
	if(ret != 0)
		fprintf(stderr, "cannot display stats (print_decomp_stats failed)\n");

error:
	return 1;
}



/*
 * Feedback flushing to the UDP socket
 */


/**
 * @brief Flush feedback packets stored at the compressor to the UDP socket
 *
 * @param comp   The ROHC compressor
 * @param to     The UDP socket descriptor to write to
 * @param raddr  The remote address of the tunnel
 * @param port   The remote port of the tunnel
 * @return       0 in case of success, a non-null value otherwise
 */
int flush_feedback(struct rohc_comp *comp,
                   int to, struct in_addr raddr, int port)
{
	static unsigned char rohc_packet[2 + MAX_ROHC_SIZE];
	int rohc_size;
	int ret;
	
#if DEBUG
	fprintf(stderr, "\n");
#endif

	/* flush feedback data as many times as necessary */
	do
	{
		/* flush feedback data */
		rohc_size = rohc_feedback_flush(comp, rohc_packet + 2, MAX_ROHC_SIZE);

#if DEBUG
		fprintf(stderr, "flush %d bytes of feedback data\n", rohc_size);
#endif

		if(rohc_size > 0)
		{
			/* increment the tunnel sequence number */
			seq++;

			/* write the ROHC packet in the UDP tunnel */
			ret = write_to_udp(to, raddr, port, rohc_packet, 2 + rohc_size);
			if(ret != 0)
			{
				fprintf(stderr, "write_to_udp failed\n");
				goto error;
			}
		}
	}
	while(rohc_size > 0);

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
 * @param length  The length of the packet to display
 */
void dump_packet(char *descr, unsigned char *packet, unsigned int length)
{
	unsigned int i;

	fprintf(stderr, "-------------------------------\n");
	fprintf(stderr, "%s (%u bytes):\n", descr, length);
	for(i = 0; i < length; i++)
	{
		if(i > 0 && (i % 16) == 0)
			fprintf(stderr, "\n");
		else if(i > 0 && (i % 8) == 0)
			fprintf(stderr, "\t");

		fprintf(stderr, "%.2x ", packet[i]);
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

