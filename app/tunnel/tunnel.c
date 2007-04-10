/**
 * @file tunnel.c
 * @brief ROHC tunnel
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
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
 * messages from the ROHC library on stdout.
 *
 * Usage
 * -----
 *
 * rohctunnel NAME remote RADDR local LADDR port PORT
 *
 * NAME    the name of the tunnel
 * RADDR   the IP address of the remote host
 * LADDR   the IP address of the local host
 * PORT    the UDP port to use (local and remote)
 *
 * Example
 * -------
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
 *  # rohctunnel rohc0 remote 192.168.0.20 local 192.168.0.21 port 5000
 *  # ip link set rohc0 up
 *  # ip -4 addr add 10.0.0.1/24 dev rohc0
 *  # ip -6 addr add 2001:eeee::1/64 dev rohc0
 *
 * Then:
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
            struct in_addr raddr, int port);
int udp2tun(struct rohc_decomp *decomp, int from, int to);

void dump_packet(char *descr, unsigned char *packet, unsigned int length);



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
usage: rohctunnel NAME remote RADDR local LADDR port PORT\n\
  NAME    the name of the tunnel\n\
  RADDR   the IP address of the remote host\n\
  LADDR   the IP address of the local host\n\
  PORT    the UDP port to use (local and remote)\n\n\
example: rohctunnel rohc0 remote 192.168.0.20 local 192.168.0.21 port 5000\n");
}


/// The file descriptor where to write the statistics
FILE *stats;


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

	int ret;

	int tun, udp;

	fd_set readfds;
	struct timespec timeout;
	sigset_t sigmask;

	struct rohc_comp *comp;
	struct rohc_decomp *decomp;

	
	/*
	 * Parse arguments:
	 */

	if(argc != 8)
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
		usage();
		goto quit;
	}


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
	comp = rohc_alloc_compressor(15);
	if(comp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC compressor\n");
		goto close_udp;
	}
	rohc_activate_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(comp, ROHC_PROFILE_UDP);
	rohc_activate_profile(comp, ROHC_PROFILE_IP);
	rohc_activate_profile(comp, ROHC_PROFILE_UDPLITE);

	/* create the decompressor (associate it with the compressor) */
	decomp = rohc_alloc_decompressor(comp);
	if(decomp == NULL)
	{
		fprintf(stderr, "cannot create the ROHC decompressor\n");
		goto destroy_comp;
	}


	/* 
	 * Main program:
	 */

	/* write the stats to fd 3 */
	stats = fdopen(3, "a");
	if(stats == NULL)
	{
		fprintf(stderr, "cannot open fd 3 for stats: %s (%d)\n",
		        strerror(errno), errno);
		goto destroy_decomp;
	}

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
				failure = tun2udp(comp, tun, udp, raddr, port);
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
	}
	while(alive);


	/*
	 * Cleaning:
	 */

	fclose(stats);
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
		fprintf(stderr, "cannot bind to UDP socket\n");
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
	        *length, sock);
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
 * @return       0 in case of success, a non-null value otherwise
 */
int tun2udp(struct rohc_comp *comp,
            int from, int to,
            struct in_addr raddr, int port)
{
	static unsigned char buffer[TUNTAP_BUFSIZE];
	static unsigned char rohc_packet[MAX_ROHC_SIZE];
	unsigned int buffer_len = TUNTAP_BUFSIZE;
	unsigned char *packet;
	unsigned int packet_len;
	int rohc_size;
	int ret;
	static char *modes[] = { "error", "U-mode", "O-mode", "R-mode" };
	static char *states[] = { "error", "IR", "FO", "SO" };
	
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

	/* compress the IP packet */
#if DEBUG
	fprintf(stderr, "compress a %u-byte packet\n", packet_len);
#endif
	rohc_size = rohc_compress(comp, packet, packet_len,
	                          rohc_packet, MAX_ROHC_SIZE);
	if(rohc_size <= 0)
	{
		fprintf(stderr, "compression failed\n");
		dump_packet("IP packet:", packet, packet_len);
		goto error;
	}
	
	/* write the ROHC packet in the UDP tunnel */
	ret = write_to_udp(to, raddr, port, rohc_packet, rohc_size);
	if(ret != 0)
	{
		fprintf(stderr, "write_to_udp failed\n");
		goto error;
	}

	/* print packet statistics */
	if(comp->last_context == NULL)
	{
		fprintf(stderr, "cannot display stats\n");
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
	fprintf(stats, "%d\t%s\t%s\t%d\t%d\t%d\t%d\n",
	        comp->last_context->num_sent_packets,
	        modes[comp->last_context->mode],
	        states[comp->last_context->state],
	        comp->last_context->total_last_uncompressed_size,
	        comp->last_context->header_last_uncompressed_size,
	        comp->last_context->total_last_compressed_size,
	        comp->last_context->header_last_compressed_size);

quit:
	return 0;

error:
	return 1;
}


/**
 * @brief Forward ROHC packets received on the UDp socket to the TUN interface
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
	static unsigned char packet[TUNTAP_BUFSIZE];
	static unsigned char decomp_packet[MAX_ROHC_SIZE + 4];
	unsigned int packet_len = TUNTAP_BUFSIZE;
	int decomp_size;
	int ret;

#if DEBUG
	fprintf(stderr, "\n");
#endif

	/* read the ROHC packet from the UDP tunnel */
	ret = read_from_udp(from, packet, &packet_len);
	if(ret != 0)
	{
		fprintf(stderr, "read_from_udp failed\n");
		goto error;
	}

	if(packet_len == 0)
		goto quit;

	/* decompress the ROHC packet */
#if DEBUG
	fprintf(stderr, "decompress the %u-byte ROHC packet\n", packet_len);
#endif
	decomp_size = rohc_decompress(decomp, packet, packet_len,
	                              &decomp_packet[4], MAX_ROHC_SIZE);
	if(decomp_size <= 0)
	{
		fprintf(stderr, "decompression failed\n");
		dump_packet("ROHC packet:", packet, packet_len);
		goto error;
	}

	fprintf(stats, "%d\t%d\t%d\t%d\n",
	        decomp->statistics.packets_received,
	        decomp->statistics.packets_failed_crc,
	        decomp->statistics.packets_failed_no_context,
	        decomp->statistics.packets_failed_package);

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
			dump_packet("ROHC packet:", packet, packet_len);
			dump_packet("Decompressed packet:", &decomp_packet[4], decomp_size);
			goto error;
	}
	
	/* write the IP packet on the virtual interface */
	ret = write_to_tun(to, decomp_packet, decomp_size + 4);
	if(ret != 0)
	{
		fprintf(stderr, "write_to_tun failed\n");
		goto error;
	}

quit:
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

	printf("-------------------------------\n");
	printf("%s\n", descr);
	for(i = 0; i < length; i++)
	{
		if(i > 0 && (i % 16) == 0)
			printf("\n");
		else if(i > 0 && (i % 8) == 0)
			printf("\t");

		printf("%.2x ", packet[i]);
	}
	printf("\n");
	printf("-------------------------------\n");
}

