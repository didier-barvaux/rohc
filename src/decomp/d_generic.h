/**
 * @file d_generic.h
 * @brief ROHC generic decompression context for IP-only, UDP and UDP Lite
 *        profiles.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef D_GENERIC_H
#define D_GENERIC_H

#include <stdlib.h>

#include "rohc_decomp.h"


/**
 * @brief Store information about an IP header between the different
 *        decompressions of IP packets.
 *
 * Defines an object that contains flags and structures related to an IP header
 * and that need to be saved between the different decompressions of packets. A
 * decompression context owns objects like this for the two first IP headers.
 */
struct d_generic_changes
{
	/// Whether the IP-ID is considered as random or not
	int rnd;
	/// Whether the IP-ID is considered as coded in NBO or not
	int nbo;
	/// The IP header
	struct iphdr ip;

	/// The next header located after the IP header(s)
	unsigned char *next_header;
	/// The length of the next header
	unsigned int next_header_len;
};


/**
 * @brief The generic decompression context
 *
 * The object defines the generic context that manages IP(/nextheader) and
 * IP/IP(/nextheader) packets. nextheader is managed by the profile-specific
 * part of the context.
 */
struct d_generic_context
{
	/// Information about the previous outer IP header
	struct d_generic_changes *last1;
	/// Information about the previous inner IP header
	struct d_generic_changes *last2;
	/// Information about the current outer IP header
	struct d_generic_changes *active1;
	/// Information about the current inner IP header
	struct d_generic_changes *active2;

	/// The LSB-encoded Sequence Number (SN)
	struct d_lsb_decode sn;
	/// The IP-ID of the outer IP header
	struct d_ip_id_decode ip_id1;
	/// The IP-ID of the inner IP header
	struct d_ip_id_decode ip_id2;

	/// Whether the decompressed packet contains a 2nd IP header
	int multiple_ip;

	/// The type of packet the decompressor may receive: IR, IR-DYN, UO*
	int packet_type;

	/* below are some information and handlers to manage the next header
 	 * (if any) located just after the IP headers (1 or 2 IP headers) */

	/// The length of the next header
	unsigned int next_header_len;

	/// @brief The handler used to build the uncompressed next header thanks
	///        to context information
	void (*build_next_header)(struct d_generic_context *context,
	                          struct d_generic_changes *active,
	                          unsigned char *dest, int payload_sizei);

	/// @brief The handler used to decode the static part of the next header
	///        in the ROHC packet
	int (*decode_static_next_header)(struct d_generic_context *context,
	                                 const unsigned char *packet,
	                                 unsigned char *dest);

	/// @brief The handler used to decode the dynamic part of the next header
	///        in the ROHC packet
	int (*decode_dynamic_next_header)(struct d_generic_context *context,
	                                  const unsigned char *packet,
	                                  int payload_size,
	                                  unsigned char *dest);

	/// Profile-specific data
	void *specific;

	/// Correction counter (see e and f in 5.3.2.2.4 of the RFC 3095)
	int counter;

	int last_packet_time;    ///< the time of the last crc-approved packet
	int current_packet_time; ///< the time of the current packet without crc-test yet
	int inter_arrival_time;  ///< a average inter-packet time of the last few packets,
};


/*
 * Public function prototypes.
 */

void * d_generic_create(void);

void d_generic_destroy(void *context);

int d_generic_decode(struct rohc_decomp *decomp,
                     struct d_context *context,
                     unsigned char *packet,
                     int size,
                     int second_byte,
                     unsigned char *dest);

int d_generic_decode_ir(struct rohc_decomp *decomp,
                        struct d_context *context,
                        unsigned char *packet,
                        int payload_size,
                        int dynamic_present,
                        unsigned char *dest);

int d_generic_detect_ir_size(unsigned char *packet, int second_byte);

int d_generic_detect_ir_dyn_size(unsigned char *first_byte,
                                 struct d_context *context);

int d_generic_get_sn(struct d_context *context);

int packet_type(const unsigned char *packet);


#endif

