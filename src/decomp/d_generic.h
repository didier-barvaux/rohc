/**
 * @file d_generic.h
 * @brief ROHC generic decompression context for IP-only, UDP and UDP Lite
 *        profiles.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 * @author David Moreau from TAS
 */

#ifndef D_GENERIC_H
#define D_GENERIC_H

#include <stdlib.h>

#include "rohc_decomp.h"
#include "comp_list.h"

#define MAX_ITEM 15

#define LIST_COMP_WINDOW 100

#define L 5

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
	/// The IP header
	struct ip_packet ip;

	/// Whether the IP-ID is considered as random or not (IPv4 only)
	int rnd;
	/// Whether the IP-ID is considered as coded in NBO or not (IPv4 only)
	int nbo;

	/// Whether the compression list is used or not(IPv6 only)
	int complist;
	/// The size of the list
	int size_list;
	
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

	/// Whether at least packet was already processed by the context or not
	int first_packet_processed;

	/// The LSB-encoded Sequence Number (SN)
	struct d_lsb_decode sn;
	/// The IP-ID of the outer IP header
	struct d_ip_id_decode ip_id1;
	/// The IP-ID of the inner IP header
	struct d_ip_id_decode ip_id2;

	/// The list decompressor of the outer IP header
	struct list_decomp * list_decomp1;
	/// The list decompressor of the inner IP header
	struct list_decomp * list_decomp2;

	/// Whether the decompressed packet contains a 2nd IP header
	int multiple_ip;

	/// The type of packet the decompressor may receive: IR, IR-DYN, UO*
	int packet_type;

	/* below are some information and handlers to manage the next header
 	 * (if any) located just after the IP headers (1 or 2 IP headers) */

	/// The IP protocol ID of the protocol the context is able to decompress
	unsigned short next_header_proto;

	/// The length of the next header
	unsigned int next_header_len;

	/// @brief The handler used to build the uncompressed next header thanks
	///        to context information
	int (*build_next_header)(struct d_generic_context *context,
	                         struct d_generic_changes *active,
	                         unsigned char *dest,
	                         int payload_size);

	/// @brief The handler used to decode the static part of the next header
	///        in the ROHC packet
	int (*decode_static_next_header)(struct d_generic_context *context,
	                                 const unsigned char *packet,
	                                 unsigned int length,
	                                 unsigned char *dest);

	/// @brief The handler used to decode the dynamic part of the next header
	///        in the ROHC packet
	int (*decode_dynamic_next_header)(struct d_generic_context *context,
	                                  const unsigned char *packet,
	                                  unsigned int length,
	                                  unsigned char *dest);

	/// The handler used to decode the tail of the UO* ROHC packet
	int (*decode_uo_tail)(struct d_generic_context *context,
	                      const unsigned char *packet,
	                      unsigned int length,
	                      unsigned char *dest);

	/// Profile-specific data
	void *specific;

	/// Correction counter (see e and f in 5.3.2.2.4 of the RFC 3095)
	int counter;

	/// The timestamp of the last CRC-approved packet
	unsigned int last_packet_time;
	/// The timestamp of the current packet (not yet CRC-tested)
	unsigned int current_packet_time;
	/// The average inter-packet time over the last few packets
	unsigned int inter_arrival_time;
};

/**
 * @brief The list decompressor
 */
struct list_decomp
{
	/// The reference list
	struct c_list * ref_list;
	/// The table of lists
	struct c_list * list_table[LIST_COMP_WINDOW];
	/// The temp list
	struct c_list * temp_list;
	/// The compression based table
	struct item  based_table[MAX_ITEM];
	/// The translation table
	struct d_translation  trans_table[MAX_ITEM];
	/// counter in list table
	int counter_list;
	/// counter which indicates if the list is reference list
	int counter;
	/// boolean which indicates if there is a list to decompress
	int list_decomp;
	/// boolean which indicates if the ref list must be decompress 
	int ref_ok;
	/// Size of the last list extension received
	int size_ext;

	/// The handler used to free the based table
	void (*free_table)(struct list_decomp * decomp);
	/// The handler used to add the extension to IP packet
	int (*encode_extension)(struct d_generic_changes * active, 
			struct list_decomp * decomp, unsigned char *dest);
	/// The handler used to check if the index
	/// corresponds to an existing item
	int (*check_index)(struct list_decomp * decomp, int index);
	/// The handler used to create the item at 
	/// the corresponding index of the based table
	void (*create_item)(const unsigned char *data,int length,
			        int index, struct list_decomp * decomp);
	/// The handler used to get the size of an extension
	int (*get_ext_size)(const unsigned char * ext);
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
                        int plen,
                        int large_cid_len,
                        int is_addcid_used,
                        unsigned char *dest);

unsigned int d_generic_detect_ir_size(struct d_context *context,
				      unsigned char *packet,
                                      unsigned int plen,
                                      int second_byte,
                                      int profile_id);

unsigned int d_generic_detect_ir_dyn_size(unsigned char *first_byte,
                                          unsigned int plen,
                                          int largecid,
                                          struct d_context *context,
					  unsigned char *packet);
int d_algo_list_decompress(struct list_decomp * decomp, 
			   const unsigned char *packet);

int decode_type_0(struct list_decomp * decomp,
		  const unsigned char * packet, 
		  int gen_id, int ps, int m);

int decode_type_1(struct list_decomp * decomp,
		  const unsigned char * packet, 
		  int gen_id, 
		  int ps, int m, int ref_id);

int decode_type_2(struct list_decomp * decomp, 
		  const unsigned char * packet, 
		  int gen_id, int ps, int ref_id);

int decode_type_3(struct list_decomp * decomp,
		  const unsigned char * packet, 
		  int gen_id, 
		  int ps, int m, int ref_id);

int d_generic_get_sn(struct d_context *context);

int packet_type(struct rohc_decomp *decomp,
                struct d_context *context,
                const unsigned char *packet);

#endif

