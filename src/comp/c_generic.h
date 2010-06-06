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
 * @file c_generic.h
 * @brief ROHC generic compression context for IP-only, UDP and UDP Lite
 *        profiles.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef C_GENERIC_H
#define C_GENERIC_H

#include "rohc_comp.h"
#include "rohc_packets.h"
#include "comp_list.h"
#include "ip.h"

#include <netinet/ip.h>


/**
 * @brief The maximal delta accepted between two consecutive IPv4 ID so that it
 *        can be considered as coded in Network Byte Order (NBO)
 */
#define IPID_MAX_DELTA  20

/// The number of compression list items
#define MAX_ITEM 15

/// The number of compressed list to send to make the reference list
/// L is the name specified in the RFC
#define L 5

/**
 * @brief Store information about an IPv4 header between the different
 *        compressions of IP packets.
 *
 * Defines an object that contains counters, flags and structures related to an
 * IPv4 header and that need to be saved between the different compressions of
 * packets. A compression context owns objects like this for the two first
 * IPv4 headers.
 */
struct ipv4_header_info
{
	/// A window to store the IP-ID
	struct c_wlsb *ip_id_window;

	/// The previous IP header
	struct iphdr old_ip;

	/// The number of times the DF field was added to the compressed header
	int df_count;
	/// @brief The number of times the IP-ID is specified as random in the
	///        compressed header
	int rnd_count;
	/// @brief The number of times the IP-ID is specified as coded in Network
	///        Byte Order (NBO) in the compressed header
	int nbo_count;

	/// Whether the IP-ID is considered as random or not
	int rnd;
	/// Whether the IP-ID is considered as coded in NBO or not
	int nbo;
	/// @brief Whether the IP-ID of the previous IP header was considered as
	///        random or not
	int old_rnd;
	/// @brief Whether the IP-ID of the previous IP header was considered as
	///        coded in NBO or not
	int old_nbo;

	/// The delta between the IP-ID and the current Sequence Number (SN)
	int id_delta;
};


/**
 * @brief Store information about an IPv6 header between the different
 *        compressions of IP packets.
 *
 * Defines an object that contains counters, flags and structures related to an
 * IPv6 header and that need to be saved between the different compressions of
 * packets. A compression context owns objects like this for the two first
 * IPv6 headers.
 */
struct ipv6_header_info
{
	/// The previous IPv6 header
	struct ip6_hdr old_ip;
	/// The extension compressor
	struct list_comp * ext_comp;
};


/**
 * @brief Store information about an IP (IPv4 or IPv6) header between the
 *        different compressions of IP packets.
 */
struct ip_header_info
{
	ip_version  version;           ///< The version of the IP header

	/// The number of times the TOS/TC field was added to the compressed header
	int tos_count;
	/// The number of times the TTL/HL field was added to the compressed header
	int ttl_count;
	/// @brief The number of times the Protocol/Next Header field was added to
	///        the compressed header
	int protocol_count;

	union
	{
		struct ipv4_header_info v4; ///< The IPv4-specific header info
		struct ipv6_header_info v6; ///< The IPv6-specific header info
	} info;                        ///< The version specific header info
};


/**
 * @brief Structure that contains variables that are used during one single
 *        compression of packet.
 *
 * Structure that contains variables that are temporary, i.e. variables that
 * will only be used for the compression of the current packet. These variables
 * must be reinitialized every time a new packet arrive.
 *
 * @see c_init_tmp_variables
 */
struct generic_tmp_variables
{
	/// The number of IP headers in the packet to compress (1 or 2 only)
	int nr_of_ip_hdr;

	/// The number of fields that changed in the outer IP header
	unsigned short changed_fields;
	/// The number of fields that changed in the inner IP header
	unsigned short changed_fields2;
	/// The number of static fields that changed in the two IP headers
	int send_static;
	/// The number of dynamic fields that changed in the two IP headers
	int send_dynamic;

	/// The number of bits needed to encode the Sequence Number (SN)
	int nr_sn_bits;
	/// The number of bits needed to encode the IP-ID of the outer IP header
	int nr_ip_id_bits;
	/// The number of bits needed to encode the IP-ID of the inner IP header
	int nr_ip_id_bits2;

	/// The type of packet the compressor must send: IR, IR-DYN, UO*
	rohc_packet_t packet_type;

	/// The maximal size of the compressed packet
	int max_size;
};


/**
 * @brief The generic compression context
 *
 * The object defines the generic context that manages IP(/nextheader) and
 * IP/IP(/nextheader) packets. nextheader is managed by the profile-specific
 * part of the context.
 */
struct c_generic_context
{
	/// The Sequence Number (SN)
	unsigned int sn;
	/// A window used to encode the SN
	struct c_wlsb *sn_window;

	/// The number of packets sent while in Initialization & Refresh (IR) state
	int ir_count;
	/// The number of packets sent while in First Order (FO) state
	int fo_count;
	/// The number of packets sent while in Second Order (SO) state
	int so_count;

	/// @brief The number of packet sent while in SO state, used for the periodic
	///        refreshes of the context
	/// @see periodic_down_transition
	int go_back_fo_count;
	/// @brief The number of packet sent while in FO or SO state, used for the
	///        periodic refreshes of the context
	/// @see periodic_down_transition
	int go_back_ir_count;
	/// @brief The minimal number of IR-DYN packets the compressor must sent
	///        before sending UO* packets
	int ir_dyn_count;

	/// Information about the outer IP header
	struct ip_header_info ip_flags;
	/// Information about the inner IP header
	struct ip_header_info ip2_flags;
	/// Whether the ip2_flags object is initialized or not
	int is_ip2_initialized;

	/// Temporary variables that are used during one single compression of packet
	struct generic_tmp_variables tmp_variables;

	/* below are some information and handlers to manage the next header
	 * (if any) located just after the IP headers (1 or 2 IP headers) */

	/// The protocol number registered by IANA for the next header protocol
	unsigned int next_header_proto;
	/// The length of the next header
	unsigned int next_header_len;

	/// @brief The handler used to decide the state that should be used for the
	///        next packet
	void (*decide_state)(struct c_context *const context);

	/// The handler used to initialize some data just before the IR packet build
	void (*init_at_IR)(const struct c_context *context,
	                   const unsigned char *next_header);

	/// @brief The handler used to add the static part of the next header to the
	///        ROHC packet
	int (*code_static_part)(const struct c_context *context,
	                        const unsigned char *next_header,
	                        unsigned char *const dest,
	                        int counter);

	/// @brief The handler used to add the dynamic part of the next header to the
	///        ROHC pachet
	int (*code_dynamic_part)(const struct c_context *context,
	                         const unsigned char *next_header,
	                         unsigned char *const dest,
	                         int counter);

	/// @brief The handler used to add an additional header in the head of the
	///        UO-0, UO-1 and UO-2 packets
	int (*code_UO_packet_head)(const struct c_context *context,
	                           const unsigned char *next_header,
	                           unsigned char *const dest,
	                           int counter,
	                           int *const first_position);

	/// @brief The handler used to add an additional header in the tail of the
	///        UO-0, UO-1 and UO-2 packets
	int (*code_UO_packet_tail)(const struct c_context *context,
	                           const unsigned char *next_header,
	                           unsigned char *const dest,
	                           int counter);

	/// @brief The handler used to compute the CRC-STATIC value
	unsigned int (*compute_crc_static)(const unsigned char *ip,
	                                   const unsigned char *ip2,
	                                   const unsigned char *next_header,
	                                   const unsigned int crc_type,
	                                   unsigned int init_val);

	/// @brief The handler used to compute the CRC-DYNAMIC value
	unsigned int (*compute_crc_dynamic)(const unsigned char *ip,
	                                    const unsigned char *ip2,
	                                    const unsigned char *next_header,
	                                    const unsigned int crc_type,
	                                    unsigned int init_val);

	/// Profile-specific data	
	void *specific;
};

/**
 * @brief The list compressor
 */
struct list_comp
{
	/// The reference list
	struct c_list * ref_list;
	/// The current list
	struct c_list * curr_list;
	/// counter which indicates if ref_list is reference list
        int counter;
	/// The compression based table
	struct item  based_table[MAX_ITEM];
	/// The translation table
	struct c_translation  trans_table[MAX_ITEM];
	/// Boolean which equals to 1 if the update is done, 0 else
	int update_done;
	/// Boolean which equals to 1 if the list change
	int list_compress;
	/// Boolean which equals to 1 if there is a list, 0 else
	int islist;

	/// @brief the handler used to get the extension in the IP packet
	unsigned char * (*get_extension)(const struct ip_packet *ip,
	                                 const int index);

	/// @brief the handler used to get the index in based table for the corresponding item
	int (*get_index_table)(const struct ip_packet *ip, const int index);

	/// @brief the handler used to get the size of an extension
	unsigned short (*get_size)(const unsigned char *ext);

	/// @brief the handler used to compare two extension of the same type
	int (*compare)(const unsigned char *ext,
	               const struct list_comp *comp,
	               const int size,
	               const int index_table);

	/// @brief the handler used to create the item with the corresponding 
	///        type of the extension
	void (*create_item)(const unsigned char *ext,
	                    const int index_table,
	                    const int size,
	                    struct list_comp *const comp);

	/// @brief the handler used to free the based table element
	void (*free_table)(struct list_comp *const comp);
};
																									    

/*
 * Function prototypes.
 */

int c_generic_create(struct c_context *const context,
                     const struct ip_packet *ip);
void c_generic_destroy(struct c_context *const context);

void change_mode(struct c_context *const context, const rohc_mode new_mode);
void change_state(struct c_context *const context, const rohc_c_state new_state);

void ip6_c_init_table(struct list_comp *const comp);
int c_algo_list_compress(struct list_comp *const comp,
                         const struct ip_packet *ip);
int c_create_current_list(const int index,
                          struct list_comp *const comp,
                          const unsigned char *ext,
                          const int index_table);
int decide_type(struct list_comp *const comp);
int encode_list(struct list_comp *const comp,
                unsigned char *const dest,
                int counter,
                const int ps,
                const int size);
int encode_type_0(struct list_comp *const comp,
                  unsigned char *const dest,
                  int counter,
                  const int ps);
int encode_type_1(struct list_comp *const comp,
                  unsigned char *const dest,
                  int counter,
                  const int ps);
int encode_type_2(struct list_comp *const comp,
                  unsigned char *const dest,
                  int counter,
                  const int ps);
int encode_type_3(struct list_comp *const comp,
                  unsigned char *const dest,
                  int counter,
                  const int ps);

int c_generic_encode(struct c_context *const context,
                     const struct ip_packet *ip,
                     const int packet_size,
                     unsigned char *const dest,
                     const int dest_size,
                     int *const payload_offset);

void c_generic_feedback(struct c_context *const context,
                        const struct c_feedback *feedback);

void decide_state(struct c_context *const context);


#endif

