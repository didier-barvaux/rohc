/**
 * @file rohc_comp.h
 * @brief ROHC compression routines
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef COMP_H
#define COMP_H

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>

#include "rohc.h"


struct c_feedback;


/// The number of ROHC profiles ready to be used
#define C_NUM_PROFILES 5


/// ROHC compressor states (see 4.3.1 in the RFC 3095)
typedef enum
{
	/// The Initialization and Refresh state
	IR = 1,
	/// The First Order state
	FO = 2,
	/// The Second Order state
	SO = 3,
} rohc_c_state;


/**
 * @brief The ROHC compressor.
 */
struct rohc_comp
{
	/// @brief Whether the compressor is enabled or not (enabled by default,
	///        can be disabled by user)
 	int enabled;

	/// The medium associated with the decompressor
	struct medium medium;

	/// The array of compression contexts that use the compressor
	struct c_context *contexts;
	/// The number of compression contexts stored in the array
	int num_contexts;
	/// The number of compression contexts in use in the array
	int num_contexts_used;

	/// @brief Which profiles are enabled and with one are not?
	/// 1 means enabled, 0 disabled
	int profiles[C_NUM_PROFILES];

	/* feedback-related variables: */

/// The maximal number of outgoing feedbacks that can be queued
#define FEEDBACK_BUFFER_SIZE 10
	/// The ring of buffers that stores outgoing feedbacks
	unsigned char *feedback_buffer[FEEDBACK_BUFFER_SIZE];
	/// The sizes of the buffers that stores outgoing feedbacks
	unsigned int feedback_size [FEEDBACK_BUFFER_SIZE];
	/// The position of the current feedback buffer in the feedback ring
	int feedback_pointer;

	/* some statistics about the compression process: */

	/// The number of sent packets
	int num_packets;
	/// The size of all the received uncompressed IP packets
	int total_uncompressed_size;
	/// The size of all the sent compressed ROHC packets
	int total_compressed_size;

	/// The last context used by the compressor
	struct c_context *last_context;
 
	/* user interaction variables: */

	/// Maximum Reconstructed Reception Unit (currently not used)
	int mrru;
	/// Maximum header size that will be compressed (currently not used)
	int max_header_size;
	/// The connection type (currently not used)
	int connection_type;
};


/**
 * @brief The ROHC compression context.
 */
struct c_context
{
	/// Whether the context is in use or not
	int used;
	/// The time when the context was created
	unsigned int latest_used;
	/// The time when the context was last used
	unsigned int first_used;

	/// The context unique ID (CID)
	int cid;

	/// The associated compressor
	struct rohc_comp *compressor;

	/// The associated profile
	struct c_profile *profile;
	/// Profile-specific data, defined by the profiles
	void *specific;

	/// The operation mode in which the context operates: U_MODE, O_MODE, R_MODE
	rohc_mode mode;
	/// The operation state in which the context operates: IR, FO, SO
	rohc_c_state state;

	/* below are some statistics */
	
	/// The average size of the uncompressed packets
	int total_uncompressed_size;
	/// The average size of the compressed packets
	int total_compressed_size;
	/// The average size of the uncompressed headers
	int header_uncompressed_size;
	/// The average size of the compressed headers
	int header_compressed_size; 

	/// The total size of the last uncompressed packet
	int total_last_uncompressed_size;
	/// The total size of the last compressed packet
	int total_last_compressed_size;
	/// The header size of the last uncompressed packet
	int header_last_uncompressed_size;
	/// The header size of the last compressed packet
	int header_last_compressed_size;

	/// The number of sent packets
	int num_sent_packets;
	/// The number of sent IR packets
	int num_sent_ir;
	/// The number of sent IR-DYN packets
	int num_sent_ir_dyn;
	/// The number of received feedbacks
	int num_recv_feedbacks;

	/// The size of the last 16 uncompressed packets
	struct c_wlsb *total_16_uncompressed;
	/// The size of the last 16 compressed packets
	struct c_wlsb *total_16_compressed;
	/// The size of the last 16 uncompressed headers
	struct c_wlsb *header_16_uncompressed;
	/// The size of the last 16 compressed headers
	struct c_wlsb *header_16_compressed;
};


/**
 * @brief The ROHC compression profile.
 *
 * The object defines a ROHC profile. Each field must be filled in
 * for each new profile.
 */
struct c_profile
{
	/// @brief The IP protocol ID used to find out which profile is able to
	///        compress an IP packet
	unsigned short protocol;
	
	/// @brief The UDP ports associated with this profile
	/// Only used with UDP as transport protocol. The pointer can be NULL if no
	/// port is specified. If defined, the list must be terminated by 0.
	/// ex: { 5000, 5001, 0 }
	int *ports;

	/// The profile ID as reserved by IANA
	unsigned short id;

	/// A string that describes the version of the implementation
	char *version;
	/// A string that describes the implementation (authors...)
	char *description;

	/// @brief The handler used to create the profile-specific part of the
	///        compression context
	int (*create)(struct c_context *context, const struct ip_packet packet);

	/// @brief The handler used to destroy the profile-specific part of the
	///        compression context
	void (*destroy)(struct c_context *context);

	/// @brief The handler used to check whether an uncompressed IP packet
	///        belongs to a context or not
	int (*check_context)(struct c_context *context, struct ip_packet packet);

	/// The handler used to encode uncompressed IP packets
	int (*encode)(struct c_context *context, const struct ip_packet packet,
	              int packet_size, unsigned char *dest, int dest_size,
	              int *payload_offset);

	/// @brief The handler used to warn the profile-specific part of the context
	///        about the arrival of feedback data
	void (*feedback)(struct c_context *context, struct c_feedback *feedback);
};


/**
 * @brief The feedback packet.
 */
struct c_feedback
{
	/// The Context ID to which the feedback packet is related
	int cid;

	/// @brief The type of feedback packet
	/// 1 means FEEDBACK-1, 2 means FEEDBACK-2
	int type;

	/// The feedback data (ie. the packet excluding the first type octet)
	unsigned char *data;
	/// The size of the feedback data
	unsigned char size;

	/// @brief The offset that indicates the beginning of the profile-specific
	///        data in the feedback data
	int specific_offset;
	/// The size of the profile-specific data
	int specific_size;

	/// The type of acknowledgement (FEEDBACK-2 only)
	enum {
		/// The classical ACKnowledgement
		ACK,
		/// The Negative ACKnowledgement
		NACK,
		/// The Negative STATIC ACKnowledgement
		STATIC_NACK,
		/// Currently unused acknowledgement type
		RESERVED
	} acktype;
};


/*
 * Functions related to compressor:
 */

struct rohc_comp * rohc_alloc_compressor(int max_cid);
void rohc_free_compressor(struct rohc_comp *comp);

int rohc_compress(struct rohc_comp *comp, unsigned char *ibuf, int isize,
                  unsigned char *obuf, int osize);

int rohc_c_info(char *buffer);
int rohc_c_statistics(struct rohc_comp *comp, unsigned int indent,
                      char *buffer);
int rohc_c_context(struct rohc_comp *comp, int cid, unsigned int indent,
                   char *buffer);

int rohc_c_is_enabled(struct rohc_comp *comp);
int rohc_c_using_small_cid(struct rohc_comp *comp);


/*
 * Functions related to context:
 */

struct c_context *c_create_context(struct rohc_comp *, struct c_profile *profile, struct ip_packet ip);
struct c_context *c_find_context(struct rohc_comp *, struct c_profile *profile, struct ip_packet ip);
struct c_context *c_get_context(struct rohc_comp *, int cid);


/*
 * Functions related to profile:
 */

struct c_profile * c_get_profile_from_packet(struct rohc_comp *comp,
                                             int protocol,
                                             struct ip_packet ip);
struct c_profile * c_get_profile_from_id(struct rohc_comp *comp,
                                         int profile_id);
void rohc_activate_profile(struct rohc_comp *comp, int profile);


/*
 * Functions related to feedback:
 */

void c_piggyback_feedback(struct rohc_comp *comp, unsigned char *packet,
                          int size);
void c_deliver_feedback(struct rohc_comp *comp, unsigned char *feedback,
                        int size);
int rohc_feedback_flush(struct rohc_comp *comp,
                        unsigned char *obuf,
                        int osize);


/*
 * Functions related to user interaction:
 */

void rohc_c_set_header(struct rohc_comp *compressor, int value);
void rohc_c_set_mrru(struct rohc_comp *compressor, int value);
void rohc_c_set_max_cid(struct rohc_comp *compressor, int value);
void rohc_c_set_large_cid(struct rohc_comp *compressor, int value);
void rohc_c_set_enable(struct rohc_comp *compressor, int value);


/*
 * ROHC library includes:
 */

#include "cid.h"


#endif

