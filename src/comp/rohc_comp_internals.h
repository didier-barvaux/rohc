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
 * @file    rohc_comp_internals.h
 * @brief   Internal structures for ROHC compression 
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author  Didier Barvaux <didier@barvaux.org>
 * @author  The hackers from ROHC for Linux
 */

#ifndef ROHC_COMP_INTERNALS_H
#define ROHC_COMP_INTERNALS_H

#include "rohc.h" /* for struct medium */
#include "rohc_packets.h"
#include "rohc_comp.h"
#include "wlsb.h"
#include "ip.h"

#include <stdbool.h>


/*
 * Constants and macros
 */

/** The number of ROHC profiles ready to be used */
#define C_NUM_PROFILES 5

/** The maximal number of outgoing feedbacks that can be queued */
#define FEEDBACK_RING_SIZE 10


/*
 * Declare ROHC compression structures that are defined at the end of this
 * file but used by other structures at the beginning of the file.
 */

struct c_feedback;
struct c_context;


/*
 * Definitions of ROHC compression structures
 */


/**
 * @brief Information on ROHC feedback data
 */
struct rohc_feedback
{
	/** The feedback data */
	unsigned char *data;
	/** The length (in bytes) of the feedback data */
	size_t length;
	/** Whether the feedback data was locked during packet build? */
	bool is_locked;
};


/**
 * @brief The ROHC compressor
 */
struct rohc_comp
{
	/**
	 * @brief Whether the compressor is enabled or not
	 *
	 * The compressor is enabled by default and may be disabled by user.
	 */
	int enabled;

	/** The medium associated with the decompressor */
	struct medium medium;

	/** The array of compression contexts that use the compressor */
	struct c_context *contexts;
	/** The number of compression contexts stored in the array */
	int num_contexts;
	/** The number of compression contexts in use in the array */
	int num_contexts_used;

	/**
	 * @brief Which profiles are enabled and with one are not?
	 *
	 * A value of 1 means that profile is enabled, 0 means disabled.
	 */
	int profiles[C_NUM_PROFILES];


	/* CRC-related variables: */

	/** The table to enable fast CRC-2 computation */
	unsigned char crc_table_2[256];
	/** The table to enable fast CRC-3 computation */
	unsigned char crc_table_3[256];
	/** The table to enable fast CRC-6 computation */
	unsigned char crc_table_6[256];
	/** The table to enable fast CRC-7 computation */
	unsigned char crc_table_7[256];
	/** The table to enable fast CRC-8 computation */
	unsigned char crc_table_8[256];


	/* feedback-related variables: */

	/** The ring of outgoing feedbacks */
	struct rohc_feedback feedbacks[FEEDBACK_RING_SIZE];
	/** The index of the oldest feedback in the feedback ring */
	size_t feedbacks_first;
	/** The index of the oldest unlocked feedback in the feedback ring */
	size_t feedbacks_first_unlocked;
	/** @brief The index of the next empty location in the feedback ring */
	size_t feedbacks_next;


	/* some statistics about the compression process: */

	/** The number of sent packets */
	int num_packets;
	/** The size of all the received uncompressed IP packets */
	int total_uncompressed_size;
	/** The size of all the sent compressed ROHC packets */
	int total_compressed_size;

	/** The last context used by the compressor */
	struct c_context *last_context;


	/* user interaction variables: */

	/** Maximum Reconstructed Reception Unit (currently not used) */
	int mrru;
	/** Maximum header size that will be compressed (currently not used) */
	int max_header_size;
	/** The connection type (currently not used) */
	int connection_type;
	/** Whether to use jamming or not (option enabled/disabled by user) */
	int jam_use;
	/** The size (in bytes) of the adaptation packets */
	int adapt_size;
	/** The size (in bytes) of the encapsulation packets */
	int encap_size;
};


/**
 * @brief The ROHC compression profile
 *
 * The object defines a ROHC profile. Each field must be filled in
 * for each new profile.
 */
struct c_profile
{
	/**
	 * @brief The IP protocol ID used to find out which profile is able to
	 *        compress an IP packet
	 */
	const unsigned short protocol;

	/**
	 * @brief The UDP ports associated with this profile
	 *
	 * Only used with UDP as transport protocol. The pointer can be NULL if no
	 * port is specified. If defined, the list must be terminated by 0.
	 * example: { 5000, 5001, 0 }
	 */
	const int *ports;

	/** The profile ID as reserved by IANA */
	const unsigned short id;

	/** A string that describes the profile */
	const char *description;

	/**
	 * @brief The handler used to create the profile-specific part of the
	 *        compression context
	 */
	int (*create)(struct c_context *const context,
	              const struct ip_packet *packet);

	/**
	 * @brief The handler used to destroy the profile-specific part of the
	 *        compression context
	 */
	void (*destroy)(struct c_context *const context);

	/**
	 * @brief The handler used to check whether an uncompressed IP packet
	 *        belongs to a context or not
	 */
	int (*check_context)(const struct c_context *context,
	                     const struct ip_packet *packet);

	/**
	 * @brief The handler used to encode uncompressed IP packets
	 */
	int (*encode)(struct c_context *const context,
	              const struct ip_packet *packet,
	              const int packet_size,
	              unsigned char *const dest,
	              const int dest_size,
	              rohc_packet_t *const packet_type,
	              int *const payload_offset);

	/**
	 * @brief The handler used to warn the profile-specific part of the
	 *        context about the arrival of feedback data
	 */
	void (*feedback)(struct c_context *const context,
	                 const struct c_feedback *feedback);
};


/**
 * @brief The ROHC compression context
 */
struct c_context
{
	/** Whether the context is in use or not */
	int used;
	/** The time when the context was created */
	unsigned int latest_used;
	/** The time when the context was last used */
	unsigned int first_used;

	/** The context unique ID (CID) */
	int cid;

	/** The associated compressor */
	struct rohc_comp *compressor;

	/** The associated profile */
	const struct c_profile *profile;
	/** Profile-specific data, defined by the profiles */
	void *specific;

	/** The operation mode in which the context operates: U_MODE, O_MODE, R_MODE */
	rohc_mode mode;
	/** The operation state in which the context operates: IR, FO, SO */
	rohc_c_state state;

	/* below are some statistics */

	/* The type of ROHC packet created for the last compressed packet */
	rohc_packet_t packet_type;

	/** The average size of the uncompressed packets */
	int total_uncompressed_size;
	/** The average size of the compressed packets */
	int total_compressed_size;
	/** The average size of the uncompressed headers */
	int header_uncompressed_size;
	/** The average size of the compressed headers */
	int header_compressed_size; 

	/** The total size of the last uncompressed packet */
	int total_last_uncompressed_size;
	/** The total size of the last compressed packet */
	int total_last_compressed_size;
	/** The header size of the last uncompressed packet */
	int header_last_uncompressed_size;
	/** The header size of the last compressed packet */
	int header_last_compressed_size;

	/** The number of sent packets */
	int num_sent_packets;
	/** The number of sent IR packets */
	int num_sent_ir;
	/** The number of sent IR-DYN packets */
	int num_sent_ir_dyn;
	/** The number of received feedbacks */
	int num_recv_feedbacks;

	/** The size of the last 16 uncompressed packets */
	struct c_wlsb *total_16_uncompressed;
	/** The size of the last 16 compressed packets */
	struct c_wlsb *total_16_compressed;
	/** The size of the last 16 uncompressed headers */
	struct c_wlsb *header_16_uncompressed;
	/** The size of the last 16 compressed headers */
	struct c_wlsb *header_16_compressed;
};


/**
 * @brief The feedback packet
 */
struct c_feedback
{
	/** The Context ID to which the feedback packet is related */
	int cid;

	/**
	 * @brief The type of feedback packet
	 *
	 * A value of 1 means FEEDBACK-1, value 2 means FEEDBACK-2.
	 */
	int type;

	/** The feedback data (ie. the packet excluding the first type octet) */
	unsigned char *data;
	/** The size of the feedback data */
	unsigned char size;

	/**
	 * @brief The offset that indicates the beginning of the profile-specific
	 *        data in the feedback data
	 */
	int specific_offset;
	/** The size of the profile-specific data */
	int specific_size;

	/** The type of acknowledgement (FEEDBACK-2 only) */
	enum
	{
		/** The classical ACKnowledgement */
		ACK,
		/** The Negative ACKnowledgement */
		NACK,
		/** The Negative STATIC ACKnowledgement */
		STATIC_NACK,
		/** Currently unused acknowledgement type */
		RESERVED
	} acktype;
};

#endif

