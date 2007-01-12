/**
 * @file c_uncompressed.h
 * @brief ROHC compression context for the uncompressed profile.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef C_UNCOMPRESSED_H
#define C_UNCOMPRESSED_H

#include "rohc_comp.h"


/**
 * @brief The Uncompressed context
 *
 * The object defines the Uncompressed context that manages all kinds of
 * packets and headers.
 */
struct sc_uncompressed_context
{
	/// The number of IR packets sent by the compressor
	int ir_count;
	/// The number of Normal packets sent by the compressor
	int normal_count;
	/// @brief The number of packet sent while in non-IR states, used for the
	///        periodic refreshes of the context
	/// @see uncompressed_periodic_down_transition
	int go_back_ir_count;
};


/*
 * Function prototypes.
 */

void uncompressed_decide_state(struct c_context *context);

void uncompressed_periodic_down_transition(struct c_context *context);

void uncompressed_change_mode(struct c_context *c, rohc_mode new_mode);

void uncompressed_change_state(struct c_context *c, rohc_c_state new_state);

int uncompressed_code_packet(struct c_context *context,
                             const struct iphdr *ip,
                             unsigned char *dest,
                             int *payload_offset,
                             int dest_size);

int uncompressed_code_IR_packet(struct c_context *context,
                                const struct iphdr *ip,
                                unsigned char *dest,
                                int *payload_offset,
                                int dest_size);

int uncompressed_code_normal_packet(struct c_context *context,
                                    const struct iphdr *ip,
                                    unsigned char *dest,
                                    int *payload_offset,
                                    int dest_size);


#endif

