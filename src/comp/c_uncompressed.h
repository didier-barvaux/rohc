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
 * @file c_uncompressed.h
 * @brief ROHC compression context for the uncompressed profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef C_UNCOMPRESSED_H
#define C_UNCOMPRESSED_H

#include "rohc_comp_internals.h"


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

void uncompressed_decide_state(struct c_context *const context);

void uncompressed_periodic_down_transition(struct c_context *const context);

void uncompressed_change_mode(struct c_context *const context,
                              const rohc_mode new_mode);

void uncompressed_change_state(struct c_context *const const,
                               const rohc_c_state new_state);

int uncompressed_code_packet(const struct c_context *context,
                             const struct ip_packet *ip,
                             unsigned char *const dest,
                             int *const payload_offset,
                             const int dest_size);

int uncompressed_code_IR_packet(const struct c_context *context,
                                const struct ip_packet *ip,
                                unsigned char *const dest,
                                int *const payload_offset,
                                const int dest_size);

int uncompressed_code_normal_packet(const struct c_context *context,
                                    const struct ip_packet *ip,
                                    unsigned char *const dest,
                                    int *const payload_offset,
                                    const int dest_size);


#endif

