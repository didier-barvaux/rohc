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
 * @file ts_sc_comp.h
 * @brief Scaled RTP Timestamp encoding
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 *
 * See section 4.5.3 of RFC 3095 for details about Scaled RTP Timestamp
 * encoding.
 */

#ifndef TS_SC_COMP_H
#define TS_SC_COMP_H

#include "rohc.h"


/**
 * @brief State of scaled RTP Timestamp encoding
 *
 * See section 4.5.3 of RFC 3095 for details about Scaled RTP Timestamp
 * encoding.
 */
typedef enum
{
	/// Initialization state (TS_STRIDE value not yet computed)
	INIT_TS = 1,
	/// Initialization state (TS_STRIDE value computed and sent)
	INIT_STRIDE = 2,
	/// Compression state (TS_SCALED value computed and sent)
	SEND_SCALED = 3,
} ts_sc_state;


/**
 * @brief Scaled RTP Timestamp encoding object
 *
 * See section 4.5.3 of RFC 3095 for details about Scaled RTP Timestamp
 * encoding.
 */
struct ts_sc_comp
{
	/// The TS_STRIDE value
	int ts_stride;

	/// The TS_SCALED value
	int ts_scaled;
	/// A window used to encode the TS_SCALED value
	struct c_wlsb *scaled_window;

	/// The TS_OFFSET value
	int ts_offset;

	/// The timestamp (TS)
	unsigned int ts;
	/// The previous timestamp
	unsigned int old_ts;

	/// The sequence number (SN)
	unsigned int sn;
	/// The previous sequence number
	unsigned int old_sn;

	/// Whether timestamp is deductible from SN or not
	int is_deductible;

	/// The state of the scaled RTP Timestamp encoding object
	ts_sc_state state;

	/// The difference between old and current TS
	int ts_delta;
};



/*
 * Function prototypes
 */

int c_create_sc(struct ts_sc_comp *ts_sc);
void c_destroy_sc(struct ts_sc_comp *ts_sc);

void c_add_ts(struct ts_sc_comp *ts_sc, unsigned int ts, unsigned int sn);

int nb_bits_stride(struct ts_sc_comp ts_sc);
int nb_bits_scaled(struct ts_sc_comp ts_sc);

void add_stride(struct ts_sc_comp *ts_sc, int sn);
void add_scaled(struct ts_sc_comp *ts_sc, int sn);

int get_ts_stride(struct ts_sc_comp ts_sc);
int get_ts_scaled(struct ts_sc_comp ts_sc);
int get_ts_offset(struct ts_sc_comp ts_sc);

int is_deductible(struct ts_sc_comp ts_sc);
int is_ts_constant(struct ts_sc_comp ts_sc);


#endif

