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
 * @file rohc_decomp.h
 * @brief ROHC decompression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 * @author David Moreau from TAS
 */

#ifndef DECOMP_H
#define DECOMP_H

#include "rohc.h"
#include "rohc_comp.h"


/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
	#define ROHC_EXPORT __declspec(dllexport)
#else
	#define ROHC_EXPORT
#endif


/*
 * Declare the private ROHC decompressor structure that is defined inside the
 * library.
 */

struct rohc_decomp;



/*
 * Public structures and types
 */

/**
 * @brief The ROHC decompressor states
 *
 * See 4.3.2 in the RFC 3095.
 *
 * @ingroup rohc_decomp
 */
typedef enum
{
	/// The No Context state
	NO_CONTEXT = 1,
	/// The Static Context state
	STATIC_CONTEXT = 2,
	/// The Full Context state
	FULL_CONTEXT = 3,
} rohc_d_state;


/**
 * @brief Some information about the last decompressed packet
 *
 * Versioning works as follow:
 *  - The 'version_major' field defines the compatibility level. If the major
 *    number given by user does not match the one expected by the library,
 *    an error is returned.
 *  - The 'version_minor' field defines the extension level. If the minor
 *    number given by user does not match the one expected by the library,
 *    only the fields supported in that minor version will be filled by
 *    \ref rohc_decomp_get_last_packet_info.
 *
 * Notes for developers:
 *  - Increase the major version if a field is removed.
 *  - Increase the major version if a field is added at the beginning or in
 *    the middle of the structure.
 *  - Increase the minor version if a field is added at the very end of the
 *    structure.
 *  - The version_major and version_minor fields must be located at the very
 *    beginning of the structure.
 *  - The structure must be packed.
 *
 * Supported versions:
 *  - Major = 0:
 *     - Minor = 0:
 *        version_major
 *        version_minor
 *        context_mode
 *        context_state
 *        profile_id
 *        nr_lost_packets
 *        nr_misordered_packets
 *        is_duplicated
 *
 * @ingroup rohc_decomp
 */
typedef struct
{
	/** The major version of this structure */
	unsigned short version_major;
	/** The minor version of this structure */
	unsigned short version_minor;
	/** The mode of the last context used by the compressor */
	rohc_mode context_mode;
	/** The state of the last context used by the compressor */
	rohc_d_state context_state;
	/** The profile ID of the last context used by the compressor */
	int profile_id;
	/** The number of (possible) lost packet(s) before last packet */
	unsigned long nr_lost_packets;
	/** The number of packet(s) before the last packet if late */
	unsigned long nr_misordered_packets;
	/** Is last packet a (possible) duplicated packet? */
	bool is_duplicated;
} __attribute__((packed)) rohc_decomp_last_packet_info_t;



/*
 * Functions related to decompressor:
 */

struct rohc_decomp * ROHC_EXPORT rohc_alloc_decompressor(struct rohc_comp *compressor);
void ROHC_EXPORT rohc_free_decompressor(struct rohc_decomp *decomp);

int ROHC_EXPORT rohc_decompress(struct rohc_decomp *decomp, unsigned char *ibuf, int isize,
                    unsigned char *obuf, int osize);
#if !defined(ENABLE_DEPRECATED_API) || ENABLE_DEPRECATED_API == 1
int ROHC_EXPORT rohc_decompress_both(struct rohc_decomp *decomp, unsigned char *ibuf,
                         int isize, unsigned char *obuf, int osize, int large)
	ROHC_DEPRECATED("please do not use this function anymore, use "
	                "rohc_decomp_set_cid_type() and rohc_decomp_set_max_cid() "
	                "instead");
#endif /* !defined(ENABLE_DEPRECATED_API) || ENABLE_DEPRECATED_API == 1 */


/*
 * Functions related to statistics:
 */

int ROHC_EXPORT rohc_d_statistics(struct rohc_decomp *decomp,
                                  unsigned int indent,
                                  char *buffer);

void ROHC_EXPORT clear_statistics(struct rohc_decomp *decomp);

const char * ROHC_EXPORT rohc_decomp_get_state_descr(const rohc_d_state state);

bool ROHC_EXPORT rohc_decomp_get_last_packet_info(const struct rohc_decomp *const decomp,
																  rohc_decomp_last_packet_info_t *const info)
	__attribute__((warn_unused_result));


/*
 * Functions related to user interaction:
 */

void ROHC_EXPORT user_interactions(struct rohc_decomp *decomp,
                                   int feedback_maxval);

bool ROHC_EXPORT rohc_decomp_set_cid_type(struct rohc_decomp *const decomp,
                                          const rohc_cid_type_t cid_type)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_set_max_cid(struct rohc_decomp *const decomp,
                                         const size_t max_cid)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_set_mrru(struct rohc_decomp *const decomp,
                                      const size_t mrru)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_set_traces_cb(struct rohc_decomp *const decomp,
                                           rohc_trace_callback_t callback)
	__attribute__((warn_unused_result));


#undef ROHC_EXPORT /* do not pollute outside this header */

#endif

