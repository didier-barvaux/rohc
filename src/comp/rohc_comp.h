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
 * @file rohc_comp.h
 * @brief ROHC compression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef COMP_H
#define COMP_H

#include "rohc.h"
#include "rohc_packets.h"

#include <stdlib.h>
#include <stdbool.h>


/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
	#define ROHC_EXPORT __declspec(dllexport)
#else
	#define ROHC_EXPORT 
#endif


/*
 * Declare the private ROHC compressor structure that is defined inside the
 * library.
 */

struct rohc_comp;


/*
 * Public structures and types
 */


/**
 * @brief The different ROHC compressor states
 *
 * See 4.3.1 in the RFC 3095.
 *
 * If you add a new compressor state, please also add the corresponding
 * textual description in \ref rohc_comp_get_state_descr.
 */
typedef enum
{
	/** The Initialization and Refresh (IR) state */
	IR = 1,
	/** The First Order (FO) state */
	FO = 2,
	/** The Second Order (SO) state */
	SO = 3,
} rohc_c_state;


/** Some information about the last compressed packet */
typedef struct
{
	/** The mode of the last context used by the compressor */
	rohc_mode context_mode;
	/** The state of the last context used by the compressor */
	rohc_c_state context_state;
	/** The type of ROHC packet created for the last compressed packet */
	rohc_packet_t packet_type;
	/** The uncompressed size (in bytes) of the last compressed packet */
	unsigned long total_last_uncomp_size;
	/** The uncompressed size (in bytes) of the last compressed header */
	unsigned long header_last_uncomp_size;
	/** The compressed size (in bytes) of the last compressed packet */
	unsigned long total_last_comp_size;
	/** The compressed size (in bytes) of the last compressed header */
	unsigned long header_last_comp_size;
} rohc_comp_last_packet_info_t;


/** The prototype of the callback for random numbers */
typedef int (*rohc_comp_random_cb_t) (const struct rohc_comp *const comp,
                                      void *const user_context)
	__attribute__((nonnull(1)));


/*
 * Prototypes of main public functions related to ROHC compression
 */

struct rohc_comp * ROHC_EXPORT rohc_alloc_compressor(int max_cid,
																	  int jam_use,
																	  int adapt_size,
																	  int encap_size);
void ROHC_EXPORT rohc_free_compressor(struct rohc_comp *comp);

bool ROHC_EXPORT rohc_comp_set_random_cb(struct rohc_comp *const comp,
                                         rohc_comp_random_cb_t callback,
                                         void *const user_context)
	__attribute__((nonnull(1, 2)));

int ROHC_EXPORT rohc_compress(struct rohc_comp *comp,
                              unsigned char *ibuf,
                              int isize,
                              unsigned char *obuf,
                              int osize);


/*
 * Prototypes of public functions related to user interaction
 */

int ROHC_EXPORT rohc_c_is_enabled(struct rohc_comp *comp);
int ROHC_EXPORT rohc_c_using_small_cid(struct rohc_comp *comp);

void ROHC_EXPORT rohc_activate_profile(struct rohc_comp *comp, int profile);

void ROHC_EXPORT rohc_c_set_header(struct rohc_comp *compressor, int value);
void ROHC_EXPORT rohc_c_set_mrru(struct rohc_comp *compressor, int value);
void ROHC_EXPORT rohc_c_set_max_cid(struct rohc_comp *compressor, int value);
void ROHC_EXPORT rohc_c_set_large_cid(struct rohc_comp *compressor, int value);
void ROHC_EXPORT rohc_c_set_enable(struct rohc_comp *compressor, int value);


/*
 * Prototypes of public functions related to ROHC feedback
 */

void ROHC_EXPORT c_piggyback_feedback(struct rohc_comp *comp,
                                      unsigned char *packet,
                                      int size);
void ROHC_EXPORT c_deliver_feedback(struct rohc_comp *comp,
                                    unsigned char *feedback,
                                    int size);
int ROHC_EXPORT rohc_feedback_flush(struct rohc_comp *comp,
                                    unsigned char *obuf,
                                    int osize);

/* Configure robustness to packet loss/damage */
bool rohc_comp_set_wlsb_window_width(struct rohc_comp *const comp,
                                     const size_t width)
	__attribute__((nonnull(1), warn_unused_result));
bool rohc_comp_set_periodic_refreshes(struct rohc_comp *const comp,
                                      const size_t ir_timeout,
                                      const size_t fo_timeout)
	__attribute__((nonnull(1), warn_unused_result));

/*
 * Prototypes of public functions related to ROHC compression statistics
 */

int ROHC_EXPORT rohc_c_info(char *buffer);
int ROHC_EXPORT rohc_c_statistics(struct rohc_comp *comp,
                                  unsigned int indent,
                                  char *buffer);
int ROHC_EXPORT rohc_c_context(struct rohc_comp *comp,
                               int cid,
                               unsigned int indent,
                               char *buffer);
int ROHC_EXPORT rohc_comp_get_last_packet_info(const struct rohc_comp *const comp,
                                               rohc_comp_last_packet_info_t *const info);
const char * ROHC_EXPORT rohc_comp_get_state_descr(const rohc_c_state state);


#undef ROHC_EXPORT /* do not pollute outside this header */

#endif

