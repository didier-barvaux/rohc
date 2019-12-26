/*
 * Copyright 2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file   schemes/comp_list.h
 * @brief  ROHC generic list compression
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_COMP_LIST_H
#define ROHC_COMP_LIST_H

#include "ip.h"
#include "rohc_list.h"
#include "rohc_traces_internal.h"
#include "rohc_comp_internals.h"

/** Print a debug trace for the given compression list */
#define rc_list_debug(comp_list, format, ...) \
	rohc_debug(comp_list, ROHC_TRACE_COMP, (comp_list)->profile_id, \
	           format, ##__VA_ARGS__)


/**
 * @brief The list compressor
 */
struct list_comp
{
	/** The translation table */
	struct rohc_list_item trans_table[ROHC_LIST_MAX_ITEM];
	/** The extension data referenced by the translation table */
	uint8_t trans_table_data[ROHC_LIST_MAX_ITEM][ROHC_LIST_ITEM_DATA_MAX];

	/* All the possible named lists, indexed by gen_id */
	struct rohc_list lists[ROHC_LIST_GEN_ID_MAX + 2];

	/** The ID of the reference list */
	unsigned int ref_id;
	/** The ID of the current list */
	unsigned int cur_id; /* TODO: should not be overwritten until compression
	                              is fully OK */

	/** The number of uncompressed transmissions for list compression (L) */
	uint8_t oa_repetitions_nr;

	/* Functions for handling the data to compress */

	/// @brief the handler used to get the index of an item
	int (*get_index_table)(const uint8_t type, const size_t occur_nr)
		__attribute__((warn_unused_result, const));

	/** The handler used to compare two items */
	rohc_list_item_cmp cmp_item;

	/* Traces */

	/** The callback function used to manage traces */
	rohc_trace_callback2_t trace_callback;
	/** The private context of the callback function used to manage traces */
	void *trace_callback_priv;
	/** The profile ID the compression list was created for */
	int profile_id;
};


/** The changes of all the extension headers of one IP header */
struct rohc_list_changes
{
	/** The translation table for list compression of IP extensions */
	struct rohc_list_item trans_table[ROHC_LIST_MAX_ITEM];
	/** The new temporary list of extension headers */
	struct rohc_list pkt_list;
	/** Whether the temporary list of extension headers is a new list? */
	bool is_new_list;
	uint8_t unused[7];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct rohc_list_changes, is_new_list) % 8) == 0,
               "is_new_list in rohc_list_changes should be aligned on 8 bytes");
_Static_assert((sizeof(struct rohc_list_changes) % 8) == 0,
               "rohc_list_changes length should be multiple of 8 bytes");
#endif


void detect_ipv6_ext_changes(const struct list_comp *const comp,
                             const struct rohc_pkt_ip_hdr *const ip_hdr,
                             struct rohc_list_changes *const exts_changes,
                             bool *const list_struct_changed,
                             bool *const list_content_changed)
	__attribute__((nonnull(1, 2, 3, 4, 5)));

int rohc_list_encode(const struct list_comp *const comp,
                     const struct rohc_list *const pkt_list,
                     uint8_t *const dest,
                     int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

void rohc_list_update_context(struct list_comp *const comp,
                              const struct rohc_list_changes *const exts_changes)
	__attribute__((nonnull(1, 2)));

#endif

