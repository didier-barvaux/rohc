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

	/* All the possible named lists, indexed by gen_id */
	struct rohc_list lists[ROHC_LIST_GEN_ID_MAX + 2];

	/** The ID of the reference list */
	unsigned int ref_id;
	/** The ID of the current list */
	unsigned int cur_id; /* TODO: should not be overwritten until compression
	                              is fully OK */

	/** The number of uncompressed transmissions for list compression (L) */
	size_t list_trans_nr;

	/* Functions for handling the data to compress */

	/// @brief the handler used to get the index of an item
	int (*get_index_table)(const uint8_t type, const size_t occur_nr)
		__attribute__((warn_unused_result, const));

	/// @brief the handler used to get the size of an item
	unsigned short (*get_size)(const unsigned char *ext);

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


bool detect_ipv6_ext_changes(struct list_comp *const comp,
                             const struct ip_packet *const ip,
                             bool *const list_struct_changed,
                             bool *const list_content_changed)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

int rohc_list_encode(struct list_comp *const comp,
                     unsigned char *const dest,
                     int counter)
	__attribute__((warn_unused_result, nonnull(1, 2)));

void rohc_list_update_context(struct list_comp *const comp)
	__attribute__((nonnull(1)));

#endif

