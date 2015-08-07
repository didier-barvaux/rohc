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
 * @file   schemes/decomp_list.h
 * @brief  ROHC generic list decompression
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_LIST_H
#define ROHC_DECOMP_LIST_H

#include "rohc_list.h"
#include "rohc_traces_internal.h"


/** Print a warning trace for the given decompression list */
#define rd_list_warn(decomp_list, format, ...) \
	rohc_warning(decomp_list, ROHC_TRACE_DECOMP, (decomp_list)->profile_id, \
	             format, ##__VA_ARGS__)

/** Print a debug trace for the given decompression list */
#define rd_list_debug(decomp_list, format, ...) \
	rohc_debug(decomp_list, ROHC_TRACE_DECOMP, (decomp_list)->profile_id, \
	           format, ##__VA_ARGS__)


/**
 * @brief The context for list decompression
 *
 * The context contains a translation table that associates IDs and list
 * items together. The different lists (gen_id ones, reference one, anonymous
 * one) references the items from the translation table.
 */
struct list_decomp
{
	/** The translation table */
	struct rohc_list_item trans_table[ROHC_LIST_MAX_ITEM];

	/** All the possible named lists, indexed by gen_id */
	struct rohc_list lists[ROHC_LIST_GEN_ID_MAX + 1];

	/** The temporary packet list (not persistent accross packets) */
	struct rohc_list pkt_list;


	/* Functions for handling the data to decompress */

	/** The handler used to check if the index corresponds to a valid item */
	bool (*check_item)(const struct list_decomp *const decomp,
	                   const size_t index_table);

	/** The handler used to get the size of a list item */
	int (*get_item_size)(const uint8_t *data, const size_t data_len);

	/** The handler used to compare two items */
	rohc_list_item_cmp cmp_item;

	/** The handler used to create a list item */
	bool (*create_item)(const uint8_t *const data,
	                    const size_t length,
	                    const size_t index_table,
	                    struct list_decomp *const decomp);

	/** The handler used to add the extension to IP packet */
	size_t (*build_uncomp_item)(const struct list_decomp *const decomp,
	                            const uint8_t ip_nh_type,
	                            uint8_t *const dest);


	/* Traces */

	/** The callback function used to manage traces */
	rohc_trace_callback2_t trace_callback;
	/** The private context of the callback function used to manage traces */
	void *trace_callback_priv;
	/** The profile ID the decompression list was created for */
	int profile_id;
};



/*
 * Generic list decompression
 */

int rohc_list_decode_maybe(struct list_decomp *const decomp,
                           const uint8_t *const packet,
                           const size_t packet_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

bool rohc_decomp_list_create_item(struct list_decomp *const decomp,
                                  const unsigned int xi_index,
                                  const unsigned int xi_index_value,
                                  const uint8_t *const rohc_packet,
                                  const size_t rohc_max_len,
                                  size_t *const item_length)
	__attribute__((warn_unused_result, nonnull(1, 4, 6)));

#endif

