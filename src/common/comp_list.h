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
 * @file comp_list.h
 * @brief Define list compression with its function
 * @author Emmanuelle Pechereau <epechereau@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef COMP_LIST_H
#define COMP_LIST_H

#include "dllexport.h"
#include "protocols/ipv6.h"
#include "protocols/ip_numbers.h"

#include <stdlib.h>


/** Print a debug trace for the given compression list */
#define rohc_list_debug(comp_list, format, ...) \
	rohc_debug(comp_list, ROHC_TRACE_COMP, (comp_list)->profile_id, \
	           format, ##__VA_ARGS__)


/// Header version
typedef enum
{
	HBH    = ROHC_IPPROTO_HOPOPTS,  /**< Hop by hop header */
	RTHDR  = ROHC_IPPROTO_ROUTING,  /**< Routing header */
	AH     = ROHC_IPPROTO_AH,       /**< AH header */
	DEST   = ROHC_IPPROTO_DSTOPTS,  /**< Destination header */
	/* CSRC lists not supported yet */
} ext_header_version;


/**
 * @brief A list item
 */
struct rohc_list_item
{
	/// item type
	ext_header_version type;
	/// size of the data in bytes
	size_t length;
	/// item data
	unsigned char *data;
};


/**
 * @brief Define a generic element in a compression list
 */
struct list_elt
{
	/// element
	struct rohc_list_item *item;
	/// index
	int index_table;
	/// next element of the list
	struct list_elt *next_elt;
	/// previous element
	struct list_elt *prev_elt;
};


/**
 * @brief Define a list for compression
 */
struct c_list
{
	///generation identifier
	int gen_id;
	/// first element of the list
	struct list_elt *first_elt;
};


/**
 * @brief Define a compression translation table element
 */
struct c_translation
{
	/// flag which indicates the mapping between an item with its index
	/// 1 if the mapping is established, 0 if not
	int known;
	/// item
	struct rohc_list_item *item;
	/// counter
	int counter;
};


/**
 * @brief Define a decompression translation table element
 */
struct d_translation
{
	/// flag which indicates the mapping between an item with its index
	/// 1 if the mapping is established, 0 if not
	int known;
	/// item
	struct rohc_list_item *item;
};


/**
 * Functions prototypes
 */

/* create, destroy list */
int ROHC_EXPORT list_create(struct c_list *list);
void ROHC_EXPORT list_destroy(struct c_list *list);

/* add elements */
int ROHC_EXPORT list_add_at_beginning(struct c_list *list,
                          struct rohc_list_item *item,
                          int index);
int ROHC_EXPORT list_add_at_end(struct c_list *list,
                    struct rohc_list_item *item,
                    int index);
int ROHC_EXPORT list_add_at_index(struct c_list *list,
                      struct rohc_list_item *item,
                      int index,
                      int index_table);

/* get an element from its position or the position from the element */
struct list_elt * ROHC_EXPORT list_get_elt_by_index(struct c_list *list,
																	 int index);
int ROHC_EXPORT list_get_index_by_elt(struct c_list *list,
                                      struct rohc_list_item *item);

/* remove an element or empty the list */
void ROHC_EXPORT list_remove(struct c_list *list,
                             struct rohc_list_item *item);
void ROHC_EXPORT list_empty(struct c_list *list);

/* retrieve information about an element of the list */
int ROHC_EXPORT list_type_is_present(struct c_list *list,
                                     struct rohc_list_item *item);

/* get the size of the list */
size_t ROHC_EXPORT list_get_size(const struct c_list *const list);

#endif

