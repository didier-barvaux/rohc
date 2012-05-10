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
 */

#ifndef COMP_LIST_H
#define COMP_LIST_H

#include <netinet/ip6.h>


/// Header version
typedef enum
{
	/// Hop by hop header
	HBH = 0,
	/// Destination header
	DEST = 60,
	/// Routing header
	RTHDR = 43,
	/// AH header
	AH = 51,
#if 0 /* CSRC lists not supported yet */
	/// CSRC
	CSRC = 10,
#endif
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

int create_list(struct c_list *list);
int add_elt(struct c_list *list, struct rohc_list_item *item, int index);
int push_back(struct c_list *list, struct rohc_list_item *item, int index);
void delete_elt(struct c_list *list, struct rohc_list_item *item);
struct list_elt * get_elt(struct c_list *list, int index);
int elt_index(struct c_list *list, struct rohc_list_item *item);
int type_is_present(struct c_list *list, struct rohc_list_item *item);
void destroy_list(struct c_list *list);
int insert_elt(struct c_list *list, struct rohc_list_item *item, int index, int index_table);
size_t size_list(const struct c_list *const list);
void empty_list(struct c_list *list);

#endif

