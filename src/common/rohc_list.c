/*
 * Copyright 2010,2012,2013,2014 Didier Barvaux
 * Copyright 2008,2010,2012 Viveris Technologies
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
 * @file   rohc_list.c
 * @brief  Define list compression with its function
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_list.h"

#include <stdlib.h>
#ifndef __KERNEL__
#  include <string.h>
#endif
#include <assert.h>


static bool rohc_list_item_update(struct rohc_list_item *const list_item,
                                  const uint8_t item_type,
                                  const uint8_t *const item_data,
                                  const size_t item_len)
	__attribute__((warn_unused_result, nonnull(1, 3)));


/**
 * @brief Reset the state of the given compressed list
 *
 * @param list  The list to reset
 */
void rohc_list_reset(struct rohc_list *const list)
{
	assert(list != NULL);
	list->id = ROHC_LIST_GEN_ID_NONE;
	list->items_nr = 0;
	list->counter = 0;
	memset(list->items, 0,
	       ROHC_LIST_ITEMS_MAX * sizeof(struct rohc_list_item *));
}


/**
 * @brief Are the two given lists equal?
 *
 * We compare only the list structure, not the list content. Two lists with
 * the same items in the same order, but with different content, are
 * considered equals.
 *
 * @param list1  The first list to compare
 * @param list2  The other list to compare
 * @return       true if the two lists are equal, false if they aren't
 */
bool rohc_list_equal(const struct rohc_list *const list1,
                     const struct rohc_list *const list2)
{
	return (list1->items_nr == list2->items_nr &&
	        memcmp(list1->items, list2->items,
	               list1->items_nr * sizeof(struct rohc_list_item *)) == 0);
}


/**
 * @brief Does the first list contains the second list?
 *
 * We compare only the list structure, not the list content. A list supersedes
 * another list if all the items of the second list are present in the first
 * list in the same order.
 *
 * @param large  The large list that should supersedes the small list
 * @param small  The small list that should be superseded by the large list
 * @return       true if the large list supersedes the small list
 */
bool rohc_list_supersede(const struct rohc_list *const large,
                         const struct rohc_list *const small)
{
	bool are_all_items_present = true;
	size_t i; /* index for the large list */
	size_t j; /* index for the small list */

	assert(large->items_nr >= small->items_nr);

	for(i = 0, j = 0;
	    are_all_items_present && i < large->items_nr && j < small->items_nr;
	    j++)
	{
		/* search for the item from the small list in the remaining items of
		 * the large list */
		while(i < large->items_nr && large->items[i] != small->items[j])
		{
			i++;
		}
		if(i >= large->items_nr)
		{
			are_all_items_present = false;
		}
	}

	return are_all_items_present;
}


/**
 * @brief Reset the given list item
 *
 * @param list_item  The item to reset
 */
void rohc_list_item_reset(struct rohc_list_item *const list_item)
{
	assert(list_item != NULL);

	/* item is not transmitted nor known yet */
	list_item->known = false;
	list_item->counter = 0;

	/* no data yet */
	list_item->length = 0;
}


/**
 * @brief Update the content of the given compressed item if it changed
 *
 * @param cmp_item   The callback function to compare two items
 * @param list_item  The item to update
 * @param item_type  The type of the item to update
 * @param item_data  The data to update item with
 * @param item_len   The data length (in bytes)
 * @return           0  if the item doesn't need to be updated,
 *                   1  if the update was successful,
 *                   -1 if a problem occurred
 */
int rohc_list_item_update_if_changed(rohc_list_item_cmp cmp_item,
                                     struct rohc_list_item *const list_item,
                                     const uint8_t item_type,
                                     const uint8_t *const item_data,
                                     const size_t item_len)
{
	int status;

	assert(list_item != NULL);

	if(!cmp_item(list_item, item_type, item_data, item_len))
	{
		if(rohc_list_item_update(list_item, item_type, item_data, item_len))
		{
			status = 1;
		}
		else
		{
			status = -1;
		}
	}
	else
	{
		status = 0;
	}

	return status;
}


/**
 * @brief Update the content the given compressed item
 *
 * @param list_item  The item to update
 * @param item_type  The type of the item to update
 * @param item_data  The data to update item with
 * @param item_len   The data length (in bytes)
 * @return           true if the update was successful, false otherwise
 */
static bool rohc_list_item_update(struct rohc_list_item *const list_item,
                                  const uint8_t item_type,
                                  const uint8_t *const item_data,
                                  const size_t item_len)
{
	assert(list_item != NULL);

	rohc_list_item_reset(list_item);

	/* record new data for the item */
	if(item_len > ROHC_LIST_ITEM_DATA_MAX)
	{
		return false;
	}
	memcpy(list_item->data, item_data, item_len);
	list_item->length = item_len;
	list_item->type = item_type;

	return true;
}

