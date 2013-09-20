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
 * @file comp_list.c
 * @brief Define list compression with its function
 * @author Emmanuelle Pechereau <epechereau@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "comp_list.h"

#include <stdlib.h>
#include <assert.h>


/**
 * @brief Create one compression_list
 *
 * @return  The list created
 */
struct c_list * list_create(void)
{
	struct c_list *list;

	list = malloc(sizeof(struct c_list));
	if(list != NULL)
	{
		list->gen_id = 0;
		list->first_elt = NULL;
	}

	return list;
}


/**
 * @brief Destroy the list
 *
 * @param list  the list to destroy
 */
void list_destroy(struct c_list *list)
{
	struct list_elt *curr_elt;
	struct list_elt *next_elt;

	assert(list != NULL);

	for(curr_elt = list->first_elt; curr_elt != NULL; curr_elt = next_elt)
	{
		next_elt = curr_elt->next_elt;
		free(curr_elt);
	}

	free(list);
}


/**
 * @brief Add an element at the beginning of the list
 *
 * @param list         The list where the element is added
 * @param item         The item of the new element
 * @param index_table  The index of the item in based table (may be -1)
 * @return             true if successful, false otherwise
 */
bool list_add_at_beginning(struct c_list *const list,
                           const struct rohc_list_item *const item,
                           const int index_table)
{
	struct list_elt *elt;

	assert(list != NULL);
	assert(item != NULL);

	elt = malloc(sizeof(struct list_elt));
	if(elt == NULL)
	{
		goto error;
	}

	elt->item = item;
	elt->index_table = index_table;
	elt->next_elt = NULL;
	elt->prev_elt = NULL;

	if(list->first_elt == NULL)
	{
		list->first_elt = elt;
	}
	else
	{
		elt->next_elt = list->first_elt;
		list->first_elt->prev_elt = elt;
		list->first_elt = elt;
	}

	return true;

error:
	return false;
}


/**
 * @brief Add an element at the end of the list
 *
 * @param list         The list where the element is added
 * @param item         The item of the new element
 * @param index_table  The index of the item in based table (may be -1)
 * @return             true if successful, false otherwise
 */
bool list_add_at_end(struct c_list *const list,
                     const struct rohc_list_item *const item,
                     const int index_table)
{
	bool is_success = false;
	struct list_elt *elt;
	struct list_elt *curr_elt;

	assert(list != NULL);
	assert(item != NULL);

	if(list->first_elt == NULL)
	{
		is_success = list_add_at_beginning(list, item, index_table);
	}
	else
	{
		elt = malloc(sizeof(struct list_elt));
		if(elt == NULL)
		{
			goto error;
		}

		elt->item = item;
		elt->index_table = index_table;
		elt->next_elt = NULL;
		elt->prev_elt = NULL;

		curr_elt = list->first_elt;
		while(curr_elt->next_elt != NULL)
		{
			curr_elt = curr_elt->next_elt;
		}
		curr_elt->next_elt = elt;
		elt->prev_elt = curr_elt;
		is_success = true;
	}

error:
	return is_success;
}


/**
 * @brief Insert an element at the specified position
 *
 * @param list         The list in which the element is inserted
 * @param item         The element to insert
 * @param pos          The position
 * @param index_table  The index in based_table (may be -1)
 * @return             true if successful, false otherwise
 */
bool list_add_at_index(struct c_list *const list,
                       const struct rohc_list_item *const item,
                       const size_t pos,
                       const int index_table)
{
	size_t size_l;

	assert(list != NULL);
	assert(item != NULL);

	size_l = list_get_size(list);
	if(pos > size_l)
	{
		goto error;
	}

	if(pos == 0)
	{
		/* special case for first element */
		if(!list_add_at_beginning(list, item, index_table))
		{
			goto error;
		}
	}
	else
	{
		struct list_elt *elt;
		struct list_elt *curr_elt;
		size_t i;

		/* create a new element */
		elt = malloc(sizeof(struct list_elt));
		if(elt == NULL)
		{
			goto error;
		}
		elt->item = item;
		elt->next_elt = NULL;
		elt->prev_elt = NULL;
		elt->index_table = index_table;

		/* loop on list elements towards the given position */
		curr_elt = list->first_elt;
		for(i = 0; i < pos; i++)
		{
			if(curr_elt->next_elt != NULL)
			{
				curr_elt = curr_elt->next_elt;
			}
		}

		/* insert new element before current element */
		if(pos == size_l)
		{
			/* insert at the very end of the list */
			curr_elt->next_elt = elt;
			elt->prev_elt = curr_elt;
		}
		else
		{
			/* insert in the middle of the list */
			elt->next_elt = curr_elt;
			elt->prev_elt = curr_elt->prev_elt;
			curr_elt->prev_elt = elt;
			if(elt->prev_elt != NULL)
			{
				elt->prev_elt->next_elt = elt;
			}
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Get the element at the specified position
 *
 * @param list  The list where is the element
 * @param pos   The specified position
 * @return      The item in case of success,
 *              NULL if there is no element at this position
 */
struct list_elt * list_get_elt_by_index(const struct c_list *const list,
                                        const size_t pos)
{
	struct list_elt *curr_elt;
	size_t i;

	assert(list != NULL);

	if(pos >= list_get_size(list))
	{
		goto error;
	}

	i = 0;
	curr_elt = list->first_elt;
	while(i < pos)
	{
		curr_elt = curr_elt->next_elt;
		i++;
	}

	return curr_elt;

error:
	return NULL;
}


/**
 * @brief Get the index of the specified element in the list
 *
 * @param list  the list where is the element
 * @param item  the specified element
 * @return      the index, -1 if the element is not in the list
 */
int list_get_index_by_elt(const struct c_list *const list,
                          const struct rohc_list_item *const item)
{
	struct list_elt *curr_elt;
	size_t i;

	assert(list != NULL);
	assert(item != NULL);

	if(list->first_elt == NULL)
	{
		goto end;
	}

	curr_elt = list->first_elt;
	i = 0;
	while(curr_elt != NULL && curr_elt->item != item)
	{
		curr_elt = curr_elt->next_elt;
		i++;
	}

	if(curr_elt == NULL)
	{
		goto end;
	}

	return i;

end:
	return -1;
}


/**
 * @brief Delete the specified element of the list
 *
 * @param list  the list where the element is destroyed
 * @param item  the element to delete
 */
void list_remove(struct c_list *const list,
                 const struct rohc_list_item *const item)
{
	struct list_elt *curr_elt;

	assert(list != NULL);
	assert(item != NULL);

	if(list->first_elt == NULL)
	{
		/* empty list, element to remove not found */
		return;
	}

	curr_elt = list->first_elt;
	while(curr_elt != NULL && curr_elt->item != item)
	{
		curr_elt = curr_elt->next_elt;
	}
	if(curr_elt == NULL)
	{
		/* element to remove not found */
		return;
	}

	/* element to remove found, update previous element if any */
	if(curr_elt->prev_elt != NULL)
	{
		curr_elt->prev_elt->next_elt = curr_elt->next_elt;
	}
	else
	{
		list->first_elt = curr_elt->next_elt;
	}

	/* update next element if any */
	if(curr_elt->next_elt != NULL)
	{
		curr_elt->next_elt->prev_elt = curr_elt->prev_elt;
	}

	/* destroy element to remove*/
	free(curr_elt);
}


/**
 * @brief Empty the list
 *
 * @param list the list to empty
 */
void rohc_list_empty(struct c_list *const list)
{
	struct list_elt *curr_elt;

	assert(list != NULL);

	if(list->first_elt != NULL)
	{
		curr_elt = list->first_elt;
		while(curr_elt->next_elt != NULL)
		{
			list->first_elt = curr_elt->next_elt;
			curr_elt->next_elt->prev_elt = NULL;
			free(curr_elt);
			curr_elt = list->first_elt;
		}
		free(list->first_elt);
	}
	list->first_elt = NULL;
}


/**
 * @brief Indicate if the type of the specified element is present
 *
 * @param list  the list where is the element
 * @param item  the specified element
 * @return      true if present, false if not
 */
bool list_type_is_present(const struct c_list *const list,
                          const struct rohc_list_item *const item)
{
	struct list_elt *curr_elt;

	assert(list != NULL);
	assert(item != NULL);

	if(list->first_elt == NULL)
	{
		goto end;
	}

	curr_elt = list->first_elt;
	while(curr_elt != NULL && curr_elt->item->type != item->type)
	{
		curr_elt = curr_elt->next_elt;
	}
	if(curr_elt == NULL)
	{
		goto end;
	}

	return true;

end:
	return false;
}


/**
 * @brief Get the size of the given list
 *
 * @param list  The list
 * @return      The size of the list
 */
size_t list_get_size(const struct c_list *const list)
{
	struct list_elt *curr_elt;
	size_t size = 0;

	assert(list != NULL);

	for(curr_elt = list->first_elt; curr_elt != NULL; curr_elt = curr_elt->next_elt)
	{
		size++;
	}

	return size;
}

