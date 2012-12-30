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
 * @return  1 if successful, 0 otherwise
 */
int list_create(struct c_list *list)
{
	list = malloc(sizeof(struct c_list));
	if(list == NULL)
	{
		goto error;
	}

	list->gen_id = 0;
	list->first_elt = NULL;

	return 1;

error:
	return 0;
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
 * @param list   the list where the element is added
 * @param item   the item of the new element
 * @param index  the index in based table
 * @return       1 if successful, 0 otherwise
 */
int list_add_at_beginning(struct c_list *list,
                          struct rohc_list_item *item,
                          int index)
{
	struct list_elt *elt;

	elt = malloc(sizeof(struct list_elt));
	if(elt == NULL)
	{
		goto error;
	}

	elt->item = item;
	elt->index_table = index;
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
	return 1;

error:
	return 0;
}


/**
 * @brief Add an element at the end of the list
 *
 * @param list   the list where the element is added
 * @param item   the item of the new element
 * @param index  the index in based table
 * @return       1 if successful, 0 otherwise
 */
int list_add_at_end(struct c_list *list,
                    struct rohc_list_item *item,
                    int index)
{
	struct list_elt *elt;
	int result = 0;
	struct list_elt *curr_elt;

	if(list->first_elt == NULL)
	{
		result = list_add_at_beginning(list, item, index);
	}
	else
	{
		elt = malloc(sizeof(struct list_elt));
		if(elt == NULL)
		{
			goto error;
		}

		elt->item = item;
		elt->index_table = index;
		elt->next_elt = NULL;
		elt->prev_elt = NULL;

		curr_elt = list->first_elt;
		while(curr_elt->next_elt != NULL)
		{
			curr_elt = curr_elt->next_elt;
		}
		curr_elt->next_elt = elt;
		elt->prev_elt = curr_elt;
		result = 1;
	}
	return result;

error:
	return 0;
}


/**
 * @brief Insert an element at the specified position
 *
 * @param list         The list in which the element is inserted
 * @param item         The element to insert
 * @param index        The position
 * @param index_table  The index in based_table
 * @return             1 if successful, 0 otherwise
 */
int list_add_at_index(struct c_list *list,
                      struct rohc_list_item *item,
                      int index,
                      int index_table)
{
	int i;
	int size_l = list_get_size(list);

	if(index > size_l)
	{
		goto error;
	}

	if(index == 0)
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

		/* loop on list elements towards the given index */
		curr_elt = list->first_elt;
		for(i = 0; i < index; i++)
		{
			if(curr_elt->next_elt != NULL)
			{
				curr_elt = curr_elt->next_elt;
			}
		}

		/* insert new element before current element */
		if(index == size_l)
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

	return 1;

error:
	return 0;
}


/**
 * @brief Get the element at the specified index
 *
 * @param list   the list where is the element
 * @param index  the specified index
 * @return       item, NULL if there is no element at this index
 */
struct list_elt * list_get_elt_by_index(struct c_list *list, int index)
{
	struct list_elt *curr_elt = list->first_elt;
	int i = 0;
	if(index >= list_get_size(list))
	{
		goto error;
	}
	while(i < index)
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
int list_get_index_by_elt(struct c_list *list, struct rohc_list_item *item)
{
	struct list_elt *curr_elt;
	int i = 0;

	if(list->first_elt == NULL)
	{
		goto end;
	}

	curr_elt = list->first_elt;
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
void list_remove(struct c_list *list, struct rohc_list_item *item)
{
	struct list_elt *curr_elt;

	if(list->first_elt != NULL)
	{
		curr_elt = list->first_elt;
		while(curr_elt != NULL && curr_elt->item != item)
		{
			curr_elt = curr_elt->next_elt;
		}
		if(curr_elt != NULL)
		{
			// current element is not first element
			if(curr_elt->prev_elt != NULL)
			{
				curr_elt->prev_elt->next_elt = curr_elt->next_elt;
			}
			else
			{
				list->first_elt = curr_elt->next_elt;
			}
			// current element is not last element
			if(curr_elt->next_elt != NULL)
			{
				curr_elt->next_elt->prev_elt = curr_elt->prev_elt;
			}
		}
		free(curr_elt);
	}
}


/**
 * @brief Empty the list
 *
 * @param list the list to empty
 */
void list_empty(struct c_list *list)
{
	struct list_elt *curr_elt;
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
 * @return      1 if present, 0 else
 */
int list_type_is_present(struct c_list *list, struct rohc_list_item *item)
{
	struct list_elt *curr_elt;

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

	return 1;
end:
	return 0;
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

