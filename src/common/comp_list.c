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
 */

#include "comp_list.h"
#include "rohc_traces.h"

#include <stdlib.h>


/**
 * @brief Create one compression_list
 * @return 1 if successful, 0 otherwise
 */
int create_list(struct c_list * list)
{
	rohc_debugf(1, "creating compression list\n");

	list = malloc(sizeof(struct c_list));

	if(list == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the compression list\n");
		goto error;
	}

	list->gen_id = 0;
	list->first_elt = NULL;

	return 1;

error:
	return 0;
}

/**
 * @brief Add an element at the begin of the list
 * 
 * @param list the list where the element is added
 * @param item the item of the new element
 * @param index the index in based table
 * @return 1 if successful, 0 otherwise
 */
int add_elt(struct c_list * list, struct rohc_list_item *item, int index)
{
	struct list_elt * elt;
	
	elt = malloc(sizeof(struct list_elt));
	if (elt == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the list element\n");
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

/** @brief Add an element at the end of the list
 *
 * @param list the list where the element is added
 * @param item the item of the new element
 * @param index the index in based table
 * @return 1 if successful, 0 otherwise
 */
int push_back(struct c_list * list, struct rohc_list_item *item, int index)
{
	struct list_elt * elt;
	int result = 0;
	struct list_elt *curr_elt;
	
	if (list->first_elt == NULL)
	{
		result = add_elt(list, item, index);
	}
	else
	{
		elt = malloc(sizeof(struct list_elt));
		if (elt == NULL)
		{
			rohc_debugf(0, "cannot allocate memory for the list element\n");
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
 * @brief Delete the specified element of the list
 *
 * @param list the list where the element is destroyed
 * @param item  the element to delete
 */
void delete_elt(struct c_list * list, struct rohc_list_item *item)
{
	struct list_elt * curr_elt;
	
	if (list->first_elt != NULL)
	{
		curr_elt = list->first_elt;
		while (curr_elt != NULL && curr_elt->item != item)
		{
			curr_elt = curr_elt->next_elt;
		}
		if (curr_elt != NULL)
		{
			// current element is not first element
			if (curr_elt->prev_elt != NULL)
			{
				curr_elt->prev_elt->next_elt = curr_elt->next_elt;
			}
			else
			{
				list->first_elt = curr_elt->next_elt;
			}
			// current element is not last element
			if (curr_elt->next_elt != NULL)
			{
				curr_elt->next_elt->prev_elt = curr_elt->prev_elt;
				
			}
		}
		free(curr_elt);	
	}
}

/**
 * @brief Get the index of the specified element in the list
 *
 * @param list the list where is the element
 * @param item the specified element
 *
 * @return the index, -1 if the element is not in the list
 */
int elt_index(struct c_list * list, struct rohc_list_item *item)
{
	struct list_elt * curr_elt;
	int i = 0;

	if (list->first_elt == NULL)
                goto end;

	curr_elt = list->first_elt;
	while (curr_elt != NULL && curr_elt->item != item)
	{
		curr_elt = curr_elt->next_elt;
		i++;
	}

	if (curr_elt == NULL)
		goto end;
	
	return i;
end:
	return -1;
}	

/**
 * @brief Get the element at the specified index
 *
 * @param list the list where is the element
 * @param index the specified index
 * @return item, NULL if there is no element at this index
 */
struct list_elt * get_elt(struct c_list * list, int index)
{
	struct list_elt * curr_elt = list->first_elt;
	int i = 0;
	if (index >= size_list(list))
		goto error;
	while(i<index)
	{
		curr_elt = curr_elt->next_elt;
		i++;
	}
	return curr_elt;
error:
	return NULL;
}

/**
 * @brief Indicate if the type of the specified element is present
 *
 * @param list the list where is the element
 * @param item the specified element
 *
 * @return 1 if present, 0 else
 */
int type_is_present(struct c_list * list, struct rohc_list_item *item)
{
	struct list_elt * curr_elt;
	
	if (list->first_elt == NULL)
	{
		rohc_debugf(0, "no element in the list\n");
		goto end;
	}

	curr_elt = list->first_elt;
	while (curr_elt != NULL && curr_elt->item->type != item->type)
	{
		curr_elt = curr_elt->next_elt;
	}
	if (curr_elt == NULL)
		goto end;
	
	return 1;
end:
	return 0;
}
/**
 *@brief Empty the list
 *
 *@param list the list to empty
 */
void empty_list(struct c_list * list)
{
	struct list_elt * curr_elt;
	if (list->first_elt == NULL)
	{
		rohc_debugf(1, "no element in the list\n");
	}
	else
	{
		curr_elt = list->first_elt;
		while (curr_elt->next_elt != NULL )
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
 * @brief Destroy the list
 *
 * @param list the list to destroy
 */
void destroy_list(struct c_list * list)
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
 * @brief Insert an element at the specified position
 *
 * @param list         The list in which the element is inserted
 * @param item         The element to insert
 * @param index        The position
 * @param index_table  The index in based_table
 * @return             1 if successful, 0 otherwise
 */
int insert_elt(struct c_list *list, struct rohc_list_item *item, int index, int index_table)
{
	int i;
	int size_l = size_list(list);

	if(index > size_l)
	{
		rohc_debugf(0, "bad index for insertion\n");
		goto error;
	}
	
	if(index == 0)
	{
		/* special case for first element */
		if(!add_elt(list, item, index_table))
		{
			rohc_debugf(0, "failed to add element in list\n");
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
			rohc_debugf(0, "cannot allocate memory for the list element\n");
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
				curr_elt = curr_elt->next_elt;
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
				elt->prev_elt->next_elt = elt;
		}
	}

	return 1;

error:
	return 0;
}


/**
 * @brief Get the size of the given list
 *
 * @param list  The list
 * @return      The size of the list
 */
size_t size_list(const struct c_list *const list)
{
	struct list_elt *curr_elt;
	size_t size = 0;

	for(curr_elt = list->first_elt; curr_elt != NULL; curr_elt = curr_elt->next_elt)
	{
		size++;
	}

	return size;
}

