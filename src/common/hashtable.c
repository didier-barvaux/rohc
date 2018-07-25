/*
 * Copyright 2018 Viveris Technologies
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
 * @file   hashtable.c
 * @brief  Efficient, secure hash table
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "hashtable.h"

#include "csiphash.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>


bool hashtable_new(struct hashtable *const hashtable,
                   const size_t key_len,
                   const size_t size)
{
	hashtable->key_len = key_len;
	hashtable->full_key_len = key_len;
	hashtable->mask = size - 1;

	hashtable->table = calloc(size, sizeof(struct hashlist *));
	if(hashtable->table == NULL)
	{
		return false;
	}

	return true;
}


void hashtable_free(struct hashtable *const hashtable)
{
	free(hashtable->table);
}


void hashtable_add(struct hashtable *const hashtable,
                   const void *const key,
                   void *const elem)
{
	const uint64_t hash = siphash24(key, hashtable->key_len, hashtable->key);
	struct hashlist *entry;

	entry = hashtable->table[hash & hashtable->mask];
	if(entry == NULL)
	{
		hashtable->table[hash & hashtable->mask] = elem;
		((struct hashlist *) elem)->prev = NULL;
	}
	else
	{
		while(entry->next != NULL)
		{
			entry = entry->next;
		}
		entry->next = elem;
		((struct hashlist *) elem)->prev = entry;
	}
	((struct hashlist *) elem)->next = NULL;
}


void * hashtable_get(const struct hashtable *const hashtable,
                     const void *const key)
{
	const uint64_t hash = siphash24(key, hashtable->key_len, hashtable->key);
	struct hashlist *entry;

	for(entry = hashtable->table[hash & hashtable->mask];
	    entry != NULL;
	    entry = entry->next)
	{
		if(memcmp(key, entry->key, hashtable->key_len) == 0)
		{
			break;
		}
	}

	return entry;
}


void hashtable_del(struct hashtable *const hashtable,
                   const void *const key)
{
	const uint64_t hash = siphash24(key, hashtable->key_len, hashtable->key);
	struct hashlist *entry;

	for(entry = hashtable->table[hash & hashtable->mask];
	    entry != NULL;
	    entry = entry->next)
	{
		if(memcmp(key, entry->key, hashtable->key_len) == 0)
		{
			if(entry->prev == NULL)
			{
				hashtable->table[hash & hashtable->mask] = entry->next;
			}
			else
			{
				entry->prev->next = entry->next;
			}

			if(entry->next != NULL)
			{
				entry->next->prev = entry->prev;
			}

			break;
		}
	}
}

