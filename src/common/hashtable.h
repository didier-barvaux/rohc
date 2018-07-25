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
 * @file   hashtable.h
 * @brief  Efficient, secure hash table
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_HASHTABLE_H
#define ROHC_HASHTABLE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


/** A linked list */
struct hashlist
{
	struct hashlist *prev;
	struct hashlist *next;
	struct hashlist *prev_cr;
	struct hashlist *next_cr;
	uint8_t key[];
} __attribute__((packed));


/** One hash table */
struct hashtable
{
	size_t key_len;
	size_t full_key_len;
	uint64_t mask;
	struct hashlist **table;
	char key[16];
};


bool hashtable_new(struct hashtable *const hashtable,
                   const size_t key_len,
                   const size_t size)
	__attribute((warn_unused_result, nonnull(1)));

void hashtable_free(struct hashtable *const hashtable)
	__attribute((nonnull(1)));

void hashtable_add(struct hashtable *const hashtable,
                   const void *const key,
                   void *const elem)
	__attribute((nonnull(1, 2, 3)));

void * hashtable_get(const struct hashtable *const hashtable,
                     const void *const key)
	__attribute((warn_unused_result, nonnull(1, 2)));

void hashtable_del(struct hashtable *const hashtable,
                   const void *const key)
	__attribute((nonnull(1, 2)));

#endif

