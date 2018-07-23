/*
 * Copyright 2012,2013,2014 Didier Barvaux
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
 * @file   rohc_list.h
 * @brief  Define list compression with its function
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_COMMON_LIST_H
#define ROHC_COMMON_LIST_H

#include "protocols/ipv6.h"
#include "protocols/ip_numbers.h"

#include <stdlib.h>


/** The maximum number of items in compressed lists */
#define ROHC_LIST_MAX_ITEM  16U
#if ROHC_LIST_MAX_ITEM <= 7
#  error "translation table must be larger enough for indexes stored on 3 bits"
#endif


/// Header version
typedef enum
{
	HBH    = ROHC_IPPROTO_HOPOPTS,  /**< Hop by hop header */
	RTHDR  = ROHC_IPPROTO_ROUTING,  /**< Routing header */
	AH     = ROHC_IPPROTO_AH,       /**< AH header */
	DEST   = ROHC_IPPROTO_DSTOPTS,  /**< Destination header */
	/* CSRC lists not supported yet */
} ext_header_version;


/** The largest gen_id value */
#define ROHC_LIST_GEN_ID_MAX   0xffU
#define ROHC_LIST_GEN_ID_ANON  (ROHC_LIST_GEN_ID_MAX + 1)
#define ROHC_LIST_GEN_ID_NONE  (ROHC_LIST_GEN_ID_MAX + 2)


/**
 * @brief Define a list for compression
 */
struct rohc_list
{
	/** The ID of the compressed list */
	unsigned int id;
/** The maximum number of items in a list (required by packet formats) */
#define ROHC_LIST_ITEMS_MAX  15U
	/** The items in the list */
	struct rohc_list_item *items[ROHC_LIST_ITEMS_MAX];
	/** The number of items in the list */
	uint8_t items_nr;
	/** How many times the list was transmitted? */
	uint8_t counter;
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((sizeof(struct rohc_list) % 8) == 0,
               "struct rohc_list length should be multiple of 8 bytes");
#endif


/**
 * @brief A list item
 */
struct rohc_list_item
{
	/** The type of the item */
	ext_header_version type;

	/** Is the compressor confident that the decompressor knows the item? */
	bool known;
	/** How many times the item was transmitted? */
	uint8_t counter;

/**
 * @brief The maximum length (in bytes) of item data
 *
 * Sized for IPv6 extension headers that may reach:
 *   (0xff + 1) * 8 = 2048 bytes
 */
#define ROHC_LIST_ITEM_DATA_MAX  IPV6_OPT_HDR_LEN_MAX

	/** The length of the item data (in bytes) */
	uint16_t length;
	/** The item data */
	uint8_t data[ROHC_LIST_ITEM_DATA_MAX];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct rohc_list_item, data) % 8) == 0,
               "data in struct rohc_list_item should be aligned on 8 bytes");
_Static_assert((sizeof(struct rohc_list_item) % 8) == 0,
               "struct rohc_list_item length should be multiple of 8 bytes");
#endif


/** The handler used to compare two items */
typedef bool (*rohc_list_item_cmp) (const struct rohc_list_item *const item,
                                    const uint8_t ext_type,
                                    const uint8_t *const ext_data,
                                    const size_t ext_len)
	__attribute__((warn_unused_result, nonnull(1, 3)));



/**
 * Functions prototypes
 */

void rohc_list_reset(struct rohc_list *const list)
	__attribute__((nonnull(1)));

bool rohc_list_equal(const struct rohc_list *const list1,
                     const struct rohc_list *const list2)
	__attribute__((warn_unused_result, nonnull(1, 2), pure));

bool rohc_list_supersede(const struct rohc_list *const large,
                         const struct rohc_list *const small)
	__attribute__((warn_unused_result, nonnull(1, 2), pure));

void rohc_list_item_reset(struct rohc_list_item *const list_item)
	__attribute__((nonnull(1)));

int rohc_list_item_update_if_changed(rohc_list_item_cmp cmp_item,
                                     struct rohc_list_item *const list_item,
                                     const uint8_t item_type,
                                     const uint8_t *const item_data,
                                     const size_t item_len)
	__attribute__((warn_unused_result, nonnull(2, 4)));

#endif

