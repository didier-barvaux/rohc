/*
 * Copyright 2013,2014 Didier Barvaux
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
 * @file   schemes/comp_list_ipv6.c
 * @brief  ROHC list compression of IPv6 extension headers
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "schemes/comp_list_ipv6.h"

#include <string.h>


static int get_index_ipv6_table(const uint8_t next_header_type,
                                const size_t occur_nr)
	__attribute__((warn_unused_result, const));

static bool cmp_ipv6_ext(const struct rohc_list_item *const item,
                         const uint8_t ext_type,
                         const uint8_t *const ext_data,
                         const size_t ext_len)
	__attribute__((warn_unused_result, nonnull(1, 3)));


/**
 * @brief Create one context for compressing lists of IPv6 extension headers
 *
 * @param comp            The context to create
 * @param list_trans_nr   The number of uncompressed transmissions (L)
 * @param trace_cb        The function to call for printing traces
 * @param trace_cb_priv   An optional private context, may be NULL
 * @param profile_id      The ID of the associated decompression profile
 */
void rohc_comp_list_ipv6_new(struct list_comp *const comp,
                             const size_t list_trans_nr,
                             rohc_trace_callback2_t trace_cb,
                             void *const trace_cb_priv,
                             const int profile_id)
{
	size_t i;

	memset(comp, 0, sizeof(struct list_comp));

	comp->ref_id = ROHC_LIST_GEN_ID_NONE;
	comp->cur_id = ROHC_LIST_GEN_ID_NONE;

	for(i = 0; i <= ROHC_LIST_GEN_ID_ANON; i++)
	{
		rohc_list_reset(&comp->lists[i]);
		comp->lists[i].id = i;
	}

	for(i = 0; i < ROHC_LIST_MAX_ITEM; i++)
	{
		rohc_list_item_reset(&comp->trans_table[i]);
	}

	comp->list_trans_nr = list_trans_nr;

	/* specific callbacks for IPv6 extension headers */
	comp->get_size = ip_get_extension_size;
	comp->get_index_table = get_index_ipv6_table;
	comp->cmp_item = cmp_ipv6_ext;

	/* traces */
	comp->trace_callback = trace_cb;
	comp->trace_callback_priv = trace_cb_priv;
	comp->profile_id = profile_id;
}


/**
 * @brief Free one context for compressing lists of IPv6 extension headers
 *
 * @param comp          The context to destroy
 */
void rohc_comp_list_ipv6_free(struct list_comp *const comp)
{
	memset(comp, 0, sizeof(struct list_comp));
}


/**
 * @brief Get the index for the given IPv6 extension type
 *
 * Handle GRE, Authentication (AH), MINE, and all IPv6 extension headers.
 *
 * The list of IPv6 extension headers was retrieved from the registry
 * maintained by IANA at:
 *   http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
 * Remember to update \ref rohc_is_ipv6_opt if you update the list.
 *
 * @param next_header_type  The Next Header type to get an index for
 * @param occur_nr          The number of occurrence of the Extension Header
 *                          seen so far (current one included)
 * @return                  The based table index
 */
static int get_index_ipv6_table(const uint8_t next_header_type,
                                const size_t occur_nr)
{
	int index_table;

	assert((next_header_type == ROHC_IPPROTO_DSTOPTS && occur_nr <= 2) ||
	       (next_header_type != ROHC_IPPROTO_DSTOPTS && occur_nr == 1));

	switch(next_header_type)
	{
		case ROHC_IPPROTO_HOPOPTS:
			index_table = 0;
			break;
		case ROHC_IPPROTO_DSTOPTS:
			if(occur_nr == 1)
			{
				index_table = 1;
			}
			else
			{
				index_table = 13;
			}
			break;
		case ROHC_IPPROTO_ROUTING:
			index_table = 2;
			break;
#if 0 /* TODO: add support for AH header */
		case ROHC_IPPROTO_AH:
			index_table = 3;
			break;
#endif
		case ROHC_IPPROTO_FRAGMENT:
			index_table = 4;
			break;
#if 0 /* TODO: add support for null ESP header */
		case ROHC_IPPROTO_ESP:
			index_table = 5;
			break;
#endif
		case ROHC_IPPROTO_MOBILITY:
			index_table = 6;
			break;
		case ROHC_IPPROTO_HIP:
			index_table = 7;
			break;
		case ROHC_IPPROTO_SHIM:
			index_table = 8;
			break;
		case ROHC_IPPROTO_RESERVED1:
			index_table = 9;
			break;
		case ROHC_IPPROTO_RESERVED2:
			index_table = 10;
			break;
#if 0 /* TODO: add support for GRE header */
		case ROHC_IPPROTO_GRE:
			index_table = 11;
			break;
#endif
#if 0 /* TODO: add support for MINE header */
		case ROHC_IPPROTO_MINE:
			index_table = 12;
			break;
#endif
		/* 13 is used for the 2nd Destination option if any */
		default:
			/* unknown extension */
			index_table = -1;
	}

	/* either we didn't find an index or we should have one that stand in the
	 * 8-bit format for indexes */
	assert(index_table == -1 || (index_table & 0x7f) == index_table);

	return index_table;
}


/**
 * @brief Compare two IPv6 items
 *
 * @param item      The IPv6 item to compare
 * @param ext_type  The IPv6 Next Header type
 * @param ext_data  The IPv6 extension context
 * @param ext_len   The length (in bytes) of the IPv6 extension context
 * @return          true if the two items are equal,
 *                  false if they are different
 */
static bool cmp_ipv6_ext(const struct rohc_list_item *const item,
                         const uint8_t ext_type,
                         const uint8_t *const ext_data,
                         const size_t ext_len)
{
	/* IPv6 items are equal if:
	 *  - they are of the same type,
	 *  - they got the same length,
	 *  - they are both at least 2-byte length,
	 *  - they got the same content (except for the Next Header byte). */
	return (item->type == ext_type &&
	        item->length == ext_len &&
	        item->length >= 2 &&
	        memcmp(item->data + 1, ext_data + 1, item->length - 1) == 0);
}

