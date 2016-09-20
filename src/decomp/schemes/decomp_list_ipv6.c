/*
 * Copyright 2013 Didier Barvaux
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
 * @file   schemes/decomp_list_ipv6.c
 * @brief  ROHC list decompression of IPv6 extension headers
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "schemes/decomp_list_ipv6.h"

#include "rohc_traces_internal.h"

#include <string.h>


static bool check_ip6_item(const struct list_decomp *const decomp,
                           const size_t index_table)
	__attribute__((warn_unused_result, nonnull(1)));

static int get_ip6_ext_size(const uint8_t *const data,
                            const size_t data_len)
	__attribute__((warn_unused_result, nonnull(1)));

static bool cmp_ipv6_ext(const struct rohc_list_item *const item,
                         const uint8_t ext_type,
                         const uint8_t *const ext_data,
                         const size_t ext_len)
	__attribute__((warn_unused_result, nonnull(1, 3)));

static bool create_ip6_item(const uint8_t *const data,
                            const size_t length,
                            const size_t index_table,
                            struct list_decomp *const decomp)
	__attribute__((warn_unused_result, nonnull(1, 4)));

static size_t rohc_build_ip6_extension(const struct list_decomp *const decomp,
                                       const uint8_t ip_nh_type,
                                       uint8_t *const dest)
	__attribute__((warn_unused_result, nonnull(1, 3)));



/**
 * @brief Create one context for decompressing lists of IPv6 extension headers
 *
 * @param decomp         The context to create
 * @param trace_cb       The function to call for printing traces
 * @param trace_cb_priv  An optional private context, may be NULL
 * @param profile_id     The ID of the associated decompression profile
 */
void rohc_decomp_list_ipv6_new(struct list_decomp *const decomp,
                               rohc_trace_callback2_t trace_cb,
                               void *const trace_cb_priv,
                               const int profile_id)
{
	memset(decomp, 0, sizeof(struct list_decomp));

	/* specific callbacks for IPv6 extension headers */
	decomp->check_item = check_ip6_item;
	decomp->get_item_size = get_ip6_ext_size;
	decomp->cmp_item = cmp_ipv6_ext;
	decomp->create_item = create_ip6_item;
	decomp->build_uncomp_item = rohc_build_ip6_extension;

	/* traces */
	decomp->trace_callback = trace_cb;
	decomp->trace_callback_priv = trace_cb_priv;
	decomp->profile_id = profile_id;
}


/**
 * @brief Free one context for decompressing lists of IPv6 extension headers
 *
 * @param decomp          The context to destroy
 */
void rohc_decomp_list_ipv6_free(struct list_decomp *const decomp)
{
	memset(decomp, 0, sizeof(struct list_decomp));
}


/**
 * @brief Check if the item is correct in IPv6 table
 *
 * @param decomp       The list decompressor
 * @param index_table  The index of the item to check the presence
 * @return             true if item is found, false if not
 */
static bool check_ip6_item(const struct list_decomp *const decomp,
                           const size_t index_table)
{
	if(index_table > ROHC_LIST_MAX_ITEM)
	{
		rd_list_debug(decomp, "no item in based table at position %zu",
		              index_table);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Get the size (in bytes) of the extension
 *
 * @param data      The extension data
 * @param data_len  The length (in bytes) of the extension data
 * @return          The size of the extension in case of success,
 *                  -1 otherwise
 */
static int get_ip6_ext_size(const uint8_t *data, const size_t data_len)
{
	if(data_len < 2)
	{
		/* too few data for extension: at least 2 bytes of data are required */
		goto error;
	}

	return (data[1] + 1) * 8;

error:
	return -1;
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


/**
 * @brief Create an IPv6 item extension list
 *
 * @param data         The data in the item
 * @param length       The length of the item
 * @param index_table  The index of the item in based table
 * @param decomp       The list decompressor
 * @return             true in case of success, false otherwise
 */
static bool create_ip6_item(const uint8_t *const data,
                            const size_t length,
                            const size_t index_table,
                            struct list_decomp *const decomp)
{
	uint8_t item_type;
	int ret;

	assert(decomp != NULL);

	/* check minimal length for Next Header and Length fields */
	if(length < 2)
	{
		rd_list_warn(decomp, "packet too small for Next Header and Length "
		             "fields: only %zu bytes available while at least 2 bytes "
		             "are required", length);
		goto error;
	}
	item_type = data[0];

	ret = rohc_list_item_update_if_changed(decomp->cmp_item,
	                                       &decomp->trans_table[index_table],
	                                       item_type, data, length);
	if(ret < 0)
	{
		rd_list_warn(decomp, "failed to update the list item #%zu in "
		             "translation table", index_table);
		goto error;
	}

	/* on decompressor, an item is considered known upon first reception */
	decomp->trans_table[index_table].known = true;

	return true;

error:
	return false;
}


/**
 * @brief Build an extension list in IPv6 header
 *
 * @param decomp      The list decompressor
 * @param ip_nh_type  The Next Header value of the base IPv6 header
 * @param dest        The buffer to store the IPv6 header
 * @return            The size of the list
 */
static size_t rohc_build_ip6_extension(const struct list_decomp *const decomp,
                                       const uint8_t ip_nh_type,
                                       uint8_t *const dest)
{
	size_t size = 0;
	size_t i;

	assert(decomp != NULL);
	assert(dest != NULL);

	/* copy IPv6 extension headers if any */
	for(i = 0; i < decomp->pkt_list.items_nr; i++)
	{
		uint8_t nh_type;
		size_t size_data; // size of one of the extension

		/* next header type */
		if((i + 1) < decomp->pkt_list.items_nr)
		{
			/* not last extension header, use next extension header type */
			nh_type = decomp->pkt_list.items[i + 1]->type;
		}
		else
		{
			/* last extension header, use given IP next header type */
			nh_type = ip_nh_type;
		}
		dest[size] = nh_type & 0xff;

		/* header length */
		size_data = decomp->pkt_list.items[i]->length;
		dest[size + 1] = ((size_data / 8) - 1) & 0xff;

		/* header data */
		memcpy(dest + size + 2, decomp->pkt_list.items[i]->data + 2,
		       size_data - 2);
		size += size_data;

		rd_list_debug(decomp, "build one %zu-byte IPv6 extension header with "
		              "Next Header 0x%02x", size_data, nh_type);
	}

	return size;
}

