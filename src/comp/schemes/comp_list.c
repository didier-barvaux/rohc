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
 * @file   schemes/comp_list.c
 * @brief  ROHC generic list compression
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "schemes/comp_list.h"
#include "rohc_comp_internals.h"

#include <string.h>


/** Print a warning trace for the given list compression context */
#define rohc_comp_list_warn(list_ctxt, format, ...) \
	rohc_warning(list_ctxt, ROHC_TRACE_COMP, (list_ctxt)->profile_id, \
	             format, ##__VA_ARGS__)



static bool build_ipv6_ext_pkt_list(struct list_comp *const comp,
                                    const struct ip_packet *const ip,
                                    struct rohc_list *const pkt_list)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static unsigned int rohc_list_get_nearest_list(const struct list_comp *const comp,
                                               const struct rohc_list *const pkt_list,
                                               bool *const is_new_list)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int rohc_list_decide_type(struct list_comp *const comp)
	__attribute__((warn_unused_result, nonnull(1)));

static int rohc_list_encode_type_0(struct list_comp *const comp,
                                   uint8_t *const dest,
                                   int counter)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_encode_type_1(struct list_comp *const comp,
                                   uint8_t *const dest,
                                   int counter)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_encode_type_2(struct list_comp *const comp,
                                   uint8_t *const dest,
                                   int counter)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_encode_type_3(struct list_comp *const comp,
                                   uint8_t *const dest,
                                   int counter)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static size_t rohc_list_compute_ins_mask(const struct list_comp *const comp,
                                         const struct rohc_list *const ref_list,
                                         const struct rohc_list *const cur_list,
                                         const uint8_t rem_mask[ROHC_LIST_ITEMS_MAX],
                                         uint8_t ins_mask[ROHC_LIST_ITEMS_MAX],
                                         uint8_t *const rohc_data,
                                         const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6)));

static size_t rohc_list_compute_rem_mask(const struct list_comp *const comp,
                                         const struct rohc_list *const ref_list,
                                         const struct rohc_list *const cur_list,
                                         uint8_t rem_mask[ROHC_LIST_ITEMS_MAX],
                                         uint8_t *const rohc_data,
                                         const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static uint8_t rohc_list_compute_ps(const struct list_comp *const comp,
                                    const struct rohc_list *const list,
                                    const uint8_t mask[ROHC_LIST_ITEMS_MAX],
                                    const size_t m)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_build_XIs(const struct list_comp *const comp,
                               const struct rohc_list *const list,
                               const uint8_t mask[ROHC_LIST_ITEMS_MAX],
                               const size_t ps,
                               uint8_t *const rohc_data,
                               const size_t rohc_max_len,
                               uint8_t *const first_4b_xi)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 7)));

static int rohc_list_build_XIs_8(const struct list_comp *const comp,
                                 const struct rohc_list *const list,
                                 const uint8_t mask[ROHC_LIST_ITEMS_MAX],
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int rohc_list_build_XIs_4(const struct list_comp *const comp,
                                 const struct rohc_list *const list,
                                 const uint8_t mask[ROHC_LIST_ITEMS_MAX],
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len,
                                 uint8_t *const first_4b_xi)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 6)));



/**
 * @brief Detect changes within the list of IPv6 extension headers
 *
 * @param comp                       The list compressor
 * @param ip                         The IP packet to compress
 * @param[out] list_struct_changed   Whether the structure of the list changed
 * @param[out] list_content_changed  Whether the content of the list changed
 * @return                           true if no error occurred,
 *                                   false if one error occurred
 */
bool detect_ipv6_ext_changes(struct list_comp *const comp,
                             const struct ip_packet *const ip,
                             bool *const list_struct_changed,
                             bool *const list_content_changed)
{
	unsigned int new_cur_id = ROHC_LIST_GEN_ID_NONE;
	struct rohc_list pkt_list;
	bool is_new_list = false;

	/* parse all extension headers:
	 *  - update the related entries in the translation table,
	 *  - create the list for the packet */
	if(!build_ipv6_ext_pkt_list(comp, ip, &pkt_list))
	{
		rohc_comp_list_warn(comp, "failed to build the list of extension headers "
		                    "for the current packet");
		goto error;
	}

	/* now that translation table is updated and packet list is generated,
	 * search for a context list with the same structure or use an anonymous
	 * list */
	new_cur_id = rohc_list_get_nearest_list(comp, &pkt_list, &is_new_list);
	if(is_new_list)
	{
		/* TODO: context should not be overwritten until compression is fully OK */
		assert(comp->lists[new_cur_id].id == new_cur_id);
		memcpy(comp->lists[new_cur_id].items, pkt_list.items,
		       ROHC_LIST_ITEMS_MAX * sizeof(struct rohc_list_item *));
		comp->lists[new_cur_id].items_nr = pkt_list.items_nr;
		comp->lists[new_cur_id].counter = 0;
	}

	/* do we need to send some bits of the compressed list? */
	if(new_cur_id != comp->cur_id)
	{
		rc_list_debug(comp, "send some bits for extension header list of the "
		              "outer IPv6 header because it changed");
		*list_struct_changed = true;
		*list_content_changed = true;
	}
	else if(new_cur_id != ROHC_LIST_GEN_ID_NONE &&
	        comp->lists[new_cur_id].counter < comp->list_trans_nr)
	{
		rc_list_debug(comp, "send some bits for extension header list of the "
		              "outer IPv6 header because it was not sent enough times");
		*list_struct_changed = true;
		*list_content_changed = false;
	}
	else
	{
		size_t i;

		*list_struct_changed = false;
		*list_content_changed = false;
		for(i = 0; i < comp->lists[comp->cur_id].items_nr; i++)
		{
			if(!comp->lists[comp->cur_id].items[i]->known)
			{
				*list_content_changed = true;
				break;
			}
		}
		if((*list_content_changed))
		{
			rc_list_debug(comp, "send some bits for extension header list of "
			              "the outer IPv6 header because some of its items were "
			              "not sent enough times");
		}
	}

	/* TODO: should not be overwritten until compression is fully OK */
	comp->cur_id = new_cur_id;

	return true;

error:
	return false;
}


/**
 * @brief Compute the list of extension headers for the current packet
 *
 * Parse all extension headers:
 *  \li update the related entries in the translation table,
 *  \li create the list for the packet
 *
 * @param comp           The list compressor
 * @param ip             The IP packet to compress
 * @param[out] pkt_list  The list of extension headers for the current packet
 * @return               true if no error occurred,
 *                       false if one error occurred
 */
static bool build_ipv6_ext_pkt_list(struct list_comp *const comp,
                                    const struct ip_packet *const ip,
                                    struct rohc_list *const pkt_list)
{
	uint8_t ext_types_count[ROHC_IPPROTO_MAX + 1] = { 0 };
	const uint8_t *ext;
	uint8_t ext_type;

	/* reset the list of the current packet */
	rohc_list_reset(pkt_list);

	/* get the next known IP extension in packet */
	ext = ip_get_next_ext_from_ip(ip, &ext_type);
	if(ext == NULL)
	{
		/* there is no list of IPv6 extension headers in the current packet */
		rc_list_debug(comp, "there is no IPv6 extension in packet");
		goto skip;
	}

	/* there is one extension or more */
	rc_list_debug(comp, "there is at least one IPv6 extension in packet");

	/* parse all extension headers:
	 *  - update the related entries in the translation table,
	 *  - create the list for the packet */
	do
	{
		bool entry_changed = false;
		int index_table;
		int ret;

		/* one more occurrence of this item */
		if(ext_types_count[ext_type] >= 255)
		{
			rohc_comp_list_warn(comp, "too many IPv6 extension header of type 0x%02x",
			                    ext_type);
			goto error;
		}
		ext_types_count[ext_type]++;

		/* find the best item to encode the extension in translation table */
		index_table = comp->get_index_table(ext_type, ext_types_count[ext_type]);
		if(index_table < 0 || ((size_t) index_table) >= ROHC_LIST_MAX_ITEM)
		{
			rohc_comp_list_warn(comp, "failed to handle unknown IPv6 "
			                    "extension header of type 0x%02x", ext_type);
			goto error;
		}

		/* update item in translation table if it changed */
		/* TODO: context should not be overwritten until compression is fully OK */
		/* TODO: put comp const in params once context is not overwritten any more */
		ret = rohc_list_item_update_if_changed(comp->cmp_item,
		                                       &(comp->trans_table[index_table]),
		                                       ext_type, ext, comp->get_size(ext));
		if(ret < 0)
		{
			rohc_comp_list_warn(comp, "failed to update entry #%d in translation "
			                    "table with %u-byte extension", index_table,
			                    comp->get_size(ext));
			goto error;
		}
		else if(ret == 1)
		{
			rc_list_debug(comp, "  entry #%d updated in translation table",
			              index_table);
			entry_changed = true;
		}

		/* update current list in context */
		pkt_list->items[pkt_list->items_nr] = &(comp->trans_table[index_table]);
		pkt_list->items_nr++;

		rc_list_debug(comp, "  extension #%zu: extension type %u uses %s entry #%d "
		              "in translation table (%s entry sent %zu/%zu times)",
		              pkt_list->items_nr, ext_type,
		              (entry_changed ? "updated" : "existing"), index_table,
		              comp->trans_table[index_table].known ? "known" : "not-yet-known",
		              comp->trans_table[index_table].counter, comp->list_trans_nr);
	}
	while((ext = ip_get_next_ext_from_ext(ext, &ext_type)) != NULL &&
	      pkt_list->items_nr < ROHC_LIST_ITEMS_MAX);

	/* too many extensions in packet? */
	if(ext != NULL)
	{
		rc_list_debug(comp, "list of IPv6 extension headers too large for "
		              "compressor internal limits");
		goto error;
	}

skip:
	return true;
error:
	return false;
}


/**
 * @brief Generic encoding of compressed list
 *
 * @param comp     The list compressor
 * @param dest     The ROHC packet under build
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer,
 *                 -1 in case of error
 */
int rohc_list_encode(struct list_comp *const comp,
                     uint8_t *const dest,
                     int counter)
{
	int encoding_type;

	/* sanity checks */
	assert(comp != NULL);
	assert(dest != NULL);

	/* determine which encoding type is required for the current list ? */
	encoding_type = rohc_list_decide_type(comp);
	assert(encoding_type >= 0 && encoding_type <= 3);
	rc_list_debug(comp, "use list encoding type %d", encoding_type);

	/* encode the current list according to the encoding type */
	switch(encoding_type)
	{
		case 0: /* Encoding type 0 (generic scheme) */
			counter = rohc_list_encode_type_0(comp, dest, counter);
			break;
		case 1: /* Encoding type 1 (insertion only scheme) */
			counter = rohc_list_encode_type_1(comp, dest, counter);
			break;
		case 2: /* Encoding type 2 (removal only scheme) */
			counter = rohc_list_encode_type_2(comp, dest, counter);
			break;
		case 3: /* encoding type 3 (remove then insert scheme) */
			counter = rohc_list_encode_type_3(comp, dest, counter);
			break;
		default:
			rohc_assert(comp, ROHC_TRACE_COMP, comp->profile_id,
			            false, error, "unknown encoding type for list "
			            "compression");
	}
	if(counter < 0)
	{
		rohc_comp_list_warn(comp, "failed to encode list type %d", encoding_type);
		goto error;
	}

	if(comp->cur_id == ROHC_LIST_GEN_ID_ANON)
	{
		rc_list_debug(comp, "send anonymous list for the #%zu time",
		              comp->lists[comp->cur_id].counter + 1);
	}
	else
	{
		rc_list_debug(comp, "send list with generation ID %u for the #%zu time",
		              comp->cur_id, comp->lists[comp->cur_id].counter + 1);
	}

	return counter;

error:
	return -1;
}


/**
 * @brief Update the list compression context
 *
 * Update the counter of the current list.
 * Update the counters of the items of the current list.
 * Update the reference list with the current list if possible.
 *
 * @param comp  The list compressor
 */
void rohc_list_update_context(struct list_comp *const comp)
{
	size_t i;

	/* nothing to do if there is no list */
	if(comp->cur_id == ROHC_LIST_GEN_ID_NONE)
	{
		return;
	}

	/* the items of the current list were sent once more, increment their
	 * counters and check whether they are known or not */
	for(i = 0; i < comp->lists[comp->cur_id].items_nr; i++)
	{
		if(!comp->lists[comp->cur_id].items[i]->known)
		{
			comp->lists[comp->cur_id].items[i]->counter++;
			if(comp->lists[comp->cur_id].items[i]->counter >= comp->list_trans_nr)
			{
				comp->lists[comp->cur_id].items[i]->known = true;
			}
		}
	}

	/* current list was sent once more, do we update the reference list? */
	if(comp->cur_id != comp->ref_id)
	{
		comp->lists[comp->cur_id].counter++;
		if(comp->cur_id != ROHC_LIST_GEN_ID_ANON &&
		   comp->lists[comp->cur_id].counter >= comp->list_trans_nr)
		{
			if(comp->ref_id != ROHC_LIST_GEN_ID_NONE)
			{
				/* replace previous reference list */
				rc_list_debug(comp, "replace the reference list (gen_id = %u) by "
				              "current list (gen_id = %u) because it was "
				              "transmitted at least L = %zu times",
				              comp->ref_id, comp->cur_id, comp->list_trans_nr);
			}
			else
			{
				/* first reference list */
				rc_list_debug(comp, "use the current list (gen_id = %u) as the "
				              "first reference list because it was transmitted "
				              "at least L = %zu times", comp->cur_id,
				              comp->list_trans_nr);
			}
			comp->ref_id = comp->cur_id;
		}
	}
}


/**
 * @brief Search the nearest list for the packet list
 *
 * Search for a context list with the same structure:
 *  \li check the reference list first as it is probably the correct one,
 *  \li then check the other identified lists,
 *  \li finally, use an anonymous list or promote the repeated anonymous
 *      list to an identified list.
 *
 * @param comp              The list compressor
 * @param pkt_list          The list of extension headers for the current packet
 * @param[out] is_new_list  Whether the list is new or not
 * @return                  The list to use as a base to transmit the packet list
 */
static unsigned int rohc_list_get_nearest_list(const struct list_comp *const comp,
                                               const struct rohc_list *const pkt_list,
                                               bool *const is_new_list)
{
	const size_t anon_thres = 2;
	unsigned int new_cur_id = ROHC_LIST_GEN_ID_NONE;
	unsigned int gen_id;

	/* check the reference list first as it is probably the correct one */
	if(comp->ref_id != ROHC_LIST_GEN_ID_NONE &&
	   rohc_list_equal(pkt_list, &comp->lists[comp->ref_id]))
	{
		/* reference list matches, no need for a new list */
		rc_list_debug(comp, "send reference list with gen_id = %u", comp->ref_id);
		*is_new_list = false;
		return comp->ref_id;
	}
	rc_list_debug(comp, "current list do not match reference list with gen_id %u",
	              comp->ref_id);

	/* search for an identified list that matches the packet one, avoid the
	 * reference list that we already checked, stop on first unused list */
	for(gen_id = 0; new_cur_id == ROHC_LIST_GEN_ID_NONE &&
	                gen_id <= ROHC_LIST_GEN_ID_MAX &&
	                comp->lists[gen_id].counter > 0; gen_id++)
	{
		if(gen_id != comp->ref_id &&
		   comp->lists[gen_id].counter > 0 &&
		   rohc_list_equal(pkt_list, &comp->lists[gen_id]))
		{
			rc_list_debug(comp, "current list matches the existing list "
			              "with gen_id %u", gen_id);
			new_cur_id = gen_id;
		}
	}

	/* if an identified list matches the structure of the packet list,
	 * let's use it as a base for the transmission */
	if(new_cur_id != ROHC_LIST_GEN_ID_NONE)
	{
		rc_list_debug(comp, "send existing context list with gen_id %u "
		              "(already sent %zu times)", new_cur_id,
		              comp->lists[new_cur_id].counter);
		*is_new_list = false;
		return new_cur_id;
	}
	rc_list_debug(comp, "current list matches no list identified with a gen_id");

	/* no idenfied list matches, the variation might be temporary for one packet,
	 * so let's use if possible an anonymous list to transmit the packet list
	 * without defining an idenfied list */

	/* if no reference list was established, anonymous list is not allowed,
	 * so still create a new identified list */
	if(comp->ref_id == ROHC_LIST_GEN_ID_NONE)
	{
		rc_list_debug(comp, "no list was ever sent");
		*is_new_list = true;
		return 0;
	}

	/* try to use an anonymous list */
	if(comp->lists[ROHC_LIST_GEN_ID_ANON].counter == 0 ||
	   !rohc_list_equal(pkt_list, &comp->lists[ROHC_LIST_GEN_ID_ANON]))
	{
		/* new or changed anonymous list */
		rc_list_debug(comp, "send current list as anonymous list (transmitted "
		              "0 / %zu)", anon_thres);
		*is_new_list = true;
		return ROHC_LIST_GEN_ID_ANON;
	}
	rc_list_debug(comp, "current list matches last anonymous list");

	/* anonymous list matches, either use it as an anonymous list another time
	 * or promote it an identified list */
	if((comp->lists[ROHC_LIST_GEN_ID_ANON].counter + 1) < anon_thres)
	{
		/* too early to promote anonymous list to an identified list with a gen_id */
		rc_list_debug(comp, "send current list as anonymous list (transmitted "
		              "%zu / %zu)", comp->lists[ROHC_LIST_GEN_ID_ANON].counter,
		              anon_thres);
		*is_new_list = false;
		return ROHC_LIST_GEN_ID_ANON;
	}

	/* promote anonymous list to an identified list with a gen_id:
	 *  - search for the first unused list,
	 *  - if no unused list was found, get the next free gen_id
	 *  - in all cases, avoid re-using ref_id */
	for(gen_id = 0; new_cur_id == ROHC_LIST_GEN_ID_NONE &&
	                gen_id <= ROHC_LIST_GEN_ID_MAX; gen_id++)
	{
		if(gen_id != comp->ref_id && comp->lists[gen_id].counter == 0)
		{
			new_cur_id = gen_id;
		}
	}
	if(new_cur_id == ROHC_LIST_GEN_ID_NONE)
	{
		new_cur_id = gen_id % (ROHC_LIST_GEN_ID_MAX + 1);
		if(new_cur_id == comp->ref_id)
		{
			new_cur_id++;
			new_cur_id %= (ROHC_LIST_GEN_ID_MAX + 1);
		}
	}
	rc_list_debug(comp, "the anonymous list is going to be transmitted for the "
	              "%zu time, promote it to an identified list with gen_id = %u",
	              comp->lists[ROHC_LIST_GEN_ID_ANON].counter + 1, new_cur_id);
	*is_new_list = true;
	return new_cur_id;
}


/**
 * @brief Decide the encoding type for compression list
 *
 * @param comp  The list compressor
 * @return      the encoding type among [0-3]
 */
static int rohc_list_decide_type(struct list_comp *const comp)
{
	int encoding_type;

	/* sanity checks */
	assert(comp != NULL);
	assert(comp->cur_id != ROHC_LIST_GEN_ID_NONE);

	if(comp->ref_id == ROHC_LIST_GEN_ID_NONE)
	{
		/* no reference list, so use encoding type 0 */
		rc_list_debug(comp, "use list encoding type 0 because there is no "
		              "reference list yet");
		encoding_type = 0;
	}
	else if(comp->lists[comp->ref_id].items_nr == 0)
	{
		/* empty reference list, so use encoding type 0 (RFC 4815, §5.7 reads
		 * that encoding types 1, 2, and 3 must not be used with an empty
		 * reference list) */
		rc_list_debug(comp, "use list encoding type 0 because reference list "
		              "is the empty list");
		encoding_type = 0;
	}
	else if(comp->lists[comp->cur_id].counter > 0)
	{
		/* the structure of the list did not change, so use encoding type 0 */
		rc_list_debug(comp, "use list encoding type 0 because the structure of "
		              "the list did not change (items may be sent if they "
		              "changed)");
		encoding_type = 0;
	}
	else if(comp->lists[comp->cur_id].items_nr <=
	        comp->lists[comp->ref_id].items_nr)
	{
		/* the structure of the list changed, there are fewer items in the
		 * current list than in the reference list: are all the items of the
		 * current list in the reference list? */
		if(!rohc_list_supersede(&comp->lists[comp->ref_id],
		                        &comp->lists[comp->cur_id]))
		{
			/* some items of the current list are not present in the reference
			 * list, so the 'Remove Then Insert scheme' (type 3) is required
			 * to encode the current list */
			encoding_type = 3;
		}
		else
		{
			/* all the items of the current list are present in the reference
			 * list, so the 'Removal Only scheme' (type 2) might be used to
			 * encode the current list, but check before that all items of the
			 * current list are known because encoding type 2 cannot update
			 * items */
			size_t k;
			encoding_type = 2;
			for(k = 0; k < comp->lists[comp->cur_id].items_nr; k++)
			{
				if(!comp->lists[comp->cur_id].items[k]->known)
				{
					encoding_type = 0;
					break;
				}
			}
		}
	}
	else
	{
		/* the structure of the list changed, there are more items in the
		 * current list than in the reference list: are all the items of the
		 * reference list in the current list? */
		if(rohc_list_supersede(&comp->lists[comp->cur_id],
		                       &comp->lists[comp->ref_id]))
		{
			/* all the items of the reference list are present in the current
			 * list, so the 'Insertion Only scheme' (type 1) may be used to
			 * encode the current list */
			encoding_type = 1;
		}
		else
		{
			/* some items of the reference list are not present in the current
			 * list, so the 'Remove Then Insert scheme' (type 3) is required
			 * to encode the current list */
			encoding_type = 3;
		}
	}

	return encoding_type;
}


/**
 * @brief Build encoding type 0 for list compression
 *
 * \verbatim

 Encoding type 0 (5.8.6.1):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  | ET = 0| GP| PS|   CC = m      |
    +---+---+---+---+---+---+---+---+
 2  :            gen_id             : 1 octet, if GP = 1
    +---+---+---+---+---+---+---+---+
    |       XI 1, ..., XI m         | m octets, or m * 4 bits
 3  /               --- --- --- --- /
    |               :    Padding    : if PS = 0 and m is odd
    +---+---+---+---+---+---+---+---+
    |                               |
 4  /      item 1, ..., item n      / variable length
    |                               |
    +---+---+---+---+---+---+---+---+

 ET: Encoding type is zero.

 GP: Indicates presence of gen_id field.

 PS: Indicates size of XI fields:
     PS = 0 indicates 4-bit XI fields;
     PS = 1 indicates 8-bit XI fields.

 CC: CSRC counter from original RTP header.

 gen_id: Identifier for a sequence of identical lists.  It is
     present in U/O-mode when the compressor decides that it may use
     this list as a future reference list.

 XI 1, ..., XI m: m XI items. The format of an XI item is as
     follows:

              +---+---+---+---+
     PS = 0:  | X |   Index   |
              +---+---+---+---+

                0   1   2   3   4   5   6   7
              +---+---+---+---+---+---+---+---+
     PS = 1:  | X |           Index           |
              +---+---+---+---+---+---+---+---+

     X = 1 indicates that the item corresponding to the Index
           is sent in the item 0, ..., item n list.
     X = 0 indicates that the item corresponding to the Index is
               not sent.

     When 4-bit XI items are used and m > 1, the XI items are placed in
     octets in the following manner:

          0   1   2   3   4   5   6   7
        +---+---+---+---+---+---+---+---+
        |     XI k      |    XI k + 1   |
        +---+---+---+---+---+---+---+---+

 Padding: A 4-bit padding field is present when PS = 0 and m is
     odd.  The Padding field is set to zero when sending and ignored
     when receiving.

 Item 1, ..., item n:
     Each item corresponds to an XI with X = 1 in XI 1, ..., XI m.

\endverbatim
 *
 * @param comp     The list compressor
 * @param dest     The ROHC packet under build
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer,
 *                 -1 in case of error
 */
static int rohc_list_encode_type_0(struct list_comp *const comp,
                                   uint8_t *const dest,
                                   int counter)
{
	uint8_t ext_types_count[ROHC_IPPROTO_MAX + 1] = { 0 };
	const uint8_t et = 0; /* list encoding type 0 */
	uint8_t gp;
	size_t m; /* the number of elements in current list = number of XIs */
	size_t k; /* the index of the current element in list */
	size_t ps; /* indicate the size of the indexes */

	assert(comp != NULL);
	assert(comp->cur_id != ROHC_LIST_GEN_ID_NONE);
	assert(dest != NULL);

	/* retrieve the number of items in the current list */
	m = comp->lists[comp->cur_id].items_nr;
	assert(m <= ROHC_LIST_ITEMS_MAX);

	/* determine whether we should use 4-bit or 8-bit indexes */
	{
		uint8_t ins_mask[ROHC_LIST_ITEMS_MAX] = { 1 };

		ps = rohc_list_compute_ps(comp, &(comp->lists[comp->cur_id]), ins_mask, m);
		if(ps != 0 && ps != 1)
		{
			goto error;
		}
	}

	/* part 1: ET, GP, PS, CC */
	gp = (comp->cur_id != ROHC_LIST_GEN_ID_ANON);
	rc_list_debug(comp, "ET = %d, GP = %d, PS = %zu, CC = m = %zu",
	              et, gp, ps, m);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	dest[counter] |= (ps & 0x01) << 4;
	dest[counter] |= m & 0x0f;
	counter++;

	/* part 2: gen_id (if not anonymous list) */
	if(gp)
	{
		dest[counter] = comp->cur_id;
		rc_list_debug(comp, "gen_id = 0x%02x", dest[counter]);
		counter++;
	}

	/* part 3: m XI (= X + Indexes) */
	if(ps)
	{
		/* each XI item is stored on 8 bits */
		rc_list_debug(comp, "use 8-bit format for the %zu XIs", m);

		/* write all XIs in packet */
		for(k = 0; k < m; k++, counter++)
		{
			const struct rohc_list_item *const item = comp->lists[comp->cur_id].items[k];
			int index_table;

			/* one more occurrence of this item */
			if(ext_types_count[item->type] >= 255)
			{
				rohc_comp_list_warn(comp, "too many IPv6 extension header of type 0x%02x",
				                    item->type);
				goto error;
			}
			ext_types_count[item->type]++;

			index_table = comp->get_index_table(item->type, ext_types_count[item->type]);
			assert(index_table >= 0);
			assert(((size_t) index_table) < ROHC_LIST_MAX_ITEM);

			dest[counter] = 0;
			/* set the X bit if item is not already known */
			if(!item->known)
			{
				dest[counter] |= 1 << 7;
			}
			/* 7-bit Index */
			assert((index_table & 0x7f) == index_table);
			dest[counter] |= index_table & 0x7f;

			rc_list_debug(comp, "add 8-bit XI #%zu = 0x%x", k, dest[counter]);
		}
	}
	else
	{
		/* each XI item is stored on 4 bits */
		rc_list_debug(comp, "use 4-bit format for the %zu XIs", m);

		/* write all XIs in packet 2 by 2 */
		for(k = 0; k < m; k += 2, counter++)
		{
			const struct rohc_list_item *const item = comp->lists[comp->cur_id].items[k];
			int index_table;

			/* one more occurrence of this item */
			if(ext_types_count[item->type] >= 255)
			{
				rohc_comp_list_warn(comp, "too many IPv6 extension header of type 0x%02x",
				                    item->type);
				goto error;
			}
			ext_types_count[item->type]++;

			index_table = comp->get_index_table(item->type, ext_types_count[item->type]);
			assert(index_table >= 0);
			assert(((size_t) index_table) < ROHC_LIST_MAX_ITEM);

			dest[counter] = 0;

			/* first 4-bit XI */
			/* set the X bit if item is not already known */
			if(!item->known)
			{
				dest[counter] |= 1 << 7;
			}
			/* 3-bit Index */
			assert((index_table & 0x07) == index_table);
			dest[counter] |= (index_table & 0x07) << 4;

			rc_list_debug(comp, "add 4-bit XI #%zu in MSB = 0x%x", k,
			              (dest[counter] & 0xf0) >> 4);

			/* second 4-bit XI or padding? */
			if((k + 1) < m)
			{
				const struct rohc_list_item *const item2 =
					comp->lists[comp->cur_id].items[k + 1];
				int index_table2;

				/* one more occurrence of this item */
				if(ext_types_count[item2->type] >= 255)
				{
					rohc_comp_list_warn(comp, "too many IPv6 extension header of type "
					                    "0x%02x", item2->type);
					goto error;
				}
				ext_types_count[item2->type]++;

				index_table2 =
					comp->get_index_table(item2->type, ext_types_count[item2->type]);
				assert(index_table2 >= 0);
				assert(((size_t) index_table2) < ROHC_LIST_MAX_ITEM);

				/* set the X bit if item is not already known */
				if(!item2->known)
				{
					dest[counter] |= 1 << 3;
				}
				/* 3-bit Index */
				assert((index_table2 & 0x07) == index_table2);
				dest[counter] |= (index_table2 & 0x07) << 0;

				rc_list_debug(comp, "add 4-bit XI #%zu in LSB = 0x%x", k + 1,
				              dest[counter] & 0x0f);
			}
			else
			{
				/* zero the padding bits */
				rc_list_debug(comp, "add 4-bit padding in LSB");
				dest[counter] &= 0xf0;
			}
		}
	}

	/* part 4: n items (only unknown items) */
	for(k = 0; k < m; k++)
	{
		const struct rohc_list_item *const item = comp->lists[comp->cur_id].items[k];

		/* copy the list element if not known yet */
		if(!item->known)
		{
			rc_list_debug(comp, "add %zu-byte not-yet-known item #%zu in "
			              "packet", item->length, k);
			assert(item->length > 1);
			dest[counter] = item->type & 0xff;
			memcpy(dest + counter + 1, item->data + 1, item->length - 1);
			counter += item->length;
		}
	}

	return counter;

error:
	return -1;
}


/**
 * @brief Build encoding type 1 for list compression
 *
 * \verbatim

 Encoding type 1 (5.8.6.2):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  | ET = 1| GP| PS|     XI 1      |
    +---+---+---+---+---+---+---+---+
 2  :            gen_id             : 1 octet, if GP = 1
    +---+---+---+---+---+---+---+---+
 3  |            ref_id             |
    +---+---+---+---+---+---+---+---+
 4  /       insertion bit mask      / 1-2 octets
    +---+---+---+---+---+---+---+---+
    |           XI list             | k octets, or (k - 1) * 4 bits
 5  /               --- --- --- --- /
    |               :    Padding    : if PS = 0 and k is even
    +---+---+---+---+---+---+---+---+
    |                               |
 6  /      item 1, ..., item n      / variable
    |                               |
    +---+---+---+---+---+---+---+---+

 ET: Encoding type is one (1).

 GP: Indicates presence of gen_id field.

 PS: Indicates size of XI fields:
     PS = 0 indicates 4-bit XI fields;
     PS = 1 indicates 8-bit XI fields.

 XI 1: When PS = 0, the first 4-bit XI item is placed here.
       When PS = 1, the field is set to zero when sending, and
       ignored when receiving.

 ref_id: The identifier of the reference CSRC list used when the
       list was compressed.  It is the 8 least significant bits of
       the RTP Sequence Number in R-mode and gen_id (see section
       5.8.2) in U/O-mode.

 insertion bit mask: Bit mask indicating the positions where new
           items are to be inserted.  See Insertion Only scheme in
           section 5.8.3.  The bit mask can have either of the
           following two formats:

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
    | 0 |        7-bit mask         |  bit 1 is the first bit
    +---+---+---+---+---+---+---+---+

    +---+---+---+---+---+---+---+---+
    | 1 |                           |  bit 1 is the first bit
    +---+      15-bit mask          +
    |                               |  bit 7 is the last bit
    +---+---+---+---+---+---+---+---+

 XI list: XI fields for items to be inserted.  When the insertion
    bit mask has k ones, the total number of XI fields is k.  When
    PS = 1, all XI fields are in the XI list.  When PS = 0, the
    first XI field is in the XI 1 field, and the remaining k - 1
    XI fields are in the XI list.

 Padding: Present when PS = 0 and k is even.

 item 1, ..., item n: One item for each XI field with the X bit set.

\endverbatim
 *
 * @param comp     The list compressor
 * @param dest     The ROHC packet under build
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer,
 *                 -1 in case of error
 */
static int rohc_list_encode_type_1(struct list_comp *const comp,
                                   uint8_t *const dest,
                                   int counter)
{
	const uint8_t et = 1; /* list encoding type 1 */
	uint8_t gp;
	const uint8_t rem_mask[ROHC_LIST_ITEMS_MAX] = { 0 }; /* empty removal mask */
	uint8_t ins_mask[ROHC_LIST_ITEMS_MAX] = { 0 };
	size_t ins_mask_len;
	size_t m; /* the number of elements in current list = number of XIs */
	size_t k; /* the index of the current element in current list */
	size_t ps; /* indicate the size of the indexes */
	size_t ps_pos; /* the position of the byte that contains the PS bit */
	int ret;

	assert(comp != NULL);
	assert(comp->ref_id != ROHC_LIST_GEN_ID_NONE);
	assert(comp->cur_id != ROHC_LIST_GEN_ID_NONE);
	assert(dest != NULL);

	/* retrieve the number of items in the current list */
	m = comp->lists[comp->cur_id].items_nr;
	assert(m <= ROHC_LIST_ITEMS_MAX);

	/* part 1: ET, GP (PS will be set later) */
	gp = (comp->cur_id != ROHC_LIST_GEN_ID_ANON);
	rc_list_debug(comp, "ET = %d, GP = %d", et, gp);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	ps_pos = counter; /* remember the position to set the PS bit later */
	dest[counter] &= 0xf0; /* clear the 4 LSB bits reserved for 1st XI */
	counter++;

	/* part 2: gen_id (if not anonymous list) */
	if(gp)
	{
		dest[counter] = comp->cur_id;
		rc_list_debug(comp, "gen_id = 0x%02x", dest[counter]);
		counter++;
	}

	/* part 3: ref_id */
	dest[counter] = comp->ref_id & 0xff;
	rc_list_debug(comp, "ref_id = 0x%02x", dest[counter]);
	counter++;

	/* part 4: insertion mask */
	ins_mask_len =
		rohc_list_compute_ins_mask(comp, &(comp->lists[comp->ref_id]),
		                           &(comp->lists[comp->cur_id]),
		                           rem_mask, ins_mask,
		                           dest + counter, 2 /* TODO */);
	if(ins_mask_len != 1 && ins_mask_len != 2)
	{
		rohc_comp_list_warn(comp, "ROHC buffer is too short for the insertion mask");
		goto error;
	}
	counter += ins_mask_len;

	/* determine whether we should use 4-bit or 8-bit indexes */
	ps = rohc_list_compute_ps(comp, &(comp->lists[comp->cur_id]), ins_mask, m);
	if(ps != 0 && ps != 1)
	{
		goto error;
	}

	/* part 5: k XI (= X + Indexes) */
	{
		uint8_t first_4b_xi;

		ret = rohc_list_build_XIs(comp, &(comp->lists[comp->cur_id]), ins_mask, ps,
		                          dest + counter, m /* TODO */, &first_4b_xi);
		if(ret < 0)
		{
			rohc_comp_list_warn(comp, "ROHC buffer is too short for the XI items");
			goto error;
		}
		if(ps == 0)
		{
			assert((first_4b_xi & 0x0f) == first_4b_xi);
			dest[ps_pos] |= first_4b_xi;
		}
		counter += ret;
	}

	/* part 6: n items (only unknown items) */
	for(k = 0; k < m; k++)
	{
		const struct rohc_list_item *const item = comp->lists[comp->cur_id].items[k];

		/* skip element if it present in the reference list */
		if(ins_mask[k] == 0 && item->known)
		{
			rc_list_debug(comp, "ignore element #%zu because it is present "
			              "in the reference list and already known", k);
			continue;
		}

		/* copy the list element if not known yet */
		if(!item->known)
		{
			rc_list_debug(comp, "add %zu-byte unknown item #%zu in packet",
			              item->length, k);
			assert(item->length > 1);
			dest[counter] = item->type & 0xff;
			memcpy(dest + counter + 1, item->data + 1, item->length - 1);
			counter += item->length;
		}
	}

	return counter;

error:
	return -1;
}


/**
 * @brief Build encoding type 2 for list compression
 *
 * \verbatim

 Encoding type 2 (5.8.6.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 1  | ET = 2| GP|res|    Count      |
    +---+---+---+---+---+---+---+---+
 2  :            gen_id             : 1 octet, if GP = 1
    +---+---+---+---+---+---+---+---+
 3  |            ref_id             |
    +---+---+---+---+---+---+---+---+
 4  /        removal bit mask       / 1-2 octets
    +---+---+---+---+---+---+---+---+

 ET: Encoding type is 2.

 GP: Indicates presence of gen_id field.

 res: Reserved.  Set to zero when sending, ignored when
      received.

 Count: Number of elements in ref_list.

 removal bit mask: Indicates the elements in ref_list to be
    removed in order to obtain the current list.  See section
    5.8.3.  The bit mask can have either of the following two
    formats:

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
    | 0 |        7-bit mask         |  bit 1 is the first bit
    +---+---+---+---+---+---+---+---+

    +---+---+---+---+---+---+---+---+
    | 1 |                           |  bit 1 is the first bit
    +---+      15-bit mask          +
    |                               |  bit 7 is the last bit
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param comp     The list compressor
 * @param dest     The ROHC packet under build
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer,
 *                 -1 in case of error
 */
static int rohc_list_encode_type_2(struct list_comp *const comp,
                                   uint8_t *const dest,
                                   int counter)
{
	const uint8_t et = 2; /* list encoding type 2 */
	uint8_t gp;
	uint8_t rem_mask[ROHC_LIST_ITEMS_MAX] = { 0 };
	size_t rem_mask_len;
	size_t count; /* size of reference list */

	assert(comp != NULL);
	assert(comp->ref_id != ROHC_LIST_GEN_ID_NONE);
	assert(comp->cur_id != ROHC_LIST_GEN_ID_NONE);
	assert(dest != NULL);

	/* retrieve the number of items in the reference list */
	count = comp->lists[comp->ref_id].items_nr;
	assert(count <= ROHC_LIST_ITEMS_MAX);

	/* part 1: ET, GP, res and Count */
	gp = (comp->cur_id != ROHC_LIST_GEN_ID_ANON);
	rc_list_debug(comp, "ET = %d, GP = %d, Count = %zu", et, gp, count);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	dest[counter] &= ~(0x01 << 4); /* clear the reserved bit */
	dest[counter] |= count & 0x0f;
	counter++;

	/* part 2: gen_id (if not anonymous list) */
	if(gp)
	{
		dest[counter] = comp->cur_id;
		rc_list_debug(comp, "gen_id = 0x%02x", dest[counter]);
		counter++;
	}

	/* part 3: ref_id */
	dest[counter] = comp->ref_id & 0xff;
	rc_list_debug(comp, "ref_id = 0x%02x", dest[counter]);
	counter++;

	/* part 4: removal mask */
	rem_mask_len =
		rohc_list_compute_rem_mask(comp, &(comp->lists[comp->ref_id]),
		                           &(comp->lists[comp->cur_id]),
		                           rem_mask, dest + counter, 2 /* TODO */);
	if(rem_mask_len != 1 && rem_mask_len != 2)
	{
		rohc_comp_list_warn(comp, "ROHC buffer is too short for the removal mask");
		goto error;
	}
	counter += rem_mask_len;

	return counter;

error:
	return -1;
}


/**
 * @brief Build encoding type 3 for list compression
 *
 * \verbatim

 Encoding type 3 (5.8.6.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 1  | ET=3  |GP |PS |     XI 1      |
    +---+---+---+---+---+---+---+---+
 2  :            gen_id             : 1 octet, if GP = 1
    +---+---+---+---+---+---+---+---+
 3  |            ref_id             |
    +---+---+---+---+---+---+---+---+
 4  /        removal bit mask       / 1-2 octets
    +---+---+---+---+---+---+---+---+
 5  /       insertion bit mask      / 1-2 octets
    +---+---+---+---+---+---+---+---+
    |           XI list             | k octets, or (k - 1) * 4 bits
 6  /               --- --- --- --- /
    |               :    Padding    : if PS = 0 and k is even
    +---+---+---+---+---+---+---+---+
    |                               |
 7  /      item 1, ..., item n      / variable
    |                               |
    +---+---+---+---+---+---+---+---+

 ET: Encoding type is 3.

 GP: Indicates presence of gen_id field.

 PS: Indicates size of XI fields:
     PS = 0 indicates 4-bit XI fields;
     PS = 1 indicates 8-bit XI fields.

 gen_id: Identifier for a sequence of identical lists.  It is
     present in U/O-mode when the compressor decides that it may use
     this list as a future reference list.

 ref_id: The identifier of the reference CSRC list used when the
       list was compressed.  It is the 8 least significant bits of
       the RTP Sequence Number in R-mode and gen_id (see section
       5.8.2) in U/O-mode.

 removal bit mask: Indicates the elements in ref_list to be
    removed in order to obtain the current list.  See section
    5.8.3.  The bit mask can have either of the following two
    formats:

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
    | 0 |        7-bit mask         |  bit 1 is the first bit
    +---+---+---+---+---+---+---+---+

    +---+---+---+---+---+---+---+---+
    | 1 |                           |  bit 1 is the first bit
    +---+      15-bit mask          +
    |                               |  bit 7 is the last bit
    +---+---+---+---+---+---+---+---+

 insertion bit mask: Bit mask indicating the positions where new
           items are to be inserted.  See Insertion Only scheme in
           section 5.8.3.  The bit mask can have either of the
           following two formats:

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
    | 0 |        7-bit mask         |  bit 1 is the first bit
    +---+---+---+---+---+---+---+---+

    +---+---+---+---+---+---+---+---+
    | 1 |                           |  bit 1 is the first bit
    +---+      15-bit mask          +
    |                               |  bit 7 is the last bit
    +---+---+---+---+---+---+---+---+

 XI list: XI fields for items to be inserted.  When the insertion
    bit mask has k ones, the total number of XI fields is k.  When
    PS = 1, all XI fields are in the XI list.  When PS = 0, the
    first XI field is in the XI 1 field, and the remaining k - 1
    XI fields are in the XI list.

 Padding: Present when PS = 0 and k is even.

 item 1, ..., item n: One item for each XI field with the X bit set.

\endverbatim
 *
 * @param comp     The list compressor
 * @param dest     The ROHC packet under build
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer,
 *                 -1 in case of error
 */
static int rohc_list_encode_type_3(struct list_comp *const comp,
                                   uint8_t *const dest,
                                   int counter)
{
	const uint8_t et = 3; /* list encoding type 3 */
	uint8_t gp;
	uint8_t rem_mask[ROHC_LIST_ITEMS_MAX] = { 0 };
	uint8_t ins_mask[ROHC_LIST_ITEMS_MAX] = { 0 };
	size_t rem_mask_len;
	size_t ins_mask_len;
	size_t count; /* size of reference list */
	size_t m; /* the number of elements in current list = number of XIs */
	size_t k; /* the index of the current element in current list */
	size_t ps; /* indicate the size of the indexes */
	size_t ps_pos; /* the position of the byte that contains the PS bit */
	int ret;

	assert(comp != NULL);
	assert(comp->ref_id != ROHC_LIST_GEN_ID_NONE);
	assert(comp->cur_id != ROHC_LIST_GEN_ID_NONE);
	assert(dest != NULL);

	/* retrieve the number of items in the reference list */
	count = comp->lists[comp->ref_id].items_nr;
	assert(count <= ROHC_LIST_ITEMS_MAX);

	/* retrieve the number of items in the current list */
	m = comp->lists[comp->cur_id].items_nr;
	assert(m <= ROHC_LIST_ITEMS_MAX);

	/* part 1: ET, GP (PS will be set later) */
	gp = (comp->cur_id != ROHC_LIST_GEN_ID_ANON);
	rc_list_debug(comp, "ET = %d, GP = %d", et, gp);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	ps_pos = counter; /* remember the position to set the PS bit later */
	dest[counter] &= 0xf0; /* clear the 4 LSB bits reserved for 1st XI */
	counter++;

	/* part 2: gen_id (if not anonymous list) */
	if(gp)
	{
		dest[counter] = comp->cur_id;
		rc_list_debug(comp, "gen_id = 0x%02x", dest[counter]);
		counter++;
	}

	/* part 3: ref_id */
	dest[counter] = comp->ref_id & 0xff;
	rc_list_debug(comp, "ref_id = 0x%02x", dest[counter]);
	counter++;

	/* part 4: removal mask */
	rem_mask_len =
		rohc_list_compute_rem_mask(comp, &(comp->lists[comp->ref_id]),
		                           &(comp->lists[comp->cur_id]),
		                           rem_mask, dest + counter, 2 /* TODO */);
	if(rem_mask_len != 1 && rem_mask_len != 2)
	{
		rohc_comp_list_warn(comp, "ROHC buffer is too short for the removal mask");
		goto error;
	}
	counter += rem_mask_len;

	/* part 5: insertion mask */
	ins_mask_len =
		rohc_list_compute_ins_mask(comp, &(comp->lists[comp->ref_id]),
		                           &(comp->lists[comp->cur_id]),
		                           rem_mask, ins_mask,
		                           dest + counter, 2 /* TODO */);
	if(ins_mask_len != 1 && ins_mask_len != 2)
	{
		rohc_comp_list_warn(comp, "ROHC buffer is too short for the insertion mask");
		goto error;
	}
	counter += ins_mask_len;

	/* determine whether we should use 4-bit or 8-bit indexes */
	ps = rohc_list_compute_ps(comp, &(comp->lists[comp->cur_id]), ins_mask, m);
	if(ps != 0 && ps != 1)
	{
		goto error;
	}

	/* part 6: k XI (= X + Indexes) */
	{
		uint8_t first_4b_xi;

		ret = rohc_list_build_XIs(comp, &(comp->lists[comp->cur_id]), ins_mask, ps,
		                          dest + counter, m /* TODO */, &first_4b_xi);
		if(ret < 0)
		{
			rohc_comp_list_warn(comp, "ROHC buffer is too short for the XI items");
			goto error;
		}
		if(ps == 0)
		{
			assert((first_4b_xi & 0x0f) == first_4b_xi);
			dest[ps_pos] |= first_4b_xi;
		}
		counter += ret;
	}

	/* part 7: n items (only unknown items) */
	for(k = 0; k < m; k++)
	{
		const struct rohc_list_item *const item = comp->lists[comp->cur_id].items[k];

		/* skip element if it present in the reference list */
		if(ins_mask[k] == 0 && item->known)
		{
			rc_list_debug(comp, "ignore element #%zu because it is present "
			              "in the reference list and already known", k);
			continue;
		}

		/* copy the list element if not known yet */
		if(!item->known)
		{
			rc_list_debug(comp, "add %zu-byte unknown item #%zu in packet",
			              item->length, k);
			assert(item->length > 1);
			dest[counter] = item->type & 0xff;
			memcpy(dest + counter + 1, item->data + 1, item->length - 1);
			counter += item->length;
		}
	}

	return counter;

error:
	return -1;
}


/**
 * @brief Determine the insertion bit mask
 *
 * @param comp           The list compressor
 * @param ref_list       The reference list
 * @param cur_list       The current list to create the insertion mask for
 * @param rem_mask       The removal mask for the list
 * @param[out] ins_mask  The insertion mask for the list
 * @param rohc_data      The ROHC packet being built
 * @param rohc_max_len   The max remaining length in the ROHC buffer
 * @return               The length of the insertion mask in case of success,
 *                       0 in case of failure
 */
static size_t rohc_list_compute_ins_mask(const struct list_comp *const comp,
                                         const struct rohc_list *const ref_list,
                                         const struct rohc_list *const cur_list,
                                         const uint8_t rem_mask[ROHC_LIST_ITEMS_MAX],
                                         uint8_t ins_mask[ROHC_LIST_ITEMS_MAX],
                                         uint8_t *const rohc_data,
                                         const size_t rohc_max_len)
{
	const size_t ref_m = ref_list->items_nr;
	const size_t m = cur_list->items_nr;
	size_t ins_mask_len;
	size_t ref_k; /* the index of the current element in reference list */
	size_t k; /* the index of the current element in current list */

	if(rohc_max_len == 0)
	{
		rohc_comp_list_warn(comp, "ROHC buffer is too short for the insertion mask");
		goto error;
	}

	/* 1- or 2-byte insertion mask? */
	rohc_data[0] = 0;
	if(m <= 7)
	{
		/* 7-bit mask is enough, so set first bit to 0 */
		rohc_data[0] &= ~(1 << 7);
		ins_mask_len = 1;
	}
	else
	{
		/* 15-bit mask is required, so set first bit to 1 */
		rohc_data[0] |= 1 << 7;
		ins_mask_len = 2;
	}
	if(rohc_max_len < ins_mask_len)
	{
		rohc_comp_list_warn(comp, "ROHC buffer is too short for the %zu-byte "
		                    "insertion mask", ins_mask_len);
		goto error;
	}

	/* first byte of the insertion mask */
	for(k = 0, ref_k = 0; k < m && k < 7; )
	{
		uint8_t bit;

		/* the item in reference list was removed with the remove scheme,
		 * ignore it */
		if(rem_mask[ref_k] == 1)
		{
			ref_k++;
			continue;
		}

		/* set bit to 1 in the insertion mask if the list item is not present
		   in the reference list */
		if(ref_k >= ref_m || cur_list->items[k] != ref_list->items[ref_k])
		{
			/* item is new, so put 1 in mask */
			bit = 1;
		}
		else
		{
			/* item isn't new, so put 0 in mask and skip the reference item */
			bit = 0;
			ref_k++;
		}
		ins_mask[k] = bit;
		rohc_data[0] |= bit << (6 - k);
		k++;
	}
	rc_list_debug(comp, "insertion bit mask (first byte) = 0x%02x", rohc_data[0]);

	/* second optional byte of the insertion mask */
	if(m <= 7)
	{
		rc_list_debug(comp, "no second byte of insertion bit mask");
	}
	else
	{
		rohc_data[1] = 0;

		for(k = 7; k < m && k < 15; )
		{
			uint8_t bit;

			/* the item in reference list was removed with the remove scheme,
			 * ignore it */
			if(rem_mask[ref_k] == 1)
			{
				ref_k++;
				continue;
			}

			/* set bit to 1 in the insertion mask if the list item is not present
			   in the reference list */
			if(ref_k >= ref_m || cur_list->items[k] != ref_list->items[ref_k])
			{
				/* item is new, so put 1 in mask */
				bit = 1;
			}
			else
			{
				/* item isn't new, so put 0 in mask and skip the reference item */
				bit = 0;
				ref_k++;
			}
			ins_mask[k] = bit;
			rohc_data[1] |= bit << (7 - (k - 7));
			k++;
		}
		rc_list_debug(comp, "insertion bit mask (second byte) = 0x%02x",
		              rohc_data[1]);
	}

	return ins_mask_len;

error:
	return 0;
}


/**
 * @brief Determine the removal bit mask
 *
 * @param comp           The list compressor
 * @param ref_list       The reference list
 * @param cur_list       The current list to create the removal mask for
 * @param[out] rem_mask  The removal mask for the list
 * @param rohc_data      The ROHC packet being built
 * @param rohc_max_len   The max remaining length in the ROHC buffer
 * @return               The length of the removal mask in case of success,
 *                       0 in case of failure
 */
static size_t rohc_list_compute_rem_mask(const struct list_comp *const comp,
                                         const struct rohc_list *const ref_list,
                                         const struct rohc_list *const cur_list,
                                         uint8_t rem_mask[ROHC_LIST_ITEMS_MAX],
                                         uint8_t *const rohc_data,
                                         const size_t rohc_max_len)
{
	const size_t ref_m = ref_list->items_nr;
	const size_t m = cur_list->items_nr;
	size_t rem_mask_len;
	size_t ref_k; /* the index of the current element in reference list */
	size_t k; /* the index of the current element in current list */

	if(rohc_max_len == 0)
	{
		rohc_comp_list_warn(comp, "ROHC buffer is too short for the removal mask");
		goto error;
	}

	/* 1- or 2-byte removal mask? */
	rohc_data[0] = 0xff;
	if(ref_m <= 7)
	{
		/* 7-bit mask is enough, so set first bit to 0 */
		rohc_data[0] &= ~(1 << 7);
		rem_mask_len = 1;
	}
	else
	{
		/* 15-bit mask is required, so set first bit to 1 */
		rohc_data[0] |= 1 << 7;
		rem_mask_len = 2;
	}
	if(rohc_max_len < rem_mask_len)
	{
		rohc_comp_list_warn(comp, "ROHC buffer is too short for the %zu-byte "
		                    "removal mask", rem_mask_len);
		goto error;
	}

	/* first byte of the removal mask */
	for(k = 0, ref_k = 0; ref_k < ref_m && ref_k < 8; ref_k++)
	{
		if(k < m && ref_list->items[ref_k] == cur_list->items[k])
		{
			/* item shall not be removed, clear its corresponding bit in the
			   removal bit mask */
			rc_list_debug(comp, "mark element #%zu of reference list as "
			              "'not to remove'", ref_k);
			rohc_data[0] &= ~(1 << (6 - ref_k));
			rem_mask[ref_k] = 0;
			k++;
		}
		else
		{
			/* item shall be removed, keep its corresponding bit set */
			rc_list_debug(comp, "mark element #%zu of reference list as "
			              "'to remove'", ref_k);
			rem_mask[ref_k] = 1;
		}
	}
	rc_list_debug(comp, "removal bit mask (first byte) = 0x%02x",
	              rohc_data[0]);

	/* second optional byte of the insertion mask */
	if(ref_m <= 7)
	{
		rc_list_debug(comp, "no second byte of removal bit mask");
	}
	else
	{
		rohc_data[1] = 0xff;
		for(ref_k = 7; ref_k < ref_m && ref_k < 15; ref_k++)
		{
			if(k < m && ref_list->items[ref_k] == cur_list->items[k])
			{
				/* item shall not be removed, clear its corresponding bit in the
				   removal bit mask */
				rc_list_debug(comp, "mark element #%zu of reference list as "
				              "'not to remove'", ref_k);
				rohc_data[1] &= ~(1 << (7 - (ref_k - 7)));
				rem_mask[ref_k] = 0;
				k++;
			}
			else
			{
				/* item shall be removed, keep its corresponding bit set */
				rc_list_debug(comp, "mark element #%zu of reference list as "
				              "'to remove'", ref_k);
				rem_mask[ref_k] = 1;
			}
		}
		rc_list_debug(comp, "removal bit mask (second byte) = 0x%02x",
		              rohc_data[1]);
	}

	return rem_mask_len;

error:
	return 0;
}


/**
 * @brief Determine whether we should use 4-bit or 8-bit indexes
 *
 * @param comp  The list compressor
 * @param list  The list to get the indexes size for
 * @param mask  The insertion mask for the list
 * @param m     The number of elements in current list
 * @return      0 for 4-bit indexes,
 *              1 for 8-bit indexes,
 *              2 for error
 */
static uint8_t rohc_list_compute_ps(const struct list_comp *const comp,
                                    const struct rohc_list *const list,
                                    const uint8_t mask[ROHC_LIST_ITEMS_MAX],
                                    const size_t m)
{
	uint8_t ext_types_count[ROHC_IPPROTO_MAX + 1] = { 0 };
	uint8_t ps = 0; /* 4-bit indexes by default */
	size_t k;

	for(k = 0; k < m && ps == 0; k++)
	{
		const struct rohc_list_item *const item = list->items[k];
		int index_table;

		/* one more occurrence of this item */
		if(ext_types_count[item->type] >= 255)
		{
			rohc_comp_list_warn(comp, "too many IPv6 extension header of type 0x%02x",
			                    item->type);
			goto error;
		}
		ext_types_count[item->type]++;

		/* get the index corresponding to the item type and the number of
		 * occurrences */
		index_table = comp->get_index_table(item->type, ext_types_count[item->type]);
		if(index_table < 0 || ((size_t) index_table) >= ROHC_LIST_MAX_ITEM)
		{
			rohc_comp_list_warn(comp, "failed to handle unknown IPv6 extension "
			                    "header of type 0x%02x", item->type);
			goto error;
		}

		if((mask[k] != 0 || !item->known) && index_table > 0x07)
		{
			ps = 1; /* 8-bit indexes are required */
		}
	}

	return ps;

error:
	return 2;
}


/**
 * @brief Build the list of indexes (XI)
 *
 * @param comp          The list compressor
 * @param list          The current list to get the indexes size for
 * @param mask          The insertion mask for the current list
 * @param ps            The size of the indexes: 1 for 8-bit XI, 0 for 4-bit XI
 * @param rohc_data     The ROHC packet being built
 * @param rohc_max_len  The max remaining length in the ROHC buffer
 * @param first_4b_xi   The first 4-bit XI item
 * @return              The length of the XI items in case of success,
 *                      -1 in case of failure
 */
static int rohc_list_build_XIs(const struct list_comp *const comp,
                               const struct rohc_list *const list,
                               const uint8_t mask[ROHC_LIST_ITEMS_MAX],
                               const size_t ps,
                               uint8_t *const rohc_data,
                               const size_t rohc_max_len,
                               uint8_t *const first_4b_xi)
{
	if(ps)
	{
		return rohc_list_build_XIs_8(comp, list, mask, rohc_data, rohc_max_len);
	}
	else
	{
		return rohc_list_build_XIs_4(comp, list, mask, rohc_data, rohc_max_len,
		                             first_4b_xi);
	}
}


/**
 * @brief Build the list of 8-bit indexes (XI)
 *
 * @param comp          The list compressor
 * @param list          The current list to get the indexes size for
 * @param mask          The insertion mask for the current list
 * @param rohc_data     The ROHC packet being built
 * @param rohc_max_len  The max remaining length in the ROHC buffer
 * @return              The length of the XI items in case of success,
 *                      -1 in case of failure
 */
static int rohc_list_build_XIs_8(const struct list_comp *const comp,
                                 const struct rohc_list *const list,
                                 const uint8_t mask[ROHC_LIST_ITEMS_MAX],
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len)
{
	uint8_t ext_types_count[ROHC_IPPROTO_MAX + 1] = { 0 };
	const size_t m = list->items_nr;
	size_t xi_len = 0;
	size_t k;

	/* write the m XI items, each XI item is stored on 8 bits */
	rc_list_debug(comp, "use 8-bit format for the %zu XIs", m);
	for(k = 0; k < m; k++)
	{
		const struct rohc_list_item *const item = list->items[k];
		int index_table;

		/* one more occurrence of this item */
		if(ext_types_count[item->type] >= 255)
		{
			rohc_comp_list_warn(comp, "too many IPv6 extension header of type 0x%02x",
			                    item->type);
			goto error;
		}
		ext_types_count[item->type]++;

		index_table = comp->get_index_table(item->type, ext_types_count[item->type]);
		assert(index_table >= 0);
		assert(((size_t) index_table) < ROHC_LIST_MAX_ITEM);

		/* skip element if it present in the reference list and compressor
		 * is confident that item is known by decompressor */
		if(mask[k] == 0 && item->known)
		{
			rc_list_debug(comp, "ignore element #%zu because it is present "
			              "in the reference list and already known", k);
			continue;
		}

		/* enough free room for the new XI item? */
		if(xi_len >= rohc_max_len)
		{
			rohc_comp_list_warn(comp, "ROHC buffer is too short for the XI items");
			goto error;
		}
		rohc_data[xi_len] = 0;

		/* set the X bit if item is not already known */
		if(!item->known)
		{
			rohc_data[xi_len] |= 1 << 7;
		}
		/* 7-bit Index */
		assert((index_table & 0x7f) == index_table);
		rohc_data[xi_len] |= (index_table & 0x7f);

		rc_list_debug(comp, "add 8-bit XI #%zu = 0x%x", k, rohc_data[xi_len]);

		/* byte is full, write to next one next time */
		xi_len++;
	}

	return xi_len;

error:
	return -1;
}


/**
 * @brief Build the list of 4-bit indexes (XI)
 *
 * @param comp          The list compressor
 * @param list          The current list to get the indexes size for
 * @param mask          The insertion mask for the current list
 * @param rohc_data     The ROHC packet being built
 * @param rohc_max_len  The max remaining length in the ROHC buffer
 * @param first_4b_xi   The first 4-bit XI item
 * @return              The length of the XI items in case of success,
 *                      -1 in case of failure
 */
static int rohc_list_build_XIs_4(const struct list_comp *const comp,
                                 const struct rohc_list *const list,
                                 const uint8_t mask[ROHC_LIST_ITEMS_MAX],
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len,
                                 uint8_t *const first_4b_xi)
{
	uint8_t ext_types_count[ROHC_IPPROTO_MAX + 1] = { 0 };
	const size_t m = list->items_nr;
	size_t xi_index = 0;
	size_t xi_len = 0;
	size_t k;

	/* write the m XI items, each XI item is stored on 4 bits */
	rc_list_debug(comp, "use 4-bit format for the %zu XIs", m);
	for(k = 0; k < m; k++)
	{
		const struct rohc_list_item *const item = list->items[k];
		int index_table;

		/* one more occurrence of this item */
		if(ext_types_count[item->type] >= 255)
		{
			rohc_comp_list_warn(comp, "too many IPv6 extension header of type 0x%02x",
			                    item->type);
			goto error;
		}
		ext_types_count[item->type]++;

		index_table = comp->get_index_table(item->type, ext_types_count[item->type]);
		assert(index_table >= 0);
		assert(((size_t) index_table) < ROHC_LIST_MAX_ITEM);

		/* skip element if it present in the reference list and compressor
		 * is confident that item is known by decompressor */
		if(mask[k] == 0 && item->known)
		{
			rc_list_debug(comp, "ignore element #%zu because it is present "
			              "in the reference list and already known", k);
			continue;
		}

		xi_index++;

		if(xi_index == 1)
		{
			/* first XI goes in the very first byte of the list
			 * along with the PS bit */
			(*first_4b_xi) = 0;

			/* set the X bit if item is not already known */
			if(!item->known)
			{
				(*first_4b_xi) |= 1 << 3;
			}
			/* 3-bit Index */
			assert((index_table & 0x07) == index_table);
			(*first_4b_xi) |= index_table & 0x07;

			rc_list_debug(comp, "add 4-bit XI #%zu in part 1 = 0x%x", k,
			              (*first_4b_xi) & 0x0f);
		}
		/* next XIs go after the insertion/removal masks: odd or even 4-bit XI? */
		else if((xi_index % 2) == 0)
		{
			/* even: use MSB part of the byte */

			/* enough free room for the new XI item? */
			if(xi_len >= rohc_max_len)
			{
				rohc_comp_list_warn(comp, "ROHC buffer is too short for the XI items");
				goto error;
			}

			/* first 4-bit XI, so clear the byte */
			rohc_data[xi_len] = 0;
			/* set the X bit if item is not already known */
			if(!item->known)
			{
				rohc_data[xi_len] |= 1 << 7;
			}
			/* 3-bit Index */
			assert((index_table & 0x07) == index_table);
			rohc_data[xi_len] |= (index_table & 0x07) << 4;

			rc_list_debug(comp, "add 4-bit XI #%zu in MSB = 0x%x", k,
			              (rohc_data[xi_len] & 0xf0) >> 4);
		}
		else
		{
			/* odd: use LSB part of the byte */

			/* set the X bit if item is not already known */
			if(!item->known)
			{
				rohc_data[xi_len] |= 1 << 3;
			}
			/* 3-bit Index */
			assert((index_table & 0x07) == index_table);
			rohc_data[xi_len] |= (index_table & 0x07) << 0;

			rc_list_debug(comp, "add 4-bit XI #%zu in LSB = 0x%x",
			              k + 1, rohc_data[xi_len] & 0x0f);

			/* byte is full, write to next one next time */
			xi_len++;
		}
	}

	/* is padding required? */
	if(xi_index > 1 && (xi_index % 2) == 0)
	{
		/* zero the padding bits */
		rc_list_debug(comp, "add 4-bit padding in LSB");
		rohc_data[xi_len] &= 0xf0;

		/* byte is full, write to next one next time */
		xi_len++;
	}

	return xi_len;

error:
	return -1;
}

