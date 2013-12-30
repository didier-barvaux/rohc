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
 * @file   /comp/schemes/list.c
 * @brief  ROHC generic list compression
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "schemes/list.h"

#ifndef __KERNEL__
#  include <string.h>
#endif


static int rohc_list_decide_type(struct list_comp *const comp)
	__attribute__((warn_unused_result, nonnull(1)));

static int rohc_list_encode_type_0(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_encode_type_1(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_encode_type_2(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_encode_type_3(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
	__attribute__((warn_unused_result, nonnull(1, 2)));



/**
* @brief Detect changes withint the list of IPv6 extension headers
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
	/* TODO: don't mess with the context except for tmp, save in update_context only in case of success */
	unsigned int new_cur_id = ROHC_LIST_GEN_ID_NONE;
	unsigned char *ext;
	uint8_t ext_type;
	int ret;

	/* reset the list of the current packet */
	rohc_list_reset(&comp->pkt_list);

	/* get the next known IP extension in packet */
	ext = ip_get_next_ext_from_ip(ip, &ext_type);
	if(ext == NULL)
	{
		/* there is no list of IPv6 extension headers in the current packet */
		rc_list_debug(comp, "there is no IPv6 extension in packet\n");
	}
	else
	{
		/* there is one extension or more */
		rc_list_debug(comp, "there is at least one IPv6 extension in packet\n");

		/* parse all extension headers:
		 *  - update the related entries in the translation table,
		 *  - create the list for the packet */
		do
		{
			int index_table;
			bool entry_changed = false;

			/* find the best item to encode the extension in translation table */
			index_table = comp->get_index_table(ext_type);
			if(index_table < 0 || index_table >= ROHC_LIST_MAX_ITEM)
			{
				rohc_warning(comp, ROHC_TRACE_COMP, comp->profile_id,
				             "failed to handle unknown IPv6 extension header of "
				             "type 0x%02x\n", ext_type);
				goto error;
			}

			/* update item in translation table if it changed */
			ret = rohc_list_item_update_if_changed(comp->cmp_item,
			                                       &comp->trans_table[index_table],
			                                       ext_type, ext, comp->get_size(ext));
			if(ret < 0)
			{
				rc_list_debug(comp, "failed to update entry #%d in translation "
				              "table\n", index_table);
				goto error;
			}
			else if(ret == 1)
			{
				rc_list_debug(comp, "  entry #%d updated in translation table\n",
				              index_table);
				entry_changed = true;
			}

			/* update current list in context */
			comp->pkt_list.items[comp->pkt_list.items_nr] =
				&comp->trans_table[index_table];
			comp->pkt_list.items_nr++;

			rc_list_debug(comp, "  extension #%zu: extension type "
			              "%u uses %s entry #%d in translation table (%s entry "
			              "sent %zu/%zu times)\n", comp->pkt_list.items_nr,
			              ext_type, (entry_changed ? "updated" : "existing"),
			              index_table, comp->trans_table[index_table].known ?
			              "known" : "not-yet-known",
			              comp->trans_table[index_table].counter,
			              comp->list_trans_nr);
		}
		while((ext = ip_get_next_ext_from_ext(ext, &ext_type)) != NULL &&
		      comp->pkt_list.items_nr < ROHC_LIST_ITEMS_MAX);

		/* too many extensions in packet? */
		if(ext != NULL)
		{
			rc_list_debug(comp, "list of IPv6 extension headers too large for "
			              "compressor internal limits\n");
			goto error;
		}
	}

	/* now that translation table is updated and packet list is generated,
	 * search for a context list with the same structure:
	 *  - check the reference list first as it is probably the correct one,
	 *  - then check the other lists */
	if(comp->ref_id != ROHC_LIST_GEN_ID_NONE &&
	   rohc_list_equal(&comp->pkt_list, &comp->lists[comp->ref_id]))
	{
		/* reference list matches, no need for a new list */
		rc_list_debug(comp, "send reference list with gen_id = %u\n",
		              comp->ref_id);
		new_cur_id = comp->ref_id;
	}
	else
	{
		unsigned int matched_existing_list = ROHC_LIST_GEN_ID_NONE;
		unsigned int gen_id;

		/* search for a list that matches the packet one, avoid the reference
		 * list that we already checked, stop on first unused list */
		for(gen_id = 0; matched_existing_list == ROHC_LIST_GEN_ID_NONE &&
		                gen_id <= ROHC_LIST_GEN_ID_MAX &&
		                comp->lists[gen_id].counter > 0; gen_id++)
		{
			if(gen_id != comp->ref_id &&
			   rohc_list_equal(&comp->pkt_list, &comp->lists[gen_id]))
			{
				rc_list_debug(comp, "current list matches the existing list "
				              "with gen_id %u\n", gen_id);
				matched_existing_list = gen_id;
			}
		}

		if(matched_existing_list != ROHC_LIST_GEN_ID_NONE)
		{
			gen_id = matched_existing_list;
			rc_list_debug(comp, "send existing context list with gen_id %u "
			              "(already sent %zu times)\n", gen_id,
			              comp->lists[gen_id].counter);
		}
		else
		{
			/* get the next free gen_id (avoid re-using ref_id) */
			gen_id &= ROHC_LIST_GEN_ID_MAX;
			if(gen_id == comp->ref_id)
			{
				gen_id++;
				gen_id &= ROHC_LIST_GEN_ID_MAX;
			}
			rc_list_debug(comp, "no context list matches the packet list, "
			              "create a new one with gen_id %u\n", gen_id);
			assert(comp->lists[gen_id].id == gen_id);
			memcpy(comp->lists[gen_id].items, comp->pkt_list.items,
					 ROHC_LIST_ITEMS_MAX);
			comp->lists[gen_id].items_nr = comp->pkt_list.items_nr;
			comp->lists[gen_id].counter = 0;
		}

		new_cur_id = gen_id;
	}

	/* do we need to send some bits of the compressed list? */
	if(new_cur_id != comp->cur_id)
	{
		rc_list_debug(comp, "send some bits for extension header list of the "
		              "outer IPv6 header because it changed\n");
		*list_struct_changed = true;
		*list_content_changed = true;
	}
	else if(new_cur_id != ROHC_LIST_GEN_ID_NONE &&
	        comp->lists[new_cur_id].counter < comp->list_trans_nr)
	{
		rc_list_debug(comp, "send some bits for extension header list of the "
		              "outer IPv6 header because it was not sent enough times\n");
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
			              "not sent enough times\n");
		}
	}

	comp->cur_id = new_cur_id;

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
 * @param ps       The size of the index
 * @param size     The number of element in current list
 * @return         The new position in the rohc-packet-under-build buffer,
 *                 -1 in case of error
 */
int rohc_list_encode(struct list_comp *const comp,
                     unsigned char *const dest,
                     int counter,
                     const int ps,
                     const int size)
{
	int encoding_type;

	/* sanity checks */
	assert(comp != NULL);
	assert(dest != NULL);
	assert(size >= 0);

	/* determine which encoding type is required for the current list ? */
	encoding_type = rohc_list_decide_type(comp);
	assert(encoding_type >= 0 && encoding_type <= 3);
	rc_list_debug(comp, "use list encoding type %d\n", encoding_type);

	/* encode the current list according to the encoding type */
	switch(encoding_type)
	{
		case 0: /* Encoding type 0 (generic scheme) */
			counter = rohc_list_encode_type_0(comp, dest, counter, ps);
			break;
		case 1: /* Encoding type 1 (insertion only scheme) */
			counter = rohc_list_encode_type_1(comp, dest, counter, ps);
			break;
		case 2: /* Encoding type 2 (removal only scheme) */
			counter = rohc_list_encode_type_2(comp, dest, counter, ps);
			break;
		case 3: /* encoding type 3 (remove then insert scheme) */
			counter = rohc_list_encode_type_3(comp, dest, counter, ps);
			break;
		default:
			rohc_assert(comp, ROHC_TRACE_COMP, comp->profile_id,
			            false, error, "unknown encoding type for list "
			            "compression\n");
	}
	if(counter < 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, comp->profile_id,
		             "failed to encode list type %d\n", encoding_type);
		goto error;
	}

	rc_list_debug(comp, "send list with generation ID %u for the #%zu time\n",
	              comp->cur_id, comp->lists[comp->cur_id].counter + 1);

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

	/* nothing to do if there is no list or if it is an anonymous list */
	if(comp->cur_id == ROHC_LIST_GEN_ID_NONE ||
	   comp->cur_id == ROHC_LIST_GEN_ID_ANON)
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
		if(comp->lists[comp->cur_id].counter >= comp->list_trans_nr)
		{
			if(comp->ref_id != ROHC_LIST_GEN_ID_NONE)
			{
				/* replace previous reference list */
				rc_list_debug(comp, "replace the reference list (gen_id = %u) by "
				              "current list (gen_id = %u) because it was "
				              "transmitted at least L = %zu times\n",
				              comp->ref_id, comp->cur_id, comp->list_trans_nr);
			}
			else
			{
				/* first reference list */
				rc_list_debug(comp, "use the current list (gen_id = %u) as the "
				              "first reference list because it was transmitted "
				              "at least L = %zu times\n", comp->cur_id,
				              comp->list_trans_nr);
			}
			comp->ref_id = comp->cur_id;
		}
	}
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
		              "reference list yet\n");
		encoding_type = 0;
	}
	else if(comp->lists[comp->cur_id].counter > 0)
	{
		/* the structure of the list did not change, so use encoding type 0 */
		rc_list_debug(comp, "use list encoding type 0 because the structure of "
		              "the list did not change (items may be sent if they "
		              "changed)\n");
		encoding_type = 0;
	}
	else if(comp->lists[comp->cur_id].items_nr <=
	        comp->lists[comp->ref_id].items_nr)
	{
		/* the structure of the list changed, there are fewer items in the
		 * current list than in the reference list: are all the items of the
		 * current list in the reference list? */
		if(rohc_list_supersede(&comp->lists[comp->ref_id],
		                       &comp->lists[comp->cur_id]))
		{
			/* all the items of the current list are present in the reference
			 * list, so the 'Removal Only scheme' (type 2) may be used to
			 * encode the current list */
			encoding_type = 2;
		}
		else
		{
			/* some items of the current list are not present in the reference
			 * list, so the 'Remove Then Insert scheme' (type 3) is required
			 * to encode the current list */
			encoding_type = 3;
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
 * @param ps       The size of the index
 * @return         The new position in the rohc-packet-under-build buffer
 */
static int rohc_list_encode_type_0(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
{
	const uint8_t et = 0; /* list encoding type 0 */
	uint8_t gp;
	int m; /* the number of elements in current list = number of XIs */
	int k; /* the index of the current element in list */

	assert(comp != NULL);
	assert(comp->cur_id != ROHC_LIST_GEN_ID_NONE);
	assert(dest != NULL);

	/* retrieve the number of items in the current list */
	m = comp->lists[comp->cur_id].items_nr;
	assert(m <= ROHC_LIST_ITEMS_MAX);

	/* part 1: ET, GP, PS, CC */
	gp = (comp->cur_id != ROHC_LIST_GEN_ID_ANON);
	rc_list_debug(comp, "ET = %d, GP = %d, PS = %d, CC = m = %d\n",
	              et, gp, ps, m);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	dest[counter] |= (ps & 0x01) << 4;
	dest[counter] |= m & 0x0f;
	counter++;

	/* part 2: gen_id (if not anonymous list) */
	if(comp->cur_id != ROHC_LIST_GEN_ID_ANON)
	{
		dest[counter] = comp->cur_id & ROHC_LIST_GEN_ID_MAX;
		rc_list_debug(comp, "gen_id = 0x%02x\n", dest[counter]);
		counter++;
	}

	/* part 3: m XI (= X + Indexes) */
	if(ps)
	{
		/* each XI item is stored on 8 bits */
		rc_list_debug(comp, "use 8-bit format for the %d XIs\n", m);

		/* write all XIs in packet */
		for(k = 0; k < m; k++, counter++)
		{
			const struct rohc_list_item *const item =
				comp->lists[comp->cur_id].items[k];
			const int index_table = comp->get_index_table(item->type);
			if(index_table < 0 || index_table >= ROHC_LIST_MAX_ITEM)
			{
				rohc_warning(comp, ROHC_TRACE_COMP, comp->profile_id,
				             "failed to handle unknown IPv6 extension header of "
				             "type 0x%02x\n", item->type);
				goto error;
			}

			dest[counter] = 0;
			/* set the X bit if item is not already known */
			if(!item->known)
			{
				dest[counter] |= 1 << 7;
			}
			/* 7-bit Index */
			dest[counter] |= index_table & 0x7f;

			rc_list_debug(comp, "add 8-bit XI #%d = 0x%x\n", k, dest[counter]);
		}
	}
	else
	{
		/* each XI item is stored on 4 bits */
		rc_list_debug(comp, "use 4-bit format for the %d XIs\n", m);

		/* write all XIs in packet 2 by 2 */
		for(k = 0; k < m; k += 2, counter++)
		{
			const struct rohc_list_item *const item =
				comp->lists[comp->cur_id].items[k];
			const int index_table = comp->get_index_table(item->type);
			if(index_table < 0 || index_table >= ROHC_LIST_MAX_ITEM)
			{
				rohc_warning(comp, ROHC_TRACE_COMP, comp->profile_id,
				             "failed to handle unknown IPv6 extension header of "
				             "type 0x%02x\n", item->type);
				goto error;
			}

			dest[counter] = 0;

			/* first 4-bit XI */
			/* set the X bit if item is not already known */
			if(!item->known)
			{
				dest[counter] |= 1 << 7;
			}
			/* 3-bit Index */
			dest[counter] |= (index_table & 0x07) << 4;

			rc_list_debug(comp, "add 4-bit XI #%d in MSB = 0x%x\n", k,
			              (dest[counter] & 0xf0) >> 4);

			/* second 4-bit XI or padding? */
			if((k + 1) < m)
			{
				const struct rohc_list_item *const item2 =
					comp->lists[comp->cur_id].items[k + 1];
				const int index_table2 = comp->get_index_table(item2->type);
				if(index_table2 < 0 || index_table2 >= ROHC_LIST_MAX_ITEM)
				{
					rohc_warning(comp, ROHC_TRACE_COMP, comp->profile_id,
					             "failed to handle unknown IPv6 extension header "
					             "of type 0x%02x\n", item2->type);
					goto error;
				}

				/* set the X bit if item is not already known */
				if(!item2->known)
				{
					dest[counter] |= 1 << 3;
				}
				/* 3-bit Index */
				dest[counter] |= (index_table2 & 0x07) << 0;

				rc_list_debug(comp, "add 4-bit XI #%d in LSB = 0x%x\n", k + 1,
				              dest[counter] & 0x0f);
			}
			else
			{
				/* zero the padding bits */
				rc_list_debug(comp, "add 4-bit padding in LSB\n");
				dest[counter] &= 0xf0;
			}
		}
	}

	/* part 4: n items (only unknown items) */
	for(k = 0; k < m; k++)
	{
		const struct rohc_list_item *const item =
			comp->lists[comp->cur_id].items[k];

		/* copy the list element if not known yet */
		if(!item->known)
		{
			rc_list_debug(comp, "add %zd-byte not-yet-known item #%d in "
			              "packet\n", item->length, k);
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
 * @param ps       The size of the index
 * @return         The new position in the rohc-packet-under-build buffer
 */
static int rohc_list_encode_type_1(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
{
	const uint8_t et = 1; /* list encoding type 1 */
	uint8_t gp;
	uint8_t mask[ROHC_LIST_ITEMS_MAX] = { 0 };
	size_t mask_size;
	size_t m; /* the number of elements in current list = number of XIs */
	size_t k; /* the index of the current element in current list */
	size_t ref_k; /* the index of the current element in reference list */

	assert(comp != NULL);
	assert(comp->ref_id != ROHC_LIST_GEN_ID_NONE);
	assert(comp->cur_id != ROHC_LIST_GEN_ID_NONE);
	assert(dest != NULL);

	/* retrieve the number of items in the current list */
	m = comp->lists[comp->cur_id].items_nr;
	assert(m <= ROHC_LIST_ITEMS_MAX);

	/* part 1: ET, GP, PS, CC */
	gp = (comp->cur_id != ROHC_LIST_GEN_ID_ANON);
	rc_list_debug(comp, "ET = %d, GP = %d, PS = %d\n", et, gp, ps);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	dest[counter] |= (ps & 0x01) << 4;
	dest[counter] &= 0xf0; /* clear the 4 LSB bits reserved for 1st XI */
	counter++;

	/* part 2: gen_id (if not anonymous list) */
	if(comp->cur_id != ROHC_LIST_GEN_ID_ANON)
	{
		dest[counter] = comp->cur_id & 0xff;
		rc_list_debug(comp, "gen_id = 0x%02x\n", dest[counter]);
		counter++;
	}

	/* part 3: ref_id */
	dest[counter] = comp->ref_id & 0xff;
	rc_list_debug(comp, "ref_id = 0x%02x\n", dest[counter]);
	counter++;

	/* part 4: insertion mask (first byte) */
	dest[counter] = 0;
	if(m <= 7)
	{
		/* 7-bit mask is enough, so set first bit to 0 */
		dest[counter] &= ~(1 << 7);
	}
	else
	{
		/* 15-bit mask is required, so set first bit to 1 */
		dest[counter] |= 1 << 7;
	}
	for(k = 0, ref_k = 0; k < m && k < 7; k++)
	{
		uint8_t bit;

		/* set bit to 1 in the insertion mask if the list item is not present
		   in the reference list */
		if(ref_k >= comp->lists[comp->ref_id].items_nr ||
		   comp->lists[comp->cur_id].items[k] !=
		   comp->lists[comp->ref_id].items[ref_k])
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
		mask[k] = bit;
		dest[counter] |= bit << (6 - k);
	}
	mask_size = 1;
	rc_list_debug(comp, "insertion mask = 0x%02x\n", dest[counter]);
	counter++;

	/* part 4: insertion mask (second optional byte) */
	if(m > 7)
	{
		for(k = 7; k < m && k < 15; k++)
		{
			uint8_t bit;

			/* set bit to 1 in the insertion mask if the list item is not present
			   in the reference list */
			if(ref_k >= comp->lists[comp->ref_id].items_nr ||
			   comp->lists[comp->cur_id].items[k] !=
			   comp->lists[comp->ref_id].items[ref_k])
			{
				/* item is new, so put 1 in mask */
				bit = 1;
				dest[counter] |= 1 << (7 - (k - 7));
			}
			else
			{
				/* item isn't new, so put 0 in mask and skip the reference item */
				bit = 0;
				ref_k++;
			}
			mask[k] = bit;
			dest[counter] |= bit << (7 - (k - 7));
		}
		mask_size = 2;
		rc_list_debug(comp, "insertion mask (2nd byte) = 0x%02x\n", dest[counter]);
		counter++;
	}

	/* part 5: k XI (= X + Indexes) */
	if(ps)
	{
		size_t xi_index = 0;

		/* each XI item is stored on 8 bits */
		rc_list_debug(comp, "use 8-bit format for the %d XIs\n", m);

		for(k = 0; k < m; k++)
		{
			const struct rohc_list_item *const item =
				comp->lists[comp->cur_id].items[k];
			const int index_table = comp->get_index_table(item->type);
			if(index_table < 0 || index_table >= ROHC_LIST_MAX_ITEM)
			{
				rohc_warning(comp, ROHC_TRACE_COMP, comp->profile_id,
				             "failed to handle unknown IPv6 extension header "
				             "of type 0x%02x\n", item->type);
				goto error;
			}

			/* skip element if it present in the reference list and compressor
			 * is confident that item is known by decompressor */
			if(mask[k] == 0 && item->known)
			{
				rc_list_debug(comp, "ignore element #%d because it is present "
				              "in the reference list and already known\n", k);
				continue;
			}

			xi_index++;

			dest[counter] = 0;

			/* set the X bit if item is not already known */
			if(!item->known)
			{
				dest[counter] |= 1 << 7;
			}
			/* 7-bit Index */
			dest[counter] |= index_table & 0x7f;

			rc_list_debug(comp, "add 8-bit XI #%d = 0x%x\n", k, dest[counter]);

			/* byte is full, write to next one next time */
			counter++;
		}
	}
	else
	{
		size_t xi_index = 0;

		/* each XI item is stored on 4 bits */
		rc_list_debug(comp, "use 4-bit format for the %d XIs\n", m);

		for(k = 0; k < m; k++)
		{
			const struct rohc_list_item *const item =
				comp->lists[comp->cur_id].items[k];
			const int index_table = comp->get_index_table(item->type);
			if(index_table < 0 || index_table >= ROHC_LIST_MAX_ITEM)
			{
				rohc_warning(comp, ROHC_TRACE_COMP, comp->profile_id,
				             "failed to handle unknown IPv6 extension header "
				             "of type 0x%02x\n", item->type);
				goto error;
			}

			/* skip element if it present in the reference list and compressor
			 * is confident that item is known by decompressor */
			if(mask[k] == 0 && item->known)
			{
				rc_list_debug(comp, "ignore element #%d because it is present "
				              "in the reference list and already known\n", k);
				continue;
			}

			xi_index++;

			if(xi_index == 1)
			{
				/* first XI goes in part 1 */

				/* set the X bit if item is not already known */
				if(!item->known)
				{
					dest[counter - (3 + mask_size)] |= 1 << 3;
				}
				/* 3-bit Index */
				dest[counter - (3 + mask_size)] |= index_table & 0x07;

				rc_list_debug(comp, "add 4-bit XI #%d in part 1 = 0x%x\n", k,
				              (dest[counter - (3 + mask_size)] & 0x0f) >> 4);
			}
			else
			{
				/* next XIs goes in part 5 */
				dest[counter] = 0;

				/* odd or even 4-bit XI ? */
				if((xi_index % 2) == 0)
				{
					/* use MSB part of the byte */

					/* set the X bit if item is not already known */
					if(!item->known)
					{
						dest[counter] |= 1 << 7;
					}
					/* 3-bit Index */
					dest[counter] |= (index_table & 0x07) << 4;

					rc_list_debug(comp, "add 4-bit XI #%d in MSB = 0x%x\n", k,
					              (dest[counter] & 0xf0) >> 4);
				}
				else
				{
					/* use LSB part of the byte */

					/* set the X bit if item is not already known */
					if(!item->known)
					{
						dest[counter] |= 1 << 3;
					}
					/* 3-bit Index */
					dest[counter] |= (index_table & 0x07) << 0;

					rc_list_debug(comp, "add 4-bit XI #%d = 0x%x in LSB\n",
					              k + 1, dest[counter] & 0xf0);

					/* byte is full, write to next one next time */
					counter++;
				}
			}
		}

		/* is padding required? */
		if(xi_index > 1 && (xi_index % 2) == 0)
		{
			/* zero the padding bits */
			rc_list_debug(comp, "add 4-bit padding in LSB\n");
			dest[counter] &= 0xf0;

			/* byte is full, write to next one next time */
			counter++;
		}
	}

	/* part 6: n items (only unknown items) */
	for(k = 0; k < m; k++)
	{
		const struct rohc_list_item *const item =
			comp->lists[comp->cur_id].items[k];

		/* skip element if it present in the reference list */
		if(mask[k] == 0 && item->known)
		{
			rc_list_debug(comp, "ignore element #%d because it is present "
			              "in the reference list and already known\n", k);
			continue;
		}

		/* copy the list element if not known yet */
		if(!item->known)
		{
			rc_list_debug(comp, "add %zd-byte unknown item #%d in packet\n",
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
 * @param ps       The size of the index
 * @return         The new position in the rohc-packet-under-build buffer
 */
static int rohc_list_encode_type_2(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
{
	const uint8_t et = 2; /* list encoding type 2 */
	uint8_t gp;
	size_t count; /* size of reference list */
	size_t k; /* the index of the current element in current list */
	size_t ref_k; /* the index of the current element in reference list */

	assert(comp != NULL);
	assert(comp->ref_id != ROHC_LIST_GEN_ID_NONE);
	assert(comp->cur_id != ROHC_LIST_GEN_ID_NONE);
	assert(dest != NULL);

	/* retrieve the number of items in the reference list */
	count = comp->lists[comp->ref_id].items_nr;
	assert(count <= ROHC_LIST_ITEMS_MAX);

	/* part 1: ET, GP, res and Count */
	gp = (comp->cur_id != ROHC_LIST_GEN_ID_ANON);
	rc_list_debug(comp, "ET = %d, GP = %d, Count = %d\n", et, gp, count);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	dest[counter] &= ~(0x01 << 4); /* clear the reserved bit */
	dest[counter] |= count & 0x0f;
	counter++;

	/* part 2: gen_id (if not anonymous list) */
	if(comp->cur_id != ROHC_LIST_GEN_ID_ANON)
	{
		dest[counter] = comp->cur_id & ROHC_LIST_GEN_ID_MAX;
		rc_list_debug(comp, "gen_id = 0x%02x\n", dest[counter]);
		counter++;
	}

	/* part 3: ref_id */
	dest[counter] = comp->ref_id & 0xff;
	rc_list_debug(comp, "ref_id = 0x%02x\n", dest[counter]);
	counter++;

	/* part 4: removal bit mask (first byte) */
	dest[counter] = 0xff;
	if(count <= 7)
	{
		/* 7-bit mask is enough, so set first bit to 0 */
		dest[counter] &= ~(1 << 7);
	}
	else
	{
		/* 15-bit mask is required, so set first bit to 1 */
		dest[counter] |= 1 << 7;
	}
	for(k = 0, ref_k = 0; ref_k < count && ref_k < 7; ref_k++)
	{
		if(k < comp->lists[comp->cur_id].items_nr &&
		   comp->lists[comp->ref_id].items[ref_k] ==
		   comp->lists[comp->cur_id].items[k])
		{
			/* item shall not be removed, clear its corresponding bit in the
			   removal bit mask */
			rc_list_debug(comp, "mark element #%zu of reference list as "
			              "'not to remove'\n", ref_k);
			dest[counter] &= ~(1 << (6 - ref_k));
			k++;
		}
		else
		{
			/* item shall be removed, keep its corresponding bit set */
			rc_list_debug(comp, "mark element #%zu of reference list as "
			              "'to remove'\n", ref_k);
		}
	}
	rc_list_debug(comp, "removal bit mask (first byte) = 0x%02x\n",
	              dest[counter]);
	counter++;

	/* part 4: removal bit mask (second optional byte) */
	if(count > 7)
	{
		dest[counter] = 0xff;
		for(ref_k = 7; ref_k < count && ref_k < 15; ref_k++)
		{
			if(k < comp->lists[comp->cur_id].items_nr &&
			   comp->lists[comp->ref_id].items[ref_k] ==
			   comp->lists[comp->cur_id].items[k])
			{
				/* item shall not be removed, clear its corresponding bit in the
				   removal bit mask */
				rc_list_debug(comp, "mark element #%zu of reference list as "
				              "'not to remove'\n", ref_k);
				dest[counter] &= ~(1 << (7 - (ref_k - 7)));
				k++;
			}
			else
			{
				/* item shall be removed, keep its corresponding bit set */
				rc_list_debug(comp, "mark element #%zu of reference list as "
				              "'to remove'\n", ref_k);
			}
		}
		rc_list_debug(comp, "removal bit mask (second byte) = 0x%02x\n",
		              dest[counter]);
		counter++;
	}
	else
	{
		rc_list_debug(comp, "no second byte of removal bit mask\n");
	}

	return counter;
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
 * @param ps       The size of the index
 * @return         The new position in the rohc-packet-under-build buffer
 */
static int rohc_list_encode_type_3(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
{
	const uint8_t et = 3; /* list encoding type 3 */
	uint8_t gp;
	uint8_t rem_mask[ROHC_LIST_ITEMS_MAX] = { 0 };
	uint8_t ins_mask[ROHC_LIST_ITEMS_MAX] = { 0 };
	size_t count; /* size of reference list */
	size_t m; /* the number of elements in current list = number of XIs */
	size_t k; /* the index of the current element in current list */
	size_t ref_k; /* the index of the current element in reference list */
	size_t mask_size = 0; /* the cumulative size of insertion/removal masks */

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

	/* part 1: ET, GP, PS */
	gp = (comp->cur_id != ROHC_LIST_GEN_ID_ANON);
	rc_list_debug(comp, "ET = %d, GP = %d, PS = %d\n", et, gp, ps);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	dest[counter] |= (ps & 0x01) << 4;
	dest[counter] &= 0xf0; /* clear the 4 LSB bits reserved for 1st XI */
	counter++;

	/* part 2: gen_id (if not anonymous list) */
	if(comp->cur_id != ROHC_LIST_GEN_ID_ANON)
	{
		dest[counter] = comp->cur_id & ROHC_LIST_GEN_ID_MAX;
		rc_list_debug(comp, "gen_id = 0x%02x\n", dest[counter]);
		counter++;
	}

	/* part 3: ref_id */
	dest[counter] = comp->ref_id & 0xff;
	rc_list_debug(comp, "ref_id = 0x%02x\n", dest[counter]);
	counter++;

	/* part 4: removal bit mask (first byte) */
	dest[counter] = 0xff;
	if(count <= 7)
	{
		/* 7-bit mask is enough, so set first bit to 0 */
		dest[counter] &= ~(1 << 7);
	}
	else
	{
		/* 15-bit mask is required, so set first bit to 1 */
		dest[counter] |= 1 << 7;
	}
	for(k = 0, ref_k = 0; ref_k < count && ref_k < 7; ref_k++)
	{
		if(k < comp->lists[comp->cur_id].items_nr &&
		   comp->lists[comp->ref_id].items[ref_k] ==
		   comp->lists[comp->cur_id].items[k])
		{
			/* item shall not be removed, clear its corresponding bit in the
			   removal bit mask */
			rc_list_debug(comp, "mark element #%zu of reference list as "
			              "'not to remove'\n", ref_k);
			dest[counter] &= ~(1 << (6 - ref_k));
			rem_mask[ref_k] = 0;
			k++;
		}
		else
		{
			/* item shall be removed, keep its corresponding bit set */
			rc_list_debug(comp, "mark element #%zu of reference list as "
			              "'to remove'\n", ref_k);
			rem_mask[ref_k] = 1;
		}
	}
	rc_list_debug(comp, "removal bit mask (first byte) = 0x%02x\n",
	              dest[counter]);
	counter++;
	mask_size++;

	/* part 4: removal bit mask (second optional byte) */
	if(count > 7)
	{
		dest[counter] = 0xff;
		for(ref_k = 7; ref_k < count && ref_k < 15; ref_k++)
		{
			if(k < comp->lists[comp->cur_id].items_nr &&
			   comp->lists[comp->ref_id].items[ref_k] ==
			   comp->lists[comp->cur_id].items[k])
			{
				/* item shall not be removed, clear its corresponding bit in the
				   removal bit mask */
				rc_list_debug(comp, "mark element #%zu of reference list as "
				              "'not to remove'\n", ref_k);
				dest[counter] &= ~(1 << (7 - (ref_k - 7)));
				rem_mask[ref_k] = 0;
				k++;
			}
			else
			{
				/* item shall be removed, keep its corresponding bit set */
				rc_list_debug(comp, "mark element #%zu of reference list as "
				              "'to remove'\n", ref_k);
				rem_mask[ref_k] = 1;
			}
		}
		rc_list_debug(comp, "removal bit mask (second byte) = 0x%02x\n",
		              dest[counter]);
		counter++;
		mask_size++;
	}
	else
	{
		rc_list_debug(comp, "no second byte of removal bit mask\n");
	}

	/* part 5: insertion mask */
	dest[counter] = 0;
	if(m <= 7)
	{
		/* 7-bit mask is enough, so set first bit to 0 */
		dest[counter] &= ~(1 << 7);
	}
	else
	{
		/* 15-bit mask is required, so set first bit to 1 */
		dest[counter] |= 1 << 7;
	}
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
		if(ref_k >= comp->lists[comp->ref_id].items_nr ||
		   comp->lists[comp->cur_id].items[k] !=
		   comp->lists[comp->ref_id].items[ref_k])
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
		dest[counter] |= bit << (6 - k);
		k++;
	}
	rc_list_debug(comp, "insertion bit mask (first byte) = 0x%02x\n",
	              dest[counter]);
	counter++;
	mask_size++;

	/* part 4: insertion mask (second optional byte) */
	if(m > 7)
	{
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
			if(ref_k >= comp->lists[comp->ref_id].items_nr ||
			   comp->lists[comp->cur_id].items[k] !=
			   comp->lists[comp->ref_id].items[ref_k])
			{
				/* item is new, so put 1 in mask */
				bit = 1;
				dest[counter] |= 1 << (7 - (k - 7));
			}
			else
			{
				/* item isn't new, so put 0 in mask and skip the reference item */
				bit = 0;
				ref_k++;
			}
			ins_mask[k] = bit;
			dest[counter] |= bit << (7 - (k - 7));
			k++;
		}
		rc_list_debug(comp, "insertion bit mask (second byte) = 0x%02x\n",
		              dest[counter]);
		counter++;
		mask_size++;
	}
	else
	{
		rc_list_debug(comp, "no second byte of insertion bit mask\n");
	}

	/* part 6: k XI (= X + Indexes) */
	/* next bytes: indexes */
	if(ps)
	{
		size_t xi_index = 0;

		/* each XI item is stored on 8 bits */
		rc_list_debug(comp, "use 8-bit format for the %d XIs\n", m);

		for(k = 0; k < m; k++)
		{
			const struct rohc_list_item *const item =
				comp->lists[comp->cur_id].items[k];
			const int index_table = comp->get_index_table(item->type);
			if(index_table < 0 || index_table >= ROHC_LIST_MAX_ITEM)
			{
				rohc_warning(comp, ROHC_TRACE_COMP, comp->profile_id,
				             "failed to handle unknown IPv6 extension header "
				             "of type 0x%02x\n", item->type);
				goto error;
			}

			/* skip element if it present in the reference list and compressor
			 * is confident that item is known by decompressor */
			if(ins_mask[k] == 0 && item->known)
			{
				rc_list_debug(comp, "ignore element #%d because it is present "
				              "in the reference list and already known\n", k);
				continue;
			}

			xi_index++;

			dest[counter]  = 0;

			/* set the X bit if item is not already known */
			if(!item->known)
			{
				dest[counter] |= 1 << 7;
			}
			/* 7-bit Index */
			dest[counter] |= (index_table & 0x7f);

			rc_list_debug(comp, "add 8-bit XI #%d = 0x%x\n", k, dest[counter]);

			/* byte is full, write to next one next time */
			counter++;
		}
	}
	else
	{
		size_t xi_index = 0;

		/* each XI item is stored on 4 bits */
		rc_list_debug(comp, "use 4-bit format for the %d XIs\n", m);

		for(k = 0; k < m; k++)
		{
			const struct rohc_list_item *const item =
				comp->lists[comp->cur_id].items[k];
			const int index_table = comp->get_index_table(item->type);
			if(index_table < 0 || index_table >= ROHC_LIST_MAX_ITEM)
			{
				rohc_warning(comp, ROHC_TRACE_COMP, comp->profile_id,
				             "failed to handle unknown IPv6 extension header "
				             "of type 0x%02x\n", item->type);
				goto error;
			}

			/* skip element if it present in the reference list and compressor
			 * is confident that item is known by decompressor */
			if(ins_mask[k] == 0 && item->known)
			{
				rc_list_debug(comp, "ignore element #%d because it is present "
				              "in the reference list and already known\n", k);
				continue;
			}

			xi_index++;

			if(xi_index == 1)
			{
				/* first XI goes in part 1 */

				/* set the X bit if item is not already known */
				if(!item->known)
				{
					dest[counter - (3 + mask_size)] |= 1 << 3;
				}
				/* 3-bit Index */
				dest[counter - (3 + mask_size)] |= index_table & 0x07;

				rc_list_debug(comp, "add 4-bit XI #%d in part 1 = 0x%x\n", k,
				              (dest[counter - (3 + mask_size)] & 0x0f) >> 4);
			}
			else
			{
				/* next XIs goes in part 6 */
				dest[counter] = 0;

				/* odd or even 4-bit XI ? */
				if((xi_index % 2) == 0)
				{
					/* use MSB part of the byte */

					/* set the X bit if item is not already known */
					if(!item->known)
					{
						dest[counter] |= 1 << 7;
					}
					/* 3-bit Index */
					dest[counter] |= (index_table & 0x07) << 4;

					rc_list_debug(comp, "add 4-bit XI #%d in MSB = 0x%x\n", k,
					              (dest[counter] & 0xf0) >> 4);
				}
				else
				{
					/* use LSB part of the byte */

					/* set the X bit if item is not already known */
					if(!item->known)
					{
						dest[counter] |= 1 << 3;
					}
					/* 3-bit Index */
					dest[counter] |= (index_table & 0x07) << 0;

					rc_list_debug(comp, "add 4-bit XI #%d in LSB = 0x%x\n",
					              k + 1, dest[counter] & 0xf0);

					/* byte is full, write to next one next time */
					counter++;
				}
			}
		}

		/* is padding required? */
		if(xi_index > 1 && (xi_index % 2) == 0)
		{
			/* zero the padding bits */
			rc_list_debug(comp, "add 4-bit padding in LSB\n");
			dest[counter] &= 0xf0;

			/* byte is full, write to next one next time */
			counter++;
		}
	}

	/* part 7: n items (only unknown items) */
	for(k = 0; k < m; k++)
	{
		const struct rohc_list_item *const item =
			comp->lists[comp->cur_id].items[k];

		/* skip element if it present in the reference list */
		if(ins_mask[k] == 0 && item->known)
		{
			rc_list_debug(comp, "ignore element #%zu because it is present "
			              "in the reference list and already known\n", k);
			continue;
		}

		/* copy the list element if not known yet */
		if(!item->known)
		{
			rc_list_debug(comp, "add %zu-byte unknown item #%zu in packet\n",
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

