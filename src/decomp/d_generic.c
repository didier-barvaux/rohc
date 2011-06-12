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
 * @file d_generic.c
 * @brief ROHC generic decompression context for IP-only, UDP and UDP Lite
 *        profiles.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "d_generic.h"
#include "d_rtp.h"
#include "config.h" /* for RTP_BIT_TYPE definition */
#include "rohc_traces.h"
#include "rohc_time.h"
#include "rohc_debug.h"
#include "rohc_packets.h"
#include "rohc_bit_ops.h"
#include "wlsb.h"
#include "sdvl.h"
#include "crc.h"

#include <assert.h>


/*
 * Definitions of private constants and macros
 */

/** Get the minimum of two values */
#define MIN(a, b) \
	((a) < (b) ? (a) : (b))

/**
 * @brief The size (in bytes) of the IPv4 dynamic part
 *
 * According to RFC3095 section 5.7.7.4:
 *   1 (TOS) + 1 (TTL) + 2 (IP-ID) + 1 (flags) + 1 (header list) = 6 bytes
 *
 * The size of the generic extension header list field is considered constant
 * because generic extension header list is not supported yet and thus 1 byte
 * of zero is used.
 */
#define IPV4_DYN_PART_SIZE  6

/** Constant to compute inter-arrival time between the received packets */
#define WEIGHT_OLD  1

/** Constant to compute inter-arrival time between the received packets */
#define WEIGHT_NEW  1


/*
 * Private function prototypes.
 */

int decode_irdyn(struct rohc_decomp *decomp,
                 struct d_context *context,
                 const unsigned char *const rohc_packet,
                 const unsigned int rohc_length,
                 int second_byte,
                 unsigned char *dest);

int decode_uo0(struct rohc_decomp *decomp,
               struct d_context *context,
               const unsigned char *const rohc_packet,
               const unsigned int rohc_length,
               int second_byte,
               unsigned char *uncomp_packet);

int decode_uo1(struct rohc_decomp *decomp,
               struct d_context *context,
               const unsigned char *const rohc_packet,
               const unsigned int rohc_length,
               int second_byte,
               unsigned char *uncomp_packet);

int decode_uor2(struct rohc_decomp *decomp,
                struct d_context *context,
                const unsigned char *const rohc_packet,
                const unsigned int rohc_length,
                int second_byte,
                unsigned char *uncomp_packet);

int decode_extension0(const unsigned char *const rohc_data,
                      const size_t rohc_data_len,
                      const rohc_packet_t packet_type,
                      uint16_t *const sn_bits,
                      size_t *const sn_bits_nr,
                      uint16_t *const ip_id_bits,
                      size_t *const ip_id_bits_nr,
                      uint32_t *const ts_bits,
                      size_t *const ts_bits_nr);

int decode_extension1(const unsigned char *const rohc_data,
                      const size_t rohc_data_len,
                      const rohc_packet_t packet_type,
                      uint16_t *const sn_bits,
                      size_t *const sn_bits_nr,
                      uint16_t *const ip_id_bits,
                      size_t *const ip_id_bits_nr,
                      uint32_t *const ts_bits,
                      size_t *const ts_bits_nr);

int decode_extension2(const unsigned char *const rohc_data,
                      const size_t rohc_data_len,
                      const rohc_packet_t packet_type,
                      const int innermost_ip_hdr,
                      uint16_t *const sn_bits,
                      size_t *const sn_bits_nr,
                      uint16_t *const ip_id_bits,
                      size_t *const ip_id_bits_nr,
                      uint16_t *const ip_id2_bits,
                      size_t *const ip_id2_bits_nr,
                      uint32_t *const ts_bits,
                      size_t *const ts_bits_nr);

int decode_extension3(struct rohc_decomp *decomp,
                      struct d_context *context,
                      const unsigned char *const rohc_data,
                      const size_t rohc_data_len,
                      uint16_t *const sn_bits,
                      size_t *const sn_bits_nr,
                      uint16_t *const ip_id_bits,
                      size_t *const ip_id_bits_nr,
                      uint16_t *const ip_id2_bits,
                      size_t *const ip_id2_bits_nr,
                      uint32_t *const ts_bits,
                      size_t *const ts_bits_nr,
                      int *const is_ts_scaled,
                      uint8_t *const rtp_m_bits,
                      size_t *const rtp_m_bits_nr,
                      uint8_t *const rtp_x_bits,
                      size_t *const rtp_x_bits_nr,
                      uint8_t *const rtp_p_bits,
                      size_t *const rtp_p_bits_nr,
                      uint8_t *const rtp_pt_bits,
                      size_t *const rtp_pt_bits_nr);

uint8_t extension_type(const unsigned char *const rohc_extension);

int d_decode_static_ip(const unsigned char *packet,
                       const unsigned int length,
                       struct d_generic_changes *info);
int d_decode_static_ip4(const unsigned char *packet,
                        const unsigned int length,
                        struct ip_packet *ip);
int d_decode_static_ip6(const unsigned char *packet,
                        const unsigned int length,
                        struct ip_packet *ip);

int d_decode_dynamic_ip(const unsigned char *packet,
                        unsigned int length,
                        struct d_generic_changes *info,
			struct list_decomp * decomp);
int d_decode_dynamic_ip4(const unsigned char *packet,
                         unsigned int length,
                         struct ip_packet *ip,
                         int *rnd, int *nbo);
int d_decode_dynamic_ip6(const unsigned char *packet,
                         unsigned int length,
                         struct ip_packet *ip,
			 struct list_decomp * decomp,
			 struct d_generic_changes *info);

int decode_outer_header_flags(struct d_context *context,
                              const unsigned char *flags,
                              const unsigned char *fields,
                              unsigned int length,
                              struct d_generic_changes *info,
                              uint16_t *const ext3_ip_id_bits,
                              unsigned int *const ext3_ip_id_bits_nr);

int decode_inner_header_flags(struct d_context *context,
                              const unsigned char *flags,
                              const unsigned char *fields,
                              unsigned int length,
                              struct d_generic_changes *info);

unsigned int build_uncompressed_ip(struct d_generic_changes *active,
                                   unsigned char *dest,
                                   unsigned int payload_size, 
				   struct list_decomp * decomp);
unsigned int build_uncompressed_ip4(struct d_generic_changes *active,
                                    unsigned char *dest,
                                    unsigned int payload_size);
unsigned int build_uncompressed_ip6(struct d_generic_changes *active,
                                    unsigned char *dest,
                                    unsigned int payload_size,
				    struct list_decomp * decomp);

void copy_generic_changes(struct d_generic_changes *dst,
                          struct d_generic_changes *src);

int cmp_generic_changes(struct d_generic_changes *first,
                        struct d_generic_changes *second);

void sync_on_failure(struct d_generic_context *context);

void synchronize(struct d_generic_context *context);

void update_inter_packet(struct d_generic_context *context);

int check_id(struct list_decomp * decomp, int gen_id);

int get_bit_index(unsigned char byte, int index);

int check_ip6_index(struct list_decomp * decomp, int index);

static void list_decomp_ipv6_destroy_table(struct list_decomp *decomp);

int encode_ip6_extension(struct d_generic_changes * active,
			 struct list_decomp * decomp, 
			  unsigned char *dest);
void create_ip6_item(const unsigned char *data, int length,int index, 
		     struct list_decomp * decomp);

void ip6_d_init_table(struct list_decomp * decomp);

int get_ip6_ext_size(const unsigned char * ext);

/**
 * @brief Create the generic decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @return The newly-created generic decompression context
 */
void * d_generic_create(void)
{
	struct d_generic_context *context;

	/* allocate memory for the generic context */
	context = malloc(sizeof(struct d_generic_context));
	if(context == NULL)
	{
		rohc_debugf(0, "no memory for the generic decompression context\n");
		goto quit;
	}
	bzero(context, sizeof(struct d_generic_context));

	/* allocate memory for the header changes */
	context->last1 = malloc(sizeof(struct d_generic_changes));
	if(context->last1 == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the header changes last1\n");
		goto free_context;
	}
	bzero(context->last1, sizeof(struct d_generic_changes));

	context->last2 = malloc(sizeof(struct d_generic_changes));
	if(context->last2 == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the header changes last2\n");
		goto free_last1;
	}
	bzero(context->last2, sizeof(struct d_generic_changes));

	context->active1 = malloc(sizeof(struct d_generic_changes));
	if(context->active1 == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the header changes active1\n");
		goto free_last2;
	}
	bzero(context->active1, sizeof(struct d_generic_changes));

	context->active2 = malloc(sizeof(struct d_generic_changes));
	if(context->active2 == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the header changes active2\n");
		goto free_active1;
	}
	bzero(context->active2, sizeof(struct d_generic_changes));

	context->list_decomp1 = malloc(sizeof(struct list_decomp));
	if(context->list_decomp1 == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the list decompressor1\n");
		goto free_active2;
	}
	bzero(context->list_decomp1, sizeof(struct list_decomp));

	context->list_decomp2 = malloc(sizeof(struct list_decomp));
        if(context->list_decomp2 == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the list decompressor2\n");
		goto free_decomp1;
	}
	bzero(context->list_decomp2, sizeof(struct list_decomp));
	
	context->list_decomp1->free_table = list_decomp_ipv6_destroy_table;
	context->list_decomp1->encode_extension = encode_ip6_extension;
	context->list_decomp1->check_index = check_ip6_index;
	context->list_decomp1->create_item = create_ip6_item;
	context->list_decomp1->get_ext_size = get_ip6_ext_size;
	context->list_decomp2->free_table = list_decomp_ipv6_destroy_table;
	context->list_decomp2->encode_extension = encode_ip6_extension;
	context->list_decomp2->check_index = check_ip6_index;
	context->list_decomp2->create_item = create_ip6_item;
	context->list_decomp2->get_ext_size = get_ip6_ext_size;
	
	ip6_d_init_table(context->list_decomp1);
	ip6_d_init_table(context->list_decomp2);
		
	/* no packet was successfully processed for the moment */
	context->first_packet_processed = 0;
	
	/* no default next header */
	context->next_header_proto = 0;

	/* default CRC computation */
	context->compute_crc_static = compute_crc_static;
	context->compute_crc_dynamic = compute_crc_dynamic;

	return context;
	
free_decomp1:
	zfree(context->list_decomp1);
free_active2:
	zfree(context->active2);
free_active1:
	zfree(context->active1);
free_last2:
	zfree(context->last2);
free_last1:
	zfree(context->last1);
free_context:
	zfree(context);
quit:
	return NULL;
}


/**
 * @brief Destroy the context.
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
void d_generic_destroy(void *context)
{
	struct d_generic_context *c = context;
	int i;

	if(c != NULL)
	{
		if(c->last1 != NULL)
			zfree(c->last1);
		if(c->last2 != NULL)
			zfree(c->last2);
		if(c->active1 != NULL)
			zfree(c->active1);
		if(c->active2 != NULL)
			zfree(c->active2);

		if(c->specific != NULL)
			zfree(c->specific);
		if(c->list_decomp1 != NULL)
		{
			c->list_decomp1->free_table(c->list_decomp1);
			if(c->list_decomp1->temp_list != NULL)
				destroy_list( c->list_decomp1->temp_list);
			for(i = 0; i < LIST_COMP_WINDOW; i++)
			{
				if(c->list_decomp1->list_table[i] != NULL)
					destroy_list(c->list_decomp1->list_table[i]);
			}
			zfree(c->list_decomp1);
		}
		if(c->list_decomp2 != NULL)
		{
			c->list_decomp2->free_table(c->list_decomp2);
			if(c->list_decomp2->temp_list != NULL)
				destroy_list( c->list_decomp2->temp_list);
			for(i = 0; i < LIST_COMP_WINDOW; i++)
			{
				if(c->list_decomp2->list_table[i] != NULL)
					destroy_list(c->list_decomp2->list_table[i]);
			}									
			zfree(c->list_decomp2);
		}
		zfree(c);
	}
}

/**
 * @brief Initialize the tables IPv6 extension in decompressor
 *
 * @param decomp The list decompressor
 */
void ip6_d_init_table(struct list_decomp * decomp)
{
	/* insert HBH type in table */
	decomp->based_table[0].type = HBH;
	decomp->based_table[0].header.hbh = malloc(sizeof(struct ip6_hbh));
	decomp->based_table[0].length = 0;
	decomp->based_table[0].data = NULL;
	decomp->trans_table[0].known = 0;
	decomp->trans_table[0].item = &decomp->based_table[0];
	/* insert DEST type in table */
	decomp->based_table[1].type = DEST;
	decomp->based_table[1].header.dest = malloc(sizeof(struct ip6_dest));
	decomp->based_table[1].length = 0;
	decomp->based_table[1].data = NULL;
	decomp->trans_table[1].known = 0;
	decomp->trans_table[1].item = &decomp->based_table[1];
	/* insert RTHDR type in table */
	decomp->based_table[2].type = RTHDR;
	decomp->based_table[2].header.rthdr = malloc(sizeof(struct ip6_rthdr));
	decomp->based_table[2].length = 0;
	decomp->based_table[2].data = NULL;
	decomp->trans_table[2].known = 0;
	decomp->trans_table[2].item = &decomp->based_table[2];
	/* insert AHHDR type in table */
	decomp->based_table[3].type = AH;
	decomp->based_table[3].header.ahhdr = malloc(sizeof(struct ip6_ahhdr));
	decomp->based_table[3].length = 0;
	decomp->based_table[3].data = NULL;
	decomp->trans_table[3].known = 0;
	decomp->trans_table[3].item = &decomp->based_table[4];
}

/**
 * @brief Free the based table of the list decompressor
 * @param decomp The list decompressor
 */
static void list_decomp_ipv6_destroy_table(struct list_decomp *decomp)
{
	int i;
	for(i = 0; i < 4; i++)
	{
		if(decomp->based_table[i].data != NULL)
			free(decomp->based_table[i].data);
	}
	if(decomp->based_table[0].header.hbh != NULL)
		free(decomp->based_table[0].header.hbh);
	if(decomp->based_table[1].header.dest != NULL)
		free(decomp->based_table[1].header.dest);
	if(decomp->based_table[2].header.rthdr != NULL)
		free(decomp->based_table[2].header.rthdr);
	if(decomp->based_table[3].header.ahhdr != NULL)
		free(decomp->based_table[3].header.ahhdr);
}

/**
 * @brief Algorithm of list decompression
 * @param decomp The list decompressor 
 * @param packet The ROHC packet to decompress
 * @return the size of the compressed list
 */

int d_algo_list_decompress(struct list_decomp * decomp, const unsigned char *packet)
{
	int et; // encoding type
	int ps; 
	int gen_id;
	int ref_id;
	int size = 0;
	int m;
	unsigned char byte = *packet & 0xff;

	if(byte == 0)
	{
		rohc_debugf(3, "no extension list \n");
		decomp->list_decomp = 0;
		goto end;
	}
	else
		decomp->list_decomp = 1;
		
	m = GET_BIT_0_3(packet);
	et = GET_BIT_6_7(packet); 
	ps = GET_BIT_4(packet);
	packet ++;
	size ++;
	rohc_debugf(3, "ET = %d, PS = %d, m = %d\n", m, et, ps);

	gen_id = *packet & 0xff;
	packet ++;
	size ++;
	rohc_debugf(3, "gen_id = 0x%02x\n", gen_id);

	if (et == 0)
	{
		size += decode_type_0(decomp, packet, gen_id, ps, m);
	}
	else 
	{
		ref_id = *packet & 0xff;
		packet ++;
		size ++;
		rohc_debugf(3, "ref_id = 0x%02x\n", ref_id);

		if (et == 1)
			size += decode_type_1(decomp, packet, gen_id, ps, m, ref_id);
		else if(et == 2)
			size += decode_type_2(decomp, packet, gen_id, ps, ref_id);
		else
			size += decode_type_3(decomp, packet, gen_id, ps, m, ref_id);	
	}
	return size;
end:
	return 1;
}

/**
 * @brief Check if the gen_id is present in list table
 * @param decomp The list decompressor
 * @param gen_id The specified id
 * @return 1 if successful, 0 else
 */
int check_id(struct list_decomp * decomp, int gen_id)
{
	int i = 0;
	int curr_id = -1;
	while(decomp->list_table[i] == NULL && i < LIST_COMP_WINDOW)
	{
		i++;
	}
	if(decomp->list_table[i] != NULL)
	{
		curr_id = decomp->list_table[i]->gen_id;
		while( gen_id != curr_id && i < LIST_COMP_WINDOW)
		{
			i++;
			if(decomp->list_table[i] != NULL)
				curr_id = decomp->list_table[i]->gen_id;
		}
	}
	if(gen_id == curr_id)
		return 1;
	else
		return 0;
}
/**
 * @brief Check if the index is correct in IPv6 table
 *
 * @param decomp The list decompressor
 * @param index The specified index
 * @return 1 if successful, 0 else
 */
int check_ip6_index(struct list_decomp * decomp, int index)
{
	if(index > 3)
	{
		rohc_debugf(0, "no item in based table at this index: %d \n", index);
		goto error;
	}
	
	return 1;
error:
	return 0;
}
/**
 * @brief Create an IPv6 item extension list
 * @param data The data in the item
 * @param length The length of the item
 * @param index The index of the item in based table
 * @param decomp The list decompressor
*/
void create_ip6_item(const unsigned char *data,int length,int index, struct list_decomp * decomp)
{
	decomp->based_table[index].length = length;
	decomp->trans_table[index].known = 1;
	switch (index)
	{
		case 0:
			decomp->based_table[index].header.hbh->ip6h_nxt = * data;
			decomp->based_table[index].header.hbh->ip6h_len = * (data + 1);
			break;
		case 1:
			decomp->based_table[index].header.dest->ip6d_nxt = * data;
			decomp->based_table[index].header.dest->ip6d_len = * (data + 1);
			break;
		case 2:
			decomp->based_table[index].header.rthdr->ip6r_nxt = * data;
			decomp->based_table[index].header.rthdr->ip6r_len = * (data + 1);
			break;
		case 3:
			decomp->based_table[index].header.ahhdr->ip6ah_nxt = * data;
			decomp->based_table[index].header.ahhdr->ip6ah_len = * (data + 1);
			break;
		default:
			rohc_debugf(0, "no item defined for IPv6 with this index\n");
			break;
	}
	if(decomp->based_table[index].data != NULL)
		zfree(decomp->based_table[index].data);
	decomp->based_table[index].data = malloc(length);
	if(decomp->based_table[index].data != NULL)
		memcpy(decomp->based_table[index].data, data, length);	
}

/**
 * @brief Decode an extension list type 0
 * @param decomp The list decompressor
 * @param packet The ROHC packet to decompress
 * @param gen_id The id of the current list
 * @param ps The ps field
 * @param m The m fiel
 * @return the size of the compressed list
 */
int decode_type_0(struct list_decomp * decomp, const unsigned char * packet, int gen_id, int ps, int m)
{
	int i;
	//struct c_list * list = NULL;
	int index;
	int X;
	int size = 0;
	int length;
	const unsigned char * data;
	int index_size = 0;
	int new_list = !check_id(decomp, gen_id);
	if(new_list)//new list
	{
		rohc_debugf(3, "creation of a new list \n");
		decomp->counter_list++;
		decomp->counter = 0;
		decomp->ref_ok = 0;
		if(decomp->counter_list >= LIST_COMP_WINDOW)
			decomp->counter_list = 0;
		//list = decomp->list_table[decomp->counter];
		if(decomp->list_table[decomp->counter_list]!= NULL )
		{
			empty_list(decomp->list_table[decomp->counter_list]);
		}
		else
		{
			rohc_debugf(1, "creating compression list %d\n", decomp->counter_list);
			decomp->list_table[decomp->counter_list] = malloc(sizeof(struct c_list));
			if(decomp->list_table[decomp->counter_list] == NULL)
			{
				rohc_debugf(0, "cannot allocate memory for the compression list\n");
				goto error;
			}
			decomp->list_table[decomp->counter_list]->gen_id = gen_id;
			decomp->list_table[decomp->counter_list]->first_elt = NULL;
		}
		decomp->counter ++;
	}
	else if(decomp->counter < L)
	{
		decomp->counter ++;
		if(decomp->counter == L)
		{
			decomp->ref_list = decomp->list_table[decomp->counter_list];
			decomp->ref_ok = 1;
		}
	}
	rohc_debugf(3, "new value of decompressor list counter: %d \n", decomp->counter);
	if(!ps && m % 2 == 0)//assessment of the index list size
		index_size = m/2;
	else if(!ps && m % 2 != 0)
		index_size = (m+1)/2;
	else if(ps)
		index_size = m;
	// creation of the list
	for(i = 0; i < m ; i++)
	{
		rohc_debugf(3, "value of m: %d and ps: %d \n", m, ps);
		if(!ps)
		{
			X = GET_BIT_7(packet + i/2);
			index =  GET_BIT_4_6(packet);
			if (X)
			{
				rohc_debugf(3, "reception of a new item \n");
				length = decomp->get_ext_size(packet + index_size + size);
				if(new_list)
				{
					data = packet + index_size + size;
					decomp->create_item(data, length, index, decomp);
				}
				size += length;
			}
			else
			{
				if(!decomp->trans_table[index].known)
					goto error;
			}
			if(new_list)
			{
				if(!insert_elt(decomp->list_table[decomp->counter_list], &(decomp->based_table[index]), i, index))
					goto error;
			}
			i++;
			X = GET_BIT_3(packet + i/2);
			index = GET_BIT_0_2(packet + i/2);
			if (X && i < m)
			{
				rohc_debugf(3, "reception of a new item \n");
				length = decomp->get_ext_size(packet + index_size + size);
				if(new_list)
				{
					data = packet + index_size + size;
					decomp->create_item(data, length, index, decomp);
				}
				size += length;
			}
			else if (i < m)
			{
				if(!decomp->trans_table[index].known)
					goto error;
			}
			if(new_list && i < m )
			{
				if(!insert_elt(decomp->list_table[decomp->counter_list], &(decomp->based_table[index]), i, index))
					goto error;
			}
		}
		else
		{
			X = GET_BIT_7(packet + i);
			index = GET_BIT_0_6(packet + i);
			if (X)
			{
				rohc_debugf(3, "reception of a new item \n");
				length = decomp->get_ext_size(packet + index_size + size);
				if(new_list)
				{
					data = packet + index_size + size;
					decomp->create_item(data, length, index, decomp);
				}
				size += length;
			}
			else
			{
				if(!decomp->trans_table[index].known)
					goto error;
			}
			if(new_list)
			{
				if(!insert_elt(decomp->list_table[decomp->counter_list], &(decomp->based_table[index]), i, index))
					goto error;
			}
		}
	}
	return (size + index_size);
error:
	return 0;
}
   
/**
 * @brief Decode an extension list type 1
 * @param decomp The list decompressor
 * @param packet The ROHC packet to decompress
 * @param gen_id The id of the current list
 * @param ps The ps field
 * @param m The m fiel
 * @param ref_id The id of the reference list
 * @return the size of the compressed list
 */
int decode_type_1(struct list_decomp * decomp, const unsigned char * packet, int gen_id, int ps, int m, int ref_id)
{
	int i;
	struct c_list * list = NULL;
	int index;
	int X;
	int size = 0;
	int index_size = 0;
	int length;
	int bit;
	int j = 0;
	struct list_elt * elt;
	unsigned char * mask = NULL;
	mask = malloc(2*sizeof(unsigned char));
	const unsigned char * data;
	unsigned char byte = 0;
	int index_nb;
	int size_l = 0;
	int new_list = !check_id(decomp, gen_id);
	if(!check_id(decomp, ref_id))
		goto error;
	else
	{
		// update the list table
		if(decomp->ref_list->gen_id != ref_id)
		{
			for( i = 0; i < LIST_COMP_WINDOW; i++)
			{
				if(decomp->list_table[i]->gen_id < ref_id)
					empty_list(decomp->list_table[i]);
				if(decomp->list_table[i]->gen_id == ref_id)
					decomp->ref_list = decomp->list_table[i];
			}
		}
		if(new_list)
		{
			decomp->ref_ok = 0;
			decomp->counter = 0;
			rohc_debugf(3, "creation of a new list\n");
			decomp->counter_list++;
			if(decomp->counter_list >= LIST_COMP_WINDOW)
				decomp->counter_list = 0;
			if(decomp->list_table[decomp->counter_list] == decomp->ref_list)
				decomp->counter_list++;
			list = decomp->list_table[decomp->counter_list];
			if(list != NULL && list->first_elt != NULL)
			{
				empty_list(list);
			}
			else 
			{
				rohc_debugf(1, "creating compression list %d\n", decomp->counter_list);
				decomp->list_table[decomp->counter_list] = malloc(sizeof(struct c_list));
				if(decomp->list_table[decomp->counter_list] == NULL)
				{
					rohc_debugf(0, "cannot allocate memory for the compression list\n");
					goto error;
				}
				decomp->list_table[decomp->counter_list]->gen_id = gen_id;
				decomp->list_table[decomp->counter_list]->first_elt = NULL;
			}
		}
		// insertion bit mask
		// assessment of index number
		size_l = size_list(decomp->ref_list);
		index_nb = size_l;
		mask[0] = *packet;
		packet++;
		for(i = 0; i < 8; i++)
		{
			bit = get_bit_index(mask[0], i);
			if(bit)
				index_nb++;
		}
		if(ps)
		{
			mask[1] = *packet;
			packet++;
			for(i = 0; i < 8; i++)
			{
				bit = get_bit_index(mask[1], i);
				if(bit)
					index_nb++;
			}
		}
		//assessment of the index list size
		if(!ps && (index_nb - 1 - size_l) % 2 == 0)
			index_size = (index_nb - 1 - size_l)/2;
		else if(!ps && (index_nb - 1 - size_l) % 2 != 0)
			index_size = (index_nb - size_l)/2;
		else if(ps)
			index_size = index_nb - size_l;
		//insertion of the elements in the new list
		for(i = 0; i < index_nb ; i++)
		{
			if(i > 7)
				bit = get_bit_index(mask[1], 15 - i);
			else
				bit = get_bit_index(mask[0], 7 - i);
			if(!bit && new_list)
			{
				elt = get_elt(decomp->ref_list, i - j);
				if(!insert_elt(decomp->list_table[decomp->counter_list], 
				   elt->item, i, elt->index_table))
					goto error;
			}
			else if(bit)
			{
				rohc_debugf(3, "value of ps :%d \n", ps);
				if(!ps) // index coded with 4 bits
				{
					if(j == 0)
					{
						byte |= m & 0x0f;
						X = GET_BIT_3(&byte);
						index = GET_BIT_0_2(&byte);
						if (X)
						{
							length = decomp->get_ext_size(packet + index_size + size);
							if(new_list)
							{
								data = packet + index_size + size;
								decomp->create_item(data, length, index, decomp);
							}
							size += length;
						}
						else
						{
							if(!decomp->trans_table[index].known)
	                                                        goto error;
						}
					}
					else if(j % 2 != 0)
					{
						X = GET_BIT_7(packet + (j-1)/2);
						index = GET_BIT_4_6(packet + (j-1)/2);
						if(!decomp->check_index(decomp, index))
							goto error;
						if (X)
						{
							length = decomp->get_ext_size(packet + index_size + size);
							if(new_list)
							{
								data = packet + index_size + size;
								decomp->create_item(data, length, index, decomp);
							}
							size += length;
						}
						else
						{
							if(!decomp->trans_table[index].known)
								goto error;
						}
					}
					else
					{
						X = GET_BIT_3(packet + (j-1)/2);
						index = GET_BIT_0_2(packet + (j-1)/2);
						if(!decomp->check_index(decomp, index))
							goto error;
						if (X)
						{
							length = decomp->get_ext_size(packet + index_size + size);
							if(new_list)
							{
								data = packet + index_size + size;
								decomp->create_item(data, length, index, decomp);
							}
							size += length;
						}
						else
						{
							 if(!decomp->trans_table[index].known)
							 	goto error;
						}
					}	
					
				}
				else // index coded with one byte
				{
					X = GET_BIT_7(packet + j);
					index = GET_BIT_0_6(packet +j);
					if(!decomp->check_index(decomp, index))
						goto error;
					if (X)
					{
						length = decomp->get_ext_size(packet + index_size + size);
						if(new_list)
						{
							data = packet + index_size + size;
							decomp->create_item(data, length, index, decomp);
						}
						size += length;
					}
					else
					{
						if(!decomp->trans_table[index].known)
							goto error;
					}
				}
				j++;
				if(new_list)
				{
					if(!insert_elt(decomp->list_table[decomp->counter_list], 
					   &(decomp->based_table[index]), i, index))
						goto error;
				}
			}	
		}
		if(decomp->counter < L)
		{
			decomp->ref_ok = 0;
			decomp->counter ++;
			if(decomp->counter == L)
			{
				decomp->ref_list = decomp->list_table[decomp->counter_list];
				decomp->ref_ok = 1;
			}
		}
	}
	if(mask != NULL)
		free(mask);
	if(ps) // mask coded with 2 bytes
		size += 2;
	else
		size ++;
		
	return size + index_size;
error:
	return 0;
}

/**
 * @brief Decode an extension list type 2
 * @param decomp The list decompressor
 * @param packet The ROHC packet to decompress
 * @param gen_id The id of the current list
 * @param ps The ps field
 * @param ref_id The id of the reference list
 * @return the size of the compressed list
 */
int decode_type_2(struct list_decomp * decomp, const unsigned char * packet, int gen_id, int ps, int ref_id)
{
	int i;
	struct c_list * list = NULL;
	int size = 0;
	int bit;
	int j = 0;
	struct list_elt * elt;
	unsigned char * mask = NULL;
	mask = malloc(2*sizeof(unsigned char));
	int size_ref_list;
	int size_l;
	int new_list = !check_id(decomp, gen_id);
	if(!check_id(decomp, ref_id))
		goto error;
	else
	{
		// update the list table
		if(decomp->ref_list->gen_id != ref_id)
		{
			for( i = 0; i < LIST_COMP_WINDOW; i++)
			{
				if(decomp->list_table[i]->gen_id < ref_id)
					empty_list(decomp->list_table[i]);
				if(decomp->list_table[i]->gen_id == ref_id)
					decomp->ref_list = decomp->list_table[i];
			}
		}
		if(new_list)
		{
			decomp->ref_ok = 0;
			decomp->counter = 0;
			rohc_debugf(3, "creation of a new list\n");
			decomp->counter_list++;
			if(decomp->counter_list >= LIST_COMP_WINDOW)
				decomp->counter_list = 0;
			if(decomp->list_table[decomp->counter_list] == decomp->ref_list)
				decomp->counter_list++;
			list = decomp->list_table[decomp->counter_list];
			if(list != NULL && list->first_elt != NULL)
			{
				empty_list(list);
			}
			else 
			{
				rohc_debugf(1, "creating compression list %d\n", decomp->counter_list);
				decomp->list_table[decomp->counter_list] = malloc(sizeof(struct c_list));
				if(decomp->list_table[decomp->counter_list] == NULL)
				{
					rohc_debugf(0, "cannot allocate memory for the compression list\n");
					goto error;
				}
				decomp->list_table[decomp->counter_list]->gen_id = gen_id;
				decomp->list_table[decomp->counter_list]->first_elt = NULL;													
			}
		}

		// removal bit mask
		size_ref_list = size_list(decomp->ref_list);
		size_l = size_ref_list;
		mask[0] = *packet;
		packet++;
		size++;
		rohc_debugf(3, "removal bit mask (first byte) = 0x%02x\n", mask[0]);
		for(i = 0; i < MIN(8, size_ref_list); i++)
		{
			bit = get_bit_index(mask[0], 7 - i);
			if(bit)
				size_l--;
		}
		if(ps)
		{
			mask[1] = *packet;
			packet++;
			rohc_debugf(3, "removal bit mask (second byte) = 0x%02x\n", mask[1]);
			if(size_ref_list > 8)
			{
				for(i = 0; i < MIN(8, size_ref_list - 8); i++)
				{
					bit = get_bit_index(mask[1], 7 - i);
					if(bit)
						size_l--;
				}
			}
			size++;
		}
		else
		{
			rohc_debugf(3, "no second byte of removal bit mask\n");
		}

		// creation of the new list
		if(new_list)
		{
			for(i = 0; i < size_l ; i++)
			{
				if(i + j > 7)
					bit = get_bit_index(mask[1], 15 - (i + j));
				else
					bit = get_bit_index(mask[0], 7 - (i + j));
				if(!bit)
				{
					rohc_debugf(3, "take element #%d of reference list as "
					            "element #%d of new list\n", i + j + 1, i + 1);
					elt = get_elt(decomp->ref_list, i + j);
					if(!insert_elt(decomp->list_table[decomp->counter_list], 
					   elt->item, i, elt->index_table))
						goto error;
				}
				else
				{
					rohc_debugf(3, "do not take element #%d of reference list\n",
					            i + j + 1);
					i--; // no elt added in new list
					j++;
				}
			}
			rohc_debugf(3, "size of new list after removal = %d elements\n", size_l);
		}

		if(decomp->counter < L)
		{
			decomp->ref_ok = 0;
			decomp->counter ++;
			if(decomp->counter == L)
			{
				decomp->ref_list = decomp->list_table[decomp->counter_list];
				decomp->ref_ok = 1;
			}
		}
		rohc_debugf(3, "new value of decompressor list counter: %d \n", decomp->counter);
	}
	if(mask != NULL)
		free(mask);
	return size;
error:
	return 0;
}

/**
 * @brief Get the size of the extension in bytes
 * @param ext The extension
 * @return The size
 */
int get_ip6_ext_size(const unsigned char * ext)
{
	int size = (*(ext+1) + 1 )*8;
	return size;
}

/**
 * @brief Decode an extension list type 3
 * @param decomp The list decompressor
 * @param packet The ROHC packet to decompress
 * @param gen_id The id of the current list
 * @param ps The ps field
 * @param m The m fiel
 * @param ref_id The id of the reference list
 * @return the size of the compressed list
 */
int decode_type_3(struct list_decomp * decomp,const unsigned char * packet, int gen_id, int ps, int m, int ref_id)
{
	int i;
	int index;
	int X;
	int size = 0;
	int size_header =0;
	int index_size = 0;
	int length;
	int bit;
	int j = 0;
	struct list_elt * elt;
	unsigned char * rem_mask = NULL;
	rem_mask = malloc(2*sizeof(unsigned char));
	unsigned char * ins_mask = NULL;
	ins_mask = malloc(2*sizeof(unsigned char));
	const unsigned char * data;
	unsigned char byte = 0;
	int index_nb;
	int size_ref_list;
	int size_l;
	int new_list = !check_id(decomp, gen_id);
	if(!check_id(decomp, ref_id))
		goto error;
	else
	{
		// update the list table
		if(decomp->ref_list->gen_id != ref_id)
		{
			for( i = 0; i < LIST_COMP_WINDOW; i++)
			{
				if(decomp->list_table[i] != NULL)
				{
					if(decomp->list_table[i]->gen_id < ref_id)
						empty_list(decomp->list_table[i]);
					if(decomp->list_table[i]->gen_id == ref_id)
						decomp->ref_list = decomp->list_table[i];
				}
			}
		}
		if(new_list)
		{
			decomp->ref_ok = 0;
			decomp->counter = 0;
			rohc_debugf(3, "creation of a new list\n");
			decomp->counter_list++;
			if(decomp->counter_list >= LIST_COMP_WINDOW)
				decomp->counter_list = 0;
			if(decomp->list_table[decomp->counter_list] == decomp->ref_list)
				decomp->counter_list++;
			if(decomp->list_table[decomp->counter_list] != NULL && 
			   decomp->list_table[decomp->counter_list]->first_elt != NULL)
			{
				empty_list(decomp->list_table[decomp->counter_list]);
			}
			else 
			{
				rohc_debugf(1, "creating compression list %d\n", decomp->counter_list);
				decomp->list_table[decomp->counter_list] = malloc(sizeof(struct c_list));
				if(decomp->list_table[decomp->counter_list] == NULL)
				{
					rohc_debugf(0, "cannot allocate memory for the compression list\n");
					goto error;
				}
				rohc_debugf(3, "value of gen_id : %d \n", gen_id);
				decomp->list_table[decomp->counter_list]->gen_id = gen_id;
				decomp->list_table[decomp->counter_list]->first_elt = NULL;
			}
			if(decomp->temp_list != NULL && decomp->temp_list->first_elt != NULL)
			{
				empty_list(decomp->temp_list);
			}
			else
			{
				rohc_debugf(1, "creating temp list\n");
				decomp->temp_list = malloc(sizeof(struct c_list));
				if(decomp->temp_list == NULL)
				{
					rohc_debugf(0, "cannot allocate memory for the temp list\n");
					goto error;
				}
				decomp->temp_list->gen_id = gen_id;
				decomp->temp_list->first_elt = NULL;
			}
		}

		// removal bit mask
		size_ref_list = size_list(decomp->ref_list);
		size_l = size_ref_list;
		rem_mask[0] = *packet;
		packet++;
		size++;
		rohc_debugf(3, "removal bit mask (first byte) = 0x%02x\n", rem_mask[0]);
		for(i = 0; i < MIN(8, size_ref_list); i++)
		{
			bit = get_bit_index(rem_mask[0], 7 - i);
			if(bit)
				size_l--;
		}
		if(ps)
		{
			rem_mask[1] = *packet;
			packet++;
			rohc_debugf(3, "removal bit mask (second byte) = 0x%02x\n", rem_mask[1]);
			if(size_ref_list > 8)
			{
				for(i = 0; i < MIN(8, size_ref_list - 8); i++)
				{
					bit = get_bit_index(rem_mask[1], 7 - i);
					if(bit)
						size_l--;
				}
			}
			size++;
		}
		else
		{
			rohc_debugf(3, "no second byte of removal bit mask\n");
		}

		// creation of the new list
		if(new_list)
		{
			for(i = 0; i < size_l ; i++)
			{
				if(i > 7)
					bit = get_bit_index(rem_mask[1], 15 - (i+j));
				else
					bit = get_bit_index(rem_mask[0], 7 - (i+j));
				if(!bit)
				{
					rohc_debugf(3, "take element #%d of reference list "
					            "as element #%d of temporary list\n",
					            i + j + 1, i + 1);
					elt = get_elt(decomp->ref_list, i + j);
					if(!insert_elt(decomp->temp_list, elt->item, i, elt->index_table))
						goto error;
				}
				else
				{
					rohc_debugf(3, "do not take element #%d of reference list\n",
					            i + j + 1);
					i--;
					j++;
				}
			}
			rohc_debugf(3, "size of new list after removal = %d elements\n", size_l);
		}

		// insertion bit mask
		// assessment of index number
		size_l = size_list(decomp->temp_list);
		index_nb = size_l;
		ins_mask[0] = *packet;
		packet++;
		rohc_debugf(3, "insertion bit mask (first byte) = 0x%02x\n", ins_mask[0]);
		for(i = 0; i < 8; i++)
		{
			bit = get_bit_index(ins_mask[0], i);
			if(bit)
				index_nb++;
		}
		size ++;
		if(ps)
		{
			ins_mask[1] = *packet;
			packet++;
			rohc_debugf(3, "insertion bit mask (second byte) = 0x%02x\n", ins_mask[1]);
			for(i = 0; i < 8; i++)
			{
				bit = get_bit_index(ins_mask[1], i);
				if(bit)
					index_nb++;
			}
			size++;
		}
		else
		{
			rohc_debugf(3, "no second byte of insertion bit mask\n");
		}
		j = 0;
		//assessment of the index list size
		if(!ps && (index_nb - 1 - size_l) % 2 == 0)
			index_size = (index_nb - 1 - size_l)/2;
		else if(!ps && (index_nb - 1 - size_l) % 2 != 0)
			index_size = (index_nb - size_l)/2;
		else if(ps)
			index_size = index_nb - size_l;
		//insertion of the elements in the new list
		size_header = size;
		for(i = 0; i < index_nb ; i++)
		{
			if(i > 7)
				bit = get_bit_index(ins_mask[1], 15 - i);
			else
				bit = get_bit_index(ins_mask[0], 7 - i);
			if(!bit && new_list)
			{
				rohc_debugf(3, "take element #%d of temporary list "
				            "as element #%d of new list\n", i - j + 1, i + 1);
				elt = get_elt(decomp->temp_list, i - j);
				if(!insert_elt(decomp->list_table[decomp->counter_list], 
						elt->item, i, elt->index_table))
				goto error;
			}
			else if(bit)
			{
				rohc_debugf(3, "value of ps :%d \n", ps);
				if(!ps) // index coded with 4 bits
				{
					rohc_debugf(3, "decode 4-bit XI list\n");

					if(j == 0)
					{
						byte |= m & 0x0f;
						X = GET_REAL(GET_BIT_3(&byte));
						index = GET_BIT_0_2(&byte);
						rohc_debugf(3, "decode first XI (X = %d, index = %d)\n", X, index);
						if (X)
						{
							length = decomp->get_ext_size(packet + index_size + size - size_header);
							if(new_list)
							{
								rohc_debugf(3, "extract %d-byte item\n", length);
								data = packet + index_size + size - size_header;
								decomp->create_item(data, length, index, decomp);
							}
							size += length;
						}
						else
						{
							if(!decomp->trans_table[index].known)
								goto error;
						}												
					}
					else if(j % 2 != 0)
					{
						X = GET_REAL(GET_BIT_7(packet + (j-1)/2));
						index = GET_BIT_4_6(packet + (j-1)/2);
						rohc_debugf(3, "decode XI #%d (X = %d, index = %d)\n", j, X, index);
						if(!decomp->check_index(decomp, index))
							goto error;
						if (X)
						{
							length = decomp->get_ext_size(packet + index_size + size - size_header);
							if(new_list)
							{
								rohc_debugf(3, "extract %d-byte item\n", length);
								data = packet + index_size + size - size_header;
								decomp->create_item(data, length, index, decomp);
							}
							size += length;
						}
						else
						{
							if(!decomp->trans_table[index].known)
								goto error;
						}
					}
					else
					{
						X = GET_REAL(GET_BIT_3(packet + (j-1)/2));
						index = GET_BIT_0_2(packet + (j-1)/2);
						rohc_debugf(3, "decode XI #%d (X = %d, index = %d)\n", j, X, index);
						if(!decomp->check_index(decomp, index))
							goto error;
						if (X)
						{
							length = decomp->get_ext_size(packet + index_size + size - size_header);
							if(new_list)
							{
								rohc_debugf(3, "extract %d-byte item\n", length);
								data = packet + index_size + size - size_header;
								decomp->create_item(data, length, index, decomp);
							}
							size += length;
						}
						else
						{
							if(!decomp->trans_table[index].known)
								goto error;
						}
					}
				}
				else // index coded with one byte
				{
					rohc_debugf(3, "decode 8-bit XI list\n");

					X = GET_REAL(GET_BIT_7(packet + j));
					index = GET_BIT_0_6(packet +j);
					rohc_debugf(3, "decode XI #%d (X = %d, index = %d)\n", j, X, index);
					if(!decomp->check_index(decomp, index))
						goto error;
					if (X)
					{
						length = decomp->get_ext_size(packet + index_size + size - size_header);
						if(new_list)
						{
							rohc_debugf(3, "extract %d-byte item\n", length);
							data = packet + index_size + size - size_header;
							decomp->create_item(data, length, index, decomp);
						}
						size += length;
					}
					else
					{
						if(!decomp->trans_table[index].known)
							goto error;
					}
				}
				if(new_list)
				{
					rohc_debugf(3, "take item #%d from packet as element #%d "
					            "of new list\n", j + 1, i + 1);
					if(!insert_elt(decomp->list_table[decomp->counter_list], 
							&(decomp->based_table[index]), i, index))
						goto error;
				}
				j++;
			}
		}
		if(decomp->counter < L)
		{
			decomp->ref_ok = 0;
			decomp->counter ++;
			if(decomp->counter == L)
			{
				decomp->ref_list = decomp->list_table[decomp->counter_list];
				decomp->ref_ok = 1;
			}
		}
		rohc_debugf(3, "new value of decompressor list counter: %d \n", decomp->counter);
	}
	if (rem_mask != NULL)
		free(rem_mask);
	if (ins_mask != NULL)
		free(ins_mask);
	return size + index_size;
error:
	return 0;
}

/**
 * @brief Get the bit in the byte at the specified index
 * @param byte the byte to analyse
 * @param index the specified index
 * @return the bit
 */
int get_bit_index(unsigned char byte, int index)
{
	int bit;
	switch (index)
	{
		case 0:
			bit = GET_BIT_0(&byte);
			break;
		case 1:
			bit = GET_BIT_1(&byte) >> 1;
			break;
		case 2:
			bit = GET_BIT_2(&byte) >> 2;
			break;
		case 3:
			bit = GET_BIT_3(&byte) >> 3;
			break;
		case 4:
			bit = GET_BIT_4(&byte) >> 4;
			break;
		case 5:
			bit = GET_BIT_5(&byte) >> 5;
			break;
		case 6:
			bit = GET_BIT_6(&byte) >> 6;
			break;
		case 7:
			bit = GET_BIT_7(&byte) >> 7;
			break;
		default:
			rohc_debugf(0, "there is no more bit in a byte \n");
			bit = -1;
			break;
	}
	return bit;
}

/**
 * @brief Decode one IR packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param rohc_packet     The ROHC packet to decode
 * @param rohc_length     The length of the ROHC packet to decode
 * @param large_cid_len   The length of the large CID field
 * @param is_addcid_used  Whether the add-CID field is present or not
 * @param dest            The decoded IP packet
 * @return                The length of the uncompressed IP packet
 *                        or ROHC_ERROR if an error occurs
 */
int d_generic_decode_ir(struct rohc_decomp *decomp,
                        struct d_context *context,
                        const unsigned char *const rohc_packet,
                        const unsigned int rohc_length,
                        int large_cid_len,
                        int is_addcid_used,
                        unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *last1 = g_context->last1;
	struct d_generic_changes *last2 = g_context->last2;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;

	/* lengths of ROHC and uncompressed headers to be computed during parsing */
	unsigned int rohc_header_len = 0;
	unsigned int uncomp_header_len = 0;

	/* remaining ROHC data not parsed yet */
	const unsigned char *rohc_remain_data = rohc_packet;
	unsigned int rohc_remain_len = rohc_length;

	/* ROHC and uncompressed payloads (they are the same) */
	const unsigned char *payload_data;
	unsigned int payload_len;

	int dynamic_present;
	int size;
	unsigned int protocol;
	int multiple_ip;

	rohc_debugf(2, "decode an IR packet\n");

	/* set the packet type */
	g_context->packet_type = PACKET_IR;

	g_context->current_packet_time = get_microseconds();

	/* is the dynamic flag set ? */
	dynamic_present = GET_BIT_0(rohc_remain_data);

	/* skip the first bytes:
	 * 	IR type + Profile ID + CRC (+ eventually CID bytes) */
	rohc_remain_data += 3 + large_cid_len;
	rohc_remain_len -= 3 + large_cid_len;
	rohc_header_len += 3 + large_cid_len;

	/* decode the static part of the outer header */
	size = d_decode_static_ip(rohc_remain_data, rohc_remain_len, active1);
	if(size == -1)
	{
		rohc_debugf(0, "cannot decode the outer IP static part\n");
		goto error;
	}
	rohc_remain_data += size;
	rohc_remain_len -= size;
	rohc_header_len += size;

	/* check the version of the outer IP header against the context if the IR
	 * packet is not the first ROHC packet processed by the context */
	if(g_context->first_packet_processed &&
	   ip_get_version(&active1->ip) != ip_get_version(&last1->ip))
	{
		rohc_debugf(0, "IP version mismatch (packet = %d, context = %d)\n",
		            ip_get_version(&active1->ip), ip_get_version(&last1->ip));
		goto error;
	}

	/* check for the presence of a second IP header */
	protocol = ip_get_protocol(&active1->ip);
	if(protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6)
	{
		multiple_ip = 1;
		rohc_debugf(1, "second IP header detected\n");
	}
	else
		multiple_ip = 0;

	/* check the number of IP headers against the context if the IR packet is
	 * not the first ROHC packet processed by the context, otherwise initialize
	 * the context */
	if(g_context->first_packet_processed &&
	   multiple_ip != g_context->multiple_ip)
	{
		rohc_debugf(0, "number of IP headers mismatch (packet = %d, "
		            "context = %d)\n", multiple_ip, g_context->multiple_ip);
		goto error;
	}
	else
		g_context->multiple_ip = multiple_ip;
	
	/* decode the static part of the inner IP header
	 * if multiple IP headers */
	if(g_context->multiple_ip)
	{
		size = d_decode_static_ip(rohc_remain_data, rohc_remain_len, active2);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the inner IP static part\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		rohc_header_len += size;

		/* check the version of the inner IP header against the context if the IR
		 * packet is not the first ROHC packet processed by the context */
		if(g_context->first_packet_processed &&
		   ip_get_version(&active2->ip) != ip_get_version(&last2->ip))
		{
			rohc_debugf(0, "IP version mismatch (packet = %d, context = %d)\n",
			            ip_get_version(&active2->ip), ip_get_version(&last2->ip));
			goto error;
		}
	
		/* update the next header protocol */
		protocol = ip_get_protocol(&active2->ip);
	}

	/* decode the static part of the next header header if necessary */
	if(g_context->decode_static_next_header != NULL)
	{
		/* check the next header protocol against the context if the IR packet is
		 * not the first ROHC packet processed by the context, otherwise
		 * initialize the context */
		if(g_context->first_packet_processed &&
		   protocol != g_context->next_header_proto)
		{
			rohc_debugf(0, "next header protocol mismatch (packet = %d, "
			            "context = %d)\n", protocol,
			            g_context->next_header_proto);
			goto error;
		}

		size = g_context->decode_static_next_header(g_context, rohc_remain_data,
		                                            rohc_remain_len,
		                                            active1->next_header);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the next header static part\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		rohc_header_len += size;
	}

	/* decode the dynamic part of the ROHC packet */
	if(dynamic_present)
	{
		/* decode the dynamic part of the outer IP header */
		size = d_decode_dynamic_ip(rohc_remain_data, rohc_remain_len,
		                           active1, g_context->list_decomp1);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the inner IP dynamic part\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		rohc_header_len += size;

		/* decode the dynamic part of the inner IP header */
		if(g_context->multiple_ip)
		{
			size = d_decode_dynamic_ip(rohc_remain_data, rohc_remain_len,
			                           active2, g_context->list_decomp2);
			if(size == -1)
			{
				rohc_debugf(0, "cannot decode the outer IP dynamic part\n");
				goto error;
			}
			rohc_remain_data += size;
			rohc_remain_len -= size;
			rohc_header_len += size;
		}

		/* decode the dynamic part of the next header header if necessary */
		if(g_context->decode_dynamic_next_header != NULL)
		{
			size = g_context->decode_dynamic_next_header(g_context, rohc_remain_data,
			                                             rohc_remain_len,
			                                             active1->next_header);
			if(size == -1)
			{
				rohc_debugf(0, "cannot decode the next header dynamic part\n");
				goto error;
			}
			rohc_remain_data += size;
			rohc_remain_len -= size;
			rohc_header_len += size;
		}

		/* reset the correction counter */
		g_context->correction_counter = 0;

		/* set the state to Full Context */
		context->state = FULL_CONTEXT;
	}
	else if(context->state != FULL_CONTEXT)
	{
		/* in 'Static Context' or 'No Context' state and the packet does not
		 * contain a dynamic part */
		rohc_debugf(0, "receive IR packet without a dynamic part, but not "
		               "in Full Context state\n");
		return ROHC_ERROR;
	}

	/* ROHC IR header is now fully decoded */
	payload_data = rohc_remain_data;
	payload_len = rohc_remain_len;

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		/* build the outer IP header */
		size = build_uncompressed_ip(active1, dest, payload_len +
		                             ip_get_hdrlen(&active2->ip) +
		                             active1->next_header_len +
		                             active2->size_list, 
		                             g_context->list_decomp1);
		dest += size;
		uncomp_header_len += size;

		/* build the inner IP header */
		size = build_uncompressed_ip(active2, dest, payload_len +
		                             active2->next_header_len,
		                             g_context->list_decomp2);
		dest += size;
		uncomp_header_len += size;
	}
	else
	{
		/* build the single IP header */
		size = build_uncompressed_ip(active1, dest, payload_len +
		                             active1->next_header_len,
		                             g_context->list_decomp1);
		dest += size;
		uncomp_header_len += size;
	}

	/* build the next header if necessary */
	if(g_context->build_next_header != NULL)
	{
		size = g_context->build_next_header(g_context, active1, dest, payload_len);
		dest += size;
		uncomp_header_len += size;
	}

	/* synchronize the IP header changes */
	synchronize(g_context);

	/* the first packet is now processed */
	if(!g_context->first_packet_processed)
		g_context->first_packet_processed = 1;

	/* update the inter-packet variable */
	update_inter_packet(g_context);

	/* payload */
	rohc_debugf(3, "ROHC payload (length = %u bytes) starts at offset %u\n",
	            payload_len, rohc_header_len);
	if((rohc_header_len + payload_len) != rohc_length)
	{
		rohc_debugf(0, "ROHC IR header (%u bytes) and payload (%u bytes) "
		            "do not match the full ROHC IR packet (%u bytes)\n",
		            rohc_header_len, payload_len, rohc_length);
		goto error;
	} 
	if(payload_len != 0)
	{
		memcpy(dest, payload_data, payload_len);
	}

	/* statistics */
	context->header_compressed_size += is_addcid_used + rohc_header_len;
	c_add_wlsb(context->header_16_compressed, 0, is_addcid_used + rohc_header_len);
	context->header_uncompressed_size += uncomp_header_len;
	c_add_wlsb(context->header_16_uncompressed, 0, uncomp_header_len);

	return (uncomp_header_len + payload_len);

error:
	return ROHC_ERROR;
}


/**
 * @brief Decode the IP static part of a ROHC packet.
 *
 * See 5.7.7.3 and 5.7.7.4 in RFC 3095 for details.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param info   The decoded IP header information
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_static_ip(const unsigned char *packet,
                       const unsigned int length,
                       struct d_generic_changes *info)
{
	unsigned int ip_version;
	int read; /* number of bytes read from the packet */

	/* check the minimal length to decode the IP version */
	if(length < 1)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", length);
		goto error;
	}

	/* retrieve the IP version */
	ip_version = GET_BIT_4_7(packet);

	/* reject non IPv4/IPv6 packets */
	if(ip_version != IPV4 && ip_version != IPV6)
	{
		rohc_debugf(0, "wrong IP version (%d)\n", ip_version);
		goto error;
	}

	/* create a new empty IP packet with no payload */
	ip_new(&info->ip, ip_version);

	/* decode the static part of the IP header depending on the IP version */
	if(ip_version == IPV4)
		read = d_decode_static_ip4(packet, length, &info->ip);
	else /* IPV6 */
		read = d_decode_static_ip6(packet, length, &info->ip);

	return read;

error:
	return -1;
}


/**
 * @brief Decode the IPv4 static part of a ROHC packet.
 *
 * See 5.7.7.4 in RFC 3095 for details.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param ip     The decoded IP packet
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_static_ip4(const unsigned char *packet,
                        const unsigned int length,
                        struct ip_packet *ip)
{
	int read = 0; /* number of bytes read from the packet */
	unsigned int version;

	/* check the minimal length to decode the IPv4 static part */
	if(length < 10)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", length);
		goto error;
	}

	/* read the IP version */
	version = GET_BIT_4_7(packet);
	if(version != IPV4 || ip->version != IPV4)
	{
		rohc_debugf(0, "wrong IP version (%d)\n", version);
		goto error;
	}
	rohc_debugf(3, "IP Version = %d\n", version);
	packet++;
	read++;

	/* read the protocol number */
	ip_set_protocol(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "Protocol = 0x%02x\n", ip_get_protocol(ip));
	packet++;
	read++;

	/* read the source IP address */
	ip_set_saddr(ip, packet);
	rohc_debugf(3, "Source Address = 0x%08x\n", ipv4_get_saddr(ip));
	packet += 4;
	read += 4;

	/* read the destination IP address */
	ip_set_daddr(ip, packet);
	rohc_debugf(3, "Destination Address = 0x%08x\n", ipv4_get_daddr(ip));
	packet += 4;
	read += 4;

	return read;

error:
	return -1;
}


/**
 * @brief Decode the IPv6 static part of a ROHC packet.
 *
 * See 5.7.7.3 in RFC 3095 for details.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param ip     The decoded IP packet
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_static_ip6(const unsigned char *packet,
                        const unsigned int length,
                        struct ip_packet *ip)
{
	int read = 0; /* number of bytes read from the packet */
	unsigned int version;

	/* check the minimal length to decode the IPv6 static part */
	if(length < 36)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", length);
		goto error;
	}

	/* read the IP version */
	version = GET_BIT_4_7(packet);
	if(version != IPV6 || ip->version != IPV6)
	{
		rohc_debugf(0, "wrong IP version (%d)\n", version);
		goto error;
	}
	rohc_debugf(3, "IP Version = %d\n", version);

	/* read the flow label */
	ipv6_set_flow_label(ip, (GET_BIT_0_3(packet) << 16) |
	                        (GET_BIT_0_7(packet + 1) << 8) |
	                        GET_BIT_0_7(packet + 2));
	rohc_debugf(3, "Flow Label = 0x%05x\n", ipv6_get_flow_label(ip));
	packet += 3;
	read += 3;

	/* read the next header value */	
	ip_set_protocol(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "Next Header = 0x%02x\n", ip->header.v6.ip6_nxt);
	packet++;
	read++;

	/* read the source IP address */
	ip_set_saddr(ip, packet);
	rohc_debugf(3, "Source Address = " IPV6_ADDR_FORMAT "\n",
	            IPV6_ADDR(ipv6_get_saddr(ip)));
	packet += 16;
	read += 16;

	/* read the destination IP address */
	ip_set_daddr(ip, packet);
	rohc_debugf(3, "Destination Address = " IPV6_ADDR_FORMAT "\n",
	            IPV6_ADDR(ipv6_get_daddr(ip)));
	packet += 16;
	read += 16;

	return read;

error:
	return -1;
}


/**
 * @brief Decode the IP dynamic part of a ROHC packet.
 *
 * See 5.7.7.3 and 5.7.7.4 in RFC 3095 for details.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param info   The decoded IP header information
 * @param decomp The list decompressor (only for IPv6)
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_dynamic_ip(const unsigned char *packet,
                        unsigned int length,
                        struct d_generic_changes *info, 
                        struct list_decomp *decomp)
{
	int read; /* number of bytes read from the packet */

	/* decode the dynamic part of the IP header depending on the IP version */
	if(ip_get_version(&info->ip) == IPV4)
		read = d_decode_dynamic_ip4(packet, length, &info->ip,
		                            &info->rnd, &info->nbo);
	else /* IPV6 */
		read = d_decode_dynamic_ip6(packet, length, &info->ip, decomp, info);
	
	return read;
}


/**
 * @brief Decode the IPv4 dynamic part of a ROHC packet.
 *
 * See 5.7.7.4 in RFC 3095 for details. Generic extension header list is not
 * managed yet.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param ip     The decoded IP packet
 * @param rnd    Boolean to store whether the IP-ID is random or not
 * @param nbo    Boolean to store whether the IP-ID is in NBO or not
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_dynamic_ip4(const unsigned char *packet,
                         unsigned int length,
                         struct ip_packet *ip,
                         int *rnd, int *nbo)
{
	int read = 0; /* number of bytes read from the packet */

	/* check the minimal length to decode the IPv4 dynamic part */
	if(length < IPV4_DYN_PART_SIZE)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", length);
		goto error;
	}

	/* read the TOS field */
	ip_set_tos(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "TOS = 0x%02x\n", ip_get_tos(ip));
	packet++;
	read++;

	/* read the TTL field */
	ip_set_ttl(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "TTL = 0x%02x\n", ip_get_ttl(ip));
	packet++;
	read++;

	/* read the IP-ID field */
	ipv4_set_id(ip, GET_NEXT_16_BITS(packet));
	rohc_debugf(3, "IP-ID = 0x%04x\n", ntohs(ipv4_get_id(ip)));
	packet += 2;
	read += 2;

	/* read the DF flag */
	ipv4_set_df(ip, GET_REAL(GET_BIT_7(packet)));

	/* read the RND flag */
	*rnd = GET_REAL(GET_BIT_6(packet));

	/* read the NBO flag */
	*nbo = GET_REAL(GET_BIT_5(packet));
	rohc_debugf(3, "DF = %d, RND = %d, NBO = %d\n",
	            ipv4_get_df(ip), *rnd, *nbo);
	packet++;
	read++;

	/* generic extension header list is not managed yet,
	   ignore the byte which should be set to 0 */
	if(GET_BIT_0_7(packet) != 0x00)
	{
		rohc_debugf(0, "generic extension header list not supported yet\n");
		goto error;
	}
	packet++;
	read++;

	return read;

error:
	return -1;
}


/**
 * @brief Decode the IPv6 dynamic part of a ROHC packet.
 *
 * See 5.7.7.3 in RFC 3095 for details. Generic extension header list is not
 * managed yet.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param ip     The decoded IP packet
 * @param decomp The list decompressor
 * @param info   The decoded IP header information 
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_dynamic_ip6(const unsigned char *packet,
                         unsigned int length,
                         struct ip_packet *ip,
                         struct list_decomp *decomp,
                         struct d_generic_changes *info)
{
	int read = 0; /* number of bytes read from the packet */
	struct c_list * list;
	int i;
	struct list_elt * elt;
	int length_list = 0; // number of element in reference list
	int size = 0; // size of the list

	/* check the minimal length to decode the IPv6 dynamic part */
	if(length < 2)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", length);
		goto error;
	}

	/* read the TC field */
	ip_set_tos(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "TC = 0x%02x\n", ip_get_tos(ip));
	packet++;
	read++;

	/* read the HL field */
	ip_set_ttl(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "HL = 0x%02x\n", ip_get_ttl(ip));
	packet++;
	read++;
	
	/* generic extension header list */
	if(!decomp->size_ext)
		goto error;
	else
	{
		read += decomp->size_ext;
		if(decomp->list_decomp)
		{
			if(decomp->ref_ok)
				list = decomp->ref_list;
			else
				list = decomp->list_table[decomp->counter_list];
	
			if(list->first_elt != NULL)
				length_list = size_list(list);
			for(i = 0; i < length_list; i++)
			{
				elt = get_elt(list, i);
				size += elt->item->length;
			}
			info->size_list = size;
		}
	}
	return read;

error:
	return -1;
}


/**
 * @brief Find the length of the IR header.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * \verbatim

 Basic structure of the IR packet (5.7.7.1):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  |         Add-CID octet         |  if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   1   0 | D |
    +---+---+---+---+---+---+---+---+
    |                               |
 3  /    0-2 octets of CID info     /  1-2 octets if for large CIDs
    |                               |
    +---+---+---+---+---+---+---+---+
 4  |            Profile            |  1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              |  1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  |         Static chain          |  variable length
    |                               |
    +---+---+---+---+---+---+---+---+
    |                               |
 7  |         Dynamic chain         |  present if D = 1, variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 8  |             SN                |  2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    |                               |
 9  |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * The function computes the length of the fields 2 + 4-7, ie. the first byte,
 * the Profile and CRC fields and the static and dynamic chains (outer and inner
 * IP headers).
 *
 * @param context         The decompression context
 * @param packet          The pointer on the IR packet minus the Add-CID byte
 *                        (ie. the field 2 in the figure)
 * @param plen            The length of the IR packet minus the Add-CID byte
 * @param large_cid_len   The size of the large CID field
 *                        (ie. the field 3 in the figure)
 * @return                The length of the IR header,
 *                        0 if an error occurs
 */
unsigned int d_generic_detect_ir_size(struct d_context *context,
                                      unsigned char *packet,
                                      unsigned int plen,
                                      unsigned int large_cid_len)
{
	struct d_generic_context *g_context = context->specific;
	unsigned int length = 0;
	int ip_offset;
	int d;
	unsigned int ip_version, ip2_version = 0;
	unsigned int proto;

	/* skip:
	 *  - the first byte of the ROHC packet (field 2)
	 *  - the Profile byte (field 4)
	 *  - the CRC byte (field 5) */
	length += 3;

	/* determine the position of the first IP version field: the second byte
	 * is the Profile byte (field 4) and we must skip the Profile byte (field 4)
	 * and the CRC byte (field 5) */
	ip_offset = large_cid_len + length;

	/* check if IR packet is large enough to contain an IP version field */
	if(ip_offset >= plen)
	{
		rohc_debugf(0, "ROHC packet too small for outer IP version field "
		               "(len = %u)\n", plen);
		goto error;
	}

	/* check IP version */
	ip_version = (packet[ip_offset] >> 4) & 0x0f;
	if(ip_version != IPV4 && ip_version != IPV6)
	{
		rohc_debugf(0, "bad outer IP version (%u)\n", ip_version);
		goto error;
	}

	/* IP static part (see 5.7.7.3 & 5.7.7.4 in RFC 3095) */ 
	if(ip_version == IPV4)
		length += 10;
	else /* IPv6 */
		length += 36;

	/* check if IR packet is large enough to contain an IP protocol field */
	if(ip_offset + (ip_version == IPV4 ? 1 : 3) >= plen)
	{
		rohc_debugf(0, "ROHC packet too small for protocol field (len = %u)\n",
		            plen);
		goto error;
	}

	/* analyze the second header if present */
	proto = packet[ip_offset + (ip_version == IPV4 ? 1 : 3)];
	if(proto == IPPROTO_IPIP || proto == IPPROTO_IPV6)
	{
		rohc_debugf(2, "inner IP header detected in static chain\n");

		/* change offset to point on the second IP header
		 * (substract 1 because of the first byte) */
		ip_offset = large_cid_len + length;

		/* check if IR packet is large enough to contain an IP version field */
		if(ip_offset >= plen)
		{
			rohc_debugf(0, "ROHC packet too small for inner IP version field "
			               "(len = %u)\n", plen);
			goto error;
		}

		/* check IP version */
		ip2_version = (packet[ip_offset] >> 4) & 0x0f;
		if(ip2_version != IPV4 && ip2_version != IPV6)
		{
			rohc_debugf(0, "bad inner IP version (%u)\n", ip2_version);
			goto error;
		}

		/* IP static part (see 5.7.7.3 & 5.7.7.4 in RFC 3095) */ 
		if(ip2_version == IPV4)
			length += 10;
		else /* IPv6 */
			length += 36;
	}

	/* IP dynamic part if included (see 5.7.7.3 & 5.7.7.4 in RFC 3095) */
	d = GET_REAL(GET_BIT_0(packet));
	if(d)
	{
		unsigned int ext_list_offset;

		rohc_debugf(2, "dynamic chain detected\n");

		/* IP dynamic part of the outer header */
		if(ip_version == IPV4)
		{
			length += IPV4_DYN_PART_SIZE;
		}
		else /* IPv6 */
		{

			/* IPv6 dynamic chain (constant part) */
			length += 2;

			/* IPv6 dynamic chain (variable part): IPv6 extensions list */
			ext_list_offset = large_cid_len + length +
			                  context->profile->get_static_part();
			g_context->list_decomp1->size_ext = 
				d_algo_list_decompress(g_context->list_decomp1,
				                       packet + ext_list_offset);
			rohc_debugf(1, "IPv6 extensions list in outer IPv6 dynamic "
			            "chain = %d bytes\n", g_context->list_decomp1->size_ext);
			length += g_context->list_decomp1->size_ext;
		}

		/* IP dynamic part of the inner header if present */
		if(proto == IPPROTO_IPIP || proto == IPPROTO_IPV6)
		{
			rohc_debugf(1, "inner IP header detected in dynamic chain\n");

			if(ip2_version == IPV4)
			{
				length += IPV4_DYN_PART_SIZE;
			}
			else /* IPv6 */
			{
				/* IPv6 dynamic chain (constant part) */
				length += 2;

				/* IPv6 dynamic chain (variable part): IPv6 extensions list */
				ext_list_offset = large_cid_len + length +
				                  context->profile->get_static_part();
				g_context->list_decomp2->size_ext =
					d_algo_list_decompress(g_context->list_decomp2,
					                       packet + ext_list_offset);
				rohc_debugf(1, "IPv6 extensions list in inner IPv6 dynamic chain "
				            "= %d bytes\n", g_context->list_decomp2->size_ext);
				length += g_context->list_decomp2->size_ext;
			}
		}
	}

	rohc_debugf(1, "length of fields 2 + 4-7 = %u bytes\n", length);

	return length;

error:
	return 0;
}


/**
 * @brief Find the length of the IR-DYN header.
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * \verbatim

 Basic structure of the IR-DYN packet (5.7.7.2):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         : if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   0   0   0 | IR-DYN packet type
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /     0-2 octets of CID info    / 1-2 octets if for large CIDs
    :                               :
    +---+---+---+---+---+---+---+---+
 4  |            Profile            | 1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              | 1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  /         Dynamic chain         / variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 7  |             SN                | 2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    :                               :
 8  /           Payload             / variable length
    :                               :
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * The function computes the length of the fields 2 + 4-7, ie. the first byte,
 * the Profile and CRC fields and the dynamic chains (outer and inner IP
 * headers).
 * 
 * @param context         The decompression context
 * @param packet          The IR-DYN packet after the Add-CID byte if present
 *                        (ie. field 2 in the figure)
 * @param plen            The length of the IR-DYN packet minus the Add-CID byte
 * @param large_cid_len   The size of the large CID field
 *                        (ie. field 3 in the figure)
 * @return                The length of the IR-DYN header,
 *                        0 if an error occurs
 */
unsigned int d_generic_detect_ir_dyn_size(struct d_context *context,
                                          unsigned char *packet,
                                          unsigned int plen,
                                          unsigned int large_cid_len)
{
	struct d_generic_context *g_context = context->specific;
	unsigned int length = 0;
	unsigned int protocol;
	ip_version version, version2;
	unsigned int ext_list_offset;

	/* skip:
	 *  - the first byte of the ROHC packet (field 2)
	 *  - the Profile byte (field 4)
	 *  - the CRC byte (field 5) */
	length += 3;

	/* get the IP version of the outer header */
	version = ip_get_version(&g_context->active1->ip);
	
	/* IP dynamic part of the outer header
	 * (see 5.7.7.3 & 5.7.7.4 in RFC 3095) */
	if(version == IPV4)
	{
		length += IPV4_DYN_PART_SIZE;
	}
	else /* IPV6 */
	{
		length += 2;
		ext_list_offset = large_cid_len + length;
		g_context->list_decomp1->size_ext =
			d_algo_list_decompress(g_context->list_decomp1,
			                       packet + ext_list_offset);
		length += g_context->list_decomp1->size_ext;
	}

	/* analyze the second header if present */
	protocol = ip_get_protocol(&g_context->active1->ip);
	if(protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6)
	{
		/* get the IP version of the inner header */
		version2 = ip_get_version(&g_context->active2->ip);

		/* IP dynamic part of the inner header
		 * (see 5.7.7.3 & 5.7.7.4 in RFC 3095) */
		if(version2 == IPV4)
		{
			length += IPV4_DYN_PART_SIZE;
		}
		else /* IPv6 */
		{
			length += 2;
			ext_list_offset = large_cid_len + length;
			g_context->list_decomp2->size_ext =
				d_algo_list_decompress(g_context->list_decomp2,
				                       packet + ext_list_offset);
			length += g_context->list_decomp2->size_ext;
		}
	}

	return length;
}


/**
 * @brief Decode one IR-DYN, UO-0, UO-1 or UOR-2 packet, but not IR packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp      The ROHC decompressor
 * @param context     The decompression context
 * @param rohc_packet The ROHC packet to decode
 * @param rohc_length The length of the ROHC packet
 * @param second_byte The offset for the second byte of the ROHC packet
 *                    (depends on the CID encoding and the packet type)
 * @param dest        OUT: The decoded IP packet
 * @return            The length of the uncompressed IP packet
 *                    or ROHC_ERROR if an error occurs
 *                    or ROHC_ERROR_CRC if a CRC error occurs
 */
int d_generic_decode(struct rohc_decomp *decomp,
                     struct d_context *context,
                     const unsigned char *const rohc_packet,
                     const unsigned int rohc_length,
                     int second_byte,
                     unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	int (*decode_packet)(struct rohc_decomp *decomp,
	                     struct d_context *context,
	                     const unsigned char *const packet,
	                     const unsigned int rohc_length,
	                     int second_byte,
	                     unsigned char *dest);
	int length = ROHC_ERROR;

	synchronize(g_context);
	g_context->current_packet_time = get_microseconds();

	/* check if the ROHC packet is large enough to read the second byte */
	if(second_byte >= rohc_length)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_length);
		goto error;
	}

	/* ---- DEBUG ---- */
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	struct d_generic_changes *last1 = g_context->last1;
	struct d_generic_changes *last2 = g_context->last2;

	if(ip_get_version(&last1->ip) == IPV4)
		rohc_debugf(2, "nbo = %d rnd = %d\n", last1->nbo, last1->rnd);
	if(g_context->multiple_ip && ip_get_version(&last2->ip) == IPV4)
			rohc_debugf(2, "multiple IP header: nbo2 = %d rnd2 = %d\n",
			            last2->nbo, last2->rnd);

	if(!cmp_generic_changes(active1, last1))
		rohc_debugf(0, "last1 and active1 structs are not synchronized\n");
	if(!cmp_generic_changes(active2, last2))
		rohc_debugf(0, "last2 and active2 structs are not synchronized\n");
	/* ---- DEBUG ---- */

	/* only the IR packet can be received in the No Context state,
	 * the IR-DYN, UO-0, UO-1 or UOR-2 can not. */
	if(context->state == NO_CONTEXT)
		goto error;

	/* parse the packet according to its type */
	switch(find_packet_type(decomp, context, rohc_packet, second_byte))
	{
		case PACKET_UO_0:
			g_context->packet_type = PACKET_UO_0;
			if(context->state == STATIC_CONTEXT)
				goto error;
			decode_packet = decode_uo0;
			break;

		case PACKET_UO_1:
			g_context->packet_type = PACKET_UO_1;
			if(context->state  == STATIC_CONTEXT)
				goto error;
			decode_packet = decode_uo1;
			break;

		case PACKET_UO_1_RTP:
			g_context->packet_type = PACKET_UO_1_RTP;
			decode_packet = decode_uo1;
			break;
		
		case PACKET_UO_1_TS:
			g_context->packet_type = PACKET_UO_1_TS;
			decode_packet = decode_uo1;
			break;

		case PACKET_UO_1_ID:
			g_context->packet_type = PACKET_UO_1_ID;
			if(context->state  == STATIC_CONTEXT)
				goto error;
			decode_packet = decode_uo1;
			break;

		case PACKET_UOR_2:
			g_context->packet_type = PACKET_UOR_2;
			decode_packet = decode_uor2;
			break;

		case PACKET_UOR_2_RTP:
			g_context->packet_type = PACKET_UOR_2_RTP;
			decode_packet = decode_uor2;
			break;
			
		case PACKET_UOR_2_TS:
			g_context->packet_type = PACKET_UOR_2_TS;
			decode_packet = decode_uor2;
			break;

		case PACKET_UOR_2_ID:
			g_context->packet_type = PACKET_UOR_2_ID;
			decode_packet = decode_uor2;
			break;
			
		case PACKET_IR_DYN:
			g_context->packet_type = PACKET_IR_DYN;
			decode_packet = decode_irdyn;
			break;

		default:
			rohc_debugf(0, "unknown packet type\n");
			goto error;
	}

	rohc_debugf(2, "decode the packet (type %d)\n", g_context->packet_type);
	length = decode_packet(decomp, context, rohc_packet, rohc_length,
	                       second_byte, dest);
#if RTP_BIT_TYPE
	// nothing to do
#else
	if(length == ROHC_NEED_REPARSE)
	{
		rohc_debugf(3, "trying to reparse the packet...\n");
		length = d_generic_decode(decomp, context, rohc_packet, rohc_length,
		                          second_byte, dest);
	}
	else if(length > 0)
	{
		rohc_debugf(2, "uncompressed packet length = %d bytes\n", length);
	}
#endif
error:
	return length;
}


/**
 * @brief Get the reference SN value of the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The decompression context
 * @return        The reference SN value
 */
int d_generic_get_sn(struct d_context *context)
{
	struct d_generic_context *g_context = context->specific;
	return d_get_lsb_ref(&g_context->sn);
}


/**
 * @brief Decode one UO-0 packet.
 *
 * Steps:
 *  A. Parsing of ROHC header
 *  B. Decode extracted bits
 *  C. Build uncompressed headers
 *  D. Check for correct decompression
 *  E. Update the compression context
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

\endverbatim

Here are the first octet and remainder of UO-0 header:

\verbatim

 UO-0 (5.7.1)

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 0 |      SN       |    CRC    |
    +===+===+===+===+===+===+===+===+

 Part 4 is empty.

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in the parent function.
 * Parts 2, 6 and 9 are parsed in this function.
 * Parts 4 and 5 do not exist in the UO-0 packet.
 * Part 13 is parsed in profile-specific function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param second_byte    The offset of the 2nd byte in the ROHC packet
 * @param uncomp_packet  OUT: The decoded IP packet
 * @return               The length of the uncompressed IP packet
 *                       ROHC_ERROR if an error occurs
 *                       ROHC_ERROR_CRC if a CRC error occurs
 */
int decode_uo0(struct rohc_decomp *decomp,
               struct d_context *context,
               const unsigned char *const rohc_packet,
               const unsigned int rohc_length,
               int second_byte,
               unsigned char *uncomp_packet)
{
	struct d_generic_context *const g_context = context->specific;

	/* Whether the current profile is RTP or not */
	const int is_rtp = (context->profile->id == ROHC_PROFILE_RTP);

	/* extracted bits and decoded value for SN */
	uint16_t sn_decoded;
	uint16_t sn_bits;
	size_t sn_bits_nr;

	/* decoded value for TS */
	uint32_t ts_decoded = 0; /* initialized only because of GCC warning */

	/* extracted bits and decoded value for outer IP-ID */
	uint16_t ip_id_decoded = 0; /* initialized only because of GCC warning */
	uint16_t ip_id_bits = 0;
	size_t ip_id_bits_nr = 0;

	/* extracted bits and decoded value for inner IP-ID */
	uint16_t ip_id2_decoded = 0; /* initialized only because of GCC warning */
	uint16_t ip_id2_bits = 0;
	size_t ip_id2_bits_nr = 0;

	/* CRC found in packet and computed one */
	uint8_t crc_packet;
	uint8_t crc_computed;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;
	size_t rohc_header_len = 0;

	/* length of the uncompressed headers and pointers on uncompressed outer
	   IP, inner IP and next headers (will be computed during building) */
	size_t uncomp_header_len;
	unsigned char *ip_hdr;
	unsigned char *ip2_hdr;
	unsigned char *next_header;

	/* ROHC and uncompressed payloads (they are the same) */
	const unsigned char *payload_data;
	size_t payload_len;

	/* helper variables for values returned by functions */
	int size;
	int ret;


	if(g_context->active1->complist)
		g_context->list_decomp1->ref_ok = 1;
	if(g_context->multiple_ip && g_context->active2->complist)
		g_context->list_decomp2->ref_ok = 1;


	/* A. Parsing of ROHC header
	 *
	 * Let's parse fields 2 to 13.
	 */

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;

	/* check if the ROHC packet is large enough to read the second byte */
	if(rohc_remain_len <= second_byte)
	{
		rohc_debugf(0, "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* part 2: 1-bit "0" + 4-bit SN + 3-bit CRC */
	assert(GET_BIT_7(rohc_remain_data) == 0);
	sn_bits = GET_BIT_3_6(rohc_remain_data);
	sn_bits_nr = 4;
	rohc_debugf(3, "%zd SN bits = 0x%x\n", sn_bits_nr, sn_bits);
	crc_packet = GET_BIT_0_2(rohc_remain_data);
	rohc_debugf(3, "CRC-3 found in packet = 0x%02x\n", crc_packet);
	/* part 3: large CID (handled elsewhere) */
	/* first byte read, second byte is part 4 */
	rohc_remain_data += second_byte;
	rohc_remain_len -= second_byte;
	rohc_header_len += second_byte;

	/* part 4: no remainder of base header for UO-0 packet */
	/* part 5: no extension for UO-0 packet */

	/* part 6: extract 16 outer IP-ID bits in case the outer IP-ID is random */
	if(ip_get_version(&g_context->active1->ip) == IPV4 && g_context->active1->rnd)
	{
		/* outer IP-ID is random, read its full 16-bit value */

		/* check if the ROHC packet is large enough to read the outer IP-ID */
		if(rohc_remain_len < 2)
		{
			rohc_debugf(0, "ROHC packet too small for random outer IP-ID bits "
			            "(len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* retrieve the full outer IP-ID value */
		ip_id_bits = ntohs(GET_NEXT_16_BITS(rohc_remain_data));
		ip_id_bits_nr = 16;
		rohc_debugf(3, "%zd outer IP-ID bits = 0x%x\n", ip_id_bits_nr, ip_id_bits);

		rohc_remain_data += 2;
		rohc_remain_len -= 2;
		rohc_header_len += 2;
	}

	/* parts 7 and 8: not supported */

	/* part 9: extract 16 inner IP-ID bits in case the inner IP-ID is random */
	if(g_context->multiple_ip &&
	   ip_get_version(&g_context->active2->ip) == IPV4 &&
	   g_context->active2->rnd)
	{
		/* inner IP-ID is random, read its full 16-bit value */

		/* check if the ROHC packet is large enough to read the inner IP-ID */
		if(rohc_remain_len < 2)
		{
			rohc_debugf(0, "ROHC packet too small for random inner IP-ID bits "
			            "(len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* retrieve the full inner IP-ID value */
		ip_id2_bits = ntohs(GET_NEXT_16_BITS(rohc_remain_data));
		ip_id2_bits_nr = 16;
		rohc_debugf(3, "%zd inner IP-ID bits = 0x%x\n", ip_id_bits_nr, ip_id_bits);

		rohc_remain_data += 2;
		rohc_remain_len -= 2;
		rohc_header_len += 2;
	}

	/* parts 10, 11 and 12: not supported */

	/* part 13: decode the tail of UO* packet */
	if(g_context->decode_uo_tail != NULL)
	{
		size = g_context->decode_uo_tail(g_context,
		                                 rohc_remain_data, rohc_remain_len,
		                                 g_context->active1->next_header);
		if(size < 0)
		{
			rohc_debugf(0, "cannot decode the tail of UO* packet\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		rohc_header_len += size;
	}

	/* ROHC UO-0 header is now fully decoded, remaining data is the payload */
	payload_data = rohc_remain_data;
	payload_len = rohc_remain_len;


	/* B. Decode extracted bits
	 *
	 * All bits are now extracted from the packet, let's decode them.
	 */

	/* decode SN */
	ret = d_lsb_decode16(&g_context->sn, sn_bits, sn_bits_nr, &sn_decoded);
	if(ret != 1)
	{
		rohc_debugf(0, "failed to decode %zd SN bits 0x%x\n", sn_bits_nr, sn_bits);
		goto error;
	}
	rohc_debugf(3, "decoded SN = %u / 0x%x (nr bits = %zd, bits = %u / 0x%x)\n",
	            sn_decoded, sn_decoded, sn_bits_nr, sn_bits, sn_bits);

	/* decode outer IP-ID (IPv4 only) */
	if(ip_get_version(&g_context->active1->ip) == IPV4)
	{
		if(g_context->active1->rnd)
		{
			ip_id_decoded = ip_id_bits;
		}
		else
		{
			ret = d_ip_id_decode(&g_context->ip_id1, ip_id_bits, ip_id_bits_nr,
			                     sn_decoded, &ip_id_decoded);
			if(ret != 1)
			{
				rohc_debugf(0, "failed to decode %zd outer IP-ID bits 0x%x\n",
				            ip_id_bits_nr, ip_id_bits);
				goto error;
			}
		}

		ipv4_set_id(&g_context->active1->ip, htons(ip_id_decoded));
		rohc_debugf(3, "decoded outer IP-ID = 0x%04x (rnd = %d, nr bits = %zd, "
		            "bits = 0x%x)\n", ntohs(ipv4_get_id(&g_context->active1->ip)),
		            g_context->active1->rnd, ip_id_bits_nr, ip_id_bits);
	}

	/* decode inner IP-ID (IPv4 only) */
	if(g_context->multiple_ip && ip_get_version(&g_context->active2->ip) == IPV4)
	{
		if(g_context->active2->rnd)
		{
			ip_id2_decoded = ip_id2_bits;
		}
		else
		{
			ret = d_ip_id_decode(&g_context->ip_id2, ip_id2_bits, ip_id2_bits_nr,
			                     sn_decoded, &ip_id2_decoded);
			if(ret != 1)
			{
				rohc_debugf(0, "failed to decode %zd inner IP-ID bits 0x%x\n",
				            ip_id2_bits_nr, ip_id2_bits);
				goto error;
			}
		}

		ipv4_set_id(&g_context->active2->ip, htons(ip_id2_decoded));
		rohc_debugf(3, "decoded inner IP-ID = 0x%04x (rnd = %d, nr bits = %zd, "
		            "bits = 0x%x)\n", ntohs(ipv4_get_id(&g_context->active2->ip)),
		            g_context->active2->rnd, ip_id2_bits_nr, ip_id2_bits);
	}

	/* decode TS (RTP profile only) */
	if(is_rtp)
	{
		struct d_rtp_context *const rtp_context =
			(struct d_rtp_context *) g_context->specific;

		rohc_debugf(3, "TS is deducted from SN\n");
		ts_decoded = ts_deducted(&rtp_context->ts_sc, sn_decoded);
	}


	/* C. Build uncompressed headers
	 *
	 * All fields are now decoded, let's build the uncompressed headers.
	 */

	uncomp_header_len = 0;

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		/* build the outer IP header */
		size = build_uncompressed_ip(g_context->active1, uncomp_packet,
		                             rohc_remain_len +
		                             ip_get_hdrlen(&g_context->active2->ip) +
		                             g_context->active1->next_header_len +
		                             g_context->active2->size_list,
		                             g_context->list_decomp1);
		ip_hdr = uncomp_packet;
		uncomp_packet += size;
		uncomp_header_len += size;

		/* build the inner IP header */
		size = build_uncompressed_ip(g_context->active2, uncomp_packet,
		                             rohc_remain_len +
		                             g_context->active2->next_header_len,
		                             g_context->list_decomp2);
		ip2_hdr = uncomp_packet;
		uncomp_packet += size;
		uncomp_header_len += size;
	}
	else
	{
		/* build the single IP header */
		size = build_uncompressed_ip(g_context->active1, uncomp_packet,
		                             rohc_remain_len +
		                             g_context->active1->next_header_len,
		                             g_context->list_decomp1);
		ip_hdr = uncomp_packet;
		ip2_hdr = NULL;
		uncomp_packet += size;
		uncomp_header_len += size;
	}

	/* TODO: next block of code should be in build_next_header() of the RTP
	         profile */
	if(is_rtp)
	{
		/* RTP Marker (M) bit.
		 * Set default value to 0 because RFC 3095 §5.7 says:
		 *   Context(M) is initially zero and is never updated. value(M) = 1
		 *   only when field(M) = 1.
		 */
		const uint8_t rtp_m_flag = 0;


		struct udphdr *const udp = (struct udphdr *) g_context->active1->next_header;
		struct rtphdr *const rtp = (struct rtphdr *) (udp + 1);

		/* update TS, SN and M flag */
		rtp->timestamp = htonl(ts_decoded);
		rtp->sn = htons(sn_decoded);
		rtp->m = rtp_m_flag & 0x1;
		rohc_debugf(3, "force RTP Marker (M) bit to %u\n", rtp->m);
	}

	/* build the next header if necessary */
	next_header = uncomp_packet;
	if(g_context->build_next_header != NULL)
	{
		size = g_context->build_next_header(g_context, g_context->active1,
		                                    uncomp_packet, rohc_remain_len);
		uncomp_packet += size;
		uncomp_header_len += size;
	}


	/* D. Check for correct decompression
	 *
	 * Use the CRC on decompressed headers to check whether decompression was
	 * correct.
	 */

	/* check CRC
	 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
	 * if the CRC-STATIC fields did not change */
	crc_computed = CRC_INIT_3;
	crc_computed = g_context->compute_crc_static(ip_hdr, ip2_hdr, next_header,
	                                             CRC_TYPE_3, crc_computed);
	crc_computed = g_context->compute_crc_dynamic(ip_hdr, ip2_hdr, next_header,
	                                              CRC_TYPE_3, crc_computed);
	rohc_debugf(3, "CRC-3 on %zd-byte uncompressed header = 0x%x\n",
	            uncomp_header_len, crc_computed);

	/* try to guess the correct SN value in case of failure */
	if(crc_computed != crc_packet)
	{
		size_t i;

		rohc_debugf(0, "CRC failure (computed = 0x%02x, packet = 0x%02x)\n",
		            crc_computed, crc_packet);
		rohc_debugf(3, "uncompressed headers (length = %zd): ", uncomp_header_len);
		for(i = 0; i < uncomp_header_len; i++)
		{
			rohc_debugf_(3, "0x%02x ", uncomp_packet[i - uncomp_header_len]);
		}
		rohc_debugf_(3, "\n");

		/* TODO: try to repair CRC failure */

		goto error_crc;
	}

	/* after CRC failure, if the SN value seems to be correctly guessed, we must
	 * wait for 3 CRC-valid packets before the correction is approved. Two
	 * packets are therefore thrown away. */
	if(g_context->correction_counter == 1)
	{
		rohc_debugf(2, "throw away packet, just 2 CRC-valid packets so far\n");

		g_context->correction_counter++;

		/* update the inter-packet variable */
		update_inter_packet(g_context);
		synchronize(g_context);

		/* update SN (and IP-IDs if IPv4) */
		d_lsb_sync_ref(&g_context->sn);
		d_lsb_update(&g_context->sn, sn_decoded);
		if(ip_get_version(&g_context->active1->ip) == IPV4)
		{
			d_ip_id_update(&g_context->ip_id1, ip_id_decoded, sn_decoded);
		}
		if(g_context->multiple_ip &&
		   ip_get_version(&g_context->active2->ip) == IPV4)
		{
			d_ip_id_update(&g_context->ip_id2, ip_id2_decoded, sn_decoded);
		}

		goto error_crc;
	}
	else if(g_context->correction_counter == 2)
	{
		g_context->correction_counter = 0;
		rohc_debugf(2, "the repair is deemed successful\n");
	}
	else if(g_context->correction_counter != 0)
	{
		rohc_debugf(0, "CRC-valid counter not valid (%u)\n",
		            g_context->correction_counter);
		g_context->correction_counter = 0;
		goto error_crc;
	}


	/* E. Update the compression context
	 *
	 * Once CRC check is done, update the compression context with the values
	 * that were decoded earlier.
	 *
	 * TODO: check what fields shall be updated in the context
	 */

	/* update the inter-packet variable */
	update_inter_packet(g_context);
	synchronize(g_context);

	/* update SN (and IP-IDs if IPv4) */	
	d_lsb_sync_ref(&g_context->sn);
	d_lsb_update(&g_context->sn, sn_decoded);
	if(ip_get_version(&g_context->active1->ip) == IPV4)
	{
		d_ip_id_update(&g_context->ip_id1, ip_id_decoded, sn_decoded);
	}
	if(g_context->multiple_ip &&
	   ip_get_version(&g_context->active2->ip) == IPV4)
	{
		d_ip_id_update(&g_context->ip_id2, ip_id2_decoded, sn_decoded);
	}

	/* RTP */
	if(is_rtp)
	{
		struct d_rtp_context *const rtp_context =
			(struct d_rtp_context *) g_context->specific;
		d_add_ts(&rtp_context->ts_sc, ts_decoded, sn_decoded);
	}

	/* payload */
	rohc_debugf(3, "ROHC payload (length = %zd bytes) starts at offset %zd\n",
	            payload_len, rohc_header_len);
	if((rohc_header_len + payload_len) != rohc_length)
	{
		rohc_debugf(0, "ROHC UO-0 header (%zd bytes) and payload (%zd bytes) "
		            "do not match the full ROHC UO-0 packet (%u bytes)\n",
		            rohc_header_len, payload_len, rohc_length);
		goto error;
	}
	if(payload_len != 0)
	{
		memcpy(uncomp_packet, payload_data, payload_len);
	}

	/* statistics */
	context->header_compressed_size += rohc_header_len;
	c_add_wlsb(context->header_16_compressed, 0, rohc_header_len);
	context->header_uncompressed_size += uncomp_header_len;
	c_add_wlsb(context->header_16_uncompressed, 0, uncomp_header_len);

	return (uncomp_header_len + payload_len);

error:
	return ROHC_ERROR;
error_crc:
	return ROHC_ERROR_CRC;
}


/**
 * @brief Decode one UO-1 packet.
 *
 * Steps:
 *  A. Parsing of ROHC header
 *  B. Decode extracted bits
 *  C. Build uncompressed headers
 *  D. Check for correct decompression
 *  E. Update the compression context
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

\endverbatim

Here are the first octet and remainder of UO-1 base headers:

\verbatim

 UO-1 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |         IP-ID         |
    +===+===+===+===+===+===+===+===+
 4  |        SN         |    CRC    |
    +---+---+---+---+---+---+---+---+

 UO-1-RTP (5.7.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |          TS           |
    +===+===+===+===+===+===+===+===+
 4  | M |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

 UO-1-ID (5.7.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |T=0|      IP-ID        |
    +===+===+===+===+===+===+===+===+
 4  | M |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

 UO-1-TS (5.7.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |T=1|        TS         |
    +===+===+===+===+===+===+===+===+
 4  | M |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

 UO-1 and UO-1-ID cannot be used if there is no IPv4 header in the context or
 if value(RND) and value(RND2) are both 1.

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in the parent function.
 * Parts 2, 4, 6 and 9 are parsed in this function.
 * Part 5 does not exist in the UO-1 packet.
 * Part 13 is parsed in profile-specific function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param second_byte    The offset of the 2nd byte in the ROHC packet
 * @param uncomp_packet  OUT: The decoded IP packet
 * @return               The length of the uncompressed IP packet
 *                       ROHC_ERROR if an error occurs
 *                       ROHC_ERROR_CRC if a CRC error occurs
 */
int decode_uo1(struct rohc_decomp *decomp,
               struct d_context *context,
               const unsigned char *const rohc_packet,
               const unsigned int rohc_length,
               int second_byte,
               unsigned char *uncomp_packet)
{
	struct d_generic_context *const g_context = context->specific;
	const rohc_packet_t packet_type = g_context->packet_type;

	/* Whether the current profile is RTP or not */
	const int is_rtp = (context->profile->id == ROHC_PROFILE_RTP);

	/* extracted bits and decoded value for SN */
	uint16_t sn_decoded;
	uint16_t sn_bits;
	size_t sn_bits_nr;

	/* extracted bits and decoded value for TS */
	uint32_t ts_decoded = 0; /* initialized only because of GCC warning */
	uint32_t ts_bits = 0;
	size_t ts_bits_nr = 0;

	/* extracted bits and decoded value for outer IP-ID */
	uint16_t ip_id_decoded = 0; /* initialized only because of GCC warning */
	uint16_t ip_id_bits = 0;
	size_t ip_id_bits_nr = 0;

	/* extracted bits and decoded value for inner IP-ID */
	uint16_t ip_id2_decoded = 0; /* initialized only because of GCC warning */
	uint16_t ip_id2_bits = 0;
	size_t ip_id2_bits_nr = 0;

	/* CRC found in packet and computed one */
	uint8_t crc_packet;
	uint8_t crc_computed;

	/* RTP Marker (M) bit.
	 * Set default value to 0 because RFC 3095 §5.7 says:
	 *   Context(M) is initially zero and is never updated. value(M) = 1
	 *   only when field(M) = 1.
	 */
	uint8_t rtp_m_flag = 0;
	/* RTP eXtension (R-X) flag */
	uint8_t rtp_x_bits = 0;
	size_t rtp_x_bits_nr = 0;
	/* RTP Padding (R-P) flag */
	uint8_t rtp_p_bits = 0;
	size_t rtp_p_bits_nr = 0;
	/* RTP Payload Type (RTP-PT) */
	uint8_t rtp_pt_bits = 0;
	size_t rtp_pt_bits_nr = 0;

	/* According to RFC 3095 §5.7.5:
	 *   The TS field is scaled in all extensions, as it is in the base header,
	 *   except optionally when using Extension 3 where the Tsc flag can
	 *   indicate that the TS field is not scaled.
	 * So init the is_ts_scaled variable to 1 by default. \ref decode_extension3
	 * will reset it to 0 if needed.
	 */
	int is_ts_scaled = 1;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;
	size_t rohc_header_len = 0;

	/* length of the uncompressed headers and pointers on uncompressed outer
	   IP, inner IP and next headers (will be computed during building) */
	size_t uncomp_header_len;
	unsigned char *ip_hdr;
	unsigned char *ip2_hdr;
	unsigned char *next_header;

	/* ROHC and uncompressed payloads (they are the same) */
	const unsigned char *payload_data;
	size_t payload_len;

	/* helper variables for values returned by functions */
	int size;
	int ret;


	/* check packet usage */
	if(is_rtp && packet_type == PACKET_UO_1)
	{
		rohc_debugf(0, "UO-1 packet cannot be used with RTP profile\n");
		assert(0);
		goto error;
	}
	else if(!is_rtp && (packet_type == PACKET_UO_1_RTP ||
	                    packet_type == PACKET_UO_1_TS ||
	                    packet_type == PACKET_UO_1_ID))
	{
		rohc_debugf(0, "UO-1-RTP/TS/ID packets cannot be used with non-RTP "
		               "profiles\n");
		assert(0);
		goto error;
	}

	if(g_context->active1->complist)
		g_context->list_decomp1->ref_ok = 1;
	if(g_context->multiple_ip && g_context->active2->complist)
		g_context->list_decomp2->ref_ok = 1;


	/* A. Parsing of ROHC base header
	 *
	 * Let's parse fields 2 to 13.
	 */

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;

	/* check if the ROHC packet is large enough to read the second byte */
	if(rohc_remain_len <= second_byte)
	{
		rohc_debugf(0, "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* parts 2 and 4 depending on the packet type */
	switch(packet_type)
	{
		case PACKET_UO_1:
		{
			/* part 2: 2-bit "10" + 6-bit IP-ID */
			assert(GET_BIT_6_7(rohc_remain_data) == 0x02);
			ip_id_bits = GET_BIT_0_5(rohc_remain_data);
			ip_id_bits_nr = 6;
			rohc_debugf(3, "%zd outer IP-ID bits = 0x%x\n", ip_id_bits_nr, ip_id_bits);
			/* part 3: large CID (handled elsewhere) */
			/* part 4: 5-bit SN + 3-bit CRC */
			sn_bits = GET_BIT_3_7(rohc_remain_data + second_byte);
			sn_bits_nr = 5;
			rohc_debugf(3, "%zd SN bits = 0x%x\n", sn_bits_nr, sn_bits);
			crc_packet = GET_BIT_0_2(rohc_remain_data + second_byte);
			rohc_debugf(3, "CRC-3 found in packet = 0x%02x\n", crc_packet);
			break;
		}

		case PACKET_UO_1_RTP:
		{
			/* part 2: 2-bit "10" + 6-bit TS */
			assert(GET_BIT_6_7(rohc_remain_data) == 0x02);
			ts_bits = GET_BIT_0_5(rohc_remain_data);
			ts_bits_nr = 6;
			rohc_debugf(3, "%zd TS bits = 0x%x\n", ts_bits_nr, ts_bits);
			/* part 3: large CID (handled elsewhere) */
			/* part 4: 1-bit M + 4-bit SN + 3-bit CRC */
			rtp_m_flag = GET_REAL(GET_BIT_7(rohc_remain_data + second_byte));
			rohc_debugf(3, "1-bit RTP Marker (M) = %u\n", rtp_m_flag);
			sn_bits = GET_BIT_3_6(rohc_remain_data + second_byte);
			sn_bits_nr = 4;
			rohc_debugf(3, "%zd SN bits = 0x%x\n", sn_bits_nr, sn_bits);
			crc_packet = GET_BIT_0_2(rohc_remain_data + second_byte);
			rohc_debugf(3, "CRC-3 found in packet = 0x%02x\n", crc_packet);
			break;
		}

		case PACKET_UO_1_ID:
		{
			/* part 2: 2-bit "10" + 1-bit "T=0" + 5-bit IP-ID */
			assert(GET_BIT_6_7(rohc_remain_data) == 0x02);
			assert(GET_BIT_5(rohc_remain_data) == 0);
			ip_id_bits = GET_BIT_0_4(rohc_remain_data);
			ip_id_bits_nr = 5;
			rohc_debugf(3, "%zd outer IP-ID bits = 0x%x\n", ip_id_bits_nr, ip_id_bits);
			/* part 3: large CID (handled elsewhere) */
			/* part 4: 1-bit M + 4-bit SN + 3-bit CRC */
			rtp_m_flag = GET_REAL(GET_BIT_7(rohc_remain_data + second_byte));
			rohc_debugf(3, "1-bit RTP Marker (M) = %u\n", rtp_m_flag);
			sn_bits = GET_BIT_3_6(rohc_remain_data + second_byte);
			sn_bits_nr = 4;
			rohc_debugf(3, "%zd SN bits = 0x%x\n", sn_bits_nr, sn_bits);
			crc_packet = GET_BIT_0_2(rohc_remain_data + second_byte);
			rohc_debugf(3, "CRC-3 found in packet = 0x%02x\n", crc_packet);
			break;
		}

		case PACKET_UO_1_TS:
		{
			/* part 2: 2-bit "10" + 1-bit "T=1" + 5-bit TS */
			assert(GET_BIT_6_7(rohc_remain_data) == 0x02);
			assert(GET_BIT_5(rohc_remain_data) != 0);
			ts_bits = GET_BIT_0_4(rohc_remain_data);
			ts_bits_nr = 5;
			rohc_debugf(3, "%zd TS bits = 0x%x\n", ts_bits_nr, ts_bits);
			/* part 3: large CID (handled elsewhere) */
			/* part 4: 1-bit M + 4-bit SN + 3-bit CRC */
			rtp_m_flag = GET_REAL(GET_BIT_7(rohc_remain_data + second_byte));
			rohc_debugf(3, "1-bit RTP Marker (M) = %u\n", rtp_m_flag);
			sn_bits = GET_BIT_3_6(rohc_remain_data + second_byte);
			sn_bits_nr = 4;
			rohc_debugf(3, "%zd SN bits = 0x%x\n", sn_bits_nr, sn_bits);
			crc_packet = GET_BIT_0_2(rohc_remain_data + second_byte);
			rohc_debugf(3, "CRC-3 found in packet = 0x%02x\n", crc_packet);
			break;
		}

		default:
		{
			rohc_debugf(0, "bad packet type (%d)\n", packet_type);
			assert(0);
			goto error;
		}
	}
	/* first and second bytes read */
	rohc_remain_data += second_byte + 1;
	rohc_remain_len -= second_byte + 1;
	rohc_header_len += second_byte + 1;

	/* part 5: no extension for UO-1 packet */

	/* part 6: extract 16 outer IP-ID bits in case the outer IP-ID is random */
	if(ip_get_version(&g_context->active1->ip) == IPV4 && g_context->active1->rnd)
	{
		/* outer IP-ID is random, read its full 16-bit value and ignore any
		   previous bits we may have read (they should be filled with zeroes) */

		/* check if the ROHC packet is large enough to read the outer IP-ID */
		if(rohc_remain_len < 2)
		{
			rohc_debugf(0, "ROHC packet too small for random outer IP-ID bits "
			            "(len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* sanity check: all bits that are above 16 bits should be zero */
		if(ip_id_bits_nr > 0 && ip_id_bits != 0)
		{
			rohc_debugf(0, "bad packet format: outer IP-ID bits from the base ROHC "
			            "header shall be filled with zeroes but 0x%x was found\n",
			            ip_id_bits);
		}

		/* retrieve the full outer IP-ID value */
		ip_id_bits = ntohs(GET_NEXT_16_BITS(rohc_remain_data));
		ip_id_bits_nr = 16;

		rohc_debugf(3, "replace any existing outer IP-ID bits with the ones "
		            "found at the end of the UO-1* packet (0x%x on %zd bits)\n",
		            ip_id_bits, ip_id_bits_nr);

		rohc_remain_data += 2;
		rohc_remain_len -= 2;
		rohc_header_len += 2;
	}

	/* parts 7 and 8: not supported */

	/* part 9: extract 16 inner IP-ID bits in case the inner IP-ID is random */
	if(g_context->multiple_ip &&
	   ip_get_version(&g_context->active2->ip) == IPV4 &&
	   g_context->active2->rnd)
	{
		/* inner IP-ID is random, read its full 16-bit value and ignore any
		   previous bits we may have read (they should be filled with zeroes) */

		/* check if the ROHC packet is large enough to read the inner IP-ID */
		if(rohc_remain_len < 2)
		{
			rohc_debugf(0, "ROHC packet too small for random inner IP-ID bits "
			            "(len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* sanity check: all bits that are above 16 bits should be zero */
		if(ip_id2_bits_nr > 0 && ip_id2_bits != 0)
		{
			rohc_debugf(0, "bad packet format: inner IP-ID bits from the base ROHC "
			            "header shall be filled with zeroes but 0x%x was found\n",
			            ip_id2_bits);
		}

		/* retrieve the full inner IP-ID value */
		ip_id2_bits = ntohs(GET_NEXT_16_BITS(rohc_remain_data));
		ip_id2_bits_nr = 16;

		rohc_debugf(3, "replace any existing inner IP-ID bits with the ones "
		            "found at the end of the UO-1* packet (0x%x on %zd bits)\n",
		            ip_id2_bits, ip_id2_bits_nr);

		rohc_remain_data += 2;
		rohc_remain_len -= 2;
		rohc_header_len += 2;
	}

	/* parts 10, 11 and 12: not supported */

	/* part 13: decode the tail of UO* packet */
	if(g_context->decode_uo_tail != NULL)
	{
		size = g_context->decode_uo_tail(g_context,
		                                 rohc_remain_data, rohc_remain_len,
		                                 g_context->active1->next_header);
		if(size < 0)
		{
			rohc_debugf(0, "cannot decode the tail of UO* packet\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		rohc_header_len += size;
	}

	/* ROHC UO-1 header and its extension are now fully decoded, remaining
	   data is the payload */
	payload_data = rohc_remain_data;
	payload_len = rohc_remain_len;


	/* B. Decode extracted bits
	 *
	 * All bits are now extracted from the packet, let's decode them.
	 */

	/* decode SN */
	ret = d_lsb_decode16(&g_context->sn, sn_bits, sn_bits_nr, &sn_decoded);
	if(ret != 1)
	{
		rohc_debugf(0, "failed to decode %zd SN bits 0x%x\n", sn_bits_nr, sn_bits);
		goto error;
	}
	rohc_debugf(3, "decoded SN = %u / 0x%x (nr bits = %zd, bits = %u / 0x%x)\n",
	            sn_decoded, sn_decoded, sn_bits_nr, sn_bits, sn_bits);

	/* decode outer IP-ID (IPv4 only) */
	if(ip_get_version(&g_context->active1->ip) == IPV4)
	{
		if(g_context->active1->rnd)
		{
			ip_id_decoded = ip_id_bits;
		}
		else
		{
			ret = d_ip_id_decode(&g_context->ip_id1, ip_id_bits, ip_id_bits_nr,
			                     sn_decoded, &ip_id_decoded);
			if(ret != 1)
			{
				rohc_debugf(0, "failed to decode %zd outer IP-ID bits 0x%x\n",
				            ip_id_bits_nr, ip_id_bits);
				goto error;
			}
		}

		ipv4_set_id(&g_context->active1->ip, htons(ip_id_decoded));
		rohc_debugf(3, "decoded outer IP-ID = 0x%04x (rnd = %d, nr bits = %zd, "
		            "bits = 0x%x)\n", ntohs(ipv4_get_id(&g_context->active1->ip)),
		            g_context->active1->rnd, ip_id_bits_nr, ip_id_bits);
	}

	/* decode inner IP-ID (IPv4 only) */
	if(g_context->multiple_ip && ip_get_version(&g_context->active2->ip) == IPV4)
	{
		if(g_context->active2->rnd)
		{
			ip_id2_decoded = ip_id2_bits;
		}
		else
		{
			ret = d_ip_id_decode(&g_context->ip_id2, ip_id2_bits, ip_id2_bits_nr,
			                     sn_decoded, &ip_id2_decoded);
			if(ret != 1)
			{
				rohc_debugf(0, "failed to decode %zd inner IP-ID bits 0x%x\n",
				            ip_id2_bits_nr, ip_id2_bits);
				goto error;
			}
		}

		ipv4_set_id(&g_context->active2->ip, htons(ip_id2_decoded));
		rohc_debugf(3, "decoded inner IP-ID = 0x%04x (rnd = %d, nr bits = %zd, "
		            "bits = 0x%x)\n", ntohs(ipv4_get_id(&g_context->active2->ip)),
		            g_context->active2->rnd, ip_id2_bits_nr, ip_id2_bits);
	}

	/* decode TS (RTP profile only) */
	if(is_rtp)
	{
		struct d_rtp_context *const rtp_context =
			(struct d_rtp_context *) g_context->specific;

		rohc_debugf(3, "%zd-bit TS delta = 0x%x\n", ts_bits_nr, ts_bits);

		if(is_ts_scaled)
		{
			rohc_debugf(3, "TS is scaled\n");
			ret = d_decode_ts(&rtp_context->ts_sc, ts_bits, ts_bits_nr, &ts_decoded);
			if(ret != 1)
			{
				rohc_debugf(0, "failed to decode %zd-bit TS_SCALED 0x%x\n",
				            ts_bits_nr, ts_bits);
				goto error;
			}
		}
		else if(ts_bits_nr == 0)
		{
			rohc_debugf(3, "TS is deducted from SN\n");
			ts_decoded = ts_deducted(&rtp_context->ts_sc, sn_decoded);
		}
		else
		{
			rohc_debugf(3, "TS is not scaled\n");
			ts_decoded = ts_bits;
		}

		rohc_debugf(3, "decoded timestamp = %u / 0x%x (nr bits = %zd, "
		            "bits = %u / 0x%x)\n", ts_decoded, ts_decoded,
		            ts_bits_nr, ts_bits, ts_bits);
	}


	/* C. Build uncompressed headers
	 *
	 * All fields are now decoded, let's build the uncompressed headers.
	 */

	uncomp_header_len = 0;

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		/* build the outer IP header */
		size = build_uncompressed_ip(g_context->active1, uncomp_packet,
		                             rohc_remain_len +
		                             ip_get_hdrlen(&g_context->active2->ip) +
		                             g_context->active1->next_header_len +
		                             g_context->active2->size_list,
		                             g_context->list_decomp1);
		ip_hdr = uncomp_packet;
		uncomp_packet += size;
		uncomp_header_len += size;

		/* build the inner IP header */
		size = build_uncompressed_ip(g_context->active2, uncomp_packet,
		                             rohc_remain_len +
		                             g_context->active2->next_header_len,
		                             g_context->list_decomp2);
		ip2_hdr = uncomp_packet;
		uncomp_packet += size;
		uncomp_header_len += size;
	}
	else
	{
		/* build the single IP header */
		size = build_uncompressed_ip(g_context->active1, uncomp_packet,
		                             rohc_remain_len +
		                             g_context->active1->next_header_len,
		                             g_context->list_decomp1);
		ip_hdr = uncomp_packet;
		ip2_hdr = NULL;
		uncomp_packet += size;
		uncomp_header_len += size;
	}

	/* TODO: next block of code should be in build_next_header() of the RTP
	         profile */
	if(is_rtp)
	{
		struct udphdr *const udp = (struct udphdr *) g_context->active1->next_header;
		struct rtphdr *const rtp = (struct rtphdr *) (udp + 1);

		/* update TS, SN and M flag */
		rtp->timestamp = htonl(ts_decoded);
		rtp->sn = htons(sn_decoded);
		rtp->m = rtp_m_flag & 0x1;
		rohc_debugf(3, "force RTP Marker (M) bit to %u\n", rtp->m);

		/* update the RTP eXtension (R-X) flag if present */
		if(rtp_x_bits_nr > 0)
		{
			rtp->extension = rtp_x_bits;
		}

		/* update RTP Padding (R-P) flag if present */
		if(rtp_p_bits_nr > 0)
		{
			rtp->padding = rtp_p_bits;
		}

		/* update RTP Payload Type (R-PT) field if present */
		if(rtp_pt_bits_nr > 0)
		{
			rtp->pt = rtp_pt_bits;
			rohc_debugf(3, "force RTP Payload Type (R-PT) = 0x%x\n", rtp_pt_bits);
		}
	}

	/* build the next header if necessary */
	next_header = uncomp_packet;
	if(g_context->build_next_header != NULL)
	{
		size = g_context->build_next_header(g_context, g_context->active1,
		                                    uncomp_packet, rohc_remain_len);
		uncomp_packet += size;
		uncomp_header_len += size;
	}

	/* D. Check for correct decompression
	 *
	 * Use the CRC on decompressed headers to check whether decompression was
	 * correct.
	 */

	/* CRC check
	 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
	 * if the CRC-STATIC fields did not change */
	crc_computed = CRC_INIT_3;
	crc_computed = g_context->compute_crc_static(ip_hdr, ip2_hdr, next_header,
	                                             CRC_TYPE_3, crc_computed);
	crc_computed = g_context->compute_crc_dynamic(ip_hdr, ip2_hdr, next_header,
	                                              CRC_TYPE_3, crc_computed);
	rohc_debugf(3, "CRC-3 on %zd-byte uncompressed header = 0x%x\n",
	            uncomp_header_len, crc_computed);

	/* try to guess the correct SN value in case of failure */
	if(crc_computed != crc_packet)
	{
		size_t i;

		rohc_debugf(0, "CRC failure (computed = 0x%02x, packet = 0x%02x)\n",
		            crc_computed, crc_packet);
		rohc_debugf(3, "uncompressed headers (length = %zd): ", uncomp_header_len);
		for(i = 0; i < uncomp_header_len; i++)
		{
			rohc_debugf_(3, "0x%02x ", uncomp_packet[i - uncomp_header_len]);
		}
		rohc_debugf_(3, "\n");

		/* TODO: try to repair CRC failure */

		goto error_crc;
	}

	/* after CRC failure, if the SN value seems to be correctly guessed, we must
	 * wait for 3 CRC-valid packets before the correction is approved. Two
	 * packets are therefore thrown away. */
	if(g_context->correction_counter == 1)
	{
		rohc_debugf(2, "throw away packet, just 2 CRC-valid packets so far\n");

		g_context->correction_counter++;

		/* update the inter-packet variable */
		update_inter_packet(g_context);
		synchronize(g_context);

		/* update SN (and IP-IDs if IPv4) */
		d_lsb_sync_ref(&g_context->sn);
		d_lsb_update(&g_context->sn, sn_decoded);
		if(ip_get_version(&g_context->active1->ip) == IPV4)
		{
			d_ip_id_update(&g_context->ip_id1, ip_id_decoded, sn_decoded);
		}
		if(g_context->multiple_ip &&
		   ip_get_version(&g_context->active2->ip) == IPV4)
		{
			d_ip_id_update(&g_context->ip_id2, ip_id2_decoded, sn_decoded);
		}

		goto error_crc;
	}
	else if(g_context->correction_counter == 2)
	{
		g_context->correction_counter = 0;
		rohc_debugf(2, "the repair is deemed successful\n");
	}
	else if(g_context->correction_counter != 0)
	{
		rohc_debugf(0, "CRC-valid counter not valid (%u)\n",
		            g_context->correction_counter);
		g_context->correction_counter = 0;
		goto error_crc;
	}


	/* E. Update the compression context
	 *
	 * Once CRC check is done, update the compression context with the values
	 * that were decoded earlier.
	 *
	 * TODO: check what fields shall be updated in the context
	 */

	/* update the inter-packet variable */
	update_inter_packet(g_context);
	synchronize(g_context);

	/* update SN and IP-IDs */
	d_lsb_sync_ref(&g_context->sn);
	d_lsb_update(&g_context->sn, sn_decoded);
	if(ip_get_version(&g_context->active1->ip) == IPV4)
	{
		d_ip_id_update(&g_context->ip_id1, ip_id_decoded, sn_decoded);
	}
	if(g_context->multiple_ip &&
	   ip_get_version(&g_context->active2->ip) == IPV4)
	{
		d_ip_id_update(&g_context->ip_id2, ip_id2_decoded, sn_decoded);
	}
		
	/* RTP */
	if(is_rtp)
	{
		struct d_rtp_context *const rtp_context =
			(struct d_rtp_context *) g_context->specific;
		d_add_ts(&rtp_context->ts_sc, ts_decoded, sn_decoded);
	}

	/* payload */
	rohc_debugf(3, "ROHC payload (length = %zd bytes) starts at offset %zd\n",
	            payload_len, rohc_header_len);
	if((rohc_header_len + payload_len) != rohc_length)
	{
		rohc_debugf(0, "ROHC UO-1 header (%zd bytes) and payload (%zd bytes) "
		            "do not match the full ROHC UO-1 packet (%u bytes)\n",
		            rohc_header_len, payload_len, rohc_length);
		goto error;
	}
	if(payload_len != 0)
	{
		memcpy(uncomp_packet, payload_data, payload_len);
	}

	/* statistics */
	context->header_compressed_size += rohc_header_len;
	c_add_wlsb(context->header_16_compressed, 0, rohc_header_len);
	context->header_uncompressed_size += uncomp_header_len;
	c_add_wlsb(context->header_16_uncompressed, 0, uncomp_header_len);

	return (uncomp_header_len + payload_len);

error:
	return ROHC_ERROR;
error_crc:
	return ROHC_ERROR_CRC;
}


/**
 * @brief Decode one UOR-2 packet.
 *
 * Steps:
 *  A. Parsing of ROHC base header
 *  B. Parsing of ROHC extension header
 *  C. Parsing of ROHC tail of header
 *  D. Decode extracted bits
 *  E. Build uncompressed headers
 *  F. Check for correct decompression
 *  G. Update the compression context
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

\endverbatim

Here are the first octet and remainder of UOR-2 base headers:

\verbatim

 UOR-2 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        SN         |
    +===+===+===+===+===+===+===+===+
 4  | X |            CRC            |
    +---+---+---+---+---+---+---+---+

 UOR-2-RTP (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        TS         |
    +===+===+===+===+===+===+===+===+
 4a | TS| M |       SN              |
    +---+---+---+---+---+---+---+---+
 4b | X |            CRC            |
    +---+---+---+---+---+---+---+---+

 UOR-2-TS (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        TS         |
    +===+===+===+===+===+===+===+===+
 4a |T=1| M |          SN           |
    +---+---+---+---+---+---+---+---+
 4b | X |           CRC             |
    +---+---+---+---+---+---+---+---+

 UOR-2-ID (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |      IP-ID        |
    +===+===+===+===+===+===+===+===+
 4a |T=0| M |          SN           |
    +---+---+---+---+---+---+---+---+
 4b | X |           CRC             |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in the parent function.
 * Parts 2, 4, 5, 6 and 9 are parsed in this function.
 * Part 13 is parsed in profile-specific function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param second_byte    The offset of the 2nd byte in the ROHC packet
 * @param uncomp_packet  OUT: The decoded IP packet
 * @return               The length of the uncompressed IP packet
 *                       ROHC_ERROR if an error occurs
 *                       ROHC_ERROR_CRC if a CRC error occurs
 *                       ROHC_NEED_REPARSE if packet needs to be parsed again
 */
int decode_uor2(struct rohc_decomp *decomp,
                struct d_context *context,
                const unsigned char *const rohc_packet,
                const unsigned int rohc_length,
                int second_byte,
                unsigned char *uncomp_packet)
{
	struct d_generic_context *const g_context = context->specific;
	const rohc_packet_t packet_type = g_context->packet_type;

	/* Whether the current profile is RTP or not */
	const int is_rtp = (context->profile->id == ROHC_PROFILE_RTP);

	/* extracted bits and decoded value for SN */
	uint16_t sn_decoded;
	uint16_t sn_bits;
	size_t sn_bits_nr;

	/* extracted bits and decoded value for TS */
	uint32_t ts_decoded = 0; /* initialized only because of GCC warning */
	uint32_t ts_bits = 0;
	size_t ts_bits_nr = 0;

	/* extracted bits and decoded value for outer IP-ID */
	uint16_t ip_id_decoded = 0; /* initialized only because of GCC warning */
	uint16_t ip_id_bits = 0;
	size_t ip_id_bits_nr = 0;

	/* extracted bits and decoded value for inner IP-ID */
	uint16_t ip_id2_decoded = 0; /* initialized only because of GCC warning */
	uint16_t ip_id2_bits = 0;
	size_t ip_id2_bits_nr = 0;

	/* CRC found in packet and computed one */
	uint8_t crc_packet;
	size_t crc_packet_size;
	uint8_t crc_computed;
	int crc_type;

	/* RTP Marker (M) bit.
	 * Set default value to 0 because RFC 3095 §5.7 says:
	 *   Context(M) is initially zero and is never updated. value(M) = 1
	 *   only when field(M) = 1.
	 */
	uint8_t rtp_m_flag = 0;
	/* RTP eXtension (R-X) flag */
	uint8_t rtp_x_bits = 0;
	size_t rtp_x_bits_nr = 0;
	/* RTP Padding (R-P) flag */
	uint8_t rtp_p_bits = 0;
	size_t rtp_p_bits_nr = 0;
	/* RTP Payload Type (RTP-PT) */
	uint8_t rtp_pt_bits = 0;
	size_t rtp_pt_bits_nr = 0;

	/* X (extension) flag */
	uint8_t ext_flag;

	/* According to RFC 3095 §5.7.5:
	 *   The TS field is scaled in all extensions, as it is in the base header,
	 *   except optionally when using Extension 3 where the Tsc flag can
	 *   indicate that the TS field is not scaled.
	 * So init the is_ts_scaled variable to 1 by default. \ref decode_extension3
	 * will reset it to 0 if needed.
	 */
	int is_ts_scaled = 1;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;
	size_t rohc_header_len = 0;

	/* length of the uncompressed headers and pointers on uncompressed outer
	   IP, inner IP and next headers (will be computed during building) */
	size_t uncomp_header_len;
	unsigned char *ip_hdr;
	unsigned char *ip2_hdr;
	unsigned char *next_header;

	/* ROHC and uncompressed payloads (they are the same) */
	const unsigned char *payload_data;
	size_t payload_len;

	/* helper variables for values returned by functions */
	int size;
	int ret;


	/* check packet usage */
	if(is_rtp && packet_type == PACKET_UOR_2)
	{
		rohc_debugf(0, "UOR-2 packet cannot be used with RTP profile\n");
		assert(0);
		goto error;
	}
	else if(!is_rtp && (packet_type == PACKET_UOR_2_RTP ||
	                    packet_type == PACKET_UOR_2_TS ||
	                    packet_type == PACKET_UOR_2_ID))
	{
		rohc_debugf(0, "UOR-2-RTP/TS/ID packets cannot be used with non-RTP "
		               "profiles\n");
		assert(0);
		goto error;
	}

	if(g_context->active1->complist)
		g_context->list_decomp1->ref_ok = 1;
	if(g_context->multiple_ip && g_context->active2->complist)
		g_context->list_decomp2->ref_ok = 1;


	/* A. Parsing of ROHC base header
	 *
	 * Let's parse fields 2 and 4.
	 */

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;

	/* check if the ROHC packet is large enough to read the second byte */
	if(rohc_remain_len <= second_byte)
	{
		rohc_debugf(0, "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* parts 2 and 4 depending on the packet type:
	   TimeStamp or IP-ID + Sequence Number + M flag */
	switch(packet_type)
	{
		case PACKET_UOR_2:
		{
			/* part 2: 3-bit "110" + 5-bit SN */
			assert(GET_BIT_5_7(rohc_remain_data) == 0x06);
			sn_bits = GET_BIT_0_4(rohc_remain_data);
			sn_bits_nr = 5;
			rohc_debugf(3, "%zd SN bits = 0x%x\n", sn_bits_nr, sn_bits);
			/* part 3: large CID (handled elsewhere) */
			/* first byte read, second byte is CRC (part 4) */
			rohc_remain_data += second_byte;
			rohc_remain_len -= second_byte;
			rohc_header_len += second_byte;
			break;
		}

		case PACKET_UOR_2_RTP:
		{
			/* part 2: 3-bit "110" + 5-bit TS */
			assert(GET_BIT_5_7(rohc_remain_data) == 0x06);
			ts_bits = GET_BIT_0_4(rohc_remain_data) << 1;
			ts_bits_nr = 5;
			/* part 3: large CID (handled elsewhere) */
			/* part 4a: 1-bit TS (ignored) + 1-bit M flag + 6-bit SN */
			ts_bits |= GET_REAL(GET_BIT_7(rohc_remain_data + second_byte));
			ts_bits_nr += 1;
			rohc_debugf(3, "%zd TS bits = 0x%x\n", ts_bits_nr, ts_bits);
			rtp_m_flag = GET_REAL(GET_BIT_6(rohc_remain_data + second_byte));
			rohc_debugf(3, "M flag = %u\n", rtp_m_flag);
			sn_bits = GET_BIT_0_5(rohc_remain_data + second_byte);
			sn_bits_nr = 6;
			rohc_debugf(3, "%zd SN bits = 0x%x\n", sn_bits_nr, sn_bits);
			/* first and second bytes read, third byte is CRC (part 4b) */
			rohc_remain_data += second_byte + 1;
			rohc_remain_len -= second_byte + 1;
			rohc_header_len += second_byte + 1;
			break;
		}

		case PACKET_UOR_2_TS:
		{
			/* part 2: 3-bit "110" + 5-bit TS */
			assert(GET_BIT_5_7(rohc_remain_data) == 0x06);
			ts_bits = GET_BIT_0_4(rohc_remain_data);
			ts_bits_nr = 5;
			rohc_debugf(3, "%zd TS bits = 0x%x\n", ts_bits_nr, ts_bits);
			/* part 3: large CID (handled elsewhere) */
			/* part 4a: 1-bit T flag (ignored) + 1-bit M flag + 6-bit SN */
			rtp_m_flag = GET_REAL(GET_BIT_6(rohc_remain_data + second_byte));
			rohc_debugf(3, "M flag = %u\n", rtp_m_flag);
			sn_bits = GET_BIT_0_5(rohc_remain_data + second_byte);
			sn_bits_nr = 6;
			rohc_debugf(3, "%zd SN bits = 0x%x\n", sn_bits_nr, sn_bits);
			/* first and second bytes read, third byte is CRC (part 4b) */
			rohc_remain_data += second_byte + 1;
			rohc_remain_len -= second_byte + 1;
			rohc_header_len += second_byte + 1;
			break;
		}

		case PACKET_UOR_2_ID:
		{
			/* check extension usage */
			if((ip_get_version(&g_context->active1->ip) != IPV4 &&
			    !g_context->multiple_ip) ||
			   (ip_get_version(&g_context->active1->ip) != IPV4 &&
			    g_context->multiple_ip &&
			    ip_get_version(&g_context->active2->ip) != IPV4))
			{
				rohc_debugf(0, "cannot use the UOR-2-ID packet with no IPv4 header\n");
				goto error;
			}

			/* part 2: 3-bit "110" + 5-bit IP-ID */
			assert(GET_BIT_5_7(rohc_remain_data) == 0x06);
			ip_id_bits = GET_BIT_0_4(rohc_remain_data);
			ip_id_bits_nr = 5;
			rohc_debugf(3, "%zd IP-ID bits = 0x%x\n", ip_id_bits_nr, ip_id_bits);
			/* part 3: large CID (handled elsewhere) */
			/* part 4a: 1-bit T flag (ignored) + 1-bit M flag + 6-bit SN */
			rtp_m_flag = GET_REAL(GET_BIT_6(rohc_remain_data + second_byte));
			rohc_debugf(3, "M flag = %u\n", rtp_m_flag);
			sn_bits = GET_BIT_0_5(rohc_remain_data + second_byte);
			sn_bits_nr = 6;
			rohc_debugf(3, "%zd SN bits = 0x%x\n", sn_bits_nr, sn_bits);
			/* first and second bytes read, third byte is CRC (part 4b) */
			rohc_remain_data += second_byte + 1;
			rohc_remain_len -= second_byte + 1;
			rohc_header_len += second_byte + 1;
			break;
		}

		default:
		{
			rohc_debugf(0, "bad packet type (%d)\n", packet_type);
			assert(0);
			goto error;
		}
	}

	/* part 4: 6-bit or 7-bit CRC */
	if(is_rtp)
	{
#if RTP_BIT_TYPE
		crc_packet = GET_BIT_0_5(rohc_remain_data);
		crc_packet_size = 6;
#else
		crc_packet = GET_BIT_0_6(rohc_remain_data);
		crc_packet_size = 7;
#endif
	}
	else
	{
		crc_packet = GET_BIT_0_6(rohc_remain_data);
		crc_packet_size = 7;
	}
	rohc_debugf(3, "CRC-%zd found in packet = 0x%02x\n",
	            crc_packet_size, crc_packet);

	/* part 4: 1-bit X (extension) flag */
	ext_flag = GET_REAL(GET_BIT_7(rohc_remain_data));
	rohc_debugf(3, "Extension is present = %u\n", ext_flag);

	/* second byte for UDP UOR-2 packet and third byte for RTP UOR-2* is read */
	rohc_remain_data++;
	rohc_remain_len--;
	rohc_header_len++;


	/* B. Parsing of ROHC extension header
	 *
	 * Let's parse field 5.
	 */

	/* part 5: Extension */
	if(ext_flag == 0)
	{
		/* no extension */
		rohc_debugf(3, "no extension to decode in UOR-2 packet\n");
	}
	else
	{
		uint16_t ext_sn_bits = 0;
		size_t ext_sn_bits_nr = 0;
		uint16_t ext_ip_id_bits = 0;
		size_t ext_ip_id_bits_nr = 0;
		uint16_t ext_ip_id2_bits = 0;
		size_t ext_ip_id2_bits_nr = 0;
		uint32_t ext_ts_bits = 0;
		size_t ext_ts_bits_nr = 0;
		int ext_size;

		/* check if the ROHC packet is large enough to read extension type */
		if(rohc_remain_len < 1)
		{
			rohc_debugf(0, "ROHC packet too small for extension (len = %zd)\n",
			            rohc_remain_len);
			goto error;
		}

		/* decode extension */
		rohc_debugf(3, "first byte of extension = 0x%02x\n",
		            GET_BIT_0_7(rohc_remain_data));
		switch(extension_type(rohc_remain_data))
		{
			case PACKET_EXT_0:
			{
				/* check extension usage */
				switch(packet_type)
				{
					case PACKET_UOR_2:
					case PACKET_UOR_2_ID:
						if((ip_get_version(&g_context->active1->ip) != IPV4 &&
						    !g_context->multiple_ip) ||
						   (ip_get_version(&g_context->active1->ip) != IPV4 &&
						    g_context->multiple_ip &&
						    ip_get_version(&g_context->active2->ip) != IPV4))
						{
							rohc_debugf(0, "cannot use extension 0 for the UOR-2 or "
							               "UOR-2-ID packet with no IPv4 header\n");
							goto error;
						}
						break;
					case PACKET_UOR_2_RTP:
					case PACKET_UOR_2_TS:
						/* nothing */
						break;
					default:
						rohc_debugf(3, "bad packet type (%d)\n", packet_type);
						goto error;
				}

				/* decode extension 0 */
				ext_size = decode_extension0(rohc_remain_data, rohc_remain_len,
				                             packet_type,
				                             &ext_sn_bits, &ext_sn_bits_nr,
				                             &ext_ip_id_bits, &ext_ip_id_bits_nr,
				                             &ext_ts_bits, &ext_ts_bits_nr);

				break;
			}

			case PACKET_EXT_1:
			{
				/* check extension usage */
				switch(packet_type)
				{
					case PACKET_UOR_2:
					case PACKET_UOR_2_ID:
					case PACKET_UOR_2_TS:
						if((ip_get_version(&g_context->active1->ip) != IPV4 &&
						    !g_context->multiple_ip) ||
						   (ip_get_version(&g_context->active1->ip) != IPV4 &&
						    g_context->multiple_ip &&
						    ip_get_version(&g_context->active2->ip) != IPV4))
						{
							rohc_debugf(0, "cannot use extension 1 for the UOR-2, UOR-2-ID or "
							               "UOR-2-TS packet with no IPv4 header\n");
							goto error;
						}
						break;
					case PACKET_UOR_2_RTP:
						/* nothing */
						break;
					default:
						rohc_debugf(3, "bad packet type (%d)\n", packet_type);
						goto error;
				}

				/* decode extension 1 */
				ext_size = decode_extension1(rohc_remain_data, rohc_remain_len,
				                             packet_type,
				                             &ext_sn_bits, &ext_sn_bits_nr,
				                             &ext_ip_id_bits, &ext_ip_id_bits_nr,
				                             &ext_ts_bits, &ext_ts_bits_nr);

				break;
			}

			case PACKET_EXT_2:
			{
				int innermost_ip_hdr;

				/* check extension usage */
				switch(packet_type)
				{
					case PACKET_UOR_2:
						if(ip_get_version(&g_context->active1->ip) != IPV4 ||
						   g_context->active1->rnd != 0 ||
						   !g_context->multiple_ip ||
						   ip_get_version(&g_context->active2->ip) != IPV4 ||
						   g_context->active2->rnd != 0)
						{
							rohc_debugf(0, "cannot use extension 2 for the UOR-2 packet "
							               "with no or only one IPv4 header that got a "
							               "non-random IP-ID\n");
							goto error;
						}
						break;
					case PACKET_UOR_2_ID:
					case PACKET_UOR_2_TS:
						if((ip_get_version(&g_context->active1->ip) != IPV4 &&
						    !g_context->multiple_ip) ||
						   (ip_get_version(&g_context->active1->ip) != IPV4 &&
						    g_context->multiple_ip &&
						    ip_get_version(&g_context->active2->ip) != IPV4))
						{
							rohc_debugf(0, "cannot use extension 2 for the UOR-2, UOR-2-ID or "
							               "UOR-2-TS packet with no IPv4 header\n");
							goto error;
						}
						break;
					case PACKET_UOR_2_RTP:
						/* nothing */
						break;
					default:
						rohc_debugf(3, "bad packet type (%d)\n", packet_type);
						goto error;
				}

				/* determine which IP header is the innermost IPv4 header with
				   value(RND) = 0 */
				if(g_context->multiple_ip &&
				   ip_get_version(&g_context->active2->ip) == IPV4 &&
				   g_context->active2->rnd == 0)
				{
					/* the second IP header is the innermost IPv4 header with
					   value(RND) = 0 */
					innermost_ip_hdr = 2;
				}
				else if(ip_get_version(&g_context->active1->ip) == IPV4 &&
				        g_context->active1->rnd == 0)
				{
					/* the first IP header is the innermost IPv4 header with
					   value(RND) = 0 */
					innermost_ip_hdr = 1;
				}
				else
				{
					rohc_debugf(0, "extension 2 for UOR-2-TS must contain at least one "
				            "IPv4 header with a non-random IP-ID\n");
					goto error;
				}
				rohc_debugf(3, "IP header #%d is the innermost IPv4 header with a "
				            "non-random IP-ID\n", innermost_ip_hdr);

				/* decode extension 2 */
				ext_size = decode_extension2(rohc_remain_data, rohc_remain_len,
				                             packet_type, innermost_ip_hdr,
				                             &ext_sn_bits, &ext_sn_bits_nr,
				                             &ext_ip_id_bits, &ext_ip_id_bits_nr,
				                             &ext_ip_id2_bits, &ext_ip_id2_bits_nr,
				                             &ext_ts_bits, &ext_ts_bits_nr);

				break;
			}

			case PACKET_EXT_3:
			{
				uint8_t rtp_m_bits_ext3 = 0;
				size_t rtp_m_bits_ext3_nr = 0;

				/* decode the extension */
				ext_size = decode_extension3(decomp, context,
				                             rohc_remain_data, rohc_remain_len,
				                             &ext_sn_bits, &ext_sn_bits_nr,
				                             &ext_ip_id_bits, &ext_ip_id_bits_nr,
				                             &ext_ip_id2_bits, &ext_ip_id2_bits_nr,
				                             &ext_ts_bits, &ext_ts_bits_nr,
				                             &is_ts_scaled,
				                             &rtp_m_bits_ext3, &rtp_m_bits_ext3_nr,
				                             &rtp_x_bits, &rtp_x_bits_nr,
				                             &rtp_p_bits, &rtp_p_bits_nr,
				                             &rtp_pt_bits, &rtp_pt_bits_nr);

				/* check that the RTP Marker (M) value found in the extension is the
				 * same as the one we previously found. RFC 4815 §8.4 says:
				 *   The RTP header part of Extension 3, as defined by RFC 3095
				 *   Section 5.7.5, includes a one-bit field for the RTP Marker bit.
				 *   This field is also present in all compressed base header formats
				 *   except for UO-1-ID; meaning, there may be two occurrences of the
				 *   field within one single compressed header. In such cases, the
				 *   two M fields must have the same value.
				 */
				if(rtp_m_bits_ext3_nr > 0)
				{
					assert(rtp_m_bits_ext3_nr == 1);
					if(rtp_m_flag != rtp_m_bits_ext3)
					{
						rohc_debugf(0, "RTP Marker flag mismatch (base header = %u, "
						            "extension 3 = %u)\n", rtp_m_flag, rtp_m_bits_ext3);
						goto error;
					}
				}

				break;
			}

			default:
			{
				rohc_debugf(0, "unknown extension (0x%x)\n",
				            GET_BIT_0_7(rohc_remain_data));
				goto error;
			}
		}

		/* was the extension successfully parsed? */
		if(extension_type(rohc_remain_data) == PACKET_EXT_3 && ext_size == -2)
		{
			rohc_debugf(3, "trying to reparse the packet...\n");
			goto reparse;
		}
		else if(ext_size < 0)
		{
			rohc_debugf(0, "cannot decode extension %u of the UOR-2* packet\n",
			            extension_type(rohc_remain_data));
			goto error;
		}

		/* append bits extracted from extension to already-extracted bits */
		/* SN bits */
		if((sn_bits_nr + ext_sn_bits_nr) <= 16)
		{
			sn_bits = (sn_bits << ext_sn_bits_nr) | ext_sn_bits;
			sn_bits_nr += ext_sn_bits_nr;
		}
		else
		{
			assert(ext_sn_bits_nr <= 16);
			assert(ext_sn_bits_nr > 0);
			sn_bits &= (1 << (16 - ext_sn_bits_nr)) - 1;
			sn_bits = (sn_bits << ext_sn_bits_nr) | ext_sn_bits;
			sn_bits_nr = 16;
		}
		/* outer IP-ID bits */
		if((ip_id_bits_nr + ext_ip_id_bits_nr) <= 16)
		{
			ip_id_bits = (ip_id_bits << ext_ip_id_bits_nr) | ext_ip_id_bits;
			ip_id_bits_nr += ext_ip_id_bits_nr;
		}
		else
		{
			assert(ext_ip_id_bits_nr <= 16);
			assert(ext_ip_id_bits_nr > 0);
			ip_id_bits &= (1 << (16 - ext_ip_id_bits_nr)) - 1;
			ip_id_bits = (ip_id_bits << ext_ip_id_bits_nr) | ext_ip_id_bits;
			ip_id_bits_nr = 16;
		}
		/* inner IP-ID bits */
		if((ip_id2_bits_nr + ext_ip_id2_bits_nr) <= 16)
		{
			ip_id2_bits = (ip_id2_bits << ext_ip_id2_bits_nr) | ext_ip_id2_bits;
			ip_id2_bits_nr += ext_ip_id2_bits_nr;
		}
		else
		{
			assert(ext_ip_id2_bits_nr <= 16);
			assert(ext_ip_id2_bits_nr > 0);
			ip_id2_bits &= (1 << (16 - ext_ip_id2_bits_nr)) - 1;
			ip_id2_bits = (ip_id2_bits << ext_ip_id2_bits_nr) | ext_ip_id2_bits;
			ip_id2_bits_nr = 16;
		}
		/* TS bits */
		if((ts_bits_nr + ext_ts_bits_nr) <= 32)
		{
			ts_bits = (ts_bits << ext_ts_bits_nr) | ext_ts_bits;
			ts_bits_nr += ext_ts_bits_nr;
		}
		else
		{
			assert(ext_ts_bits_nr <= 32);
			assert(ext_ts_bits_nr > 0);
			ts_bits &= (1 << (32 - ext_ts_bits_nr)) - 1;
			ts_bits = (ts_bits << ext_ts_bits_nr) | ext_ts_bits;
			ts_bits_nr = 32;
		}

		/* now, skip the extension in the ROHC header */
		rohc_remain_data += ext_size;
		rohc_remain_len -= ext_size;
		rohc_header_len += ext_size;
	}


	/* C. Parsing of ROHC tail of header
	 *
	 * Let's parse fields 6 to 13.
	 */

	/* part 6: extract 16 outer IP-ID bits in case the outer IP-ID is random */
	if(ip_get_version(&g_context->active1->ip) == IPV4 && g_context->active1->rnd)
	{
		/* outer IP-ID is random, read its full 16-bit value and ignore any
		   previous bits we may have read (they should be filled with zeroes) */

		/* check if the ROHC packet is large enough to read the outer IP-ID */
		if(rohc_remain_len < 2)
		{
			rohc_debugf(0, "ROHC packet too small for random outer IP-ID bits "
			            "(len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* sanity check: all bits that are above 16 bits should be zero */
		if(ip_id_bits_nr > 0 && ip_id_bits != 0)
		{
			rohc_debugf(0, "bad packet format: outer IP-ID bits from the base ROHC "
			            "header shall be filled with zeroes but 0x%x was found\n",
			            ip_id_bits);
		}

		/* retrieve the full outer IP-ID value */
		ip_id_bits = ntohs(GET_NEXT_16_BITS(rohc_remain_data));
		ip_id_bits_nr = 16;

		rohc_debugf(3, "replace any existing outer IP-ID bits with the ones "
		            "found at the end of the UOR-2* packet (0x%x on %zd bits)\n",
		            ip_id_bits, ip_id_bits_nr);

		rohc_remain_data += 2;
		rohc_remain_len -= 2;
		rohc_header_len += 2;
	}

	/* parts 7 and 8: not supported */

	/* part 9: extract 16 inner IP-ID bits in case the inner IP-ID is random */
	if(g_context->multiple_ip &&
	   ip_get_version(&g_context->active2->ip) == IPV4 &&
	   g_context->active2->rnd)
	{
		/* inner IP-ID is random, read its full 16-bit value and ignore any
		   previous bits we may have read (they should be filled with zeroes) */

		/* check if the ROHC packet is large enough to read the inner IP-ID */
		if(rohc_remain_len < 2)
		{
			rohc_debugf(0, "ROHC packet too small for random inner IP-ID bits "
			            "(len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* sanity check: all bits that are above 16 bits should be zero */
		if(ip_id2_bits_nr > 0 && ip_id2_bits != 0)
		{
			rohc_debugf(0, "bad packet format: inner IP-ID bits from the base ROHC "
			            "header shall be filled with zeroes but 0x%x was found\n",
			            ip_id2_bits);
		}

		/* retrieve the full inner IP-ID value */
		ip_id2_bits = ntohs(GET_NEXT_16_BITS(rohc_remain_data));
		ip_id2_bits_nr = 16;

		rohc_debugf(3, "replace any existing inner IP-ID bits with the ones "
		            "found at the end of the UOR-2* packet (0x%x on %zd bits)\n",
		            ip_id2_bits, ip_id2_bits_nr);

		rohc_remain_data += 2;
		rohc_remain_len -= 2;
		rohc_header_len += 2;
	}

	/* parts 10, 11 and 12: not supported */

	/* part 13: decode the tail of UO* packet */
	if(g_context->decode_uo_tail != NULL)
	{
		size = g_context->decode_uo_tail(g_context,
		                                 rohc_remain_data, rohc_remain_len,
		                                 g_context->active1->next_header);
		if(size < 0)
		{
			rohc_debugf(0, "cannot decode the tail of UO* packet\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		rohc_header_len += size;
	}

	/* ROHC UOR-2 header and its extension are now fully decoded, remaining
	   data is the payload */
	payload_data = rohc_remain_data;
	payload_len = rohc_remain_len;


	/* D. Decode extracted bits
	 *
	 * All bits are now extracted from the packet, let's decode them.
	 */

	/* decode SN */
	ret = d_lsb_decode16(&g_context->sn, sn_bits, sn_bits_nr, &sn_decoded);
	if(ret != 1)
	{
		rohc_debugf(0, "failed to decode %zd SN bits 0x%x\n", sn_bits_nr, sn_bits);
		goto error;
	}
	rohc_debugf(3, "decoded SN = %u / 0x%x (nr bits = %zd, bits = %u / 0x%x)\n",
	            sn_decoded, sn_decoded, sn_bits_nr, sn_bits, sn_bits);

	/* decode outer IP-ID (IPv4 only) */
	if(ip_get_version(&g_context->active1->ip) == IPV4)
	{
		if(g_context->active1->rnd)
		{
			ip_id_decoded = ip_id_bits;
		}
		else
		{
/* TODO */ rohc_debugf(3, "decode outer IP-ID (rnd = %d, nr bits = %zd, bits = 0x%x)\n", g_context->active1->rnd, ip_id_bits_nr, ip_id_bits);
			ret = d_ip_id_decode(&g_context->ip_id1, ip_id_bits, ip_id_bits_nr,
			                     sn_decoded, &ip_id_decoded);
			if(ret != 1)
			{
				rohc_debugf(0, "failed to decode %zd outer IP-ID bits 0x%x\n",
				            ip_id_bits_nr, ip_id_bits);
				goto error;
			}
		}

		ipv4_set_id(&g_context->active1->ip, htons(ip_id_decoded));
		rohc_debugf(3, "decoded outer IP-ID = 0x%04x (rnd = %d, nr bits = %zd, "
		            "bits = 0x%x)\n", ntohs(ipv4_get_id(&g_context->active1->ip)),
		            g_context->active1->rnd, ip_id_bits_nr, ip_id_bits);
	}

	/* decode inner IP-ID (IPv4 only) */
	if(g_context->multiple_ip && ip_get_version(&g_context->active2->ip) == IPV4)
	{
		if(g_context->active2->rnd)
		{
			ip_id2_decoded = ip_id2_bits;
		}
		else
		{
			ret = d_ip_id_decode(&g_context->ip_id2, ip_id2_bits, ip_id2_bits_nr,
			                     sn_decoded, &ip_id2_decoded);
			if(ret != 1)
			{
				rohc_debugf(0, "failed to decode %zd inner IP-ID bits 0x%x\n",
				            ip_id2_bits_nr, ip_id2_bits);
				goto error;
			}
		}

		ipv4_set_id(&g_context->active2->ip, htons(ip_id2_decoded));
		rohc_debugf(3, "decoded inner IP-ID = 0x%04x (rnd = %d, nr bits = %zd, "
		            "bits = 0x%x)\n", ntohs(ipv4_get_id(&g_context->active2->ip)),
		            g_context->active2->rnd, ip_id2_bits_nr, ip_id2_bits);
	}

	/* decode TS (RTP profile only) */
	if(is_rtp)
	{
		struct d_rtp_context *const rtp_context =
			(struct d_rtp_context *) g_context->specific;

		rohc_debugf(3, "%zd-bit TS delta = 0x%x\n", ts_bits_nr, ts_bits);

		if(is_ts_scaled)
		{
			rohc_debugf(3, "TS is scaled\n");
			ret = d_decode_ts(&rtp_context->ts_sc, ts_bits, ts_bits_nr, &ts_decoded);
			if(ret != 1)
			{
				rohc_debugf(0, "failed to decode %zd-bit TS_SCALED 0x%x\n",
				            ts_bits_nr, ts_bits);
				goto error;
			}
		}
		else if(ts_bits_nr == 0)
		{
			rohc_debugf(3, "TS is deducted from SN\n");
			ts_decoded = ts_deducted(&rtp_context->ts_sc, sn_decoded);
		}
		else
		{
			rohc_debugf(3, "TS is not scaled\n");
			ts_decoded = ts_bits;
		}

		rohc_debugf(3, "decoded timestamp = %u / 0x%x (nr bits = %zd, "
		            "bits = %u / 0x%x)\n", ts_decoded, ts_decoded,
		            ts_bits_nr, ts_bits, ts_bits);
	}


	/* E. Build uncompressed headers
	 *
	 * All fields are now decoded, let's build the uncompressed headers.
	 */

	uncomp_header_len = 0;

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		/* build the outer IP header */
		size = build_uncompressed_ip(g_context->active1, uncomp_packet,
		                             rohc_remain_len +
		                             ip_get_hdrlen(&g_context->active2->ip) +
		                             g_context->active1->next_header_len +
		                             g_context->active2->size_list,
		                             g_context->list_decomp1);
		ip_hdr = uncomp_packet;
		uncomp_packet += size;
		uncomp_header_len += size;

		/* build the inner IP header */
		size = build_uncompressed_ip(g_context->active2, uncomp_packet,
		                             rohc_remain_len +
		                             g_context->active2->next_header_len,
		                             g_context->list_decomp2);
		ip2_hdr = uncomp_packet;
		uncomp_packet += size;
		uncomp_header_len += size;
	}
	else
	{
		/* build the single IP header */
		size = build_uncompressed_ip(g_context->active1, uncomp_packet,
		                             rohc_remain_len +
		                             g_context->active1->next_header_len,
		                             g_context->list_decomp1);
		ip_hdr = uncomp_packet;
		ip2_hdr = NULL;
		uncomp_packet += size;
		uncomp_header_len += size;
	}

	/* TODO: next block of code should be in build_next_header() of the RTP
	         profile */
	if(is_rtp)
	{
		struct udphdr *const udp = (struct udphdr *) g_context->active1->next_header;
		struct rtphdr *const rtp = (struct rtphdr *) (udp + 1);

		/* update TS, SN and M flag */
		rtp->timestamp = htonl(ts_decoded);
		rtp->sn = htons(sn_decoded);
		rtp->m = rtp_m_flag & 0x1;
		rohc_debugf(3, "force RTP Marker (M) bit to %u\n", rtp->m);

		/* update the RTP eXtension (R-X) flag if present */
		if(rtp_x_bits_nr > 0)
		{
			rtp->extension = rtp_x_bits;
		}

		/* update RTP Padding (R-P) flag if present */
		if(rtp_p_bits_nr > 0)
		{
			rtp->padding = rtp_p_bits;
		}

		/* update RTP Payload Type (R-PT) field if present */
		if(rtp_pt_bits_nr > 0)
		{
			rtp->pt = rtp_pt_bits;
			rohc_debugf(3, "force RTP Payload Type (R-PT) = 0x%x\n", rtp_pt_bits);
		}
	}

	/* build the next header if necessary */
	next_header = uncomp_packet;
	if(g_context->build_next_header != NULL)
	{
		size = g_context->build_next_header(g_context, g_context->active1,
		                                    uncomp_packet, rohc_remain_len);
		uncomp_packet += size;
		uncomp_header_len += size;
	}


	/* F. Check for correct decompression
	 *
	 * Use the CRC on decompressed headers to check whether decompression was
	 * correct.
	 */

	/* CRC check
	 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
	 * if the CRC-STATIC fields did not change */
	crc_computed = CRC_INIT_7;
	crc_type = CRC_TYPE_7;
#if RTP_BIT_TYPE
	if(is_rtp)
	{
		crc_computed = CRC_INIT_6;
		crc_type = CRC_TYPE_6;
	}
#endif
	crc_computed = g_context->compute_crc_static(ip_hdr, ip2_hdr, next_header,
	                                             crc_type, crc_computed);
	crc_computed = g_context->compute_crc_dynamic(ip_hdr, ip2_hdr, next_header,
	                                              crc_type, crc_computed);
	rohc_debugf(3, "CRC on %zd-byte uncompressed header = 0x%x\n",
	            uncomp_header_len, crc_computed);

	/* try to guess the correct SN value in case of failure */
	if(crc_computed != crc_packet)
	{
		size_t i;

		rohc_debugf(0, "CRC failure (computed = 0x%02x, packet = 0x%02x)\n",
		            crc_computed, crc_packet);
		rohc_debugf(3, "uncompressed headers (length = %zd): ", uncomp_header_len);
		for(i = 0; i < uncomp_header_len; i++)
		{
			rohc_debugf_(3, "0x%02x ", uncomp_packet[i - uncomp_header_len]);
		}
		rohc_debugf_(3, "\n");

		/* TODO: try to repair CRC failure */

		goto error_crc;
	}

	/* after CRC failure, if the SN value seems to be correctly guessed, we must
	 * wait for 3 CRC-valid packets before the correction is approved. Two
	 * packets are therefore thrown away. */
	if(g_context->correction_counter == 1)
	{
		rohc_debugf(2, "throw away packet, just 2 CRC-valid packets so far\n");

		g_context->correction_counter++;

		/* update the inter-packet variable */
		update_inter_packet(g_context);
		synchronize(g_context);

		/* update SN (and IP-IDs if IPv4) */
		d_lsb_sync_ref(&g_context->sn);
		d_lsb_update(&g_context->sn, sn_decoded);
		if(ip_get_version(&g_context->active1->ip) == IPV4)
		{
			d_ip_id_update(&g_context->ip_id1, ip_id_decoded, sn_decoded);
		}
		if(g_context->multiple_ip &&
		   ip_get_version(&g_context->active2->ip) == IPV4)
		{
			d_ip_id_update(&g_context->ip_id2, ip_id2_decoded, sn_decoded);
		}

		goto error_crc;
	}
	else if(g_context->correction_counter == 2)
	{
		g_context->correction_counter = 0;
		rohc_debugf(2, "the repair is deemed successful\n");
	}
	else if(g_context->correction_counter != 0)
	{
		rohc_debugf(0, "CRC-valid counter not valid (%u)\n",
		            g_context->correction_counter);
		g_context->correction_counter = 0;
		goto error_crc;
	}


	/* G. Update the compression context
	 *
	 * Once CRC check is done, update the compression context with the values
	 * that were decoded earlier.
	 *
	 * TODO: check what fields shall be updated in the context
	 */

	context->state = FULL_CONTEXT;

	/* update the inter-packet variable */
	update_inter_packet(g_context);
	synchronize(g_context);

	/* update SN and IP-IDs */
	d_lsb_sync_ref(&g_context->sn);
	d_lsb_update(&g_context->sn, sn_decoded);
	if(ip_get_version(&g_context->active1->ip) == IPV4)
	{
		d_ip_id_update(&g_context->ip_id1, ip_id_decoded, sn_decoded);
	}
	if(g_context->multiple_ip &&
	   ip_get_version(&g_context->active2->ip) == IPV4)
	{
		d_ip_id_update(&g_context->ip_id2, ip_id2_decoded, sn_decoded);
	}

	/* RTP */
	if(is_rtp)
	{
		struct d_rtp_context *const rtp_context =
			(struct d_rtp_context *) g_context->specific;
		d_add_ts(&rtp_context->ts_sc, ts_decoded, sn_decoded);
	}
	
	/* payload */
	rohc_debugf(3, "ROHC payload (length = %zd bytes) starts at offset %zd\n",
	            payload_len, rohc_header_len);
	if((rohc_header_len + payload_len) != rohc_length)
	{
		rohc_debugf(0, "ROHC UOR-2 header (%zd bytes) and payload (%zd bytes) "
		            "do not match the full ROHC UOR-2 packet (%u bytes)\n",
		            rohc_header_len, payload_len, rohc_length);
		goto error;
	}
	if(payload_len != 0)
	{
		memcpy(uncomp_packet, payload_data, payload_len);
	}

	/* statistics */
	context->header_compressed_size += rohc_header_len;
	c_add_wlsb(context->header_16_compressed, 0, rohc_header_len);
	context->header_uncompressed_size += uncomp_header_len;
	c_add_wlsb(context->header_16_uncompressed, 0, uncomp_header_len);

	return (uncomp_header_len + payload_len);

error:
	return ROHC_ERROR;
error_crc:
	return ROHC_ERROR_CRC;
reparse:
	return ROHC_NEED_REPARSE;
}


/**
 * @brief Decode one IR-DYN packet.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param rohc_packet  The ROHC packet to decode
 * @param rohc_length  The length of the ROHC packet
 * @param second_byte  The offset of the 2nd byte in the ROHC packet
 * @param dest         OUT: The decoded IP packet
 * @return             The length of the uncompressed IP packet
 *                     or ROHC_ERROR if an error occurs
 */
int decode_irdyn(struct rohc_decomp *decomp,
                 struct d_context *context,
                 const unsigned char *const rohc_packet,
                 const unsigned int rohc_length,
                 int second_byte,
                 unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	int size;

	/* lengths of ROHC and uncompressed headers to be computed during parsing */
	unsigned int rohc_header_len = 0;
	unsigned int uncomp_header_len = 0;

	/* remaining ROHC data not parsed yet */
	const unsigned char *rohc_remain_data = rohc_packet;
	unsigned int rohc_remain_len = rohc_length;

	/* ROHC and uncompressed payloads (they are the same) */
	const unsigned char *payload_data;
	unsigned int payload_len;

	/* skip the first bytes:
	 *  IR-DYN type + Profile ID + CRC (+ eventually CID bytes) */
	rohc_remain_data += second_byte + 1 + 1;
	rohc_remain_len -= second_byte + 1 + 1;
	rohc_header_len += second_byte + 1 + 1;

	/* decode the dynamic part of the outer IP header */
	size = d_decode_dynamic_ip(rohc_remain_data, rohc_remain_len,
	                           active1, g_context->list_decomp1);
	if(size == -1)
	{
		rohc_debugf(0, "cannot decode the outer IP dynamic part\n");
		goto error;
	}
	rohc_remain_data += size;
	rohc_remain_len -= size;
	rohc_header_len += size;

	/* decode the dynamic part of the inner IP header */
	if(g_context->multiple_ip)
	{
		size = d_decode_dynamic_ip(rohc_remain_data, rohc_remain_len,
		                           active2, g_context->list_decomp2);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the outer IP dynamic part\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		rohc_header_len += size;
	}

	/* decode the dynamic part of the next header if necessary */
	if(g_context->decode_dynamic_next_header != NULL)
	{
		size = g_context->decode_dynamic_next_header(g_context, rohc_remain_data,
		                                             rohc_remain_len,
		                                             active1->next_header);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the next header dynamic part\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		rohc_header_len += size;
	}

	/* ROHC IR-DYN header is now fully decoded */
	payload_data = rohc_remain_data;
	payload_len = rohc_remain_len;

	/* synchronize the old headers with the new ones in the context */
	synchronize(g_context);

	/* reset the correction counter */
	g_context->correction_counter = 0;

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		/* build the outer IP header */
		size = build_uncompressed_ip(active1, dest, payload_len +
		                             ip_get_hdrlen(&active2->ip) +
		                             active1->next_header_len +
		                             active2->size_list,
		                             g_context->list_decomp1);
		dest += size;
		uncomp_header_len += size;

		/* build the inner IP header */
		size = build_uncompressed_ip(active2, dest, payload_len +
		                             active2->next_header_len,
		                             g_context->list_decomp2);
		dest += size;
		uncomp_header_len += size;
	}
	else
	{
		/* build the single IP header */
		size = build_uncompressed_ip(active1, dest, payload_len +
		                             active1->next_header_len,
		                             g_context->list_decomp1);
		dest += size;
		uncomp_header_len += size;
	}

	/* build the next header if necessary */
	if(g_context->build_next_header != NULL)
	{
		size = g_context->build_next_header(g_context, active1, dest, payload_len);
		dest += size;
		uncomp_header_len += size;
	}

	context->state = FULL_CONTEXT;

	/* update the inter-packet variable */
	update_inter_packet(g_context);

	/* copy the payload */
	rohc_debugf(3, "ROHC payload (length = %u bytes) starts at offset %u\n",
	            payload_len, rohc_header_len);
	if((rohc_header_len + payload_len) != rohc_length)
	{
		rohc_debugf(0, "ROHC IR-DYN header (%u bytes) and payload (%u bytes) "
		            "do not match the full ROHC IR-DYN packet (%u bytes)\n",
		            rohc_header_len, payload_len, rohc_length);
		goto error;
	}
	if(payload_len != 0)
	{
		memcpy(dest, payload_data, payload_len);
	}

	/* statistics */
	context->header_compressed_size += rohc_header_len;
	c_add_wlsb(context->header_16_compressed, 0, rohc_header_len);
	context->header_uncompressed_size += uncomp_header_len;
	c_add_wlsb(context->header_16_uncompressed, 0, uncomp_header_len);

	return (uncomp_header_len + payload_len);

error:
	return ROHC_ERROR;
}


/**
 * @brief Decode the extension 0 of the UOR-2 packet
 *
 * Bits extracted:
 *  - 3 bits of SN
 *  - UOR-2 or UOR-2-ID: 3 bits of IP-ID
 *  - UOR-2-RTP or UOR-2-TS: 3 bits of TS
 *
 * @param rohc_data      The ROHC packet to decode
 * @param rohc_data_len  The length of the ROHC packet
 * @param packet_type    The type of ROHC packet
 * @param sn_bits        OUT: The SN bits found in the extension
 * @param sn_bits_nr     OUT: The number of SN bits found in the extension
 * @param ip_id_bits     OUT: The IP-ID bits found in the extension
 * @param ip_id_bits_nr  OUT: The number of IP-ID bits found in the extension
 * @param ts_bits        OUT: The TS bits found in the extension
 * @param ts_bits_nr     OUT: The number of TS bits found in the extension
 * @return               The data length read from the ROHC packet,
 *                       -1 in case of error
 */
int decode_extension0(const unsigned char *const rohc_data,
                      const size_t rohc_data_len,
                      const rohc_packet_t packet_type,
                      uint16_t *const sn_bits,
                      size_t *const sn_bits_nr,
                      uint16_t *const ip_id_bits,
                      size_t *const ip_id_bits_nr,
                      uint32_t *const ts_bits,
                      size_t *const ts_bits_nr)
{
	const size_t rohc_ext0_len = 1;

	rohc_debugf(3, "decode UOR-2* extension 0\n");

	/* check the minimal length to decode the extension 0 */
	if(rohc_data_len < 1)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_data_len);
		goto error;
	}

	/* parse 3 bits of SN */
	*sn_bits = GET_BIT_3_5(rohc_data);
	*sn_bits_nr = 3;

	/* parse the IP-ID and TS bits */
	switch(packet_type)
	{
		case PACKET_UOR_2:
		case PACKET_UOR_2_ID:
		{
			/* read 3 bits of IP-ID */
			*ip_id_bits = GET_BIT_0_2(rohc_data);
			*ip_id_bits_nr = 3;
			/* no TS bit */
			*ts_bits = 0;
			*ts_bits_nr = 0;
			break;
		}

		case PACKET_UOR_2_RTP:
		case PACKET_UOR_2_TS:
		{
			/* read 3 bits of TS */
			*ts_bits = GET_BIT_0_2(rohc_data);
			*ts_bits_nr = 3;
			/* no IP-ID bit */
			*ip_id_bits = 0;
			*ip_id_bits_nr = 0;
			break;
		}

		default:
		{
			rohc_debugf(3, "bad packet type (%d)\n", packet_type);
			goto error;
		}
	}

	rohc_debugf(3, "%u bits of SN found in EXT0 = 0x%x\n",
	            *sn_bits_nr, *sn_bits);
	rohc_debugf(3, "%u bits of outer IP-ID found in EXT0 = 0x%x\n",
	            *ip_id_bits_nr, *ip_id_bits);
	rohc_debugf(3, "%u bits of TS found in EXT0 = 0x%x\n",
	            *ts_bits_nr, *ts_bits);

	return rohc_ext0_len;

error:
	return -1;
}


/**
 * @brief Decode the extension 1 of the UOR-2 packet
 *
 * Bits extracted:
 *  - 3 bits of SN
 *  - UOR-2: 11 bits of IP-ID
 *  - UOR-2-RTP: 11 bits of TS
 *  - UOR-2-TS: 3 bits of TS / 8 bits of IP-ID
 *  - UOR-2-ID: 3 bits of IP-ID / 8 bits of TS
 *
 * @param rohc_data      The ROHC packet to decode
 * @param rohc_data_len  The length of the ROHC packet
 * @param packet_type    The type of ROHC packet
 * @param sn_bits        OUT: The SN bits found in the extension
 * @param sn_bits_nr     OUT: The number of SN bits found in the extension
 * @param ip_id_bits     OUT: The IP-ID bits found in the extension
 * @param ip_id_bits_nr  OUT: The number of IP-ID bits found in the extension
 * @param ts_bits        OUT: The TS bits found in the extension
 * @param ts_bits_nr     OUT: The number of TS bits found in the extension
 * @return               The data length read from the ROHC packet,
 *                       -1 in case of error
 */
int decode_extension1(const unsigned char *const rohc_data,
                      const size_t rohc_data_len,
                      const rohc_packet_t packet_type,
                      uint16_t *const sn_bits,
                      size_t *const sn_bits_nr,
                      uint16_t *const ip_id_bits,
                      size_t *const ip_id_bits_nr,
                      uint32_t *const ts_bits,
                      size_t *const ts_bits_nr)
{
	const size_t rohc_ext1_len = 2;

	rohc_debugf(3, "decode UOR-2* extension 1\n");

	/* check the minimal length to decode the extension 1 */
	if(rohc_data_len < 2)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_data_len);
		goto error;
	}

	/* parse 3 bits of SN */
	*sn_bits = GET_BIT_3_5(rohc_data);
	*sn_bits_nr = 3;

	switch(packet_type)
	{
		case PACKET_UOR_2:
		{
			/* parse 11 bits of IP-ID */
			*ip_id_bits = (GET_BIT_0_2(rohc_data) << 8) | GET_BIT_0_7(rohc_data + 1);
			*ip_id_bits_nr = 11;
			/* no TS bit */
			*ts_bits = 0;
			*ts_bits_nr = 0;
			break;
		}

		case PACKET_UOR_2_RTP:
		{
			/* parse 11 bits of TS */
			*ts_bits = (GET_BIT_0_2(rohc_data) << 8) | GET_BIT_0_7(rohc_data + 1);
			*ts_bits_nr = 11;
			/* no IP-ID bit */
			*ip_id_bits = 0;
			*ip_id_bits_nr = 0;
			break;
		}

		case PACKET_UOR_2_TS:
		{
			/* parse 3 bits of TS */
			*ts_bits = GET_BIT_0_2(rohc_data);
			*ts_bits_nr = 3;
			/* parse 8 bits of IP-ID */
			*ip_id_bits = GET_BIT_0_7(rohc_data + 1);
			*ip_id_bits_nr = 8;
			break;
		}

		case PACKET_UOR_2_ID:
		{
			/* parse 3 bits of IP-ID */
			*ip_id_bits = GET_BIT_0_2(rohc_data);
			*ip_id_bits_nr = 3;
			/* parse 8 bits of TS */
			*ts_bits = GET_BIT_0_7(rohc_data + 1);
			*ts_bits_nr = 8;
			break;
		}

		default:
		{
			rohc_debugf(3, "bad packet type (%d)\n", packet_type);
			goto error;
		}
	}

	rohc_debugf(3, "%u bits of SN found in EXT1 = 0x%x\n",
	            *sn_bits_nr, *sn_bits);
	rohc_debugf(3, "%u bits of outer IP-ID found in EXT1 = 0x%x\n",
	            *ip_id_bits_nr, *ip_id_bits);
	rohc_debugf(3, "%u bits of TS found in EXT1 = 0x%x\n",
	            *ts_bits_nr, *ts_bits);

	return rohc_ext1_len;

error:
	return -1;
}


/**
 * @brief Decode the extension 2 of the UOR-2 packet
 *
 * Bits extracted:
 *  - 3 bits of SN
 *  - UOR-2: 11 bits of outer IP-ID / 8 bits of inner IP-ID
 *  - UOR-2-RTP: 19 bits of TS
 *  - UOR-2-TS: 11 bits of TS / 8 bits of the innermost IP-ID
 *  - UOR-2-ID: 8 bits of TS / 11 bits of the innermost IP-ID
 *
 * @param rohc_data         The ROHC packet to decode
 * @param rohc_data_len     The length of the ROHC packet
 * @param packet_type       The type of ROHC packet
 * @param innermost_ip_hdr  The innermost IP header (1 means first IP header,
 *                          2 means second IP header)
 * @param sn_bits           OUT: The SN bits found in the extension
 * @param sn_bits_nr        OUT: The number of SN bits found in the extension
 * @param ip_id_bits        OUT: The outer IP-ID bits found in the extension
 * @param ip_id_bits_nr     OUT: The number of outer IP-ID bits found in the
 *                               extension
 * @param ip_id2_bits       OUT: The inner IP-ID bits found in the extension
 * @param ip_id2_bits_nr    OUT: The number of inner IP-ID bits found in the
 *                               extension
 * @param ts_bits           OUT: The TS bits found in the extension
 * @param ts_bits_nr        OUT: The number of TS bits found in the extension
 * @return                  The data length read from the ROHC packet,
 *                          -1 in case of error
 */
int decode_extension2(const unsigned char *const rohc_data,
                      const size_t rohc_data_len,
                      const rohc_packet_t packet_type,
											const int innermost_ip_hdr,
                      uint16_t *const sn_bits,
                      size_t *const sn_bits_nr,
                      uint16_t *const ip_id_bits,
                      size_t *const ip_id_bits_nr,
                      uint16_t *const ip_id2_bits,
                      size_t *const ip_id2_bits_nr,
                      uint32_t *const ts_bits,
                      size_t *const ts_bits_nr)
{
	const size_t rohc_ext2_len = 3;

	/* sanity checks */
	assert(innermost_ip_hdr == 1 || innermost_ip_hdr == 2);

	rohc_debugf(3, "decode UOR-2* extension 2\n");

	/* check the minimal length to decode the extension 2 */
	if(rohc_data_len < 3)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_data_len);
		goto error;
	}

	/* parse 3 bits of SN */
	*sn_bits = GET_BIT_3_5(rohc_data);
	*sn_bits_nr = 3;

	switch(packet_type)
	{
		case PACKET_UOR_2:
		{
			/* parse 11 bits of outer IP-ID */
			*ip_id_bits = (GET_BIT_0_2(rohc_data) << 8) | GET_BIT_0_7(rohc_data + 1);
			*ip_id_bits_nr = 11;
			/* parse 8 bits of inner IP-ID */
			*ip_id_bits = GET_BIT_0_7(rohc_data + 2);
			*ip_id_bits_nr = 8;
			/* no TS bit */
			*ts_bits = 0;
			*ts_bits_nr = 0;
			break;
		}

		case PACKET_UOR_2_RTP:
		{
			/* parse 19 bits of TS */
			*ts_bits = (GET_BIT_0_2(rohc_data) << 8) |
			           GET_BIT_0_7(rohc_data + 1) |
			           GET_BIT_0_7(rohc_data + 2);
			/* no outer IP-ID bit */
			*ip_id_bits = 0;
			*ip_id_bits_nr = 0;
			/* no inner IP-ID bit */
			*ip_id2_bits = 0;
			*ip_id2_bits_nr = 0;
			break;
		}
		
		case PACKET_UOR_2_TS:
		{
			/* parse 11 bits of TS */
			*ts_bits = (GET_BIT_0_2(rohc_data) << 8) | GET_BIT_0_7(rohc_data + 1);
			*ts_bits_nr = 11;
			/* parse 8 bits of the innermost IP-ID */
			if(innermost_ip_hdr == 1)
			{
				*ip_id_bits = GET_BIT_0_7(rohc_data + 2);
				*ip_id_bits_nr = 8;
				*ip_id2_bits = 0;
				*ip_id2_bits_nr = 0;
			}
			else
			{
				*ip_id2_bits = GET_BIT_0_7(rohc_data + 2);
				*ip_id2_bits_nr = 8;
				*ip_id_bits = 0;
				*ip_id_bits_nr = 0;
			}
			break;
		}

		case PACKET_UOR_2_ID:
		{
			/* parse 11 bits of the innermost IP-ID */
			if(innermost_ip_hdr == 1)
			{
				*ip_id_bits = (GET_BIT_0_2(rohc_data) << 8) |
				              GET_BIT_0_7(rohc_data + 1);
				*ip_id_bits_nr = 11;
				*ip_id2_bits = 0;
				*ip_id2_bits_nr = 0;
			}
			else
			{
				*ip_id2_bits = (GET_BIT_0_2(rohc_data) << 8) |
				               GET_BIT_0_7(rohc_data + 1);
				*ip_id2_bits_nr = 11;
				*ip_id_bits = 0;
				*ip_id_bits_nr = 0;
			}
			/* parse 8 bits of TS */
			*ts_bits = GET_BIT_0_7(rohc_data + 2);
			*ts_bits_nr = 8;
			break;
		}

		default:
		{
			rohc_debugf(3, "bad packet type (%d)\n", packet_type);
			goto error;
		}
	}

	rohc_debugf(3, "%u bits of SN found in EXT2 = 0x%x\n",
	            *sn_bits_nr, *sn_bits);
	rohc_debugf(3, "%u bits of outer IP-ID found in EXT2 = 0x%x\n",
	            *ip_id_bits_nr, *ip_id_bits);
	rohc_debugf(3, "%u bits of inner IP-ID found in EXT2 = 0x%x\n",
	            *ip_id2_bits_nr, *ip_id2_bits);
	rohc_debugf(3, "%u bits of TS found in EXT2 = 0x%x\n",
	            *ts_bits_nr, *ts_bits);

	return rohc_ext2_len;

error:
	return -1;
}


/**
 * @brief Decode the extension 3 of the UOR-2 packet
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param rohc_data       The ROHC date to decode
 * @param rohc_data_len   The length of the ROHC data to decode
 * @param sn_bits         OUT: The SN bits found in the extension
 * @param sn_bits_nr      OUT: The number of SN bits found in the extension
 * @param ip_id_bits      OUT: The outer IP-ID bits found in the extension
 * @param ip_id_bits_nr   OUT: The number of outer IP-ID bits found in the
 *                             extension
 * @param ip_id2_bits     OUT: The inner IP-ID bits found in the extension
 * @param ip_id2_bits_nr  OUT: The number of inner IP-ID bits found in the
 *                             extension
 * @param ts_bits         OUT: The TS bits found in the extension
 * @param ts_bits_nr      OUT: The number of TS bits found in the extension
 * @param is_ts_scaled    OUT: Whether TS is sent scaled or not
 * @param rtp_m_bits      OUT: The RTP Marker (M) bits founr in the extension
 * @param rtp_m_bits_nr   OUT: The number of RTP Marker (M) bits found in the
 *                             extension
 * @param rtp_x_bits      OUT: The RTP eXtension (R-X) bits found in the
 *                             extension
 * @param rtp_x_bits_nr   OUT: The number of RTP eXtension (R-X) bits found
 *                             in the extension
 * @param rtp_p_bits      OUT: The RTP Padding (R-P) bits found in the
 *                             extension
 * @param rtp_p_bits_nr   OUT: The number of RTP Padding (R-P) bits found
 *                             in the extension
 * @param rtp_pt_bits     OUT: The RTP Payload Type (R-PT) bits found in the
 *                             extension
 * @param rtp_pt_bits_nr  OUT: The number of RTP Payload Type (R-PT) bits
 *                             found in the extension
 * @return                The data length read from the ROHC packet,
 *                        -2 in case packet must be parsed again,
 *                        -1 in case of error
 */
int decode_extension3(struct rohc_decomp *decomp,
                      struct d_context *context,
                      const unsigned char *const rohc_data,
                      const size_t rohc_data_len,
                      uint16_t *const sn_bits,
                      size_t *const sn_bits_nr,
                      uint16_t *const ip_id_bits,
                      size_t *const ip_id_bits_nr,
                      uint16_t *const ip_id2_bits,
                      size_t *const ip_id2_bits_nr,
                      uint32_t *const ts_bits,
                      size_t *const ts_bits_nr,
                      int *const is_ts_scaled,
                      uint8_t *const rtp_m_bits,
                      size_t *const rtp_m_bits_nr,
                      uint8_t *const rtp_x_bits,
                      size_t *const rtp_x_bits_nr,
                      uint8_t *const rtp_p_bits,
                      size_t *const rtp_p_bits_nr,
                      uint8_t *const rtp_pt_bits,
                      size_t *const rtp_pt_bits_nr)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	const unsigned char *ip_flags_pos = NULL;
	const unsigned char *ip2_flags_pos = NULL;
	int S, rts, mode, I, ip, rtp, ip2;
	int size;
	rohc_packet_t packet_type;

	/* remaining ROHC data */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* sanity checks */
	assert(sn_bits != NULL);
	assert(sn_bits_nr != NULL);
	assert(ip_id_bits != NULL);
	assert(ip_id_bits_nr != NULL);
	assert(ip_id2_bits != NULL);
	assert(ip_id2_bits_nr != NULL);
	
	packet_type = g_context->packet_type;
	
	rohc_debugf(3, "decode UOR-2* extension 3\n");

	rohc_remain_data = rohc_data;
	rohc_remain_len = rohc_data_len;

	/* check the minimal length to decode the flags */
	if(rohc_remain_len < 1)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_remain_len);
		goto error;
	}

	/* extract flags */
	S = GET_REAL(GET_BIT_5(rohc_remain_data));
	I = GET_REAL(GET_BIT_2(rohc_remain_data));
	ip = GET_REAL(GET_BIT_1(rohc_remain_data));
	
	switch(packet_type)
	{
		case PACKET_UOR_2:
		{
			rts = 0;
			*is_ts_scaled = 0;
			mode = GET_BIT_3_4(rohc_remain_data);
			rtp = 0;
			ip2 = GET_REAL(GET_BIT_0(rohc_remain_data));
			rohc_debugf(3, "S = %d, mode = 0x%x, I = %d, ip = %d, ip2 = %d\n",
			            S, mode, I, ip, ip2);
			break;
		}

		case PACKET_UOR_2_RTP:
		case PACKET_UOR_2_TS:
		case PACKET_UOR_2_ID:
		{
			/* check the minimal length to decode the first byte of flags and ip2 flag */
			if(rohc_remain_len < 2)
			{
				rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_remain_len);
				goto error;
			}
			rts = GET_REAL(GET_BIT_4(rohc_remain_data));
			*is_ts_scaled = GET_REAL(GET_BIT_3(rohc_remain_data));
			mode = 0;
			rtp = GET_REAL(GET_BIT_0(rohc_remain_data));
			if(ip)
			{
				ip2 = GET_REAL(GET_BIT_0(rohc_remain_data + 1));
			}
			else
			{
				ip2 = 0;
			}
			rohc_debugf(3, "S = %d, R-TS = %d, Tsc = %d, I = %d, ip = %d, rtp = %d\n",
			            S, rts, *is_ts_scaled, I, ip, rtp);
			break;
		}

		default:
		{
			rohc_debugf(3, "bad packet type (%d)\n", packet_type);
			goto error;
		}
	}

	rohc_remain_data++;
	rohc_remain_len--;

	/* check the minimal length to decode the inner & outer IP header flags
	 * and the SN */
	if(rohc_remain_len < ip + ip2 + S)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_remain_len);
		goto error;
	}

	/* remember position of inner IP header flags if present */
	if(ip)
	{
		rohc_debugf(3, "inner IP header flags field is present "
		            "in EXT-3 = 0x%02x\n", GET_BIT_0_7(rohc_remain_data));
		if(g_context->multiple_ip)
			ip2_flags_pos = rohc_remain_data;
		else
			ip_flags_pos = rohc_remain_data;
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* remember position of outer IP header flags if present */
	if(ip2)
	{
		rohc_debugf(3, "outer IP header flags field is present "
		            "in EXT-3 = 0x%02x\n", GET_BIT_0_7(rohc_remain_data));
		ip_flags_pos = rohc_remain_data;
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* extract the SN if present */
	if(S)
	{
		*sn_bits = GET_BIT_0_7(rohc_remain_data);
		*sn_bits_nr = 8;
		rohc_debugf(3, "8 bits of SN found in EXT-3 = 0x%02x\n", *sn_bits);
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* extract and decode TS if present (RTP profile only) */
	if(rts)
	{
		int ts_sdvl_size;
		int ret;

		/* check the minimal length to read at least one byte of TS, then
		 * extract TS field size and check if packet is large enough to
		 * contain the whole field */
		if(rohc_remain_len < 1)
		{
			rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_remain_len);
			goto error;
		}

		ts_sdvl_size = d_sdvalue_size(rohc_remain_data);
		if(ts_sdvl_size < 0)
		{
			rohc_debugf(0, "bad TS SDVL-encoded field length\n");
			goto error;
		}

		if(rohc_remain_len < ts_sdvl_size)
		{
			rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_remain_len);
			goto error;
		}

		/* decode SDVL-encoded TS value */
		ret = d_sdvalue_decode(rohc_remain_data);
		if(ret < 0)
		{
			rohc_debugf(0, "bad TS SDVL-encoded field\n");
			goto error;
		}
		*ts_bits = ret;

		if(ts_sdvl_size == 1)
		{
			*ts_bits_nr = 7;
		}
		else if(ts_sdvl_size == 2)
		{
			*ts_bits_nr = 14;
		}
		else if(ts_sdvl_size == 3)
		{
			*ts_bits_nr = 21;
		}
		else if(ts_sdvl_size == 4)
		{
			*ts_bits_nr = MAX_BITS_IN_4_BYTE_SDVL;
		}
		else
		{
			rohc_debugf(3, "failed to decode SDVL-encoded TS\n");
			goto error;
		}

		rohc_remain_data += ts_sdvl_size;
		rohc_remain_len -= ts_sdvl_size;
	}
	else /* non-RTP profiles or RTP profile without RTS flag set */
	{
		/* no TS bits */
		*ts_bits = 0;
		*ts_bits_nr = 0;
	}

	/* decode the inner IP header fields (pointed by packet) according to the
	 * inner IP header flags (pointed by ip(2)_flags_pos) if present */
	if(ip)
	{
		if(g_context->multiple_ip)
		{
			size = decode_inner_header_flags(context, ip2_flags_pos,
			                                 rohc_remain_data, rohc_remain_len,
			                                 active2);
		}
		else
		{
			size = decode_inner_header_flags(context, ip_flags_pos,
			                                 rohc_remain_data, rohc_remain_len,
			                                 active1);
		}
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the inner IP header flags & fields\n");
			goto error;
		}
		else if(size == -2)
		{
			/* we need to reparse the packet */
			rohc_debugf(3, "trying to reparse the packet...\n");
			goto reparse;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
	}

	/* decode the IP-ID if present */
	if(I)
	{
		/* check the minimal length to decode the IP-ID field */
		if(rohc_remain_len < 2)
		{
			rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_remain_len);
			goto error;
		}

		if(g_context->multiple_ip)
		{
			if(ip_get_version(&active2->ip) != IPV4)
			{
				rohc_debugf(0, "extension 3 must not update the inner IP-ID "
				               "because the inner header is IPv6\n");
				goto error;
			}

			*ip_id2_bits = ntohs(GET_NEXT_16_BITS(rohc_remain_data));
			*ip_id2_bits_nr = 16;
			*ip_id_bits = 0;
			*ip_id_bits_nr = 0;

			rohc_debugf(3, "%u bits of inner IP-ID in EXT3 = 0x%x\n",
			            *ip_id2_bits_nr, *ip_id2_bits);
		}
		else
		{
			if(ip_get_version(&active1->ip) != IPV4)
			{
				rohc_debugf(0, "extension 3 must not update the outer IP-ID "
				               "because the outer header is IPv6\n");
				goto error;
			}

			*ip_id_bits = ntohs(GET_NEXT_16_BITS(rohc_remain_data));
			*ip_id_bits_nr = 16;
			*ip_id2_bits = 0;
			*ip_id2_bits_nr = 0;

			rohc_debugf(3, "%u bits of outer IP-ID in EXT3 = 0x%x\n",
			            *ip_id_bits_nr, *ip_id_bits);
		}

		/* both inner and outer IP-ID fields are 2-byte long */
		rohc_remain_data += 2;
		rohc_remain_len -= 2;
	}
	else
	{
		/* no IP-ID bits */
		*ip_id_bits = 0;
		*ip_id_bits_nr = 0;
		*ip_id2_bits = 0;
		*ip_id2_bits_nr = 0;
	}

	/* decode the outer IP header fields (pointed by packet) according to the
	 * outer IP header flags (pointed by ip2_flags_pos) if present */
	if(ip2)
	{
		size = decode_outer_header_flags(context, ip2_flags_pos,
		                                 rohc_remain_data, rohc_remain_len,
		                                 active1, ip_id_bits, ip_id_bits_nr);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the outer IP header flags & fields\n");
			goto error;
		}
		else if(size == -2)
		{
			/* we need to reparse the packet */
			rohc_debugf(3, "trying to reparse the packet...\n");
			goto reparse;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
	}

	/* decode RTP header flags & fields if present */
	if(rtp)
	{
		int rpt, csrc, tss, tis;

		/* check the minimal length to decode RTP header flags */
		if(rohc_remain_len < 1)
		{
			rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_remain_len);
			goto error;
		}
	
		/* decode RTP header flags */
		mode = GET_BIT_6_7(rohc_remain_data);
		rpt = GET_REAL(GET_BIT_5(rohc_remain_data));
		*rtp_m_bits = GET_REAL(GET_BIT_4(rohc_remain_data));
		*rtp_m_bits_nr = 1;
		rohc_debugf(3, "%u-bit RTP Marker (M) = %u\n",
		            *rtp_m_bits_nr, *rtp_m_bits);
		*rtp_x_bits = GET_REAL(GET_BIT_3(rohc_remain_data));
		*rtp_x_bits_nr = 1;
		rohc_debugf(3, "%u-bit RTP eXtension (R-X) = %u\n",
		            *rtp_x_bits_nr, *rtp_x_bits);
		csrc = GET_REAL(GET_BIT_2(rohc_remain_data));
		tss = GET_REAL(GET_BIT_1(rohc_remain_data));
		tis = GET_REAL(GET_BIT_0(rohc_remain_data));
		rohc_remain_data++;
		rohc_remain_len--;

		/* check the minimal length to decode RTP header fields */
		if(rohc_remain_len < (rpt + csrc + tss + tis))
		{
			rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_remain_len);
			goto error;
		}
	
		/* decode RTP header fields */
		if(rpt)
		{
			*rtp_p_bits = GET_REAL(GET_BIT_7(rohc_remain_data));
			*rtp_p_bits_nr = 1;
			*rtp_pt_bits = GET_BIT_0_6(rohc_remain_data);
			*rtp_pt_bits_nr = 7;
			rohc_debugf(3, "%u-bit RTP Payload Type (R-PT) = 0x%x\n",
			            *rtp_pt_bits_nr, *rtp_pt_bits);
			rohc_remain_data++;
			rohc_remain_len--;
		}
		else
		{
			/* RTP Padding (R-P) and RTP Payload Type (R-PT) not updated by
			   extension 3 */
			*rtp_p_bits = 0;
			*rtp_p_bits_nr = 0;
			*rtp_pt_bits = 0;
			*rtp_pt_bits_nr = 0;
		}

		if(csrc)
		{
			/* TODO: Compressed CSRC list */
			rohc_debugf(0, "Compressed CSRC list not supported yet\n");
			goto error;
		}

		if(tss)
		{
			struct d_rtp_context *rtp_context;
			int ts_stride;
			int ts_stride_size;

			rtp_context = (struct d_rtp_context *) g_context->specific;

			/* check the minimal length to read at least one byte of TS_SRTIDE,
			 * then extract TS_SRTIDE field size and check if packet is large
			 * enough to contain the whole field */
			if(rohc_remain_len < 1)
			{
				rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_remain_len);
				goto error;
			}

			ts_stride_size = d_sdvalue_size(rohc_remain_data);
			if(ts_stride_size < 0)
			{
				rohc_debugf(0, "bad TS_SRTIDE SDVL-encoded field length\n");
				goto error;
			}

			if(rohc_remain_len < ts_stride_size)
			{
				rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_remain_len);
				goto error;
			}

			/* decode SDVL-encoded TS_STRIDE value */
			ts_stride = d_sdvalue_decode(rohc_remain_data);
			if(ts_stride < 0)
			{
				rohc_debugf(0, "bad TS_SRTIDE SDVL-encoded field\n");
				goto error;
			}

			rohc_remain_data += ts_stride_size;
			rohc_remain_len -= ts_stride_size;
		
			rohc_debugf(3, "decoded ts_stride = %u / 0x%x\n", ts_stride, ts_stride);
			d_add_ts_stride(&rtp_context->ts_sc, ts_stride);
		}

		if(tis)
		{
			/* TODO: TIME_STRIDE */
			rohc_debugf(0, "TIME_STRIDE not supported yet\n");
			goto error;
		}
	}
	else
	{
		/* RTP eXtension (R-X), RTP Padding (R-P) and RTP Payload Type (R-PT)
		   not updated by extension 3 */
		*rtp_x_bits = 0;
		*rtp_x_bits_nr = 0;
		*rtp_p_bits = 0;
		*rtp_p_bits_nr = 0;
		*rtp_pt_bits = 0;
		*rtp_pt_bits_nr = 0;
	}
	
	if((packet_type == PACKET_UOR_2 || rtp) && mode != context->mode)
	{
		rohc_debugf(2, "mode different in compressor (%d) and "
		               "decompressor (%d)\n", mode, context->mode);
		d_change_mode_feedback(decomp, context);
	}

	return (rohc_data_len - rohc_remain_len);

error:
	return -1;
reparse:
	return -2;
}


/**
 * @brief Find out of which type is the ROHC packet.
 *
 * @param decomp      The ROHC decompressor
 * @param context     The decompression context
 * @param packet      The ROHC packet
 * @param second_byte The offset for the second byte of the ROHC packet
 *                    (depends on the CID encoding and the packet type)
 * @return            The packet type among PACKET_UO_0, PACKET_UO_1,
 *                    PACKET_UO_1_RTP, PACKET_UO_1_TS, PACKET_UO_1_ID,
 *                    PACKET_UOR_2, PACKET_UOR_2_RTP, PACKET_UOR_2_TS,
 *                    PACKET_UOR_2_ID, PACKET_IR_DYN, PACKET_IR or
 *                    PACKET_UNKNOWN
 */
rohc_packet_t find_packet_type(struct rohc_decomp *decomp,
                               struct d_context *context,
                               const unsigned char *packet,
                               int second_byte)
{
	rohc_packet_t type;
	struct d_generic_context *g_context = context->specific;
	int multiple_ip = g_context->multiple_ip;
	int rnd = g_context->last1->rnd;
	int is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	int is_ip_v4 = (ip_get_version(&g_context->last1->ip) == IPV4);

	if(GET_BIT_7(packet) == 0x00)
	{
		/* UO-0 packet */
		type = PACKET_UO_0;
	}
	else if(GET_BIT_6_7(packet) == 0x02)
	{
		/* UO-1* packet */

		if(is_rtp)
		{
			/* UO-1-* packet */

			if(!multiple_ip)
			{
				if((is_ip_v4 && rnd) || !is_ip_v4)
				{
					/* UO-1-RTP packet */
					type = PACKET_UO_1_RTP;
				}
				else
				{
					/* UO-1-ID or UO-1-TS packet */
					if(GET_BIT_5(packet) == 0)
						type = PACKET_UO_1_ID;
					else
						type = PACKET_UO_1_TS;
				}
			}
			else /* double IP headers */
			{
				int rnd2 = g_context->last2->rnd;
				int is_ip2_v4 = (ip_get_version(&g_context->last2->ip) == IPV4);

				if(((is_ip_v4 && rnd) || !is_ip_v4) &&
				   ((is_ip2_v4 && rnd2) || !is_ip2_v4))
				{
					/* UO-1-RTP packet */
					type = PACKET_UO_1_RTP;
				}
				else
				{
					/* UO-1-ID or UO-1-TS packet */
					if(GET_BIT_5(packet) == 0)
						type = PACKET_UO_1_ID;
					else
						type = PACKET_UO_1_TS;
				}
			}
		}
		else /* non-RTP profiles */
		{
			/* UO-1 packet */
			type = PACKET_UO_1;
		}
	}
	else if(GET_BIT_5_7(packet) == 0x06)
	{
		/* UOR-2* packet */

		if(is_rtp)
		{
			/* UOR-2-* packet */

			if(!multiple_ip)
			{
				if(!is_ip_v4)
				{
					/* UOR-2-RTP packet */
					type = PACKET_UOR_2_RTP;
				}
				else if((is_ip_v4 && rnd))
				{
					/* UOR-2-RTP or UOR-2-ID packet */
#if RTP_BIT_TYPE
					/* check the RTP disambiguation bit type to avoid reparsing
					 * (proprietary extention of the ROHC standard) */
					if(GET_BIT_6(packet + second_byte + 1) == 0)
					{
						/* UOR-2-RTP packet */
						type = PACKET_UOR_2_RTP;
					}
					else
					{
						/* UOR-2-ID */
						type = PACKET_UOR_2_ID;
					}
#else
					/* try to decode as UOR-2-RTP packet and change to UOR-2-ID
					 * later if UOR-2-RTP was the wrong choice */
					type = PACKET_UOR_2_RTP;
#endif
				}
				else
				{
					/* UOR-2-ID or UOR-2-TS packet, check the T field */
					if(GET_BIT_7(packet + second_byte) == 0)
					{
						/* UOR-2-ID packet */
						type = PACKET_UOR_2_ID;
					}
					else
					{
						/* UOR-2-TS packet */
						type = PACKET_UOR_2_TS;
					}
				}
			}
			else /* double IP headers */
			{
				int rnd2 = g_context->last2->rnd;
				int is_ip2_v4 = (ip_get_version(&g_context->last2->ip) == IPV4);

				if (!is_ip2_v4) 
				{
					/* UOR-2-RTP packet */
					type = PACKET_UOR_2_RTP;
				}
				else if(((is_ip_v4 && rnd) && (is_ip2_v4 && rnd2)) || 
					((!is_ip_v4) && (is_ip2_v4 && rnd2)))
				{
					/* UOR-2-RTP or UOR-2-ID packet */
#if RTP_BIT_TYPE
					/* check the RTP disambiguation bit type to avoid reparsing
					 * (proprietary extention of the ROHC standard) */
					if(GET_BIT_6(packet + second_byte + 1) == 0)
					{
						/* UOR-2-RTP packet */
						type = PACKET_UOR_2_RTP;
					}
					else
					{
						/* UOR-2-ID */
						type = PACKET_UOR_2_ID;
					}
#else
					/* try to decode as UOR-2-RTP packet and change to UOR-2-ID
					 * later if UOR-2-RTP was the wrong choice */
					type = PACKET_UOR_2_RTP;
#endif
				}
				else
				{
					/* UOR-2-ID or UOR-2-TS packet, check the T field */
					if(GET_BIT_7(packet + second_byte) == 0)
					{
						/* UOR-2-ID packet */
						type = PACKET_UOR_2_ID;
					}
					else
					{
						/* UOR-2-TS packet */
						type = PACKET_UOR_2_TS;
					}
				}
			}
		}
		else /* non-RTP profiles */
		{
			/* UOR-2 packet */
			type = PACKET_UOR_2;
		}
	}
	else if(*packet == 0xf8)
	{
		/* IR-DYN packet */
		type = PACKET_IR_DYN;
	}
	else if((*packet & 0xfe) == 0xfc)
	{
		/* IR packet */
		type = PACKET_IR;
	}
	else
	{
		/* unknown packet */
		type = PACKET_UNKNOWN;
	}

	return type;
}


/**
 * @brief Find out which extension is carried by the UOR-2 packet.
 *
 * @param rohc_extension  The ROHC UOR-2 packet
 * @return                The UOR-2 extension type among:
 *                        \li PACKET_EXT_0
 *                        \li PACKET_EXT_1
 *                        \li PACKET_EXT_2
 *                        \li PACKET_EXT_3
 */
uint8_t extension_type(const unsigned char *const rohc_extension)
{
	return GET_BIT_6_7(rohc_extension);
}


/**
 * @brief Decode the inner IP header flags and fields.
 *
 * Store the values in an IP header info structure.
 *
 * \verbatim

  Inner IP header flags (5.7.5):

       0     1     2     3     4     5     6     7
     ..... ..... ..... ..... ..... ..... ..... .....
    | TOS | TTL | DF  | PR  | IPX | NBO | RND | ip2 |  if ip = 1
     ..... ..... ..... ..... ..... ..... ..... .....

  Inner IP header fields (5.7.5):

    ..... ..... ..... ..... ..... ..... ..... .....
   |         Type of Service/Traffic Class         |  if TOS = 1
    ..... ..... ..... ..... ..... ..... ..... .....
   |         Time to Live/Hop Limit                |  if TTL = 1
    ..... ..... ..... ..... ..... ..... ..... .....
   |         Protocol/Next Header                  |  if PR = 1
    ..... ..... ..... ..... ..... ..... ..... .....
   /         IP extension headers                  /  variable,
    ..... ..... ..... ..... ..... ..... ..... .....   if IPX = 1

\endverbatim
 *
 * @param context  The decompression context
 * @param flags    The ROHC flags that indicate which IP fields are present
 *                 in the packet
 * @param fields   The ROHC packet part that contains some IP header fields
 * @param length   The length of the ROHC packet part that contains some IP
 *                 header fields
 * @param info     The IP header info to store the decoded values in
 * @return         The data length read from the ROHC packet,
 *                 -2 in case packet must be parsed again,
 *                 -1 in case of error
 */
int decode_inner_header_flags(struct d_context *context,
                              const unsigned char *flags,
                              const unsigned char *fields,
                              unsigned int length,
                              struct d_generic_changes *info)
{
	int is_tos, is_ttl, is_pr, is_ipx;
	int df, nbo, rnd;
	int read = 0;
	int is_rtp = (context->profile->id == ROHC_PROFILE_RTP);

	/* get the inner IP header flags */
	is_tos = GET_REAL(GET_BIT_7(flags));
	is_ttl = GET_REAL(GET_BIT_6(flags));
	df = GET_REAL(GET_BIT_5(flags));
	is_pr = GET_REAL(GET_BIT_4(flags));
	is_ipx = GET_REAL(GET_BIT_3(flags));
	nbo = GET_REAL(GET_BIT_2(flags));
	rnd = GET_REAL(GET_BIT_1(flags));
	rohc_debugf(3, "header flags: TOS = %d, TTL = %d, PR = %d, IPX = %d\n",
	            is_tos, is_ttl, is_pr, is_ipx);

	/* force the NBO flag to 1 if RND is detected */
	if(rnd)
	{
		nbo = 1;
	}

	/* check the minimal length to decode the header fields */
	if(length < is_tos + is_ttl + is_pr + is_ipx)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", length);
		goto error;
	}

	/* get the TOS/TC field if present */
	if(is_tos)
	{
		ip_set_tos(&info->ip, *fields);
		rohc_debugf(3, "TOS/TC = 0x%02x\n", *fields);
		fields++;
		read++;
	}

	/* get the TTL/HL field if present */
	if(is_ttl)
	{
		ip_set_ttl(&info->ip, *fields);
		rohc_debugf(3, "TTL/HL = 0x%02x\n", *fields);
		fields++;
		read++;
	}

	/* get the DF flag if IPv4 */
	if(ip_get_version(&info->ip) == IPV4)
	{
		ipv4_set_df(&info->ip, df);
		rohc_debugf(3, "DF = %d\n", ipv4_get_df(&info->ip));
	}
	else if(df) /* IPv6 and DF flag set */
	{
		rohc_debugf(0, "DF flag set and IP header is IPv6\n");
		goto error;
	}

	/* get the Protocol field if present */
	if(is_pr)
	{
		ip_set_protocol(&info->ip, *fields);
		rohc_debugf(3, "Protocol/Next Header = 0x%02x\n", *fields);
		fields++;
		read++;
	}

	/* get the IP extension headers */
	if(is_ipx)
	{
		/* TODO: list compression */
		rohc_debugf(0, "list compression is not supported\n");
		goto error;
	}

	/* get the NBO and RND flags if IPv4 */
	if(ip_get_version(&info->ip) == IPV4)
	{
		info->nbo = nbo;

		/* if RND changed, we must restart parsing for RTP profile
		   (except if the RTP bit type mechanism is used) */
		if(info->rnd != rnd)
		{
			rohc_debugf(1, "RND change detected (%d -> %d)\n", info->rnd, rnd);
			info->rnd = rnd;

			if(is_rtp)
			{
#if RTP_BIT_TYPE
#else
				rohc_debugf(1, "RND changed, so we MUST reparse "
				            "the UOR-2* packet\n");
				return -2;
#endif
			}
		}
	}
	else
	{
		/* IPv6 and NBO flag set */
		if(nbo)
		{
			rohc_debugf(0, "NBO flag set and IP header is IPv6\n");
			goto error;
		}

		/* IPv6 and RND flag set */
		if(rnd)
		{
			rohc_debugf(0, "RND flag set and IP header is IPv6\n");
			goto error;
		}
	}

	return read;

error:
	return -1;
}


/**
 * @brief Decode the outer IP header flags and fields.
 *
 * Store the values in an IP header info structure.
 *
 * \verbatim

  Outer IP header flags (5.7.5):

       0     1     2     3     4     5     6     7
     ..... ..... ..... ..... ..... ..... ..... .....
    | TOS2| TTL2| DF2 | PR2 |IPX2 |NBO2 |RND2 |  I2 |  if ip2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....

  Outer IP header fields

     ..... ..... ..... ..... ..... ..... ..... .....
    |      Type of Service/Traffic Class            |  if TOS2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....
    |         Time to Live/Hop Limit                |  if TTL2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....
    |         Protocol/Next Header                  |  if PR2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....
    /         IP extension header(s)                /  variable,
     ..... ..... ..... ..... ..... ..... ..... .....    if IPX2 = 1
    |                  IP-ID                        |  2 octets,
     ..... ..... ..... ..... ..... ..... ..... .....    if I2 = 1

\endverbatim
 *
 * @param context             The decompression context
 * @param flags               The ROHC flags that indicate which IP fields are
 *                            present in the packet
 * @param fields              The ROHC packet part that contain some IP header
 *                            fields
 * @param length              The length of the ROHC packet part that contains
 *                            some IP header fields
 * @param info                The IP header info to store the decoded values
 * @param ext3_ip_id_bits     OUT: The outer IP-ID bits found in extension 3
 * @param ext3_ip_id_bits_nr  OUT: The number of outer IP-ID bits found in
 *                            extension 3
 * @return                    The data length read from the ROHC packet,
 *                            -1 in case of error
 */
int decode_outer_header_flags(struct d_context *context,
                              const unsigned char *flags,
                              const unsigned char *fields,
                              unsigned int length,
                              struct d_generic_changes *info,
                              uint16_t *const ext3_ip_id_bits,
                              unsigned int *const ext3_ip_id_bits_nr)
{
	int is_I2;
	int read;

	/* decode the some outer IP header flags and fields that are identical
	 * to inner IP header flags and fields */
	read = decode_inner_header_flags(context, flags, fields, length, info);
	if(read == -1)
		goto error;
	if(read == -2)
		goto reparse;
	length -= read;

	/* get other outer IP header flags */
	is_I2 = GET_REAL(GET_BIT_0(flags));
	rohc_debugf(3, "header flags: I2 = %d\n", is_I2);

	/* check the minimal length to decode the outer header fields */
	if(length < is_I2 * 2)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", length);
		goto error;
	}

	/* get the outer IP-ID if IPv4 */
	if(is_I2)
	{
		if(ip_get_version(&info->ip) != IPV4)
		{
			rohc_debugf(0, "IP-ID field present (I2 = 1) and "
			               "IP header is IPv6\n");
			goto error;
		}

		if((*ext3_ip_id_bits_nr) > 0)
		{
			rohc_debugf(0, "IP-ID field present (I2 = 1) but IP-ID already "
			               "updated\n");
			goto error;
		}

		*ext3_ip_id_bits = ntohs(GET_NEXT_16_BITS(fields));
		*ext3_ip_id_bits_nr = 16;

		rohc_debugf(3, "%u bits of outer IP-ID in EXT3 = 0x%x\n",
		            *ext3_ip_id_bits_nr, *ext3_ip_id_bits);

		fields += 2;
		read += 2;
	}

	return read;

error:
	return -1;
reparse:
	return -2;
}


/**
 * @brief Build an uncompressed IP header.
 *
 * @param active       The IP header changes
 * @param dest         The buffer to store the IP header (MUST be at least
 *                     of sizeof(struct iphdr) or sizeof(struct ip6_hdr) bytes
 *                     depending on the IP version)
 * @param payload_size The length of the IP payload
 * @param decomp       The list decompressor (IPv6 only)
 * @return             The length of the IP header
 */
unsigned int build_uncompressed_ip(struct d_generic_changes *active,
                                   unsigned char *dest,
                                   unsigned int payload_size,
                                   struct list_decomp *decomp)
{
	unsigned int length;

	if(ip_get_version(&active->ip) == IPV4)
		length = build_uncompressed_ip4(active, dest, payload_size);
	else
		length = build_uncompressed_ip6(active, dest, payload_size, decomp);

	return length;
}


/**
 * @brief Build an uncompressed IPv4 header.
 *
 * @param active       The IPv4 header changes
 * @param dest         The buffer to store the IPv4 header (MUST be at least
 *                     of sizeof(struct iphdr) bytes)
 * @param payload_size The length of the IPv4 payload
 * @return             The length of the IPv4 header
 */
unsigned int build_uncompressed_ip4(struct d_generic_changes *active,
                                    unsigned char *dest,
                                    unsigned int payload_size)
{
	struct iphdr *ip = (struct iphdr *) dest;

	/* static & changing */
	memcpy(dest, &active->ip.header.v4, sizeof(struct iphdr));

	/* IP-ID: reverse the byte order if necessary */
	if(!active->nbo)
		ip->id = swab16(ip->id);
	rohc_debugf(3, "IP-ID = 0x%04x\n", ntohs(ip->id));

	/* static-known fields */
	ip->ihl = 5;
	rohc_debugf(3, "IHL = 0x%x\n", ip->ihl);

	/* interfered fields */
	ip->tot_len = htons(payload_size + ip->ihl * 4);
	rohc_debugf(3, "Total Length = 0x%04x (IHL * 4 + %d)\n",
	            ntohs(ip->tot_len), payload_size);
	ip->check = 0;
	ip->check = ip_fast_csum(dest, ip->ihl);
	rohc_debugf(3, "IP checksum = 0x%04x\n", ntohs(ip->check));

	return sizeof(struct iphdr);
}


/**
 * @brief Build an uncompressed IPv6 header.
 *
 * @param active       The IPv6 header changes
 * @param dest         The buffer to store the IPv6 header (MUST be at least
 *                     of sizeof(struct ip6_hdr) bytes)
 * @param payload_size The length of the IPv6 payload
 * @param decomp       The list decompressor
 * @return             The length of the IPv6 header
 */
unsigned int build_uncompressed_ip6(struct d_generic_changes *active,
                                    unsigned char *dest,
                                    unsigned int payload_size, 
                                    struct list_decomp *decomp)
{
	struct ip6_hdr *ip = (struct ip6_hdr *) dest;
	int size = 0;
	uint8_t next_proto = active->ip.header.v6.ip6_nxt;

	/* static & changing */
	if(decomp->list_decomp)
	{
		if(decomp->list_table[decomp->counter_list] != NULL &&
		   size_list(decomp->list_table[decomp->counter_list]) > 0)
		{
			active->ip.header.v6.ip6_nxt =
				(uint8_t)(decomp->list_table[decomp->counter_list]->first_elt->item->type);
		}
	}
	memcpy(dest, &active->ip.header.v6, sizeof(struct ip6_hdr));
	dest += sizeof(struct ip6_hdr);
	active->ip.header.v6.ip6_nxt = next_proto;
	
	/* extension list */
	if(decomp->list_decomp)
	{
		active->complist = 1;
		size += decomp->encode_extension(active, decomp, dest);
		active->size_list = size;
	}
	
	/* interfered fields */
	ip->ip6_plen = htons(payload_size + size);
	rohc_debugf(3, "Payload Length = 0x%04x (extensions = %d bytes, "
	            "payload = %u bytes)\n", ntohs(payload_size), size,
	            ntohs(payload_size));

	return sizeof(struct ip6_hdr) + size;
}

/**
 * @brief Build an extension list in IPv6 header
 * @param active The IPv6 header changes
 * @param decomp The list decompressor
 * @param dest The buffer to store the IPv6 header
 * @return The size of the list
 */
int encode_ip6_extension(struct d_generic_changes * active,
			  struct list_decomp * decomp,
                          unsigned char *dest)
{
	int length; // number of element in reference list
	int i;
	unsigned char next_header_type;
	struct list_elt * elt;
	unsigned char byte = 0;
	struct c_list * list;
	if(decomp->ref_ok)
	{
		rohc_debugf(3, "reference list to use \n");
		list = decomp->ref_list;
	}
	else
		list= decomp->list_table[decomp->counter_list];
	int size = 0; // size of the list
	int size_data; // size of one of the extension
	
	if(list->first_elt != NULL)
	{
		length = size_list(list);
		for(i = 0; i < length; i++)
		{
			byte = 0;
			// next header 
			elt = get_elt(list, i);
			if(elt->next_elt != NULL)
			{
				next_header_type = elt->next_elt->item->type;
				byte |= (next_header_type & 0xff);
			}
			else // next_header is protocol header
			{
				next_header_type = active->ip.header.v6.ip6_nxt;
				byte |= (next_header_type & 0xff);
			}
			memcpy(dest, &byte, 1);
			dest ++;
			byte = 0;
			// length
			size_data = elt->item->length;
			byte |= (((size_data/8)-1) & 0xff);
			memcpy(dest, &byte, 1);
			dest ++;
			// data
			memcpy(dest, elt->item->data + 2, size_data - 2);
			dest += (size_data - 2);
			size += size_data;	
		}
	}
	return size;
}


/**
 * @brief Replace last header changes with the active ones.
 *
 * @param context The generic decompression context
 */
void synchronize(struct d_generic_context *context)
{
	copy_generic_changes(context->last1, context->active1);
	copy_generic_changes(context->last2, context->active2);
}


/**
 * @brief Replace the active header changes with the last ones.
 *
 * @param context The generic decompression context
 */
void sync_on_failure(struct d_generic_context *context)
{
	copy_generic_changes(context->active1, context->last1);
	copy_generic_changes(context->active2, context->last2);
}


/**
 * @brief Copy the header changes object into another one.
 *
 * @param dst The destination header changes
 * @param src The source header changes
 */
void copy_generic_changes(struct d_generic_changes *dst,
                          struct d_generic_changes *src)
{
	if(dst->next_header_len != src->next_header_len)
	{
		rohc_debugf(0, "src and dest next headers have not the same length "
		            "(%u != %u)\n", src->next_header_len, dst->next_header_len);
		return;
	}

	dst->rnd = src->rnd;
	dst->nbo = src->nbo;
	dst->ip = src->ip;

	memcpy(dst->next_header, src->next_header, dst->next_header_len);
}


/**
 * @brief Compare two header changes objects.
 *
 * @param first  One header changes object
 * @param second Another header changes object
 * @return       1 if the two objects match, 0 otherwise
 */
int cmp_generic_changes(struct d_generic_changes *first,
                        struct d_generic_changes *second)
{
	return (first->rnd == second->rnd &&
	        first->nbo == second->nbo &&
	        memcmp(&first->ip, &second->ip, sizeof(struct ip_packet)) == 0 &&
			  memcmp(first->next_header, second->next_header, first->next_header_len) == 0);
}


/**
 * @brief Update the inter-packet time, a sort of average over the last
 *        inter-packet times.
 *
 * @param context The generic decompression context
 */
void update_inter_packet(struct d_generic_context *context)
{
	unsigned int last_time = context->last_packet_time;
	int delta = 0;

	rohc_debugf(2, "current time = %u and last time = %u\n",
	            context->current_packet_time, last_time);

	if(last_time)
		delta = context->current_packet_time - last_time;

	context->last_packet_time = context->current_packet_time;

	if(context->inter_arrival_time)
		context->inter_arrival_time = (context->inter_arrival_time >> WEIGHT_OLD)
		                              + (delta >> WEIGHT_NEW);
	else
		context->inter_arrival_time = delta;

	rohc_debugf(2, "inter_arrival_time = %u and current arrival delta is = %d\n",
	            context->inter_arrival_time, delta);
}

