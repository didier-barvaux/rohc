/**
 * @file comp_list.h
 * @brief Define list compression with its function
 * @author Emmanuelle Pechereau <epechereau@toulouse.viveris.com>
 */

#ifndef COMP_LIST_H
#define COMP_LIST_H

#include <netinet/ip6.h>
#include "rohc.h"


/// Header version
typedef enum
{
        /// Hop by hop header
	HBH = 0,
	/// Destination header
	DEST = 60,
	/// Routing header
	RTHDR = 43,
	/// AH header
	AH = 51,
/*	/// CSRC
	CSRC = 10,*/
} ext_header_version;
				


/**
 * @brief Define the item
 */
struct item
{
	/// item type
	ext_header_version type;	
	/// item header
	union
	{
		struct ip6_hbh * hbh;       ///< Hop by hop header
		struct ip6_dest * dest;     ///< Destination header
		struct ip6_rthdr * rthdr;   ///< Routing header
		struct ip6_ahhdr * ahhdr;   ///< AH header
	}header;
	/// size of the data in bytes
	int length;
	/// item data
	unsigned char * data;
};

/**
 * @brief Define a generic element in a compression list
 */
struct list_elt
{
	/// element 
	struct item * item;
	/// index
	int index_table;
	/// next element of the list
	struct list_elt * next_elt;
	/// previous element
	struct list_elt * prev_elt;
};

/**
 * @brief Define a list for compression
 */
struct c_list
{
	///generation identifier
	int gen_id;
	/// first element of the list
	struct list_elt * first_elt;
};

/**
 * @brief Define a compression translation table element
 */
struct c_translation
{
	/// flag which indicates the mapping between an item with its index
	/// 1 if the mapping is established, 0 if not
	int known;
	/// item
	struct item * item;
	/// counter
	int counter;
};

/**
 * @brief Define a decompression translation table element
 */
struct d_translation
{
	/// flag which indicates the mapping between an item with its index
        /// 1 if the mapping is established, 0 if not
	int known;
	/// item
	struct item * item;
};				 

/**
 * Functions prototypes
 */

int create_list(struct c_list * list);
int add_elt(struct c_list * list, struct item * item, int index);
int push_back(struct c_list * list, struct item * item, int index);
void delete_elt(struct c_list * list, struct item * item);
struct list_elt * get_elt(struct c_list * list, int index);
int elt_index(struct c_list * list, struct item * item);
int type_is_present(struct c_list * list, struct item * item);
void destroy_list(struct c_list * list);
int insert_elt(struct c_list * list, struct item * item, int index, int index_table);
int size_list(struct c_list * list);
void empty_list(struct c_list * list);

#endif
