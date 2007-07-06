/**
 * @file ip_id.h
 * @brief IP-ID decompression routines
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef IP_ID_H
#define IP_ID_H

#include "wlsb.h"


/**
 * @brief Defines a IP-ID object to help computing the IP-ID value
 *        from an IP-ID offset
 */
struct d_ip_id_decode
{
	int id_ref; ///< The reference IP-ID
	int sn_ref; ///< The reference Sequence Number (SN)
};


/*
 * Function prototypes.
 */

void d_ip_id_init(struct d_ip_id_decode *s, int id_ref, int sn_ref);

int d_ip_id_decode(struct d_ip_id_decode *s, int m, int length, int sn);

void d_ip_id_update(struct d_ip_id_decode *s, int id_ref, int sn_ref);


#endif

