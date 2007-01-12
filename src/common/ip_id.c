/**
 * @file ip_id.c
 * @brief IP-ID decompression routines
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include "ip_id.h"


/**
 * @brief Initialize an IP-ID object
 *
 * @param s      The IP-ID object to initialize
 * @param id_ref The IP-ID reference
 * @param sn_ref The reference Sequence Number (SN)
 */
void d_ip_id_init(struct d_ip_id_decode *s, int id_ref, int sn_ref)
{
	s->id_ref = id_ref;
	s->sn_ref = sn_ref;
}


/**
 * @brief Decode the IP-ID offset in a ROHC packet and compute the associated
 *        IP-ID
 *
 * @param s  The IP-ID object
 * @param m  The IP-ID offset
 * @param k  The number of bits used to code the IP-ID offset
 * @param sn The SN of the ROHC packet that contains the IP-ID offset
 * @return   The computed IP-ID
 */
int d_ip_id_decode(struct d_ip_id_decode *s, int m, int k, int sn)
{
	int offset_ref = (s->id_ref - s->sn_ref) % 65536;
	int offset_m = -1;
	
	int bitmask = ~((1 << k) - 1);
	int ip_id = (offset_ref & bitmask) | m;
	
	if(ip_id < offset_ref)
		ip_id += 1 << k;
	
	offset_m = ip_id & 0xFFFF;

	return (sn + offset_m) % 65536;
}


/**
 * @brief Update the reference values for the IP-ID and the SN
 *
 * @param s      The IP-ID object
 * @param id_ref The new IP-ID reference
 * @param sn_ref The new SN reference
 */
void d_ip_id_update(struct d_ip_id_decode *s, int id_ref, int sn_ref)
{
	s->id_ref = id_ref;
	s->sn_ref = sn_ref;
}

