/**
 * @file lsb.c
 * @brief Least Significant Bits (LSB) encoding
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include "lsb.h"


/**
 * @brief Initialize a Least Significant Bits (LSB) encoding object
 *
 * See 4.5.1 in the RFC 3095 for details about LSB encoding.
 *
 * @param s       The LSB object to initialize
 * @param v_ref_d The reference value
 * @param p       The p value used to efficiently encode the values
 */
void d_lsb_init(struct d_lsb_decode *s, int v_ref_d, int p)
{
	s->p = p;
	s->v_ref_d = v_ref_d;
	s->old_v_ref_d = v_ref_d;
}


/**
 * @brief Decode a LSB-encoded value
 *
 * See 4.5.1 in the RFC 3095 for details about LSB encoding.
 *
 * @param s The LSB object used to decode
 * @param m The LSB value to decode
 * @param k The length of the LSB value to decode
 * @return  The decoded value
 */
int d_lsb_decode(struct d_lsb_decode *s, int m, int k) {

	int min;
	int max;
	int tmp;
	int mask = ((1 << k) - 1);

	f(s->v_ref_d, k, s->p, &min, &max);

	tmp = min;
	m &= mask;

	while(tmp <= max && (tmp & mask) != m)
		tmp++;

	if((tmp & mask) != m)
		tmp = -1;

	return tmp;
}


/**
 * @brief Update the LSB reference value
 *
 * This function is called after a CRC success to update the last decoded
 * value (for example, the SN value). See 4.5.1 in the RFC 3095 for details
 * about LSB encoding.
 *
 * @param s       The LSB object
 * @param v_ref_d The new reference value
 */
void d_lsb_update(struct d_lsb_decode *s, int v_ref_d)
{
	s->v_ref_d = v_ref_d;
}


/**
 * @brief Replace the previous LSB reference value with the current one
 *
 * @param s The LSB object
 */
void d_lsb_sync_ref(struct d_lsb_decode *s)
{
	s->old_v_ref_d = s->v_ref_d;
}


/**
 * @brief Get the previous LSB reference value
 *
 * @param s The LSB object
 */
int d_get_lsb_old_ref(struct d_lsb_decode *s)
{
	return s->old_v_ref_d;
}


/**
 * @brief Get the current LSB reference value
 *
 * @param s The LSB object
 */
int d_get_lsb_ref(struct d_lsb_decode *s)
{
	return s->v_ref_d;
}

