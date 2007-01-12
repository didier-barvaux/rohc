/**
 * @file lsb.h
 * @brief Least Significant Bits (LSB) encoding
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef LSB_H
#define LSB_H


/**
 * @brief Least Significant Bits decoding object
 */
struct d_lsb_decode
{
	/// The current reference value
	int v_ref_d;
	/// The previous reference value
	int old_v_ref_d;
	/// The p shift parameter (see 4.5.1 in the RFC 3095)
	int p;
};


/*
 * Function prototypes
 */

void d_lsb_update(struct d_lsb_decode *s, int v_ref_d);

void d_lsb_sync_ref(struct d_lsb_decode *s);

int d_get_lsb_old_ref(struct d_lsb_decode *s);

int d_lsb_decode(struct d_lsb_decode *s, int m, int length);

void d_lsb_init(struct d_lsb_decode *s, int v_ref_d, int p);

int d_get_lsb_ref(struct d_lsb_decode *s);


#endif

