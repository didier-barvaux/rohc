/*
 * Copyright 2010,2011,2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2013,2014 Viveris Technologies
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
 * @file   schemes/comp_wlsb.c
 * @brief  Window-based Least Significant Bits (W-LSB) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 */

#include "comp_wlsb.h"
#include "interval.h" /* for the rohc_f_*bits() functions */

#include <string.h>
#include <assert.h>


/*
 * Private structures and types
 */

/**
 * @brief Define a W-LSB window entry
 */
struct c_window
{
	uint32_t sn;     /**< The Sequence Number (SN) associated with the entry
	                      (used to acknowledge the entry) */
	uint32_t value;  /**< The value stored in the window entry */
};


/**
 * @brief Defines a W-LSB encoding object
 */
struct c_wlsb
{
	/// The width of the window
	size_t window_width; /* TODO: R-mode needs a non-fixed window width */

	/// The size of the window (power of 2) minus 1
	size_t window_mask;

	/// A pointer on the oldest entry in the window (change on acknowledgement)
	size_t oldest;
	/// A pointer on the current entry in the window  (change on add and ack)
	size_t next;

	/// Count of entries in the window
	size_t count;

	/// The maximal number of bits for representing the value
	size_t bits;
	/// Shift parameter (see 4.5.2 in the RFC 3095)
	rohc_lsb_shift_t p;

	/** The window in which previous values of the encoded value are stored */
	struct c_window window[1];
};


/*
 * Private function prototypes:
 */

static size_t wlsb_get_next_older(const size_t entry, const size_t max)
	__attribute__((warn_unused_result, const));

static size_t wlsb_ack_remove(struct c_wlsb *const wlsb, const size_t pos)
	__attribute__((warn_unused_result, nonnull(1)));

static size_t rohc_g_8bits(const uint8_t v_ref,
                           const uint8_t v,
                           const rohc_lsb_shift_t p,
                           const size_t bits_nr)
	__attribute__((warn_unused_result));

static size_t rohc_g_16bits(const uint16_t v_ref,
                            const uint16_t v,
                            const size_t min_k,
                            const rohc_lsb_shift_t p,
                            const size_t bits_nr)
	__attribute__((warn_unused_result));

static size_t rohc_g_32bits(const uint32_t v_ref,
                            const uint32_t v,
                            const size_t min_k,
                            const rohc_lsb_shift_t p,
                            const size_t bits_nr)
	__attribute__((warn_unused_result));


/*
 * Public functions
 */

/**
 * @brief Create a new Window-based Least Significant Bits (W-LSB) encoding
 *        object
 *
 * @param bits         The maximal number of bits for representing a value
 * @param window_width The number of entries in the window (power of 2)
 * @param p            Shift parameter (see 4.5.2 in the RFC 3095)
 * @return             The newly-created W-LSB encoding object
 */
struct c_wlsb * c_create_wlsb(const size_t bits,
                              const size_t window_width,
                              const rohc_lsb_shift_t p)
{
	struct c_wlsb *wlsb;

	assert(bits > 0);
	assert(window_width > 0);
	/* window_width must be a power of 2! */
	assert(window_width != 0 && (window_width & (window_width - 1)) == 0);

	wlsb = malloc(sizeof(struct c_wlsb) + (window_width - 1) * sizeof(struct c_window));
	if(wlsb == NULL)
	{
		goto error;
	}

	wlsb->oldest = 0;
	wlsb->next = 0;
	wlsb->count = 0;
	wlsb->window_width = window_width;
	wlsb->window_mask = window_width - 1;
	wlsb->bits = bits;
	wlsb->p = p;

	return wlsb;

error:
	return NULL;
}


/**
 * @brief Destroy a Window-based LSB (W-LSB) encoding object
 *
 * @param wlsb  The W-LSB object to destroy
 */
void c_destroy_wlsb(struct c_wlsb *const wlsb)
{
	free(wlsb);
}


/**
 * @brief Add a value into a W-LSB encoding object
 *
 * @param wlsb  The W-LSB object
 * @param sn    The Sequence Number (SN) for the new entry
 * @param value The value to base the LSB coding on
 */
void c_add_wlsb(struct c_wlsb *const wlsb,
                const uint32_t sn,
                const uint32_t value)
{
	assert(wlsb != NULL);
	assert(wlsb->window != NULL);
	assert(wlsb->next < wlsb->window_width);

	/* if window is full, an entry is overwritten */
	if(wlsb->count == wlsb->window_width)
	{
		wlsb->oldest = (wlsb->oldest + 1) & wlsb->window_mask;
	}
	else
	{
		wlsb->count++;
	}

	wlsb->window[wlsb->next].sn = sn;
	wlsb->window[wlsb->next].value = value;
	wlsb->next = (wlsb->next + 1) & wlsb->window_mask;
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 8-bit fields.
 *
 * @param wlsb   The W-LSB object
 * @param value  The value to encode using the LSB algorithm
 * @return       The number of bits required to uniquely recreate the value
 */
size_t wlsb_get_k_8bits(const struct c_wlsb *const wlsb, const uint8_t value)
{
	return wlsb_get_kp_8bits(wlsb, value, wlsb->p);
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 8-bit fields.
 *
 * @param wlsb   The W-LSB object
 * @param value  The value to encode using the LSB algorithm
 * @param p      The shift parameter p
 * @return       The number of bits required to uniquely recreate the value
 */
size_t wlsb_get_kp_8bits(const struct c_wlsb *const wlsb,
                         const uint8_t value,
                         const rohc_lsb_shift_t p)
{
	size_t bits_nr;

	/* use all bits if the window contains no value */
	if(wlsb->count == 0)
	{
		bits_nr = wlsb->bits;
	}
	else
	{
		size_t entry;
		size_t i;

		bits_nr = 0;

		/* find the minimal number of bits of the value required to be able
		 * to recreate it thanks to ANY value in the window */
		for(i = wlsb->count, entry = wlsb->oldest;
		    i > 0;
		    i--, entry = (entry + 1) & wlsb->window_mask)
		{
			const size_t k =
				rohc_g_8bits(wlsb->window[entry].value, value, p, wlsb->bits);
			if(k > bits_nr)
			{
				bits_nr = k;
			}
		}
	}
	assert(bits_nr <= 8);

	return bits_nr;
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 16-bit fields.
 *
 * @param wlsb   The W-LSB object
 * @param value  The value to encode using the LSB algorithm
 * @return       The number of bits required to uniquely recreate the value
 */
size_t wlsb_get_k_16bits(const struct c_wlsb *const wlsb, const uint16_t value)
{
	const size_t min_k = 0;
	return wlsb_get_mink_16bits(wlsb, value, min_k);
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 16-bit fields.
 *
 * @param wlsb   The W-LSB object
 * @param value  The value to encode using the LSB algorithm
 * @param min_k  The minimum number of bits to find out
 * @return       The number of bits required to uniquely recreate the value
 */
size_t wlsb_get_mink_16bits(const struct c_wlsb *const wlsb,
                            const uint16_t value,
                            const size_t min_k)
{
	return wlsb_get_minkp_16bits(wlsb, value, min_k, wlsb->p);
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 16-bit fields.
 *
 * @param wlsb   The W-LSB object
 * @param value  The value to encode using the LSB algorithm
 * @param p      The shift parameter p
 * @return       The number of bits required to uniquely recreate the value
 */
size_t wlsb_get_kp_16bits(const struct c_wlsb *const wlsb,
                          const uint16_t value,
                          const rohc_lsb_shift_t p)
{
	const size_t min_k = 0;
	return wlsb_get_minkp_16bits(wlsb, value, min_k, p);
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 16-bit fields.
 *
 * @param wlsb   The W-LSB object
 * @param value  The value to encode using the LSB algorithm
 * @param min_k  The minimum number of bits to find out
 * @param p      The shift parameter p
 * @return       The number of bits required to uniquely recreate the value
 */
size_t wlsb_get_minkp_16bits(const struct c_wlsb *const wlsb,
                             const uint16_t value,
                             const size_t min_k,
                             const rohc_lsb_shift_t p)
{
	size_t bits_nr;

	/* use all bits if the window contains no value */
	if(wlsb->count == 0)
	{
		bits_nr = wlsb->bits;
	}
	else
	{
		size_t entry;
		size_t i;

		bits_nr = 0;

		/* find the minimal number of bits of the value required to be able
		 * to recreate it thanks to ANY value in the window */
		for(i = wlsb->count, entry = wlsb->oldest;
		    i > 0;
		    i--, entry = (entry + 1) & wlsb->window_mask)
		{
			const size_t k =
				rohc_g_16bits(wlsb->window[entry].value, value, min_k, p, wlsb->bits);
			if(k > bits_nr)
			{
				bits_nr = k;
			}
		}
	}
	assert(bits_nr <= 16);

	return bits_nr;
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 32-bit fields.
 *
 * @param wlsb   The W-LSB object
 * @param value  The value to encode using the LSB algorithm
 * @return       The number of bits required to uniquely recreate the value
 */
size_t wlsb_get_k_32bits(const struct c_wlsb *const wlsb, const uint32_t value)
{
	const size_t min_k = 0;
	return wlsb_get_mink_32bits(wlsb, value, min_k);
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 32-bit fields.
 *
 * @param wlsb   The W-LSB object
 * @param value  The value to encode using the LSB algorithm
 * @param min_k  The minimum number of bits to find out
 * @return       The number of bits required to uniquely recreate the value
 */
size_t wlsb_get_mink_32bits(const struct c_wlsb *const wlsb,
                            const uint32_t value,
                            const size_t min_k)
{
	return wlsb_get_minkp_32bits(wlsb, value, min_k, wlsb->p);
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 32-bit fields.
 *
 * @param wlsb   The W-LSB object
 * @param value  The value to encode using the LSB algorithm
 * @param p      The shift parameter p
 * @return       The number of bits required to uniquely recreate the value
 */
size_t wlsb_get_kp_32bits(const struct c_wlsb *const wlsb,
                          const uint32_t value,
                          const rohc_lsb_shift_t p)
{
	const size_t min_k = 0;
	return wlsb_get_minkp_32bits(wlsb, value, min_k, p);
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 32-bit fields.
 *
 * @param wlsb   The W-LSB object
 * @param value  The value to encode using the LSB algorithm
 * @param min_k  The minimum number of bits to find out
 * @param p      The shift parameter p
 * @return       The number of bits required to uniquely recreate the value
 */
size_t wlsb_get_minkp_32bits(const struct c_wlsb *const wlsb,
                             const uint32_t value,
                             const size_t min_k,
                             const rohc_lsb_shift_t p)
{
	size_t bits_nr;

	assert(wlsb->window != NULL);
	assert(value <= 0xffffffff);

	/* use all bits if the window contains no value */
	if(wlsb->count == 0)
	{
		bits_nr = wlsb->bits;
	}
	else
	{
		size_t entry;
		size_t i;

		bits_nr = 0;

		/* find the minimal number of bits of the value required to be able
		 * to recreate it thanks to ANY value in the window */
		for(i = wlsb->count, entry = wlsb->oldest;
		    i > 0;
		    i--, entry = (entry + 1) & wlsb->window_mask)
		{
			const size_t k =
				rohc_g_32bits(wlsb->window[entry].value, value, min_k, p, wlsb->bits);
			if(k > bits_nr)
			{
				bits_nr = k;
			}
		}
	}
	assert(bits_nr <= 32);

	return bits_nr;
}


/**
 * @brief Acknowledge based on the Sequence Number (SN)
 *
 * Removes all window entries older (and including) than the one that matches
 * the given SN bits.
 *
 * @param wlsb        The W-LSB object
 * @param sn_bits     The LSB of the SN to acknowledge
 * @param sn_bits_nr  The number of LSB of the SN to acknowledge
 * @return            The number of acked window entries
 */
size_t wlsb_ack(struct c_wlsb *const wlsb,
                const uint32_t sn_bits,
                const size_t sn_bits_nr)
{
	size_t entry = wlsb->next;
	uint32_t sn_mask;
	size_t i;

	if(sn_bits_nr < 32)
	{
		sn_mask = (1U << sn_bits_nr) - 1;
	}
	else
	{
		sn_mask = 0xffffffffUL;
	}
	assert((sn_bits & sn_mask) == sn_bits);

	/* search for the window entry that matches the given SN LSB
	 * starting from the one */
	for(i = 0; i < wlsb->count; i++)
	{
		entry = wlsb_get_next_older(entry, wlsb->window_mask);
		if((wlsb->window[entry].sn & sn_mask) == sn_bits)
		{
			/* remove the window entry and all the older ones if found */
			return wlsb_ack_remove(wlsb, entry);
		}
	}

	return 0;
}


/*
 * Private functions
 */


/**
 * @brief Get the next older entry
 *
 * @param entry  The entry for which to get the next older entry
 * @param max    The max entry value
 * @return       The next older entry
 */
static size_t wlsb_get_next_older(const size_t entry, const size_t max)
{
	return ((entry == 0) ? max : (entry - 1));
}


/**
 * @brief Removes all W-LSB window entries prior to the given position
 *
 * @param wlsb  The W-LSB object
 * @param pos   The position to set as the oldest
 * @return      The number of acked window entries
 */
static size_t wlsb_ack_remove(struct c_wlsb *const wlsb, const size_t pos)
{
	size_t acked_nr = 0;

	while(wlsb->oldest != pos)
	{
		/* remove the oldest entry */
		wlsb->oldest = (wlsb->oldest + 1) & wlsb->window_mask;
		wlsb->count--;
		acked_nr++;
	}

	return acked_nr;
}


/**
 * @brief The g function as defined in LSB encoding for 8-bit fields
 *
 * Find the minimal k value so that v falls into the interval given by
 * f(v_ref, k). See 4.5.1 in the RFC 3095.
 *
 * @param v_ref    The reference value
 * @param v        The value to encode
 * @param p        The shift parameter
 * @param bits_nr  The number of bits that may be used to represent the
 *                 LSB-encoded value
 * @return         The minimal k value as defined by the LSB algorithm
 */
static size_t rohc_g_8bits(const uint8_t v_ref,
                           const uint8_t v,
                           const rohc_lsb_shift_t p,
                           const size_t bits_nr)
{
	struct rohc_interval8 interval;
	size_t k;

	assert(bits_nr <= 8);

	for(k = 0; k < bits_nr; k++)
	{
		interval = rohc_f_8bits(v_ref, k, p);
		if(interval.min <= interval.max)
		{
			/* interpretation interval does not straddle field boundaries,
			 * check if value is in [min, max] */
			if(v >= interval.min && v <= interval.max)
			{
				break;
			}
		}
		else
		{
			/* the interpretation interval does straddle the field boundaries,
			 * check if value is in [min, 0xffff] or [0, max] */
			if(v >= interval.min || v <= interval.max)
			{
				break;
			}
		}
	}

	return k;
}


/**
 * @brief The g function as defined in LSB encoding for 16-bit fields
 *
 * Find the minimal k value so that v falls into the interval given by
 * f(v_ref, k). See 4.5.1 in the RFC 3095.
 *
 * @param v_ref    The reference value
 * @param v        The value to encode
 * @param min_k    The minimum number of bits to find out
 * @param p        The shift parameter
 * @param bits_nr  The number of bits that may be used to represent the
 *                 LSB-encoded value
 * @return         The minimal k value as defined by the LSB algorithm
 */
static size_t rohc_g_16bits(const uint16_t v_ref,
                            const uint16_t v,
                            const size_t min_k,
                            const rohc_lsb_shift_t p,
                            const size_t bits_nr)
{
	struct rohc_interval16 interval;
	size_t k;

	assert(bits_nr <= 16);
	assert(min_k <= bits_nr);

	for(k = min_k; k < bits_nr; k++)
	{
		interval = rohc_f_16bits(v_ref, k, p);
		if(interval.min <= interval.max)
		{
			/* interpretation interval does not straddle field boundaries,
			 * check if value is in [min, max] */
			if(v >= interval.min && v <= interval.max)
			{
				break;
			}
		}
		else
		{
			/* the interpretation interval does straddle the field boundaries,
			 * check if value is in [min, 0xffff] or [0, max] */
			if(v >= interval.min || v <= interval.max)
			{
				break;
			}
		}
	}

	return k;
}


/**
 * @brief The g function as defined in LSB encoding for 32-bit fields
 *
 * Find the minimal k value so that v falls into the interval given by
 * f(v_ref, k). See 4.5.1 in the RFC 3095.
 *
 * @param v_ref    The reference value
 * @param v        The value to encode
 * @param min_k    The minimum number of bits to find out
 * @param p        The shift parameter
 * @param bits_nr  The number of bits that may be used to represent the
 *                 LSB-encoded value
 * @return         The minimal k value as defined by the LSB algorithm
 */
static size_t rohc_g_32bits(const uint32_t v_ref,
                            const uint32_t v,
                            const size_t min_k,
                            const rohc_lsb_shift_t p,
                            const size_t bits_nr)
{
	struct rohc_interval32 interval;
	size_t k;

	assert(bits_nr <= 32);
	assert(min_k < bits_nr);

	for(k = min_k; k < bits_nr; k++)
	{
		interval = rohc_f_32bits(v_ref, k, p);
		if(interval.min <= interval.max)
		{
			/* interpretation interval does not straddle field boundaries,
			 * check if value is in [min, max] */
			if(v >= interval.min && v <= interval.max)
			{
				break;
			}
		}
		else
		{
			/* the interpretation interval does straddle the field boundaries,
			 * check if value is in [min, 0xffff] or [0, max] */
			if(v >= interval.min || v <= interval.max)
			{
				break;
			}
		}
	}

	return k;
}

