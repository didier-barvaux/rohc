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
 * @file wlsb.c
 * @brief Window-based Least Significant Bits (W-LSB) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author David Moreau from TAS
 * @author The hackers from ROHC for Linux
 */

#include "wlsb.h"
#include "interval.h" /* for the rohc_f_*bits() functions */
#include "rohc_traces.h"
#include "rohc_debug.h"

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
	uint16_t sn;     /**< The Sequence Number (SN) associated with the entry
	                      (used to acknowledge the entry) */
	uint32_t value;  /**< The value stored in the window entry */
	bool is_used;    /**< Whether the window entry is used or not */
};


/**
 * @brief Defines a W-LSB encoding object
 */
struct c_wlsb
{
	/// The width of the window
	size_t window_width;

	/// A pointer on the oldest entry in the window (change on acknowledgement)
	size_t oldest;
	/// A pointer on the current entry in the window  (change on add and ack)
	size_t next;

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

static void c_ack_remove(struct c_wlsb *s, int index);

static size_t rohc_g_16bits(const uint16_t v_ref,
                            const uint16_t v,
                            const rohc_lsb_shift_t p,
                            const size_t bits_nr);

static size_t rohc_g_32bits(const uint32_t v_ref,
                            const uint32_t v,
                            const rohc_lsb_shift_t p,
                            const size_t bits_nr);


/*
 * Public functions
 */

/**
 * @brief Create a new Window-based Least Significant Bits (W-LSB) encoding
 *        object
 *
 * @param bits         The maximal number of bits for representing a value
 * @param window_width The number of entries in the window
 * @param p            Shift parameter (see 4.5.2 in the RFC 3095)
 * @return             The newly-created W-LSB encoding object
 */
struct c_wlsb * c_create_wlsb(const size_t bits,
                              const size_t window_width,
                              const rohc_lsb_shift_t p)
{
	struct c_wlsb *wlsb;
	size_t entry;

	assert(bits > 0);
	assert(window_width > 0);

	wlsb = malloc(sizeof(struct c_wlsb) + (window_width - 1) * sizeof(struct c_window));
	if(wlsb == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the W-LSB object\n");
		goto error;
	}

	wlsb->oldest = 0;
	wlsb->next = 0;
	wlsb->window_width = window_width;
	wlsb->bits = bits;
	wlsb->p = p;

	for(entry = 0; entry < window_width; entry++)
	{
		wlsb->window[entry].is_used = false;
	}

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
	assert(wlsb != NULL);
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
                const uint16_t sn,
                const uint32_t value)
{
	assert(wlsb != NULL);
	assert(wlsb->window != NULL);
	assert(wlsb->next < wlsb->window_width);

	/* if window is full, an entry is overwritten */
	if(wlsb->window[wlsb->next].is_used)
	{
		wlsb->oldest = (wlsb->oldest + 1) % wlsb->window_width;
	}

	wlsb->window[wlsb->next].sn = sn;
	wlsb->window[wlsb->next].value = value;
	wlsb->window[wlsb->next].is_used = true;
	wlsb->next = (wlsb->next + 1) % wlsb->window_width;
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 16-bit fields.
 *
 * @param wlsb     The W-LSB object
 * @param value    The value to encode using the LSB algorithm
 * @param bits_nr  OUT: The number of bits required to uniquely recreate the
 *                      value
 * @return         true in case of success,
 *                 false if the minimal number of bits can not be found
 */
bool wlsb_get_k_16bits(const struct c_wlsb *const wlsb,
                       const uint16_t value,
                       size_t *const bits_nr)
{
	size_t entry;
	bool is_window_valid;
	uint16_t min;
	uint16_t max;

	assert(wlsb != NULL);
	assert(wlsb->window != NULL);
	/* (value <= 0xffff) always ensured because value is of type uint16_t */
	assert(bits_nr != NULL);

	min = 0xffff;
	max = 0;
	is_window_valid = false;

	/* find out the interval in which all the values from the window stand */
	for(entry = 0; entry < wlsb->window_width; entry++)
	{
		/* skip entry if not in use */
		if(!(wlsb->window[entry].is_used))
		{
			continue;
		}

		/* the window contains at least one value */
		is_window_valid = true;

		/* change the minimal and maximal values if appropriate */
		if(wlsb->window[entry].value < min)
		{
			min = wlsb->window[entry].value;
		}
		if(wlsb->window[entry].value > max)
		{
			max = wlsb->window[entry].value;
		}
	}

	/* cannot do anything if the window contains no value */
	if(!is_window_valid)
	{
		goto error;
	}

	/* find the minimal number of bits of the value required to be able
	 * to recreate it thanks to the window */
	if(min == max)
	{
		/* find the minimal number of bits for the lower/upper limit of the interval */
		*bits_nr = rohc_g_16bits(min, value, wlsb->p, wlsb->bits);
	}
	else
	{
		/* find the minimal number of bits for the lower limit of the interval */
		const size_t k1 = rohc_g_16bits(min, value, wlsb->p, wlsb->bits);
		/* find the minimal number of bits for the upper limit of the interval */
		const size_t k2 = rohc_g_16bits(max, value, wlsb->p, wlsb->bits);
		/* keep the greatest one */
		*bits_nr = (k1 > k2) ? k1 : k2;
	}

	assert((*bits_nr) <= 16);

	return true;

error:
	return false;
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * The function is dedicated to 32-bit fields.
 *
 * @param wlsb     The W-LSB object
 * @param value    The value to encode using the LSB algorithm
 * @param bits_nr  OUT: The number of bits required to uniquely recreate the
 *                      value
 * @return         true in case of success,
 *                 false if the minimal number of bits can not be found
 */
bool wlsb_get_k_32bits(const struct c_wlsb *const wlsb,
                       const uint32_t value,
                       size_t *const bits_nr)
{
	size_t entry;
	bool is_window_valid;
	uint32_t min;
	uint32_t max;

	assert(wlsb != NULL);
	assert(wlsb->window != NULL);
	assert(value <= 0xffffffff);
	assert(bits_nr != NULL);

	min = 0xffffffff;
	max = 0;
	is_window_valid = false;

	/* find out the interval in which all the values from the window stand */
	for(entry = 0; entry < wlsb->window_width; entry++)
	{
		/* skip entry if not in use */
		if(!(wlsb->window[entry].is_used))
		{
			continue;
		}

		/* the window contains at least one value */
		is_window_valid = true;

		/* change the minimal and maximal values if appropriate */
		if(wlsb->window[entry].value < min)
		{
			min = wlsb->window[entry].value;
		}
		if(wlsb->window[entry].value > max)
		{
			max = wlsb->window[entry].value;
		}
	}

	/* cannot do anything if the window contains no value */
	if(!is_window_valid)
	{
		goto error;
	}

	/* find the minimal number of bits of the value required to be able
	 * to recreate it thanks to the window */
	if(min == max)
	{
		/* find the minimal number of bits for the lower/upper limit of the interval */
		*bits_nr = rohc_g_32bits(min, value, wlsb->p, wlsb->bits);
	}
	else
	{
		/* find the minimal number of bits for the lower limit of the interval */
		const size_t k1 = rohc_g_32bits(min, value, wlsb->p, wlsb->bits);
		/* find the minimal number of bits for the upper limit of the interval */
		const size_t k2 = rohc_g_32bits(max, value, wlsb->p, wlsb->bits);
		/* keep the greatest one */
		*bits_nr = (k1 > k2) ? k1 : k2;
	}

	assert((*bits_nr) <= 32);

	return true;

error:
	return false;
}


/**
 * @brief Acknowledge based on the Sequence Number (SN)
 *
 * Removes all entries older than the given SN in the window.
 *
 * @param s  The W-LSB object
 * @param sn The SN to acknowledge
 */
void c_ack_sn_wlsb(struct c_wlsb *s, int sn)
{
	int found = 0;
	int i;

	/* check the W-LSB object validity */
	if(s == NULL)
	{
		return;
	}

	/* search for the window entry that matches the given SN
	 * starting from the oldest one */
	for(i = s->oldest; i < s->window_width; i++)
	{
		if(s->window[i].is_used && s->window[i].sn == sn)
		{
			found = 1;
			break;
		}
	}

	if(!found)
	{
		for(i = 0; i < s->oldest; i++)
		{
			if(s->window[i].is_used && s->window[i].sn == sn)
			{
				found = 1;
				break;
			}
		}
	}

	/* remove the window entry if found */
	if(found)
	{
		c_ack_remove(s, i);
	}
}


/**
 * @brief Compute the sum of all the values stored in the W-LSB window
 *
 * This function is used for statistics.
 *
 * @param s The W-LSB object
 * @return  The sum over the W-LSB window
 */
int c_sum_wlsb(struct c_wlsb *s)
{
	int i;
	int sum = 0;

	for(i = 0; i < s->window_width; i++)
	{
		if(s->window[i].is_used)
		{
			sum += s->window[i].value;
		}
	}

	return sum;
}


/**
 * @brief Compute the mean of all the values stored in the W-LSB window
 *
 * This function is used for statistics.
 *
 * @param s The W-LSB object
 * @return  The mean over the W-LSB window
 */
int c_mean_wlsb(struct c_wlsb *s)
{
	int i;
	int sum = 0;
	int num = 0;

	for(i = 0; i < s->window_width; i++)
	{
		if(s->window[i].is_used)
		{
			sum += s->window[i].value;
			num++;
		}
	}

	return (num > 0 ? sum / num : 0);
}


/*
 * Private functions
 */

/**
 * @brief Removes all W-LSB window entries prior to the given index
 *
 * @param s       The W-LSB object
 * @param index   The position to set as the oldest
 */
static void c_ack_remove(struct c_wlsb *s, int index)
{
	int j;

	/* check the W-LSB object validity */
	if(s == NULL)
	{
		return;
	}

	rohc_debugf(2, "index is %d\n", index);

	if(s->oldest == index)
	{
		/* remove only the oldest entry */
		s->window[s->oldest].is_used = false;
	}
	else if(s->oldest < index)
	{
		/* remove all entries from oldest to (not including) index */
		for(j = s->oldest; j < index; j++)
		{
			s->window[j].is_used = false;
		}
	}
	else /* s->oldest > index */
	{
		/* remove all entries from oldest to wrap-around and all from start
		 * to (excluding) index */
		for(j = s->oldest; j < s->window_width; j++)
		{
			s->window[j].is_used = false;
		}
		for(j = 0; j < index; j++)
		{
			s->window[j].is_used = false;
		}
	}

	/* fix the s->oldest pointer */
	if(index >= (s->window_width - 1))
	{
		s->oldest = 0;
	}
	else
	{
		s->oldest = index;
		if(s->oldest >= s->window_width)
		{
			s->oldest = 0;
		}
	}

	/* fix the s->next pointer */
	s->next = s->oldest;
	for(j = s->oldest; j < s->window_width; j++)
	{
		if(s->window[j].is_used)
		{
			s->next = (s->next + 1) % s->window_width;
		}
		else
		{
			break;
		}
	}
	for(j = 0; j < s->oldest; j++)
	{
		if(s->window[j].is_used)
		{
			s->next = (s->next + 1) % s->window_width;
		}
		else
		{
			break;
		}
	}

	if(s->oldest >= s->window_width)
	{
		s->oldest = 0;
	}
}


/**
 * @brief The g function as defined in LSB encoding for 16-bit fields
 *
 * Find the minimal k value so that v falls into the interval given by
 * \f$f(v\_ref, k)\f$. See 4.5.1 in the RFC 3095.
 *
 * @param v_ref The reference value
 * @param v     The value to encode
 * @param p     The shift parameter
 * @param bits  The number of bits that may be used to represent the
 *              LSB-encoded value
 * @return      The minimal k value as defined by the LSB calculation algorithm
 */
static size_t rohc_g_16bits(const uint16_t v_ref,
                            const uint16_t v,
                            const rohc_lsb_shift_t p,
                            const size_t bits_nr)
{
	uint16_t min;
	uint16_t max;
	size_t k;

	assert(bits_nr <= 16);

	for(k = 0; k < bits_nr; k++)
	{
		rohc_f_16bits(v_ref, k, p, &min, &max);
		if(min <= max)
		{
			/* interpretation interval does not straddle field boundaries,
			 * check if value is in [min, max] */
			if(v >= min && v <= max)
			{
				break;
			}
		}
		else
		{
			/* the interpretation interval does straddle the field boundaries,
			 * check if value is in [min, 0xffff] or [0, max] */
			if(v >= min || v <= max)
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
 * \f$f(v\_ref, k)\f$. See 4.5.1 in the RFC 3095.
 *
 * @param v_ref The reference value
 * @param v     The value to encode
 * @param p     The shift parameter
 * @param bits  The number of bits that may be used to represent the
 *              LSB-encoded value
 * @return      The minimal k value as defined by the LSB calculation algorithm
 */
static size_t rohc_g_32bits(const uint32_t v_ref,
                            const uint32_t v,
                            const rohc_lsb_shift_t p,
                            const size_t bits_nr)
{
	uint32_t min;
	uint32_t max;
	size_t k;

	assert(bits_nr <= 32);

	for(k = 0; k < bits_nr; k++)
	{
		rohc_f_32bits(v_ref, k, p, &min, &max);
		if(min <= max)
		{
			/* interpretation interval does not straddle field boundaries,
			 * check if value is in [min, max] */
			if(v >= min && v <= max)
			{
				break;
			}
		}
		else
		{
			/* the interpretation interval does straddle the field boundaries,
			 * check if value is in [min, 0xffff] or [0, max] */
			if(v >= min || v <= max)
			{
				break;
			}
		}
	}

	return k;
}

