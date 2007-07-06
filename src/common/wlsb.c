/**
 * @file wlsb.c
 * @brief Window-based Least Significant Bits (W-LSB) encoding
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author David Moreau from TAS
 * @author The hackers from ROHC for Linux
 */

#include "wlsb.h"


/*
 * Private function prototypes:
 */

void c_ack_remove(struct c_wlsb *s, int index, int time);


/**
 * @brief Create a new Window-based Least Significant Bits (W-LSB) encoding
 *        object
 *
 * @param bits         The maximal number of bits for representing a value
 * @param window_width The number of entries in the window
 * @param p            Shift parameter (see 4.5.2 in the RFC 3095)
 * @return             The newly-created W-LSB encoding object
 */
struct c_wlsb * c_create_wlsb(int bits, int window_width, int p)
{
	struct c_wlsb *s;
	int i;

	if(window_width <= 0)
	{
		rohc_debugf(0, "the window width must be greater than 0\n");
		goto error;
	}

	s = malloc(sizeof(struct c_wlsb));
	if(s == NULL)
	{
	  rohc_debugf(0, "cannot allocate memory for the W-LSB object\n");
	  goto error;
	}
	bzero(s, sizeof(struct c_wlsb));

	s->oldest = 0;
	s->next = 0;
	s->window_width = window_width;

	s->window = (struct c_window *) calloc(window_width, sizeof(struct c_window));
	if(s->window == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the W-LSB window\n");
		goto clean;
	}
	bzero(s->window, sizeof(struct c_window) * window_width);

	s->bits = bits;
	s->p = p;
	for(i = 0; i < window_width; i++)
	{
		s->window[i].time = -1;
		s->window[i].used = ROHC_FALSE;
	}

	return s;

clean:
	zfree(s);
error:
	return NULL;
}


/**
 * @brief Destroy a Window-based LSB (W-LSB) encoding object
 *
 * @param s The W-LSB object to destory
 */
void c_destroy_wlsb(struct c_wlsb *s)
{
	if(s != NULL)
	{
		if(s->window != NULL)
	  		zfree(s->window);
		zfree(s);
	}
}


/**
 * @brief Print statistics about a W-LSB encoding object
 *
 * This function is a debug function.
 *
 * @param s The W-LSB object to print stats about
 */
void print_wlsb_stats(struct c_wlsb *s)
{
	int i;

	if(s != NULL)
	{
		for(i = 0; i < s->window_width; i++)
		{
			if(s->window[i].used == ROHC_TRUE)
				rohc_debugf(2, "window[%d].sn = %d, .time = %d, .value = %d\n", i,
				            s->window[i].sn, s->window[i].time, s->window[i].value);
		}
	
		rohc_debugf(3, "oldest entry has number %d\n", s->oldest);
		rohc_debugf(3, " and its sn = %d\n", s->window[s->oldest].sn);
		rohc_debugf(3, "Next entry has number %d, oldest entry has number %d\n",
		            s->next, s->oldest);
	}
}


/**
 * @brief Add a value into a W-LSB encoding object
 *
 * @param s     The W-LSB object
 * @param sn    The Sequence Number (SN) for the new entry
 * @param time  The time stamp for the new entry
 * @param value The value to base the LSB coding on (i.e. sn)
 */
void c_add_wlsb(struct c_wlsb * s, int sn, int time, int value)
{
	if(s == NULL || s->window == NULL)
	{
		rohc_debugf(0, "invalid window\n");
		return;
	}

	if(s->next < 0 || s->next >= s->window_width)
	{
		rohc_debugf(0, "invalid window index (index = %d, width = %d)\n",
		            s->next, s->window_width);
		return;
	}

	if(s->window[s->next].used == ROHC_TRUE)
		s->oldest++; /* if window is full and an entry is overwritten */

	s->window[s->next].sn = sn;
	s->window[s->next].time = time;
	s->window[s->next].value = value;
	s->window[s->next].used = ROHC_TRUE;
	s->next++;

	if(s->next >= s->window_width)
		s->next = 0;
	if(s->oldest >= s->window_width)
		s->oldest = 0;
}


/**
 * @brief The f function as defined in the LSB calculation algorithm
 *
 * Find out the interval \f$[v\_ref - p, v\_ref + (2^k - 1) - p]\f$ for a given k.
 * See 4.5.1 in the RFC 3095.
 *
 * @param v_ref The reference value
 * @param k     The number of least significant bits of the value that are
 *              transmitted
 * @param p     The shift parameter
 * @param min   The lower limit of the interval
 * @param max   The upper limit of the interval
 */
void f(int v_ref, int k, int p, int *min, int *max)
{
	if(p == 2)
	{
		/* for timestamp encoding */
		if(k <= 2)
			p = 0;
		else
			p = (1 << (k - 2)) - 1;
	}
	else if(p == 3)
	{
		/* for SN encoding */
		if(k <= 4)
			p = 1;
		else
			p = (1 << (k - 5)) - 1;
	}

	*min = v_ref - p;
	*max = v_ref + ((1 << k) - 1) - p; /* (1 << k) = 2 to the power of k */
}


/**
 * @brief The g function as defined in the LSB calculation algorithm
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
int g(int v_ref, int v, int p, int bits)
{
	int k, min, max;
	for(k = 0; k < bits; k++)
	{
		f(v_ref, k, p, &min, &max);
		if(v >= min && v <= max)
			break;
	}

	return k;
}


/**
 * @brief Find out the minimal number of bits of the to-be-encoded value
 *        required to be able to uniquely recreate it given the window
 *
 * @param s     The W-LSB object
 * @param value The value to encode using the LSB algorithm
 * @return      The number of bits required to uniquely recreate the value,
 *              0 if an error occurs and -1 if the minimal number of bits can
 *              not be found
 */
int c_get_k_wlsb(struct c_wlsb *s, int value)
{
	int i;
	int valid;
	int min, max;
	int k1, k2, k = 0;
	
	if(s == NULL || s->window == NULL)
	{
		rohc_debugf(0, "invalid window\n");
		goto quit;
	}
	
	min = 0x7fffffff;
	max = 0x80000000;
	valid = 0;

	/* find out the interval in which all the values from the window stand */
	for(i = 0; i < s->window_width; i++)
	{
		if(!s->window[i].used == ROHC_TRUE)
			continue;

		/* the window contains at least one value */
		valid = 1;

		/* change the minimal and maximal values if appropriate */
		if(s->window[i].value < min)
			min = s->window[i].value;
		if(s->window[i].value > max)
			max = s->window[i].value;
	}

	/* if the window contained at least one value */
	if(valid)
	{
		/* find the minimal number of bits of the value required to be able
		 * to recreate it thanks to the window */

		/* find the minimal number of bits for the lower limit of the interval */
		k1 = g(min, value, s->p, s->bits);
		/* find the minimal number of bits for the upper limit of the interval */
		k2 = g(max, value, s->p, s->bits);

		/* keep the greatest one */
		k = k1 > k2 ? k1 : k2;
	}
	else /* else no k matches */
		k = -1; 

quit:
	return k;
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
		return;

	/* search for the window entry that matches the given SN
	 * starting from the oldest one */
	for(i = s->oldest; i < s->window_width; i++)
	{
		if(s->window[i].used == ROHC_TRUE && s->window[i].sn == sn)
		{
			found = 1;
			break;
		}
	}

	if(!found)
	{
		for(i = 0; i < s->oldest; i++)
		{
			if(s->window[i].used == ROHC_TRUE && s->window[i].sn == sn)
			{
				found = 1;
				break;
			}
		}
	}

	/* remove the window entry if found */
	if(found)
		c_ack_remove(s, i, 0);
}


/**
 * @brief Acknowledge based on the time stamp
 *
 * Removes all entries older than the given time stamp in the window.
 *
 * @param s    The W-LSB object
 * @param time The time stamp to acknowledge
 */
void c_ack_time_wlsb(struct c_wlsb *s, int time)
{
	int found = 0;
	int i;

	/* check the W-LSB object validity */
	if(s == NULL)
	  return;

	/* search for the window entry that matches the given SN
	 * starting from the oldest one */
	for(i = s->oldest; i < s->window_width; i++)
	{
		if(s->window[i].used == ROHC_TRUE && s->window[i].time <= time)
		{
			if(s->window[i].time < time)
				i++;
			if(i >= s->window_width)
				i = 0;
			found = 1;
			break;
		}
	}

	if(!found)
	{
		for(i = 0; i < s->oldest; i++)
		{
			if(s->window[i].used == ROHC_TRUE && s->window[i].time <= time)
			{
				found = 1;
				break;
			}
		}
	}

	/* remove the window entry if found */
	if(found)
		c_ack_remove(s, i, 1);
}


/**
 * @brief Removes all W-LSB window entries prior to the given index
 *
 * @param s       The W-LSB object
 * @param index   The position to set as the oldest
 * @param by_time Whether the function is called by SN or time acknowledgement
 */
void c_ack_remove(struct c_wlsb *s, int index, int by_time)
{
	int j;

	/* check the W-LSB object validity */
	if(s == NULL)
		return;

	rohc_debugf(2, "index is %d\n", index);

	if(s->oldest == index)
	{
		/* remove only the oldest entry */
		s->window[s->oldest].time = -1;
		s->window[s->oldest].used = ROHC_FALSE;
	}
	else if(s->oldest < index)
	{
		/* remove all entries from oldest to (not including) index */
		for(j = s->oldest; j < index; j++)
		{
			s->window[j].time = -1;
			s->window[j].used = ROHC_FALSE;
		}
	}
	else /* s->oldest > index */
	{
		/* remove all entries from oldest to wrap-around and all from start
		 * to (excluding) index */
		for(j = s->oldest; j < s->window_width; j++)
		{
			s->window[j].time = -1;
			s->window[j].used = ROHC_FALSE;
		}
		for(j = 0; j < index; j++)
		{
			s->window[j].time = -1;
			s->window[j].used = ROHC_FALSE;
		}
	}

	/* fix the s->oldest pointer */
	if(index >= (s->window_width - 1))
	{
		s->oldest = index;
		/*if(time)*/ s->oldest = 0;
	}
	else
	{
		s->oldest = index;
		if(s->oldest >= s->window_width)
			s->oldest = 0;
	}

	/* fix the s->next pointer */
	s->next = s->oldest;
	for(j = s->oldest; j < s->window_width; j++)
	{
		if(s->window[j].used == ROHC_TRUE)
			s->next = (s->next + 1) % s->window_width;
		else
			break;
	}
	for(j = 0; j < s->oldest; j++)
	{
		if(s->window[j].used == ROHC_TRUE)
			s->next = (s->next + 1) % s->window_width;
		else
			break;
	}

	if(s->oldest >= s->window_width)
		s->oldest = 0;
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
		if(s->window[i].used == ROHC_TRUE)
			sum += s->window[i].value;
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
		if(s->window[i].used == ROHC_TRUE)
		{
			sum += s->window[i].value;
			num++;
		}
	}

	return (num > 0 ? sum / num : 0);
}

