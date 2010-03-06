/**
 * @file ts_sc_comp.c
 * @brief Scaled RTP Timestamp encoding
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "ts_sc_comp.h"
#include "rohc_traces.h"


/**
 * @brief Create the ts_sc_comp object
 *
 * @param ts_sc        The ts_sc_comp object to create
 * @return             1 if creation is successful, 0 otherwise
 */
int c_create_sc(struct ts_sc_comp *ts_sc)
{
	ts_sc->ts_stride = 0;
	ts_sc->ts_scaled = 0;
	ts_sc->ts_offset = 0;
	ts_sc->old_ts = 0;
	ts_sc->ts = 0;
	ts_sc->ts_delta = 0;
	ts_sc->old_sn = 0;
	ts_sc->sn = 0;
	ts_sc->is_deductible = 0;
	ts_sc->state = INIT_TS;

	ts_sc->scaled_window = c_create_wlsb(16, 4, 2);
	if(ts_sc->scaled_window == NULL)
	{
		rohc_debugf(0, "cannot create a W-LSB window for TS scaled\n");
		goto error;
	}

	return 1;

error:
	return 0;
}


/**
 * @brief Destroy the ts_sc_comp object
 *
 * @param ts_sc        The ts_sc_comp object to destroy
 */
void c_destroy_sc(struct ts_sc_comp *ts_sc)
{
	if(ts_sc != NULL)
	{
		if(ts_sc->scaled_window != NULL)
			c_destroy_wlsb(ts_sc->scaled_window);
	}
}


/**
 * @brief Store the new TS, calculate new values and update the state
 *
 * @param ts_sc        The ts_sc_comp object
 * @param ts           The timestamp to add
 * @param sn           The sequence number of the RTP packet
 */
void c_add_ts(struct ts_sc_comp *ts_sc, unsigned int ts, unsigned int sn)
{
	int rest = 0;
	int ts_stride = ts_sc->ts_stride;
	int ts_delta = 0;

	rohc_debugf(2, "Timestamp = %u\n", ts);

	/* we save the old value */
	ts_sc->old_ts = ts_sc->ts;
	ts_sc->old_sn = ts_sc->sn;

	/* we store the new value */
	ts_sc->ts = ts;
	ts_sc->sn = sn;

	ts_sc->ts_delta = abs(ts_sc->ts - ts_sc->old_ts);
	ts_delta = ts_sc->ts_delta;

	switch(ts_sc->state)
	{
		case INIT_TS:
			rohc_debugf(2, "state INIT_TS\n");
			break;

		case INIT_STRIDE:
			rohc_debugf(2, "state INIT_STRIDE\n");
			if(ts_delta == 0)
				rohc_debugf(3, "timestamp has not changed\n");
			else
			{
				rohc_debugf(3, "ts_stride = %u\n", ts_delta);
				ts_sc->ts_stride = ts_delta;
				ts_sc->ts_offset = ts_sc->ts % ts_sc->ts_stride;
				rohc_debugf(3, "ts_offset = %u modulo %d = %d\n",
				            ts_sc->ts, ts_sc->ts_stride, ts_sc->ts_offset);
				ts_sc->ts_scaled = (ts_sc->ts - ts_sc->ts_offset) / ts_sc->ts_stride;
				rohc_debugf(3, "ts_scaled = (%u - %d) / %d = %d\n", ts_sc->ts,
				            ts_sc->ts_offset, ts_sc->ts_stride, ts_sc->ts_scaled);
			}
			break;

		case SEND_SCALED :
			rohc_debugf(2, "state SEND_SCALED\n");

			rohc_debugf(3, "ts_stride calculated = %u\n", ts_delta);
			rohc_debugf(3, "previous ts_stride = %u\n", ts_sc->ts_stride);
			rest = ts_delta % ts_stride;
			if(rest != 0 && ts_delta != 0)
			{
				/* ts_stride has changed */
				rohc_debugf(2, "/!\\ ts_stride changed\n");
				ts_sc->state = INIT_STRIDE;
				rohc_debugf(2, "state -> INIT_STRIDE\n");
				ts_sc->ts_stride = ts_delta;
			}

			int old_scaled = ts_sc->ts_scaled;
			rohc_debugf(3, "ts_stride = %u\n", ts_sc->ts_stride);
			ts_sc->ts_offset = ts_sc->ts % ts_sc->ts_stride;
			rohc_debugf(3, "ts_offset = %u modulo %u = %u\n",
			            ts_sc->ts, ts_sc->ts_stride, ts_sc->ts_offset);
			ts_sc->ts_scaled = (ts_sc->ts - ts_sc->ts_offset) / ts_sc->ts_stride;
			rohc_debugf(3, "ts_scaled = (%u - %u) / %u = %u\n", ts_sc->ts,
			            ts_sc->ts_offset, ts_sc->ts_stride, ts_sc->ts_scaled);

			if(ts_sc->state != INIT_STRIDE &&
			   (ts_sc->ts_scaled - old_scaled) == (ts_sc->sn - ts_sc->old_sn))
			{
				rohc_debugf(2, "TS can be deducted from SN\n");
				ts_sc->is_deductible = 1;
			}
			else
			{
				rohc_debugf(2, "TS can not be deducted from SN\n");
				ts_sc->is_deductible = 0;
			}

			/* Wraparound (See RFC 4815 Section 4.4.3) */
			int wraparound =
				(ts_sc->ts_scaled > 0 && ts_sc->ts < ts_sc->old_ts) ||
				(ts_sc->ts_scaled < 0 && ts_sc->ts > ts_sc->old_ts);

			if(rest == 0 && wraparound)
			{
				rohc_debugf(2, "wraparoud detected\n");
				if(ts_sc->ts_stride % 2 != 0)
				{
					rohc_debugf(3, "ts_stride is not a power of two");
					ts_sc->state = INIT_STRIDE;
				}
			}
			break;
	}
}


/**
 * @brief Return the number of bits needed to encode TS_SCALED
 *
 * @param ts_sc        The ts_sc_comp object
 * @return             The number of bits needed
 */
int nb_bits_scaled(struct ts_sc_comp ts_sc)
{
	return c_get_k_wlsb(ts_sc.scaled_window, ts_sc.ts_scaled);
}


/**
 * @brief Add a new TS_SCALED value to the ts_sc_comp object
 *
 * @param ts_sc        The ts_sc_comp object
 * @param sn           The Sequence Number
 */
void add_scaled(struct ts_sc_comp *ts_sc, int sn)
{
	c_add_wlsb(ts_sc->scaled_window, sn, 0, ts_sc->ts_scaled);
}


/**
 * @brief Return the TS_SCALED value
 *
 * @param ts_sc        The ts_sc_comp object
 * @return             The TS_SCALED value
 */
int get_ts_scaled(struct ts_sc_comp ts_sc)
{
	return ts_sc.ts_scaled;
}


/**
 * @brief Return the TS_OFFSET value
 *
 * @param ts_sc        The ts_sc_comp object
 * @return             The TS_OFFSET value
 */
int get_offset(struct ts_sc_comp ts_sc)
{
	return ts_sc.ts_offset;
}


/**
 * @brief Return the TS_STRIDE value
 *
 * @param ts_sc        The ts_sc_comp object
 * @return             TS_STRIDE value
 */
int get_ts_stride(struct ts_sc_comp ts_sc)
{
	return ts_sc.ts_stride;
}


/**
 * @brief Whether TimeStamp (TS) is deductible from the Sequence Number (SN)
 *        or not
 *
 * @param ts_sc        The ts_sc_comp object
 * @return             1 if TS is deductible from SN, 0 otherwise
 */
int is_deductible(struct ts_sc_comp ts_sc)
{
	return ts_sc.is_deductible;
}


/**
 * @brief Whether TimeStamp (TS) did not change or not
 *
 * @param ts_sc        The ts_sc_comp object
 * @return             1 if TS did not change, 0 otherwise
 */
int is_ts_constant(struct ts_sc_comp ts_sc)
{
	return (ts_sc.ts_delta == 0);
}

