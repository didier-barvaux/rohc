/*
 * Copyright 2012,2013 Didier Barvaux
 * Copyright 2012,2013,2014 Viveris Technologies
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
 * @file    test_rtp_ts_wraparound.c
 * @brief   Test RTP TS encoding/decoding at wraparound
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "schemes/comp_scaled_rtp_ts.h"
#include "schemes/decomp_scaled_rtp_ts.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>


/** The width of the W-LSB sliding window */
#define ROHC_WLSB_WINDOW_WIDTH  4U

/** The number of TS_STRIDE transmissions */
#define ROHC_INIT_TS_STRIDE_MIN  3U


/** Print trace on stdout only in verbose mode */
#define trace(is_verbose, format, ...) \
	do { \
		if(is_verbose) { \
			fprintf(stderr, format, ##__VA_ARGS__); \
		} \
	} while(0)


static bool run_test(bool be_verbose, const unsigned int incr);


/**
 * @brief Test RTP TS encoding/decoding at wraparound
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
	bool verbose; /* whether to run in verbose mode or not */
	int is_failure = 1; /* test fails by default */

	/* do we run in verbose mode ? */
	if(argc == 1)
	{
		/* no argument, run in silent mode */
		verbose = false;
	}
	else if(argc == 2 && strcmp(argv[1], "verbose") == 0)
	{
		/* run in verbose mode */
		verbose = true;
	}
	else
	{
		/* invalid usage */
		printf("test the RTP TS encoding/decoding at wraparound\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* run the test with irregular increment */
	trace(verbose, "test TS wraparound with irregular increment\n");
	if(!run_test(verbose, 0))
	{
		fprintf(stderr, "failed to handle RTP TS wraparound with irregular "
		        "increment\n");
		goto error;
	}

	/* run the test with power-of-two increment */
	trace(verbose, "test TS wraparound with power-of-two increment\n");
	if(!run_test(verbose, 256))
	{
		fprintf(stderr, "failed to handle RTP TS wraparound with power-of-two "
		        "increment\n");
		goto error;
	}

	/* run the test with non-power-of-two increment */
	trace(verbose, "test TS wraparound with non-power-of-two increment\n");
	if(!run_test(verbose, 257))
	{
		fprintf(stderr, "failed to handle RTP TS wraparound with "
		        "non-power-of-two increment\n");
		goto error;
	}

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Run the test
 *
 * @param be_verbose  Whether to print traces or not
 * @param incr        Increment between TS values
 * @return            true if test succeeds, false otherwise
 */
bool run_test(bool be_verbose, const unsigned int incr)
{
	const bool do_refresh_ts_stride = false;

	struct ts_sc_comp ts_sc_comp;      /* the RTP TS encoding context */
	struct ts_sc_decomp ts_sc_decomp; /* the RTP TS decoding context */

	uint32_t value; /* the value to encode */
	uint32_t value_encoded; /* the encoded value to decode */
	uint32_t value_decoded; /* the decoded value */

	unsigned int real_incr;

	int is_success = false; /* test fails by default */
	int ret;

	uint64_t i;

	/* create the RTP TS encoding context */
	ret = c_create_sc(&ts_sc_comp, ROHC_WLSB_WINDOW_WIDTH, NULL, NULL);
	if(ret != 1)
	{
		fprintf(stderr, "failed to initialize the RTP TS encoding context\n");
		goto error;
	}

	/* create the RTP TS decoding context */
	d_init_sc(&ts_sc_decomp, NULL, NULL);

	/* compute the initial value to encode */
	if(incr == 0)
	{
		real_incr = (20 + 10) / 2;
	}
	else
	{
		real_incr = incr;
	}
	value = (0xffffffff - 50 * real_incr);

	/* encode then decode values from ranges [0xffffffff - 50 * incr, 0xffffffff]
	 * and [0, 49 * incr] */
	for(i = 1; i < 100; i++)
	{
		struct ts_sc_changes ts_changes;
		size_t required_bits;
		uint32_t required_bits_mask;
		uint32_t ts_stride;

		/* value to encode/decode */
		if(incr == 0)
		{
			if((i % 2) == 0)
			{
				real_incr = 20;
			}
			else
			{
				real_incr = 10;
			}
		}
		else
		{
			real_incr = incr;
		}
		value += real_incr;
		if(value > 0xffffffff)
		{
			value = 0;
		}
		trace(be_verbose, "\t#%" PRIu64 ": encode value 0x%08x (+%u) ...\n",
		      i, value, real_incr);

		/* update encoding context */
		ts_detect_changes(&ts_sc_comp, value, i, do_refresh_ts_stride, &ts_changes);

		/* transmit the required bits wrt to encoding state */
		switch(ts_changes.state)
		{
			case INIT_TS:
				/* transmit all bits without encoding */
				trace(be_verbose, "\t\ttransmit all bits without encoding\n");
				value_encoded = value;
				required_bits = 32;
				/* update context */
				ts_sc_update(&ts_sc_comp, &ts_changes);
				/* change for INIT_STRIDE state */
				ts_changes.state = INIT_STRIDE;
				/* simulate transmission */
				/* decode received unscaled TS */
				if(!ts_decode_unscaled_bits(&ts_sc_decomp, value_encoded,
				                            required_bits, &value_decoded))
				{
					trace(be_verbose, "failed to decode received absolute unscaled TS\n");
					goto destroy_ts_sc_comp;
				}
				break;

			case INIT_STRIDE:
				/* transmit all bits along with TS_STRIDE */
				trace(be_verbose, "\t\ttransmit all bits without encoding "
				      "and TS_STRIDE\n");
				value_encoded = value;
				ts_stride = ts_changes.ts_stride;
				required_bits = 32;
				/* update context */
				ts_sc_update(&ts_sc_comp, &ts_changes);
				/* change for INIT_STRIDE state? */
				ts_sc_comp.nr_init_stride_packets++;
				if(ts_sc_comp.nr_init_stride_packets >= ROHC_INIT_TS_STRIDE_MIN)
				{
					ts_changes.state = SEND_SCALED;
				}
				/* simulate transmission */
				/* decode received unscaled TS */
				if(!ts_decode_unscaled_bits(&ts_sc_decomp, value_encoded,
				                            required_bits, &value_decoded))
				{
					trace(be_verbose, "failed to decode received unscaled TS\n");
					goto destroy_ts_sc_comp;
				}
				d_record_ts_stride(&ts_sc_decomp, ts_stride);
				break;

			case SEND_SCALED:
				/* transmit TS_SCALED */
				trace(be_verbose, "\t\ttransmit some bits of TS_SCALED\n");
				/* get TS_SCALED */
				value_encoded = ts_changes.ts_scaled;
				/* determine how many bits of TS_SCALED we need to send */
				required_bits = nb_bits_scaled(&ts_sc_comp.ts_scaled_wlsb, value_encoded,
				                               ts_changes.is_ts_scaled_deducible);
				assert(required_bits <= 32);
				/* truncate the encoded TS_SCALED to the number of bits we send */
				if(required_bits == 32)
				{
					required_bits_mask = 0xffffffff;
				}
				else
				{
					required_bits_mask = (1 << required_bits) - 1;
				}
				value_encoded = value_encoded & required_bits_mask;
				/* update context */
				ts_sc_update(&ts_sc_comp, &ts_changes);
				/* simulate transmission */
				/* decode TS */
				if(required_bits > 0)
				{
					/* decode the received TS_SCALED value */
					if(!ts_decode_scaled_bits(&ts_sc_decomp, value_encoded,
					                          required_bits, &value_decoded))
					{
						trace(be_verbose, "failed to decode received TS_SCALED\n");
						goto destroy_ts_sc_comp;
					}
				}
				else
				{
					/* deduct TS from SN */
					value_decoded = ts_deduce_from_sn(&ts_sc_decomp, i);
				}
				break;
			default:
				trace(be_verbose, "unknown RTP TS encoding state, "
				      "should not happen\n");
				assert(0);
				goto destroy_ts_sc_comp;
		}
		trace(be_verbose, "\t\tencoded on %zu bits: 0x%04x\n",
		      required_bits, value_encoded);

		/* check test result */
		if(value != value_decoded)
		{
			fprintf(stderr, "original and decoded values do not match while "
			        "testing value 0x%08x\n", value);
			goto destroy_ts_sc_comp;
		}

		/* update decoding context */
		ts_update_context(&ts_sc_decomp, value_decoded, i);
	}

	/* test succeeds */
	trace(be_verbose, "\ttest is successful\n");
	is_success = true;

destroy_ts_sc_comp:
	c_destroy_sc(&ts_sc_comp);
error:
	return is_success;
}

