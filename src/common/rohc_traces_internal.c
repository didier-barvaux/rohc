/*
 * Copyright 2012,2013 Didier Barvaux
 * Copyright 2009,2010 Thales Communications
 * Copyright 2012 Viveris Technologies
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
 * @file   rohc_traces_internal.c
 * @brief  ROHC for traces
 * @author Julien Bernard <julien.bernard@toulouse.viveris.com>
 * @author Audric Schiltknecht <audric.schiltknecht@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_traces_internal.h"
#include "rohc_utils.h"

#ifndef ROHC_NO_TRACES

#include <stdio.h> /* for snprintf(3) */
#include <assert.h>


/**
 * @brief Dump the content of the given packet
 *
 * @param trace_cb      The function to log traces
 * @param trace_cb_priv An optional private context, may be NULL
 * @param trace_entity  The entity that emits the traces
 * @param trace_level   The priority level for the trace
 * @param descr         The description of the packet to dump
 * @param packet        The packet to dump
 */
void rohc_dump_packet(const rohc_trace_callback2_t trace_cb,
                      void *const trace_cb_priv,
                      const rohc_trace_entity_t trace_entity,
                      const rohc_trace_level_t trace_level,
                      const char *const descr,
                      const struct rohc_buf packet)
{
	/* leave early if no trace callback was defined */
	if(trace_cb == NULL)
	{
		return;
	}

	assert(!rohc_buf_is_malformed(packet));

	rohc_dump_buf(trace_cb, trace_cb_priv, trace_entity, trace_level, descr,
	              rohc_buf_data(packet), rohc_min(packet.len, 100U));
}


/**
 * @brief Dump the content of the given buffer
 *
 * @param trace_cb      The function to log traces
 * @param trace_cb_priv An optional private context, may be NULL
 * @param trace_entity  The entity that emits the traces
 * @param trace_level   The priority level for the trace
 * @param descr         The description of the packet to dump
 * @param packet        The packet to dump
 * @param length        The length (in bytes) of the packet to dump
 */
void rohc_dump_buf(const rohc_trace_callback2_t trace_cb,
                   void *const trace_cb_priv,
                   const rohc_trace_entity_t trace_entity,
                   const rohc_trace_level_t trace_level,
                   const char *const descr,
                   const uint8_t *const packet,
                   const size_t length)
{
	/* leave early if no trace callback was defined */
	if(trace_cb == NULL)
	{
		return;
	}

	if(length == 0)
	{
		__rohc_print(trace_cb, trace_cb_priv, ROHC_TRACE_DEBUG, trace_entity,
		             ROHC_PROFILE_GENERAL, "%s (0 byte)", descr);
	}
	else
	{
#define rohc_dump_buf_byte_width   3U /* 'XX ' */
#define rohc_dump_buf_byte_nr     16U /* 16 bytes per line */
#define rohc_dump_buf_column_sep   2U /* spaces between 8 1st/last bytes */
#define rohc_dump_buf_line_max \
	((rohc_dump_buf_byte_width) * (rohc_dump_buf_byte_nr) + \
	 (rohc_dump_buf_column_sep))
#define rohc_dump_buf_size_max ((rohc_dump_buf_line_max) + 1)
		char line[rohc_dump_buf_size_max];
		size_t line_index;
		size_t i;

		__rohc_print(trace_cb, trace_cb_priv, trace_level, trace_entity,
		             ROHC_PROFILE_GENERAL, "%s (%zd bytes):", descr, length);
		line_index = 0;
		for(i = 0; i < length; i++)
		{
			if(i > 0 && (i % 16) == 0)
			{
				assert(line_index <= rohc_dump_buf_line_max);
				line[line_index] = '\0';
				__rohc_print(trace_cb, trace_cb_priv, trace_level, trace_entity,
				             ROHC_PROFILE_GENERAL, "%s", line);
				line_index = 0;
			}
			else if(i > 0 && (i % 8) == 0)
			{
				assert(line_index <= (rohc_dump_buf_line_max - rohc_dump_buf_column_sep));
				snprintf(line + line_index, rohc_dump_buf_column_sep + 1, "  ");
				line_index += rohc_dump_buf_column_sep;
			}
			assert(line_index <= (rohc_dump_buf_line_max - rohc_dump_buf_byte_width));
			snprintf(line + line_index, rohc_dump_buf_byte_width + 1, "%02x ", packet[i]);
			line_index += rohc_dump_buf_byte_width;
		}

		/* flush incomplete line */
		if(line_index > 0)
		{
			assert(line_index <= rohc_dump_buf_line_max);
			line[line_index] = '\0';
			__rohc_print(trace_cb, trace_cb_priv, trace_level, trace_entity,
			             ROHC_PROFILE_GENERAL, "%s", line);
		}
#undef rohc_dump_buf_byte_width
#undef rohc_dump_buf_byte_nr
#undef rohc_dump_buf_column_sep
#undef rohc_dump_buf_line_max
#undef rohc_dump_buf_size_max
	}
}

#endif

