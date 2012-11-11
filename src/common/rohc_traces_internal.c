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
 * @file   rohc_traces_internal.c
 * @brief  ROHC for traces
 * @author Julien Bernard <julien.bernard@toulouse.viveris.com>
 * @author Audric Schiltknecht <audric.schiltknecht@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_traces_internal.h"

#include <assert.h>


/**
 * @brief Dump given packet content
 *
 * @param trace_cb      The function to log traces
 * @param trace_entity  The entity that emits the traces
 * @param descr         The description of the packet to dump
 * @param packet        The packet to dump
 * @param length        The length (in bytes) of the packet to dump
 */
void rohc_dump_packet(const rohc_trace_callback_t trace_cb,
                      const rohc_trace_entity_t trace_entity,
                      const char *const descr,
                      const unsigned char *const packet,
                      const size_t length)
{
	size_t i;

	assert(descr != NULL);
	assert(packet != NULL);
	assert(length > 0);

	__rohc_print(trace_cb, ROHC_TRACE_DEBUG, trace_entity,
	             ROHC_PROFILE_GENERAL, "%s (%zd bytes):\n", descr, length);
	for(i = 0; i < length; i++)
	{
		if(i > 0 && (i % 16) == 0)
		{
			__rohc_print_raw(trace_cb, ROHC_TRACE_DEBUG, trace_entity,
			                 ROHC_PROFILE_GENERAL, "\n");
		}
		else if(i > 0 && (i % 8) == 0)
		{
			__rohc_print_raw(trace_cb, ROHC_TRACE_DEBUG, trace_entity,
			                 ROHC_PROFILE_GENERAL, " ");
		}
		__rohc_print_raw(trace_cb, ROHC_TRACE_DEBUG, trace_entity,
		                 ROHC_PROFILE_GENERAL, "%02x ", packet[i]);
	}
	__rohc_print_raw(trace_cb, ROHC_TRACE_DEBUG, trace_entity,
	                 ROHC_PROFILE_GENERAL, "\n");
}

