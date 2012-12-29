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
 * @file   rohc_traces_internal.h
 * @brief  Internal ROHC macros and functions for traces
 * @author Julien Bernard <julien.bernard@toulouse.viveris.com>
 * @author Audric Schiltknecht <audric.schiltknecht@toulouse.viveris.com>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_TRACES_INTERNAL_H
#define ROHC_TRACES_INTERNAL_H

#include "rohc_traces.h"

#include <stdlib.h>
#include <assert.h>

#include "dllexport.h"


/** Print information depending on the debug level (internal usage) */
#define __rohc_print(trace_cb, level, entity, profile, format, ...) \
	do { \
		if(trace_cb != NULL) { \
			trace_cb(level, entity, profile, "[%s:%d %s()] " format, \
			         __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
		} \
	} while(0)

/** Print information depending on the debug level */
#define rohc_print(entity_struct, level, entity, profile, format, ...) \
	do { \
		assert((entity_struct) != NULL); \
		__rohc_print((entity_struct)->trace_callback, \
		             level, entity, profile, \
		             format, ##__VA_ARGS__); \
	} while(0)

/** Print debug messages prefixed with the function name */
#define rohc_debug(entity_struct, entity, profile, format, ...) \
	rohc_print(entity_struct, ROHC_TRACE_DEBUG, entity, profile, \
	           format, ##__VA_ARGS__)

/** Print information prefixed with the function name */
#define rohc_info(entity_struct, entity, profile, format, ...) \
	rohc_print(entity_struct, ROHC_TRACE_INFO, entity, profile, \
	           format, ##__VA_ARGS__)

/** Print warning messages prefixed with the function name */
#define rohc_warning(entity_struct, entity, profile, format, ...) \
	rohc_print(entity_struct, ROHC_TRACE_WARNING, entity, profile, \
	           format, ##__VA_ARGS__)

/** Print error messages prefixed with the function name */
#define rohc_error(entity_struct, entity, profile, format, ...) \
	rohc_print(entity_struct, ROHC_TRACE_ERROR, entity, profile, \
	           format, ##__VA_ARGS__)

/**
 * @brief Stop processing if the given condition is false
 *
 * In non-debug mode (ie. NDEBUG set): if the given condition fails, prints
 * the given message then jump to the given label.
 *
 * In debug mode (ie. NDEBUG not set): if the given condition fails, prints
 * the given message then asserts.
 */
#define rohc_assert(entity_struct, entity, profile, \
                    condition, label, format, ...) \
	do { \
		if(!(condition)) { \
			rohc_error(entity_struct, entity, profile, \
			           format, ##__VA_ARGS__); \
			assert(condition); \
			goto label; \
		} \
	} while(0)


void ROHC_EXPORT rohc_dump_packet(const rohc_trace_callback_t trace_cb,
                                  const rohc_trace_entity_t trace_entity,
                                  const rohc_trace_level_t trace_level,
                                  const char *const descr,
                                  const unsigned char *const packet,
                                  const size_t length)
	__attribute__((nonnull(4, 5)));


#endif

