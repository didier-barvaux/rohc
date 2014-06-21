/*
 * Copyright 2011,2012,2013 Didier Barvaux
 * Copyright 2009,2010 Thales Communications
 * Copyright 2010,2012 Viveris Technologies
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
#include "rohc_buf.h"

#include "config.h" /* for ROHC_ENABLE_DEPRECATED_API */

#include <stdlib.h>
#include <assert.h>

#include "dllexport.h"


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
/** Print information depending on the debug level (internal usage) */
#define __rohc_print(trace_cb, trace_cb2, trace_cb_priv, \
                     level, entity, profile, format, ...) \
	do { \
		if(trace_cb2 != NULL) { \
			trace_cb2(trace_cb_priv, level, entity, profile, \
			         "[%s:%d %s()] " format "\n", \
			         __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
		} else if(trace_cb != NULL) { \
			trace_cb(level, entity, profile, \
			         "[%s:%d %s()] " format "\n", \
			         __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
		} \
	} while(0)
#else
/** Print information depending on the debug level (internal usage) */
#define __rohc_print(trace_cb, trace_cb_priv, \
                     level, entity, profile, format, ...) \
	do { \
		if(trace_cb != NULL) { \
			trace_cb(trace_cb_priv, level, entity, profile, \
			         "[%s:%d %s()] " format "\n", \
			         __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
		} \
	} while(0)
#endif

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
/** Print information depending on the debug level */
#define rohc_print(entity_struct, level, entity, profile, format, ...) \
	do { \
		assert((entity_struct) != NULL); \
		__rohc_print((entity_struct)->trace_callback, \
		             (entity_struct)->trace_callback2, \
		             (entity_struct)->trace_callback_priv, \
		             level, entity, profile, \
		             format, ##__VA_ARGS__); \
	} while(0)
#else
/** Print information depending on the debug level */
#define rohc_print(entity_struct, level, entity, profile, format, ...) \
	do { \
		assert((entity_struct) != NULL); \
		__rohc_print((entity_struct)->trace_callback2, \
		             (entity_struct)->trace_callback_priv, \
		             level, entity, profile, \
		             format, ##__VA_ARGS__); \
	} while(0)
#endif

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


void ROHC_EXPORT rohc_dump_packet(
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
                                  const rohc_trace_callback_t trace_cb,
#endif
                                  const rohc_trace_callback2_t trace_cb2,
                                  void *const trace_cb_priv,
                                  const rohc_trace_entity_t trace_entity,
                                  const rohc_trace_level_t trace_level,
                                  const char *const descr,
                                  const struct rohc_buf packet);

void ROHC_EXPORT rohc_dump_buf(
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
                               const rohc_trace_callback_t trace_cb,
#endif
                               const rohc_trace_callback2_t trace_cb2,
                               void *const trace_cb_priv,
                               const rohc_trace_entity_t trace_entity,
                               const rohc_trace_level_t trace_level,
                               const char *const descr,
                               const unsigned char *const packet,
                               const size_t length);

#endif

