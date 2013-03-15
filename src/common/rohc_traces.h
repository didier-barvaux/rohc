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
 * @file   rohc_traces.h
 * @brief  ROHC definitions for traces
 * @author Julien Bernard <julien.bernard@toulouse.viveris.com>
 * @author Audric Schiltknecht <audric.schiltknecht@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_TRACES_H
#define ROHC_TRACES_H


/** A general profile number used for traces not related to a specific profile */
#define ROHC_PROFILE_GENERAL       0xffff


/** The different levels of the traces */
typedef enum
{
	ROHC_TRACE_DEBUG = 0,
	ROHC_TRACE_INFO = 1,
	ROHC_TRACE_WARNING = 2,
	ROHC_TRACE_ERROR = 3,
	ROHC_TRACE_LEVEL_MAX
} rohc_trace_level_t;


/** The different entities concerned by the traces */
typedef enum
{
	ROHC_TRACE_COMP = 0,
	ROHC_TRACE_DECOMP = 1,
	ROHC_TRACE_ENTITY_MAX
} rohc_trace_entity_t;


/**
 * @brief The function prototype for the trace callback
 *
 * @param level    The level of the message, @see rohc_trace_level_t
 * @param entity   The entity concerned by the traces, @see rohc_trace_entity_t
 * @param profile  The number of the profile concerned by the message
 * @param format   The format string for the trace message
 */
typedef void (*rohc_trace_callback_t) (const rohc_trace_level_t level,
                                       const rohc_trace_entity_t entity,
                                       const int profile,
                                       const char *const format,
                                       ...)
#if defined(__USE_MINGW_ANSI_STDIO) && __USE_MINGW_ANSI_STDIO == 1
	/* MinGW interprets 'printf' format as 'ms_printf', so force
	 * usage of 'gnu_printf' */
	__attribute__((format(gnu_printf, 4, 5), nonnull(4)));
#else
	/* Use 'printf' format in other cases, because old GCC versions
	 * and Clang do not recognize 'gnu_printf' format */
	__attribute__((format(printf, 4, 5), nonnull(4)));
#endif


#endif

