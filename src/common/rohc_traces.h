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


/**
 * @brief A general profile number used for traces not related to a specific
 *        profile
 *
 * @ingroup rohc
 */
#define ROHC_PROFILE_GENERAL       0xffff


/**
 * @brief The different levels of the traces
 *
 * Used for the \e level parameter of the \ref rohc_trace_callback_t
 * user-defined callback.
 *
 * @ingroup rohc
 *
 * @see rohc_trace_callback_t
 * @see rohc_comp_set_traces_cb
 * @see rohc_decomp_set_traces_cb
 */
typedef enum
{
	ROHC_TRACE_DEBUG = 0,   /**< Print debug traces */
	ROHC_TRACE_INFO = 1,    /**< Print info (or lower) traces */
	ROHC_TRACE_WARNING = 2, /**< Print warning (or lower) traces */
	ROHC_TRACE_ERROR = 3,   /**< Print error (or lower) traces */
	ROHC_TRACE_LEVEL_MAX    /**< The maximum number of trace levels */
} rohc_trace_level_t;


/**
 * @brief The different entities concerned by the traces
 *
 * Used for the source \e entity parameter of the \ref rohc_trace_callback_t
 * user-defined callback.
 *
 * @ingroup rohc
 *
 * @see rohc_trace_callback_t
 * @see rohc_comp_set_traces_cb
 * @see rohc_decomp_set_traces_cb
 */
typedef enum
{
	ROHC_TRACE_COMP = 0,    /**< Compressor traces */
	ROHC_TRACE_DECOMP = 1,  /**< Decompressor traces */
	ROHC_TRACE_ENTITY_MAX   /**< The maximum number of trace entities */
} rohc_trace_entity_t;


/**
 * @brief The function prototype for the trace callback
 *
 * User-defined function that is called by the ROHC library every time it
 * wants to print something, from errors to debug. User may thus decide what
 * traces are interesting (filter on \e level, source \e entity, or
 * \e profile) and what to do with them (print on console, storage in file,
 * syslog...).
 *
 * The user-defined function is set by calling:
 *  \li function \ref rohc_comp_set_traces_cb for a ROHC compressor,
 *  \li function \ref rohc_decomp_set_traces_cb for a ROHC decompressor.
 *
 * Both functions accept the NULL value to fully disable tracing.
 *
 * @param level    The level of the message, @see rohc_trace_level_t
 * @param entity   The entity concerned by the traces, @see rohc_trace_entity_t
 * @param profile  The number of the profile concerned by the message
 * @param format   The format string for the trace message
 *
 * @ingroup rohc
 *
 * @see rohc_trace_level_t
 * @see rohc_trace_entity_t
 * @see rohc_comp_set_traces_cb
 * @see rohc_decomp_set_traces_cb
 */
typedef void (*rohc_trace_callback_t) (const rohc_trace_level_t level,
                                       const rohc_trace_entity_t entity,
                                       const int profile,
                                       const char *const format,
                                       ...)
#if defined(__USE_MINGW_ANSI_STDIO) && __USE_MINGW_ANSI_STDIO == 1
	/* MinGW interprets 'printf' format as 'ms_printf', so force
	 * usage of 'gnu_printf' */
	__attribute__((format(gnu_printf, 4, 5)));
#else
	/* Use 'printf' format in other cases, because old GCC versions
	 * and Clang do not recognize 'gnu_printf' format */
	__attribute__((format(printf, 4, 5)));
#endif


#endif

