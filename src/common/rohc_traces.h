/**
 * @file rohc_traces.h
 * @brief ROHC macros for traces
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_TRACES_H
#define ROHC_TRACES_H

#include "config.h" /* for ROHC_DEBUG_LEVEL */

/// @brief Print information depending on the debug level and prefixed
///        with the function name
#define rohc_debugf(level, format, ...) \
	rohc_debugf_(level, "%s[%s:%d %s()] " format, \
	             (level == 0 ? "[ERROR] " : ""), \
	             __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

/// Print information depending on the debug level
#define rohc_debugf_(level, format, ...) \
	do { \
		if((level) <= ROHC_DEBUG_LEVEL) \
			printf(format, ##__VA_ARGS__); \
	} while(0)


#endif
