/**
 * @file rohc.c
 * @brief ROHC common definitions and routines 
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author Emmanuelle Pechereau <epechereau@b2i-toulouse.com>
 */

#include "rohc.h"


/**
 * @brief Get the version of the ROHC library
 *
 * @return the version of the library
 */
char *rohc_version(void)
{
	return VERSION;
}

