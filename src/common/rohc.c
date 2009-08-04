/**
 * @file rohc.c
 * @brief ROHC common definitions and routines 
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Emmanuelle Pechereau <epechereau@toulouse.viveris.com>
 */

#include "rohc.h"


/**
 * @brief Get the version of the ROHC library
 *
 * @return the version of the library
 *
 * @ingroup rohc_comp
 * @ingroup rohc_decomp
 */
char *rohc_version(void)
{
	return VERSION;
}

