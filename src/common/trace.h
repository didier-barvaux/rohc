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
 * @file   trace.h
 * @brief  Trace prototypes function.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
*/

#include <stdint.h>

#include "dllexport.h"

void ROHC_EXPORT TraceData(unsigned char *Data, unsigned int NumBytes);

#if ROHC_TCP_DEBUG
void ROHC_EXPORT TraceIp(base_header_ip_vx_t *ip);
void ROHC_EXPORT TraceIpV4(base_header_ip_v4_t *ip);
void ROHC_EXPORT TraceIpV6(base_header_ip_v6_t *ip);
void ROHC_EXPORT TraceIpV6option(uint8_t previous_header,
                                 base_header_ip_t base_header);
void ROHC_EXPORT TraceTcp(tcphdr_t *tcp);
#else
#define TraceIp(ptr)
#define TraceIpV4(ptr)
#define TraceIpV6(ptr)
#define TraceIpV6option(header,ptr)
#define TraceTcp(ptr)
#endif

