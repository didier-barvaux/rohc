/**
 * @file udp_lite.h
 * @brief Define the UDP-Lite protocol.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 */

#ifndef UDP_LITE_H
#define UDP_LITE_H

#include <netinet/udp.h>


#ifndef IPPROTO_UDPLITE
/// define the UDP-Lite protocol number if not already defined by the system
#define IPPROTO_UDPLITE  136
#warning "UDP-Lite not defined on the system, set the protocol number to 136"
#endif


#endif

