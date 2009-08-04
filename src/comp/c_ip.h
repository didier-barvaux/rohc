/**
 * @file c_ip.h
 * @brief ROHC compression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef C_IP_H
#define C_IP_H

#include <netinet/ip.h>
#include "c_generic.h"

/*
 * Function prototypes.
 */

int c_ip_check_context(struct c_context *context, const struct ip_packet ip);

#endif
