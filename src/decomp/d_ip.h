/**
 * @file d_ip.h
 * @brief ROHC decompression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef D_IP_H
#define D_IP_H

#include <netinet/ip.h>

#include "d_generic.h"


/*
 * Public function prototypes.
 */

unsigned int ip_detect_ir_size(struct d_context *context,
			       unsigned char *packet,
                               unsigned int plen,
                               int second_byte,
                               int profile_id);

unsigned int ip_detect_ir_dyn_size(unsigned char *first_byte,
                                   unsigned int plen,
                                   int largecid,
                                   struct d_context *context,
				   unsigned char *packet);

int ip_decode_dynamic_ip(struct d_generic_context *context,
                         const unsigned char *packet,
                         unsigned int length,
                         unsigned char *dest);

int ip_get_static_part(void);

#endif

