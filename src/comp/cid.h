/**
 * @file cid.h
 * @brief Context ID (CID) routines.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef CID_H
#define CID_H

#include "rohc_comp.h"


/*
 * Function prototypes.
 */

unsigned char c_add_cid(int cid);

int code_cid_values(struct c_context *context, unsigned char *dest, int dest_size, int *first_position);


#endif

