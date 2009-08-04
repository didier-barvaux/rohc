/**
 * @file sdvl.h
 * @brief Self-Describing Variable-Length (SDVL) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef SDVL_H
#define SDVL_H

#include "rohc.h"


/*
 * Function prototypes.
 */

int c_bytesSdvl(int value, int length);

boolean c_encodeSdvl(unsigned char *dest, int value, int length);

int d_sdvalue_size(const unsigned char *data);

int d_sdvalue_decode(const unsigned char *data);


#endif

