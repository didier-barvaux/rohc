/*
 * Copyright 2017 Didier Barvaux
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file   linux/include/inttypes.h
 * @brief  Define inttypes.h for the Linux kernel
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_KERNEL_INTTYPES_H
#define ROHC_KERNEL_INTTYPES_H

#ifndef __KERNEL__
#	error "for Linux kernel only!"
#endif

#include <stdint.h>

#endif /* ROHC_KERNEL_INTTYPES_H */
