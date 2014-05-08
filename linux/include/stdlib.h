/*
 * Copyright 2013 Viveris Technologies
 *
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
 * @file   linux/include/stdlib.h
 * @brief  Define the malloc functions for the Linux kernel
 * @author Mikhail Gruzdev <michail.gruzdev@gmail.com>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Thales Communications
 */

#ifndef STDLIB_H_
#define STDLIB_H_

#ifndef __KERNEL__
#	error "for Linux kernel only!"
#endif

#include <linux/slab.h>

/** Alias malloc to kmalloc */
#define malloc(x)  kmalloc((x), GFP_ATOMIC)

/** Alias calloc to kcalloc */
#define calloc(x, y)  kcalloc((x), (y), GFP_ATOMIC)

/** Alias free to kfree */
#define free(x)  kfree(x)

#endif /* STDLIB_H_ */

