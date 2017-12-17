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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file    rohc_math64.h
 * @brief   ROHC internal functions for 64-bit math
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_MATH64_H
#define ROHC_MATH64_H

/*
 * rohc_do_div macro modifies 64-bit dividend in-place
 * and returns the 32-bit remainder
 */

#ifdef __KERNEL__
# include <asm/div64.h>
# define rohc_do_div(dividend, divisor) do_div(dividend, divisor)
#else
# define rohc_do_div(dividend, divisor) ({			\
	uint32_t __divisor = (divisor);				\
	uint32_t __remainder;					\
	__remainder = ((uint64_t)(dividend)) % __divisor;	\
	(dividend) = ((uint64_t)(dividend)) / __divisor;	\
	__remainder;						\
 })
#endif

#endif /* ROHC_MATH64_H */

