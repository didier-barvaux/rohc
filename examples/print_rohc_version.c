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
 * @file     print_rohc_version.c
 * @brief    A simple program that prints the version of the ROHC library
 * @author   Didier Barvaux <didier@barvaux.org>
 */

/**
 * @example print_rohc_version.c
 *
 * How to print a textual representation of the version of the ROHC library.
 */

/* system includes */
#include <stdlib.h>
#include <stdio.h>

/* include required to use the common part of the ROHC library */
#include <rohc/rohc.h>


/**
 * @brief Print the version of the ROHC library
 *
 * @param argc  The number of arguments given to the program
 * @param argv  The table of arguments given to the program
 * @return      0 in case of success, 1 otherwise
 */
int main(int argc, char **argv)
{
//! [get ROHC version]
	const char *version;

	version = rohc_version();

	printf("ROHC version %s\n", version);
//! [get ROHC version]

	return 0;
}

