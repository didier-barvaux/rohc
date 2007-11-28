#!/bin/bash

# Process this file with autoconf to produce a configure script.
AC_INIT(B2i, 0.0.1, didier.barvaux@b2i-toulouse.com)
AC_CONFIG_SRCDIR([src])
AM_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

# By default, generate static libraries
#AC_DISABLE_SHARED

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for libraries.
AC_SUBST(SET_MAKE,MAKE=make)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([netinet/ip.h netinet/udp.h stdio.h stdlib.h string.h strings.h time.h sys/time.h netinet/in.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([malloc calloc free memcpy memcmp bzero ceil])

# check if RTP bit type is enable
AC_ARG_ENABLE(rtp_bit_type, [  --enable-rtp-bit-type   enable RTP bit type (use an additionnal bit to distinguish UOR-2-TS and UOR-2-ID packets) [[default=no]]], enable_rtp_bit_type=$enableval, enable_rtp_bit_type=no)
if test "$enable_rtp_bit_type" = "yes"; then
	rtp_bit_type=1
else
	rtp_bit_type=0
fi
AC_DEFINE_UNQUOTED([RTP_BIT_TYPE], [$rtp_bit_type], [Whether RTP bit type is enable or not.])



# Install binaries and libraries in the current directory tree
AC_PREFIX_DEFAULT(`pwd`)

AM_DEP_TRACK

AC_CONFIG_FILES([Makefile src/Makefile src/common/Makefile src/comp/Makefile src/decomp/Makefile test/Makefile app/Makefile app/tunnel/Makefile])

AC_OUTPUT
