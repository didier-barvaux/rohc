################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@b2i-toulouse.com>
#	Description: create the ROHC test program
################################################################################

bin_PROGRAMS = test

INCLUDES = \
	-I../src/common \
	-I../src/comp \
	-I../src/decomp

AM_CFLAGS = -g -Wall -Wstrict-prototypes -Werror

AM_LDFLAGS = \
	-L../src/common/.libs \
	-L../src/comp/.libs \
	-L../src/decomp/.libs

noinst_HEADERS = test.h

test_SOURCES = test.c

test_LDADD = \
	-lpcap \
	-lrohc_common \
	-lrohc_comp \
	-lrohc_decomp \
	-lm

