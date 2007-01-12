################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@b2i-toulouse.com>
#	Description: create the ROHC test program
################################################################################

bin_PROGRAMS = test

INCLUDES = \
	-I../include

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_MAKEFLAGS = -s

AM_LDFLAGS = \
	-L../lib

noinst_HEADERS = test.h

test_SOURCES = test.c

test_LDADD = \
	-lpcap \
	-lrohc_common \
	-lrohc_comp \
	-lrohc_decomp

