################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@b2i-toulouse.com>
#	Description: create the ROHC tunnel application
################################################################################

bin_PROGRAMS = rohctunnel

INCLUDES = \
	-I../../src/common \
	-I../../src/comp \
	-I../../src/decomp

AM_CFLAGS = -g -Wall -Wstrict-prototypes -Werror

AM_LDFLAGS = \
	-L../../src/common/.libs \
	-L../../src/comp/.libs \
	-L../../src/decomp/.libs

rohctunnel_SOURCES = tunnel.c

rohctunnel_LDADD = \
	-lrohc_common \
	-lrohc_comp \
	-lrohc_decomp\
	-lm

