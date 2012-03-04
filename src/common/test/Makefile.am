################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check behaviour of the common library
################################################################################


TESTS = \
	test_lsb_decode


check_PROGRAMS = \
	test_lsb_decode


INCLUDES = \
	-I$(top_srcdir)/src/common

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs


test_lsb_decode_SOURCES = test_lsb_decode.c
test_lsb_decode_LDADD = \
	-lrohc_common

EXTRA_DIST =

