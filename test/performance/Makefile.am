################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	             Didier Barvaux <didier@barvaux.org>
#	Description: create and run the ROHC performance tests
################################################################################

check_PROGRAMS = \
	test_performance


INCLUDES = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs


test_performance_SOURCES = test_performance.c
test_performance_LDADD = \
	-lpcap \
	-lrohc_comp \
	-lrohc_common \
	-lm

