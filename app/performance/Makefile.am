################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	             Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC performance application
################################################################################

sbin_PROGRAMS = \
	rohc_test_performance


INCLUDES = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs

rohc_test_performance_SOURCES = test_performance.c
rohc_test_performance_LDADD = \
	-lpcap \
	-lrohc_comp \
	-lrohc_common \
	-lm

