################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC tunnel application
################################################################################

sbin_PROGRAMS = rohctunnel

rohctunnel_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

rohctunnel_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

rohctunnel_SOURCES = \
	tunnel.c

rohctunnel_LDADD = \
	-lrohc_comp \
	-lrohc_decomp\
	-lrohc_common

