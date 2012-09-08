################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC example programs
################################################################################

examplesdir = $(docdir)/examples

examples_DATA = \
	simple_rohc_program.c

noinst_PROGRAMS = \
	simple_rohc_program


simple_rohc_program_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

simple_rohc_program_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs

simple_rohc_program_SOURCES = \
	simple_rohc_program.c

simple_rohc_program_LDADD = \
	-lrohc_comp \
	-lrohc_common

