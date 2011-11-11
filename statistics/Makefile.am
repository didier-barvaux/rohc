################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC statistics program
################################################################################

TESTS = \
	./generate_statistics.sh


check_PROGRAMS = \
	generate_statistics


INCLUDES = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs


generate_statistics_SOURCES = generate_statistics.c
generate_statistics_LDADD = \
	-lpcap \
	-lrohc_comp \
	-lrohc_common \
	-lm


distclean-am: clean-am distclean-compile distclean-generic distclean-tags
	$(RM) -r ./html

EXTRA_DIST = \
	generate_statistics.sh \
	inputs

