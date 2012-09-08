################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC statistics program
################################################################################

TESTS = \
	./generate_statistics.sh


check_PROGRAMS = \
	generate_statistics


generate_statistics_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/src/compat \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

generate_statistics_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs

generate_statistics_SOURCES = \
	generate_statistics.c

generate_statistics_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_common \
	$(additional_platform_libs)


distclean-am: clean-am distclean-compile distclean-generic distclean-tags
	$(RM) -r ./html

EXTRA_DIST = \
	generate_statistics.sh \
	inputs

