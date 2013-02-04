################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC fuzzer application
################################################################################

sbin_PROGRAMS = \
	rohc_fuzzer


rohc_fuzzer_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

rohc_fuzzer_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

rohc_fuzzer_SOURCES = \
	fuzzer.c

rohc_fuzzer_LDADD = \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(additional_platform_libs)

# extra files for releases
EXTRA_DIST = \
   start_fuzzer.sh

