################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC fuzzer application
################################################################################

sbin_PROGRAMS = \
	rohc_fuzzer \
	rohc_rtp_fuzzer

if BUILD_DOC_MAN
man_MANS = \
	rohc_fuzzer.1 \
	rohc_rtp_fuzzer.1
endif


rohc_fuzzer_CFLAGS = \
	$(configure_cflags)

rohc_fuzzer_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

rohc_fuzzer_LDFLAGS = \
	$(configure_ldflags) \
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

rohc_fuzzer.1: $(rohc_fuzzer_SOURCES) rohc_fuzzer
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		-n "The ROHC fuzzing tool" \
		$(builddir)/rohc_fuzzer


rohc_rtp_fuzzer_CFLAGS = \
	$(configure_cflags)

rohc_rtp_fuzzer_CPPFLAGS = \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

rohc_rtp_fuzzer_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

rohc_rtp_fuzzer_SOURCES = \
	rtp_fuzzer.c

rohc_rtp_fuzzer_LDADD = \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(additional_platform_libs)

rohc_rtp_fuzzer.1: $(rohc_rtp_fuzzer_SOURCES) rohc_rtp_fuzzer
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		-n "The ROHC fuzzing tool for RTP traffic" \
		$(builddir)/rohc_rtp_fuzzer


# extra files for releases
EXTRA_DIST = \
   start_fuzzer.sh

