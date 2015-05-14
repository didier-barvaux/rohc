################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC performance application
################################################################################

bin_PROGRAMS = \
	rohc_test_performance \
	rohc_gen_stream

man_MANS = \
	rohc_test_performance.1 \
	rohc_gen_stream.1


rohc_test_performance_CFLAGS = \
	$(configure_cflags)
rohc_test_performance_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)
rohc_test_performance_LDFLAGS = \
	$(configure_ldflags)
rohc_test_performance_SOURCES = test_performance.c
rohc_test_performance_LDADD = \
	-l$(pcap_lib_name) \
	$(top_builddir)/src/librohc.la \
	$(additional_platform_libs)


rohc_gen_stream_CFLAGS = \
	$(configure_cflags)
rohc_gen_stream_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	$(libpcap_includes)
rohc_gen_stream_LDFLAGS = \
	$(configure_ldflags)
rohc_gen_stream_SOURCES = rohc_gen_stream.c
rohc_gen_stream_LDADD = \
	-l$(pcap_lib_name) \
	$(top_builddir)/src/librohc.la \
	$(additional_platform_libs)


if BUILD_DOC_MAN
rohc_test_performance.1: $(rohc_test_performance_SOURCES) $(builddir)/rohc_test_performance
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		-n "The ROHC performance application" \
		$(builddir)/rohc_test_performance

rohc_gen_stream.1: $(rohc_gen_stream_SOURCES) $(builddir)/rohc_gen_stream
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		-n "The generator of compressed/uncompressed RTP streams" \
		$(builddir)/rohc_gen_stream
endif

# extra files for releases
EXTRA_DIST = \
	$(man_MANS)

