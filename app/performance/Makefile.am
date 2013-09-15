################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC performance application
################################################################################

sbin_PROGRAMS = \
	rohc_test_performance \
	rohc_gen_stream

if BUILD_DOC_MAN
man_MANS = \
	rohc_test_performance.1 \
	rohc_gen_stream.1
endif


rohc_test_performance_CFLAGS = \
	$(configure_cflags)
rohc_test_performance_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)
rohc_test_performance_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs
rohc_test_performance_SOURCES = test_performance.c
rohc_test_performance_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(sched_lib) \
	-lrt \
	$(additional_platform_libs)


rohc_gen_stream_CFLAGS = \
	$(configure_cflags)
rohc_gen_stream_CPPFLAGS = \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	$(libpcap_includes)
rohc_gen_stream_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs
rohc_gen_stream_SOURCES = rohc_gen_stream.c
rohc_gen_stream_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_common \
	$(additional_platform_libs)


rohc_test_performance.1: $(rohc_test_performance_SOURCES)
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		-n "The ROHC performance application" \
		$(builddir)/rohc_test_performance

rohc_gen_stream.1: $(rohc_gen_stream_SOURCES)
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		-n "The generator of compressed/uncompressed RTP streams" \
		$(builddir)/rohc_gen_stream

