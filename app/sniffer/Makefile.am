################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC sniffer application
################################################################################

sbin_PROGRAMS = \
	rohc_sniffer

if BUILD_DOC_MAN
man_MANS = rohc_sniffer.1
endif


rohc_sniffer_CFLAGS = \
	$(configure_cflags)

rohc_sniffer_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

rohc_sniffer_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

rohc_sniffer_SOURCES = \
	sniffer.c

rohc_sniffer_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(additional_platform_libs)


rohc_sniffer.1: $(rohc_sniffer_SOURCES) rohc_sniffer
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		-n "The ROHC sniffer" \
		$(builddir)/rohc_sniffer

