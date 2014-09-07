################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC sniffer application
################################################################################

sbin_PROGRAMS = \
	rohc_sniffer

man_MANS = rohc_sniffer.1


rohc_sniffer_CFLAGS = \
	$(configure_cflags)

rohc_sniffer_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

rohc_sniffer_LDFLAGS = \
	$(configure_ldflags)

rohc_sniffer_SOURCES = \
	sniffer.c

rohc_sniffer_LDADD = \
	-l$(pcap_lib_name) \
	$(top_builddir)/src/comp/librohc_comp.la \
	$(top_builddir)/src/decomp/librohc_decomp.la \
	$(top_builddir)/src/common/librohc_common.la \
	$(additional_platform_libs)


if BUILD_DOC_MAN
rohc_sniffer.1: $(rohc_sniffer_SOURCES) $(builddir)/rohc_sniffer
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		-n "The ROHC sniffer" \
		$(builddir)/rohc_sniffer
endif

# extra files for releases
EXTRA_DIST = \
	$(man_MANS)

