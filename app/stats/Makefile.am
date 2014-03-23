################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC statistics program
################################################################################

bin_PROGRAMS = \
	rohc_stats

if BUILD_DOC_MAN
man_MANS = \
	rohc_stats.1
endif


rohc_stats_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

rohc_stats_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	$(libpcap_includes)

rohc_stats_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs

rohc_stats_SOURCES = \
	rohc_stats.c

rohc_stats_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_common \
	$(additional_platform_libs)


rohc_stats.1: $(rohc_stats_SOURCES) $(builddir)/rohc_stats
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		-n "The ROHC statistics tool" \
		$(builddir)/rohc_stats


# extra files for releases
EXTRA_DIST = \
	rohc_stats.sh

