################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC tunnel application
################################################################################

sbin_PROGRAMS = rohctunnel

if BUILD_DOC_MAN
man_MANS = rohctunnel.1
endif


rohctunnel_CFLAGS = \
	$(configure_cflags)

rohctunnel_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

rohctunnel_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

rohctunnel_SOURCES = \
	tunnel.c

rohctunnel_LDADD = \
	-lrohc_comp \
	-lrohc_decomp\
	-lrohc_common


rohctunnel.1: $(rohctunnel_SOURCES) $(builddir)/rohctunnel
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		--help-option=help --version-option=version \
		-n "The ROHC tunnel" \
		$(builddir)/rohctunnel

