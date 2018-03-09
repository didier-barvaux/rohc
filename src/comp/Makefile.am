################################################################################
# Name       : Makefile
# Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC compression library
################################################################################

if ROHC_TESTS
COMP_TESTS_DIR = test
else
COMP_TESTS_DIR = 
endif

SUBDIRS = schemes . $(COMP_TESTS_DIR)


noinst_LTLIBRARIES = librohc_comp.la

librohc_comp_la_SOURCES = \
	rohc_comp.c \
	c_uncompressed.c \
	rohc_comp_rfc3095.c \
	c_ip.c \
	c_udp.c \
	c_udp_lite.c \
	c_esp.c \
	c_rtp.c \
	c_tcp_opts_list.c \
	c_tcp_static.c \
	c_tcp_dynamic.c \
	c_tcp_replicate.c \
	c_tcp_irregular.c \
	c_tcp.c \
	comp_rfc5225_ip.c \
	comp_rfc5225_ip_esp.c \
	comp_rfc5225_ip_udp.c \
	comp_rfc5225_ip_udp_rtp.c

librohc_comp_la_LIBADD = \
	$(builddir)/schemes/librohc_comp_schemes.la \
	$(additional_platform_libs)

librohc_comp_la_LDFLAGS = \
	$(configure_ldflags)

librohc_comp_la_CFLAGS = \
	$(configure_cflags) \
	$(configure_cflags_for_lib)

librohc_comp_la_CPPFLAGS = \
	-I$(top_srcdir)/src/common

librohc_comp_la_DEPENDENCIES = \
	$(top_builddir)/src/common/librohc_common.la \
	$(builddir)/schemes/librohc_comp_schemes.la

pkginclude_HEADERS = \
	rohc_comp.h

noinst_HEADERS = \
	rohc_comp_internals.h \
	rohc_comp_rfc3095.h \
	c_ip.h \
	c_udp.h \
	c_rtp.h \
	c_tcp_defines.h \
	c_tcp_opts_list.h \
	c_tcp_static.h \
	c_tcp_dynamic.h \
	c_tcp_replicate.h \
	c_tcp_irregular.h

# extra files for releases
EXTRA_DIST = \
	rohc

