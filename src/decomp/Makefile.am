################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the ROHC decompression library
################################################################################

lib_LTLIBRARIES = librohc_decomp.la

librohc_decomp_la_SOURCES = \
	rohc_decomp.c \
	feedback.c \
	d_uncompressed.c \
	d_generic.c \
	d_ip.c \
	d_udp.c \
	d_udp_lite.c \
	d_rtp.c

librohc_decomp_la_LIBADD = \
	$(top_builddir)/src/common/librohc_common.la \
	$(top_builddir)/src/comp/librohc_comp.la

INCLUDES = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

AM_CFLAGS = -g -Wall -Wstrict-prototypes

include_HEADERS = rohc_decomp.h

noinst_HEADERS = \
	feedback.h \
	d_uncompressed.h \
	d_generic.h \
	d_ip.h \
	d_udp.h \
	d_udp_lite.h \
	d_rtp.h

