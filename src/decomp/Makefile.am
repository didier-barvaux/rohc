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

INCLUDES = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

AM_CFLAGS = -g -Wall -Wstrict-prototypes

include_HEADERS = rohc_decomp.h

EXTRA_DIST = \
	feedback.h \
	d_uncompressed.h \
	d_generic.h \
	d_ip.h \
	d_udp.h \
	d_udp_lite.h \
	d_rtp.h

