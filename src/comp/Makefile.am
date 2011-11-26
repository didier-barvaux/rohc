################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the ROHC compression library
################################################################################

lib_LTLIBRARIES = librohc_comp.la

librohc_comp_la_SOURCES = \
	rohc_comp.c \
	c_uncompressed.c \
	c_generic.c \
	c_ip.c \
	c_udp.c \
	c_udp_lite.c \
	c_rtp.c

INCLUDES = \
	-I$(top_srcdir)/src/common

AM_CFLAGS = -g -Wall -Wstrict-prototypes

include_HEADERS = \
	rohc_comp.h

noinst_HEADERS = \
	rohc_comp_internals.h \
	c_generic.h \
	c_ip.h \
	c_udp.h \
	c_udp_lite.h \
	c_rtp.h

