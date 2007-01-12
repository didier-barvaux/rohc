################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@b2i-toulouse.com>
#	Description: create the ROHC compression library
################################################################################

lib_LTLIBRARIES = librohc_comp.la

sources = \
	rohc_comp.c \
	cid.c \
	c_uncompressed.c \
	c_generic.c \
	c_ip.c \
	c_udp.c \
	c_udp_lite.c

headers = \
	rohc_comp.h \
	cid.h \
	c_uncompressed.h \
	c_generic.h \
	c_ip.h \
	c_udp.h \
	c_udp_lite.h

librohc_comp_la_SOURCES = $(sources) $(headers)

include_HEADERS = rohc_comp.h cid.h

INCLUDES = \
	-I../common

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_MAKEFLAGS = -s

