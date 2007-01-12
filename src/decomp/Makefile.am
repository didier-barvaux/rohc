################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@b2i-toulouse.com>
#	Description: create the ROHC decompression library
################################################################################

AM_MAKEFLAGS = -s

lib_LTLIBRARIES = librohc_decomp.la

sources = \
	rohc_decomp.c \
	feedback.c \
	d_uncompressed.c \
	d_generic.c \
	d_ip.c \
	d_udp.c \
	d_udp_lite.c

headers = \
	rohc_decomp.h \
	feedback.h \
	d_uncompressed.h \
	d_generic.h \
	d_ip.h \
	d_udp.h \
	d_udp_lite.h

librohc_decomp_la_SOURCES = $(sources) $(headers)

include_HEADERS = rohc_decomp.h

INCLUDES = \
	-I../common \
	-I../comp

AM_CFLAGS = -g -Wall -Wstrict-prototypes

