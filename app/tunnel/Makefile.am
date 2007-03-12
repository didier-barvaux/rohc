################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@b2i-toulouse.com>
#	Description: create the ROHC tunnel application
################################################################################

bin_PROGRAMS = rohctunnel

INCLUDES = \
	-I../../include

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_MAKEFLAGS = -s

AM_LDFLAGS = \
	-L../../lib

rohctunnel_SOURCES = tunnel.c

rohctunnel_LDADD = \
	-lrohc_common \
	-lrohc_comp \
	-lrohc_decomp

