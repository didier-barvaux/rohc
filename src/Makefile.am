################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the ROHC common, compression and decompression libraries
################################################################################

SUBDIRS = \
	. \
	common \
	comp \
	decomp

lib_LTLIBRARIES = librohc.la

librohc_la_SOURCES =
librohc_la_LIBADD = \
	-lrohc_common \
	-lrohc_comp \
	-lrohc_decomp \
	$(additional_platform_libs)
librohc_la_LDFLAGS = \
	$(configure_ldflags) \
	-no-undefined \
	-version-info $(ROHC_API_CURRENT):$(ROHC_API_REVISION):$(ROHC_API_AGE) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs
librohc_la_CFLAGS =
librohc_la_CPPFLAGS =

EXTRA_DIST = \
	dllexport.h

