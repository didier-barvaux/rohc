################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the ROHC common, compression and decompression libraries
################################################################################

SUBDIRS = \
	common \
	comp \
	decomp \
	test \
	.

lib_LTLIBRARIES = librohc.la

librohc_la_SOURCES =
librohc_la_LIBADD = \
	$(builddir)/common/librohc_common.la \
	$(builddir)/comp/librohc_comp.la \
	$(builddir)/decomp/librohc_decomp.la \
	$(additional_platform_libs)
librohc_la_LDFLAGS = \
	$(configure_ldflags) \
	-no-undefined \
	-version-info $(ROHC_API_CURRENT):$(ROHC_API_REVISION):$(ROHC_API_AGE)
librohc_la_CFLAGS =
librohc_la_CPPFLAGS =
librohc_la_DEPENDENCIES = \
	$(builddir)/common/librohc_common.la \
	$(builddir)/comp/librohc_comp.la \
	$(builddir)/decomp/librohc_decomp.la

EXTRA_DIST = \
	dllexport.h

