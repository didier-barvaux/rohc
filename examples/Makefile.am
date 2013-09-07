################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC example programs
################################################################################

examplesdir = $(docdir)/examples

examples_DATA = \
	simple_rohc_program.c \
	print_rohc_version.c

noinst_PROGRAMS = \
	simple_rohc_program \
	print_rohc_version


simple_rohc_program_CFLAGS = \
	$(configure_cflags)
simple_rohc_program_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp
simple_rohc_program_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs
simple_rohc_program_SOURCES = \
	simple_rohc_program.c
simple_rohc_program_LDADD = \
	-lrohc_comp \
	-lrohc_common \
	$(additional_platform_libs)


print_rohc_version_CFLAGS = \
	$(configure_cflags)
print_rohc_version_CPPFLAGS = \
	-I$(top_srcdir)/src/common
print_rohc_version_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs
print_rohc_version_SOURCES = \
	print_rohc_version.c
print_rohc_version_LDADD = \
	-lrohc_common \
	$(additional_platform_libs)

