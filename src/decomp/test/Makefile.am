################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check behaviour of the comp library
################################################################################


TESTS = \
	test_api_robustness.sh


check_PROGRAMS = \
	test_api_robustness \
	print_struct_sizes


test_api_robustness_SOURCES = test_api_robustness.c
test_api_robustness_LDADD = \
	$(top_builddir)/src/decomp/librohc_decomp.la \
	$(top_builddir)/src/common/librohc_common.la
test_api_robustness_LDFLAGS = \
	$(configure_ldflags)
test_api_robustness_CFLAGS = \
	$(configure_cflags)
test_api_robustness_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/decomp


print_struct_sizes_SOURCES = print_struct_sizes.c
print_struct_sizes_LDADD = \
	$(top_builddir)/src/decomp/librohc_decomp.la \
	$(top_builddir)/src/common/librohc_common.la
print_struct_sizes_LDFLAGS = \
	$(configure_ldflags)
print_struct_sizes_CFLAGS = \
	$(configure_cflags)
print_struct_sizes_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/decomp


EXTRA_DIST = \
	test_api_robustness.sh

