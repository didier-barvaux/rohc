################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check behaviour of the comp library
################################################################################


TESTS = \
	test_api_robustness.sh


check_PROGRAMS = \
	test_api_robustness


test_api_robustness_SOURCES = test_api_robustness.c
test_api_robustness_LDADD = \
	-lrohc_decomp \
	-lrohc_comp \
	-lrohc_common
test_api_robustness_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs
test_api_robustness_CFLAGS = \
	$(configure_cflags)
test_api_robustness_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp


EXTRA_DIST = \
	test_api_robustness.sh

