################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check behaviour of the common library
################################################################################


TESTS = \
	test_api_robustness.sh \
	test_rfc4996_encoding.sh


check_PROGRAMS = \
	test_api_robustness \
	test_rfc4996_encoding


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


test_rfc4996_encoding_SOURCES = test_rfc4996_encoding.c
test_rfc4996_encoding_LDADD = \
	-lrohc_comp
test_rfc4996_encoding_LDFLAGS = \
	-L$(top_builddir)/src/comp/.libs
test_rfc4996_encoding_CFLAGS = \
	$(configure_cflags)
test_rfc4996_encoding_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/comp


EXTRA_DIST = \
	test_api_robustness.sh \
	test_rfc4996_encoding.sh

