################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check behaviour of the comp library
################################################################################


TESTS = \
	test_feedback_parse.sh \
	test_api_robustness.sh


check_PROGRAMS = \
	test_feedback_parse \
	test_api_robustness


test_feedback_parse_SOURCES = \
	test_feedback_parse.c
test_feedback_parse_LDADD = \
	$(top_builddir)/src/common/librohc_common.la
test_feedback_parse_LDFLAGS = \
	$(configure_ldflags)
test_feedback_parse_CFLAGS = \
	$(configure_cflags)
test_feedback_parse_CPPFLAGS = \
	-I$(top_srcdir)/src/common


test_api_robustness_SOURCES = test_api_robustness.c
test_api_robustness_LDADD = \
	$(top_builddir)/src/common/librohc_common.la
test_api_robustness_LDFLAGS = \
	$(configure_ldflags)
test_api_robustness_CFLAGS = \
	$(configure_cflags)
test_api_robustness_CPPFLAGS = \
	-I$(top_srcdir)/src/common


EXTRA_DIST = \
	test_feedback_parse.sh \
	test_api_robustness.sh

