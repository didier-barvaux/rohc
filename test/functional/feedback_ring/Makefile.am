################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check library features
################################################################################

TESTS = \
	test_feedback_ring.sh

check_PROGRAMS = \
	test_feedback_ring

test_feedback_ring_SOURCES = test_feedback_ring.c

test_feedback_ring_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

test_feedback_ring_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs

test_feedback_ring_LDADD = \
	-lrohc_comp \
	-lrohc_common \
	$(additional_platform_libs)

EXTRA_DIST = \
	$(TESTS)

