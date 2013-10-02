################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check behaviour of the comp library
################################################################################


TESTS = \
	test_rfc4996.sh


check_PROGRAMS = \
	test_rfc4996


test_rfc4996_SOURCES = test_rfc4996.c
test_rfc4996_LDADD = \
	-lrohc_comp
test_rfc4996_LDFLAGS = \
	-L$(top_builddir)/src/comp/.libs
test_rfc4996_CFLAGS = \
	$(configure_cflags)
test_rfc4996_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(srcdir)/..


EXTRA_DIST = \
	test_rfc4996.sh

