################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create and run the ROHC non-regression tests
################################################################################

SUBDIRS = . rfc3095 rfc6846


check_PROGRAMS = \
	test_non_regression

if ROHC_LINUX_MODULE
check_PROGRAMS += test_non_regression_kernel
endif


test_non_regression_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_non_regression_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_non_regression_LDFLAGS = \
	-L$(top_builddir)/src/.libs \
	$(configure_ldflags)

test_non_regression_SOURCES = \
	test_non_regression.c

test_non_regression_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc \
	$(additional_platform_libs)


test_non_regression_kernel_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_non_regression_kernel_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	$(libpcap_includes)

test_non_regression_kernel_LDFLAGS = \
	$(configure_ldflags)

test_non_regression_kernel_SOURCES = \
	test_non_regression_kernel.c

test_non_regression_kernel_LDADD = \
	-l$(pcap_lib_name) \
	$(additional_platform_libs)


EXTRA_DIST = \
	test_non_regression.sh

