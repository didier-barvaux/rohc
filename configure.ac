#!/bin/bash

# Process this file with autoconf to produce a configure script.
AC_INIT(rohc, trunk, http://launchpad.net/rohc/)
AC_CONFIG_SRCDIR([src])
AM_CONFIG_HEADER([config.h])

# Init automake with:
#  - silent rules enabled to make 'make' less verbose, but do not call the
#    AM_SILENT_RULES macro if it is not defined to keep compatibility with
#    automake < 1.11 for the moment.
#  - color-tests to get nice colored results for tests (currently disabled
#    to keep compatibility with automake 1.10 for the moment.
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Disable static libraries by default
AC_DISABLE_STATIC

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADERS([stdio.h stdlib.h string.h strings.h])
AC_CHECK_HEADERS([time.h sys/time.h])
AC_CHECK_HEADERS([netinet/ip.h netinet/udp.h netinet/in.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE

# Checks for library functions.
AC_CHECK_FUNCS([malloc calloc free memcpy memcmp bzero ceil])


# get debug level
AC_ARG_ENABLE(rohc_debug,
              AS_HELP_STRING([--enable-rohc-debug],
                             [set level for ROHC traces: \
                              0 = error messages only, \
                              1 = a few informative messages, \
                              2 = more informative messages, \
                              3 = even more informative messages \
                              [[default=3]]]),
              rohc_debug_level=$enableval,
              rohc_debug_level=3)
AC_DEFINE_UNQUOTED([ROHC_DEBUG_LEVEL], [$rohc_debug_level],
                   [Debug level for ROHC library])


# check if -Werror must be appended to CFLAGS
AC_ARG_ENABLE(fail_on_warning,
              AS_HELP_STRING([--enable-fail-on-warning],
                             [build fails on warnings if enabled [[default=no]]]),
              fail_on_warning=$enableval,
              fail_on_warning=no)
if test "x$fail_on_warning" != "xno"; then
	CFLAGS="${CFLAGS} -Werror"
fi


# allow users to specify a special location for libpcap includes
AC_ARG_WITH(libpcap_includes,
            AS_HELP_STRING([--with-libpcap-includes=DIR],
                           [libpcap include directory]),
            [with_libpcap_includes="$withval"],
            [with_libpcap_includes="no"])
if test "x$with_libpcap_includes" != "xno"; then
	CPPFLAGS="${CPPFLAGS} -I${with_libpcap_includes}"
fi


# allow users to specify a special location for libpcap libraries
AC_ARG_WITH(libpcap_libraries,
            AS_HELP_STRING([--with-libpcap-libraries=DIR],
                           [libpcap library directory]),
            [with_libpcap_libraries="$withval"],
            [with_libpcap_libraries="no"])
if test "x$with_libpcap_libraries" != "xno"; then
	LDFLAGS="${LDFLAGS}  -L${with_libpcap_libraries}"
fi


# check if ROHC tests are enabled
AC_ARG_ENABLE(rohc_tests,
              AS_HELP_STRING([--enable-rohc-tests],
                             [enable ROHC tests [[default=no]]]),
              enable_rohc_tests=$enableval,
              enable_rohc_tests=no)
AM_CONDITIONAL([ROHC_TESTS], [test x$enable_rohc_tests = xyes])


# check if ROHC statistics application is enabled
AC_ARG_ENABLE(rohc_stats,
              AS_HELP_STRING([--enable-rohc-stats],
                             [enable ROHC statistics application [[default=no]]]),
              enable_rohc_stats=$enableval,
              enable_rohc_stats=no)
AM_CONDITIONAL([ROHC_STATS], [test x$enable_rohc_stats = xyes])


# if ROHC tests or statistics are enabled:
#  - fail if cross-compiling
#  - libpcap is mandatory if ROHC tests or statistics are enabled
if test "x$enable_rohc_tests" = "xyes" || test "x$enable_rohc_stats" = "xyes"; then
	# cross-compiling is not compatible with tests and stats yet
	if test "x$cross_compiling" = "xyes" ; then
		echo
		echo "ERROR: --enable-rohc-tests and --enable-rohc-stats are not compatible"
		echo "       with cross-compiling"
		echo
		echo "Please disable both options and try again."
		exit 1
	fi

	# check for libpcap presence
	LPCAP=""
	AC_CHECK_LIB(pcap, pcap_open_offline, [ ], LPCAP="no")
	AC_CHECK_LIB(pcap, pcap_datalink, [ ], LPCAP="no")
	AC_CHECK_LIB(pcap, pcap_next, [ ], LPCAP="no")
	AC_CHECK_LIB(pcap, pcap_close, [ ], LPCAP="no")
	AC_CHECK_LIB(pcap, pcap_dump_open, [ ], LPCAP="no")
	AC_CHECK_LIB(pcap, pcap_dump, [ ], LPCAP="no")
	AC_CHECK_LIB(pcap, pcap_dump_close, [ ], LPCAP="no")

	# abort if libpcap is not found
    if test "x$LPCAP" = "xno"; then
		echo
		echo "ERROR: libpcap library/headers not found"
		echo
		echo "Go get it from http://www.tcpdump.org/ or use the --with-libpcap-* "
		echo "options, if you have it installed in unusual place. Also check if "
		echo "your libpcap depends on another shared library that may be installed "
		echo "in an unusual place."
		exit 1
	fi
fi


# gnuplot is mandatory if ROHC statistics is enabled
if test "x$enable_rohc_stats" = "xyes" ; then
	# check for the gnuplot binary and abort if it is not found
	AC_CHECK_PROG(is_gnuplot_found, gnuplot, "yes", "no")
	if test "x$is_gnuplot_found" != "xyes"; then
		echo
		echo "ERROR: gnuplot binary not found"
		echo
		echo "gnuplot is required in order to generate compression statistics."
		echo
		echo "Go get it from http://www.gnuplot.info/ or use your package manager "
		echo "to install it on your system."
		exit 1
	fi
fi


# check if RTP bit type is enabled
AC_ARG_ENABLE(rtp_bit_type,
              AS_HELP_STRING([--enable-rtp-bit-type],
                             [enable RTP bit type (use an additionnal bit \
                              to distinguish UOR-2-TS and UOR-2-ID packets) \
                              [[default=no]]]),
              enable_rtp_bit_type=$enableval,
              enable_rtp_bit_type=no)
if test "$enable_rtp_bit_type" = "yes"; then
	rtp_bit_type=1
else
	rtp_bit_type=0
fi
AC_DEFINE_UNQUOTED([RTP_BIT_TYPE], [$rtp_bit_type], [Whether RTP bit type is enabled or not.])


# check if API documentation should be generated (HTML format with doxygen)
AC_ARG_ENABLE(doc,
              AS_HELP_STRING([--enable-doc],
                             [generate API documentation in HTML format [default=no]]),
              [build_doc=$enableval],
              [build_doc=no])
AM_CONDITIONAL([BUILD_DOC], [test "x$build_doc" = "xyes"])


# doxygen and latex are mandatory if API documentation generation is enabled
if test "x$build_doc" = "xyes" ; then
	# check for the doxygen binary and abort if it is not found
	AC_CHECK_PROG(is_doxygen_found, doxygen, "yes", "no")
	if test "x$is_doxygen_found" != "xyes"; then
		echo
		echo "ERROR: doxygen binary not found"
		echo
		echo "doxygen is required in order to generate the library documentation."
		echo
		echo "Go get it from http://www.doxygen.org/ or use your package manager "
		echo "to install it on your system."
		exit 1
	fi

	# check for the latex binary and abort if it is not found
	AC_CHECK_PROG(is_latex_found, latex, "yes", "no")
	if test "x$is_latex_found" != "xyes"; then
		echo
		echo "ERROR: latex binary not found"
		echo
		echo "latex is required by doxygen in order to generate the library documentation."
		echo
		echo "Install your favorite latex distribution on your system either manually or "
		echo "using your package manager."
		exit 1
	fi

	# check for the dot binary and abort if it is not found
	AC_CHECK_PROG(is_dot_found, dot, "yes", "no")
	if test "x$is_dot_found" != "xyes"; then
		echo
		echo "ERROR: dot binary not found"
		echo
		echo "dot is required by doxygen in order to generate the library documentation."
		echo
		echo "dot is part of Graphviz, a set of tools for creating graphs."
		echo
		echo "Go get it from http://graphviz.org/ or use your package manager "
		echo "to install it on your system."
		exit 1
	fi
fi


# check if library examples should be generated
AC_ARG_ENABLE(examples,
              AS_HELP_STRING([--disable-examples],
                             [build example programs [default=no]]),
              [build_examples=$enableval],
              [build_examples=no])
AM_CONDITIONAL([BUILD_EXAMPLES], [test "x$build_examples" = "xyes"])


AM_DEP_TRACK

AC_CONFIG_FILES([ \
	Makefile \
	src/Makefile \
	src/common/Makefile \
	src/common/test/Makefile \
	src/comp/Makefile \
	src/decomp/Makefile \
	test/Makefile \
	test/functional/Makefile \
	test/functional/feedback2/Makefile \
	test/functional/decompress_feedback_only/Makefile \
	test/robustness/Makefile \
	test/robustness/empty_payload/Makefile \
	test/robustness/damaged_packet/Makefile \
	test/robustness/piggybacking_feedback/Makefile \
	test/non_regression/Makefile \
	test/performance/Makefile \
	statistics/Makefile \
	examples/Makefile \
	app/Makefile \
	app/tunnel/Makefile \
	doc/doxygen.conf \
	doc/Makefile \
	rohc.pc \
])

AC_OUTPUT
