#!/bin/bash

# Process this file with autoconf to produce a configure script.
AC_INIT([ROHC library], [trunk], [http://rohc-lib.org/],
        [rohc], [http://rohc-lib.org/])
AC_CONFIG_SRCDIR([src])
AM_CONFIG_HEADER([config.h])

# Define library versioning:
#
# Option -version-info current:revision:age <-> libXXX.so.current.age.revision
#  - current  = the number of the current interface exported by the library.
#  - revision = the implementation number of the current interface exported
#               by this library.
#  - age      = the number of previous additional interfaces supported by this
#               library, ie. compatibility with previous versions.
#
# See http://sources.redhat.com/autobook/autobook/autobook_91.html for details.
#
# Basic rules are:
#  - library code modified:                               REVISION++
#  - interfaces changed/added/removed:  CURRENT++         REVISION=0
#  - interfaces added:                             AGE++
#  - interfaces removed:                           AGE=0
#
AC_SUBST([ROHC_API_CURRENT], 1)
AC_SUBST([ROHC_API_REVISION], 0)
AC_SUBST([ROHC_API_AGE], 1)

# Define a package homepage in a way compatible with autoconf < 2.64
m4_ifndef([AC_PACKAGE_URL],
          [AC_DEFINE([PACKAGE_URL], ["http://rohc-lib.org/";],
                     [Define to home page for this package])
           AC_SUBST([PACKAGE_URL], ["http://rohc-lib.org/";])])

# Init automake with:
#  - silent rules enabled to make 'make' less verbose, but do not call the
#    AM_SILENT_RULES macro if it is not defined to keep compatibility with
#    automake < 1.11 for the moment.
#  - color-tests to get nice colored results for tests (currently disabled
#    to keep compatibility with automake 1.10 for the moment.
#  - prefer bzip2 over gzip for dist tarballs
#  - tar-ustar to allow paths that exceeds 99 characters in the dist tarball
AM_INIT_AUTOMAKE([foreign no-dist-gzip dist-bzip2 tar-pax parallel-tests])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Init libtool:
#  - require >= 2.2.0,
#  - disable static libraries by default,
#  - ready for Windows DLL
LT_PREREQ([2.2.0])
LT_INIT([disable-static win32-dll])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADERS([stdio.h stdlib.h string.h strings.h])
AC_CHECK_HEADERS([time.h sys/time.h])
AC_CHECK_HEADERS([arpa/inet.h]) # ntohl, htonl, ntohs, htons on Linux
AC_CHECK_HEADERS([winsock2.h])  # ntohl, htonl, ntohs, htons on Windows
AC_CHECK_HEADERS([linux/if_tun.h]) # TUN/TAP support on Linux
AC_CHECK_HEADERS([sched.h]) # scheduling priority on Linux
AC_CHECK_HEADERS([sys/mman.h]) # memory management on Linux

# Handle library flags according to the platform
if test "x$ac_cv_header_winsock2_h" = "xyes" ; then
	# for windows platforms
	additional_platform_libs="-lws2_32"
else
	# other platforms
	additional_platform_libs=""
fi
AC_SUBST([additional_platform_libs], [$additional_platform_libs])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_BIGENDIAN
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = "xno" ; then
	echo
	echo "ERROR: your compiler cannot run in C99 mode"
	echo
	echo "Please use another compiler or tweak compiler options and try again."
	exit 1
fi

# Checks for library functions.
AC_CHECK_FUNCS([malloc calloc free memcpy memcmp])
AC_CHECK_FUNCS([ntohl htonl ntohs htons])

# If sched.h is present, check sched_setscheduler() availability & usage
if test "x$ac_cv_header_sched_h" = "xyes" ; then
	# Check if sched_setscheduler() is available without external library then with libpthread
	sched_lib=""
	AC_CHECK_FUNC([sched_setscheduler], ,
	              [AC_CHECK_LIB([pthread], sched_setscheduler, sched_lib="-lpthread",
	                            [AC_MSG_ERROR([sched.h header found, but sched_setscheduler not found])])])
	AC_SUBST([sched_lib], [$sched_lib])
	# Check whether sched_setscheduler() takes 2 or 3 arguments
	AC_MSG_CHECKING([how many arguments sched_setscheduler takes])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <sched.h>
	                                     #include <string.h>
	                                     struct sched_param param;]],
	                                   [[memset(&param, 0, sizeof(struct sched_param));
	                                     sched_setscheduler(0, SCHED_FIFO, &param);]])],
	                  [sched_setscheduler_params=3],
	                  [sched_setscheduler_params=2])
	AC_DEFINE_UNQUOTED([SCHED_SETSCHEDULER_PARAMS], [$sched_setscheduler_params],
	                   [Define the number of arguments that sched_setscheduler takes])
	AC_MSG_RESULT([$sched_setscheduler_params])
fi

# Define uint*_t and u_int*_t if not defined on target platform
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Special tweaks for mingw
AC_CANONICAL_HOST
if test "x$host_os" = "xmingw32" || \
   test "x$host_os" = "xmingw64" ; then
	# Avoid warnings about 'unknown conversion type character ‘z’ in format'
	CFLAGS="${CFLAGS} -D__USE_MINGW_ANSI_STDIO=1"
	if test "x$enable_shared" = "xyes" ; then
		LDFLAGS="${LDFLAGS} -no-undefined"
	fi
fi

# Check whether the compiler computes the bit-field lengths as expected
# (added because such a problem was detected with tinycc http://tinycc.org/)
AC_MSG_CHECKING([whether the compiler computes bit-field lengths as expected])
AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <stdint.h>
struct bitfield
{
	unsigned int foo:4;
	unsigned int bar:4;
	uint8_t other;
	uint16_t other2;
};]],
                               [[if(sizeof(struct bitfield) != 4) return 1;]])],
              [AC_MSG_RESULT([yes])],
              [AC_MSG_RESULT([no])
               AC_MSG_FAILURE([The compiler does not behave as expect for bit-field lengths, it would break the library])],
              [AC_MSG_RESULT([yes])])


# get extra debug traces
AC_ARG_ENABLE(rohc_debug,
              AS_HELP_STRING([--enable-rohc-debug],
                             [enable library extra debug traces with \
                              performances impact [[default=no]]]),
              [enable_rohc_debug=$enableval],
              [enable_rohc_debug=no])
if test "x$enable_rohc_debug" = "xyes" ; then
	rohc_extra_debug=1
elif test "x$enable_rohc_debug" = "xno" ; then
	rohc_extra_debug=0
else
	AC_MSG_ERROR([option --enable-rohc-debug does not take an integer value \
	              anymore, only 'yes' or 'no'])
fi
AC_DEFINE_UNQUOTED([ROHC_EXTRA_DEBUG], [$rohc_extra_debug],
                   [Extra debug traces for ROHC library])


# check if -Werror must be appended to CFLAGS
AC_ARG_ENABLE(fail_on_warning,
              AS_HELP_STRING([--enable-fail-on-warning],
                             [build fails on warnings if enabled [[default=no]]]),
              fail_on_warning=$enableval,
              fail_on_warning=no)
if test "x$fail_on_warning" != "xno"; then
	CFLAGS="${CFLAGS} -Werror"
fi


# check if -D_FORTIFY_SOURCE=2 must be appended to CFLAGS
AC_ARG_ENABLE(fortify_sources,
              AS_HELP_STRING([--enable-fortify-sources],
                             [build uses -D_FORTIFY_SOURCE=2 if enabled [[default=no]]]),
              fortify_sources=$enableval,
              fortify_sources=no)
if test "x$fortify_sources" != "xno"; then
	CFLAGS="${CFLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
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
tests_environment=""


# check if valgrind support in tests is enabled
AC_ARG_ENABLE(rohc_tests_valgrind,
              AS_HELP_STRING([--enable-rohc-tests-valgrind],
                             [enable valgrind support within tests [[default=no]]]),
              enable_rohc_tests_valgrind=$enableval,
              enable_rohc_tests_valgrind=no)
AM_CONDITIONAL([ROHC_TESTS_VALGRIND], [test x$enable_rohc_tests_valgrind = xyes])


# check if ROHC statistics application is enabled
AC_ARG_ENABLE(rohc_stats,
              AS_HELP_STRING([--enable-rohc-stats],
                             [enable ROHC statistics application [[default=no]]]),
              enable_rohc_stats=$enableval,
              enable_rohc_stats=no)
AM_CONDITIONAL([ROHC_STATS], [test x$enable_rohc_stats = xyes])


# check if ROHC applications (located in the app/ subdir) are enabled
AC_ARG_ENABLE(rohc_apps,
              AS_HELP_STRING([--enable-rohc-apps],
                             [enable ROHC applications found in the app/ subdir [[default=no]]]),
              enable_rohc_apps=$enableval,
              enable_rohc_apps=no)
if test "x$enable_rohc_apps" = "xyes" && \
   test "x$ac_cv_header_linux_if_tun_h" != "xyes" ; then
	echo
	echo "ERROR: --enable-rohc-apps cannot be enabled on non Linux platforms yet"
	echo
	echo "Please disable both the option and try again."
	exit 1
fi
AM_CONDITIONAL([ROHC_APPS], [test x$enable_rohc_apps = xyes])


# if ROHC tests or statistics are enabled:
#  - build but do not run tests/stats if cross-compiling except if an emulator
#    is available
#  - sed is mandatory
if test "x$enable_rohc_tests" = "xyes" || test "x$enable_rohc_stats" = "xyes"; then

	# cross-compiling is not fully compatible with tests and stats yet
	if test "x$cross_compiling" = "xyes" ; then

		# some cross-compiled binaries may be run:
		#  - mingw cross-compilation may run the tests/stats if wine is installed,
		#  - ARM cross-compilation may run the tests/stats if qemu-arm is installed
		#    and static libraries only are used,
		#  - PPC cross-compilation may run the tests/stats if qemu-ppc is installed
		#    and static libraries only are used.
		cross_compiling_emulator_name=""
		cross_compiling_emulator_cmd=""
		if test "x$host_os" = "xmingw32" || \
		   test "x$host_os" = "xmingw64" ; then
			AC_CHECK_PROG(is_wine_found, wine, "yes", "no")
			if test "x$is_wine_found" = "xyes"; then
				cross_compiling_emulator_name="wine"
				cross_compiling_emulator_cmd="wine"
			fi
		elif test "x$host_cpu" = "xarm" && \
		     test "x$enable_shared" != "xyes" && \
		     test "x$enable_static" = "xyes" ; then
			AC_CHECK_PROG(is_qemu_found, qemu-arm, "yes", "no")
			if test "x$is_qemu_found" = "xyes"; then
				cross_compiling_libgcc_file="`${CC} -print-libgcc-file-name`"
				cross_compiling_libgcc_dir="`dirname "${cross_compiling_libgcc_file}"`"
				cross_compiling_sysroot="`${CC} -print-sysroot`"
				cross_compiling_emulator_name="qemu-arm"
				cross_compiling_emulator_cmd="qemu-arm -B 1048576 \
				                              ${cross_compiling_sysroot}/lib/ld-linux.so.2 \
				                              --library-path ${cross_compiling_sysroot}/lib:${cross_compiling_sysroot}/usr/lib:${cross_compiling_libgcc_dir}"
			fi
		elif test "x$host_cpu" = "xpowerpc" && \
		     test "x$enable_shared" != "xyes" && \
		     test "x$enable_static" = "xyes" ; then
			AC_CHECK_PROG(is_qemu_found, qemu-ppc, "yes", "no")
			if test "x$is_qemu_found" = "xyes"; then
				cross_compiling_libgcc_file="`${CC} -print-libgcc-file-name`"
				cross_compiling_libgcc_dir="`dirname "${cross_compiling_libgcc_file}"`"
				cross_compiling_sysroot="`${CC} -print-sysroot`"
				cross_compiling_emulator_name="qemu-ppc"
				cross_compiling_emulator_cmd="qemu-ppc \
				                              ${cross_compiling_sysroot}/lib/ld.so.1 \
				                              --library-path ${cross_compiling_sysroot}/lib:${cross_compiling_sysroot}/usr/lib:${cross_compiling_libgcc_dir}"
			fi
		fi

		if test "x$cross_compiling_emulator_cmd" = "x" ; then
			echo
			echo "WARNING: --enable-rohc-tests and/or --enable-rohc-stats are enabled "
			echo "         and you are cross-compiling, binaries will be built but none "
			echo "         will be run."
			echo
		else
			echo
			echo "WARNING: --enable-rohc-tests and/or --enable-rohc-stats are enabled "
			echo "         and you are cross-compiling, binaries will be built and run "
			echo "         with the '$cross_compiling_emulator_name' emulator."
			echo
		fi

		tests_environment="${tests_environment} \
		                   CROSS_COMPILATION=yes \
		                   CROSS_COMPILATION_EXEEXT=$EXEEXT \
		                   CROSS_COMPILATION_EMULATOR=\"$cross_compiling_emulator_cmd\""
	fi

	# check for sed and abort if it is not found
	AC_PROG_SED
	if test "x$SED" = "x" ; then
		echo
		echo "ERROR: no sed implementation found"
		echo
		echo "sed is required in order to run tests."
		echo
		echo "Please install one of the sed tool."
		exit 1
	fi
	tests_environment="${tests_environment} SED=$SED"

	# check for awk and abort if it is not found
	AC_PROG_AWK
	if test "x$AWK" = "x" ; then
		echo
		echo "ERROR: no awk implementation found"
		echo
		echo "awk is required in order to generate compression statistics."
		echo
		echo "Please install one of the gawk, mawk, nawk, or awk tool."
		exit 1
	fi
	tests_environment="${tests_environment} AWK=$AWK"
fi


# if ROHC tests, statistics, or apps are enabled:
#  - libpcap is mandatory
if test "x$enable_rohc_tests" = "xyes" || \
   test "x$enable_rohc_stats" = "xyes" || \
   test "x$enable_rohc_apps" = "xyes" ; then

	# use winpcap for mingw, libpcap for other platforms
	if test "x$host_os" = "xmingw32" || \
	   test "x$host_os" = "xmingw64" ; then
		pcap_lib_name="wpcap"
		pcap_lib_pretty_name="WinPcap"
		pcap_lib_url="http://www.winpcap.org/"
	else
		pcap_lib_name="pcap"
		pcap_lib_pretty_name="libpcap"
		pcap_lib_url="http://www.tcpdump.org/"
	fi

	# check for libpcap header presence
	AC_CHECK_HEADERS([pcap.h pcap/pcap.h])

	# check for libpcap presence
	LPCAP=""
	AC_CHECK_LIB([$pcap_lib_name], pcap_open_offline, [ ], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_datalink, [ ], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_next, [ ], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_close, [ ], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_dump_open, [ ], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_dump, [ ], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_dump_close, [ ], LPCAP="no")

	# abort if libpcap is not found
	if test "x$LPCAP" = "xno"; then
		echo
		echo "ERROR: $pcap_lib_pretty_name library/headers not found"
		echo
		echo "Go get it from $pcap_lib_url or use the --with-libpcap-* "
		echo "options, if you have it installed in unusual place. Also check if "
		echo "it depends on another shared library that may be installed in an "
		echo "unusual place."
		exit 1
	fi

	AC_SUBST([pcap_lib_name], [$pcap_lib_name])
fi


# check requirements for valgrind support to tests
if test "x$enable_rohc_tests_valgrind" = "xyes" ; then

	# valgrind support for tests cannot be enabled if tests are not
	if test "x$enable_rohc_tests" = "xno" ; then
		echo
		echo "ERROR: valgrind support for tests enabled but tests are not"
		echo
		echo "Please add the --enable-rohc-tests or the --enable-rohc-tests-valgrind "
		echo "option to configure to solve the problem."
		exit 1
	fi

	# check for the valgrind binary and abort if it is not found
	AC_CHECK_PROG(is_valgrind_found, valgrind, "yes", "no")
	if test "x$is_valgrind_found" != "xyes" ; then
		echo
		echo "ERROR: valgrind binary not found"
		echo
		echo "Valgrind is required in order to check for memory leaks during tests."
		echo
		echo "Either disable the feature with the --disable-rohc-tests-valgrind, "
		echo "or install Valgrind to solve the problem. You may get Valgrind from "
		echo "http://www.valgrind.org/ or use your package manager to install it on "
		echo "your system."
		exit 1
	fi

	# check for the xsltproc binary and abort if it is not found
	AC_CHECK_PROG(is_xsltproc_found, xsltproc, "yes", "no")
	if test "x$is_xsltproc_found" != "xyes" ; then
		echo
		echo "ERROR: xsltproc binary not found"
		echo
		echo "xsltproc is required in order to analyze Valgrind memory leak reports "
		echo "during tests."
		echo
		echo "Either disable the feature with the --disable-rohc-tests-valgrind, "
		echo "or install xsltproc to solve the problem. xsltproc is often bundled "
		echo "with libxslt. You may get xsltproc from http://www.xmlsoft.org/ or "
		echo "use your package manager to install it on your system."
		exit 1
	fi
	tests_environment="${tests_environment} USE_VALGRIND=yes"

	# check for grep and abort if it is not found
	AC_PROG_GREP
	if test "x$GREP" = "x" ; then
		echo
		echo "ERROR: no grep implementation found"
		echo
		echo "grep is required in order to run tests within valgrind."
		echo
		echo "Please install one of the grep, or ggrep tool."
		exit 1
	fi
	tests_environment="${tests_environment} GREP=$GREP"
fi


# gnuplot, grep, sort, and tr are mandatory if ROHC statistics are enabled
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

	# check for grep and abort if it is not found
	AC_PROG_GREP
	if test "x$GREP" = "x" ; then
		echo
		echo "ERROR: no grep implementation found"
		echo
		echo "grep is required in order to generate compression statistics."
		echo
		echo "Please install one of the grep, or ggrep tool."
		exit 1
	fi
	tests_environment="${tests_environment} GREP=$GREP"

	# check for the sort binary and abort if it is not found
	AC_CHECK_PROG(is_sort_found, sort, "yes", "no")
	if test "x$is_sort_found" != "xyes"; then
		echo
		echo "ERROR: sort binary not found"
		echo
		echo "sort is required in order to generate compression statistics."
		echo
		echo "Go get it from http://www.gnu.org/software/coreutils/ or use your "
		echo "package manager to install it on your system."
		exit 1
	fi

	# check for the tr binary and abort if it is not found
	AC_CHECK_PROG(is_tr_found, tr, "yes", "no")
	if test "x$is_tr_found" != "xyes"; then
		echo
		echo "ERROR: tr binary not found"
		echo
		echo "tr is required in order to generate compression statistics."
		echo
		echo "Go get it from http://www.gnu.org/software/coreutils/ or use your "
		echo "package manager to install it on your system."
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


# export TESTS_ENVIRONMENT
AC_SUBST([TESTS_ENVIRONMENT], [$tests_environment])

AM_DEP_TRACK

AC_CONFIG_FILES([ \
	Makefile \
	src/Makefile \
	src/common/Makefile \
	src/common/protocols/Makefile \
	src/common/test/Makefile \
	src/comp/Makefile \
	src/decomp/Makefile \
	test/Makefile \
	test/functional/Makefile \
	test/functional/feedback2/Makefile \
	test/functional/decompress_feedback_only/Makefile \
	test/functional/context_reuse/Makefile \
	test/functional/rtp_uor2_disambiguation/Makefile \
	test/robustness/Makefile \
	test/robustness/empty_payload/Makefile \
	test/robustness/damaged_packet/Makefile \
	test/robustness/piggybacking_feedback/Makefile \
	test/non_regression/Makefile \
	statistics/Makefile \
	examples/Makefile \
	app/Makefile \
	app/performance/Makefile \
	app/tunnel/Makefile \
	doc/doxygen.conf \
	doc/Makefile \
	contrib/Makefile \
	rohc.pc \
])

AC_OUTPUT
