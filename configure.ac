#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
#
# Process this file with autoconf to produce a configure script.
#
# Authors: Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#          Didier Barvaux <didier@barvaux.org>
#          Mikhail Gruzdev <michail.gruzdev@gmail.com>
#

AC_INIT([ROHC library], 2.0.0, [http://rohc-lib.org/],
        [rohc], [http://rohc-lib.org/])
AC_CONFIG_SRCDIR([src])
AM_CONFIG_HEADER([config.h])

# Retrieve the Bazaar revision number
if test -d "$srcdir/.bzr" ; then
	bzr="`which bzr`"
	if test $? -ne 0 ; then
		PACKAGE_REVNO="~unknown"
	else
		PACKAGE_REVNO="~`${bzr} revno`"
	fi
elif test -f "$srcdir/bzr_revno" ; then
	PACKAGE_REVNO="`cat $srcdir/bzr_revno`"
else
	PACKAGE_REVNO=""
fi
AC_SUBST(PACKAGE_REVNO)
AC_DEFINE_UNQUOTED([PACKAGE_REVNO], ["$PACKAGE_REVNO"],
                   [Bazaar revision number])

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
AC_SUBST([ROHC_API_CURRENT], 2)
AC_SUBST([ROHC_API_REVISION], 0)
AC_SUBST([ROHC_API_AGE], 2)

# Define a package homepage in a way compatible with autoconf < 2.64
m4_ifndef([AC_PACKAGE_URL],
          [AC_DEFINE([PACKAGE_URL], ["http://rohc-lib.org/"],
                     [Define to home page for this package])
           AC_SUBST([PACKAGE_URL], ["http://rohc-lib.org/"])])

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

# CFLAGS/LDFLAGS default values, more will be added on purpose
configure_cflags="-g -Wall -Wstrict-prototypes -Wextra -Wunreachable-code"
configure_cflags="${configure_cflags} -Wunused-function -Wunused-variable"
configure_cflags="${configure_cflags} -Wshadow"
configure_ldflags=""

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADERS([stdio.h stdlib.h string.h strings.h])
AC_CHECK_HEADERS([time.h sys/time.h])
AC_CHECK_HEADERS([arpa/inet.h]) # ntohl, htonl, ntohs, htons on Linux
AC_CHECK_HEADERS([winsock2.h])  # ntohl, htonl, ntohs, htons on Windows
AC_CHECK_HEADERS([sys/types.h]) # ntohl, htonl, ntohs, htons on OpenBSD

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

# Define uint*_t and u_int*_t if not defined on target platform
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Special tweaks for mingw
AC_CANONICAL_HOST
if test "x$host_os" = "xmingw32" || \
   test "x$host_os" = "xmingw64" ; then
	# Avoid warnings about 'unknown conversion type character ‘z’ in format'
	configure_cflags="${configure_cflags} -D__USE_MINGW_ANSI_STDIO=1"
	# Tell mingw to pack structs and bitfields the way gcc does
	configure_cflags="${configure_cflags} -mno-ms-bitfields"
	# Enable dead code on mingw64 to avoid warnings
	configure_cflags="${configure_cflags} -DENABLE_DEAD_CODE"
	if test "x$enable_shared" = "xyes" ; then
		configure_ldflags="${configure_ldflags} -Wl,--no-undefined"
	fi
fi


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
	configure_cflags="${configure_cflags} -Werror"
fi


# check if -D_FORTIFY_SOURCE=2 must be appended to CFLAGS
AC_ARG_ENABLE(fortify_sources,
              AS_HELP_STRING([--enable-fortify-sources],
                             [build uses -D_FORTIFY_SOURCE=2 if enabled [[default=no]]]),
              fortify_sources=$enableval,
              fortify_sources=no)
if test "x$fortify_sources" != "xno"; then
	configure_cflags="${configure_cflags} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
fi


# check if code coverage must be enabled
AC_ARG_ENABLE(code_coverage,
              AS_HELP_STRING([--enable-code-coverage],
                             [enable code coverage if enabled [[default=no]]]),
              code_coverage=$enableval,
              code_coverage=no)
if test "x$code_coverage" != "xno"; then
	configure_cflags="${configure_cflags} -fprofile-arcs -ftest-coverage"

	# check for the zcov-scan and zcov-genhtml binaries
	# and abort if they are not found
	AC_CHECK_PROG(is_zcov_scan_found, zcov-scan, "yes", "no")
	AC_CHECK_PROG(is_zcov_genhtml_found, zcov-genthml, "yes", "no")
	if test "x$is_zcov_scan_found" != "xyes" || \
	   test "x$is_zcov_scan_found" != "xyes" ; then
		echo
		if test "x$is_zcov_scan_found" != "xyes" ; then
			echo "ERROR: zcov-scan binary not found"
		fi
		if test "x$is_zcov_genhtml_found" != "xyes" ; then
			echo "ERROR: zcov-genhtml binary not found"
		fi
		echo
		echo "zcov is required in order to report code coverage."
		echo
		echo "Either disable the feature with the --disable-code-coverage option, "
		echo "or install zcov to solve the problem. You may get Zcov from "
		echo "http://minormatter.com/zcov/ or use your package manager to install "
		echo "it on your system."
		exit 1
	fi
fi
AM_CONDITIONAL([CODE_COVERAGE], [test x$code_coverage = xyes])


# check if deprecated code shall be enabled
AC_ARG_ENABLE(deprecated_api,
              AS_HELP_STRING([--disable-deprecated-api],
                             [build deprecated API if enabled [[default=yes]]]),
              enable_deprecated_api=$enableval,
              enable_deprecated_api=yes)
if test "x$enable_deprecated_api" != "xyes"; then
	echo
	echo "WARNING: you disabled the deprecated API, it means that the API/ABI"
	echo "         compatibility of the ROHC library is broken; are you sure "
	echo "         to do so?"
	echo
	sleep 5
	deprecated_api=0
	configure_cflags="${configure_cflags} -DROHC_ENABLE_DEPRECATED_API=0"
else
	configure_cflags="${configure_cflags} -DROHC_ENABLE_DEPRECATED_API=1"
	deprecated_api=1
fi
AC_DEFINE_UNQUOTED([ROHC_ENABLE_DEPRECATED_API], [$deprecated_api],
                   [Whether deprecated API is enabled or not.])


# allow users to specify a special location for libpcap includes
AC_ARG_WITH(libpcap_includes,
            AS_HELP_STRING([--with-libpcap-includes=DIR],
                           [libpcap include directory]),
            [with_libpcap_includes="$withval"],
            [with_libpcap_includes="no"])
if test "x$with_libpcap_includes" != "xno"; then
	libpcap_includes="-I${with_libpcap_includes}"
fi


# allow users to specify a special location for libpcap libraries
AC_ARG_WITH(libpcap_libraries,
            AS_HELP_STRING([--with-libpcap-libraries=DIR],
                           [libpcap library directory]),
            [with_libpcap_libraries="$withval"],
            [with_libpcap_libraries="no"])
if test "x$with_libpcap_libraries" != "xno"; then
	configure_ldflags="${configure_ldflags}  -L${with_libpcap_libraries}"
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


# abort is --enable-rohc-apps is used as it is deprecated
AC_ARG_ENABLE(rohc_apps,
              AS_HELP_STRING([--enable-rohc-apps],
                             [enable ROHC applications found in the app/ subdir [[default=no]]]),
                             enable_rohc_apps=$enableval,
                             enable_rohc_apps="undefined")
if test "x$enable_rohc_apps" != "xundefined" ; then
	echo
	echo "ERROR: --enable-rohc-apps and --disable-rohc-apps are "
	echo "       deprecated, do not use them any more."
	echo
	echo "Please use a combination of the following options instead:"
	echo "  --enable-app-fuzzer / --disable-app-fuzzer"
	echo "  --enable-app-performance / --disable-app-performance"
	echo "  --enable-app-sniffer / --disable-app-sniffer"
	echo "  --enable-app-stats / --disable-app-stats"
	echo
	exit 1
fi


# check if ROHC fuzzer (located in the app/fuzzer/ subdir) is enabled
AC_ARG_ENABLE(app_fuzzer,
              AS_HELP_STRING([--enable-app-fuzzer],
                             [enable ROHC fuzzer tool [default=no]]),
              enable_app_fuzzer=$enableval,
              enable_app_fuzzer=no)
AM_CONDITIONAL([APP_FUZZER], [test x$enable_app_fuzzer = xyes])


# check if ROHC performance tool (located in the app/performance/ subdir)
# is enabled
AC_ARG_ENABLE(app_performance,
              AS_HELP_STRING([--enable-app-performance],
                             [enable ROHC performance tool [default=no]]),
              enable_app_perf=$enableval,
              enable_app_perf=no)
AM_CONDITIONAL([APP_PERF], [test x$enable_app_perf = xyes])


# check if ROHC sniffer tool (located in the app/sniffer/ subdir)
# is enabled
AC_ARG_ENABLE(app_sniffer,
              AS_HELP_STRING([--enable-app-sniffer],
                             [enable ROHC sniffer tool [default=no]]),
              enable_app_sniffer=$enableval,
              enable_app_sniffer=no)
AM_CONDITIONAL([APP_SNIFFER], [test x$enable_app_sniffer = xyes])


# check if ROHC stats tool (located in the app/stats/ subdir)
# is enabled
AC_ARG_ENABLE(app_stats,
              AS_HELP_STRING([--enable-app-stats],
                             [enable ROHC stats [default=no]]),
              enable_app_stats=$enableval,
              enable_app_stats=no)
AM_CONDITIONAL([APP_STATS], [test x$enable_app_stats = xyes])


# if ROHC tests are enabled:
#  - build but do not run tests if cross-compiling except if an emulator
#    is available
#  - sed is mandatory
if test "x$enable_rohc_tests" = "xyes" ; then

	# cross-compiling is not fully compatible with tests yet
	if test "x$cross_compiling" = "xyes" ; then

		# some cross-compiled binaries may be run:
		#  - mingw cross-compilation may run the tests if wine is installed,
		#  - ARM cross-compilation may run the tests if qemu-arm is installed
		#    and static libraries only are used,
		#  - PPC cross-compilation may run the tests if qemu-ppc is installed
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
			echo "WARNING: --enable-rohc-tests is enabled and you are cross-compiling, "
			echo "         binaries will be built but none will be run."
			echo
		else
			echo
			echo "WARNING: --enable-rohc-tests is enabled and you are cross-compiling, "
			echo "         binaries will be built and run with the '$cross_compiling_emulator_name' emulator."
			echo
		fi

		tests_environment="${tests_environment} \
		                   DISPLAY= \
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


# if ROHC tests or apps are enabled: libpcap is mandatory
if test "x$enable_rohc_tests" = "xyes" || \
   test "x$enable_app_perf" = "xyes" || \
   test "x$enable_app_sniffer" = "xyes" || \
   test "x$enable_app_stats" = "xyes" ; then

	# use winpcap for mingw and cygwin, libpcap for other platforms
	if test "x$host_os" = "xmingw32" || \
	   test "x$host_os" = "xmingw64" || \
	   test "x$host_os" = "xcygwin" ; then
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
	if test "x$ac_cv_header_pcap_h" != "xyes" &&
	   test "x$ac_cv_header_pcap_pcap_h" != "xyes" ; then
		IPCAP="no"
	else
		IPCAP="yes"
	fi

	# check for libpcap presence
	LPCAP="yes"
	AC_CHECK_LIB([$pcap_lib_name], pcap_open_offline, [unused=1], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_datalink, [unused=1], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_next, [unused=1], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_close, [unused=1], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_dump_open, [unused=1], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_dump, [unused=1], LPCAP="no")
	AC_CHECK_LIB([$pcap_lib_name], pcap_dump_close, [unused=1], LPCAP="no")

	# abort if libpcap is not found
	if test "x$IPCAP" != "xyes" ||
	   test "x$LPCAP" != "xyes"; then
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

	# check for DLT_LINUX_SLL symbol
	AC_MSG_CHECKING([whether DLT_LINUX_SLL is defined by libpcap headers])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#if HAVE_PCAP_PCAP_H == 1
	                                     #  include <pcap/pcap.h>
	                                     #elif HAVE_PCAP_H == 1
	                                     #  include <pcap.h>
	                                     #else
	                                     #  error "pcap.h header not found"
	                                     #endif
	                                     int dlt;]],
	                                   [[dlt = DLT_LINUX_SLL;]])],
	                  [dlt_linux_sll_defined="yes"],
	                  [dlt_linux_sll_defined="no"])
	AC_MSG_RESULT([$dlt_linux_sll_defined])
	if test "x$dlt_linux_sll_defined" != "xyes" ; then
		AC_DEFINE([DLT_LINUX_SLL], [113],
		          [Define DLT_LINUX_SLL if not defined by the system])
	fi
fi


# if ROHC tests are enabled: libcmocka is mandatory
if test "x$enable_rohc_tests" = "xyes" ; then

	PKG_CHECK_MODULES([CMOCKA], [cmocka >= 0.3.1],
	                  [cmocka_found="yes"], [cmocka_found="no"])
	if test "x$cmocka_found" != "xyes" ; then
		echo
		echo "ERROR: cmocka library/headers not found"
		echo
		echo "Go get it from http://www.cmocka.org/ or use the CMOCKA_* "
		echo "variables, if you have it installed in unusual place. Also check if "
		echo "it depends on another shared library that may be installed in an "
		echo "unusual place."
		exit 1
	fi
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

	# check whether --show-possibly-lost option is supported
	AC_MSG_CHECKING([whether valgrind supports option --show-possibly-lost])
	valgrind --help | $GREP -q -- '--show-possibly-lost'
	if test $? -eq 0 ; then
		valgrind_opt_show_possibly_lost=yes
	else
		valgrind_opt_show_possibly_lost=no
	fi
	AC_MSG_RESULT([$valgrind_opt_show_possibly_lost])
	if test "x$valgrind_opt_show_possibly_lost" == "xyes" ; then
		tests_environment="${tests_environment} VALGRIND_OPTS=\"--show-possibly-lost=yes\""
	else
		tests_environment="${tests_environment} VALGRIND_OPTS=\"\""
	fi
fi


# gnuplot, grep, sort, and tr are mandatory if ROHC statistics are enabled
if test "x$enable_app_stats" = "xyes" ; then

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


# check if Linux kernel module is enabled
AC_ARG_ENABLE(linux_kernel_module,
              AS_HELP_STRING([--enable-linux-kernel-module],
                             [build Linux kernel module [[default=no]]]),
              [enable_linux_kmod=$enableval],
              [enable_linux_kmod=no])
AM_CONDITIONAL([ROHC_LINUX_MODULE], [test "x$enable_linux_kmod" = "xyes"])

# allow users to specify kernel soure directory
AC_ARG_WITH(linux_kernel_src,
            AS_HELP_STRING([--with-linux-kernel-src=DIR],
                           [Linux kernel sources directory]),
            [linux_kernel_src="$withval"],
            [linux_kernel_src="no"])

AC_MSG_CHECKING([whether the Linux kernel module shall be built])
if test "x$enable_linux_kmod" != "xyes" ; then
	AC_MSG_RESULT([no])
else
	AC_MSG_RESULT([yes])

	# stop now if building for Windows
	if test "x$host_os" = "xmingw32" || \
	   test "x$host_os" = "xmingw64" || \
	   test "x$host_os" = "xcygwin" ; then
		AC_MSG_ERROR([The Linux kernel cannot be built when compiling
		              for the Windows platform])
	fi

	# get path for running kernel if none was specified manually
	if test "x$linux_kernel_src" = "xno" ; then
		AC_MSG_CHECKING([current Linux kernel version])
		runver=$( uname -r )
		AC_MSG_RESULT([$runver])
		linux_kernel_src=/lib/modules/${runver}/build
	fi

	AC_MSG_CHECKING([Linux kernel source directory])
	if test -z "$linux_kernel_src" ; then
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([Linux kernel source not found. Specify the location of the \
		              kernel source with the --with-linux-kernel-src=DIR option])
	fi
	AC_MSG_RESULT([$linux_kernel_src])

	AC_MSG_CHECKING([Linux kernel source usability])
	if test ! -e "$linux_kernel_src" ; then
		kernel_src_ok="no"
	elif test -L "$linux_kernel_src" && \
	     test -z $( readlink "$linux_kernel_src" ) ; then
		kernel_src_ok="no"
	else
		kernel_src_ok="yes"
	fi
	if test "x$kernel_src_ok" != "xyes" ; then
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Linux kernel source cannot be used. Specify the location of the \
		              kernel source with the --with-linux-kernel-src=DIR option])
	fi
	AC_MSG_RESULT([yes])
	AC_SUBST(linux_kernel_src)
fi


# check if RTP bit type is enabled
AC_ARG_ENABLE(rtp_bit_type,
              AS_HELP_STRING([--enable-rtp-bit-type],
                             [enable RTP bit type (use an additionnal bit \
                              to distinguish UOR-2-TS and UOR-2-ID packets) \
                              [deprecated]]),
              enable_rtp_bit_type=$enableval,
              enable_rtp_bit_type=no)
if test "$enable_rtp_bit_type" = "yes"; then
	echo
	echo "The RTP bit type was not part of any RFC standard. It was also a "
	echo "maintenance burden. It was therefore removed from the ROHC library. "
	echo
	echo "Please remove the --enable-rtp-bit-type option from the ./autogen.sh "
	echo "or ./configure command to continue."
	echo
	exit 1
fi


# check if API documentation should be generated (HTML format with doxygen)
AC_ARG_ENABLE(doc,
              AS_HELP_STRING([--enable-doc],
                             [generate API documentation in HTML format [default=no]]),
              [build_doc=$enableval],
              [build_doc=no])
AM_CONDITIONAL([BUILD_DOC], [test "x$build_doc" = "xyes"])

# check if API documentation should be generated (man format with doxygen
# and a modified version of doxy2man)
AC_ARG_ENABLE(doc-man,
				  AS_HELP_STRING([--enable-doc-man],
                             [generate API documentation in man format [default=no]]),
              [build_doc_man=$enableval],
              [build_doc_man=no])
AM_CONDITIONAL([BUILD_DOC_MAN], [test "x$build_doc_man" = "xyes"])


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
# if man pages need to be generated, same requirement as HTML pages in addition
# to doxy2man
if test "x$build_doc_man" = "xyes" ; then
	if test "x$build_doc" != "xyes" ; then
		echo
		echo "ERROR: --enable-doc-man requires --enable-doc"
		echo
		echo "Add --enable-doc to your configure options or remove --enable-doc-man "
		echo "from your configure options."
		exit 1
	fi

	# check for the doxy2man binary and abort if it is not found
	AC_CHECK_PROG(is_doxy2man_found, doxy2man, "yes", "no")
	if test "x$is_doxy2man_found" != "xyes"; then
		echo
		echo "ERROR: doxy2man binary not found"
		echo
		echo "doxy2man is required in order to generate the man pages for the"
		echo "library documentation."
		exit 1
	fi

	# check for the help2man binary and abort if it is not found
	AC_CHECK_PROG(is_help2man_found, help2man, "yes", "no")
	if test "x$is_help2man_found" != "xyes"; then
		echo
		echo "ERROR: help2man binary not found"
		echo
		echo "help2man is required in order to generate the man pages for the "
		echo "documentation of library's tools."
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


# export TESTS_ENVIRONMENT, configure_cflags, and configure_ldflags
AC_SUBST([TESTS_ENVIRONMENT], [$tests_environment])
AC_SUBST([libpcap_includes], [$libpcap_includes])
AC_SUBST([configure_cflags], [$configure_cflags])
AC_SUBST([configure_ldflags], [$configure_ldflags])

AM_DEP_TRACK

AC_CONFIG_FILES([ \
	Makefile \
	bzr_revno \
	src/Makefile \
	src/test/Makefile \
	src/common/Makefile \
	src/common/protocols/Makefile \
	src/comp/Makefile \
	src/comp/test/Makefile \
	src/comp/schemes/Makefile \
	src/comp/schemes/test/Makefile \
	src/decomp/Makefile \
	src/decomp/test/Makefile \
	src/decomp/schemes/Makefile \
	src/decomp/schemes/test/Makefile \
	test/Makefile \
	test/functional/Makefile \
	test/functional/feedback2/Makefile \
	test/functional/decompress_padding/Makefile \
	test/functional/decompress_feedback_only/Makefile \
	test/functional/context_reuse/Makefile \
	test/functional/rtp_uo_disambiguation/Makefile \
	test/functional/rtp_detection/Makefile \
	test/functional/segment/Makefile \
	test/robustness/Makefile \
	test/robustness/empty_payload/Makefile \
	test/robustness/damaged_packet/Makefile \
	test/robustness/lost_packet/Makefile \
	test/robustness/piggybacking_feedback/Makefile \
	test/robustness/malformed_rohc_packets/Makefile \
	test/non_regression/Makefile \
	test/interop/Makefile \
	examples/Makefile \
	linux/Makefile \
	app/Makefile \
	app/performance/Makefile \
	app/sniffer/Makefile \
	app/fuzzer/Makefile \
	app/stats/Makefile \
	doc/Makefile \
	doc/doxygen.conf \
	doc/rohc.7 \
	doc/rohc_protocol.7 \
	doc/rohc_library.7 \
	contrib/Makefile \
	contrib/rohc.spec \
	rohc.pc \
])

AC_OUTPUT
