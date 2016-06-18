# How to install the ROHC library and its applications

# Requirements

The library itself does not require external resources. Optional configure
flags require external resources:

* `--enable-app-performance` requires:
  * `libpcap` library and headers
* `--enable-app-sniffer` requires:
  * `libpcap` library and headers
* `--enable-app-stats` requires:
  * `libpcap` library and headers
  * `gnuplot` binary
  * basic tools `grep`, `sed`, `awk`, `sort` and `tr`
* `--enable-linux-kernel-module` requires:
  * a Linux kernel
* `--enable-doc` requires:
  * `doxygen` binary
  * the `dot` binary from the `graphviz` project
* `--enable-doc-man` requires:
  * `--enable-doc` option
  * `doxy2man` binary
  * `help2man` binary
* `--enable-rohc-tests` requires:
  * `libpcap` library and headers
  * `cmocka` library and headers
  * basic tools `sed`
* `--enable-rohc-tests-valgrind` requires:
  * `--enable-rohc-tests` option
  * `valgrind` binary
  * `xsltproc` binary
  * basic tools `grep`


# Libraries and tools

Configure the libraries and tools:
```
$ ./configure --prefix=/path/to/installation/directory
```

Notes:
* Use `./autogen.sh` instead of `./configure` if you are building from the source
  repository
* Add option `--enable-examples` if you want to build the examples located in
  the `examples/` directory.

Build the libraries and tools:
```
$ make all
```

Install the libraries and tools:
```
$ make install
```

The libraries are now located in the `/path/to/installation/directory/lib`
directory, the header files in the `/path/to/installation/directory/include`
directory and the tools in the `/path/to/installation/directory/bin` directory.

In case of problem:
* check you got the last release of the library (see [README.md](README.md)),
* contact the mailing list (see [README.md](README.md)),
* check the bugtracker for known bugs (see [README.md](README.md)).


## Documentation

HTML documentation can be generated from the source code thanks to Doxygen:
```
$ ./configure --enable-doc
$ make -C doc/
```

Open the `./doc/html/index.html` file in your favorite web browser.


## Python binding

As of version 2.0.0, a Python binding was added. It is located in the
`contrib/python/` sub-directory.

The Python binding is not as CPU performant as the C library, so it is only
recommended for testing or rapid prototyping.

Install required system dependencies:
```
# yum install swig            # for RHEL/CentOS
# apt-get install swig        # for Debian/Ubuntu
# emerge -av swig             # for Gentoo
```

Install required Python dependencies:
```
# pip2 install future         # for Python 2
# pip3 install future         # for Python 3
```

Build the Python binding:
```
$ cd contrib/python/
$ python2 setup.py build      # for Python 2
$ python3 setup.py build      # for Python 3
```

Install the Python binding:
```
$ python2 setup.py install    # for Python 2
$ python3 setup.py install    # for Python 3
```

An example is provided in `contrib/python/example.py`. You may execute it to
test the Python binding (once it was installed on your system):
```
$ python3 ./contrib/python/example.py 10
create a stream of RTP packets
10 60-byte RTP packets created with 20-byte payload
create ROHC compressor
create ROHC decompressor
..........
all 10 packets were successfully compressed
232 bytes (39%) saved by compression`

You may also compute test coverage with:
$ cd contrib/python/
$ ./coverage 2.7             # for Python 2.7
$ ./coverage 3.4             # for Python 3.4
```
(install Python coverage module before)

You may also run the non-regression tests for the Python binding:
```
$ USE_PYTHON=2.7 make -C test/non_regression/ check    # for Python 2.7
$ USE_PYTHON=3.4 make -C test/non_regression/ check    # for Python 3.4
```


## Tests

The functional, robustness and non-regression tests may be run:
```
$ ./configure --enable-rohc-tests
$ make check
```

Add option `--enable-rohc-tests-valgrind` if you want to run tests within
valgrind.


## Developers

Developers may be interested in additional configure options:
* `--enable-fail-on-warning` causes the build to fail if a warning is emitted
  by the compiler (`-Werror`)
* `--enable-rohc-debug` enables library extra debug traces with performances
  impact
* `--enable-fortify-sources` enables some overflow protections (`-D_FORTIFY_SOURCE=2`)
* `--enable-code-coverage` compute code coverage

Developers may be interested in additional Makefile targets:
* `make distcheck` ensures that the library and tools may be released and packaged
  correctly
* `make cppcheck` runs `cppcheck` on the ROHC library and tools
* `make complexity` runs `GNU complexity` on the ROHC library and tools
* `make checkpatch` runs `checkpatch.pl` on the Linux kernel module
* `make qa` is a shortcut for `make cppcheck complexity checkpatch`

