#!/usr/bin/env python
#
# Copyright 2015 Didier Barvaux
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
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

"""
Build the python binding for the ROHC library
"""

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension


rohc_inc_dirs = ['../../src/common',
                 '../../src/comp',
                 '../../src/decomp']
swig_opts = ['-I' + rohc_inc_dir for rohc_inc_dir in rohc_inc_dirs]

rohc_module = Extension('_rohc',
                        sources=['rohc.i'],
                        include_dirs=rohc_inc_dirs,
                        swig_opts=swig_opts,
                        libraries=['rohc'],
                        library_dirs=['../../src/.libs'],
                        )

setup(name             = 'rohc',
      version          = '0.1',
      author           = 'Didier Barvaux',
      author_email     = '<didier@barvaux.org>',
      description      = """Python binding for the ROHC library""",
      license          = 'LGPL version 2.1 or later',
      url              = 'http://rohc-lib.org/',
      ext_modules      = [rohc_module],
      py_modules       = ['rohc', 'RohcCompressor', 'RohcDecompressor'],
#      install_requires = ['scapy'],
      classifiers      = [
          'Topic :: System :: Networking',
          'Topic :: Software Development :: Libraries',
          'Intended Audience :: Telecommunications Industry',
          'Intended Audience :: Developers',
          'Development Status :: 4 - Beta',
          'License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)',
          'Programming Language :: Python :: 2.7'
      ]
)

