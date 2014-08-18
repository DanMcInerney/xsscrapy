#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) Jean-Paul Calderone 2008-2014, All rights reserved
#

"""
Installation script for the OpenSSL module
"""

from setuptools import setup

# XXX Deduplicate this
__version__ = '0.14'

setup(name='pyOpenSSL', version=__version__,
      packages = ['OpenSSL'],
      package_dir = {'OpenSSL': 'OpenSSL'},
      py_modules  = ['OpenSSL.__init__',
                     'OpenSSL.tsafe',
                     'OpenSSL.rand',
                     'OpenSSL.crypto',
                     'OpenSSL.SSL',
                     'OpenSSL.version',
                     'OpenSSL.test.__init__',
                     'OpenSSL.test.util',
                     'OpenSSL.test.test_crypto',
                     'OpenSSL.test.test_rand',
                     'OpenSSL.test.test_ssl'],
      description = 'Python wrapper module around the OpenSSL library',
      author = 'Jean-Paul Calderone',
      author_email = 'exarkun@twistedmatrix.com',
      maintainer = 'Jean-Paul Calderone',
      maintainer_email = 'exarkun@twistedmatrix.com',
      url = 'https://github.com/pyca/pyopenssl',
      license = 'APL2',
      install_requires=["cryptography>=0.2.1", "six>=1.5.2"],
      long_description = """\
High-level wrapper around a subset of the OpenSSL library, includes
 * SSL.Connection objects, wrapping the methods of Python's portable
   sockets
 * Callbacks written in Python
 * Extensive error-handling mechanism, mirroring OpenSSL's error codes
...  and much more ;)""",
      classifiers = [
        'Development Status :: 6 - Mature',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        ],
      test_suite="OpenSSL")
