#!/usr/bin/env python
from ez_setup import use_setuptools
use_setuptools()

import os

from setuptools import setup, find_packages, Extension

VERSION = '1.1'
DESCRIPTION = "PyBloom: A Probabilistic data structure"
LONG_DESCRIPTION = """
pybloom is a Python implementation of the bloom filter probabilistic data
structure. The module also provides a Scalable Bloom Filter that allows a 
bloom filter to grow without knowing the original set size.
"""

CLASSIFIERS = filter(None, map(str.strip,
"""                 
Intended Audience :: Developers
License :: OSI Approved :: MIT License
Programming Language :: Python
Operating System :: OS Independent
Topic :: Utilities
Topic :: Database :: Database Engines/Servers
Topic :: Software Development :: Libraries :: Python Modules
""".splitlines()))

setup(
    name="pybloom",
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    classifiers=CLASSIFIERS,
    keywords=('data structures', 'bloom filter', 'bloom', 'filter',
              'probabilistic', 'set'),
    author="Jay Baird",
    author_email="jay.baird@me.com",
    url="http://github.com/jaybaird/python-bloomfilter/",
    license="MIT License",
    packages=find_packages(exclude=['ez_setup']),
    platforms=['any'],
    test_suite="pybloom.tests",
    zip_safe=True,
    install_requires=['bitarray>=0.3.4']
)
