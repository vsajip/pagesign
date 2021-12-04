from setuptools import setup

from pagesign import __version__ as version

setup(name = "pagesign",
    description="A wrapper for the modern encryption and signing tools age and minisign",
    long_description = """This module allows easy access to key \
management, encryption and signature functionality using age and minisign from \
Python programs. It is intended for use with Python 3.6 or greater.

Releases are normally signed using a GnuPG key with the user id \
vinay_sajip@yahoo.co.uk and the following fingerprint:

CA74 9061 914E AC13 8E66  EADB 9147 B477 339A 9B86

As PyPI no longer shows signatures, you should be able to download release archives \
and signatures from

https://bitbucket.org/vinay.sajip/pagesign/downloads/

The archives should be the same as those uploaded to PyPI.
""",
    license="""Copyright (C) 2021 by Vinay Sajip. All Rights Reserved. See LICENSE.txt for license.""",
    version=version,
    author="Vinay Sajip",
    author_email="vinay_sajip@yahoo.co.uk",
    maintainer="Vinay Sajip",
    maintainer_email="vinay_sajip@yahoo.co.uk",
    url="https://docs.red-dove.com/pagesign/",
    py_modules=["pagesign"],
    platforms="No particular restrictions",
    download_url="https://pypi.io/packages/source/p/pagesign/pagesign-%s.tar.gz" % version,
    classifiers=[
        'Development Status :: 4 - Beta',
        "Intended Audience :: Developers",
        'License :: OSI Approved :: BSD License',
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
