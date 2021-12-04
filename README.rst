What is it?
===========

`age <https://age-encryption.org/>`_ and `minisign
<https://jedisct1.github.io/minisign/>`_ are modern command-line programs which
respectively provide support for encryption/decryption and signing/verification of
data. It is possible to provide programmatic access to their functionality by spawning
separate processes to run them and then communicating with those processes from your
program.

This project, ``pagesign``, implements a Python library which takes care
of the internal details and allows its users to generate and manage keys,
encrypt and decrypt data, and sign and verify messages using `age` and `minisign`.

Installation
============

Installing from PyPI
--------------------

You can install this package from the Python Package Index (pyPI) by running::

    pip install pagesign


Installing from a source distribution archive
---------------------------------------------
To install this package from a source distribution archive, do the following:

1. Extract all the files in the distribution archive to some directory on your
   system.
2. In that directory, run ``python setup.py install``.
3. Optionally, run ``python test_pagesign.py`` to ensure that the package is
   working as expected.

Credits
=======

* The developers of `age` and `minisign`.

Change log
==========

0.1.0
-----

Released: not yet.

* Initial release.
