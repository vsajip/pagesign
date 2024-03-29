.. Age/Minisign Wrapper for Python documentation master file.

######################################################
`pagesign` - A Python wrapper for `age` and `minisign`
######################################################

.. rst-class:: release-info

   .. list-table::
      :widths: auto
      :stub-columns: 1

      * - Release:
        - |release|
      * - Date:
        - |today|

.. |--| unicode:: U+2013

.. module:: pagesign
   :synopsis: A Python wrapper for age and minisign

.. moduleauthor:: Vinay Sajip <vinay_sajip@red-dove.com>
.. sectionauthor:: Vinay Sajip <vinay_sajip@red-dove.com>


The ``pagesign`` (for 'Python-age-sign') module allows Python programs to make use of
the functionality provided by the modern cryptography tools `age
<https://age-encryption.org/>`_ and `minisign
<https://jedisct1.github.io/minisign/>`_. Using this module, Python programs can
encrypt and decrypt data, digitally sign documents, verify digital signatures,
and manage (generate, list and delete) encryption and signing keys.

This module is expected to be used with Python versions >= 3.6. Install this module
using ``pip install pagesign``. You can then use this module in your own code by
doing ``import pagesign`` or similar.

.. index:: Deployment

.. _deployment:

Deployment Requirements
=======================

Apart from a recent-enough version of Python, in order to use this module you need to
have access to a compatible versions of `age-keygen`, `age` and `minisign` executables.
The system has been tested with `age` later than v1.0.0 and `minisign` later than v0.8 on
Windows, macOS and Ubuntu. You can see test runs (which show the versions of `age` and
`minisign` used) `here <https://github.com/vsajip/pagesign/actions>`__.

.. index:: Acknowledgements

Acknowledgements
================

The ``pagesign`` module follows a similar approach to `python-gnupg
<https://docs.red-dove.com/python-gnupg/>`_ (by the same author), and uses Python's
``subprocess`` module to communicate with the `age-keygen`, `age` and `minisign`
executables, which it uses to spawn subprocesses to do the real work of key creation,
encryption, decryption, signing and verification.

Of course this module wouldn't exist without the great work by the `age` and `minisign`
developers.

Installation
============

Installing from PyPI
--------------------

You can install this package from the Python Package Index (PyPI) by running::

    pip install pagesign


Installing from a source distribution archive
---------------------------------------------
To install this package from a source distribution archive, do the following:

1. Extract all the files in the distribution archive to some directory on your
   system.
2. In that directory, run ``pip install .``, referencing a suitable ``pip`` (e.g. one
   from a specific venv which you want to install to).
3. Optionally, run ``python test_pagesign.py`` to ensure that the package is
   working as expected.

Installing ``age``
------------------

You can get binary releases of the latest version of ``age`` for Linux, macOS and
Windows from `here <https://github.com/FiloSottile/age/releases>`__. Alternatively,
you might be able to use package managers such as your distro package manager (Linux),
`MacPorts <https://ports.macports.org/port/age/>`__ or `Homebrew
<https://formulae.brew.sh/formula/age>`__ (macOS) or `Chocolatey
<https://community.chocolatey.org/packages/age.portable>`__ (Windows).

Installing ``minisign``
-----------------------

You can get binary releases of the latest version of ``minisign`` for Linux, macOS and
Windows from `here <https://jedisct1.github.io/minisign/>`__. Alternatively, you might
be able to use package managers such as your distro package manager (Linux), `MacPorts
<https://ports.macports.org/port/minisign/>`__ or `Homebrew
<https://formulae.brew.sh/formula/minisign>`__ (macOS) or `Chocolatey
<https://community.chocolatey.org/packages/minisign>`__ (Windows).


Before you Start
================

`pagesign` works on the basis of a "home directory" which is used to store public and
secret key data. (Whereas `age` and `minisign` will save created keys in files for
you, but nothing beyond that, `pagesign` will allow you to refer to `identities` using
simple names). The directory on POSIX systems is `~/.pagesign` and on Windows is
`%LOCALAPPDATA%\\pagesign`. If this directory doesn't exist, it is created. On POSIX,
its permissions are set so only the owner has full access, and everyone else has no
access (permission mask of octal 0700).

This directory will contain an identity store (called `keystore` from now on, as it
mainly holds keys). On POSIX, its permissions are set so only the owner has full
access, and everyone else has no access (permission mask of octal 0600).

Although identity names could be email addresses (as used with GnuPG, for example) but
they could equally be things like `'project-X-signing'` or similar, reflecting
their function rather than a person or organisation. However, keys that are exported
for sharing and then imported should be saved with a name that indicates unambiguously
what they are / where they're from.

.. index:: Getting started

Getting Started
===============

You interface to the `age` and `minisign` functionality through the following items in
the `pagesign` module:

* The :class:`~pagesign.Identity` class.

* The :func:`~pagesign.encrypt`, :func:`~pagesign.decrypt`, :func:`~pagesign.sign` and
  :func:`~pagesign.verify` functions. (There are other functions you can use,
  but those are the main ones.)

Identity Management
===================

The :class:`~pagesign.Identity` class represents an identity, which can either be a local identity
(which has access to secret keys and passphrases in order to decrypt and sign things)
or a remote identity (which only has public keys, so it can only be used to encrypt and
verify things).

A remote identity consists of:

* A string indicating the creation time of the identity in `YYYY-mm-ddTHH:MM:SSZ`
  format.
* A public key (from `age`) for encrypting files.
* A public key (from `minisign`) for verifying file signatures.
* A signature ID (from `minisign`) |--| this is not currently used.

A local identity, in addition to the above, contains:

* A secret key (from `age`) for decrypting files.
* A secret key (from `minisign`) for signing files.
* A passphrase (created automatically by `pagesign` and used for signing). This is
  needed to use `minisign`'s secret key.

These are stored in attributes of an :class:`~pagesign.Identity` instance named `created`,
`crypt_public`, `sign_public`, `sign_id`, `crypt_secret`, `sign_secret` and
`sign_pass`. Creation of a local identity generates four keys |--| two secret and two
public, two for encryption/decryption and two for signing/verification. The following
table illustrates what they're for.

.. cssclass:: generic-table table-bordered table-striped table-responsive-sm colwidths-auto mx-auto

+---------------------------------+----------------------+
| Attribute                       | Used for ...         |
+=================================+======================+
| `crypt_public` (from `age`)     | Encrypting data      |
+---------------------------------+----------------------+
| `crypt_secret` (from `age`)     | Decrypting data      |
+---------------------------------+----------------------+
| `sign_public` (from `minisign`) | Verifying signatures |
+---------------------------------+----------------------+
| `sign_secret` (from `minisign`) | Signing data         |
+---------------------------------+----------------------+

.. raw:: html

    <style>
    .generic-table th, .generic-table td {
      padding: 2px 0.5em;
    }
    .generic-table th {
      background-color: rgb(224, 224, 224);
    }
    </style>

Generating identities
---------------------

To create a new local identity, you simply call

.. code-block:: python

    from pagesign import Identity
    identity = Identity()

Once you've called this, the identity is in memory, but not saved anywhere. To save it,
you call its `save()` method with a name |--| just a string you choose. It could be a
simple identifier like `alice` or `bob`, or an email address.

.. code-block:: python

    identity.save('bob')

This saves the identity under the name `bob`. To get it back at a later time, pass it
to the `Identity` constructor:

.. code-block:: python

    bob = Identity('bob')

The `save()` method saves the local identity in a keystore which is stored in the
`pagesign` home directory mentioned earlier. Passing that name to the constructor just
retrieves it from the store. If you pass a name that's not in the keystore, you will
get an error.

The keystore is currently just a plaintext file in JSON format. It relies on directory
and file permissions for keeping your secret keys secret.

.. index::
    single: Key; performance issues
    single: Entropy

Performance Issues
------------------

Key generation requires the system to work with a source of random numbers. Systems
which are better at generating random numbers than others are said to have higher
*entropy*. This is typically obtained from the system hardware; keys should usually be
generated *only* on a local machine (i.e. not one being accessed across a network),
and that keyboard, mouse and disk activity be maximised during key generation to
increase the entropy of the system.

Unfortunately, there are some scenarios |--| for example, on virtual machines which
don't have real hardware - where insufficient entropy can cause key generation to be
slow. If you come across this problem, you should investigate means of increasing the
system entropy. On virtualised Linux systems, this can often be achieved by installing
the ``rng-tools`` package. This is available at least on RPM-based and APT-based
systems (Red Hat/Fedora, Debian, Ubuntu and derivative distributions).


.. index:: Key; exporting

Exporting identities
--------------------

You can export the public parts of an identity to send to someone. To do this, you call
the :meth:`~pagesign.Identity.export` method of an instance:

.. code-block:: python

    exported = identity.export()

This returns a dictionary which contains the public attributes of the identity, whose
keys are the attribute names mentioned earlier.

Importing identities
--------------------

If you receive a dictionary representing an exported identity from someone, you
can import it into your local keystore by calling the class method
:meth:`~pagesign.Identity.imported`:

.. code-block:: python

    alice = Identity.imported(sent_by_alice, 'alice')

This saves the remote identity in the keystore with the given name. You (`bob`, say)
can use this when exchanging information with `alice`.

Deleting identities
-------------------

If you want to completely get rid of an identity, you can call the
:func:`~pagesign.remove_identities` function. To remove all identities from the
keystore, the :func:`~pagesign.clear_identities()` function is used.

.. code-block:: python

    from pagesign import remove_identities, clear_identities

    remove_identities('bob', 'alice')  # removes just these two
    clear_identities()  # removes everything

There is no way to undo these operations, so be careful!

.. index:: Key; listing

Listing identities
------------------

Now that we've seen how to create, import and export identities, let's move on to
finding which identities we have in our keystore. This is fairly straightforward
using :func:`~pagesign.list_identities`:

.. code-block:: python

    from pagesign import list_identities

    identities = list_identities()

This returns an iterable of `(name, info)` tuples in random order. The `name` is the
identity name, and the `info` is a dictionary of all the identity attributes for that
identity.

The `Identity` class
--------------------

The `Identity` class API is here:

.. class:: Identity

   .. cssclass:: class-members-heading

   Attributes

   .. attribute:: Identity.created : str

      This attribute is a string indicating when the identity was created.

   .. attribute:: Identity.crypt_public : str

      This attribute is the public key used for encryption.

   .. attribute:: Identity.sign_public : str

      This attribute is the public key used for signature verification.

   .. attribute:: Identity.sign_id : str

      This attribute is a key ID which is generated by `minisign` but not currently
      used in `pagesign`.

   .. attribute:: Identity.sign_pass : str

      This attribute is a passphrase automatically generated by `pagesign` and used
      for signing. It should not be shared with the wrong people, else they could
      impersonate you when signing stuff.

   .. attribute:: Identity.crypt_secret : str

      This attribute is the secret key used for decryption. It should not be shared
      with the wrong people, else they can decrypt stuff meant only for you.

   .. attribute:: Identity.sign_secret : str

      This attribute is the secret key used for signing. It should not be shared with
      the wrong people, else they could impersonate you when signing stuff.

   .. cssclass:: class-members-heading

   Methods

   .. method:: Identity.__init__(name : Optional[str] = None) -> Identity

      If `name` is specified, create an instance populated from data in the
      keystore associated with that name. Otherwise, create a new instance with
      autogenerated keys for signing and encryption (the key generation takes
      half a second). To persist such an instance, call its
      :meth:`~pagesign.Identity.save` method with a name of your choice.

   .. method:: Identity.export() -> dict[str, str]

      Return the public elements of this instance as a dictionary. The dictionary keys
      match the attribute names listed earlier.

   .. method:: Identity.save(name : str) -> None

      Save this instance as a dictionary in the keystore against `name`, overwriting
      any existing data under that name.

   .. classmethod:: imported(public_data : dict[str, str]) -> Identity

      This is a factory method which generates an :class:`~pagesign.Identity` instance from the
      dictionary `public_data`. The instance isn't saved in your keystore until you
      call its :meth:`~pagesign.Identity.save` method with a name of your choice.


Exceptions
==========

Currently, all operations which fail raise instances of
:class:`~pagesign.CryptException`, which is a subclass of ``Exception`` and
currently does not add any functionality to it.


Encryption and Decryption
=========================

Data intended for some particular recipients is encrypted with the public keys of
those recipients. Each recipient can decrypt the encrypted data using the
corresponding secret key. A recipient is denoted by a local or remote identity.

.. index:: Encryption

Encryption
----------

To encrypt data, use the `encrypt` function:

.. function:: encrypt(path: str, recipients: Union[str, list[str]], outpath: Optional[str] = None, armor: bool = False) -> str

   Encrypt a file at `path` to `outpath`. If `outpath` isn't specified, the value of
   `path` with `'.age'` appended is used. If `armor` is `True`, the output file is PEM
   encoded. The `recipients` can be a single identity name or a list or tuple of
   identity names. The encrypted file will be decryptable by any of the recipient
   identities.

   The function returns `outpath` if successful and raises an exception if not.

   .. note:: Although `age` supports encryption and decryption using passphrases, that
      is currently not supported here because there is currently no way to pass in a
      passphrase to `age` using a subprocess pipe.

.. index:: Decryption

Decryption
----------

To decrypt data, use the `decrypt` function:

.. function:: decrypt(path: str, identities: Union[str, list[str]], outpath: Optional[str] = None) -> str

   Decrypt a file at `path` to `outpath`. If `outpath` isn't specified, then if `path`
   ends with `.age`, it is stripped to compute `outpath` |--| otherwise it has `'.dec'`
   appended to determine `outpath`. The `identities` can be a single identity name or
   a list or tuple of identity names.

   The function returns `outpath` if successful and raises an exception if not.

.. index::
    single: Memory; encrypting and decrypting in

Encryption and Decryption in memory
===================================

You can encrypt and decrypt in memory using the following functions:

.. function:: encrypt_mem(data: Union[str, bytes] , recipients: Union[str, list[str]], armor: bool = False) -> bytes

   Encrypt data in `data` and return the encrypted value as a bytestring. If `data` is
   a string, it is encoded to binary using UTF-8 encoding. If `armor` is `True`, the
   output is PEM encoded. The `recipients` can be a single identity name or a list or
   tuple of identity names. The encrypted result will be decryptable by any of the
   recipient identities.

   .. versionadded:: 0.1.1

.. function:: decrypt_mem(data: Union[str, bytes] , identities: Union[str, list[str]]) -> bytes

   Decrypt data in `data` and return the decrypted value as a bytestring. If `data` is
   a string, it is encoded to binary using UTF-8 encoding. (This really only makes
   sense if the encrypted data is in PEM format.) The `identities` can be a single
   identity name or a list or tuple of identity names.

   .. versionadded:: 0.1.1

Signing and Verification
========================

Data intended for digital signing is signed with the secret key of the signer. Each
recipient can verify the signed data using the corresponding public key.

Signatures are always stored 'detached', i.e. in separate files from what they are
signing.

.. note:: Although encryption and decryption can be performed in memory, there is no
   analogous in-memory API for signing and verification, because `minisign` only signs
   and verifies signature files against source files and identities.

.. index:: Signing

Signing
-------

To sign some data, use the `sign()` function:

.. function:: sign(path: str, identity: str, outpath: Optional[str] = None) -> str

   Sign the file at `path` using `identity` as the signer. Write the signature to
   `outpath`. If `outpath` isn't specified, it is computed by appending `'.sig'` to
   `path`.

   The function returns `outpath` if successful and raises an exception if not.

.. index:: Verification

Verification
------------

To verify some data which you've received, use the `verify()` function:

.. function:: verify(path: str, identity: str, sigpath: Optional[str] = None)

   Verify that the file at `path` was signed by `identity` using the signature in
   `sigpath`. If `sigpath` isn't specified, it is computed by appending `'.sig'` to
   `path`.

   The function raises an exception if verification fails.

.. index::
    single: Operations; combining encryption and signing

Combining operations
====================

Often, you may want to combine encryption and signing, or verification before
decryption. However, please note the caveats listed in :ref:`problems`.

Using signing and encryption together
-------------------------------------

If you want to use signing and encryption together, use `encrypt_and_sign()`:

.. function:: encrypt_and_sign(path: str, recipients: Union[str, list[str]], signer: str, armor: bool = False, outpath: Optional[str] = None, sigpath: Optional[str] = None) -> [str, str]

   Encrypt and sign the file at `path` for `recipients` and sign with identity
   `signer`. Place the encrypted output at `outpath` and the signature in `sigpath`.

   If `armor` is `True`, the encrypted output is PEM encoded.

   If `outpath` isn't specified, it is computed by appending `'.age'` to `path`.
   If `sigpath` isn't specified, it is computed by appending `'.sig'` to `outpath`.

   The function returns `(outpath`, sigpath)` if successful and raises an exception if
   not.

   .. versionchanged:: 0.1.1

   The algorithm has changed from a naïve encrypt and sign operation to:

   #. Sign the plaintext.
   #. Construct a JSON object of the base64-encoded plaintext and signature.
   #. Encrypt that.
   #. Compute the SHA-256 hashes of all recipients' public keys into an array.
   #. Construct a JSON object of the encrypted data and hashes.
   #. Sign that and save it and its signature.

   To reverse the process, you need to use :func:`~pagesign.verify_and_decrypt`.

   This corresponds to `Section 5.2 of the Davis paper
   <https://archive.ph/VFWcb#SES>`_.

Using verification and decryption together
------------------------------------------

As a counterpart to :func:`~pagesign.encrypt_and_sign`, there's also `verify_and_decrypt()`:

.. function:: verify_and_decrypt(path: str, recipients: Union[str, list[str]], signer: str, outpath: Optional[str] = None, sigpath: Optional[str] = None) -> str

   Verify and decrypt the file at `path` for `recipients` and signed with identity
   `signer`. Place the decrypted output at `outpath` and use the signature in
   `sigpath`.

   If `sigpath` isn't specified, it is computed by appending `'.sig'` to `path`.
   If `outpath` isn't specified, it is computed as in :func:`~pagesign.decrypt`.

   The function returns `outpath` if successful and raises an exception if not.

   .. versionchanged:: 0.1.1

   The files passed to this function must have been produced by
   :func:`~pagesign.encrypt_and_sign`, as we need to reverse the algorithm which is applied there.

.. index::
    single: Caveats; combining encryption and signing

.. _problems:

Problems with naïve combination of signing and encryption
=========================================================

Naïvely combining encryption and signing can lead to problems. These are described in
some depth in `Don Davis' paper on the subject <https://archive.ph/VFWcb>`_. While
`pagesign` provides access to encryption and signing primitives and allows a
relatively easy means of combining them, the actual data to be encrypted and signed
needs to be constructed with care. The solutions proposed in `Section 5 of Davis'
paper <https://archive.ph/VFWcb#Repair>`_ involve combining data with identities
during signing and encryption.

The current implementation of :func:`encrypt_and_sign` uses a sign/encrypt/sign
strategy (`Section 5.2 of Davis'
paper <https://archive.ph/VFWcb#SES>`_), which involves the following steps.

1. Sign the plaintext.
2. Construct a JSON of the base64-encoded plaintext and signature.
3. Encrypt that.
4. Hash all the recipient public keys into a list.
5. Construct a JSON of the encrypted data and recipient hashes.
6. Sign that.

The output from a :func:`~pagesign.encrypt_and_sign` might look something like
this:

.. code-block:: text

    {
      "encrypted": "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0 ... z1LMsTB83iIVZYPzEgUomGx0Q",
      "armored": false,
      "recipients": [
        "0e6f8764a139c9a8fd90c3ee4a40c69d0c2a638756485911ad9660a593410442"
      ]
    }

In the above, the opaque ``encrypted`` value will be the result of encrypting a JSON
which looks like

.. code-block:: text

    {
      "plaintext": <base-64 encoded plaintext>
      "signature": <base-64 encoded signature from the first step above>
    }


Key distribution
================

The question of key distribution in a trustworthy way is currently out of scope for
`pagesign` |--| you are expected to get exported keys securely to people you need to
exchange data with, and they are expected to get their public keys to you securely.

.. index:: Logging

.. _logging:

Logging
=======

The module makes use of the facilities provided by Python's ``logging`` package. A
single logger is created with the module's ``__name__``, hence ``pagesign`` unless you
rename the module.

.. index:: Download

Test Harness
============

The distribution includes a test harness, ``test_pagesign.py``, which contains unit
tests covering the functionality described above.

.. note:: If you run the test harness, it will create a log file `test_pagesign.log`
   in a `logs` subdirectory under your home directory.

Download
========

The latest version is available from the PyPI_ page.

.. _PyPI: https://pypi.python.org/pypi/pagesign

Status and Further Work
=======================

The ``pagesign`` module is quite usable, though in its early stages and with the API
still a little fluid. How this module evolves will be determined by feedback from its
user community.

If you find bugs and want to raise issues, or want to suggest improvements, please do
so `here <https://github.com/vsajip/pagesign/issues/new/choose>`__. All feedback will
be gratefully received.

The source code repository is `here <https://github.com/vsajip/pagesign>`__.

.. cssclass:: hidden

.. cssclass:: hidden

.. toctree::
   :maxdepth: 4
