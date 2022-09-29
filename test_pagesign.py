#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021-2022 Red Dove Consultants Limited. MIT Licensed.
#
import json
import logging
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from pagesign import (Identity, CryptException, encrypt, encrypt_mem, decrypt,
                      decrypt_mem, sign, verify, encrypt_and_sign,
                      verify_and_decrypt, remove_identities, clear_identities,
                      list_identities, _get_work_file)

DEBUGGING = 'PY_DEBUG' in os.environ

logger = logging.getLogger(__name__)


class BaseTest(unittest.TestCase):
    HSEP = '=' * 60
    FSEP = '-' * 60

    def setUp(self):
        ident = self.id().rsplit('.', 1)[-1]
        logger.debug(self.HSEP)
        logger.debug('%s starting ...', ident)
        logger.debug(self.HSEP)

    def tearDown(self):
        ident = self.id().rsplit('.', 1)[-1]
        logger.debug(self.FSEP)
        logger.debug('%s finished.', ident)


class BasicTest(BaseTest):

    def test_clearing_creating_listing_and_removal(self):
        clear_identities()
        d = dict(list_identities())
        self.assertEqual(len(d), 0)
        clear_identities()  # call again when already cleared (coverage)
        d = dict(list_identities())
        self.assertEqual(len(d), 0)
        names = {'bob', 'carol', 'ted', 'alice'}
        for name in names:
            identity = Identity()
            identity.save(name)
        d = dict(list_identities())
        self.assertEqual(set(d), names)
        remove_identities('bob', 'alice')
        d = dict(list_identities())
        self.assertEqual(set(d), {'ted', 'carol'})
        remove_identities('foo')  # non-existent identity
        d = dict(list_identities())
        self.assertEqual(set(d), {'ted', 'carol'})

    def test_export(self):
        for name in ('foo', 'bar'):
            identity = Identity()
            identity.save(name)
            d = identity.export()
            for k in d:
                self.assertNotIn('_secret', k)
                self.assertNotIn('_pass', k)

    def test_import(self):
        identity = Identity()
        identity.save('foo')
        exported = identity.export()
        imported = Identity.imported(exported, 'bar')
        self.assertEqual(exported, imported.export())

    def test_encryption_and_signing_separately(self):
        for name in ('alice', 'bob'):
            identity = Identity()
            identity.save(name)

        for armor in (False, True):
            fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
            self.addCleanup(os.remove, fn)
            data = b'Hello, world!'
            os.write(fd, data)
            os.close(fd)
            encrypted = encrypt(fn, 'bob', armor=armor)
            self.addCleanup(os.remove, encrypted)
            # Now sign it
            signed = sign(encrypted, 'alice')
            self.addCleanup(os.remove, signed)
            # Now verify it
            verify(encrypted, 'alice', signed)
            fn = _get_work_file(prefix='test-pagesign-')
            self.addCleanup(os.remove, fn)
            decrypted = decrypt(encrypted, 'bob', fn)
            ddata = Path(decrypted).read_bytes()
            self.assertEqual(data, ddata)
            with self.assertRaises(CryptException) as ec:
                verify(encrypted, 'bob', signed)
            self.assertEqual(str(ec.exception), 'Verification failed')

    def test_encryption_and_signing_together(self):
        for name in ('alice', 'bob'):
            identity = Identity()
            identity.save(name)

        for armor in (False, True):
            fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
            self.addCleanup(os.remove, fn)
            data = b'Hello, world!'
            os.write(fd, data)
            os.close(fd)
            outpath, sigpath = encrypt_and_sign(fn,
                                                'bob',
                                                'alice',
                                                armor=armor)
            # self.assertEqual(outpath, fn + '.age')
            self.assertEqual(sigpath, outpath + '.sig')
            self.addCleanup(os.remove, outpath)
            self.addCleanup(os.remove, sigpath)
            verify(outpath, 'alice', sigpath)
            # Repeat call using recipient as list
            outpath, sigpath = encrypt_and_sign(fn, ['bob'],
                                                'alice',
                                                armor=armor)
            # self.assertEqual(outpath, fn + '.age')
            self.assertEqual(sigpath, outpath + '.sig')
            self.addCleanup(os.remove, outpath)
            self.addCleanup(os.remove, sigpath)
            verify(outpath, 'alice', sigpath)

    def test_verifying_and_decrypting_together(self):
        for name in ('alice', 'bob'):
            identity = Identity()
            identity.save(name)

        for armor in (False, True):
            fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
            self.addCleanup(os.remove, fn)
            data = b'Hello, world!'
            os.write(fd, data)
            os.close(fd)
            outpath, sigpath = encrypt_and_sign(fn,
                                                'bob',
                                                'alice',
                                                armor=armor)
            self.addCleanup(os.remove, outpath)
            self.addCleanup(os.remove, sigpath)
            fn = _get_work_file(prefix='test-pagesign-')
            self.addCleanup(os.remove, fn)
            decrypted = verify_and_decrypt(outpath, 'bob', 'alice', fn,
                                           sigpath)
            ddata = Path(decrypted).read_bytes()
            self.assertEqual(data, ddata)
            # Repeat call with recipient as list
            decrypted = verify_and_decrypt(outpath, ['bob'], 'alice', fn,
                                           sigpath)
            ddata = Path(decrypted).read_bytes()
            self.assertEqual(data, ddata)
            os.remove(decrypted)

    def test_encryption_in_memory(self):
        for name in ('alice', 'bob'):
            identity = Identity()
            identity.save(name)

        data = 'Hello, world!'
        for armor in (False, True):
            encrypted = encrypt_mem(data, 'bob', armor=armor)
            decrypted = decrypt_mem(encrypted, 'bob')
            self.assertEqual(decrypted, data.encode('utf-8'))

    def test_multiple_recipients(self):
        for name in ('alice', 'bob', 'carol', 'ted'):
            identity = Identity()
            identity.save(name)
        data = b'Hello, world!'
        recipients = ['alice', 'carol', 'ted']
        encrypted = encrypt_mem(data, recipients)
        for name in recipients:
            ddata = decrypt_mem(encrypted, name)
            self.assertEqual(data, ddata)
        with self.assertRaises(CryptException) as ec:
            ddata = decrypt_mem(encrypted, 'bob')
        self.assertEqual(str(ec.exception), 'Decryption failed')

    def test_identity_failures(self):

        class Dummy1(Identity):

            def _parse_age_file(self, fn):
                pass

        class Dummy2(Identity):

            def _parse_minisign_file(self, fn):
                pass

        with self.assertRaises(CryptException) as ec:
            Dummy1()
        self.assertEqual(str(ec.exception), 'Identity creation failed (crypt)')

        with self.assertRaises(CryptException) as ec:
            Dummy2()
        self.assertEqual(str(ec.exception), 'Identity creation failed (sign)')

    def test_signing_failure(self):

        def dummy(*args, **kwargs):
            raise ValueError()

        identity = Identity()
        identity.save('alice')

        fn = _get_work_file(prefix='test-pagesign-')
        sfn = _get_work_file(prefix='test-pagesign-sig-')
        self.addCleanup(os.remove, fn)
        self.addCleanup(os.remove, sfn)

        with self.assertRaises(CryptException) as ec:
            with patch('pagesign._run_command', dummy):
                sign(fn, 'alice', sfn)
        self.assertEqual(str(ec.exception), 'Signing failed')

    def test_default_paths(self):
        for name in ('alice', 'bob'):
            identity = Identity()
            identity.save(name)

        fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
        self.addCleanup(os.remove, fn)
        data = b'Hello, world!'
        os.write(fd, data)
        os.close(fd)

        # Encryption / decryption

        # Test with no encrypted outpath
        encrypted = encrypt(fn, 'alice')
        self.assertEqual(encrypted, fn + '.age')
        decrypted = decrypt(encrypted, 'alice')
        self.assertEqual(decrypted, fn)
        # Test with specified encrypted outpath
        fd, ofn = tempfile.mkstemp(prefix='test-pagesign-')
        os.close(fd)
        encrypted = encrypt(fn, 'alice', outpath=ofn)
        self.assertEqual(encrypted, ofn)
        decrypted = decrypt(ofn, 'alice')
        self.assertEqual(decrypted, ofn + '.dec')

        # Signing / verification

        # Test with no signed outpath
        signed = sign(fn, 'alice')
        self.assertEqual(signed, fn + '.sig')
        verify(fn, 'alice')
        # Test with specified signed outpath
        signed = sign(fn, 'alice', outpath=ofn)
        self.assertEqual(signed, ofn)
        verify(fn, 'alice', sigpath=signed)

        # Encryption and signing / decryption and verification together

        # Using default paths

        outpath, sigpath = encrypt_and_sign(fn, 'bob', 'alice')
        self.addCleanup(os.remove, outpath)
        self.addCleanup(os.remove, sigpath)
        self.assertEqual(sigpath, outpath + '.sig')
        dfn = _get_work_file(prefix='test-pagesign-')
        self.addCleanup(os.remove, dfn)
        decrypted = verify_and_decrypt(outpath, 'bob', 'alice', dfn, sigpath)
        ddata = Path(decrypted).read_bytes()
        self.assertEqual(data, ddata)
        os.remove(decrypted)


def main():
    fn = os.path.basename(__file__)
    fn = os.path.splitext(fn)[0]
    lfn = os.path.expanduser('~/logs/%s.log' % fn)
    d = os.path.dirname(lfn)
    if not os.path.exists(d):  # pragma: no cover
        os.makedirs(d)
    if os.path.isdir(os.path.dirname(lfn)):  # pragma: no branch
        logging.basicConfig(level=logging.DEBUG,
                            filename=lfn,
                            filemode='w',
                            format='%(message)s')
    # Is there an existing store?
    from pagesign import PAGESIGN_DIR
    existing = os.path.join(PAGESIGN_DIR, 'keys')
    if not os.path.exists(existing):  # pragma: no cover
        preserved = backup = None
    else:
        with open(existing, encoding='utf-8') as f:
            preserved = json.load(f)
        backup = existing + '.bak'
        shutil.copy(existing, backup)
    try:
        unittest.main()
    finally:
        if preserved:  # pragma: no branch
            shutil.copy(backup, existing)
            os.remove(backup)


if __name__ == '__main__':  # pragma: no branch
    try:
        rc = main()
    except KeyboardInterrupt:  # pragma: no cover
        rc = 2
    except SystemExit as e:  # pragma: no cover
        rc = 3 if e.args[0] else 0
    except Exception as e:  # pragma: no cover
        if DEBUGGING:
            s = ' %s:' % type(e).__name__
        else:
            s = ''
        sys.stderr.write('Failed:%s %s\n' % (s, e))
        if DEBUGGING:
            import traceback
            traceback.print_exc()
        rc = 1
    sys.exit(rc)
