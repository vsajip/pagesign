#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Red Dove Consultants Limited. MIT Licensed.
#
import json
import logging
import os
import shutil
import sys
import tempfile
import unittest

from pagesign import (Identity, encrypt, encrypt_mem, decrypt, decrypt_mem,
                      sign, verify, encrypt_and_sign, verify_and_decrypt,
                      remove_identities, clear_identities, list_identities,
                      _get_work_file)

DEBUGGING = 'PY_DEBUG' in os.environ

logger = logging.getLogger(__name__)


class BaseTest(unittest.TestCase):
    SEP = '-' * 60

    def setUp(self):
        ident = self.id().rsplit('.', 1)[-1]
        logger.debug('%s starting ...', ident)
        logger.debug(self.SEP)

    def tearDown(self):
        ident = self.id().rsplit('.', 1)[-1]
        logger.debug(self.SEP)
        logger.debug('%s finished.', ident)


class BasicTest(BaseTest):
    def test_clearing_creating_listing_and_removal(self):
        clear_identities()
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
        identity = Identity()
        identity.save('alice')
        identity = Identity()
        identity.save('bob')
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
            with open(decrypted, 'rb') as f:
                ddata = f.read()
            self.assertEqual(data, ddata)

    def test_encryption_and_signing_together(self):
        identity = Identity()
        identity.save('alice')
        identity = Identity()
        identity.save('bob')
        for armor in (False, True):
            fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
            self.addCleanup(os.remove, fn)
            data = b'Hello, world!'
            os.write(fd, data)
            os.close(fd)
            outpath, sigpath = encrypt_and_sign(fn, 'bob', 'alice', armor=armor)
            # self.assertEqual(outpath, fn + '.age')
            self.assertEqual(sigpath, outpath + '.sig')
            self.addCleanup(os.remove, outpath)
            self.addCleanup(os.remove, sigpath)
            verify(outpath, 'alice', sigpath)

    def test_verifying_and_decrypting_together(self):
        identity = Identity()
        identity.save('alice')
        identity = Identity()
        identity.save('bob')
        for armor in (False, True):
            fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
            self.addCleanup(os.remove, fn)
            data = b'Hello, world!'
            os.write(fd, data)
            os.close(fd)
            outpath, sigpath = encrypt_and_sign(fn, 'bob', 'alice', armor=armor)
            self.addCleanup(os.remove, outpath)
            self.addCleanup(os.remove, sigpath)
            fn = _get_work_file(prefix='test-pagesign-')
            self.addCleanup(os.remove, fn)
            decrypted = verify_and_decrypt(outpath, 'bob', 'alice', fn, sigpath)
            with open(decrypted, 'rb') as f:
                ddata = f.read()
            self.assertEqual(data, ddata)
            os.remove(decrypted)

    def test_encryption_in_memory(self):
        identity = Identity()
        identity.save('alice')
        identity = Identity()
        identity.save('bob')
        data = 'Hello, world!'
        for armor in (False, True):
            encrypted = encrypt_mem(data, 'bob', armor=armor)
            decrypted = decrypt_mem(encrypted, 'bob')
            self.assertEqual(decrypted, data.encode('utf-8'))

    def ztest_encryption_passphrase(self):
        fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
        self.addCleanup(os.remove, fn)
        data = b'Hello, world!'
        os.write(fd, data)
        os.close(fd)
        passphrase = 'correct-horse-battery-staple'
        encrypted = encrypt(fn, passphrase=passphrase)
        self.addCleanup(os.remove, encrypted)
        fn = _get_work_file(prefix='test-pagesign-')
        self.addCleanup(os.remove, fn)
        decrypted = decrypt(encrypted, outpath=fn, passphrase=passphrase)
        with open(decrypted, 'rb') as f:
            ddata = f.read()
        self.assertEqual(data, ddata)


def main():
    fn = os.path.basename(__file__)
    fn = os.path.splitext(fn)[0]
    lfn = os.path.expanduser('~/logs/%s.log' % fn)
    d = os.path.dirname(lfn)
    if not os.path.exists(d):
        os.makedirs(d)
    if os.path.isdir(os.path.dirname(lfn)):
        logging.basicConfig(level=logging.DEBUG, filename=lfn, filemode='w',
                            format='%(message)s')
    # Is there an existing store?
    from pagesign import PAGESIGN_DIR
    existing = os.path.join(PAGESIGN_DIR, 'keys')
    if not os.path.exists(existing):
        preserved = backup = None
    else:
        with open(existing, encoding='utf-8') as f:
            preserved = json.load(f)
        backup = existing + '.bak'
        shutil.copy(existing, backup)
    try:
        unittest.main()
    finally:
        if preserved:
            shutil.copy(backup, existing)
            # with open(existing, 'w', encoding='utf-8') as f:
                # json.dump(preserved, indent=2, sort_keys=True)
            os.remove(backup)


if __name__ == '__main__':
    try:
        rc = main()
    except KeyboardInterrupt:
        rc = 2
    except Exception as e:
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
