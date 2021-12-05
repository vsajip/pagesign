#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Red Dove Consultants Limited. MIT Licensed.
#
import logging
import os
import sys
import tempfile
import unittest

from pagesign import (Identity, encrypt, decrypt, sign, verify,
                      remove_identities, clear_identities, list_identities)

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
        logger.debug('%s finished.', ident)
        logger.debug(self.SEP)


class BasicTest(BaseTest):
    def ztest_creation(self):
        for name in ('foo', 'bar'):
            identity = Identity()
            identity.save(name)

    def ztest_clearing_listing_and_removal(self):
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

    def ztest_export(self):
        for name in ('foo', 'bar'):
            identity = Identity()
            identity.save(name)
            d = identity.export()
            for k in d:
                self.assertNotIn('_secret', k)
                self.assertNotIn('_pass', k)

    def ztest_import(self):
        identity = Identity()
        identity.save('foo')
        exported = identity.export()
        imported = Identity.imported(exported, 'bar')
        self.assertEqual(exported, imported.export())

    def ztest_encryption_and_signing(self):
        identity = Identity()
        identity.save('alice')
        identity = Identity()
        identity.save('bob')
        fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
        self.addCleanup(os.remove, fn)
        data = b'Hello, world!'
        os.write(fd, data)
        os.close(fd)
        encrypted = encrypt(fn, recipients='bob')
        self.addCleanup(os.remove, encrypted)
        # Now sign it
        signed = sign(encrypted, 'alice')
        self.addCleanup(os.remove, signed)
        # Now verify it
        verify(encrypted, 'alice', signed)
        fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
        os.close(fd)
        self.addCleanup(os.remove, fn)
        decrypted = decrypt(encrypted, outpath=fn, identities='bob')
        with open(decrypted, 'rb') as f:
            ddata = f.read()
        self.assertEqual(data, ddata)

    def test_encryption_passphrase(self):
        fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
        self.addCleanup(os.remove, fn)
        data = b'Hello, world!'
        os.write(fd, data)
        os.close(fd)
        passphrase = 'correct-horse-battery-staple'
        encrypted = encrypt(fn, passphrase=passphrase)
        self.addCleanup(os.remove, encrypted)
        fd, fn = tempfile.mkstemp(prefix='test-pagesign-')
        os.close(fd)
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
    unittest.main()


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
