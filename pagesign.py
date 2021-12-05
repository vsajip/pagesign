# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Red Dove Consultants Limited
#
import base64
import functools
import json
import logging
import os
import re
import shutil
# import stat
import subprocess
import sys
import tempfile
import threading

__version__ = '0.1.0.dev0'
__author__ = 'Vinay Sajip'
__date__ = "$04-Dec-2021 21:23:47$"

if sys.version_info[:2] < (3, 6):
    raise ImportError('This module requires Python >= 3.6 to run.')

logger = logging.getLogger(__name__)

__all__ = [
    'Identity',
    'remove_identities',
    'clear_identities',
    'list_identities',
    'encrypt',
    'decrypt',
    'sign',
    'verify'
]

if os.name == 'nt':
    PAGESIGN_DIR = os.path.join(os.environ['LOCALAPPDATA'], 'pagesign')
else:
    PAGESIGN_DIR = os.path.expanduser('~/.pagesign')

CREATED_PATTERN = re.compile('# created: (.*)', re.I)
APK_PATTERN = re.compile('# public key: (.*)', re.I)
ASK_PATTERN = re.compile(r'AGE-SECRET-KEY-.*')
MPI_PATTERN = re.compile(r'minisign public key (\S+)')

if not os.path.exists(PAGESIGN_DIR):
    os.makedirs(PAGESIGN_DIR)

if not os.path.isdir(PAGESIGN_DIR):
    raise ValueError('%s exists but is not a directory.' % PAGESIGN_DIR)

os.chmod(PAGESIGN_DIR, 0o700)


def _load_keys():
    result = {}
    p = os.path.join(PAGESIGN_DIR, 'keys')
    if os.path.exists(p):
        with open(p, encoding='utf-8') as f:
            result = json.load(f)
    return result


def _save_keys(keys):
    p = os.path.join(PAGESIGN_DIR, 'keys')
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(keys, f, indent=2, sort_keys=True)
    os.chmod(p, 0o600)


KEYS = _load_keys()

PUBLIC_ATTRS = ('created', 'crypt_public', 'sign_public', 'sign_id')

ATTRS = PUBLIC_ATTRS + ('crypt_secret', 'sign_secret', 'sign_pass')


def clear_identities(keys=KEYS):
    if len(keys):
        keys.clear()
        _save_keys(keys)


def remove_identities(*args):
    changed = False
    for name in args:
        if name in KEYS:
            del KEYS[name]
            changed = True
    if changed:
        _save_keys(KEYS)


def list_identities():
    return KEYS.items()


def _make_password(length):
    return base64.b64encode(os.urandom(length)).decode('ascii')


def _read_out(stream, result):
    data = b''
    while True:
        c = stream.read1(100)
        if not c:
            break
        data += c
    result['stdout'] = data


def _read_age_encrypt_err(passphrase, stream, stdin, result):
    data = b''
    pwd = (passphrase + os.linesep).encode('ascii')
    pwd_written = 0
    sep = os.linesep.encode('ascii')
    prompt1 = b'Enter passphrase (leave empty to autogenerate a secure one): '
    prompt2 = prompt1 + sep + b'Confirm passphrase: '
    prompts = (prompt1, prompt2)
    while True:
        c = stream.read1(100)
        data += c
        # print('err: %s' % data)
        if data in prompts:
            stdin.write(pwd)
            stdin.flush()
            pwd_written += 1
            if pwd_written == 2:
                stdin.close()
                break
    result['stderr'] = data


def _read_age_decrypt_err(passphrase, stream, stdin, result):
    data = b''
    pwd = (passphrase + os.linesep).encode('ascii')
    while True:
        c = stream.read1(100)
        data += c
        # print('err: %s' % data)
        if data == b'Enter passphrase: ':
            stdin.write(pwd)
            stdin.flush()
            stdin.close()
            break
    result['stderr'] = data


def _run_command(cmd, wd, err_reader=None):
    print('Running: %s' % (cmd if isinstance(cmd, str) else ' '.join(cmd)))
    # if cmd[0] == 'age': import pdb; pdb.set_trace()
    if not isinstance(cmd, list):
        cmd = cmd.split()
    logger.debug('Running: %s' % cmd)
    kwargs = {
        'cwd': wd,
        'stdout': subprocess.PIPE,
        'stderr': subprocess.PIPE
    }
    if err_reader:
        kwargs['stdin'] = subprocess.PIPE
    p = subprocess.Popen(cmd, **kwargs)
    if err_reader is None:
        stdout, stderr = p.communicate()
    else:
        data = {}
        rout = threading.Thread(target=_read_out, args=(p.stdout, data))
        rout.daemon = True
        rout.start()

        rerr = threading.Thread(target=err_reader, args=(p.stderr, p.stdin, data))
        rerr.daemon = True
        rerr.start()

        rout.join()
        rerr.join()

        p.wait()

        stdout = data['stdout']
        stderr = data['stderr']

        p.stdout.close()
        p.stderr.close()

    if p.returncode == 0:
        return stdout.decode('utf-8'), stderr.decode('utf-8')
    else:
        # import pdb; pdb.set_trace()
        if False:
            print('Command %r failed with return code %d' % (cmd[0], p.returncode))
            print('stdout was:')
            if stdout:
                print(stdout.decode('utf-8'))
            print('stderr was:')
            if stderr:
                print(stderr.decode('utf-8'))
            print('Raising an exception')
        raise subprocess.CalledProcessError(p.returncode, p.args,
                                            output=stdout, stderr=stderr)


class Identity:

    encoding = 'utf-8'

    def __init__(self, name=None):
        if name:
            if name in KEYS:
                self.__dict__.update(KEYS[name])
            else:
                raise ValueError('No such identity: %r' % name)
        else:
            # Generate a new identity
            wd = tempfile.mkdtemp(dir=PAGESIGN_DIR, prefix='work-')
            p = os.path.join(wd, 'age-key')
            cmd = 'age-keygen -o %s' % p
            _run_command(cmd, wd)
            with open(p, encoding=self.encoding) as f:
                lines = f.read().splitlines()
            for line in lines:
                m = CREATED_PATTERN.match(line)
                if m:
                    self.created = m.groups()[0]
                    continue
                m = APK_PATTERN.match(line)
                if m:
                    self.crypt_public = m.groups()[0]
                    continue
                m = ASK_PATTERN.match(line)
                if m:
                    self.crypt_secret = line
            fd, sfn = tempfile.mkstemp(prefix='msk-', dir=wd)
            os.close(fd)
            fd, pfn = tempfile.mkstemp(prefix='mpk-', dir=wd)
            os.close(fd)
            self.sign_pass = _make_password(12)
            cmd = 'minisign -fG -p %s -s %s' % (pfn, sfn)
            _run_command(cmd, wd, self._read_minisign_gen_err)
            with open(pfn, encoding=self.encoding) as f:
                lines = f.read().splitlines()
                for line in lines:
                    m = MPI_PATTERN.search(line)
                    if m:
                        self.sign_id = m.groups()[0]
                    else:
                        self.sign_public = line
            with open(sfn, encoding=self.encoding) as f:
                self.sign_secret = f.read()
            shutil.rmtree(wd)

            for attr in ATTRS:
                assert hasattr(self, attr)

    def save(self, name):
        d = dict(self.__dict__)
        # might need to remove some attrs from d here ...
        KEYS[name] = d
        _save_keys(KEYS)

    def _read_minisign_gen_err(self, stream, stdin, result):
        data = b''
        pwd = (self.sign_pass + os.linesep).encode('ascii')
        pwd_written = 0
        sep = os.linesep.encode('ascii')
        prompt1 = b'Password: '
        prompt2 = prompt1 + sep + b'Password (one more time): '
        prompts = (prompt1, prompt2)
        while True:
            c = stream.read1(100)
            data += c
            # print('err: %s' % data)
            if data in prompts:
                stdin.write(pwd)
                stdin.flush()
                pwd_written += 1
                # print('Wrote pwd')
                if pwd_written == 2:
                    stdin.close()
                    break
        result['stderr'] = data

    def _read_minisign_sign_err(self, stream, stdin, result):
        data = b''
        pwd = (self.sign_pass + os.linesep).encode('ascii')
        while True:
            c = stream.read(1)
            data += c
            # print('err: %s' % data)
            if data == b'Password: ':
                stdin.write(pwd)
                stdin.close()
                break
        result['stderr'] = data

    def export(self):
        d = dict(self.__dict__)
        for k in self.__dict__:
            if '_secret' in k or '_pass' in k:
                del d[k]
        return d

    @classmethod
    def imported(cls, d, name):
        result = object.__new__(cls)
        for k in PUBLIC_ATTRS:
            try:
                setattr(result, k, d[k])
            except KeyError:
                logger.warning('Attribute absent: %s', k)
        result.save(name)
        return result


def encrypt(path, outpath=None, armor=True, recipients=None, passphrase=None):
    if passphrase is not None:
        passphrase = passphrase.strip()
    if not recipients and not passphrase:
        raise ValueError('Either recipients or a passphrase need to be specified.')
    if recipients and passphrase:
        raise ValueError('Both recipients and a passphrase should not be specified.')
    if not os.path.isfile(path):
        raise ValueError('No such file: %s' % path)
    if outpath is None:
        outpath = '%s.age' % path
    else:
        d = os.path.dirname(outpath)
        if not os.path.exists(d):
            os.makedirs(d)
        elif not os.path.isdir(d):
            raise ValueError('Not a directory: %s' % d)
        # if dir, assume writeable, for now

    cmd = ['age', '-e']
    if armor:
        cmd.append('-a')
    if passphrase:
        cmd.append('-p')
    else:
        if isinstance(recipients, str):
            recipients = [recipients]
        if not isinstance(recipients, (list, tuple)):
            raise ValueError('invalid recipients: %s' % recipients)
        for r in recipients:
            if r not in KEYS:
                raise ValueError('No such recipient: %s' % r)
            info = KEYS[r]
            cmd.extend(['-r', info['crypt_public']])
    cmd.extend(['-o', outpath])
    cmd.append(path)
    if not passphrase:
        err_reader = None
    else:
        err_reader = functools.partial(_read_age_encrypt_err, passphrase)
    _run_command(cmd, os.getcwd(), err_reader)
    return outpath


def decrypt(path, outpath=None, identities=None, passphrase=None):
    if passphrase is not None:
        passphrase = passphrase.strip()
    if not identities and not passphrase:
        raise ValueError('Either identities or a passphrase need to be specified.')
    if identities and passphrase:
        raise ValueError('Both identities and a passphrase should not be specified.')
    if not os.path.isfile(path):
        raise ValueError('No such file: %s' % path)
    if outpath is None:
        if path.endswith('.age'):
            outpath = path[:-4]
        else:
            outpath = '%s.dec' % path
            NotImplementedError('No outpath specified and input does not end with .age')
    else:
        d = os.path.dirname(outpath)
        if not os.path.exists(d):
            os.makedirs(d)
        elif not os.path.isdir(d):
            raise ValueError('Not a directory: %s' % d)
        # if dir, assume writeable, for now

    cmd = ['age', '-d']
    if passphrase:
        cmd.append('-p')
    else:
        if isinstance(identities, str):
            identities = [identities]
        if not isinstance(identities, (list, tuple)):
            raise ValueError('invalid identities: %s' % identities)
        fd, fn = tempfile.mkstemp(dir=PAGESIGN_DIR, prefix='ident-')
        os.close(fd)
        ident_values = []
        for ident in identities:
            if ident not in KEYS:
                raise ValueError('No such identity: %s' % ident)
            ident_values.append(KEYS[ident]['crypt_secret'])
        with open(fn, 'w', encoding='utf-8') as f:
            f.write('\n'.join(ident_values))
        cmd.extend(['-i', fn])
    # import pdb; pdb.set_trace()
    try:
        cmd.extend(['-o', outpath])
        cmd.append(path)
        if not passphrase:
            err_reader = None
        else:
            err_reader = functools.partial(_read_age_decrypt_err, passphrase)
        _run_command(cmd, os.getcwd(), err_reader)
        return outpath
    finally:
        os.remove(fn)


def sign(path, identity, outpath=None):
    if not identity:
        raise ValueError('An identity needs to be specified.')
    if identity not in KEYS:
        raise ValueError('No such identity: %s' % identity)
    ident = Identity(identity)
    if not os.path.isfile(path):
        raise ValueError('No such file: %s' % path)
    if outpath is None:
        outpath = '%s.sig' % path
    else:
        d = os.path.dirname(outpath)
        if not os.path.exists(d):
            os.makedirs(d)
        elif not os.path.isdir(d):
            raise ValueError('Not a directory: %s' % d)
        # if dir, assume writeable, for now

    fd, fn = tempfile.mkstemp(dir=PAGESIGN_DIR, prefix='seckey-')
    os.write(fd, (KEYS[identity]['sign_secret'] + os.linesep).encode('ascii'))
    os.close(fd)
    try:
        cmd = ['minisign', '-S', '-x', outpath, '-s', fn, '-m', path]
        _run_command(cmd, os.getcwd(), ident._read_minisign_sign_err)
    finally:
        os.remove(fn)
    return outpath


def verify(path, identity, sigpath=None):
    if not identity:
        raise ValueError('An identity needs to be specified.')
    if identity not in KEYS:
        raise ValueError('No such identity: %s' % identity)
    ident = Identity(identity)
    if not os.path.isfile(path):
        raise ValueError('No such file: %s' % path)
    if sigpath is None:
        sigpath = '%s.sig' % path
    if not os.path.isfile(sigpath):
        raise ValueError('No such file: %s' % sigpath)
    cmd = ['minisign', '-V', '-x', sigpath, '-P', ident.sign_public, '-m', path]
    # import pdb; pdb.set_trace()
    _run_command(cmd, os.getcwd())
