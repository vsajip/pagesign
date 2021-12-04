# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Red Dove Consultants Limited
#
import base64
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading

__version__ = '0.1.0'

if sys.version_info[:2] < (3, 6):
    raise ImportError('This module requires Python >= 3.6 to run.')

logger = logging.getLogger(__name__)

__all__ = [
    'Identity',
    'KEYS',
    'clear_keys',
    'encrypt',
    'decrypt',
    'sign',
    'verify'
]

if os.name == 'nt':
    PAGESIGN_DIR = os.path.join(os.environ('LOCALAPPDATA'), '.pagesign')
else:
    PAGESIGN_DIR = os.path.expanduser('~/.pagesign')

CREATED_PATTERN = re.compile('# created: (.*)', re.I)
APK_PATTERN = re.compile('# public key: (.*)', re.I)
ASK_PATTERN = re.compile(r'AGE-SECRET-KEY-.*')
MPI_PATTERN = re.compile(r'minisign public key (\S+)')
MSI_PATTERN = re.compile(r'minisign encrypted secret key')

if not os.path.exists(PAGESIGN_DIR):
    os.makedirs(PAGESIGN_DIR)

if not os.path.isdir(PAGESIGN_DIR):
    raise ValueError('%s exists but is not a directory.' % PAGESIGN_DIR)

os.chmod(PAGESIGN_DIR, 0o700)

def load_keys():
    result = {}
    p = os.path.join(PAGESIGN_DIR, 'keys')
    if os.path.exists(p):
        with open(p, encoding='utf-8') as f:
            result = json.load(f)
    return result


def save_keys(keys):
    p = os.path.join(PAGESIGN_DIR, 'keys')
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(keys, f, indent=2, sort_keys=True)
    os.chmod(p, 0o600)


KEYS = load_keys()

PUBLIC_ATTRS = ('created', 'crypt_public', 'sign_public', 'sign_id')

ATTRS = PUBLIC_ATTRS + ('crypt_secret', 'sign_secret', 'sign_pass')

def clear_keys(keys=KEYS):
    keys.clear()


def _make_password(length):
    return base64.b64encode(os.urandom(length)).decode('ascii')


def run_command(cmd, wd, ident=None):
    # print('Running: %s' % (cmd if isinstance(cmd, str) else ' '.join(cmd)))
    # if cmd[0] == 'age': import pdb; pdb.set_trace()
    if not isinstance(cmd, list):
        cmd = cmd.split()
    logger.debug('Running: %s' % cmd)
    kwargs = {
        'cwd': wd,
        'stdout': subprocess.PIPE,
        'stderr': subprocess.PIPE
    }
    if ident:
        kwargs['stdin'] = subprocess.PIPE
    p = subprocess.Popen(cmd, **kwargs)
    if ident is None:
        stdout, stderr = p.communicate()
    else:
        data = {}
        rout = threading.Thread(target=ident._read_out, args=(p.stdout, p, data))
        rout.daemon = True
        rout.start()
        if cmd[0] == 'minisign':
            if cmd[1] == '-fG':
                target = ident._read_minisign_gen_err
            else:
                target = ident._read_minisign_sign_err

        rerr = threading.Thread(target=target, args=(p.stderr, p, data))
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
        import pdb; pdb.set_trace()
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
            run_command(cmd, wd)
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
            run_command(cmd, wd, self)
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
        save_keys(KEYS)

    def _read_out(self, stream, process, result):
        data = b''
        while True:
            c = stream.read(1)
            if not c:
                break
            data += c
        result['stdout'] = data

    def _read_minisign_gen_err(self, stream, process, result):
        data = b''
        pwd = (self.sign_pass + os.linesep).encode('ascii')
        pwd_written = 0
        while True:
            c = stream.read(1)
            data += c
            # print('err: %s' % data)
            if data in (b'Password: ', b'Password: \nPassword (one more time): '):
                process.stdin.write(pwd)
                process.stdin.flush()
                pwd_written += 1
                # print('Wrote pwd')
                if pwd_written == 2:
                    process.stdin.close()
                    break
        result['stderr'] = data

    def _read_minisign_sign_err(self, stream, process, result):
        data = b''
        pwd = (self.sign_pass + os.linesep).encode('ascii')
        while True:
            c = stream.read(1)
            data += c
            # print('err: %s' % data)
            if data == b'Password: ':
                process.stdin.write(pwd)
                # process.stdin.flush()
                process.stdin.close()
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
        raise NotImplementedError('Passphrase not yet implemented')
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
    run_command(cmd, os.getcwd())
    return outpath


def decrypt(path, outpath=None, identities=None):
    if not identities:
        raise ValueError('At least one identity must be specified.')
    if not os.path.isfile(path):
        raise ValueError('No such file: %s' % path)
    if outpath is None:
        if path.endswith('.age'):
            outpath = path[:-4]
        else:
            NotImplementedError('No outpath specified and input does not end with .age')
    else:
        d = os.path.dirname(outpath)
        if not os.path.exists(d):
            os.makedirs(d)
        elif not os.path.isdir(d):
            raise ValueError('Not a directory: %s' % d)
        # if dir, assume writeable, for now

    cmd = ['age', '-d']
    if isinstance(identities, str):
        identities = [identities]
    if not isinstance(identities, (list, tuple)):
        raise ValueError('invalid identities: %s' % identities)
    fd, fn = tempfile.mkstemp(dir=PAGESIGN_DIR, prefix='ident-')
    os.close(fd)
    # import pdb; pdb.set_trace()
    try:
        ident_values = []
        for ident in identities:
            if ident not in KEYS:
                raise ValueError('No such identity: %s' % ident)
            ident_values.append(KEYS[ident]['crypt_secret'])
        with open(fn, 'w', encoding='utf-8') as f:
            f.write('\n'.join(ident_values))
        cmd.extend(['-i', fn])
        cmd.extend(['-o', outpath])
        cmd.append(path)
        run_command(cmd, os.getcwd())
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
        run_command(cmd, os.getcwd(), ident)
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
    run_command(cmd, os.getcwd())
