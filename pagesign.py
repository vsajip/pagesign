# -*- coding: utf-8 -*-
#
# Copyright (C) 2021-2022 Red Dove Consultants Limited
#
import base64
import functools
import hashlib
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

__version__ = '0.1.1.dev0'
__author__ = 'Vinay Sajip'
__date__ = "$05-Dec-2021 12:39:53$"

if sys.version_info[:2] < (3, 6):  # pragma: no cover
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
    'verify',
    'encrypt_and_sign',
    'verify_and_decrypt'
]

if os.name == 'nt':
    PAGESIGN_DIR = os.path.join(os.environ['LOCALAPPDATA'], 'pagesign')
else:
    PAGESIGN_DIR = os.path.expanduser('~/.pagesign')

CREATED_PATTERN = re.compile('# created: (.*)', re.I)
APK_PATTERN = re.compile('# public key: (.*)', re.I)
ASK_PATTERN = re.compile(r'AGE-SECRET-KEY-.*')
MPI_PATTERN = re.compile(r'minisign public key (\S+)')

if not os.path.exists(PAGESIGN_DIR):  # pragma: no cover
    os.makedirs(PAGESIGN_DIR)

if not os.path.isdir(PAGESIGN_DIR):  # pragma: no cover
    raise ValueError('%s exists but is not a directory.' % PAGESIGN_DIR)

os.chmod(PAGESIGN_DIR, 0o700)


def _load_keys():
    result = {}
    p = os.path.join(PAGESIGN_DIR, 'keys')
    if os.path.exists(p):  # pragma: no branch
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


def _read_out(stream, result, key='stdout'):
    data = b''
    while True:
        c = stream.read1(100)
        if not c:
            break
        data += c
    result[key] = data


# def _read_age_encrypt_err(passphrase, stream, stdin, result):
    # data = b''
    # pwd = (passphrase + os.linesep).encode('ascii')
    # pwd_written = 0
    # sep = os.linesep.encode('ascii')
    # prompt1 = b'Enter passphrase (leave empty to autogenerate a secure one): '
    # prompt2 = prompt1 + sep + b'Confirm passphrase: '
    # prompts = (prompt1, prompt2)
    # while True:
        # c = stream.read1(100)
        # data += c
        # # print('err: %s' % data)
        # if data in prompts:
            # stdin.write(pwd)
            # stdin.flush()
            # pwd_written += 1
            # if pwd_written == 2:
                # stdin.close()
                # break
    # result['stderr'] = data


# def _read_age_decrypt_err(passphrase, stream, stdin, result):
    # data = b''
    # pwd = (passphrase + os.linesep).encode('ascii')
    # while True:
        # c = stream.read1(100)
        # data += c
        # # print('err: %s' % data)
        # if data == b'Enter passphrase: ':
            # stdin.write(pwd)
            # stdin.flush()
            # stdin.close()
            # break
    # result['stderr'] = data


def _run_command(cmd, wd, err_reader=None, decode=True):
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
        if decode:
            stdout = stdout.decode('utf-8')
            stderr = stderr.decode('utf-8')
        return stdout, stderr
    else:  # pragma: no cover
        raise subprocess.CalledProcessError(p.returncode, p.args,
                                            output=stdout, stderr=stderr)


def _get_work_file(**kwargs):
    fd, result = tempfile.mkstemp(**kwargs)
    os.close(fd)
    return result


def _shred(path, delete=True):
    size = os.stat(path).st_size
    passes = 2
    with open(path, 'wb') as f:
        for i in range(passes):
            if i > 0:
                f.seek(0)
            f.write(os.urandom(size))
    if delete:
        os.remove(path)


class Identity:

    encoding = 'utf-8'

    def __init__(self, name=None):
        if name:
            if name in KEYS:
                self.__dict__.update(KEYS[name])
            else:  # pragma: no cover
                raise ValueError('No such identity: %r' % name)
        else:
            # Generate a new identity
            wd = tempfile.mkdtemp(dir=PAGESIGN_DIR, prefix='work-')
            try:
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
                    assert m, 'Secret key line not seen'
                    self.crypt_secret = line
                _shred(p, False)  # the whole directory will get removed
                sfn = _get_work_file(prefix='msk-', dir=wd)
                pfn = _get_work_file(prefix='mpk-', dir=wd)
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
                _shred(sfn, False)  # the whole directory will get removed
            finally:
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
            except KeyError:  # pragma: no cover
                logger.warning('Attribute absent: %s', k)
        result.save(name)
        return result


def _get_encryption_command(recipients, armor):
    if not recipients:  # pragma: no cover
        raise ValueError('At least one recipient needs to be specified.')
    result = ['age', '-e']
    if armor:
        result.append('-a')
    if isinstance(recipients, str):
        recipients = [recipients]
    if not isinstance(recipients, (list, tuple)):  # pragma: no cover
        raise ValueError('invalid recipients: %s' % recipients)
    for r in recipients:
        if r not in KEYS:  # pragma: no cover
            raise ValueError('No such recipient: %s' % r)
        info = KEYS[r]
        result.extend(['-r', info['crypt_public']])
    return result


def encrypt(path, recipients, outpath=None, armor=False):
    if not os.path.isfile(path):  # pragma: no cover
        raise ValueError('No such file: %s' % path)
    if outpath is None:
        outpath = '%s.age' % path
    else:
        d = os.path.dirname(outpath)
        if not os.path.exists(d):  # pragma: no cover
            os.makedirs(d)
        elif not os.path.isdir(d):  # pragma: no cover
            raise ValueError('Not a directory: %s' % d)
        # if dir, assume writeable, for now

    cmd = _get_encryption_command(recipients, armor)
    cmd.extend(['-o', outpath])
    cmd.append(path)
    _run_command(cmd, os.getcwd())
    return outpath


def _data_writer(data, stream, stdin, result):
    stdin.write(data)
    stdin.close()
    _read_out(stream, result, 'stderr')


def encrypt_mem(data, recipients, armor=False):
    cmd = _get_encryption_command(recipients, armor)
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not isinstance(data, bytes):  # pragma: no cover
        raise TypeError('invalid data: %s' % data)
    err_reader = functools.partial(_data_writer, data)
    stdout, stderr = _run_command(cmd, os.getcwd(), err_reader, False)
    return stdout


def _get_decryption_command(identities):
    if not identities:  # pragma: no cover
        raise ValueError('At least one identity needs to be specified.')
    cmd = ['age', '-d']
    if isinstance(identities, str):
        identities = [identities]
    if not isinstance(identities, (list, tuple)):  # pragma: no cover
        raise ValueError('invalid identities: %s' % identities)
    fn = _get_work_file(dir=PAGESIGN_DIR, prefix='ident-')
    ident_values = []
    for ident in identities:
        if ident not in KEYS:  # pragma: no cover
            raise ValueError('No such identity: %s' % ident)
        ident_values.append(KEYS[ident]['crypt_secret'])
    with open(fn, 'w', encoding='utf-8') as f:
        f.write('\n'.join(ident_values))
    cmd.extend(['-i', fn])
    return cmd, fn


def decrypt(path, identities, outpath=None):
    if not os.path.isfile(path):  # pragma: no cover
        raise ValueError('No such file: %s' % path)
    if outpath is None:
        if path.endswith('.age'):
            outpath = path[:-4]
        else:
            outpath = '%s.dec' % path
    else:
        d = os.path.dirname(outpath)
        if not os.path.exists(d):  # pragma: no cover
            os.makedirs(d)
        elif not os.path.isdir(d):  # pragma: no cover
            raise ValueError('Not a directory: %s' % d)
        # if dir, assume writeable, for now

    cmd, fn = _get_decryption_command(identities)
    # import pdb; pdb.set_trace()
    try:
        cmd.extend(['-o', outpath])
        cmd.append(path)
        _run_command(cmd, os.getcwd())
        return outpath
    finally:
        _shred(fn)


def decrypt_mem(data, identities):
    cmd, fn = _get_decryption_command(identities)
    if isinstance(data, str):  # pragma: no cover
        data = data.encode('utf-8')
    if not isinstance(data, bytes):  # pragma: no cover
        raise TypeError('invalid data: %s' % data)
    err_reader = functools.partial(_data_writer, data)
    try:
        stdout, stderr = _run_command(cmd, os.getcwd(), err_reader, False)
        return stdout
    finally:
        _shred(fn)


def sign(path, identity, outpath=None):
    if not identity:  # pragma: no cover
        raise ValueError('An identity needs to be specified.')
    if identity not in KEYS:  # pragma: no cover
        raise ValueError('No such identity: %s' % identity)
    ident = Identity(identity)
    if not os.path.isfile(path):  # pragma: no cover
        raise ValueError('No such file: %s' % path)
    if outpath is None:
        outpath = '%s.sig' % path
    else:
        d = os.path.dirname(outpath)
        if not os.path.exists(d):  # pragma: no cover
            os.makedirs(d)
        elif not os.path.isdir(d):  # pragma: no cover
            raise ValueError('Not a directory: %s' % d)
        # if dir, assume writeable, for now

    fd, fn = tempfile.mkstemp(dir=PAGESIGN_DIR, prefix='seckey-')
    os.write(fd, (KEYS[identity]['sign_secret'] + os.linesep).encode('ascii'))
    os.close(fd)
    try:
        cmd = ['minisign', '-S', '-x', outpath, '-s', fn, '-m', path]
        _run_command(cmd, os.getcwd(), ident._read_minisign_sign_err)
    finally:
        _shred(fn)
    return outpath


def verify(path, identity, sigpath=None):
    if not identity:  # pragma: no cover
        raise ValueError('An identity needs to be specified.')
    if identity not in KEYS:  # pragma: no cover
        raise ValueError('No such identity: %s' % identity)
    ident = Identity(identity)
    if not os.path.isfile(path):  # pragma: no cover
        raise ValueError('No such file: %s' % path)
    if sigpath is None:
        sigpath = '%s.sig' % path
    if not os.path.isfile(sigpath):  # pragma: no cover
        raise ValueError('No such file: %s' % sigpath)
    cmd = ['minisign', '-V', '-x', sigpath, '-P', ident.sign_public, '-m', path]
    # import pdb; pdb.set_trace()
    _run_command(cmd, os.getcwd())


def _get_b64(path):
    with open(path, 'rb') as f:
        return base64.b64encode(f.read()).decode('ascii')


def encrypt_and_sign(path, recipients, signer, armor=False, outpath=None, sigpath=None):
    if not recipients or not signer:  # pragma: no cover
        raise ValueError('At least one recipient (and one signer) needs to be specified.')
    if not os.path.isfile(path):  # pragma: no cover
        raise ValueError('No such file: %s' % path)
    naive = False
    if naive:  # pragma: no cover
        outpath = encrypt(path, recipients, outpath=outpath, armor=armor)
        sigpath = sign(outpath, signer, outpath=sigpath)
        return outpath, sigpath
    else:
        # Use a sign/encrypt/sign strategy:
        # 1. Sign the plaintext.
        # 2. Construct a JSON of the base64-encoded plaintext and signature.
        # 3. Encrypt that.
        # 4. Hash all the recipient public keys into a list.
        # 5. Construct a JSON of the encrypted data and recipient hashes.
        # 6. Sign that.
        fn = _get_work_file(dir=PAGESIGN_DIR, prefix='sig-')
        sigpath = sign(path, signer, fn)
        inner = {
            'plaintext': _get_b64(path),
            'signature': _get_b64(sigpath)
        }
        os.remove(sigpath)
        data = json.dumps(inner).encode('ascii')
        encrypted = encrypt_mem(data, recipients, armor)
        if not armor:
            encrypted = base64.b64encode(encrypted)
        if isinstance(recipients, str):
            recipients = [recipients]
        # if we encrypted OK, there can't have been problems with the recipients
        hashes = []
        for r in recipients:
            info = KEYS[r]
            pk = info['crypt_public'].encode('ascii')
            hashes.append(hashlib.sha256(pk).hexdigest())
        outer = {
            'encrypted': encrypted.decode('ascii'),
            'armored': armor,
            'recipients': hashes
        }
        data = json.dumps(outer).encode('ascii')
        outpath = _get_work_file(dir=PAGESIGN_DIR, prefix='message-')
        with open(outpath, 'wb') as f:
            f.write(data)
        sigpath = sign(outpath, signer)
        return outpath, sigpath


def verify_and_decrypt(path, recipients, signer, outpath=None, sigpath=None):
    if not signer or not recipients:  # pragma: no cover
        raise ValueError('At least one recipient (and one signer) needs to be specified.')
    if not os.path.isfile(path):  # pragma: no cover
        raise ValueError('No such file: %s' % path)
    if sigpath is None:  # pragma: no cover
        sigpath = path + '.sig'
    if not os.path.exists(sigpath):  # pragma: no cover
        raise ValueError('no such file: %s' % sigpath)
    verify(path, signer, sigpath)
    naive = False
    if naive:  # pragma: no cover
        return decrypt(path, recipients, outpath)
    else:
        with open(path, 'r', encoding='ascii') as f:
            outer = json.load(f)
        encrypted = outer['encrypted'].encode('ascii')
        if not outer['armored']:
            encrypted = base64.b64decode(encrypted)
        hashes = set(outer['recipients'])
        if isinstance(recipients, str):
            recipients = [recipients]
        for r in recipients:
            if r not in KEYS:  # pragma: no cover
                raise ValueError('No such recipient: %s' % r)
            info = KEYS[r]
            pk = info['crypt_public'].encode('ascii')
            h = hashlib.sha256(pk).hexdigest()
            if h not in hashes:  # pragma: no cover
                raise ValueError('Not a valid recipient: %s' % r)
        decrypted = decrypt_mem(encrypted, recipients).decode('ascii')
        inner = json.loads(decrypted)
        fd, outpath = tempfile.mkstemp(dir=PAGESIGN_DIR, prefix='msg-')
        os.write(fd, base64.b64decode(inner['plaintext'].encode('ascii')))
        os.close(fd)
        sigpath = outpath + '.sig'
        with open(sigpath, 'wb') as f:
            f.write(base64.b64decode(inner['signature'].encode('ascii')))
        verify(outpath, signer, sigpath)
        os.remove(sigpath)
        return outpath
