# -*- coding: utf-8 -*-
#
# Copyright (C) 2021-2022 Red Dove Consultants Limited
#
"""
This module supports key management, encryption/decryption and signing/verification
using age and minisign.
"""
import base64
import functools
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
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
    'Identity', 'CryptException', 'remove_identities', 'clear_identities',
    'list_identities', 'encrypt', 'decrypt', 'encrypt_mem', 'decrypt_mem',
    'sign', 'verify', 'encrypt_and_sign', 'verify_and_decrypt'
]


class CryptException(Exception):
    """
    Base class of all exceptions defined in this module.
    """
    pass


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


def clear_identities():
    """
    Clear all identities saved locally.
    """
    if len(KEYS):
        KEYS.clear()
        _save_keys(KEYS)


def remove_identities(*args):
    """
    Remove the identities stored locally whose names are in *args*. Names are
    case-sensitive.

    Args:
        args (list[str]): The list of identities to remove.
    """
    changed = False
    for name in args:
        if name in KEYS:
            del KEYS[name]
            changed = True
    if changed:
        _save_keys(KEYS)


def list_identities():
    """
    Return an iterator over the locally stored identities, as name-value 2-tuples.
    """
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


def _run_command(cmd, wd, err_reader=None, decode=True):
    # print('Running: %s' % (cmd if isinstance(cmd, str) else ' '.join(cmd)))
    # if cmd[0] == 'age': import pdb; pdb.set_trace()
    if not isinstance(cmd, list):
        cmd = cmd.split()
    logger.debug('Running: %s' % cmd)
    kwargs = {'cwd': wd, 'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE}
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

        rerr = threading.Thread(target=err_reader,
                                args=(p.stderr, p.stdin, data))
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
        raise subprocess.CalledProcessError(p.returncode,
                                            p.args,
                                            output=stdout,
                                            stderr=stderr)


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
    """
    This class represents both remote identities (used for encryption and verification
    only) and local identities (used for all functions - encryption, decryption,
    signing and verification).
    """
    encoding = 'utf-8'

    def __init__(self, name=None):
        """
        Either retrieve an existing identity named *name*, or, if not specified, create
        a new local identity which can later be named using its :meth:`save` method.
        Names are case-sensitive.
        """
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
                try:
                    _run_command(cmd, wd)
                    self._parse_age_file(p)
                    for name in ('created', 'crypt_public', 'crypt_secret'):
                        getattr(self, name)  # ensure the attribute is there
                except Exception as e:  # pragma: no cover
                    raise CryptException(
                        'Identity creation failed (crypt)') from e
                finally:
                    # the whole working directory will get removed, so pass False
                    # to _shred as we don't need to delete the file now
                    # (same logic applies to _shred calls below)
                    _shred(p, False)
                sfn = _get_work_file(prefix='msk-', dir=wd)
                pfn = _get_work_file(prefix='mpk-', dir=wd)
                self.sign_pass = _make_password(12)
                cmd = 'minisign -fG -p %s -s %s' % (pfn, sfn)
                try:
                    _run_command(cmd, wd, self._read_minisign_gen_err)
                    self._parse_minisign_file(pfn)
                    for name in ('sign_id', 'sign_public'):
                        getattr(self, name)  # ensure the attribute is there
                    self.sign_secret = Path(sfn).read_text(self.encoding)
                except Exception as e:  # pragma: no cover
                    raise CryptException(
                        'Identity creation failed (sign)') from e
                finally:
                    _shred(pfn, False)
                    _shred(sfn, False)
            finally:
                shutil.rmtree(wd)

            for attr in ATTRS:
                assert hasattr(self, attr)

    def _parse_age_file(self, fn):
        with open(fn, encoding=self.encoding) as f:
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

    def _parse_minisign_file(self, fn):
        with open(fn, encoding=self.encoding) as f:
            lines = f.read().splitlines()
        for line in lines:
            m = MPI_PATTERN.search(line)
            if m:
                self.sign_id = m.groups()[0]
            else:
                self.sign_public = line

    def save(self, name):
        """
        Save this instance with the specified *name*, which cannot be blank or
        ``None``. Names are case-sensitive.
        """
        if not name or not isinstance(name, str):  # pragma: no cover
            raise ValueError('Invalid name: %r' % name)
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
        """
        Export this instance. Only public attributes are preserved in the export
        --- it is meant for sending to someone securely.

        Returns:
            dict: A dictionary containing the exportable items of the instance.
        """
        d = dict(self.__dict__)
        for k in self.__dict__:
            if '_secret' in k or '_pass' in k:
                del d[k]
        return d

    @classmethod
    def imported(cls, d, name):
        """
        Return a remote identity instance created from *d* and with local name *name*.

        Args:
            d (dict): A dictionary from some external source. It must contain the public
                      attributes *created*, *crypt_public*, *sign_public* and
                      *sign_id* (which will be present in dictionaries created
                      using the :meth:`export` method)

            name (str): A name against which to save the imported information.
                        Note that names are case-sensitive.

        Returns:
            Identity: The saved identity constructed from *d*.
        """
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
    """
    Encrypt the file at *path* for identities whose names are in *recipients* and
    save the encrypted data in *outpath*. The output data is ASCII-armored if *armor*
    is true, else it is binary.

    Args:
        path (str): The path to the data to be encrypted.

        recipients (str|list[str]): The name(s) of the identities of the recipient(s)
                                    of the data.

        outpath (str): The path to which the encrypted data should be written.
                       If not specified, it will be set to *path* with
                       ``'.age'`` appended.

        armor (bool): Whether the output is to be ASCII-armored.

    Returns:
        str: The value of *outpath* is returned.
    """
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
    try:
        _run_command(cmd, os.getcwd())
        return outpath
    except subprocess.CalledProcessError as e:  # pragma: no cover
        raise CryptException('Encryption failed') from e


def _data_writer(data, stream, stdin, result):
    stdin.write(data)
    stdin.close()
    _read_out(stream, result, 'stderr')


def encrypt_mem(data, recipients, armor=False):
    """
    Encrypt the in-memory *data* for identities whose names are in *recipients*. The
    output data is ASCII-armored if *armor* is true, else it is binary. The encrypted
    data is returned as bytes.

    Args:
        data (str|bytes): The data to be encrypted.

        recipients (str|list[str]): The name(s) of the identities of the
                                    recipient(s) of the data.

        armor (bool): Whether the output is to be ASCII-armored.

    Returns:
        bytes: The encrypted data.
    """
    cmd = _get_encryption_command(recipients, armor)
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not isinstance(data, bytes):  # pragma: no cover
        raise TypeError('invalid data: %s' % data)
    err_reader = functools.partial(_data_writer, data)
    try:
        stdout, stderr = _run_command(cmd, os.getcwd(), err_reader, False)
        return stdout
    except subprocess.CalledProcessError as e:  # pragma: no cover
        raise CryptException('Encryption failed') from e


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
    """
    Decrypt the data at *path* which is intended for recipients named in *identities*
    and save the decrypted data at *outpath*.

    Args:
        path (str): The path to the data to be decrypted.

        identities (str|list[str]): The name(s) of the recipient(s) of the data.

        outpath (str): The path to which the decrypted data should be written.
                       If not specified and *path* ends with ``'.age'``, then
                       *outpath* will be set to *path* with that suffix
                       stripped. Otherwise, it will be set to *path* with
                       ``'.dec'`` appended.

    Returns:
        str: The value of *outpath* is returned.
    """
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
    except subprocess.CalledProcessError as e:  # pragma: no cover
        raise CryptException('Decryption failed') from e
    finally:
        _shred(fn)


def decrypt_mem(data, identities):
    """
    Decrypt the in-memory *data* for recipients whose names are in *identities*.

    Args:
        data (str|bytes): The data to decrypt.

        identities (str|list[str]): The name(s) of the identities of the
                                    recipient(s) of the data.

    Returns:
        bytes: The decrypted data.
    """
    cmd, fn = _get_decryption_command(identities)
    if isinstance(data, str):  # pragma: no cover
        data = data.encode('utf-8')
    if not isinstance(data, bytes):  # pragma: no cover
        raise TypeError('invalid data: %s' % data)
    err_reader = functools.partial(_data_writer, data)
    try:
        stdout, stderr = _run_command(cmd, os.getcwd(), err_reader, False)
        return stdout
    except subprocess.CalledProcessError as e:  # pragma: no cover
        raise CryptException('Decryption failed') from e
    finally:
        _shred(fn)


def sign(path, identity, outpath=None):
    """
    Sign the data at *path* with the named *identity* and save the signature in
    *outpath*.

    Args:
        path (str): The path to the data to be signed.

        identity (str): The name of the signer's identity.

        outpath (str): The path to which the signature is to be written. If not
                       specified, *outpath* is set to *path* with ``'.sig'``
                       appended.

    Returns:
        str: The value of *outpath* is returned.
    """
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
    except Exception as e:  # pragma: no cover
        raise CryptException('Signing failed') from e
    finally:
        _shred(fn)
    return outpath


def verify(path, identity, sigpath=None):
    """
    Verify that the data at *path* was signed with the identity named *identity*,
    where the signature is at *sigpath*. If verification fails, an exception is
    raised, otherwise this function returns `None`.

    Args:
        path (str): The path to the data to be verified.

        identity (str): The name of the signer's identity.

        sigpath (str): The path where the signature is stored. If not specified,
                       *sigpath* is set to *path* with `'.sig'` appended.
    """
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
    cmd = [
        'minisign', '-V', '-x', sigpath, '-P', ident.sign_public, '-m', path
    ]
    # import pdb; pdb.set_trace()
    try:
        _run_command(cmd, os.getcwd())
    except subprocess.CalledProcessError as e:  # pragma: no cover
        raise CryptException('Verification failed') from e


def _get_b64(path):
    with open(path, 'rb') as f:
        return base64.b64encode(f.read()).decode('ascii')


def encrypt_and_sign(path,
                     recipients,
                     signer,
                     armor=False,
                     outpath=None,
                     sigpath=None):
    """
    Encrypt the data at *path* for identities named in *recipients* and sign it with
    the identity named by *signer*. Write the encrypted data to *outpath* and
    the signature to *sigpath*.

    Note that you'll need to call :func:`verify_and_decrypt` to reverse this process.

    Args:
        path (str): The path to the data to be decrypted.

        recipients (str|list[str]): The name(s) of the identities of the
                                    recipient(s) of the encrypted data.

        signer (str): The name of the signer identity.

        armor (bool):  If `True`, use ASCII armor for the encrypted data, else
                       save it as binary.

        outpath (str): The output path to which the encrypted data should be
                       written, If not specified, it will be set to *path*
                       with ``'.age'`` appended.

        sigpath (str): The path to which the signature should be written. If not
                       specified, *sigpath* is set to *outpath* with ``'.sig'``
                       appended.

    Returns:
        tuple(str, str): A tuple of *outpath* and *sigpath* is returned.
    """
    if not recipients or not signer:  # pragma: no cover
        raise ValueError(
            'At least one recipient (and one signer) needs to be specified.')
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
        inner = {'plaintext': _get_b64(path), 'signature': _get_b64(sigpath)}
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
        Path(outpath).write_bytes(data)
        sigpath = sign(outpath, signer)
        return outpath, sigpath


def verify_and_decrypt(path, recipients, signer, outpath=None, sigpath=None):
    """
    Verify the encrypted and signed data at *path* as having been signed by the
    identity named by *signer* and intended for identities named in *recipients*.
    The signature for *path* is in *sigpath*. If not specified, it will be set to
    *path* with ``'.sig'`` appended. If verification or decryption fails, an exception
    will be raised. Otherwise, the decrypted data will be stored at *outpath*. If
    not specified, it will be set to *path* with the suffix stripped (if it ends in
    ``'.age'``) or with ``'.dec'`` appended.

    The function returns *outpath*.

    Note that the file inputs to this function should have been created using
    :func:`encrypt_and_sign`.

    Args:
        path (str): The path to the encrypted and signed data.

        recipients (str|list[str]): The name(s) of the recipient(s) of the encrypted data.

        signer (str): The name of the signer identity.

        outpath (str): The output path to which the decrypted data should be written,

        sigpath (str): The path in which the signature is to be found.

    Returns:
        str: The value of outpath is returned.
    """
    if not signer or not recipients:  # pragma: no cover
        raise ValueError(
            'At least one recipient (and one signer) needs to be specified.')
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
        Path(sigpath).write_bytes(
            base64.b64decode(inner['signature'].encode('ascii')))
        verify(outpath, signer, sigpath)
        os.remove(sigpath)
        return outpath
