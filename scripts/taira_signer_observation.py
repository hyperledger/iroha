#!/usr/bin/env python3
"""Observe the deployed flat-config Taira profile without Python reading private TOML.

Requires a hash-admitted LocalNode class, native-assembled inventory and Linux root.
Only /usr/bin/sha256sum receives the held config descriptor. The public observation
uses direct loopback, never operator credentials, proxies or environment discovery.
This library does not load its publisher module, mutate a deployment or provide a
fallback to the publisher's private-config reader. --help is the only CLI action.
"""
import argparse
import errno
import http.client
import json
import os
from pathlib import Path
import re
import resource
import secrets
import stat
import socket
import threading
import subprocess
import time

MAX_BYTES = 1024 * 1024
MAX_ATTEMPTS = 3
NODE_SECONDS = 30
REQUEST_SECONDS = 5
NATIVE_HASH = Path('/usr/bin/sha256sum')


class SignerObservationError(RuntimeError):
    """A fixed, secret-free observation failure; never publish an underlying exception."""


class _Retryable(SignerObservationError):
    pass


def _need(ok, label):
    if not ok:
        raise SignerObservationError(label)


def _stamp(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_size',
        'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_gid', 'st_mode', 'st_nlink'))


def _remaining(deadline):
    value = deadline - time.monotonic()
    _need(value > 0, 'signer observation deadline exceeded')
    return min(REQUEST_SECONDS, value)


def _open_direct(path):
    path = Path(path)
    _need(path.is_absolute() and str(path) == os.path.normpath(str(path)), 'invalid authority path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open('/', flags)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            _need(info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022,
                  'authority directory custody differs')
        return os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                       dir_fd=parent)
    finally:
        os.close(parent)


def native_config_identity(path, expected, deadline):
    """Return a stable config stamp after native hashing; Python never reads its FD."""
    _need(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected),
          'invalid config digest binding')
    fd = program = None
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        fd = _open_direct(path)
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
              and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
              and 0 < before.st_size <= MAX_BYTES, 'private config custody differs')
        _need(_stamp(before) == _stamp(os.lstat(path)), 'private config path changed')
        program = _open_direct(NATIVE_HASH)
        executable = os.fstat(program)
        _need(stat.S_ISREG(executable.st_mode) and executable.st_uid == 0
              and not executable.st_mode & 0o022 and executable.st_mode & 0o111,
              'native digest executable custody differs')
        # The bounded regular file is passed as stdin; neither its bytes nor its
        # path can occur in digest stdout, command arguments or stderr evidence.
        result = subprocess.run([str(NATIVE_HASH)], stdin=fd, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=_remaining(deadline), check=False,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        _need(result.returncode == 0 and result.stdout == (expected + '  -\n').encode(),
              'native config digest differs')
        _remaining(deadline)
        _need(_stamp(os.fstat(program)) == _stamp(executable) == _stamp(os.lstat(NATIVE_HASH)),
              'native digest executable changed')
        _need(_stamp(os.fstat(fd)) == _stamp(before) == _stamp(os.lstat(path)),
              'private config identity changed')
        return _stamp(before)
    except SignerObservationError:
        raise
    except Exception:
        raise SignerObservationError('native config observation failed') from None
    finally:
        if fd is not None:
            os.close(fd)
        if program is not None:
            os.close(program)


def _node(node_class, binding, deadline):
    _need(os.geteuid() == 0, 'signer observation requires Linux root')
    _need(isinstance(binding, dict) and binding.get('launch_selector') is not None
          and binding.get('config_files') == [{'path': binding.get('config_path'),
                                              'sha256': binding.get('config_sha256')}],
          'native-assembled single flat config binding required')
    # This closed override retains all publisher process/selector/executable/
    # listener checks. There is intentionally no call to the original _configs.
    class NativeConfigNode(node_class):
        def _configs(self):
            stamp = native_config_identity(self.config_path, self.config_sha256, deadline)
            return ((self.config_path, (self.config_sha256, stamp)),)
    return NativeConfigNode(binding)


def _identity(node, deadline):
    _remaining(deadline)
    try:
        node.assert_identity()
    except Exception:
        raise SignerObservationError('bound local validator identity changed') from None
    _remaining(deadline)


def _object(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'duplicate public JSON field')
        result[key] = value
    return result


def _constant(value):
    raise SignerObservationError('invalid public JSON number')


def _get(node, path, headers, deadline):
    """One bounded direct request, including identity rechecks on every failure."""
    _identity(node, deadline)
    connection = timer = response = None
    expired = threading.Event()
    try:
        request_deadline = min(deadline, time.monotonic() + REQUEST_SECONDS)
        connection = http.client.HTTPConnection('127.0.0.1', node.port,
                                                timeout=_remaining(request_deadline))
        # Per-read socket timeouts alone permit indefinitely dripping headers.
        # This watchdog owns only this request's explicitly connected socket.
        connection.connect()
        owned_socket = connection.sock
        def expire():
            expired.set()
            try:
                owned_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            owned_socket.close()
        timer = threading.Timer(_remaining(request_deadline), expire)
        timer.daemon = True
        timer.start()
        connection.request('GET', path, headers={'Accept': 'application/json',
            'Accept-Encoding': 'identity', 'Connection': 'close', **headers})
        response = connection.getresponse()
        if response.status in (404, 500, 503):
            raise _Retryable('public startup observation temporarily unavailable')
        _need(response.status == 200, 'public startup observation HTTP rejected')
        lengths = response.headers.get_all('Content-Length', [])
        transfers = response.headers.get_all('Transfer-Encoding', [])
        _need(len(lengths) <= 1 and len(transfers) <= 1 and not (lengths and transfers),
              'ambiguous public response framing')
        _need(not lengths or (re.fullmatch('[0-9]+', lengths[0]) and int(lengths[0]) <= MAX_BYTES),
              'public response exceeds bound')
        _need(not transfers or transfers[0].lower() == 'chunked', 'invalid public response encoding')
        _need(response.headers.get('Content-Encoding', 'identity').lower() == 'identity'
              and response.headers.get_content_type() == 'application/json', 'public response is not plain JSON')
        body = bytearray()
        while not response.isclosed():
            timeout = _remaining(request_deadline)
            # HTTPConnection may detach its socket for Connection: close. The
            # response retains that same socket until its final byte is read.
            response.fp.raw._sock.settimeout(timeout)
            block = response.read1(min(65536, MAX_BYTES + 1 - len(body)))
            if not block:
                break
            body.extend(block)
            _need(len(body) <= MAX_BYTES, 'public response exceeds bound')
        _need(not lengths or len(body) == int(lengths[0]), 'truncated public response')
        _remaining(request_deadline)
        document = json.loads(body.decode('utf-8'), object_pairs_hook=_object, parse_constant=_constant)
        _remaining(request_deadline)
        return document
    except _Retryable:
        raise
    except (TimeoutError, ConnectionError, http.client.RemoteDisconnected, http.client.IncompleteRead):
        raise _Retryable('public startup transport interrupted') from None
    except OSError as error:
        if expired.is_set():
            raise _Retryable('public startup transport interrupted') from None
        if error.errno in (errno.ETIMEDOUT, errno.ECONNRESET, errno.ECONNREFUSED, errno.EPIPE):
            raise _Retryable('public startup transport interrupted') from None
        raise SignerObservationError('public startup transport rejected') from None
    except SignerObservationError:
        raise
    except Exception:
        if expired.is_set():
            raise _Retryable('public startup transport interrupted') from None
        raise SignerObservationError('invalid public startup response') from None
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()
        try:
            if response is not None:
                response.close()
        finally:
            try:
                if connection is not None:
                    connection.close()
            finally:
                _identity(node, deadline)


def _hash(value):
    _need(isinstance(value, str) and re.fullmatch('hash:[0-9A-F]{64}#[0-9A-F]{4}', value),
          'invalid checked public hash')
    return value[5:69].lower()


def _validate(attestation, height, challenge, row, network_id, genesis_hash):
    try:
        body = attestation['body']
        status = body['status']
        # Norito's [u8; 32] JSON codec emits one uppercase hexadecimal string.
        _need(type(body['version']) is int and body['version'] == 1
              and isinstance(body['challenge'], str)
              and re.fullmatch('[0-9A-F]{64}', body['challenge']) is not None
              and body['challenge'] == challenge.hex().upper() and body['network_id'] == network_id
              and body['node_id'] == row['peer_id'], 'attestation identity differs')
        _need(body['genesis_block_hash'] == network_id and _hash(network_id) == genesis_hash,
              'attestation genesis differs')
        _need(type(status['protocol_version']) is int and status['protocol_version'] == 4
              and status['restart_required'] is False
              and type(status['last_committed_height']) is int
              and status['last_committed_height'] == height,
              'attestation applied status differs')
        _need(all(_hash(status[name]) == row[name] for name in
                  ('node_fingerprint', 'build_fingerprint', 'config_fingerprint'))
              and isinstance(body['genesis_finality_proof'], dict)
              and isinstance(body['finality_proof'], dict), 'attestation proof or fingerprint differs')
        return status
    except SignerObservationError:
        raise
    except Exception:
        raise SignerObservationError('invalid attestation schema') from None


def observe_attested_status(node_class, binding, expected_row, network_id, genesis_hash):
    """Return (node, status, attestation) before the shared30s success deadline.

    Identity work retains the publisher's bounded systemctl calls and executable
    hashing; the deadline is checked around it. Network requests additionally
    have an absolute5s own-socket watchdog. No late success is admitted.
    """
    deadline = time.monotonic() + NODE_SECONDS
    try:
        node = _node(node_class, binding, deadline)
        for attempt in range(MAX_ATTEMPTS):
            try:
                height = _get(node, '/status/blocks', {}, deadline)
                _need(type(height) is int and 1 <= height <= 18446744073709551615,
                      'invalid public applied height')
                challenge = secrets.token_bytes(32)
                _need(len(challenge) == 32 and any(challenge), 'invalid generated challenge')
                attestation = _get(node, '/v1/bridge/finality/attestation/' + str(height),
                                  {'x-iroha-finality-challenge': challenge.hex()}, deadline)
                status = _validate(attestation, height, challenge, expected_row, network_id, genesis_hash)
                _identity(node, deadline)
                return node, status, attestation
            except _Retryable:
                if attempt + 1 == MAX_ATTEMPTS:
                    raise SignerObservationError('public startup retries exhausted') from None
                _remaining(deadline)
        raise SignerObservationError('public startup retries exhausted')
    except SignerObservationError:
        raise
    except Exception:
        raise SignerObservationError('signer observation failed') from None


if __name__ == '__main__':
    argparse.ArgumentParser(description=__doc__).parse_args()
