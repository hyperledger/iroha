#!/usr/bin/env python3
"""Linux-only loopback HTTPS supervisor for the real Rust eligibility adapter.

Requires Python 3.12+, Linux sealed memfd execution, an explicitly selected native
ELF adapter, loopback TLS certificate/key, private token and operator directory.
The private JSON configuration contains exactly: port, certificate, tls_key,
transport_token, adapter, adapter_sha256, operator_directory, timeout_seconds.
Run --config ABSOLUTE_PRIVATE_JSON. No environment configuration or approval defaults.
This is a disposable SchemeOperator test service, not bank KYC/production admission.
The selected executable bytes are immutable; the trusted OS loader and its system
libraries are still dependencies, not a qualified reproducible loader closure.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import selectors
import socket
import ssl
import stat
import subprocess
import sys
import time

MAX_BODY = 2048
MAX_HEADER = 8192
MAX_ADAPTER = 512 * 1024 * 1024
MIME = b"application/x-norito"


class Refused(Exception):
    """Closed transport refusal; never includes input material."""


def identity(info):
    """Ignore read-induced access time while retaining mutation/custody observations."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info):
    """Directory contents may change atomically; custody and identity must not change."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def absolute(path: str) -> Path:
    if not isinstance(path, str):
        raise Refused()
    p = Path(path)
    if not p.is_absolute() or str(p) != path or '..' in p.parts or '\0' in path:
        raise Refused()
    return p


class DirectoryCustody:
    """Retain descriptor-relative ancestry; refuse symlinks, substitutions and unsafe owners."""
    def __init__(self, path: str, private: bool):
        self.path = absolute(path)
        self.links = []
        try:
            parts = self.path.parts
            for index, part in enumerate(parts):
                parent = None if index == 0 else self.links[-1][0]
                descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                     os.O_CLOEXEC, dir_fd=parent)
                info = os.fstat(descriptor)
                self.links.append((descriptor, parent, part, directory_identity(info)))
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                        or (info.st_mode & 0o022 and not
                            (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))
                        or info.st_mode & (stat.S_ISUID | stat.S_ISGID)):
                    raise Refused()
            self.fd = self.links[-1][0]
            last = os.fstat(self.fd)
            if private and (last.st_uid != os.geteuid() or stat.S_IMODE(last.st_mode) != 0o700):
                raise Refused()
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def revalidate(self):
        for descriptor, parent, part, original in self.links:
            held = os.fstat(descriptor)
            named = os.stat(part, dir_fd=parent, follow_symlinks=False)
            if directory_identity(held) != original or directory_identity(named) != original:
                raise Refused()

    def close(self):
        for descriptor, _, _, _ in reversed(self.links):
            os.close(descriptor)
        self.links = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class SelectedFile:
    """Retained stable source leaf under retained safe ancestry; never reopen its pathname."""
    def __init__(self, path: str, maximum: int, private: bool = True, executable: bool = False):
        self.path = absolute(path)
        self.directory = DirectoryCustody(str(self.path.parent), private=private)
        self.fd = None
        try:
            # NONBLOCK avoids blocking on a substituted FIFO before fstat rejects it.
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                              os.O_NONBLOCK, dir_fd=self.directory.fd)
            info = os.fstat(self.fd)
            mode = stat.S_IMODE(info.st_mode)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or not 0 < info.st_size <= maximum
                    or (private and mode not in (0o400, 0o600))
                    or (executable and (mode not in (0o500, 0o700, 0o555, 0o755)
                                        or not info.st_mode & stat.S_IXUSR))):
                raise Refused()
            self.original = identity(info)
            self.size = info.st_size
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def revalidate(self):
        self.directory.revalidate()
        if (identity(os.fstat(self.fd)) != self.original
                or identity(os.stat(self.path.name, dir_fd=self.directory.fd,
                                    follow_symlinks=False)) != self.original):
            raise Refused()

    def chunks(self):
        self.revalidate()
        offset = 0
        while offset < self.size:
            part = os.pread(self.fd, min(65536, self.size - offset), offset)
            if not part:
                raise Refused()
            offset += len(part)
            yield part
        if os.pread(self.fd, 1, self.size):
            raise Refused()
        self.revalidate()

    def read(self) -> bytes:
        return b''.join(self.chunks())

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.directory.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def private_bytes(path: str, maximum: int) -> bytes:
    """Admit a private, single-link, stable original with a private immediate parent."""
    with SelectedFile(path, maximum) as selected:
        return selected.read()


def require_linux():
    if (sys.platform != 'linux' or not hasattr(os, 'memfd_create')
            or not os.path.isdir('/proc/self/fd')):
        raise Refused()


class SealedOriginal:
    """Exact selected bytes in a non-writable, non-resizable kernel-sealed descriptor."""
    def __init__(self, name: str, chunks, executable: bool = False):
        require_linux()
        self.fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        self.path = f'/proc/self/fd/{self.fd}'
        try:
            digest = hashlib.sha256()
            for chunk in chunks:
                digest.update(chunk)
                offset = 0
                while offset < len(chunk):
                    written = os.write(self.fd, chunk[offset:])
                    if written <= 0:
                        raise Refused()
                    offset += written
            if executable and os.pread(self.fd, 4, 0) != b'\x7fELF':
                raise Refused()
            os.fchmod(self.fd, 0o500 if executable else 0o400)
            self.seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, self.seals)
            self.original = identity(os.fstat(self.fd))
            self.digest = digest.hexdigest()
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def revalidate(self):
        if (identity(os.fstat(self.fd)) != self.original
                or fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) & self.seals != self.seals):
            raise Refused()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class SelectedExecutable:
    """Pinned source plus immutable execution descriptor; dynamic loader dependencies remain."""
    def __init__(self, path: str, expected: str):
        require_linux()
        if (not isinstance(expected, str) or len(expected) != 64
                or any(c not in '0123456789abcdef' for c in expected)):
            raise Refused()
        self.resources = ExitStack()
        try:
            self.source = self.resources.enter_context(SelectedFile(path, MAX_ADAPTER, private=False, executable=True))
            self.image = self.resources.enter_context(SealedOriginal('kagemusha-eligibility-adapter', self.source.chunks(), executable=True))
            if not hmac.compare_digest(self.image.digest, expected):
                raise Refused()
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def revalidate(self):
        self.source.revalidate()
        self.image.revalidate()

    def close(self):
        self.resources.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def parse_request(stream, token: bytes, authority: bytes, *, connection=None, deadline=None) -> bytes:
    """Authenticate before returning any body, with an absolute deadline for socket reads."""
    def read(size):
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refused()
            if connection is not None:
                connection.settimeout(remaining)
        # read1 issues at most one underlying read, so slow trickles cannot restart a full timeout.
        return stream.read1(size)

    header = bytearray()
    while not header.endswith(b'\r\n\r\n'):
        part = read(1)
        if not part or len(header) == MAX_HEADER:
            raise Refused()
        header.extend(part)
    lines = bytes(header[:-4]).split(b'\r\n')
    if lines[0] != b'POST /eligibility HTTP/1.1':
        raise Refused()
    fields = {}
    for line in lines[1:]:
        if b':' not in line or line[:1] in (b' ', b'\t'):
            raise Refused()
        name, value = line.split(b':', 1)
        if not name or not all(c in b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-' for c in name):
            raise Refused()
        name = name.lower()
        if name in fields or any(c < 32 and c != 9 or c == 127 for c in value):
            raise Refused()
        fields[name] = value.strip(b' \t')
    if (fields.get(b'host') != authority
            or fields.get(b'content-type') != MIME or fields.get(b'accept') != MIME
            or b'transfer-encoding' in fields or b'content-encoding' in fields or b'expect' in fields
            or not hmac.compare_digest(fields.get(b'authorization', b''), b'Bearer ' + token)):
        raise Refused()
    length = fields.get(b'content-length', b'')
    if not length.isdigit() or len(length) > 4:
        raise Refused()
    size = int(length)
    if not 1 <= size <= MAX_BODY or str(size).encode() != length:
        raise Refused()
    body = bytearray()
    while len(body) < size:
        part = read(size - len(body))
        if not part:
            raise Refused()
        body.extend(part)
    return bytes(body)


def invoke(adapter: SelectedExecutable, directory: DirectoryCustody, body: bytes, timeout: int) -> bytes:
    """One pinned child, empty environment, bounded pipe output; never pathname execution/retry."""
    if not 1 <= len(body) <= MAX_BODY or not 0 < timeout <= 60:
        raise Refused()
    adapter.revalidate()
    directory.revalidate()
    deadline = time.monotonic() + timeout
    with subprocess.Popen([adapter.image.path, str(directory.path)],
                          pass_fds=(adapter.image.fd,), stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={}, cwd='/') as process:
        try:
            # Body <= 2048 fits in an empty Linux pipe; no input thread or unbounded buffer.
            process.stdin.write(body)
            process.stdin.close()
            os.set_blocking(process.stdout.fileno(), False)
            original = bytearray()
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not ready.select(remaining):
                        raise Refused()
                    part = os.read(process.stdout.fileno(), MAX_BODY + 1 - len(original))
                    if not part:
                        break
                    original.extend(part)
                    if len(original) > MAX_BODY:
                        raise Refused()
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) or not original:
                raise Refused()
            adapter.revalidate()
            directory.revalidate()
            return bytes(original)
        finally:
            if process.poll() is None:
                # This is only the adapter child created above, never another task's process.
                process.kill()
            process.wait()


def unique_object(pairs):
    """Reject duplicate configuration names instead of selecting a last value."""
    result = {}
    for name, value in pairs:
        if name in result:
            raise Refused()
        result[name] = value
    return result


def selected_tls_context(certificate: SealedOriginal, key: SealedOriginal):
    """Load only the exact immutable descriptors, with no source-path reopen."""
    certificate.revalidate()
    key.revalidate()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate.path, key.path)
    certificate.revalidate()
    key.revalidate()
    return context


class Configuration:
    """Hold selected source custody, immutable executable/TLS images and TLS context until close."""
    def __init__(self, path: str):
        require_linux()
        self.resources = ExitStack()
        self.sources = []
        try:
            def select(path, maximum):
                source = self.resources.enter_context(SelectedFile(path, maximum))
                self.sources.append(source)
                return source.read()
            self.value = value = json.loads(select(path, 16384), object_pairs_hook=unique_object)
            if not isinstance(value, dict) or set(value) != {
                'port', 'certificate', 'tls_key', 'transport_token', 'adapter',
                'adapter_sha256', 'operator_directory', 'timeout_seconds'
            }:
                raise Refused()
            if (type(value['port']) is not int or not 1024 <= value['port'] <= 65535
                    or type(value['timeout_seconds']) is not int or not 1 <= value['timeout_seconds'] <= 60):
                raise Refused()
            self.token = select(value['transport_token'], 4096)
            if not all(c in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/=' for c in self.token):
                raise Refused()
            self.adapter = self.resources.enter_context(SelectedExecutable(value['adapter'], value['adapter_sha256']))
            self.directory = self.resources.enter_context(DirectoryCustody(value['operator_directory'], private=True))
            cert = self.resources.enter_context(SealedOriginal('kagemusha-eligibility-cert', [select(value['certificate'], 65536)]))
            key = self.resources.enter_context(SealedOriginal('kagemusha-eligibility-tls-key', [select(value['tls_key'], 16384)]))
            self.context = selected_tls_context(cert, key)
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def revalidate(self):
        for source in self.sources:
            source.revalidate()
        self.adapter.revalidate()
        self.directory.revalidate()

    def close(self):
        self.resources.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def serve(config: str) -> None:
    with Configuration(config) as selected:
        value = selected.value
        authority = f"127.0.0.1:{value['port']}".encode()
        timeout = value['timeout_seconds']
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1', value['port']))
            listener.listen(8)
            while True:
                socket_, _ = listener.accept()
                with socket_:
                    deadline = time.monotonic() + timeout
                    socket_.settimeout(timeout)
                    try:
                        selected.revalidate()
                        with selected.context.wrap_socket(socket_, server_side=True) as tls:
                            with tls.makefile('rb') as stream:
                                try:
                                    body = parse_request(stream, selected.token, authority,
                                                         connection=tls, deadline=deadline)
                                    selected.revalidate()
                                    response = invoke(selected.adapter, selected.directory, body, timeout)
                                    selected.revalidate()
                                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: ' + MIME
                                                + b'\r\nContent-Length: ' + str(len(response)).encode()
                                                + b'\r\nConnection: close\r\n\r\n' + response)
                                except (Refused, OSError, subprocess.SubprocessError):
                                    tls.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    except (Refused, OSError, ssl.SSLError):
                        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    try:
        serve(args.config)
    except (Refused, OSError, ValueError, TypeError, KeyError):
        print('local eligibility service refused startup', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
