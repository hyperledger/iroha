"""Transport/custody contracts only; local fixture programs are never enrollment evidence."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import importlib.util

SERVICE_PATH = Path(__file__).resolve().parents[2] / "scripts/kagemusha_eligibility_https.py"
SPEC = importlib.util.spec_from_file_location("kagemusha_eligibility_https", SERVICE_PATH)
assert SPEC is not None and SPEC.loader is not None
service = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(service)


class Transport(unittest.TestCase):
    def request(self, body=b'canonical-original', replacements=None, extra=b''):
        fields = {b'Host': b'127.0.0.1:8443', b'Content-Type': service.MIME, b'Accept': service.MIME,
                  b'Authorization': b'Bearer disposable-transport', b'Content-Length': str(len(body)).encode()}
        fields.update(replacements or {})
        return (b'POST /eligibility HTTP/1.1\r\n'
                + b'\r\n'.join(k + b': ' + v for k, v in fields.items()) + extra + b'\r\n\r\n' + body)

    def parse(self, original):
        return service.parse_request(io.BytesIO(original), b'disposable-transport', b'127.0.0.1:8443')

    def test_exact_original_survives_authenticated_transport(self):
        for body in [bytes(range(256)), b'x', b'x' * 2048]:
            self.assertEqual(self.parse(self.request(body)), body)

    def test_rejected_authentication_never_reads_the_body(self):
        data = self.request(replacements={b'Authorization': b'Bearer wrong'})
        stream = io.BytesIO(data)
        with self.assertRaises(service.Refused):
            service.parse_request(stream, b'disposable-transport', b'127.0.0.1:8443')
        self.assertEqual(stream.tell(), data.index(b'\r\n\r\n') + 4)

    def test_duplicates_encodings_lengths_and_foreign_routes_refuse(self):
        cases = [self.request(extra=b'\r\nAuthorization: Bearer disposable-transport'),
                 self.request(extra=b'\r\nTransfer-Encoding: chunked'),
                 self.request(extra=b'\r\nContent-Encoding: gzip'),
                 self.request(extra=b'\r\nExpect: 100-continue'),
                 self.request(extra=b'\r\n folded: no'), self.request(extra=b'\r\nUnknown: a\x00b'),
                 self.request(replacements={b'Host': b'foreign:8443'}),
                 self.request(replacements={b'Content-Type': b'application/json'}),
                 self.request(replacements={b'Content-Length': b'01'}),
                 self.request(replacements={b'Content-Length': b'0'}),
                 self.request(replacements={b'Content-Length': b'2049'}),
                 self.request(replacements={b'Content-Length': b'-1'}),
                 self.request().replace(b'/eligibility ', b'/eligibility?bypass=1 '),
                 self.request().replace(b'POST ', b'GET ', 1), self.request()[:-1], b'X' * 8193, b'']
        for value in cases:
            with self.subTest(value=value[:30]), self.assertRaises(service.Refused):
                self.parse(value)

    def test_short_reads_preserve_body_but_slow_trickles_cannot_extend_deadline(self):
        class OneByte(io.BytesIO):
            def read1(self, size):
                return super().read1(min(size, 1))
        data = self.request()
        self.assertEqual(service.parse_request(OneByte(data), b'disposable-transport', b'127.0.0.1:8443'),
                         b'canonical-original')
        stream = OneByte(data)
        with mock.patch.object(service.time, 'monotonic', side_effect=[1, 2, 3]):
            with self.assertRaises(service.Refused):
                service.parse_request(stream, b'disposable-transport', b'127.0.0.1:8443', deadline=3)
        self.assertEqual(stream.tell(), 2)

    def test_private_original_refuses_aliases_links_overflow_and_shared_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); p = root / 'original'
            p.write_bytes(b'private'); p.chmod(0o600)
            self.assertEqual(service.private_bytes(str(p), 7), b'private')
            with self.assertRaises(service.Refused): service.private_bytes(str(p), 6)
            alias = root / 'alias'; alias.symlink_to(p)
            with self.assertRaises((service.Refused, OSError)): service.private_bytes(str(alias), 7)
            hard = root / 'hard'; os.link(p, hard)
            with self.assertRaises(service.Refused): service.private_bytes(str(p), 7)
            hard.unlink(); p.chmod(0o644)
            with self.assertRaises(service.Refused): service.private_bytes(str(p), 7)
            with self.assertRaises(service.Refused): service.private_bytes('relative', 7)
            p.chmod(0o600); root.chmod(0o755)
            with self.assertRaises(service.Refused): service.private_bytes(str(p), 7)
            root.chmod(0o700)
            fifo = root / 'fifo'; os.mkfifo(fifo, 0o600)
            with self.assertRaises(service.Refused): service.private_bytes(str(fifo), 7)

    def test_retained_source_rejects_permission_links_namespace_and_ancestor_changes(self):
        for mutation in ('mode', 'hardlink', 'replacement', 'ancestor'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(); folder = root / 'private'; folder.mkdir(mode=0o700)
                p = folder / 'original'; p.write_bytes(b'private'); p.chmod(0o600)
                with service.SelectedFile(str(p), 7) as selected:
                    self.assertEqual(selected.read(), b'private')
                    if mutation == 'mode': p.chmod(0o644)
                    elif mutation == 'hardlink': os.link(p, folder / 'alias')
                    elif mutation == 'replacement':
                        p.rename(folder / 'old'); p.write_bytes(b'private'); p.chmod(0o600)
                    else:
                        folder.rename(root / 'old'); folder.mkdir(mode=0o700)
                        p.write_bytes(b'private'); p.chmod(0o600)
                    with self.assertRaises(service.Refused): selected.revalidate()

    def test_current_directory_contents_may_change_without_changing_custody(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with service.DirectoryCustody(str(root), private=True) as custody:
                current = root / 'current.json'; current.write_bytes(b'one'); current.chmod(0o600)
                other = root / 'next.json'; other.write_bytes(b'two'); other.chmod(0o600)
                other.replace(current)
                custody.revalidate()
                self.assertEqual(current.read_bytes(), b'two')
                root.chmod(0o755)
                with self.assertRaises(service.Refused): custody.revalidate()
                root.chmod(0o700)

    def test_untrusted_ancestor_and_symlink_directory_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); shared = root / 'shared'; shared.mkdir(mode=0o777); shared.chmod(0o777)
            child = shared / 'private'; child.mkdir(mode=0o700)
            with self.assertRaises(service.Refused): service.DirectoryCustody(str(child), private=True)
            shared.chmod(0o700); link = root / 'link'; link.symlink_to(child)
            with self.assertRaises((service.Refused, OSError)): service.DirectoryCustody(str(link), private=True)

    def test_configuration_rejects_duplicate_names(self):
        with self.assertRaises(service.Refused):
            json.loads('{"port":8443,"port":8444}', object_pairs_hook=service.unique_object)
        self.assertEqual(service.unique_object([('port', 8443)]), {'port': 8443})

    def test_nonlinux_execution_fails_closed(self):
        with mock.patch.object(service.sys, 'platform', 'darwin'):
            with self.assertRaises(service.Refused): service.Configuration('/no/path/is/opened')
            with self.assertRaises(service.Refused): service.SelectedExecutable('/no/path/is/opened', 'a' * 64)


@unittest.skipUnless(sys.platform == 'linux', 'Linux sealed descriptor/TLS tests require the Linux runner')
class LinuxCustody(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)
        cc = shutil.which('cc')
        if cc is None:
            self.fail('Linux custody tests require cc for a clearly non-Native fixture')
        source = self.root / 'fixture.c'
        source.write_text(r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2 || getenv("KAGEMUSHA_FIXTURE_ENV")) return 9;
    char path[4096], mode[32] = {0};
    if (snprintf(path, sizeof(path), "%s/mode", argv[1]) >= sizeof(path)) return 8;
    FILE *f = fopen(path, "r"); if (!f) return 7;
    fgets(mode, sizeof(mode), f); fclose(f);
    if (!strcmp(mode, "fail")) return 1;
    if (!strcmp(mode, "empty")) return 0;
    if (!strcmp(mode, "timeout")) { sleep(10); return 0; }
    if (!strcmp(mode, "huge")) { for (;;) putchar('x'); }
    snprintf(path, sizeof(path), "%s/invoked", argv[1]);
    f = fopen(path, "a"); if (!f) return 6; fputs("call\n", f); fclose(f);
    printf("valid-original"); return 0;
}
''')
        self.adapter = self.root / 'adapter'
        subprocess.run([cc, str(source), '-o', str(self.adapter)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.adapter.chmod(0o700)
        self.digest = hashlib.sha256(self.adapter.read_bytes()).hexdigest()

    def mode(self, value):
        (self.root / 'mode').write_text(value)

    def test_adapter_failure_empty_oversize_and_timeout_never_return_success(self):
        with service.SelectedExecutable(str(self.adapter), self.digest) as selected, \
                service.DirectoryCustody(str(self.root), private=True) as directory:
            for mode in ('fail', 'empty', 'huge', 'timeout', 'success'):
                self.mode(mode)
                with self.subTest(mode=mode):
                    if mode == 'success':
                        with mock.patch.dict(os.environ, {'KAGEMUSHA_FIXTURE_ENV': 'must-not-leak'}):
                            self.assertEqual(service.invoke(selected, directory, b'input', 1), b'valid-original')
                    else:
                        started = time.monotonic()
                        with self.assertRaises((service.Refused, OSError, subprocess.SubprocessError)):
                            service.invoke(selected, directory, b'input', 1)
                        self.assertLess(time.monotonic() - started, 3)

    def test_sealed_descriptor_rejects_writes_resize_and_nonelf_adapter(self):
        with service.SelectedExecutable(str(self.adapter), self.digest) as selected:
            with self.assertRaises(OSError): os.pwrite(selected.image.fd, b'bad', 0)
            with self.assertRaises(OSError): os.ftruncate(selected.image.fd, 1)
            selected.revalidate()
            descriptor = selected.image.fd
        with self.assertRaises(OSError): os.fstat(descriptor)
        script = self.root / 'script'; script.write_bytes(b'#!/bin/sh\nprintf unsafe'); script.chmod(0o700)
        with self.assertRaises(service.Refused):
            service.SelectedExecutable(str(script), hashlib.sha256(script.read_bytes()).hexdigest())
        with self.assertRaises(service.Refused): service.SelectedExecutable(str(self.adapter), '0' * 64)

    def test_source_replacement_cannot_select_other_executable(self):
        self.mode('success')
        with service.SelectedExecutable(str(self.adapter), self.digest) as selected, \
                service.DirectoryCustody(str(self.root), private=True) as directory:
            original_popen = service.subprocess.Popen
            def swap_before_exec(argv, **kwargs):
                self.assertEqual(argv[0], selected.image.path)
                self.assertEqual(kwargs['pass_fds'], (selected.image.fd,))
                self.assertEqual(kwargs['env'], {})
                self.adapter.rename(self.root / 'former-adapter')
                self.adapter.write_bytes(b'#!/bin/sh\ntouch '+str(self.root / 'unselected-executed').encode()+b'\n')
                self.adapter.chmod(0o700)
                return original_popen(argv, **kwargs)
            with mock.patch.object(service.subprocess, 'Popen', side_effect=swap_before_exec):
                with self.assertRaises(service.Refused): service.invoke(selected, directory, b'input', 2)
            self.assertFalse((self.root / 'unselected-executed').exists())

    def configure(self):
        openssl = shutil.which('openssl')
        if openssl is None: self.fail('Linux TLS custody tests require openssl for ephemeral local fixtures')
        certificate, key = self.root / 'cert.pem', self.root / 'tls.key'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-keyout', str(key), '-out', str(certificate)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        certificate.chmod(0o600); key.chmod(0o600)
        token = self.root / 'token'; token.write_bytes(b'fixture-token'); token.chmod(0o600)
        config = self.root / 'config.json'
        value = dict(port=8443, certificate=str(certificate), tls_key=str(key), transport_token=str(token),
                     adapter=str(self.adapter), adapter_sha256=self.digest,
                     operator_directory=str(self.root), timeout_seconds=2)
        config.write_text(json.dumps(value)); config.chmod(0o600)
        return config, certificate, key

    def test_real_tls_context_loads_only_selected_sealed_originals(self):
        config, certificate, key = self.configure()
        real_load = service.selected_tls_context
        paths = []
        def capture(cert, secret):
            paths.extend((cert.path, secret.path))
            self.assertEqual(Path(cert.path).read_bytes(), certificate.read_bytes())
            self.assertEqual(Path(secret.path).read_bytes(), key.read_bytes())
            return real_load(cert, secret)
        with mock.patch.object(service, 'selected_tls_context', side_effect=capture):
            with service.Configuration(str(config)) as selected:
                self.assertTrue(all(p.startswith('/proc/self/fd/') for p in paths))
                self.assertEqual(selected.context.minimum_version, service.ssl.TLSVersion.TLSv1_2)
                selected.revalidate()
                key.chmod(0o644)
                with self.assertRaises(service.Refused): selected.revalidate()

    def test_tls_source_substitution_during_load_refuses_startup(self):
        config, certificate, key = self.configure()
        real_load = service.selected_tls_context
        def swap(cert, secret):
            old = key.read_bytes(); key.rename(key.with_suffix('.former'))
            key.write_bytes(old); key.chmod(0o600)
            return real_load(cert, secret)
        with mock.patch.object(service, 'selected_tls_context', side_effect=swap):
            with self.assertRaises(service.Refused): service.Configuration(str(config))

    def test_loopback_https_authenticates_before_invocation_and_checks_retained_custody(self):
        config, certificate, key = self.configure()
        self.mode('success')
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        value = json.loads(config.read_text()); value['port'] = port
        config.write_text(json.dumps(value))
        process = subprocess.Popen([sys.executable, str(Path(service.__file__).resolve()),
                                    '--config', str(config)], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env={'PYTHONDONTWRITEBYTECODE': '1'})
        try:
            end = time.monotonic() + 5
            while True:
                self.assertIsNone(process.poll(), 'test service exited before listening')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= end: self.fail('test service did not start')
                    time.sleep(0.02)
            tls_context = ssl.create_default_context(cafile=str(certificate))
            def request(token):
                original = (f'POST /eligibility HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
                            'Content-Type: application/x-norito\r\nAccept: application/x-norito\r\n'
                            f'Authorization: Bearer {token}\r\nContent-Length: 1\r\n\r\nx').encode()
                with socket.create_connection(('127.0.0.1', port), timeout=2) as connected:
                    with tls_context.wrap_socket(connected, server_hostname='localhost') as tls:
                        tls.sendall(original)
                        result = bytearray()
                        while True:
                            part = tls.recv(4096)
                            if not part: return bytes(result)
                            result.extend(part)
            self.assertTrue(request('wrong').startswith(b'HTTP/1.1 503 '))
            self.assertFalse((self.root / 'invoked').exists())
            response = request('fixture-token')
            self.assertTrue(response.startswith(b'HTTP/1.1 200 '))
            self.assertTrue(response.endswith(b'\r\n\r\nvalid-original'))
            self.assertEqual((self.root / 'invoked').read_text(), 'call\n')
            key.chmod(0o644)
            with self.assertRaises((OSError, ssl.SSLError)):
                request('fixture-token')
            self.assertEqual((self.root / 'invoked').read_text(), 'call\n')
        finally:
            # This is only the throwaway service process created by this test.
            if process.poll() is None: process.terminate()
            process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
