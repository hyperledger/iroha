"""Synthetic loopback HTTP and injected-process controls, never trial evidence."""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/nexus'))
import resource_probe as probe
import resource_process as process
import kura_resource_metrics as metrics
from resource_evidence_budget import CapturePolicy

POLICY = CapturePolicy(status_body_bytes=probe.MAX_STATUS_BYTES, metrics_body_bytes=metrics.MAX_RESPONSE_BYTES)


def inventory(storage=8192, represented=3):
    rows = ['iroha_kura_resource_available 1', 'iroha_kura_resource_status{reason="available"} 1',
            'iroha_kura_resource_generation 17', 'iroha_kura_resource_fault_count 0']
    fields = ('resident_associations', 'persisted_entries', 'index_bytes', 'temporary_index_bytes', 'storage_bytes')
    totals = (represented, 0, 0, 0, storage)
    for family in metrics.FAMILIES:
        for field in fields:
            value = represented if family == 'resident_canonical' and field == 'resident_associations' else (
                storage if family == 'storage_bytes' and field == 'storage_bytes' else 0)
            rows.append(f'iroha_kura_resource_{field}{{family="{family}"}} {value}')
    rows.extend(f'iroha_kura_resource_{field}_sum {value}' for field, value in zip(fields, totals, strict=True))
    rows.append(f'iroha_kura_resource_represented_entries {represented}')
    return ('\n'.join(rows) + '\n').encode()


def response(body=b'{"queue_size":7}', content_type=b'application/json', headers=b'', status=b'200 OK', framing='length'):
    if framing == 'length':
        headers += b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
    elif framing == 'chunked':
        headers += b'Transfer-Encoding: chunked\r\n'
        body = f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n\r\n'
    return b'HTTP/1.1 ' + status + b'\r\nContent-Type: ' + content_type + b'\r\n' + headers + b'\r\n' + body


@contextmanager
def server(responder):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(16)
    listener.settimeout(.05)
    stopped = threading.Event()
    requests = []
    failures = []

    def serve():
        while not stopped.is_set():
            try:
                stream, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with stream:
                stream.settimeout(1)
                request = bytearray()
                try:
                    while b'\r\n\r\n' not in request:
                        chunk = stream.recv(4096)
                        if not chunk:
                            break
                        request.extend(chunk)
                        if len(request) > 65536:
                            raise AssertionError('test request too large')
                    requests.append(bytes(request))
                    result = responder(bytes(request)) if callable(responder) else responder
                    if isinstance(result, tuple):
                        if len(result) == 3:
                            head, raw, delay = result
                            stream.sendall(head)
                        else:
                            raw, delay = result
                        for byte in raw:
                            if stopped.is_set():
                                break
                            stream.sendall(bytes([byte]))
                            time.sleep(delay)
                    else:
                        stream.sendall(result)
                except (BrokenPipeError, ConnectionResetError, socket.timeout):
                    pass
                except BaseException as error:
                    failures.append(error)
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield f'http://127.0.0.1:{listener.getsockname()[1]}', requests
    finally:
        stopped.set()
        listener.close()
        worker.join(2)
        assert not worker.is_alive()
        assert failures == []


class Reader:
    def __init__(self):
        self.counts = {}
        self.change_after = None
        self.fail_after = None

    def sample(self, pid, _image):
        count = self.counts.get(pid, 0) + 1
        self.counts[pid] = count
        if self.fail_after is not None and count >= self.fail_after:
            raise OSError('private path /secrets/never-print-me')
        generation = 2 if self.change_after is not None and count >= self.change_after else 1
        identity = process.ProcessIdentity(pid, 501, generation, 0, generation,
                                           '01' * 16, 'a' * 64)
        return process.ProcessSample(identity, 1000 + pid + count)


def targets(url, count=4, reader=None):
    reader = reader or Reader()
    return tuple(probe.PeerTarget(process.PinnedProcess(f'peer{i}', 100 + i, SimpleNamespace(), reader),
                                  probe.Endpoint.parse(url + f'/peer{i}')) for i in range(count))


def regular(request):
    path = request.split(b' ')[1]
    if path.endswith(b'/metrics'):
        return response(inventory(), b'text/plain; version=0.0.4; charset=utf-8')
    return response()


def test_complete_fixed_peer_observation_retains_raw_replay_and_checked_aggregates():
    with server(regular) as (url, requests):
        reader = Reader()
        result = probe.Probe(targets(url, reader=reader), POLICY).collect(2)
        assert len(requests) == 8
        assert all(request.count(b'Connection: close') == 1 for request in requests)
        assert [request.split(b' ')[1].decode() for request in requests] == [
            f'/peer{i}/{route}' for i in range(4) for route in ('status', 'metrics')]
    assert result.available is True
    assert result.inventory.storage_bytes == 4 * 8192
    assert result.inventory.represented_entries == 4 * 3
    assert result.queue_size_sum == 28
    assert result.queue_size_max == 7
    assert result.rss_before_bytes == sum(1000 + pid + 2 for pid in range(100, 104))
    assert result.rss_after_bytes == sum(1000 + pid + 3 for pid in range(100, 104))
    assert 0 < result.local_elapsed_ns < 2_000_000_000
    assert result.wire_bytes > sum(peer.status.body_bytes + peer.metrics.body_bytes for peer in result.peers)
    assert reader.counts == {pid: 3 for pid in range(100, 104)}
    for peer in result.peers:
        assert metrics.parse_kura_resource_metrics(peer.metrics.raw_body) == peer.kura
        assert probe._status_queue(peer.status.raw_body) == peer.queue_size
        for observed in (peer.status, peer.metrics):
            assert observed.body_sha256 == hashlib.sha256(observed.raw_body).hexdigest()
            assert observed.body_bytes == len(observed.raw_body)
        assert peer.process_before.identity == peer.process_after.identity
    assert not hasattr(result, 'timestamp_ms')
    assert not hasattr(result, 'index_peer_id')


@pytest.mark.parametrize('reason', tuple(reason.value for reason in metrics.UnavailableReason))
def test_unavailable_retains_all_peers_and_raw_reason_without_aggregate(reason):
    missing = f'iroha_kura_resource_available 0\niroha_kura_resource_status{{reason="{reason}"}} 1\n'.encode()
    def respond(request):
        if request.split(b' ')[1] == b'/peer2/metrics':
            return response(missing, b'text/plain')
        return regular(request)
    with server(respond) as (url, requests):
        result = probe.Probe(targets(url), POLICY).collect(2)
        assert len(requests) == 8
    assert result.available is False
    assert result.inventory is None
    assert len(result.peers) == 4
    assert result.peers[2].metrics.raw_body == missing
    assert result.peers[2].kura.reason.value == reason
    assert not hasattr(result.peers[2].kura, 'generation')


@pytest.mark.parametrize('framing', ['length', 'chunked', 'close'])
def test_actual_response_framing_success(framing):
    raw = b'{"queue_size":9}'
    with server(response(raw, framing=framing)) as (url, _):
        body, provenance = probe._fetch(probe.Endpoint.parse(url), '/status', probe._Deadline(1), POLICY)
    assert body == raw == provenance.raw_body
    assert provenance.body_sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize('raw,code', [
    (response(status=b'301 Moved', headers=b'Location: http://secret.example/token\r\n'), 'http_status_invalid'),
    (response(status=b'503 Busy'), 'http_status_invalid'),
    (response(status=b'401 No'), 'http_status_invalid'),
    (b'HTTP/1.1 100 Continue\r\n\r\n' + response(), 'http_status_invalid'),
    (response(headers=b'Content-Length: 16\r\n'), 'http_headers_duplicate'),
    (response(headers=b'Transfer-Encoding: chunked\r\n'), 'http_framing_ambiguous'),
    (response(content_type=b'text/html'), 'http_content_type_invalid'),
    (response(headers=b'Content-Encoding: gzip\r\n'), 'http_content_encoding_invalid'),
    (response(headers=b'Bad : value\r\n'), 'http_headers_invalid'),
    (response(headers=b'Fold: one\r\n two\r\n'), 'http_headers_invalid'),
    (response(headers=b'X: a\r\nx: b\r\n'), 'http_headers_duplicate'),
    (response()[:-2], 'http_truncated'),
    (response() + b'garbage', 'http_trailing_data'),
    (response(headers=b'Content-Length: -1\r\n', framing='close'), 'http_length_invalid'),
    (response(headers=b'Content-Length: 10000000000\r\n', framing='close'), 'http_length_invalid'),
    (response(headers=b'Content-Length: 1048577\r\n', framing='close'), 'http_body_exceeded'),
    (response(headers=b'Transfer-Encoding: gzip\r\n', framing='close'), 'http_transfer_invalid'),
    (response(b'1;x=y\r\na\r\n0\r\n\r\n', headers=b'Transfer-Encoding: chunked\r\n', framing='close'), 'http_chunk_invalid'),
    (response(b'1\r\naXX0\r\n\r\n', headers=b'Transfer-Encoding: chunked\r\n', framing='close'), 'http_chunk_invalid'),
    (response(b'0\r\nX: ignored\r\n\r\n', headers=b'Transfer-Encoding: chunked\r\n', framing='close'), 'http_trailer_invalid'),
    (response(b'100001\r\n', headers=b'Transfer-Encoding: chunked\r\n', framing='close'), 'http_body_exceeded'),
    (b'HTTP/1.1 200 OK\r\nX:' + b'a' * 8192 + b'\r\n\r\n', 'http_line_exceeded'),
    (response(headers=b''.join(f'X{i}: a\r\n'.encode() for i in range(129))), 'http_headers_exceeded'),
    (response(headers=b''.join(f'X{i}: '.encode() + b'a' * 8100 + b'\r\n' for i in range(5))), 'http_headers_exceeded'),
])
def test_http_protocol_errors_are_closed_and_never_redirect(raw, code):
    with server(raw) as (url, requests):
        with pytest.raises(probe.ProbeError) as error:
            probe._fetch(probe.Endpoint.parse(url), '/status', probe._Deadline(1), POLICY)
        assert len(requests) == 1
    assert str(error.value) == code
    assert 'secret' not in str(error.value)


def test_aggregate_header_refusal_stops_at_original_framing_capacity():
    raw = response(headers=b''.join(
        f'X{i}: '.encode() + b'a' * 8100 + b'\r\n' for i in range(5)))

    class Stream:
        def __init__(self): self.offset = 0
        def settimeout(self, _): pass
        def recv(self, count):
            data = raw[self.offset:self.offset + count]
            self.offset += len(data)
            return data

    stream = Stream()
    with pytest.raises(probe.ProbeError, match='http_headers_exceeded'):
        probe._response(probe._Reader(stream, probe._Deadline(1)), '/status', 32)
    assert stream.offset == probe.MAX_HEADER_BYTES
    assert stream.offset < raw.index(b'\r\n\r\n') + 4


@pytest.mark.parametrize('extra', [0, 1])
def test_aggregate_header_exact_boundary_keeps_body_admission(extra):
    headers = b''.join(f'X{i}: '.encode() + b'a' * 8100 + b'\r\n' for i in range(4))
    empty = response(headers=headers + b'X4: \r\n')
    padding = probe.MAX_HEADER_BYTES - (empty.index(b'\r\n\r\n') + 4)
    raw = response(headers=headers + b'X4: ' + b'a' * (padding + extra) + b'\r\n')
    assert raw.index(b'\r\n\r\n') + 4 == probe.MAX_HEADER_BYTES + extra

    class Stream:
        def __init__(self): self.offset = 0
        def settimeout(self, _): pass
        def recv(self, count):
            data = raw[self.offset:self.offset + count]
            self.offset += len(data)
            return data

    stream = Stream()
    reader = probe._Reader(stream, probe._Deadline(1))
    if extra:
        with pytest.raises(probe.ProbeError, match='http_headers_exceeded'):
            probe._response(reader, '/status', 32)
        assert stream.offset <= probe.MAX_HEADER_BYTES
    else:
        body, content_type = probe._response(reader, '/status', 32)
        assert body == b'{"queue_size":7}'
        assert content_type == 'application/json'
        assert stream.offset == len(raw)


@pytest.mark.parametrize('length', [0, 1, probe.MAX_LINE_BYTES])
def test_fragmented_line_search_is_linear_without_plaintext_read_ahead(length):
    raw = b'a' * length + b'\r\n' + b'unadmitted-body'

    class Stream:
        def __init__(self): self.offset = 0
        def settimeout(self, _): pass
        def recv(self, count):
            data = raw[self.offset:self.offset + count]
            self.offset += len(data)
            return data

    class ScanCounter(bytearray):
        searched = 0
        def find(self, value, start=0):
            self.searched += len(self) - start
            return super().find(value, start)

    stream = Stream()
    reader = probe._Reader(stream, probe._Deadline(1))
    reader.buffer = ScanCounter()
    assert reader.line() == b'a' * length
    assert stream.offset == length + 2
    assert reader.buffer == b''
    assert reader.buffer.searched <= 3 * (length + 2)


@pytest.mark.parametrize('phase', ['headers', 'body'])
def test_slow_drip_uses_one_absolute_deadline(phase):
    raw = response(b'{"queue_size":7}')
    if phase == 'body':
        def respond(_):
            # Enough progress per read to defeat a reset-on-read timeout.
            head, body = raw.split(b'\r\n\r\n', 1)
            return head + b'\r\n\r\n', body, .02
    else:
        def respond(_):
            return raw, .006
    started = time.monotonic()
    with server(respond) as (url, _):
        with pytest.raises(probe.ProbeError, match='deadline_exceeded'):
            probe._fetch(probe.Endpoint.parse(url), '/status', probe._Deadline(.08), POLICY)
    assert time.monotonic() - started < .8


@pytest.mark.parametrize('raw,code', [
    (b'{}', 'status_queue_invalid'), (b'[]', 'status_queue_invalid'),
    (b'{"queue_size":true}', 'status_queue_invalid'), (b'{"queue_size":"1"}', 'status_queue_invalid'),
    (b'{"queue_size":1.0}', 'status_queue_invalid'), (b'{"queue_size":-1}', 'status_queue_invalid'),
    (b'{"queue_size":9007199254740993}', 'status_queue_invalid'),
    (b'{"queue_size":1,"queue_size":2}', 'status_duplicate_key'),
    (b'{"queue_size":1,"other":{"x":1,"x":2}}', 'status_duplicate_key'),
    (b'{"queue_size":NaN}', 'status_number_invalid'),
    (b'{"queue_size":1,"x":1e9999}', 'status_number_invalid'),
    (b'{"queue_size":' + b'1' * 129 + b'}', 'status_number_exceeded'),
    (b'{"queue_size":0}' + b'{}', 'status_json_invalid'),
    (b'\xff', 'status_json_invalid'),
    (b'[' * 65 + b']' * 65, 'status_depth_exceeded'),
    (b'', 'status_size_invalid'), (b' ' * (probe.MAX_STATUS_BYTES + 1), 'status_size_invalid'),
])
def test_status_requires_exact_fresh_queue_and_bounded_json(raw, code):
    with pytest.raises(probe.ProbeError, match=code):
        probe._status_queue(raw)


def test_status_extra_fields_and_exact_integer_limit_are_supported():
    assert probe._status_queue(b'{"queue_size":9007199254740992,"nested":["[{}]",1.5]}') == 2**53
    assert probe._status_queue(b'{"queue_size":0}') == 0


@pytest.mark.parametrize('url', [
    'http://localhost:1234', 'ftp://127.0.0.1', 'http://u:p@127.0.0.1',
    'http://127.0.0.1/?token=secret', 'http://127.0.0.1/#secret',
    'http://127.0.0.1/?', 'http://127.0.0.1/#', 'http://127.0.0.1:0',
    'http://127.0.0.1:65536', 'http://0.0.0.0', 'http://224.0.0.1',
    'http://127.0.0.1/../escape', 'http://127.0.0.1/%2ftoken',
    'http://127.0.0.1/\r\nHost:bad', 'http://[fe80::1%lo0]', 'http://127.0.0.1/space here',
])
def test_endpoint_rejects_dns_ambiguity_and_credentials(url):
    with pytest.raises(probe.ProbeError, match='endpoint_invalid'):
        probe.Endpoint.parse(url)


@pytest.mark.parametrize('headers', [
    (('Host', 'secret'),), (('Connection', 'secret'),), (('x-secret', 'a\r\nb'),),
    (('bad name', 'a'),), (('x', 'a'), ('X', 'b')), (('x', ''),),
    (('x', 'a' * 4097),), (('x', '\u2603'),), (('proxy-authorization', 'token'),),
])
def test_secret_headers_cannot_override_transport_or_inject(headers):
    with pytest.raises(probe.ProbeError, match='headers_invalid'):
        probe.Endpoint.parse('http://127.0.0.1', headers)


def test_authentication_is_runtime_only_and_echoed_secrets_are_not_retained():
    secret = 'VeryPrivateToken-value-8392'
    headers = (('Authorization', 'Bearer ' + secret),)
    with server(response(b'{"queue_size":1,"echo":"' + secret.encode() + b'"}')) as (url, requests):
        endpoint = probe.Endpoint.parse(url, headers)
        assert secret not in repr(endpoint)
        with pytest.raises(probe.ProbeError, match='response_contains_credentials') as error:
            probe._fetch(endpoint, '/status', probe._Deadline(1), POLICY)
        assert secret.encode() in requests[0]
    assert secret not in str(error.value)


@pytest.mark.parametrize('change,code', [('restart', 'process_observation_failed'), ('error', 'process_observation_failed')])
def test_process_after_all_http_rejects_restart_and_scrubs_os_diagnostics(change, code):
    reader = Reader()
    reader.change_after = 3 if change == 'restart' else None
    reader.fail_after = 3 if change == 'error' else None
    with server(regular) as (url, requests):
        with pytest.raises(probe.ProbeError, match=code) as error:
            probe.Probe(targets(url, reader=reader), POLICY).collect(2)
        assert len(requests) == 8
    assert 'private' not in str(error.value)


@pytest.mark.parametrize('mutation', ['three', 'pid', 'peer', 'endpoint'])
def test_scope_requires_complete_distinct_processes_peers_and_endpoints(mutation):
    peers = targets('http://127.0.0.1:1234')
    if mutation == 'three':
        peers = peers[:3]
    elif mutation == 'endpoint':
        peers = (*peers[:3], replace(peers[3], endpoint=peers[0].endpoint))
    else:
        setattr(peers[3].process, 'pid' if mutation == 'pid' else 'peer_id',
                peers[0].process.pid if mutation == 'pid' else peers[0].process.peer_id)
    with pytest.raises(probe.ProbeError, match='peer_scope_invalid'):
        probe.Probe(peers, POLICY)


@pytest.mark.parametrize('field', ['storage', 'represented', 'queue'])
def test_aggregate_limits_apply_to_all_peers_and_never_saturate(field):
    def respond(request):
        if request.split(b' ')[1].endswith(b'/metrics'):
            return response(inventory(storage=2**53 if field == 'storage' else 1,
                                      represented=2**53 if field == 'represented' else 1), b'text/plain')
        return response(b'{"queue_size":9007199254740992}' if field == 'queue' else b'{"queue_size":1}')
    with server(respond) as (url, _):
        with pytest.raises(probe.ProbeError, match='aggregate_outside_exact_range'):
            probe.Probe(targets(url), POLICY).collect(2)


def test_transport_failure_is_static_and_does_not_read_proxy_environment(monkeypatch):
    monkeypatch.setenv('HTTP_PROXY', 'http://user:secret@127.0.0.1:1')
    with server(response()) as (url, _):
        assert probe._fetch(probe.Endpoint.parse(url), '/status', probe._Deadline(1), POLICY)[0]
    with pytest.raises(probe.ProbeError, match='http_transport_failed'):
        probe._fetch(probe.Endpoint.parse(url), '/status', probe._Deadline(1), POLICY)


@pytest.mark.parametrize('timeout', [0, -1, 61, float('inf'), float('nan'), True, '1', 10**1000])
def test_deadline_must_be_bounded_positive_numeric(timeout):
    with pytest.raises(probe.ProbeError, match='deadline_invalid'):
        probe._Deadline(timeout)


def test_one_deadline_includes_process_sampling_and_parsing(monkeypatch):
    clock = [10_000_000_000]
    monkeypatch.setattr(probe.time, 'monotonic_ns', lambda: clock[0])
    def slow_sample(_):
        clock[0] += 2_000_000_000
        return ()
    monkeypatch.setattr(probe, 'sample_peers', slow_sample)
    with pytest.raises(probe.ProbeError, match='deadline_exceeded'):
        probe.Probe(targets('http://127.0.0.1:1234'), POLICY).collect(1)


def test_whole_probe_wire_budget_and_chunk_count_are_enforced(monkeypatch):
    monkeypatch.setattr(probe, 'MAX_PROBE_WIRE_BYTES', 10)
    with server(response()) as (url, _):
        with pytest.raises(probe.ProbeError, match='probe_size_exceeded'):
            probe._fetch(probe.Endpoint.parse(url), '/status', probe._Deadline(1), POLICY)
    monkeypatch.setattr(probe, 'MAX_PROBE_WIRE_BYTES', 64 * 1024 * 1024)
    raw = response(b'1\r\na\r\n' * probe.MAX_CHUNKS + b'0\r\n\r\n',
                   headers=b'Transfer-Encoding: chunked\r\n', framing='close')
    with server(raw) as (url, _):
        with pytest.raises(probe.ProbeError, match='http_chunks_exceeded'):
            probe._fetch(probe.Endpoint.parse(url), '/status', probe._Deadline(1), POLICY)


@pytest.mark.parametrize("mutation", ["dns", "request_injection", "headers", "port"])
def test_direct_endpoint_constructor_cannot_bypass_closed_validation(mutation):
    args = ["http", "127.0.0.1", 1234, "", ()]
    if mutation == "dns": args[1] = "example.org"
    if mutation == "request_injection": args[3] = "/path\r\nHost: secret"
    if mutation == "headers": args[4] = (("Host", "secret"),)
    if mutation == "port": args[2] = True
    with pytest.raises(probe.ProbeError):
        probe.Endpoint(*args)


def test_scope_mutation_after_initialization_is_rejected_before_http():
    peers = targets("http://127.0.0.1:1234")
    collector = probe.Probe(peers, POLICY)
    peers[0].process.peer_id = "replacement"
    with pytest.raises(probe.ProbeError, match="peer_scope_changed"):
        collector.collect(1)


def test_complete_metric_parse_is_inside_absolute_deadline(monkeypatch):
    clock = [10_000_000_000]
    monkeypatch.setattr(probe.time, 'monotonic_ns', lambda: clock[0])
    original = probe.parse_kura_resource_metrics
    def delayed_parse(raw):
        result = original(raw)
        clock[0] += 2_000_000_000
        return result
    monkeypatch.setattr(probe, 'parse_kura_resource_metrics', delayed_parse)
    with server(regular) as (url, requests):
        with pytest.raises(probe.ProbeError, match="deadline_exceeded"):
            probe.Probe(targets(url), POLICY).collect(1)
        assert len(requests) == 2


def test_malformed_kura_is_not_a_partial_success_or_previous_value():
    def respond(request):
        if request.split(b' ')[1] == b'/peer1/metrics':
            return response(b'iroha_kura_resource_available 1\n', b'text/plain')
        return regular(request)
    with server(respond) as (url, requests):
        with pytest.raises(probe.ProbeError, match="kura_projection_invalid"):
            probe.Probe(targets(url), POLICY).collect(2)
        assert len(requests) == 4


def test_process_failure_before_requests_does_not_emit_raw_os_error():
    reader = Reader()
    reader.fail_after = 2
    with server(regular) as (url, requests):
        with pytest.raises(probe.ProbeError, match="process_observation_failed") as error:
            probe.Probe(targets(url, reader=reader), POLICY).collect(1)
        assert requests == []
        assert "never-print-me" not in str(error.value)


def test_https_default_verification_is_never_disabled(monkeypatch):
    called = []
    original = probe.ssl.create_default_context
    def verified_context():
        context = original()
        assert context.check_hostname is True
        assert context.verify_mode == probe.ssl.CERT_REQUIRED
        called.append(True)
        return context
    monkeypatch.setattr(probe.ssl, 'create_default_context', verified_context)
    # Plain synthetic HTTP cannot impersonate a trusted TLS endpoint.
    with server(b'not TLS') as (url, _):
        with pytest.raises(probe.ProbeError):
            probe._fetch(probe.Endpoint.parse(url.replace('http:', 'https:')),
                         '/status', probe._Deadline(.15), POLICY)
    assert called == [True]


@pytest.mark.parametrize("change", ["host", "port", "base_path", "scheme", "headers"])
def test_endpoint_replacement_with_same_peer_and_pid_fails_before_any_observation(change, monkeypatch):
    peers = targets("http://127.0.0.1:1234")
    collector = probe.Probe(peers, POLICY)
    endpoint = peers[0].endpoint
    replacement = {"host": "127.0.0.2", "port": 1235, "base_path": "/replacement",
                   "scheme": "https", "headers": (("authorization", "Bearer NeverExpose"),)}[change]
    collector.peers = (replace(peers[0], endpoint=replace(endpoint, **{change: replacement})), *peers[1:])
    calls = []
    monkeypatch.setattr(probe, 'sample_peers', lambda _: calls.append('process'))
    monkeypatch.setattr(probe, '_fetch', lambda *_: calls.append('http'))
    with pytest.raises(probe.ProbeError, match="peer_scope_changed") as error:
        collector.collect(1)
    assert calls == []
    assert str(error.value) == "peer_scope_changed"
    assert "NeverExpose" not in repr(collector._scope)


@pytest.mark.parametrize("change", ["new_lifetime_owner", "equal_lifetime_owner", "identity", "image", "reader"])
def test_same_pid_process_lifetime_or_owner_replacement_fails_before_io(change, monkeypatch):
    peers = targets("http://127.0.0.1:1234")
    collector = probe.Probe(peers, POLICY)
    original = peers[0].process
    if change in ("new_lifetime_owner", "equal_lifetime_owner"):
        reader = Reader()
        reader.change_after = 1 if change == "new_lifetime_owner" else None
        replacement = process.PinnedProcess(original.peer_id, original.pid, SimpleNamespace(), reader)
        collector.peers = (replace(peers[0], process=replacement), *peers[1:])
    elif change == "identity":
        original.identity = replace(original.identity, start_seconds=2, start_abstime=2)
    elif change == "image":
        original.image = SimpleNamespace()
    else:
        original.reader = Reader()
    calls = []
    monkeypatch.setattr(probe, 'sample_peers', lambda _: calls.append('process'))
    monkeypatch.setattr(probe, '_fetch', lambda *_: calls.append('http'))
    with pytest.raises(probe.ProbeError, match="peer_scope_changed"):
        collector.collect(1)
    assert calls == []


def test_equal_immutable_endpoint_values_keep_the_original_admitted_scope():
    with server(regular) as (url, requests):
        peers = targets(url)
        collector = probe.Probe(peers, POLICY)
        collector.peers = (replace(peers[0], endpoint=replace(peers[0].endpoint)), *peers[1:])
        result = collector.collect(2)
        assert result.available
        assert len(requests) == 8


def test_removed_peer_scope_fails_before_io(monkeypatch):
    peers = targets("http://127.0.0.1:1234")
    collector = probe.Probe(peers, POLICY)
    collector.peers = peers[:3]
    calls = []
    monkeypatch.setattr(probe, 'sample_peers', lambda _: calls.append('process'))
    with pytest.raises(probe.ProbeError, match="peer_scope_changed"):
        collector.collect(1)
    assert calls == []


@pytest.mark.parametrize('route', ['/status', '/metrics'])
@pytest.mark.parametrize('framing', ['length', 'chunked', 'close'])
@pytest.mark.parametrize('extra', [0, 1])
def test_actual_http_enforces_explicit_policy_at_body_boundary(route, framing, extra):
    policy = CapturePolicy(status_body_bytes=32, metrics_body_bytes=32)
    raw = b'x' * (32 + extra)
    content_type = b'application/json' if route == '/status' else b'text/plain'
    with server(response(raw, content_type, framing=framing)) as (url, requests):
        if extra:
            with pytest.raises(probe.ProbeError, match='http_body_exceeded'):
                probe._fetch(probe.Endpoint.parse(url), route, probe._Deadline(1), policy)
        else:
            body, provenance = probe._fetch(probe.Endpoint.parse(url), route, probe._Deadline(1), policy)
            assert body == raw == provenance.raw_body
            assert provenance.body_bytes == 32
        assert len(requests) == 1


@pytest.mark.parametrize('framing', ['length', 'chunked', 'close'])
def test_advertised_oversize_rejected_before_plaintext_body_consumption(framing):
    raw = response(b'x' * 33, framing=framing)
    class Stream:
        def __init__(self): self.offset = 0
        def settimeout(self, _): pass
        def recv(self, count):
            data = raw[self.offset:self.offset + count]
            self.offset += len(data)
            return data
    stream = Stream()
    with pytest.raises(probe.ProbeError, match='http_body_exceeded'):
        probe._response(probe._Reader(stream, probe._Deadline(1)), '/status', 32)
    framing_end = raw.index(b'\r\n\r\n') + 4
    if framing == 'chunked': framing_end += len(b'21\r\n')
    if framing == 'close': framing_end += 33  # One bounded overflow byte, never a large read.
    assert stream.offset == framing_end


@pytest.mark.parametrize('value', [None, {}, True, 1, SimpleNamespace(status_body_bytes=32, metrics_body_bytes=32)])
def test_policy_is_an_exact_required_immutable_owner_before_io(value, monkeypatch):
    peers = targets('http://127.0.0.1:1234')
    calls = []
    monkeypatch.setattr(probe, 'sample_peers', lambda *_: calls.append('process'))
    monkeypatch.setattr(probe, '_fetch', lambda *_: calls.append('http'))
    with pytest.raises(probe.ProbeError, match='capture_policy_invalid'):
        probe.Probe(peers, value)
    with pytest.raises(TypeError):
        probe.Probe(peers)
    assert calls == []


@pytest.mark.parametrize('change', ['equal_replacement', 'larger_replacement', 'field_mutation', 'invalid_mutation'])
def test_admitted_policy_cannot_be_substituted_before_later_observations(change, monkeypatch):
    policy = CapturePolicy(status_body_bytes=32, metrics_body_bytes=32)
    collector = probe.Probe(targets('http://127.0.0.1:1234'), policy)
    if change == 'equal_replacement': collector.policy = CapturePolicy(32, 32)
    if change == 'larger_replacement': collector.policy = CapturePolicy(64, 64)
    if change == 'field_mutation': object.__setattr__(policy, 'status_body_bytes', 64)
    if change == 'invalid_mutation': object.__setattr__(policy, 'status_body_bytes', True)
    calls = []
    monkeypatch.setattr(probe, 'sample_peers', lambda *_: calls.append('process'))
    monkeypatch.setattr(probe, '_fetch', lambda *_: calls.append('http'))
    with pytest.raises(probe.ProbeError, match='capture_policy_(?:changed|invalid)'):
        collector.collect(1)
    assert calls == []


def test_first_and_every_later_collect_use_same_policy_and_preserve_provenance():
    raw = inventory()
    policy = CapturePolicy(status_body_bytes=32, metrics_body_bytes=len(raw))
    metric_calls = [0]
    def respond(request):
        if request.split(b' ')[1].endswith(b'/metrics'):
            metric_calls[0] += 1
            return response(raw + (b'\n' if metric_calls[0] > 4 else b''), b'text/plain')
        return response()
    with server(respond) as (url, requests):
        collector = probe.Probe(targets(url), policy)
        first = collector.collect(2)
        assert first.capture_policy is policy
        assert all(peer.metrics.raw_body == raw for peer in first.peers)
        with pytest.raises(probe.ProbeError, match='http_body_exceeded'):
            collector.collect(2)
        assert len(requests) == 10
        assert first.capture_policy is policy


def test_fetch_requires_policy_and_closed_route_before_connection():
    endpoint = probe.Endpoint.parse('http://127.0.0.1:1234')
    with pytest.raises(TypeError):
        probe._fetch(endpoint, '/status', probe._Deadline(1))
    with pytest.raises(probe.ProbeError, match='http_route_invalid'):
        probe._fetch(endpoint, '/other', probe._Deadline(1), POLICY)


@pytest.mark.parametrize('extra', [0, 1])
def test_policy_substitution_during_response_cannot_enlarge_later_body_reads(extra):
    raw = inventory()
    policy = CapturePolicy(status_body_bytes=32, metrics_body_bytes=len(raw))
    def respond(request):
        collector.policy = CapturePolicy(status_body_bytes=32, metrics_body_bytes=len(raw) + 1)
        if request.split(b' ')[1].endswith(b'/metrics'):
            return response(raw + b'\n' * extra, b'text/plain')
        return response()
    with server(respond) as (url, requests):
        collector = probe.Probe(targets(url), policy)
        with pytest.raises(probe.ProbeError, match='http_body_exceeded' if extra else 'capture_policy_changed'):
            collector.collect(2)
        assert len(requests) == (2 if extra else 8)


def _replace_inflight_owner(collector, change, replacement_reader):
    """Mutate only public owners; request-local copies must remain independent."""
    peers = collector.peers
    first = peers[0]
    if change == 'target_tuple':
        collector.peers = tuple(replace(peer, endpoint=replace(peer.endpoint, base_path='/unadmitted'))
                                for peer in peers)
    elif change == 'target_endpoint':
        object.__setattr__(first, 'endpoint', replace(first.endpoint, base_path='/unadmitted'))
    elif change == 'endpoint_path':
        object.__setattr__(first.endpoint, 'base_path', '/unadmitted')
    elif change == 'endpoint_headers':
        object.__setattr__(first.endpoint, 'headers', (('authorization', 'Bearer NeverExpose'),))
    elif change == 'process_owner':
        replacement = process.PinnedProcess(first.process.peer_id, first.process.pid,
                                            first.process.image, replacement_reader)
        collector.peers = (replace(first, process=replacement), *peers[1:])
    elif change == 'process_reader':
        first.process.reader = replacement_reader
    elif change == 'process_image':
        first.process.image = SimpleNamespace()
    else:
        raise AssertionError('unknown test mutation')


@pytest.mark.parametrize('change', ['target_tuple', 'target_endpoint', 'endpoint_path',
                                    'endpoint_headers', 'process_owner', 'process_reader', 'process_image'])
def test_initial_process_read_cannot_change_admitted_http_or_process_scope(change, monkeypatch):
    replacement_reader = Reader()
    class InitialMutationReader(Reader):
        def sample(self, pid, image):
            sample = super().sample(pid, image)
            if pid == 100 and self.counts[pid] == 2:
                _replace_inflight_owner(collector, change, replacement_reader)
            return sample
    reader = InitialMutationReader()
    collector = probe.Probe(targets('http://127.0.0.1:1234', reader=reader), POLICY)
    requests = []
    monkeypatch.setattr(probe, '_fetch', lambda *_: requests.append('http'))
    with pytest.raises(probe.ProbeError, match='^peer_scope_changed$') as error:
        collector.collect(2)
    assert requests == []
    assert str(error.value) == 'peer_scope_changed'
    assert reader.counts == {pid: 2 for pid in range(100, 104)}
    assert replacement_reader.counts == ({100: 1} if change == 'process_owner' else {})


@pytest.mark.parametrize('change', ['target_tuple', 'target_endpoint', 'endpoint_path',
                                    'endpoint_headers', 'process_owner', 'process_reader', 'process_image'])
@pytest.mark.parametrize('unavailable', [False, True])
def test_response_mutation_keeps_every_request_on_admitted_values_and_never_returns(change, unavailable):
    replacement_reader = Reader()
    reader = Reader()
    changed = False
    missing = b'iroha_kura_resource_available 0\niroha_kura_resource_status{reason="busy"} 1\n'
    def respond(request):
        nonlocal changed
        if not changed:
            changed = True
            _replace_inflight_owner(collector, change, replacement_reader)
        if unavailable and request.split(b' ')[1] == b'/peer2/metrics':
            return response(missing, b'text/plain')
        return regular(request)
    with server(respond) as (url, requests):
        collector = probe.Probe(targets(url, reader=reader), POLICY)
        with pytest.raises(probe.ProbeError, match='^peer_scope_changed$') as error:
            collector.collect(2)
        assert len(requests) == 8
        assert [request.split(b' ')[1].decode() for request in requests] == [
            f'/peer{i}/{route}' for i in range(4) for route in ('status', 'metrics')]
        assert all(b'NeverExpose' not in request and b'authorization:' not in request for request in requests)
    assert str(error.value) == 'peer_scope_changed'
    assert reader.counts == {pid: 2 for pid in range(100, 104)}
    assert replacement_reader.counts == ({100: 1} if change == 'process_owner' else {})


@pytest.mark.parametrize('change', ['target_tuple', 'endpoint_path', 'process_owner', 'process_reader'])
@pytest.mark.parametrize('unavailable', [False, True])
def test_final_process_read_owner_change_rejects_complete_and_unavailable_results(change, unavailable):
    replacement_reader = Reader()
    class FinalMutationReader(Reader):
        def sample(self, pid, image):
            sample = super().sample(pid, image)
            if pid == 100 and self.counts[pid] == 3:
                _replace_inflight_owner(collector, change, replacement_reader)
            return sample
    reader = FinalMutationReader()
    missing = b'iroha_kura_resource_available 0\niroha_kura_resource_status{reason="busy"} 1\n'
    def respond(request):
        if unavailable and request.split(b' ')[1] == b'/peer2/metrics':
            return response(missing, b'text/plain')
        return regular(request)
    with server(respond) as (url, requests):
        collector = probe.Probe(targets(url, reader=reader), POLICY)
        with pytest.raises(probe.ProbeError, match='^peer_scope_changed$') as error:
            collector.collect(2)
        assert len(requests) == 8
    assert str(error.value) == 'peer_scope_changed'
    assert reader.counts == {pid: 3 for pid in range(100, 104)}
    assert replacement_reader.counts == ({100: 1} if change == 'process_owner' else {})
