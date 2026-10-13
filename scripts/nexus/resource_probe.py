"""Bounded local-validator HTTP and process observations for the CLI clock bracket.

Only numeric-IP endpoints are admitted: name resolution is outside this adapter's
bounded transport contract. The caller owns the outer child deadline, sampling
cadence and measurement clock. This module never generates CLI clock offsets.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import math
import re
import socket
import ssl
import time
from urllib.parse import urlsplit

from kura_resource_metrics import (
    AvailableObservation, ProjectionError, UnavailableObservation,
    parse_kura_resource_metrics,
)
from resource_process import PinnedProcess, ProcessSample, sample_peers
from resource_evidence_budget import (
    BudgetError, CapturePolicy, MAX_STATUS_BODY_BYTES as MAX_STATUS_BYTES,
    MAX_WIRE_BYTES as MAX_PROBE_WIRE_BYTES,
)

MAX_EXACT_INTEGER = 1 << 53
MAX_TIMEOUT_SECONDS = 60.0
MAX_HEADER_BYTES = 32 * 1024
MAX_LINE_BYTES = 8192
MAX_HEADER_ROWS = 128
MAX_CHUNKS = 4096
MAX_JSON_DEPTH = 64
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


class ProbeError(ValueError):
    """A closed public failure code; never contains upstream diagnostics/secrets."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ProbeError(code)


def _policy_values(policy: CapturePolicy) -> tuple[int, int]:
    """Validate the exact immutable policy, including any illicit value mutation."""
    _require(type(policy) is CapturePolicy, "capture_policy_invalid")
    values = policy.status_body_bytes, policy.metrics_body_bytes
    try:
        CapturePolicy(*values)
    except BudgetError:
        raise ProbeError("capture_policy_invalid") from None
    return values


@dataclass(frozen=True, repr=False)
class Endpoint:
    """Runtime-only connection details; artifacts retain peer labels and routes."""
    scheme: str
    host: str
    port: int
    base_path: str
    headers: tuple[tuple[str, str], ...] = field(repr=False)

    def __post_init__(self) -> None:
        # Direct construction obeys the same transport rules as URL parsing.
        try:
            _require(self.scheme in ("http", "https") and type(self.host) is str,
                     "endpoint_invalid")
            address = ipaddress.ip_address(self.host)
            _require(str(address) == self.host and not address.is_unspecified
                     and not address.is_multicast and "%" not in self.host
                     and type(self.port) is int and 1 <= self.port <= 65535
                     and type(self.base_path) is str and len(self.base_path) <= 2048
                     and re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*", self.base_path) is not None,
                     "endpoint_invalid")
            _validate_headers(self.headers)
        except ValueError as error:
            if isinstance(error, ProbeError):
                raise
            raise ProbeError("endpoint_invalid") from None

    @classmethod
    def parse(cls, url: str, headers: tuple[tuple[str, str], ...] = ()) -> Endpoint:
        """Reject ambiguous or credential-bearing URLs and request injection."""
        try:
            _require(type(url) is str and 1 <= len(url) <= 2048
                     and all(32 < ord(ch) < 127 for ch in url), "endpoint_invalid")
            parsed = urlsplit(url)
            _require(parsed.scheme in ("http", "https") and parsed.hostname is not None
                     and parsed.username is None and parsed.password is None
                     and not parsed.query and not parsed.fragment
                     and "?" not in url and "#" not in url, "endpoint_invalid")
            address = ipaddress.ip_address(parsed.hostname)
            _require(not address.is_unspecified and not address.is_multicast
                     and "%" not in parsed.hostname, "endpoint_invalid")
            port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
            _require(1 <= port <= 65535, "endpoint_invalid")
            path = parsed.path.rstrip("/")
            _require(re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*", path) is not None,
                     "endpoint_invalid")
            _validate_headers(headers)
            return cls(parsed.scheme, str(address), port, path,
                       tuple((name.lower(), value) for name, value in headers))
        except (ValueError, UnicodeError) as error:
            if isinstance(error, ProbeError):
                raise
            raise ProbeError("endpoint_invalid") from None


def _validate_headers(headers) -> None:
    _require(type(headers) is tuple and len(headers) <= 8, "headers_invalid")
    admitted = set()
    for pair in headers:
        _require(type(pair) is tuple and len(pair) == 2, "headers_invalid")
        name, value = pair
        _require(type(name) is str and type(value) is str
                 and all(ord(ch) < 128 for ch in name), "headers_invalid")
        encoded = name.encode("ascii")
        _require(1 <= len(encoded) <= 128 and _TOKEN.fullmatch(encoded) is not None
                 and 1 <= len(value) <= 4096
                 and all(32 <= ord(ch) < 127 for ch in value), "headers_invalid")
        name = name.lower()
        _require(name not in {"host", "accept", "accept-encoding", "connection",
                             "content-length", "transfer-encoding", "te", "trailer",
                             "upgrade", "proxy-authorization"}
                 and name not in admitted, "headers_invalid")
        admitted.add(name)


@dataclass(frozen=True)
class PeerTarget:
    """A manifest-bound endpoint and process; no process discovery is performed."""
    process: PinnedProcess = field(repr=False)
    endpoint: Endpoint = field(repr=False)


@dataclass(frozen=True, repr=False)
class _AdmittedPeer:
    """Retain original lifetime/descriptor/read owners and copied connection values."""
    process: PinnedProcess
    image: object
    reader: object
    identity: object
    peer_id: str
    pid: int
    endpoint: tuple

    @classmethod
    def capture(cls, peer: PeerTarget) -> _AdmittedPeer:
        owner = peer.process
        return cls(owner, owner.image, owner.reader, owner.identity,
                   owner.peer_id, owner.pid, cls.endpoint_values(peer.endpoint))

    @staticmethod
    def endpoint_values(endpoint: Endpoint) -> tuple:
        return (endpoint.scheme, endpoint.host, endpoint.port, endpoint.base_path,
                tuple((name, value) for name, value in endpoint.headers))

    def matches(self, peer: PeerTarget) -> bool:
        return (isinstance(peer, PeerTarget) and isinstance(peer.endpoint, Endpoint)
                and peer.process is self.process
                and peer.process.image is self.image and peer.process.reader is self.reader
                and peer.process.identity == self.identity
                and peer.process.peer_id == self.peer_id and peer.process.pid == self.pid
                and self.endpoint_values(peer.endpoint) == self.endpoint)


@dataclass(frozen=True)
class HttpProvenance:
    """Exact public response entity for later owner-only immutable capture files."""
    route: str
    body_sha256: str
    body_bytes: int
    content_type: str
    raw_body: bytes = field(repr=False)


@dataclass(frozen=True)
class PeerObservation:
    """One fresh status read and one complete Kura gather for a declared peer."""
    peer_id: str
    queue_size: int
    status: HttpProvenance
    metrics: HttpProvenance
    kura: AvailableObservation | UnavailableObservation
    process_before: ProcessSample
    process_after: ProcessSample


@dataclass(frozen=True)
class InventoryAggregate:
    """Complete reductions over every declared validator, never one selected peer."""
    storage_bytes: int
    represented_entries: int


@dataclass(frozen=True)
class ProbeObservation:
    """Observations across a CLI-owned bracket, never an instantaneous snapshot."""
    peers: tuple[PeerObservation, ...]
    local_elapsed_ns: int
    wire_bytes: int
    rss_before_bytes: int
    rss_after_bytes: int
    queue_size_sum: int
    queue_size_max: int
    inventory: InventoryAggregate | None
    capture_policy: CapturePolicy

    @property
    def available(self) -> bool:
        """A partial/unavailable Kura vector cannot become a successful aggregate."""
        return self.inventory is not None


class _Deadline:
    def __init__(self, seconds: float):
        _require(type(seconds) in (int, float) and 0 < seconds <= MAX_TIMEOUT_SECONDS
                 and math.isfinite(seconds), "deadline_invalid")
        self.started = time.monotonic_ns()
        self.end = self.started + int(seconds * 1_000_000_000)
        self.wire_bytes = 0

    def remaining(self) -> float:
        remaining = self.end - time.monotonic_ns()
        _require(remaining > 0, "deadline_exceeded")
        return remaining / 1_000_000_000

    def received(self, count: int) -> None:
        self.wire_bytes += count
        _require(self.wire_bytes <= MAX_PROBE_WIRE_BYTES, "probe_size_exceeded")
        self.remaining()


class _Reader:
    """Every kernel receive uses the remaining absolute deadline, not a reset timer."""
    def __init__(self, stream: socket.socket, deadline: _Deadline):
        self.stream, self.deadline, self.buffer = stream, deadline, bytearray()

    def receive(self, maximum: int) -> bytes:
        self.stream.settimeout(self.deadline.remaining())
        data = self.stream.recv(min(16 * 1024, maximum))
        self.deadline.received(len(data))
        return data

    def line(self, *, maximum: int = MAX_LINE_BYTES,
             exceeded: str = "http_line_exceeded") -> bytes:
        # Only the last byte of the previous prefix can begin a new CRLF pair.
        # Rescanning the complete prefix per byte makes bounded framing quadratic.
        search_from = 0
        while True:
            boundary = self.buffer.find(b"\r\n", search_from)
            if boundary >= 0:
                _require(boundary <= maximum, exceeded)
                line = bytes(self.buffer[:boundary])
                del self.buffer[:boundary + 2]
                _require(b"\n" not in line and b"\r" not in line, "http_framing_invalid")
                return line
            _require(len(self.buffer) <= maximum + 1, exceeded)
            search_from = max(0, len(self.buffer) - 1)
            # Read only framing until the advertised body/chunk length has
            # passed the policy check. TLS may buffer encrypted records below
            # this plaintext interface; no excess plaintext body is retained.
            data = self.receive(1)
            _require(bool(data), "http_truncated")
            self.buffer.extend(data)

    def exact(self, count: int) -> bytes:
        while len(self.buffer) < count:
            data = self.receive(count - len(self.buffer))
            _require(bool(data), "http_truncated")
            self.buffer.extend(data)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result


def _response(reader: _Reader, route: str, cap: int) -> tuple[bytes, str]:
    status = reader.line()
    _require(re.fullmatch(rb"HTTP/1\.[01] 200(?: [\x20-\x7e]*)?", status) is not None,
             "http_status_invalid")
    total, rows, headers = len(status) + 2, 0, {}
    while True:
        # Admit the next line, including its CRLF, against the remaining header
        # capacity before consuming it. A long final field cannot borrow another
        # full line of input after the aggregate framing budget is exhausted.
        remaining = MAX_HEADER_BYTES - total - 2
        _require(remaining >= 0, "http_headers_exceeded")
        line = reader.line(maximum=min(MAX_LINE_BYTES, remaining),
                           exceeded="http_headers_exceeded" if remaining < MAX_LINE_BYTES
                           else "http_line_exceeded")
        total += len(line) + 2
        _require(total <= MAX_HEADER_BYTES, "http_headers_exceeded")
        if not line:
            break
        rows += 1
        _require(rows <= MAX_HEADER_ROWS, "http_headers_exceeded")
        name, separator, value = line.partition(b":")
        _require(separator == b":" and _TOKEN.fullmatch(name) is not None
                 and all(ch == 9 or 32 <= ch < 127 for ch in value), "http_headers_invalid")
        name = name.lower()
        _require(name not in headers, "http_headers_duplicate")
        headers[name] = value.strip(b" \t")
    content_type = headers.get(b"content-type", b"").lower()
    allowed = {b"application/json", b"application/json; charset=utf-8"} if route == "/status" else {
        b"text/plain", b"text/plain; version=0.0.4", b"text/plain; version=0.0.4; charset=utf-8",
        b"text/plain; charset=utf-8",
    }
    _require(content_type in allowed, "http_content_type_invalid")
    _require(headers.get(b"content-encoding", b"identity").lower() == b"identity",
             "http_content_encoding_invalid")
    length, transfer = headers.get(b"content-length"), headers.get(b"transfer-encoding")
    _require(not (length is not None and transfer is not None), "http_framing_ambiguous")
    if length is not None:
        _require(re.fullmatch(rb"[0-9]{1,10}", length) is not None, "http_length_invalid")
        count = int(length)
        _require(count <= cap, "http_body_exceeded")
        body = reader.exact(count)
        _require(not reader.buffer and not reader.receive(1), "http_trailing_data")
    elif transfer is not None:
        _require(transfer.lower() == b"chunked", "http_transfer_invalid")
        parts, size, chunks = bytearray(), 0, 0
        while True:
            chunks += 1
            _require(chunks <= MAX_CHUNKS, "http_chunks_exceeded")
            line = reader.line()
            _require(re.fullmatch(rb"[0-9A-Fa-f]{1,8}", line) is not None,
                     "http_chunk_invalid")
            count = int(line, 16)
            _require(count <= cap - size, "http_body_exceeded")
            if count == 0:
                _require(reader.line() == b"" and not reader.buffer and not reader.receive(1), "http_trailer_invalid")
                break
            size += count
            parts.extend(reader.exact(count))
            _require(reader.exact(2) == b"\r\n", "http_chunk_invalid")
        body = bytes(parts)
    else:
        parts, size = bytearray(reader.buffer), len(reader.buffer)
        reader.buffer.clear()
        while True:
            _require(size <= cap, "http_body_exceeded")
            data = reader.receive(cap - size + 1)
            if not data:
                break
            _require(len(data) <= cap - size, "http_body_exceeded")
            size += len(data)
            parts.extend(data)
        body = bytes(parts)
    reader.deadline.remaining()
    return body, content_type.decode("ascii")


def _fetch(endpoint: Endpoint, route: str, deadline: _Deadline,
           policy: CapturePolicy) -> tuple[bytes, HttpProvenance]:
    """Direct numeric connection, no ambient proxy, redirect, retry or decompression."""
    caps = _policy_values(policy)
    _require(route in ("/status", "/metrics"), "http_route_invalid")
    cap = caps[0 if route == "/status" else 1]
    stream = None
    try:
        family = socket.AF_INET6 if ":" in endpoint.host else socket.AF_INET
        stream = socket.socket(family, socket.SOCK_STREAM)
        stream.settimeout(deadline.remaining())
        address = (endpoint.host, endpoint.port, 0, 0) if family == socket.AF_INET6 else (endpoint.host, endpoint.port)
        stream.connect(address)
        if endpoint.scheme == "https":
            context = ssl.create_default_context()
            stream = context.wrap_socket(stream, server_hostname=endpoint.host, do_handshake_on_connect=False)
            stream.settimeout(deadline.remaining())
            stream.do_handshake()
        host = f"[{endpoint.host}]" if family == socket.AF_INET6 else endpoint.host
        accept = "application/json" if route == "/status" else "text/plain; version=0.0.4"
        lines = [f"GET {endpoint.base_path}{route} HTTP/1.1", f"Host: {host}:{endpoint.port}",
                 f"Accept: {accept}", "Accept-Encoding: identity", "Connection: close"]
        lines.extend(f"{name}: {value}" for name, value in endpoint.headers)
        request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
        stream.settimeout(deadline.remaining())
        stream.sendall(request)
        raw, content_type = _response(_Reader(stream, deadline), route, cap)
        for name, value in endpoint.headers:
            tokens = (value, value[7:]) if name.lower() == "authorization" and value.lower().startswith("bearer ") else (value,)
            _require(not any(token.encode("ascii") in raw for token in tokens if token),
                     "response_contains_credentials")
        deadline.remaining()
        return raw, HttpProvenance(route, hashlib.sha256(raw).hexdigest(), len(raw), content_type, raw)
    except ProbeError:
        raise
    except (TimeoutError, socket.timeout):
        raise ProbeError("deadline_exceeded") from None
    except (OSError, ValueError):
        raise ProbeError("http_transport_failed") from None
    finally:
        if stream is not None:
            stream.close()


def _status_queue(raw: bytes) -> int:
    """Read authoritative fresh /status queue_size, with bounded strict JSON framing."""
    _require(0 < len(raw) <= MAX_STATUS_BYTES, "status_size_invalid")
    depth, in_string, escaped = 0, False, False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
        elif byte == 34:
            in_string = True
        elif byte in (91, 123):
            depth += 1
            _require(depth <= MAX_JSON_DEPTH, "status_depth_exceeded")
        elif byte in (93, 125):
            depth -= 1
            _require(depth >= 0, "status_json_invalid")
    _require(depth == 0 and not in_string, "status_json_invalid")

    def pairs(rows):
        result = {}
        for key, value in rows:
            _require(key not in result, "status_duplicate_key")
            result[key] = value
        return result

    def integer(token):
        _require(len(token) <= 128, "status_number_exceeded")
        return int(token)

    def real(token):
        _require(len(token) <= 128, "status_number_exceeded")
        value = float(token)
        _require(math.isfinite(value), "status_number_invalid")
        return value

    def constant(_):
        raise ProbeError("status_number_invalid")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_int=integer, parse_float=real, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, ProbeError):
            raise
        raise ProbeError("status_json_invalid") from None
    _require(type(value) is dict and type(value.get("queue_size")) is int
             and 0 <= value["queue_size"] <= MAX_EXACT_INTEGER, "status_queue_invalid")
    return value["queue_size"]


class Probe:
    """Reuse already pinned process owners; one status and metrics request per peer."""
    def __init__(self, peers: tuple[PeerTarget, ...], policy: CapturePolicy):
        self._policy_scope = _policy_values(policy)
        self.policy = self._admitted_policy = policy
        _require(type(peers) is tuple and 4 <= len(peers) <= 64, "peer_scope_invalid")
        _require(all(isinstance(peer, PeerTarget) and isinstance(peer.endpoint, Endpoint)
                     and isinstance(peer.process, PinnedProcess) for peer in peers), "peer_scope_invalid")
        ids = tuple(peer.process.peer_id for peer in peers)
        pids = tuple(peer.process.pid for peer in peers)
        endpoints = {(peer.endpoint.scheme, peer.endpoint.host, peer.endpoint.port, peer.endpoint.base_path)
                     for peer in peers}
        _require(len(set(ids)) == len(peers) and len(set(pids)) == len(peers)
                 and len(endpoints) == len(peers), "peer_scope_invalid")
        self.peers = peers
        self._scope = tuple(_AdmittedPeer.capture(peer) for peer in peers)

    def collect(self, timeout_seconds: float) -> ProbeObservation:
        """Fail the entire request on missing/late HTTP or changed process identity."""
        _require(self.policy is self._admitted_policy
                 and _policy_values(self.policy) == self._policy_scope,
                 "capture_policy_changed")
        # A request-local immutable copy prevents replacing the public policy
        # attribute during a response from enlarging a later body read.
        policy = CapturePolicy(*self._policy_scope)
        scope = self._scope
        self._require_scope(scope)
        # The admitted value tuples and original process owners define this
        # entire collection. Public targets may be replaced while I/O yields.
        endpoints = tuple(Endpoint(*admitted.endpoint) for admitted in scope)
        processes = tuple(admitted.process for admitted in scope)
        deadline = _Deadline(timeout_seconds)
        try:
            deadline.remaining()
            before = sample_peers(processes)
            deadline.remaining()
            self._require_scope(scope)
            gathered = []
            for admitted, endpoint in zip(scope, endpoints, strict=True):
                raw_status, status = _fetch(endpoint, "/status", deadline, policy)
                queue = _status_queue(raw_status)
                raw_metrics, metrics = _fetch(endpoint, "/metrics", deadline, policy)
                try:
                    kura = parse_kura_resource_metrics(raw_metrics)
                except ProjectionError:
                    raise ProbeError("kura_projection_invalid") from None
                gathered.append((admitted.peer_id, queue, status, metrics, kura))
                deadline.remaining()
            self._require_scope(scope)
            after = sample_peers(processes)
            deadline.remaining()
        except ProbeError:
            raise
        except (OSError, ValueError):
            raise ProbeError("process_observation_failed") from None
        _require(all(first.identity == last.identity for first, last in zip(before, after, strict=True)),
                 "process_identity_changed")
        peers = tuple(PeerObservation(*observation, first, last)
                      for observation, first, last in zip(gathered, before, after, strict=True))
        rss_before = _checked_sum(sample.rss_bytes for sample in before)
        rss_after = _checked_sum(sample.rss_bytes for sample in after)
        queue_sum = _checked_sum(peer.queue_size for peer in peers)
        inventory = None
        if all(isinstance(peer.kura, AvailableObservation) for peer in peers):
            inventory = InventoryAggregate(
                _checked_sum(peer.kura.total.storage_bytes for peer in peers),
                _checked_sum(peer.kura.represented_entries for peer in peers),
            )
        deadline.remaining()
        elapsed = time.monotonic_ns() - deadline.started
        _require(0 < elapsed <= MAX_EXACT_INTEGER and elapsed < deadline.end - deadline.started,
                 "deadline_exceeded")
        _require(self.policy is self._admitted_policy
                 and _policy_values(self.policy) == self._policy_scope,
                 "capture_policy_changed")
        self._require_scope(scope)
        return ProbeObservation(peers, elapsed, deadline.wire_bytes,
                                rss_before, rss_after, queue_sum,
                                max(peer.queue_size for peer in peers), inventory, self._admitted_policy)

    def _require_scope(self, scope: tuple[_AdmittedPeer, ...]) -> None:
        """Reject changed ownership before reads and before either result shape."""
        peers = self.peers
        _require(self._scope is scope and type(peers) is tuple and len(peers) == len(scope)
                 and all(admitted.matches(peer) for admitted, peer in zip(scope, peers, strict=True)),
                 "peer_scope_changed")


def _checked_sum(values) -> int:
    result = 0
    for value in values:
        _require(type(value) is int and 0 <= value <= MAX_EXACT_INTEGER - result,
                 "aggregate_outside_exact_range")
        result += value
    return result
