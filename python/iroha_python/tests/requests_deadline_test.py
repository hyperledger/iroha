"""Real Requests worker deadlines, immutable configuration and exact cleanup."""
import base64
import errno
import os
import selectors
import subprocess
import sys
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests
from norito.errors import LengthMismatchError, SchemaMismatchError, UnsupportedVersionError

from iroha_python import requests_deadline as owner
from staking_transport_server import observation_server


@pytest.fixture
def children(monkeypatch):
    original = owner.subprocess.Popen
    processes = []

    def start(*args, **kwargs):
        process = original(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(owner.subprocess, "Popen", start)
    yield processes
    for process in processes:
        assert process.poll() is not None
        assert process.stdin.closed and process.stdout.closed
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)


def send(url, *, duration=2, session=None, max_body=256 * 1024):
    if session is None:
        session = requests.Session()
        session.trust_env = False
    return owner.send_bounded_request(
        session=session, method="POST", url=url + "/v1/nexus/staking/prepare",
        headers={"Content-Type": "application/x-norito", "Authorization": "Bearer disposable-test"},
        body=b"exact request", timeout=duration, deadline_ns=time.monotonic_ns() + int(duration * 1e9),
        max_body=max_body, media_type="application/x-norito",
    )


def test_bounded_requests_preserves_prepared_wire_and_reaps_success(children):
    with observation_server(b"exact response") as server:
        with send(server["url"]) as response:
            assert response.content == b"exact response"
            assert response.status_code == 200
        assert server["finished"].wait(1)
        assert len(server["calls"]) == 1
        method, path, headers, body = server["calls"][0]
        assert (method, path, body) == ("POST", "/v1/nexus/staking/prepare", b"exact request")
        assert headers["Authorization"] == "Bearer disposable-test"
        assert headers["Content-Type"] == "application/x-norito"
    assert len(children) == 1


@pytest.mark.parametrize("status", [200, 503, 302])
def test_bounded_requests_slow_body_keeps_original_deadline_after_late_headers(status, children):
    started = time.monotonic()
    with observation_server(b"slow response" * 30, status=status, header_delay=0.6,
                            chunk_delay=0.03, chunk_size=1,
                            headers={"Location": "/must-not-follow"}) as server:
        with pytest.raises(requests.Timeout):
            send(server["url"], duration=1.2)
        elapsed = time.monotonic() - started
        # A fresh 1.2 s deadline started at headers would take at least 1.8 s.
        assert 1.1 <= elapsed < 1.55
        assert server["finished"].wait(1)
        assert server["peer_closed"] and len(server["calls"]) == 1
        assert 0 < server["body_writes"] < len(b"slow response" * 30)
    assert len(children) == 1


def test_bounded_requests_late_headers_cannot_create_late_response_or_leaked_child(children):
    started = time.monotonic()
    with observation_server(b"late", header_delay=0.9, probe_before_body=True) as server:
        with pytest.raises(requests.Timeout):
            send(server["url"], duration=0.5)
        assert time.monotonic() - started < 1.1
        assert server["finished"].wait(1.5)
        assert server["peer_closed"] and len(server["calls"]) == 1
    assert len(children) == 1


@pytest.mark.parametrize("headers", [
    {"Content-Length": "262145"}, {"Content-Length": "01"},
    {"Content-Encoding": "gzip"}, {"Content-Type": "application/json"},
    {"Set-Cookie": "session=disposable; HttpOnly"},
])
def test_bounded_requests_rejects_headers_before_body_and_reaps(headers, children):
    with observation_server(headers=headers, probe_before_body=True) as server:
        with pytest.raises(ValueError):
            send(server["url"])
        assert server["finished"].wait(1)
        assert server["peer_closed"] and server["body_writes"] == 0
        assert len(server["calls"]) == 1
    assert len(children) == 1


def test_bounded_requests_redirect_body_is_bounded_before_requests_redirect_processing(children):
    with observation_server(b"x" * 65536, status=302, headers={"Location": "/forbidden"}) as server:
        with pytest.raises(ValueError):
            send(server["url"], max_body=32)
        assert server["finished"].wait(1)
        assert len(server["calls"]) == 1
    assert len(children) == 1


def test_bounded_requests_error_body_is_finite_and_never_retried(children):
    with observation_server(b"unavailable", status=503) as server:
        response = send(server["url"])
        assert response.status_code == 503 and response.content == b"unavailable"
        response.close()
        assert len(server["calls"]) == 1
    assert len(children) == 1


@pytest.mark.parametrize("kind", ["session", "adapter", "hooks", "cookies", "auth", "retry", "tls_pool"])
def test_bounded_requests_rejects_unsupported_session_before_child_or_dispatch(kind, children):
    class CustomSession(requests.Session):
        pass
    class CustomAdapter(requests.adapters.HTTPAdapter):
        pass
    session = CustomSession() if kind == "session" else requests.Session()
    if kind == "adapter":
        session.mount("http://", CustomAdapter())
    if kind == "hooks":
        session.hooks["response"].append(lambda value: value)
    if kind == "cookies":
        session.cookies.set("session", "test")
    if kind == "auth":
        session.auth = ("test", "test")
    if kind == "retry":
        session.mount("http://", requests.adapters.HTTPAdapter(max_retries=1))
    if kind == "tls_pool":
        session.get_adapter("http://x").poolmanager.connection_pool_kw["ssl_context"] = object()
    with observation_server() as server:
        with pytest.raises((TypeError, ValueError)):
            send(server["url"], session=session)
        assert not server["calls"] and not children


def test_bounded_requests_snapshots_original_prepared_headers_body_proxy_tls_and_cert():
    session = requests.Session()
    session.trust_env = False
    session.params = {"scope": "global"}
    session.headers["X-Test-Session"] = "retained"
    session.proxies = {"https": "http://proxy.invalid:8000"}
    session.verify = "/configured/ca.pem"
    session.cert = ("/configured/client.pem", "/configured/client.key")
    frame, environment = owner._snapshot(session, "POST", "https://example.invalid/prepare", {"X-Test-Request": "exact"}, b"original", 3, time.monotonic_ns() + 3_000_000_000, 200, "application/x-norito")
    value = owner._unframe(frame, owner._REQUEST, owner._REQUEST_SCHEMA)
    assert value["method"] == "POST" and value["url"] == "https://example.invalid/prepare"
    assert dict(value["headers"]) == {"X-Test-Request": "exact"}
    assert dict(value["session_headers"]) == dict(session.headers)
    assert dict(value["session_params"]) == session.params
    assert value["body"] == b"original" and value["trust_env"] is False
    assert dict(value["proxies"]) == session.proxies
    assert value["verify"] == 2 and value["ca_path"] == session.verify
    assert tuple(value["cert"]) == session.cert
    assert value["timeout_ns"] == 3_000_000_000
    assert environment == dict(os.environ)
    expected = session.prepare_request(requests.Request("POST", value["url"], headers=dict(value["headers"]), data=b"original"))
    expected_settings = session.merge_environment_settings(expected.url, {}, True, None, None)
    with requests.Session() as worker_session:
        prepared, settings = owner._prepare_request(worker_session, value)
        assert prepared.method == expected.method and prepared.url == expected.url
        assert dict(prepared.headers) == dict(expected.headers) and prepared.body == expected.body
        assert settings == expected_settings
    session.headers["X-Test-Session"] = "changed"
    session.proxies.clear()
    assert dict(value["session_headers"])["X-Test-Session"] == "retained"
    assert dict(value["proxies"]) == {"https": "http://proxy.invalid:8000"}


def test_bounded_requests_expired_before_snapshot_has_no_dispatch(children):
    with pytest.raises(requests.Timeout):
        owner.send_bounded_request(session=requests.Session(), method="POST", url="http://127.0.0.1:1/", headers={}, body=b"x", timeout=1, deadline_ns=time.monotonic_ns() - 1, max_body=1, media_type="application/x-norito")
    assert not children


def test_bounded_requests_private_norito_frames_reject_wrong_schema_flags_and_unbounded_payload():
    value = {**owner._empty_result(), "status": 200, "body": b"ok"}
    frame = owner._frame(value, owner._RESPONSE, owner._RESPONSE_SCHEMA)
    assert owner._unframe(frame, owner._RESPONSE, owner._RESPONSE_SCHEMA) == value
    for invalid, error in ((frame[:-1], LengthMismatchError), (frame + b"\0", ValueError),
                           (bytes(owner._FRAME_LIMIT + 1), ValueError)):
        with pytest.raises(error):
            owner._unframe(invalid, owner._RESPONSE, owner._RESPONSE_SCHEMA)
    for index, error in ((4, UnsupportedVersionError), (6, SchemaMismatchError),
                         (22, ValueError), (39, SchemaMismatchError)):
        invalid = bytearray(frame)
        invalid[index] ^= 1
        with pytest.raises(error):
            owner._unframe(bytes(invalid), owner._RESPONSE, owner._RESPONSE_SCHEMA)
    with pytest.raises(ValueError, match="byte limit"):
        owner._frame({**value, "body": bytes(owner._FRAME_LIMIT)}, owner._RESPONSE, owner._RESPONSE_SCHEMA)


def test_bounded_requests_cleanup_kills_only_owned_child_that_ignores_term():
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", "import signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); time.sleep(10)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=2), "owned cleanup-test child did not become ready"
        assert process.stdout.readline() == b"ready\n"
        started = time.monotonic()
        owner._retire(process)
        assert time.monotonic() - started < 1.2
        assert process.returncode == -9
        assert process.stdin.closed and process.stdout.closed
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
    finally:
        owner._retire(process)


def test_bounded_requests_netrc_fifo_is_inside_original_deadline_and_owned_child(tmp_path, monkeypatch, children):
    fifo = tmp_path / "netrc"
    os.mkfifo(fifo, 0o600)
    monkeypatch.setenv("NETRC", str(fifo))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    session = requests.Session()
    session.trust_env = True
    writer = None
    started = time.monotonic()
    with observation_server() as server:
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(send, server["url"], duration=1.2, session=session)
        try:
            # Opening the writer proves the request owner reached the real NETRC
            # FIFO. Keeping it empty/open then blocks netrc.read until child expiry.
            while writer is None and time.monotonic() - started < 0.9:
                try:
                    writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                except OSError as error:
                    assert error.errno == errno.ENXIO
                    time.sleep(0.01)
            assert writer is not None, "the Requests owner never reached its original NETRC read"
            assert len(children) == 1, "NETRC preparation happened before owned-worker dispatch"
            with pytest.raises(requests.Timeout):
                future.result(timeout=1.6)
            assert time.monotonic() - started < 1.6
            assert server["calls"] == []
        finally:
            if writer is not None:
                os.close(writer)
            executor.shutdown(wait=True)
    assert len(children) == 1


def test_bounded_requests_preserves_original_environment_netrc_auth_and_prepared_metadata(tmp_path, monkeypatch, children):
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login disposable password exact-secret\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    session = requests.Session()
    session.trust_env = True
    session.params = {"scope": "global"}
    session.headers["X-Session-Exact"] = "retained"
    with observation_server() as server:
        response = send(server["url"], session=session)
        expected_auth = "Basic " + base64.b64encode(b"disposable:exact-secret").decode()
        assert len(server["calls"]) == 1
        method, path, headers, body = server["calls"][0]
        assert (method, path, body) == ("POST", "/v1/nexus/staking/prepare?scope=global", b"exact request")
        assert headers["Authorization"] == expected_auth
        assert headers["X-Session-Exact"] == "retained"
        assert response.request.headers["Authorization"] == expected_auth
        assert response.request.url == server["url"] + path
        assert response.request.body == body
        response.close()
    assert len(children) == 1


def callback_bombs(calls):
    def fail(*args, **kwargs):
        calls.append("untrusted callback")
        raise AssertionError("untrusted callback ran before rejection")
    class Object:
        __len__ = __bool__ = __iter__ = __eq__ = __float__ = fail
        items = get = __getitem__ = fail
    class Mapping(dict):
        __len__ = __bool__ = __iter__ = __eq__ = items = get = __getitem__ = fail
    class Sequence(list):
        __len__ = __bool__ = __iter__ = __eq__ = fail
    class Tuple(tuple):
        __len__ = __bool__ = __iter__ = __eq__ = fail
    class Text(str):
        __hash__ = str.__hash__
        __len__ = __bool__ = __iter__ = __eq__ = lower = encode = fail
    return fail, Object, Mapping, Sequence, Tuple, Text


@pytest.mark.parametrize("kind", [
    "cookies", "cookie_storage", "cookie_policy", "cookie_lock",
    "adapters", "adapters_items", "adapter_prefix", "get_adapter",
    "header_storage", "header_items", "header_entry", "hooks", "hook_list",
    "auth", "retry", "retry_total", "retry_history", "pool", "pool_headers",
    "pool_config", "pool_classes", "pool_keys", "pool_entries", "pool_size",
    "adapter_config", "adapter_proxy", "adapter_send", "pool_key_keywords", "pool_connections", "params", "proxies",
    "verify", "cert", "request_headers",
])
def test_bounded_requests_custom_nested_state_rejects_without_callbacks_encoding_child_or_dispatch(kind, monkeypatch, children):
    calls = []
    fail, Object, Mapping, Sequence, Tuple, Text = callback_bombs(calls)
    session = requests.Session()
    session.trust_env = False
    adapter = session.adapters["http://"]
    pool = adapter.poolmanager
    headers = {"Content-Type": "application/x-norito"}
    if kind == "cookies":
        session.cookies = Object()
    if kind == "cookie_storage":
        session.cookies._cookies = Mapping()
    if kind == "cookie_policy":
        session.cookies._policy = Object()
    if kind == "cookie_lock":
        session.cookies._cookies_lock = Object()
    if kind == "adapters":
        session.adapters = Mapping()
    if kind == "adapters_items":
        session.adapters.items = fail
    if kind == "adapter_prefix":
        session.adapters = OrderedDict([("https://", session.adapters["https://"]), (Text("http://"), adapter)])
    if kind == "get_adapter":
        session.get_adapter = fail
    if kind == "header_storage":
        session.headers._store = Mapping()
    if kind == "header_items":
        session.headers._store.items = fail
    if kind == "header_entry":
        session.headers._store["user-agent"] = Tuple(("User-Agent", "exact"))
    if kind == "hooks":
        session.hooks = Mapping()
    if kind == "hook_list":
        session.hooks["response"] = Sequence()
    if kind == "auth":
        session.auth = Object()
    if kind == "retry":
        adapter.max_retries = Object()
    if kind == "retry_total":
        adapter.max_retries.total = Object()
    if kind == "retry_history":
        adapter.max_retries.history = Tuple()
    if kind == "pool":
        adapter.poolmanager = Object()
    if kind == "pool_headers":
        pool.headers = Mapping()
    if kind == "pool_config":
        pool.connection_pool_kw = Mapping()
    if kind == "pool_classes":
        pool.pool_classes_by_scheme = {"http": Object(), "https": pool.pool_classes_by_scheme["https"]}
    if kind == "pool_keys":
        pool.key_fn_by_scheme["http"] = Object()
    if kind == "pool_entries":
        pool.pools._container = Mapping()
    if kind == "pool_size":
        pool.pools._maxsize = Object()
    if kind == "adapter_config":
        adapter.config = Mapping()
    if kind == "adapter_proxy":
        adapter.proxy_manager = Mapping()
    if kind == "adapter_send":
        adapter.send = fail
    if kind == "pool_key_keywords":
        monkeypatch.setitem(pool.key_fn_by_scheme["http"].keywords, "context", "altered")
    if kind == "pool_connections":
        adapter._pool_connections = Object()
    if kind == "params":
        session.params = Mapping()
    if kind == "proxies":
        session.proxies = Mapping()
    if kind == "verify":
        session.verify = Text("/path")
    if kind == "cert":
        session.cert = (Text("/certificate"), "/key")
    if kind == "request_headers":
        headers = Mapping()
    calls.clear()
    monkeypatch.setattr(owner, "encode", fail)
    with observation_server() as server:
        with pytest.raises((TypeError, ValueError)):
            owner.send_bounded_request(session=session, method="POST", url=server["url"],
                headers=headers, body=b"exact", timeout=2,
                deadline_ns=time.monotonic_ns() + 2_000_000_000,
                max_body=200, media_type="application/x-norito")
        assert server["calls"] == [] and children == [] and calls == []


@pytest.mark.parametrize("kind", [
    "method", "url", "verify", "cert", "cert_pair", "media_type", "header_key",
    "header_value", "utf8_value", "session_header", "proxy", "parameter",
    "request_entries", "session_entries", "adapter_prefix",
])
def test_bounded_requests_oversized_scalars_and_cardinality_reject_before_encoding_child_or_dispatch(kind, monkeypatch, children):
    calls = []
    def unexpected(*args, **kwargs):
        calls.append("encoder")
        raise AssertionError("full Norito encoding ran before bounds admission")
    monkeypatch.setattr(owner, "encode", unexpected)
    session = requests.Session()
    session.trust_env = False
    headers = {"Content-Type": "application/x-norito"}
    method = "POST"
    media_type = "application/x-norito"
    suffix = ""
    large = "x" * (owner._FRAME_LIMIT + 1)
    if kind == "method":
        method = large
    if kind == "url":
        suffix = "/" + large
    if kind == "verify":
        session.verify = large
    if kind == "cert":
        session.cert = large
    if kind == "cert_pair":
        session.cert = ("/certificate", large)
    if kind == "media_type":
        media_type = large
    if kind == "header_key":
        headers = {large: "x"}
    if kind == "header_value":
        headers["X-Test"] = large
    if kind == "utf8_value":
        headers["X-Test"] = "\u0800" * 21846
    if kind == "session_header":
        session.headers["X-Test"] = large
    if kind == "proxy":
        session.proxies["https"] = large
    if kind == "parameter":
        session.params["q"] = large
    if kind == "request_entries":
        headers = {str(index): "x" for index in range(129)}
    if kind == "session_entries":
        session.params = {str(index): "x" for index in range(129)}
    if kind == "adapter_prefix":
        session.adapters = OrderedDict([("https://", session.adapters["https://"]), (large, session.adapters["http://"])])
    with observation_server() as server:
        with pytest.raises((TypeError, ValueError)):
            owner.send_bounded_request(session=session, method=method, url=server["url"] + suffix,
                headers=headers, body=b"exact", timeout=2,
                deadline_ns=time.monotonic_ns() + 2_000_000_000,
                max_body=200, media_type=media_type)
        assert server["calls"] == [] and children == [] and calls == []


def test_bounded_requests_aggregate_ipc_envelope_is_admitted_before_full_encoding(monkeypatch, children):
    calls = []
    def unexpected(*args, **kwargs):
        calls.append("encoder")
        raise AssertionError("aggregate envelope encoded before admission")
    monkeypatch.setattr(owner, "encode", unexpected)
    session = requests.Session()
    session.trust_env = False
    text = "x" * 65000
    session.headers = requests.structures.CaseInsensitiveDict({"s": text})
    session.params = {"p": text}
    session.proxies = {"https": text}
    session.verify = text
    session.cert = (text, text)
    with observation_server() as server:
        with pytest.raises(ValueError, match="envelope"):
            owner.send_bounded_request(session=session, method="POST", url=server["url"] + "/" + "x" * 10000,
                headers={"h": text}, body=bytes(64 * 1024), timeout=2,
                deadline_ns=time.monotonic_ns() + 2_000_000_000,
                max_body=200, media_type="application/x-norito")
        assert calls == [] and children == [] and server["calls"] == []


def test_bounded_requests_expanded_prepared_url_is_rejected_in_child_before_dispatch(children):
    session = requests.Session()
    session.trust_env = False
    session.params = {"expanded": "%" * 23000}
    with observation_server() as server:
        with pytest.raises(ValueError):
            send(server["url"], session=session)
        assert server["calls"] == []
    assert len(children) == 1


def alias_fixture_headers(*, expired=False):
    from iroha_python.sorafs import alias_proof_fixture, evaluate_alias_proof
    now = int(time.time())
    proof = alias_proof_fixture(generated_at_unix=now - 500,
                                expires_at_unix=now - 1 if expired else now + 30)
    evaluation = evaluate_alias_proof(proof["proof_b64"])
    if not expired:
        assert evaluation.state == "refresh_window" and evaluation.servable
    return {"Sora-Name": proof["alias"], "Sora-Proof": proof["proof_b64"]}, proof


def alias_logger(stream=None):
    import logging
    logger = logging.Logger("staking.alias.tests")
    logger.propagate = False
    logger.addHandler(logging.NullHandler() if stream is None else logging.StreamHandler(stream))
    return logger


def test_bounded_staking_genuine_refresh_proof_updates_exact_metrics_and_logs_once_per_response(children):
    from staking_preparation_test import client, fixture
    request, prepared, _, body = fixture()
    headers, proof = alias_fixture_headers()
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(write_fd, "w", encoding="utf-8")
    try:
        with observation_server(body, headers=headers) as server:
            api = client(server["url"], prepared.network_id)
            api._sorafs_alias_logger = alias_logger(stream)
            actual = api.prepare_public_lane_plan(request, prepared.xor_asset_definition_id)
            assert actual.to_norito() == prepared.to_norito()
            evaluation = api.get_last_sorafs_alias_evaluation()
            assert evaluation.state == "refresh_window" and evaluation.servable
            assert evaluation.generated_at_unix == proof["generated_at_unix"]
            assert evaluation.expires_at_unix == proof["expires_at_unix"]
            assert api.get_sorafs_alias_metrics() == {"total": 1, evaluation.status_label: 1, "warnings": 1}
            api.prepare_public_lane_plan(request, prepared.xor_asset_definition_id)
            assert api.get_sorafs_alias_metrics() == {"total": 2, evaluation.status_label: 2, "warnings": 2}
            assert len(server["calls"]) == 2
        os.set_blocking(read_fd, False)
        notice = os.read(read_fd, 4096).decode()
        assert notice.count("SoraFS alias 'docs/sora' nearing refresh window:") == 2
        assert f"status={evaluation.status_label} age=" in notice
        assert notice.count("\n") == 2
        # The worker owns duplicate descriptors; the original logger stays open.
        assert not stream.closed and os.fstat(write_fd)
    finally:
        stream.close()
        os.close(read_fd)
    assert len(children) == 2


@pytest.mark.parametrize("kind", ["invalid", "expired"])
def test_bounded_staking_alias_proof_rejection_uses_real_native_policy_and_no_metrics(kind, children):
    from staking_preparation_test import client, fixture
    request, prepared, _, body = fixture()
    headers, _ = alias_fixture_headers(expired=kind == "expired")
    if kind == "invalid":
        headers["Sora-Proof"] = "AAAA"
    with observation_server(body, headers=headers) as server:
        api = client(server["url"], prepared.network_id)
        with pytest.raises(ValueError if kind == "invalid" else RuntimeError):
            api.prepare_public_lane_plan(request, prepared.xor_asset_definition_id)
        assert api.get_sorafs_alias_metrics() == {}
        assert api.get_last_sorafs_alias_evaluation() is None
        assert len(server["calls"]) == 1
    assert len(children) == 1


@pytest.mark.parametrize("kind", ["callback", "handler", "logger", "filter", "formatter", "format_width", "manager", "metrics", "previous"])
def test_bounded_staking_rejects_blocking_alias_graph_before_callback_child_or_dispatch(kind, children):
    import logging

    from staking_preparation_test import client, fixture
    request, prepared, _, body = fixture()
    headers, _ = alias_fixture_headers()
    markers = []
    def blocked(*args, **kwargs):
        markers.append("unowned alias callback")
        time.sleep(2)
    class Handler(logging.Handler):
        def emit(self, record): blocked(record)
    class Logger(logging.Logger):
        def warning(self, *args, **kwargs): blocked(*args, **kwargs)
    class Filter:
        def filter(self, record): blocked(record)
    class Metrics(dict):
        def get(self, *args, **kwargs): blocked(*args, **kwargs)
    class Formatter(logging.Formatter):
        def format(self, record): blocked(record)
    with observation_server(body, headers=headers) as server:
        api = client(server["url"], prepared.network_id, timeout=0.6)
        if kind == "callback":
            api.set_sorafs_alias_warning(blocked)
        if kind == "handler":
            api._sorafs_alias_logger.handlers = [Handler()]
        if kind == "logger":
            api._sorafs_alias_logger = Logger("unowned")
        if kind == "filter":
            api._sorafs_alias_logger.filters = [Filter()]
        if kind in ("formatter", "format_width"):
            handler = logging.StreamHandler()
            handler.setFormatter(Formatter() if kind == "formatter" else logging.Formatter("%(message)999999999999s"))
            api._sorafs_alias_logger.handlers = [handler]
        if kind == "manager":
            api._sorafs_alias_logger.manager = object()
        if kind == "metrics":
            api._sorafs_alias_metrics = Metrics()
        if kind == "previous":
            api._last_sorafs_alias_evaluation = object()
        started = time.monotonic()
        with pytest.raises((TypeError, ValueError)):
            api.prepare_public_lane_plan(request, prepared.xor_asset_definition_id)
        assert time.monotonic() - started < 0.6
        assert markers == [] and children == [] and server["calls"] == []


def test_bounded_staking_standard_alias_log_pipe_block_is_owned_by_original_deadline(children):
    from staking_preparation_test import client, fixture
    request, prepared, _, body = fixture()
    headers, _ = alias_fixture_headers()
    read_fd, write_fd = os.pipe()
    os.set_blocking(write_fd, False)
    filled = 0
    try:
        while True:
            filled += os.write(write_fd, b"x" * 4096)
    except BlockingIOError:
        pass
    os.set_blocking(write_fd, True)
    stream = os.fdopen(write_fd, "w", encoding="utf-8")
    try:
        with observation_server(body, headers=headers) as server:
            api = client(server["url"], prepared.network_id, timeout=0.9)
            api._sorafs_alias_logger = alias_logger(stream)
            started = time.monotonic()
            with pytest.raises(requests.Timeout):
                api.prepare_public_lane_plan(request, prepared.xor_asset_definition_id)
            assert 0.8 <= time.monotonic() - started < 1.5
            assert len(server["calls"]) == 1 and server["finished"].wait(1)
            assert api.get_sorafs_alias_metrics() == {}
            assert not stream.closed and os.fstat(write_fd)
        os.set_blocking(read_fd, False)
        drained = bytearray()
        while True:
            try:
                drained.extend(os.read(read_fd, 8192))
            except BlockingIOError:
                break
        assert bytes(drained) == b"x" * filled
    finally:
        stream.close()
        os.close(read_fd)
    assert len(children) == 1


def test_bounded_staking_default_last_resort_logging_stays_in_owned_worker(monkeypatch, children):
    import logging

    from staking_preparation_test import client, fixture
    request, prepared, _, body = fixture()
    headers, _ = alias_fixture_headers()
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(write_fd, "w", encoding="utf-8")
    root = logging.RootLogger(logging.WARNING)
    logger = logging.Logger("iroha_python.sorafs.client")
    logger.parent = root
    try:
        monkeypatch.setattr(sys, "stderr", stream)
        with observation_server(body, headers=headers) as server:
            api = client(server["url"], prepared.network_id)
            api._sorafs_alias_logger = logger
            api.prepare_public_lane_plan(request, prepared.xor_asset_definition_id)
            assert api.get_sorafs_alias_metrics()["warnings"] == 1
        os.set_blocking(read_fd, False)
        assert os.read(read_fd, 4096).count(b"SoraFS alias 'docs/sora'") == 1
    finally:
        monkeypatch.undo()
        stream.close()
        os.close(read_fd)
    assert len(children) == 1


@pytest.mark.parametrize("state", ["fresh", "hard_expired"])
def test_bounded_staking_worker_preserves_exact_configured_alias_thresholds(state, children):
    from dataclasses import replace

    from iroha_python.sorafs import SorafsAliasPolicy, evaluate_alias_proof
    from staking_preparation_test import client, fixture
    request, prepared, _, body = fixture()
    headers, proof = alias_fixture_headers()
    policy = SorafsAliasPolicy.defaults()
    policy = (replace(policy, refresh_window_secs=1) if state == "fresh" else
              replace(policy, positive_ttl_secs=1, refresh_window_secs=1, hard_expiry_secs=1))
    expected = evaluate_alias_proof(proof["proof_b64"], policy=policy)
    assert expected.state == state
    with observation_server(body, headers=headers) as server:
        api = client(server["url"], prepared.network_id)
        api.set_sorafs_alias_policy(policy)
        if expected.servable:
            api.prepare_public_lane_plan(request, prepared.xor_asset_definition_id)
            actual = api.get_last_sorafs_alias_evaluation()
            assert actual.state == expected.state and actual.status_label == expected.status_label
            assert actual.generated_at_unix == expected.generated_at_unix
            assert api.get_sorafs_alias_metrics() == {"total": 1, expected.status_label: 1}
        else:
            with pytest.raises(RuntimeError, match="failed to validate SoraFS alias proof"):
                api.prepare_public_lane_plan(request, prepared.xor_asset_definition_id)
            assert api.get_sorafs_alias_metrics() == {}
            assert api.get_last_sorafs_alias_evaluation() is None
        assert len(server["calls"]) == 1
    assert len(children) == 1


@pytest.mark.parametrize("kind", ["subclass", "instance_dispatch", "instance_context",
    "default_headers", "header_key", "timeout", "base_url", "request_codec",
    "request_field", "quantity_field", "local_context"])
def test_bounded_staking_parent_graph_refuses_before_original_point35_second_callbacks(kind, children):
    from iroha_python import ToriiClient
    from staking_preparation_test import client, fixture
    request, prepared, _, body = fixture()
    markers = []

    def blocked(*args, **kwargs):
        markers.append("unowned parent callback")
        time.sleep(0.35)
        raise AssertionError("parent callback exceeded original 0.1 second deadline")

    class CustomClient(ToriiClient):
        def _request(self, *args, **kwargs):
            return blocked(*args, **kwargs)

    class Headers:
        def keys(self):
            blocked()
            return []

    class Text(str):
        def __format__(self, spec): return blocked(spec)
        def lower(self): return blocked()
        def __str__(self): return blocked()

    class Number(float):
        def __gt__(self, value): return blocked(value)
        def __mul__(self, value): return blocked(value)

    with observation_server(body) as server:
        api = client(server["url"], prepared.network_id, timeout=0.1)
        if kind == "subclass":
            api.__class__ = CustomClient
        if kind == "instance_dispatch":
            api._request = blocked
        if kind == "instance_context":
            api._require_local_signing_context = blocked
        if kind == "default_headers":
            api._default_headers = Headers()
        if kind == "header_key":
            api._default_headers = {Text("Accept"): "application/x-norito"}
        if kind == "timeout":
            api._timeout = Number(0.1)
        if kind == "base_url":
            api._base_url = Text(server["url"])
        if kind == "request_codec":
            object.__setattr__(request, "to_norito", blocked)
        if kind == "request_field":
            object.__setattr__(request.operation, "validator", Text(request.operation.validator))
        if kind == "quantity_field":
            object.__setattr__(request.operation.amount, "mantissa", Number(1))
        if kind == "local_context":
            api._ToriiClient__local_signing_context = object()
        started = time.monotonic()
        # Invoke the inherited public entry even when an instance has a virtual
        # dispatch override; unsupported state must reject before that callback.
        with pytest.raises((TypeError, ValueError)):
            ToriiClient.prepare_public_lane_plan(api, request, prepared.xor_asset_definition_id)
        assert time.monotonic() - started < 0.1
        assert markers == [] and children == [] and server["calls"] == []


@pytest.mark.parametrize("kind", ["method", "path", "headers", "stream_flag", "timeout"])
def test_bounded_request_entry_admits_scalars_before_ordinary_helpers(kind, children):
    from iroha_python import ToriiClient
    from staking_preparation_test import client, fixture
    request, prepared, request_body, response_body = fixture()
    markers = []

    def blocked(*args):
        markers.append("unowned request callback")
        time.sleep(0.35)
        raise AssertionError("request callback ran")

    class Text(str):
        def upper(self): return blocked()
        def startswith(self, *args): return blocked(*args)

    class Headers:
        def keys(self): return blocked()

    class Flag:
        def __bool__(self): return blocked()

    class Number(float):
        def __float__(self): return blocked()

    with observation_server(response_body) as server:
        api = client(server["url"], prepared.network_id)
        values = dict(method="POST", path="/v1/nexus/staking/prepare", headers={},
            data=request_body, stream=True, allow_retry=False, allow_redirects=False,
            _operation_deadline_ns=time.monotonic_ns() + 100_000_000,
            _maximum_body_bytes=256 * 1024, _response_media_type="application/x-norito")
        if kind == "method":
            values["method"] = Text("POST")
        if kind == "path":
            values["path"] = Text("/v1/nexus/staking/prepare")
        if kind == "headers":
            values["headers"] = Headers()
        if kind == "stream_flag":
            values["stream"] = Flag()
        if kind == "timeout":
            values["timeout"] = Number(0.1)
        with pytest.raises((TypeError, ValueError)):
            ToriiClient._request(api, **values)
        assert markers == [] and children == [] and server["calls"] == []


def test_bounded_staking_admission_retains_original_closed_inputs_after_caller_rebinding():
    from iroha_python.validator_staking import encode_staking_preparation_frame_v1
    from staking_preparation_test import client, fixture
    request, prepared, request_bytes, _ = fixture()
    api = client("http://127.0.0.1:1", prepared.network_id)
    timeout, network, frozen = owner.check_preparation_inputs(api, request, prepared.xor_asset_definition_id)
    configuration = owner.check_bounded_client(api)
    original_headers = dict(api._default_headers)
    markers = []

    def blocked(*args):
        markers.append("rebound caller callback")
        raise AssertionError("admitted snapshot used rebound original")

    object.__setattr__(request, "to_norito", blocked)
    object.__setattr__(request.operation.amount, "mantissa", 1)
    api._default_headers = object()
    api._timeout = object()
    api._ToriiClient__local_signing_context = object()
    assert frozen is not request and frozen.operation is not request.operation
    assert encode_staking_preparation_frame_v1(frozen) == request_bytes
    assert timeout == 3 and network == prepared.network_id
    assert configuration["headers"] == original_headers and configuration["timeout"] == 3
    assert markers == []
