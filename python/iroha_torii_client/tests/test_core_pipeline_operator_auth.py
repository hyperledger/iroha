"""Exact operator-authentication tests for node-local core and pipeline reads."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, List, Tuple

import pytest
import requests
from client_test_support import canonical_hash
from requests.adapters import HTTPAdapter
from sumeragi_exact_json_test_support import RecordingSession, StubResponse

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from iroha_torii_client import (  # noqa: E402
    ToriiClient,
    ToriiOperatorSigningContext,
    build_operator_request_headers,
    operator_network_request_signature_message,
)

NETWORK_ID = canonical_hash(0xA5)
FOREIGN_NETWORK_ID = canonical_hash(0xA7)
OPERATOR_READS: Tuple[Tuple[str, Callable[[ToriiClient], object]], ...] = (
    ("/v1/peers", lambda client: client.list_peers()),
    ("/v1/time/status", lambda client: client.get_time_status()),
    ("/v1/pipeline/preflight", lambda client: client.get_pipeline_preflight()),
)


def operator_context(captured: List[bytes] | None = None) -> ToriiOperatorSigningContext:
    """Return a deterministic signer while retaining exact signed messages."""

    def signer(message: bytes) -> bytes:
        if captured is not None:
            captured.append(message)
        return b"\x55" * 64

    return ToriiOperatorSigningContext(
        network_id=NETWORK_ID,
        public_key="ed0120" + "66" * 32,
        signer=signer,
    )


def test_public_operator_header_builder_signs_the_requests_prepared_target() -> None:
    caller_target = "/v1/%2e%2Fasset/%252e"
    prepared = requests.Request(
        "GET",
        f"https://node.test{caller_target}",
    ).prepare()
    captured: List[bytes] = []
    headers = build_operator_request_headers(
        operator_context(captured),
        "GET",
        caller_target,
        b"",
    )

    assert prepared.path_url == "/v1/.%2Fasset/%252e"
    assert captured == [
        operator_network_request_signature_message(
            NETWORK_ID,
            "GET",
            prepared.path_url,
            b"",
            timestamp_ms=int(headers["X-Iroha-Operator-Timestamp-Ms"]),
            nonce=headers["X-Iroha-Operator-Nonce"],
        )
    ]


def test_operator_transport_signs_and_sends_one_prepared_target() -> None:
    caller_target = "/v1/%2e%2Fasset/%252e"
    session = RecordingSession()
    session.queue(StubResponse(status_code=503, text="unavailable"))
    captured: List[bytes] = []
    client = ToriiClient(
        "https://node.test",
        session=session,
        operator_signing_context=operator_context(captured),
    )

    response = client._operator_get(caller_target)

    assert response.status_code == 503
    call = session.calls[0]
    assert call["url"] == "https://node.test/v1/.%2Fasset/%252e"
    headers = call["headers"]
    assert captured == [
        operator_network_request_signature_message(
            NETWORK_ID,
            "GET",
            "/v1/.%2Fasset/%252e",
            b"",
            timestamp_ms=int(headers["X-Iroha-Operator-Timestamp-Ms"]),
            nonce=headers["X-Iroha-Operator-Nonce"],
        )
    ]


@pytest.mark.parametrize(("path", "invoke"), OPERATOR_READS)
def test_operator_reads_sign_one_exact_network_empty_body_get(
    path: str,
    invoke: Callable[[ToriiClient], object],
) -> None:
    session = RecordingSession()
    session.queue(StubResponse(status_code=503, text="unavailable"))
    captured: List[bytes] = []
    client = ToriiClient(
        "https://node.test",
        session=session,
        operator_signing_context=operator_context(captured),
    )

    with pytest.raises(RuntimeError, match="unexpected status 503"):
        invoke(client)

    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == f"https://node.test{path}"
    assert call["params"] == {}
    assert call["data"] is None
    assert call["allow_redirects"] is False
    assert call["stream"] is False
    headers = call["headers"]
    assert "Authorization" not in headers
    assert "X-API-Token" not in headers
    assert headers["X-Iroha-Operator-Public-Key"]
    assert headers["X-Iroha-Operator-Signature"]
    timestamp_ms = int(headers["X-Iroha-Operator-Timestamp-Ms"])
    nonce = headers["X-Iroha-Operator-Nonce"]
    assert captured == [
        operator_network_request_signature_message(
            NETWORK_ID,
            "GET",
            path,
            b"",
            timestamp_ms=timestamp_ms,
            nonce=nonce,
        )
    ]
    assert captured[0] != operator_network_request_signature_message(
        FOREIGN_NETWORK_ID,
        "GET",
        path,
        b"",
        timestamp_ms=timestamp_ms,
        nonce=nonce,
    )


@pytest.mark.parametrize(("path", "invoke"), OPERATOR_READS)
def test_operator_reads_reject_missing_context_before_dispatch(
    path: str,
    invoke: Callable[[ToriiClient], object],
) -> None:
    del path
    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session)

    with pytest.raises(ValueError, match="ToriiOperatorSigningContext"):
        invoke(client)

    assert session.calls == []


def test_operator_reads_reject_token_fallback_and_refresh_nonce_per_call() -> None:
    fallback_session = RecordingSession()
    fallback_session.headers["Authorization"] = "Bearer retired"
    fallback_client = ToriiClient(
        "https://node.test",
        session=fallback_session,
        operator_signing_context=operator_context(),
    )
    with pytest.raises(ValueError, match="reject token"):
        fallback_client.list_peers()
    assert fallback_session.calls == []

    auth_session = RecordingSession()
    auth_session.auth = ("retired-user", "retired-password")
    auth_client = ToriiClient(
        "https://node.test",
        session=auth_session,
        operator_signing_context=operator_context(),
    )
    with pytest.raises(ValueError, match="Session.auth"):
        auth_client.list_peers()
    assert auth_session.calls == []

    retry_session = RecordingSession()
    retry_session.mount("https://", HTTPAdapter(max_retries=1))
    retry_client = ToriiClient(
        "https://node.test",
        session=retry_session,
        operator_signing_context=operator_context(),
    )
    with pytest.raises(ValueError, match="adapter retries"):
        retry_client.get_pipeline_preflight()
    assert retry_session.calls == []

    session = RecordingSession()
    session.queue(StubResponse(status_code=503, text="unavailable"))
    session.queue(StubResponse(status_code=503, text="unavailable"))
    captured: List[bytes] = []
    client = ToriiClient(
        "https://node.test",
        session=session,
        operator_signing_context=operator_context(captured),
    )
    for _ in range(2):
        with pytest.raises(RuntimeError, match="unexpected status 503"):
            client.get_time_status()

    assert len(session.calls) == 2
    assert len(captured) == 2
    assert captured[0] != captured[1]
    assert (
        session.calls[0]["headers"]["X-Iroha-Operator-Nonce"]
        != session.calls[1]["headers"]["X-Iroha-Operator-Nonce"]
    )
