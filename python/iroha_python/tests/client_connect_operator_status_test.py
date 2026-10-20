"""Focused operator-auth tests for the Connect aggregate status read."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
import requests
from iroha_torii_client.client import canonical_request_message

from iroha_python import NetworkId, OperatorSigningContext, ToriiClient
from iroha_python.crypto import Ed25519KeyPair

NETWORK_BYTES = bytes([0xC7]) * 32
NETWORK_ID = NetworkId.from_bytes(NETWORK_BYTES)
KEY_PAIR = Ed25519KeyPair.from_private_key(bytes([0x17]) * 32)


class RecordingSession(requests.Session):
    """Record the single request while retaining real no-retry adapter policy."""

    def __init__(self, response: requests.Response) -> None:
        super().__init__()
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str | bytes, url: str | bytes, **kwargs: Any) -> requests.Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.response


def json_response(status: int, payload: object) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(payload).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    return response


def test_connect_aggregate_status_requires_operator_context_before_dispatch() -> None:
    session = RecordingSession(json_response(200, {"enabled": True}))
    client = ToriiClient("https://torii.example", session=session, chain_discriminant=753)

    with pytest.raises(ValueError, match="operator_signing_context"):
        client.get_connect_status()

    assert session.calls == []


def test_connect_aggregate_status_signs_exact_network_target_once() -> None:
    session = RecordingSession(json_response(200, {"enabled": True}))
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=OperatorSigningContext(NETWORK_ID, KEY_PAIR),
        max_retries=5,
        retry_on_methods=["GET"],
        retry_on_status=[503],
        chain_discriminant=753,
    )

    assert client.get_connect_status() == {"enabled": True}

    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://torii.example/v1/connect/status/aggregate"
    assert call["data"] == b""
    assert call["allow_redirects"] is False
    headers = call["headers"]
    timestamp = headers["x-iroha-operator-timestamp-ms"]
    nonce = headers["x-iroha-operator-nonce"]
    signature = base64.b64decode(headers["x-iroha-operator-signature"], validate=True)
    canonical = canonical_request_message(
        "GET",
        "/v1/connect/status/aggregate",
        b"",
    )
    message = b"".join(
        (
            b"iroha.operator.http-request.network.v1\0",
            NETWORK_BYTES,
            canonical,
            f"\n{timestamp}\n{nonce}".encode("ascii"),
        )
    )
    assert KEY_PAIR.verify(message, signature)
    foreign_message = message.replace(NETWORK_BYTES, bytes([0xC8]) * 32, 1)
    assert not KEY_PAIR.verify(foreign_message, signature)
