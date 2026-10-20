"""Strict Python SDK coverage for SoraFS hedging and billing Torii routes."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode, urlparse

import pytest
import requests
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

from iroha_python import (
    SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_NAME_V1,
    SorafsBillingAcknowledgementProofV1,
    ToriiCanonicalRequestAuth,
    ToriiClient,
    canonical_network_request_signature_message,
    encode_sorafs_billing_acknowledgement_proof_v1,
)
from iroha_python.client import (
    _SORAFS_BILLING_STATEMENT_RESPONSE_MAX_BYTES,
    _SORAFS_HEDGING_BILLING_JSON_RESPONSE_MAX_BYTES,
)
from iroha_python.crypto import NetworkId

from .helpers import StubResponse

BASE_URL = "https://torii.example"
CHECKPOINT = "11" * 32
STATEMENT_ID = "22" * 32
AFTER_STATEMENT_ID = "33" * 32
AFTER_PROJECTION = "44" * 32
REQUEST_NONCE = "91" * 32
AUTHENTICATION_PROOF = b"\xa5" * 64
HEDGING_NETWORK_ID = NetworkId.from_bytes(bytes([0xB5]) * 32)
EXPECTED_PROOF_FRAME_HEX = (
    "4e5254300000fe75acabe03d788012f2e7c556319997006a00000000000000"
    "80460fddbba276090220" + "91" * 32 + "484000000000000000" + "a5" * 64
)


class ChunkedResponse(StubResponse):
    """Response whose body is available only through bounded iteration."""

    def __init__(
        self,
        body: bytes,
        *,
        content_type: str = "application/json",
        content_encoding: str | None = "identity",
        content_length: int | None = None,
    ) -> None:
        super().__init__(200, None)
        self._content = False
        self._body = body
        self.closed = False
        headers = {"Content-Type": content_type}
        if content_encoding is not None:
            headers["Content-Encoding"] = content_encoding
        headers["Content-Length"] = str(len(body) if content_length is None else content_length)
        self.headers = CaseInsensitiveDict(headers)

    def iter_content(self, chunk_size: int = 1, decode_unicode: bool = False):
        assert chunk_size == 8_192
        assert decode_unicode is False
        midpoint = len(self._body) // 2
        if midpoint:
            yield self._body[:midpoint]
        yield self._body[midpoint:]

    def close(self) -> None:
        self.closed = True


class SequencedSession(requests.Session):
    """Capture exact outgoing requests and return responses in order."""

    def __init__(self, responses: list[requests.Response | Exception]) -> None:
        super().__init__()
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str | bytes,
        url: str | bytes,
        *args: Any,
        **kwargs: Any,
    ) -> requests.Response:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "params": kwargs.get("params") or {},
                "headers": kwargs.get("headers") or {},
                "data": kwargs.get("data"),
                "stream": kwargs.get("stream"),
                "allow_redirects": kwargs.get("allow_redirects"),
            }
        )
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def json_response(payload: Any, **kwargs: Any) -> ChunkedResponse:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    return ChunkedResponse(body, **kwargs)


def canonical_auth(
    signer: Any = None,
) -> ToriiCanonicalRequestAuth:
    return ToriiCanonicalRequestAuth(
        network_id=HEDGING_NETWORK_ID.literal,
        account_id="billing-reader@sora",
        signer=signer or (lambda _message: b"\x7c" * 64),
    )


def test_acknowledgement_encoder_matches_shared_rust_schema_and_exact_bytes() -> None:
    proof = SorafsBillingAcknowledgementProofV1(
        REQUEST_NONCE,
        AUTHENTICATION_PROOF,
    )
    assert "authentication_proof" not in repr(proof)
    assert AUTHENTICATION_PROOF.hex() not in repr(proof)
    encoded = encode_sorafs_billing_acknowledgement_proof_v1(
        REQUEST_NONCE,
        AUTHENTICATION_PROOF,
    )
    assert encoded.hex() == EXPECTED_PROOF_FRAME_HEX
    assert encoded[6:22].hex() == "fe75acabe03d788012f2e7c556319997"
    assert encoded[39] == 0x02
    assert (
        SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_NAME_V1
        == "iroha.torii.v1.sorafs.billing.acknowledgement_proof"
    )

    for invalid_nonce in (
        "0" * 64,
        "AA" * 32,
        f"0x{REQUEST_NONCE}",
        "91" * 31,
        bytes.fromhex(REQUEST_NONCE),
    ):
        with pytest.raises((TypeError, ValueError)):
            encode_sorafs_billing_acknowledgement_proof_v1(
                invalid_nonce,  # type: ignore[arg-type]
                b"\x01",
            )
    for invalid_proof in (
        b"",
        b"\x00" * (64 * 1024 + 1),
        bytearray(b"\x01"),
        memoryview(b"\x01"),
        "a5",
    ):
        with pytest.raises((TypeError, ValueError)):
            encode_sorafs_billing_acknowledgement_proof_v1(
                REQUEST_NONCE,
                invalid_proof,  # type: ignore[arg-type]
            )


def test_hedging_billing_routes_sign_exact_requests_once_and_bound_responses() -> None:
    signed_messages: list[bytes] = []

    def signer(message: bytes) -> bytes:
        signed_messages.append(message)
        return b"\x5a" * 64

    statement = b"NRT1"
    acknowledgement_body = encode_sorafs_billing_acknowledgement_proof_v1(
        REQUEST_NONCE,
        AUTHENTICATION_PROOF,
    )
    session = SequencedSession(
        [
            json_response({"route": "status"}),
            json_response({"route": "statements"}),
            ChunkedResponse(statement, content_type="application/x-norito"),
            json_response({"route": "acknowledgement"}),
            json_response({"route": "reconciliation"}),
            json_response({"route": "exposure"}),
            json_response({"route": "intents"}),
        ]
    )
    auth = canonical_auth(signer)
    client = ToriiClient(BASE_URL, session=session, max_retries=9, chain_discriminant=753)

    assert client.get_sorafs_billing_status(canonical_auth=auth) == {"route": "status"}
    assert client.list_sorafs_billing_statements(
        expected_checkpoint_fingerprint_hex=CHECKPOINT,
        after_statement_id_hex=AFTER_STATEMENT_ID,
        limit=25,
        canonical_auth=auth,
    ) == {"route": "statements"}
    assert (
        client.get_sorafs_billing_statement(
            STATEMENT_ID,
            CHECKPOINT,
            canonical_auth=auth,
        )
        == statement
    )
    assert client.acknowledge_sorafs_billing_statement(
        STATEMENT_ID,
        CHECKPOINT,
        request_nonce_hex=REQUEST_NONCE,
        authentication_proof=AUTHENTICATION_PROOF,
        canonical_auth=auth,
    ) == {"route": "acknowledgement"}
    assert client.get_sorafs_billing_reconciliation(canonical_auth=auth) == {
        "route": "reconciliation"
    }
    assert client.get_sorafs_hedging_exposure(
        expected_checkpoint_fingerprint_hex=CHECKPOINT,
        after_hex=AFTER_PROJECTION,
        limit=50,
        canonical_auth=auth,
    ) == {"route": "exposure"}
    assert client.get_sorafs_hedging_intents(
        expected_checkpoint_fingerprint_hex=CHECKPOINT,
        limit=100,
        canonical_auth=auth,
    ) == {"route": "intents"}

    expected = [
        ("GET", "/v1/sorafs/billing/status", {}, b""),
        (
            "GET",
            "/v1/sorafs/billing/statements",
            {
                "expected_checkpoint_fingerprint": CHECKPOINT,
                "after_statement_id": AFTER_STATEMENT_ID,
                "limit": "25",
            },
            b"",
        ),
        (
            "GET",
            f"/v1/sorafs/billing/statements/{STATEMENT_ID}",
            {"expected_checkpoint_fingerprint": CHECKPOINT},
            b"",
        ),
        (
            "POST",
            f"/v1/sorafs/billing/statements/{STATEMENT_ID}/acknowledgements",
            {"expected_checkpoint_fingerprint": CHECKPOINT},
            acknowledgement_body,
        ),
        ("GET", "/v1/sorafs/billing/reconciliation", {}, b""),
        (
            "GET",
            "/v1/sorafs/hedging/exposure",
            {
                "expected_checkpoint_fingerprint": CHECKPOINT,
                "after": AFTER_PROJECTION,
                "limit": "50",
            },
            b"",
        ),
        (
            "GET",
            "/v1/sorafs/hedging/intents",
            {
                "expected_checkpoint_fingerprint": CHECKPOINT,
                "limit": "100",
            },
            b"",
        ),
    ]
    assert len(session.calls) == len(expected) == len(signed_messages)
    for index, (method, path, params, body) in enumerate(expected):
        call = session.calls[index]
        assert call["method"] == method
        assert urlparse(str(call["url"])).path == path
        assert call["params"] == params
        assert call["stream"] is True
        assert call["allow_redirects"] is False
        assert call["headers"]["Accept-Encoding"] == "identity"
        query = urlencode(params)
        request_target = path if not query else f"{path}?{query}"
        headers = call["headers"]
        assert signed_messages[index] == canonical_network_request_signature_message(
            HEDGING_NETWORK_ID.literal,
            method,
            request_target,
            body,
            timestamp_ms=int(headers["X-Iroha-Timestamp-Ms"]),
            nonce=headers["X-Iroha-Nonce"],
        )
    assert session.calls[2]["headers"]["Accept"] == "application/x-norito"
    assert session.calls[3]["headers"]["Content-Type"] == "application/x-norito"
    assert session.calls[3]["data"] == acknowledgement_body


def test_hedging_billing_inputs_are_rejected_before_transport() -> None:
    session = SequencedSession([])
    client = ToriiClient(BASE_URL, session=session, max_retries=0, chain_discriminant=753)
    auth = canonical_auth()

    for invalid in (
        "AA" * 32,
        f"0x{CHECKPOINT}",
        f" {CHECKPOINT}",
        "0" * 64,
        "11" * 31,
        bytes.fromhex(CHECKPOINT),
    ):
        with pytest.raises((TypeError, ValueError)):
            client.list_sorafs_billing_statements(
                expected_checkpoint_fingerprint_hex=invalid,  # type: ignore[arg-type]
                limit=1,
                canonical_auth=auth,
            )
    for invalid_limit in (0, 101, "1", True, 1.0):
        with pytest.raises((TypeError, ValueError)):
            client.get_sorafs_hedging_intents(
                expected_checkpoint_fingerprint_hex=CHECKPOINT,
                limit=invalid_limit,  # type: ignore[arg-type]
                canonical_auth=auth,
            )
    with pytest.raises((TypeError, ValueError)):
        client.acknowledge_sorafs_billing_statement(
            STATEMENT_ID,
            CHECKPOINT,
            request_nonce_hex="0" * 64,
            authentication_proof=b"\x01",
            canonical_auth=auth,
        )
    with pytest.raises(TypeError, match="unexpected keyword argument 'headers'"):
        client.get_sorafs_billing_status(
            canonical_auth=auth,
            headers={},  # type: ignore[call-arg]
        )
    assert session.calls == []


def test_hedging_billing_rejects_oversized_and_transformed_responses() -> None:
    oversized = SequencedSession(
        [
            json_response(
                {},
                content_length=_SORAFS_HEDGING_BILLING_JSON_RESPONSE_MAX_BYTES + 1,
            )
        ]
    )
    with pytest.raises(ValueError, match="byte limit"):
        ToriiClient(BASE_URL, session=oversized, chain_discriminant=753).get_sorafs_billing_status(
            canonical_auth=canonical_auth()
        )

    transformed = SequencedSession([json_response({}, content_encoding="gzip")])
    with pytest.raises(ValueError, match="Content-Encoding must be identity"):
        ToriiClient(BASE_URL, session=transformed, chain_discriminant=753).get_sorafs_billing_status(
            canonical_auth=canonical_auth()
        )

    ambiguous = SequencedSession(
        [
            ChunkedResponse(
                b"x",
                content_type="application/x-norito; version=1",
            )
        ]
    )
    with pytest.raises(ValueError, match="exactly application/x-norito"):
        ToriiClient(BASE_URL, session=ambiguous, chain_discriminant=753).get_sorafs_billing_statement(
            STATEMENT_ID,
            CHECKPOINT,
            canonical_auth=canonical_auth(),
        )

    too_large_statement = SequencedSession(
        [
            ChunkedResponse(
                b"",
                content_type="application/x-norito",
                content_length=_SORAFS_BILLING_STATEMENT_RESPONSE_MAX_BYTES + 1,
            )
        ]
    )
    with pytest.raises(ValueError, match="byte limit"):
        ToriiClient(
            BASE_URL,
            session=too_large_statement,
            chain_discriminant=753,
        ).get_sorafs_billing_statement(
            STATEMENT_ID,
            CHECKPOINT,
            canonical_auth=canonical_auth(),
        )


def test_hedging_billing_rejects_adapter_retries_before_signing() -> None:
    signed_messages: list[bytes] = []
    session = SequencedSession([json_response({"route": "status"})])
    session.mount("https://", HTTPAdapter(max_retries=1))
    client = ToriiClient(BASE_URL, session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises(ValueError, match="transport retries to be disabled"):
        client.get_sorafs_billing_status(canonical_auth=canonical_auth(signed_messages.append))
    assert signed_messages == []
    assert session.calls == []
