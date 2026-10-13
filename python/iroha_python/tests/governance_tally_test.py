"""Exact standalone-governance tally responses and authenticated transport."""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import requests
from iroha_torii_client.client import GovernanceTally as LowGovernanceTally
from iroha_torii_client.client import ToriiClient as LowToriiClient
from iroha_torii_client.governance_tally import GOVERNANCE_TALLY_RESPONSE_MAX_BYTES
from requests.structures import CaseInsensitiveDict

from iroha_python.address import AccountAddress
from iroha_python.client import (
    GovernanceTally,
    LocalSigningContext,
    ToriiCanonicalRequestAuth,
    ToriiClient,
    canonical_network_request_signature_message,
)
from iroha_python.crypto import Ed25519KeyPair, NetworkId
from iroha_python.sorafs import SorafsAliasPolicy

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures/governance/plain_v1"
_CASES = json.loads((_FIXTURES / "cases.json").read_bytes())
_TALLY_CASES = [case for case in _CASES["cases"] if case["kind"] == "tally"]
_METHODS = ("get_governance_tally", "get_governance_tally_typed", "low_typed")
_U128_MAX = (1 << 128) - 1
_U64_MAX = (1 << 64) - 1


class TallyResponse(requests.Response):
    """Expose original response bytes through actual bounded reads only."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        super().__init__()
        self.status_code = status
        self.headers = CaseInsensitiveDict(
            {
                "Content-Type": "application/json",
                "Content-Encoding": "identity",
                "Content-Length": str(len(body)),
            }
        )
        self.body = body
        self.closed = False
        self.reads = 0
        self._content = False

    def iter_content(self, chunk_size: int = 1, decode_unicode: bool = False):
        assert chunk_size == 8192
        assert decode_unicode is False
        self.reads += 1
        midpoint = len(self.body) // 2
        yield self.body[:midpoint]
        yield self.body[midpoint:]

    def json(self, **kwargs: Any) -> Any:
        raise AssertionError("the tally must parse its bounded original bytes")

    def close(self) -> None:
        self.closed = True


class TallySession(requests.Session):
    """Capture the final signed request and preserve streaming options."""

    def __init__(self, response: TallyResponse) -> None:
        super().__init__()
        self.response = response
        self.calls: list[tuple[requests.PreparedRequest, dict[str, Any]]] = []

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        self.calls.append((request, kwargs))
        self.response.url = request.url
        return self.response


@pytest.fixture
def auth() -> ToriiCanonicalRequestAuth:
    """Use the ordinary native identity owner for canonical request authentication."""

    network = NetworkId.from_bytes(bytes([0xA5]) * 32)
    key = Ed25519KeyPair.from_private_key(bytes([0x11]) * 32)
    account = AccountAddress.from_account(public_key=key.public_key).to_i105(0x02F1)
    return ToriiCanonicalRequestAuth(
        network_id=network.literal,
        account_id=account,
        signer=lambda _message: bytes([0x44]) * 64,
        timestamp_ms=4_102_444_801_000,
        nonce="python-governance-tally-test",
    )


def client_for(response: TallyResponse, auth: ToriiCanonicalRequestAuth):
    session = TallySession(response)
    client = ToriiClient(
        "http://node.test",
        session=session,
        local_signing_context=LocalSigningContext(NetworkId.parse(auth.network_id)),
        sorafs_alias_policy=SorafsAliasPolicy(
            positive_ttl_secs=60,
            refresh_window_secs=30,
            hard_expiry_secs=120,
            negative_ttl_secs=30,
            revocation_ttl_secs=30,
            rotation_max_age_secs=60,
            successor_grace_secs=0,
            governance_grace_secs=0,
        ),
    )
    return client, session


def tally_method_for(response: TallyResponse, auth: ToriiCanonicalRequestAuth, method: str):
    if method == "low_typed":
        session = TallySession(response)
        client = LowToriiClient("http://node.test", session=session)
        return client.get_governance_tally, session
    client, session = client_for(response, auth)
    return getattr(client, method), session


def test_tally_both_packages_export_the_same_model_owner() -> None:
    assert GovernanceTally is LowGovernanceTally


def valid_payload() -> dict[str, Any]:
    return {
        "referendum_id": "ref-1",
        "evaluated_block_height": 7,
        "evaluated_block_hash": "12" * 32,
        "approve": 11,
        "reject": 3,
        "abstain": 2,
    }


def encoded(payload: Any) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


@pytest.mark.parametrize("method", _METHODS)
@pytest.mark.parametrize("case", _TALLY_CASES, ids=lambda case: case["file"])
def test_tally_shared_source_contract_vectors(method, case, auth) -> None:
    # These shared vectors are hand-authored, not native-generated release evidence.
    body = (_FIXTURES / case["file"]).read_bytes()
    response = TallyResponse(body)
    fetch, session = tally_method_for(response, auth, method)
    if case["valid"]:
        result = fetch("ref-1", canonical_auth=auth)
        expected = json.loads(body)
        if method != "get_governance_tally":
            assert result == GovernanceTally.from_payload(expected)
            assert result.evaluated_block_height == expected["evaluated_block_height"]
            assert result.evaluated_block_hash == expected["evaluated_block_hash"]
        else:
            assert result == expected
            assert type(result["approve"]) is int
    else:
        with pytest.raises((TypeError, ValueError)):
            fetch("ref-1", canonical_auth=auth)
    assert len(session.calls) == 1
    assert response.closed


@pytest.mark.parametrize("field", ["approve", "reject", "abstain", "evaluated_block_height"])
@pytest.mark.parametrize("value", [True, False, None, "1", 1.0, Decimal("1"), -1])
def test_tally_model_rejects_integer_coercions(field, value) -> None:
    payload = valid_payload()
    payload[field] = value
    with pytest.raises((TypeError, ValueError)):
        GovernanceTally.from_payload(payload)


@pytest.mark.parametrize("field", tuple(valid_payload()))
def test_tally_model_requires_every_field(field) -> None:
    payload = valid_payload()
    del payload[field]
    with pytest.raises(TypeError, match="missing required"):
        GovernanceTally.from_payload(payload)


@pytest.mark.parametrize("field", ["approve", "reject", "abstain"])
def test_tally_model_accepts_each_u128_boundary_without_rounding(field) -> None:
    payload = {**valid_payload(), "approve": 0, "reject": 0, "abstain": 0}
    payload[field] = _U128_MAX
    tally = GovernanceTally.from_payload(payload)
    assert getattr(tally, field) == _U128_MAX
    payload[field] += 1
    with pytest.raises(ValueError, match="u128"):
        GovernanceTally.from_payload(payload)


@pytest.mark.parametrize("method", _METHODS)
def test_tally_404_is_absent_without_body_read_or_zero_result(method, auth) -> None:
    response = TallyResponse(b"not a tally", 404)
    fetch, session = tally_method_for(response, auth, method)
    assert fetch("ref-1", canonical_auth=auth) is None
    assert len(session.calls) == 1
    assert response.reads == 0
    assert response.closed


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b" \r\n\t",
        b"{}",
        b"[]",
        b"null",
        b"true",
        b"{",
        b"\xff",
        b"\xef\xbb\xbf" + encoded(valid_payload()),
        encoded(valid_payload()) + b"{}",
        encoded(valid_payload()).replace(b'"approve":11', b'"approve":11,"approve":12'),
        encoded(valid_payload()).replace(b'"approve":11', b'"approve":-0'),
        encoded(valid_payload()).replace(b'"approve":11', b'"approve":1.0'),
        encoded(valid_payload()).replace(b'"approve":11', b'"approve":1e0'),
        encoded(valid_payload()).replace(b'"approve":11', b'"approve":NaN'),
        encoded({**valid_payload(), "extra": 0}),
    ],
)
def test_tally_200_malformed_body_rejects_and_closes(body, auth) -> None:
    response = TallyResponse(body)
    client, _ = client_for(response, auth)
    with pytest.raises((TypeError, ValueError)):
        client.get_governance_tally_typed("ref-1", canonical_auth=auth)
    assert response.closed


@pytest.mark.parametrize(
    "header,value",
    [
        ("Content-Length", "1"),
        ("Content-Length", "01"),
        ("Content-Length", str(GOVERNANCE_TALLY_RESPONSE_MAX_BYTES + 1)),
        ("Content-Type", "text/html"),
        ("Content-Encoding", "gzip"),
    ],
)
def test_tally_transport_rejects_invalid_framing_and_closes(header, value, auth) -> None:
    response = TallyResponse(encoded(valid_payload()))
    response.headers[header] = value
    client, _ = client_for(response, auth)
    with pytest.raises(ValueError):
        client.get_governance_tally("ref-1", canonical_auth=auth)
    assert response.closed


def test_tally_actual_byte_bound_precedes_json_whitespace_removal(auth) -> None:
    response = TallyResponse(b" " * GOVERNANCE_TALLY_RESPONSE_MAX_BYTES + b"{}")
    del response.headers["Content-Length"]
    client, _ = client_for(response, auth)
    with pytest.raises(ValueError, match="byte limit"):
        client.get_governance_tally("ref-1", canonical_auth=auth)
    assert response.closed


def test_tally_transport_rejects_prebuffered_body(auth) -> None:
    response = TallyResponse(encoded(valid_payload()))
    response._content = response.body
    client, _ = client_for(response, auth)
    with pytest.raises(ValueError, match="prebuffered"):
        client.get_governance_tally("ref-1", canonical_auth=auth)
    assert response.closed


def test_tally_maximal_selector_and_numeric_width_fit_body_cap(auth) -> None:
    payload = {
        **valid_payload(),
        "referendum_id": "a" * 128,
        "evaluated_block_height": _U64_MAX,
        "approve": 1 << 126,
        "reject": 1 << 126,
        "abstain": 1 << 126,
    }
    body = encoded(payload)
    assert len(body) < GOVERNANCE_TALLY_RESPONSE_MAX_BYTES
    response = TallyResponse(b" \r\n" + body + b"\t\n")
    client, _ = client_for(response, auth)
    assert client.get_governance_tally(payload["referendum_id"], canonical_auth=auth) == payload
    assert response.closed


@pytest.mark.parametrize("method", _METHODS)
def test_tally_keeps_exact_canonical_auth_and_one_shot_streaming(method, auth) -> None:
    response = TallyResponse(encoded(valid_payload()))
    fetch, session = tally_method_for(response, auth, method)
    signed = []
    key = Ed25519KeyPair.from_private_key(bytes([0x11]) * 32)
    exact_auth = replace(
        auth, signer=lambda message: signed.append(message) or key.sign(message)
    )
    fetch("ref-1", canonical_auth=exact_auth)
    assert signed == [
        canonical_network_request_signature_message(
            auth.network_id,
            "GET",
            "/v1/gov/tally/ref-1",
            b"",
            timestamp_ms=auth.timestamp_ms,
            nonce=auth.nonce,
        )
    ]
    assert len(session.calls) == 1
    request, options = session.calls[0]
    assert request.method == "GET"
    assert request.url == "http://node.test/v1/gov/tally/ref-1"
    assert request.body in (None, b"")
    assert request.headers["Accept"] == "application/json"
    assert request.headers["Accept-Encoding"] == "identity"
    assert request.headers["X-Iroha-Account"] == AccountAddress.parse_encoded(
        auth.account_id, expected_discriminant=0x02F1
    ).canonical_hex()
    signature = base64.b64decode(request.headers["X-Iroha-Signature"], validate=True)
    assert key.verify(signed[0], signature)
    for changed_message in (
        canonical_network_request_signature_message(
            auth.network_id,
            "POST",
            "/v1/gov/tally/ref-1",
            b"",
            timestamp_ms=auth.timestamp_ms,
            nonce=auth.nonce,
        ),
        canonical_network_request_signature_message(
            auth.network_id,
            "GET",
            "/v1/gov/tally/ref-2",
            b"",
            timestamp_ms=auth.timestamp_ms,
            nonce=auth.nonce,
        ),
    ):
        assert not key.verify(changed_message, signature)
    assert options["stream"] is True
    assert options["allow_redirects"] is False
    assert response.closed


def test_tally_rejects_missing_canonical_auth_before_dispatch(auth) -> None:
    response = TallyResponse(encoded(valid_payload()))
    client, session = client_for(response, auth)
    with pytest.raises((TypeError, ValueError)):
        client.get_governance_tally("ref-1", canonical_auth=None)
    assert session.calls == []


@pytest.mark.parametrize("status", [204, 307, 401, 500])
def test_tally_unexpected_status_closes_without_body_read(status, auth) -> None:
    response = TallyResponse(b"must not be read", status)
    client, session = client_for(response, auth)
    with pytest.raises(RuntimeError, match=f"unexpected status {status}"):
        client.get_governance_tally("ref-1", canonical_auth=auth)
    assert len(session.calls) == 1
    assert response.reads == 0
    assert response.closed
