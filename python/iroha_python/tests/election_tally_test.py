"""One exact signed standalone-election tally path in both Python clients."""

from __future__ import annotations

import json
from typing import Any

import pytest
import requests
from iroha_torii_client.client import ElectionTally as LowElectionTally
from iroha_torii_client.client import ToriiClient as LowToriiClient
from requests.structures import CaseInsensitiveDict

from iroha_python import ElectionTally
from iroha_python.client import (
    LocalSigningContext,
    ToriiCanonicalRequestAuth,
    ToriiClient,
    canonical_network_request_signature_message,
)
from iroha_python.crypto import NetworkId

NETWORK_ID = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
ACCOUNT_ID = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"
HASH = "12" * 32
MAX_U128 = (1 << 128) - 1


class ElectionResponse(requests.Response):
    """Supply only streamed original bytes to the canonical response reader."""

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
        self.reads = 0
        self.closes = 0
        self._content = False

    def iter_content(self, chunk_size=1, decode_unicode=False):
        assert (chunk_size, decode_unicode) == (8192, False)
        self.reads += 1
        yield self.body[:17]
        yield self.body[17:]

    def json(self, **kwargs: Any) -> Any:
        raise AssertionError("election tally must not use requests' JSON parser")

    def close(self) -> None:
        self.closes += 1


class ElectionSession(requests.Session):
    """Record the sole signed request without retrying or redirecting it."""

    def __init__(self, response: ElectionResponse) -> None:
        super().__init__()
        self.response = response
        self.calls: list[tuple[requests.PreparedRequest, dict[str, Any]]] = []

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        self.calls.append((request, kwargs))
        self.response.url = request.url
        return self.response


def response_body(weights=None) -> bytes:
    """Emit the exact Torii JSON numeric-token shape."""

    payload = {
        "evaluated_block_height": 9007199254740993,
        "evaluated_block_hash": HASH,
        "finalized": True,
        "tally": weights if weights is not None else [9007199254740993, 1 << 64],
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def make_auth(signed: list[bytes]) -> ToriiCanonicalRequestAuth:
    """Bind the request to a deterministic exact network, body and nonce."""

    return ToriiCanonicalRequestAuth(
        network_id=NETWORK_ID,
        account_id=ACCOUNT_ID,
        signer=lambda message: signed.append(message) or bytes([0x44]) * 64,
        timestamp_ms=4_102_444_801_000,
        nonce="python-election-tally-test",
    )


def make_client(kind: str, response: ElectionResponse):
    """Exercise the same inherited owner through both public clients."""

    session = ElectionSession(response)
    if kind == "low":
        return LowToriiClient("http://node.test", session=session), session
    return (
        ToriiClient(
            "http://node.test",
            session=session,
            local_signing_context=LocalSigningContext(NetworkId.parse(NETWORK_ID)),
            chain_discriminant=753,
        ),
        session,
    )


def test_both_packages_export_one_election_tally_model() -> None:
    assert ElectionTally is LowElectionTally


@pytest.mark.parametrize("kind", ["low", "high"])
def test_election_tally_exact_signed_post_and_u128_response(kind: str) -> None:
    response = ElectionResponse(response_body())
    client, session = make_client(kind, response)
    signed: list[bytes] = []
    auth = make_auth(signed)
    result = client.get_election_tally("election-1", canonical_auth=auth)
    assert result == ElectionTally(9007199254740993, HASH, True, (9007199254740993, 1 << 64))
    assert len(session.calls) == 1
    request, options = session.calls[0]
    body = b'{"election_id":"election-1"}'
    assert (request.method, request.url, request.body) == (
        "POST", "http://node.test/v1/zk/vote/tally", body
    )
    assert signed == [
        canonical_network_request_signature_message(
            NETWORK_ID,
            "POST",
            "/v1/zk/vote/tally",
            body,
            timestamp_ms=auth.timestamp_ms,
            nonce=auth.nonce,
        )
    ]
    assert request.headers["Content-Type"] == "application/json"
    assert request.headers["Accept"] == "application/json"
    assert request.headers["Accept-Encoding"] == "identity"
    assert request.headers["X-Iroha-Signature"]
    assert options["stream"] is True
    assert options["allow_redirects"] is False
    assert response.reads == 1 and response.closes == 1


@pytest.mark.parametrize("kind", ["low", "high"])
def test_election_tally_invalid_selector_and_auth_fail_before_dispatch(kind: str) -> None:
    response = ElectionResponse(response_body())
    client, session = make_client(kind, response)
    auth = make_auth([])
    with pytest.raises((TypeError, ValueError)):
        client.get_election_tally(".alias", canonical_auth=auth)
    with pytest.raises((TypeError, ValueError)):
        client.get_election_tally("election-1", canonical_auth=None)
    assert session.calls == []


@pytest.mark.parametrize("kind", ["low", "high"])
def test_election_tally_404_is_absent_without_read(kind: str) -> None:
    response = ElectionResponse(b"not a tally", status=404)
    client, _ = make_client(kind, response)
    assert client.get_election_tally("election-1", canonical_auth=make_auth([])) is None
    assert response.reads == 0 and response.closes == 1


@pytest.mark.parametrize("kind", ["low", "high"])
@pytest.mark.parametrize(
    "body",
    [
        response_body([MAX_U128, 1]),
        response_body().replace(b'"tally":', b'"tally":[0,0],"tally":'),
        response_body().replace(b'"tally":[', b'"tally":[1.0,'),
    ],
)
def test_election_tally_malformed_response_fails_both_clients(kind: str, body: bytes) -> None:
    response = ElectionResponse(body)
    client, _ = make_client(kind, response)
    with pytest.raises((TypeError, ValueError)):
        client.get_election_tally("election-1", canonical_auth=make_auth([]))
    assert response.closes == 1
