"""Exact standalone-election tally parsing and original streamed-response ownership."""

from __future__ import annotations

import json

import pytest
import requests
from iroha_torii_client.client import (
    ToriiCanonicalRequestAuth,
    ToriiClient,
    canonical_network_request_signature_message,
)
from iroha_torii_client.election_tally import (
    ELECTION_TALLY_RESPONSE_MAX_BYTES,
    ElectionTally,
    read_election_tally_response,
)

_NETWORK_ID = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
_ACCOUNT_ID = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"


def payload(tally=None):
    """Build one valid four-field response with exact integer weights."""

    return {
        "evaluated_block_height": (1 << 64) - 1,
        "evaluated_block_hash": "12" * 32,
        "finalized": True,
        "tally": tally if tally is not None else [1 << 64, (1 << 64) + 1],
    }


def encoded(value) -> bytes:
    """Encode an ordinary Torii JSON response without altering integer tokens."""

    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class StreamResponse(requests.Response):
    """Record actual body reads and close events from the original response."""

    def __init__(self, body: bytes, *, status: int = 200) -> None:
        super().__init__()
        self.status_code = status
        self.headers.update(
            {
                "Content-Type": "application/json",
                "Content-Encoding": "identity",
                "Content-Length": str(len(body)),
            }
        )
        self.body = body
        self.reads = 0
        self.closes = 0

    def iter_content(self, chunk_size=1, decode_unicode=False):
        assert (chunk_size, decode_unicode) == (8192, False)
        self.reads += 1
        midpoint = len(self.body) // 2
        yield self.body[:midpoint]
        yield self.body[midpoint:]

    def json(self, **kwargs):
        raise AssertionError("election tally must parse original bounded bytes")

    def close(self) -> None:
        self.closes += 1


class RecordingSession(requests.Session):
    """Expose the one signed POST and its one-shot transport options."""

    def __init__(self, response: StreamResponse) -> None:
        super().__init__()
        self.response = response
        self.calls = []

    def send(self, request, **kwargs):
        self.calls.append((request, kwargs))
        self.response.url = request.url
        return self.response


def auth(signed):
    """Capture exact network-bound signing bytes with a deterministic signer."""

    return ToriiCanonicalRequestAuth(
        network_id=_NETWORK_ID,
        account_id=_ACCOUNT_ID,
        signer=lambda message: signed.append(message) or bytes([0x44]) * 64,
        timestamp_ms=4_102_444_801_000,
        nonce="python-election-tally-test",
    )


def test_election_tally_client_signs_one_exact_streamed_post() -> None:
    response = StreamResponse(encoded(payload()))
    session = RecordingSession(response)
    client = ToriiClient("http://node.test", session=session)
    signed = []
    authorization = auth(signed)
    assert client.get_election_tally("election-1", canonical_auth=authorization) == (
        ElectionTally.from_payload(payload())
    )
    assert len(session.calls) == 1
    request, options = session.calls[0]
    body = b'{"election_id":"election-1"}'
    assert (request.method, request.url, request.body) == (
        "POST", "http://node.test/v1/zk/vote/tally", body
    )
    assert signed == [
        canonical_network_request_signature_message(
            _NETWORK_ID,
            "POST",
            "/v1/zk/vote/tally",
            body,
            timestamp_ms=authorization.timestamp_ms,
            nonce=authorization.nonce,
        )
    ]
    assert request.headers["Content-Type"] == "application/json"
    assert request.headers["Accept"] == "application/json"
    assert request.headers["Accept-Encoding"] == "identity"
    assert request.headers["X-Iroha-Signature"]
    assert options["stream"] is True and options["allow_redirects"] is False
    assert response.reads == 1 and response.closes == 1


def test_election_tally_client_rejects_invalid_selector_or_auth_before_dispatch() -> None:
    response = StreamResponse(encoded(payload()))
    session = RecordingSession(response)
    client = ToriiClient("http://node.test", session=session)
    with pytest.raises((TypeError, ValueError)):
        client.get_election_tally(".alias", canonical_auth=auth([]))
    with pytest.raises((TypeError, ValueError)):
        client.get_election_tally("election-1", canonical_auth=None)
    assert session.calls == []


def test_election_tally_preserves_u128_and_maximum_shape() -> None:
    maximum = (1 << 128) - 1
    response = StreamResponse(encoded(payload([maximum, 0])))
    result = read_election_tally_response(response)
    assert result == ElectionTally((1 << 64) - 1, "12" * 32, True, (maximum, 0))
    assert type(result.tally[0]) is int
    assert response.reads == 1 and response.closes == 1
    assert len(ElectionTally.from_payload(payload([0] * 64)).tally) == 64


@pytest.mark.parametrize(
    "weights",
    [[], [0], [0] * 65, [(1 << 128) - 1, 1], [1 << 128, 0], [-1, 0],
     [True, 0], ["1", 0], [1.0, 0]],
)
def test_election_tally_rejects_bad_weights_and_aggregate(weights) -> None:
    with pytest.raises((TypeError, ValueError), match="election tally"):
        ElectionTally.from_payload(payload(weights))


@pytest.mark.parametrize(
    "change",
    [
        {"evaluated_block_height": 1 << 64},
        {"evaluated_block_height": 0},
        {"evaluated_block_hash": "0" * 64},
        {"evaluated_block_hash": "AB" * 32},
        {"finalized": 1},
        {"extra": 1},
    ],
)
def test_election_tally_rejects_invalid_coordinates_and_schema(change) -> None:
    with pytest.raises((TypeError, ValueError), match="election tally"):
        ElectionTally.from_payload({**payload(), **change})
    missing = payload()
    missing.pop("finalized")
    with pytest.raises(TypeError, match="missing required"):
        ElectionTally.from_payload(missing)


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b"[]",
        b"\xef\xbb\xbf" + encoded(payload()),
        b" " + encoded(payload()),
        encoded(payload()).replace(b'"tally":', b'"tally":[0,0],"tally":'),
        encoded(payload()).replace(b'"tally":[', b'"tally":[1e0,'),
        encoded(payload()).replace(b'"tally":[', b'"tally":[-1,'),
    ],
)
def test_election_tally_rejects_malformed_wire_and_closes_response(body) -> None:
    response = StreamResponse(body)
    with pytest.raises((TypeError, ValueError)):
        read_election_tally_response(response)
    assert response.closes == 1


def test_election_tally_404_never_reads_body() -> None:
    response = StreamResponse(b"not a tally", status=404)
    assert read_election_tally_response(response) is None
    assert response.reads == 0 and response.closes == 1


@pytest.mark.parametrize(
    "header,value",
    [
        ("Content-Type", "text/plain"),
        ("Content-Encoding", "gzip"),
        ("Content-Length", "01"),
        ("Content-Length", str(ELECTION_TALLY_RESPONSE_MAX_BYTES + 1)),
    ],
)
def test_election_tally_rejects_bad_framing_before_body_read(header, value) -> None:
    response = StreamResponse(encoded(payload()))
    response.headers[header] = value
    with pytest.raises(ValueError):
        read_election_tally_response(response)
    assert response.reads == 0 and response.closes == 1


def test_election_tally_rejects_prebuffered_or_oversized_body() -> None:
    response = StreamResponse(encoded(payload()))
    response._content = response.body
    with pytest.raises(ValueError, match="prebuffered"):
        read_election_tally_response(response)
    assert response.reads == 0 and response.closes == 1
    oversized = StreamResponse(b" " * (ELECTION_TALLY_RESPONSE_MAX_BYTES + 1))
    del oversized.headers["Content-Length"]
    with pytest.raises(ValueError, match="byte limit"):
        read_election_tally_response(oversized)
    assert oversized.closes == 1
