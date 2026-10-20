from __future__ import annotations

import base64
import copy
import io
import json
from typing import Any

import pytest
import requests
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

from iroha_python import (
    ToriiCanonicalRequestAuth,
    ToriiClient,
    canonical_network_request_signature_message,
)
from iroha_python.address import AccountAddress
from iroha_python.client import (
    _SORAFS_REPUTATION_RESPONSE_MAX_BYTES,
    _SORAFS_REPUTATION_SSE_MAX_EVENT_BYTES,
)
from iroha_python.crypto import Ed25519KeyPair, NetworkId

from .helpers import StubResponse

SNAPSHOT_ID = "ab" * 16
NEXT_SNAPSHOT_ID = "bc" * 16
MERKLE_ROOT = "cd" * 32
RAW_METRICS_HASH = "ef" * 32
PROVIDER_ID = "provider:alpha"
GENERATED_AT = 1_800_000_000
REPUTATION_NETWORK_ID = NetworkId.from_bytes(bytes([0xA5]) * 32)


def weights_payload() -> dict[str, Any]:
    return {
        "version": 1,
        "por_success_bps": 2200,
        "pdp_success_bps": 1800,
        "potr_success_bps": 1500,
        "latency_bps": 1200,
        "dispute_bps": 1100,
        "token_violation_bps": 1100,
        "repair_breach_bps": 1100,
    }


def metrics_payload() -> dict[str, Any]:
    return {
        "version": 1,
        "por_success_bps": 9800,
        "pdp_success_bps": 9700,
        "potr_success_bps": 9600,
        "latency_health_bps": 9500,
        "dispute_rate_bps": 100,
        "token_violation_rate_bps": 200,
        "repair_breach_rate_bps": 300,
    }


def provider_payload(provider_id: str = PROVIDER_ID) -> dict[str, Any]:
    return {
        "provider_id": provider_id,
        "score_bps": 9800,
        "degradation_flags": [
            {"flag": "reserve_warning", "value": None},
            {"flag": "low_score", "value": None},
        ],
        "raw_metrics": metrics_payload(),
        "raw_metrics_hash_hex": RAW_METRICS_HASH,
    }


def snapshot_payload() -> dict[str, Any]:
    return {
        "snapshot_id_hex": SNAPSHOT_ID,
        "generated_at_unix": GENERATED_AT,
        "previous_snapshot_id_hex": None,
        "merkle_root_hex": MERKLE_ROOT,
        "provider_count": 1,
        "returned_provider_count": 1,
        "limit": 1,
        "truncated_providers": False,
        "alpha_bps": 8500,
        "current_score_weight_bps": 7000,
        "weights": weights_payload(),
        "providers": [provider_payload()],
    }


def provider_response_payload() -> dict[str, Any]:
    return {
        "snapshot_id_hex": SNAPSHOT_ID,
        "generated_at_unix": GENERATED_AT,
        "merkle_root_hex": MERKLE_ROOT,
        "provider": provider_payload(),
        "proof": {
            "provider_id": PROVIDER_ID,
            "leaf_index": 0,
            "leaf_count": 1,
            "siblings_hex": [],
        },
    }


def weights_response_payload() -> dict[str, Any]:
    return {
        "snapshot_id_hex": SNAPSHOT_ID,
        "generated_at_unix": GENERATED_AT,
        "alpha_bps": 8500,
        "current_score_weight_bps": 7000,
        "weights": weights_payload(),
    }


def event_payload(
    *,
    sequence: int = 8,
    snapshot_id: str = SNAPSHOT_ID,
    generated_at: int = GENERATED_AT,
    previous_snapshot_id: str | None = None,
) -> dict[str, Any]:
    return {
        "version": 1,
        "sequence": sequence,
        "snapshot_id_hex": snapshot_id,
        "generated_at_unix": generated_at,
        "merkle_root_hex": MERKLE_ROOT,
        "provider_count": 1,
        "previous_snapshot_id_hex": previous_snapshot_id,
    }


def event_page_payload() -> dict[str, Any]:
    return {
        "since": 0,
        "limit": 2,
        "count": 1,
        "next_since": 8,
        "events": [event_payload()],
    }


def compact_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def raw_response(body: bytes, status: int = 200) -> StubResponse:
    response = StubResponse(status, None)
    response._content = body
    response.encoding = "utf-8"
    response.headers = CaseInsensitiveDict({"Content-Type": "application/json"})
    return response


def canonical_auth(
    signer: Any = None,
    *,
    nonce: str | None = None,
) -> ToriiCanonicalRequestAuth:
    return ToriiCanonicalRequestAuth(
        network_id=REPUTATION_NETWORK_ID.literal,
        account_id="reputation-reader@sora",
        signer=signer or (lambda _message: b"\x7c" * 64),
        nonce=nonce,
    )


class SequencedSession(requests.Session):
    """Capture outgoing requests and return responses in order."""

    def __init__(
        self,
        responses: list[requests.Response | Exception],
        *,
        honor_stream: bool = True,
    ) -> None:
        super().__init__()
        self._responses = list(responses)
        self._honor_stream = honor_stream
        self.calls: list[dict[str, Any]] = []

    def request(
        self, method: str | bytes, url: str | bytes, *args: Any, **kwargs: Any
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
        if not self._responses:
            raise AssertionError("unexpected HTTP request")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if (
            self._honor_stream
            and kwargs.get("stream") is True
            and isinstance(response._content, bytes)
        ):
            response.raw = io.BytesIO(response._content)
            response._content = False
            response._content_consumed = False
        return response

    def get(self, url: str | bytes, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def send(
        self, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
        self.calls.append(
            {
                "method": request.method,
                "url": request.url,
                "params": {},
                "headers": dict(request.headers),
                "data": request.body,
                "stream": kwargs.get("stream"),
                "allow_redirects": kwargs.get("allow_redirects"),
            }
        )
        if not self._responses:
            raise AssertionError("unexpected prepared HTTP request")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if (
            self._honor_stream
            and kwargs.get("stream") is True
            and isinstance(response._content, bytes)
        ):
            response.raw = io.BytesIO(response._content)
            response._content = False
            response._content_consumed = False
        return response


class SseStubResponse(StubResponse):
    """Minimal byte-aware SSE response for strict stream tests."""

    def __init__(self, lines: list[str | bytes | Exception]) -> None:
        super().__init__(200, None)
        self.headers = CaseInsensitiveDict({"Content-Type": "text/event-stream"})
        self._lines = lines

    def iter_content(self, chunk_size: int = 1, decode_unicode: bool = False):
        del chunk_size
        assert decode_unicode is False
        for line in self._lines:
            if isinstance(line, Exception):
                raise line
            raw = line if isinstance(line, bytes) else line.encode("utf-8")
            yield raw + b"\n"


class ChunkedStubResponse(StubResponse):
    """Stream exact response chunks without exposing a prebuffered body."""

    def __init__(
        self,
        chunks: list[bytes],
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status, None)
        self._content = False
        self._chunks = chunks
        self.iterated = False
        self.closed = False
        self.headers = CaseInsensitiveDict(
            headers or {"Content-Type": "application/json"}
        )

    def iter_content(self, chunk_size: int = 1, decode_unicode: bool = False):
        assert chunk_size == 8_192
        assert decode_unicode is False
        self.iterated = True
        yield from self._chunks

    def close(self) -> None:
        self.closed = True


def test_sorafs_reputation_rest_helpers_validate_and_return_closed_profiles() -> None:
    signed_messages: list[bytes] = []

    def signer(message: bytes) -> bytes:
        signed_messages.append(message)
        return b"\x5a" * 64

    auth = canonical_auth(signer)
    session = SequencedSession(
        [
            StubResponse(200, snapshot_payload()),
            StubResponse(200, provider_response_payload()),
            StubResponse(304, None),
            StubResponse(200, weights_response_payload()),
            StubResponse(200, event_page_payload()),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=9, chain_discriminant=753)

    latest = client.get_sorafs_reputation_latest(
        canonical_auth=auth,
        if_none_match='"old"',
    )
    assert latest == snapshot_payload()
    assert str(session.calls[0]["url"]).endswith("/v1/sorafs/reputation/latest")
    assert session.calls[0]["headers"]["If-None-Match"] == '"old"'

    provider = client.get_sorafs_reputation_provider(PROVIDER_ID, canonical_auth=auth)
    assert provider == provider_response_payload()
    assert str(session.calls[1]["url"]).endswith(
        "/v1/sorafs/reputation/providers/provider:alpha"
    )

    snapshot = client.get_sorafs_reputation_snapshot(
        SNAPSHOT_ID,
        canonical_auth=auth,
        if_none_match='"snapshot-etag"',
    )
    assert snapshot is None
    assert str(session.calls[2]["url"]).endswith(
        f"/v1/sorafs/reputation/snapshots/{SNAPSHOT_ID}"
    )

    weights = client.get_sorafs_reputation_weights(canonical_auth=auth)
    assert weights == weights_response_payload()

    events = client.list_sorafs_reputation_events(
        canonical_auth=auth,
        since=0,
        limit="2",
        if_none_match='"events-etag"',
    )
    assert events == event_page_payload()
    assert session.calls[4]["params"] == {"since": "0", "limit": "2"}
    event_headers = session.calls[4]["headers"]
    expected_message = canonical_network_request_signature_message(
        REPUTATION_NETWORK_ID.literal,
        "GET",
        "/v1/sorafs/reputation/events?since=0&limit=2",
        b"",
        timestamp_ms=int(event_headers["X-Iroha-Timestamp-Ms"]),
        nonce=event_headers["X-Iroha-Nonce"],
    )
    assert signed_messages[4] == expected_message
    assert all(call["allow_redirects"] is False for call in session.calls)
    assert all(call["stream"] is True for call in session.calls)
    assert all(
        call["headers"]["Accept-Encoding"] == "identity" for call in session.calls
    )


def test_sorafs_reputation_stream_validates_snapshot_and_lagged_profiles() -> None:
    snapshot = event_payload()
    session = SequencedSession(
        [
            SseStubResponse(
                [
                    "id: 8",
                    "event: reputation_snapshot",
                    f"data: {compact_json(snapshot)}",
                    "",
                    "event: lagged",
                    "data: 2",
                    "",
                ]
            )
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=9, chain_discriminant=753)
    iterator = client.stream_sorafs_reputation_events(
        canonical_auth=canonical_auth(),
        since=7,
        limit=1,
        with_metadata=True,
    )

    event = next(iterator)
    lagged = next(iterator)
    assert event.event == "reputation_snapshot"
    assert event.id == "8"
    assert event.data == snapshot
    assert lagged.event == "lagged"
    assert lagged.id is None
    assert lagged.data == 2
    assert session.calls[0]["params"] == {"since": "7", "limit": "1"}
    assert "Last-Event-ID" not in session.calls[0]["headers"]
    assert session.calls[0]["headers"]["Accept"] == "text/event-stream"
    assert session.calls[0]["headers"]["X-Iroha-Signature"]
    assert session.calls[0]["allow_redirects"] is False
    with pytest.raises(StopIteration):
        next(iterator)
    assert len(session.calls) == 1


def test_sorafs_reputation_stream_rejects_redirect_without_following() -> None:
    session = SequencedSession([StubResponse(302, None)])
    client = ToriiClient("http://torii.example", session=session, max_retries=9, chain_discriminant=753)
    iterator = client.stream_sorafs_reputation_events(
        canonical_auth=canonical_auth(),
        with_metadata=True,
    )

    with pytest.raises(RuntimeError, match="unexpected status 302"):
        next(iterator)
    assert len(session.calls) == 1
    assert session.calls[0]["allow_redirects"] is False


def test_sorafs_reputation_stream_never_reconnects_after_delivering_event() -> None:
    signed_messages: list[bytes] = []

    def signer(message: bytes) -> bytes:
        signed_messages.append(message)
        return b"\x4d" * 64

    session = SequencedSession(
        [
            SseStubResponse(
                [
                    "id: 8",
                    "event: reputation_snapshot",
                    f"data: {compact_json(event_payload())}",
                    "",
                    requests.ConnectionError("stream failed after delivery"),
                ]
            ),
            SseStubResponse(
                [
                    "id: 8",
                    "event: reputation_snapshot",
                    f"data: {compact_json(event_payload())}",
                    "",
                ]
            ),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=9, chain_discriminant=753)
    iterator = client.stream_sorafs_reputation_events(
        canonical_auth=canonical_auth(signer),
        with_metadata=True,
    )

    assert next(iterator).id == "8"
    with pytest.raises(requests.ConnectionError, match="stream failed after delivery"):
        next(iterator)
    assert len(session.calls) == 1
    assert len(signed_messages) == 1


def test_sorafs_reputation_helpers_validate_inputs_before_request() -> None:
    session = SequencedSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    auth = canonical_auth()

    with pytest.raises(TypeError, match="unexpected keyword argument 'etag'"):
        client.get_sorafs_reputation_latest(canonical_auth=auth, etag='"retired"')
    with pytest.raises(
        ValueError,
        match="requires canonical_auth or an exact X-Iroha-Witness header",
    ):
        client.get_sorafs_reputation_latest()
    with pytest.raises(ValueError, match="unsupported characters"):
        client.get_sorafs_reputation_provider("bad provider", canonical_auth=auth)
    for provider_id in (".", ".."):
        with pytest.raises(ValueError, match="must not be a URL dot segment"):
            client.get_sorafs_reputation_provider(
                provider_id,
                canonical_auth=auth,
            )
    for invalid_snapshot in (
        "ab" * 15,
        "AB" * 16,
        f"0x{'ab' * 16}",
        f" {'ab' * 16}",
        "0" * 32,
    ):
        with pytest.raises((TypeError, ValueError)):
            client.get_sorafs_reputation_snapshot(
                invalid_snapshot,
                canonical_auth=auth,
            )
    with pytest.raises(ValueError, match="positive"):
        client.list_sorafs_reputation_events(canonical_auth=auth, limit=0)
    with pytest.raises(TypeError, match="canonical unsigned decimal"):
        client.list_sorafs_reputation_events(canonical_auth=auth, since="01")
    with pytest.raises(TypeError, match="unexpected keyword argument 'last_event_id'"):
        client.stream_sorafs_reputation_events(
            canonical_auth=auth,
            last_event_id="7",
        )
    with pytest.raises(TypeError, match="unexpected keyword argument 'max_retries'"):
        client.stream_sorafs_reputation_events(
            canonical_auth=auth,
            max_retries=0,
        )
    with pytest.raises(TypeError, match="unexpected keyword argument 'backoff_base'"):
        client.stream_sorafs_reputation_events(
            canonical_auth=auth,
            backoff_base=0,
        )
    with pytest.raises(ValueError, match="requires strict JSON decoding"):
        client.stream_sorafs_reputation_events(
            canonical_auth=auth,
            decode_json=False,
        )
    with pytest.raises(ValueError, match="does not accept Last-Event-ID"):
        client.stream_sorafs_reputation_events(
            canonical_auth=auth,
            headers={"Last-Event-ID": "7"},
        )
    with pytest.raises(ValueError, match="cannot supply signature proof fields directly"):
        client.get_sorafs_reputation_latest(headers={"X-Iroha-Signature": "partial"})
    with pytest.raises(ValueError, match="exactly one canonical authentication mode"):
        client.get_sorafs_reputation_latest(
            canonical_auth=auth,
            headers={"X-Iroha-Witness": base64_witness()},
        )
    assert session.calls == []


def test_sorafs_reputation_rejects_adapter_retries_before_signing() -> None:
    signed_messages: list[bytes] = []
    session = SequencedSession([StubResponse(200, snapshot_payload())])
    session.mount("http://", HTTPAdapter(max_retries=1))
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises(ValueError, match="transport retries to be disabled"):
        client.get_sorafs_reputation_latest(
            canonical_auth=canonical_auth(signed_messages.append)
        )
    with pytest.raises(ValueError, match="transport retries to be disabled"):
        client.stream_sorafs_reputation_events(
            canonical_auth=canonical_auth(signed_messages.append)
        )
    assert signed_messages == []
    assert session.calls == []


def test_sorafs_reputation_auth_honors_client_chain_discriminant() -> None:
    public_key = Ed25519KeyPair.from_private_key(bytes([0x5A]) * 32).public_key
    testnet_account = AccountAddress.from_account(
        public_key=public_key,
    ).to_i105(0x0171)
    session = SequencedSession([StubResponse(200, snapshot_payload())])
    client = ToriiClient(
        "http://torii.example",
        session=session,
        chain_discriminant=0x0171,
    )

    result = client.get_sorafs_reputation_latest(
        canonical_auth=ToriiCanonicalRequestAuth(
            network_id=REPUTATION_NETWORK_ID.literal,
            account_id=testnet_account,
            signer=lambda _message: b"\x7c" * 64,
        )
    )

    assert result == snapshot_payload()
    assert session.calls[0]["headers"]["X-Iroha-Account"] == AccountAddress.parse_encoded(
        testnet_account, expected_discriminant=0x0171
    ).canonical_hex()


def base64_witness() -> str:
    """Return a canonical non-empty witness placeholder for transport tests."""

    return base64.b64encode(b"canonical-witness").decode("ascii")


def test_sorafs_reputation_witness_auth_is_exact_and_stream_is_single_attempt() -> None:
    session = SequencedSession(
        [
            StubResponse(404, None),
            requests.ConnectionError("connection failed"),
            SseStubResponse(
                [
                    "id: 8",
                    "event: reputation_snapshot",
                    f"data: {compact_json(event_payload())}",
                    "",
                ]
            ),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=9, chain_discriminant=753)
    witness = base64_witness()
    public_key = Ed25519KeyPair.from_private_key(bytes([0x36]) * 32).public_key
    account = AccountAddress.from_account(public_key=public_key)
    account_i105 = account.to_i105(0x02F1)
    headers = {
        "X-Iroha-Witness": witness,
        "X-Iroha-Account": account_i105,
    }

    assert client.get_sorafs_reputation_latest(headers=headers) is None
    assert session.calls[0]["headers"]["X-Iroha-Account"] == account.canonical_hex()
    iterator = client.stream_sorafs_reputation_events(
        headers={"X-Iroha-Witness": witness},
        with_metadata=True,
    )
    with pytest.raises(requests.ConnectionError, match="connection failed"):
        next(iterator)
    assert len(session.calls) == 2
    with pytest.raises(ValueError, match="exact canonical standard base64"):
        client.get_sorafs_reputation_latest(headers={"X-Iroha-Witness": f" {witness}"})


def test_sorafs_reputation_finite_json_boundary_rejects_invalid_bytes() -> None:
    valid = compact_json(snapshot_payload()).encode("utf-8")
    duplicate = valid.replace(
        b'"snapshot_id_hex":',
        f'"snapshot_id_hex":"{SNAPSHOT_ID}","snapshot_id_hex":'.encode(),
        1,
    )
    nonfinite = valid.replace(b'"score_bps":9800', b'"score_bps":NaN', 1)
    cases = [
        (duplicate, "duplicate object key"),
        (b'{"invalid":"\xff"}', "strict UTF-8"),
        (nonfinite, "non-finite value NaN"),
        (b"{" + b" " * _SORAFS_REPUTATION_RESPONSE_MAX_BYTES, "byte limit"),
        (b"\xef\xbb\xbf" + valid, "must not contain a UTF-8 BOM"),
        (valid + b"\n", "without surrounding data"),
    ]

    for body, message in cases:
        session = SequencedSession([raw_response(body)])
        client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
        with pytest.raises(ValueError, match=message):
            client.get_sorafs_reputation_latest(canonical_auth=canonical_auth())


def test_sorafs_reputation_finite_response_uses_streamed_actual_byte_bound() -> None:
    body = compact_json(snapshot_payload()).encode("utf-8")
    valid = ChunkedStubResponse(
        [body[:19], body[19:]],
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Content-Encoding": "identity",
            "Content-Length": str(len(body)),
        },
    )
    session = SequencedSession([valid])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    assert client.get_sorafs_reputation_latest(
        canonical_auth=canonical_auth()
    ) == snapshot_payload()
    assert valid.iterated is True
    assert valid.closed is True
    assert session.calls[0]["stream"] is True
    assert session.calls[0]["headers"]["Accept-Encoding"] == "identity"

    declared_oversize = ChunkedStubResponse(
        [b"must-not-be-read"],
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(_SORAFS_REPUTATION_RESPONSE_MAX_BYTES + 1),
        },
    )
    session = SequencedSession([declared_oversize])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    with pytest.raises(ValueError, match="byte limit"):
        client.get_sorafs_reputation_latest(canonical_auth=canonical_auth())
    assert declared_oversize.iterated is False
    assert declared_oversize.closed is True

    actual_oversize = ChunkedStubResponse(
        [b"{" + b" " * _SORAFS_REPUTATION_RESPONSE_MAX_BYTES],
    )
    session = SequencedSession([actual_oversize])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    with pytest.raises(ValueError, match="byte limit"):
        client.get_sorafs_reputation_latest(canonical_auth=canonical_auth())
    assert actual_oversize.closed is True


def test_sorafs_reputation_finite_response_rejects_transport_aliases() -> None:
    body = compact_json(snapshot_payload()).encode("utf-8")
    cases = (
        (
            {
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
            "Content-Encoding must be identity",
        ),
        (
            {"Content-Type": "text/plain"},
            "Content-Type must be application/json",
        ),
        (
            {
                "Content-Type": "application/json",
                "Content-Length": f"0{len(body)}",
            },
            "Content-Length must be a canonical",
        ),
        (
            {
                "Content-Type": "application/json",
                "Content-Length": str(len(body) + 1),
            },
            "did not match Content-Length",
        ),
    )
    for headers, message in cases:
        response = ChunkedStubResponse([body], headers=headers)
        session = SequencedSession([response])
        client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
        with pytest.raises(ValueError, match=message):
            client.get_sorafs_reputation_latest(canonical_auth=canonical_auth())
        assert response.closed is True

    prebuffered = raw_response(body)
    session = SequencedSession([prebuffered], honor_stream=False)
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    with pytest.raises(ValueError, match="transport prebuffered"):
        client.get_sorafs_reputation_latest(canonical_auth=canonical_auth())


def test_sorafs_reputation_error_status_is_payload_free_and_unread() -> None:
    response = ChunkedStubResponse(
        [b"private failure bytes"],
        status=500,
        headers={"Content-Type": "application/json"},
    )
    session = SequencedSession([response])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises(RuntimeError, match="unexpected status 500"):
        client.get_sorafs_reputation_latest(canonical_auth=canonical_auth())
    assert response.iterated is False
    assert response.closed is True


def test_sorafs_reputation_snapshot_validator_rejects_noncanonical_profiles() -> None:
    cases: list[tuple[dict[str, Any], str]] = []

    extra = snapshot_payload()
    extra["alias"] = "retired"
    cases.append((extra, "fields are not canonical"))

    boolean_integer = snapshot_payload()
    boolean_integer["generated_at_unix"] = True
    cases.append((boolean_integer, "canonical unsigned integer"))

    zero_snapshot = snapshot_payload()
    zero_snapshot["snapshot_id_hex"] = "0" * 32
    cases.append((zero_snapshot, "must be nonzero"))

    underfilled = snapshot_payload()
    underfilled["provider_count"] = 2
    underfilled["limit"] = 2
    underfilled["truncated_providers"] = True
    cases.append((underfilled, "must equal min"))

    unsorted = snapshot_payload()
    unsorted["provider_count"] = 2
    unsorted["returned_provider_count"] = 2
    unsorted["limit"] = 2
    unsorted["providers"] = [
        provider_payload("provider:zulu"),
        provider_payload("provider:alpha"),
    ]
    cases.append((unsorted, "strictly ordered"))

    duplicate_flags = snapshot_payload()
    duplicate_flags["providers"][0]["degradation_flags"] = [
        {"flag": "low_score", "value": None},
        {"flag": "low_score", "value": None},
    ]
    cases.append((duplicate_flags, "must be unique"))

    wrong_weight_sum = snapshot_payload()
    wrong_weight_sum["weights"]["por_success_bps"] = 2199
    cases.append((wrong_weight_sum, "sum to exactly 10000"))

    for payload, message in cases:
        session = SequencedSession([StubResponse(200, payload)])
        client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
        with pytest.raises(ValueError, match=message):
            client.get_sorafs_reputation_latest(canonical_auth=canonical_auth())


def test_sorafs_reputation_provider_proof_validator_rejects_mismatches() -> None:
    cases: list[tuple[dict[str, Any], str]] = []

    wrong_provider = provider_response_payload()
    wrong_provider["proof"]["provider_id"] = "provider:other"
    cases.append((wrong_provider, "reference the returned provider"))

    wrong_index = provider_response_payload()
    wrong_index["proof"]["leaf_count"] = 2
    wrong_index["proof"]["leaf_index"] = 2
    wrong_index["proof"]["siblings_hex"] = [MERKLE_ROOT]
    cases.append((wrong_index, "less than leaf_count"))

    wrong_depth = provider_response_payload()
    wrong_depth["proof"]["leaf_count"] = 2
    cases.append((wrong_depth, "exact Merkle depth"))

    for payload, message in cases:
        session = SequencedSession([StubResponse(200, payload)])
        client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
        with pytest.raises(ValueError, match=message):
            client.get_sorafs_reputation_provider(
                PROVIDER_ID,
                canonical_auth=canonical_auth(),
            )


def test_sorafs_reputation_event_page_validator_rejects_chain_inconsistency() -> None:
    first = event_payload(sequence=8)
    second = event_payload(
        sequence=9,
        snapshot_id=NEXT_SNAPSHOT_ID,
        generated_at=GENERATED_AT + 1,
        previous_snapshot_id=SNAPSHOT_ID,
    )
    valid_page = {
        "since": 7,
        "limit": 2,
        "count": 2,
        "next_since": 9,
        "events": [first, second],
    }
    cases: list[tuple[dict[str, Any], str]] = []

    over_limit = copy.deepcopy(valid_page)
    over_limit["limit"] = 1
    cases.append((over_limit, "must not exceed limit"))

    wrong_next = copy.deepcopy(valid_page)
    wrong_next["next_since"] = 8
    cases.append((wrong_next, "last event sequence"))

    sequence_gap = copy.deepcopy(valid_page)
    sequence_gap["events"][1]["sequence"] = 10
    sequence_gap["next_since"] = 10
    cases.append((sequence_gap, "contiguous within the page"))

    unlinked = copy.deepcopy(valid_page)
    unlinked["events"][1]["previous_snapshot_id_hex"] = None
    cases.append((unlinked, "link adjacent events"))

    stale_time = copy.deepcopy(valid_page)
    stale_time["events"][1]["generated_at_unix"] = GENERATED_AT
    cases.append((stale_time, "strictly increase"))

    for payload, message in cases:
        session = SequencedSession([StubResponse(200, payload)])
        client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
        with pytest.raises(ValueError, match=message):
            client.list_sorafs_reputation_events(
                canonical_auth=canonical_auth(),
                since=7,
                limit=payload["limit"],
            )


def test_sorafs_reputation_sse_validator_rejects_invalid_profiles_before_callback() -> None:
    cases = [
        (
            ["id: 9", "event: reputation_snapshot", f"data: {compact_json(event_payload())}", ""],
            "id must equal data.sequence",
        ),
        (
            ["id: 8", "event: reputation_snapshot", 'data: {"version":1}', ""],
            "fields are not canonical",
        ),
        (["event: unknown", "data: 1", ""], "is unsupported"),
        (["id: 8", "event: lagged", "data: 2", ""], "must not carry an id"),
        (
            [
                "id: 8",
                "id: 8",
                "event: reputation_snapshot",
                f"data: {compact_json(event_payload())}",
                "",
            ],
            "exactly one id",
        ),
        (
            [
                "id: 8",
                "event: reputation_snapshot",
                "retry: 100",
                f"data: {compact_json(event_payload())}",
                "",
            ],
            "must not carry a retry field",
        ),
    ]

    for lines, message in cases:
        delivered: list[Any] = []
        session = SequencedSession([SseStubResponse(lines)])
        client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
        iterator = client.stream_sorafs_reputation_events(
            canonical_auth=canonical_auth(),
            with_metadata=True,
            on_event=delivered.append,
        )
        with pytest.raises(ValueError, match=message):
            next(iterator)
        assert delivered == []
        assert len(session.calls) == 1


def test_sorafs_reputation_sse_rejects_malformed_utf8_and_oversized_event() -> None:
    malformed = SseStubResponse(
        [b"event: reputation_snapshot", b"data: \xff", b""]
    )
    oversized = SseStubResponse(
        [
            b"event: lagged",
            b"data: " + b"1" * _SORAFS_REPUTATION_SSE_MAX_EVENT_BYTES,
            b"",
        ]
    )
    for response, message in (
        (malformed, "strict UTF-8"),
        (oversized, "exceeds its .*byte size bound"),
    ):
        session = SequencedSession([response])
        client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
        iterator = client.stream_sorafs_reputation_events(
            canonical_auth=canonical_auth(),
            with_metadata=True,
        )
        with pytest.raises(ValueError, match=message):
            next(iterator)


def test_sorafs_reputation_sse_requires_identity_event_stream_transport() -> None:
    cases = (
        (
            {"Content-Type": "text/event-stream", "Content-Encoding": "gzip"},
            "Content-Encoding must be identity",
        ),
        (
            {"Content-Type": "application/json"},
            "Content-Type must be text/event-stream",
        ),
    )
    for headers, message in cases:
        response = SseStubResponse([])
        response.headers = CaseInsensitiveDict(headers)
        session = SequencedSession([response])
        client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
        iterator = client.stream_sorafs_reputation_events(
            canonical_auth=canonical_auth(),
            with_metadata=True,
        )
        with pytest.raises(ValueError, match=message):
            next(iterator)
        assert session.calls[0]["headers"]["Accept-Encoding"] == "identity"
