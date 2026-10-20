from __future__ import annotations

import inspect
import json
from typing import Any
from urllib.parse import urlsplit

import pytest
import requests
from requests.structures import CaseInsensitiveDict

import iroha_python
import iroha_python.client as client_module
from iroha_python import (
    BlockEvent,
    EventCursor,
    F,
    GenericEvent,
    NetworkId,
    OperatorSigningContext,
    PipelineWarningEvent,
    ProofId,
    ProofPrunedEvent,
    ProofRejectedEvent,
    ProofVerifiedEvent,
    SseEvent,
    SseStreamError,
    ToriiCanonicalRequestAuth,
    ToriiClient,
    TransactionEvent,
    WitnessEvent,
    canonical_network_request_signature_message,
    decode_event,
)

from .helpers import StubResponse


class SequencedSession(requests.Session):
    """Capture streaming requests and return queued SSE responses."""

    def __init__(self, responses: list[requests.Response]) -> None:
        super().__init__()
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str | bytes,
        url: str | bytes,
        **kwargs: Any,
    ) -> requests.Response:
        self.calls.append(
            {
                "url": url,
                "params": kwargs.get("params"),
                "headers": kwargs.get("headers") or {},
                "stream": kwargs.get("stream"),
                "allow_redirects": kwargs.get("allow_redirects"),
            }
        )
        if not self._responses:
            raise AssertionError("unexpected SSE request")
        response = self._responses.pop(0)
        response.url = str(url)
        return response

    def get(self, url: str | bytes, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def send(
        self,
        request: requests.PreparedRequest,
        **kwargs: Any,
    ) -> requests.Response:
        self.calls.append(
            {
                "url": request.url,
                "params": {},
                "headers": dict(request.headers),
                "stream": kwargs.get("stream"),
                "allow_redirects": kwargs.get("allow_redirects"),
            }
        )
        if not self._responses:
            raise AssertionError("unexpected prepared SSE request")
        response = self._responses.pop(0)
        response.request = request
        response.url = request.url
        return response


class SseStubResponse(StubResponse):
    """Minimal successful SSE response."""

    def __init__(self, lines: list[str]) -> None:
        super().__init__(200, None)
        self.headers = CaseInsensitiveDict({"Content-Type": "text/event-stream"})
        self._lines = lines

    def iter_content(self, chunk_size: int = 1, decode_unicode: bool = False):
        del chunk_size
        assert decode_unicode is False
        for line in self._lines:
            yield line.encode("utf-8") + b"\n"


class ChunkSseStubResponse(StubResponse):
    """SSE response that can emit a newline-free hostile chunk."""

    def __init__(self, chunks: list[bytes | Exception]) -> None:
        super().__init__(200, None)
        self.headers = CaseInsensitiveDict({"Content-Type": "text/event-stream"})
        self._chunks = chunks

    def iter_content(self, chunk_size: int = 1, decode_unicode: bool = False):
        del chunk_size
        assert decode_unicode is False
        for chunk in self._chunks:
            if isinstance(chunk, Exception):
                raise chunk
            yield chunk


class StubOperatorKeyPair:
    """Deterministic operator signer sufficient for transport-boundary tests."""

    public_key_multihash = "ed0120" + "11" * 32

    @staticmethod
    def sign(message: bytes) -> bytes:
        assert message
        return b"\x5a" * 64


def operator_context() -> OperatorSigningContext:
    """Return one immutable exact-network status-stream signer."""

    return OperatorSigningContext(
        NetworkId.from_bytes(bytes([0xA5]) * 32),
        StubOperatorKeyPair(),
    )


_LIVE_STREAM_HELPERS = (
    "stream_events",
    "stream_sumeragi_status",
)


def test_live_stream_signatures_expose_no_replay_controls() -> None:
    forbidden = {"last_event_id", "resume", "cursor"}
    for name in (*_LIVE_STREAM_HELPERS, "stream_sorafs_reputation_events"):
        parameters = inspect.signature(getattr(ToriiClient, name)).parameters
        assert forbidden.isdisjoint(parameters), name

    orderbook_parameters = inspect.signature(
        ToriiClient.stream_sorafs_orderbook_events
    ).parameters
    assert forbidden.issubset(orderbook_parameters)

    client = ToriiClient(
        "http://torii.example",
        session=SequencedSession([]),
        max_retries=0,
        chain_discriminant=753,
    )
    with pytest.raises(TypeError, match="unexpected keyword argument 'last_event_id'"):
        client.stream_events(last_event_id="stale")  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="unexpected keyword argument 'resume'"):
        client.stream_events(resume=True)  # type: ignore[call-arg]


def test_sse_stream_has_a_mandatory_event_bound_and_never_redirects() -> None:
    session = SequencedSession([SseStubResponse(["data: 123456", ""])])
    client = ToriiClient("https://torii.example", session=session, max_retries=0, chain_discriminant=753)

    stream = client._stream_sse(
        "/v1/events/sse",
        maximum_event_bytes=8,
        max_retries=0,
        decode_json=False,
    )
    with pytest.raises(ValueError, match="8-byte size bound"):
        next(stream)
    assert session.calls[0]["allow_redirects"] is False

    with pytest.raises(ValueError, match="positive integer"):
        client._stream_sse(
            "/v1/events/sse",
            maximum_event_bytes=0,
            max_retries=0,
        )


def test_sse_stream_bounds_newline_free_chunks_and_normalizes_accept_header() -> None:
    session = SequencedSession([ChunkSseStubResponse([b"x" * 9])])
    client = ToriiClient(
        "https://torii.example",
        session=session,
        default_headers={"accept": "application/json"},
        max_retries=0,
        chain_discriminant=753,
    )

    stream = client._stream_sse(
        "/v1/events/sse",
        maximum_event_bytes=8,
        max_retries=0,
    )
    with pytest.raises(ValueError, match="8-byte size bound"):
        next(stream)

    headers = session.calls[0]["headers"]
    assert sum(name.lower() == "accept" for name in headers) == 1
    assert next(value for name, value in headers.items() if name.lower() == "accept") == (
        "text/event-stream"
    )


def test_sse_mid_body_failures_exhaust_the_retry_budget() -> None:
    session = SequencedSession(
        [
            ChunkSseStubResponse([requests.ConnectionError("first")]),
            ChunkSseStubResponse([requests.ConnectionError("second")]),
            SseStubResponse(["data: should-not-be-read", ""]),
        ]
    )
    client = ToriiClient("https://torii.example", session=session, max_retries=0, chain_discriminant=753)
    stream = client._stream_sse(
        "/v1/events/sse",
        max_retries=1,
        backoff_base=0,
    )

    with pytest.raises(requests.ConnectionError, match="second"):
        next(stream)
    assert len(session.calls) == 2


def test_sse_event_bound_counts_crlf_wire_bytes() -> None:
    session = SequencedSession([ChunkSseStubResponse([b":\r\n:\r\n\r\n"])])
    client = ToriiClient("https://torii.example", session=session, max_retries=0, chain_discriminant=753)
    stream = client._stream_sse(
        "/v1/events/sse",
        maximum_event_bytes=7,
        max_retries=0,
    )

    with pytest.raises(ValueError, match="7-byte size bound"):
        next(stream)


@pytest.mark.parametrize(
    "chunks",
    [
        [b"data: cr-only\r\r"],
        [b"data: cr-only\r", b"\r"],
        [b"data: crlf\r", b"\n\r", b"\n"],
    ],
)
def test_sse_stream_accepts_all_standard_line_endings(chunks: list[bytes]) -> None:
    session = SequencedSession([ChunkSseStubResponse(chunks)])
    client = ToriiClient("https://torii.example", session=session, max_retries=0, chain_discriminant=753)

    event = next(client._stream_sse("/v1/events/sse", max_retries=0))

    assert event.data in {"cr-only", "crlf"}
    assert len(session.calls) == 1


def test_sse_callback_request_errors_are_not_retried_or_checkpointed() -> None:
    session = SequencedSession(
        [
            SseStubResponse(["id: event-1", "data: payload", ""]),
            SseStubResponse(["data: duplicate", ""]),
        ]
    )
    client = ToriiClient("https://torii.example", session=session, max_retries=0, chain_discriminant=753)
    cursor = EventCursor()

    def fail_callback(_event: object) -> None:
        raise requests.ConnectionError("application callback failed")

    stream = client._stream_sse(
        "/v1/events/sse",
        allow_resume=True,
        cursor=cursor,
        max_retries=3,
        backoff_base=0,
        on_event=fail_callback,
    )

    with pytest.raises(requests.ConnectionError, match="application callback failed"):
        next(stream)
    assert len(session.calls) == 1
    assert cursor.last_event_id is None


def test_retired_sumeragi_new_view_surface_is_absent() -> None:
    retired_methods = (
        "get_sumeragi_new_view",
        "get_sumeragi_new_view_typed",
        "stream_sumeragi_new_view",
        "stream_verifying_key_events",
        "stream_proof_events",
        "stream_trigger_events",
        "stream_pipeline_transactions",
        "stream_pipeline_blocks",
        "stream_pipeline_witnesses",
        "stream_pipeline_merges",
    )
    for name in retired_methods:
        assert not hasattr(ToriiClient, name), name

    retired_models = (
        "SumeragiNewViewReceipt",
        "SumeragiNewViewSnapshot",
    )
    for name in retired_models:
        assert not hasattr(client_module, name), name
        assert name not in client_module.__all__, name
        assert not hasattr(iroha_python, name), name
        assert name not in iroha_python.__all__, name


_QUEUED = {
    "category": "Pipeline",
    "event": "Transaction",
    "hash": "ab" * 32,
    "lane_id": 0,
    "dataspace_id": 0,
    "block_height": None,
    "status": "Queued",
}


def test_specialized_live_stream_filters_normally_and_surfaces_terminal_error() -> None:
    event_payload = dict(_QUEUED)
    terminal_payload = {
        "code": "stream_lagged",
        "message": "The event stream lost buffered events and cannot replay them.",
        "dropped_messages": 3,
        "replay_available": False,
    }
    session = SequencedSession(
        [
            SseStubResponse(
                [
                    f"data: {json.dumps(event_payload)}",
                    "",
                    "event: stream_error",
                    f"data: {json.dumps(terminal_payload)}",
                    "",
                ]
            )
        ]
    )
    observed: list[tuple[Any, Any]] = []
    client = ToriiClient(
        "http://torii.example",
        session=session,
        default_headers={"lAsT-EvEnT-Id": "must-not-leak"},
        max_retries=0,
        chain_discriminant=753,
    )

    events = client.stream_events(
        filter=F.tx_status == "Queued",
        max_retries=0,
        on_event=lambda payload, event_id: observed.append((payload, event_id)),
    )
    first = next(events)
    assert first == TransactionEvent(hash="ab" * 32, status="Queued", lane_id=0, dataspace_id=0)
    assert first.raw == event_payload
    with pytest.raises(SseStreamError) as raised:
        next(events)

    error = raised.value
    assert error.code == "stream_lagged"
    assert error.message == terminal_payload["message"]
    assert error.dropped_messages == 3
    assert error.replay_available is False
    assert error.payload == terminal_payload
    assert error.malformed_reason is None
    assert observed == [(first, None)]

    call = session.calls[0]
    assert call["stream"] is True
    assert call["headers"]["Accept"] == "text/event-stream"
    assert all(name.lower() != "last-event-id" for name in call["headers"])
    assert all(not name.lower().startswith("x-iroha-") for name in call["headers"])
    assert call["params"]["filter"] == 'tx_status = "Queued"'


def test_live_event_stream_optionally_signs_exact_final_uri() -> None:
    event_payload = dict(_QUEUED)
    session = SequencedSession(
        [SseStubResponse([f"data: {json.dumps(event_payload)}", ""])]
    )
    captured: list[bytes] = []
    auth = ToriiCanonicalRequestAuth(
        network_id=(
            "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
        ),
        account_id=(
            "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"
        ),
        signer=lambda message: captured.append(message) or b"\x5a" * 64,
        timestamp_ms=4_102_444_801_000,
        nonce="python-event-stream-final-uri",
    )
    client = ToriiClient(
        "https://torii.example",
        session=session,
        canonical_request_auth=auth,
        max_retries=3,
        chain_discriminant=753,
    )

    assert next(client.stream_events(filter=F.tx_status == "Queued", max_retries=0)).raw == event_payload

    call = session.calls[0]
    prepared = urlsplit(str(call["url"]))
    exact_target = prepared.path + (f"?{prepared.query}" if prepared.query else "")
    assert prepared.path == "/v1/events/sse"
    assert "filter=" in prepared.query
    assert captured == [
        canonical_network_request_signature_message(
            auth.network_id,
            "GET",
            exact_target,
            b"",
            timestamp_ms=auth.timestamp_ms or 0,
            nonce=auth.nonce or "",
        )
    ]
    assert call["stream"] is True
    assert call["headers"]["Accept"] == "text/event-stream"
    assert "X-Iroha-Account" in call["headers"]
    assert "X-Iroha-Signature" in call["headers"]


def test_sumeragi_status_stream_uses_fresh_one_shot_operator_auth() -> None:
    payload = {"view": 2}
    session = SequencedSession(
        [
            SseStubResponse([f"data: {json.dumps(payload)}", ""]),
            SseStubResponse([f"data: {json.dumps(payload)}", ""]),
        ]
    )
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=operator_context(),
        default_headers={"Last-Event-ID": "stale-subscription"},
        max_retries=3,
        chain_discriminant=753,
    )

    assert next(client.stream_sumeragi_status()) == payload
    assert next(client.stream_sumeragi_status()) == payload

    assert len(session.calls) == 2
    nonces = []
    for call in session.calls:
        headers = {name.lower(): value for name, value in call["headers"].items()}
        assert call["stream"] is True
        assert call["allow_redirects"] is False
        assert headers["accept"] == "text/event-stream"
        assert "last-event-id" not in headers
        assert headers["x-iroha-operator-public-key"] == StubOperatorKeyPair.public_key_multihash
        assert headers["x-iroha-operator-signature"]
        nonces.append(headers["x-iroha-operator-nonce"])
    assert nonces[0] != nonces[1]


def test_sumeragi_status_stream_drops_ambient_resume_header_and_signs_once() -> None:
    class RecordingOperatorKeyPair:
        public_key_multihash = StubOperatorKeyPair.public_key_multihash

        def __init__(self) -> None:
            self.messages: list[bytes] = []

        def sign(self, message: bytes) -> bytes:
            self.messages.append(message)
            return b"\x5a" * 64

    from iroha_torii_client.client import operator_network_request_signature_message

    key_pair = RecordingOperatorKeyPair()
    network_id = NetworkId.from_bytes(bytes([0xA5]) * 32)
    session = SequencedSession([SseStubResponse(['data: {"view": 2}', ""])])
    session.trust_env = False
    client = ToriiClient(
        "https://torii.example",
        session=session,
        default_headers={"lAsT-EvEnT-Id": "stale-cursor", "X-Trace": "kept"},
        operator_signing_context=OperatorSigningContext(
            network_id, key_pair
        ),
        chain_discriminant=753,
    )

    assert next(client.stream_sumeragi_status()) == {"view": 2}
    assert len(session.calls) == 1
    call = session.calls[0]
    headers = {name.lower(): value for name, value in call["headers"].items()}
    assert "last-event-id" not in headers
    assert headers["x-trace"] == "kept"
    assert headers["x-iroha-operator-public-key"] == key_pair.public_key_multihash
    assert key_pair.messages == [
        operator_network_request_signature_message(
            network_id.literal,
            "GET",
            "/v1/sumeragi/status/sse",
            b"",
            timestamp_ms=int(headers["x-iroha-operator-timestamp-ms"]),
            nonce=headers["x-iroha-operator-nonce"],
        )
    ]
    assert call["allow_redirects"] is False


def test_nonreplayable_stream_rejects_session_resume_header_before_dispatch() -> None:
    session = SequencedSession([])
    session.headers["Last-Event-ID"] = "ambient-cursor"
    client = ToriiClient("https://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises(ValueError, match="Session.headers Last-Event-ID"):
        next(client.stream_events(max_retries=0))
    assert session.calls == []


def test_sumeragi_status_stream_rejects_missing_signer_and_retries_before_dispatch() -> None:
    session = SequencedSession([])
    client = ToriiClient("https://torii.example", session=session, max_retries=3, chain_discriminant=753)

    with pytest.raises(ValueError, match="operator_signing_context"):
        client.stream_sumeragi_status()
    with pytest.raises(ValueError, match="max_retries must be zero"):
        ToriiClient(
            "https://torii.example",
            session=session,
            operator_signing_context=operator_context(),
            chain_discriminant=753,
        ).stream_sumeragi_status(max_retries=1)
    assert session.calls == []


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        ("not-json", "data must be a JSON object"),
        (
            json.dumps(
                {
                    "code": "stream_lagged",
                    "message": "gap",
                    "dropped_messages": True,
                    "replay_available": False,
                }
            ),
            "dropped_messages must be a non-negative integer or null",
        ),
        (
            json.dumps(
                {
                    "code": "stream_lagged",
                    "message": "gap",
                    "dropped_messages": 1,
                }
            ),
            "replay_available is required",
        ),
    ],
)
def test_malformed_terminal_stream_error_is_typed(data: str, reason: str) -> None:
    session = SequencedSession(
        [SseStubResponse(["event: stream_error", f"data: {data}", ""])]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises(SseStreamError) as raised:
        next(client.stream_events(max_retries=0))

    error = raised.value
    assert error.code == SseStreamError.MALFORMED_CODE
    assert error.dropped_messages is None
    assert error.replay_available is None
    assert error.malformed_reason == reason
    assert reason in str(error)


def test_stream_error_is_decoded_even_when_normal_payload_json_decode_is_disabled() -> None:
    payload = {
        "code": "stream_source_closed",
        "message": "The event source closed.",
        "dropped_messages": None,
        "replay_available": False,
    }
    session = SequencedSession(
        [
            SseStubResponse(
                ["event: stream_error", f"data: {json.dumps(payload)}", ""]
            )
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises(SseStreamError) as raised:
        next(client.stream_events(max_retries=0, decode_json=False))

    assert raised.value.code == "stream_source_closed"
    assert raised.value.replay_available is False


_PROOF = {
    "backend": "halo2/ipa",
    "proof_hash": "11" * 32,
    "call_hash": None,
    "envelope_hash": "22" * 32,
    "vk_ref": "halo2/ipa::vk_transfer",
    "vk_commitment": None,
}

_EVENT_CASES = [
    (
        {
            **_QUEUED,
            "block_height": 7,
            "status": "Rejected",
            "rejection_code": "validation",
            "rejection_reason": "Transaction validation failed.",
        },
        TransactionEvent(
            hash="ab" * 32,
            status="Rejected",
            lane_id=0,
            dataspace_id=0,
            block_height=7,
            rejection_code="validation",
            rejection_reason="Transaction validation failed.",
        ),
    ),
    ({"category": "Pipeline", "event": "Block", "status": "Committed"}, BlockEvent(status="Committed")),
    (
        {
            "category": "Pipeline",
            "event": "Block",
            "status": "Rejected",
            "rejection_code": "ConsensusBlockRejection",
        },
        BlockEvent(status="Rejected", rejection_code="ConsensusBlockRejection"),
    ),
    (
        {"category": "Pipeline", "event": "Warning", "kind": "slow", "details": "late", "height": 3},
        PipelineWarningEvent(kind="slow", details="late", height=3),
    ),
    (
        {
            "category": "Pipeline",
            "event": "Witness",
            "block_hash": "cd" * 32,
            "height": 4,
            "view": 1,
            "epoch": 0,
            "read_count": 5,
            "write_count": 2,
        },
        WitnessEvent(block_hash="cd" * 32, height=4, view=1, epoch=0, read_count=5, write_count=2),
    ),
    (
        {"category": "Data", "event": "ProofVerified", **_PROOF},
        ProofVerifiedEvent(
            backend="halo2/ipa",
            proof_hash="11" * 32,
            envelope_hash="22" * 32,
            vk_ref="halo2/ipa::vk_transfer",
        ),
    ),
    (
        {"category": "Data", "event": "ProofRejected", **_PROOF},
        ProofRejectedEvent(
            backend="halo2/ipa",
            proof_hash="11" * 32,
            envelope_hash="22" * 32,
            vk_ref="halo2/ipa::vk_transfer",
        ),
    ),
    (
        {
            "category": "Data",
            "event": "ProofPruned",
            "backend": "halo2/ipa",
            "removed_count": 1,
            "remaining": 9,
            "cap": 10,
            "grace_blocks": 2,
            "prune_batch": 4,
            "pruned_at_height": 12,
            "pruned_by": "authority",
            "origin": "Insert",
            "removed": [{"backend": "halo2/ipa", "proof_hash": "33" * 32}],
        },
        ProofPrunedEvent(
            backend="halo2/ipa",
            removed=(ProofId("halo2/ipa", "33" * 32),),
            removed_count=1,
            remaining=9,
            cap=10,
            grace_blocks=2,
            prune_batch=4,
            pruned_at_height=12,
            pruned_by="authority",
            origin="Insert",
        ),
    ),
    (
        {"category": "Data", "event": "Asset", "summary": "Asset(Added(..))"},
        GenericEvent(category="Data", event="Asset", summary="Asset(Added(..))"),
    ),
    (
        {"category": "Other", "event": "Time", "summary": "Time(..)"},
        GenericEvent(category="Other", event="Time", summary="Time(..)"),
    ),
    (
        {"category": "Pipeline", "event": "Fork", "depth": 2},
        GenericEvent(category="Pipeline", event="Fork"),
    ),
    ({"category": "Telemetry", "event": "Tick"}, GenericEvent(category="Telemetry", event="Tick")),
]


@pytest.mark.parametrize(("payload", "expected"), _EVENT_CASES, ids=[case[1].event for case in _EVENT_CASES])
def test_event_payloads_decode_to_typed_records(payload: dict, expected: object) -> None:
    decoded = decode_event(json.dumps(payload))
    assert decoded == expected
    assert type(decoded) is type(expected)
    assert decoded.raw == payload
    assert (decoded.category, decoded.event) == (payload["category"], payload["event"])
    assert decode_event(payload) == expected


def test_event_stream_yields_typed_events_and_never_fails_on_unknown_kinds() -> None:
    lines: list[str] = [": heartbeat", "", "retry: 10", ""]
    for payload, _ in _EVENT_CASES:
        lines += [f"data: {json.dumps(payload)}", ""]
    session = SequencedSession([SseStubResponse(lines)])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    events = list(client.stream_events(max_retries=0))

    assert events == [expected for _, expected in _EVENT_CASES]


def test_event_stream_metadata_and_raw_text_modes() -> None:
    session = SequencedSession(
        [
            SseStubResponse([f"data: {json.dumps(_QUEUED)}", ""]),
            SseStubResponse([f"data: {json.dumps(_QUEUED)}", ""]),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    seen: list[Any] = []

    frame = next(client.stream_events(max_retries=0, with_metadata=True, on_event=seen.append))
    assert isinstance(frame, SseEvent) and isinstance(frame.data, TransactionEvent)
    assert frame.data.raw == _QUEUED and frame.raw == f"data: {json.dumps(_QUEUED)}"
    assert seen == [frame]
    assert next(client.stream_events(max_retries=0, decode_json=False)) == json.dumps(_QUEUED)


@pytest.mark.parametrize(
    ("data", "needle"),
    [
        ('Pipeline(Transaction { status: Queued })', "must be a JSON object"),
        (json.dumps([_QUEUED]), "must be a JSON object"),
        (json.dumps({"Pipeline": {"Transaction": {"status": "Queued"}}}), "`category` and `event`"),
        ('{"category": "Pipeline", "category": "Pipeline", "event": "Block"}', "duplicate JSON member"),
        (json.dumps({**_QUEUED, "status": None}), "`status` must be a string"),
        (json.dumps({**_QUEUED, "block_height": -1}), "`block_height` must be an unsigned"),
        (json.dumps({"category": "Data", "event": "Asset", "summary": 1}), "`summary` must be a string"),
    ],
)
def test_malformed_event_payloads_fail_the_stream(data: str, needle: str) -> None:
    session = SequencedSession([SseStubResponse([f"data: {data}", ""])])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises(ValueError, match=needle):
        next(client.stream_events(max_retries=0))


def test_closing_the_event_iterator_releases_the_stream() -> None:
    class TrackedResponse(SseStubResponse):
        closed = False

        def close(self) -> None:
            self.closed = True

    response = TrackedResponse([f"data: {json.dumps(_QUEUED)}", "", f"data: {json.dumps(_QUEUED)}", ""])
    client = ToriiClient(
        "http://torii.example",
        session=SequencedSession([response]),
        max_retries=0,
        chain_discriminant=753,
    )

    events = client.stream_events(max_retries=0)
    assert isinstance(next(events), TransactionEvent)
    assert response.closed is False
    events.close()
    assert response.closed is True
