from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import parse_qs, urlparse

import iroha_torii_client.orderbook_submission as orderbook_submission
import pytest
import requests
from iroha_torii_client.tests.orderbook_submission_test import (
    IDENTITY,
    SIGNER,
    Verifier,
    stock_session,
)
from iroha_torii_client.tests.orderbook_submission_test import (
    Response as OrderbookResponse,
)
from requests.structures import CaseInsensitiveDict

import iroha_python.client as client_module
from iroha_python import (
    LocalSigningContext,
    SorafsOrderbookSubmissionAmbiguousError,
    SorafsOrderbookSubmissionIdentity,
    SorafsOrderbookSubmissionReceipt,
    SorafsOrderbookSubmissionReceiptPayload,
    ToriiClient,
)
from iroha_python.crypto import NetworkId

from .helpers import StubResponse


class SequencedSession(requests.Session):
    """Capture outgoing requests and return responses in order."""

    def __init__(self, responses: list[requests.Response]) -> None:
        super().__init__()
        self._responses = list(responses)
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
            }
        )
        if not self._responses:
            raise AssertionError("unexpected HTTP request")
        return self._responses.pop(0)

    def get(self, url: str | bytes, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)


class SseStubResponse(StubResponse):
    """Minimal SSE response for `_stream_sse` tests."""

    def __init__(self, lines: list[str]) -> None:
        super().__init__(200, None)
        self.headers = CaseInsensitiveDict({"Content-Type": "text/event-stream"})
        self._lines = lines

    def iter_content(self, chunk_size: int = 1, decode_unicode: bool = False):
        del chunk_size
        assert decode_unicode is False
        for line in self._lines:
            yield line.encode("utf-8") + b"\n"


class FakeWebSocket:
    """Deterministic WebSocket stub for orderbook frame streaming tests."""

    def __init__(self, frames: list[str]) -> None:
        self.frames = list(frames)
        self.closed = False

    def recv(self) -> str:
        if not self.frames:
            raise AssertionError("unexpected WebSocket recv")
        return self.frames.pop(0)

    def close(self) -> None:
        self.closed = True


def _fixed(seed: int) -> list[int]:
    return [seed] * 32


def _cursor() -> dict[str, Any]:
    return {"height": 42, "block_hash": _fixed(0xA0)}


def _order() -> dict[str, Any]:
    return {
        "order_id": _fixed(0x11),
        "owner": "alice@wonderland",
        "canonical_order": base64.b64encode(b"canonical-order").decode("ascii"),
        "admitted_policy_digest": _fixed(0x12),
        "admitted_at_unix": 1_700_000_000,
        "admission_sequence": 7,
        "remaining_gib": 2,
        "status": {"status": "open", "value": None},
        "updated_at_unix": 1_700_000_001,
        "canonical_cancel": None,
        "cancelled_at_unix": None,
        "cancelled_policy_digest": None,
    }


def _trade() -> dict[str, Any]:
    return {
        "trade_id": _fixed(0x22),
        "maker_order_id": _fixed(0x11),
        "taker_order_id": _fixed(0x13),
        "trade_sequence": 3,
        "canonical_trade": base64.b64encode(b"canonical-trade").decode("ascii"),
        "channel_id": _fixed(0x33),
        "book_revision": 9,
        "recorded_at_unix": 1_700_000_100,
    }


def _channel() -> dict[str, Any]:
    return {
        "channel_id": _fixed(0x33),
        "trade_id": _fixed(0x22),
        "buyer": "alice@wonderland",
        "provider": "provider@storage",
        "provider_id": _fixed(0x55),
        "settlement_authority": "settlement@governance",
        "total_bytes": 2_147_483_648,
        "remaining_bytes": 1_073_741_824,
        "initial_xor_locked": "10",
        "remaining_xor_locked": "5",
        "status": {"status": "open", "value": None},
        "opened_at_unix": 1_700_000_101,
        "expires_at_unix": 1_800_000_000,
        "updated_at_unix": 1_700_000_102,
    }


def _receipt() -> dict[str, Any]:
    return {
        "receipt_id": _fixed(0x44),
        "channel_id": _fixed(0x33),
        "trade_id": _fixed(0x22),
        "canonical_receipt": base64.b64encode(b"canonical-receipt").decode("ascii"),
        "admitted_policy_digest": _fixed(0x12),
        "admitted_at_unix": 1_700_000_103,
        "recorded_by": "settlement@governance",
    }


def _status() -> dict[str, int]:
    return {
        "open_orders": 1,
        "partially_filled_orders": 0,
        "filled_orders": 1,
        "cancelled_orders": 0,
        "expired_orders": 0,
        "trades": 1,
        "settlement_receipts": 1,
        "settlement_channels": 1,
        "open_settlement_channels": 1,
        "book_revision": 10,
        "next_admission_sequence": 8,
        "next_trade_sequence": 4,
        "updated_at_unix": 1_700_000_104,
    }


def _finalized_event() -> dict[str, Any]:
    return {
        "sequence": 9,
        "block_height": 42,
        "block_hash": _fixed(0xA0),
        "event_index": 2,
        "event": {
            "kind": {"kind": "receipt_recorded", "detail": None},
            "order_id": None,
            "trade_id": _fixed(0x22),
            "channel_id": _fixed(0x33),
            "receipt_id": _fixed(0x44),
            "provider_id": _fixed(0x55),
            "book_revision": 10,
            "authority": "settlement@governance",
            "occurred_at_unix_ms": 1_700_000_104_000,
        },
    }


def _submission_receipt() -> dict[str, Any]:
    return {
        "payload": {
            "entrypoint_hash": "hash:ENTRYPOINT",
            "signed_transaction_hash": "hash:SIGNED",
            "submitted_at_ms": 1_700_000_200_000,
            "submitted_at_height": 42,
            "signer": "ed0120ABCDEF",
        },
        "signature": "AB" * 64,
    }


def _page(field: str, records: list[dict[str, Any]], cursor_field: str) -> dict[str, Any]:
    return {
        "finalized_cursor": _cursor(),
        field: records,
        "has_more": False,
        cursor_field: None,
    }


def test_orderbook_has_no_competing_local_wire_parsers() -> None:
    assert not hasattr(client_module, "_normalize_sorafs_orderbook_order")
    assert not hasattr(client_module, "_sorafs_orderbook_payload_bytes")
    assert all(value.__module__ == "iroha_torii_client.orderbook_submission" for value in (
        SorafsOrderbookSubmissionIdentity, SorafsOrderbookSubmissionReceipt,
        SorafsOrderbookSubmissionReceiptPayload,
    ))


def test_sorafs_orderbook_read_helpers_parse_finalized_pages() -> None:
    session = SequencedSession(
        [
            StubResponse(
                200,
                {
                    "source": "finalized_chain",
                    "status": _status(),
                    "orders": _page(
                        "orders",
                        [_order()],
                        "next_after_order_id",
                    ),
                },
            ),
            StubResponse(
                200,
                {
                    "source": "finalized_chain",
                    "trades": _page(
                        "trades",
                        [_trade()],
                        "next_after_trade_id",
                    ),
                },
            ),
            StubResponse(
                200,
                {
                    "source": "finalized_chain",
                    "channels": _page(
                        "channels",
                        [_channel()],
                        "next_after_channel_id",
                    ),
                },
            ),
            StubResponse(
                200,
                {
                    "source": "finalized_chain",
                    "receipts": _page(
                        "receipts",
                        [_receipt()],
                        "next_after_receipt_id",
                    ),
                },
            ),
            StubResponse(
                200,
                {
                    "source": "finalized_chain",
                    "events": {
                        "finalized_cursor": _cursor(),
                        "events": [_finalized_event()],
                        "has_more": False,
                        "next_after": None,
                    },
                },
            ),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    anchor_hex = "a0" * 32

    book = client.get_sorafs_orderbook(
        expected_finalized_height=42,
        expected_finalized_block_hash_hex=anchor_hex,
        after_id_hex="10" * 32,
        limit=25,
        headers={"X-Trace": "book"},
    )
    assert book["source"] == "finalized_chain"
    assert book["status"]["book_revision"] == 10
    assert book["orders"]["orders"][0]["order_id"] == _fixed(0x11)
    assert session.calls[0]["params"] == {
        "expected_finalized_height": 42,
        "expected_finalized_block_hash_hex": anchor_hex,
        "after_id_hex": "10" * 32,
        "limit": 25,
    }
    assert session.calls[0]["headers"]["X-Trace"] == "book"

    assert client.list_sorafs_orderbook_trades()["trades"]["trades"][0] == _trade()
    assert client.list_sorafs_orderbook_channels()["channels"]["channels"][0] == _channel()
    assert client.list_sorafs_orderbook_receipts()["receipts"]["receipts"][0] == _receipt()

    events = client.list_sorafs_orderbook_events(
        expected_finalized_height=42,
        expected_finalized_block_hash_hex=anchor_hex,
        after_sequence=8,
        after_block_height=41,
        after_block_hash_hex="9f" * 32,
        after_event_index=1,
        limit=10,
        if_none_match='"events-v1"',
    )
    assert events is not None
    assert events["events"]["events"][0]["event"]["receipt_id"] == _fixed(0x44)
    assert session.calls[4]["params"]["after_sequence"] == 8
    assert session.calls[4]["headers"]["If-None-Match"] == '"events-v1"'


def test_sorafs_orderbook_event_list_honors_not_modified() -> None:
    session = SequencedSession([StubResponse(304, None)])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    assert client.list_sorafs_orderbook_events(if_none_match='"same"') is None
    assert session.calls[0]["headers"]["If-None-Match"] == '"same"'


def test_sorafs_orderbook_helpers_reject_retired_and_unbounded_inputs() -> None:
    client = ToriiClient("http://torii.example", session=SequencedSession([]), max_retries=0, chain_discriminant=753)

    with pytest.raises(TypeError, match="unexpected keyword argument 'since'"):
        client.list_sorafs_orderbook_events(since=8)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="1..=500"):
        client.list_sorafs_orderbook_events(limit=501)
    with pytest.raises(ValueError, match="all four finalized event cursor"):
        client.list_sorafs_orderbook_events(after_sequence=8)


def test_high_client_supplies_native_orderbook_adapter_and_local_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = NetworkId.from_bytes(bytes([0xA5]) * 32)
    native = Verifier(expected_network=network)
    response = OrderbookResponse()
    session, transport = stock_session(response)
    monkeypatch.setattr(
        orderbook_submission,
        "_HTTP_ADAPTER_SEND",
        lambda _adapter, request, **kwargs: (
            transport.calls.append({"request": request, **kwargs}) or response
        ),
    )
    monkeypatch.setattr(client_module, "_require_crypto", lambda: native)
    client = ToriiClient(
        "https://torii.example",
        session=session,
        local_signing_context=LocalSigningContext(network),
        chain_discriminant=369,
        auth_token="bearer-secret",
        api_token="api-secret",
        default_headers={"X-Benign": "preserved"},
        timeout=5,
        max_retries=0,
    )
    receipt = client.submit_sorafs_orderbook_order(
        bytearray(b"\x01"), expected_receipt_signer=SIGNER
    )
    assert receipt["payload"]["signer"] == SIGNER
    assert native.inspected == b"\x01"
    sent = transport.calls[0]
    assert sent["request"].headers["Accept"] == "application/x-norito"
    assert sent["request"].headers["Authorization"] == "Bearer bearer-secret"
    assert sent["request"].headers["X-API-Token"] == "api-secret"
    assert sent["request"].headers["X-Benign"] == "preserved"
    assert sent["stream"] is True and sent["timeout"] == 5.0


def test_high_client_requires_local_network_before_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Verifier()
    session, transport = stock_session(AssertionError("must not send"))
    monkeypatch.setattr(client_module, "_require_crypto", lambda: native)
    client = ToriiClient("https://torii.example", session=session, max_retries=0, chain_discriminant=753)
    with pytest.raises(ValueError, match="local_signing_context"):
        client.submit_sorafs_orderbook_order(
            b"\x01", expected_receipt_signer=SIGNER
        )
    assert transport.calls == []


def test_high_client_exposes_ambiguous_orderbook_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = NetworkId.from_bytes(bytes([0xA5]) * 32)
    native = Verifier(expected_network=network)
    session, _ = stock_session(OrderbookResponse(headers={"Content-Type": "text/plain"}))
    monkeypatch.setattr(client_module, "_require_crypto", lambda: native)
    client = ToriiClient(
        "https://torii.example",
        session=session,
        local_signing_context=LocalSigningContext(network),
        chain_discriminant=369,
        max_retries=0,
    )
    with pytest.raises(SorafsOrderbookSubmissionAmbiguousError) as caught:
        client.submit_sorafs_orderbook_order(
            b"\x01", expected_receipt_signer=SIGNER
        )
    assert dict(caught.value.expected_identity) == IDENTITY


def test_sorafs_orderbook_stream_helper_parses_finalized_sse() -> None:
    event = _finalized_event()
    session = SequencedSession(
        [
            SseStubResponse(
                [
                    "id: 9",
                    "event: receipt_recorded",
                    f"data: {json.dumps(event)}",
                    "",
                ]
            )
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    iterator = client.stream_sorafs_orderbook_events(
        after_sequence=8,
        after_block_height=41,
        after_block_hash_hex="9f" * 32,
        after_event_index=1,
        limit=1,
        last_event_id="8",
        max_retries=0,
        with_metadata=True,
    )
    streamed = next(iterator)

    assert streamed.event == "receipt_recorded"
    assert streamed.id == "9"
    assert streamed.data["event"]["receipt_id"] == _fixed(0x44)
    assert session.calls[0]["params"] == {
        "after_sequence": 8,
        "after_block_height": 41,
        "after_block_hash_hex": "9f" * 32,
        "after_event_index": 1,
        "limit": 1,
    }
    assert session.calls[0]["headers"]["Last-Event-ID"] == "8"


def test_sorafs_orderbook_websocket_helper_uses_finalized_cursor() -> None:
    event = _finalized_event()
    socket = FakeWebSocket(
        [json.dumps({"event": "receipt_recorded", "data": event})]
    )
    captured: dict[str, Any] = {}

    def factory(url: str, **kwargs: Any) -> FakeWebSocket:
        captured["url"] = url
        captured["kwargs"] = kwargs
        return socket

    client = ToriiClient("https://torii.example", session=SequencedSession([]), max_retries=0, chain_discriminant=753)
    url = client.build_sorafs_orderbook_events_websocket_url(
        after_sequence=8,
        after_block_height=41,
        after_block_hash_hex="9f" * 32,
        after_event_index=1,
        limit=1,
    )
    parsed = urlparse(url)
    assert parsed.scheme == "wss"
    assert parsed.path == "/v1/sorafs/orderbook/events/ws"
    assert parse_qs(parsed.query) == {
        "after_sequence": ["8"],
        "after_block_height": ["41"],
        "after_block_hash_hex": ["9f" * 32],
        "after_event_index": ["1"],
        "limit": ["1"],
    }

    iterator = client.stream_sorafs_orderbook_events_websocket(
        after_sequence=8,
        after_block_height=41,
        after_block_hash_hex="9f" * 32,
        after_event_index=1,
        limit=1,
        subprotocols=["iroha.sorafs.orderbook.v1"],
        websocket_factory=factory,
        with_metadata=True,
    )
    streamed = next(iterator)
    assert streamed.event == "receipt_recorded"
    assert streamed.data["event"]["receipt_id"] == _fixed(0x44)
    assert captured["kwargs"]["subprotocols"] == ["iroha.sorafs.orderbook.v1"]

    iterator.close()
    assert socket.closed is True


def test_sorafs_orderbook_websocket_helper_validates_before_connect() -> None:
    client = ToriiClient("http://torii.example", session=SequencedSession([]), max_retries=0, chain_discriminant=753)

    with pytest.raises(ValueError, match="1..=500"):
        client.build_sorafs_orderbook_events_websocket_url(limit=0)
    with pytest.raises(ValueError, match="must start with '/'"):
        client.connect_sorafs_orderbook_events_websocket(
            endpoint_path="v1/sorafs/orderbook/events/ws",
            websocket_factory=lambda *_args, **_kwargs: FakeWebSocket([]),
        )
