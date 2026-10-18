"""Exact tally parser and streamed-response ownership without network fixtures."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest
import requests
from iroha_torii_client.governance_tally import (
    GOVERNANCE_TALLY_RESPONSE_MAX_BYTES,
    GovernanceTally,
    read_tally_response,
    require_tally_selector,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures/governance/plain_v1"
_CASES = [
    case
    for case in json.loads((_FIXTURES / "cases.json").read_bytes())["cases"]
    if case["kind"] == "tally"
]
_VALID = (_FIXTURES / "tally-large.json").read_bytes()


class StreamResponse(requests.Response):
    """Preserve a real Response contract while controlling individual read events."""

    def __init__(self, body: bytes = _VALID, *, status: int = 200, chunks=None) -> None:
        super().__init__()
        self.status_code = status
        self.headers["Content-Type"] = "application/json"
        self.headers["Content-Length"] = str(len(body))
        self.body = body
        self.chunks = chunks if chunks is not None else [body[:17], body[17:]]
        self.reads = 0
        self.closes = 0

    def iter_content(self, chunk_size=1, decode_unicode=False):
        assert (chunk_size, decode_unicode) == (8192, False)
        for chunk in self.chunks:
            self.reads += 1
            if isinstance(chunk, Exception):
                raise chunk
            yield chunk

    def close(self) -> None:
        self.closes += 1

    def json(self, **kwargs):
        raise AssertionError("tally parsing must retain original bounded bytes")


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case["file"])
def test_tally_response_shared_source_vectors(case) -> None:
    body = (_FIXTURES / case["file"]).read_bytes()
    response = StreamResponse(body)
    if case["valid"]:
        payload = read_tally_response(response, "ref-1")
        assert payload == json.loads(body)
        result = GovernanceTally.from_payload(payload)
        assert type(result.approve) is int
        assert result.evaluated_block_hash == payload["evaluated_block_hash"]
    else:
        with pytest.raises((TypeError, ValueError)):
            read_tally_response(response, "ref-1")
    assert response.closes == 1


@pytest.mark.parametrize(
    "value", [None, True, 1, "", ".hidden", " ref-1", "ref/1", "ref%31", "投票", "a" * 129]
)
def test_tally_selector_rejects_noncanonical_values(value) -> None:
    with pytest.raises((TypeError, ValueError)):
        require_tally_selector(value, "selector")
    response = StreamResponse()
    with pytest.raises((TypeError, ValueError)):
        read_tally_response(response, value)
    assert response.reads == 0
    assert response.closes == 1


@pytest.mark.parametrize("selector", ["a", "a" * 128, "A9_selector~with.dots"])
def test_tally_selector_preserves_exact_boundaries(selector) -> None:
    assert require_tally_selector(selector, "selector") == selector


@pytest.mark.parametrize("field", ["approve", "reject", "abstain", "evaluated_block_height"])
@pytest.mark.parametrize("value", [None, True, False, "1", 1.0, Decimal("1"), -1])
def test_tally_model_rejects_coercion_and_negative_values(field, value) -> None:
    payload = json.loads(_VALID)
    payload[field] = value
    with pytest.raises((TypeError, ValueError)):
        GovernanceTally.from_payload(payload)


@pytest.mark.parametrize("field", tuple(json.loads(_VALID)))
def test_tally_model_has_no_missing_field_defaults(field) -> None:
    payload = json.loads(_VALID)
    del payload[field]
    with pytest.raises(TypeError, match="missing required"):
        GovernanceTally.from_payload(payload)


@pytest.mark.parametrize("field", ["approve", "reject", "abstain"])
def test_tally_model_checks_each_u128_boundary(field) -> None:
    payload = {**json.loads(_VALID), "approve": 0, "reject": 0, "abstain": 0}
    payload[field] = (1 << 128) - 1
    assert getattr(GovernanceTally.from_payload(payload), field) == (1 << 128) - 1
    payload[field] += 1
    with pytest.raises(ValueError, match="u128"):
        GovernanceTally.from_payload(payload)


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
def test_tally_invalid_framing_closes_original_stream(header, value) -> None:
    response = StreamResponse()
    response.headers[header] = value
    with pytest.raises(ValueError):
        read_tally_response(response, "ref-1")
    assert response.closes == 1


def test_tally_prebuffered_response_cannot_establish_actual_byte_bound() -> None:
    response = StreamResponse()
    response._content = _VALID
    with pytest.raises(ValueError, match="prebuffered"):
        read_tally_response(response, "ref-1")
    assert response.reads == 0
    assert response.closes == 1


def test_tally_maximum_selector_and_numeric_widths_fit_actual_byte_cap() -> None:
    payload = {
        "referendum_id": "a" * 128,
        "evaluated_block_height": (1 << 64) - 1,
        "evaluated_block_hash": "12" * 32,
        "approve": 1 << 126,
        "reject": 1 << 126,
        "abstain": 1 << 126,
    }
    body = b" \r\n" + json.dumps(payload).encode("utf-8") + b"\t\n"
    assert len(body) < GOVERNANCE_TALLY_RESPONSE_MAX_BYTES
    response = StreamResponse(body)
    del response.headers["Content-Length"]
    assert read_tally_response(response, payload["referendum_id"]) == payload
    assert response.closes == 1


@pytest.mark.parametrize(
    "chunks,error",
    [
        ([b"{", requests.ConnectionError("late stream failure")], requests.ConnectionError),
        ([b"{", "not bytes"], TypeError),
        ([b" " * (GOVERNANCE_TALLY_RESPONSE_MAX_BYTES + 1)], ValueError),
    ],
)
def test_tally_stream_failure_closes_without_returning_partial_state(chunks, error) -> None:
    response = StreamResponse(chunks=chunks)
    del response.headers["Content-Length"]
    with pytest.raises(error):
        read_tally_response(response, "ref-1")
    assert response.closes == 1


@pytest.mark.parametrize("status", [204, 307, 401, 500])
def test_tally_unexpected_status_never_reads_body(status) -> None:
    response = StreamResponse(status=status)
    with pytest.raises(RuntimeError, match=f"unexpected status {status}"):
        read_tally_response(response, "ref-1")
    assert response.reads == 0
    assert response.closes == 1


def test_tally_absence_is_not_a_zero_result() -> None:
    response = StreamResponse(b"not JSON", status=404)
    assert read_tally_response(response, "ref-1") is None
    assert response.reads == 0
    assert response.closes == 1


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"{}",
        b"[]",
        b"null",
        b"\xff",
        b"\xef\xbb\xbf" + _VALID,
        _VALID + b"{}",
        _VALID.replace(b'"approve":18446744073709551617', b'"approve":-0'),
        _VALID.replace(b'"approve":18446744073709551617', b'"approve":1.0'),
        _VALID.replace(b'"approve":18446744073709551617', b'"approve":1e0'),
        _VALID.replace(b'"approve":18446744073709551617', b'"approve":NaN'),
        _VALID.replace(b'"approve":18446744073709551617', b'"approve":1,"appro\\u0076e":2'),
    ],
)
def test_tally_lexical_failures_close_the_original_response(body) -> None:
    response = StreamResponse(body)
    with pytest.raises((TypeError, ValueError)):
        read_tally_response(response, "ref-1")
    assert response.closes == 1
