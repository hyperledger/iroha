"""Exact operator-auth regressions for Kaigi relay diagnostic reads."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
from urllib.parse import quote

import pytest
import requests
from iroha_torii_client.client import canonical_request_message

from iroha_python import (
    KaigiRelayDetail,
    KaigiRelayHealthSnapshot,
    KaigiRelaySummary,
    KaigiRelaySummaryList,
    NetworkId,
    OperatorSigningContext,
    ToriiClient,
    hash_blake2b_32,
)
from iroha_python.crypto import Ed25519KeyPair

NETWORK_BYTES = bytes([0xB5]) * 32
NETWORK_ID = NetworkId.from_bytes(NETWORK_BYTES)
FOREIGN_NETWORK_BYTES = bytes([0xB7]) * 32
KEY_PAIR = Ed25519KeyPair.from_private_key(bytes([0x2D]) * 32)
RELAY_ID = "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE"
HPKE_PUBLIC_KEY = b"ABCD"
HPKE_PUBLIC_KEY_B64 = base64.b64encode(HPKE_PUBLIC_KEY).decode("ascii")
HPKE_FINGERPRINT_HEX = "58c7dab691f514e0bd6f4082852ac0f1e08df24b5864038ff70ecd68419f4a23"


class RecordingSession(requests.Session):
    """Record requests while retaining Requests' default no-retry adapters."""

    def __init__(self, responses: list[requests.Response]) -> None:
        super().__init__()
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str | bytes, url: str | bytes, **kwargs: Any) -> requests.Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError("unexpected Kaigi HTTP request")
        return self.responses.pop(0)


def response(status: int, payload: object | None = None) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result._content = b"" if payload is None else json.dumps(payload).encode("utf-8")
    result._content_consumed = True
    if payload is not None:
        result.headers["Content-Type"] = "application/json"
    return result


def context() -> OperatorSigningContext:
    return OperatorSigningContext(NETWORK_ID, KEY_PAIR)


def relay_summary_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "relay_id": RELAY_ID,
        "domain": "kaigi.core",
        "bandwidth_class": 3,
        "hpke_fingerprint_hex": "ab" * 32,
        "status": "healthy",
        "reported_at_ms": 123,
    }
    payload.update(overrides)
    return payload


def relay_detail_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "relay": relay_summary_payload(
            hpke_fingerprint_hex=HPKE_FINGERPRINT_HEX,
        ),
        "hpke_public_key_b64": HPKE_PUBLIC_KEY_B64,
        "reported_call": {"domain_id": "kaigi.core", "call_name": "health"},
        "reported_by": RELAY_ID,
    }
    payload.update(overrides)
    return payload


def test_kaigi_hpke_fingerprint_matches_iroha_hash_new_fixture() -> None:
    raw_digest = hashlib.blake2b(HPKE_PUBLIC_KEY, digest_size=32).digest()

    assert raw_digest.hex() == ("58c7dab691f514e0bd6f4082852ac0f1e08df24b5864038ff70ecd68419f4a22")
    assert raw_digest[-1] & 1 == 0
    assert hash_blake2b_32(HPKE_PUBLIC_KEY).hex() == HPKE_FINGERPRINT_HEX
    assert KaigiRelayDetail.from_payload(relay_detail_payload()).hpke_public_key_b64 == (
        HPKE_PUBLIC_KEY_B64
    )


@pytest.mark.parametrize("bandwidth_class", [1, 255])
def test_kaigi_relay_summary_accepts_u8_bandwidth_boundaries(
    bandwidth_class: int,
) -> None:
    summary = KaigiRelaySummary.from_payload(relay_summary_payload(bandwidth_class=bandwidth_class))

    assert summary.bandwidth_class == bandwidth_class


@pytest.mark.parametrize("bandwidth_class", [0, -1, 256])
def test_kaigi_relay_summary_rejects_out_of_range_bandwidth(
    bandwidth_class: int,
) -> None:
    with pytest.raises(ValueError, match=r"bandwidth_class must be within 1\.\.=255"):
        KaigiRelaySummary.from_payload(relay_summary_payload(bandwidth_class=bandwidth_class))


def test_kaigi_relay_summary_requires_bandwidth_class() -> None:
    payload = relay_summary_payload()
    del payload["bandwidth_class"]

    with pytest.raises(ValueError, match="bandwidth_class is required"):
        KaigiRelaySummary.from_payload(payload)


def test_kaigi_relay_summary_rejects_boolean_bandwidth() -> None:
    with pytest.raises(TypeError, match="bandwidth_class must be an integer"):
        KaigiRelaySummary.from_payload(relay_summary_payload(bandwidth_class=True))


@pytest.mark.parametrize("reported_at_ms", [True, 1.5, -1, 1 << 64])
def test_kaigi_relay_summary_rejects_lossy_or_out_of_range_timestamps(
    reported_at_ms: object,
) -> None:
    with pytest.raises((TypeError, ValueError), match=r"reported_at_ms must"):
        KaigiRelaySummary.from_payload(relay_summary_payload(reported_at_ms=reported_at_ms))


def test_kaigi_relay_summary_requires_a_32_byte_fingerprint() -> None:
    with pytest.raises(ValueError, match="64 lowercase hex characters"):
        KaigiRelaySummary.from_payload(relay_summary_payload(hpke_fingerprint_hex="ab"))


def test_kaigi_relay_summary_requires_the_iroha_hash_marker() -> None:
    with pytest.raises(ValueError, match="Iroha Hash marker bit"):
        KaigiRelaySummary.from_payload(
            relay_summary_payload(hpke_fingerprint_hex="aa" * 32)
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("reported_at_ms", "123"),
        ("status", "HEALTHY"),
        ("hpke_fingerprint_hex", "AB" * 32),
    ],
)
def test_kaigi_relay_summary_rejects_noncanonical_wire_values(
    field: str,
    value: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        KaigiRelaySummary.from_payload(relay_summary_payload(**{field: value}))


@pytest.mark.parametrize("missing", ["status", "reported_at_ms"])
def test_kaigi_relay_summary_requires_health_fields_as_a_pair(missing: str) -> None:
    payload = relay_summary_payload()
    del payload[missing]

    with pytest.raises(ValueError, match="present together"):
        KaigiRelaySummary.from_payload(payload)


def test_kaigi_relay_summary_rejects_unknown_fields() -> None:
    with pytest.raises(ValueError, match="not part of the first-release contract"):
        KaigiRelaySummary.from_payload(relay_summary_payload(alias_tag="private"))


def test_kaigi_relay_summary_requires_canonical_i105_output() -> None:
    with pytest.raises(ValueError, match="canonical I105"):
        KaigiRelaySummary.from_payload(relay_summary_payload(relay_id="relay-alpha"))


@pytest.mark.parametrize(
    "payload",
    [
        {"total": 0, "items": False},
        {"items": []},
        {"total": 501, "items": [{}] * 501},
    ],
)
def test_kaigi_relay_summary_list_rejects_malformed_or_oversized_envelopes(
    payload: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError), match=r"(?:items|total).*(?:array|required|limit)"):
        KaigiRelaySummaryList.from_payload(payload)


def test_kaigi_relay_summary_list_rejects_partial_or_duplicate_results() -> None:
    item = relay_summary_payload()
    with pytest.raises(ValueError, match="total must equal"):
        KaigiRelaySummaryList.from_payload({"total": 2, "items": [item]})
    with pytest.raises(ValueError, match="duplicate relay ids"):
        KaigiRelaySummaryList.from_payload({"total": 2, "items": [item, item]})


def test_kaigi_relay_detail_rejects_non_string_notes_and_non_object_optionals() -> None:
    for field, value in (("notes", 7), ("reported_call", []), ("metrics", [])):
        with pytest.raises(TypeError, match=field):
            KaigiRelayDetail.from_payload(relay_detail_payload(**{field: value}))


@pytest.mark.parametrize("public_key", ["not-base64", "", "QUJDRA", None])
def test_kaigi_relay_detail_requires_exact_base64_public_key(public_key: object) -> None:
    with pytest.raises((TypeError, ValueError), match="base64|string|non-empty"):
        KaigiRelayDetail.from_payload(relay_detail_payload(hpke_public_key_b64=public_key))


def test_kaigi_relay_detail_binds_public_key_to_fingerprint() -> None:
    with pytest.raises(ValueError, match="does not match the relay fingerprint"):
        KaigiRelayDetail.from_payload(
            relay_detail_payload(relay=relay_summary_payload(hpke_fingerprint_hex="ab" * 32))
        )


def test_kaigi_relay_detail_preserves_empty_notes() -> None:
    detail = KaigiRelayDetail.from_payload(relay_detail_payload(notes=""))

    assert detail.notes == ""


def test_kaigi_relay_detail_metrics_must_match_relay_domain() -> None:
    with pytest.raises(ValueError, match="metrics.domain must match"):
        KaigiRelayDetail.from_payload(
            relay_detail_payload(
                metrics={
                    "domain": "other.core",
                    "registrations_total": 0,
                    "manifest_updates_total": 0,
                    "failovers_total": 0,
                    "health_reports_total": 0,
                }
            )
        )


def test_kaigi_relay_detail_requires_consistent_feedback_fields() -> None:
    payload = relay_detail_payload()
    del payload["reported_by"]
    with pytest.raises(ValueError, match="present together"):
        KaigiRelayDetail.from_payload(payload)

    relay_without_feedback = relay_summary_payload(
        hpke_fingerprint_hex=HPKE_FINGERPRINT_HEX,
    )
    del relay_without_feedback["status"]
    del relay_without_feedback["reported_at_ms"]
    with pytest.raises(ValueError, match="agree with the relay health summary"):
        KaigiRelayDetail.from_payload(relay_detail_payload(relay=relay_without_feedback))


@pytest.mark.parametrize(
    "payload",
    [
        {
            "healthy_total": 0,
            "degraded_total": 0,
            "unavailable_total": 0,
            "reports_total": 0,
            "registrations_total": 0,
            "failovers_total": 0,
            "domains": False,
        },
        {
            "healthy_total": 0,
            "degraded_total": 0,
            "unavailable_total": 0,
            "registrations_total": 0,
            "failovers_total": 0,
            "domains": [],
        },
    ],
)
def test_kaigi_relay_health_rejects_malformed_required_fields(
    payload: dict[str, object],
) -> None:
    with pytest.raises(
        (TypeError, ValueError),
        match=r"(?:domains|reports_total).*(?:array|required)",
    ):
        KaigiRelayHealthSnapshot.from_payload(payload)


def test_kaigi_relay_health_rejects_impossible_current_status_total() -> None:
    with pytest.raises(ValueError, match="status totals exceed"):
        KaigiRelayHealthSnapshot.from_payload(
            {
                "healthy_total": 501,
                "degraded_total": 0,
                "unavailable_total": 0,
                "reports_total": 0,
                "registrations_total": 0,
                "failovers_total": 0,
                "domains": [],
            }
        )


def test_kaigi_relay_health_requires_strictly_sorted_domains() -> None:
    with pytest.raises(ValueError, match="strictly sorted by domain"):
        KaigiRelayHealthSnapshot.from_payload(
            {
                "healthy_total": 0,
                "degraded_total": 0,
                "unavailable_total": 0,
                "reports_total": 3,
                "registrations_total": 3,
                "failovers_total": 3,
                "domains": [
                    {
                        "domain": "zeta",
                        "registrations_total": 1,
                        "manifest_updates_total": 0,
                        "failovers_total": 1,
                        "health_reports_total": 1,
                    },
                    {
                        "domain": "alpha",
                        "registrations_total": 2,
                        "manifest_updates_total": 0,
                        "failovers_total": 2,
                        "health_reports_total": 2,
                    },
                ],
            }
        )


def assert_exact_signature(call: dict[str, Any], target: str) -> None:
    headers = call["headers"]
    timestamp = headers["x-iroha-operator-timestamp-ms"]
    nonce = headers["x-iroha-operator-nonce"]
    signature = base64.b64decode(headers["x-iroha-operator-signature"], validate=True)
    canonical = canonical_request_message("GET", target, b"")
    suffix = f"\n{timestamp}\n{nonce}".encode("ascii")
    message = b"".join(
        (
            b"iroha.operator.http-request.network.v1\0",
            NETWORK_BYTES,
            canonical,
            suffix,
        )
    )
    assert KEY_PAIR.verify(message, signature)
    assert not KEY_PAIR.verify(message.replace(NETWORK_BYTES, FOREIGN_NETWORK_BYTES, 1), signature)

    wrong_path = b"".join(
        (
            b"iroha.operator.http-request.network.v1\0",
            NETWORK_BYTES,
            canonical_request_message("GET", "/v1/kaigi/relays/foreign", b""),
            suffix,
        )
    )
    wrong_query = b"".join(
        (
            b"iroha.operator.http-request.network.v1\0",
            NETWORK_BYTES,
            canonical_request_message("GET", f"{target}?format=json", b""),
            suffix,
        )
    )
    assert not KEY_PAIR.verify(wrong_path, signature)
    assert not KEY_PAIR.verify(wrong_query, signature)


def test_kaigi_diagnostics_require_operator_context_and_reject_precomputed_auth() -> None:
    missing_session = RecordingSession([])
    missing = ToriiClient("https://torii.example", session=missing_session, chain_discriminant=753)
    for call in (
        missing.list_kaigi_relays,
        lambda: missing.get_kaigi_relay(RELAY_ID),
        missing.get_kaigi_relays_health,
    ):
        with pytest.raises(ValueError, match="operator_signing_context"):
            call()
    assert missing_session.calls == []

    precomputed_session = RecordingSession([])
    with pytest.raises(
        ValueError,
        match="canonical authentication headers|generated operator signing",
    ):
        precomputed = ToriiClient(
            "https://torii.example",
            session=precomputed_session,
            operator_signing_context=context(),
            default_headers={"X-Iroha-Operator-Nonce": "precomputed"},
            chain_discriminant=753,
        )
        precomputed.list_kaigi_relays()
    assert precomputed_session.calls == []

    cookie_session = RecordingSession([])
    cookie_client = ToriiClient(
        "https://torii.example",
        session=cookie_session,
        operator_signing_context=context(),
        chain_discriminant=753,
    )
    cookie_session.cookies.set("session", "ambient-authority")
    with pytest.raises(ValueError, match="Session.cookies"):
        cookie_client.list_kaigi_relays()
    assert cookie_session.calls == []


def test_kaigi_diagnostics_sign_exact_network_targets_once() -> None:
    session = RecordingSession(
        [
            response(200, {"total": 0, "items": []}),
            response(404),
            response(
                200,
                {
                    "healthy_total": 0,
                    "degraded_total": 0,
                    "unavailable_total": 0,
                    "reports_total": 0,
                    "registrations_total": 0,
                    "failovers_total": 0,
                    "domains": [],
                },
            ),
        ]
    )
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=context(),
        max_retries=7,
        retry_on_methods=["GET"],
        retry_on_status=[503],
        chain_discriminant=753,
    )

    assert client.list_kaigi_relays_typed().total == 0
    assert client.get_kaigi_relay_typed(RELAY_ID) is None
    assert client.get_kaigi_relays_health_typed().healthy_total == 0

    targets = (
        "/v1/kaigi/relays",
        f"/v1/kaigi/relays/{quote(RELAY_ID, safe='')}",
        "/v1/kaigi/relays/health",
    )
    assert len(session.calls) == len(targets)
    for call, target in zip(session.calls, targets, strict=True):
        assert call["method"] == "GET"
        assert call["url"] == f"https://torii.example{target}"
        assert call["data"] == b""
        assert call["allow_redirects"] is False
        assert call["stream"] is True
        assert_exact_signature(call, target)


def test_kaigi_operator_read_does_not_retry_after_dispatch() -> None:
    session = RecordingSession([response(503, {"error": "unavailable"})])
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=context(),
        max_retries=7,
        retry_on_methods=["GET"],
        retry_on_status=[503],
        chain_discriminant=753,
    )

    with pytest.raises(RuntimeError):
        client.list_kaigi_relays()
    assert len(session.calls) == 1
    assert session.calls[0]["allow_redirects"] is False


def test_kaigi_detail_empty_success_is_not_treated_as_not_found() -> None:
    session = RecordingSession([response(200)])
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=context(),
        chain_discriminant=753,
    )

    with pytest.raises(RuntimeError, match="empty success response"):
        client.get_kaigi_relay(RELAY_ID)
