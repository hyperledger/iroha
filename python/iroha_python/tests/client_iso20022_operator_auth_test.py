"""Focused exact-operator-auth tests for the existing ISO 20022 SDK methods."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
import requests
from iroha_torii_client.client import canonical_request_message
from requests.adapters import HTTPAdapter

from iroha_python import NetworkId, OperatorSigningContext, ToriiClient
from iroha_python.crypto import Ed25519KeyPair

NETWORK_BYTES = bytes([0xA5]) * 32
NETWORK_ID = NetworkId.from_bytes(NETWORK_BYTES)
KEY_PAIR = Ed25519KeyPair.from_private_key(bytes([0x0B]) * 32)


def response(status: int, payload: object | None = None) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result._content = b"" if payload is None else json.dumps(payload).encode("utf-8")
    result._content_consumed = True
    if payload is not None:
        result.headers["Content-Type"] = "application/json"
    return result


class RecordingSession(requests.Session):
    """Requests session with real adapter policy and deterministic responses."""

    def __init__(self, responses: list[requests.Response]) -> None:
        super().__init__()
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str | bytes, url: str | bytes, **kwargs: Any) -> requests.Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError("unexpected ISO HTTP request")
        return self.responses.pop(0)


def context() -> OperatorSigningContext:
    return OperatorSigningContext(NETWORK_ID, KEY_PAIR)


def test_iso_submission_signs_exact_network_query_and_body_once() -> None:
    session = RecordingSession([response(202, {"message_id": "signed-1", "status": "Accepted"})])
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=context(),
        max_retries=5,
        retry_on_methods=["POST"],
        retry_on_status=[503],
        chain_discriminant=753,
    )
    body = b"<Document><MsgId>signed-1</MsgId></Document>"

    client.submit_iso_pacs008(body, profile="swift-cbpr-plus")

    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == ("https://torii.example/v1/iso20022/pacs008?profile=swift-cbpr-plus")
    assert call["params"] is None
    assert call["data"] == body
    assert call["allow_redirects"] is False
    headers = call["headers"]
    assert "X-Iroha-Iso-Profile" not in headers
    timestamp = headers["x-iroha-operator-timestamp-ms"]
    nonce = headers["x-iroha-operator-nonce"]
    signature = base64.b64decode(headers["x-iroha-operator-signature"], validate=True)
    request = canonical_request_message(
        "POST",
        "/v1/iso20022/pacs008?profile=swift-cbpr-plus",
        body,
    )
    message = b"".join(
        (
            b"iroha.operator.http-request.network.v1\0",
            NETWORK_BYTES,
            request,
            f"\n{timestamp}\n{nonce}".encode("ascii"),
        )
    )
    assert KEY_PAIR.verify(message, signature)
    foreign_query = message.replace(b"swift-cbpr-plus", b"foreign-profile")
    assert not KEY_PAIR.verify(foreign_query, signature)


def test_iso_operator_auth_is_mandatory_one_shot_and_rejects_retired_shapes() -> None:
    unsigned_session = RecordingSession([])
    unsigned = ToriiClient("https://torii.example", session=unsigned_session, chain_discriminant=753)
    with pytest.raises(ValueError, match="operator_signing_context"):
        unsigned.submit_iso_pacs008(b"<xml/>")
    assert unsigned_session.calls == []

    retry_session = RecordingSession([response(503, {"error": "unavailable"})])
    retrying = ToriiClient(
        "https://torii.example",
        session=retry_session,
        operator_signing_context=context(),
        max_retries=5,
        retry_on_methods=["POST"],
        retry_on_status=[503],
        chain_discriminant=753,
    )
    with pytest.raises(RuntimeError):
        retrying.submit_iso_pacs009(b"<xml/>")
    assert len(retry_session.calls) == 1

    retired_options = (
        {"auth_token": "retired-bearer"},
        {"api_token": "retired-api-token"},
        {"default_headers": {"X-Iroha-Account": "retired-app-auth"}},
        {"default_headers": {"X-Iroha-Iso-Profile": "legacy-profile"}},
        {"default_headers": {"X-Iroha-Operator-Nonce": "precomputed"}},
    )
    for options in retired_options:
        session = RecordingSession([])
        with pytest.raises(
            ValueError,
            match="canonical authentication headers|generated operator signing",
        ):
            client = ToriiClient(
                "https://torii.example",
                session=session,
                operator_signing_context=context(),
                **options,
                chain_discriminant=753,
            )
            client.get_iso_message_status("signed-1")
        assert session.calls == []


def test_iso_rejects_retrying_adapter_before_signing_or_dispatch() -> None:
    session = RecordingSession([])
    session.mount("https://", HTTPAdapter(max_retries=1))
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=context(),
        chain_discriminant=753,
    )

    with pytest.raises(ValueError, match="transport retries to be disabled"):
        client.get_iso_message_status("signed-1")
    assert session.calls == []


def test_iso_status_polls_use_fresh_operator_nonces() -> None:
    session = RecordingSession(
        [
            response(200, {"message_id": "poll-1", "status": "Pending"}),
            response(200, {"message_id": "poll-1", "status": "Committed"}),
        ]
    )
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=context(),
        chain_discriminant=753,
    )

    result = client.wait_for_iso_message_status(
        "poll-1",
        poll_interval=0.0,
        max_attempts=2,
    )

    assert result.status == "Committed"
    assert len(session.calls) == 2
    nonces = [call["headers"]["x-iroha-operator-nonce"] for call in session.calls]
    assert nonces[0] != nonces[1]
    assert all(call["allow_redirects"] is False for call in session.calls)


def test_iso_status_exposes_pinned_participant_provenance() -> None:
    session = RecordingSession(
        [
            response(
                200,
                {
                    "message_id": "provenance-1",
                    "status": "Accepted",
                    "originator_participant_id": "originator-bank",
                    "counterparty_participant_id": "counterparty-bank",
                    "admitting_participant_id": "originator-bank",
                    "admitting_operator_key": "ed0120operator",
                    "pinned_profile_id": "generic-pacs008",
                    "pinned_signature_policy": "operator-request-v1",
                },
            )
        ]
    )
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=context(),
        chain_discriminant=753,
    )

    record = client.get_iso_message_status_typed("provenance-1")

    assert record is not None
    assert record.originator_participant_id == "originator-bank"
    assert record.counterparty_participant_id == "counterparty-bank"
    assert record.admitting_participant_id == "originator-bank"
    assert record.admitting_operator_key == "ed0120operator"
    assert record.pinned_profile_id == "generic-pacs008"
    assert record.pinned_signature_policy == "operator-request-v1"


def test_iso_status_preserves_schema_v3_replay_settlement_and_plan_fields() -> None:
    session = RecordingSession(
        [
            response(
                200,
                {
                    "message_id": "schema-v3",
                    "status": "Committed",
                    "pacs002_code": "ACSC",
                    "profile_id": "generic-pacs008",
                    "message_type": "pacs.008",
                    "business_service": "swift.cbprplus.02",
                    "business_message_id": "BIZ-42",
                    "uetr": "123e4567-e89b-12d3-a456-426614174000",
                    "payload_hash": "11" * 32,
                    "reference_snapshot_id": "snapshot-7",
                    "embedded_signature_detected": True,
                    "status_history": [
                        {
                            "status": "Accepted",
                            "pacs002_code": "ACSP",
                            "updated_at_ms": 42,
                            "detail": "admitted",
                            "reason_code": None,
                        }
                    ],
                    "settlement_amount": "1250.00",
                    "settlement_currency": "USD",
                    "settlement_date": "2026-09-02",
                    "settlement_quantity": "25",
                    "settlement_movement_type": "DELIVERY",
                    "settlement_payment_type": "AGAINST_PAYMENT",
                    "security_instrument_id": "US0378331005",
                    "collateral_obligation_id": "COLL-42",
                    "collateral_original_amount": "1000",
                    "collateral_original_currency": "USD",
                    "collateral_original_instrument_id": "US0000000001",
                    "collateral_substitute_amount": "990",
                    "collateral_substitute_currency": "EUR",
                    "collateral_substitute_instrument_id": "EU0000000002",
                    "collateral_effective_date": "2026-09-03",
                    "collateral_substitution_type": "FULL",
                    "collateral_haircut": "0.01",
                    "collateral_reason_code": "SUBS",
                    "plan_execution_order": "1",
                    "plan_atomicity": "atomic",
                },
            )
        ]
    )
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=context(),
        chain_discriminant=753,
    )

    record = client.get_iso_message_status_typed("schema-v3")

    assert record is not None
    assert record.status == "Committed"
    assert record.profile_id == "generic-pacs008"
    assert record.business_message_id == "BIZ-42"
    assert record.embedded_signature_detected is True
    assert record.status_history[0].status == "Accepted"
    assert record.status_history[0].pacs002_code == "ACSP"
    assert record.settlement_amount == "1250.00"
    assert record.security_instrument_id == "US0378331005"
    assert record.collateral_substitute_currency == "EUR"
    assert record.plan_execution_order == "1"
    assert record.plan_atomicity == "atomic"


@pytest.mark.parametrize(
    "profile",
    [" Swift-CBPR-Plus", "swift_cbpr_plus", "swift-"],
)
def test_iso_profiles_require_exact_catalog_identifiers(profile: str) -> None:
    session = RecordingSession([])
    client = ToriiClient(
        "https://torii.example",
        session=session,
        operator_signing_context=context(),
        chain_discriminant=753,
    )

    with pytest.raises(ValueError, match="canonical lowercase profile id"):
        client.submit_iso_pacs008(b"<xml/>", profile=profile)
    assert session.calls == []
