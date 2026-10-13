"""Exact operator-authentication tests for Sumeragi reads."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from client_test_support import canonical_hash
from sumeragi_exact_json_test_support import RecordingSession, StubResponse

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

import iroha_torii_client.client as client_module  # noqa: E402
from iroha_torii_client import (  # noqa: E402
    ToriiClient,
    ToriiOperatorSigningContext,
    operator_network_request_signature_message,
)

GOVERNANCE_NETWORK_ID = canonical_hash(0xA5)


def _operator_context(captured: Optional[List[bytes]] = None) -> ToriiOperatorSigningContext:
    def signer(message: bytes) -> bytes:
        if captured is not None:
            captured.append(message)
        return b"\x55" * 64

    return ToriiOperatorSigningContext(
        network_id=GOVERNANCE_NETWORK_ID,
        public_key="ed0120" + "66" * 32,
        signer=signer,
    )


def _sumeragi_native_evidence_record(
    *, penalty_status: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    return {
        "kind": "NativeSumeragiEvidence",
        "value": {
            "scope": {"kind": "root", "value": None},
            "class": "phase_vote",
            "height": 31,
            "epoch": 2,
            "context_id": "11" * 32,
            "instance": "22" * 32,
            "authority_generation": "33" * 32,
            "offenders": [{"signer": 3, "peer_id": "ea0130" + "22" * 48}],
            "safety_violation": False,
            "native_frame_hash": "44" * 32,
            "recorded_height": 40,
            "recorded_view": 2,
            "recorded_ms": 1_700_000_000_000,
            "consensus_admitted_height": 41,
            "penalty_status": penalty_status
            if penalty_status is not None
            else {"status": "pending", "details": None},
        },
    }


def test_operator_reads_reject_missing_or_fallback_auth_before_dispatch() -> None:
    missing_session = RecordingSession()
    missing_client = ToriiClient("http://node.test", session=missing_session)
    with pytest.raises(ValueError, match="ToriiOperatorSigningContext"):
        missing_client.get_sumeragi_status()
    assert missing_session.calls == []

    fallback_session = RecordingSession()
    fallback_session.headers["Authorization"] = "Bearer retired"
    fallback_client = ToriiClient(
        "http://node.test",
        session=fallback_session,
        operator_signing_context=_operator_context(),
    )
    with pytest.raises(ValueError, match="reject token"):
        fallback_client.get_sumeragi_status()
    assert fallback_session.calls == []

    precomputed_session = RecordingSession()
    precomputed_client = ToriiClient(
        "http://node.test",
        session=precomputed_session,
        operator_signing_context=_operator_context(),
    )
    with pytest.raises(ValueError, match="precomputed operator"):
        precomputed_client._operator_get(
            "/v1/sumeragi/status",
            headers={"X-Iroha-Operator-Signature": "precomputed"},
        )
    assert precomputed_session.calls == []


def test_list_sumeragi_evidence_signs_canonical_query_and_parses_records() -> None:
    session = RecordingSession()
    session.queue(
        StubResponse(
            payload={
                "total": 4,
                "items": [
                    _sumeragi_native_evidence_record(),
                    _sumeragi_native_evidence_record(
                        penalty_status={
                            "status": "applied",
                            "details": {"height": 42},
                        }
                    ),
                    _sumeragi_native_evidence_record(
                        penalty_status={
                            "status": "applied",
                            "details": {"height": 43},
                        }
                    ),
                ],
            }
        )
    )
    captured: List[bytes] = []
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(captured),
    )

    page = client.list_sumeragi_evidence(limit=5, offset=1, kind="NativeSumeragiEvidence")

    assert page.total == 4
    assert len(page.items) == 3
    equivocation = page.items[0]
    assert isinstance(equivocation, client_module.SumeragiEvidenceRecord)
    assert equivocation.value.class_ == "phase_vote"
    assert equivocation.value.offenders[0].signer == 3
    assert equivocation.value.context_id == "11" * 32
    assert equivocation.value.consensus_admitted_height == 41
    assert isinstance(
        equivocation.value.penalty_status,
        client_module.SumeragiEvidencePendingPenaltyStatus,
    )
    assert isinstance(
        page.items[1].value.penalty_status,
        client_module.SumeragiEvidenceAppliedPenaltyStatus,
    )
    assert page.items[1].value.penalty_status.details.height == 42
    assert isinstance(
        page.items[2].value.penalty_status,
        client_module.SumeragiEvidenceAppliedPenaltyStatus,
    )
    assert page.items[2].value.penalty_status.details.height == 43
    call = session.calls[0]
    assert call["url"].endswith(
        "/v1/sumeragi/evidence?kind=NativeSumeragiEvidence&limit=5&offset=1"
    )
    assert call["params"] == {}
    assert call["allow_redirects"] is False
    assert call["data"] is None
    assert call["stream"] is True
    assert len(captured) == 1
    timestamp_ms = int(call["headers"]["X-Iroha-Operator-Timestamp-Ms"])
    nonce = call["headers"]["X-Iroha-Operator-Nonce"]
    assert captured[0] == operator_network_request_signature_message(
        GOVERNANCE_NETWORK_ID,
        "GET",
        "/v1/sumeragi/evidence?kind=NativeSumeragiEvidence&limit=5&offset=1",
        b"",
        timestamp_ms=timestamp_ms,
        nonce=nonce,
    )


@pytest.mark.parametrize("route", ["list", "count"])
@pytest.mark.parametrize(
    ("failure", "error_type", "message"),
    [
        ("content_type", TypeError, "application/json content type"),
        ("content_length", ValueError, ""),
        ("actual_body", ValueError, ""),
        ("duplicate", ValueError, "duplicate field"),
    ],
)
def test_sumeragi_evidence_reads_enforce_strict_bounded_json(
    route: str,
    failure: str,
    error_type: type[Exception],
    message: str,
) -> None:
    maximum_body_bytes = 1024 * 1024 if route == "list" else 1024
    if route == "list":
        canonical_body = json.dumps({"total": 0, "items": []}).encode()
        duplicate_body = b'{"total":0,"total":1,"items":[]}'
    else:
        canonical_body = json.dumps({"count": 0}).encode()
        duplicate_body = b'{"count":0,"count":1}'

    headers = {"Content-Type": "application/json"}
    body = canonical_body
    if failure == "content_type":
        headers["Content-Type"] = "text/plain"
    elif failure == "content_length":
        headers["Content-Length"] = str(maximum_body_bytes + 1)
        message = f"{maximum_body_bytes}-byte size bound"
    elif failure == "actual_body":
        body = b" " * (maximum_body_bytes + 1)
        message = f"{maximum_body_bytes}-byte size bound"
    else:
        body = duplicate_body

    response = StubResponse(raw=body, headers=headers)
    session = RecordingSession()
    session.queue(response)
    client = ToriiClient(
        "http://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )

    with pytest.raises(error_type, match=message):
        if route == "list":
            client.list_sumeragi_evidence()
        else:
            client.get_sumeragi_evidence_count()

    assert response.was_closed is True
    assert session.calls[0]["stream"] is True
    assert session.calls[0]["headers"]["Accept"] == "application/json"


def test_evidence_preserves_unattributed_certificate_safety_violation() -> None:
    record = _sumeragi_native_evidence_record()
    record["value"].update({
        "class": "conflicting_certificates", "safety_violation": True, "offenders": [],
    })
    session = RecordingSession()
    session.queue(StubResponse(payload={"total": 1, "items": [record]}))
    client = ToriiClient(
        "http://node.test", session=session, operator_signing_context=_operator_context()
    )
    parsed = client.list_sumeragi_evidence().items[0]
    assert parsed.value.class_ == "conflicting_certificates"
    assert parsed.value.safety_violation is True
    assert parsed.value.offenders == ()
    assert parsed.value.native_frame_hash == record["value"]["native_frame_hash"]


@pytest.mark.parametrize("evidence_class,safety_violation", [
    ("conflicting_certificates", False), ("conflicting_certificates", 1),
    ("phase_vote", True),
])
def test_empty_offenders_require_exact_certificate_safety_violation(
    evidence_class: str, safety_violation: Any,
) -> None:
    record = _sumeragi_native_evidence_record()
    record["value"].update({
        "class": evidence_class, "safety_violation": safety_violation, "offenders": [],
    })
    session = RecordingSession()
    session.queue(StubResponse(payload={"total": 1, "items": [record]}))
    client = ToriiClient(
        "http://node.test", session=session, operator_signing_context=_operator_context()
    )
    with pytest.raises(RuntimeError, match="offenders must contain"):
        client.list_sumeragi_evidence()
