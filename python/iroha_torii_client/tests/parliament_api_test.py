"""Strict transport and binding tests for the Python Parliament API V1."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, List, Optional, Sequence

import iroha_torii_client.parliament_api as parliament_api_module
import pytest
import requests
from client_test_support import CANONICAL_OWNER
from iroha_torii_client import (
    PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1,
    PARLIAMENT_ATTEMPT_DRAFT_PATH_V1,
    PARLIAMENT_ATTEMPT_READ_PATH_V1,
    PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1,
    PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
    PARLIAMENT_TRANSITION_DRAFT_PATH_V1,
    PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
    GovernanceCapabilitiesV1,
    ParliamentAttemptDraftResponseV1,
    ParliamentAttemptReadResponseV1,
    ParliamentTransitionDraftResponseV1,
    ToriiCanonicalRequestAuth,
    ToriiClient,
)
from iroha_torii_client.norito_frame import (
    schema_hash_for_type_name,
    validate_opaque_norito_frame,
)
from sumeragi_exact_json_test_support import RecordingSession, StubResponse

NETWORK_ID = "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"
PROPOSAL_ID = "11" * 32
ATTEMPT_ID = "22" * 32
BODY_ID = "33" * 32
ATTEMPT_INSTRUCTION_TYPE_NAME = (
    "iroha_data_model::isi::governance::parliament::"
    "CreateParliamentGovernanceAttemptV1"
)
TRANSITION_INSTRUCTION_TYPE_NAME = (
    "iroha_data_model::isi::governance::parliament::"
    "SubmitParliamentLifecycleTransitionV1"
)
FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "governance"
    / "parliament_api_v1.json"
)
OPENAPI_PATH = (
    Path(__file__).resolve().parents[3] / "artifacts" / "openapi" / "torii.json"
)
PRIVATE_BODIES = ("policy-jury", "confirmation-jury")
SERVER_SUPPORTED_ROUTES = [
    "/v1/gov/capabilities",
    "/v1/gov/citizens/draft",
    "/v1/gov/parliament/attempts/draft",
    "/v1/gov/parliament/attempts/{governance_attempt_id}",
    "/v1/gov/parliament/attempts/{governance_attempt_id}/plan",
    "/v1/gov/parliament/transitions/draft",
    "/v1/gov/ballots/plain",
    "/v1/gov/ballots/zk-v1",
    "/v1/gov/ballots/zk-v1/ballot-proof",
    "/v1/validation-fee/proposals",
    "/v1/validation-fee/proposals/{proposal_id}",
    "/v1/validation-fee/proposals/draft",
]


def _auth(
    messages: Optional[List[bytes]] = None,
    *,
    network_id: str = NETWORK_ID,
) -> ToriiCanonicalRequestAuth:
    def sign(message: bytes) -> bytes:
        if messages is not None:
            messages.append(message)
        return bytes([0x77]) * 64

    return ToriiCanonicalRequestAuth(
        network_id=network_id,
        account_id=CANONICAL_OWNER,
        signer=sign,
        timestamp_ms=4_102_444_801_000,
        nonce="python-parliament-api-test",
    )


def _crc64_xz(payload: bytes) -> int:
    polynomial = 0xC96C_5795_D787_0F42
    mask = (1 << 64) - 1
    crc = mask
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (polynomial if crc & 1 else 0)
    return (crc ^ mask) & mask


def _frame(
    payload: bytes,
    schema: str = "test.opaque.v1",
    *,
    padding: int = 0,
    flags: int = 0,
) -> bytes:
    return b"".join(
        (
            b"NRT0",
            b"\x00\x00",
            schema_hash_for_type_name(schema),
            b"\x00",
            len(payload).to_bytes(8, "little"),
            _crc64_xz(payload).to_bytes(8, "little"),
            flags.to_bytes(1, "little"),
            bytes(padding),
            payload,
        )
    )


def _instruction_frame(payload: bytes, wire_id: str) -> bytes:
    type_names = {
        PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1: ATTEMPT_INSTRUCTION_TYPE_NAME,
        PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1: TRANSITION_INSTRUCTION_TYPE_NAME,
    }
    return _frame(payload, type_names[wire_id])


def _json_response(payload: Any, **headers: str) -> StubResponse:
    return StubResponse(
        200,
        payload,
        headers={"Content-Type": "application/json", **headers},
    )


def _proposal() -> dict[str, Any]:
    return {
        "kind": "DeployContract",
        "payload": {
            "contract_address": "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
            "code_hash": "11" * 32,
            "abi_hash": "22" * 32,
            "abi_version": 1,
            "manifest_provenance": None,
        },
    }


def _runtime_upgrade_proposal(start_height: int, end_height: int) -> dict[str, Any]:
    return {
        "kind": "RuntimeUpgrade",
        "payload": {
            "manifest": {
                "name": "runtime-v1",
                "description": "exact public JSON",
                "abi_version": 1,
                "abi_hash": [0x22] * 32,
                "added_syscalls": [],
                "added_pointer_types": [],
                "start_height": start_height,
                "end_height": end_height,
                "sbom_digests": [],
                "slsa_attestation": "",
                "provenance": [],
            }
        },
    }


def _sortition_request(
    *,
    body: str = "rules-committee",
    request_id: str = "88" * 32,
    election_attempt_id: str = "77" * 32,
    candidate_count: int = 1,
) -> dict[str, Any]:
    return {
        "id": request_id,
        "governance_attempt_id": ATTEMPT_ID,
        "body_election_attempt_id": election_attempt_id,
        "body": body,
        "candidate_root": [0x31] * 32,
        "candidate_count": candidate_count,
        "target_seats": 1,
        "request_height": 10,
        "pulse_height": 20,
        "beacon_session_id": "99" * 32,
    }


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _transition_draft_response(kind: str, digest: bytes) -> dict[str, Any]:
    return {
        "version": 1,
        "governance_attempt_id": ATTEMPT_ID,
        "transition_kind": {"kind": kind},
        "transition_digest": list(digest),
        "tx_instructions": [
            {
                "wire_id": PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
                "payload_hex": _instruction_frame(
                    b"transition instruction",
                    PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
                ).hex(),
            }
        ],
    }


def _capabilities() -> dict[str, Any]:
    return {
        "schema": "iroha.governance.capabilities.v1",
        "version": 1,
        "network_id": NETWORK_ID,
        "current_height": "20",
        "network_prefix": "753",
        "abi_version": "1",
        "data_model_version": "4",
        "proposal_backed_referendum_ballots_supported": False,
        "standalone_plain_ballots_supported": False,
        "standalone_zk_ballots_supported": True,
        "citizenship_asset_id": "citizenship#governance",
        "citizenship_bond_amount": "100",
        "citizenship_escrow_account": CANONICAL_OWNER,
        "voting_asset_id": "xor#sora",
        "min_bond_amount": "1",
        "bond_escrow_account": CANONICAL_OWNER,
        "min_enactment_delay": "10",
        "invitation_phase_blocks": "10",
        "target_body_sizes": {
            "rules_committee": "4",
            "agenda_council": "4",
            "interest_panel": "4",
            "review_panel": "4",
            "coordination_council": "4",
            "mpc_committee": "4",
            "fma_committee": "4",
            "oversight_committee": "4",
            "policy_jury": "4",
            "confirmation_jury": "4",
        },
        "supported_proposal_kinds": [
            "CONTRACT_EMERGENCY_HOLD",
            "CONTRACT_LIFECYCLE_GOVERNANCE",
            "DEPLOY_CONTRACT",
            "GLOBAL_DATA_TRIGGER_PERMISSION_GOVERNANCE",
            "MUSUBI_REGISTRY_GOVERNANCE",
            "RUNTIME_UPGRADE",
            "SCCP_ROUTE_GOVERNANCE",
            "SORAFS_PROVIDER_GOVERNANCE",
            "VALIDATION_FEE_PAYOUT_LIFECYCLE",
            "VALIDATION_FEE_POLICY",
        ],
        "supported_routes": list(SERVER_SUPPORTED_ROUTES),
    }


def _attempt_read() -> dict[str, Any]:
    return {
        "version": 1,
        "current_height": 20,
        "attempt": {
            "id": ATTEMPT_ID,
            "proposal_content_id": PROPOSAL_ID,
            "sequence": 0,
            "risk_tier": {"tier": "Routine"},
            "stage": {"stage": "Qualification"},
            "status": {"status": "Active"},
        },
        "policy_version": 1,
        "required_bodies": [
            {"body": "rules-committee", "decision_mode": {"mode": "PublicFinding"}}
        ],
        "body_states": [
            {
                "body": "rules-committee",
                "body_instance_id": None,
                "status": None,
                "public_finding_opened_at_height": None,
                "public_finding_phase_blocks": None,
                "public_finding_deadline_height": None,
                "no_result_kind": None,
                "no_result_height": None,
            }
        ],
        "certificate": None,
        "terminal_height": None,
        "execution_failure_root": None,
        "superseding_head": None,
        "state_payload_hex": _frame(b"attempt state").hex(),
    }


def _distinct_id(base: int, index: int) -> str:
    return f"{base + index:02x}" * 32


def _certificate_attempt_read(
    bodies: Sequence[str] = ("rules-committee", "agenda-council"),
) -> dict[str, Any]:
    """Return a consistent attempt read whose certificate covers ``bodies`` in order."""

    payload = _attempt_read()
    payload["current_height"] = 30
    payload["required_bodies"] = []
    payload["body_states"] = []
    body_bindings = []
    for index, body in enumerate(bodies):
        private = body in PRIVATE_BODIES
        body_instance_id = _distinct_id(0x33, index)
        election_attempt_id = _distinct_id(0x77, index)
        request_id = _distinct_id(0x88, index)
        beacon_session_id = _distinct_id(0x99, index)
        payload["required_bodies"].append(
            {
                "body": body,
                "decision_mode": {
                    "mode": "HiddenBindingBallot" if private else "PublicFinding"
                },
            }
        )
        payload["body_states"].append(
            {
                "body": body,
                "body_instance_id": body_instance_id,
                "status": {"status": "Approved"},
                "public_finding_opened_at_height": None,
                "public_finding_phase_blocks": None,
                "public_finding_deadline_height": None,
                "no_result_kind": None,
                "no_result_height": None,
            }
        )
        body_bindings.append(
            {
                "body_instance_id": body_instance_id,
                "election_attempt_id": election_attempt_id,
                "election_attempt_sequence": 0,
                "sortition_request_id": request_id,
                "sortition_request": {
                    "id": request_id,
                    "governance_attempt_id": ATTEMPT_ID,
                    "body_election_attempt_id": election_attempt_id,
                    "body": body,
                    "candidate_root": [0x31] * 32,
                    "candidate_count": 1,
                    "target_seats": 1,
                    "request_height": 10,
                    "pulse_height": 20,
                    "beacon_session_id": beacon_session_id,
                },
                "body": body,
                "original_seats": 1,
                "beacon_session_id": beacon_session_id,
                "beacon_pulse_id": _distinct_id(0xAA, index),
                "roster_root": [0x32] * 32,
                "assignment_root": [0x33] * 32,
                "result_root": [0x34] * 32,
                "result_height": 25 + index,
                "public_finding": None
                if private
                else {
                    "endorsement_root": [0x35] * 32,
                    "endorsing_assignments": [_distinct_id(0xBB, index)],
                    "endorsements": 1,
                    "quorum": 1,
                },
                "ballot": {} if private else None,
            }
        )
    payload["certificate"] = {
        "proposal_content_id": PROPOSAL_ID,
        "governance_attempt_id": ATTEMPT_ID,
        "governance_attempt_sequence": 0,
        "risk_tier": {"tier": "Routine"},
        "body_bindings": body_bindings,
        "policy_version": 1,
        "effect_preimage_hash": [0x36] * 32,
        "expected_head": {"state": "Absent", "head": {"subject_id": [0x37] * 32}},
        "certified_at_height": 25 + len(bodies) - 1,
        "enact_at_height": 40,
    }
    return payload


def test_all_canonical_routes_are_authenticated_bounded_and_bound() -> None:
    session = RecordingSession()
    transition_digest = bytes([0xE1]) * 32
    for response in (
        _json_response(_capabilities()),
        _json_response(
            {
                "version": 1,
                "proposal_content_id": PROPOSAL_ID,
                "governance_attempt_id": ATTEMPT_ID,
                "tx_instructions": [
                    {
                        "wire_id": PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1,
                        "payload_hex": _instruction_frame(
                            b"attempt instruction",
                            PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1,
                        ).hex(),
                    }
                ],
            }
        ),
        _json_response(_attempt_read()),
        _json_response(
            _transition_draft_response("CompleteQualification", transition_digest)
        ),
    ):
        session.queue(response)
    client = ToriiClient("https://node.test", session=session)
    auth = _auth([])

    assert isinstance(client.get_governance_capabilities_v1(canonical_auth=auth), GovernanceCapabilitiesV1)
    assert isinstance(
        client.draft_parliament_attempt_v1(
            _proposal(),
            PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
            expected_proposal_content_id=PROPOSAL_ID,
            expected_governance_attempt_id=ATTEMPT_ID,
            canonical_auth=auth,
        ),
        ParliamentAttemptDraftResponseV1,
    )
    assert isinstance(
        client.get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=auth),
        ParliamentAttemptReadResponseV1,
    )
    assert isinstance(
        client.draft_parliament_transition_v1(
            ATTEMPT_ID,
            {"transition": "CompleteQualification"},
            expected_transition_digest=transition_digest,
            canonical_auth=auth,
        ),
        ParliamentTransitionDraftResponseV1,
    )

    assert [call["method"] for call in session.calls] == ["GET", "POST", "GET", "POST"]
    assert [call["url"] for call in session.calls] == [
        "https://node.test/v1/gov/capabilities",
        "https://node.test" + PARLIAMENT_ATTEMPT_DRAFT_PATH_V1,
        "https://node.test"
        + PARLIAMENT_ATTEMPT_READ_PATH_V1.replace("{governance_attempt_id}", ATTEMPT_ID),
        "https://node.test" + PARLIAMENT_TRANSITION_DRAFT_PATH_V1,
    ]
    assert all(call["allow_redirects"] is False for call in session.calls)
    assert all(call["stream"] is True for call in session.calls)
    attempt_call = session.calls[1]
    assert json.loads(attempt_call["data"].decode("utf-8"))["attempt_sequence"] == (
        PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1
    )


@pytest.mark.parametrize("identifier", ["0" * 64, "AA" * 32, "11" * 31, "not-an-id"])
def test_noncanonical_or_zero_ids_fail_before_dispatch(identifier: str) -> None:
    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session)
    with pytest.raises(TypeError, match="64 lowercase non-zero"):
        client.get_parliament_attempt_v1(identifier, canonical_auth=_auth())
    assert session.calls == []


def test_strict_json_rejects_duplicates_media_type_and_size() -> None:
    duplicate = RecordingSession()
    duplicate.queue(
        StubResponse(
            200,
            raw=b'{"schema":"first","schema":"second"}',
            headers={"Content-Type": "application/json"},
        )
    )
    with pytest.raises(ValueError, match="duplicate field `schema`"):
        ToriiClient("https://node.test", session=duplicate).get_governance_capabilities_v1(
            canonical_auth=_auth()
        )

    media = RecordingSession()
    media.queue(StubResponse(200, raw=b"{}", headers={"Content-Type": "text/plain"}))
    with pytest.raises(TypeError, match="application/json content type"):
        ToriiClient("https://node.test", session=media).get_governance_capabilities_v1(
            canonical_auth=_auth()
        )

    oversized = RecordingSession()
    oversized.queue(
        StubResponse(
            200,
            raw=b"{}",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(64 * 1024 + 1),
            },
        )
    )
    with pytest.raises(ValueError, match="65536-byte size bound"):
        ToriiClient("https://node.test", session=oversized).get_governance_capabilities_v1(
            canonical_auth=_auth()
        )


def test_shared_fixture_pins_routes_wire_ids_and_limits() -> None:
    fixture = _fixture()

    assert fixture["routes"] == {
        "attempt_draft": PARLIAMENT_ATTEMPT_DRAFT_PATH_V1,
        "attempt_read": PARLIAMENT_ATTEMPT_READ_PATH_V1,
        "transition_draft": PARLIAMENT_TRANSITION_DRAFT_PATH_V1,
    }
    assert parliament_api_module._PARLIAMENT_ROUTES_V1 == {
        "/v1/gov/capabilities",
        *fixture["routes"].values(),
    }
    assert fixture["wire_ids"] == {
        "attempt_create": PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1,
        "transition_submit": PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
    }
    assert fixture["limits"] == {
        "attempt_state_bytes": PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1,
        "governance_attempt_sequence_max": PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
    }


def test_shared_fixture_pins_the_public_transition_table() -> None:
    transitions = _fixture()["public_transitions"]
    table = parliament_api_module._PUBLIC_TRANSITION_FIELDS

    assert [entry["norito_index"] for entry in transitions] == list(range(len(transitions)))
    assert set(table) == {entry["json_tag"] for entry in transitions}
    for entry in transitions:
        assert (table[entry["json_tag"]] is None) == (entry["json_payload"] == "forbidden")


def test_shared_fixture_pins_the_no_result_kinds() -> None:
    kinds = _fixture()["no_result_kinds"]

    assert [entry["norito_index"] for entry in kinds] == list(range(len(kinds)))
    assert parliament_api_module._NO_RESULT_KINDS_V1 == {entry["json_tag"] for entry in kinds}
    assert kinds[-1] == {"norito_index": 4, "json_tag": "RandomnessRedrawBudgetExhausted"}


def test_shared_fixture_pins_body_order_and_projection_shapes() -> None:
    fixture = _fixture()

    assert list(parliament_api_module._BODY_ORDER) == fixture["canonical_body_order"]

    state = _attempt_read()["body_states"][0]
    assert set(state) == set(fixture["attempt_read_body_state"]["json_fields"])
    assert len(state) == len(fixture["attempt_read_body_state"]["json_fields"])

    binding_shape = fixture["certificate_body_binding"]
    certificate = _certificate_attempt_read()["certificate"]
    for binding in certificate["body_bindings"]:
        assert set(binding) == set(binding_shape["norito_field_order"])
        assert set(binding["public_finding"]) == set(
            binding_shape["public_nonbinding_body"]["public_finding_norito_field_order"]
        )
    assert binding_shape["public_nonbinding_body"]["ballot"] == "forbidden"


def test_attempt_read_body_states_expose_exactly_the_shared_fields() -> None:
    widened = _attempt_read()
    widened["body_states"][0]["unexpected_field"] = None
    narrowed = _attempt_read()
    del narrowed["body_states"][0]["no_result_height"]

    for payload, message in (
        (widened, "contains unknown field `unexpected_field`"),
        (narrowed, "missing required field `no_result_height`"),
    ):
        session = RecordingSession()
        session.queue(_json_response(payload))
        with pytest.raises(TypeError, match=message):
            ToriiClient("https://node.test", session=session).get_parliament_attempt_v1(
                ATTEMPT_ID, canonical_auth=_auth()
            )


def test_capabilities_fields_match_the_published_openapi_contract() -> None:
    schema = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))["components"]["schemas"][
        "GovernanceCapabilitiesV1"
    ]
    published = set(schema["properties"])

    assert set(schema["required"]) == published
    assert parliament_api_module._CAPABILITIES_FIELDS == published
    assert set(_capabilities()) == published


def test_attempt_read_accepts_sortition_retries_exhausted_no_result() -> None:
    payload = _attempt_read()
    state = payload["body_states"][0]
    state["body_instance_id"] = BODY_ID
    state["status"] = {"status": "NoResult"}
    state["no_result_kind"] = {"reason": "SortitionRetriesExhausted"}
    state["no_result_height"] = 20
    session = RecordingSession()
    session.queue(_json_response(payload))
    parsed = ToriiClient(
        "https://node.test", session=session
    ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())
    assert parsed.raw["body_states"][0]["no_result_kind"] == {
        "reason": "SortitionRetriesExhausted"
    }


def test_attempt_read_accepts_confirmation_capacity_no_result() -> None:
    payload = _attempt_read()
    state = payload["body_states"][0]
    state["body_instance_id"] = BODY_ID
    state["status"] = {"status": "NoResult"}
    state["no_result_kind"] = {"reason": "ConfirmationJuryCapacityUnavailable"}
    state["no_result_height"] = 20
    session = RecordingSession()
    session.queue(_json_response(payload))
    parsed = ToriiClient(
        "https://node.test", session=session
    ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())
    assert parsed.raw["body_states"][0]["no_result_kind"] == {
        "reason": "ConfirmationJuryCapacityUnavailable"
    }


def test_attempt_read_accepts_randomness_redraw_budget_no_result() -> None:
    payload = _attempt_read()
    state = payload["body_states"][0]
    state["body_instance_id"] = BODY_ID
    state["status"] = {"status": "NoResult"}
    state["no_result_kind"] = {"reason": "RandomnessRedrawBudgetExhausted"}
    state["no_result_height"] = 20
    session = RecordingSession()
    session.queue(_json_response(payload))
    parsed = ToriiClient(
        "https://node.test", session=session
    ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())
    assert parsed.raw["body_states"][0]["no_result_kind"] == {
        "reason": "RandomnessRedrawBudgetExhausted"
    }


def test_attempt_read_accepts_every_shared_no_result_kind() -> None:
    for entry in _fixture()["no_result_kinds"]:
        payload = _attempt_read()
        state = payload["body_states"][0]
        state["body_instance_id"] = BODY_ID
        state["status"] = {"status": "NoResult"}
        state["no_result_kind"] = {"reason": entry["json_tag"]}
        state["no_result_height"] = 20
        session = RecordingSession()
        session.queue(_json_response(payload))
        parsed = ToriiClient(
            "https://node.test", session=session
        ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())
        assert parsed.raw["body_states"][0]["no_result_kind"] == {"reason": entry["json_tag"]}


def test_attempt_read_rejects_an_unlisted_no_result_kind() -> None:
    payload = _attempt_read()
    state = payload["body_states"][0]
    state["body_instance_id"] = BODY_ID
    state["status"] = {"status": "NoResult"}
    state["no_result_kind"] = {"reason": "UnlistedNoResultKind"}
    state["no_result_height"] = 20
    session = RecordingSession()
    session.queue(_json_response(payload))
    with pytest.raises(TypeError, match="no_result_kind.reason is not an admitted"):
        ToriiClient("https://node.test", session=session).get_parliament_attempt_v1(
            ATTEMPT_ID, canonical_auth=_auth()
        )


def test_transition_rejects_private_material_and_automatic_outcomes() -> None:
    client = ToriiClient("https://node.test", session=RecordingSession())
    with pytest.raises(TypeError, match="private_key is forbidden"):
        client.draft_parliament_transition_v1(
            ATTEMPT_ID,
            {
                "transition": "EndorsePublicFinding",
                "payload": {
                    "body_instance_id": BODY_ID,
                    "result_root": [1] * 32,
                    "private_key": "never",
                },
            },
            expected_transition_digest=bytes([1]) * 32,
            canonical_auth=_auth(),
        )
    with pytest.raises(TypeError, match="unknown, removed, or consensus-owned"):
        client.draft_parliament_transition_v1(
            ATTEMPT_ID,
            {"transition": "Enacted"},
            expected_transition_digest=bytes([1]) * 32,
            canonical_auth=_auth(),
        )


def test_request_bindings_and_exact_proposal_integers_fail_before_dispatch() -> None:
    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session)
    with pytest.raises(TypeError, match="64 lowercase non-zero"):
        client.draft_parliament_attempt_v1(
            _proposal(),
            0,
            expected_proposal_content_id="0" * 64,
            expected_governance_attempt_id=ATTEMPT_ID,
            canonical_auth=_auth(),
        )
    with pytest.raises(TypeError, match="9007199254740991"):
        client.draft_parliament_attempt_v1(
            _runtime_upgrade_proposal(1 << 53, (1 << 53) + 1),
            0,
            expected_proposal_content_id=PROPOSAL_ID,
            expected_governance_attempt_id=ATTEMPT_ID,
            canonical_auth=_auth(),
        )
    with pytest.raises(TypeError, match="32 non-zero immutable bytes"):
        client.draft_parliament_transition_v1(
            ATTEMPT_ID,
            {"transition": "CompleteQualification"},
            expected_transition_digest=bytes(32),
            canonical_auth=_auth(),
        )
    with pytest.raises(TypeError, match="attempt_sequence"):
        client.draft_parliament_attempt_v1(
            _proposal(),
            PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1 + 1,
            expected_proposal_content_id=PROPOSAL_ID,
            expected_governance_attempt_id=ATTEMPT_ID,
            canonical_auth=_auth(),
        )
    assert session.calls == []


def test_transition_nested_shapes_fail_before_dispatch() -> None:
    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session)
    with pytest.raises(TypeError, match="canonical Parliament body"):
        client.draft_parliament_transition_v1(
            ATTEMPT_ID,
            {
                "transition": "RecordInvitationResponse",
                "payload": {
                    "election_attempt_id": BODY_ID,
                    "body": "shadow-council",
                    "decision": {"decision": "Accept"},
                },
            },
            expected_transition_digest=bytes([1]) * 32,
            canonical_auth=_auth(),
        )
    with pytest.raises(TypeError, match="missing required field `beacon_session_id`"):
        client.draft_parliament_transition_v1(
            ATTEMPT_ID,
            {
                "transition": "RegisterSortitionRequest",
                "payload": {
                    "requests": [{"sequence": 0, "request": {}}],
                },
            },
            expected_transition_digest=bytes([1]) * 32,
            canonical_auth=_auth(),
        )
    assert session.calls == []


def test_register_sortition_request_uses_one_atomic_body_ordered_batch() -> None:
    digest = bytes([0xE3]) * 32
    transition = {
        "transition": "RegisterSortitionRequest",
        "payload": {
            "requests": [
                {
                    "sequence": 0,
                    "request": _sortition_request(candidate_count=1_001),
                },
                {
                    "sequence": 0,
                    "request": _sortition_request(
                        body="agenda-council",
                        request_id="89" * 32,
                        election_attempt_id="78" * 32,
                        candidate_count=1_001,
                    ),
                },
            ]
        },
    }
    accepted = RecordingSession()
    accepted.queue(
        _json_response(
            {
                "version": 1,
                "governance_attempt_id": ATTEMPT_ID,
                "transition_kind": {"kind": "RegisterSortitionRequest"},
                "transition_digest": list(digest),
                "tx_instructions": [
                    {
                        "wire_id": PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
                        "payload_hex": _instruction_frame(
                            b"atomic sortition instruction",
                            PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
                        ).hex(),
                    }
                ],
            }
        )
    )
    result = ToriiClient(
        "https://node.test", session=accepted
    ).draft_parliament_transition_v1(
        ATTEMPT_ID,
        transition,
        expected_transition_digest=digest,
        canonical_auth=_auth(),
    )
    assert result.transition_kind == "RegisterSortitionRequest"
    sent = json.loads(accepted.calls[0]["data"].decode("utf-8"))
    assert sent["transition"] == transition
    assert "candidate_snapshot" not in accepted.calls[0]["data"].decode("utf-8")

    forbidden_snapshot = copy.deepcopy(transition)
    forbidden_snapshot["payload"]["candidate_snapshot"] = [CANONICAL_OWNER]
    reversed_order = copy.deepcopy(transition)
    reversed_order["payload"]["requests"].reverse()
    different_count = copy.deepcopy(transition)
    different_count["payload"]["requests"][1]["request"]["candidate_count"] = 1_002
    oversized_batch = copy.deepcopy(transition)
    oversized_batch["payload"]["requests"] = oversized_batch["payload"]["requests"] * 6

    for malformed, message in (
        (forbidden_snapshot, "unknown field `candidate_snapshot`"),
        (reversed_order, "strictly body-ordered"),
        (different_count, "share one pulse slot and count"),
        (oversized_batch, "one through 10 requests"),
    ):
        rejected = RecordingSession()
        with pytest.raises((TypeError, ValueError), match=message):
            ToriiClient(
                "https://node.test", session=rejected
            ).draft_parliament_transition_v1(
                ATTEMPT_ID,
                malformed,
                expected_transition_digest=digest,
                canonical_auth=_auth(),
            )
        assert rejected.calls == []


def test_transition_drafts_reject_every_tag_outside_the_shared_public_table() -> None:
    fixture = _fixture()
    rejected = [entry["json_tag"] for entry in fixture["automatic_execution_outcomes"]]
    rejected += [
        case["value"] for case in fixture["negative_json_cases"] if case["name"].endswith("_tag")
    ]
    assert len(rejected) >= 8
    assert set(rejected).isdisjoint(parliament_api_module._PUBLIC_TRANSITION_FIELDS)

    session = RecordingSession()
    client = ToriiClient("https://node.test", session=session)
    for tag in rejected:
        with pytest.raises(TypeError, match="unknown, removed, or consensus-owned"):
            client.draft_parliament_transition_v1(
                ATTEMPT_ID,
                {"transition": tag},
                expected_transition_digest=bytes([1]) * 32,
                canonical_auth=_auth(),
            )
    assert session.calls == []


def test_register_initial_sortition_is_a_payload_free_public_transition() -> None:
    digest = bytes([0xE4]) * 32
    accepted = RecordingSession()
    accepted.queue(_json_response(_transition_draft_response("RegisterInitialSortition", digest)))
    result = ToriiClient(
        "https://node.test", session=accepted
    ).draft_parliament_transition_v1(
        ATTEMPT_ID,
        {"transition": "RegisterInitialSortition"},
        expected_transition_digest=digest,
        canonical_auth=_auth(),
    )
    assert result.transition_kind == "RegisterInitialSortition"
    sent = json.loads(accepted.calls[0]["data"].decode("utf-8"))
    assert sent["transition"] == {"transition": "RegisterInitialSortition"}

    rejected = RecordingSession()
    with pytest.raises(TypeError, match="contains unknown field `payload`"):
        ToriiClient(
            "https://node.test", session=rejected
        ).draft_parliament_transition_v1(
            ATTEMPT_ID,
            {"transition": "RegisterInitialSortition", "payload": {}},
            expected_transition_digest=digest,
            canonical_auth=_auth(),
        )
    assert rejected.calls == []


def test_instruction_payload_must_be_a_canonical_norito_frame() -> None:
    session = RecordingSession()
    session.queue(
        _json_response(
            {
                "version": 1,
                "proposal_content_id": PROPOSAL_ID,
                "governance_attempt_id": ATTEMPT_ID,
                "tx_instructions": [
                    {
                        "wire_id": PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1,
                        "payload_hex": "00ff",
                    }
                ],
            }
        )
    )
    with pytest.raises(ValueError, match="40-byte Norito header"):
        ToriiClient("https://node.test", session=session).draft_parliament_attempt_v1(
            _proposal(),
            0,
            expected_proposal_content_id=PROPOSAL_ID,
            expected_governance_attempt_id=ATTEMPT_ID,
            canonical_auth=_auth(),
        )
    assert len(session.calls) == 1


@pytest.mark.parametrize(
    ("wire_id", "type_name", "foreign_type_name"),
    [
        (
            PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1,
            ATTEMPT_INSTRUCTION_TYPE_NAME,
            TRANSITION_INSTRUCTION_TYPE_NAME,
        ),
        (
            PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
            TRANSITION_INSTRUCTION_TYPE_NAME,
            ATTEMPT_INSTRUCTION_TYPE_NAME,
        ),
    ],
)
def test_instruction_payload_requires_the_exact_rust_schema_hash(
    wire_id: str,
    type_name: str,
    foreign_type_name: str,
) -> None:
    context = "tx_instructions"
    valid = _frame(b"instruction", type_name)
    parsed = parliament_api_module._instruction(
        [{"wire_id": wire_id, "payload_hex": valid.hex()}],
        wire_id,
        context,
    )
    assert parsed.payload_hex == valid.hex()

    zero_schema = bytearray(valid)
    zero_schema[6:22] = bytes(16)
    for invalid in (bytes(zero_schema), _frame(b"instruction", foreign_type_name)):
        with pytest.raises(ValueError, match="schema hash"):
            parliament_api_module._instruction(
                [{"wire_id": wire_id, "payload_hex": invalid.hex()}],
                wire_id,
                context,
            )


def test_opaque_norito_frame_still_requires_an_advertised_schema_hash() -> None:
    frame = bytearray(_frame(b"opaque payload"))
    frame[6:22] = bytes(16)

    with pytest.raises(ValueError, match="non-zero Norito schema hash"):
        validate_opaque_norito_frame(bytes(frame), context="opaque carrier")


def test_attempt_certificate_rejects_unknown_nested_sortition_fields() -> None:
    payload = _certificate_attempt_read()
    payload["certificate"]["body_bindings"][0]["sortition_request"][
        "candidate_snapshot"
    ] = [CANONICAL_OWNER]
    session = RecordingSession()
    session.queue(_json_response(payload))
    with pytest.raises(TypeError, match="contains unknown field `candidate_snapshot`"):
        ToriiClient("https://node.test", session=session).get_parliament_attempt_v1(
            ATTEMPT_ID, canonical_auth=_auth()
        )


def test_attempt_certificate_rejects_unparsed_finding_objects() -> None:
    public = _certificate_attempt_read()
    public["certificate"]["body_bindings"][0]["public_finding"] = {}
    public_session = RecordingSession()
    public_session.queue(_json_response(public))
    with pytest.raises(TypeError, match="missing required field `endorsement_root`"):
        ToriiClient(
            "https://node.test", session=public_session
        ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())


def test_attempt_certificate_public_bodies_carry_only_a_public_finding_binding() -> None:
    with_ballot = _certificate_attempt_read()
    with_ballot["certificate"]["body_bindings"][0]["ballot"] = {}
    without_finding = _certificate_attempt_read()
    without_finding["certificate"]["body_bindings"][0]["public_finding"] = None

    for payload in (with_ballot, without_finding):
        session = RecordingSession()
        session.queue(_json_response(payload))
        with pytest.raises(
            TypeError,
            match=r"certificate\.body_bindings\[0\] must carry only a public-finding binding",
        ):
            ToriiClient("https://node.test", session=session).get_parliament_attempt_v1(
                ATTEMPT_ID, canonical_auth=_auth()
            )


def test_attempt_certificate_accepts_public_finding_only_pipelines() -> None:
    session = RecordingSession()
    session.queue(_json_response(_certificate_attempt_read()))
    parsed = ToriiClient(
        "https://node.test", session=session
    ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())
    assert [
        binding["body"] for binding in parsed.raw["certificate"]["body_bindings"]
    ] == ["rules-committee", "agenda-council"]
    assert parsed.raw["certificate"]["certified_at_height"] == 26


@pytest.mark.parametrize(
    ("bodies", "private_index"),
    [
        (("policy-jury",), 0),
        (("rules-committee", "policy-jury"), 1),
        (("policy-jury", "confirmation-jury"), 0),
    ],
)
def test_attempt_certificate_rejects_private_jury_bindings_until_anonymous_ballot_support(
    bodies: tuple[str, ...], private_index: int
) -> None:
    session = RecordingSession()
    session.queue(_json_response(_certificate_attempt_read(bodies)))
    with pytest.raises(ValueError) as rejection:
        ToriiClient("https://node.test", session=session).get_parliament_attempt_v1(
            ATTEMPT_ID, canonical_auth=_auth()
        )
    assert str(rejection.value) == (
        f"certificate.body_bindings[{private_index}] private-jury result binding is not "
        "admitted until the anonymous-ballot result binding is supported"
    )


@pytest.mark.parametrize(
    "field", ["body_instance_id", "election_attempt_id", "sortition_request_id"]
)
def test_attempt_certificate_rejects_reused_body_election_and_request_identifiers(
    field: str,
) -> None:
    payload = _certificate_attempt_read()
    bindings = payload["certificate"]["body_bindings"]
    reused = bindings[0][field]
    bindings[1][field] = reused
    if field == "body_instance_id":
        payload["body_states"][1]["body_instance_id"] = reused
    elif field == "election_attempt_id":
        bindings[1]["sortition_request"]["body_election_attempt_id"] = reused
    else:
        bindings[1]["sortition_request"]["id"] = reused
    session = RecordingSession()
    session.queue(_json_response(payload))
    with pytest.raises(ValueError, match=f"certificate.body_bindings reuses {field}"):
        ToriiClient("https://node.test", session=session).get_parliament_attempt_v1(
            ATTEMPT_ID, canonical_auth=_auth()
        )


def test_attempt_certificate_binds_certification_to_the_latest_body_result_height() -> None:
    early = _certificate_attempt_read()
    early["certificate"]["certified_at_height"] = 25
    late = _certificate_attempt_read()
    late["certificate"]["certified_at_height"] = 27

    for payload, message in (
        (early, "result_height follows certificate finalization"),
        (late, "must equal the latest body result height"),
    ):
        session = RecordingSession()
        session.queue(_json_response(payload))
        with pytest.raises(ValueError, match=message):
            ToriiClient("https://node.test", session=session).get_parliament_attempt_v1(
                ATTEMPT_ID, canonical_auth=_auth()
            )


def test_attempt_certificate_rejects_forged_repeated_and_sortition_bindings() -> None:
    mutations = (
        (
            lambda payload: payload["certificate"].__setitem__(
                "proposal_content_id", "ab" * 32
            ),
            "proposal_content_id differs",
        ),
        (
            lambda payload: payload["certificate"].__setitem__(
                "governance_attempt_sequence", 1
            ),
            "governance_attempt_sequence differs",
        ),
        (
            lambda payload: payload["certificate"].__setitem__(
                "risk_tier", {"tier": "Emergency"}
            ),
            "risk_tier differs",
        ),
        (
            lambda payload: payload["certificate"].__setitem__("policy_version", 2),
            "policy_version is not first-release",
        ),
        (
            lambda payload: payload["certificate"].__setitem__("enact_at_height", 25),
            "must follow certified_at_height",
        ),
        (
            lambda payload: payload["certificate"]["body_bindings"][0][
                "sortition_request"
            ].__setitem__("beacon_session_id", "bc" * 32),
            "sortition_request differs from its binding indexes",
        ),
        (
            lambda payload: payload["certificate"]["body_bindings"][0][
                "sortition_request"
            ].__setitem__("request_height", 0),
            "request_height",
        ),
        (
            lambda payload: payload["certificate"]["body_bindings"][0][
                "sortition_request"
            ].__setitem__("candidate_count", 0),
            "candidate_count",
        ),
    )
    canonical = _certificate_attempt_read()
    for mutate, message in mutations:
        forged = copy.deepcopy(canonical)
        mutate(forged)
        session = RecordingSession()
        session.queue(_json_response(forged))
        with pytest.raises((TypeError, ValueError), match=message):
            ToriiClient(
                "https://node.test", session=session
            ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())


def test_attempt_certificate_pins_policy_retry_seat_and_present_head_bounds() -> None:
    unsupported_projection = _attempt_read()
    unsupported_projection["policy_version"] = 2
    unsupported_session = RecordingSession()
    unsupported_session.queue(_json_response(unsupported_projection))
    with pytest.raises(TypeError, match="policy_version is not first-release"):
        ToriiClient(
            "https://node.test", session=unsupported_session
        ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())

    mutations = (
        (
            lambda payload: payload["certificate"].__setitem__(
                "expected_head",
                {
                    "state": "Present",
                    "head": {
                        "subject_id": [0x37] * 32,
                        "version": 0,
                        "head_root": [0x38] * 32,
                    },
                },
            ),
            "head.version",
        ),
        (
            lambda payload: payload["attempt"].__setitem__("sequence", 17),
            "attempt.sequence",
        ),
        (
            lambda payload: payload["certificate"]["body_bindings"][0].__setitem__(
                "election_attempt_sequence", 17
            ),
            "election_attempt_sequence",
        ),
        (
            lambda payload: payload["certificate"]["body_bindings"][0].__setitem__(
                "original_seats", 2
            ),
            "original_seats exceeds its sortition bounds",
        ),
    )
    for mutate, message in mutations:
        malformed = _certificate_attempt_read()
        mutate(malformed)
        session = RecordingSession()
        session.queue(_json_response(malformed))
        with pytest.raises((TypeError, ValueError), match=message):
            ToriiClient(
                "https://node.test", session=session
            ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())


def test_attempt_certificate_allows_nonzero_u32_candidate_count_above_the_seat_cap() -> None:
    payload = _certificate_attempt_read()
    payload["certificate"]["body_bindings"][0]["sortition_request"][
        "candidate_count"
    ] = 1_001
    session = RecordingSession()
    session.queue(_json_response(payload))
    parsed = ToriiClient(
        "https://node.test", session=session
    ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())
    assert (
        parsed.raw["certificate"]["body_bindings"][0]["sortition_request"][
            "candidate_count"
        ]
        == 1_001
    )


def test_attempt_read_rejects_decision_mode_that_differs_from_the_body_protocol() -> None:
    public_with_ballot_mode = _attempt_read()
    public_with_ballot_mode["required_bodies"][0]["decision_mode"] = {
        "mode": "HiddenBindingBallot"
    }
    private_with_public_mode = _attempt_read()
    private_with_public_mode["required_bodies"][0] = {
        "body": "policy-jury",
        "decision_mode": {"mode": "PublicFinding"},
    }
    private_with_public_mode["body_states"][0]["body"] = "policy-jury"

    for payload in (public_with_ballot_mode, private_with_public_mode):
        session = RecordingSession()
        session.queue(_json_response(payload))
        with pytest.raises(ValueError, match="differs from the body protocol"):
            ToriiClient("https://node.test", session=session).get_parliament_attempt_v1(
                ATTEMPT_ID, canonical_auth=_auth()
            )


def test_attempt_read_projects_private_bodies_without_a_certificate() -> None:
    payload = _attempt_read()
    payload["required_bodies"] = [
        {"body": "policy-jury", "decision_mode": {"mode": "HiddenBindingBallot"}}
    ]
    state = payload["body_states"][0]
    state["body"] = "policy-jury"
    state["body_instance_id"] = BODY_ID
    state["status"] = {"status": "Balloting"}
    session = RecordingSession()
    session.queue(_json_response(payload))
    parsed = ToriiClient(
        "https://node.test", session=session
    ).get_parliament_attempt_v1(ATTEMPT_ID, canonical_auth=_auth())
    assert parsed.raw["body_states"][0]["status"] == {"status": "Balloting"}
    assert parsed.raw["certificate"] is None


def test_ambient_credentials_and_nonidentity_responses_fail_closed() -> None:
    ambient = RecordingSession()
    ambient.auth = ("ambient", "credential")
    with pytest.raises(ValueError, match="Session.auth credential fallback"):
        ToriiClient(
            "https://node.test", session=ambient
        ).get_governance_capabilities_v1(canonical_auth=_auth())
    assert ambient.calls == []

    encoded = RecordingSession()
    encoded.queue(
        StubResponse(
            200,
            _capabilities(),
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
    )
    with pytest.raises(TypeError, match="must not use content encoding"):
        ToriiClient(
            "https://node.test", session=encoded
        ).get_governance_capabilities_v1(canonical_auth=_auth())


def test_environment_netrc_cannot_add_ambient_authorization(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        requests.sessions,
        "get_netrc_auth",
        lambda _url: ("ambient-user", "ambient-password"),
    )
    session = RecordingSession()
    session.trust_env = True
    session.queue(_json_response(_capabilities()))
    ToriiClient(
        "https://node.test", session=session
    ).get_governance_capabilities_v1(canonical_auth=_auth())
    assert "Authorization" not in session.calls[0]["headers"]


def test_ambient_environment_proxy_is_rejected_before_dispatch(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(
        requests.sessions,
        "get_environ_proxies",
        lambda _url, **_kwargs: {
            "https": "https://ambient-proxy.test:8443"
        },
    )
    session = RecordingSession()
    session.trust_env = True

    with pytest.raises(ValueError, match="ambient environment proxies"):
        ToriiClient(
            "https://node.test", session=session
        ).get_governance_capabilities_v1(canonical_auth=_auth())

    assert session.calls == []


def test_environment_proxy_authentication_is_rejected_before_dispatch(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(
        requests.sessions,
        "get_environ_proxies",
        lambda _url, **_kwargs: {
            "https": "https://ambient-user:ambient-password@ambient-proxy.test:8443"
        },
    )
    session = RecordingSession()
    session.trust_env = True

    with pytest.raises(ValueError, match="proxy authentication"):
        ToriiClient(
            "https://node.test", session=session
        ).get_governance_capabilities_v1(canonical_auth=_auth())

    assert session.calls == []


def test_explicit_proxy_authentication_is_rejected_before_dispatch() -> None:
    session = RecordingSession()
    session.proxies["https"] = (
        "https://explicit-user:explicit-password@explicit-proxy.test:8443"
    )

    with pytest.raises(ValueError, match="proxy authentication"):
        ToriiClient(
            "https://node.test", session=session
        ).get_governance_capabilities_v1(canonical_auth=_auth())

    assert session.calls == []


def test_environment_ca_bundle_is_not_merged(monkeypatch: Any) -> None:
    class TransportRecordingSession(RecordingSession):
        send_settings: dict[str, Any]

        def send(
            self,
            request: requests.PreparedRequest,
            **kwargs: Any,
        ) -> requests.Response:
            self.send_settings = dict(kwargs)
            return super().send(request, **kwargs)

    monkeypatch.setattr(
        requests.sessions,
        "get_environ_proxies",
        lambda _url, **_kwargs: {},
    )
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/ambient/ca-bundle.pem")
    session = TransportRecordingSession()
    session.trust_env = True
    session.queue(_json_response(_capabilities()))

    ToriiClient(
        "https://node.test", session=session
    ).get_governance_capabilities_v1(canonical_auth=_auth())

    assert session.send_settings["proxies"] == {}
    assert session.send_settings["verify"] is True
    assert session.send_settings["cert"] is None
    assert "Proxy-Authorization" not in session.calls[0]["headers"]


def test_json_media_parameters_and_integer_tokens_are_strict() -> None:
    media = RecordingSession()
    media.queue(
        StubResponse(
            200,
            _capabilities(),
            headers={"Content-Type": "application/json; boundary=not-json"},
        )
    )
    with pytest.raises(TypeError, match="UTF-8 application/json"):
        ToriiClient(
            "https://node.test", session=media
        ).get_governance_capabilities_v1(canonical_auth=_auth())

    floating = RecordingSession()
    floating.queue(
        StubResponse(
            200,
            raw=b'{"version":1.0}',
            headers={"Content-Type": "application/json"},
        )
    )
    with pytest.raises(ValueError, match="must not contain floating-point numbers"):
        ToriiClient(
            "https://node.test", session=floating
        ).get_governance_capabilities_v1(canonical_auth=_auth())

    boolean_version = _capabilities()
    boolean_version["version"] = True
    boolean = RecordingSession()
    boolean.queue(_json_response(boolean_version))
    with pytest.raises(TypeError, match="version must be an integer"):
        ToriiClient(
            "https://node.test", session=boolean
        ).get_governance_capabilities_v1(canonical_auth=_auth())


def test_capabilities_reject_unsupported_data_model_version() -> None:
    payload = _capabilities()
    payload["data_model_version"] = "5"
    session = RecordingSession()
    session.queue(_json_response(payload))
    with pytest.raises(TypeError, match="unsupported data-model version"):
        ToriiClient(
            "https://node.test", session=session
        ).get_governance_capabilities_v1(canonical_auth=_auth())


@pytest.mark.parametrize("field", sorted(_capabilities()))
def test_capabilities_require_every_published_field(field: str) -> None:
    payload = _capabilities()
    del payload[field]
    session = RecordingSession()
    session.queue(_json_response(payload))
    with pytest.raises(TypeError, match=f"missing required field `{field}`"):
        ToriiClient(
            "https://node.test", session=session
        ).get_governance_capabilities_v1(canonical_auth=_auth())


def test_capabilities_reject_fields_outside_the_published_contract() -> None:
    payload = _capabilities()
    payload["unexpected_field"] = True
    session = RecordingSession()
    session.queue(_json_response(payload))
    with pytest.raises(TypeError, match="contains unknown field `unexpected_field`"):
        ToriiClient(
            "https://node.test", session=session
        ).get_governance_capabilities_v1(canonical_auth=_auth())


@pytest.mark.parametrize("route", sorted(parliament_api_module._PARLIAMENT_ROUTES_V1))
def test_capabilities_require_every_canonical_parliament_route(route: str) -> None:
    payload = _capabilities()
    payload["supported_routes"].remove(route)
    session = RecordingSession()
    session.queue(_json_response(payload))
    with pytest.raises(ValueError, match="does not advertise every canonical Parliament route"):
        ToriiClient(
            "https://node.test", session=session
        ).get_governance_capabilities_v1(canonical_auth=_auth())


def test_capabilities_admit_the_complete_server_route_list() -> None:
    session = RecordingSession()
    session.queue(_json_response(_capabilities()))
    parsed = ToriiClient(
        "https://node.test", session=session
    ).get_governance_capabilities_v1(canonical_auth=_auth())
    assert parsed.supported_routes == tuple(SERVER_SUPPORTED_ROUTES)
    assert parsed.target_body_sizes.policy_jury == 4


@pytest.mark.parametrize(
    "retired_kind",
    [
        "KAGEMUSHA_VERIFIER_POLICY_INSTALL",
        "KAGEMUSHA_VERIFIER_RELEASE_INSTALL",
        "KAGEMUSHA_VERIFIER_RELEASE_ACTIVATE",
        "KAGEMUSHA_VERIFIER_RELEASE_RETIRE",
    ],
)
def test_capabilities_reject_retired_kagemusha_proposal_kinds(
    retired_kind: str,
) -> None:
    payload = _capabilities()
    assert len(payload["supported_proposal_kinds"]) == 10
    assert retired_kind not in payload["supported_proposal_kinds"]
    payload["supported_proposal_kinds"].append(retired_kind)
    session = RecordingSession()
    session.queue(_json_response(payload))
    with pytest.raises(ValueError, match="exact first-release set"):
        ToriiClient(
            "https://node.test", session=session
        ).get_governance_capabilities_v1(canonical_auth=_auth())
