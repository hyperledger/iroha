"""Tests for the exact governed-contract lifecycle response projection."""

from __future__ import annotations

import copy

import pytest

from iroha_python.client import GovernanceContractRecord

CONTRACT_ADDRESS = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
OWNER = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"


def active_response() -> dict[str, object]:
    """Return one exact active governed-contract response."""

    return {
        "found": True,
        "contract_address": CONTRACT_ADDRESS,
        "contract_subject_account": OWNER,
        "dataspace": "universal",
        "active": True,
        "lifecycle": {
            "version": 1,
            "origin": "direct",
            "origin_account": OWNER,
            "origin_proposal_content_id_hex": None,
            "origin_governance_attempt_id_hex": None,
            "owner": OWNER,
            "pending_owner": "parliament",
            "parliament_delegated": True,
            "active_code_hash_hex": "22" * 32,
            "retained_code_hash_hex": "22" * 32,
            "revision": 7,
            "emergency_hold": None,
        },
        "emergency_hold_active": False,
        "code_hash_hex": "22" * 32,
        "abi_hash_hex": "33" * 32,
        "public_entrypoints": ["transfer", "view_balance"],
    }


def test_governance_contract_record_parses_active_and_absent_shapes() -> None:
    active = GovernanceContractRecord.from_payload(active_response())
    assert active.active is True
    assert active.lifecycle is not None
    assert active.lifecycle.version == 1
    assert active.lifecycle.revision == 7
    assert active.public_entrypoints == ("transfer", "view_balance")

    absent = GovernanceContractRecord.from_payload(
        {
            "found": False,
            "contract_address": CONTRACT_ADDRESS,
            "dataspace": "universal",
        }
    )
    assert absent.found is False
    assert absent.active is None
    assert absent.lifecycle is None


def test_governance_contract_record_parses_bounded_emergency_hold() -> None:
    payload = active_response()
    payload["emergency_hold_active"] = True
    payload["lifecycle"]["emergency_hold"] = {  # type: ignore[index]
        "incident_digest_hex": "44" * 32,
        "proposal_content_id_hex": "55" * 32,
        "governance_attempt_id_hex": "66" * 32,
        "reason": "containment",
        "imposed_at_height": 10,
        "expires_at_height": 20,
    }

    record = GovernanceContractRecord.from_payload(payload)

    assert record.lifecycle is not None
    assert record.lifecycle.emergency_hold is not None
    assert record.lifecycle.emergency_hold.imposed_at_height == 10
    assert record.lifecycle.emergency_hold.expires_at_height == 20


def test_governance_contract_record_rejects_cross_field_and_shape_drift() -> None:
    invalid = []
    mismatched = active_response()
    mismatched["lifecycle"]["active_code_hash_hex"] = "44" * 32  # type: ignore[index]
    invalid.append(mismatched)
    unsorted = active_response()
    unsorted["public_entrypoints"] = ["view_balance", "transfer"]
    invalid.append(unsorted)
    alias_owner = active_response()
    alias_owner["lifecycle"]["owner"] = "alice@universal"  # type: ignore[index]
    invalid.append(alias_owner)
    direct_with_parliament_ids = active_response()
    direct_with_parliament_ids["lifecycle"]["origin_proposal_content_id_hex"] = (  # type: ignore[index]
        "55" * 32
    )
    invalid.append(direct_with_parliament_ids)
    unsupported_version = active_response()
    unsupported_version["lifecycle"]["version"] = 2  # type: ignore[index]
    invalid.append(unsupported_version)
    zero_revision = active_response()
    zero_revision["lifecycle"]["revision"] = 0  # type: ignore[index]
    invalid.append(zero_revision)
    absent_with_extra = {
        "found": False,
        "contract_address": CONTRACT_ADDRESS,
        "dataspace": "universal",
        "active": None,
    }
    invalid.append(absent_with_extra)

    for payload in invalid:
        with pytest.raises((TypeError, ValueError)):
            GovernanceContractRecord.from_payload(copy.deepcopy(payload))


@pytest.mark.parametrize("value", [True, "7", 7.0, -1, 1 << 64])
def test_governance_contract_record_rejects_non_wire_revision(value: object) -> None:
    payload = active_response()
    payload["lifecycle"]["revision"] = value  # type: ignore[index]

    with pytest.raises((TypeError, ValueError), match="unsigned 64-bit integer"):
        GovernanceContractRecord.from_payload(payload)


@pytest.mark.parametrize("value", [True, "10", 10.0, -1, 1 << 64])
def test_governance_contract_record_rejects_non_wire_hold_heights(value: object) -> None:
    payload = active_response()
    payload["emergency_hold_active"] = True
    payload["lifecycle"]["emergency_hold"] = {  # type: ignore[index]
        "incident_digest_hex": "44" * 32,
        "proposal_content_id_hex": "55" * 32,
        "governance_attempt_id_hex": "66" * 32,
        "reason": "containment",
        "imposed_at_height": value,
        "expires_at_height": 20,
    }

    with pytest.raises((TypeError, ValueError), match="unsigned 64-bit integer"):
        GovernanceContractRecord.from_payload(payload)


def test_suspended_contract_preserves_required_schema_binding() -> None:
    payload = active_response()
    payload["active"] = False
    for field in ("code_hash_hex", "abi_hash_hex", "public_entrypoints"):
        del payload[field]
    payload["lifecycle"]["active_code_hash_hex"] = None
    record = GovernanceContractRecord.from_payload(payload)
    assert record.lifecycle.active_code_hash_hex is None
    assert record.lifecycle.retained_code_hash_hex == "22" * 32
    del payload["lifecycle"]["retained_code_hash_hex"]
    with pytest.raises(TypeError, match="lifecycle fields"):
        GovernanceContractRecord.from_payload(payload)
