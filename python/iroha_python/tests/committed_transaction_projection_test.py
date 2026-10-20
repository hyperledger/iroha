"""Projection and transport units; native finality acceptance is tested in Rust.

The eight batch fields match batch_outcome_json in iroha_python_rs/src/lib.rs
and the actual paid/rejected batch in committed_transaction_verification_tests.rs.
These records test Python projection only; they are not fabricated proof evidence.
"""
from __future__ import annotations

import copy
import sys
import types

import pytest
from iroha_torii_client.errors import ToriiUnavailableError

from generic_transfer_escrow_contract_test import (
    FakeSession, NETWORK_ID, PURE_PACKAGE, ToriiClient,
    VerifiedCommittedTransaction, _norito_response, client_module, _route_projection,
)


def _batch_projection():
    # Controller labels stand in for already natively rendered account text.
    # This parser never establishes account identity or cryptographic authority.
    applied = {
        "leg_index": 0, "leg_id": "paid", "asset": "coin#sender",
        "destination": "recipient", "amount": "3", "status": "Applied",
        "rejection_code": None, "rejection_message": None,
    }
    rejected = {
        "leg_index": 1, "leg_id": "insufficient", "asset": "coin#sender",
        "destination": "recipient", "amount": "1000", "status": "Rejected",
        "rejection_code": "InsufficientFunds", "rejection_message": "insufficient funds",
    }
    return {
        "proof_kind": "selective-v1", "transaction_hash": "11" * 32,
        "block_hash": "23" * 32, "block_height": 3, "output_hash": "35" * 32,
        "network_id": "native-network-label", "context_id": "native-context-label",
        "promoted_checkpoint": b"unit-projection-checkpoint",
        "execution_commitment": {"executed_block_wire_len": 123},
        "execution_context": _route_projection(),
        "executed_block_wire_hash": "57" * 32, "executed_block_wire_len": 123,
        "entrypoint_kind": "External", "authority": "sender",
        "signer_public_key_hex": "44" * 32, "metadata": {},
        "executable": {"Instructions": []}, "result_ok": True,
        "rejection_code": None, "rejection_message": None,
        "contract_rejection": None, "ivm_fault": None,
        "batch_outcomes": [applied, rejected], "committed_transaction": {},
    }


def test_committed_batch_projection_matches_native_output_schema():
    payload = _batch_projection()
    original = copy.deepcopy(payload)
    result = VerifiedCommittedTransaction.from_payload(payload)
    assert result.proof_kind == "selective-v1"
    assert result.result_ok is True
    assert result.batch_outcomes == tuple(payload["batch_outcomes"])
    assert result.batch_outcomes[0]["status"] == "Applied"
    assert result.batch_outcomes[1]["rejection_code"] == "InsufficientFunds"
    assert payload == original
    assert all("proof_kind" not in leg for leg in result.batch_outcomes)


def test_committed_batch_projection_refuses_extra_missing_and_contradictory_fields():
    for index in (0, 1):
        for field in _batch_projection()["batch_outcomes"][index]:
            payload = _batch_projection()
            del payload["batch_outcomes"][index][field]
            with pytest.raises(ValueError, match="must contain exactly"):
                VerifiedCommittedTransaction.from_payload(payload)
        for extra in ("proof_kind", "unverified_hint"):
            payload = _batch_projection()
            payload["batch_outcomes"][index][extra] = "selective-v1"
            with pytest.raises(ValueError, match="must contain exactly"):
                VerifiedCommittedTransaction.from_payload(payload)
    for index, changes in (
        (0, {"rejection_code": "InsufficientFunds"}),
        (0, {"rejection_message": "unexpected"}),
        (1, {"rejection_code": None}),
        (1, {"rejection_message": None}),
        (0, {"status": "Unknown"}),
    ):
        payload = _batch_projection()
        payload["batch_outcomes"][index].update(changes)
        with pytest.raises((TypeError, ValueError)):
            VerifiedCommittedTransaction.from_payload(payload)
    payload = _batch_projection()
    del payload["proof_kind"]
    with pytest.raises(ValueError, match="must contain exactly"):
        VerifiedCommittedTransaction.from_payload(payload)


def test_verified_committed_query_does_not_replay_nonce_under_post_retry_policy(monkeypatch):
    # Stub only query construction and crypto result, so the actual HTTP dispatch
    # must respect once-only nonce custody even under a caller's POST retry policy.
    crypto = types.ModuleType(f"{PURE_PACKAGE}.crypto")
    queries = []
    verifications = []
    def build(authority, private_key, network, transaction_hash):
        queries.append((authority, network, transaction_hash))
        return b"unit-native-nonce-bearing-query"
    def verify(*args, **kwargs):
        verifications.append((args, kwargs))
        return _batch_projection()
    crypto.build_find_committed_transaction_query = build
    crypto.verify_committed_transaction_inclusion = verify
    monkeypatch.setitem(sys.modules, f"{PURE_PACKAGE}.crypto", crypto)
    monkeypatch.setattr(client_module, "_normalize_network_id", lambda value, _context: value)
    monkeypatch.setattr(ToriiClient, "_native_transaction_account_id", lambda self, value, _context: value)
    deferred = _norito_response(b"capacity", status=503)
    unused = _norito_response(b"query-response", status=200)
    # requests.Response.close must work if the uncorrected client attempts retry.
    deferred._content_consumed = unused._content_consumed = True
    session = FakeSession([deferred, unused])
    client = ToriiClient("https://torii.example", session=session,
        chain_discriminant=369, max_retries=1, retry_on_methods=["POST"],
        retry_on_status=[503], backoff_initial=0.001, backoff_max=0.001)
    try:
        with pytest.raises(ToriiUnavailableError) as refused:
            client.get_verified_committed_transaction(
                transaction_hash="11" * 32, authority="reader", network_id=NETWORK_ID,
                native_finality_proof_chain_json="[unit-proof]", expected_chain="unit-chain",
                trusted_checkpoint=b"unit-checkpoint", private_key=b"\x44" * 32,
            )
        assert refused.value.status == 503
        assert queries == [("reader", NETWORK_ID, "11" * 32)]
        assert len(session.calls) == 1
        assert session.calls[0]["allow_redirects"] is False
        assert session.calls[0]["url"] == "https://torii.example/v1/query"
        assert session.calls[0]["data"] == b"unit-native-nonce-bearing-query"
        assert session.responses == [unused]
        assert verifications == []
    finally:
        client.close()


def test_original_route_preserves_all_legs_without_inferring_lane_zero():
    payload = _batch_projection()
    result = VerifiedCommittedTransaction.from_payload(payload)
    route = result.execution_context["route"]
    assert result.execution_context == payload["execution_context"]
    assert result.execution_context["input_index"] == 1
    assert route["dataspace_id"] == 0
    assert route["lane_id"] == 7
    assert [leg["lane_id"] for leg in route["routing_plan_legs"]] == [7, 9]
    payload["execution_context"]["route"]["routing_plan_legs"][0]["role"]["role"] = "participant"
    assert route["routing_plan_legs"][0]["role"]["role"] == "coordinator"


@pytest.mark.parametrize("path,value", [
    (("bundle_version",), True), (("bundle_version",), 0), (("bundle_version",), 2),
    (("input_index",), True), (("input_index",), -1), (("input_index",), 2 ** 32),
    (("route", "entrypoint_hash"), None),
    (("route", "entrypoint_hash"), _route_projection("33" * 32)["route"]["entrypoint_hash"]),
    (("route", "routing_plan_digest"), None),
    (("route", "routing_plan_digest"), "57" * 32),
    (("route", "lane_id"), True), (("route", "lane_id"), 2 ** 32),
    (("route", "dataspace_id"), -1), (("route", "dataspace_id"), 2 ** 64),
    (("route", "routing_plan_legs"), ()),
    (("route", "routing_plan_legs", 1, "lane_id"), -1),
    (("route", "routing_plan_legs", 1, "dataspace_id"), False),
    (("route", "routing_plan_legs", 1, "role", "role"), "unknown"),
    (("route", "routing_plan_legs", 1, "role", "detail"), {}),
])
def test_original_route_refuses_wrong_types_versions_hashes_and_roles(path, value):
    payload = _batch_projection()
    cursor = payload["execution_context"]
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value
    with pytest.raises((TypeError, ValueError)):
        VerifiedCommittedTransaction.from_payload(payload)


def test_original_route_refuses_missing_and_extra_fields_at_every_level():
    for path in (
        (), ("route",), ("route", "routing_plan_legs", 0),
        ("route", "routing_plan_legs", 0, "role"),
    ):
        baseline = _batch_projection()["execution_context"]
        for part in path:
            baseline = baseline[part]
        for field in (*baseline, "extra"):
            payload = _batch_projection()
            cursor = payload["execution_context"]
            for part in path:
                cursor = cursor[part]
            if field == "extra":
                cursor[field] = None
            else:
                del cursor[field]
            with pytest.raises((TypeError, ValueError)):
                VerifiedCommittedTransaction.from_payload(payload)
    payload = _batch_projection()
    del payload["execution_context"]
    with pytest.raises(ValueError):
        VerifiedCommittedTransaction.from_payload(payload)
