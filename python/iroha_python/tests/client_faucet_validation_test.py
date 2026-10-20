"""Prepared faucet recovery authenticates original signed wire without dispatch."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import requests

import iroha_python.client as client_module
from iroha_python import NetworkId, ToriiClient, authority_fee_payment


class NoDispatchSession(requests.Session):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def request(self, *args: object, **kwargs: object) -> requests.Response:
        self.calls += 1
        raise AssertionError("faucet validation must not dispatch HTTP")


@pytest.fixture
def faucet_case():
    path = (
        Path(__file__).resolve().parents[3]
        / "fixtures/prepared_transactions/prepared_transaction_signature_v1.json"
    )
    vector = next(
        item for item in json.loads(path.read_text(encoding="utf-8"))["vectors"]
        if item["name"] == "faucet_prepared"
    )
    prepared = copy.deepcopy(vector["response"])
    pins = {
        "expected_fee_payment": copy.deepcopy(prepared["fee_payment"]),
        "expected_asset_definition_id": prepared["asset_definition_id"],
        "expected_amount": prepared["amount"],
        "expected_authority": vector["signer_account_id"],
        "network_id": NetworkId.parse(vector["network_id"]),
    }
    session = NoDispatchSession()
    return ToriiClient("https://torii.example", session=session, chain_discriminant=753), session, prepared, pins


def test_faucet_validation_authenticates_golden_without_dispatch(
    faucet_case, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session, prepared, pins = faucet_case
    expiry = prepared["binding"]["execution_expires_at_unix_ms"]
    monkeypatch.setattr(client_module.time, "time_ns", lambda: (expiry - 1) * 1_000_000)
    original = copy.deepcopy(prepared)

    authenticated = client.validate_prepared_account_faucet(prepared, **pins)

    assert authenticated == original
    assert authenticated is not prepared
    assert authenticated["binding"] is not prepared["binding"]
    assert authenticated["claim"] is not prepared["claim"]
    assert json.dumps(authenticated, allow_nan=False, separators=(",", ":")).encode() == (
        json.dumps(original, allow_nan=False, separators=(",", ":")).encode()
    )
    authenticated["binding"]["request_id"] = "00" * 32
    assert prepared == original
    assert session.calls == 0


def test_expired_faucet_can_only_be_authenticated_for_recovery(
    faucet_case, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session, prepared, pins = faucet_case
    expiry = prepared["binding"]["execution_expires_at_unix_ms"]
    monkeypatch.setattr(client_module.time, "time_ns", lambda: expiry * 1_000_000)

    with pytest.raises(ValueError, match="expired"):
        client.validate_prepared_account_faucet(prepared, **pins)
    recovered = client.validate_prepared_account_faucet(
        prepared, **pins, allow_expired_for_recovery=True,
    )
    assert recovered == prepared
    with pytest.raises(ValueError, match="expired"):
        client.submit_prepared_account_faucet(recovered, **pins)
    assert session.calls == 0


@pytest.mark.parametrize("invalid", [None, 1, 0, "true"])
def test_faucet_recovery_requires_explicit_boolean(faucet_case, invalid: object) -> None:
    client, session, prepared, pins = faucet_case
    with pytest.raises(TypeError, match="must be a bool"):
        client.validate_prepared_account_faucet(
            prepared, **pins, allow_expired_for_recovery=invalid,
        )
    assert session.calls == 0


@pytest.mark.parametrize("mutation", [
    "network", "authority", "wire", "wire_sha256", "transaction_hash", "signature",
    "fee", "asset", "amount", "binding", "claim", "account", "extra_field",
])
def test_faucet_recovery_preserves_all_authentication_checks(faucet_case, mutation: str) -> None:
    client, session, prepared, pins = faucet_case
    if mutation == "network":
        pins["network_id"] = NetworkId.from_bytes(bytes([0x77]) * 32)
    elif mutation == "authority":
        assert pins["expected_authority"] != prepared["account_id"]
        pins["expected_authority"] = prepared["account_id"]
    elif mutation == "wire":
        wire = bytearray.fromhex(prepared["signed_transaction_wire_hex"])
        wire[-1] ^= 1
        prepared["signed_transaction_wire_hex"] = wire.hex()
    elif mutation == "wire_sha256":
        prepared["signed_transaction_wire_sha256"] = "00" * 32
    elif mutation == "transaction_hash":
        prepared["transaction_hash_hex"] = "67" * 32
    elif mutation == "signature":
        signature = bytearray.fromhex(prepared["server_signature"])
        signature[0] ^= 1
        prepared["server_signature"] = signature.hex().upper()
    elif mutation == "fee":
        pins["expected_fee_payment"] = authority_fee_payment(charge_limits=[], gas_limit=1)
    elif mutation == "asset":
        pins["expected_asset_definition_id"] = "61CtjvNd9T3THAR65GsMVHr82Bjc"
    elif mutation == "amount":
        pins["expected_amount"] = "999"
    elif mutation == "binding":
        prepared["binding"]["request_id"] = "00" * 32
    elif mutation == "claim":
        prepared["claim"]["pow_nonce_hex"] = "0001"
    elif mutation == "account":
        prepared["account_id"] = pins["expected_authority"]
    elif mutation == "extra_field":
        prepared["untrusted"] = True

    with pytest.raises((TypeError, ValueError)):
        client.validate_prepared_account_faucet(
            prepared, **pins, allow_expired_for_recovery=True,
        )
    assert session.calls == 0


def test_submit_still_authenticates_before_dispatch(
    faucet_case, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session, prepared, pins = faucet_case
    expiry = prepared["binding"]["execution_expires_at_unix_ms"]
    monkeypatch.setattr(client_module.time, "time_ns", lambda: (expiry - 1) * 1_000_000)
    signature = bytearray.fromhex(prepared["server_signature"])
    signature[0] ^= 1
    prepared["server_signature"] = signature.hex().upper()
    with pytest.raises(ValueError, match="server signature is invalid"):
        client.submit_prepared_account_faucet(prepared, **pins)
    assert session.calls == 0
