"""Selected-account-context regressions against the required real native extension."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from iroha_python import (Ed25519KeyPair, Instruction, LocalSigningContext, NetworkId,
    ToriiClient, TransactionConfig, TransactionDraft)
from iroha_python.crypto import (TransactionBuilder, SignedTransactionEnvelope,
    build_signed_transaction, signed_transaction_envelope_from_json,
    signed_transaction_envelope_from_versioned_v1, verify_prepared_transaction_context_v1)
from iroha_python.tx import sponsor_fee_payment

NETWORK = NetworkId.from_bytes(bytes([0xA5]) * 32)
PREFIXES = (117, 369, 753)
KEY = Ed25519KeyPair.from_private_key(bytes([0x51]) * 32)
SPONSOR_KEY = Ed25519KeyPair.from_private_key(bytes([0x52]) * 32)

def account(prefix: int) -> str:
    return KEY.account_id(discriminant=prefix)

def fee(prefix: int, *, maximum: str = "1") -> dict:
    return dict(sponsor_fee_payment(
        f"{SPONSOR_KEY.account_id(discriminant=prefix)}/retail", 1,
        charge_limits=[{"kind": "nexus", "asset_definition_id": "66owaQmAQMuHxPzxUN3bqZ6FJfDa", "max_amount": maximum}],
        gas_limit=100,
    ))

def config(prefix: int) -> TransactionConfig:
    return TransactionConfig(network_id=NETWORK, authority=account(prefix),
        fee_payment=fee(prefix), chain_discriminant=prefix, creation_time_ms=42, ttl_ms=30000, nonce=7)

def typed_instruction(prefix: int) -> str:
    return json.dumps({"name": "SetAssetHoldingLimit", "params": {
        "account_id": account(prefix), "asset_definition_id": "66owaQmAQMuHxPzxUN3bqZ6FJfDa", "holding_limit": "100"}})

@pytest.mark.parametrize("prefix", PREFIXES)
def test_selected_prefix_roundtrips_real_native_envelopes_without_wire_rewrite(prefix: int) -> None:
    draft = TransactionDraft(config(prefix))
    instruction = Instruction.from_json(typed_instruction(prefix), chain_discriminant=prefix)
    draft.add_instruction(instruction)
    builder = draft.to_builder()
    payload = json.loads(builder.payload_json())
    assert payload["authority"] == account(prefix)
    assert payload["fee_payment"]["value"]["program_id"]["sponsor"] == SPONSOR_KEY.account_id(discriminant=prefix)
    signed = draft.sign(KEY.private_key)
    imported = signed_transaction_envelope_from_json(signed.to_json(), chain_discriminant=prefix)
    rebuilt = signed_transaction_envelope_from_versioned_v1(signed.signed_transaction_versioned, NETWORK, chain_discriminant=prefix)
    assert imported.authority == rebuilt.authority == signed.authority == account(prefix)
    assert imported.signed_transaction_versioned == rebuilt.signed_transaction_versioned == signed.signed_transaction_versioned
    other_draft = TransactionDraft(config(753))
    other_draft.add_instruction(Instruction.from_norito_bytes(instruction.to_norito_bytes()))
    other = other_draft.sign(KEY.private_key)
    assert other.signed_transaction_versioned == signed.signed_transaction_versioned
    for foreign in set(PREFIXES) - {prefix}:
        with pytest.raises(ValueError):
            SignedTransactionEnvelope.from_json(signed.to_json(), chain_discriminant=foreign)

@pytest.mark.parametrize("prefix", PREFIXES)
def test_quote_only_updates_maxima_and_failure_retains_selected_draft(prefix: int) -> None:
    builder = TransactionDraft(config(prefix)).to_builder()
    builder.add_instruction_json(typed_instruction(prefix))
    original = builder.payload_json()
    for foreign in set(PREFIXES) - {prefix}:
        with pytest.raises(ValueError): builder.set_fee_payment_json(json.dumps(fee(foreign)))
        with pytest.raises(ValueError): builder.add_instruction_json(typed_instruction(foreign))
        with pytest.raises(ValueError): builder.sign_quoted_payload(original, json.dumps(fee(foreign)), KEY.private_key)
        assert builder.payload_json() == original
    signed = builder.sign_quoted_payload(original, json.dumps(fee(prefix, maximum="2")), KEY.private_key)
    assert signed.authority == account(prefix)
    # A successful sign clears executable state but retains independently selected context.
    builder.add_instruction_json(typed_instruction(prefix))
    assert json.loads(builder.payload_json())["authority"] == account(prefix)

class IntSubclass(int):
    pass

@pytest.mark.parametrize("bad", [True, False, -1, 65536, 369.0, "369", None, IntSubclass(369)])
def test_native_and_python_boundaries_reject_non_exact_u16_context(bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        TransactionBuilder(NETWORK, account(369), json.dumps(fee(369)), chain_discriminant=bad)
    with pytest.raises((TypeError, ValueError)):
        TransactionConfig(network_id=NETWORK, authority=account(369), fee_payment=fee(369), chain_discriminant=bad)
    with pytest.raises((TypeError, ValueError)):
        Instruction.from_json(typed_instruction(369), chain_discriminant=bad)
    with pytest.raises((TypeError, ValueError)):
        build_signed_transaction(NETWORK, account(369), KEY.private_key, fee_payment=fee(369), chain_discriminant=bad)

def test_omitted_context_never_implicitly_selects_753() -> None:
    with pytest.raises(TypeError): TransactionBuilder(NETWORK, account(753), json.dumps(fee(753)))
    with pytest.raises(TypeError): TransactionConfig(network_id=NETWORK, authority=account(753), fee_payment=fee(753))
    with pytest.raises(TypeError): Instruction.from_json(typed_instruction(753))
    client = ToriiClient("https://example.invalid", local_signing_context=LocalSigningContext(NETWORK))
    with pytest.raises(ValueError, match="explicit.*chain_discriminant"):
        client._transaction_draft(authority=account(753), fee_payment=fee(753))
    client.close()

@pytest.mark.parametrize("prefix", PREFIXES)
def test_client_preserves_selected_literals_and_refuses_foreign_controller_presentation(prefix: int) -> None:
    client = ToriiClient("https://example.invalid", chain_discriminant=prefix,
        local_signing_context=LocalSigningContext(NETWORK))
    draft = client._transaction_draft(authority=account(prefix), fee_payment=fee(prefix))
    assert draft.config.authority == account(prefix)
    assert draft.config.chain_discriminant == prefix
    asset = f"66owaQmAQMuHxPzxUN3bqZ6FJfDa#{account(prefix)}#dataspace:12"
    assert client._native_transaction_asset_id(asset, "asset") == asset
    for foreign in set(PREFIXES) - {prefix}:
        with pytest.raises(ValueError): client._transaction_draft(authority=account(foreign), fee_payment=fee(prefix))
        with pytest.raises(ValueError): client._native_transaction_asset_id(asset.replace(account(prefix), account(foreign)), "asset")
    client.close()

def test_fixed_prepared_receipts_cannot_reinterpret_signature_bound_account_strings() -> None:
    fixture = json.loads((Path(__file__).resolve().parents[3] / "fixtures/prepared_transactions/prepared_transaction_signature_v1.json").read_text())
    for vector in fixture["vectors"]:
        if vector["name"] == "onboarding_proof_required": continue
        prepared = vector["response"]
        operation = prepared["operation"]
        context = ({key: prepared[key] for key in ("receipt", "account_id", "alias", "disposition")}
            if operation == "onboarding" else {key: prepared[key] for key in ("claim", "account_id", "asset_definition_id", "asset_id", "amount")})
        args = (bytes.fromhex(prepared["signed_transaction_wire_hex"]), NetworkId.parse(vector["network_id"]),
            vector["signer_account_id"], json.dumps(prepared["binding"]), operation,
            prepared["semantic_hash_hex"], json.dumps(prepared["fee_payment"]), json.dumps(context))
        # These canonical fixtures were authored with prefix 753; do not rewrite signed strings.
        assert verify_prepared_transaction_context_v1(*args, chain_discriminant=753).hash_hex() == prepared["transaction_hash_hex"]
        for foreign in (117, 369):
            with pytest.raises(ValueError): verify_prepared_transaction_context_v1(*args, chain_discriminant=foreign)
