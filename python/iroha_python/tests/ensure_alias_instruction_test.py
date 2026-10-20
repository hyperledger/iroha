"""Exact alias construction through the required native SDK binding."""
from __future__ import annotations

import json

import pytest

from iroha_python import Ed25519KeyPair, Instruction


def _documents(prefix: int = 369) -> tuple[str, str, str]:
    key = Ed25519KeyPair.from_private_key(bytes([0x71]) * 32)
    return tuple(json.dumps(value) for value in (
        {
            "kind": "account_alias",
            "intent": {
                "alias": {
                    "canonical_name": {
                        "label": "owner", "domain": "app", "dataspace": "universal",
                    },
                    "dataspace_id": 0,
                },
                "target_account": key.account_id(discriminant=prefix),
                "provision": {"kind": "create", "value": None},
                "role": {"kind": "primary", "value": None},
            },
        },
        {"term_years": 1, "pricing_class_hint": None},
        {
            "expected_policy_version": 1,
            "expected_payment_asset": "4rPeAP6jAjiLVZThZYwwPRBuQagt",
            "max_amount": "10",
            "valid_until_ms": 4_102_444_800_000,
        },
    ))


@pytest.mark.parametrize("prefix", [117, 369, 753])
def test_ensure_alias_native_binding_selects_only_alias_and_preserves_wire(prefix: int) -> None:
    instruction = Instruction.ensure_alias(*_documents(prefix), chain_discriminant=prefix)
    assert instruction.wire_id() == "iroha.alias.ensure"
    assert instruction.to_norito_bytes() == Instruction.ensure_alias(
        *_documents(369), chain_discriminant=369,
    ).to_norito_bytes()
    for foreign in {117, 369, 753} - {prefix}:
        with pytest.raises(ValueError):
            Instruction.ensure_alias(*_documents(prefix), chain_discriminant=foreign)


class _IntSubclass(int):
    pass


@pytest.mark.parametrize("bad", [True, False, -1, 65536, 369.0, "369", None, _IntSubclass(369)])
def test_ensure_alias_native_binding_requires_exact_u16_context(bad: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        Instruction.ensure_alias(*_documents(), chain_discriminant=bad)


def test_ensure_alias_native_binding_requires_keyword_context() -> None:
    with pytest.raises(TypeError):
        Instruction.ensure_alias(*_documents())
    with pytest.raises(TypeError):
        Instruction.ensure_alias(*_documents(), 369)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_ensure_alias_native_binding_requires_each_typed_json_document(index: int) -> None:
    documents = list(_documents())
    documents[index] = json.dumps({"wire_id": "iroha.transfer", "framed_payload": "00"})
    with pytest.raises(ValueError):
        Instruction.ensure_alias(*documents, chain_discriminant=369)
