"""Canonical Python/Norito construction of choice-free public conviction updates."""

from __future__ import annotations

import base64
import inspect
import json
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest

from iroha_python import (
    Ed25519KeyPair,
    Instruction,
    NetworkId,
    TransactionConfig,
    TransactionDraft,
    authority_fee_payment,
)


def _owner(seed: int) -> str:
    return Ed25519KeyPair.from_private_key(bytes([seed]) * 32).account_id(
        discriminant=0x02F1,
    )


def _draft(owner: str) -> TransactionDraft:
    return TransactionDraft(
        TransactionConfig(
            network_id=NetworkId.from_bytes(bytes([0xA5]) * 32),
            authority=owner,
            fee_payment=authority_fee_payment(charge_limits=[]),
            creation_time_ms=42,
            chain_discriminant=753,
        )
    )


def test_update_plain_conviction_uses_exact_native_instruction_in_transaction() -> None:
    owner = _owner(0x47)
    expected = Instruction.update_plain_conviction("ref-1", owner, "2.5", 42)
    assert expected.wire_id() == "iroha.instruction.v1::governance::UpdatePlainConviction"
    assert Instruction.from_json(expected.to_json(), chain_discriminant=753).to_norito_bytes() == expected.to_norito_bytes()

    draft = _draft(owner)
    assert draft.update_plain_conviction("ref-1", owner, Decimal("2.500"), 42) is draft
    (actual,) = tuple(draft.instructions)
    assert actual.to_norito_bytes() == expected.to_norito_bytes()
    payload = json.loads(draft.to_builder().payload_json())
    assert payload["authority"] == owner


def test_update_plain_conviction_matches_rust_native_golden() -> None:
    root = Path(__file__).resolve().parents[3]
    fixture = json.loads(
        (root / "fixtures/governance/plain_v1/update_plain_conviction_instruction_v1.json")
        .read_text(encoding="utf-8")
    )
    inputs = fixture["inputs"]
    instruction = Instruction.update_plain_conviction(
        inputs["referendum_id"],
        inputs["owner"],
        inputs["amount"],
        inputs["duration_blocks"],
    )
    assert fixture["wire_id"] == instruction.wire_id()
    assert fixture["wire_id"] == "iroha.instruction.v1::governance::UpdatePlainConviction"
    boxed_frame = bytes(instruction.to_norito_bytes())
    assert boxed_frame.hex() == fixture["standalone_instruction_box_frame_hex"]
    assert bytes(Instruction.from_json(instruction.to_json(), chain_discriminant=753).to_norito_bytes()) == boxed_frame

    def payload(frame: bytes) -> bytes:
        assert frame[:6] == b"NRT0\x00\x00"
        assert frame[22] == 0
        declared = int.from_bytes(frame[23:31], "little")
        padding = len(frame) - 40 - declared
        assert padding >= 0
        assert frame[40 : 40 + padding] == bytes(padding)
        result = frame[40 + padding :]
        assert len(result) == declared
        return result

    pair = bytes.fromhex(fixture["instruction_box_pair_hex"])
    assert boxed_frame[39] == fixture["header_flags"]
    assert payload(boxed_frame) == pair
    concrete = bytes.fromhex(fixture["concrete_frame_hex"])
    assert fixture["concrete_schema_name"] == (
        "iroha_data_model::isi::governance::UpdatePlainConviction"
    )
    assert concrete[6:22].hex() == fixture["concrete_schema_hash"]
    assert concrete[39] == fixture["header_flags"]
    assert payload(concrete).hex() == fixture["bare_payload_hex"]
    assert len(concrete) == fixture["framed_instruction_len"]
    assert base64.b64encode(concrete).decode("ascii") == fixture["framed_instruction_base64"]
    assert pair.endswith(concrete), "registered pair retains the exact concrete native frame"
    assert fixture["wire_id"].encode("ascii") in pair

    draft = _draft(inputs["owner"])
    for alias in ("direction", "choice"):
        with pytest.raises(TypeError):
            cast(Any, Instruction.update_plain_conviction)(
                inputs["referendum_id"], inputs["owner"], inputs["amount"],
                inputs["duration_blocks"], **{alias: 1},
            )
        with pytest.raises(TypeError):
            cast(Any, draft.update_plain_conviction)(
                inputs["referendum_id"], inputs["owner"], inputs["amount"],
                inputs["duration_blocks"], **{alias: 1},
            )
    assert len(draft) == 0

def test_update_plain_conviction_has_no_choice_argument_or_extra_wire_field() -> None:
    owner = _owner(0x48)
    signature = inspect.signature(Instruction.update_plain_conviction)
    assert tuple(signature.parameters) == (
        "referendum_id",
        "owner",
        "amount",
        "duration_blocks",
    )
    direct = cast(Any, Instruction.update_plain_conviction)
    with pytest.raises(TypeError):
        direct("ref-1", owner, "2", 42, 0)
    with pytest.raises(TypeError):
        direct("ref-1", owner, "2", 42, direction=0)

    draft = _draft(owner)
    with pytest.raises(TypeError):
        cast(Any, draft.update_plain_conviction)("ref-1", owner, "2", 42, choice=1)
    assert len(draft) == 0


@pytest.mark.parametrize("bad_selector", ["", ".hidden", "space value", "x" * 129])
def test_update_plain_conviction_rejects_noncanonical_selector(bad_selector: str) -> None:
    owner = _owner(0x49)
    with pytest.raises(ValueError, match="governance selector"):
        Instruction.update_plain_conviction(bad_selector, owner, "2", 42)


@pytest.mark.parametrize("bad_amount", ["01", " 2", "1e0", "-1"])
def test_update_plain_conviction_rejects_noncanonical_or_negative_quantity(
    bad_amount: str,
) -> None:
    owner = _owner(0x4A)
    with pytest.raises(ValueError):
        Instruction.update_plain_conviction("ref-1", owner, bad_amount, 42)


def test_update_plain_conviction_rejects_wrong_owner_and_bad_duration_before_append() -> None:
    owner = _owner(0x4B)
    other = _owner(0x4C)
    draft = _draft(owner)
    with pytest.raises(ValueError, match="owner must equal the transaction authority"):
        draft.update_plain_conviction("ref-1", other, "2", 42)
    with pytest.raises(ValueError, match="canonical I105"):
        Instruction.update_plain_conviction("ref-1", "alice@example", "2", 42)
    for duration in (True, -1, 1 << 64, None):
        with pytest.raises((TypeError, ValueError)):
            cast(Any, draft.update_plain_conviction)("ref-1", owner, "2", duration)
    assert len(draft) == 0
