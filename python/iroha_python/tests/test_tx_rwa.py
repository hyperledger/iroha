from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

import pytest

from iroha_python import NetworkId, tx

AUTHORITY = "soraゴヂアニヤナサヰイユヶサヲワニュスゥァヨワコモペバプボチョナソヒョニュニョムベイゴエホタフナナハカウセミカ"
DESTINATION = "soraゴヂアニィルサフユイサヹピビレッデヹボテハキョメベチュヒャネィギチュヲベァヱェベモネェネツデトツオチハセ"
RWA_ID = (
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities"
)


def _load_tx_module(monkeypatch):
    class FakeInstruction:
        calls: list[dict[str, Any]] = []

        def __init__(self, payload: dict[str, Any]) -> None:
            self._payload = payload

        @classmethod
        def _record(cls, method: str, payload: dict[str, Any]) -> "FakeInstruction":
            cls.calls.append({"method": method, "payload": payload})
            return cls(payload)

        @classmethod
        def register_rwa(cls, rwa: dict[str, Any]) -> "FakeInstruction":
            return cls._record("register_rwa", {"RegisterRwa": {"rwa": rwa}})

        @classmethod
        def transfer_rwa(
            cls,
            source: str,
            rwa_id: str,
            quantity: str,
            destination: str,
        ) -> "FakeInstruction":
            return cls._record(
                "transfer_rwa",
                {
                    "TransferRwa": {
                        "source": source,
                        "rwa": rwa_id,
                        "quantity": quantity,
                        "destination": destination,
                    }
                },
            )

        @classmethod
        def merge_rwas(cls, merge: dict[str, Any]) -> "FakeInstruction":
            return cls._record("merge_rwas", {"MergeRwas": merge})

        @classmethod
        def redeem_rwa(cls, rwa_id: str, quantity: str) -> "FakeInstruction":
            return cls._record(
                "redeem_rwa",
                {"RedeemRwa": {"rwa": rwa_id, "quantity": quantity}},
            )

        @classmethod
        def freeze_rwa(cls, rwa_id: str) -> "FakeInstruction":
            return cls._record("freeze_rwa", {"FreezeRwa": {"rwa": rwa_id}})

        @classmethod
        def unfreeze_rwa(cls, rwa_id: str) -> "FakeInstruction":
            return cls._record("unfreeze_rwa", {"UnfreezeRwa": {"rwa": rwa_id}})

        @classmethod
        def hold_rwa(cls, rwa_id: str, quantity: str) -> "FakeInstruction":
            return cls._record(
                "hold_rwa",
                {"HoldRwa": {"rwa": rwa_id, "quantity": quantity}},
            )

        @classmethod
        def release_rwa(cls, rwa_id: str, quantity: str) -> "FakeInstruction":
            return cls._record(
                "release_rwa",
                {"ReleaseRwa": {"rwa": rwa_id, "quantity": quantity}},
            )

        @classmethod
        def force_transfer_rwa(
            cls,
            rwa_id: str,
            quantity: str,
            destination: str,
        ) -> "FakeInstruction":
            return cls._record(
                "force_transfer_rwa",
                {
                    "ForceTransferRwa": {
                        "rwa": rwa_id,
                        "quantity": quantity,
                        "destination": destination,
                    }
                },
            )

        @classmethod
        def set_rwa_controls(
            cls,
            rwa_id: str,
            controls: dict[str, Any],
        ) -> "FakeInstruction":
            return cls._record(
                "set_rwa_controls",
                {"SetRwaControls": {"rwa": rwa_id, "controls": controls}},
            )

        @classmethod
        def set_rwa_key_value(
            cls,
            rwa_id: str,
            key: str,
            value: Any,
        ) -> "FakeInstruction":
            return cls._record(
                "set_rwa_key_value",
                {"SetRwaKeyValue": {"rwa": rwa_id, "key": key, "value": value}},
            )

        @classmethod
        def remove_rwa_key_value(cls, rwa_id: str, key: str) -> "FakeInstruction":
            return cls._record(
                "remove_rwa_key_value",
                {"RemoveRwaKeyValue": {"rwa": rwa_id, "key": key}},
            )

        def to_json(self) -> str:
            return json.dumps(self._payload)

    monkeypatch.setattr(tx, "Instruction", FakeInstruction)
    return tx, FakeInstruction


def test_transaction_draft_register_and_merge_rwa_wrap_payload_mappings(monkeypatch) -> None:
    tx, fake_instruction = _load_tx_module(monkeypatch)
    draft = tx.TransactionDraft(
        tx.TransactionConfig(
            network_id=NetworkId.from_bytes(bytes([0xA5]) * 32),
            authority=AUTHORITY,
            fee_payment=tx.authority_fee_payment(charge_limits=[]),
            ttl_ms=60_000,
            chain_discriminant=753,
        )
    )

    returned = draft.register_rwa(
        {
            "domain": "commodities",
            "quantity": Decimal("10.500"),
            "spec": {"scale": 1},
            "primary_reference": "vault-cert-001",
            "status": None,
            "metadata": {"origin": "AE"},
            "parents": [],
            "controls": {
                "controller_accounts": [],
                "controller_roles": [],
                "freeze_enabled": True,
                "hold_enabled": False,
                "force_transfer_enabled": False,
                "redeem_enabled": False,
            },
        }
    ).merge_rwas(
        {
            "parents": [{"rwa": RWA_ID, "quantity": Decimal("1.500")}],
            "primary_reference": "blend-cert-007",
            "status": "blended",
            "metadata": {"grade": "A"},
        }
    )

    assert returned is draft
    assert [call["method"] for call in fake_instruction.calls] == [
        "register_rwa",
        "merge_rwas",
    ]
    assert fake_instruction.calls[0]["payload"]["RegisterRwa"]["rwa"]["quantity"] == "10.5"
    assert (
        fake_instruction.calls[1]["payload"]["MergeRwas"]["parents"][0]["quantity"]
        == "1.5"
    )


def test_transaction_draft_rwa_scalar_helpers_use_canonical_quantities(monkeypatch) -> None:
    tx, fake_instruction = _load_tx_module(monkeypatch)
    draft = tx.TransactionDraft(
        tx.TransactionConfig(
            network_id=NetworkId.from_bytes(bytes([0xA5]) * 32),
            authority=AUTHORITY,
            fee_payment=tx.authority_fee_payment(charge_limits=[]),
            ttl_ms=60_000,
            chain_discriminant=753,
        )
    )

    returned = (
        draft.transfer_rwa(RWA_ID, quantity=Decimal("2.500"), destination=DESTINATION)
        .redeem_rwa(RWA_ID, quantity=Decimal("1.2500"))
        .freeze_rwa(RWA_ID)
        .unfreeze_rwa(RWA_ID)
        .hold_rwa(RWA_ID, quantity=Decimal("0.7500"))
        .release_rwa(RWA_ID, quantity=Decimal("0.2500"))
        .force_transfer_rwa(RWA_ID, quantity=Decimal("4.000"), destination=DESTINATION)
    )

    assert returned is draft
    assert [call["method"] for call in fake_instruction.calls] == [
        "transfer_rwa",
        "redeem_rwa",
        "freeze_rwa",
        "unfreeze_rwa",
        "hold_rwa",
        "release_rwa",
        "force_transfer_rwa",
    ]
    assert fake_instruction.calls[0]["payload"]["TransferRwa"]["source"] == AUTHORITY
    assert fake_instruction.calls[0]["payload"]["TransferRwa"]["quantity"] == "2.5"
    assert fake_instruction.calls[1]["payload"]["RedeemRwa"]["quantity"] == "1.25"
    assert fake_instruction.calls[4]["payload"]["HoldRwa"]["quantity"] == "0.75"
    assert fake_instruction.calls[5]["payload"]["ReleaseRwa"]["quantity"] == "0.25"
    assert (
        fake_instruction.calls[6]["payload"]["ForceTransferRwa"]["destination"]
        == DESTINATION
    )


def test_transaction_draft_rwa_metadata_helpers_forward_json_values(monkeypatch) -> None:
    tx, fake_instruction = _load_tx_module(monkeypatch)
    draft = tx.TransactionDraft(
        tx.TransactionConfig(
            network_id=NetworkId.from_bytes(bytes([0xA5]) * 32),
            authority=AUTHORITY,
            fee_payment=tx.authority_fee_payment(charge_limits=[]),
            ttl_ms=60_000,
            chain_discriminant=753,
        )
    )

    returned = draft.set_rwa_controls(
        RWA_ID,
        {
            "controller_accounts": [AUTHORITY],
            "controller_roles": [],
            "freeze_enabled": True,
            "hold_enabled": True,
            "force_transfer_enabled": False,
            "redeem_enabled": True,
        },
    ).set_rwa_key_value(
        RWA_ID,
        "grade",
        {"origin": "AE", "score": "9"},
    ).remove_rwa_key_value(
        RWA_ID,
        "grade",
    )

    assert returned is draft
    assert [call["method"] for call in fake_instruction.calls] == [
        "set_rwa_controls",
        "set_rwa_key_value",
        "remove_rwa_key_value",
    ]
    assert fake_instruction.calls[0]["payload"]["SetRwaControls"]["controls"]["hold_enabled"] is True
    assert fake_instruction.calls[1]["payload"]["SetRwaKeyValue"]["value"] == {
        "origin": "AE",
        "score": "9",
    }
    payload = json.loads(next(iter(draft)).to_json())
    assert payload["SetRwaControls"]["rwa"] == RWA_ID
    with pytest.raises(TypeError, match="only exact JSON values"):
        draft.set_rwa_key_value(RWA_ID, "grade", {"score": Decimal("9")})
