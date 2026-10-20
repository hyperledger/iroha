"""Native asset-lock transaction and Torii helper parity tests."""

from __future__ import annotations

import base64
import inspect
import json
from decimal import Decimal
from typing import Any, cast

import pytest
import requests

from iroha_python import (
    CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1,
    Ed25519KeyPair,
    Instruction,
    LocalSigningContext,
    NetworkId,
    ToriiClient,
    TransactionConfig,
    TransactionDraft,
    authority_fee_payment,
    decode_cancel_asset_lock_v1,
)

CANONICAL_GENESIS_HASH = bytes([0xA5]) * 32
NETWORK_ID = NetworkId.from_bytes(CANONICAL_GENESIS_HASH)
FEE_PAYMENT = authority_fee_payment(charge_limits=[])
TRANSACTION_LOCAL_SIGNING_CONTEXT = LocalSigningContext(NETWORK_ID)


class NoRequestSession(requests.Session):
    """Fail if a helper unexpectedly performs network I/O."""

    def __init__(self) -> None:
        super().__init__()

    def request(self, method: str, url: str, **kwargs: object) -> Any:
        raise AssertionError(f"unexpected request {method} {url}")


def account_address(seed: int, discriminant: int = 0x02F1) -> str:
    """Derive a deterministic account address for one test key."""

    return Ed25519KeyPair.from_private_key(bytes([seed] * 32)).account_id(
        discriminant=discriminant,
    )


def test_asset_lock_instruction_helpers_serialize_full_surface() -> None:
    asset_definition_id = "7MBRDd8cGFBZkFGdDMwV7S6FPwbw"
    source = account_address(0x70)
    destination = account_address(0x71)
    release_authority = account_address(0x72)

    instructions = [
        Instruction.open_asset_lock(
            "lock-sdk-1",
            asset_definition_id,
            destination,
            "12.5",
            release_authority=release_authority,
            expires_at_ms=1_234_567,
            evidence_hashes=["11" * 32],
        ),
        Instruction.drawdown_asset_lock("lock-sdk-1", "2.5", "12.5"),
        Instruction.cancel_asset_lock("lock-sdk-1", "10"),
        Instruction.expire_asset_lock("lock-sdk-1"),
    ]
    encoded = [instruction.to_json() for instruction in instructions]
    assert [Instruction.from_json(payload, chain_discriminant=753).to_json() for payload in encoded] == encoded

    draft = TransactionDraft(
        TransactionConfig(
            network_id=NETWORK_ID,
            authority=source,
            fee_payment=authority_fee_payment(charge_limits=[]),
            chain_discriminant=753,
        )
    )
    draft.open_asset_lock(
        "lock-sdk-2",
        asset_definition_id,
        destination,
        Decimal("12.500"),
        release_authority=release_authority,
        expires_at_ms=1_234_567,
        evidence_hashes=("22" * 32,),
    )
    draft.drawdown_asset_lock("lock-sdk-2", Decimal("2.500"), Decimal("12.500"))
    draft.cancel_asset_lock("lock-sdk-2", Decimal("10.000"))
    draft.expire_asset_lock("lock-sdk-2")

    draft_encoded = [instruction.to_json() for instruction in draft.instructions]
    assert len(draft_encoded) == 4
    assert [Instruction.from_json(payload, chain_discriminant=753).to_json() for payload in draft_encoded] == draft_encoded


def test_cancel_asset_lock_instruction_builder_has_exact_two_argument_runtime_shape() -> None:
    signature = inspect.signature(Instruction.cancel_asset_lock)
    assert [
        (parameter.name, parameter.kind, parameter.default)
        for parameter in signature.parameters.values()
    ] == [
        (
            "escrow_id",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.empty,
        ),
        (
            "expected_remaining_amount",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.empty,
        ),
    ]

    builder = cast(Any, Instruction.cancel_asset_lock)
    with pytest.raises(TypeError):
        builder("lock-sdk-runtime-shape")
    with pytest.raises(TypeError):
        builder("lock-sdk-runtime-shape", "1", "retired-third-argument")


def test_cancel_asset_lock_and_wait_builds_compare_and_cancel_instruction() -> None:
    client = ToriiClient(
        "http://torii.example",
        session=NoRequestSession(),
        max_retries=0,
        local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT,
        chain_discriminant=753,
    )
    captured: dict[str, object] = {}

    def fake_submit(draft: object, **kwargs: object) -> dict[str, object]:
        captured["draft"] = draft
        captured["kwargs"] = kwargs
        return {"hash": "cancel-lock"}

    client._submit_transaction_draft_result = fake_submit  # type: ignore[method-assign]

    result = client.cancel_asset_lock_and_wait(
        authority=account_address(0x72),
        fee_payment=FEE_PAYMENT,
        private_key_hex="11" * 32,
        escrow_id="lock-sdk-client-cancel",
        expected_remaining_amount=Decimal("10.000"),
        transaction_metadata={"purpose": "stale-cancel-guard"},
        wait=False,
    )

    draft = cast(TransactionDraft, captured["draft"])
    submitted_kwargs = cast(dict[str, object], captured["kwargs"])
    instruction_json_bytes = draft.instructions[0].to_json().encode("utf-8")
    instruction_archive = base64.b64decode(
        json.loads(instruction_json_bytes),
        validate=True,
    )
    cancel_asset_lock_archive = instruction_archive[-85:]
    decoded_cancel_asset_lock = decode_cancel_asset_lock_v1(cancel_asset_lock_archive)
    assert result == {"hash": "cancel-lock"}
    assert len(draft) == 1
    assert draft.config.metadata == {"purpose": "stale-cancel-guard"}
    assert instruction_json_bytes == (
        b'"TlJUMAAAhip9dwddTSP/bBJh2wJ4EQCNAAAAAAAAAG8KFNTMlvogAi4taXJvaGEuaW5zdHJ1Y3Rpb24u'
        b"djE6OmVzY3Jvdzo6Q2FuY2VsQXNzZXRMb2NrXVUAAAAAAAAATlJUMAAAtcimZafegOLu91zLKHB4+gAtAAAA"
        b'AAAAAIbcWm2Sf6HDAiCKDJLQeMGaIprCKTQS+MqhXoMFVKjFonGqLzT5SzkmSQsFAQAAAAoEAAAAAA=="'
    )
    assert instruction_archive == bytes.fromhex(
        "4e5254300000862a7d77075d4d23ff6c1261db027811008d000000000000006f0a14d4cc96fa20"
        "022e2d69726f68612e696e737472756374696f6e2e76313a3a657363726f773a3a43616e63656c"
        "41737365744c6f636b5d55000000000000004e5254300000b5c8a665a7de80e2eef75ccb287078"
        "fa002d0000000000000086dc5a6d927fa1c302208a0c92d078c19a229ac2293412f8caa15e8305"
        "54a8c5a271aa2f34f94b3926490b05010000000a0400000000"
    )
    assert len(cancel_asset_lock_archive) == 85
    assert decoded_cancel_asset_lock.escrow_id == (
        "hash:8A0C92D078C19A229AC2293412F8CAA15E830554A8C5A271AA2F34F94B392649#91BC"
    )
    assert decoded_cancel_asset_lock.expected_remaining_amount == "10"
    assert submitted_kwargs["wait"] is False


def test_cancel_asset_lock_and_wait_requires_expected_remaining_amount() -> None:
    client = ToriiClient(
        "http://torii.example",
        session=NoRequestSession(),
        max_retries=0,
        local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT,
        chain_discriminant=753,
    )

    with pytest.raises(TypeError, match="expected_remaining_amount"):
        client.cancel_asset_lock_and_wait(  # type: ignore[call-arg]
            authority=account_address(0x72),
            fee_payment=FEE_PAYMENT,
            private_key_hex="11" * 32,
            escrow_id="lock-sdk-client-cancel",
            wait=False,
        )


def test_cancel_asset_lock_and_wait_rejects_non_positive_remaining_amount() -> None:
    client = ToriiClient(
        "http://torii.example",
        session=NoRequestSession(),
        max_retries=0,
        local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT,
        chain_discriminant=753,
    )

    with pytest.raises(ValueError, match="expected_remaining_amount must be positive"):
        client.cancel_asset_lock_and_wait(
            authority=account_address(0x72),
            fee_payment=FEE_PAYMENT,
            private_key_hex="11" * 32,
            escrow_id="lock-sdk-client-cancel",
            expected_remaining_amount=0,
            wait=False,
        )


@pytest.mark.parametrize(
    "amount",
    [
        "0." + "0" * 27 + "1",
        str((1 << 128) - 1),
    ],
    ids=["scale-28", "u128-max"],
)
def test_native_asset_lock_accepts_exact_quantity_boundaries(amount: str) -> None:
    instruction = Instruction.open_asset_lock(
        "lock-sdk-quantity-boundary",
        "7MBRDd8cGFBZkFGdDMwV7S6FPwbw",
        account_address(0x73),
        amount,
    )

    encoded = instruction.to_json()
    assert Instruction.from_json(encoded, chain_discriminant=753).to_json() == encoded


@pytest.mark.parametrize(
    "amount",
    [
        "-1",
        "0." + "0" * 28 + "1",
        str(1 << 512),
    ],
    ids=["negative", "scale-29", "over-512-bits"],
)
def test_native_asset_lock_rejects_out_of_domain_quantities(amount: str) -> None:
    with pytest.raises(ValueError):
        Instruction.open_asset_lock(
            "lock-sdk-invalid-quantity",
            "7MBRDd8cGFBZkFGdDMwV7S6FPwbw",
            account_address(0x73),
            amount,
        )


@pytest.mark.parametrize(
    "expected_remaining_amount",
    ["0", "-1", "01", "1.0"],
    ids=["zero", "negative", "leading-zero", "noncanonical-scale"],
)
def test_cancel_asset_lock_instruction_rejects_non_positive_or_noncanonical_remaining_amount(
    expected_remaining_amount: str,
) -> None:
    with pytest.raises(ValueError):
        Instruction.cancel_asset_lock(
            "lock-sdk-invalid-cancel-remaining",
            expected_remaining_amount,
        )


def test_cancel_asset_lock_bounds_exact_utf8_lock_id_preimage() -> None:
    exact_bound = "🔒" * 1_024
    assert len(exact_bound.encode("utf-8")) == 4_096
    assert CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1 == 4_096
    Instruction.cancel_asset_lock(exact_bound, "1")
    draft = TransactionDraft(
        TransactionConfig(
            network_id=NETWORK_ID,
            authority=account_address(0x75),
            fee_payment=authority_fee_payment(charge_limits=[]),
            chain_discriminant=753,
        )
    )
    draft.cancel_asset_lock(exact_bound, "1")

    over_bound = exact_bound + "a"
    assert len(over_bound.encode("utf-8")) == 4_097
    with pytest.raises(ValueError, match="at most 4096 UTF-8 bytes"):
        Instruction.cancel_asset_lock(over_bound, "1")
    with pytest.raises(ValueError, match="at most 4096 UTF-8 bytes"):
        draft.cancel_asset_lock(over_bound, "1")


@pytest.mark.parametrize(
    "lock_id",
    ["", " ", " lock", "lock ", "\ufefflock", "lock\ufeff", "\ud800", "\udc00"],
)
def test_cancel_asset_lock_rejects_unclean_lock_id_preimage(lock_id: str) -> None:
    with pytest.raises(ValueError, match="lock-ID preimage"):
        Instruction.cancel_asset_lock(lock_id, "1")

    draft = TransactionDraft(
        TransactionConfig(
            network_id=NETWORK_ID,
            authority=account_address(0x75),
            fee_payment=authority_fee_payment(charge_limits=[]),
            chain_discriminant=753,
        )
    )
    with pytest.raises(ValueError):
        draft.cancel_asset_lock(lock_id, "1")


@pytest.mark.parametrize(
    ("method_name", "args"),
    [
        (
            "open_asset_lock",
            (
                "lock-sdk-bad",
                "7MBRDd8cGFBZkFGdDMwV7S6FPwbw",
                account_address(0x73),
            ),
        ),
        ("drawdown_asset_lock", ("lock-sdk-bad",)),
    ],
)
@pytest.mark.parametrize(
    "amount",
    [0, "0", "-1", Decimal("-0.1"), "NaN", "Infinity"],
)
def test_asset_lock_transaction_draft_rejects_non_positive_amounts(
    method_name: str,
    args: tuple[object, ...],
    amount: object,
) -> None:
    account = account_address(0x74)
    draft = TransactionDraft(
        TransactionConfig(
            network_id=NETWORK_ID,
            authority=account,
            fee_payment=authority_fee_payment(charge_limits=[]),
            chain_discriminant=753,
        )
    )
    method = getattr(draft, method_name)

    with pytest.raises(
        ValueError,
        match=(
            "amount must be positive|expected_remaining_amount must be positive|"
            "quantity must be a finite"
        ),
    ):
        if method_name == "drawdown_asset_lock":
            method(*args, amount, 1)
        else:
            method(*args, amount)


@pytest.mark.parametrize("method_name", ["drawdown_asset_lock", "cancel_asset_lock"])
@pytest.mark.parametrize(
    "expected_remaining_amount",
    [0, "0", "-1", Decimal("-0.1"), "NaN", "Infinity"],
)
def test_asset_lock_transaction_draft_rejects_non_positive_expected_remaining_amount(
    method_name: str,
    expected_remaining_amount: object,
) -> None:
    account = account_address(0x75)
    draft = TransactionDraft(
        TransactionConfig(
            network_id=NETWORK_ID,
            authority=account,
            fee_payment=authority_fee_payment(charge_limits=[]),
            chain_discriminant=753,
        )
    )
    method = getattr(draft, method_name)

    with pytest.raises(
        (TypeError, ValueError),
        match=(
            "expected_remaining_amount must be positive|"
            "expected_remaining_amount must be positive and use a finite canonical quantity"
        ),
    ):
        if method_name == "drawdown_asset_lock":
            method("lock-sdk-bad-remaining", 1, expected_remaining_amount)
        else:
            method("lock-sdk-bad-remaining", expected_remaining_amount)


def test_asset_lock_transaction_draft_rejects_empty_identifiers() -> None:
    account = account_address(0x75)
    draft = TransactionDraft(
        TransactionConfig(
            network_id=NETWORK_ID,
            authority=account,
            fee_payment=authority_fee_payment(charge_limits=[]),
            chain_discriminant=753,
        )
    )

    with pytest.raises(ValueError, match="escrow_id"):
        draft.cancel_asset_lock("", 1)
    with pytest.raises(ValueError, match="release_authority"):
        draft.open_asset_lock(
            "lock-sdk-empty-authority",
            "7MBRDd8cGFBZkFGdDMwV7S6FPwbw",
            account_address(0x76),
            1,
            release_authority="",
        )
