"""Focused tests for ordered mixed transaction batch authoring."""

from __future__ import annotations

import inspect
from typing import Any

import pytest

import iroha_python.crypto as crypto_module
import iroha_python.tx as tx_module
from iroha_python import ContractCall, Instruction, NetworkId, TransactionConfig, TransactionDraft

VALID_HASH = "00" * 31 + "01"
NETWORK_ID = NetworkId.from_bytes(bytes.fromhex(VALID_HASH))
VALID_ADDRESS = "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"


def config(*, gas_limit: int | None = 1000) -> TransactionConfig:
    return TransactionConfig(
        network_id=NETWORK_ID,
        authority="ed0120" + "11" * 32,
        fee_payment={
            "payer": "authority",
            "value": {"charge_limits": [], "gas_limit": gas_limit},
        },
        creation_time_ms=42,
    )


def test_contract_call_defensively_copies_and_bounds_arguments() -> None:
    source = bytearray(b"args")
    call = ContractCall(VALID_ADDRESS, VALID_HASH, "run", source)
    source[:] = b"nope"

    assert call.arguments == b"args"
    with pytest.raises(ValueError, match="1048576-byte limit"):
        ContractCall(VALID_ADDRESS, VALID_HASH, "run", b"x" * (1024 * 1024 + 1))
    with pytest.raises(ValueError, match="least significant bit"):
        ContractCall(VALID_ADDRESS, "00" * 32, "run")
    with pytest.raises(ValueError, match="entrypoint"):
        ContractCall(VALID_ADDRESS, VALID_HASH, " ")


def test_transaction_draft_keeps_instruction_call_instruction_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_build_signed_transaction(*args: Any, **kwargs: Any) -> str:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return "signed"

    monkeypatch.setattr(tx_module, "build_signed_transaction", fake_build_signed_transaction)
    first = object()
    last = object()
    draft = TransactionDraft(config())
    draft.add_instruction(first)  # type: ignore[arg-type]
    call = draft.add_contract_call(VALID_ADDRESS, VALID_HASH, "run", bytearray(b"abc"))
    draft.add_instruction(last)  # type: ignore[arg-type]

    assert tuple(draft.entries) == (first, call, last)
    assert tuple(draft.instructions) == (first, last)
    assert tuple(draft) == (first, call, last)
    assert draft.sign(bytes([0x11]) * 32) == "signed"
    assert captured["kwargs"]["instructions"] is None
    assert captured["kwargs"]["entries"] == [first, call, last]


def test_instruction_only_draft_uses_instruction_executable_unless_batch_is_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    def fake_build_signed_transaction(*_args: Any, **kwargs: Any) -> str:
        calls.append(kwargs)
        return "signed"

    monkeypatch.setattr(tx_module, "build_signed_transaction", fake_build_signed_transaction)
    instruction = object()
    instruction_draft = TransactionDraft(config())
    instruction_draft.add_instruction(instruction)  # type: ignore[arg-type]
    instruction_draft.sign(bytes([0x11]) * 32)

    explicit = TransactionDraft(config()).use_executable_batch()
    explicit.add_instruction(instruction)  # type: ignore[arg-type]
    explicit.sign(bytes([0x11]) * 32)

    assert calls[0]["instructions"] == [instruction]
    assert calls[0]["entries"] is None
    assert calls[1]["instructions"] is None
    assert calls[1]["entries"] == [instruction]


def test_transaction_config_is_strict_and_defensively_immutable() -> None:
    fee_payment = {
        "payer": "authority",
        "value": {"charge_limits": [], "gas_limit": 1000},
    }
    metadata = {"labels": ["first"]}
    value = TransactionConfig(
        network_id=NETWORK_ID,
        authority="ed0120" + "11" * 32,
        fee_payment=fee_payment,
        creation_time_ms=0,
        ttl_ms=1,
        nonce=1,
        metadata=metadata,
    )
    fee_payment["value"]["charge_limits"].append("changed")
    metadata["labels"].append("changed")

    assert value.creation_time_ms == 0
    assert value.fee_payment["value"]["charge_limits"] == ()
    assert value.metadata is not None
    assert value.metadata["labels"] == ("first",)
    with pytest.raises(TypeError):
        value.fee_payment["payer"] = "changed"  # type: ignore[index]

    for field, invalid in (
        ("creation_time_ms", True),
        ("creation_time_ms", -1),
        ("ttl_ms", 0),
        ("nonce", 0),
        ("nonce", 1 << 32),
    ):
        kwargs = {field: invalid}
        with pytest.raises((TypeError, ValueError), match=field):
            TransactionConfig(
                network_id=NETWORK_ID,
                authority="ed0120" + "11" * 32,
                fee_payment={"payer": "authority"},
                **kwargs,
            )

    for invalid_metadata in (
        {"value": float("nan")},
        {"value": float("inf")},
        {"value": object()},
    ):
        with pytest.raises((TypeError, ValueError), match="metadata"):
            TransactionConfig(
                network_id=NETWORK_ID,
                authority="ed0120" + "11" * 32,
                fee_payment={"payer": "authority"},
                metadata=invalid_metadata,
            )


def test_sign_uses_exact_staged_state_without_override_channels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr(
        tx_module,
        "build_signed_transaction",
        lambda *_args, **kwargs: captured.append(kwargs) or "signed",
    )
    monkeypatch.setattr(tx_module.time, "time", lambda: 123.456)
    draft = TransactionDraft(
        TransactionConfig(
            network_id=NETWORK_ID,
            authority="ed0120" + "11" * 32,
            fee_payment={"payer": "authority"},
        )
    )
    draft.add_instruction(object())  # type: ignore[arg-type]
    monkeypatch.setattr(tx_module.time, "time", lambda: 999.0)

    assert draft.sign(bytes([0x11]) * 32) == "signed"
    assert draft.sign(bytes([0x11]) * 32) == "signed"
    assert [call["creation_time_ms"] for call in captured] == [123456, 123456]
    assert set(inspect.signature(draft.sign).parameters) == {"private_key"}
    with pytest.raises(TypeError, match="unexpected keyword argument 'metadata'"):
        draft.sign(bytes([0x11]) * 32, metadata={})  # type: ignore[call-arg]


def test_generated_creation_time_is_shared_by_manifest_and_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builders: list[RecordingBuilder] = []
    monkeypatch.setattr(tx_module.time, "time", lambda: 123.456)
    draft = TransactionDraft(
        TransactionConfig(
            network_id=NETWORK_ID,
            authority="ed0120" + "11" * 32,
            fee_payment={"payer": "authority"},
        )
    )
    monkeypatch.setattr(tx_module.time, "time", lambda: 999.0)
    monkeypatch.setattr(
        tx_module,
        "TransactionBuilder",
        lambda *_args: builders.append(RecordingBuilder()) or builders[-1],
    )

    first_manifest = draft.to_manifest_dict(include_creation_time=True)
    second_manifest = draft.to_manifest_dict(include_creation_time=True)
    draft.to_builder()

    assert first_manifest["creation_time_ms"] == 123456
    assert second_manifest == first_manifest
    assert "creation_time_ms" not in draft.to_manifest_dict()
    assert ("time", 123456) in builders[0].operations


@pytest.mark.parametrize("private_key", [bytearray(32), memoryview(bytes(32)), bytes(31)])
def test_sign_rejects_mutable_or_wrong_length_private_keys(private_key: object) -> None:
    draft = TransactionDraft(config())

    with pytest.raises((TypeError, ValueError), match="private_key"):
        draft.sign(private_key)  # type: ignore[arg-type]


def test_asset_definition_registration_uses_transaction_authority_as_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeInstruction:
        @staticmethod
        def register_asset_definition(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
            captured["args"] = args
            captured["kwargs"] = kwargs
            return ("register_asset_definition", args, kwargs)

    monkeypatch.setattr(tx_module, "Instruction", FakeInstruction)
    draft = TransactionDraft(config())
    draft.register_asset_definition(
        "definition",
        owning_domain=None,
        balance_scope_policy="Global",
        name="coin",
    )
    assert captured["args"] == ("definition",)
    assert captured["kwargs"]["owning_domain"] is None
    assert captured["kwargs"]["balance_scope_policy"] == "Global"
    assert captured["kwargs"]["name"] == "coin"

    with pytest.raises(TypeError):
        draft.register_asset_definition(  # type: ignore[misc]
            "definition",
            "different-owner",
            owning_domain=None,
            balance_scope_policy="Global",
            name="coin",
        )
    with pytest.raises(TypeError, match="owning_domain"):
        draft.register_asset_definition(  # type: ignore[call-arg]
            "definition", balance_scope_policy="Global", name="coin"
        )
    with pytest.raises(TypeError, match="balance_scope_policy"):
        draft.register_asset_definition(  # type: ignore[call-arg]
            "definition", owning_domain=None, name="coin"
        )
    with pytest.raises(TypeError, match="name"):
        draft.register_asset_definition(  # type: ignore[call-arg]
            "definition",
            owning_domain=None,
            balance_scope_policy="Global",
        )
    with pytest.raises(TypeError, match="confidential_policy"):
        draft.register_asset_definition(  # type: ignore[call-arg]
            "definition",
            owning_domain=None,
            balance_scope_policy="Global",
            name="coin",
            confidential_policy="Convertible",
        )
    with pytest.raises(ValueError, match="name"):
        draft.register_asset_definition(
            "definition",
            owning_domain=None,
            balance_scope_policy="Global",
            name="   ",
        )
    with pytest.raises(ValueError, match="required for DataspaceRestricted"):
        draft.register_asset_definition(
            "definition",
            owning_domain=None,
            balance_scope_policy="DataspaceRestricted",
            name="coin",
        )


def test_native_asset_definition_registration_rejects_owner_override() -> None:
    definition_id = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
    instruction = Instruction.register_asset_definition(
        definition_id,
        owning_domain=None,
        balance_scope_policy="Global",
        name="coin",
    )
    assert isinstance(instruction, Instruction)

    with pytest.raises(TypeError):
        Instruction.register_asset_definition(
            definition_id,
            config().authority,
            owning_domain=None,
            balance_scope_policy="Global",
            name="coin",
        )


@pytest.mark.parametrize("dataspace_id", [(1 << 53) + 1, (1 << 64) - 1])
@pytest.mark.parametrize("balance_scope_policy", ["Global", "DataspaceRestricted"])
def test_direct_dataspace_draft_preserves_exact_home_and_definition_payload(
    monkeypatch: pytest.MonkeyPatch,
    dataspace_id: int,
    balance_scope_policy: str,
) -> None:
    captured: dict[str, Any] = {}
    instruction = object()

    class FakeInstruction:
        @staticmethod
        def register_dataspace_asset_definition(*args: Any, **kwargs: Any) -> object:
            captured["args"] = args
            captured["kwargs"] = kwargs
            return instruction

    monkeypatch.setattr(tx_module, "Instruction", FakeInstruction)
    draft = TransactionDraft(config())
    assert draft.register_dataspace_asset_definition(
        "definition",
        dataspace_id=dataspace_id,
        balance_scope_policy=balance_scope_policy,
        name="coin",
        description="exact direct namespace",
        alias="coin#public",
        scale="2",
        mintable="Once",
        metadata={"rate": 1.25},
    ) is draft
    assert captured == {
        "args": ("definition",),
        "kwargs": {
            "dataspace_id": dataspace_id,
            "balance_scope_policy": balance_scope_policy,
            "name": "coin",
            "description": "exact direct namespace",
            "alias": "coin#public",
            "scale": 2,
            "mintable": "Once",
            "metadata": {"rate": 1.25},
        },
    }
    assert tuple(draft.instructions) == (instruction,)


@pytest.mark.parametrize("dataspace_id", [True, False, "42", 1.0, None, 0, -1, 1 << 64])
def test_direct_dataspace_boundaries_reject_noncanonical_home(dataspace_id: Any) -> None:
    kwargs = {
        "dataspace_id": dataspace_id,
        "balance_scope_policy": "Global",
        "name": "coin",
    }
    native = crypto_module._crypto.Instruction
    with pytest.raises((TypeError, ValueError), match="dataspace_id"):
        native.register_dataspace_asset_definition("62Fk4FPcMuLvW5QjDGNF2a4jAmjM", **kwargs)
    draft = TransactionDraft(config())
    with pytest.raises((TypeError, ValueError), match="dataspace_id"):
        draft.register_dataspace_asset_definition("definition", **kwargs)
    assert tuple(draft.instructions) == ()


@pytest.mark.parametrize("balance_scope_policy", ["Global", "DataspaceRestricted"])
def test_native_direct_dataspace_preserves_full_u64_and_native_roundtrip(
    balance_scope_policy: str,
) -> None:
    native = crypto_module._crypto.Instruction
    encoded = []
    for dataspace_id in [(1 << 53), (1 << 53) + 1, (1 << 64) - 1]:
        instruction = native.register_dataspace_asset_definition(
            "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
            dataspace_id=dataspace_id,
            balance_scope_policy=balance_scope_policy,
            name="coin",
            description="exact direct namespace",
            scale=2,
            mintable="Once",
            metadata={"rate": 1.25},
        )
        payload = instruction.to_json()
        assert native.from_json(payload).to_json() == payload
        encoded.append(payload)
    assert len(set(encoded)) == 3


@pytest.mark.parametrize("field", ["owning_domain", "owner"])
def test_direct_dataspace_registration_rejects_conflicting_home_or_owner(field: str) -> None:
    kwargs = {
        "dataspace_id": 42,
        "balance_scope_policy": "Global",
        "name": "coin",
        field: "issuer.public",
    }
    with pytest.raises(TypeError, match=field):
        crypto_module._crypto.Instruction.register_dataspace_asset_definition(
            "62Fk4FPcMuLvW5QjDGNF2a4jAmjM", **kwargs
        )
    with pytest.raises(TypeError, match=field):
        TransactionDraft(config()).register_dataspace_asset_definition("definition", **kwargs)


def test_direct_dataspace_client_forwards_exact_draft_and_submission_options() -> None:
    from iroha_python.client import ToriiClient

    captured: dict[str, Any] = {}
    result = {"status": "committed"}

    class FakeDraft:
        def register_dataspace_asset_definition(self, *args: Any, **kwargs: Any) -> None:
            captured["registration"] = (args, kwargs)

    draft = FakeDraft()

    class FakeClient:
        def _transaction_draft(self, **kwargs: Any) -> FakeDraft:
            captured["draft"] = kwargs
            return draft

        def _submit_transaction_draft_result(self, actual: Any, **kwargs: Any) -> dict[str, str]:
            assert actual is draft
            captured["submission"] = kwargs
            return result

    actual = ToriiClient.register_dataspace_asset_definition_and_wait(
        FakeClient(),  # type: ignore[arg-type]
        authority=config().authority,
        fee_payment={"payer": "authority"},
        private_key=bytes([0x11]) * 32,
        definition_id="definition",
        dataspace_id=(1 << 64) - 1,
        balance_scope_policy="DataspaceRestricted",
        name="coin",
        asset_metadata={"rate": 1.25},
        transaction_metadata={"purpose": "registration"},
        wait=False,
        timeout=9.0,
        interval=0.5,
    )
    assert actual is result
    assert captured["draft"] == {
        "authority": config().authority,
        "fee_payment": {"payer": "authority"},
        "metadata": {"purpose": "registration"},
    }
    assert captured["registration"] == (("definition",), {
        "dataspace_id": (1 << 64) - 1,
        "balance_scope_policy": "DataspaceRestricted",
        "name": "coin",
        "description": None,
        "alias": None,
        "scale": None,
        "mintable": "Infinitely",
        "metadata": {"rate": 1.25},
    })
    assert captured["submission"] == {
        "private_key": bytes([0x11]) * 32,
        "private_key_hex": None,
        "wait": False,
        "timeout": 9.0,
        "interval": 0.5,
    }


def test_wallet_transfer_controls_chain_into_one_atomic_draft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class FakeInstruction:
        @staticmethod
        def set_asset_transfer_availability(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
            instruction = ("availability", *args, kwargs)
            calls.append(instruction)
            return instruction

        @staticmethod
        def set_asset_transfer_blacklist(*args: Any) -> tuple[Any, ...]:
            instruction = ("blacklist", *args)
            calls.append(instruction)
            return instruction

        @staticmethod
        def set_asset_transfer_control(*args: Any) -> tuple[Any, ...]:
            instruction = ("transfer_control", *args)
            calls.append(instruction)
            return instruction

        @staticmethod
        def set_asset_holding_limit(*args: Any) -> tuple[Any, ...]:
            instruction = ("holding_limit", *args)
            calls.append(instruction)
            return instruction

    monkeypatch.setattr(tx_module, "Instruction", FakeInstruction)
    draft = TransactionDraft(config())

    returned = (
        draft.set_asset_transfer_availability(
            "wallet",
            "digital_shekel",
            0,
            tx_module.AssetTransferAvailability.DISABLED,
            tx_module.AssetTransferAvailability.DISABLED,
            reason="operator close",
        )
        .set_asset_transfer_blacklist(
            "wallet",
            "digital_shekel",
            False,
        )
        .set_asset_transfer_control(
            "wallet",
            "digital_shekel",
            [{"window": "day", "cap_amount": 50}],
        )
        .set_asset_holding_limit("wallet", "digital_shekel", 0)
    )

    assert returned is draft
    assert tuple(draft.entries) == tuple(calls)
    assert calls == [
        (
            "availability",
            "wallet",
            "digital_shekel",
            0,
            "Disabled",
            "Disabled",
            {"reason": "operator close"},
        ),
        ("blacklist", "wallet", "digital_shekel", False),
        (
            "transfer_control",
            "wallet",
            "digital_shekel",
            [{"window": "DAY", "cap_amount": "50"}],
        ),
        ("holding_limit", "wallet", "digital_shekel", "0"),
    ]


@pytest.mark.parametrize(
    "reason",
    [
        "line\nbreached",
        "ר" * 257,
    ],
)
def test_asset_transfer_availability_rejects_noncanonical_reason_before_native_call(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    class FakeInstruction:
        @staticmethod
        def set_asset_transfer_availability(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
            raise AssertionError(
                f"native constructor must not be called: {args!r} {kwargs!r}"
            )

    monkeypatch.setattr(tx_module, "Instruction", FakeInstruction)
    with pytest.raises(ValueError):
        TransactionDraft(config()).set_asset_transfer_availability(
            "wallet",
            "digital_shekel",
            0,
            tx_module.AssetTransferAvailability.DISABLED,
            tx_module.AssetTransferAvailability.DISABLED,
            reason=reason,
        )


def test_asset_transfer_caps_reject_duplicate_windows_before_native_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeInstruction:
        @staticmethod
        def set_asset_transfer_control(*args: Any) -> tuple[Any, ...]:
            raise AssertionError(f"native constructor must not be called: {args!r}")

    monkeypatch.setattr(tx_module, "Instruction", FakeInstruction)
    draft = TransactionDraft(config())

    with pytest.raises(ValueError, match="duplicates"):
        draft.set_asset_transfer_control(
            "wallet",
            "digital_shekel",
            [
                {"window": "DAY", "cap_amount": 50},
                {"window": "day", "cap_amount": 25},
            ],
        )

    assert tuple(draft.entries) == ()


class RecordingBuilder:
    """Minimal native-builder stand-in used to inspect authoring calls."""

    def __init__(self, *_args: Any) -> None:
        self.operations: list[tuple[Any, ...]] = []

    def use_executable_batch(self) -> None:
        self.operations.append(("batch",))

    def add_instruction(self, instruction: Any) -> None:
        self.operations.append(("instruction", instruction))

    def add_contract_call(self, *call: Any) -> None:
        self.operations.append(("call", *call))

    def set_creation_time_ms(self, value: int) -> None:
        self.operations.append(("time", value))

    def bind_privacy_exact12_capability_manifest_v1(self, manifest: Any) -> None:
        self.operations.append(("manifest", manifest))

    def sign(self, private_key: bytes) -> str:
        self.operations.append(("sign", private_key))
        return "signed"


def test_to_builder_is_a_pure_repeatable_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builders: list[RecordingBuilder] = []

    class BoundManifest:
        def __init__(self) -> None:
            self.checked_networks: list[NetworkId] = []

        def require_transaction_network(self, network_id: NetworkId) -> None:
            self.checked_networks.append(network_id)

    manifest = BoundManifest()
    monkeypatch.setattr(
        tx_module,
        "_is_native_crypto_instance",
        lambda value, name: value is manifest and name == "PrivacyExact12CapabilityManifestV1",
    )
    monkeypatch.setattr(
        tx_module,
        "TransactionBuilder",
        lambda *_args: builders.append(RecordingBuilder()) or builders[-1],
    )
    draft = TransactionDraft(config()).bind_privacy_exact12_capability_manifest_v1(
        manifest  # type: ignore[arg-type]
    )
    assert manifest.checked_networks == [NETWORK_ID]

    first = draft.to_builder()
    second = draft.to_builder()

    assert first is builders[0]
    assert second is builders[1]
    assert builders[0].operations == [("manifest", manifest), ("time", 42)]
    assert builders[1].operations == [("manifest", manifest), ("time", 42)]


def test_build_signed_transaction_entries_select_batch_and_reject_dual_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builders: list[RecordingBuilder] = []

    def make_builder(*args: Any) -> RecordingBuilder:
        builder = RecordingBuilder(*args)
        builders.append(builder)
        return builder

    monkeypatch.setattr(crypto_module, "TransactionBuilder", make_builder)
    instruction = object()
    call = ContractCall(VALID_ADDRESS, VALID_HASH, "run", b"abc")

    result = crypto_module.build_signed_transaction(
        NETWORK_ID,
        "authority",
        bytes([0x11]) * 32,
        fee_payment={"payer": "authority", "value": {}},
        entries=[instruction, call],  # type: ignore[list-item]
        creation_time_ms=42,
    )

    assert result == "signed"
    assert builders[0].operations == [
        ("time", 42),
        ("batch",),
        ("instruction", instruction),
        ("call", VALID_ADDRESS, VALID_HASH, "run", b"abc"),
        ("sign", bytes([0x11]) * 32),
    ]
    with pytest.raises(ValueError, match="mutually exclusive"):
        crypto_module.build_signed_transaction(
            NETWORK_ID,
            "authority",
            bytes([0x11]) * 32,
            fee_payment={"payer": "authority", "value": {}},
            instructions=[],
            entries=[],
        )
    with pytest.raises(TypeError, match="exact immutable bytes"):
        crypto_module.build_signed_transaction(
            NETWORK_ID,
            "authority",
            bytearray(32),  # type: ignore[arg-type]
            fee_payment={"payer": "authority", "value": {}},
        )
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        crypto_module.build_signed_transaction(
            NETWORK_ID,
            "authority",
            bytes(31),
            fee_payment={"payer": "authority", "value": {}},
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("creation_time_ms", True, "integer"),
        ("ttl_ms", 1.5, "integer"),
        ("ttl_ms", 0, "positive"),
        ("nonce", "1", "integer"),
        ("nonce", 1 << 32, "no greater than"),
    ],
)
def test_build_signed_transaction_rejects_lossy_integer_inputs(
    field: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        crypto_module.build_signed_transaction(
            NETWORK_ID,
            "authority",
            bytes([0x11]) * 32,
            fee_payment={"payer": "authority", "value": {}},
            **{field: value},
        )


def test_build_signed_transaction_rejects_non_json_payload_values() -> None:
    with pytest.raises(ValueError, match="NaN or Infinity"):
        crypto_module.build_signed_transaction(
            NETWORK_ID,
            "authority",
            bytes([0x11]) * 32,
            fee_payment={"payer": "authority", "value": {"gas": float("nan")}},
        )
    with pytest.raises(TypeError, match="keys must be strings"):
        crypto_module.build_signed_transaction(
            NETWORK_ID,
            "authority",
            bytes([0x11]) * 32,
            fee_payment={"payer": "authority", 1: "not-json"},  # type: ignore[dict-item]
        )
    with pytest.raises(TypeError, match="exact JSON values"):
        crypto_module.build_signed_transaction(
            NETWORK_ID,
            "authority",
            bytes([0x11]) * 32,
            fee_payment={"payer": "authority", "value": {}},
            metadata={"unsupported": object()},
        )


@pytest.mark.parametrize("retired_domain", ["test-chain", bytes.fromhex(VALID_HASH)])
def test_build_signed_transaction_rejects_label_and_bare_hash_domains(
    retired_domain: object,
) -> None:
    with pytest.raises(TypeError, match="network_id must be a NetworkId"):
        crypto_module.build_signed_transaction(
            retired_domain,  # type: ignore[arg-type]
            "authority",
            b"private",
            fee_payment={"payer": "authority", "value": {}},
        )
