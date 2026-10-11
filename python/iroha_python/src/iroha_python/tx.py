"""High-level transaction helpers built on top of the low-level `Instruction` APIs."""

from __future__ import annotations

import json
import time
import unicodedata
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Mapping, Optional, Sequence, Union

from ._quantity import (
    QuantityLike,
    _normalize_positive_quantity,
    _normalize_quantity,
)
from ._quantity import _normalize_u128_quantity as _normalize_u128_quantity
from ._validation import (
    _normalize_json_value,
    _normalize_mapping_payload,
    _optional_uint,
)
from .address import require_canonical_asset_definition_id
from .crypto import (
    _LANE_PRIVACY_MAX_MERKLE_DEPTH_V1,
    ContractCall,
    Ed25519KeyPair,
    Instruction,
    NetworkId,
    PrivacyExact12CapabilityManifestV1,
    PrivacyNativeActionBuildResultV1,
    SignedTransactionEnvelope,
    TransactionBuilder,
    TransactionExecutableEntry,
    _is_native_crypto_instance,
    _normalize_lane_privacy_attachment,
    _require_network_id,
    build_signed_transaction,
)
from .settlement import SettlementLeg, SettlementPlan

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .client import ToriiClient
    from .repo import RepoCashLeg, RepoCollateralLeg, RepoGovernance

__all__ = [
    "ASSET_TRANSFER_AVAILABILITY_MAX_REASON_BYTES_V1",
    "AssetTransferAvailability",
    "ContractCall",
    "TransactionConfig",
    "TransactionDraft",
    "TransactionExecutableEntry",
    "authority_fee_payment",
    "sponsor_fee_payment",
]


MetadataLike = Optional[Mapping[str, Any]]
FixedBytesLike = Union[str, bytes, bytearray, memoryview]
VerifyingKeyLike = Union[str, Mapping[str, Any]]
_U64_MAX = (1 << 64) - 1
ASSET_TRANSFER_AVAILABILITY_MAX_REASON_BYTES_V1 = 512


class AssetTransferAvailability(str, Enum):
    """Directional availability state for account-to-account asset transfers."""

    ENABLED = "Enabled"
    DISABLED = "Disabled"


def _normalize_asset_transfer_availability(
    value: Union[AssetTransferAvailability, str],
    context: str,
) -> str:
    raw = value.value if isinstance(value, AssetTransferAvailability) else value
    if raw not in {"Enabled", "Disabled"}:
        raise ValueError(f"{context} must be AssetTransferAvailability.ENABLED or DISABLED")
    return raw


def _normalize_asset_transfer_availability_reason(value: Any) -> str:
    reason = _require_exact_non_empty_string(value, "reason")
    if any(unicodedata.category(character) == "Cc" for character in reason):
        raise ValueError("reason must not contain control characters")
    if (
        len(reason.encode("utf-8"))
        > ASSET_TRANSFER_AVAILABILITY_MAX_REASON_BYTES_V1
    ):
        raise ValueError(
            "reason exceeds the 512-byte asset-transfer availability limit"
        )
    return reason


def _require_non_empty_string(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    text = value.strip()
    if not text:
        raise ValueError(f"{context} must be non-empty")
    return text


def _require_exact_non_empty_string(value: Any, context: str) -> str:
    text = _require_non_empty_string(value, context)
    if text != value:
        raise ValueError(f"{context} must not contain surrounding whitespace")
    return value


def _normalize_asset_transfer_limits(
    limits: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Optional[str]]]:
    if isinstance(limits, (str, bytes, bytearray, Mapping)) or not isinstance(limits, Sequence):
        raise TypeError("limits must be a sequence of window/cap_amount mappings")
    if len(limits) > 3:
        raise ValueError("limits may contain at most DAY, WEEK, and MONTH")

    normalized: List[Dict[str, Optional[str]]] = []
    windows: set[str] = set()
    for index, limit in enumerate(limits):
        if not isinstance(limit, Mapping):
            raise TypeError(f"limits[{index}] must be a mapping")
        unknown = set(limit).difference({"window", "cap_amount"})
        if unknown:
            names = ", ".join(sorted(str(name) for name in unknown))
            raise ValueError(f"limits[{index}] contains unknown fields: {names}")
        if "window" not in limit:
            raise ValueError(f"limits[{index}].window is required")
        if "cap_amount" not in limit:
            raise ValueError(f"limits[{index}].cap_amount is required")
        window = _require_exact_non_empty_string(limit["window"], f"limits[{index}].window").upper()
        if window not in {"DAY", "WEEK", "MONTH"}:
            raise ValueError(f"limits[{index}].window must be DAY, WEEK, or MONTH")
        if window in windows:
            raise ValueError(f"limits[{index}].window duplicates an earlier window")
        windows.add(window)
        cap = limit["cap_amount"]
        normalized.append(
            {
                "window": window,
                "cap_amount": _normalize_quantity(cap) if cap is not None else None,
            }
        )
    return normalized


@dataclass(frozen=True, slots=True)
class TransactionConfig:
    """Configuration shared across transactions signed by :class:`TransactionDraft`."""

    network_id: NetworkId
    authority: str
    fee_payment: Mapping[str, Any]
    creation_time_ms: Optional[int] = None
    ttl_ms: Optional[int] = None
    nonce: Optional[int] = None
    metadata: Optional[Mapping[str, Any]] = None

    def __post_init__(self) -> None:
        network_id = _require_network_id(
            self.network_id,
            "TransactionConfig.network_id",
        )
        authority = _require_exact_non_empty_string(
            self.authority,
            "TransactionConfig.authority",
        )
        fee_payment = _freeze_json(
            _normalize_mapping_payload(
                self.fee_payment,
                "TransactionConfig.fee_payment",
            )
        )
        creation_time_ms = _optional_uint(
            self.creation_time_ms,
            "TransactionConfig.creation_time_ms",
            maximum=_U64_MAX,
            allow_zero=True,
        )
        ttl_ms = _optional_uint(
            self.ttl_ms,
            "TransactionConfig.ttl_ms",
            maximum=_U64_MAX,
            allow_zero=False,
        )
        nonce = _optional_uint(
            self.nonce,
            "TransactionConfig.nonce",
            maximum=(1 << 32) - 1,
            allow_zero=False,
        )
        metadata = (
            None
            if self.metadata is None
            else _freeze_json(_normalize_metadata(self.metadata))
        )
        object.__setattr__(
            self,
            "network_id",
            network_id,
        )
        object.__setattr__(self, "authority", authority)
        object.__setattr__(self, "fee_payment", fee_payment)
        object.__setattr__(self, "creation_time_ms", creation_time_ms)
        object.__setattr__(self, "ttl_ms", ttl_ms)
        object.__setattr__(self, "nonce", nonce)
        object.__setattr__(self, "metadata", metadata)


def _ensure_creation_time_ms(config: TransactionConfig) -> int:
    if config.creation_time_ms is not None:
        return config.creation_time_ms
    return int(time.time() * 1000)


def _normalize_metadata(metadata: MetadataLike) -> Optional[Dict[str, Any]]:
    if metadata is None:
        return None
    if not isinstance(metadata, Mapping):
        raise TypeError("metadata must be a mapping when provided")
    normalized = _normalize_json_value(metadata, "metadata")
    if not isinstance(normalized, dict):
        raise TypeError("metadata must be a mapping when provided")
    return normalized


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _payload_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    to_payload = getattr(value, "to_payload", None)
    if not callable(to_payload):
        raise TypeError(f"{context} must be a mapping or expose to_payload()")
    payload = to_payload()
    if not isinstance(payload, Mapping):
        raise TypeError(f"{context}.to_payload() must return a mapping")
    return payload


def _fee_charge_limits(charge_limits: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    if isinstance(charge_limits, (str, bytes, bytearray, memoryview)):
        raise TypeError("charge_limits must be a sequence of mappings")
    normalized: List[Dict[str, Any]] = []
    previous_kind = -1
    for index, raw in enumerate(charge_limits):
        if not isinstance(raw, Mapping):
            raise TypeError(f"charge_limits[{index}] must be a mapping")
        kind_literal = raw.get("kind")
        kind = 0 if kind_literal == "nexus" else 1 if kind_literal == "pipeline_gas" else -1
        if kind < 0:
            raise ValueError(f"charge_limits[{index}].kind must be nexus or pipeline_gas")
        if kind <= previous_kind:
            raise ValueError("charge_limits must be unique and ordered nexus before pipeline_gas")
        previous_kind = kind
        asset_definition_id = require_canonical_asset_definition_id(
            raw.get("asset_definition_id"),
            f"charge_limits[{index}].asset_definition_id",
        )
        raw_max_amount = raw.get("max_amount")
        if raw_max_amount is None:
            raise ValueError(f"charge_limits[{index}].max_amount is required")
        max_amount = _normalize_positive_quantity(
            raw_max_amount,
            f"charge_limits[{index}].max_amount",
        )
        normalized.append(
            {
                "kind": {
                    "kind": "nexus" if kind == 0 else "pipeline_gas",
                    "value": None,
                },
                "asset_definition_id": asset_definition_id,
                "max_amount": max_amount,
            }
        )
    return normalized


def _fee_gas_limit(gas_limit: Optional[int]) -> Optional[int]:
    if gas_limit is None:
        return None
    if isinstance(gas_limit, bool) or not isinstance(gas_limit, int) or gas_limit <= 0:
        raise ValueError("gas_limit must be a positive integer when provided")
    if gas_limit > (1 << 64) - 1:
        raise ValueError("gas_limit exceeds u64")
    return gas_limit


def authority_fee_payment(
    *,
    charge_limits: Sequence[Mapping[str, Any]],
    gas_limit: Optional[int] = None,
) -> Mapping[str, Any]:
    """Build an exact authority-paid ``FeePaymentIntent`` mapping."""

    return {
        "payer": "authority",
        "value": {
            "charge_limits": _fee_charge_limits(charge_limits),
            "gas_limit": _fee_gas_limit(gas_limit),
        },
    }


def sponsor_fee_payment(
    program_id: str,
    program_revision: int,
    *,
    charge_limits: Sequence[Mapping[str, Any]],
    gas_limit: Optional[int] = None,
) -> Mapping[str, Any]:
    """Build a sponsor-paid intent bound to one immutable program revision."""

    literal = _require_exact_non_empty_string(program_id, "program_id")
    sponsor, separator, name = literal.partition("/")
    if separator != "/" or not sponsor or not name or "/" in name:
        raise ValueError("program_id must use the exact sponsor/program form")
    if (
        isinstance(program_revision, bool)
        or not isinstance(program_revision, int)
        or program_revision <= 0
        or program_revision > (1 << 64) - 1
    ):
        raise ValueError("program_revision must be a positive u64 integer")
    return {
        "payer": "sponsor",
        "value": {
            "program_id": {"sponsor": sponsor, "name": name},
            "program_revision": program_revision,
            "charge_limits": _fee_charge_limits(charge_limits),
            "gas_limit": _fee_gas_limit(gas_limit),
        },
    }


def _normalize_rwa_quantity_fields(
    payload: Mapping[str, Any],
    context: str,
    *,
    top_level_quantity: bool,
) -> Dict[str, Any]:
    """Normalize only the nominal quantity fields in one RWA input payload."""

    if not isinstance(payload, Mapping):
        raise TypeError(f"{context} must be a mapping")
    normalized_input: Dict[str, Any] = dict(payload)
    if top_level_quantity and "quantity" in normalized_input:
        normalized_input["quantity"] = _normalize_quantity(normalized_input["quantity"])

    parents = normalized_input.get("parents")
    if parents is not None:
        if isinstance(parents, (str, bytes, bytearray, memoryview)) or not isinstance(
            parents, Sequence
        ):
            raise TypeError(f"{context}.parents must be a sequence")
        normalized_parents: List[Any] = []
        for index, parent in enumerate(parents):
            if not isinstance(parent, Mapping):
                raise TypeError(f"{context}.parents[{index}] must be a mapping")
            normalized_parent = dict(parent)
            if "quantity" in normalized_parent:
                normalized_parent["quantity"] = _normalize_quantity(normalized_parent["quantity"])
            normalized_parents.append(normalized_parent)
        normalized_input["parents"] = normalized_parents

    return _normalize_mapping_payload(normalized_input, context)


class TransactionDraft:
    """Collect ordered executable entries and sign transactions with ergonomic helpers."""

    def __init__(self, config: TransactionConfig):
        if not isinstance(config, TransactionConfig):
            raise TypeError("config must be a TransactionConfig")
        self._config = config
        self._creation_time_ms = _ensure_creation_time_ms(config)
        self._entries: List[TransactionExecutableEntry] = []
        self._explicit_batch = False
        self._lane_privacy_attachments: List[Mapping[str, Any]] = []
        self._privacy_capability_manifest: Optional[
            PrivacyExact12CapabilityManifestV1
        ] = None

    @property
    def config(self) -> TransactionConfig:
        """Return the configuration used by this draft."""

        return self._config

    @property
    def instructions(self) -> Iterable[Instruction]:
        """Iterator over appended instructions."""

        return tuple(entry for entry in self._entries if not isinstance(entry, ContractCall))

    @property
    def entries(self) -> Iterable[TransactionExecutableEntry]:
        """Return the ordered instruction and contract-call entries."""

        return tuple(self._entries)

    def __iter__(self):
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self._entries)

    def add_instruction(self, instruction: Instruction) -> Instruction:
        """Append an existing :class:`Instruction` to the draft."""

        self._entries.append(instruction)
        return instruction

    def update_plain_conviction(
        self,
        referendum_id: str,
        owner: str,
        amount: QuantityLike,
        duration_blocks: int,
    ) -> TransactionDraft:
        """Append a choice-free update for the authority's existing public ballot."""

        referendum_id = _require_exact_non_empty_string(referendum_id, "referendum_id")
        owner = _require_exact_non_empty_string(owner, "owner")
        if owner != self._config.authority:
            raise ValueError("owner must equal the transaction authority")
        duration = _optional_uint(
            duration_blocks,
            "duration_blocks",
            maximum=_U64_MAX,
            allow_zero=True,
        )
        if duration is None:
            raise TypeError("duration_blocks is required")
        self.add_instruction(
            Instruction.update_plain_conviction(
                referendum_id,
                owner,
                _normalize_quantity(amount),
                duration,
            )
        )
        return self

    def extend_instructions(self, instructions: Iterable[Instruction]) -> None:
        """Append multiple instructions in order."""

        for instruction in instructions:
            self.add_instruction(instruction)

    def use_executable_batch(self) -> TransactionDraft:
        """Select batch encoding explicitly, including for instruction-only batches."""

        self._explicit_batch = True
        return self

    def add_contract_call(
        self,
        contract_address: str,
        expected_code_hash_hex: str,
        entrypoint: str,
        arguments: Optional[bytes | bytearray | memoryview] = None,
    ) -> ContractCall:
        """Append a deployed-contract invocation at the current ordered batch position."""

        call = ContractCall(
            contract_address=contract_address,
            expected_code_hash_hex=expected_code_hash_hex,
            entrypoint=entrypoint,
            arguments=arguments,
        )
        self._entries.append(call)
        self._explicit_batch = True
        return call

    def commit_contract_deployment(
        self,
        *,
        expected_deploy_nonce: int,
        contract_address: str,
        code_hash_hex: str,
        contract_alias: str,
        lease_expiry_ms: Optional[int] = None,
        expected_previous_contract_address: Optional[str] = None,
    ) -> Instruction:
        """Append the atomic nonce- and alias-CAS guarded deployment instruction."""

        instruction = Instruction.commit_contract_deployment(
            expected_deploy_nonce,
            contract_address,
            code_hash_hex,
            contract_alias,
            lease_expiry_ms,
            expected_previous_contract_address,
        )
        return self.add_instruction(instruction)

    def clear_instructions(self) -> None:
        """Remove all executable entries from the draft."""

        self._entries.clear()
        self._explicit_batch = False
        self._lane_privacy_attachments.clear()

    def add_lane_privacy_merkle_proof(
        self,
        *,
        commitment_id: int,
        leaf: bytes,
        leaf_index: int,
        audit_path: Iterable[bytes],
        proof_backend: str,
        proof_bytes: bytes,
        verifying_key_name: str,
    ) -> TransactionDraft:
        """Attach a lane privacy Merkle proof used by Nexus commitment-only lanes.

        Parameters mirror :func:`iroha_python.crypto.build_signed_transaction` and are validated
        using the shared normalization helper.
        """

        bounded_audit_path: List[bytes] = []
        for index, sibling in enumerate(audit_path):
            if index >= _LANE_PRIVACY_MAX_MERKLE_DEPTH_V1:
                raise ValueError(
                    "audit_path must contain between 1 and "
                    f"{_LANE_PRIVACY_MAX_MERKLE_DEPTH_V1} siblings"
                )
            bounded_audit_path.append(sibling)
        attachment = _normalize_lane_privacy_attachment(
            {
                "commitment_id": commitment_id,
                "leaf": leaf,
                "leaf_index": leaf_index,
                "audit_path": bounded_audit_path,
                "proof_backend": proof_backend,
                "proof_bytes": proof_bytes,
                "verifying_key_name": verifying_key_name,
            }
        )
        self._lane_privacy_attachments.append(attachment)
        return self

    def clear_lane_privacy_attachments(self) -> None:
        """Remove any staged lane privacy attachments."""

        self._lane_privacy_attachments.clear()

    def bind_privacy_exact12_capability_manifest_v1(
        self,
        manifest: PrivacyExact12CapabilityManifestV1,
    ) -> TransactionDraft:
        """Bind one native-validated Torii manifest to every build of this draft.

        Native privacy construction remains closed until this binding exists;
        it then requires the selected row to be active and its complete
        compiled profile to equal the executing binary. The native manifest must
        come from :meth:`ToriiClient.privacy_capabilities_v1` and be bound to this
        draft's exact network. Offline decoded archives cannot grant admission.
        """

        if not _is_native_crypto_instance(manifest, "PrivacyExact12CapabilityManifestV1"):
            raise TypeError(
                "manifest must be a native PrivacyExact12CapabilityManifestV1"
            )
        if self._privacy_capability_manifest is not None:
            raise ValueError("transaction draft already has an Exact12 manifest binding")
        manifest.require_transaction_network(self._config.network_id)
        self._privacy_capability_manifest = manifest
        return self

    # ------------------------------------------------------------------
    # High-level helpers for common instruction families
    # ------------------------------------------------------------------
    def register_domain(
        self,
        domain_id: str,
        *,
        metadata: MetadataLike = None,
    ) -> TransactionDraft:
        """Append a `RegisterDomain` instruction and return the draft for fluent chaining."""

        metadata_payload = _normalize_metadata(metadata)
        self.add_instruction(Instruction.register_domain(domain_id, metadata_payload))
        return self

    def register_account(
        self,
        account_id: str,
        *,
        metadata: MetadataLike = None,
    ) -> TransactionDraft:
        """Append a `RegisterAccount` instruction."""

        metadata_payload = _normalize_metadata(metadata)
        self.add_instruction(Instruction.register_account(account_id, metadata_payload))
        return self

    def register_rwa(
        self,
        rwa: Mapping[str, Any],
    ) -> TransactionDraft:
        """Append a `RegisterRwa` instruction."""

        rwa_payload = _normalize_rwa_quantity_fields(
            rwa,
            "rwa",
            top_level_quantity=True,
        )
        self.add_instruction(Instruction.register_rwa(rwa_payload))
        return self

    def register_asset_definition(
        self,
        definition_id: str,
        *,
        owning_domain: Optional[str],
        balance_scope_policy: str,
        name: str,
        description: Optional[str] = None,
        alias: Optional[str] = None,
        scale: Optional[Union[int, str]] = None,
        mintable: Optional[str] = None,
        metadata: MetadataLike = None,
    ) -> TransactionDraft:
        """Append an asset definition owned by this transaction's authority."""

        normalized_scale: Optional[int]
        if scale is None:
            normalized_scale = None
        elif isinstance(scale, int):
            normalized_scale = scale
        elif isinstance(scale, str):
            try:
                normalized_scale = int(scale)
            except ValueError as exc:  # pragma: no cover - defensive
                raise ValueError(f"scale '{scale}' must be an integer value") from exc
        else:
            raise TypeError("scale must be an integer or string when provided")

        normalized_owning_domain = (
            None
            if owning_domain is None
            else _require_exact_non_empty_string(owning_domain, "owning_domain")
        )
        if balance_scope_policy not in {"Global", "DataspaceRestricted"}:
            raise ValueError(
                "balance_scope_policy must be Global or DataspaceRestricted"
            )
        if (
            balance_scope_policy == "DataspaceRestricted"
            and normalized_owning_domain is None
        ):
            raise ValueError(
                "owning_domain is required for DataspaceRestricted balances"
            )
        normalized_name = _require_exact_non_empty_string(name, "name")

        metadata_payload = _normalize_metadata(metadata)

        self.add_instruction(
            Instruction.register_asset_definition(
                definition_id,
                owning_domain=normalized_owning_domain,
                name=normalized_name,
                description=description,
                alias=alias,
                scale=normalized_scale,
                mintable=mintable,
                balance_scope_policy=balance_scope_policy,
                metadata=metadata_payload,
            )
        )
        return self

    def register_dataspace_asset_definition(
        self,
        definition_id: str,
        *,
        dataspace_id: int,
        balance_scope_policy: str,
        name: str,
        description: Optional[str] = None,
        alias: Optional[str] = None,
        scale: Optional[Union[int, str]] = None,
        mintable: Optional[str] = None,
        metadata: MetadataLike = None,
    ) -> TransactionDraft:
        """Append a direct-dataspace definition; namespace authority is checked by the ledger."""

        normalized_scale: Optional[int]
        if scale is None:
            normalized_scale = None
        elif isinstance(scale, int):
            normalized_scale = scale
        elif isinstance(scale, str):
            try:
                normalized_scale = int(scale)
            except ValueError as exc:  # pragma: no cover - defensive
                raise ValueError(f"scale '{scale}' must be an integer value") from exc
        else:
            raise TypeError("scale must be an integer or string when provided")

        if isinstance(dataspace_id, bool) or not isinstance(dataspace_id, int):
            raise TypeError("dataspace_id must be an exact integer")
        if not 0 < dataspace_id <= (1 << 64) - 1:
            raise ValueError("dataspace_id must be a nonzero u64")
        if balance_scope_policy not in {"Global", "DataspaceRestricted"}:
            raise ValueError(
                "balance_scope_policy must be Global or DataspaceRestricted"
            )
        normalized_name = _require_exact_non_empty_string(name, "name")

        metadata_payload = _normalize_metadata(metadata)

        self.add_instruction(
            Instruction.register_dataspace_asset_definition(
                definition_id,
                dataspace_id=dataspace_id,
                name=normalized_name,
                description=description,
                alias=alias,
                scale=normalized_scale,
                mintable=mintable,
                balance_scope_policy=balance_scope_policy,
                metadata=metadata_payload,
            )
        )
        return self

    def register_zk_asset(
        self,
        asset_definition_id: str,
        *,
        vk_unshield: Optional[VerifyingKeyLike] = None,
    ) -> TransactionDraft:
        """Append a `RegisterZkAsset` instruction."""

        definition = _require_non_empty_string(
            asset_definition_id,
            "asset_definition_id",
        )
        self.add_instruction(
            Instruction.register_zk_asset(
                definition,
                vk_unshield=vk_unshield,
            )
        )
        return self

    def verify_proof(self, proof: Mapping[str, Any]) -> TransactionDraft:
        """Append a generic `zk::VerifyProof` instruction."""

        if not isinstance(proof, Mapping):
            raise TypeError("proof must be a mapping")
        self.add_instruction(Instruction.verify_proof(dict(proof)))
        return self

    def mint_asset_quantity(self, asset_id: str, quantity: QuantityLike) -> TransactionDraft:
        """Append a nominal-quantity `MintAsset` instruction."""

        normalized_quantity = _normalize_quantity(quantity)
        self.add_instruction(Instruction.mint_asset_quantity(asset_id, normalized_quantity))
        return self

    def burn_asset_quantity(self, asset_id: str, quantity: QuantityLike) -> TransactionDraft:
        """Append a nominal-quantity `BurnAsset` instruction."""

        normalized_quantity = _normalize_quantity(quantity)
        self.add_instruction(Instruction.burn_asset_quantity(asset_id, normalized_quantity))
        return self

    def transfer_asset_quantity(
        self,
        asset_id: str,
        quantity: QuantityLike,
        destination: str,
    ) -> TransactionDraft:
        """Append a nominal-quantity `TransferAsset` instruction."""

        normalized_quantity = _normalize_quantity(quantity)
        self.add_instruction(
            Instruction.transfer_asset_quantity(
                asset_id,
                normalized_quantity,
                destination,
            )
        )
        return self

    def transfer_asset_batch(
        self,
        source_account: str,
        asset_definition_id: str,
        payments: Sequence[Any],
        *,
        mode: Any = "Independent",
    ) -> TransactionDraft:
        """Append one native multi-payment instruction."""

        if isinstance(payments, (str, bytes, bytearray, memoryview)) or not isinstance(
            payments, Sequence
        ):
            raise TypeError("payments must be a sequence")
        normalized_payments: List[Dict[str, str]] = []
        for index, payment in enumerate(payments):
            payment = _payload_mapping(payment, f"payments[{index}]")
            unknown = set(payment).difference({"id", "to", "amount"})
            missing = {"id", "to", "amount"}.difference(payment)
            if unknown or missing:
                raise ValueError(
                    f"payments[{index}] must contain exactly id, to, and amount"
                )
            normalized_payments.append(
                {
                    "id": _require_exact_non_empty_string(
                        payment["id"], f"payments[{index}].id"
                    ),
                    "to": _require_exact_non_empty_string(
                        payment["to"], f"payments[{index}].to"
                    ),
                    "amount": _normalize_positive_quantity(
                        payment["amount"], f"payments[{index}].amount"
                    ),
                }
            )
        mode_value = getattr(mode, "value", mode)
        self.add_instruction(
            Instruction.transfer_asset_batch(
                _require_exact_non_empty_string(source_account, "source_account"),
                _require_exact_non_empty_string(
                    asset_definition_id, "asset_definition_id"
                ),
                json.dumps(normalized_payments, separators=(",", ":"), sort_keys=True),
                mode=_require_exact_non_empty_string(mode_value, "mode"),
            )
        )
        return self

    def set_asset_transfer_availability(
        self,
        account_id: str,
        asset_definition_id: str,
        expected_revision: int,
        incoming: Union[AssetTransferAvailability, str],
        outgoing: Union[AssetTransferAvailability, str],
        *,
        reason: Optional[str] = None,
    ) -> TransactionDraft:
        """Atomically update incoming and outgoing availability using revision CAS."""

        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
            or expected_revision > (1 << 64) - 1
        ):
            raise ValueError("expected_revision must be an unsigned 64-bit integer")
        normalized_reason = (
            _normalize_asset_transfer_availability_reason(reason)
            if reason is not None
            else None
        )
        self.add_instruction(
            Instruction.set_asset_transfer_availability(
                _require_exact_non_empty_string(account_id, "account_id"),
                _require_exact_non_empty_string(asset_definition_id, "asset_definition_id"),
                expected_revision,
                _normalize_asset_transfer_availability(incoming, "incoming"),
                _normalize_asset_transfer_availability(outgoing, "outgoing"),
                reason=normalized_reason,
            )
        )
        return self

    def set_asset_transfer_blacklist(
        self,
        account_id: str,
        asset_definition_id: str,
        blacklisted: bool,
    ) -> TransactionDraft:
        """Blacklist or restore outbound transfers for one account and asset."""

        if not isinstance(blacklisted, bool):
            raise TypeError("blacklisted must be a bool")
        self.add_instruction(
            Instruction.set_asset_transfer_blacklist(
                _require_exact_non_empty_string(account_id, "account_id"),
                _require_exact_non_empty_string(asset_definition_id, "asset_definition_id"),
                blacklisted,
            )
        )
        return self

    def set_asset_transfer_control(
        self,
        account_id: str,
        asset_definition_id: str,
        limits: Sequence[Mapping[str, Any]],
    ) -> TransactionDraft:
        """Replace native DAY/WEEK/MONTH outbound caps for one account and asset."""

        self.add_instruction(
            Instruction.set_asset_transfer_control(
                _require_exact_non_empty_string(account_id, "account_id"),
                _require_exact_non_empty_string(asset_definition_id, "asset_definition_id"),
                _normalize_asset_transfer_limits(limits),
            )
        )
        return self

    def set_asset_holding_limit(
        self,
        account_id: str,
        asset_definition_id: str,
        holding_limit: Optional[QuantityLike],
    ) -> TransactionDraft:
        """Set or clear the maximum balance an account may hold for one asset."""

        self.add_instruction(
            Instruction.set_asset_holding_limit(
                _require_exact_non_empty_string(account_id, "account_id"),
                _require_exact_non_empty_string(asset_definition_id, "asset_definition_id"),
                (_normalize_quantity(holding_limit) if holding_limit is not None else None),
            )
        )
        return self

    def open_asset_lock(
        self,
        escrow_id: str,
        asset_definition_id: str,
        destination: str,
        amount: QuantityLike,
        *,
        release_authority: Optional[str] = None,
        expires_at_ms: Optional[int] = None,
        evidence_hashes: Optional[Sequence[FixedBytesLike]] = None,
    ) -> TransactionDraft:
        """Append an `OpenAssetLock` instruction."""

        self.add_instruction(
            Instruction.open_asset_lock(
                _require_non_empty_string(escrow_id, "escrow_id"),
                _require_non_empty_string(asset_definition_id, "asset_definition_id"),
                _require_non_empty_string(destination, "destination"),
                _normalize_positive_quantity(amount, "amount"),
                release_authority=(
                    _require_non_empty_string(release_authority, "release_authority")
                    if release_authority is not None
                    else None
                ),
                expires_at_ms=expires_at_ms,
                evidence_hashes=list(evidence_hashes or []),
            )
        )
        return self

    def open_conditional_escrow(
        self,
        escrow_id: str,
        asset_definition_id: str,
        beneficiary: str,
        amount: QuantityLike,
        conditions: Sequence[Any],
        expires_at_ms: int,
        *,
        evidence_digests: Optional[Sequence[FixedBytesLike]] = None,
    ) -> TransactionDraft:
        """Append an ordered native ``OpenConditionalEscrow`` instruction."""

        if isinstance(conditions, (str, bytes, bytearray, memoryview)):
            raise TypeError("conditions must be a sequence")
        normalized_conditions = [
            dict(
                _normalize_mapping_payload(
                    _payload_mapping(condition, f"conditions[{index}]"),
                    f"conditions[{index}]",
                )
            )
            for index, condition in enumerate(conditions)
        ]
        if not normalized_conditions:
            raise ValueError("conditions must not be empty")
        if isinstance(expires_at_ms, bool) or not isinstance(expires_at_ms, int):
            raise TypeError("expires_at_ms must be a positive integer")
        if expires_at_ms <= 0:
            raise ValueError("expires_at_ms must be a positive integer")
        self.add_instruction(
            Instruction.open_conditional_escrow(
                _require_exact_non_empty_string(escrow_id, "escrow_id"),
                _require_exact_non_empty_string(
                    asset_definition_id,
                    "asset_definition_id",
                ),
                _require_exact_non_empty_string(beneficiary, "beneficiary"),
                _normalize_positive_quantity(amount, "amount"),
                normalized_conditions,
                expires_at_ms,
                evidence_digests=list(evidence_digests or []),
            )
        )
        return self

    def attest_escrow_condition(
        self,
        escrow_id: str,
        condition_id: str,
        value: Any,
        *,
        evidence_digest: Optional[FixedBytesLike] = None,
    ) -> TransactionDraft:
        """Append an ordered native ``AttestEscrowCondition`` instruction."""

        self.add_instruction(
            Instruction.attest_escrow_condition(
                _require_exact_non_empty_string(escrow_id, "escrow_id"),
                _require_exact_non_empty_string(condition_id, "condition_id"),
                dict(_normalize_mapping_payload(_payload_mapping(value, "value"), "value")),
                evidence_digest=evidence_digest,
            )
        )
        return self

    def expire_conditional_escrow(self, escrow_id: str) -> TransactionDraft:
        """Append a native ``ExpireConditionalEscrow`` refund instruction."""

        self.add_instruction(
            Instruction.expire_conditional_escrow(
                _require_exact_non_empty_string(escrow_id, "escrow_id")
            )
        )
        return self

    def drawdown_asset_lock(
        self,
        escrow_id: str,
        amount: QuantityLike,
        expected_remaining_amount: QuantityLike,
    ) -> TransactionDraft:
        """Append a compare-and-draw `DrawdownAssetLock` instruction."""

        self.add_instruction(
            Instruction.drawdown_asset_lock(
                _require_non_empty_string(escrow_id, "escrow_id"),
                _normalize_positive_quantity(amount, "amount"),
                _normalize_positive_quantity(
                    expected_remaining_amount,
                    "expected_remaining_amount",
                ),
            )
        )
        return self

    def cancel_asset_lock(
        self,
        escrow_id: str,
        expected_remaining_amount: QuantityLike,
    ) -> TransactionDraft:
        """Append cancellation from an exact, bounded lock-ID preimage."""

        self.add_instruction(
            Instruction.cancel_asset_lock(
                _require_exact_non_empty_string(escrow_id, "escrow_id"),
                _normalize_positive_quantity(
                    expected_remaining_amount,
                    "expected_remaining_amount",
                ),
            )
        )
        return self

    def expire_asset_lock(self, escrow_id: str) -> TransactionDraft:
        """Append an `ExpireAssetLock` instruction."""

        self.add_instruction(
            Instruction.expire_asset_lock(_require_non_empty_string(escrow_id, "escrow_id"))
        )
        return self

    def grant_account_permission(
        self,
        destination: str,
        name: str,
        *,
        payload: Any = None,
    ) -> TransactionDraft:
        """Append a `Grant::Permission` instruction for an account."""

        destination = _require_non_empty_string(destination, "destination")
        name = _require_non_empty_string(name, "permission name")
        self.add_instruction(
            Instruction.grant_account_permission(destination, name, payload=payload)
        )
        return self

    def revoke_account_permission(
        self,
        destination: str,
        name: str,
        *,
        payload: Any = None,
    ) -> TransactionDraft:
        """Append a `Revoke::Permission` instruction for an account."""

        destination = _require_non_empty_string(destination, "destination")
        name = _require_non_empty_string(name, "permission name")
        self.add_instruction(
            Instruction.revoke_account_permission(destination, name, payload=payload)
        )
        return self

    def repo_initiate(
        self,
        agreement_id: str,
        initiator: str,
        counterparty: str,
        cash_leg: "RepoCashLeg",
        collateral_leg: "RepoCollateralLeg",
        *,
        custodian: Optional[str] = None,
        rate_bps: int,
        maturity_timestamp_ms: int,
        governance: Optional["RepoGovernance"] = None,
    ) -> TransactionDraft:
        """Append a `RepoIsi` instruction for repo initiation or rolling."""

        governance = governance or RepoGovernance(haircut_bps=0, margin_frequency_secs=0)
        cash_payload: Dict[str, Any] = {
            "asset_definition_id": cash_leg.asset_definition_id,
            "quantity": _normalize_quantity(cash_leg.quantity),
        }
        collateral_payload: Dict[str, Any] = {
            "asset_definition_id": collateral_leg.asset_definition_id,
            "quantity": _normalize_quantity(collateral_leg.quantity),
        }
        if collateral_leg.metadata:
            collateral_payload["metadata"] = _normalize_metadata(collateral_leg.metadata)

        governance_payload = {
            "haircut_bps": int(governance.haircut_bps),
            "margin_frequency_secs": int(governance.margin_frequency_secs),
        }

        instruction = Instruction.repo_initiate(
            agreement_id,
            initiator,
            counterparty,
            custodian,
            cash_payload,
            collateral_payload,
            int(rate_bps),
            int(maturity_timestamp_ms),
            governance_payload,
        )
        self.add_instruction(instruction)
        return self

    def repo_unwind(
        self,
        agreement_id: str,
    ) -> TransactionDraft:
        """Settle a repo using only its immutable on-chain maturity terms."""

        instruction = Instruction.repo_unwind(agreement_id)
        self.add_instruction(instruction)
        return self

    def repo_margin_call(self, agreement_id: str) -> TransactionDraft:
        """Append a `RepoMarginCallIsi` instruction to record a margin check."""

        instruction = Instruction.repo_margin_call(agreement_id)
        self.add_instruction(instruction)
        return self

    def set_account_key_value(
        self,
        key: str,
        value: Any,
        *,
        account_id: Optional[str] = None,
    ) -> TransactionDraft:
        """Append a `SetKeyValue` instruction targeting an account.

        When ``account_id`` is omitted, the draft authority is used.
        """

        target = account_id or self._config.authority
        self.add_instruction(Instruction.set_account_key_value(target, key, value))
        return self

    def remove_account_key_value(
        self,
        key: str,
        *,
        account_id: Optional[str] = None,
    ) -> TransactionDraft:
        """Append a `RemoveKeyValue` instruction targeting an account.

        When ``account_id`` is omitted, the draft authority is used.
        """

        target = account_id or self._config.authority
        self.add_instruction(Instruction.remove_account_key_value(target, key))
        return self

    def transfer_domain(
        self,
        domain_id: str,
        *,
        destination: str,
        source: Optional[str] = None,
    ) -> TransactionDraft:
        """Append a `TransferDomain` instruction."""

        origin = source or self._config.authority
        self.add_instruction(Instruction.transfer_domain(origin, domain_id, destination))
        return self

    def transfer_asset_definition(
        self,
        definition_id: str,
        *,
        destination: str,
        source: Optional[str] = None,
    ) -> TransactionDraft:
        """Append a `TransferAssetDefinition` instruction."""

        origin = source or self._config.authority
        self.add_instruction(
            Instruction.transfer_asset_definition(origin, definition_id, destination)
        )
        return self

    def transfer_nft(
        self,
        nft_id: str,
        *,
        destination: str,
        source: Optional[str] = None,
    ) -> TransactionDraft:
        """Append a `TransferNft` instruction."""

        origin = source or self._config.authority
        self.add_instruction(Instruction.transfer_nft(origin, nft_id, destination))
        return self

    def transfer_rwa(
        self,
        rwa_id: str,
        *,
        quantity: QuantityLike,
        destination: str,
        source: Optional[str] = None,
    ) -> TransactionDraft:
        """Append a `TransferRwa` instruction."""

        origin = source or self._config.authority
        normalized_quantity = _normalize_quantity(quantity)
        self.add_instruction(
            Instruction.transfer_rwa(origin, rwa_id, normalized_quantity, destination)
        )
        return self

    def merge_rwas(
        self,
        merge: Mapping[str, Any],
    ) -> TransactionDraft:
        """Append a `MergeRwas` instruction."""

        merge_payload = _normalize_rwa_quantity_fields(
            merge,
            "merge",
            top_level_quantity=False,
        )
        self.add_instruction(Instruction.merge_rwas(merge_payload))
        return self

    def redeem_rwa(
        self,
        rwa_id: str,
        *,
        quantity: QuantityLike,
    ) -> TransactionDraft:
        """Append a `RedeemRwa` instruction."""

        normalized_quantity = _normalize_quantity(quantity)
        self.add_instruction(Instruction.redeem_rwa(rwa_id, normalized_quantity))
        return self

    def freeze_rwa(self, rwa_id: str) -> TransactionDraft:
        """Append a `FreezeRwa` instruction."""

        self.add_instruction(Instruction.freeze_rwa(rwa_id))
        return self

    def unfreeze_rwa(self, rwa_id: str) -> TransactionDraft:
        """Append an `UnfreezeRwa` instruction."""

        self.add_instruction(Instruction.unfreeze_rwa(rwa_id))
        return self

    def hold_rwa(
        self,
        rwa_id: str,
        *,
        quantity: QuantityLike,
    ) -> TransactionDraft:
        """Append a `HoldRwa` instruction."""

        normalized_quantity = _normalize_quantity(quantity)
        self.add_instruction(Instruction.hold_rwa(rwa_id, normalized_quantity))
        return self

    def release_rwa(
        self,
        rwa_id: str,
        *,
        quantity: QuantityLike,
    ) -> TransactionDraft:
        """Append a `ReleaseRwa` instruction."""

        normalized_quantity = _normalize_quantity(quantity)
        self.add_instruction(Instruction.release_rwa(rwa_id, normalized_quantity))
        return self

    def force_transfer_rwa(
        self,
        rwa_id: str,
        *,
        quantity: QuantityLike,
        destination: str,
    ) -> TransactionDraft:
        """Append a `ForceTransferRwa` instruction."""

        normalized_quantity = _normalize_quantity(quantity)
        self.add_instruction(
            Instruction.force_transfer_rwa(rwa_id, normalized_quantity, destination)
        )
        return self

    def set_rwa_controls(
        self,
        rwa_id: str,
        controls: Mapping[str, Any],
    ) -> TransactionDraft:
        """Append a `SetRwaControls` instruction."""

        controls_payload = _normalize_mapping_payload(controls, "controls")
        self.add_instruction(Instruction.set_rwa_controls(rwa_id, controls_payload))
        return self

    def set_rwa_key_value(
        self,
        rwa_id: str,
        key: str,
        value: Any,
    ) -> TransactionDraft:
        """Append a `SetRwaKeyValue` instruction."""

        normalized_value = _normalize_json_value(value, "value")
        self.add_instruction(Instruction.set_rwa_key_value(rwa_id, key, normalized_value))
        return self

    def remove_rwa_key_value(
        self,
        rwa_id: str,
        key: str,
    ) -> TransactionDraft:
        """Append a `RemoveRwaKeyValue` instruction."""

        self.add_instruction(Instruction.remove_rwa_key_value(rwa_id, key))
        return self

    def settlement_dvp(
        self,
        settlement_id: str,
        delivery_leg: SettlementLeg,
        payment_leg: SettlementLeg,
        *,
        plan: Optional[SettlementPlan] = None,
        metadata: MetadataLike = None,
    ) -> TransactionDraft:
        """Append a delivery-versus-payment settlement instruction."""

        effective_plan = plan or SettlementPlan()
        metadata_payload = _normalize_metadata(metadata) if metadata is not None else None
        instruction = Instruction.settlement_dvp(
            settlement_id,
            delivery_leg.to_payload(),
            payment_leg.to_payload(),
            order=effective_plan.order.value,
            atomicity=effective_plan.atomicity.value,
            metadata=metadata_payload,
        )
        self.add_instruction(instruction)
        return self

    def settlement_pvp(
        self,
        settlement_id: str,
        primary_leg: SettlementLeg,
        counter_leg: SettlementLeg,
        *,
        plan: Optional[SettlementPlan] = None,
        metadata: MetadataLike = None,
    ) -> TransactionDraft:
        """Append a payment-versus-payment settlement instruction."""

        effective_plan = plan or SettlementPlan()
        metadata_payload = _normalize_metadata(metadata) if metadata is not None else None
        instruction = Instruction.settlement_pvp(
            settlement_id,
            primary_leg.to_payload(),
            counter_leg.to_payload(),
            order=effective_plan.order.value,
            atomicity=effective_plan.atomicity.value,
            metadata=metadata_payload,
        )
        self.add_instruction(instruction)
        return self

    # ------------------------------------------------------------------
    # Signing helpers
    # ------------------------------------------------------------------
    def sign(
        self,
        private_key: bytes,
    ) -> SignedTransactionEnvelope:
        """Sign exactly the state staged on this draft."""

        if type(private_key) is not bytes:
            raise TypeError("private_key must be exact immutable bytes")
        if len(private_key) != 32:
            raise ValueError("private_key must contain exactly 32 bytes")
        if self._explicit_batch:
            payload_instructions = None
            payload_entries = list(self._entries)
        else:
            payload_instructions = list(self.instructions)
            payload_entries = None
        return build_signed_transaction(
            self._config.network_id,
            self._config.authority,
            private_key,
            fee_payment=_thaw_json(self._config.fee_payment),
            instructions=payload_instructions,
            entries=payload_entries,
            creation_time_ms=self._creation_time_ms,
            ttl_ms=self._config.ttl_ms,
            nonce=self._config.nonce,
            metadata=(
                None
                if self._config.metadata is None
                else _thaw_json(self._config.metadata)
            ),
            lane_privacy_attachments=self._lane_privacy_attachments,
        )

    def prepare_privacy_zk_x509_identity_presentation_action_v1(
        self,
        *,
        canonical_statement_archive: bytes,
    ) -> bytes:
        """Freeze a draft X509 statement and return its transaction intent.

        The draft's typed ``NetworkId`` selects the exact transaction network.
        ``canonical_statement_archive`` must contain the native typed X509
        statement with a zero transaction-intent field. The returned digest is
        the exact intent that an isolated credential prover must bind into the
        finalized statement and ``X5S1`` proof container.
        """

        if self._explicit_batch or self._entries or self._lane_privacy_attachments:
            raise ValueError(
                "native ZK-X509 presentation action requires an otherwise "
                "empty transaction draft"
            )
        return bytes(
            self.to_builder().prepare_privacy_zk_x509_identity_presentation_action_v1(
                canonical_statement_archive,
            )
        )

    def sign_privacy_zk_x509_identity_presentation_action_v1(
        self,
        private_key: bytes,
        *,
        canonical_statement_archive: bytes,
        credential_proof: bytes,
    ) -> PrivacyNativeActionBuildResultV1:
        """Validate and sign one worker-produced ZK-X509 presentation action.

        The native signer accepts only a canonical, intent-bound typed
        statement and an exact ``X5S1`` credential proof whose public header is
        bound to the draft's exact ``NetworkId``. Certificate, CRL, and witness
        material stays in the isolated prover and never enters this draft.
        Signing fails closed until the production compiled profile has passed
        its release-readiness gates; unsigned candidate material is not enough.
        """

        if self._explicit_batch or self._entries or self._lane_privacy_attachments:
            raise ValueError(
                "native ZK-X509 presentation action requires an otherwise "
                "empty transaction draft"
            )
        return self.to_builder().sign_privacy_zk_x509_identity_presentation_action_v1(
            private_key,
            canonical_statement_archive,
            credential_proof,
        )

    def sign_with_keypair(
        self,
        keypair: Ed25519KeyPair,
    ) -> SignedTransactionEnvelope:
        """Sign using an :class:`Ed25519KeyPair`."""

        return self.sign(keypair.private_key)

    def sign_hex_private_key(
        self,
        private_key_hex: str,
    ) -> SignedTransactionEnvelope:
        """Sign using a hex-encoded private key string."""

        return self.sign(Ed25519KeyPair.from_private_key_hex(private_key_hex).private_key)

    def sign_and_submit(
        self,
        client: "ToriiClient",
        private_key: bytes,
    ) -> tuple[SignedTransactionEnvelope, Any]:
        """Sign the draft and submit it via the provided :class:`ToriiClient`."""

        envelope = self.sign(private_key)
        status = client.submit_transaction_envelope(envelope)
        return envelope, status

    def quote_and_sign(
        self,
        client: "ToriiClient",
        private_key: bytes,
    ) -> tuple[SignedTransactionEnvelope, Mapping[str, Any]]:
        """Quote and sign one exact unsigned payload without rebuilding it.

        The draft fixes the payer (including an exact sponsor program revision)
        and executable gas bound. Torii may return updated charge maxima; the
        native signer rejects payer, revision, or gas substitution.
        """

        builder = self.to_builder()
        draft_payload_json = builder.payload_json()
        draft_payload = json.loads(draft_payload_json)
        from iroha_torii_client.client import (
            ToriiCanonicalRequestAuth,
            validate_fee_quote_response_for_draft,
        )

        keypair = Ed25519KeyPair.from_private_key(private_key)
        authority = draft_payload.get("authority")
        if not isinstance(authority, str) or not authority:
            raise RuntimeError("exact transaction draft is missing its canonical authority")
        quote = client.quote_fees(
            draft_payload,
            canonical_auth=ToriiCanonicalRequestAuth(
                network_id=self._config.network_id.literal,
                account_id=authority,
                signer=keypair.sign,
            ),
        )
        quote = validate_fee_quote_response_for_draft(draft_payload, quote)
        intent = quote.get("intent")
        if not isinstance(intent, Mapping):
            raise RuntimeError("fee quote response is missing an intent object")
        envelope = builder.sign_quoted_payload(
            draft_payload_json,
            json.dumps(intent, separators=(",", ":")),
            private_key,
        )
        return envelope, quote

    def sign_hex_and_submit(
        self,
        client: "ToriiClient",
        private_key_hex: str,
    ) -> tuple[SignedTransactionEnvelope, Any]:
        """Sign using a hex-encoded key and submit the transaction."""

        return self.sign_and_submit(
            client,
            Ed25519KeyPair.from_private_key_hex(private_key_hex).private_key,
        )

    def to_builder(self) -> TransactionBuilder:
        """Return a :class:`TransactionBuilder` populated with the draft state."""

        builder = TransactionBuilder(
            self._config.network_id,
            self._config.authority,
            json.dumps(_thaw_json(self._config.fee_payment), separators=(",", ":")),
        )
        if self._privacy_capability_manifest is not None:
            builder.bind_privacy_exact12_capability_manifest_v1(
                self._privacy_capability_manifest
            )
        builder.set_creation_time_ms(self._creation_time_ms)
        if self._config.ttl_ms is not None:
            builder.set_ttl_ms(int(self._config.ttl_ms))
        if self._config.nonce is not None:
            builder.set_nonce(int(self._config.nonce))
        if self._config.metadata is not None:
            builder.set_metadata(_thaw_json(self._config.metadata))
        if self._explicit_batch:
            builder.use_executable_batch()
        for entry in self._entries:
            if isinstance(entry, ContractCall):
                builder.add_contract_call(
                    entry.contract_address,
                    entry.expected_code_hash_hex,
                    entry.entrypoint,
                    entry.arguments,
                )
            else:
                builder.add_instruction(entry)
        for entry in self._lane_privacy_attachments:
            normalized = _normalize_lane_privacy_attachment(entry)
            builder.add_lane_privacy_merkle_attachment(
                normalized["commitment_id"],
                normalized["leaf"],
                normalized["leaf_index"],
                normalized["audit_path"],
                normalized["proof_backend"],
                normalized["proof_bytes"],
                normalized["verifying_key_name"],
            )
        return builder

    # ------------------------------------------------------------------
    # Manifest helpers
    # ------------------------------------------------------------------
    def to_manifest_dict(
        self,
        *,
        include_creation_time: bool = False,
        include_metadata: bool = True,
    ) -> Mapping[str, Any]:
        """Return a JSON-serialisable manifest describing the draft.

        Parameters
        ----------
        include_creation_time:
            When ``True`` the manifest includes ``creation_time_ms`` using the deterministic
            timestamp derived from :class:`TransactionConfig`. By default the field is omitted
            unless the configuration already provides an explicit value.
        include_metadata:
            When ``True`` (default) the manifest embeds the configured metadata. Disable when
            callers intend to redact metadata before serialising the manifest.
        """

        manifest: dict[str, Any] = {
            "network_id": self._config.network_id.literal,
            "authority": self._config.authority,
        }
        if self._explicit_batch:
            manifest["entries"] = [
                {
                    "ContractCall": {
                        "contract_address": entry.contract_address,
                        "expected_code_hash": entry.expected_code_hash_hex,
                        "entrypoint": entry.entrypoint,
                        "arguments": None if entry.arguments is None else list(entry.arguments),
                    }
                }
                if isinstance(entry, ContractCall)
                else {"Instruction": json.loads(entry.to_json())}
                for entry in self._entries
            ]
        else:
            manifest["instructions"] = [
                json.loads(instruction.to_json()) for instruction in self.instructions
            ]

        if include_metadata and self._config.metadata is not None:
            manifest["metadata"] = _normalize_metadata(self._config.metadata)
        if self._config.ttl_ms is not None:
            manifest["ttl_ms"] = int(self._config.ttl_ms)
        if self._config.nonce is not None:
            manifest["nonce"] = int(self._config.nonce)

        creation_time_ms = (
            self._creation_time_ms
            if include_creation_time
            else self._config.creation_time_ms
        )
        if creation_time_ms is not None:
            manifest["creation_time_ms"] = int(creation_time_ms)

        return manifest

    def to_manifest_json(
        self,
        *,
        include_creation_time: bool = False,
        include_metadata: bool = True,
        indent: Optional[int] = None,
    ) -> str:
        """Serialise :meth:`to_manifest_dict` as a JSON string."""

        manifest = self.to_manifest_dict(
            include_creation_time=include_creation_time,
            include_metadata=include_metadata,
        )
        return json.dumps(manifest, indent=indent, separators=None if indent else (",", ":"))

    # ------------------------------------------------------------------
    # Convenience factory
    # ------------------------------------------------------------------
