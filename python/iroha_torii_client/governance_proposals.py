"""Closed typed readers for the first-release governance proposal surface."""

from __future__ import annotations

import base64
import re
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum
from typing import Any, Optional, Union, cast

from ._account_id import decode_canonical_i105_account_id
from ._canonical_values import _canonical_quantity, _offline_canonical_asset_definition_id

_U64_MAX = (1 << 64) - 1
_JSON_SAFE_UINT_MAX = (1 << 53) - 1
_BECH32M_CONST = 0x2BC830A3
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_KEBAB = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_SCCP_GOVERNANCE_MAX_ACTIONS = 16


def _exact(value: Any, fields: frozenset[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise TypeError(f"{context} must be an object with string field names")
    actual = set(value)
    if actual != fields:
        missing = sorted(fields - actual)
        unknown = sorted(actual - fields)
        if missing:
            raise TypeError(f"{context} is missing required field `{missing[0]}`")
        raise TypeError(f"{context} contains unknown field `{unknown[0]}`")
    return value


def _string(value: Any, context: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or value != value.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise TypeError(f"{context} must be exact text without surrounding whitespace")
    if nonempty and not value:
        raise TypeError(f"{context} must be non-empty")
    return value


def _uint(value: Any, context: str, maximum: int = _U64_MAX, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise TypeError(f"{context} must be an integer in {minimum}..{maximum}")
    return value


def _decimal_u64(value: Any, context: str, *, positive: bool = False) -> int:
    pattern = r"[1-9][0-9]*" if positive else r"(?:0|[1-9][0-9]*)"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise TypeError(f"{context} must be a canonical unsigned decimal string")
    parsed = int(value)
    if parsed > _U64_MAX:
        raise TypeError(f"{context} must fit in u64")
    return parsed


def _numeric(value: Any, context: str) -> str:
    try:
        return _canonical_quantity(value, context)
    except RuntimeError as exc:
        raise TypeError(str(exc)) from exc

def _lower_hex32(value: Any, context: str, *, nonzero: bool = False) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise TypeError(f"{context} must be exactly 32 lowercase hexadecimal bytes")
    if nonzero and set(value) == {"0"}:
        raise TypeError(f"{context} must be non-zero")
    return value


def _upper_hex32(value: Any, context: str, *, nonzero: bool = False) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9A-F]{64}", value) is None:
        raise TypeError(f"{context} must be exactly 32 uppercase hexadecimal bytes")
    if nonzero and set(value) == {"0"}:
        raise TypeError(f"{context} must be non-zero")
    return value


def _bytes32(value: Any, context: str, *, nonzero: bool = False) -> tuple[int, ...]:
    if not isinstance(value, list) or len(value) != 32:
        raise TypeError(f"{context} must be an exact 32-byte JSON array")
    result = tuple(_uint(byte, f"{context}[{index}]", 255) for index, byte in enumerate(value))
    if nonzero and not any(result):
        raise TypeError(f"{context} must be non-zero")
    return result


def _proposal_exact_json_uint(
    value: Any,
    context: str,
    *,
    positive: bool = False,
) -> int:
    """Apply the Torii first-release exact public-JSON integer invariant."""

    return _uint(value, context, _JSON_SAFE_UINT_MAX, positive=positive)


def _provider_id(value: Any, context: str) -> tuple[int, ...]:
    if not isinstance(value, list) or len(value) != 1:
        raise TypeError(f"{context} must be the exact one-field ProviderId tuple")
    return _bytes32(value[0], f"{context}[0]", nonzero=True)


def _string_tuple(value: Any, context: str) -> str:
    if not isinstance(value, list) or len(value) != 1:
        raise TypeError(f"{context} must be the exact one-field string tuple")
    return _string(value[0], f"{context}[0]")


def _ascii_kebab(value: str, context: str, maximum: int) -> str:
    if len(value.encode("utf-8")) > maximum or _KEBAB.fullmatch(value) is None:
        raise TypeError(f"{context} must be canonical lowercase ASCII kebab text")
    return value


def _iroha_name(value: Any, context: str) -> str:
    literal = _string(value, context)
    forbidden = {"@", "#", "$"}
    if (
        len(literal.encode("utf-8")) > 255
        or unicodedata.normalize("NFC", literal) != literal
        or any(
            char.isspace()
            or char in forbidden
            or unicodedata.category(char) == "Cc"
            for char in literal
        )
    ):
        raise TypeError(f"{context} must be a canonical Iroha Name")
    return literal


def _crc16(value: bytes) -> int:
    crc = 0xFFFF
    for byte in value:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _network_id(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a canonical NetworkId")
    match = re.fullmatch(r"hash:([0-9A-F]{64})#([0-9A-F]{4})", value)
    if match is None:
        raise TypeError(f"{context} must use canonical hash:<uppercase hex>#<CRC16> syntax")
    body, checksum = match.groups()
    if _crc16(f"hash:{body}".encode("ascii")) != int(checksum, 16) or int(body[-2:], 16) & 1 == 0:
        raise TypeError(f"{context} is not a canonical Iroha hash")
    return value


def _bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    check = 1
    for value in values:
        top = check >> 25
        check = ((check & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                check ^= generator
    return check


def _contract_address(value: Any, context: str) -> str:
    literal = _string(value, context)
    if literal != literal.lower() or not literal.startswith("irohac1"):
        raise TypeError(f"{context} must be a canonical lowercase irohac Bech32m address")
    data_text = literal[7:]
    try:
        data = [_BECH32_CHARSET.index(char) for char in data_text]
    except ValueError as exc:
        raise TypeError(f"{context} contains a non-Bech32 character") from exc
    hrp = "irohac"
    expanded = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]
    if len(data) < 7 or _bech32_polymod(expanded + data) != _BECH32M_CONST:
        raise TypeError(f"{context} has an invalid Bech32m checksum")
    accumulator = 0
    bits = 0
    decoded = bytearray()
    for digit in data[:-6]:
        accumulator = (accumulator << 5) | digit
        bits += 5
        while bits >= 8:
            bits -= 8
            decoded.append((accumulator >> bits) & 255)
    if bits >= 5 or (accumulator & ((1 << bits) - 1)) != 0 or len(decoded) != 29 or decoded[0] != 1:
        raise TypeError(f"{context} is not a canonical V1 contract address")
    return literal


def _account_id(value: Any, context: str) -> str:
    literal = _string(value, context)
    if "@" in literal:
        raise TypeError(f"{context} must be an exact canonical I105 account id")
    try:
        decode_canonical_i105_account_id(literal)
    except ValueError as exc:
        raise TypeError(f"{context} must be an exact canonical I105 account id") from exc
    return literal


def _asset_definition_id(value: Any, context: str) -> str:
    literal = _string(value, context)
    try:
        return _offline_canonical_asset_definition_id(literal, context)
    except RuntimeError as exc:
        raise TypeError(str(exc)) from exc

def _canonical_base64(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be canonical padded base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise TypeError(f"{context} must be canonical padded base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise TypeError(f"{context} must be canonical padded base64")
    return value


@dataclass(frozen=True)
class GovernanceCanonicalObject(Mapping[str, Any]):
    """Recursively immutable object after variant-specific shape validation."""

    entries: tuple[tuple[str, Any], ...]

    def __getitem__(self, key: str) -> Any:
        for name, value in self.entries:
            if name == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (name for name, _ in self.entries)

    def __len__(self) -> int:
        return len(self.entries)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical governance objects require string field names")
        return GovernanceCanonicalObject(tuple((key, _freeze(entry)) for key, entry in value.items()))
    if isinstance(value, list):
        return tuple(_freeze(entry) for entry in value)
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise TypeError("governance payload contains a non-JSON value")


@dataclass(frozen=True)
class GovernanceManifestProvenance:
    """One exact public manifest signature."""

    signer: str
    signature: str

    @classmethod
    def from_payload(cls, value: Any, context: str) -> "GovernanceManifestProvenance":
        record = _exact(value, frozenset({"signer", "signature"}), context)
        return cls(_string(record["signer"], f"{context}.signer"), _string(record["signature"], f"{context}.signature"))


@dataclass(frozen=True)
class GovernanceProposalDeployContract:
    """Canonical `DeployContractProposal` payload."""

    contract_address: str
    code_hash: str
    abi_hash: str
    abi_version: int
    manifest_provenance: Optional[GovernanceManifestProvenance]

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalDeployContract":
        context = "DeployContract payload"
        record = _exact(value, frozenset({"contract_address", "code_hash", "abi_hash", "abi_version", "manifest_provenance"}), context)
        abi_version = _uint(record["abi_version"], f"{context}.abi_version", 0xFFFF, positive=True)
        if abi_version != 1:
            raise TypeError(f"{context}.abi_version must be the integer 1")
        provenance = None if record["manifest_provenance"] is None else GovernanceManifestProvenance.from_payload(record["manifest_provenance"], f"{context}.manifest_provenance")
        return cls(_contract_address(record["contract_address"], f"{context}.contract_address"), _lower_hex32(record["code_hash"], f"{context}.code_hash"), _lower_hex32(record["abi_hash"], f"{context}.abi_hash"), abi_version, provenance)


@dataclass(frozen=True)
class GovernanceRuntimeUpgradeManifest:
    """Complete canonical first-release runtime-upgrade manifest."""

    name: str
    description: str
    abi_version: int
    abi_hash: tuple[int, ...]
    added_syscalls: tuple[int, ...]
    added_pointer_types: tuple[int, ...]
    start_height: int
    end_height: int
    sbom_digests: tuple[GovernanceCanonicalObject, ...]
    slsa_attestation: str
    provenance: tuple[GovernanceManifestProvenance, ...]

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceRuntimeUpgradeManifest":
        context = "RuntimeUpgrade payload.manifest"
        fields = frozenset({"name", "description", "abi_version", "abi_hash", "added_syscalls", "added_pointer_types", "start_height", "end_height", "sbom_digests", "slsa_attestation", "provenance"})
        record = _exact(value, fields, context)
        abi = _uint(record["abi_version"], f"{context}.abi_version", 0xFFFF, positive=True)
        if abi != 1 or record["added_syscalls"] != [] or record["added_pointer_types"] != []:
            raise TypeError(f"{context} must use ABI 1 with empty syscall and pointer-type deltas")
        start = _proposal_exact_json_uint(
            record["start_height"], f"{context}.start_height"
        )
        end = _proposal_exact_json_uint(record["end_height"], f"{context}.end_height")
        if end <= start:
            raise TypeError(f"{context}.end_height must be greater than start_height")
        if not isinstance(record["sbom_digests"], list) or not isinstance(record["provenance"], list):
            raise TypeError(f"{context} SBOM and provenance fields must be arrays")
        sboms = []
        for index, item in enumerate(record["sbom_digests"]):
            item_context = f"{context}.sbom_digests[{index}]"
            item_record = _exact(item, frozenset({"algorithm", "digest"}), item_context)
            sboms.append(_freeze({"algorithm": _string(item_record["algorithm"], f"{item_context}.algorithm"), "digest": _canonical_base64(item_record["digest"], f"{item_context}.digest")}))
        provenance = tuple(GovernanceManifestProvenance.from_payload(item, f"{context}.provenance[{index}]") for index, item in enumerate(record["provenance"]))
        return cls(_string(record["name"], f"{context}.name"), _string(record["description"], f"{context}.description", nonempty=False), abi, _bytes32(record["abi_hash"], f"{context}.abi_hash"), (), (), start, end, tuple(sboms), _canonical_base64(record["slsa_attestation"], f"{context}.slsa_attestation"), provenance)


@dataclass(frozen=True)
class GovernanceProposalRuntimeUpgrade:
    """Canonical `RuntimeUpgradeProposal` payload."""

    manifest: GovernanceRuntimeUpgradeManifest

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalRuntimeUpgrade":
        record = _exact(value, frozenset({"manifest"}), "RuntimeUpgrade payload")
        return cls(GovernanceRuntimeUpgradeManifest.from_payload(record["manifest"]))


@dataclass(frozen=True)
class GovernanceProposalSccpRouteGovernance:
    """Canonical `SccpRouteGovernanceProposal` payload.

    `proposal` is the exact `SccpGovernanceProposalV1` object (`network_id`,
    `base_revisions`, `actions`), frozen after its top-level shape is checked.
    """

    proposal: GovernanceCanonicalObject

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalSccpRouteGovernance":
        # TODO: decode SccpGovernanceProposalV1 base revisions and actions into typed
        # records (specs/sccp.md §4.14.3); they are kept as canonical objects for now.
        context = "SccpRouteGovernance payload"
        payload = _exact(value, frozenset({"proposal"}), context)
        proposal = _exact(
            payload["proposal"],
            frozenset({"network_id", "base_revisions", "actions"}),
            f"{context}.proposal",
        )
        _network_id(proposal["network_id"], f"{context}.proposal.network_id")
        if not isinstance(proposal["base_revisions"], list):
            raise TypeError(f"{context}.proposal.base_revisions must be an array")
        actions = proposal["actions"]
        if not isinstance(actions, list) or not 1 <= len(actions) <= _SCCP_GOVERNANCE_MAX_ACTIONS:
            raise TypeError(
                f"{context}.proposal.actions must be an array of "
                f"1..{_SCCP_GOVERNANCE_MAX_ACTIONS} actions"
            )
        return cls(cast(GovernanceCanonicalObject, _freeze(proposal)))


class GovernanceValidationFeeChargingMode(str, Enum):
    """The sole first-release validation-fee charging mode."""

    RETAIL_MONTHLY_ALLOWANCE = "RETAIL_MONTHLY_ALLOWANCE"


@dataclass(frozen=True)
class GovernanceValidationFeeMaintenanceTier:
    minimum_average_balance_minor: int
    monthly_fee_minor: int


@dataclass(frozen=True)
class GovernanceValidationFeeRetailSchedule:
    included_payments: int
    overage_minor: int
    maintenance_tiers: tuple[GovernanceValidationFeeMaintenanceTier, ...]

    @classmethod
    def from_payload(cls, value: Any, context: str) -> "GovernanceValidationFeeRetailSchedule":
        record = _exact(value, frozenset({"included_payments", "overage_minor", "maintenance_tiers"}), context)
        offered = record["maintenance_tiers"]
        if not isinstance(offered, list) or not 1 <= len(offered) <= 32:
            raise TypeError(f"{context}.maintenance_tiers must contain 1..32 tiers")
        tiers = []
        for index, item in enumerate(offered):
            label = f"{context}.maintenance_tiers[{index}]"
            tier = _exact(item, frozenset({"minimum_average_balance_minor", "monthly_fee_minor"}), label)
            tiers.append(GovernanceValidationFeeMaintenanceTier(
                _uint(tier["minimum_average_balance_minor"], f"{label}.minimum_average_balance_minor"),
                _uint(tier["monthly_fee_minor"], f"{label}.monthly_fee_minor", positive=True),
            ))
        if tiers[0].minimum_average_balance_minor != 0 or any(
            right.minimum_average_balance_minor <= left.minimum_average_balance_minor
            or right.monthly_fee_minor < left.monthly_fee_minor
            for left, right in zip(tiers, tiers[1:])
        ):
            raise TypeError(f"{context} requires a zero floor, increasing thresholds and nondecreasing charges")
        return cls(
            _uint(record["included_payments"], f"{context}.included_payments", 0xFFFFFFFF, positive=True),
            _uint(record["overage_minor"], f"{context}.overage_minor", positive=True),
            tuple(tiers),
        )


@dataclass(frozen=True)
class GovernanceValidationFeeRewardCustody:
    """Immutable DATA projection; Native/Parliament still authenticates custody."""

    contract_address: str
    treasury_account_id: str
    ds_asset_id: str
    xor_asset_id: str
    reward_pool_account_id: str
    validator_lane_id: int

    @classmethod
    def from_payload(cls, value: Any, context: str) -> "GovernanceValidationFeeRewardCustody":
        fields = frozenset({"contract_address", "treasury_account_id", "ds_asset_id", "xor_asset_id", "reward_pool_account_id", "validator_lane_id"})
        record = _exact(value, fields, context)
        result = cls(
            _contract_address(record["contract_address"], f"{context}.contract_address"),
            _account_id(record["treasury_account_id"], f"{context}.treasury_account_id"),
            _asset_definition_id(record["ds_asset_id"], f"{context}.ds_asset_id"),
            _asset_definition_id(record["xor_asset_id"], f"{context}.xor_asset_id"),
            _account_id(record["reward_pool_account_id"], f"{context}.reward_pool_account_id"),
            _uint(record["validator_lane_id"], f"{context}.validator_lane_id", 0xFFFFFFFF),
        )
        if result.ds_asset_id == result.xor_asset_id or result.treasury_account_id == result.reward_pool_account_id:
            raise TypeError(f"{context} fee/reward assets and custody must differ")
        return result


@dataclass(frozen=True)
class GovernanceValidationFeePayoutBinding:
    """Exact independently governed conversion binding; never approval authority."""

    contract_address: str
    code_hash: str
    entrypoint: str
    treasury_account_id: str
    ds_asset_id: str
    xor_asset_id: str
    pool_contract_address: str
    pool_code_hash: str
    pool_vault_account_id: str
    reward_pool_account_id: str
    reference_feed_id: str
    reference_feed_config_version: int
    reference_provider_accounts: tuple[str, ...]
    max_sbd_per_attempt_minor: int
    max_sbd_per_day_minor: int
    min_interval_ms: int
    max_source_age_ms: int
    max_slippage_bps: int
    validator_lane_id: int
    min_reward_claim_xor_minor: int

    @classmethod
    def from_payload(cls, value: Any, context: str) -> "GovernanceValidationFeePayoutBinding":
        fields = frozenset(cls.__dataclass_fields__)
        record = _exact(value, fields, context)
        values: dict[str, Any] = {}
        for field in ("contract_address", "pool_contract_address"):
            values[field] = _contract_address(record[field], f"{context}.{field}")
        for field in ("code_hash", "pool_code_hash"):
            values[field] = _upper_hex32(record[field], f"{context}.{field}", nonzero=True)
        if record["entrypoint"] != "autonomous_validation_fee_tick":
            raise TypeError(f"{context}.entrypoint must be autonomous_validation_fee_tick")
        values["entrypoint"] = record["entrypoint"]
        for field in ("treasury_account_id", "pool_vault_account_id", "reward_pool_account_id"):
            values[field] = _account_id(record[field], f"{context}.{field}")
        if len({values[field] for field in ("treasury_account_id", "pool_vault_account_id", "reward_pool_account_id")}) != 3:
            raise TypeError(f"{context} treasury, pool and reward custody must differ")
        for field in ("ds_asset_id", "xor_asset_id"):
            values[field] = _asset_definition_id(record[field], f"{context}.{field}")
        if values["ds_asset_id"] == values["xor_asset_id"]:
            raise TypeError(f"{context} SBD and XOR assets must differ")
        values["reference_feed_id"] = _iroha_name(_string_tuple(record["reference_feed_id"], f"{context}.reference_feed_id"), f"{context}.reference_feed_id[0]")
        providers = record["reference_provider_accounts"]
        if not isinstance(providers, list) or len(providers) != 5:
            raise TypeError(f"{context} requires five independently controlled reference providers")
        provider_ids = tuple(_account_id(item, f"{context}.reference_provider_accounts[{index}]") for index, item in enumerate(providers))
        # Admission remains with the actual Rust account codec. Compare complete
        # single-controller originals, so changing the I105 network sentinel cannot
        # make a repeated signing key appear to be an independent provider.
        controllers = [decode_canonical_i105_account_id(item) for item in provider_ids]
        if any(len(raw) < 2 or raw[1] != 0 for raw in controllers) or len(set(controllers)) != 5:
            raise TypeError(f"{context} requires five distinct single-signature provider controllers")
        values["reference_provider_accounts"] = provider_ids
        for field in ("reference_feed_config_version", "max_sbd_per_attempt_minor", "max_sbd_per_day_minor", "min_interval_ms", "max_source_age_ms", "min_reward_claim_xor_minor", "max_slippage_bps", "validator_lane_id"):
            maximum = 0xFFFFFFFF if field in ("reference_feed_config_version", "validator_lane_id") else _U64_MAX
            values[field] = _uint(record[field], f"{context}.{field}", maximum, positive=field not in ("max_slippage_bps", "validator_lane_id"))
        if values["max_slippage_bps"] >= 10000 or values["max_sbd_per_day_minor"] < values["max_sbd_per_attempt_minor"]:
            raise TypeError(f"{context} conversion limits exceed native bounds")
        return cls(**values)


@dataclass(frozen=True)
class GovernanceValidationFeePolicy:
    """Complete current retail policy DATA; no old off or automatic-expiry shape."""

    schema_version: int
    network_id: str
    policy_version: int
    previous_policy_hash: Optional[str]
    ds_asset_id: str
    ds_scale: int
    retail_schedule: GovernanceValidationFeeRetailSchedule
    effective_from_ms: int
    notice_published_at_ms: int
    fee: str
    treasury_account_id: str
    charging_mode: GovernanceValidationFeeChargingMode
    exemption_classes: tuple[str, ...]
    reward_custody: GovernanceValidationFeeRewardCustody

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceValidationFeePolicy":
        context = "ValidationFeePolicy payload.policy"
        record = _exact(value, frozenset(cls.__dataclass_fields__), context)
        if _uint(record["schema_version"], f"{context}.schema_version", 1) != 1 or _uint(record["ds_scale"], f"{context}.ds_scale", 255) != 2:
            raise TypeError(f"{context} requires schema 1 and SBD scale 2")
        mode = _exact(record["charging_mode"], frozenset({"charging_mode", "value"}), f"{context}.charging_mode")
        if mode["charging_mode"] != "RETAIL_MONTHLY_ALLOWANCE" or mode["value"] is not None:
            raise TypeError(f"{context}.charging_mode must be RETAIL_MONTHLY_ALLOWANCE with null value")
        version = _decimal_u64(record["policy_version"], f"{context}.policy_version", positive=True)
        previous = None if record["previous_policy_hash"] is None else _upper_hex32(record["previous_policy_hash"], f"{context}.previous_policy_hash", nonzero=True)
        if (version == 1) != (previous is None):
            raise TypeError(f"{context}.previous_policy_hash differs from policy_version")
        fee = _numeric(record["fee"], f"{context}.fee")
        if fee == "0" or len(fee.partition(".")[2]) > 2:
            raise TypeError(f"{context}.fee must be positive exact SBD minor units")
        effective = _uint(record["effective_from_ms"], f"{context}.effective_from_ms", positive=True)
        notice = _uint(record["notice_published_at_ms"], f"{context}.notice_published_at_ms")
        local_ms = effective + 39_600_000
        try:
            local_day = date(1970, 1, 1) + timedelta(days=local_ms // 86_400_000)
            # The Model derives both month endpoints, so the next month
            # must also lie inside the supported calendar domain.
            date(local_day.year + (local_day.month == 12), local_day.month % 12 + 1, 1)
        except (OverflowError, ValueError) as exc:
            raise TypeError(f"{context}.effective_from_ms is outside the supported calendar") from exc
        if effective < notice + 30 * 86_400_000 or local_ms % 86_400_000 or local_day.day != 1:
            raise TypeError(f"{context} requires a Honiara month boundary after thirty days notice")
        if record["exemption_classes"] != ["TREASURY_PAYOUT"]:
            raise TypeError(f"{context} requires exactly the governed TREASURY_PAYOUT exemption")
        custody = GovernanceValidationFeeRewardCustody.from_payload(record["reward_custody"], f"{context}.reward_custody")
        asset = _asset_definition_id(record["ds_asset_id"], f"{context}.ds_asset_id")
        treasury = _account_id(record["treasury_account_id"], f"{context}.treasury_account_id")
        if custody.ds_asset_id != asset or custody.treasury_account_id != treasury:
            raise TypeError(f"{context} fee asset and treasury must match immutable reward custody")
        return cls(1, _network_id(record["network_id"], f"{context}.network_id"), version, previous, asset, 2,
                   GovernanceValidationFeeRetailSchedule.from_payload(record["retail_schedule"], f"{context}.retail_schedule"),
                   effective, notice, fee, treasury, GovernanceValidationFeeChargingMode.RETAIL_MONTHLY_ALLOWANCE,
                   ("TREASURY_PAYOUT",), custody)


@dataclass(frozen=True)
class GovernanceProposalValidationFeePolicy:
    """Current two-field `ValidationFeePolicyProposal` payload."""

    proposal_operator: str
    policy: GovernanceValidationFeePolicy

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalValidationFeePolicy":
        context = "ValidationFeePolicy payload"
        record = _exact(value, frozenset({"proposal_operator", "policy"}), context)
        return cls(_account_id(record["proposal_operator"], f"{context}.proposal_operator"), GovernanceValidationFeePolicy.from_payload(record["policy"]))


@dataclass(frozen=True)
class GovernanceProposalValidationFeePayoutLifecycle:
    """Canonical independent `ValidationFeePayoutLifecycleProposal` payload."""

    proposal_operator: str
    payout_binding: GovernanceValidationFeePayoutBinding

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalValidationFeePayoutLifecycle":
        context = "ValidationFeePayoutLifecycle payload"
        record = _exact(value, frozenset({"proposal_operator", "payout_binding"}), context)
        return cls(_account_id(record["proposal_operator"], f"{context}.proposal_operator"), GovernanceValidationFeePayoutBinding.from_payload(record["payout_binding"], f"{context}.payout_binding"))


class GovernanceMusubiActionKind(str, Enum):
    """Closed Musubi Parliament action tags."""

    RECOVER_PACKAGE_OWNERS = "RecoverPackageOwners"
    RETARGET_ALIAS = "RetargetAlias"
    TAKEDOWN_ARTIFACT = "TakedownArtifact"
    SET_REGISTRY_POLICY = "SetRegistryPolicy"


class GovernanceMusubiPackageScopeKind(str, Enum):
    """Closed Musubi structural package scopes."""

    DATASPACE_ROOT = "DataspaceRoot"
    DOMAIN = "Domain"


@dataclass(frozen=True)
class GovernanceMusubiPackageScope:
    """One exact structural package scope."""

    kind: GovernanceMusubiPackageScopeKind
    value: Optional[str]

    @classmethod
    def from_payload(cls, value: Any, context: str) -> "GovernanceMusubiPackageScope":
        record = _exact(value, frozenset({"kind", "value"}), context)
        try:
            kind = GovernanceMusubiPackageScopeKind(record["kind"])
        except (ValueError, TypeError) as exc:
            raise TypeError(f"{context}.kind is unsupported") from exc
        if kind is GovernanceMusubiPackageScopeKind.DATASPACE_ROOT:
            if record["value"] is not None:
                raise TypeError(f"{context}.value must be null for DataspaceRoot")
            return cls(kind, None)
        return cls(kind, _iroha_name(record["value"], f"{context}.value"))


@dataclass(frozen=True)
class GovernanceMusubiPackageId:
    """Canonical stable structural package identifier."""

    home_dataspace: int
    scope: GovernanceMusubiPackageScope
    name: str

    @classmethod
    def from_payload(cls, value: Any, context: str) -> "GovernanceMusubiPackageId":
        record = _exact(value, frozenset({"home_dataspace", "scope", "name"}), context)
        name = _string_tuple(record["name"], f"{context}.name")
        return cls(
            _proposal_exact_json_uint(
                record["home_dataspace"], f"{context}.home_dataspace"
            ),
            GovernanceMusubiPackageScope.from_payload(record["scope"], f"{context}.scope"),
            _ascii_kebab(name, f"{context}.name[0]", 64),
        )


class GovernanceMusubiPrereleaseIdentifierKind(str, Enum):
    """Closed Musubi semantic-version prerelease identifier tags."""

    NUMERIC = "Numeric"
    ALPHA_NUMERIC = "AlphaNumeric"


@dataclass(frozen=True)
class GovernanceMusubiPrereleaseIdentifier:
    """One canonical Musubi semantic-version prerelease identifier."""

    kind: GovernanceMusubiPrereleaseIdentifierKind
    value: Union[int, str]

    @classmethod
    def from_payload(
        cls, value: Any, context: str
    ) -> "GovernanceMusubiPrereleaseIdentifier":
        record = _exact(value, frozenset({"kind", "value"}), context)
        try:
            kind = GovernanceMusubiPrereleaseIdentifierKind(record["kind"])
        except (ValueError, TypeError) as exc:
            raise TypeError(f"{context}.kind is unsupported") from exc
        if kind is GovernanceMusubiPrereleaseIdentifierKind.NUMERIC:
            return cls(
                kind,
                _proposal_exact_json_uint(record["value"], f"{context}.value"),
            )
        literal = _string(record["value"], f"{context}.value")
        if (
            len(literal.encode("ascii", errors="ignore")) != len(literal)
            or len(literal) > 64
            or re.fullmatch(r"[A-Za-z0-9-]+", literal) is None
            or literal.isdigit()
        ):
            raise TypeError(f"{context}.value is not a canonical alphanumeric identifier")
        return cls(kind, literal)


@dataclass(frozen=True)
class GovernanceMusubiVersion:
    """Canonical structured Musubi semantic version."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[GovernanceMusubiPrereleaseIdentifier, ...]

    @classmethod
    def from_payload(cls, value: Any, context: str) -> "GovernanceMusubiVersion":
        record = _exact(
            value, frozenset({"major", "minor", "patch", "prerelease"}), context
        )
        if not isinstance(record["prerelease"], list):
            raise TypeError(f"{context}.prerelease must be an array")
        if len(record["prerelease"]) > 16:
            raise TypeError(f"{context}.prerelease exceeds the V1 bound")
        prerelease = tuple(
            GovernanceMusubiPrereleaseIdentifier.from_payload(
                item, f"{context}.prerelease[{index}]"
            )
            for index, item in enumerate(record["prerelease"])
        )
        return cls(
            _proposal_exact_json_uint(record["major"], f"{context}.major"),
            _proposal_exact_json_uint(record["minor"], f"{context}.minor"),
            _proposal_exact_json_uint(record["patch"], f"{context}.patch"),
            prerelease,
        )


@dataclass(frozen=True)
class GovernanceMusubiReleaseId:
    """Exact structural Musubi release identifier."""

    package: GovernanceMusubiPackageId
    version: GovernanceMusubiVersion

    @classmethod
    def from_payload(cls, value: Any, context: str) -> "GovernanceMusubiReleaseId":
        record = _exact(value, frozenset({"package", "version"}), context)
        return cls(
            GovernanceMusubiPackageId.from_payload(record["package"], f"{context}.package"),
            GovernanceMusubiVersion.from_payload(record["version"], f"{context}.version"),
        )


class GovernanceMusubiRegistryAdmissionMode(str, Enum):
    """Closed Musubi registry admission modes."""

    CLOSED = "Closed"
    ALLOWLISTED = "Allowlisted"
    OPEN = "Open"


@dataclass(frozen=True)
class GovernanceMusubiAliasPricingPolicy:
    """Canonical prospective alias pricing policy."""

    revision: int
    length_1_xor: int
    length_2_xor: int
    length_3_xor: int
    length_4_xor: int
    length_5_to_32_xor: int

    @classmethod
    def from_payload(
        cls, value: Any, context: str
    ) -> "GovernanceMusubiAliasPricingPolicy":
        fields = (
            "revision",
            "length_1_xor",
            "length_2_xor",
            "length_3_xor",
            "length_4_xor",
            "length_5_to_32_xor",
        )
        record = _exact(value, frozenset(fields), context)
        return cls(
            *(
                _proposal_exact_json_uint(
                    record[field], f"{context}.{field}", positive=True
                )
                for field in fields
            )
        )


@dataclass(frozen=True)
class GovernanceMusubiRegistryPolicy:
    """Complete canonical first-release Musubi registry policy."""

    version: int
    revision: int
    mode: GovernanceMusubiRegistryAdmissionMode
    allowlisted_dataspaces: tuple[int, ...]
    alias_pricing: GovernanceMusubiAliasPricingPolicy

    @classmethod
    def from_payload(cls, value: Any, context: str) -> "GovernanceMusubiRegistryPolicy":
        fields = frozenset(
            {"version", "revision", "mode", "allowlisted_dataspaces", "alias_pricing"}
        )
        record = _exact(value, fields, context)
        if _uint(record["version"], f"{context}.version", 1) != 1:
            raise TypeError(f"{context}.version must be 1")
        mode_record = _exact(
            record["mode"], frozenset({"kind", "value"}), f"{context}.mode"
        )
        if mode_record["value"] is not None:
            raise TypeError(f"{context}.mode.value must be null")
        try:
            mode = GovernanceMusubiRegistryAdmissionMode(mode_record["kind"])
        except (ValueError, TypeError) as exc:
            raise TypeError(f"{context}.mode.kind is unsupported") from exc
        if not isinstance(record["allowlisted_dataspaces"], list):
            raise TypeError(f"{context}.allowlisted_dataspaces must be an array")
        allowlisted = tuple(
            _proposal_exact_json_uint(
                item, f"{context}.allowlisted_dataspaces[{index}]"
            )
            for index, item in enumerate(record["allowlisted_dataspaces"])
        )
        if len(allowlisted) > 1_024 or any(
            left >= right for left, right in zip(allowlisted, allowlisted[1:])
        ):
            raise TypeError(
                f"{context}.allowlisted_dataspaces must be bounded, sorted, and unique"
            )
        if mode is not GovernanceMusubiRegistryAdmissionMode.ALLOWLISTED and allowlisted:
            raise TypeError(f"{context}.allowlisted_dataspaces does not match mode")
        return cls(
            1,
            _proposal_exact_json_uint(
                record["revision"], f"{context}.revision", positive=True
            ),
            mode,
            allowlisted,
            GovernanceMusubiAliasPricingPolicy.from_payload(
                record["alias_pricing"], f"{context}.alias_pricing"
            ),
        )


@dataclass(frozen=True)
class GovernanceMusubiRecoverPackageOwners:
    """Canonical package-owner recovery payload."""

    package: GovernanceMusubiPackageId
    owners: tuple[str, ...]
    expected_revision: int


@dataclass(frozen=True)
class GovernanceMusubiRetargetAlias:
    """Canonical permanent-alias retarget payload."""

    alias: str
    target: GovernanceMusubiPackageId
    expected_revision: int


@dataclass(frozen=True)
class GovernanceMusubiTakedownArtifact:
    """Canonical immutable-artifact takedown payload."""

    release: GovernanceMusubiReleaseId
    reason: str
    expected_artifact_governance_revision: int


@dataclass(frozen=True)
class GovernanceMusubiSetRegistryPolicy:
    """Canonical prospective registry-policy replacement payload."""

    policy: GovernanceMusubiRegistryPolicy
    expected_revision: int


GovernanceMusubiActionValue = Union[
    GovernanceMusubiRecoverPackageOwners,
    GovernanceMusubiRetargetAlias,
    GovernanceMusubiTakedownArtifact,
    GovernanceMusubiSetRegistryPolicy,
]


@dataclass(frozen=True)
class GovernanceProposalMusubiRegistryGovernance:
    """Canonical closed Musubi Parliament action."""

    kind: GovernanceMusubiActionKind
    value: GovernanceMusubiActionValue

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalMusubiRegistryGovernance":
        context = "MusubiRegistryGovernance payload"
        record = _exact(value, frozenset({"kind", "value"}), context)
        try:
            kind = GovernanceMusubiActionKind(record["kind"])
        except (ValueError, TypeError) as exc:
            raise TypeError(f"{context}.kind is not a first-release Musubi action") from exc
        action_context = f"{context}.value"
        if kind is GovernanceMusubiActionKind.RECOVER_PACKAGE_OWNERS:
            action = _exact(
                record["value"],
                frozenset({"package", "owners", "expected_revision"}),
                action_context,
            )
            if not isinstance(action["owners"], list):
                raise TypeError(f"{action_context}.owners must be an array")
            owners = tuple(
                _account_id(owner, f"{action_context}.owners[{index}]")
                for index, owner in enumerate(action["owners"])
            )
            if not 1 <= len(owners) <= 64 or len(set(owners)) != len(owners):
                raise TypeError(f"{action_context}.owners must contain 1-64 unique accounts")
            payload: GovernanceMusubiActionValue = GovernanceMusubiRecoverPackageOwners(
                GovernanceMusubiPackageId.from_payload(
                    action["package"], f"{action_context}.package"
                ),
                owners,
                _proposal_exact_json_uint(
                    action["expected_revision"],
                    f"{action_context}.expected_revision",
                    positive=True,
                ),
            )
        elif kind is GovernanceMusubiActionKind.RETARGET_ALIAS:
            action = _exact(
                record["value"],
                frozenset({"alias", "target", "expected_revision"}),
                action_context,
            )
            alias = _string_tuple(action["alias"], f"{action_context}.alias")
            payload = GovernanceMusubiRetargetAlias(
                _ascii_kebab(alias, f"{action_context}.alias[0]", 32),
                GovernanceMusubiPackageId.from_payload(
                    action["target"], f"{action_context}.target"
                ),
                _proposal_exact_json_uint(
                    action["expected_revision"],
                    f"{action_context}.expected_revision",
                    positive=True,
                ),
            )
        elif kind is GovernanceMusubiActionKind.TAKEDOWN_ARTIFACT:
            action = _exact(
                record["value"],
                frozenset({"release", "reason", "expected_artifact_governance_revision"}),
                action_context,
            )
            reason = _string_tuple(action["reason"], f"{action_context}.reason")
            if len(reason.encode("utf-8")) > 1_024:
                raise TypeError(f"{action_context}.reason[0] exceeds the V1 bound")
            payload = GovernanceMusubiTakedownArtifact(
                GovernanceMusubiReleaseId.from_payload(
                    action["release"], f"{action_context}.release"
                ),
                reason,
                _proposal_exact_json_uint(
                    action["expected_artifact_governance_revision"],
                    f"{action_context}.expected_artifact_governance_revision",
                    positive=True,
                ),
            )
        else:
            action = _exact(
                record["value"],
                frozenset({"policy", "expected_revision"}),
                action_context,
            )
            expected_revision = _proposal_exact_json_uint(
                action["expected_revision"],
                f"{action_context}.expected_revision",
                positive=True,
            )
            policy = GovernanceMusubiRegistryPolicy.from_payload(
                action["policy"], f"{action_context}.policy"
            )
            if policy.revision != expected_revision + 1:
                raise TypeError(f"{action_context}.policy.revision must follow expected_revision")
            payload = GovernanceMusubiSetRegistryPolicy(policy, expected_revision)
        return cls(kind, payload)


class GovernanceSorafsProviderActionKind(str, Enum):
    """Closed SoraFS provider-owner action tags."""

    ESTABLISH = "establish"
    REBIND = "rebind"
    REMOVE = "remove"


@dataclass(frozen=True)
class GovernanceSorafsProviderAction:
    """One exact SoraFS provider-owner transition."""

    action: GovernanceSorafsProviderActionKind
    provider_id: tuple[int, ...]
    owner: Optional[str]
    expected_owner: Optional[str]
    next_owner: Optional[str]

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceSorafsProviderAction":
        context = "SorafsProviderGovernance payload.action"
        record = _exact(value, frozenset({"action", "value"}), context)
        try:
            action = GovernanceSorafsProviderActionKind(record["action"])
        except (ValueError, TypeError) as exc:
            raise TypeError(f"{context}.action is not a first-release provider action") from exc
        fields = {
            action.ESTABLISH: frozenset({"provider_id", "owner"}),
            action.REBIND: frozenset({"provider_id", "expected_owner", "next_owner"}),
            action.REMOVE: frozenset({"provider_id", "expected_owner"}),
        }[action]
        transition = _exact(record["value"], fields, f"{context}.value")
        return cls(action, _provider_id(transition["provider_id"], f"{context}.value.provider_id"), _account_id(transition["owner"], f"{context}.value.owner") if "owner" in transition else None, _account_id(transition["expected_owner"], f"{context}.value.expected_owner") if "expected_owner" in transition else None, _account_id(transition["next_owner"], f"{context}.value.next_owner") if "next_owner" in transition else None)


@dataclass(frozen=True)
class GovernanceProposalSorafsProviderGovernance:
    """Canonical `SorafsProviderGovernanceProposal` payload."""

    action: GovernanceSorafsProviderAction

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalSorafsProviderGovernance":
        record = _exact(value, frozenset({"action"}), "SorafsProviderGovernance payload")
        return cls(GovernanceSorafsProviderAction.from_payload(record["action"]))


class GovernanceContractLifecycleActionKind(str, Enum):
    """Closed contract-lifecycle Parliament action tags."""

    ACTIVATE = "Activate"
    DEACTIVATE = "Deactivate"
    OFFER_OWNERSHIP = "OfferOwnership"
    CANCEL_OWNERSHIP_OFFER = "CancelOwnershipOffer"
    ACCEPT_PARLIAMENT_OWNERSHIP = "AcceptParliamentOwnership"
    COMPLETE_EMERGENCY_HOLD_RETROSPECTIVE = "CompleteEmergencyHoldRetrospective"


@dataclass(frozen=True)
class GovernanceContractLifecycleActivate:
    """Exact governed contract activation payload."""

    code_hash: str
    abi_hash: str
    abi_version: int
    manifest_provenance: Optional[GovernanceManifestProvenance]


@dataclass(frozen=True)
class GovernanceContractLifecycleDeactivate:
    """Exact governed contract deactivation payload."""

    expected_code_hash: str
    reason: Optional[str]


@dataclass(frozen=True)
class GovernanceContractLifecycleOfferOwnership:
    """Exact governed contract ownership-offer payload."""

    new_owner: str


@dataclass(frozen=True)
class GovernanceContractLifecycleEmergencyHoldRetrospective:
    """Exact expired emergency-hold retrospective payload."""

    hold_proposal_content_id: tuple[int, ...]
    hold_governance_attempt_id: tuple[int, ...]
    incident_digest: tuple[int, ...]
    retrospective_finding_root: tuple[int, ...]


GovernanceContractLifecycleActionPayload = Union[
    GovernanceContractLifecycleActivate,
    GovernanceContractLifecycleDeactivate,
    GovernanceContractLifecycleOfferOwnership,
    GovernanceContractLifecycleEmergencyHoldRetrospective,
    None,
]


@dataclass(frozen=True)
class GovernanceContractLifecycleAction:
    """One exact adjacently-tagged lifecycle action."""

    action: GovernanceContractLifecycleActionKind
    payload: GovernanceContractLifecycleActionPayload

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceContractLifecycleAction":
        context = "ContractLifecycleGovernance payload.action"
        record = _exact(value, frozenset({"action", "payload"}), context)
        try:
            action = GovernanceContractLifecycleActionKind(record["action"])
        except (ValueError, TypeError) as exc:
            raise TypeError(f"{context}.action is not a first-release lifecycle action") from exc
        payload_context = f"{context}.payload"
        if action in {
            GovernanceContractLifecycleActionKind.CANCEL_OWNERSHIP_OFFER,
            GovernanceContractLifecycleActionKind.ACCEPT_PARLIAMENT_OWNERSHIP,
        }:
            if record["payload"] is not None:
                raise TypeError(f"{payload_context} must be null for {action.value}")
            return cls(action, None)
        if action is GovernanceContractLifecycleActionKind.ACTIVATE:
            payload = _exact(
                record["payload"],
                frozenset({"code_hash", "abi_hash", "abi_version", "manifest_provenance"}),
                payload_context,
            )
            abi_version = _proposal_exact_json_uint(
                payload["abi_version"], f"{payload_context}.abi_version", positive=True
            )
            if abi_version != 1:
                raise TypeError(f"{payload_context}.abi_version must be the integer 1")
            provenance = (
                None
                if payload["manifest_provenance"] is None
                else GovernanceManifestProvenance.from_payload(
                    payload["manifest_provenance"], f"{payload_context}.manifest_provenance"
                )
            )
            return cls(
                action,
                GovernanceContractLifecycleActivate(
                    _lower_hex32(payload["code_hash"], f"{payload_context}.code_hash"),
                    _lower_hex32(payload["abi_hash"], f"{payload_context}.abi_hash"),
                    abi_version,
                    provenance,
                ),
            )
        if action is GovernanceContractLifecycleActionKind.DEACTIVATE:
            payload = _exact(
                record["payload"],
                frozenset({"expected_code_hash", "reason"})
                if isinstance(record["payload"], Mapping) and "reason" in record["payload"]
                else frozenset({"expected_code_hash"}),
                payload_context,
            )
            reason_value = payload.get("reason")
            if reason_value is not None and not isinstance(reason_value, str):
                raise TypeError(f"{payload_context}.reason must be a string or null")
            reason = cast(Optional[str], reason_value)
            return cls(
                action,
                GovernanceContractLifecycleDeactivate(
                    _lower_hex32(
                        payload["expected_code_hash"], f"{payload_context}.expected_code_hash"
                    ),
                    reason,
                ),
            )
        if action is GovernanceContractLifecycleActionKind.OFFER_OWNERSHIP:
            payload = _exact(record["payload"], frozenset({"new_owner"}), payload_context)
            return cls(
                action,
                GovernanceContractLifecycleOfferOwnership(
                    _account_id(payload["new_owner"], f"{payload_context}.new_owner")
                ),
            )
        payload = _exact(
            record["payload"],
            frozenset(
                {
                    "hold_proposal_content_id",
                    "hold_governance_attempt_id",
                    "incident_digest",
                    "retrospective_finding_root",
                }
            ),
            payload_context,
        )
        return cls(
            action,
            GovernanceContractLifecycleEmergencyHoldRetrospective(
                _bytes32(
                    payload["hold_proposal_content_id"],
                    f"{payload_context}.hold_proposal_content_id",
                    nonzero=True,
                ),
                _bytes32(
                    payload["hold_governance_attempt_id"],
                    f"{payload_context}.hold_governance_attempt_id",
                    nonzero=True,
                ),
                _bytes32(
                    payload["incident_digest"],
                    f"{payload_context}.incident_digest",
                    nonzero=True,
                ),
                _bytes32(
                    payload["retrospective_finding_root"],
                    f"{payload_context}.retrospective_finding_root",
                    nonzero=True,
                ),
            ),
        )


@dataclass(frozen=True)
class GovernanceProposalContractLifecycleGovernance:
    """Canonical `ContractLifecycleGovernanceProposalV1` payload."""

    contract_address: str
    expected_revision: int
    action: GovernanceContractLifecycleAction

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalContractLifecycleGovernance":
        context = "ContractLifecycleGovernance payload"
        record = _exact(
            value, frozenset({"contract_address", "expected_revision", "action"}), context
        )
        return cls(
            _contract_address(record["contract_address"], f"{context}.contract_address"),
            _proposal_exact_json_uint(
                record["expected_revision"], f"{context}.expected_revision", positive=True
            ),
            GovernanceContractLifecycleAction.from_payload(record["action"]),
        )


@dataclass(frozen=True)
class GovernanceProposalContractEmergencyHold:
    """Canonical `ContractEmergencyHoldProposalV1` payload."""

    contract_address: str
    expected_revision: int
    expected_code_hash: str
    incident_digest: tuple[int, ...]
    reason: str
    duration_blocks: int

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalContractEmergencyHold":
        context = "ContractEmergencyHold payload"
        record = _exact(
            value,
            frozenset(
                {
                    "contract_address",
                    "expected_revision",
                    "expected_code_hash",
                    "incident_digest",
                    "reason",
                    "duration_blocks",
                }
            ),
            context,
        )
        if not isinstance(record["reason"], str):
            raise TypeError(f"{context}.reason must be a string")
        reason = record["reason"]
        if not reason.strip():
            raise TypeError(f"{context}.reason must not be blank")
        duration_blocks = _proposal_exact_json_uint(
            record["duration_blocks"], f"{context}.duration_blocks", positive=True
        )
        if duration_blocks > 3_600:
            raise TypeError(f"{context}.duration_blocks must be in 1..3600")
        return cls(
            _contract_address(record["contract_address"], f"{context}.contract_address"),
            _proposal_exact_json_uint(
                record["expected_revision"], f"{context}.expected_revision", positive=True
            ),
            _lower_hex32(record["expected_code_hash"], f"{context}.expected_code_hash"),
            _bytes32(record["incident_digest"], f"{context}.incident_digest", nonzero=True),
            reason,
            duration_blocks,
        )


class GovernanceGlobalDataTriggerPermissionAction(str, Enum):
    """Closed exact-account global data-trigger permission transition."""

    GRANT = "grant"
    REVOKE = "revoke"


@dataclass(frozen=True)
class GovernanceProposalGlobalDataTriggerPermissionGovernance:
    """Canonical exact-account global data-trigger permission proposal."""

    authority: str
    action: GovernanceGlobalDataTriggerPermissionAction

    @classmethod
    def from_payload(
        cls, value: Any
    ) -> "GovernanceProposalGlobalDataTriggerPermissionGovernance":
        context = "GlobalDataTriggerPermissionGovernance payload"
        record = _exact(value, frozenset({"authority", "action"}), context)
        action_record = _exact(
            record["action"], frozenset({"action", "value"}), f"{context}.action"
        )
        if action_record["value"] is not None:
            raise TypeError(f"{context}.action.value must be null")
        try:
            action = GovernanceGlobalDataTriggerPermissionAction(action_record["action"])
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{context}.action.action must be grant or revoke") from exc
        return cls(_account_id(record["authority"], f"{context}.authority"), action)


GovernanceProposalPayload = Union[
    GovernanceProposalDeployContract,
    GovernanceProposalRuntimeUpgrade,
    GovernanceProposalSccpRouteGovernance,
    GovernanceProposalValidationFeePolicy,
    GovernanceProposalValidationFeePayoutLifecycle,
    GovernanceProposalMusubiRegistryGovernance,
    GovernanceProposalSorafsProviderGovernance,
    GovernanceProposalContractLifecycleGovernance,
    GovernanceProposalContractEmergencyHold,
    GovernanceProposalGlobalDataTriggerPermissionGovernance,
]


class GovernanceProposalKindTag(str, Enum):
    """Exactly the ten current first-release `ProposalKind` tags."""

    DEPLOY_CONTRACT = "DeployContract"
    RUNTIME_UPGRADE = "RuntimeUpgrade"
    SCCP_ROUTE_GOVERNANCE = "SccpRouteGovernance"
    VALIDATION_FEE_POLICY = "ValidationFeePolicy"
    VALIDATION_FEE_PAYOUT_LIFECYCLE = "ValidationFeePayoutLifecycle"
    MUSUBI_REGISTRY_GOVERNANCE = "MusubiRegistryGovernance"
    SORAFS_PROVIDER_GOVERNANCE = "SorafsProviderGovernance"
    CONTRACT_LIFECYCLE_GOVERNANCE = "ContractLifecycleGovernance"
    CONTRACT_EMERGENCY_HOLD = "ContractEmergencyHold"
    GLOBAL_DATA_TRIGGER_PERMISSION_GOVERNANCE = "GlobalDataTriggerPermissionGovernance"


@dataclass(frozen=True)
class GovernanceProposalKind:
    """Closed adjacently-tagged Rust V1 `ProposalKind`."""

    kind: GovernanceProposalKindTag
    payload: GovernanceProposalPayload

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalKind":
        record = _exact(value, frozenset({"kind", "payload"}), "proposal kind")
        try:
            kind = GovernanceProposalKindTag(record["kind"])
        except (ValueError, TypeError) as exc:
            raise TypeError("proposal kind tag is not one of the ten first-release variants") from exc
        parser = {
            kind.DEPLOY_CONTRACT: GovernanceProposalDeployContract.from_payload,
            kind.RUNTIME_UPGRADE: GovernanceProposalRuntimeUpgrade.from_payload,
            kind.SCCP_ROUTE_GOVERNANCE: GovernanceProposalSccpRouteGovernance.from_payload,
            kind.VALIDATION_FEE_POLICY: GovernanceProposalValidationFeePolicy.from_payload,
            kind.VALIDATION_FEE_PAYOUT_LIFECYCLE: GovernanceProposalValidationFeePayoutLifecycle.from_payload,
            kind.MUSUBI_REGISTRY_GOVERNANCE: GovernanceProposalMusubiRegistryGovernance.from_payload,
            kind.SORAFS_PROVIDER_GOVERNANCE: GovernanceProposalSorafsProviderGovernance.from_payload,
            kind.CONTRACT_LIFECYCLE_GOVERNANCE: GovernanceProposalContractLifecycleGovernance.from_payload,
            kind.CONTRACT_EMERGENCY_HOLD: GovernanceProposalContractEmergencyHold.from_payload,
            kind.GLOBAL_DATA_TRIGGER_PERMISSION_GOVERNANCE: GovernanceProposalGlobalDataTriggerPermissionGovernance.from_payload,
        }[kind]
        payload = cast(GovernanceProposalPayload, parser(record["payload"]))
        return cls(kind, payload)


class GovernanceProposalLifecycleStatus(str, Enum):
    """Closed retained proposal lifecycle status."""

    PROPOSED = "Proposed"
    REJECTED = "Rejected"
    ENACTED = "Enacted"
    SUPERSEDED = "Superseded"
    EXECUTION_FAILED = "ExecutionFailed"


@dataclass(frozen=True)
class GovernanceProposalRecord:
    """Exact first-release retained governance proposal record."""

    proposer: str
    kind: GovernanceProposalKind
    created_height: int
    status: GovernanceProposalLifecycleStatus

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalRecord":
        context = "proposal record"
        record = _exact(value, frozenset({"proposer", "kind", "created_height", "status"}), context)
        try:
            status = GovernanceProposalLifecycleStatus(record["status"])
        except (ValueError, TypeError) as exc:
            raise TypeError(f"{context}.status is unsupported") from exc
        proposer = _account_id(record["proposer"], f"{context}.proposer")
        kind = GovernanceProposalKind.from_payload(record["kind"])
        return cls(proposer, kind, _uint(record["created_height"], f"{context}.created_height"), status)


@dataclass(frozen=True)
class GovernanceProposalResult:
    """Strict response from `GET /v1/gov/proposals/{id}`."""

    found: bool
    proposal: Optional[GovernanceProposalRecord]

    @classmethod
    def from_payload(cls, value: Any) -> "GovernanceProposalResult":
        if not isinstance(value, Mapping):
            raise TypeError("proposal response must be an object")
        found = value.get("found")
        if not isinstance(found, bool):
            raise TypeError("proposal response.found must be boolean")
        fields = frozenset({"found", "proposal"}) if found else frozenset({"found"})
        record = _exact(value, fields, "proposal response")
        if not found:
            return cls(False, None)
        return cls(True, GovernanceProposalRecord.from_payload(record["proposal"]))


__all__ = [name for name in globals() if name.startswith("Governance")]
