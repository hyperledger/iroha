"""SoraFS helpers for alias proofs and multi-source orchestrator bindings."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from iroha_native import load_crypto_extension

from .numeric_v1 import NumericV1Codec

try:
    _crypto: Any = load_crypto_extension()
    _CRYPTO_IMPORT_ERROR: Optional[RuntimeError] = None
except RuntimeError as err:  # pragma: no cover - optional dependency
    _CRYPTO_IMPORT_ERROR = err

    class _UnavailableCrypto:
        """Fail-closed proxy for an unavailable native release dependency."""

        def __getattr__(self, name: str) -> Any:
            raise RuntimeError(
                f"{name} requires the compiled iroha_native._crypto extension module. "
                "Run `maturin develop --release` inside `python/iroha_python` (or install the wheel)."
            ) from _CRYPTO_IMPORT_ERROR

    _crypto = _UnavailableCrypto()

if TYPE_CHECKING:
    pass

__all__ = [
    "SorafsAliasPolicy",
    "SorafsAliasEvaluation",
    "SorafsAliasWarning",
    "SorafsAliasError",
    "evaluate_alias_proof",
    "enforce_alias_policy",
    "alias_proof_fixture",
    "SorafsReplicationAssignment",
    "SorafsReplicationSla",
    "SorafsReplicationMetadataEntry",
    "SorafsReplicationOrder",
    "decode_replication_order",
    "ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1",
    "SORAFS_ORDERBOOK_PAYLOAD_KINDS",
    "SORAFS_PDP_PAYLOAD_KINDS",
    "SORAFS_FIXTURE_BUNDLE_PAYLOAD_KINDS",
    "SORAFS_FIXTURE_BUNDLE_MAX_PAYLOADS_V1",
    "SORAFS_GOVERNANCE_DAG_CID_BYTES_V1",
    "SORAFS_GOVERNANCE_DAG_MAX_BLOCKS_V1",
    "SORAFS_REFERENCE_MAX_INPUT_BYTES_V1",
    "SORAFS_REFERENCE_MAX_LABEL_BYTES_V1",
    "SorafsGovernanceDagBlockInput",
    "SorafsFixtureBundlePayloadInput",
    "validate_appeal_finance_cancel_asset_lock",
    "validate_orderbook_payload",
    "sign_orderbook_payload",
    "derive_orderbook_order_id",
    "build_signed_orderbook_order_request",
    "build_signed_orderbook_order_cancel",
    "build_signed_orderbook_settlement_receipt",
    "validate_pdp_payload",
    "validate_pdp_commitment_challenge",
    "validate_pdp_challenge_proof",
    "validate_pdp_bundle",
    "validate_fixture_bundle",
    "validate_governance_log_node",
    "validate_governance_dag_block",
    "validate_governance_dag_head_chain",
    "SorafsRangeCapability",
    "SorafsStreamBudget",
    "SorafsTransportHint",
    "SorafsProviderMetadata",
    "SorafsLocalProviderSpec",
    "SorafsTelemetryEntry",
    "SorafsProviderBoost",
    "SorafsMultiFetchOptions",
    "SorafsProviderReport",
    "SorafsChunkReceipt",
    "SorafsScoreboardRow",
    "SorafsMultiFetchResult",
    "SorafsMultiFetchError",
    "multi_fetch_local",
]

_LOGGER = logging.getLogger("iroha_python.sorafs")
_HEADER_SORA_NAME = "Sora-Name"
_HEADER_SORA_PROOF = "Sora-Proof"
_HEADER_SORA_PROOF_STATUS = "Sora-Proof-Status"
_ALIAS_POLICY_DEFAULT_FIELDS = frozenset(
    {
        "positive_ttl_secs",
        "refresh_window_secs",
        "hard_expiry_secs",
        "negative_ttl_secs",
        "revocation_ttl_secs",
        "rotation_max_age_secs",
        "successor_grace_secs",
        "governance_grace_secs",
    }
)


class SorafsMultiFetchError(RuntimeError):
    """Stable SDK error raised when the native multi-source fetch fails."""


def _coerce_positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be a positive integer")
    if value <= 0:
        raise ValueError(f"{field} must be greater than zero")
    if value > (1 << 64) - 1:
        raise ValueError(f"{field} must fit an unsigned 64-bit integer")
    return value


def _coerce_non_negative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be a non-negative integer")
    if value < 0:
        raise ValueError(f"{field} must be non-negative")
    if value > (1 << 64) - 1:
        raise ValueError(f"{field} must fit an unsigned 64-bit integer")
    return value


def _default_policy_payload() -> Mapping[str, Any]:
    payload = _crypto.sorafs_alias_policy_defaults()
    if not isinstance(payload, Mapping):
        raise TypeError("alias policy defaults returned an unexpected payload")
    if not all(isinstance(field, str) for field in payload):
        raise TypeError("alias policy defaults returned non-string field names")
    fields = frozenset(payload)
    if fields != _ALIAS_POLICY_DEFAULT_FIELDS:
        missing = sorted(_ALIAS_POLICY_DEFAULT_FIELDS - fields)
        unexpected = sorted(fields - _ALIAS_POLICY_DEFAULT_FIELDS)
        raise RuntimeError(
            "native SoraFS alias policy surface is incompatible with this SDK "
            f"(missing={missing}, unexpected={unexpected})"
        )
    return payload


@dataclass(frozen=True)
class SorafsAliasPolicy:
    """Cache policy thresholds mirroring the Torii gateway defaults."""

    positive_ttl_secs: int
    refresh_window_secs: int
    hard_expiry_secs: int
    negative_ttl_secs: int
    revocation_ttl_secs: int
    rotation_max_age_secs: int
    successor_grace_secs: int
    governance_grace_secs: int

    def __post_init__(self) -> None:
        for field in (
            "positive_ttl_secs",
            "refresh_window_secs",
            "hard_expiry_secs",
            "negative_ttl_secs",
            "revocation_ttl_secs",
            "rotation_max_age_secs",
        ):
            object.__setattr__(
                self,
                field,
                _coerce_positive_int(getattr(self, field), field),
            )
        for field in ("successor_grace_secs", "governance_grace_secs"):
            object.__setattr__(
                self,
                field,
                _coerce_non_negative_int(getattr(self, field), field),
            )
        if self.refresh_window_secs > self.positive_ttl_secs:
            raise ValueError("refresh_window_secs must not exceed positive_ttl_secs")
        if self.hard_expiry_secs < self.positive_ttl_secs:
            raise ValueError("hard_expiry_secs must be greater than or equal to positive_ttl_secs")

    @classmethod
    def defaults(cls) -> "SorafsAliasPolicy":
        """Return the canonical SoraFS alias policy."""

        defaults = _default_policy_payload()
        return cls(
            positive_ttl_secs=defaults["positive_ttl_secs"],
            refresh_window_secs=defaults["refresh_window_secs"],
            hard_expiry_secs=defaults["hard_expiry_secs"],
            negative_ttl_secs=defaults["negative_ttl_secs"],
            revocation_ttl_secs=defaults["revocation_ttl_secs"],
            rotation_max_age_secs=defaults["rotation_max_age_secs"],
            successor_grace_secs=defaults["successor_grace_secs"],
            governance_grace_secs=defaults["governance_grace_secs"],
        )

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "SorafsAliasPolicy":
        """Construct a policy from exact snake-case first-release fields."""

        if not isinstance(mapping, Mapping):
            raise TypeError("SoraFS alias policy must be a mapping")
        unknown = set(mapping).difference(_ALIAS_POLICY_DEFAULT_FIELDS)
        if unknown:
            names = ", ".join(sorted(str(name) for name in unknown))
            raise ValueError(f"SoraFS alias policy contains unsupported fields: {names}")
        defaults_payload = _default_policy_payload()

        def configured(field: str) -> Any:
            return mapping[field] if field in mapping else defaults_payload[field]

        return cls(
            positive_ttl_secs=configured("positive_ttl_secs"),
            refresh_window_secs=configured("refresh_window_secs"),
            hard_expiry_secs=configured("hard_expiry_secs"),
            negative_ttl_secs=configured("negative_ttl_secs"),
            revocation_ttl_secs=configured("revocation_ttl_secs"),
            rotation_max_age_secs=configured("rotation_max_age_secs"),
            successor_grace_secs=configured("successor_grace_secs"),
            governance_grace_secs=configured("governance_grace_secs"),
        )

    def to_mapping(self) -> Dict[str, int]:
        """Return the policy encoded in snake_case keys."""

        return {
            "positive_ttl_secs": self.positive_ttl_secs,
            "refresh_window_secs": self.refresh_window_secs,
            "hard_expiry_secs": self.hard_expiry_secs,
            "negative_ttl_secs": self.negative_ttl_secs,
            "revocation_ttl_secs": self.revocation_ttl_secs,
            "rotation_max_age_secs": self.rotation_max_age_secs,
            "successor_grace_secs": self.successor_grace_secs,
            "governance_grace_secs": self.governance_grace_secs,
        }


@dataclass(frozen=True)
class SorafsAliasEvaluation:
    """Result of validating a `Sora-Proof` bundle."""

    state: str
    status_label: str
    rotation_due: bool
    age_seconds: int
    generated_at_unix: int
    expires_at_unix: int
    expires_in_seconds: Optional[int]
    servable: bool

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "SorafsAliasEvaluation":
        return cls(
            state=str(mapping.get("state")),
            status_label=str(mapping.get("status_label")),
            rotation_due=bool(mapping.get("rotation_due", False)),
            age_seconds=int(mapping.get("age_seconds", 0)),
            generated_at_unix=int(mapping.get("generated_at_unix", 0)),
            expires_at_unix=int(mapping.get("expires_at_unix", 0)),
            expires_in_seconds=(
                None
                if mapping.get("expires_in_seconds") is None
                else int(mapping["expires_in_seconds"])
            ),
            servable=bool(mapping.get("servable", False)),
        )


@dataclass(frozen=True)
class SorafsAliasWarning:
    """Warning raised when proofs enter the refresh window or rotation deadline."""

    alias: Optional[str]
    evaluation: SorafsAliasEvaluation
    status_header: Optional[str]


class SorafsAliasError(RuntimeError):
    """Raised when alias proofs are missing or fail policy checks."""


@dataclass(frozen=True)
class SorafsReplicationAssignment:
    """Assignment binding a provider to store a manifest slice."""

    provider_id_hex: str
    slice_gib: int
    lane: Optional[str]


@dataclass(frozen=True)
class SorafsReplicationSla:
    """Service-level agreement expectations for a replication order."""

    ingest_deadline_secs: int
    min_availability_percent_milli: int
    min_por_success_percent_milli: int


@dataclass(frozen=True)
class SorafsReplicationMetadataEntry:
    """Metadata entry embedded in a replication order."""

    key: str
    value: str


@dataclass(frozen=True)
class SorafsReplicationOrder:
    """Structured view over a Norito-encoded replication order."""

    schema_version: int
    order_id_hex: str
    manifest_cid_utf8: Optional[str]
    manifest_cid_base64: str
    manifest_digest_hex: str
    chunking_profile: str
    target_replicas: int
    assignments: Tuple[SorafsReplicationAssignment, ...]
    issued_at_unix: int
    deadline_at_unix: int
    sla: SorafsReplicationSla
    metadata: Tuple[SorafsReplicationMetadataEntry, ...]


def evaluate_alias_proof(
    proof_b64: str,
    policy: Optional[SorafsAliasPolicy] = None,
    *,
    now_secs: Optional[int] = None,
) -> SorafsAliasEvaluation:
    """Validate a base64-encoded alias proof bundle."""

    if policy is None:
        policy_value = SorafsAliasPolicy.defaults()
    elif isinstance(policy, SorafsAliasPolicy):
        policy_value = policy
    else:
        raise TypeError("policy must be a SorafsAliasPolicy or None")
    evaluated_at = (
        None
        if now_secs is None
        else _coerce_non_negative_int(now_secs, "now_secs")
    )
    result = _crypto.sorafs_evaluate_alias_proof(
        proof_b64,
        policy_value.to_mapping(),
        evaluated_at,
    )
    if not isinstance(result, Mapping):
        raise TypeError("alias proof evaluation returned unexpected payload")
    return SorafsAliasEvaluation.from_mapping(result)


def enforce_alias_policy(
    response: Any,
    *,
    policy: Optional[SorafsAliasPolicy] = None,
    now_secs: Optional[int] = None,
    warning_hook: Optional[Callable[[SorafsAliasWarning], None]] = None,
    logger: Optional[logging.Logger] = None,
) -> Optional[SorafsAliasEvaluation]:
    """Inspect an HTTP response and enforce SoraFS alias policy when headers are present."""

    status = getattr(response, "status_code", None)
    if status != 200:
        return None
    headers = getattr(response, "headers", None)
    if not isinstance(headers, MutableMapping):
        return None
    proof_b64 = headers.get(_HEADER_SORA_PROOF)
    if not proof_b64:
        return None
    alias = headers.get(_HEADER_SORA_NAME)
    status_header = headers.get(_HEADER_SORA_PROOF_STATUS)

    evaluation = evaluate_alias_proof(
        str(proof_b64),
        policy=policy,
        now_secs=now_secs,
    )
    if not evaluation.servable:
        status_hint = f"; header reported {status_header}" if status_header else ""
        alias_label = alias if alias else "<unknown>"
        raise SorafsAliasError(
            f"alias proof for '{alias_label}' rejected: state {evaluation.status_label}{status_hint} "
            f"(age {evaluation.age_seconds} seconds)"
        )

    needs_warning = evaluation.state == "refresh_window" or evaluation.rotation_due
    if needs_warning:
        warning = SorafsAliasWarning(alias=alias, evaluation=evaluation, status_header=status_header)
        if warning_hook:
            warning_hook(warning)
        (logger or _LOGGER).warning(
            "SoraFS alias '%s' nearing refresh window: status=%s age=%s",
            alias or "<unknown>",
            evaluation.status_label,
            evaluation.age_seconds,
        )

    return evaluation


def alias_proof_fixture(**options: Any) -> Mapping[str, Any]:
    """Return a deterministic alias proof fixture for testing."""

    payload = _crypto.sorafs_alias_proof_fixture(options or None)
    if not isinstance(payload, Mapping):
        raise TypeError("alias_proof_fixture returned an unexpected value")
    return payload


def decode_replication_order(norito_bytes: bytes | bytearray | memoryview) -> SorafsReplicationOrder:
    """Decode a Norito-encoded replication order into typed dataclasses."""

    if isinstance(norito_bytes, memoryview):
        payload = bytes(norito_bytes)
    elif isinstance(norito_bytes, (bytes, bytearray)):
        payload = bytes(norito_bytes)
    else:
        raise TypeError("norito_bytes must be bytes-like")

    mapping = _crypto.sorafs_decode_replication_order(payload)
    if not isinstance(mapping, Mapping):
        raise TypeError("replication order decode returned unexpected payload")

    schema_version = int(mapping.get("schema_version", 0))
    order_id_hex = str(mapping.get("order_id_hex", ""))
    manifest_cid_utf8 = mapping.get("manifest_cid_utf8")
    if manifest_cid_utf8 is not None:
        manifest_cid_utf8 = str(manifest_cid_utf8)
    manifest_cid_base64 = str(mapping.get("manifest_cid_base64", ""))
    manifest_digest_hex = str(mapping.get("manifest_digest_hex", ""))
    chunking_profile = str(mapping.get("chunking_profile", ""))
    target_replicas = int(mapping.get("target_replicas", 0))
    issued_at_unix = int(mapping.get("issued_at_unix", 0))
    deadline_at_unix = int(mapping.get("deadline_at_unix", 0))

    sla_mapping = mapping.get("sla")
    if not isinstance(sla_mapping, Mapping):
        sla_mapping = {}
    sla = SorafsReplicationSla(
        ingest_deadline_secs=int(sla_mapping.get("ingest_deadline_secs", 0)),
        min_availability_percent_milli=int(
            sla_mapping.get("min_availability_percent_milli", 0)
        ),
        min_por_success_percent_milli=int(
            sla_mapping.get("min_por_success_percent_milli", 0)
        ),
    )

    assignments_raw = mapping.get("assignments", [])
    assignments: Tuple[SorafsReplicationAssignment, ...] = tuple(
        SorafsReplicationAssignment(
            provider_id_hex=str(entry.get("provider_id_hex", "")),
            slice_gib=int(entry.get("slice_gib", 0)),
            lane=(
                None
                if entry.get("lane") is None
                else str(entry.get("lane"))
            ),
        )
        for entry in assignments_raw
        if isinstance(entry, Mapping)
    )

    metadata_raw = mapping.get("metadata", [])
    metadata: Tuple[SorafsReplicationMetadataEntry, ...] = tuple(
        SorafsReplicationMetadataEntry(
            key=str(entry.get("key", "")),
            value=str(entry.get("value", "")),
        )
        for entry in metadata_raw
        if isinstance(entry, Mapping)
    )

    return SorafsReplicationOrder(
        schema_version=schema_version,
        order_id_hex=order_id_hex,
        manifest_cid_utf8=manifest_cid_utf8,
        manifest_cid_base64=manifest_cid_base64,
        manifest_digest_hex=manifest_digest_hex,
        chunking_profile=chunking_profile,
        target_replicas=target_replicas,
        assignments=assignments,
        issued_at_unix=issued_at_unix,
        deadline_at_unix=deadline_at_unix,
        sla=sla,
        metadata=metadata,
    )


ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 = 256
SORAFS_ORDERBOOK_PAYLOAD_KINDS: Mapping[str, str] = MappingProxyType(
    {
        "ORDER_REQUEST": "order-request",
        "ORDER_CANCEL": "order-cancel",
        "TRADE_EVENT": "trade-event",
        "SETTLEMENT_CHANNEL": "settlement-channel",
        "SETTLEMENT_RECEIPT": "settlement-receipt",
    }
)
SORAFS_PDP_PAYLOAD_KINDS: Mapping[str, str] = MappingProxyType(
    {
        "COMMITMENT": "commitment",
        "CHALLENGE": "challenge",
        "PROOF": "proof",
    }
)
SORAFS_FIXTURE_BUNDLE_PAYLOAD_KINDS: Mapping[str, str] = MappingProxyType(
    {
        "PROVIDER_ADVERT": "provider-advert",
        "PROVIDER_ADMISSION_ENVELOPE": "provider-admission-envelope",
        "REPLICATION_ORDER": "replication-order",
        "POR_CHALLENGE": "por-challenge",
        "POR_PROOF": "por-proof",
        "POTR_RECEIPT": "potr-receipt",
        "REPAIR_EVIDENCE": "repair-evidence",
        "REPAIR_REPORT": "repair-report",
        "REPAIR_TASK_RECORD": "repair-task-record",
        "REPAIR_SLASH_PROPOSAL": "repair-slash-proposal",
        "REPAIR_TASK_EVENT": "repair-task-event",
        "ORDERBOOK_ORDER_REQUEST": "orderbook-order-request",
        "ORDERBOOK_ORDER_CANCEL": "orderbook-order-cancel",
        "ORDERBOOK_TRADE_EVENT": "orderbook-trade-event",
        "ORDERBOOK_SETTLEMENT_CHANNEL": "orderbook-settlement-channel",
        "ORDERBOOK_SETTLEMENT_RECEIPT": "orderbook-settlement-receipt",
        "PDP_COMMITMENT": "pdp-commitment",
        "PDP_CHALLENGE": "pdp-challenge",
        "PDP_PROOF": "pdp-proof",
    }
)
SORAFS_FIXTURE_BUNDLE_MAX_PAYLOADS_V1 = 64
SORAFS_GOVERNANCE_DAG_CID_BYTES_V1 = 32
SORAFS_GOVERNANCE_DAG_MAX_BLOCKS_V1 = 64
SORAFS_REFERENCE_MAX_INPUT_BYTES_V1 = 67_108_864
SORAFS_REFERENCE_MAX_LABEL_BYTES_V1 = 1_024

_ORDERBOOK_PAYLOAD_KIND_VALUES = frozenset(SORAFS_ORDERBOOK_PAYLOAD_KINDS.values())
_PDP_PAYLOAD_KIND_VALUES = frozenset(SORAFS_PDP_PAYLOAD_KINDS.values())
_FIXTURE_BUNDLE_PAYLOAD_KIND_VALUES = frozenset(
    SORAFS_FIXTURE_BUNDLE_PAYLOAD_KINDS.values()
)
_ORDERBOOK_SIDE_VALUES = frozenset(("bid", "ask"))
_ORDERBOOK_TIER_VALUES = frozenset(("hot", "warm", "archive"))
_ORDERBOOK_CANCEL_REASON_VALUES = frozenset(
    ("owner_requested", "expired", "governance", "replaced")
)
_U64_MAX = (1 << 64) - 1
_XOR_QUANTITY_MAX_TEXT_LENGTH = 155
_MISSING = object()


def _bytes_payload(value: bytes | bytearray | memoryview, field: str) -> bytes:
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError(f"{field} must be bytes-like")


@dataclass(frozen=True)
class SorafsGovernanceDagBlockInput:
    """One ordered governance DAG block used for signed-head-chain validation."""

    payload: bytes | bytearray | memoryview
    label: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", _bytes_payload(self.payload, "payload"))
        if self.label is not None:
            _governance_reference_label(self.label, "", "label")


@dataclass(frozen=True)
class SorafsFixtureBundlePayloadInput:
    """One typed canonical payload supplied to fixture-bundle validation."""

    kind: str
    payload: bytes | bytearray | memoryview
    label: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "kind",
            _normalize_reference_kind(
                self.kind,
                _FIXTURE_BUNDLE_PAYLOAD_KIND_VALUES,
                "fixture-bundle",
            ),
        )
        object.__setattr__(self, "payload", _bytes_payload(self.payload, "payload"))
        object.__setattr__(
            self,
            "label",
            _governance_reference_label(
                self.label,
                f"{self.kind}.to",
                "label",
            ),
        )


def _orderbook_owner_account(value: bytes | bytearray | memoryview, field: str) -> bytes:
    payload = _bytes_payload(value, field)
    if not payload:
        raise ValueError(f"{field} must not be empty")
    if len(payload) > ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1:
        raise ValueError(
            f"{field} must be at most {ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1} bytes"
        )
    return payload


def _required_field(mapping: Mapping[str, Any], field: str, *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            value = mapping[key]
            if value is None:
                break
            return value
    raise TypeError(f"{field} is required")


def _optional_field(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            value = mapping[key]
            return _MISSING if value is None else value
    return _MISSING


def _decimal_integer_text(value: Any, field: str, *, positive: bool = False) -> str:
    if isinstance(value, bool):
        raise TypeError(f"{field} must be an unsigned decimal integer")
    if isinstance(value, int):
        if value < 0 or (positive and value <= 0):
            qualifier = "greater than zero" if positive else "non-negative"
            raise ValueError(f"{field} must be {qualifier}")
        return str(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped.isdecimal():
            raise ValueError(f"{field} must be an unsigned decimal integer")
        if positive and int(stripped) <= 0:
            raise ValueError(f"{field} must be greater than zero")
        return stripped
    raise TypeError(f"{field} must be an unsigned decimal integer")


def _xor_quantity_text(value: Any, field: str, *, positive: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(f"{field} must be a canonical XOR quantity string")
    if len(value) > _XOR_QUANTITY_MAX_TEXT_LENGTH:
        raise ValueError(f"{field} exceeds the bounded XOR quantity text length")
    quantity = NumericV1Codec.decode_quantity_json(value)
    if quantity.scale > 9:
        raise ValueError(f"{field} must have at most 9 fractional decimal places")
    if positive and quantity.mantissa <= 0:
        raise ValueError(f"{field} must be greater than zero")
    return str(quantity)


def _reject_retired_orderbook_fields(fields: Mapping[str, Any], names: Sequence[str]) -> None:
    for name in names:
        if name in fields:
            raise TypeError(f"{name} is retired from the canonical V1 SDK surface")


def _fixed32_field(mapping: Mapping[str, Any], field: str, *keys: str) -> bytes:
    payload = _bytes_payload(_required_field(mapping, field, *keys), field)
    if len(payload) != 32:
        raise ValueError(f"{field} must be exactly 32 bytes")
    return payload


def _bytes_field(mapping: Mapping[str, Any], field: str, *keys: str) -> bytes:
    return _orderbook_owner_account(_required_field(mapping, field, *keys), field)


def _orderbook_fee_bps(value: Any, field: str) -> int:
    text = _decimal_integer_text(value, field)
    fee = int(text)
    if fee > 0xFFFF:
        raise ValueError(f"{field} must fit within a 16-bit unsigned integer")
    return fee


def _normalize_reference_kind(kind: str, canonical: frozenset[str], label: str) -> str:
    if not isinstance(kind, str):
        raise TypeError("kind must be a string")
    if kind not in canonical:
        raise ValueError(f"unsupported SoraFS {label} payload kind: {kind}")
    return kind


def _normalize_orderbook_payload_kind(kind: str) -> str:
    return _normalize_reference_kind(kind, _ORDERBOOK_PAYLOAD_KIND_VALUES, "orderbook")


def _normalize_pdp_payload_kind(kind: str) -> str:
    return _normalize_reference_kind(kind, _PDP_PAYLOAD_KIND_VALUES, "PDP")


def _canonical_orderbook_selector(value: Any, allowed: frozenset[str], field: str) -> str:
    if type(value) is not str or value not in allowed:
        raise ValueError(f"{field} is not a canonical V1 selector")
    return value


def _normalize_reference_unix(
    value: Optional[int],
    field: str,
    *,
    default_now: bool,
) -> int:
    raw = int(time.time()) if value is None and default_now else value
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise TypeError(f"{field} must be a non-negative integer")
    if raw < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    if raw > _U64_MAX:
        raise ValueError(f"{field} must fit in u64")
    return raw


def _normalize_generated_at_unix(value: Optional[int]) -> int:
    return _normalize_reference_unix(
        value,
        "generated_at_unix",
        default_now=True,
    )


def _reference_label(value: Optional[str], fallback: str, field: str) -> str:
    if value is None:
        return fallback
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    stripped = value.strip()
    return stripped if stripped else fallback


def _governance_reference_label(value: Optional[str], fallback: str, field: str) -> str:
    label = fallback if value is None else value
    if not isinstance(label, str):
        raise TypeError(f"{field} must be a string")
    if not label or not label.strip():
        raise ValueError(f"{field} must not be blank")
    if label.strip() != label:
        raise ValueError(f"{field} must not contain surrounding whitespace")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in label):
        raise ValueError(f"{field} must be valid Unicode text")
    if any(
        ord(character) <= 0x1F or 0x7F <= ord(character) <= 0x9F
        for character in label
    ):
        raise ValueError(f"{field} must not contain control characters")
    if len(label.encode("utf-8")) > SORAFS_REFERENCE_MAX_LABEL_BYTES_V1:
        raise ValueError(
            f"{field} must be at most {SORAFS_REFERENCE_MAX_LABEL_BYTES_V1} UTF-8 bytes"
        )
    return label


def _governance_reference_aggregate_bytes(context: str, *sizes: int) -> None:
    total = 0
    for size in sizes:
        total += size
        if total > SORAFS_REFERENCE_MAX_INPUT_BYTES_V1:
            raise ValueError(
                f"{context} inputs exceed "
                f"{SORAFS_REFERENCE_MAX_INPUT_BYTES_V1} aggregate bytes"
            )


def _reference_outcome_from_json(payload: Any, capability: str) -> Dict[str, Any]:
    if not isinstance(payload, str):
        raise TypeError(f"native {capability} returned a non-string payload")
    outcome = json.loads(payload)
    if not isinstance(outcome, dict):
        raise TypeError(f"native {capability} returned an invalid outcome")
    return outcome


def _require_sorafs_native_function(
    function_name: str,
    capability: str,
) -> Callable[..., Any]:
    try:
        function = getattr(_crypto, function_name)
    except (AttributeError, RuntimeError) as error:
        raise RuntimeError(
            f"SoraFS {capability} requires native function `{function_name}`. "
            "Install or rebuild the iroha_native._crypto extension."
        ) from error
    if not callable(function):
        raise RuntimeError(
            f"SoraFS {capability} requires callable native function `{function_name}`. "
            "Install or rebuild the iroha_native._crypto extension."
        )
    return function


def validate_orderbook_payload(
    kind: str,
    norito_bytes: bytes | bytearray | memoryview,
    *,
    label: Optional[str] = None,
    generated_at_unix: Optional[int] = None,
) -> Dict[str, Any]:
    """Validate a Norito-encoded orderbook payload with the Rust reference validator."""

    canonical_kind = _normalize_orderbook_payload_kind(kind)
    payload = _crypto.sorafs_validate_orderbook_payload_json(
        canonical_kind,
        _bytes_payload(norito_bytes, "norito_bytes"),
        _reference_label(label, f"sdk:sorafs.orderbook.{canonical_kind}", "label"),
        _normalize_generated_at_unix(generated_at_unix),
    )
    return _reference_outcome_from_json(payload, "orderbook validation")


def validate_appeal_finance_cancel_asset_lock(
    norito_bytes: bytes | bytearray | memoryview,
    *,
    label: Optional[str] = None,
    generated_at_unix: Optional[int] = None,
) -> Dict[str, Any]:
    """Diagnose one bare appeal-finance ``CancelAssetLock`` V1 archive."""

    payload_bytes = _bytes_payload(norito_bytes, "norito_bytes")
    resolved_label = _reference_label(
        label,
        "sdk:sorafs.appeal_finance.cancel_asset_lock",
        "label",
    )
    generated_at = _normalize_generated_at_unix(generated_at_unix)
    native = _require_sorafs_native_function(
        "sorafs_validate_appeal_finance_cancel_asset_lock_json",
        "appeal-finance CancelAssetLock validation",
    )
    payload = native(
        payload_bytes,
        resolved_label,
        generated_at,
    )
    return _reference_outcome_from_json(
        payload,
        "appeal-finance CancelAssetLock validation",
    )


def sign_orderbook_payload(
    kind: str,
    norito_bytes: bytes | bytearray | memoryview,
    private_key: bytes | bytearray | memoryview,
) -> bytes:
    """Sign a Norito-encoded mutable orderbook payload with an Ed25519 private key."""

    canonical_kind = _normalize_orderbook_payload_kind(kind)
    return bytes(
        _crypto.sorafs_sign_orderbook_payload(
            canonical_kind,
            _bytes_payload(norito_bytes, "norito_bytes"),
            _bytes_payload(private_key, "private_key"),
        )
    )


def derive_orderbook_order_id(
    owner_account: bytes | bytearray | memoryview,
    nonce: int | str,
) -> bytes:
    """Derive the canonical V1 order id from owner-account bytes and nonce."""

    owner = _orderbook_owner_account(owner_account, "owner_account")
    canonical_nonce = _decimal_integer_text(nonce, "nonce", positive=True)
    order_id = bytes(_crypto.sorafs_derive_orderbook_order_id(owner, canonical_nonce))
    if len(order_id) != 32:
        raise RuntimeError("native binding returned a non-32-byte orderbook order id")
    return order_id


def build_signed_orderbook_order_request(
    fields: Mapping[str, Any],
    private_key: bytes | bytearray | memoryview,
) -> bytes:
    """Build and sign canonical Norito `OrderRequestV1` bytes from field values."""

    if not isinstance(fields, Mapping):
        raise TypeError("fields must be a mapping")
    _reject_retired_orderbook_fields(
        fields,
        (
            "orderId",
            "pricePerGib",
            "quantityGib",
            "remainingGib",
            "ownerAccount",
            "providerId",
            "expiryUnix",
            "makerFeeBps",
            "takerFeeBps",
            "price_per_gib_micro_xor",
            "pricePerGibMicroXor",
            "price_per_gib_micro",
            "pricePerGibMicro",
        ),
    )
    side = _canonical_orderbook_selector(
        _required_field(fields, "side", "side"), _ORDERBOOK_SIDE_VALUES, "side"
    )
    tier = _canonical_orderbook_selector(
        _required_field(fields, "tier", "tier"), _ORDERBOOK_TIER_VALUES, "tier"
    )
    quantity_gib = _decimal_integer_text(
        _required_field(fields, "quantity_gib", "quantity_gib"),
        "quantity_gib",
        positive=True,
    )
    remaining_gib = _optional_field(fields, "remaining_gib")
    owner_account = _bytes_field(fields, "owner_account", "owner_account")
    provider_value = _optional_field(fields, "provider_id")
    provider_id = (
        b""
        if provider_value is _MISSING
        else _bytes_payload(provider_value, "provider_id")
    )
    if side == "bid":
        if provider_id:
            raise ValueError("provider_id must be absent or empty for bid orders")
    else:
        if len(provider_id) != 32:
            raise ValueError("provider_id must be exactly 32 bytes for ask orders")
        if provider_id == bytes(32):
            raise ValueError("provider_id must not be all zero")
    nonce = _decimal_integer_text(
        _required_field(fields, "nonce", "nonce"),
        "nonce",
        positive=True,
    )
    price_per_gib = _xor_quantity_text(
        _required_field(fields, "price_per_gib", "price_per_gib"),
        "price_per_gib",
        positive=True,
    )
    order_id = derive_orderbook_order_id(owner_account, nonce)
    supplied_order_id = _optional_field(fields, "order_id")
    if supplied_order_id is not _MISSING:
        supplied = _bytes_payload(supplied_order_id, "order_id")
        if len(supplied) != 32 or supplied != order_id:
            raise ValueError(
                "order_id must equal the canonical owner-and-nonce derivation "
                f"{order_id.hex()}"
            )
    return bytes(
        _crypto.sorafs_build_signed_orderbook_order_request(
            order_id,
            side,
            tier,
            price_per_gib,
            quantity_gib,
            None
            if remaining_gib is _MISSING
            else _decimal_integer_text(remaining_gib, "remaining_gib", positive=True),
            owner_account,
            provider_id,
            _decimal_integer_text(
                _required_field(fields, "expiry_unix", "expiry_unix"),
                "expiry_unix",
                positive=True,
            ),
            nonce,
            _orderbook_fee_bps(
                _required_field(fields, "maker_fee_bps", "maker_fee_bps"),
                "maker_fee_bps",
            ),
            _orderbook_fee_bps(
                _required_field(fields, "taker_fee_bps", "taker_fee_bps"),
                "taker_fee_bps",
            ),
            _bytes_payload(private_key, "private_key"),
        )
    )


def build_signed_orderbook_order_cancel(
    fields: Mapping[str, Any],
    private_key: bytes | bytearray | memoryview,
) -> bytes:
    """Build and sign canonical Norito `OrderCancelV1` bytes from field values."""

    if not isinstance(fields, Mapping):
        raise TypeError("fields must be a mapping")
    _reject_retired_orderbook_fields(fields, ("orderId", "ownerAccount"))
    reason = _canonical_orderbook_selector(
        _required_field(fields, "reason", "reason"),
        _ORDERBOOK_CANCEL_REASON_VALUES,
        "reason",
    )
    return bytes(
        _crypto.sorafs_build_signed_orderbook_order_cancel(
            _fixed32_field(fields, "order_id", "order_id"),
            _bytes_field(fields, "owner_account", "owner_account"),
            reason,
            _decimal_integer_text(
                _required_field(fields, "nonce", "nonce"),
                "nonce",
                positive=True,
            ),
            _bytes_payload(private_key, "private_key"),
        )
    )


def build_signed_orderbook_settlement_receipt(
    fields: Mapping[str, Any],
    private_key: bytes | bytearray | memoryview,
) -> bytes:
    """Build and sign canonical Norito `SettlementReceiptV1` bytes from field values."""

    if not isinstance(fields, Mapping):
        raise TypeError("fields must be a mapping")
    _reject_retired_orderbook_fields(
        fields,
        (
            "receiptId",
            "channelId",
            "tradeId",
            "rangeStart",
            "rangeEnd",
            "chunkHash",
            "bytesDelivered",
            "xorDebited",
            "providerCredit",
            "feeAmount",
            "issuedAtUnix",
            "xor_debited_micro_xor",
            "xorDebitedMicroXor",
            "xor_debited_micro",
            "xorDebitedMicro",
            "provider_credit_micro_xor",
            "providerCreditMicroXor",
            "provider_credit_micro",
            "providerCreditMicro",
            "fee_amount_micro_xor",
            "feeAmountMicroXor",
            "fee_amount_micro",
            "feeAmountMicro",
        ),
    )
    xor_debited = _xor_quantity_text(
        _required_field(fields, "xor_debited", "xor_debited"),
        "xor_debited",
        positive=True,
    )
    provider_credit = _xor_quantity_text(
        _required_field(fields, "provider_credit", "provider_credit"),
        "provider_credit",
    )
    fee_amount = _xor_quantity_text(
        _required_field(fields, "fee_amount", "fee_amount"),
        "fee_amount",
    )
    return bytes(
        _crypto.sorafs_build_signed_orderbook_settlement_receipt(
            _fixed32_field(fields, "receipt_id", "receipt_id"),
            _fixed32_field(fields, "channel_id", "channel_id"),
            _fixed32_field(fields, "trade_id", "trade_id"),
            _decimal_integer_text(
                _required_field(fields, "range_start", "range_start"),
                "range_start",
            ),
            _decimal_integer_text(
                _required_field(fields, "range_end", "range_end"),
                "range_end",
                positive=True,
            ),
            _fixed32_field(fields, "chunk_hash", "chunk_hash"),
            _decimal_integer_text(
                _required_field(fields, "bytes_delivered", "bytes_delivered"),
                "bytes_delivered",
                positive=True,
            ),
            xor_debited,
            provider_credit,
            fee_amount,
            _decimal_integer_text(
                _required_field(fields, "issued_at_unix", "issued_at_unix"),
                "issued_at_unix",
                positive=True,
            ),
            _bytes_payload(private_key, "private_key"),
        )
    )


def validate_pdp_payload(
    kind: str,
    norito_bytes: bytes | bytearray | memoryview,
    *,
    label: Optional[str] = None,
    generated_at_unix: Optional[int] = None,
) -> Dict[str, Any]:
    """Diagnose one PDP payload; success never authorizes production acceptance."""

    canonical_kind = _normalize_pdp_payload_kind(kind)
    payload = _crypto.sorafs_validate_pdp_payload_json(
        canonical_kind,
        _bytes_payload(norito_bytes, "norito_bytes"),
        _reference_label(label, f"sdk:sorafs.pdp.{canonical_kind}", "label"),
        _normalize_generated_at_unix(generated_at_unix),
    )
    return _reference_outcome_from_json(payload, "PDP validation")


def validate_pdp_commitment_challenge(
    commitment_bytes: bytes | bytearray | memoryview,
    challenge_bytes: bytes | bytearray | memoryview,
    *,
    commitment_label: Optional[str] = None,
    challenge_label: Optional[str] = None,
    generated_at_unix: Optional[int] = None,
) -> Dict[str, Any]:
    """Diagnose commitment/challenge binding without admission or Merkle witnesses."""

    payload = _crypto.sorafs_validate_pdp_commitment_challenge_json(
        _bytes_payload(commitment_bytes, "commitment_bytes"),
        _reference_label(commitment_label, "sdk:sorafs.pdp.commitment", "commitment_label"),
        _bytes_payload(challenge_bytes, "challenge_bytes"),
        _reference_label(challenge_label, "sdk:sorafs.pdp.challenge", "challenge_label"),
        _normalize_generated_at_unix(generated_at_unix),
    )
    return _reference_outcome_from_json(payload, "PDP commitment/challenge validation")


def validate_pdp_challenge_proof(
    challenge_bytes: bytes | bytearray | memoryview,
    proof_bytes: bytes | bytearray | memoryview,
    *,
    challenge_label: Optional[str] = None,
    proof_label: Optional[str] = None,
    generated_at_unix: Optional[int] = None,
) -> Dict[str, Any]:
    """Diagnose challenge/proof binding without admission or commitment roots."""

    payload = _crypto.sorafs_validate_pdp_challenge_proof_json(
        _bytes_payload(challenge_bytes, "challenge_bytes"),
        _reference_label(challenge_label, "sdk:sorafs.pdp.challenge", "challenge_label"),
        _bytes_payload(proof_bytes, "proof_bytes"),
        _reference_label(proof_label, "sdk:sorafs.pdp.proof", "proof_label"),
        _normalize_generated_at_unix(generated_at_unix),
    )
    return _reference_outcome_from_json(payload, "PDP challenge/proof validation")


def validate_pdp_bundle(
    commitment_bytes: bytes | bytearray | memoryview,
    challenge_bytes: bytes | bytearray | memoryview,
    proof_bytes: bytes | bytearray | memoryview,
    *,
    commitment_label: Optional[str] = None,
    challenge_label: Optional[str] = None,
    proof_label: Optional[str] = None,
    generated_at_unix: Optional[int] = None,
) -> Dict[str, Any]:
    """Diagnose PDP bytes and both roots without evaluating governed admission.

    Success returns ``SFS-PDP-DIAG-000`` with
    ``production_acceptance=false`` and must not be used as production proof
    acceptance.
    """

    payload = _crypto.sorafs_validate_pdp_bundle_json(
        _bytes_payload(commitment_bytes, "commitment_bytes"),
        _reference_label(commitment_label, "sdk:sorafs.pdp.commitment", "commitment_label"),
        _bytes_payload(challenge_bytes, "challenge_bytes"),
        _reference_label(challenge_label, "sdk:sorafs.pdp.challenge", "challenge_label"),
        _bytes_payload(proof_bytes, "proof_bytes"),
        _reference_label(proof_label, "sdk:sorafs.pdp.proof", "proof_label"),
        _normalize_generated_at_unix(generated_at_unix),
    )
    return _reference_outcome_from_json(payload, "PDP bundle validation")


def validate_fixture_bundle(
    payloads: Sequence[SorafsFixtureBundlePayloadInput],
    *,
    now_unix: Optional[int] = None,
    generated_at_unix: Optional[int] = None,
) -> Dict[str, Any]:
    """Validate a bounded heterogeneous fixture bundle and canonical cross-links."""

    if isinstance(payloads, (str, bytes, bytearray, memoryview)) or not isinstance(
        payloads,
        Sequence,
    ):
        raise TypeError(
            "payloads must be a sequence of SorafsFixtureBundlePayloadInput"
        )
    if not 1 <= len(payloads) <= SORAFS_FIXTURE_BUNDLE_MAX_PAYLOADS_V1:
        raise ValueError(
            "payloads must contain "
            f"1..={SORAFS_FIXTURE_BUNDLE_MAX_PAYLOADS_V1} entries"
        )
    native_payloads: list[tuple[str, bytes, str]] = []
    aggregate_bytes = 0
    for index, payload in enumerate(payloads):
        if not isinstance(payload, SorafsFixtureBundlePayloadInput):
            raise TypeError(
                f"payloads[{index}] must be a SorafsFixtureBundlePayloadInput"
            )
        label = payload.label
        if label is None:  # Frozen input normalization makes this unreachable.
            raise ValueError(f"payloads[{index}].label must be present")
        aggregate_bytes += len(payload.payload) + len(label.encode("utf-8"))
        if aggregate_bytes > SORAFS_REFERENCE_MAX_INPUT_BYTES_V1:
            raise ValueError(
                "fixture-bundle inputs exceed "
                f"{SORAFS_REFERENCE_MAX_INPUT_BYTES_V1} aggregate bytes"
            )
        native_payloads.append((payload.kind, bytes(payload.payload), label))
    generated_at = _normalize_generated_at_unix(generated_at_unix)
    resolved_now = _normalize_reference_unix(
        generated_at if now_unix is None else now_unix,
        "now_unix",
        default_now=False,
    )
    outcome = _crypto.sorafs_validate_fixture_bundle_json(
        native_payloads,
        resolved_now,
        generated_at,
    )
    return _reference_outcome_from_json(outcome, "fixture-bundle validation")


def validate_governance_log_node(
    norito_bytes: bytes | bytearray | memoryview,
    *,
    expected_node_cid: bytes | bytearray | memoryview,
    label: Optional[str] = None,
    generated_at_unix: Optional[int] = None,
) -> Dict[str, Any]:
    """Validate a canonical governance log node bound to its expected CID."""

    payload_bytes = _bytes_payload(norito_bytes, "norito_bytes")
    resolved_label = _governance_reference_label(
        label,
        "governance.to",
        "label",
    )
    expected_cid = _bytes_payload(expected_node_cid, "expected_node_cid")
    if len(expected_cid) != SORAFS_GOVERNANCE_DAG_CID_BYTES_V1:
        raise ValueError(
            "expected_node_cid must contain exactly "
            f"{SORAFS_GOVERNANCE_DAG_CID_BYTES_V1} bytes"
        )
    _governance_reference_aggregate_bytes(
        "governance log-node validation",
        len(payload_bytes),
        len(resolved_label.encode("utf-8")),
        len(expected_cid),
    )
    native_validator = _require_sorafs_native_function(
        "sorafs_validate_governance_log_node_json",
        "governance log-node validation",
    )
    outcome = native_validator(
        payload_bytes,
        resolved_label,
        expected_cid,
        _normalize_generated_at_unix(generated_at_unix),
    )
    return _reference_outcome_from_json(outcome, "governance log-node validation")


def validate_governance_dag_block(
    norito_bytes: bytes | bytearray | memoryview,
    *,
    label: Optional[str] = None,
    expected_block_cid: Optional[bytes | bytearray | memoryview] = None,
    generated_at_unix: Optional[int] = None,
) -> Dict[str, Any]:
    """Validate one canonical governance DAG block with the Rust reference validator."""

    payload_bytes = _bytes_payload(norito_bytes, "norito_bytes")
    resolved_label = _governance_reference_label(
        label,
        "governance-dag-block.to",
        "label",
    )
    expected_cid = (
        None
        if expected_block_cid is None
        else _bytes_payload(expected_block_cid, "expected_block_cid")
    )
    if (
        expected_cid is not None
        and len(expected_cid) != SORAFS_GOVERNANCE_DAG_CID_BYTES_V1
    ):
        raise ValueError(
            "expected_block_cid must contain exactly "
            f"{SORAFS_GOVERNANCE_DAG_CID_BYTES_V1} bytes"
        )
    _governance_reference_aggregate_bytes(
        "governance DAG block validation",
        len(payload_bytes),
        len(resolved_label.encode("utf-8")),
        0 if expected_cid is None else len(expected_cid),
    )
    outcome = _crypto.sorafs_validate_governance_dag_block_json(
        payload_bytes,
        resolved_label,
        expected_cid,
        _normalize_generated_at_unix(generated_at_unix),
    )
    return _reference_outcome_from_json(outcome, "governance DAG block validation")


def validate_governance_dag_head_chain(
    head_bytes: bytes | bytearray | memoryview,
    blocks: Sequence[SorafsGovernanceDagBlockInput],
    *,
    head_label: Optional[str] = None,
    generated_at_unix: Optional[int] = None,
) -> Dict[str, Any]:
    """Validate a signed head against a bounded, ordered contiguous DAG block tail."""

    if isinstance(blocks, (str, bytes, bytearray, memoryview)) or not isinstance(
        blocks, Sequence
    ):
        raise TypeError("blocks must be a sequence of SorafsGovernanceDagBlockInput")
    if not 1 <= len(blocks) <= SORAFS_GOVERNANCE_DAG_MAX_BLOCKS_V1:
        raise ValueError(
            f"blocks must contain 1..={SORAFS_GOVERNANCE_DAG_MAX_BLOCKS_V1} entries"
        )
    head = _bytes_payload(head_bytes, "head_bytes")
    resolved_head_label = _governance_reference_label(
        head_label,
        "governance-dag-head.to",
        "head_label",
    )
    block_payloads: list[bytes] = []
    block_labels: list[str] = []
    aggregate_sizes = [len(head), len(resolved_head_label.encode("utf-8"))]
    for index, block in enumerate(blocks):
        if not isinstance(block, SorafsGovernanceDagBlockInput):
            raise TypeError(
                f"blocks[{index}] must be a SorafsGovernanceDagBlockInput"
            )
        payload = _bytes_payload(block.payload, f"blocks[{index}].payload")
        label = _governance_reference_label(
            block.label,
            f"governance-dag-block-{index}.to",
            f"blocks[{index}].label",
        )
        block_payloads.append(payload)
        block_labels.append(label)
        aggregate_sizes.extend([len(payload), len(label.encode("utf-8"))])
    _governance_reference_aggregate_bytes(
        "governance DAG head-chain validation",
        *aggregate_sizes,
    )
    outcome = _crypto.sorafs_validate_governance_dag_head_chain_json(
        head,
        resolved_head_label,
        block_payloads,
        block_labels,
        _normalize_generated_at_unix(generated_at_unix),
    )
    return _reference_outcome_from_json(outcome, "governance DAG head-chain validation")


# -- Multi-source orchestrator bindings ---------------------------------------------------------


def _plan_to_json(plan: Union[str, bytes, bytearray, memoryview, Mapping[str, Any], os.PathLike[str]]) -> str:
    if isinstance(plan, str):
        stripped = plan.strip()
        if not stripped:
            raise ValueError("plan must not be empty")
        return stripped
    if isinstance(plan, memoryview):
        return plan.tobytes().decode("utf-8")
    if isinstance(plan, (bytes, bytearray)):
        text = bytes(plan).decode("utf-8")
        stripped = text.strip()
        if not stripped:
            raise ValueError("plan must not be empty")
        return stripped
    if isinstance(plan, Mapping):
        return json.dumps(plan, sort_keys=True, separators=(",", ":"))
    if isinstance(plan, os.PathLike):
        path = Path(plan)
        return path.read_text(encoding="utf-8").strip()
    raise TypeError("plan must be a JSON string, mapping, bytes, or path-like object")


def _normalize_path(path: Union[str, os.PathLike[str]]) -> str:
    if isinstance(path, os.PathLike):
        value = os.fspath(path)
    else:
        value = path
    if not isinstance(value, str) or not value:
        raise TypeError("provider path must be a non-empty string or path-like object")
    return value


@dataclass(frozen=True)
class SorafsRangeCapability:
    """Range capability advertised by a provider."""

    max_chunk_span: int
    min_granularity: int
    supports_sparse_offsets: bool = True
    requires_alignment: bool = False
    supports_merkle_proof: bool = True

    def to_mapping(self) -> Mapping[str, Any]:
        return {
            "max_chunk_span": self.max_chunk_span,
            "min_granularity": self.min_granularity,
            "supports_sparse_offsets": self.supports_sparse_offsets,
            "requires_alignment": self.requires_alignment,
            "supports_merkle_proof": self.supports_merkle_proof,
        }


@dataclass(frozen=True)
class SorafsStreamBudget:
    """Per-provider concurrency + bandwidth limits."""

    max_in_flight: int
    max_bytes_per_sec: int
    burst_bytes: Optional[int] = None

    def to_mapping(self) -> Mapping[str, Any]:
        payload: Dict[str, Any] = {
            "max_in_flight": self.max_in_flight,
            "max_bytes_per_sec": self.max_bytes_per_sec,
        }
        if self.burst_bytes is not None:
            payload["burst_bytes"] = self.burst_bytes
        return payload


@dataclass(frozen=True)
class SorafsTransportHint:
    """Protocol hint used by guard/proxy selection."""

    protocol: str
    protocol_id: int
    priority: int

    def to_mapping(self) -> Mapping[str, Any]:
        return {
            "protocol": self.protocol,
            "protocol_id": self.protocol_id,
            "priority": self.priority,
        }


@dataclass(frozen=True)
class SorafsProviderMetadata:
    """Advert metadata mirrored from the scoreboard pipeline."""

    provider_id: Optional[str] = None
    profile_id: Optional[str] = None
    profile_aliases: Optional[Tuple[str, ...]] = None
    availability: Optional[str] = None
    stake_amount: Optional[str] = None
    max_streams: Optional[int] = None
    refresh_deadline: Optional[int] = None
    expires_at: Optional[int] = None
    ttl_secs: Optional[int] = None
    allow_unknown_capabilities: Optional[bool] = None
    capability_names: Optional[Tuple[str, ...]] = None
    rendezvous_topics: Optional[Tuple[str, ...]] = None
    notes: Optional[str] = None
    range_capability: Optional[SorafsRangeCapability] = None
    stream_budget: Optional[SorafsStreamBudget] = None
    transport_hints: Optional[Tuple[SorafsTransportHint, ...]] = None

    def to_mapping(self) -> Mapping[str, Any]:
        payload: Dict[str, Any] = {}
        if self.provider_id is not None:
            payload["provider_id"] = self.provider_id
        if self.profile_id is not None:
            payload["profile_id"] = self.profile_id
        if self.profile_aliases is not None:
            payload["profile_aliases"] = list(self.profile_aliases)
        if self.availability is not None:
            payload["availability"] = self.availability
        if self.stake_amount is not None:
            payload["stake_amount"] = self.stake_amount
        if self.max_streams is not None:
            payload["max_streams"] = self.max_streams
        if self.refresh_deadline is not None:
            payload["refresh_deadline"] = self.refresh_deadline
        if self.expires_at is not None:
            payload["expires_at"] = self.expires_at
        if self.ttl_secs is not None:
            payload["ttl_secs"] = self.ttl_secs
        if self.allow_unknown_capabilities is not None:
            payload["allow_unknown_capabilities"] = self.allow_unknown_capabilities
        if self.capability_names is not None:
            payload["capability_names"] = list(self.capability_names)
        if self.rendezvous_topics is not None:
            payload["rendezvous_topics"] = list(self.rendezvous_topics)
        if self.notes is not None:
            payload["notes"] = self.notes
        if self.range_capability is not None:
            payload["range_capability"] = self.range_capability.to_mapping()
        if self.stream_budget is not None:
            payload["stream_budget"] = self.stream_budget.to_mapping()
        if self.transport_hints is not None:
            payload["transport_hints"] = [hint.to_mapping() for hint in self.transport_hints]
        return payload


@dataclass(frozen=True)
class SorafsLocalProviderSpec:
    """Local provider descriptor used by the multi-fetch orchestrator."""

    name: str
    path: Union[str, os.PathLike[str]]
    max_concurrent: Optional[int] = None
    weight: Optional[int] = None
    metadata: Optional[SorafsProviderMetadata] = None

    def to_mapping(self) -> Mapping[str, Any]:
        payload: Dict[str, Any] = {
            "name": self.name,
            "path": _normalize_path(self.path),
        }
        if self.max_concurrent is not None:
            payload["max_concurrent"] = int(self.max_concurrent)
        if self.weight is not None:
            payload["weight"] = int(self.weight)
        if self.metadata is not None:
            payload["metadata"] = self.metadata.to_mapping()
        return payload


@dataclass(frozen=True)
class SorafsTelemetryEntry:
    """Telemetry snapshot consumed by the scoreboard pipeline."""

    provider_id: str
    qos_score: Optional[float] = None
    latency_p95_ms: Optional[float] = None
    failure_rate_ewma: Optional[float] = None
    token_health: Optional[float] = None
    staking_weight: Optional[float] = None
    reputation_score_bps: Optional[int] = None
    penalty: Optional[bool] = None
    last_updated_unix: Optional[int] = None

    def to_mapping(self) -> Mapping[str, Any]:
        payload: Dict[str, Any] = {"provider_id": self.provider_id}
        if self.qos_score is not None:
            payload["qos_score"] = float(self.qos_score)
        if self.latency_p95_ms is not None:
            payload["latency_p95_ms"] = float(self.latency_p95_ms)
        if self.failure_rate_ewma is not None:
            payload["failure_rate_ewma"] = float(self.failure_rate_ewma)
        if self.token_health is not None:
            payload["token_health"] = float(self.token_health)
        if self.staking_weight is not None:
            payload["staking_weight"] = float(self.staking_weight)
        if self.reputation_score_bps is not None:
            score = int(self.reputation_score_bps)
            if score < 0 or score > 10000:
                raise ValueError("reputation_score_bps must be in 0..=10000")
            payload["reputation_score_bps"] = score
        if self.penalty is not None:
            payload["penalty"] = bool(self.penalty)
        if self.last_updated_unix is not None:
            payload["last_updated_unix"] = int(self.last_updated_unix)
        return payload


@dataclass(frozen=True)
class SorafsProviderBoost:
    """Manual boost/deny entry for deterministic policy testing."""

    provider: str
    delta: int

    def to_mapping(self) -> Mapping[str, Any]:
        return {
            "provider": self.provider,
            "delta": self.delta,
        }


@dataclass(frozen=True)
class SorafsMultiFetchOptions:
    """Orchestrator knobs surfaced to Python callers."""

    verify_digests: Optional[bool] = None
    verify_lengths: Optional[bool] = None
    retry_budget: Optional[int] = None
    provider_failure_threshold: Optional[int] = None
    max_parallel: Optional[int] = None
    max_peers: Optional[int] = None
    chunker_handle: Optional[str] = None
    telemetry_region: Optional[str] = None
    telemetry: Optional[Tuple[SorafsTelemetryEntry, ...]] = None
    use_scoreboard: Optional[bool] = None
    deny_providers: Optional[Tuple[str, ...]] = None
    boost_providers: Optional[Tuple[SorafsProviderBoost, ...]] = None
    return_scoreboard: Optional[bool] = None
    scoreboard_out_path: Optional[os.PathLike[str] | str] = None
    scoreboard_now_unix_secs: Optional[int] = None
    scoreboard_telemetry_label: Optional[str] = None

    def to_mapping(self) -> Mapping[str, Any]:
        payload: Dict[str, Any] = {}
        if self.verify_digests is not None:
            payload["verify_digests"] = bool(self.verify_digests)
        if self.verify_lengths is not None:
            payload["verify_lengths"] = bool(self.verify_lengths)
        if self.retry_budget is not None:
            payload["retry_budget"] = int(self.retry_budget)
        if self.provider_failure_threshold is not None:
            payload["provider_failure_threshold"] = int(self.provider_failure_threshold)
        if self.max_parallel is not None:
            payload["max_parallel"] = int(self.max_parallel)
        if self.max_peers is not None:
            payload["max_peers"] = int(self.max_peers)
        if self.chunker_handle is not None:
            payload["chunker_handle"] = self.chunker_handle
        if self.telemetry_region is not None:
            region = self.telemetry_region.strip()
            if not region:
                raise ValueError("telemetry_region must not be empty when provided")
            payload["telemetry_region"] = region
        if self.telemetry is not None:
            payload["telemetry"] = [entry.to_mapping() for entry in self.telemetry]
        if self.use_scoreboard is not None:
            payload["use_scoreboard"] = bool(self.use_scoreboard)
        if self.deny_providers is not None:
            payload["deny_providers"] = list(self.deny_providers)
        if self.boost_providers is not None:
            payload["boost_providers"] = [entry.to_mapping() for entry in self.boost_providers]
        if self.return_scoreboard is not None:
            payload["return_scoreboard"] = bool(self.return_scoreboard)
        if self.scoreboard_out_path is not None:
            payload["scoreboard_out_path"] = os.fspath(self.scoreboard_out_path)
        if self.scoreboard_now_unix_secs is not None:
            payload["scoreboard_now_unix_secs"] = int(self.scoreboard_now_unix_secs)
        if self.scoreboard_telemetry_label is not None:
            if self.scoreboard_out_path is None:
                raise ValueError(
                    "scoreboard_telemetry_label requires scoreboard_out_path to be set"
                )
            label = self.scoreboard_telemetry_label.strip()
            if not label:
                raise ValueError("scoreboard_telemetry_label must not be empty when provided")
            payload["scoreboard_telemetry_label"] = label
        return payload


@dataclass(frozen=True)
class SorafsProviderReport:
    """Outcome summary for a provider session."""

    provider: str
    successes: int
    failures: int
    disabled: bool

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "SorafsProviderReport":
        return cls(
            provider=str(mapping.get("provider")),
            successes=int(mapping.get("successes", 0)),
            failures=int(mapping.get("failures", 0)),
            disabled=bool(mapping.get("disabled", False)),
        )


@dataclass(frozen=True)
class SorafsChunkReceipt:
    """Detailed chunk receipt emitted by the orchestrator."""

    chunk_index: int
    provider: str
    attempts: int
    latency_ms: int
    bytes: int

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "SorafsChunkReceipt":
        return cls(
            chunk_index=int(mapping.get("chunk_index", 0)),
            provider=str(mapping.get("provider")),
            attempts=int(mapping.get("attempts", 0)),
            latency_ms=int(mapping.get("latency_ms", 0)),
            bytes=int(mapping.get("bytes", 0)),
        )


@dataclass(frozen=True)
class SorafsScoreboardRow:
    """Row from the deterministic scoreboard export."""

    provider_id: str
    alias: str
    raw_score: float
    normalized_weight: float
    eligibility: str

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "SorafsScoreboardRow":
        return cls(
            provider_id=str(mapping.get("provider_id")),
            alias=str(mapping.get("alias")),
            raw_score=float(mapping.get("raw_score", 0.0)),
            normalized_weight=float(mapping.get("normalized_weight", 0.0)),
            eligibility=str(mapping.get("eligibility", "")),
        )


@dataclass(frozen=True)
class SorafsMultiFetchResult:
    """Structured result returned by :func:`multi_fetch_local`."""

    chunk_count: int
    payload: bytes
    provider_reports: Tuple[SorafsProviderReport, ...]
    chunk_receipts: Tuple[SorafsChunkReceipt, ...]
    scoreboard: Optional[Tuple[SorafsScoreboardRow, ...]]

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "SorafsMultiFetchResult":
        chunk_count = int(mapping.get("chunk_count", 0))
        payload = mapping.get("payload")
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("multi-fetch payload must be bytes-like")
        provider_reports_raw = mapping.get("provider_reports", [])
        receipts_raw = mapping.get("chunk_receipts", [])
        scoreboard_raw = mapping.get("scoreboard")
        provider_reports = tuple(
            SorafsProviderReport.from_mapping(entry)
            for entry in provider_reports_raw
            if isinstance(entry, Mapping)
        )
        receipts = tuple(
            SorafsChunkReceipt.from_mapping(entry)
            for entry in receipts_raw
            if isinstance(entry, Mapping)
        )
        scoreboard = None
        if isinstance(scoreboard_raw, Sequence):
            scoreboard = tuple(
                SorafsScoreboardRow.from_mapping(entry)
                for entry in scoreboard_raw
                if isinstance(entry, Mapping)
            )
        return cls(
            chunk_count=chunk_count,
            payload=bytes(payload),
            provider_reports=provider_reports,
            chunk_receipts=receipts,
            scoreboard=scoreboard,
        )


def multi_fetch_local(
    plan: Union[str, bytes, bytearray, memoryview, Mapping[str, Any], os.PathLike[str]],
    providers: Sequence[Union[SorafsLocalProviderSpec, Mapping[str, Any]]],
    *,
    options: Optional[SorafsMultiFetchOptions] = None,
) -> SorafsMultiFetchResult:
    """Execute the deterministic multi-source orchestrator against local payloads.

    Parameters
    ----------
    plan:
        JSON string (or mapping/path) containing the payload-bound
        ``sorafs.chunk_fetch_plan.v1`` envelope emitted by
        ``sorafs_manifest_builder``. Retired bare-array plans are rejected.
    providers:
        Iterable of :class:`SorafsLocalProviderSpec` definitions. Each entry points at a local
        payload file (tests reuse the shared fixture bundle).
    options:
        Optional :class:`SorafsMultiFetchOptions` controlling scoreboard/verification behaviour.
    """

    if not providers:
        raise ValueError("providers must contain at least one entry")
    plan_json = _plan_to_json(plan)
    provider_payloads = []
    for entry in providers:
        if isinstance(entry, SorafsLocalProviderSpec):
            provider_payloads.append(entry.to_mapping())
        elif isinstance(entry, Mapping):
            provider_payloads.append(dict(entry))
        else:
            raise TypeError("providers must be SorafsLocalProviderSpec or mapping entries")
    options_payload = options.to_mapping() if options else None
    try:
        result = _crypto.sorafs_multi_fetch_local(
            plan_json,
            provider_payloads,
            options=options_payload,
        )
    except Exception as exc:
        if _CRYPTO_IMPORT_ERROR is None and isinstance(
            exc,
            _crypto.SorafsMultiFetchError,
        ):
            raise SorafsMultiFetchError(str(exc)) from exc
        raise
    if not isinstance(result, Mapping):
        raise TypeError("multi-fetch returned an unexpected payload")
    return SorafsMultiFetchResult.from_mapping(result)
