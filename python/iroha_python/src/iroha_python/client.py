"""Client helpers for interacting with Iroha Torii endpoints."""

from __future__ import annotations

from iroha_torii_client.native_sumeragi import SumeragiStatus, SumeragiFootprint, SumeragiBeaconHorizon, SumeragiHaltReason
from iroha_torii_client.native_sumeragi import SumeragiLaneStatus, SumeragiLaneRecord, SumeragiLaneMember, SumeragiLaneFrontier, SumeragiParameters

import base64
import binascii
import copy
import hashlib
import hmac
import json
import logging
import math
import re
import secrets
import time
import unicodedata
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from decimal import Decimal
from enum import Enum
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Literal,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    TypedDict,
    Union,
)
from urllib.parse import quote, urlencode, urlparse, urlunparse

import requests
from blake3 import blake3
from iroha_torii_client._strict_json_response import (
    decode_exact_json_bytes,
    expect_status_without_body,
    read_bounded_identity_response,
)
from iroha_torii_client.canonical_request_v1 import (
    require_zero_retry_adapter as _require_zero_retry_adapter,
)
from iroha_torii_client.canonical_transport import (
    CanonicalRequestHeaderPlan as _CanonicalRequestHeaderPlan,
)
from iroha_torii_client.canonical_transport import (
    OperatorRequestHeaderPlan as _OperatorRequestHeaderPlan,
)
from iroha_torii_client.client import (
    ConfidentialGasSchedule,
    ConfigurationSnapshot,
    ElectionTally,
    GovernanceProposalDraft,
    GovernanceTally,
    NetworkTimeRttBucket,
    NetworkTimeSample,
    NetworkTimeSnapshot,
    NetworkTimeStatus,
    SorafsOrderbookSubmissionAmbiguousError,
    SorafsOrderbookSubmissionIdentity,
    SorafsOrderbookSubmissionReceipt,
    SorafsOrderbookSubmissionReceiptPayload,
    SubscriptionActionResult,
    SubscriptionCreateResult,
    SubscriptionGetResponse,
    SubscriptionPlanCreateResult,
    ToriiCanonicalRequestAuth,
    VpnProfile,
    VpnQuote,
    VpnQuoteCreateRequest,
    VpnReceipt,
    VpnReceiptListResponse,
    VpnReceiptSubmitRequest,
    VpnSession,
    VpnSessionCreateRequest,
    _read_bounded_response_body,
    build_canonical_request_headers,
    canonical_network_request_signature_message,
    canonical_query_string,
    canonical_request_message,
    inspect_i105_network_prefix,
)
from iroha_torii_client.client import (
    ToriiOperatorSigningContext as _BaseToriiOperatorSigningContext,
)
from iroha_torii_client.client import (
    ToriiClient as _BaseToriiClient,
)
from iroha_torii_client.client import (
    ToriiLocalSigningContext as _BaseLocalSigningContext,
)
from iroha_torii_client.client_status_models import (
    TransportConfig,
    TransportNoritoRpcConfig,
    parse_sumeragi_json_object,
)
from iroha_torii_client.collection import Account, AccountsCollection, Collection, Domain, HistoryCollection
from iroha_torii_client.list_query import (
    F,
    Filter,
    FilterLike,
    filter_text,
)
from iroha_torii_client.governance_proposals import (
    GovernanceCanonicalObject,
    GovernanceContractLifecycleAction,
    GovernanceContractLifecycleActionKind,
    GovernanceContractLifecycleActionPayload,
    GovernanceContractLifecycleActivate,
    GovernanceContractLifecycleDeactivate,
    GovernanceContractLifecycleEmergencyHoldRetrospective,
    GovernanceContractLifecycleOfferOwnership,
    GovernanceGlobalDataTriggerPermissionAction,
    GovernanceManifestProvenance,
    GovernanceMusubiActionKind,
    GovernanceProposalContractEmergencyHold,
    GovernanceProposalContractLifecycleGovernance,
    GovernanceProposalDeployContract,
    GovernanceProposalGlobalDataTriggerPermissionGovernance,
    GovernanceProposalKind,
    GovernanceProposalKindTag,
    GovernanceProposalLifecycleStatus,
    GovernanceProposalMusubiRegistryGovernance,
    GovernanceProposalRecord,
    GovernanceProposalResult,
    GovernanceProposalRuntimeUpgrade,
    GovernanceProposalSccpRouteGovernance,
    GovernanceProposalSorafsProviderGovernance,
    GovernanceProposalValidationFeePayoutLifecycle,
    GovernanceProposalValidationFeePolicy,
    GovernanceRuntimeUpgradeManifest,
    GovernanceSorafsProviderAction,
    GovernanceSorafsProviderActionKind,
    GovernanceValidationFeeChargingMode,
    GovernanceValidationFeePayoutBinding,
    GovernanceValidationFeeRewardCustody,
    GovernanceValidationFeePolicy,
)

from ._privacy_backends import (
    _require_production_verify_backend_label,
    _verifier_backend_registry_tag_v1,
)
from .address import (
    I105_DISCRIMINANT_MAX,
    AccountAddress,
    AccountAddressError,
    normalize_i105_discriminant,
)
from .address import (
    require_canonical_asset_definition_id as _require_canonical_asset_definition_id,
)
from .connect import (
    ConnectSessionInfo,
    _connect_session_info_from_response,
    _normalize_connect_session_request,
)
from .connect_models import (
    ConnectAdmissionManifest,
    ConnectAdmissionManifestEntry,
    ConnectAppPolicyControls,
    ConnectAppRecord,
    ConnectAppRegistryPage,
)
from .connect_transport import prepare_connect_websocket_request
from .dataspaces import (
    DataspacePlan,
    DataspaceSpec,
    DataspaceStatus,
)
from .dataspaces import (
    plan_dataspace as _plan_dataspace,
)
from .dataspaces import (
    write_dataspace_plan as _write_dataspace_plan,
)
from .nexus_app import _strict_nexus_lane_config as _strict_nexus_lane_config_impl
from .numeric_v1 import NumericV1Codec
from .repo import RepoAgreementRecord
from .sorafs import (
    SorafsAliasError,
    SorafsAliasEvaluation,
    SorafsAliasPolicy,
    SorafsAliasWarning,
)
from .sorafs import (
    enforce_alias_policy as enforce_sorafs_alias_policy,
)
from .sorafs_hedging_billing import (
    encode_sorafs_billing_acknowledgement_proof_v1,
)
from .sorafs_por import normalize_cursor as _normalize_sorafs_por_cursor
from .stream_events import (
    EventCursor,
    SseEvent,
    SseStreamError,
    WebSocketEvent,
    decode_event,
)
from .torii_client_config_normalization import (
    _coerce_duration_seconds,
    _coerce_float,
    _coerce_int,
    _coerce_timeout_seconds,
    _normalize_headers,
    _parse_retry_methods,
    _parse_retry_statuses,
)
from .torii_client_governance_ballots import (
    bind_governance_ballot_network_id,
    create_torii_client_governance_ballot_mixin,
)
from .torii_client_iso20022 import (
    OperatorSigningContext,
    ToriiClientIsoOperatorContextMixin,
)
from .torii_client_iso20022 import (
    get_iso_message_status as _get_iso_message_status,
)
from .torii_client_iso20022 import (
    is_iso_status_terminal as _is_iso_status_terminal,
)
from .torii_client_iso20022 import (
    normalize_iso_optional_string as _normalize_iso_optional_string,
)
from .torii_client_iso20022 import (
    normalize_iso_status as _normalize_iso_status,
)
from .torii_client_iso20022 import (
    normalize_iso_string_array as _normalize_iso_string_array,
)
from .torii_client_iso20022 import (
    normalize_iso_wait_kwargs as _normalize_iso_wait_kwargs,
)
from .torii_client_iso20022 import (
    normalize_pacs002_code as _normalize_pacs002_code,
)
from .torii_client_pipeline_status import (
    _extract_pipeline_status_kind,
    _normalize_transaction_status_scope,
)
from .torii_client_runtime_auth import (
    _validate_client_data_model,
    create_torii_client_runtime_auth_mixin,
)
from .torii_client_space_directory import create_torii_client_space_directory_mixin
from .torii_client_streaming_query import create_torii_client_streaming_query_mixin
if TYPE_CHECKING:  # pragma: no cover - typing only
    from .connect import _ConnectControlBase as ConnectControlBase  # noqa: F401
    from .crypto import (  # noqa: F401
        Instruction,
        NetworkId,
        PrivacyExact12CapabilityManifestV1,
        SignedTransactionEnvelope,
    )
    from .tx import AssetTransferAvailability, QuantityLike, TransactionDraft
else:  # pragma: no cover - runtime type aliases
    Instruction = Any  # type: ignore[assignment]
    NetworkId = Any  # type: ignore[assignment]
    PrivacyExact12CapabilityManifestV1 = Any  # type: ignore[assignment]
    SignedTransactionEnvelope = Any  # type: ignore[assignment]
    ConnectControlBase = Any  # type: ignore[assignment]
    QuantityLike = Any  # type: ignore[assignment]
    AssetTransferAvailability = Any  # type: ignore[assignment]
    TransactionDraft = Any  # type: ignore[assignment]


def _json_safe_value(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, Mapping):
        return {key: _json_safe_value(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_json_safe_value(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe_value(item) for item in value]
    return value


DEFAULT_I105_DISCRIMINANT = 0x02F1
# Must match `iroha_data_model::DATA_MODEL_VERSION` on the node.
DATA_MODEL_VERSION = 4
ACCOUNT_FAUCET_POW_ALGORITHM = "scrypt-leading-zero-bits-v1"
ACCOUNT_FAUCET_POW_DOMAIN_SEPARATOR = b"iroha:accounts:faucet:pow:v1"
ACCOUNT_FAUCET_MAX_SCRYPT_ROMIX_BYTES = 64 * 1024 * 1024
ACCOUNT_FAUCET_MAX_SCRYPT_PARALLELIZATION = 16
ACCOUNT_FAUCET_PUZZLE_FIELDS_V1 = frozenset(
    {
        "algorithm",
        "network_id",
        "chain_discriminant",
        "difficulty_bits",
        "anchor_height",
        "anchor_block_hash_hex",
        "challenge_salt_hex",
        "scrypt_log_n",
        "scrypt_r",
        "scrypt_p",
        "max_anchor_age_blocks",
    }
)
ACCOUNT_ONBOARDING_TOKEN_HEADER = "X-Iroha-Onboarding-Token"
PREPARED_OPERATION_BINDING_SCHEMA = "iroha.prepared-operation.binding.v1"
ACCOUNT_ONBOARDING_PREPARE_SCHEMA = "iroha.accounts.onboard.prepare.v1"
ACCOUNT_FAUCET_PREPARE_SCHEMA = "iroha.accounts.faucet.prepare.v1"
PREPARED_TRANSACTION_SCHEMA = "iroha.prepared-transaction.v1"
PREPARED_SIGNATURE_TRANSCRIPT_SCHEMA = (
    "iroha.prepared-signature-transcript.v1"
)
PREPARED_SIGNATURE_DOMAIN = b"iroha:prepared-transaction:v1\0"
ACCOUNT_ONBOARDING_PROOF_REQUIRED_SCHEMA = "iroha.accounts.onboard.prepare-proof-required.v1"
ACCOUNT_ONBOARDING_CURRENT_STATE_RESPONSE_MAX_BYTES = 4 * 1024
_ROUTE_SECRET_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "cookie2",
        "x-api-token",
        "x-api-key",
        "x-auth-token",
    }
)
_HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _require_account_onboarding_token(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("onboarding_token must be a string")
    encoded = value.encode("utf-8")
    if not 32 <= len(encoded) <= 256 or any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise ValueError(
            "onboarding_token must contain 32..256 printable ASCII bytes "
            "without spaces or normalization"
        )
    return value


def _require_route_token(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{context} must contain printable ASCII without spaces") from exc
    if not 1 <= len(encoded) <= 4096 or any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise ValueError(
            f"{context} must contain 1..4096 printable ASCII bytes without spaces"
        )
    return value


def _copy_http_headers(headers: Mapping[str, Any], context: str) -> Dict[str, str]:
    if not isinstance(headers, Mapping):
        raise TypeError(f"{context} must be a mapping")
    result: Dict[str, str] = {}
    normalized_names: set[str] = set()
    for name, value in headers.items():
        if not isinstance(name, str) or _HTTP_HEADER_NAME_RE.fullmatch(name) is None:
            raise ValueError(f"{context} contains an invalid HTTP header name")
        lower_name = name.lower()
        if lower_name in normalized_names:
            raise ValueError(f"{context} contains duplicate HTTP header {name!r}")
        if not isinstance(value, str):
            raise TypeError(f"{context}[{name!r}] must be a string")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError(f"{context}[{name!r}] must not contain control characters")
        normalized_names.add(lower_name)
        result[name] = value
    return result


def _set_exact_header(headers: MutableMapping[str, str], name: str, value: str) -> None:
    lower_name = name.lower()
    for existing in list(headers):
        if existing.lower() == lower_name:
            del headers[existing]
    headers[name] = value


def _reject_reserved_default_headers(headers: Mapping[str, Any], context: str) -> None:
    normalized = {str(name).lower() for name in headers}
    if ACCOUNT_ONBOARDING_TOKEN_HEADER.lower() in normalized:
        raise ValueError(
            f"{context} must not contain {ACCOUNT_ONBOARDING_TOKEN_HEADER}; "
            "pass onboarding_token explicitly to the onboarding request"
        )
    if "authorization" in normalized:
        raise ValueError(
            f"{context} must not contain Authorization; pass auth_token explicitly"
        )
    if "x-api-token" in normalized:
        raise ValueError(
            f"{context} must not contain X-API-Token; pass api_token explicitly"
        )
    if any(name.startswith("x-iroha-") for name in normalized):
        raise ValueError(
            f"{context} must not contain canonical authentication headers; "
            "pass the route authentication input explicitly"
        )
    reserved_secret = sorted(normalized & _ROUTE_SECRET_HEADER_NAMES)
    if reserved_secret:
        raise ValueError(
            f"{context} must not contain route-secret header {reserved_secret[0]}"
        )


def _reject_session_route_secrets(session: Any) -> None:
    headers = getattr(session, "headers", None)
    if headers is not None:
        if not isinstance(headers, Mapping):
            raise TypeError("session.headers must be a mapping")
        _reject_reserved_default_headers(headers, "session.headers")
    if getattr(session, "auth", None) is not None:
        raise ValueError("session.auth must not contain fallback route credentials")
    cookies = getattr(session, "cookies", None)
    if cookies is not None:
        try:
            has_cookies = len(cookies) != 0
        except TypeError as exc:
            raise TypeError("session.cookies must be a sized cookie jar") from exc
        if has_cookies:
            raise ValueError("session.cookies must not contain fallback route credentials")


def _reject_alias_keys(
    source: Mapping[str, Any], aliases: Mapping[str, str], *, context: str
) -> None:
    for alias_key, canonical_key in aliases.items():
        if alias_key in source:
            raise TypeError(f"{context} does not accept {alias_key}; use {canonical_key}")


_DEFAULT_ISO_POLL_INTERVAL_SECONDS = 2.0
_DEFAULT_ISO_WAIT_ATTEMPTS = 12
_MIN_ISO_POLL_INTERVAL_SECONDS = 0.01


def _require_non_empty_string(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"{context} must be a non-empty string")
    return trimmed


def _require_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be a JSON object")
    return value


def _copy_prepared_operation_binding(
    value: Any,
    *,
    expected_kind: str,
    context: str,
    require_active: bool,
) -> Dict[str, Any]:
    binding = _require_mapping(value, context)
    required = {
        "schema",
        "semantic_hash_hex",
        "kind",
        "request_id",
        "execution_expires_at_unix_ms",
    }
    if set(binding) != required:
        raise TypeError(f"{context} must contain exactly the V1 prepared-operation binding fields")
    if binding.get("schema") != PREPARED_OPERATION_BINDING_SCHEMA:
        raise ValueError(f"{context}.schema is not the V1 prepared-operation binding schema")
    if binding.get("kind") != expected_kind:
        raise ValueError(f"{context}.kind must be {expected_kind!r}")
    for hex_field in ("semantic_hash_hex", "request_id"):
        field_value = binding.get(hex_field)
        if not isinstance(field_value, str) or re.fullmatch(r"[0-9a-f]{64}", field_value) is None:
            raise ValueError(f"{context}.{hex_field} must be exactly 64 lowercase hex characters")
    expiry = binding.get("execution_expires_at_unix_ms")
    if isinstance(expiry, bool) or not isinstance(expiry, int) or not 0 < expiry < 1 << 64:
        raise ValueError(f"{context}.execution_expires_at_unix_ms must be positive")
    if require_active and expiry <= time.time_ns() // 1_000_000:
        raise ValueError(f"{context} is expired")
    return copy.deepcopy(dict(binding))


def _require_onboarding_binding_receipt(
    binding: Mapping[str, Any], receipt: Mapping[str, Any], context: str
) -> None:
    """Bind an operation to its independently authenticated semantic receipt."""
    if binding["semantic_hash_hex"] != _canonical_receipt_plan_hash_hex(receipt, context):
        raise ValueError(f"{context}.binding.semantic_hash_hex differs from the receipt")
    valid_until = _require_mapping(receipt.get("body"), f"{context}.body").get("valid_until_ms")
    if (
        isinstance(valid_until, bool)
        or not isinstance(valid_until, int)
        or not 0 < valid_until < 1 << 64
        or binding["execution_expires_at_unix_ms"] > valid_until
    ):
        raise ValueError(f"{context}.binding execution deadline exceeds the receipt validity")

def _copy_fee_payment_intent_v1(value: Any, context: str) -> Dict[str, Any]:
    intent = _require_mapping(value, context)
    if set(intent) != {"payer", "value"}:
        raise TypeError(f"{context} must contain exactly payer and value")
    payer = intent.get("payer")
    if payer not in {"authority", "sponsor"}:
        raise ValueError(f"{context}.payer must be exactly 'authority' or 'sponsor'")
    payment = _require_mapping(intent.get("value"), f"{context}.value")
    required_payment_fields = {"charge_limits", "gas_limit"}
    if payer == "sponsor":
        required_payment_fields |= {"program_id", "program_revision"}
    if set(payment) != required_payment_fields:
        raise TypeError(f"{context}.value does not contain the exact {payer} fee fields")

    gas_limit = payment.get("gas_limit")
    if gas_limit is not None and (
        isinstance(gas_limit, bool)
        or not isinstance(gas_limit, int)
        or not 0 < gas_limit < 1 << 64
    ):
        raise ValueError(f"{context}.value.gas_limit must be null or a positive u64")

    limits = payment.get("charge_limits")
    if isinstance(limits, (str, bytes, bytearray)) or not isinstance(limits, Sequence):
        raise TypeError(f"{context}.value.charge_limits must be an array")
    previous_kind = -1
    for index, limit_value in enumerate(limits):
        limit_context = f"{context}.value.charge_limits[{index}]"
        limit = _require_mapping(limit_value, limit_context)
        if set(limit) != {"kind", "asset_definition_id", "max_amount"}:
            raise TypeError(f"{limit_context} does not contain the exact V1 fields")
        kind_value = _require_mapping(limit.get("kind"), f"{limit_context}.kind")
        if set(kind_value) != {"kind", "value"} or kind_value.get("value") is not None:
            raise TypeError(f"{limit_context}.kind is not an exact unit variant")
        kind_literal = kind_value.get("kind")
        kind = 0 if kind_literal == "nexus" else 1 if kind_literal == "pipeline_gas" else -1
        if kind < 0 or kind <= previous_kind:
            raise ValueError(
                f"{context}.value.charge_limits must be unique and ordered nexus before pipeline_gas"
            )
        previous_kind = kind
        _require_canonical_asset_definition_id(
            limit.get("asset_definition_id"),
            f"{limit_context}.asset_definition_id",
        )
        _require_positive_exact_quantity_text(
            limit.get("max_amount"),
            f"{limit_context}.max_amount",
        )

    if payer == "sponsor":
        program_id = _require_mapping(payment.get("program_id"), f"{context}.value.program_id")
        if set(program_id) != {"sponsor", "name"}:
            raise TypeError(f"{context}.value.program_id must contain exactly sponsor and name")
        _normalize_exact_any_i105_account_id(
            program_id.get("sponsor"), f"{context}.value.program_id.sponsor"
        )
        _require_exact_non_empty_string(
            program_id.get("name"), f"{context}.value.program_id.name"
        )
        revision = payment.get("program_revision")
        if (
            isinstance(revision, bool)
            or not isinstance(revision, int)
            or not 0 < revision < 1 << 64
        ):
            raise ValueError(f"{context}.value.program_revision must be a positive u64")
    return copy.deepcopy(dict(intent))


def _require_same_fee_payer_and_gas_bound_v1(
    expected: Any,
    actual: Any,
    context: str,
) -> Dict[str, Any]:
    expected_intent = _copy_fee_payment_intent_v1(expected, f"{context}.expected")
    actual_intent = _copy_fee_payment_intent_v1(actual, f"{context}.actual")
    expected_payment = expected_intent["value"]
    actual_payment = actual_intent["value"]
    assert isinstance(expected_payment, Mapping)
    assert isinstance(actual_payment, Mapping)
    if (
        expected_intent["payer"] != actual_intent["payer"]
        or expected_payment["gas_limit"] != actual_payment["gas_limit"]
        or (
            expected_intent["payer"] == "sponsor"
            and (
                expected_payment["program_id"] != actual_payment["program_id"]
                or expected_payment["program_revision"] != actual_payment["program_revision"]
            )
        )
    ):
        raise ValueError(
            f"{context} fee payer, sponsor revision, or gas bound differs from the independent selection"
        )
    return expected_intent


def _copy_prepared_transaction(
    value: Any,
    *,
    expected_operation: str,
    context: str,
) -> Dict[str, Any]:
    prepared = _require_mapping(value, context)
    common = {
        "schema",
        "binding",
        "operation",
        "semantic_hash_hex",
        "account_id",
        "transaction_hash_hex",
        "signed_transaction_wire_hex",
        "signed_transaction_wire_sha256",
        "fee_payment",
        "server_signature",
    }
    operation_fields = {
        "onboarding": {"receipt", "alias", "disposition"},
        "faucet": {
            "claim",
            "asset_definition_id",
            "asset_id",
            "amount",
        },
    }
    expected_fields = common | operation_fields[expected_operation]
    if set(prepared) != expected_fields:
        raise TypeError(f"{context} must contain exactly the {expected_operation} V1 fields")
    if prepared.get("schema") != PREPARED_TRANSACTION_SCHEMA:
        raise ValueError(f"{context}.schema is not the prepared-transaction V1 schema")
    if prepared.get("operation") != expected_operation:
        raise ValueError(f"{context}.operation must be {expected_operation!r}")
    _copy_prepared_operation_binding(
        prepared.get("binding"),
        expected_kind=expected_operation,
        context=f"{context}.binding",
        require_active=False,
    )
    if prepared["binding"]["semantic_hash_hex"] != prepared.get("semantic_hash_hex"):
        raise ValueError(f"{context}.binding.semantic_hash_hex differs from the envelope")
    for hex_field in ("semantic_hash_hex", "signed_transaction_wire_sha256"):
        field_value = prepared.get(hex_field)
        if not isinstance(field_value, str) or re.fullmatch(r"[0-9a-f]{64}", field_value) is None:
            raise ValueError(f"{context}.{hex_field} must be exactly 64 lowercase hex characters")
    _require_exact_pipeline_transaction_hash(
        prepared.get("transaction_hash_hex"),
        f"{context}.transaction_hash_hex",
    )
    wire = prepared.get("signed_transaction_wire_hex")
    if (
        not isinstance(wire, str)
        or not wire
        or len(wire) % 2 != 0
        or re.fullmatch(r"[0-9a-f]+", wire) is None
    ):
        raise ValueError(f"{context}.signed_transaction_wire_hex must be non-empty lowercase hex")
    _require_exact_non_empty_string(prepared.get("account_id"), f"{context}.account_id")
    _copy_fee_payment_intent_v1(prepared.get("fee_payment"), f"{context}.fee_payment")
    signature = prepared.get("server_signature")
    if (
        not isinstance(signature, str)
        or re.fullmatch(r"[0-9A-F]{128}", signature) is None
        or not any(bytes.fromhex(signature))
    ):
        raise ValueError(
            f"{context}.server_signature must be one nonzero uppercase Ed25519 signature"
        )
    if expected_operation == "onboarding":
        receipt = _require_mapping(prepared.get("receipt"), f"{context}.receipt")
        _require_onboarding_binding_receipt(prepared["binding"], receipt, context)
        _require_exact_non_empty_string(prepared.get("alias"), f"{context}.alias")
        _require_mapping(prepared.get("disposition"), f"{context}.disposition")
    else:
        claim = _require_mapping(prepared.get("claim"), f"{context}.claim")
        claim_fields = {"account_id", "pow_anchor_height", "pow_nonce_hex"}
        if set(claim) != claim_fields:
            raise TypeError(f"{context}.claim must contain exactly the faucet V1 fields")
        claim_account = _require_exact_non_empty_string(
            claim.get("account_id"), f"{context}.claim.account_id"
        )
        if claim_account != prepared.get("account_id"):
            raise ValueError(f"{context}.claim.account_id does not match account_id")
        anchor = claim.get("pow_anchor_height")
        if isinstance(anchor, bool) or not isinstance(anchor, int) or not 0 < anchor < 1 << 64:
            raise ValueError(f"{context}.claim.pow_anchor_height must be a positive u64")
        nonce = claim.get("pow_nonce_hex")
        if (
            not isinstance(nonce, str)
            or re.fullmatch(r"[0-9a-f]+", nonce) is None
            or len(nonce) % 2 != 0
            or not 2 <= len(nonce) <= 64
        ):
            raise ValueError(f"{context}.claim.pow_nonce_hex must be 1..32 bytes of lowercase hex")
        for field_name in ("asset_definition_id", "asset_id"):
            _require_exact_non_empty_string(prepared.get(field_name), f"{context}.{field_name}")
        amount = prepared.get("amount")
        if amount is None or isinstance(amount, (bool, float)):
            raise ValueError(f"{context}.amount must contain an exact quantity")
    return copy.deepcopy(dict(prepared))


def _prepared_signature_frame(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _prepared_signature_field(label: str, value: str | bytes) -> bytes:
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    return _prepared_signature_frame(label.encode("ascii")) + _prepared_signature_frame(encoded)


def _prepared_binding_transcript(
    envelope_schema: str,
    operation: str,
    binding: Mapping[str, Any],
) -> bytearray:
    transcript = bytearray(_prepared_signature_frame(PREPARED_SIGNATURE_DOMAIN))
    for label, value in (
        ("transcript_schema", PREPARED_SIGNATURE_TRANSCRIPT_SCHEMA),
        ("envelope_schema", envelope_schema),
        ("operation", operation),
        ("binding.schema", binding["schema"]),
        ("binding.semantic_hash_hex", binding["semantic_hash_hex"]),
        ("binding.kind", binding["kind"]),
        ("binding.request_id", binding["request_id"]),
        (
            "binding.execution_expires_at_unix_ms",
            str(binding["execution_expires_at_unix_ms"]),
        ),
    ):
        transcript.extend(_prepared_signature_field(label, value))
    return transcript


def _prepared_disposition_text(value: Any, context: str) -> str:
    disposition = _require_mapping(value, context)
    if set(disposition) != {"kind", "value"} or disposition.get("value") is not None:
        raise ValueError(f"{context} must be one exact unit disposition")
    kind = disposition.get("kind")
    if kind not in {"create", "repair", "no_op"}:
        raise ValueError(f"{context}.kind is not a prepared V1 disposition")
    return str(kind)


def _prepared_signature_transcript(value: Mapping[str, Any], context: str) -> bytes:
    operation = str(value["operation"])
    binding = _require_mapping(value["binding"], f"{context}.binding")
    transcript = _prepared_binding_transcript(str(value["schema"]), operation, binding)
    if operation == "onboarding":
        transcript.extend(
            _prepared_signature_field("semantic_hash_hex", str(value["semantic_hash_hex"]))
        )
        transcript.extend(_prepared_signature_field("account_id", str(value["account_id"])))
        transcript.extend(_prepared_signature_field("alias", str(value["alias"])))
        transcript.extend(
            _prepared_signature_field(
                "disposition",
                _prepared_disposition_text(value["disposition"], f"{context}.disposition"),
            )
        )
        transcript.extend(
            _prepared_signature_field("transaction_hash_hex", str(value["transaction_hash_hex"]))
        )
        transcript.extend(
            _prepared_signature_field(
                "signed_transaction_wire_sha256",
                str(value["signed_transaction_wire_sha256"]),
            )
        )
        transcript.extend(
            _prepared_signature_field(
                "signed_transaction_wire",
                bytes.fromhex(str(value["signed_transaction_wire_hex"])),
            )
        )
    elif operation == "faucet":
        claim = _require_mapping(value["claim"], f"{context}.claim")
        anchor = claim.get("pow_anchor_height")
        nonce = claim.get("pow_nonce_hex")
        if isinstance(anchor, bool) or not isinstance(anchor, int) or not 0 < anchor < 1 << 64:
            raise ValueError(f"{context}.claim.pow_anchor_height must be a positive u64")
        if (
            not isinstance(nonce, str)
            or re.fullmatch(r"[0-9a-f]+", nonce) is None
            or len(nonce) % 2 != 0
            or not 2 <= len(nonce) <= 64
        ):
            raise ValueError(
                f"{context}.claim.pow_nonce_hex must be 1..32 bytes of lowercase hex"
            )
        for label, field_value in (
            ("claim.account_id", str(claim["account_id"])),
            ("claim.pow_anchor_height", str(anchor)),
            ("claim.pow_nonce_hex", nonce),
            ("semantic_hash_hex", str(value["semantic_hash_hex"])),
            ("account_id", str(value["account_id"])),
            ("asset_definition_id", str(value["asset_definition_id"])),
            ("asset_id", str(value["asset_id"])),
            ("amount", str(value["amount"])),
            ("transaction_hash_hex", str(value["transaction_hash_hex"])),
            (
                "signed_transaction_wire_sha256",
                str(value["signed_transaction_wire_sha256"]),
            ),
        ):
            transcript.extend(_prepared_signature_field(label, field_value))
        transcript.extend(
            _prepared_signature_field(
                "signed_transaction_wire",
                bytes.fromhex(str(value["signed_transaction_wire_hex"])),
            )
        )
    else:  # pragma: no cover - closed by the exact envelope validator
        raise ValueError(f"{context}.operation is unsupported")
    return bytes(transcript)


def _canonical_receipt_plan_hash_hex(receipt: Mapping[str, Any], context: str) -> str:
    literal = receipt.get("plan_hash")
    if not isinstance(literal, str):
        raise TypeError(f"{context}.plan_hash must be a canonical Iroha hash literal")
    match = re.fullmatch(r"hash:([0-9A-F]{64})#([0-9A-F]{4})", literal)
    if match is None:
        raise ValueError(f"{context}.plan_hash is not a canonical Iroha hash literal")
    body, checksum = match.groups()
    expected_checksum = _crc16_ccitt_false(f"hash:{body}".encode("ascii"))
    if int(checksum, 16) != expected_checksum:
        raise ValueError(f"{context}.plan_hash checksum is invalid")
    return body.lower()


def _verify_prepared_transaction_authentication_v1(
    prepared: Mapping[str, Any],
    *,
    expected_authority: str,
    network_id: "NetworkId",
    context: str,
) -> None:
    from .crypto import AccountId as ExactAccountId
    from .crypto import (
        hash_blake2b_32,
        verify_ed25519,
        verify_prepared_transaction_context_v1,
    )

    wire = bytes.fromhex(str(prepared["signed_transaction_wire_hex"]))
    expected_wire_sha256 = str(prepared["signed_transaction_wire_sha256"])
    if not hmac.compare_digest(hashlib.sha256(wire).hexdigest(), expected_wire_sha256):
        raise ValueError(f"{context} prepared wire SHA-256 mismatch")
    binding_json = json.dumps(
        prepared["binding"],
        sort_keys=True,
        separators=(",", ":"),
    )
    fee_payment_json = json.dumps(
        prepared["fee_payment"],
        sort_keys=True,
        separators=(",", ":"),
    )
    if prepared["operation"] == "onboarding":
        operation_context = {
            "receipt": prepared["receipt"],
            "account_id": prepared["account_id"],
            "alias": prepared["alias"],
            "disposition": prepared["disposition"],
        }
    else:
        operation_context = {
            "claim": prepared["claim"],
            "account_id": prepared["account_id"],
            "asset_definition_id": prepared["asset_definition_id"],
            "asset_id": prepared["asset_id"],
            "amount": prepared["amount"],
        }
    envelope = verify_prepared_transaction_context_v1(
        wire,
        network_id,
        expected_authority,
        binding_json,
        str(prepared["operation"]),
        str(prepared["semantic_hash_hex"]),
        fee_payment_json,
        json.dumps(operation_context, sort_keys=True, separators=(",", ":")),
    )
    if not hmac.compare_digest(envelope.hash_hex(), str(prepared["transaction_hash_hex"])):
        raise ValueError(f"{context} transaction hash differs from the exact signed wire")
    public_key = bytes.fromhex(ExactAccountId(expected_authority).public_key_hex)
    if not hmac.compare_digest(public_key, bytes(envelope.public_key)):
        raise ValueError(f"{context} prepared authority differs from the trust pin")
    signature = bytes.fromhex(str(prepared["server_signature"]))
    digest = hash_blake2b_32(_prepared_signature_transcript(prepared, context))
    if not verify_ed25519(public_key, digest, signature):
        raise ValueError(f"{context} server signature is invalid")


def _copy_account_onboarding_request_v1(
    value: Any,
    context: str,
) -> Dict[str, Any]:
    """Validate and retain the caller's complete canonical onboarding intent."""

    request = _require_mapping(value, context)
    if set(request) != {"version", "alias", "account_id", "permissions"}:
        raise TypeError(f"{context} must contain exactly the V1 request fields")
    if request.get("version") != 1:
        raise ValueError(f"{context}.version must be 1")
    alias = _require_exact_non_empty_string(request.get("alias"), f"{context}.alias")
    account_id = _require_exact_non_empty_string(
        request.get("account_id"), f"{context}.account_id"
    )
    permissions = request.get("permissions")
    if not isinstance(permissions, list):
        raise TypeError(f"{context}.permissions must be an array of strings")
    exact_permissions = [
        _require_exact_non_empty_string(permission, f"{context}.permissions[{index}]")
        for index, permission in enumerate(permissions)
    ]
    if exact_permissions != sorted(set(exact_permissions)):
        raise ValueError(f"{context}.permissions must be sorted and duplicate-free")
    return {
        "version": 1,
        "alias": alias,
        "account_id": account_id,
        "permissions": exact_permissions,
    }


def _copy_account_onboarding_receipt_v1(
    value: Any,
    *,
    expected_authority: str,
    network_id: "NetworkId",
    expected_request: Mapping[str, Any],
    context: str,
) -> Dict[str, Any]:
    """Authenticate one exact V1 onboarding receipt and complete request."""

    from .crypto import verify_account_onboarding_receipt_v1

    receipt = _require_mapping(value, context)
    if set(receipt) != {"body", "plan_hash", "signature"}:
        raise TypeError(f"{context} must contain exactly the V1 receipt fields")
    body = _require_mapping(receipt.get("body"), f"{context}.body")
    expected_body_fields = {
        "version",
        "request",
        "authority",
        "network_id",
        "anchor",
        "resource",
        "acquisition",
        "quote_guard",
        "instructions",
        "owner_auto_renew_instruction",
        "valid_until_ms",
    }
    if set(body) != expected_body_fields:
        raise TypeError(f"{context}.body must contain exactly the V1 body fields")
    request = _require_mapping(body.get("request"), f"{context}.body.request")
    if set(request) != {"version", "alias", "account_id", "permissions"}:
        raise TypeError(f"{context}.body.request must contain exactly the V1 request fields")
    exact_expected_request = _copy_account_onboarding_request_v1(
        expected_request,
        f"{context}.expected_request",
    )
    if body.get("version") != 1 or request.get("version") != 1:
        raise ValueError(f"{context} is not a V1 onboarding receipt")
    if body.get("network_id") != network_id.literal:
        raise ValueError(f"{context}.body.network_id differs from the trust pin")
    account_id = _require_exact_non_empty_string(
        request.get("account_id"), f"{context}.body.request.account_id"
    )
    alias = _require_exact_non_empty_string(request.get("alias"), f"{context}.body.request.alias")
    permissions = request.get("permissions")
    if not isinstance(permissions, list) or not all(
        isinstance(permission, str) for permission in permissions
    ):
        raise TypeError(f"{context}.body.request.permissions must be an array of strings")
    if dict(request) != exact_expected_request:
        raise ValueError(f"{context}.body.request differs from the complete request")
    plan_hash_hex = _canonical_receipt_plan_hash_hex(receipt, context)
    verified_hash_hex = verify_account_onboarding_receipt_v1(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")),
        network_id,
        expected_authority,
        account_id,
        alias,
        json.dumps(permissions, separators=(",", ":")),
    )
    if not hmac.compare_digest(verified_hash_hex, plan_hash_hex):
        raise ValueError(f"{context}.plan_hash differs from the authenticated body")
    return copy.deepcopy(dict(receipt))


def _copy_account_onboarding_proof_required_v1(
    value: Any,
    *,
    expected_binding: Mapping[str, Any],
    expected_receipt: Mapping[str, Any],
    expected_authority: str,
    context: str,
) -> Dict[str, Any]:
    proof_required = _require_mapping(value, context)
    expected_fields = {
        "schema",
        "binding",
        "operation",
        "outcome",
        "proof_kind",
        "semantic_hash_hex",
        "account_id",
        "alias",
        "disposition",
        "server_signature",
    }
    if set(proof_required) != expected_fields:
        raise TypeError(f"{context} must contain exactly the proof-required V1 fields")
    if proof_required.get("schema") != ACCOUNT_ONBOARDING_PROOF_REQUIRED_SCHEMA:
        raise ValueError(f"{context}.schema is not the proof-required V1 schema")
    if (
        proof_required.get("operation") != "onboarding"
        or proof_required.get("outcome") != "ProofRequired"
        or proof_required.get("proof_kind") != "account_alias_current_state"
    ):
        raise ValueError(f"{context} is not the exact nonterminal proof-required outcome")
    binding = _copy_prepared_operation_binding(
        proof_required.get("binding"),
        expected_kind="onboarding",
        context=f"{context}.binding",
        require_active=False,
    )
    if binding != expected_binding:
        raise ValueError(f"{context}.binding differs from the exact prepare request")
    body = _require_mapping(expected_receipt.get("body"), f"{context}.receipt.body")
    request = _require_mapping(body.get("request"), f"{context}.receipt.body.request")
    _require_onboarding_binding_receipt(binding, expected_receipt, context)
    semantic_hash_hex = _canonical_receipt_plan_hash_hex(expected_receipt, f"{context}.receipt")
    if proof_required.get("semantic_hash_hex") != semantic_hash_hex:
        raise ValueError(f"{context}.semantic_hash_hex differs from the receipt")
    if proof_required.get("account_id") != request.get("account_id"):
        raise ValueError(f"{context}.account_id differs from the receipt")
    if proof_required.get("alias") != request.get("alias"):
        raise ValueError(f"{context}.alias differs from the receipt")
    if (
        _prepared_disposition_text(
            proof_required.get("disposition"), f"{context}.disposition"
        )
        != "no_op"
    ):
        raise ValueError(f"{context}.disposition must be no_op")
    signature = proof_required.get("server_signature")
    if (
        not isinstance(signature, str)
        or re.fullmatch(r"[0-9A-F]{128}", signature) is None
        or not any(bytes.fromhex(signature))
    ):
        raise ValueError(f"{context}.server_signature is not one exact Ed25519 signature")
    from .crypto import AccountId as ExactAccountId
    from .crypto import hash_blake2b_32, verify_ed25519

    transcript = _prepared_binding_transcript(
        ACCOUNT_ONBOARDING_PROOF_REQUIRED_SCHEMA,
        "onboarding",
        binding,
    )
    for label, field_value in (
        ("outcome", "ProofRequired"),
        ("proof_kind", "account_alias_current_state"),
        ("semantic_hash_hex", semantic_hash_hex),
        ("account_id", str(proof_required["account_id"])),
        ("alias", str(proof_required["alias"])),
        ("disposition", "no_op"),
    ):
        transcript.extend(_prepared_signature_field(label, field_value))
    public_key = bytes.fromhex(ExactAccountId(expected_authority).public_key_hex)
    digest = hash_blake2b_32(bytes(transcript))
    if not verify_ed25519(public_key, digest, bytes.fromhex(signature)):
        raise ValueError(f"{context}.server_signature is invalid")
    return copy.deepcopy(dict(proof_required))


def _validate_prepared_submit_response_v1(
    response: requests.Response,
    *,
    expected_prepared: Mapping[str, Any],
    context: str,
) -> None:
    if response.status_code not in {200, 202}:
        return
    try:
        value = response.json()
    except ValueError as error:
        raise RuntimeError(f"{context} returned invalid JSON") from error
    payload = _require_mapping(value, context)
    if set(payload) != {
        "schema",
        "binding",
        "operation",
        "transaction_hash_hex",
        "outcome",
    }:
        raise TypeError(f"{context} must contain exactly the submit V1 fields")
    if payload.get("schema") != "iroha.prepared-transaction-submit.v1":
        raise ValueError(f"{context}.schema is not the submit V1 schema")
    for response_field in ("binding", "operation", "transaction_hash_hex"):
        if payload.get(response_field) != expected_prepared.get(response_field):
            raise ValueError(f"{context}.{response_field} differs from the exact envelope")
    outcome = payload.get("outcome")
    if outcome not in {"Applied", "Pending", "Rejected"}:
        raise ValueError(f"{context}.outcome is not a closed V1 outcome")
    if response.status_code == 202 and outcome != "Pending":
        raise ValueError(f"{context} HTTP 202 requires outcome Pending")


def _require_exact_non_empty_string(value: Any, context: str) -> str:
    trimmed = _require_non_empty_string(value, context)
    if trimmed != value:
        raise ValueError(f"{context} must not contain surrounding whitespace")
    return value


def _require_exact_token_string(value: Any, context: str) -> str:
    exact = _require_exact_non_empty_string(value, context)
    if any(char.isspace() or unicodedata.category(char) == "Cc" for char in exact):
        raise ValueError(f"{context} must not contain whitespace or control characters")
    return exact


def _require_governance_selector_string(value: Any, context: str) -> str:
    exact = _require_exact_token_string(value, context)
    if re.fullmatch(r"[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,127}", exact) is None:
        raise ValueError(
            f"{context} must be 1-128 RFC 3986 unreserved ASCII characters "
            "and must not start with a dot"
        )
    return exact


def _require_governance_proposal_id(value: Any, context: str) -> str:
    proposal_id = _require_exact_token_string(value, context)
    if re.fullmatch(r"[0-9a-f]{64}", proposal_id) is None:
        raise ValueError(
            f"{context} must be exactly 64 lowercase hexadecimal characters"
        )
    return proposal_id


def _normalize_optional_exact_string(value: Any, context: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    trimmed = value.strip()
    if not trimmed:
        return None
    if trimmed != value:
        raise ValueError(f"{context} must not contain surrounding whitespace")
    return value


class ZkVerifyingKeyTransactionDraft(TypedDict):
    """Unsigned verifying-key registry transaction prepared by Torii."""

    submitted: Literal[False]
    transaction_payload_b64: str
    signing_message_b64: str


class AppApiTransactionDraft(TypedDict):
    """Canonical unsigned transaction prepared by an app-facing Torii route."""

    submitted: Literal[False]
    transaction_payload_b64: str
    signing_message_b64: str


@dataclass(frozen=True)
class LocalSigningContext:
    """Immutable client-owned context for validating local-signing drafts."""

    network_id: "NetworkId"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "network_id",
            _normalize_network_id(
                self.network_id,
                "LocalSigningContext.network_id",
            ),
        )


@dataclass(frozen=True)
class AccountOnboardingCurrentStateV1:
    """Classified atomic account-onboarding state anchored to one committed block."""

    kind: Literal["Applied", "AliasAbsent", "AliasConflict"]
    block_height: int
    block_hash: str


_ZK_VERIFYING_KEY_TRANSACTION_PAYLOAD_MAX_BYTES = 16 * 1024 * 1024
_ZK_VERIFYING_KEY_PRIVATE_KEY_FIELDS = frozenset(
    {
        "private_key",
        "privateKey",
        "private_key_hex",
        "privateKeyHex",
        "private_key_bytes",
        "privateKeyBytes",
        "private_key_seed",
        "privateKeySeed",
        "private_key_multihash",
        "privateKeyMultihash",
        "private_key_algorithm",
        "privateKeyAlgorithm",
    }
)


def _reject_zk_verifying_key_private_key_fields(
    payload: Mapping[str, Any],
    context: str,
) -> None:
    fields = sorted(
        key
        for key in payload
        if isinstance(key, str) and key in _ZK_VERIFYING_KEY_PRIVATE_KEY_FIELDS
    )
    if fields:
        raise ValueError(
            f"{context} does not accept private-key fields ({', '.join(fields)}); "
            "sign the returned transaction draft locally"
        )


def _normalize_zk_verifying_key_registration_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise TypeError("ZK verifying-key registration payload must be a mapping")
    _reject_zk_verifying_key_private_key_fields(payload, "register_zk_verifying_key")
    body = dict(_json_safe_value(dict(payload)))
    _normalize_zk_verifying_key_submission_payload(
        body,
        "register_zk_verifying_key",
        require_gas_schedule=True,
    )
    return body


def _normalize_zk_verifying_key_update_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise TypeError("ZK verifying-key update payload must be a mapping")
    _reject_zk_verifying_key_private_key_fields(payload, "update_zk_verifying_key")
    body = dict(_json_safe_value(dict(payload)))
    _normalize_zk_verifying_key_submission_payload(
        body,
        "update_zk_verifying_key",
        require_gas_schedule=False,
    )
    return body


def _normalize_zk_verifying_key_submission_payload(
    body: MutableMapping[str, Any],
    context: str,
    *,
    require_gas_schedule: bool,
) -> None:
    body["backend"] = _require_production_verify_backend_label(
        body.get("backend"),
        f"{context}.backend",
    )
    body["name"] = _require_exact_non_empty_string(body.get("name"), f"{context}.name")
    if ":" in body["name"]:
        raise ValueError(f"{context}.name must not contain ':'")
    body["authority"] = _require_non_empty_string(
        body.get("authority"),
        f"{context}.authority",
    )
    version = _coerce_int(body.get("version"), f"{context}.version")
    if version is None:
        raise ValueError(f"{context}.version must be provided")
    if version > 0xFFFF_FFFF:
        raise ValueError(f"{context}.version must fit in a u32")
    body["version"] = version
    body["circuit_id"] = _require_exact_non_empty_string(
        body.get("circuit_id"),
        f"{context}.circuit_id",
    )
    body["public_inputs_schema_hash_hex"] = _normalize_32_byte_hex(
        body.get("public_inputs_schema_hash_hex"),
        f"{context}.public_inputs_schema_hash_hex",
    )
    if require_gas_schedule:
        body["gas_schedule_id"] = _require_exact_non_empty_string(
            body.get("gas_schedule_id"),
            f"{context}.gas_schedule_id",
        )
    elif "gas_schedule_id" in body:
        gas_schedule_id = _normalize_optional_exact_string(
            body.get("gas_schedule_id"),
            f"{context}.gas_schedule_id",
        )
        if gas_schedule_id is None:
            body.pop("gas_schedule_id", None)
        else:
            body["gas_schedule_id"] = gas_schedule_id

    for field_name in ("curve", "metadata_uri_cid", "vk_bytes_cid"):
        if field_name in body:
            normalized = _normalize_optional_string(
                body.get(field_name), f"{context}.{field_name}"
            )
            if normalized is None:
                body.pop(field_name, None)
            else:
                body[field_name] = normalized

    if "max_proof_bytes" in body:
        max_proof_bytes = _normalize_optional_u32_field(
            body.get("max_proof_bytes"),
            f"{context}.max_proof_bytes",
            allow_zero=True,
        )
        if max_proof_bytes is None:
            body.pop("max_proof_bytes", None)
        else:
            body["max_proof_bytes"] = max_proof_bytes
    if "status" in body:
        status = _normalize_optional_zk_verifying_key_status(
            body.get("status"), f"{context}.status"
        )
        if status is None:
            body.pop("status", None)
        else:
            body["status"] = status
    _validate_zk_verifying_key_height_range(body, context)
    _validate_zk_verifying_key_material_and_commitment(body, context)


def _normalize_zk_verifying_key_transaction_draft(
    payload: Any,
    context: str,
    *,
    network_id: "NetworkId",
    operation: str,
    request: Mapping[str, Any],
) -> ZkVerifyingKeyTransactionDraft:
    record = _require_mapping(payload, context)
    allowed_fields = {
        "submitted",
        "transaction_payload_b64",
        "signing_message_b64",
    }
    unsupported_fields = sorted(str(key) for key in record if key not in allowed_fields)
    if unsupported_fields:
        raise ValueError(f"{context} contains unsupported fields: {', '.join(unsupported_fields)}")
    if record.get("submitted") is not False:
        raise ValueError(f"{context}.submitted must be false")
    transaction_payload_b64, transaction_payload = (
        _decode_zk_verifying_key_draft_base64(
            record.get("transaction_payload_b64"),
            f"{context}.transaction_payload_b64",
            max_bytes=_ZK_VERIFYING_KEY_TRANSACTION_PAYLOAD_MAX_BYTES,
            limit_label="transaction payload",
        )
    )
    signing_message_b64, signing_message = _decode_zk_verifying_key_draft_base64(
        record.get("signing_message_b64"),
        f"{context}.signing_message_b64",
        exact_bytes=32,
    )
    expected_signing_message = bytearray(
        hashlib.blake2b(transaction_payload, digest_size=32).digest()
    )
    expected_signing_message[-1] |= 1
    if not hmac.compare_digest(signing_message, bytes(expected_signing_message)):
        raise ValueError(
            f"{context}.signing_message_b64 must equal the canonical Iroha "
            "HashOf(transaction_payload_b64)"
        )
    decoded_instruction = _require_crypto().decode_zk_vk_transaction_payload(
        transaction_payload,
        network_id,
        request["authority"],
        operation,
    )
    expected_instruction = _expected_zk_verifying_key_instruction(request)
    if decoded_instruction != expected_instruction:
        raise ValueError(
            f"{context}.transaction_payload_b64 does not contain the exact requested "
            "verifying-key registry record"
        )
    return {
        "submitted": False,
        "transaction_payload_b64": transaction_payload_b64,
        "signing_message_b64": signing_message_b64,
    }


def _normalize_app_api_transaction_draft(
    payload: Any,
    context: str,
) -> AppApiTransactionDraft:
    record = _require_mapping(payload, context)
    allowed_fields = {
        "submitted",
        "transaction_payload_b64",
        "signing_message_b64",
    }
    unsupported_fields = sorted(str(key) for key in record if key not in allowed_fields)
    if unsupported_fields:
        raise ValueError(
            f"{context} contains unsupported fields: {', '.join(unsupported_fields)}"
        )
    if record.get("submitted") is not False:
        raise ValueError(f"{context}.submitted must be false")
    transaction_payload_b64, transaction_payload = (
        _decode_zk_verifying_key_draft_base64(
            record.get("transaction_payload_b64"),
            f"{context}.transaction_payload_b64",
            max_bytes=_ZK_VERIFYING_KEY_TRANSACTION_PAYLOAD_MAX_BYTES,
            limit_label="transaction payload",
        )
    )
    signing_message_b64, signing_message = _decode_zk_verifying_key_draft_base64(
        record.get("signing_message_b64"),
        f"{context}.signing_message_b64",
        exact_bytes=32,
    )
    expected_message = bytearray(
        hashlib.blake2b(transaction_payload, digest_size=32).digest()
    )
    expected_message[-1] |= 1
    if not hmac.compare_digest(signing_message, bytes(expected_message)):
        raise ValueError(
            f"{context}.signing_message_b64 must equal the canonical Iroha "
            "HashOf(transaction_payload_b64)"
        )
    return {
        "submitted": False,
        "transaction_payload_b64": transaction_payload_b64,
        "signing_message_b64": signing_message_b64,
    }


def _expected_zk_verifying_key_instruction(
    request: Mapping[str, Any],
) -> Dict[str, Any]:
    vk_bytes = (
        None
        if request.get("vk_bytes") is None
        else base64.b64decode(request["vk_bytes"], validate=True)
    )
    commitment_hex = (
        request["commitment_hex"]
        if vk_bytes is None
        else _zk_verifying_key_commitment_hex(request["backend"], vk_bytes)
    )
    backend_tag = _verifier_backend_registry_tag_v1(request["backend"])
    if backend_tag is None:
        raise ValueError("verifying-key request uses an unsupported backend")
    return {
        "id": {
            "backend": request["backend"],
            "name": request["name"],
        },
        "record": {
            "version": request["version"],
            "circuit_id": request["circuit_id"],
            "owner_manifest_id": None,
            "namespace": "core",
            "backend": backend_tag,
            "curve": request.get("curve", "unknown"),
            "public_inputs_schema_hash": bytes.fromhex(
                request["public_inputs_schema_hash_hex"]
            ),
            "commitment": bytes.fromhex(commitment_hex),
            "vk_len": len(vk_bytes) if vk_bytes is not None else request["vk_len"],
            "max_proof_bytes": request.get("max_proof_bytes", 0),
            "gas_schedule_id": request.get("gas_schedule_id"),
            "metadata_uri_cid": request.get("metadata_uri_cid"),
            "vk_bytes_cid": request.get("vk_bytes_cid"),
            "activation_height": request.get("activation_height"),
            "withdraw_height": request.get("withdraw_height"),
            "key": (
                None
                if vk_bytes is None
                else {
                    "backend": request["backend"],
                    "bytes": vk_bytes,
                }
            ),
            "status": request.get("status", "Active"),
        },
    }


def _decode_zk_verifying_key_draft_base64(
    value: Any,
    context: str,
    *,
    max_bytes: Optional[int] = None,
    exact_bytes: Optional[int] = None,
    limit_label: str = "payload",
) -> Tuple[str, bytes]:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be canonical padded base64")
    if max_bytes is not None:
        max_encoded_bytes = 4 * ((max_bytes + 2) // 3)
        if len(value) > max_encoded_bytes:
            raise ValueError(
                f"{context} exceeds the {max_bytes}-byte {limit_label} limit"
            )
    if exact_bytes is not None:
        exact_encoded_bytes = 4 * ((exact_bytes + 2) // 3)
        if len(value) != exact_encoded_bytes:
            raise ValueError(f"{context} must decode to exactly {exact_bytes} bytes")
    if not value or value.strip() != value:
        raise ValueError(f"{context} must be canonical padded base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{context} must be canonical padded base64") from exc
    if not decoded or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{context} must be canonical padded base64")
    if max_bytes is not None and len(decoded) > max_bytes:
        raise ValueError(f"{context} exceeds the {max_bytes}-byte {limit_label} limit")
    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise ValueError(f"{context} must decode to exactly {exact_bytes} bytes")
    return value, decoded


def _validate_zk_verifying_key_height_range(
    body: MutableMapping[str, Any],
    context: str,
) -> None:
    activation_height = None
    withdraw_height = None
    if "activation_height" in body:
        activation_height = _normalize_optional_int_field(
            body.get("activation_height"),
            f"{context}.activation_height",
        )
        body["activation_height"] = activation_height
    if "withdraw_height" in body:
        withdraw_height = _normalize_optional_int_field(
            body.get("withdraw_height"),
            f"{context}.withdraw_height",
        )
        body["withdraw_height"] = withdraw_height
    if (
        activation_height is not None
        and withdraw_height is not None
        and withdraw_height < activation_height
    ):
        raise ValueError(
            f"{context}.withdraw_height must be greater than or equal to activation_height"
        )


def _validate_zk_verifying_key_material_and_commitment(
    body: MutableMapping[str, Any],
    context: str,
) -> None:
    commitment_hex: Optional[str] = None
    if "commitment_hex" in body:
        commitment_value = body.get("commitment_hex")
        if commitment_value is not None:
            commitment_hex = _normalize_32_byte_hex(
                commitment_value,
                f"{context}.commitment_hex",
            )
            body["commitment_hex"] = commitment_hex
        else:
            body.pop("commitment_hex", None)

    vk_len: Optional[int] = None
    if "vk_len" in body:
        vk_len = _normalize_optional_u32_field(
            body.get("vk_len"),
            f"{context}.vk_len",
            allow_zero=False,
        )
        if vk_len is None:
            body.pop("vk_len", None)
        else:
            body["vk_len"] = vk_len

    vk_bytes_value = body.get("vk_bytes")
    vk_bytes: Optional[bytes] = None
    if vk_bytes_value is None:
        body.pop("vk_bytes", None)
    else:
        if not isinstance(vk_bytes_value, str):
            raise TypeError(f"{context}.vk_bytes must be a base64 string")
        try:
            vk_bytes = base64.b64decode(vk_bytes_value, validate=True)
        except binascii.Error as exc:
            raise ValueError(f"{context}.vk_bytes must be valid base64") from exc
        if not vk_bytes:
            raise ValueError(f"{context}.vk_bytes must be non-empty")
        if len(vk_bytes) > 0xFFFF_FFFF:
            raise ValueError(f"{context}.vk_bytes length must fit in a u32")
        body["vk_bytes"] = base64.b64encode(vk_bytes).decode("ascii")
        if vk_len is not None and vk_len != len(vk_bytes):
            raise ValueError(f"{context}.vk_len must match vk_bytes length")
        body["vk_len"] = len(vk_bytes)

    if vk_bytes is None:
        if commitment_hex is None:
            raise ValueError(f"{context}.commitment_hex is required when vk_bytes is omitted")
        if vk_len is None:
            raise ValueError(f"{context}.vk_len is required when vk_bytes is omitted")

    if vk_bytes is not None and commitment_hex is not None:
        expected = _zk_verifying_key_commitment_hex(body["backend"], vk_bytes)
        if commitment_hex != expected:
            raise ValueError(
                f"{context}.commitment_hex must match domain-separated SHA-256 of backend and vk_bytes"
            )


def _zk_verifying_key_commitment_hex(backend: str, vk_bytes: bytes) -> str:
    backend_bytes = backend.encode("utf-8")
    preimage = (
        b"iroha:zk:v1:vk"
        + len(backend_bytes).to_bytes(8, "big")
        + backend_bytes
        + len(vk_bytes).to_bytes(8, "big")
        + vk_bytes
    )
    return hashlib.sha256(preimage).hexdigest()


def _normalize_network_id(value: Any, context: str) -> "NetworkId":
    from .crypto import _require_network_id

    return _require_network_id(value, context)


def _normalize_optional_zk_verifying_key_status(value: Any, context: str) -> Optional[str]:
    normalized = _normalize_optional_string(value, context)
    if normalized is None:
        return None
    lowered = normalized.lower()
    if lowered == "proposed":
        return "Proposed"
    if lowered == "active":
        return "Active"
    if lowered == "withdrawn":
        return "Withdrawn"
    raise ValueError(f"{context} must be Proposed, Active, or Withdrawn")


def _normalize_optional_u32_field(
    value: Any,
    context: str,
    *,
    allow_zero: bool,
) -> Optional[int]:
    parsed = _coerce_int(value, context, allow_zero=allow_zero)
    if parsed is None:
        return None
    if parsed > 0xFFFF_FFFF:
        raise ValueError(f"{context} must fit in a u32")
    return parsed


def _normalize_32_byte_hex(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a 32-byte hex string")
    literal = _require_exact_non_empty_string(value, context)
    normalized = literal[2:] if literal[:2].lower() == "0x" else literal
    return _normalize_hex_string(normalized.lower(), context, expected_length=64)


def _normalize_optional_int_field(value: Any, context: str) -> Optional[int]:
    parsed = _coerce_int(value, context, allow_zero=True)
    return parsed if parsed is not None else None


def _normalize_optional_string(value: Any, context: str) -> Optional[str]:
    if value is None:
        return None
    return _require_non_empty_string(value, context)


def _canonical_quantity_text(value: Any, context: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{context} must be a canonical JSON string")
    if len(value) > 155:
        raise ValueError(f"{context} exceeds the canonical V1 text bound")
    return str(NumericV1Codec.decode_quantity_json(value))


def _require_positive_exact_quantity_text(value: Any, context: str) -> str:
    quantity = _canonical_quantity_text(value, context)
    if Decimal(quantity) <= 0:
        raise ValueError(f"{context} must be a positive exact quantity")
    return quantity


def _copy_expected_faucet_policy_v1(
    asset_definition_id: Any,
    amount: Any,
    context: str,
) -> tuple[str, str]:
    return (
        _require_canonical_asset_definition_id(
            asset_definition_id,
            f"{context}.asset_definition_id",
        ),
        _require_positive_exact_quantity_text(amount, f"{context}.amount"),
    )


def _require_prepared_faucet_policy_v1(
    prepared: Mapping[str, Any],
    *,
    expected_asset_definition_id: str,
    expected_amount: str,
    context: str,
) -> None:
    actual_asset_definition_id = _require_canonical_asset_definition_id(
        prepared.get("asset_definition_id"),
        f"{context}.asset_definition_id",
    )
    actual_amount = _require_positive_exact_quantity_text(
        prepared.get("amount"),
        f"{context}.amount",
    )
    if actual_asset_definition_id != expected_asset_definition_id:
        raise ValueError(
            f"{context}.asset_definition_id differs from the independent faucet policy"
        )
    if actual_amount != expected_amount:
        raise ValueError(f"{context}.amount differs from the independent faucet policy")


def _leading_zero_bits(payload: bytes) -> int:
    count = 0
    for byte in payload:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count


def _normalize_canonical_account_id(
    value: Any,
    context: str,
    *,
    expected_discriminant: int = DEFAULT_I105_DISCRIMINANT,
) -> str:
    literal = _require_non_empty_string(value, context)
    if any(ch.isspace() for ch in literal):
        raise ValueError(f"{context} must be a canonical I105 account id or on-chain account alias")
    if "@" in literal:
        label, separator, scope = literal.partition("@")
        scope_parts = scope.split(".") if separator else []
        if (
            not label
            or not separator
            or not scope
            or len(scope_parts) not in (1, 2)
            or any(not part for part in scope_parts)
        ):
            raise ValueError(
                f"{context} must use canonical I105 account id or account alias `name@dataspace` / `name@domain.dataspace`"
            )
        return literal
    try:
        address = AccountAddress.parse_encoded(literal, expected_discriminant=expected_discriminant)
    except AccountAddressError as exc:
        raise ValueError(
            f"{context} must be a canonical I105 account id or on-chain account alias"
        ) from exc
    canonical = address.to_i105(expected_discriminant)
    if canonical != literal:
        raise ValueError(
            f"{context} must use canonical I105 account id form when not using an alias"
        )
    return canonical


def _normalize_exact_i105_account_id(
    value: Any,
    context: str,
    *,
    expected_discriminant: int = DEFAULT_I105_DISCRIMINANT,
) -> str:
    literal = _require_exact_non_empty_string(value, context)
    if "@" in literal:
        raise ValueError(f"{context} must be an exact canonical I105 account id")
    try:
        address = AccountAddress.parse_encoded(
            literal,
            expected_discriminant=expected_discriminant,
        )
    except AccountAddressError as exc:
        raise ValueError(
            f"{context} must be an exact canonical I105 account id"
        ) from exc
    canonical = address.to_i105(expected_discriminant)
    if canonical != literal:
        raise ValueError(f"{context} must be an exact canonical I105 account id")
    return canonical


def _normalize_exact_any_i105_account_id(value: Any, context: str) -> str:
    """Validate one exact canonical I105 account id using its encoded discriminant."""

    literal = _require_exact_non_empty_string(value, context)
    if "@" in literal:
        raise ValueError(f"{context} must be an exact canonical I105 account id")
    try:
        AccountAddress.parse_encoded(literal)
    except AccountAddressError as exc:
        raise ValueError(
            f"{context} must be an exact canonical I105 account id"
        ) from exc
    return literal


def _bytes_like_to_hex(value: Any, context: str) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, (list, tuple)):
        try:
            return bytes(value).hex()
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{context} must contain byte values") from exc
    raise TypeError(f"{context} must be bytes-like")


def _normalize_hex_string(
    value: Any,
    context: str,
    *,
    expected_length: Optional[int] = None,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a hex string")
    trimmed = value.strip().lower()
    if not trimmed:
        raise ValueError(f"{context} must be a non-empty hex string")
    if expected_length is not None and len(trimmed) != expected_length:
        raise ValueError(f"{context} must contain {expected_length} hex characters")
    try:
        bytes.fromhex(trimmed)
    except ValueError as exc:
        raise ValueError(f"{context} must contain valid hexadecimal characters") from exc
    return trimmed


def _normalize_hash_hex(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a hex string")
    trimmed = value.strip().lower()
    if trimmed.startswith("0x"):
        trimmed = trimmed[2:].strip()
    if ":" in trimmed:
        scheme, rest = trimmed.split(":", 1)
        if scheme and scheme != "blake2b32":
            raise ValueError(f"{context} must use blake2b32 hex encoding")
        trimmed = rest.strip()
    return _normalize_hex_string(trimmed, context, expected_length=64)


def _require_exact_pipeline_transaction_hash(value: Any, context: str) -> str:
    """Require the V1 public pipeline hash spelling without compatibility coercion."""

    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    if re.fullmatch(r"[0-9a-f]{63}[13579bdf]", value) is None:
        raise ValueError(
            f"{context} must match [0-9a-f]{{63}}[13579bdf] with the canonical "
            "Iroha HashOf marker"
        )
    return value


def _normalize_uaid_literal(value: Any, *, context: str = "uaid") -> str:
    """Validate an exact canonical ``uaid:<64 lowercase hex>`` literal (LSB=1)."""

    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    if re.fullmatch(r"uaid:[0-9a-f]{64}", value) is None:
        raise ValueError(
            f"{context} must be an exact canonical uaid:<64 lowercase hex> literal"
        )
    if int(value[-1], 16) % 2 == 0:
        raise ValueError(f"{context} must have least significant bit set to 1")
    return value


def _normalize_positive_int(value: Any, context: str, *, allow_zero: bool) -> int:
    try:
        integer = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{context} must be numeric") from exc
    if integer < 0 or (integer == 0 and not allow_zero):
        comparator = "non-negative" if allow_zero else "greater than zero"
        raise ValueError(f"{context} must be {comparator}")
    return integer


def _require_u64(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{context} must be an unsigned 64-bit integer")
    if value < 0 or value > (1 << 64) - 1:
        raise ValueError(f"{context} must be an unsigned 64-bit integer")
    return value


def _require_wire_fields(
    payload: Mapping[str, Any],
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
    context: str,
) -> None:
    required_fields = set(required)
    allowed_fields = required_fields | set(optional)
    unknown = sorted(set(payload) - allowed_fields)
    if unknown:
        raise ValueError(f"{context} contains unknown field `{unknown[0]}`")
    missing = sorted(required_fields - set(payload))
    if missing:
        raise TypeError(f"{context} is missing required `{missing[0]}` field")


def _space_directory_manifest_scope(
    value: Any,
    *,
    context: str,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be an object")
    _require_wire_fields(
        value,
        required=(),
        optional={"asset", "dataspace", "method", "program", "role"},
        context=context,
    )
    scope: Dict[str, Any] = {}
    for field_name, raw in value.items():
        if raw is None:
            raise ValueError(f"{context}.{field_name} must be omitted instead of null")
        if field_name == "dataspace":
            scope[field_name] = _require_u64(raw, f"{context}.{field_name}")
            continue
        literal = _require_exact_non_empty_string(raw, f"{context}.{field_name}")
        if field_name == "role" and literal not in {"Initiator", "Participant"}:
            raise ValueError(f"{context}.role must be Initiator or Participant")
        scope[field_name] = literal
    return scope


def _space_directory_manifest_effect(
    value: Any,
    *,
    context: str,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be an object")
    _require_wire_fields(
        value,
        required=(),
        optional={"Allow", "Deny"},
        context=context,
    )
    if len(value) != 1:
        raise ValueError(f"{context} must contain exactly one Allow or Deny decision")
    decision, raw_details = next(iter(value.items()))
    if not isinstance(raw_details, Mapping):
        raise TypeError(f"{context}.{decision} must be an object")
    if decision == "Allow":
        _require_wire_fields(
            raw_details,
            required={"window"},
            optional={"max_amount"},
            context=f"{context}.Allow",
        )
        window = _require_exact_non_empty_string(
            raw_details["window"],
            f"{context}.Allow.window",
        )
        if window not in {"PerSlot", "PerMinute", "PerDay"}:
            raise ValueError(
                f"{context}.Allow.window must be PerSlot, PerMinute, or PerDay"
            )
        details: Dict[str, Any] = {"window": window}
        if "max_amount" in raw_details:
            if raw_details["max_amount"] is None:
                raise ValueError(
                    f"{context}.Allow.max_amount must be omitted instead of null"
                )
            details["max_amount"] = _canonical_quantity_text(
                raw_details["max_amount"],
                f"{context}.Allow.max_amount",
            )
        return {"Allow": details}
    if decision == "Deny":
        _require_wire_fields(
            raw_details,
            required=(),
            optional={"reason"},
            context=f"{context}.Deny",
        )
        if "reason" not in raw_details:
            return {"Deny": {}}
        reason = raw_details["reason"]
        if reason is None:
            raise ValueError(f"{context}.Deny.reason must be omitted instead of null")
        if not isinstance(reason, str):
            raise TypeError(f"{context}.Deny.reason must be a string")
        return {"Deny": {"reason": reason}}
    raise ValueError(f"{context} must contain exactly one Allow or Deny decision")


def _space_directory_manifest_entry(
    value: Any,
    *,
    context: str,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be an object")
    _require_wire_fields(
        value,
        required={"scope", "effect"},
        optional={"notes"},
        context=context,
    )
    entry: Dict[str, Any] = {
        "scope": _space_directory_manifest_scope(
            value["scope"],
            context=f"{context}.scope",
        ),
        "effect": _space_directory_manifest_effect(
            value["effect"],
            context=f"{context}.effect",
        ),
    }
    if "notes" in value:
        notes = value["notes"]
        if notes is None:
            raise ValueError(f"{context}.notes must be omitted instead of null")
        if not isinstance(notes, str):
            raise TypeError(f"{context}.notes must be a string")
        entry["notes"] = notes
    return entry


def _parse_space_directory_manifest(
    manifest: Any,
    *,
    context: str,
) -> Dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise TypeError(f"{context} must be an object")
    _require_wire_fields(
        manifest,
        required={
            "version",
            "uaid",
            "dataspace",
            "issued_ms",
            "activation_epoch",
            "entries",
        },
        optional={"expiry_epoch"},
        context=context,
    )
    version = _require_u64(manifest["version"], f"{context}.version")
    if version != 1:
        raise ValueError(f"{context}.version must equal 1")
    entries_raw = manifest["entries"]
    if not isinstance(entries_raw, list):
        raise TypeError(f"{context}.entries must be an array")
    result: Dict[str, Any] = {
        "version": version,
        "uaid": _normalize_uaid_literal(manifest["uaid"], context=f"{context}.uaid"),
        "dataspace": _require_u64(manifest["dataspace"], f"{context}.dataspace"),
        "issued_ms": _require_u64(manifest["issued_ms"], f"{context}.issued_ms"),
        "activation_epoch": _require_u64(
            manifest["activation_epoch"],
            f"{context}.activation_epoch",
        ),
        "entries": [
            _space_directory_manifest_entry(
                entry,
                context=f"{context}.entries[{index}]",
            )
            for index, entry in enumerate(entries_raw)
        ],
    }
    if "expiry_epoch" in manifest:
        if manifest["expiry_epoch"] is None:
            raise ValueError(f"{context}.expiry_epoch must be omitted instead of null")
        result["expiry_epoch"] = _require_u64(
            manifest["expiry_epoch"],
            f"{context}.expiry_epoch",
        )
    return result


def _normalize_space_directory_manifest_payload(
    manifest: Any,
    *,
    context: str,
) -> Dict[str, Any]:
    return _parse_space_directory_manifest(manifest, context=context)


def _normalize_publish_space_directory_manifest_request(
    request: Mapping[str, Any],
) -> Dict[str, Any]:
    _reject_zk_verifying_key_private_key_fields(
        request, "publish_space_directory_manifest"
    )
    authority = _require_non_empty_string(
        request.get("authority"),
        "publish_space_directory_manifest.authority",
    )
    manifest_payload = request.get("manifest")
    if manifest_payload is None:
        raise TypeError("publish_space_directory_manifest.manifest is required")
    manifest = _normalize_space_directory_manifest_payload(
        manifest_payload,
        context="publish_space_directory_manifest.manifest",
    )
    payload: Dict[str, Any] = {"authority": authority, "manifest": manifest}
    reason = request.get("reason")
    if reason is not None:
        if not isinstance(reason, str):
            raise TypeError("publish_space_directory_manifest.reason must be a string")
        payload["reason"] = reason
    return payload


def _normalize_revoke_space_directory_manifest_request(
    request: Mapping[str, Any],
) -> Dict[str, Any]:
    _reject_zk_verifying_key_private_key_fields(
        request, "revoke_space_directory_manifest"
    )
    authority = _require_non_empty_string(
        request.get("authority"),
        "revoke_space_directory_manifest.authority",
    )
    _reject_alias_keys(
        request,
        {
            "uaid_literal": "uaid",
            "uaidLiteral": "uaid",
            "dataspace_id": "dataspace",
            "dataspaceId": "dataspace",
            "revokedEpoch": "revoked_epoch",
        },
        context="revoke_space_directory_manifest",
    )
    uaid_literal = request.get("uaid")
    uaid = _normalize_uaid_literal(
        uaid_literal,
        context="revoke_space_directory_manifest.uaid",
    )
    dataspace_raw = request.get("dataspace")
    if dataspace_raw is None:
        raise TypeError("revoke_space_directory_manifest.dataspace is required")
    dataspace = _normalize_positive_int(
        dataspace_raw,
        "revoke_space_directory_manifest.dataspace",
        allow_zero=True,
    )
    revoked_epoch_raw = request.get("revoked_epoch")
    if revoked_epoch_raw is None:
        raise TypeError("revoke_space_directory_manifest.revoked_epoch is required")
    revoked_epoch = _normalize_positive_int(
        revoked_epoch_raw,
        "revoke_space_directory_manifest.revoked_epoch",
        allow_zero=True,
    )
    payload: Dict[str, Any] = {
        "authority": authority,
        "uaid": uaid,
        "dataspace": dataspace,
        "revoked_epoch": revoked_epoch,
    }
    reason = request.get("reason")
    if reason is not None:
        if not isinstance(reason, str):
            raise TypeError("revoke_space_directory_manifest.reason must be a string")
        payload["reason"] = reason
    return payload


def _normalize_iso_week_label(value: Any, context: str) -> str:
    if isinstance(value, str):
        label = value.strip().upper()
        if not _ISO_WEEK_RE.match(label):
            raise ValueError(f"{context} must match YYYY-Www (e.g., 2026-W05)")
        return label
    if isinstance(value, (tuple, list)):
        if len(value) != 2:
            raise ValueError(f"{context} tuple must contain (year, week)")
        year = _normalize_positive_int(value[0], f"{context}.year", allow_zero=False)
        week = _normalize_positive_int(value[1], f"{context}.week", allow_zero=False)
        if week > 53:
            raise ValueError(f"{context}.week must be between 1 and 53")
        return f"{year:04d}-W{week:02d}"
    raise TypeError(f"{context} must be a string or (year, week) tuple")


def _coerce_bool_flag(value: Any, context: str) -> bool:
    if isinstance(value, bool):
        return value
    raise TypeError(f"{context} must be a boolean")


def _coerce_finite_float(value: Any, context: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise TypeError(f"{context} must be a finite number") from None
    if not math.isfinite(number):
        raise ValueError(f"{context} must be finite")
    return number


def _parse_optional_duration_ms_field(value: Any, context: str) -> Optional[int]:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be an object")
    return _coerce_int(value.get("ms"), f"{context}.ms", allow_zero=True)


def _normalize_base64_payload(
    explicit_b64: Optional[Any],
    default_payload: Optional[Any],
    context: str,
) -> str:
    source = explicit_b64 if explicit_b64 is not None else default_payload
    if source is None:
        raise ValueError(f"{context} must be provided")
    if isinstance(source, str):
        trimmed = source.strip()
        if not trimmed:
            raise ValueError(f"{context} must be a non-empty base64 string")
        try:
            base64.b64decode(trimmed, validate=True)
        except binascii.Error as exc:
            raise ValueError(f"{context} must be base64 encoded") from exc
        return trimmed
    if isinstance(source, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(source)).decode("ascii")
    raise TypeError(f"{context} must be bytes or a base64 string")


def _normalize_sorafs_reputation_snapshot_id_hex(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be exactly 32 lowercase hexadecimal characters")
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise ValueError(f"{context} must be exactly 32 lowercase hexadecimal characters")
    if value == "0" * 32:
        raise ValueError(f"{context} must be nonzero")
    return value


def _normalize_sorafs_reputation_provider_id(value: Any, context: str) -> str:
    provider_id = _require_exact_non_empty_string(value, context)
    if len(provider_id) > 256:
        raise ValueError(f"{context} must be at most 256 characters")
    if not re.fullmatch(r"[0-9A-Za-z_.:-]+", provider_id):
        raise ValueError(f"{context} contains unsupported characters")
    if provider_id in {".", ".."}:
        raise ValueError(f"{context} must not be a URL dot segment")
    return provider_id


_SORAFS_REPUTATION_RESPONSE_MAX_BYTES = 4_194_304
_SORAFS_REPUTATION_SSE_MAX_EVENT_BYTES = 65_536
_SORAFS_REPUTATION_U64_MAX = (1 << 64) - 1
_SORAFS_POR_PAGE_DEFAULT_LIMIT = 100
_SORAFS_POR_PAGE_MAX_LIMIT = 1_000
_SORAFS_POR_PAGE_MAX_BYTES = 4_194_304
_SORAFS_HEDGING_BILLING_JSON_RESPONSE_MAX_BYTES = 1_048_576
_SORAFS_BILLING_STATEMENT_RESPONSE_MAX_BYTES = 23_068_672
_SORAFS_REPUTATION_SNAPSHOT_FIELDS = frozenset(
    {
        "snapshot_id_hex",
        "generated_at_unix",
        "previous_snapshot_id_hex",
        "merkle_root_hex",
        "provider_count",
        "returned_provider_count",
        "limit",
        "truncated_providers",
        "alpha_bps",
        "current_score_weight_bps",
        "weights",
        "providers",
    }
)
_SORAFS_REPUTATION_PROVIDER_RESPONSE_FIELDS = frozenset(
    {
        "snapshot_id_hex",
        "generated_at_unix",
        "merkle_root_hex",
        "provider",
        "proof",
    }
)
_SORAFS_REPUTATION_WEIGHTS_RESPONSE_FIELDS = frozenset(
    {
        "snapshot_id_hex",
        "generated_at_unix",
        "alpha_bps",
        "current_score_weight_bps",
        "weights",
    }
)
_SORAFS_REPUTATION_WEIGHTS_FIELDS = frozenset(
    {
        "version",
        "por_success_bps",
        "pdp_success_bps",
        "potr_success_bps",
        "latency_bps",
        "dispute_bps",
        "token_violation_bps",
        "repair_breach_bps",
    }
)
_SORAFS_REPUTATION_PROVIDER_FIELDS = frozenset(
    {
        "provider_id",
        "score_bps",
        "degradation_flags",
        "raw_metrics",
        "raw_metrics_hash_hex",
    }
)
_SORAFS_REPUTATION_PROVIDER_METRICS_FIELDS = frozenset(
    {
        "version",
        "por_success_bps",
        "pdp_success_bps",
        "potr_success_bps",
        "latency_health_bps",
        "dispute_rate_bps",
        "token_violation_rate_bps",
        "repair_breach_rate_bps",
    }
)
_SORAFS_REPUTATION_DEGRADATION_FLAG_FIELDS = frozenset({"flag", "value"})
_SORAFS_REPUTATION_PROOF_FIELDS = frozenset(
    {"provider_id", "leaf_index", "leaf_count", "siblings_hex"}
)
_SORAFS_REPUTATION_EVENT_FIELDS = frozenset(
    {
        "version",
        "sequence",
        "snapshot_id_hex",
        "generated_at_unix",
        "merkle_root_hex",
        "provider_count",
        "previous_snapshot_id_hex",
    }
)
_SORAFS_REPUTATION_EVENT_PAGE_FIELDS = frozenset(
    {"since", "limit", "count", "next_since", "events"}
)
_SORAFS_REPUTATION_DEGRADATION_FLAG_ORDER = (
    "reserve_warning",
    "reserve_grace",
    "reserve_delinquent",
    "reserve_default",
    "proof_success_below90",
    "proof_success_below80",
    "active_dispute",
    "slashing_event",
    "low_score",
)
_SORAFS_REPUTATION_DEGRADATION_FLAGS = frozenset(
    _SORAFS_REPUTATION_DEGRADATION_FLAG_ORDER
)


def _normalize_sorafs_hedging_billing_digest(value: Any, context: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{context} must be an exact lowercase 32-byte hex string")
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{context} must be an exact lowercase 32-byte hex string")
    if value == "0" * 64:
        raise ValueError(f"{context} must be nonzero")
    return value


def _normalize_sorafs_hedging_billing_limit(value: Any, context: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{context} must be an integer from 1 through 100")
    if not 1 <= value <= 100:
        raise ValueError(f"{context} must be an integer from 1 through 100")
    return value


def _decode_sorafs_reputation_sse_json(payload: str) -> Any:
    context = "SoraFS reputation SSE data"
    if not isinstance(payload, str) or not payload:
        raise ValueError(f"{context} must be exact compact JSON")
    if any(character.isspace() for character in payload):
        raise ValueError(f"{context} must be exact compact JSON")
    return decode_exact_json_bytes(
        payload.encode("utf-8"),
        context,
        maximum_bytes=_SORAFS_REPUTATION_RESPONSE_MAX_BYTES,
    )


def _sorafs_reputation_object(value: Any, context: str) -> Dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{context} must be a JSON object")
    return value


def _sorafs_reputation_list(value: Any, context: str) -> List[Any]:
    if type(value) is not list:
        raise ValueError(f"{context} must be a JSON array")
    return value


def _sorafs_reputation_exact_fields(
    value: Dict[str, Any],
    expected: frozenset[str],
    context: str,
) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(
            f"{context} fields are not canonical; missing={missing} extra={extra}"
        )


def _sorafs_reputation_exact_string(value: Any, context: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{context} must be an exact non-empty string")
    return value


def _sorafs_reputation_provider_id(value: Any, context: str) -> str:
    provider_id = _sorafs_reputation_exact_string(value, context)
    if len(provider_id) > 256 or not re.fullmatch(r"[0-9A-Za-z_.:-]+", provider_id):
        raise ValueError(
            f"{context} must be 1..256 ASCII characters from [A-Za-z0-9_.:-]"
        )
    if provider_id in {".", ".."}:
        raise ValueError(f"{context} must not be a URL dot segment")
    return provider_id


def _sorafs_reputation_snapshot_id(value: Any, context: str) -> str:
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise ValueError(f"{context} must be exactly 32 lowercase hexadecimal characters")
    if value == "0" * 32:
        raise ValueError(f"{context} must be nonzero")
    return value


def _sorafs_reputation_optional_snapshot_id(value: Any, context: str) -> Optional[str]:
    return None if value is None else _sorafs_reputation_snapshot_id(value, context)


def _sorafs_reputation_digest(value: Any, context: str) -> str:
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{context} must be exactly 64 lowercase hexadecimal characters")
    return value


def _sorafs_reputation_u64(
    value: Any,
    context: str,
    *,
    allow_zero: bool,
) -> int:
    if type(value) is not int:
        raise ValueError(f"{context} must be a canonical unsigned integer")
    if value < 0 or value > _SORAFS_REPUTATION_U64_MAX:
        raise ValueError(f"{context} must fit canonical u64")
    if not allow_zero and value == 0:
        raise ValueError(f"{context} must be positive")
    return value


def _sorafs_reputation_optional_u64(
    value: Any,
    context: str,
    *,
    allow_zero: bool,
) -> Optional[int]:
    return (
        None
        if value is None
        else _sorafs_reputation_u64(value, context, allow_zero=allow_zero)
    )


def _sorafs_reputation_bounded_int(
    value: Any,
    context: str,
    minimum: int,
    maximum: int,
) -> int:
    parsed = _sorafs_reputation_u64(value, context, allow_zero=minimum == 0)
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{context} must be between {minimum} and {maximum}")
    return parsed


def _sorafs_reputation_exact_int(value: Any, context: str, expected: int) -> int:
    parsed = _sorafs_reputation_bounded_int(value, context, expected, expected)
    if parsed != expected:
        raise ValueError(f"{context} must equal {expected}")
    return parsed


def _validate_sorafs_reputation_weights(
    value: Any,
    context: str,
) -> Dict[str, Any]:
    weights = _sorafs_reputation_object(value, context)
    _sorafs_reputation_exact_fields(
        weights,
        _SORAFS_REPUTATION_WEIGHTS_FIELDS,
        context,
    )
    _sorafs_reputation_exact_int(weights["version"], f"{context}.version", 1)
    fields = (
        "por_success_bps",
        "pdp_success_bps",
        "potr_success_bps",
        "latency_bps",
        "dispute_bps",
        "token_violation_bps",
        "repair_breach_bps",
    )
    total = sum(
        _sorafs_reputation_bounded_int(
            weights[field_name],
            f"{context}.{field_name}",
            0,
            10_000,
        )
        for field_name in fields
    )
    if total != 10_000:
        raise ValueError(f"{context} basis-point fields must sum to exactly 10000")
    return weights


def _validate_sorafs_reputation_provider_metrics(
    value: Any,
    context: str,
) -> Dict[str, Any]:
    metrics = _sorafs_reputation_object(value, context)
    _sorafs_reputation_exact_fields(
        metrics,
        _SORAFS_REPUTATION_PROVIDER_METRICS_FIELDS,
        context,
    )
    _sorafs_reputation_exact_int(metrics["version"], f"{context}.version", 1)
    for field_name in (
        "por_success_bps",
        "pdp_success_bps",
        "potr_success_bps",
        "latency_health_bps",
        "dispute_rate_bps",
        "token_violation_rate_bps",
        "repair_breach_rate_bps",
    ):
        _sorafs_reputation_bounded_int(
            metrics[field_name],
            f"{context}.{field_name}",
            0,
            10_000,
        )
    return metrics


def _validate_sorafs_reputation_provider(
    value: Any,
    context: str,
) -> Dict[str, Any]:
    provider = _sorafs_reputation_object(value, context)
    _sorafs_reputation_exact_fields(
        provider,
        _SORAFS_REPUTATION_PROVIDER_FIELDS,
        context,
    )
    _sorafs_reputation_provider_id(provider["provider_id"], f"{context}.provider_id")
    _sorafs_reputation_bounded_int(provider["score_bps"], f"{context}.score_bps", 500, 9_900)
    flags = _sorafs_reputation_list(
        provider["degradation_flags"],
        f"{context}.degradation_flags",
    )
    labels: List[str] = []
    for index, value in enumerate(flags):
        flag_context = f"{context}.degradation_flags[{index}]"
        flag = _sorafs_reputation_object(value, flag_context)
        _sorafs_reputation_exact_fields(
            flag,
            _SORAFS_REPUTATION_DEGRADATION_FLAG_FIELDS,
            flag_context,
        )
        if flag["value"] is not None:
            raise ValueError(f"{flag_context}.value must be null")
        label = _sorafs_reputation_exact_string(flag["flag"], f"{flag_context}.flag")
        if label not in _SORAFS_REPUTATION_DEGRADATION_FLAGS:
            raise ValueError(f"{flag_context}.flag is unsupported")
        labels.append(label)
    if len(labels) > 5 or len(set(labels)) != len(labels):
        raise ValueError(
            f"{context}.degradation_flags must be unique and contain at most five entries"
        )
    order = {
        label: index
        for index, label in enumerate(_SORAFS_REPUTATION_DEGRADATION_FLAG_ORDER)
    }
    if any(order[left] >= order[right] for left, right in zip(labels, labels[1:], strict=False)):
        raise ValueError(f"{context}.degradation_flags must use canonical enum order")
    _validate_sorafs_reputation_provider_metrics(
        provider["raw_metrics"],
        f"{context}.raw_metrics",
    )
    _sorafs_reputation_digest(
        provider["raw_metrics_hash_hex"],
        f"{context}.raw_metrics_hash_hex",
    )
    return provider


def _sorafs_reputation_merkle_depth(leaf_count: int) -> int:
    width = leaf_count
    depth = 0
    while width > 1:
        width = (width + 1) // 2
        depth += 1
    return depth


def _validate_sorafs_reputation_proof(
    value: Any,
    context: str,
) -> Dict[str, Any]:
    proof = _sorafs_reputation_object(value, context)
    _sorafs_reputation_exact_fields(
        proof,
        _SORAFS_REPUTATION_PROOF_FIELDS,
        context,
    )
    _sorafs_reputation_provider_id(proof["provider_id"], f"{context}.provider_id")
    leaf_index = _sorafs_reputation_bounded_int(
        proof["leaf_index"],
        f"{context}.leaf_index",
        0,
        65_535,
    )
    leaf_count = _sorafs_reputation_bounded_int(
        proof["leaf_count"],
        f"{context}.leaf_count",
        1,
        65_536,
    )
    if leaf_index >= leaf_count:
        raise ValueError(f"{context}.leaf_index must be less than leaf_count")
    siblings = _sorafs_reputation_list(proof["siblings_hex"], f"{context}.siblings_hex")
    for index, sibling in enumerate(siblings):
        _sorafs_reputation_digest(sibling, f"{context}.siblings_hex[{index}]")
    if len(siblings) != _sorafs_reputation_merkle_depth(leaf_count):
        raise ValueError(
            f"{context}.siblings_hex must have the exact Merkle depth for leaf_count"
        )
    return proof


def _validate_sorafs_reputation_event(
    value: Any,
    context: str,
) -> Dict[str, Any]:
    event = _sorafs_reputation_object(value, context)
    _sorafs_reputation_exact_fields(
        event,
        _SORAFS_REPUTATION_EVENT_FIELDS,
        context,
    )
    _sorafs_reputation_exact_int(event["version"], f"{context}.version", 1)
    _sorafs_reputation_u64(event["sequence"], f"{context}.sequence", allow_zero=False)
    snapshot_id = _sorafs_reputation_snapshot_id(
        event["snapshot_id_hex"],
        f"{context}.snapshot_id_hex",
    )
    _sorafs_reputation_u64(
        event["generated_at_unix"],
        f"{context}.generated_at_unix",
        allow_zero=False,
    )
    _sorafs_reputation_digest(event["merkle_root_hex"], f"{context}.merkle_root_hex")
    _sorafs_reputation_bounded_int(
        event["provider_count"],
        f"{context}.provider_count",
        1,
        65_536,
    )
    previous = _sorafs_reputation_optional_snapshot_id(
        event["previous_snapshot_id_hex"],
        f"{context}.previous_snapshot_id_hex",
    )
    if previous == snapshot_id:
        raise ValueError(
            f"{context}.previous_snapshot_id_hex must differ from snapshot_id_hex"
        )
    return event


def _validate_sorafs_reputation_snapshot(
    value: Any,
    context: str,
) -> Dict[str, Any]:
    snapshot = _sorafs_reputation_object(value, context)
    _sorafs_reputation_exact_fields(
        snapshot,
        _SORAFS_REPUTATION_SNAPSHOT_FIELDS,
        context,
    )
    snapshot_id = _sorafs_reputation_snapshot_id(
        snapshot["snapshot_id_hex"],
        f"{context}.snapshot_id_hex",
    )
    _sorafs_reputation_u64(
        snapshot["generated_at_unix"],
        f"{context}.generated_at_unix",
        allow_zero=False,
    )
    previous = _sorafs_reputation_optional_snapshot_id(
        snapshot["previous_snapshot_id_hex"],
        f"{context}.previous_snapshot_id_hex",
    )
    if previous == snapshot_id:
        raise ValueError(
            f"{context}.previous_snapshot_id_hex must differ from snapshot_id_hex"
        )
    _sorafs_reputation_digest(snapshot["merkle_root_hex"], f"{context}.merkle_root_hex")
    provider_count = _sorafs_reputation_bounded_int(
        snapshot["provider_count"],
        f"{context}.provider_count",
        1,
        65_536,
    )
    returned_count = _sorafs_reputation_bounded_int(
        snapshot["returned_provider_count"],
        f"{context}.returned_provider_count",
        1,
        500,
    )
    limit = _sorafs_reputation_bounded_int(
        snapshot["limit"],
        f"{context}.limit",
        1,
        500,
    )
    providers = _sorafs_reputation_list(snapshot["providers"], f"{context}.providers")
    for index, provider in enumerate(providers):
        _validate_sorafs_reputation_provider(provider, f"{context}.providers[{index}]")
    provider_ids = [provider["provider_id"] for provider in providers]
    if any(
        left >= right
        for left, right in zip(provider_ids, provider_ids[1:], strict=False)
    ):
        raise ValueError(f"{context}.providers must be strictly ordered by provider_id")
    if returned_count != len(providers):
        raise ValueError(
            f"{context}.returned_provider_count must equal providers.length"
        )
    if returned_count != min(provider_count, limit):
        raise ValueError(
            f"{context}.returned_provider_count must equal min(provider_count, limit)"
        )
    truncated = snapshot["truncated_providers"]
    if type(truncated) is not bool:
        raise ValueError(f"{context}.truncated_providers must be a boolean")
    if truncated != (provider_count > returned_count):
        raise ValueError(
            f"{context}.truncated_providers is inconsistent with provider counts"
        )
    _sorafs_reputation_exact_int(snapshot["alpha_bps"], f"{context}.alpha_bps", 8_500)
    _sorafs_reputation_exact_int(
        snapshot["current_score_weight_bps"],
        f"{context}.current_score_weight_bps",
        7_000,
    )
    _validate_sorafs_reputation_weights(snapshot["weights"], f"{context}.weights")
    return snapshot


def _validate_sorafs_reputation_provider_response(
    value: Any,
    context: str,
) -> Dict[str, Any]:
    response = _sorafs_reputation_object(value, context)
    _sorafs_reputation_exact_fields(
        response,
        _SORAFS_REPUTATION_PROVIDER_RESPONSE_FIELDS,
        context,
    )
    _sorafs_reputation_snapshot_id(
        response["snapshot_id_hex"],
        f"{context}.snapshot_id_hex",
    )
    _sorafs_reputation_u64(
        response["generated_at_unix"],
        f"{context}.generated_at_unix",
        allow_zero=False,
    )
    _sorafs_reputation_digest(response["merkle_root_hex"], f"{context}.merkle_root_hex")
    provider = _validate_sorafs_reputation_provider(
        response["provider"],
        f"{context}.provider",
    )
    proof = _validate_sorafs_reputation_proof(response["proof"], f"{context}.proof")
    if provider["provider_id"] != proof["provider_id"]:
        raise ValueError(f"{context}.proof must reference the returned provider")
    return response


def _validate_sorafs_reputation_weights_response(
    value: Any,
    context: str,
) -> Dict[str, Any]:
    response = _sorafs_reputation_object(value, context)
    _sorafs_reputation_exact_fields(
        response,
        _SORAFS_REPUTATION_WEIGHTS_RESPONSE_FIELDS,
        context,
    )
    _sorafs_reputation_snapshot_id(
        response["snapshot_id_hex"],
        f"{context}.snapshot_id_hex",
    )
    _sorafs_reputation_u64(
        response["generated_at_unix"],
        f"{context}.generated_at_unix",
        allow_zero=False,
    )
    _sorafs_reputation_exact_int(response["alpha_bps"], f"{context}.alpha_bps", 8_500)
    _sorafs_reputation_exact_int(
        response["current_score_weight_bps"],
        f"{context}.current_score_weight_bps",
        7_000,
    )
    _validate_sorafs_reputation_weights(response["weights"], f"{context}.weights")
    return response


def _validate_sorafs_reputation_event_page(
    value: Any,
    context: str,
) -> Dict[str, Any]:
    page = _sorafs_reputation_object(value, context)
    _sorafs_reputation_exact_fields(
        page,
        _SORAFS_REPUTATION_EVENT_PAGE_FIELDS,
        context,
    )
    since = _sorafs_reputation_optional_u64(
        page["since"],
        f"{context}.since",
        allow_zero=True,
    )
    limit = _sorafs_reputation_bounded_int(page["limit"], f"{context}.limit", 1, 500)
    count = _sorafs_reputation_bounded_int(page["count"], f"{context}.count", 0, 500)
    events = _sorafs_reputation_list(page["events"], f"{context}.events")
    for index, event in enumerate(events):
        _validate_sorafs_reputation_event(event, f"{context}.events[{index}]")
    if count != len(events):
        raise ValueError(f"{context}.count must equal events.length")
    if count > limit:
        raise ValueError(f"{context}.count must not exceed limit")
    next_since = _sorafs_reputation_optional_u64(
        page["next_since"],
        f"{context}.next_since",
        allow_zero=False,
    )
    expected_next = events[-1]["sequence"] if events else None
    if next_since != expected_next:
        raise ValueError(f"{context}.next_since must equal the last event sequence")
    previous_sequence = since if since is not None else 0
    for index, event in enumerate(events):
        sequence = event["sequence"]
        if (index == 0 and sequence <= previous_sequence) or (
            index > 0 and sequence != previous_sequence + 1
        ):
            raise ValueError(
                f"{context} sequences must increase after since and be contiguous within the page"
            )
        previous_sequence = sequence
    for previous, current in zip(events, events[1:], strict=False):
        if current["previous_snapshot_id_hex"] != previous["snapshot_id_hex"]:
            raise ValueError(
                f"{context} previous_snapshot_id_hex must link adjacent events"
            )
        if current["generated_at_unix"] <= previous["generated_at_unix"]:
            raise ValueError(f"{context} generated_at_unix must strictly increase")
    return page


def _parse_and_validate_sorafs_reputation_response(
    response: requests.Response,
    validator: Callable[[Any, str], Dict[str, Any]],
    context: str,
) -> Dict[str, Any]:
    payload = decode_exact_json_bytes(
        read_bounded_identity_response(
            response,
            _SORAFS_REPUTATION_RESPONSE_MAX_BYTES,
            context,
            expected_content_type="application/json",
        ),
        context,
        maximum_bytes=_SORAFS_REPUTATION_RESPONSE_MAX_BYTES,
    )
    return validator(payload, context)


def _require_one_shot_transport(
    session: requests.Session,
    url: str,
    context: str,
) -> None:
    """Fail before signing when the selected requests adapter may retry."""

    try:
        adapter = session.get_adapter(url)
    except (LookupError, ValueError) as exc:
        raise ValueError(
            f"{context} requires a verifiable one-shot HTTP transport"
        ) from exc
    retry_policy = getattr(adapter, "max_retries", None)
    retry_total = getattr(retry_policy, "total", None)
    if retry_policy is None or retry_total is None:
        raise ValueError(f"{context} requires a verifiable one-shot HTTP transport")
    if retry_total is not False and retry_total != 0:
        raise ValueError(f"{context} requires transport retries to be disabled")


def _validate_sorafs_reputation_sse_event(event: SseEvent) -> SseEvent:
    context = "SoraFS reputation SSE event"
    if event.retry is not None:
        raise ValueError(f"{context} must not carry a retry field")
    fields: List[str] = []
    for line in event.raw.split("\n"):
        if not line or line.startswith(":"):
            raise ValueError(f"{context} must use the exact field profile")
        field_name, separator, _ = line.partition(":")
        if not separator:
            raise ValueError(f"{context} must use the exact field profile")
        fields.append(field_name)
    if event.event == "reputation_snapshot":
        if sorted(fields) != ["data", "event", "id"]:
            raise ValueError(f"{context} must use exactly one id, event, and data field")
        payload = _validate_sorafs_reputation_event(
            event.data,
            f"{context}.data",
        )
        if (
            type(event.id) is not str
            or not re.fullmatch(r"[1-9][0-9]*", event.id)
            or int(event.id) > _SORAFS_REPUTATION_U64_MAX
        ):
            raise ValueError(f"{context} id must be a positive canonical u64")
        if int(event.id) != payload["sequence"]:
            raise ValueError(f"{context} id must equal data.sequence")
        return event
    if event.event == "lagged":
        if event.id is not None:
            raise ValueError(f"{context} lagged frames must not carry an id")
        if sorted(fields) != ["data", "event"]:
            raise ValueError(f"{context} lagged frames must use one event and data field")
        _sorafs_reputation_u64(
            event.data,
            f"{context}.lagged_count",
            allow_zero=False,
        )
        return event
    raise ValueError(f"{context} type {event.event!r} is unsupported")


_SORAFS_REPUTATION_CANONICAL_AUTH_HEADERS = frozenset(
    {
        "x-iroha-account",
        "x-iroha-signature",
        "x-iroha-timestamp-ms",
        "x-iroha-nonce",
        "x-iroha-witness",
    }
)


def _sorafs_reputation_auth_entries(
    headers: Optional[Mapping[str, Any]],
    context: str,
) -> Dict[str, Tuple[str, Any]]:
    entries: Dict[str, Tuple[str, Any]] = {}
    if headers is None:
        return entries
    for raw_name, value in headers.items():
        name = str(raw_name)
        normalized = name.lower()
        if normalized not in _SORAFS_REPUTATION_CANONICAL_AUTH_HEADERS:
            continue
        if normalized in entries:
            raise ValueError(f"{context} contains duplicate canonical authentication header {name}")
        entries[normalized] = (name, value)
    return entries


def _normalize_sorafs_reputation_canonical_auth(
    canonical_auth: Any,
    context: str,
    *,
    expected_discriminant: int,
) -> ToriiCanonicalRequestAuth:
    if not isinstance(canonical_auth, ToriiCanonicalRequestAuth):
        raise TypeError(f"{context} must be ToriiCanonicalRequestAuth")
    account_id = _require_exact_non_empty_string(
        canonical_auth.account_id,
        f"{context}.account_id",
    )
    if (
        _normalize_canonical_account_id(
            account_id,
            f"{context}.account_id",
            expected_discriminant=expected_discriminant,
        )
        != account_id
    ):
        raise ValueError(f"{context}.account_id must be exact and canonical")
    if not callable(canonical_auth.signer):
        raise TypeError(f"{context}.signer must be callable")
    return canonical_auth

def _normalize_sorafs_reputation_witness_header(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{context} must be exact canonical standard base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{context} must be exact canonical standard base64") from exc
    if not decoded or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{context} must be exact canonical standard base64")
    return value


def _sorafs_reputation_request_auth(
    *,
    canonical_auth: Optional[ToriiCanonicalRequestAuth],
    headers: Dict[str, Any],
    default_headers: Mapping[str, str],
    context: str,
    expected_discriminant: int,
) -> Tuple[Dict[str, str], Optional[ToriiCanonicalRequestAuth]]:
    if _sorafs_reputation_auth_entries(
        default_headers,
        "ToriiClient.default_headers",
    ):
        raise ValueError(
            f"{context} requires per-request canonical authentication; "
            "canonical auth headers are not accepted through default_headers"
        )

    entries = _sorafs_reputation_auth_entries(headers, f"{context}.headers")
    if canonical_auth is not None:
        if entries:
            raise ValueError(f"{context} accepts exactly one canonical authentication mode")
        return (
            _validated_sorafs_reputation_header_strings(headers, context),
            _normalize_sorafs_reputation_canonical_auth(
                canonical_auth,
                f"{context}.canonical_auth",
                expected_discriminant=expected_discriminant,
            ),
        )

    proof_fields = [
        name
        for name in ("x-iroha-signature", "x-iroha-timestamp-ms", "x-iroha-nonce")
        if name in entries
    ]
    if proof_fields:
        raise ValueError(
            f"{context}.headers cannot supply signature proof fields directly; use canonical_auth"
        )
    witness = entries.get("x-iroha-witness")
    if witness is None:
        raise ValueError(f"{context} requires canonical_auth or an exact X-Iroha-Witness header")
    _set_exact_header(
        headers,
        "X-Iroha-Witness",
        _normalize_sorafs_reputation_witness_header(
            witness[1],
            f"{context}.headers.X-Iroha-Witness",
        ),
    )
    account = entries.get("x-iroha-account")
    if account is not None:
        account_context = f"{context}.headers.X-Iroha-Account"
        account_id = _require_exact_non_empty_string(account[1], account_context)
        canonical_account = _normalize_canonical_account_id(
            account_id, account_context, expected_discriminant=expected_discriminant,
        )
        if canonical_account != account_id:
            raise ValueError(f"{context}.headers.X-Iroha-Account must be exact and canonical")
        account_header = canonical_account
        if "@" not in canonical_account:
            account_header = AccountAddress.parse_encoded(
                canonical_account, expected_discriminant=expected_discriminant
            ).canonical_hex()
        _set_exact_header(headers, "X-Iroha-Account", account_header)
    return _validated_sorafs_reputation_header_strings(headers, context), None

def _validated_sorafs_reputation_header_strings(
    headers: Mapping[str, Any],
    context: str,
) -> Dict[str, str]:
    final_headers: Dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(value, str):
            raise TypeError(f"{context}.headers.{name} must be a string")
        final_headers[name] = value
    return final_headers

def _sorafs_reputation_headers(
    *,
    if_none_match: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
    context: str,
    accept: str = "application/json",
) -> Dict[str, Any]:
    final_headers: Dict[str, Any] = {}
    if headers is not None:
        if not isinstance(headers, Mapping):
            raise TypeError(f"{context}.headers must be a mapping")
        for raw_key, value in headers.items():
            key = str(raw_key)
            final_headers[key] = (
                value
                if key.lower() in _SORAFS_REPUTATION_CANONICAL_AUTH_HEADERS
                else str(value)
            )
    _set_exact_header(final_headers, "Accept", accept)
    _set_exact_header(final_headers, "Accept-Encoding", "identity")
    if if_none_match is not None:
        if any(name.lower() == "if-none-match" for name in final_headers):
            raise ValueError(f"{context} accepts If-None-Match only through if_none_match")
        final_headers["If-None-Match"] = _require_exact_non_empty_string(
            if_none_match,
            f"{context}.if_none_match",
        )
    return final_headers


def _normalize_sorafs_reputation_decimal(
    value: Any,
    context: str,
    *,
    allow_zero: bool,
    maximum: int,
) -> str:
    if isinstance(value, bool):
        raise TypeError(f"{context} must be a canonical unsigned decimal integer")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        number = int(value)
    else:
        raise TypeError(f"{context} must be a canonical unsigned decimal integer")
    if number < 0 or (number == 0 and not allow_zero):
        raise ValueError(f"{context} must be {'non-negative' if allow_zero else 'positive'}")
    if number > maximum:
        raise ValueError(f"{context} must be at most {maximum}")
    return str(number)


def _sorafs_reputation_event_params(
    *,
    since: Optional[Any] = None,
    limit: Optional[Any] = None,
    context: str,
) -> Optional[Dict[str, str]]:
    params: Dict[str, str] = {}
    if since is not None:
        params["since"] = _normalize_sorafs_reputation_decimal(
            since,
            f"{context}.since",
            allow_zero=True,
            maximum=(1 << 64) - 1,
        )
    if limit is not None:
        params["limit"] = _normalize_sorafs_reputation_decimal(
            limit,
            f"{context}.limit",
            allow_zero=False,
            maximum=500,
        )
    return params or None


def _sorafs_orderbook_events_websocket_url(
    base_url: str,
    *,
    params: Optional[Mapping[str, Any]],
    endpoint_path: str = "/v1/sorafs/orderbook/events/ws",
    context: str,
) -> str:
    if not isinstance(endpoint_path, str) or not endpoint_path:
        raise TypeError(f"{context}.endpoint_path must be a non-empty string")
    if "?" in endpoint_path or "#" in endpoint_path:
        raise ValueError(f"{context}.endpoint_path must not include query or fragment")
    if not endpoint_path.startswith("/"):
        raise ValueError(f"{context}.endpoint_path must start with '/'")
    parsed = urlparse(base_url)
    scheme_map = {"http": "ws", "https": "wss", "ws": "ws", "wss": "wss"}
    if parsed.scheme not in scheme_map:
        raise ValueError(f"{context}.base_url uses unsupported scheme {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError(f"{context}.base_url must include a host")
    query = urlencode(params or {})
    return urlunparse((scheme_map[parsed.scheme], parsed.netloc, endpoint_path, "", query, ""))


def _websocket_text_frame(raw: Any, context: str) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw).decode("utf-8")
    raise TypeError(f"{context} expected WebSocket text or bytes frame")


def _parse_websocket_json_event(raw: Any, context: str) -> "WebSocketEvent":
    text = _websocket_text_frame(raw, context)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{context} received non-JSON WebSocket frame") from exc
    record = _require_mapping(payload, f"{context} frame")
    event = record.get("event")
    if event is not None:
        event = _require_non_empty_string(event, f"{context}.event")
    return WebSocketEvent(event=event, data=record.get("data", ""), raw=text)


def _normalize_required_base64_payload(value: Any, context: str) -> str:
    normalized = _normalize_base64_payload(None, value, context)
    decoded = base64.b64decode(normalized, validate=True)
    if not decoded:
        raise ValueError(f"{context} must be a non-empty base64 string")
    return base64.b64encode(decoded).decode("ascii")


_GOVERNANCE_PRIVATE_KEY_FIELDS = frozenset(
    {
        "private_key",
        "privateKey",
        "private_key_hex",
        "privateKeyHex",
        "private_key_bytes",
        "privateKeyBytes",
        "private_key_seed",
        "privateKeySeed",
        "private_key_multihash",
        "privateKeyMultihash",
        "private_key_algorithm",
        "privateKeyAlgorithm",
    }
)

_GOVERNANCE_DEPLOY_CONTRACT_FIELDS = frozenset(
    {
        "contract_address",
        "contract_alias",
        "abi_version",
        "code_hash",
        "abi_hash",
        "manifest_provenance",
    }
)
_GOVERNANCE_MANIFEST_PROVENANCE_FIELDS = frozenset({"signer", "signature"})
_GOVERNANCE_PLAIN_BALLOT_FIELDS = frozenset(
    {
        "authority",
        "network_id",
        "referendum_id",
        "owner",
        "amount",
        "duration_blocks",
        "direction",
    }
)
_GOVERNANCE_ZK_BALLOT_V1_FIELDS = frozenset(
    {
        "authority",
        "network_id",
        "election_id",
        "backend",
        "envelope_b64",
        "root_hint",
        "owner",
        "amount",
        "duration_blocks",
        "direction",
        "nullifier",
    }
)
_GOVERNANCE_ZK_BALLOT_PROOF_V1_FIELDS = frozenset(
    {"authority", "network_id", "election_id", "ballot"}
)
_GOVERNANCE_BALLOT_PROOF_FIELDS = frozenset(
    {
        "backend",
        "envelope_bytes",
        "root_hint",
        "owner",
        "nullifier",
        "amount",
        "duration_blocks",
        "direction",
    }
)
_GOVERNANCE_BALLOT_DIRECTIONS = frozenset({"Aye", "Nay", "Abstain"})


def _reject_governance_private_key_fields(
    payload: Any,
    *,
    context: str,
) -> None:
    pending: list[tuple[Any, str]] = [(payload, context)]
    visited: set[int] = set()
    while pending:
        candidate, path = pending.pop()
        if isinstance(candidate, Mapping):
            identity = id(candidate)
            if identity in visited:
                continue
            visited.add(identity)
            fields = sorted(
                key
                for key in candidate
                if isinstance(key, str) and key in _GOVERNANCE_PRIVATE_KEY_FIELDS
            )
            if fields:
                raise ValueError(
                    f"{path} does not accept private-key fields ({', '.join(fields)}); "
                    "sign the returned transaction draft locally"
                )
            pending.extend((nested, f"{path}.{key}") for key, nested in candidate.items())
        elif isinstance(candidate, (list, tuple)):
            identity = id(candidate)
            if identity in visited:
                continue
            visited.add(identity)
            pending.extend(
                (nested, f"{path}[{index}]")
                for index, nested in enumerate(candidate)
            )


def _copy_exact_governance_payload(
    payload: Mapping[str, Any],
    supported_fields: frozenset[str],
    *,
    context: str,
) -> Dict[str, Any]:
    record = _require_mapping(payload, context)
    _reject_governance_private_key_fields(record, context=context)
    if any(not isinstance(key, str) for key in record):
        raise TypeError(f"{context} field names must be strings")
    unknown = sorted(set(record).difference(supported_fields))
    if unknown:
        raise ValueError(f"{context} contains unknown field `{unknown[0]}`")
    return dict(record)


def _normalize_governance_manifest_provenance(
    value: Any,
    *,
    context: str,
) -> Dict[str, str]:
    record = _copy_exact_governance_payload(
        value,
        _GOVERNANCE_MANIFEST_PROVENANCE_FIELDS,
        context=context,
    )
    missing = sorted(_GOVERNANCE_MANIFEST_PROVENANCE_FIELDS.difference(record))
    if missing:
        raise ValueError(f"{context} is missing required field `{missing[0]}`")
    return {
        field: _require_exact_non_empty_string(record[field], f"{context}.{field}")
        for field in ("signer", "signature")
    }


def _normalize_governance_ballot_direction(
    value: Any,
    *,
    context: str,
    required: bool = False,
) -> Optional[str]:
    if value is None:
        if required:
            raise ValueError(f"{context} must be Aye, Nay, or Abstain")
        return None
    if not isinstance(value, str):
        raise TypeError(f"{context} must be Aye, Nay, or Abstain")
    if value not in _GOVERNANCE_BALLOT_DIRECTIONS:
        raise ValueError(f"{context} must be Aye, Nay, or Abstain")
    return value


def _reject_governance_public_input_key(
    record: Dict[str, Any],
    key: str,
    canonical_key: str,
    *,
    context: str,
) -> None:
    if key not in record:
        return
    raise ValueError(f"{context} must use {canonical_key} (unsupported key {key})")


def _normalize_governance_public_hex_hint(
    record: Dict[str, Any],
    key: str,
    *,
    context: str,
) -> None:
    if key not in record:
        return
    value = record[key]
    if value is None:
        return
    if isinstance(value, (bytes, bytearray, memoryview, list, tuple)):
        raw = _bytes_like_to_hex(value, f"{context}.{key}")
        if len(raw) != 64:
            raise ValueError(f"{context}.{key} must be a 32-byte hex string")
        record[key] = raw.lower()
        return
    if not isinstance(value, str):
        raise ValueError(f"{context}.{key} must be a 32-byte hex string")
    raw = value
    if ":" in raw:
        scheme, rest = raw.split(":", 1)
        if not scheme or scheme.lower() != "blake2b32":
            raise ValueError(f"{context}.{key} must be a 32-byte hex string")
        raw = rest
    if raw.startswith(("0x", "0X")):
        raw = raw[2:]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        raise ValueError(f"{context}.{key} must be a 32-byte hex string")
    record[key] = raw.lower()


def _ensure_governance_lock_hints_complete(
    owner: Any,
    amount: Any,
    duration_blocks: Any,
    *,
    context: str,
) -> None:
    has_owner = owner is not None
    has_amount = amount is not None
    has_duration = duration_blocks is not None
    has_any = has_owner or has_amount or has_duration
    if has_any and not (has_owner and has_amount and has_duration):
        raise ValueError(
            f"{context} must include owner, amount, duration_blocks when providing lock hints"
        )


def _ensure_governance_owner_canonical(owner: Any, *, context: str) -> None:
    if owner is None:
        return
    if not isinstance(owner, str):
        raise ValueError(f"{context}.owner must be a canonical I105 account id")
    trimmed = owner.strip()
    if not trimmed or trimmed != owner:
        raise ValueError(f"{context}.owner must be a canonical I105 account id")
    if any(ch.isspace() for ch in trimmed):
        raise ValueError(f"{context}.owner must be a canonical I105 account id")
    if "@" in trimmed:
        raise ValueError(f"{context}.owner must be a canonical I105 account id")
    try:
        address = AccountAddress.parse_encoded(
            trimmed, expected_discriminant=DEFAULT_I105_DISCRIMINANT
        )
    except AccountAddressError as exc:
        raise ValueError(f"{context}.owner must be a canonical I105 account id") from exc
    canonical = address.to_i105(DEFAULT_I105_DISCRIMINANT)
    if canonical != owner:
        raise ValueError(f"{context}.owner must be a canonical I105 account id")


def _normalize_governance_deploy_contract_payload(
    payload: Mapping[str, Any],
    *,
    context: str,
) -> Dict[str, Any]:
    record = _copy_exact_governance_payload(
        payload,
        _GOVERNANCE_DEPLOY_CONTRACT_FIELDS,
        context=context,
    )
    contract_address = record.get("contract_address")
    contract_alias = record.get("contract_alias")
    if (contract_address is None) == (contract_alias is None):
        raise ValueError(
            f"{context} requires exactly one of contract_address or contract_alias"
        )
    if contract_address is not None:
        record["contract_address"] = _require_exact_non_empty_string(
            contract_address,
            f"{context}.contract_address",
        )
        record.pop("contract_alias", None)
    else:
        record["contract_alias"] = _require_exact_non_empty_string(
            contract_alias,
            f"{context}.contract_alias",
        )
        record.pop("contract_address", None)

    abi_version = record.get("abi_version")
    if isinstance(abi_version, bool) or not isinstance(abi_version, int):
        raise TypeError(f"{context}.abi_version must be the integer 1")
    if abi_version != 1:
        raise ValueError(f"{context}.abi_version must be 1")
    for hash_field in ("code_hash", "abi_hash"):
        value = record.get(hash_field)
        if value is None:
            raise ValueError(f"{context} is missing required field `{hash_field}`")
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError(
                f"{context}.{hash_field} must be exactly 32 lowercase hexadecimal bytes"
            )
    if record.get("manifest_provenance") is not None:
        record["manifest_provenance"] = _normalize_governance_manifest_provenance(
            record["manifest_provenance"],
            context=f"{context}.manifest_provenance",
        )
    return record


def _normalize_governance_u64_decimal(value: Any, context: str) -> str:
    return _normalize_sorafs_reputation_decimal(
        value,
        context,
        allow_zero=True,
        maximum=(1 << 64) - 1,
    )


_normalize_governance_ballot_network_id = bind_governance_ballot_network_id(_normalize_network_id)

def _normalize_governance_plain_ballot_payload(
    payload: Mapping[str, Any],
    *,
    context: str,
) -> Dict[str, Any]:
    record = _copy_exact_governance_payload(
        payload,
        _GOVERNANCE_PLAIN_BALLOT_FIELDS,
        context=context,
    )
    _normalize_governance_ballot_network_id(record, context=context)
    record["authority"] = _require_exact_token_string(
        record.get("authority"),
        f"{context}.authority",
    )
    record["referendum_id"] = _require_governance_selector_string(
        record.get("referendum_id"),
        f"{context}.referendum_id",
    )
    record["amount"] = _canonical_quantity_text(
        record.get("amount"),
        f"{context} amount",
    )
    record["duration_blocks"] = _normalize_governance_u64_decimal(
        record.get("duration_blocks"),
        f"{context}.duration_blocks",
    )
    record["direction"] = _normalize_governance_ballot_direction(
        record.get("direction"),
        context=f"{context}.direction",
        required=True,
    )
    return record


def _normalize_governance_zk_ballot_v1_payload(
    payload: Mapping[str, Any],
    *,
    context: str,
) -> Dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise TypeError(f"{context} must be a JSON object")
    _reject_governance_private_key_fields(payload, context=context)
    record = dict(payload)
    _reject_governance_public_input_key(
        record,
        "durationBlocks",
        "duration_blocks",
        context=context,
    )
    _reject_governance_public_input_key(
        record,
        "root_hint_hex",
        "root_hint",
        context=context,
    )
    _reject_governance_public_input_key(
        record,
        "rootHintHex",
        "root_hint",
        context=context,
    )
    _reject_governance_public_input_key(
        record,
        "rootHint",
        "root_hint",
        context=context,
    )
    _reject_governance_public_input_key(
        record,
        "nullifier_hex",
        "nullifier",
        context=context,
    )
    _reject_governance_public_input_key(
        record,
        "nullifierHex",
        "nullifier",
        context=context,
    )
    record = _copy_exact_governance_payload(
        record,
        _GOVERNANCE_ZK_BALLOT_V1_FIELDS,
        context=context,
    )
    _normalize_governance_ballot_network_id(record, context=context)
    record["authority"] = _require_exact_token_string(
        record.get("authority"),
        f"{context}.authority",
    )
    record["election_id"] = _require_governance_selector_string(
        record.get("election_id"),
        f"{context}.election_id",
    )
    record["backend"] = _require_exact_token_string(
        record.get("backend"),
        f"{context}.backend",
    )
    record["envelope_b64"] = _normalize_required_base64_payload(
        record.get("envelope_b64"),
        f"{context}.envelope_b64",
    )
    _normalize_governance_public_hex_hint(
        record,
        "root_hint",
        context=context,
    )
    _normalize_governance_public_hex_hint(
        record,
        "nullifier",
        context=context,
    )
    _ensure_governance_lock_hints_complete(
        record.get("owner"),
        record.get("amount"),
        record.get("duration_blocks"),
        context=context,
    )
    if record.get("amount") is not None:
        record["amount"] = _canonical_quantity_text(
            record["amount"],
            f"{context}.amount",
        )
    _ensure_governance_owner_canonical(record.get("owner"), context=context)
    if record.get("duration_blocks") is not None:
        record["duration_blocks"] = int(
            _normalize_governance_u64_decimal(
                record["duration_blocks"],
                f"{context}.duration_blocks",
            )
        )
    elif "duration_blocks" in record:
        record.pop("duration_blocks")
    if "direction" in record:
        direction = _normalize_governance_ballot_direction(
            record["direction"],
            context=f"{context}.direction",
        )
        if direction is None:
            record.pop("direction")
        else:
            record["direction"] = direction
    return record


def _normalize_governance_zk_ballot_proof_payload(
    payload: Mapping[str, Any],
    *,
    context: str,
) -> Dict[str, Any]:
    record = _copy_exact_governance_payload(
        payload,
        _GOVERNANCE_ZK_BALLOT_PROOF_V1_FIELDS,
        context=context,
    )
    _normalize_governance_ballot_network_id(record, context=context)
    record["authority"] = _require_exact_token_string(
        record.get("authority"),
        f"{context}.authority",
    )
    record["election_id"] = _require_governance_selector_string(
        record.get("election_id"),
        f"{context}.election_id",
    )
    ballot = record.get("ballot")
    if ballot is None:
        raise ValueError(f"{context}.ballot must be provided")
    if not isinstance(ballot, Mapping):
        raise TypeError(f"{context}.ballot must be an object")
    _reject_governance_private_key_fields(ballot, context=f"{context}.ballot")
    ballot_record = dict(ballot)
    ballot_context = f"{context}.ballot"
    _reject_governance_public_input_key(
        ballot_record,
        "rootHintHex",
        "root_hint",
        context=ballot_context,
    )
    _reject_governance_public_input_key(
        ballot_record,
        "root_hint_hex",
        "root_hint",
        context=ballot_context,
    )
    _reject_governance_public_input_key(
        ballot_record,
        "rootHint",
        "root_hint",
        context=ballot_context,
    )
    _reject_governance_public_input_key(
        ballot_record,
        "nullifierHex",
        "nullifier",
        context=ballot_context,
    )
    _reject_governance_public_input_key(
        ballot_record,
        "nullifier_hex",
        "nullifier",
        context=ballot_context,
    )
    ballot_record = _copy_exact_governance_payload(
        ballot_record,
        _GOVERNANCE_BALLOT_PROOF_FIELDS,
        context=ballot_context,
    )
    ballot_record["backend"] = _require_exact_token_string(
        ballot_record.get("backend"),
        f"{ballot_context}.backend",
    )
    ballot_record["envelope_bytes"] = _normalize_required_base64_payload(
        ballot_record.get("envelope_bytes"),
        f"{ballot_context}.envelope_bytes",
    )
    _normalize_governance_public_hex_hint(
        ballot_record,
        "root_hint",
        context=ballot_context,
    )
    _normalize_governance_public_hex_hint(
        ballot_record,
        "nullifier",
        context=ballot_context,
    )
    _ensure_governance_lock_hints_complete(
        ballot_record.get("owner"),
        ballot_record.get("amount"),
        ballot_record.get("duration_blocks"),
        context=ballot_context,
    )
    if ballot_record.get("amount") is not None:
        ballot_record["amount"] = _canonical_quantity_text(
            ballot_record["amount"],
            f"{ballot_context}.amount",
        )
    _ensure_governance_owner_canonical(ballot_record.get("owner"), context=ballot_context)
    if ballot_record.get("duration_blocks") is not None:
        ballot_record["duration_blocks"] = int(
            _normalize_governance_u64_decimal(
                ballot_record["duration_blocks"],
                f"{ballot_context}.duration_blocks",
            )
        )
    elif "duration_blocks" in ballot_record:
        ballot_record.pop("duration_blocks")
    if "direction" in ballot_record:
        direction = _normalize_governance_ballot_direction(
            ballot_record["direction"],
            context=f"{ballot_context}.direction",
        )
        if direction is None:
            ballot_record.pop("direction")
        else:
            ballot_record["direction"] = direction
    record["ballot"] = ballot_record
    return record


def _build_sorafs_por_status_params(
    manifest_hex: Optional[str],
    provider_hex: Optional[str],
    epoch: Optional[int],
    status: Optional[str],
    limit: Optional[int],
    max_bytes: Optional[int],
    cursor: Optional[str],
) -> Optional[Dict[str, Any]]:
    params: Dict[str, Any] = {}
    if manifest_hex is not None:
        params["manifest"] = _normalize_hex_string(
            manifest_hex, "sorafs_por_status.manifest_hex", expected_length=64
        )
    if provider_hex is not None:
        params["provider"] = _normalize_hex_string(
            provider_hex, "sorafs_por_status.provider_hex", expected_length=64
        )
    if epoch is not None:
        params["epoch"] = _normalize_positive_int(
            epoch, "sorafs_por_status.epoch", allow_zero=False
        )
    if status is not None:
        trimmed = status.strip()
        if not trimmed:
            raise ValueError("sorafs_por_status.status must be non-empty")
        params["status"] = trimmed
    normalized_limit = _normalize_positive_int(
        _SORAFS_POR_PAGE_DEFAULT_LIMIT if limit is None else limit,
        "sorafs_por_status.limit",
        allow_zero=False,
    )
    if normalized_limit > _SORAFS_POR_PAGE_MAX_LIMIT:
        raise ValueError(
            f"sorafs_por_status.limit must be at most {_SORAFS_POR_PAGE_MAX_LIMIT}"
        )
    params["limit"] = normalized_limit
    normalized_max_bytes = _normalize_positive_int(
        _SORAFS_POR_PAGE_MAX_BYTES if max_bytes is None else max_bytes,
        "sorafs_por_status.max_bytes",
        allow_zero=False,
    )
    if normalized_max_bytes > _SORAFS_POR_PAGE_MAX_BYTES:
        raise ValueError(
            f"sorafs_por_status.max_bytes must be at most {_SORAFS_POR_PAGE_MAX_BYTES}"
        )
    params["max_bytes"] = normalized_max_bytes
    if cursor is not None:
        params["cursor"] = _normalize_sorafs_por_cursor(
            cursor, "sorafs_por_status.cursor"
        )
    return params


def _build_sorafs_por_export_params(
    start_epoch: Optional[int],
    end_epoch: Optional[int],
    limit: Optional[int],
    max_bytes: Optional[int],
    cursor: Optional[str],
) -> Optional[Dict[str, Any]]:
    params: Dict[str, Any] = {}
    if (start_epoch is None) != (end_epoch is None):
        raise ValueError(
            "sorafs_por_export.start_epoch and sorafs_por_export.end_epoch "
            "must be supplied together"
        )
    if start_epoch is not None:
        params["start_epoch"] = _normalize_positive_int(
            start_epoch, "sorafs_por_export.start_epoch", allow_zero=False
        )
    if end_epoch is not None:
        params["end_epoch"] = _normalize_positive_int(
            end_epoch, "sorafs_por_export.end_epoch", allow_zero=False
        )
    normalized_limit = _normalize_positive_int(
        _SORAFS_POR_PAGE_DEFAULT_LIMIT if limit is None else limit,
        "sorafs_por_export.limit",
        allow_zero=False,
    )
    if normalized_limit > _SORAFS_POR_PAGE_MAX_LIMIT:
        raise ValueError(
            f"sorafs_por_export.limit must be at most {_SORAFS_POR_PAGE_MAX_LIMIT}"
        )
    params["limit"] = normalized_limit
    normalized_max_bytes = _normalize_positive_int(
        _SORAFS_POR_PAGE_MAX_BYTES if max_bytes is None else max_bytes,
        "sorafs_por_export.max_bytes",
        allow_zero=False,
    )
    if normalized_max_bytes > _SORAFS_POR_PAGE_MAX_BYTES:
        raise ValueError(
            f"sorafs_por_export.max_bytes must be at most {_SORAFS_POR_PAGE_MAX_BYTES}"
        )
    params["max_bytes"] = normalized_max_bytes
    if cursor is not None:
        params["cursor"] = _normalize_sorafs_por_cursor(
            cursor, "sorafs_por_export.cursor"
        )
    return params


_CRYPTO_MODULE: Optional[ModuleType] = None
_ISO_WEEK_RE = re.compile(r"^\d{4}-W(0[1-9]|[1-4][0-9]|5[0-3])$")


@dataclass(frozen=True, slots=True)
class ResolvedToriiClientConfig:
    """Fully merged Torii client configuration."""

    timeout: float
    max_retries: int
    backoff_initial: float
    backoff_multiplier: float
    max_backoff: float
    retry_statuses: frozenset[int]
    retry_methods: frozenset[str]
    default_headers: Mapping[str, str]
    auth_token: Optional[str] = field(repr=False, compare=False)
    api_token: Optional[str] = field(repr=False, compare=False)
    sorafs_alias_policy: SorafsAliasPolicy

    def __post_init__(self) -> None:
        timeout = _require_positive_finite_float(self.timeout, "timeout")
        max_retries = _require_retry_count(self.max_retries)
        backoff_initial = _require_non_negative_finite_float(
            self.backoff_initial,
            "backoff_initial",
        )
        backoff_multiplier = _require_positive_finite_float(
            self.backoff_multiplier,
            "backoff_multiplier",
        )
        max_backoff = _require_non_negative_finite_float(
            self.max_backoff,
            "max_backoff",
        )
        if backoff_multiplier < 1.0:
            raise ValueError("backoff_multiplier must be at least 1")
        if max_backoff < backoff_initial:
            raise ValueError("max_backoff must be greater than or equal to backoff_initial")
        object.__setattr__(self, "timeout", timeout)
        object.__setattr__(self, "max_retries", max_retries)
        object.__setattr__(self, "backoff_initial", backoff_initial)
        object.__setattr__(self, "backoff_multiplier", backoff_multiplier)
        object.__setattr__(self, "max_backoff", max_backoff)
        object.__setattr__(
            self,
            "retry_statuses",
            _normalize_retry_statuses(self.retry_statuses),
        )
        object.__setattr__(
            self,
            "retry_methods",
            _normalize_retry_methods(self.retry_methods),
        )
        default_headers = _copy_http_headers(self.default_headers, "default_headers")
        _reject_reserved_default_headers(default_headers, "default_headers")
        object.__setattr__(self, "default_headers", MappingProxyType(default_headers))
        if self.auth_token is not None:
            object.__setattr__(
                self,
                "auth_token",
                _require_route_token(self.auth_token, "auth_token"),
            )
        if self.api_token is not None:
            object.__setattr__(
                self,
                "api_token",
                _require_route_token(self.api_token, "api_token"),
            )
        if not isinstance(self.sorafs_alias_policy, SorafsAliasPolicy):
            raise TypeError("sorafs_alias_policy must be a SorafsAliasPolicy")


@dataclass(frozen=True)
class _ToriiClientConfigDefaults:
    """Non-SoraFS defaults that are safe to materialize without native policy code."""

    timeout: float
    max_retries: int
    backoff_initial: float
    backoff_multiplier: float
    max_backoff: float
    retry_statuses: frozenset[int]
    retry_methods: frozenset[str]
    default_headers: Dict[str, str]
    auth_token: Optional[str]
    api_token: Optional[str]


_DEFAULT_RESOLVED_CONFIG = _ToriiClientConfigDefaults(
    timeout=30.0,
    max_retries=3,
    backoff_initial=0.5,
    backoff_multiplier=2.0,
    max_backoff=5.0,
    retry_statuses=frozenset({429, 502, 503, 504}),
    retry_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
    default_headers={"Accept": "application/json"},
    auth_token=None,
    api_token=None,
)


@dataclass(frozen=True)
class SorafsPorSubmissionResponse:
    """Response wrapper for PoR proof submissions."""

    status: str

    @classmethod
    def from_payload(
        cls, payload: Mapping[str, Any], context: str
    ) -> "SorafsPorSubmissionResponse":
        if not isinstance(payload, Mapping):
            raise TypeError(f"{context} must be a JSON object")
        status = payload.get("status")
        if not isinstance(status, str) or not status.strip():
            raise TypeError(f"{context} missing string `status` field")
        return cls(status=status.strip())


@dataclass(frozen=True)
class SorafsPorVerdictResponse:
    """Response wrapper for PoR verdict submissions."""

    status: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any], context: str) -> "SorafsPorVerdictResponse":
        base = SorafsPorSubmissionResponse.from_payload(payload, context)
        return cls(status=base.status)


@dataclass(frozen=True)
class SorafsPinRegisterResponse:
    """Queue-admission identity returned by `/v1/sorafs/pin/register`."""

    status: str
    tx_hash_hex: str
    manifest_digest_hex: str

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
        context: str,
    ) -> "SorafsPinRegisterResponse":
        required = {"status", "tx_hash_hex", "manifest_digest_hex"}
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise TypeError(
                f"{context} must contain only status, tx_hash_hex, and manifest_digest_hex"
            )
        if payload["status"] != "submitted":
            raise ValueError(f"{context}.status must be submitted")

        def canonical_digest(field: str) -> str:
            value = payload[field]
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ValueError(
                    f"{context}.{field} must be exactly 64 lowercase hexadecimal characters"
                )
            return value

        return cls(
            status="submitted",
            tx_hash_hex=_require_exact_pipeline_transaction_hash(
                payload["tx_hash_hex"],
                f"{context}.tx_hash_hex",
            ),
            manifest_digest_hex=canonical_digest("manifest_digest_hex"),
        )


@dataclass(frozen=True)
class SorafsPorIngestionProviderStatus:
    """Provider-level PoR ingestion snapshot returned by `/v1/sorafs/por/ingestion/{manifest}`."""

    provider_id_hex: str
    pending_challenges: int
    oldest_epoch_id: Optional[int]
    oldest_response_deadline_unix: Optional[int]
    last_success_unix: Optional[int]
    last_failure_unix: Optional[int]
    failures_total: int
    consecutive_failures: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SorafsPorIngestionProviderStatus":
        if not isinstance(payload, Mapping):
            raise TypeError("por ingestion provider entry must be an object")
        provider_literal = payload.get("provider_id_hex")
        if not isinstance(provider_literal, str) or not provider_literal:
            raise TypeError("por ingestion provider entry missing string `provider_id_hex` field")
        provider_id_hex = _normalize_hex_string(
            provider_literal,
            "por_ingestion.provider_id_hex",
            expected_length=64,
        )
        pending = _coerce_int(
            payload.get("pending_challenges"),
            "por ingestion provider pending_challenges",
            allow_zero=True,
        )
        if pending is None:
            raise TypeError(
                "por ingestion provider entry missing numeric `pending_challenges` field"
            )
        oldest_epoch = _coerce_int(
            payload.get("oldest_epoch_id"),
            "por ingestion provider oldest_epoch_id",
            allow_zero=True,
        )
        oldest_deadline = _coerce_int(
            payload.get("oldest_response_deadline_unix"),
            "por ingestion provider oldest_response_deadline_unix",
            allow_zero=True,
        )
        last_success = _coerce_int(
            payload.get("last_success_unix"),
            "por ingestion provider last_success_unix",
            allow_zero=True,
        )
        last_failure = _coerce_int(
            payload.get("last_failure_unix"),
            "por ingestion provider last_failure_unix",
            allow_zero=True,
        )
        failures_total = _coerce_int(
            payload.get("failures_total"),
            "por ingestion provider failures_total",
            allow_zero=True,
        )
        if failures_total is None:
            raise TypeError("por ingestion provider entry missing numeric `failures_total` field")
        consecutive_failures = _coerce_int(
            payload.get("consecutive_failures"),
            "por ingestion provider consecutive_failures",
            allow_zero=True,
        )
        if consecutive_failures is None:
            raise TypeError(
                "por ingestion provider entry missing numeric `consecutive_failures` field"
            )
        return cls(
            provider_id_hex=provider_id_hex,
            pending_challenges=pending,
            oldest_epoch_id=oldest_epoch,
            oldest_response_deadline_unix=oldest_deadline,
            last_success_unix=last_success,
            last_failure_unix=last_failure,
            failures_total=failures_total,
            consecutive_failures=consecutive_failures,
        )


@dataclass(frozen=True)
class SorafsPorIngestionStatus:
    """Manifest-level PoR ingestion snapshot."""

    manifest_digest_hex: str
    providers: List[SorafsPorIngestionProviderStatus]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SorafsPorIngestionStatus":
        if not isinstance(payload, Mapping):
            raise TypeError("por ingestion response must be an object")
        manifest_literal = payload.get("manifest_digest_hex")
        if not isinstance(manifest_literal, str) or not manifest_literal:
            raise TypeError("por ingestion response missing string `manifest_digest_hex` field")
        manifest_digest_hex = _normalize_hex_string(
            manifest_literal,
            "por_ingestion.manifest_digest_hex",
            expected_length=64,
        )
        providers_payload = payload.get("providers")
        if not isinstance(providers_payload, list):
            raise TypeError("por ingestion response `providers` must be a list")
        providers: List[SorafsPorIngestionProviderStatus] = []
        for index, entry in enumerate(providers_payload):
            if not isinstance(entry, Mapping):
                raise TypeError(f"por ingestion providers[{index}] must be an object")
            providers.append(SorafsPorIngestionProviderStatus.from_payload(entry))
        return cls(manifest_digest_hex=manifest_digest_hex, providers=providers)


@dataclass(frozen=True)
class ExplorerMetricsSnapshot:
    """Network metrics exposed via `/v1/explorer/metrics`."""

    peers: int
    domains: int
    accounts: int
    assets: int
    transactions_accepted: int
    transactions_rejected: int
    block_height: int
    block_created_at: Optional[str]
    finalized_block_height: int
    average_commit_time_ms: Optional[int]
    average_block_time_ms: Optional[int]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ExplorerMetricsSnapshot":
        if not isinstance(payload, Mapping):
            raise TypeError("explorer metrics payload must be an object")

        def _resolve_int(key: str, label: str) -> int:
            raw = payload.get(key)
            parsed = _coerce_int(raw, label, allow_zero=True)
            return 0 if parsed is None else parsed

        def _resolve_optional_string(key: str, label: str) -> Optional[str]:
            raw = payload.get(key)
            if raw is None:
                return None
            if not isinstance(raw, str):
                raise TypeError(f"{label} must be a string")
            trimmed = raw.strip()
            return trimmed or None

        def _resolve_optional_duration(
            key: str,
            label: str,
        ) -> Optional[int]:
            raw = payload.get(key)
            return _parse_optional_duration_ms_field(raw, label)

        return cls(
            peers=_resolve_int("peers", "explorer_metrics.peers"),
            domains=_resolve_int("domains", "explorer_metrics.domains"),
            accounts=_resolve_int("accounts", "explorer_metrics.accounts"),
            assets=_resolve_int("assets", "explorer_metrics.assets"),
            transactions_accepted=_resolve_int(
                "transactions_accepted",
                "explorer_metrics.transactions_accepted",
            ),
            transactions_rejected=_resolve_int(
                "transactions_rejected",
                "explorer_metrics.transactions_rejected",
            ),
            block_height=_resolve_int(
                "block",
                "explorer_metrics.block",
            ),
            block_created_at=_resolve_optional_string(
                "block_created_at",
                "explorer_metrics.block_created_at",
            ),
            finalized_block_height=_resolve_int(
                "finalized_block",
                "explorer_metrics.finalized_block",
            ),
            average_commit_time_ms=_resolve_optional_duration(
                "avg_commit_time",
                "explorer_metrics.avg_commit_time",
            ),
            average_block_time_ms=_resolve_optional_duration(
                "avg_block_time",
                "explorer_metrics.avg_block_time",
            ),
        )


@dataclass(frozen=True)
class ExplorerAccountQrSnapshot:
    """Account QR metadata exposed via `/v1/explorer/accounts/{account_id}/qr`."""

    canonical_id: str
    literal: str
    network_prefix: int
    error_correction: str
    modules: int
    qr_version: int
    svg: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ExplorerAccountQrSnapshot":
        if not isinstance(payload, Mapping):
            raise TypeError("explorer account qr payload must be an object")

        def _require_string(key: str, label: str) -> str:
            raw = payload.get(key)
            if not isinstance(raw, str) or not raw.strip():
                raise TypeError(f"{label} must be a non-empty string")
            return raw.strip()

        def _require_positive_int(key: str, label: str) -> int:
            value = _coerce_int(payload.get(key), label, allow_zero=False)
            if value is None:
                raise TypeError(f"{label} must be provided")
            return value

        canonical_id = _require_string(
            "canonical_id",
            "explorer_account_qr.canonical_id",
        )
        literal = _require_string("literal", "explorer_account_qr.literal")
        error_correction = _require_string(
            "error_correction",
            "explorer_account_qr.error_correction",
        )
        svg = _require_string("svg", "explorer_account_qr.svg")

        network_prefix = _require_positive_int(
            "network_prefix",
            "explorer_account_qr.network_prefix",
        )
        modules = _require_positive_int("modules", "explorer_account_qr.modules")
        qr_version = _require_positive_int(
            "qr_version",
            "explorer_account_qr.qr_version",
        )

        return cls(
            canonical_id=canonical_id,
            literal=literal,
            network_prefix=network_prefix,
            error_correction=error_correction,
            modules=modules,
            qr_version=qr_version,
            svg=svg,
        )


@dataclass(frozen=True)
class ExplorerRwaRecord:
    """Explorer RWA lot projection returned by `/v1/explorer/rwas`."""

    id: str
    owned_by: str
    quantity: str
    held_quantity: str
    primary_reference: str
    status: Optional[str]
    is_frozen: bool
    metadata: Dict[str, Any]
    raw: Dict[str, Any]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ExplorerRwaRecord":
        if not isinstance(payload, Mapping):
            raise TypeError("explorer RWA record must be an object")

        def _require_string(key: str, label: str) -> str:
            raw = payload.get(key)
            if not isinstance(raw, str) or not raw.strip():
                raise TypeError(f"{label} must be a non-empty string")
            return raw.strip()

        identifier = _require_string("id", "explorer_rwa.id")
        owned_by = _require_string("owned_by", "explorer_rwa.owned_by")
        quantity = _canonical_quantity_text(
            payload.get("quantity"),
            "explorer_rwa.quantity",
        )
        held_quantity = _canonical_quantity_text(
            payload.get("held_quantity"),
            "explorer_rwa.held_quantity",
        )
        primary_reference = _require_string(
            "primary_reference",
            "explorer_rwa.primary_reference",
        )

        is_frozen = payload.get("is_frozen")
        if not isinstance(is_frozen, bool):
            raise TypeError("explorer_rwa.is_frozen must be a boolean")

        status_raw = payload.get("status")
        if status_raw is None:
            status = None
        elif isinstance(status_raw, str) and status_raw.strip():
            status = status_raw.strip()
        else:
            raise TypeError("explorer_rwa.status must be a string when present")

        metadata_payload = payload.get("metadata", {})
        if metadata_payload is None:
            metadata: Dict[str, Any] = {}
        elif isinstance(metadata_payload, Mapping):
            metadata = dict(metadata_payload)
        else:
            raise TypeError("explorer_rwa.metadata must be an object when present")

        return cls(
            id=identifier,
            owned_by=owned_by,
            quantity=quantity,
            held_quantity=held_quantity,
            primary_reference=primary_reference,
            status=status,
            is_frozen=is_frozen,
            metadata=metadata,
            raw=dict(payload),
        )


@dataclass(frozen=True)
class IsoStatusHistoryRecord:
    """One immutable transition retained in an ISO schema-V3 record."""

    status: str
    pacs002_code: str
    updated_at_ms: Optional[int]
    detail: Optional[str]
    reason_code: Optional[str]

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
        *,
        context: str,
    ) -> "IsoStatusHistoryRecord":
        if not isinstance(payload, Mapping):
            raise TypeError(f"{context} must be a JSON object")
        status = _normalize_iso_status(payload.get("status"), f"{context}.status")
        pacs002_code = _normalize_pacs002_code(
            payload.get("pacs002_code"),
            f"{context}.pacs002_code",
        )
        if pacs002_code is None:
            raise ValueError(f"{context}.pacs002_code must be present")
        updated_at_field = payload.get("updated_at_ms")
        updated_at_ms = (
            None
            if updated_at_field is None
            else _normalize_positive_int(
                updated_at_field,
                f"{context}.updated_at_ms",
                allow_zero=True,
            )
        )
        return cls(
            status=status,
            pacs002_code=pacs002_code,
            updated_at_ms=updated_at_ms,
            detail=_normalize_iso_optional_string(
                payload.get("detail"),
                f"{context}.detail",
                allow_empty=True,
            ),
            reason_code=_normalize_iso_optional_string(
                payload.get("reason_code"),
                f"{context}.reason_code",
            ),
        )


@dataclass(frozen=True)
class IsoSubmissionRecord:
    """Normalized ISO record with immutable V3 replay and policy provenance.

    Torii returns the record only to its original parties or to a separately
    configured read-only ISO audit administrator.
    """

    message_id: str
    status: str
    pacs002_code: Optional[str]
    transaction_hash: Optional[str]
    profile_id: Optional[str]
    message_type: Optional[str]
    business_service: Optional[str]
    business_message_id: Optional[str]
    uetr: Optional[str]
    payload_hash: Optional[str]
    reference_snapshot_id: Optional[str]
    embedded_signature_detected: bool
    originator_participant_id: Optional[str]
    counterparty_participant_id: Optional[str]
    admitting_participant_id: Optional[str]
    admitting_operator_key: Optional[str]
    pinned_profile_id: Optional[str]
    pinned_signature_policy: Optional[str]
    status_history: Tuple[IsoStatusHistoryRecord, ...]
    hold_reason_code: Optional[str]
    change_reason_codes: Tuple[str, ...]
    rejection_reason_code: Optional[str]
    ledger_id: Optional[str]
    source_account_id: Optional[str]
    source_account_address: Optional[str]
    target_account_id: Optional[str]
    target_account_address: Optional[str]
    asset_definition_id: Optional[str]
    asset_id: Optional[str]
    settlement_amount: Optional[str]
    settlement_currency: Optional[str]
    settlement_date: Optional[str]
    settlement_quantity: Optional[str]
    settlement_movement_type: Optional[str]
    settlement_payment_type: Optional[str]
    security_instrument_id: Optional[str]
    collateral_obligation_id: Optional[str]
    collateral_original_amount: Optional[str]
    collateral_original_currency: Optional[str]
    collateral_original_instrument_id: Optional[str]
    collateral_substitute_amount: Optional[str]
    collateral_substitute_currency: Optional[str]
    collateral_substitute_instrument_id: Optional[str]
    collateral_effective_date: Optional[str]
    collateral_substitution_type: Optional[str]
    collateral_haircut: Optional[str]
    collateral_reason_code: Optional[str]
    plan_execution_order: Optional[str]
    plan_atomicity: Optional[str]
    detail: Optional[str]
    updated_at_ms: Optional[int]

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
        *,
        context: str,
    ) -> "IsoSubmissionRecord":
        if not isinstance(payload, Mapping):
            raise TypeError(f"{context} must be a JSON object")
        record = dict(payload)
        message_id = _require_non_empty_string(record.get("message_id"), f"{context}.message_id")
        status = _normalize_iso_status(record.get("status"), f"{context}.status")
        pacs002_code = _normalize_pacs002_code(
            record.get("pacs002_code"), f"{context}.pacs002_code"
        )
        transaction_hash = _normalize_iso_optional_string(
            record.get("transaction_hash"),
            f"{context}.transaction_hash",
        )
        profile_id = _normalize_iso_optional_string(
            record.get("profile_id"),
            f"{context}.profile_id",
        )
        message_type = _normalize_iso_optional_string(
            record.get("message_type"),
            f"{context}.message_type",
        )
        business_service = _normalize_iso_optional_string(
            record.get("business_service"),
            f"{context}.business_service",
        )
        business_message_id = _normalize_iso_optional_string(
            record.get("business_message_id"),
            f"{context}.business_message_id",
        )
        uetr = _normalize_iso_optional_string(record.get("uetr"), f"{context}.uetr")
        payload_hash = _normalize_iso_optional_string(
            record.get("payload_hash"),
            f"{context}.payload_hash",
        )
        reference_snapshot_id = _normalize_iso_optional_string(
            record.get("reference_snapshot_id"),
            f"{context}.reference_snapshot_id",
        )
        embedded_signature_detected = record.get("embedded_signature_detected", False)
        if not isinstance(embedded_signature_detected, bool):
            raise TypeError(f"{context}.embedded_signature_detected must be a boolean")
        originator_participant_id = _normalize_iso_optional_string(
            record.get("originator_participant_id"),
            f"{context}.originator_participant_id",
        )
        counterparty_participant_id = _normalize_iso_optional_string(
            record.get("counterparty_participant_id"),
            f"{context}.counterparty_participant_id",
        )
        admitting_participant_id = _normalize_iso_optional_string(
            record.get("admitting_participant_id"),
            f"{context}.admitting_participant_id",
        )
        admitting_operator_key = _normalize_iso_optional_string(
            record.get("admitting_operator_key"),
            f"{context}.admitting_operator_key",
        )
        pinned_profile_id = _normalize_iso_optional_string(
            record.get("pinned_profile_id"),
            f"{context}.pinned_profile_id",
        )
        pinned_signature_policy = _normalize_iso_optional_string(
            record.get("pinned_signature_policy"),
            f"{context}.pinned_signature_policy",
        )
        status_history_field = record.get("status_history")
        if status_history_field is None:
            status_history: Tuple[IsoStatusHistoryRecord, ...] = ()
        elif isinstance(status_history_field, list):
            status_history = tuple(
                IsoStatusHistoryRecord.from_payload(
                    entry,
                    context=f"{context}.status_history[{index}]",
                )
                for index, entry in enumerate(status_history_field)
            )
        else:
            raise TypeError(f"{context}.status_history must be an array")
        hold_reason_code = _normalize_iso_optional_string(
            record.get("hold_reason_code"),
            f"{context}.hold_reason_code",
        )
        change_reason_codes = _normalize_iso_string_array(
            record.get("change_reason_codes"),
            f"{context}.change_reason_codes",
        )
        rejection_reason_code = _normalize_iso_optional_string(
            record.get("rejection_reason_code"),
            f"{context}.rejection_reason_code",
        )
        ledger_id = _normalize_iso_optional_string(record.get("ledger_id"), f"{context}.ledger_id")
        source_account_id = _normalize_iso_optional_string(
            record.get("source_account_id"),
            f"{context}.source_account_id",
        )
        source_account_address = _normalize_iso_optional_string(
            record.get("source_account_address"),
            f"{context}.source_account_address",
        )
        target_account_id = _normalize_iso_optional_string(
            record.get("target_account_id"),
            f"{context}.target_account_id",
        )
        target_account_address = _normalize_iso_optional_string(
            record.get("target_account_address"),
            f"{context}.target_account_address",
        )
        asset_definition_id = _normalize_iso_optional_string(
            record.get("asset_definition_id"),
            f"{context}.asset_definition_id",
        )
        asset_id = _normalize_iso_optional_string(record.get("asset_id"), f"{context}.asset_id")
        v3_status_fields = {
            field_name: _normalize_iso_optional_string(
                record.get(field_name),
                f"{context}.{field_name}",
            )
            for field_name in (
                "settlement_amount",
                "settlement_currency",
                "settlement_date",
                "settlement_quantity",
                "settlement_movement_type",
                "settlement_payment_type",
                "security_instrument_id",
                "collateral_obligation_id",
                "collateral_original_amount",
                "collateral_original_currency",
                "collateral_original_instrument_id",
                "collateral_substitute_amount",
                "collateral_substitute_currency",
                "collateral_substitute_instrument_id",
                "collateral_effective_date",
                "collateral_substitution_type",
                "collateral_haircut",
                "collateral_reason_code",
                "plan_execution_order",
                "plan_atomicity",
            )
        }
        detail = _normalize_iso_optional_string(
            record.get("detail"),
            f"{context}.detail",
            allow_empty=True,
        )
        updated_at_field = record.get("updated_at_ms")
        if updated_at_field is None:
            updated_at_ms = None
        else:
            updated_at_ms = _normalize_positive_int(
                updated_at_field,
                f"{context}.updated_at_ms",
                allow_zero=True,
            )
        return cls(
            message_id=message_id,
            status=status,
            pacs002_code=pacs002_code,
            transaction_hash=transaction_hash,
            profile_id=profile_id,
            message_type=message_type,
            business_service=business_service,
            business_message_id=business_message_id,
            uetr=uetr,
            payload_hash=payload_hash,
            reference_snapshot_id=reference_snapshot_id,
            embedded_signature_detected=embedded_signature_detected,
            originator_participant_id=originator_participant_id,
            counterparty_participant_id=counterparty_participant_id,
            admitting_participant_id=admitting_participant_id,
            admitting_operator_key=admitting_operator_key,
            pinned_profile_id=pinned_profile_id,
            pinned_signature_policy=pinned_signature_policy,
            status_history=status_history,
            hold_reason_code=hold_reason_code,
            change_reason_codes=change_reason_codes,
            rejection_reason_code=rejection_reason_code,
            ledger_id=ledger_id,
            source_account_id=source_account_id,
            source_account_address=source_account_address,
            target_account_id=target_account_id,
            target_account_address=target_account_address,
            asset_definition_id=asset_definition_id,
            asset_id=asset_id,
            **v3_status_fields,
            detail=detail,
            updated_at_ms=updated_at_ms,
        )


class IsoMessageTimeoutError(RuntimeError):
    """Raised when ISO bridge messages fail to reach a terminal state."""

    def __init__(
        self,
        message_id: str,
        attempts: int,
        last_status: Optional[IsoSubmissionRecord],
    ) -> None:
        detail = f"Timed out waiting for ISO message {message_id} after {attempts} attempts"
        if last_status is not None:
            detail = f"{detail} (last status: {last_status.status})"
        super().__init__(detail)
        self.message_id = message_id
        self.attempts = attempts
        self.last_status = last_status


_KAIGI_HEALTH_STATUSES = frozenset({"healthy", "degraded", "unavailable"})
_KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS = 500
_KAIGI_U64_MAX = (1 << 64) - 1
_KAIGI_RELAY_SUMMARY_REQUIRED_FIELDS = frozenset(
    {"relay_id", "domain", "bandwidth_class", "hpke_fingerprint_hex"}
)
_KAIGI_RELAY_SUMMARY_OPTIONAL_FIELDS = frozenset({"status", "reported_at_ms"})


def _require_kaigi_fields(
    payload: Mapping[str, Any],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    context: str,
) -> None:
    """Require the exact first-release field set advertised by Torii."""

    missing = required.difference(payload)
    if missing:
        field = min(missing)
        raise ValueError(f"{context}.{field} is required")
    unexpected = set(payload).difference(required | optional)
    if unexpected:
        field = min(unexpected)
        raise ValueError(f"{context}.{field} is not part of the first-release contract")


def _require_kaigi_exact_string(value: Any, context: str) -> str:
    """Parse one non-empty response string without normalizing wire bytes."""

    return _require_exact_non_empty_string(value, context)


def _require_kaigi_canonical_account_id(value: Any, context: str) -> str:
    """Require a canonical I105 account literal emitted by Torii."""

    literal = _require_kaigi_exact_string(value, context)
    if "@" in literal:
        raise ValueError(f"{context} must be a canonical I105 account id")
    try:
        inspect_i105_network_prefix(literal)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{context} must be a canonical I105 account id") from exc
    return literal


def _require_kaigi_lower_hex_32(value: Any, context: str) -> str:
    """Require the exact lowercase 32-byte fingerprint spelling from Torii."""

    literal = _require_kaigi_exact_string(value, context)
    if re.fullmatch(r"[0-9a-f]{64}", literal) is None:
        raise ValueError(f"{context} must contain exactly 64 lowercase hex characters")
    if bytes.fromhex(literal)[-1] & 1 != 1:
        raise ValueError(f"{context} must set the Iroha Hash marker bit")
    return literal


def _decode_kaigi_exact_base64(value: Any, context: str) -> tuple[str, bytes]:
    """Decode one non-empty canonical standard-base64 response field."""

    literal = _require_kaigi_exact_string(value, context)
    if any(character.isspace() for character in literal):
        raise ValueError(f"{context} must be exact standard-base64")
    try:
        decoded = base64.b64decode(literal, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{context} must be exact standard-base64") from exc
    if not decoded or base64.b64encode(decoded).decode("ascii") != literal:
        raise ValueError(f"{context} must be exact non-empty standard-base64")
    return literal, decoded


def _require_kaigi_u64(value: Any, context: str) -> int:
    """Parse an exact unsigned Kaigi JSON integer without coercion."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{context} must be an unsigned integer")
    if not 0 <= value <= _KAIGI_U64_MAX:
        raise ValueError(f"{context} must fit in a u64")
    return value


@dataclass(frozen=True)
class KaigiRelaySummary:
    """Summary entry returned by `/v1/kaigi/relays`."""

    relay_id: str
    domain: str
    bandwidth_class: int
    hpke_fingerprint_hex: str
    status: Optional[str]
    reported_at_ms: Optional[int]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "KaigiRelaySummary":
        if not isinstance(payload, Mapping):
            raise TypeError("kaigi relay summary payload must be an object")
        _require_kaigi_fields(
            payload,
            required=_KAIGI_RELAY_SUMMARY_REQUIRED_FIELDS,
            optional=_KAIGI_RELAY_SUMMARY_OPTIONAL_FIELDS,
            context="kaigi_relay_summary",
        )
        relay_id = _require_kaigi_canonical_account_id(
            payload["relay_id"],
            "kaigi_relay_summary.relay_id",
        )
        domain = _require_kaigi_exact_string(
            payload["domain"],
            "kaigi_relay_summary.domain",
        )
        bandwidth_literal = payload["bandwidth_class"]
        if isinstance(bandwidth_literal, bool) or not isinstance(bandwidth_literal, int):
            raise TypeError("kaigi_relay_summary.bandwidth_class must be an integer")
        if not 1 <= bandwidth_literal <= 0xFF:
            raise ValueError("kaigi_relay_summary.bandwidth_class must be within 1..=255")
        bandwidth_value = bandwidth_literal
        fingerprint = _require_kaigi_lower_hex_32(
            payload["hpke_fingerprint_hex"],
            "kaigi_relay_summary.hpke_fingerprint_hex",
        )
        has_status = "status" in payload
        has_reported_at = "reported_at_ms" in payload
        if has_status != has_reported_at:
            raise ValueError(
                "kaigi_relay_summary.status and reported_at_ms must be present together"
            )
        status: Optional[str] = None
        reported_at_ms: Optional[int] = None
        if has_status:
            status_value = _require_kaigi_exact_string(
                payload["status"],
                "kaigi_relay_summary.status",
            )
            if status_value not in _KAIGI_HEALTH_STATUSES:
                raise ValueError(
                    f"kaigi_relay_summary.status must be one of {sorted(_KAIGI_HEALTH_STATUSES)}"
                )
            status = status_value
            reported_at_ms = _require_kaigi_u64(
                payload["reported_at_ms"],
                "kaigi_relay_summary.reported_at_ms",
            )

        return cls(
            relay_id=relay_id,
            domain=domain,
            bandwidth_class=bandwidth_value,
            hpke_fingerprint_hex=fingerprint,
            status=status,
            reported_at_ms=reported_at_ms,
        )


@dataclass(frozen=True)
class KaigiRelaySummaryList:
    """Payload envelope returned by `/v1/kaigi/relays`."""

    items: List[KaigiRelaySummary]
    total: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "KaigiRelaySummaryList":
        if not isinstance(payload, Mapping):
            raise TypeError("kaigi relay summary response must be an object")
        _require_kaigi_fields(
            payload,
            required=frozenset({"items", "total"}),
            context="kaigi_relay_summary",
        )
        raw_items = payload["items"]
        if not isinstance(raw_items, list):
            raise TypeError("kaigi relay summary response `items` must be an array")
        if len(raw_items) > _KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS:
            raise ValueError(
                "kaigi relay summary response `items` exceeds the 500-entry limit"
            )
        items = []
        for index, entry in enumerate(raw_items):
            if not isinstance(entry, Mapping):
                raise TypeError(
                    f"kaigi relay summary response items[{index}] must be an object"
                )
            items.append(KaigiRelaySummary.from_payload(entry))
        total_value = _require_kaigi_u64(
            payload["total"],
            "kaigi_relay_summary.total",
        )
        if total_value != len(items):
            raise ValueError("kaigi_relay_summary.total must equal the number of items")
        relay_ids = [item.relay_id for item in items]
        if len(set(relay_ids)) != len(relay_ids):
            raise ValueError("kaigi_relay_summary.items contains duplicate relay ids")
        return cls(items=items, total=total_value)


@dataclass(frozen=True)
class KaigiRelayReportedCall:
    """Call metadata referenced by `/v1/kaigi/relays/{relay_id}`."""

    domain_id: str
    call_name: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "KaigiRelayReportedCall":
        if not isinstance(payload, Mapping):
            raise TypeError("kaigi relay call payload must be an object")
        _require_kaigi_fields(
            payload,
            required=frozenset({"domain_id", "call_name"}),
            context="kaigi_relay_reported_call",
        )
        return cls(
            domain_id=_require_kaigi_exact_string(
                payload["domain_id"],
                "kaigi_relay_reported_call.domain_id",
            ),
            call_name=_require_kaigi_exact_string(
                payload["call_name"],
                "kaigi_relay_reported_call.call_name",
            ),
        )


@dataclass(frozen=True)
class KaigiRelayDomainMetrics:
    """Per-domain metrics included in Kaigi relay responses."""

    domain: str
    registrations_total: int
    manifest_updates_total: int
    failovers_total: int
    health_reports_total: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "KaigiRelayDomainMetrics":
        if not isinstance(payload, Mapping):
            raise TypeError("kaigi relay domain metrics payload must be an object")
        _require_kaigi_fields(
            payload,
            required=frozenset(
                {
                    "domain",
                    "registrations_total",
                    "manifest_updates_total",
                    "failovers_total",
                    "health_reports_total",
                }
            ),
            context="kaigi_relay_domain_metrics",
        )

        def _resolve_counter(name: str) -> int:
            if name not in payload:
                raise ValueError(f"kaigi_relay_domain_metrics.{name} is required")
            return _require_kaigi_u64(
                payload[name],
                f"kaigi_relay_domain_metrics.{name}",
            )

        return cls(
            domain=_require_kaigi_exact_string(
                payload["domain"],
                "kaigi_relay_domain_metrics.domain",
            ),
            registrations_total=_resolve_counter("registrations_total"),
            manifest_updates_total=_resolve_counter("manifest_updates_total"),
            failovers_total=_resolve_counter("failovers_total"),
            health_reports_total=_resolve_counter("health_reports_total"),
        )


@dataclass(frozen=True)
class KaigiRelayDetail:
    """Detailed relay metadata returned by `/v1/kaigi/relays/{relay_id}`."""

    relay: KaigiRelaySummary
    hpke_public_key_b64: str
    reported_call: Optional[KaigiRelayReportedCall]
    reported_by: Optional[str]
    notes: Optional[str]
    metrics: Optional[KaigiRelayDomainMetrics]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "KaigiRelayDetail":
        if not isinstance(payload, Mapping):
            raise TypeError("kaigi relay detail payload must be an object")
        _require_kaigi_fields(
            payload,
            required=frozenset({"relay", "hpke_public_key_b64"}),
            optional=frozenset({"reported_call", "reported_by", "notes", "metrics"}),
            context="kaigi_relay_detail",
        )
        relay_payload = payload.get("relay")
        if not isinstance(relay_payload, Mapping):
            raise TypeError("kaigi relay detail payload missing object `relay` field")
        hpke_literal, hpke_bytes = _decode_kaigi_exact_base64(
            payload["hpke_public_key_b64"],
            "kaigi_relay_detail.hpke_public_key_b64",
        )
        reported_call_payload = payload.get("reported_call")
        metrics_payload = payload.get("metrics")
        reported_by_literal = payload.get("reported_by")
        notes_literal = payload.get("notes")

        reported_by: Optional[str] = None
        if "reported_by" in payload:
            reported_by = _require_kaigi_canonical_account_id(
                reported_by_literal,
                "kaigi_relay_detail.reported_by",
            )
        notes: Optional[str] = None
        if "notes" in payload:
            if not isinstance(notes_literal, str):
                raise TypeError("kaigi_relay_detail.notes must be a string")
            notes = notes_literal

        if "reported_call" in payload and not isinstance(reported_call_payload, Mapping):
            raise TypeError("kaigi_relay_detail.reported_call must be an object")
        if "metrics" in payload and not isinstance(metrics_payload, Mapping):
            raise TypeError("kaigi_relay_detail.metrics must be an object")

        relay = KaigiRelaySummary.from_payload(relay_payload)
        from .crypto import hash_blake2b_32

        expected_fingerprint = hash_blake2b_32(hpke_bytes).hex()
        if relay.hpke_fingerprint_hex != expected_fingerprint:
            raise ValueError(
                "kaigi_relay_detail.hpke_public_key_b64 does not match the relay fingerprint"
            )
        has_reported_call = "reported_call" in payload
        has_reported_by = "reported_by" in payload
        if has_reported_call != has_reported_by:
            raise ValueError(
                "kaigi_relay_detail.reported_call and reported_by must be present together"
            )
        has_feedback = relay.status is not None
        if has_feedback != has_reported_call:
            raise ValueError(
                "kaigi_relay_detail feedback fields must agree with the relay health summary"
            )
        if "notes" in payload and not has_feedback:
            raise ValueError("kaigi_relay_detail.notes requires relay health feedback")
        metrics = None
        if "metrics" in payload:
            if not isinstance(metrics_payload, Mapping):
                raise TypeError("kaigi_relay_detail.metrics must be an object")
            metrics = KaigiRelayDomainMetrics.from_payload(metrics_payload)
        if metrics is not None and metrics.domain != relay.domain:
            raise ValueError(
                "kaigi_relay_detail.metrics.domain must match the relay domain"
            )

        reported_call = None
        if "reported_call" in payload:
            if not isinstance(reported_call_payload, Mapping):
                raise TypeError("kaigi_relay_detail.reported_call must be an object")
            reported_call = KaigiRelayReportedCall.from_payload(reported_call_payload)

        return cls(
            relay=relay,
            hpke_public_key_b64=hpke_literal,
            reported_call=reported_call,
            reported_by=reported_by,
            notes=notes,
            metrics=metrics,
        )


@dataclass(frozen=True)
class KaigiRelayHealthSnapshot:
    """Aggregated relay health counters returned by `/v1/kaigi/relays/health`."""

    healthy_total: int
    degraded_total: int
    unavailable_total: int
    reports_total: int
    registrations_total: int
    failovers_total: int
    domains: List[KaigiRelayDomainMetrics]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "KaigiRelayHealthSnapshot":
        if not isinstance(payload, Mapping):
            raise TypeError("kaigi relay health payload must be an object")
        _require_kaigi_fields(
            payload,
            required=frozenset(
                {
                    "healthy_total",
                    "degraded_total",
                    "unavailable_total",
                    "reports_total",
                    "registrations_total",
                    "failovers_total",
                    "domains",
                }
            ),
            context="kaigi_relay_health",
        )
        domains_value = payload["domains"]
        if not isinstance(domains_value, list):
            raise TypeError("kaigi relay health payload `domains` must be an array")
        if len(domains_value) > _KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS:
            raise ValueError(
                "kaigi relay health payload `domains` exceeds the 500-entry limit"
            )
        domains: List[KaigiRelayDomainMetrics] = []
        for index, entry in enumerate(domains_value):
            if not isinstance(entry, Mapping):
                raise TypeError(
                    f"kaigi relay health payload domains[{index}] must be an object"
                )
            domains.append(KaigiRelayDomainMetrics.from_payload(entry))
        domain_ids = [entry.domain for entry in domains]
        if len(set(domain_ids)) != len(domain_ids):
            raise ValueError("kaigi_relay_health.domains contains duplicate domains")
        if any(
            previous >= current
            for previous, current in zip(domain_ids, domain_ids[1:], strict=False)
        ):
            raise ValueError("kaigi_relay_health.domains must be strictly sorted by domain")

        def _resolve_counter(name: str) -> int:
            if name not in payload:
                raise ValueError(f"kaigi_relay_health.{name} is required")
            return _require_kaigi_u64(payload[name], f"kaigi_relay_health.{name}")

        snapshot = cls(
            healthy_total=_resolve_counter("healthy_total"),
            degraded_total=_resolve_counter("degraded_total"),
            unavailable_total=_resolve_counter("unavailable_total"),
            reports_total=_resolve_counter("reports_total"),
            registrations_total=_resolve_counter("registrations_total"),
            failovers_total=_resolve_counter("failovers_total"),
            domains=domains,
        )
        current_status_total = (
            snapshot.healthy_total
            + snapshot.degraded_total
            + snapshot.unavailable_total
        )
        if current_status_total > _KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS:
            raise ValueError(
                "kaigi_relay_health current status totals exceed the relay diagnostic cap"
            )
        aggregate_checks = (
            (
                "reports_total",
                snapshot.reports_total,
                sum(entry.health_reports_total for entry in domains),
            ),
            (
                "registrations_total",
                snapshot.registrations_total,
                sum(entry.registrations_total for entry in domains),
            ),
            (
                "failovers_total",
                snapshot.failovers_total,
                sum(entry.failovers_total for entry in domains),
            ),
        )
        for field_name, actual, summed in aggregate_checks:
            expected = min(summed, _KAIGI_U64_MAX)
            if actual != expected:
                raise ValueError(
                    f"kaigi_relay_health.{field_name} must equal the saturated domain total"
                )
        return snapshot


def _configuration_snapshot_to_dict(snapshot: ConfigurationSnapshot) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "public_key": snapshot.public_key_hex,
        "logger": snapshot.logger.to_payload(),
        "network": {
            "block_gossip_size": snapshot.network.block_gossip_size,
            "block_gossip_period_ms": snapshot.network.block_gossip_period_ms,
            "transaction_gossip_size": snapshot.network.transaction_gossip_size,
            "transaction_gossip_period_ms": snapshot.network.transaction_gossip_period_ms,
        },
    }
    if snapshot.queue is not None:
        result["queue"] = {"capacity": snapshot.queue.capacity}
    if snapshot.confidential_gas is not None:
        result["confidential_gas"] = snapshot.confidential_gas.to_payload()
    if snapshot.transport is not None:
        transport_payload: Dict[str, Any] = {}
        if snapshot.transport.norito_rpc is not None:
            norito_rpc = snapshot.transport.norito_rpc
            transport_payload["norito_rpc"] = {
                "enabled": norito_rpc.enabled,
                "stage": norito_rpc.stage,
                "require_mtls": norito_rpc.require_mtls,
                "canary_allowlist_size": norito_rpc.canary_allowlist_size,
            }
        if transport_payload:
            result["transport"] = transport_payload
    return result


@dataclass(frozen=True)
class GovernanceReferendumResult:
    """Wrapper for `/v1/gov/referenda/{id}` responses."""

    found: bool
    referendum: Optional[Dict[str, Any]]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "GovernanceReferendumResult":
        if not isinstance(payload, Mapping):
            raise TypeError("referendum payload must be a mapping")
        found = payload.get("found")
        if not isinstance(found, bool):
            raise TypeError("referendum payload missing bool `found` field")
        referendum = payload.get("referendum")
        if referendum is not None and not isinstance(referendum, Mapping):
            raise TypeError("referendum payload `referendum` must be an object when present")
        copied = dict(referendum) if isinstance(referendum, Mapping) else None
        return cls(found=found, referendum=copied)


@dataclass(frozen=True)
class GovernanceContractEmergencyHoldRecord:
    """Retained bounded Parliament emergency-hold projection."""

    incident_digest_hex: str
    proposal_content_id_hex: str
    governance_attempt_id_hex: str
    reason: str
    imposed_at_height: int
    expires_at_height: int

    @classmethod
    def from_payload(
        cls, payload: Mapping[str, Any], *, context: str
    ) -> "GovernanceContractEmergencyHoldRecord":
        expected = {
            "incident_digest_hex",
            "proposal_content_id_hex",
            "governance_attempt_id_hex",
            "reason",
            "imposed_at_height",
            "expires_at_height",
        }
        if set(payload) != expected:
            raise TypeError(f"{context} must contain exactly the first-release hold fields")

        def hash_field(name: str) -> str:
            value = payload.get(name)
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise TypeError(f"{context}.{name} must be exact lowercase 32-byte hex")
            return value

        imposed = _require_u64(
            payload.get("imposed_at_height"),
            f"{context}.imposed_at_height",
        )
        expires = _require_u64(
            payload.get("expires_at_height"),
            f"{context}.expires_at_height",
        )
        if imposed == 0:
            raise ValueError(f"{context}.imposed_at_height must be positive")
        if expires <= imposed:
            raise ValueError(f"{context}.expires_at_height must follow imposed_at_height")
        return cls(
            incident_digest_hex=hash_field("incident_digest_hex"),
            proposal_content_id_hex=hash_field("proposal_content_id_hex"),
            governance_attempt_id_hex=hash_field("governance_attempt_id_hex"),
            reason=_require_exact_non_empty_string(payload.get("reason"), f"{context}.reason"),
            imposed_at_height=imposed,
            expires_at_height=expires,
        )


@dataclass(frozen=True)
class GovernanceContractLifecycleRecord:
    """Complete retained ownership and lifecycle projection for one contract."""

    version: int
    origin: str
    origin_account: str
    origin_proposal_content_id_hex: Optional[str]
    origin_governance_attempt_id_hex: Optional[str]
    owner: str
    pending_owner: Optional[str]
    parliament_delegated: bool
    active_code_hash_hex: Optional[str]
    revision: int
    emergency_hold: Optional[GovernanceContractEmergencyHoldRecord]

    @classmethod
    def from_payload(
        cls, payload: Mapping[str, Any], *, context: str
    ) -> "GovernanceContractLifecycleRecord":
        expected = {
            "version",
            "origin",
            "origin_account",
            "origin_proposal_content_id_hex",
            "origin_governance_attempt_id_hex",
            "owner",
            "pending_owner",
            "parliament_delegated",
            "active_code_hash_hex",
            "revision",
            "emergency_hold",
        }
        if set(payload) != expected:
            raise TypeError(f"{context} must contain exactly the first-release lifecycle fields")
        version = _require_u64(payload.get("version"), f"{context}.version")
        if version != 1:
            raise ValueError(f"{context}.version must be exactly 1")

        def optional_hash(name: str) -> Optional[str]:
            value = payload.get(name)
            if value is None:
                return None
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise TypeError(f"{context}.{name} must be exact lowercase 32-byte hex or null")
            return value

        origin = _require_exact_non_empty_string(payload.get("origin"), f"{context}.origin")
        if origin not in {"direct", "parliament"}:
            raise ValueError(f"{context}.origin must be direct or parliament")
        revision = _require_u64(payload.get("revision"), f"{context}.revision")
        if revision == 0:
            raise ValueError(f"{context}.revision must be positive")
        parliament_delegated = payload.get("parliament_delegated")
        if not isinstance(parliament_delegated, bool):
            raise TypeError(f"{context}.parliament_delegated must be a boolean")
        pending_owner = payload.get("pending_owner")
        if pending_owner is not None:
            pending_owner = _require_exact_non_empty_string(
                pending_owner, f"{context}.pending_owner"
            )
        hold_value = payload.get("emergency_hold")
        if hold_value is not None and not isinstance(hold_value, Mapping):
            raise TypeError(f"{context}.emergency_hold must be an object or null")
        origin_proposal_content_id_hex = optional_hash("origin_proposal_content_id_hex")
        origin_governance_attempt_id_hex = optional_hash(
            "origin_governance_attempt_id_hex"
        )
        if origin == "direct" and (
            origin_proposal_content_id_hex is not None
            or origin_governance_attempt_id_hex is not None
        ):
            raise ValueError(f"{context} direct origin must not carry Parliament identifiers")
        if origin == "parliament" and (
            origin_proposal_content_id_hex is None
            or origin_governance_attempt_id_hex is None
        ):
            raise ValueError(
                f"{context} Parliament origin requires both governance identifiers"
            )

        def owner(field: str) -> str:
            value = payload.get(field)
            if value == "parliament":
                return "parliament"
            return _normalize_exact_any_i105_account_id(value, f"{context}.{field}")

        return cls(
            version=version,
            origin=origin,
            origin_account=_normalize_exact_any_i105_account_id(
                payload.get("origin_account"), f"{context}.origin_account"
            ),
            origin_proposal_content_id_hex=origin_proposal_content_id_hex,
            origin_governance_attempt_id_hex=origin_governance_attempt_id_hex,
            owner=owner("owner"),
            pending_owner=None if pending_owner is None else owner("pending_owner"),
            parliament_delegated=parliament_delegated,
            active_code_hash_hex=optional_hash("active_code_hash_hex"),
            revision=revision,
            emergency_hold=(
                GovernanceContractEmergencyHoldRecord.from_payload(
                    hold_value, context=f"{context}.emergency_hold"
                )
                if hold_value is not None
                else None
            ),
        )


@dataclass(frozen=True)
class GovernanceContractRecord:
    """Governance binding returned by `GET /v1/gov/contracts/{contract_address}`."""

    found: bool
    contract_address: str
    contract_subject_account: Optional[str]
    dataspace: Optional[str]
    active: Optional[bool]
    lifecycle: Optional[GovernanceContractLifecycleRecord]
    emergency_hold_active: Optional[bool]
    code_hash_hex: Optional[str]
    abi_hash_hex: Optional[str]
    public_entrypoints: Optional[Tuple[str, ...]]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "GovernanceContractRecord":
        if not isinstance(payload, Mapping):
            raise TypeError("governance contract payload must be an object")
        allowed = {
            "found",
            "contract_address",
            "contract_subject_account",
            "dataspace",
            "active",
            "lifecycle",
            "emergency_hold_active",
            "code_hash_hex",
            "abi_hash_hex",
            "public_entrypoints",
        }
        if not {"found", "contract_address"}.issubset(payload) or set(payload) - allowed:
            raise TypeError("governance contract payload has an incompatible first-release shape")
        found = payload.get("found")
        if not isinstance(found, bool):
            raise TypeError("governance contract payload `found` must be a boolean")
        contract_address = payload.get("contract_address")
        if not isinstance(contract_address, str):
            raise TypeError("governance contract payload missing string `contract_address` field")
        active = payload.get("active")
        if found and not isinstance(active, bool):
            raise TypeError("governance contract payload `active` must be a boolean or null")
        expected_fields = (
            allowed
            if active is True
            else {
                "found",
                "contract_address",
                "contract_subject_account",
                "dataspace",
                "active",
                "lifecycle",
                "emergency_hold_active",
            }
            if found
            else {"found", "contract_address", "dataspace"}
        )
        if set(payload) != expected_fields:
            raise TypeError("governance contract payload has an incompatible first-release shape")
        contract_address = _require_exact_non_empty_string(
            contract_address, "governance contract payload.contract_address"
        )
        dataspace = _require_exact_non_empty_string(
            payload.get("dataspace"), "governance contract payload.dataspace"
        )
        subject = (
            _normalize_exact_any_i105_account_id(
                payload.get("contract_subject_account"),
                "governance contract payload.contract_subject_account",
            )
            if found
            else None
        )
        hold_active = payload.get("emergency_hold_active")
        if found and not isinstance(hold_active, bool):
            raise TypeError("governance contract payload hold state must be a boolean or null")
        lifecycle_value = payload.get("lifecycle")
        if lifecycle_value is not None and not isinstance(lifecycle_value, Mapping):
            raise TypeError("governance contract payload `lifecycle` must be an object or null")

        def optional_hash(name: str) -> Optional[str]:
            value = payload.get(name)
            if value is None:
                return None
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise TypeError(f"governance contract payload `{name}` must be exact lowercase 32-byte hex")
            return value

        lifecycle = (
            GovernanceContractLifecycleRecord.from_payload(
                lifecycle_value, context="governance contract payload.lifecycle"
            )
            if lifecycle_value is not None
            else None
        )
        code_hash_hex = optional_hash("code_hash_hex")
        abi_hash_hex = optional_hash("abi_hash_hex")
        entrypoints_value = payload.get("public_entrypoints")
        if entrypoints_value is None:
            public_entrypoints = None
        elif isinstance(entrypoints_value, list):
            public_entrypoints = tuple(
                _require_exact_non_empty_string(
                    entrypoint, f"governance contract payload.public_entrypoints[{index}]"
                )
                for index, entrypoint in enumerate(entrypoints_value)
            )
            if not public_entrypoints:
                raise TypeError("governance contract payload.public_entrypoints must not be empty")
            for index, entrypoint in enumerate(public_entrypoints):
                if re.fullmatch(r"[a-z][a-z0-9_]{0,127}", entrypoint) is None:
                    raise TypeError(
                        "governance contract payload.public_entrypoints"
                        f"[{index}] must be a canonical public entrypoint name"
                    )
            if public_entrypoints != tuple(sorted(set(public_entrypoints))):
                raise TypeError(
                    "governance contract payload.public_entrypoints must be sorted and unique"
                )
        else:
            raise TypeError("governance contract payload `public_entrypoints` must be an array or null")
        if found:
            if subject is None or dataspace is None or active is None or lifecycle is None or hold_active is None:
                raise TypeError("found governance contract payload must contain lifecycle identity and status")
            if active:
                if code_hash_hex is None or abi_hash_hex is None or public_entrypoints is None:
                    raise TypeError("active governance contract payload must contain artifact fields")
                if lifecycle.active_code_hash_hex != code_hash_hex:
                    raise ValueError("governance lifecycle active code hash must match code_hash_hex")
            elif lifecycle.active_code_hash_hex is not None:
                raise TypeError(
                    "inactive governance lifecycle must not carry an active code hash"
                )
            if hold_active and lifecycle.emergency_hold is None:
                raise TypeError("active emergency-hold state requires a retained hold record")
        return cls(
            found=found,
            contract_address=contract_address,
            contract_subject_account=subject,
            dataspace=dataspace,
            active=active,
            lifecycle=lifecycle,
            emergency_hold_active=hold_active,
            code_hash_hex=code_hash_hex,
            abi_hash_hex=abi_hash_hex,
            public_entrypoints=public_entrypoints,
        )


@dataclass(frozen=True)
class GovernanceLockCustody:
    """Immutable asset custody retained with a governance lock."""

    escrowed: bool
    asset_definition_id: str
    bond_escrow_account: str
    slash_receiver_account: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "GovernanceLockCustody":
        if not isinstance(payload, Mapping):
            raise TypeError("governance lock custody must be an object")
        expected_fields = {
            "escrowed",
            "asset_definition_id",
            "bond_escrow_account",
            "slash_receiver_account",
        }
        if set(payload) != expected_fields:
            raise TypeError(
                "governance lock custody must contain exactly "
                "`escrowed`, `asset_definition_id`, `bond_escrow_account`, and "
                "`slash_receiver_account`"
            )
        escrowed = payload["escrowed"]
        if not isinstance(escrowed, bool):
            raise TypeError("governance lock custody `escrowed` must be bool")
        identifiers: Dict[str, str] = {}
        for field_name in (
            "asset_definition_id",
            "bond_escrow_account",
            "slash_receiver_account",
        ):
            value = payload[field_name]
            if not isinstance(value, str) or not value:
                raise TypeError(
                    f"governance lock custody `{field_name}` must be a non-empty string"
                )
            if value.strip() != value:
                raise TypeError(
                    f"governance lock custody `{field_name}` must not contain "
                    "surrounding whitespace"
                )
            identifiers[field_name] = value
        return cls(
            escrowed=escrowed,
            asset_definition_id=identifiers["asset_definition_id"],
            bond_escrow_account=identifiers["bond_escrow_account"],
            slash_receiver_account=identifiers["slash_receiver_account"],
        )


@dataclass(frozen=True)
class GovernanceLockRecord:
    """Governance lock record stored for a referendum."""

    owner: str
    amount: str
    slashed: str
    expiry_height: int
    direction: int
    duration_blocks: int
    custody: Optional[GovernanceLockCustody]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "GovernanceLockRecord":
        if not isinstance(payload, Mapping):
            raise TypeError("governance lock record must be an object")
        owner = payload.get("owner")
        if not isinstance(owner, str):
            raise TypeError("governance lock record missing string `owner` field")
        amount_raw = payload.get("amount")
        if amount_raw is None:
            raise TypeError("governance lock record missing Quantity `amount` field")
        amount = _canonical_quantity_text(
            amount_raw,
            "governance lock record `amount`",
        )
        slashed = _canonical_quantity_text(
            payload.get("slashed"),
            "governance lock record `slashed`",
        )
        expiry_raw = payload.get("expiry_height")
        if expiry_raw is None:
            raise TypeError("governance lock record missing numeric `expiry_height` field")
        try:
            expiry_height = int(expiry_raw)
        except (TypeError, ValueError) as exc:
            raise TypeError("governance lock record `expiry_height` must be numeric") from exc
        direction_raw = payload.get("direction")
        if direction_raw is None:
            raise TypeError("governance lock record missing numeric `direction` field")
        try:
            direction = int(direction_raw)
        except (TypeError, ValueError) as exc:
            raise TypeError("governance lock record `direction` must be numeric") from exc
        if direction < 0 or direction > 255:
            raise ValueError("governance lock record `direction` must be within 0-255")
        duration_raw = payload.get("duration_blocks", 0)
        try:
            duration_blocks = int(duration_raw)
        except (TypeError, ValueError) as exc:
            raise TypeError("governance lock record `duration_blocks` must be numeric") from exc
        if "custody" not in payload:
            raise TypeError("governance lock record missing nullable `custody` field")
        custody_raw = payload["custody"]
        custody = (
            None
            if custody_raw is None
            else GovernanceLockCustody.from_payload(custody_raw)
        )
        return cls(
            owner=owner,
            amount=amount,
            slashed=slashed,
            expiry_height=expiry_height,
            direction=direction,
            duration_blocks=duration_blocks,
            custody=custody,
        )


@dataclass(frozen=True)
class GovernanceLocksResult:
    """Wrapper for `/v1/gov/locks/{id}` responses."""

    found: bool
    referendum_id: str
    locks: Dict[str, GovernanceLockRecord]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "GovernanceLocksResult":
        if not isinstance(payload, Mapping):
            raise TypeError("locks response must be an object")
        found = payload.get("found")
        if not isinstance(found, bool):
            raise TypeError("locks response missing bool `found` field")
        referendum_id = payload.get("referendum_id")
        if not isinstance(referendum_id, str):
            raise TypeError("locks response missing string `referendum_id` field")
        locks_payload = payload.get("locks")
        parsed: Dict[str, GovernanceLockRecord] = {}
        if locks_payload is not None:
            if not isinstance(locks_payload, Mapping):
                raise TypeError("locks response `locks` must be an object when present")
            for account, record_payload in locks_payload.items():
                if not isinstance(account, str):
                    raise TypeError("locks response keys must be account-id strings")
                if not isinstance(record_payload, Mapping):
                    raise TypeError("locks response values must be objects")
                parsed[account] = GovernanceLockRecord.from_payload(record_payload)
        return cls(found=found, referendum_id=referendum_id, locks=parsed)


@dataclass(frozen=True)
class GovernanceUnlockStats:
    """Aggregate unlock sweep statistics returned by `/v1/gov/unlocks/stats`."""

    height_current: int
    expired_locks_now: int
    referenda_with_expired: int
    last_sweep_height: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "GovernanceUnlockStats":
        if not isinstance(payload, Mapping):
            raise TypeError("unlock stats payload must be an object")

        def _require_int(name: str) -> int:
            value = payload.get(name)
            if value is None:
                raise TypeError(f"unlock stats missing `{name}` field")
            try:
                return int(value)
            except (TypeError, ValueError) as exc:
                raise TypeError(f"unlock stats `{name}` must be numeric") from exc

        height_current = _require_int("height_current")
        expired_locks_now = _require_int("expired_locks_now")
        referenda_with_expired = _require_int("referenda_with_expired")
        last_sweep_height = _require_int("last_sweep_height")
        return cls(
            height_current=height_current,
            expired_locks_now=expired_locks_now,
            referenda_with_expired=referenda_with_expired,
            last_sweep_height=last_sweep_height,
        )


# BEGIN GENERATED: kotodama-v1-validator-policy
_KOTODAMA_RESERVED_IDENTIFIERS = frozenset(
    {
        "as",
        "authorize",
        "break",
        "const",
        "continue",
        "else",
        "enum",
        "error",
        "export",
        "false",
        "fn",
        "for",
        "hajimari",
        "始まり",
        "if",
        "import",
        "in",
        "include",
        "kaizen",
        "改善",
        "kotoage",
        "言挙げ",
        "let",
        "match",
        "module",
        "return",
        "seiyaku",
        "誓約",
        "state",
        "struct",
        "trigger",
        "true",
        "var",
        "view",
        "Amount",
    }
)

_KOTODAMA_RESERVED_DECLARATION_IDENTIFIERS = frozenset(
    {
        "int",
        "decimal",
        "quantity",
        "bool",
        "string",
        "bytes",
        "Json",
        "AccountId",
        "AssetDefinitionId",
        "AssetId",
        "DomainId",
        "Name",
        "NftId",
        "DataSpaceId",
        "Option",
        "Result",
        "List",
        "ListError",
        "NumericError",
        "StateMap",
        "StateCursor",
        "StatePage",
        "Secret",
        "AccountView",
        "AssetView",
        "AssetDefinitionView",
        "DomainView",
        "NftView",
        "QueryPage",
        "AxtDescriptor",
        "AxtAnchoredSpendV1",
        "ProofBlob",
        "SoracloudRequest",
        "SoracloudResponse",
        "state_map_get",
        "__kotodama_state_page",
        "__kotodama_state_take",
        "__kotodama_list_len",
        "__kotodama_list_get",
        "__kotodama_list_set",
        "__kotodama_list_push",
        "__kotodama_list_try_set",
        "__kotodama_list_try_push",
        "__kotodama_list_pop",
        "__kotodama_list_contains",
        "__kotodama_list_take",
        "__kotodama_list_enumerate",
        "__kotodama_decimal_div_round",
        "__kotodama_decimal_mul_div_round",
        "__kotodama_quantity_mul_div_round",
        "__kotodama_quantity_div_round",
        "__kotodama_quantity_ratio_round",
        "__kotodama_decimal_to_int_trunc",
        "__kotodama_decimal_to_int_round",
        "is_some",
        "is_none",
        "is_ok",
        "is_err",
        "unwrap_or",
        "unwrap_err_or",
        "expect",
    }
)

_KOTODAMA_RETIRED_NUMERIC_TYPE_NAMES = frozenset(
    {
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "num",
        "Int",
        "Integer",
        "float",
        "f32",
        "f64",
        "Decimal",
        "Fixed",
        "FixedPoint",
        "Amount",
        "amount",
        "money",
        "Quantity",
        "number",
    }
)

_KOTODAMA_V1_STATE_MAP_KEY_TYPES = (
    "int",
    "decimal",
    "quantity",
    "bool",
    "string",
    "bytes",
    "DataSpaceId",
    "AccountId",
    "AssetDefinitionId",
    "AssetId",
    "NftId",
    "DomainId",
    "Name",
)

_KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KINDS = (
    "page",
    "take",
)

_KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS = 64
# END GENERATED: kotodama-v1-validator-policy
_KOTODAMA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_KOTODAMA_RETIRED_NUMERIC_TYPE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    + "|".join(re.escape(name) for name in _KOTODAMA_RETIRED_NUMERIC_TYPE_NAMES)
    + r")(?![A-Za-z0-9_])"
)


def _contract_object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{path} must be an object")
    return value


def _contract_exact_fields(
    value: Mapping[str, Any], allowed: Sequence[str], path: str
) -> None:
    unknown = sorted(str(field) for field in value if field not in allowed)
    if unknown:
        raise TypeError(f"{path} contains unsupported fields: {', '.join(unknown)}")


def _contract_array(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TypeError(f"{path} must be an array")
    return value


def _contract_required_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value or not value.strip() or value.strip() != value:
        raise TypeError(f"{path} must be an exact non-empty string")
    return value


def _contract_optional_string(value: Any, path: str) -> Optional[str]:
    if value is None:
        return None
    return _contract_required_string(value, path)


def _contract_type_name(value: Any, path: str) -> str:
    type_name = _contract_required_string(value, path)
    type_nesting_depth = 0
    struct_type_nesting_depths: list[int] = []
    scanned_to = 0
    locked_struct_ranges = [
        (token.start(), token.end())
        for token in re.finditer(r"[A-Za-z0-9_./@:-]+", type_name)
        if "::" in token.group() and _canonical_kotodama_struct_name(token.group())
    ]
    for match in _KOTODAMA_RETIRED_NUMERIC_TYPE_RE.finditer(type_name):
        for character in type_name[scanned_to : match.start()]:
            if character == "{":
                struct_type_nesting_depths.append(type_nesting_depth)
            elif character == "}":
                if struct_type_nesting_depths:
                    struct_type_nesting_depths.pop()
            elif character in "<([":
                type_nesting_depth += 1
            elif character in ">)]":
                type_nesting_depth = max(0, type_nesting_depth - 1)
        previous = match.start() - 1
        while previous >= 0 and type_name[previous].isspace():
            previous -= 1
        cursor = match.end()
        while cursor < len(type_name) and type_name[cursor].isspace():
            cursor += 1
        is_struct_field = (
            bool(struct_type_nesting_depths)
            and type_nesting_depth == struct_type_nesting_depths[-1]
            and previous >= 0
            and type_name[previous] in "{,"
            and cursor < len(type_name)
            and type_name[cursor] == ":"
            and not type_name.startswith("::", cursor)
        )
        is_locked_struct_component = any(start <= match.start() and match.end() <= end for start, end in locked_struct_ranges)
        if not is_struct_field and not is_locked_struct_component:
            raise TypeError(f"{path} contains a retired Kotodama numeric type")
        scanned_to = match.end()
    return type_name


def _contract_string_tuple(value: Any, path: str) -> Tuple[str, ...]:
    return tuple(
        _contract_required_string(item, f"{path}[{index}]")
        for index, item in enumerate(_contract_array(value, path))
    )


def _canonical_kotodama_identifier(
    value: str, *, declaration: bool = False, type_declaration: bool = False
) -> bool:
    return (
        _KOTODAMA_IDENTIFIER_RE.fullmatch(value) is not None
        and value not in _KOTODAMA_RESERVED_IDENTIFIERS
        and not value.startswith("__kotodama_link_")
        and (not declaration or value not in _KOTODAMA_RESERVED_DECLARATION_IDENTIFIERS)
        and (
            not type_declaration
            or (
                value not in _KOTODAMA_RESERVED_DECLARATION_IDENTIFIERS
                and value not in _KOTODAMA_RETIRED_NUMERIC_TYPE_NAMES
            )
        )
    )



def _canonical_kotodama_struct_name(value: str) -> bool:
    if not isinstance(value, str) or len(value) > 1024:
        return False
    if "::" not in value:
        return _canonical_kotodama_identifier(value, type_declaration=True)
    if "__kotodama_link_" in value:
        return False
    parts = value.split("::")
    if len(parts) == 4 and parts[0] == "local":
        return (re.fullmatch(r"[0-9a-f]{64}", parts[1]) is not None
                and all(_canonical_kotodama_identifier(part, type_declaration=True) for part in parts[2:]))
    if len(parts) != 3 or not all(_canonical_kotodama_identifier(part, type_declaration=True) for part in parts[1:]):
        return False
    package = parts[0].split("@")
    component = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
    return (len(package) <= 2 and all(component.fullmatch(part) for part in package[0].split("/"))
            and (len(package) == 1 or component.fullmatch(package[1]) is not None))


def _canonical_contract_error_identity(value: str) -> bool:
    return (
        isinstance(value, str)
        and "__kotodama_link_" not in value
        and all(character.isalnum() or character in "_:/@.-" for character in value)
        and 1 <= len(value.encode("utf-8")) <= 1024
    )


def _canonical_contract_error_variant(value: str) -> bool:
    return _canonical_kotodama_identifier(value) or (
        bool(value)
        and not value.isascii()
        and (value[0].isalpha() or value[0] == "_")
        and all(character.isalnum() or character == "_" for character in value)
    )

_KOTODAMA_V1_STATE_SCALAR_TYPES = frozenset(
    {
        "int",
        "decimal",
        "quantity",
        "bool",
        "string",
        "bytes",
        "DataSpaceId",
        "AccountId",
        "AssetDefinitionId",
        "AssetId",
        "NftId",
        "DomainId",
        "Name",
        "Json",
    }
)
_KOTODAMA_V1_MAX_TYPE_DEPTH = 256
_KOTODAMA_V1_MAX_TYPE_NODES = 256


def _canonical_kotodama_dynamic_access_base_key(value: str) -> bool:
    prefix = "state:"
    return value.startswith(prefix) and _canonical_kotodama_identifier(
        value[len(prefix):], declaration=True
    )


def _kotodama_v1_state_map_key_type_name(type_name: str) -> Optional[str]:
    if not _canonical_kotodama_state_type_name(type_name):
        return None
    match = re.match(r"\AStateMap<([A-Za-z_][A-Za-z0-9_]*), ", type_name)
    if match is None or match.group(1) not in _KOTODAMA_V1_STATE_MAP_KEY_TYPES:
        return None
    return match.group(1)


def _canonical_kotodama_state_type_name(
    value: str, error_identities: Optional[set[str]] = None
) -> bool:
    cursor = 0
    nodes = 0

    def consume(literal: str) -> bool:
        nonlocal cursor
        if not value.startswith(literal, cursor):
            return False
        cursor += len(literal)
        return True

    def identifier() -> Optional[str]:
        nonlocal cursor
        if cursor >= len(value):
            return None
        first = value[cursor]
        if not (first == "_" or "A" <= first <= "Z" or "a" <= first <= "z"):
            return None
        start = cursor
        cursor += 1
        while cursor < len(value):
            character = value[cursor]
            if not (
                character == "_"
                or "A" <= character <= "Z"
                or "a" <= character <= "z"
                or "0" <= character <= "9"
            ):
                break
            cursor += 1
        return value[start:cursor]

    def list_capacity() -> bool:
        nonlocal cursor
        start = cursor
        while cursor < len(value) and "0" <= value[cursor] <= "9":
            cursor += 1
        spelling = value[start:cursor]
        return (
            bool(spelling)
            and len(spelling) <= 2
            and (len(spelling) == 1 or spelling[0] != "0")
            and 1 <= int(spelling) <= 64
        )

    def parse_type(allow_state_map: bool, depth: int) -> Optional[str]:
        nonlocal nodes, cursor
        nodes += 1
        if depth > _KOTODAMA_V1_MAX_TYPE_DEPTH or nodes > _KOTODAMA_V1_MAX_TYPE_NODES:
            return None

        if consume("()"):
            return "unit"
        error_end = cursor
        while error_end < len(value) and (value[error_end].isalnum() or value[error_end] in "_:/@.-"):
            error_end += 1
        error_identity = value[cursor:error_end]
        if "::" in error_identity and value[error_end:error_end + 1] != "{" and _canonical_contract_error_identity(error_identity):
            if error_identities is not None and error_identity not in error_identities:
                return None
            cursor = error_end
            return "error"
        if consume("("):
            if parse_type(False, depth + 1) is None or not consume(", "):
                return None
            if parse_type(False, depth + 1) is None:
                return None
            while consume(", "):
                if parse_type(False, depth + 1) is None:
                    return None
            return "aggregate" if consume(")") else None

        qualified_struct = re.match(r"[A-Za-z0-9_./@:-]+(?=\{)", value[cursor:])
        if qualified_struct is not None and "::" in qualified_struct.group():
            name = qualified_struct.group()
            cursor += len(name)
        else:
            name = identifier()
        if name is None:
            return None
        if name in _KOTODAMA_V1_STATE_SCALAR_TYPES:
            return name
        if name == "StateCursor":
            if not consume("<") or identifier() not in _KOTODAMA_V1_STATE_MAP_KEY_TYPES or not consume(">"):
                return None
            return "cursor"
        if name == "Option":
            if not consume("<") or parse_type(False, depth + 1) is None or not consume(">"):
                return None
            return "aggregate"
        if name == "Result":
            if (
                not consume("<")
                or parse_type(False, depth + 1) is None
                or not consume(", ")
                or parse_type(False, depth + 1) is None
                or not consume(">")
            ):
                return None
            return "aggregate"
        if name == "List":
            if (
                not consume("<")
                or parse_type(False, depth + 1) is None
                or not consume(", ")
                or not list_capacity()
                or not consume(">")
            ):
                return None
            return "aggregate"
        if name == "StateMap":
            if not allow_state_map or not consume("<"):
                return None
            # StateMap's scalar key and wrapper are not StateValueSchemaV1
            # nodes, but its wrapper still consumes one CNTR depth level.
            nodes -= 1
            key_type = identifier()
            if (
                key_type not in _KOTODAMA_V1_STATE_MAP_KEY_TYPES
                or not consume(", ")
                or parse_type(False, depth + 1) is None
                or not consume(">")
            ):
                return None
            return "aggregate"
        if name == "StatePage":
            nodes += 5  # List, Tuple, scalar key, Option, StateCursor.
            if nodes > _KOTODAMA_V1_MAX_TYPE_NODES or depth + 3 > _KOTODAMA_V1_MAX_TYPE_DEPTH:
                return None
            if not consume("{items: List<("):
                return None
            key_type = identifier()
            if (key_type not in _KOTODAMA_V1_STATE_MAP_KEY_TYPES or not consume(", ")
                    or parse_type(False, depth + 3) is None or not consume("), ")
                    or not list_capacity() or not consume(">, next: Option<StateCursor<")):
                return None
            return "aggregate" if consume(key_type) and consume(">>}") else None
        if not _canonical_kotodama_struct_name(name) or not consume("{"):
            return None

        # Empty products retain their validated nominal name and have no fields.
        if consume("}"):
            return "aggregate"
        fields: set[str] = set()
        while True:
            field = identifier()
            if (
                field is None
                or not _canonical_kotodama_identifier(field)
                or field in fields
                or not consume(": ")
            ):
                return None
            fields.add(field)
            if parse_type(False, depth + 1) is None:
                return None
            if consume("}"):
                return "aggregate"
            if not consume(", "):
                return None

    return bool(value) and parse_type(True, 1) is not None and cursor == len(value)


def _contract_state_type_name(value: Any, path: str) -> str:
    type_name = _contract_type_name(value, path)
    if not _canonical_kotodama_state_type_name(type_name):
        raise TypeError(f"{path} must be an exact canonical Kotodama V1 state type")
    return type_name


def _canonical_kotodama_entrypoint(value: str) -> bool:
    return value in {"hajimari", "始まり", "kaizen", "改善"} or (
        _canonical_kotodama_identifier(value, declaration=True)
    )


def _contract_hash_crc16(body: str) -> int:
    crc = 0xFFFF
    for byte in f"hash:{body}".encode("ascii"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _contract_canonical_hash_hex(value: Any, path: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{path} must be a canonical checksummed Norito Hash literal")
    matched = re.fullmatch(r"hash:([0-9A-F]{64})#([0-9A-F]{4})", value)
    if matched is None:
        raise TypeError(f"{path} must be a canonical checksummed Norito Hash literal")
    body, checksum = matched.groups()
    expected = _contract_hash_crc16(body)
    if int(checksum, 16) != expected:
        raise TypeError(f"{path} has an invalid Norito literal checksum")
    raw = bytes.fromhex(body)
    if raw[-1] & 1 != 1:
        raise TypeError(f"{path} must set the Iroha Hash marker bit")
    return body.lower()


def _contract_hash_convenience_hex(value: Any, path: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise TypeError(f"{path} must be canonical lowercase 64-hex")
    if bytes.fromhex(value)[-1] & 1 != 1:
        raise TypeError(f"{path} must set the Iroha Hash marker bit")
    return value


class ContractEntrypointKind(str, Enum):
    """Canonical V1 category encoded in an entrypoint descriptor."""

    KOTOAGE = "Kotoage"
    VIEW = "View"
    HAJIMARI = "Hajimari"
    KAIZEN = "Kaizen"

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractEntrypointKind":
        tagged = _contract_object(payload, "entrypoint kind")
        _contract_exact_fields(tagged, ("kind", "value"), "entrypoint kind")
        if "value" not in tagged or tagged["value"] is not None:
            raise TypeError("entrypoint kind `value` must be null")
        label = _contract_required_string(tagged.get("kind"), "entrypoint kind.kind")
        try:
            return cls(label)
        except ValueError as exc:
            raise TypeError(f"unsupported Kotodama entrypoint kind `{label}`") from exc


class EntrypointValueKindV1(str, Enum):
    """Leaf representation used by the exact V1 public boundary schema."""

    INT = "Int"
    DECIMAL = "Decimal"
    QUANTITY = "Quantity"
    BOOL = "Bool"
    STRING = "String"
    JSON = "Json"
    NAME = "Name"
    ACCOUNT_ID = "AccountId"
    ASSET_DEFINITION_ID = "AssetDefinitionId"
    ASSET_ID = "AssetId"
    DOMAIN_ID = "DomainId"
    NFT_ID = "NftId"
    DATA_SPACE_ID = "DataSpaceId"
    BLOB = "Blob"

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "EntrypointValueKindV1":
        tagged = _contract_object(payload, "entrypoint value kind")
        _contract_exact_fields(tagged, ("kind", "value"), "entrypoint value kind")
        if "value" not in tagged or tagged["value"] is not None:
            raise TypeError("entrypoint value kind `value` must be null")
        label = _contract_required_string(tagged.get("kind"), "entrypoint value kind.kind")
        try:
            return cls(label)
        except ValueError as exc:
            raise TypeError(f"unsupported Kotodama boundary value kind `{label}`") from exc


class EntrypointValueTypeNodeKindV1(str, Enum):
    """One exact V1 recursive boundary-schema node category."""

    STRUCT = "Struct"
    TUPLE = "Tuple"
    OPTION = "Option"
    RESULT = "Result"
    LIST = "List"
    LEAF = "Leaf"
    UNIT = "Unit"
    ERROR = "Error"
    STATE_CURSOR = "StateCursor"


_RESERVED_ENTRYPOINT_STRUCT_NAMES = frozenset(
    {
        "AccountView",
        "AssetView",
        "AssetDefinitionView",
        "DomainView",
        "NftView",
        "QueryPage",
        "StatePage",
    }
)


@dataclass(frozen=True)
class EntrypointStructTypeNodeV1:
    """Named product metadata in an exact V1 boundary schema."""

    name: str
    fields: Tuple[str, ...]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "EntrypointStructTypeNodeV1":
        value = _contract_object(payload, "entrypoint struct node")
        _contract_exact_fields(value, ("name", "fields"), "entrypoint struct node")
        return cls(
            name=_contract_required_string(value.get("name"), "entrypoint struct node.name"),
            fields=_contract_string_tuple(value.get("fields"), "entrypoint struct node.fields"),
        )


@dataclass(frozen=True)
class EntrypointListTypeNodeV1:
    """Bounded-list metadata in the flat V1 boundary-schema tape."""

    capacity: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "EntrypointListTypeNodeV1":
        value = _contract_object(payload, "entrypoint list node")
        _contract_exact_fields(value, ("capacity",), "entrypoint list node")
        capacity = value.get("capacity")
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("entrypoint list node.capacity must be an integer")
        if not 1 <= capacity <= 64:
            raise TypeError("entrypoint list node.capacity must be in 1..64")
        return cls(capacity=capacity)


@dataclass(frozen=True)
class EntrypointValueTypeNodeV1:
    """One typed preorder node in an exact V1 public boundary schema."""

    kind: EntrypointValueTypeNodeKindV1
    value: Any

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "EntrypointValueTypeNodeV1":
        tagged = _contract_object(payload, "entrypoint value type node")
        _contract_exact_fields(tagged, ("kind", "value"), "entrypoint value type node")
        label = _contract_required_string(tagged.get("kind"), "entrypoint value type node.kind")
        try:
            kind = EntrypointValueTypeNodeKindV1(label)
        except ValueError as exc:
            raise TypeError(f"unsupported Kotodama boundary type node `{label}`") from exc
        if "value" not in tagged:
            raise TypeError("entrypoint value type node is missing `value`")
        raw_value = tagged["value"]
        if kind is EntrypointValueTypeNodeKindV1.STRUCT:
            value: Any = EntrypointStructTypeNodeV1.from_payload(raw_value)
        elif kind is EntrypointValueTypeNodeKindV1.TUPLE:
            if isinstance(raw_value, bool) or not isinstance(raw_value, int):
                raise TypeError("entrypoint tuple arity must be an integer")
            if not 2 <= raw_value <= 0xFFFF:
                raise TypeError("entrypoint tuple arity must be in 2..65535")
            value = raw_value
        elif kind in (
            EntrypointValueTypeNodeKindV1.OPTION,
            EntrypointValueTypeNodeKindV1.RESULT,
            EntrypointValueTypeNodeKindV1.UNIT,
        ):
            if raw_value is not None:
                raise TypeError(f"entrypoint {kind.value} node `value` must be null")
            value = None
        elif kind is EntrypointValueTypeNodeKindV1.LIST:
            value = EntrypointListTypeNodeV1.from_payload(raw_value)
        elif kind is EntrypointValueTypeNodeKindV1.ERROR:
            value = ContractErrorTypeDescriptor.from_payload(raw_value)
        elif kind is EntrypointValueTypeNodeKindV1.STATE_CURSOR:
            value = EntrypointValueKindV1.from_payload(raw_value)
            if value is EntrypointValueKindV1.JSON:
                raise TypeError("StateCursor key type cannot be Json")
        else:
            value = EntrypointValueKindV1.from_payload(raw_value)
        return cls(kind=kind, value=value)


@dataclass(frozen=True)
class EntrypointValueTypeV1:
    """Validated preorder representation of one exact V1 boundary type."""

    nodes: Tuple[EntrypointValueTypeNodeV1, ...]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "EntrypointValueTypeV1":
        value = _contract_object(payload, "entrypoint value type")
        _contract_exact_fields(value, ("nodes",), "entrypoint value type")
        nodes = tuple(
            EntrypointValueTypeNodeV1.from_payload(node)
            for node in _contract_array(value.get("nodes"), "entrypoint value type.nodes")
        )
        result = cls(nodes=nodes)
        analysis = result._analyze(1)
        if analysis is None:
            raise TypeError("entrypoint value type is not a valid canonical V1 schema")
        try:
            _ = result.canonical_type_name
        except ValueError as exc:
            raise TypeError("entrypoint value type contains a forged reserved V1 schema") from exc
        return result

    def _analyze(self, root_depth: int) -> Optional[Tuple[int, int, int]]:
        """Return `(node_count, word_count, max_depth)` for a canonical schema."""

        if not self.nodes or len(self.nodes) > 256 or root_depth != 1:
            return None

        def child_count(node: EntrypointValueTypeNodeV1) -> Optional[int]:
            if node.kind is EntrypointValueTypeNodeKindV1.STRUCT:
                if not isinstance(node.value, EntrypointStructTypeNodeV1):
                    return None
                return len(node.value.fields)
            if node.kind is EntrypointValueTypeNodeKindV1.TUPLE:
                return node.value if isinstance(node.value, int) else None
            if node.kind in (
                EntrypointValueTypeNodeKindV1.OPTION,
                EntrypointValueTypeNodeKindV1.LIST,
            ):
                return 1
            if node.kind is EntrypointValueTypeNodeKindV1.RESULT:
                return 2
            if node.kind in (
                EntrypointValueTypeNodeKindV1.LEAF,
                EntrypointValueTypeNodeKindV1.UNIT,
                EntrypointValueTypeNodeKindV1.ERROR,
                EntrypointValueTypeNodeKindV1.STATE_CURSOR,
            ):
                return 0
            return None

        frames: list[dict[str, Any]] = []
        word_count = 0
        max_depth = 0
        for index, node in enumerate(self.nodes):
            while frames and frames[-1]["remaining"] == 0:
                frames.pop()
            suppress_words = False
            if index != 0:
                if not frames or frames[-1]["remaining"] == 0:
                    return None
                frames[-1]["remaining"] -= 1
                suppress_words = bool(frames[-1]["suppress_words"])
            depth = len(frames) + 1
            if depth > 256:
                return None
            max_depth = max(max_depth, depth)

            if node.kind is EntrypointValueTypeNodeKindV1.STRUCT:
                descriptor = node.value
                reserved_schema_name = (
                    isinstance(descriptor, EntrypointStructTypeNodeV1)
                    and descriptor.name in _RESERVED_ENTRYPOINT_STRUCT_NAMES
                )
                if (
                    not isinstance(descriptor, EntrypointStructTypeNodeV1)
                    or (
                        not reserved_schema_name
                        and not _canonical_kotodama_struct_name(descriptor.name)
                    )
                    or any(not _canonical_kotodama_identifier(field) for field in descriptor.fields)
                    or len(set(descriptor.fields)) != len(descriptor.fields)
                ):
                    return None
            elif node.kind is EntrypointValueTypeNodeKindV1.TUPLE:
                if not isinstance(node.value, int) or not 2 <= node.value <= 0xFFFF:
                    return None
            elif node.kind is EntrypointValueTypeNodeKindV1.LIST:
                if not isinstance(node.value, EntrypointListTypeNodeV1):
                    return None
            elif node.kind is EntrypointValueTypeNodeKindV1.LEAF:
                if not isinstance(node.value, EntrypointValueKindV1):
                    return None

            elif node.kind is EntrypointValueTypeNodeKindV1.UNIT:
                if node.value is not None:
                    return None
            elif node.kind is EntrypointValueTypeNodeKindV1.ERROR:
                if not isinstance(node.value, ContractErrorTypeDescriptor):
                    return None
                try:
                    node.value.validate()
                except TypeError:
                    return None
            elif node.kind is EntrypointValueTypeNodeKindV1.STATE_CURSOR:
                if not isinstance(node.value, EntrypointValueKindV1) or node.value is EntrypointValueKindV1.JSON:
                    return None

            handle = node.kind in (
                EntrypointValueTypeNodeKindV1.OPTION,
                EntrypointValueTypeNodeKindV1.RESULT,
                EntrypointValueTypeNodeKindV1.LIST,
            )
            if not suppress_words and (handle or child_count(node) == 0):
                word_count += 1
            children = child_count(node)
            if children is None:
                return None
            if children:
                frames.append(
                    {
                        "remaining": children,
                        "suppress_words": suppress_words or handle,
                    }
                )
        while frames and frames[-1]["remaining"] == 0:
            frames.pop()
        if frames:
            return None
        return len(self.nodes), word_count, max_depth

    @property
    def word_count(self) -> int:
        """Return the fixed V1 ABI word count after schema validation."""

        analysis = self._analyze(1)
        if analysis is None:
            raise ValueError("invalid entrypoint value type")
        return analysis[1]

    @property
    def canonical_type_name(self) -> str:
        """Render the exact canonical Kotodama V1 type name."""

        leaf_names = {
            EntrypointValueKindV1.INT: "int",
            EntrypointValueKindV1.DECIMAL: "decimal",
            EntrypointValueKindV1.QUANTITY: "quantity",
            EntrypointValueKindV1.BOOL: "bool",
            EntrypointValueKindV1.STRING: "string",
            EntrypointValueKindV1.JSON: "Json",
            EntrypointValueKindV1.NAME: "Name",
            EntrypointValueKindV1.ACCOUNT_ID: "AccountId",
            EntrypointValueKindV1.ASSET_DEFINITION_ID: "AssetDefinitionId",
            EntrypointValueKindV1.ASSET_ID: "AssetId",
            EntrypointValueKindV1.DOMAIN_ID: "DomainId",
            EntrypointValueKindV1.NFT_ID: "NftId",
            EntrypointValueKindV1.DATA_SPACE_ID: "DataSpaceId",
            EntrypointValueKindV1.BLOB: "bytes",
        }

        core_views = {
            "AccountView": (["id", "metadata"], ["AccountId", "Json"]),
            "AssetView": (["id", "amount"], ["AssetId", "quantity"]),
            "AssetDefinitionView": (
                [
                    "id",
                    "name",
                    "description",
                    "owned_by",
                    "total_quantity",
                    "numeric_scale",
                    "metadata",
                ],
                [
                    "AssetDefinitionId",
                    "string",
                    "Option<string>",
                    "AccountId",
                    "quantity",
                    "Option<int>",
                    "Json",
                ],
            ),
            "DomainView": (
                ["id", "owned_by", "metadata"],
                ["DomainId", "AccountId", "Json"],
            ),
            "NftView": (
                ["id", "owned_by", "content"],
                ["NftId", "AccountId", "Json"],
            ),
        }

        def child_count(node: EntrypointValueTypeNodeV1) -> int:
            if node.kind is EntrypointValueTypeNodeKindV1.STRUCT:
                return len(node.value.fields)
            if node.kind is EntrypointValueTypeNodeKindV1.TUPLE:
                return int(node.value)
            if node.kind in (
                EntrypointValueTypeNodeKindV1.OPTION,
                EntrypointValueTypeNodeKindV1.LIST,
            ):
                return 1
            if node.kind is EntrypointValueTypeNodeKindV1.RESULT:
                return 2
            return 0

        rendered: list[Dict[str, Any]] = []
        for node in reversed(self.nodes):
            count = child_count(node)
            if len(rendered) < count:
                raise ValueError("invalid entrypoint value type")
            children = rendered[len(rendered) - count :] if count else []
            if count:
                del rendered[len(rendered) - count :]
                children.reverse()

            result: Dict[str, Any]
            if node.kind is EntrypointValueTypeNodeKindV1.STRUCT:
                descriptor = node.value
                if not isinstance(descriptor, EntrypointStructTypeNodeV1):
                    raise ValueError("invalid struct node")
                child_names = [child["text"] for child in children]
                if descriptor.name in core_views:
                    expected_fields, expected_children = core_views[descriptor.name]
                    if (
                        list(descriptor.fields) != expected_fields
                        or child_names != expected_children
                    ):
                        raise ValueError("forged reserved query view")
                    result = {"text": descriptor.name, "core_view": descriptor.name}
                elif descriptor.name == "QueryPage":
                    if (
                        list(descriptor.fields) != ["items", "next_offset"]
                        or len(children) != 2
                        or children[0].get("kind") != "List"
                        or children[0].get("capacity") != 64
                        or children[0].get("list_element_core_view") is None
                        or children[1]["text"] != "Option<int>"
                    ):
                        raise ValueError("forged QueryPage schema")
                    result = {"text": f"QueryPage<{children[0]['list_element_core_view']}>"}
                elif descriptor.name == "StatePage":
                    items = children[0] if children else {}
                    pair = items.get("list_element", {}).get("tuple_children", [])
                    continuation = children[1].get("option_child", {}) if len(children) == 2 else {}
                    if (
                        list(descriptor.fields) != ["items", "next"]
                        or items.get("kind") != "List"
                        or len(pair) != 2
                        or pair[0].get("key_type") is None
                        or continuation.get("kind") != "StateCursor"
                        or continuation.get("key_type") != pair[0]["key_type"]
                    ):
                        raise ValueError("forged StatePage schema")
                    result = {"text": f"StatePage<{pair[0]['text']}, {pair[1]['text']}, {items['capacity']}>"}
                else:
                    result = {"text": f"struct {descriptor.name}"}
            elif node.kind is EntrypointValueTypeNodeKindV1.TUPLE:
                result = {"text": f"({', '.join(child['text'] for child in children)})", "tuple_children": children}
            elif node.kind is EntrypointValueTypeNodeKindV1.OPTION:
                result = {"text": f"Option<{children[0]['text']}>", "option_child": children[0]}
            elif node.kind is EntrypointValueTypeNodeKindV1.RESULT:
                result = {"text": f"Result<{children[0]['text']}, {children[1]['text']}>"}
            elif node.kind is EntrypointValueTypeNodeKindV1.LIST:
                descriptor = node.value
                if not isinstance(descriptor, EntrypointListTypeNodeV1):
                    raise ValueError("invalid list node")
                result = {
                    "text": f"List<{children[0]['text']}, {descriptor.capacity}>",
                    "kind": "List",
                    "capacity": descriptor.capacity,
                    "list_element_core_view": children[0].get("core_view"),
                    "list_element": children[0],
                }
            elif node.kind is EntrypointValueTypeNodeKindV1.LEAF:
                if not isinstance(node.value, EntrypointValueKindV1):
                    raise ValueError("invalid leaf node")
                result = {"text": leaf_names[node.value], "key_type": node.value if node.value is not EntrypointValueKindV1.JSON else None}
            elif node.kind is EntrypointValueTypeNodeKindV1.UNIT:
                result = {"text": "()"}
            elif node.kind is EntrypointValueTypeNodeKindV1.ERROR:
                node.value.validate()
                result = {"text": node.value.identity}
            elif node.kind is EntrypointValueTypeNodeKindV1.STATE_CURSOR:
                result = {"text": f"StateCursor<{leaf_names[node.value]}>", "kind": "StateCursor", "key_type": node.value}
            else:
                raise ValueError("invalid entrypoint value type")
            rendered.append(result)

        if len(rendered) != 1:
            raise ValueError("invalid entrypoint value type")
        return str(rendered[0]["text"])


@dataclass(frozen=True)
class EntrypointArgumentFieldV1:
    """One named field in a canonical V1 argument record."""

    name: str
    type: EntrypointValueTypeV1

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "EntrypointArgumentFieldV1":
        value = _contract_object(payload, "entrypoint argument field")
        _contract_exact_fields(value, ("name", "ty"), "entrypoint argument field")
        return cls(
            name=_contract_required_string(value.get("name"), "entrypoint argument field.name"),
            type=EntrypointValueTypeV1.from_payload(
                _contract_object(value.get("ty"), "entrypoint argument field.ty")
            ),
        )


_KOTODAMA_CALL_TABLE_WORD_LIMIT_V1 = 8192


@dataclass(frozen=True)
class EntrypointArgumentSchemaV1:
    """Exact canonical V1 schema for one public argument record."""

    fields: Tuple[EntrypointArgumentFieldV1, ...]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "EntrypointArgumentSchemaV1":
        value = _contract_object(payload, "entrypoint argument schema")
        _contract_exact_fields(value, ("fields",), "entrypoint argument schema")
        fields = tuple(
            EntrypointArgumentFieldV1.from_payload(field)
            for field in _contract_array(value.get("fields"), "entrypoint argument schema.fields")
        )
        names = [field.name for field in fields]
        if (
            not 1 <= len(fields) <= _KOTODAMA_CALL_TABLE_WORD_LIMIT_V1
            or any(not _canonical_kotodama_identifier(name) for name in names)
            or len(set(names)) != len(names)
            or sum(field.type.word_count for field in fields) > _KOTODAMA_CALL_TABLE_WORD_LIMIT_V1
        ):
            raise TypeError("entrypoint argument schema violates canonical V1 bounds")
        return cls(fields=fields)


@dataclass(frozen=True)
class ContractEntrypointParameter:
    """One declared public Kotodama parameter."""

    name: str
    type_name: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractEntrypointParameter":
        value = _contract_object(payload, "entrypoint parameter")
        _contract_exact_fields(value, ("name", "type_name"), "entrypoint parameter")
        return cls(
            name=_contract_required_string(value.get("name"), "entrypoint parameter.name"),
            type_name=_contract_type_name(value.get("type_name"), "entrypoint parameter.type_name"),
        )


class ContractTriggerRepeatKind(str, Enum):
    """Repeat policy advertised by a manifest-declared trigger."""

    INDEFINITELY = "Indefinitely"
    EXACTLY = "Exactly"


@dataclass(frozen=True)
class ContractTriggerRepeats:
    """Typed manifest trigger repeat policy."""

    kind: ContractTriggerRepeatKind
    count: Optional[int] = None


@dataclass(frozen=True)
class ContractTriggerCallback:
    """Kotodama callback selected when a manifest trigger fires."""

    namespace: Optional[str]
    entrypoint: str


@dataclass(frozen=True)
class ContractTriggerDescriptor:
    """Typed trigger declaration embedded in a contract manifest."""

    id: str
    repeats: ContractTriggerRepeats
    filter_b64: str
    filter_bytes: bytes
    authority: Optional[str]
    metadata: Mapping[str, Any]
    callback: ContractTriggerCallback


def _contract_trigger_descriptor(
    payload: Mapping[str, Any], path: str
) -> ContractTriggerDescriptor:
    value = _contract_object(payload, path)
    _contract_exact_fields(
        value,
        ("id", "repeats", "filter", "authority", "metadata", "callback"),
        path,
    )
    trigger_id = _contract_required_string(value.get("id"), f"{path}.id")
    if not _canonical_kotodama_identifier(trigger_id, declaration=True):
        raise TypeError(f"{path}.id must be a canonical Kotodama declaration identifier")
    repeats = _contract_object(value.get("repeats"), f"{path}.repeats")
    _contract_exact_fields(
        repeats,
        ("Indefinitely", "Exactly"),
        f"{path}.repeats",
    )
    if len(repeats) != 1 or next(iter(repeats)) not in {"Indefinitely", "Exactly"}:
        raise TypeError(f"{path}.repeats must contain exactly one canonical variant")
    repeat_kind, repeat_value = next(iter(repeats.items()))
    if repeat_kind == "Indefinitely":
        if repeat_value is not None:
            raise TypeError(f"{path}.repeats.Indefinitely must be null")
    elif (
        isinstance(repeat_value, bool)
        or not isinstance(repeat_value, int)
        or not 0 <= repeat_value <= 0xFFFFFFFF
    ):
        raise TypeError(f"{path}.repeats.Exactly must be a u32")

    encoded_filter = value.get("filter")
    if not isinstance(encoded_filter, str) or not encoded_filter:
        raise TypeError(f"{path}.filter must be non-empty exact standard-base64")
    try:
        decoded_filter = base64.b64decode(encoded_filter, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TypeError(f"{path}.filter must be exact standard-base64") from exc
    if not decoded_filter or base64.b64encode(decoded_filter).decode("ascii") != encoded_filter:
        raise TypeError(f"{path}.filter must be non-empty exact standard-base64")

    authority = value.get("authority")
    if authority is not None:
        _contract_required_string(authority, f"{path}.authority")
    metadata = _contract_object(value.get("metadata", {}), f"{path}.metadata")
    callback = _contract_object(value.get("callback"), f"{path}.callback")
    _contract_exact_fields(
        callback,
        ("namespace", "entrypoint"),
        f"{path}.callback",
    )
    namespace = callback.get("namespace")
    if namespace is not None:
        namespace = _contract_required_string(namespace, f"{path}.callback.namespace")
        if not _canonical_kotodama_identifier(namespace, type_declaration=True):
            raise TypeError(
                f"{path}.callback.namespace must be a canonical Kotodama type-declaration identifier"
            )
    callback_entrypoint = _contract_required_string(
        callback.get("entrypoint"), f"{path}.callback.entrypoint"
    )
    if not _canonical_kotodama_entrypoint(callback_entrypoint):
        raise TypeError(f"{path}.callback.entrypoint is not canonical")
    return ContractTriggerDescriptor(
        id=trigger_id,
        repeats=ContractTriggerRepeats(
            kind=ContractTriggerRepeatKind(repeat_kind),
            count=repeat_value if repeat_kind == "Exactly" else None,
        ),
        filter_b64=encoded_filter,
        filter_bytes=bytes(decoded_filter),
        authority=authority,
        metadata=copy.deepcopy(dict(metadata)),
        callback=ContractTriggerCallback(
            namespace=namespace,
            entrypoint=callback_entrypoint,
        ),
    )


@dataclass(frozen=True)
class ContractEntrypointDescriptor:
    """Exact public interface metadata for one Kotodama entrypoint."""

    name: str
    kind: ContractEntrypointKind
    params: Tuple[ContractEntrypointParameter, ...]
    argument_schema: Optional[EntrypointArgumentSchemaV1]
    return_type: Optional[str]
    return_schema: Optional[EntrypointValueTypeV1]
    permission: Optional[str]
    read_keys: Tuple[str, ...]
    write_keys: Tuple[str, ...]
    access_hints_complete: Optional[bool]
    access_hints_skipped: Tuple[str, ...]
    triggers: Tuple[ContractTriggerDescriptor, ...]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractEntrypointDescriptor":
        value = _contract_object(payload, "entrypoint descriptor")
        _contract_exact_fields(
            value,
            (
                "name",
                "kind",
                "params",
                "argument_schema",
                "return_type",
                "return_schema",
                "permission",
                "read_keys",
                "write_keys",
                "access_hints_complete",
                "access_hints_skipped",
                "triggers",
            ),
            "entrypoint descriptor",
        )
        params_raw = value.get("params", ())
        params = tuple(
            ContractEntrypointParameter.from_payload(param)
            for param in _contract_array(params_raw, "entrypoint descriptor.params")
        )
        argument_schema_raw = value.get("argument_schema")
        argument_schema = (
            None
            if argument_schema_raw is None
            else EntrypointArgumentSchemaV1.from_payload(argument_schema_raw)
        )
        return_schema_raw = value.get("return_schema")
        return_schema = (
            None
            if return_schema_raw is None
            else EntrypointValueTypeV1.from_payload(return_schema_raw)
        )
        access_hints_complete = value.get("access_hints_complete")
        if access_hints_complete is not None and not isinstance(access_hints_complete, bool):
            raise TypeError("entrypoint descriptor.access_hints_complete must be a boolean")
        trigger_values = []
        for index, trigger in enumerate(
            _contract_array(value.get("triggers", ()), "entrypoint descriptor.triggers")
        ):
            trigger_values.append(
                _contract_trigger_descriptor(
                    _contract_object(trigger, f"entrypoint descriptor.triggers[{index}]"),
                    f"entrypoint descriptor.triggers[{index}]",
                )
            )
        name = _contract_required_string(value.get("name"), "entrypoint descriptor.name")
        if not _canonical_kotodama_entrypoint(name):
            raise TypeError("entrypoint descriptor.name is not canonical")
        descriptor = cls(
            name=name,
            kind=ContractEntrypointKind.from_payload(
                _contract_object(value.get("kind"), "entrypoint descriptor.kind")
            ),
            params=params,
            argument_schema=argument_schema,
            return_type=(
                None
                if value.get("return_type") is None
                else _contract_type_name(
                    value.get("return_type"), "entrypoint descriptor.return_type"
                )
            ),
            return_schema=return_schema,
            permission=_contract_optional_string(
                value.get("permission"), "entrypoint descriptor.permission"
            ),
            read_keys=_contract_string_tuple(
                value.get("read_keys", ()), "entrypoint descriptor.read_keys"
            ),
            write_keys=_contract_string_tuple(
                value.get("write_keys", ()), "entrypoint descriptor.write_keys"
            ),
            access_hints_complete=access_hints_complete,
            access_hints_skipped=_contract_string_tuple(
                value.get("access_hints_skipped", ()),
                "entrypoint descriptor.access_hints_skipped",
            ),
            triggers=tuple(trigger_values),
        )
        parameter_names = [parameter.name for parameter in descriptor.params]
        schema_names = (
            None
            if descriptor.argument_schema is None
            else [field.name for field in descriptor.argument_schema.fields]
        )
        if not descriptor.params:
            exact_arguments = descriptor.argument_schema is None
        elif descriptor.argument_schema is None:
            exact_arguments = False
        else:
            exact_arguments = schema_names == parameter_names and all(
                argument_field.type.canonical_type_name == parameter.type_name
                for argument_field, parameter in zip(
                    descriptor.argument_schema.fields,
                    descriptor.params,
                    strict=True,
                )
            )
        exact_return = (
            descriptor.return_type is not None
            and descriptor.return_schema is not None
            and descriptor.return_schema.word_count <= _KOTODAMA_CALL_TABLE_WORD_LIMIT_V1
            and descriptor.return_schema.canonical_type_name == descriptor.return_type
        )
        lifecycle_kind = (
            ContractEntrypointKind.HAJIMARI
            if descriptor.name in {"hajimari", "始まり"}
            else ContractEntrypointKind.KAIZEN
            if descriptor.name in {"kaizen", "改善"}
            else None
        )
        exact_lifecycle = (
            descriptor.kind is lifecycle_kind
            if lifecycle_kind is not None
            else descriptor.kind
            not in {ContractEntrypointKind.HAJIMARI, ContractEntrypointKind.KAIZEN}
        )
        exact_authorization = (
            descriptor.permission is not None
            if descriptor.kind is ContractEntrypointKind.KOTOAGE
            else descriptor.permission is None
            if descriptor.kind in {ContractEntrypointKind.HAJIMARI, ContractEntrypointKind.KAIZEN}
            else True
        )
        exact_access_hints = not (
            descriptor.access_hints_complete is True and descriptor.access_hints_skipped
        ) and not (
            descriptor.access_hints_complete is False and not descriptor.access_hints_skipped
        )
        if (
            len(descriptor.params) > _KOTODAMA_CALL_TABLE_WORD_LIMIT_V1
            or len(set(parameter_names)) != len(parameter_names)
            or any(
                not _canonical_kotodama_identifier(parameter.name)
                for parameter in descriptor.params
            )
            or not exact_arguments
            or not exact_return
            or not exact_lifecycle
            or not exact_authorization
            or not exact_access_hints
        ):
            raise TypeError("entrypoint descriptor is not a canonical exact V1 interface")
        return descriptor


@dataclass(frozen=True)
class ContractStateDescriptor:
    """One durable state slot advertised by a Kotodama seiyaku."""

    name: str
    type_name: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractStateDescriptor":
        value = _contract_object(payload, "state descriptor")
        _contract_exact_fields(value, ("name", "type_name"), "state descriptor")
        name = _contract_required_string(value.get("name"), "state descriptor.name")
        if not _canonical_kotodama_identifier(name, declaration=True):
            raise TypeError("state descriptor.name must be a canonical Kotodama identifier")
        return cls(
            name=name,
            type_name=_contract_state_type_name(
                value.get("type_name"), "state descriptor.type_name"
            ),
        )


@dataclass(frozen=True)
class ContractErrorVariantDescriptor:
    """One named nonzero u32 discriminant, local to its nominal error type."""

    name: str
    code: int

    def validate(self) -> None:
        if not isinstance(self.name, str) or not _canonical_contract_error_variant(self.name):
            raise TypeError("error variant name must be a canonical Kotodama identifier")
        if isinstance(self.code, bool) or not isinstance(self.code, int) or not 1 <= self.code <= 0xFFFFFFFF:
            raise TypeError("error variant code must be a non-zero u32")

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractErrorVariantDescriptor":
        value = _contract_object(payload, "error variant descriptor")
        _contract_exact_fields(value, ("name", "code"), "error variant descriptor")
        result = cls(name=value.get("name"), code=value.get("code"))
        result.validate()
        return result


@dataclass(frozen=True)
class ContractErrorTypeDescriptor:
    """Stable nominal identity and its exact ordered variant schema."""

    identity: str
    variants: Tuple[ContractErrorVariantDescriptor, ...]

    def validate(self) -> None:
        if not _canonical_contract_error_identity(self.identity):
            raise TypeError("error type identity must be a canonical nominal identity")
        if not isinstance(self.variants, tuple) or not 1 <= len(self.variants) <= 256:
            raise TypeError("error type must declare 1..256 variants")
        for variant in self.variants:
            if not isinstance(variant, ContractErrorVariantDescriptor):
                raise TypeError("error type variants must be typed descriptors")
            variant.validate()
        if len({variant.name for variant in self.variants}) != len(self.variants) or any(left.code >= right.code for left, right in zip(self.variants, self.variants[1:])):
            raise TypeError("error variants must have unique names and increasing enum-local codes")

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractErrorTypeDescriptor":
        value = _contract_object(payload, "error type descriptor")
        _contract_exact_fields(value, ("identity", "variants"), "error type descriptor")
        result = cls(identity=value.get("identity"), variants=tuple(
            ContractErrorVariantDescriptor.from_payload(variant)
            for variant in _contract_array(value.get("variants"), "error type variants")
        ))
        result.validate()
        return result


@dataclass(frozen=True)
class ContractDynamicAccessHint:
    """One bounded dynamic access-set hint from the compiler."""

    base_key: str
    key_type: str
    bound_kind: str
    max_keys: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractDynamicAccessHint":
        value = _contract_object(payload, "dynamic access hint")
        _contract_exact_fields(
            value,
            ("base_key", "key_type", "bound_kind", "max_keys"),
            "dynamic access hint",
        )
        max_keys = value.get("max_keys")
        if isinstance(max_keys, bool) or not isinstance(max_keys, int):
            raise TypeError("dynamic access hint.max_keys must be an integer")
        if not 1 <= max_keys <= _KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS:
            raise TypeError("dynamic access hint.max_keys must be in the V1 range 1..64")
        base_key = _contract_required_string(
            value.get("base_key"), "dynamic access hint.base_key"
        )
        if not _canonical_kotodama_dynamic_access_base_key(base_key):
            raise TypeError(
                "dynamic access hint.base_key must be state: plus one canonical "
                "state declaration identifier"
            )
        key_type = _contract_required_string(
            value.get("key_type"), "dynamic access hint.key_type"
        )
        if key_type not in _KOTODAMA_V1_STATE_MAP_KEY_TYPES:
            raise TypeError(
                "dynamic access hint.key_type must be an exact Kotodama V1 "
                "StateMap key scalar"
            )
        bound_kind = _contract_required_string(
            value.get("bound_kind"), "dynamic access hint.bound_kind"
        )
        if bound_kind not in _KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KINDS:
            raise TypeError(
                "dynamic access hint.bound_kind must be exactly take or page"
            )
        return cls(
            base_key=base_key,
            key_type=key_type,
            bound_kind=bound_kind,
            max_keys=max_keys,
        )


@dataclass(frozen=True)
class ContractAccessSetHints:
    """Exact static and bounded-dynamic scheduler hints in a manifest."""

    read_keys: Tuple[str, ...]
    write_keys: Tuple[str, ...]
    dynamic_reads: Tuple[ContractDynamicAccessHint, ...]
    dynamic_writes: Tuple[ContractDynamicAccessHint, ...]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractAccessSetHints":
        value = _contract_object(payload, "access set hints")
        _contract_exact_fields(
            value,
            ("read_keys", "write_keys", "dynamic_reads", "dynamic_writes"),
            "access set hints",
        )

        def dynamic(name: str) -> Tuple[ContractDynamicAccessHint, ...]:
            return tuple(
                ContractDynamicAccessHint.from_payload(item)
                for item in _contract_array(value.get(name, ()), f"access set hints.{name}")
            )

        return cls(
            read_keys=_contract_string_tuple(value.get("read_keys"), "access set hints.read_keys"),
            write_keys=_contract_string_tuple(
                value.get("write_keys"), "access set hints.write_keys"
            ),
            dynamic_reads=dynamic("dynamic_reads"),
            dynamic_writes=dynamic("dynamic_writes"),
        )


def _validate_contract_dynamic_access_hint_state_maps(
    access_set_hints: Optional[ContractAccessSetHints],
    states: Optional[Tuple["ContractStateDescriptor", ...]],
) -> None:
    if access_set_hints is None:
        return
    state_maps = {
        state.name: key_type
        for state in states or ()
        if (key_type := _kotodama_v1_state_map_key_type_name(state.type_name))
        is not None
    }
    for field_name, hints in (
        ("dynamic_reads", access_set_hints.dynamic_reads),
        ("dynamic_writes", access_set_hints.dynamic_writes),
    ):
        seen = set()
        for index, hint in enumerate(hints):
            if hint in seen:
                raise TypeError(
                    f"manifest access_set_hints.{field_name} contains a duplicate dynamic access hint"
                )
            seen.add(hint)
            state_name = hint.base_key[len("state:") :]
            expected_key_type = state_maps.get(state_name)
            path = f"manifest access_set_hints.{field_name}[{index}]"
            if expected_key_type is None:
                raise TypeError(
                    f"{path}.base_key must reference a declared top-level StateMap"
                )
            if hint.key_type != expected_key_type:
                raise TypeError(
                    f"{path}.key_type {hint.key_type} does not match declared "
                    f"StateMap key type {expected_key_type}"
                )


@dataclass(frozen=True)
class ContractKotobaTranslation:
    """One localized message text in a Kotodama manifest."""

    language: str
    text: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractKotobaTranslation":
        value = _contract_object(payload, "kotoba translation")
        _contract_exact_fields(value, ("lang", "text"), "kotoba translation")
        text = value.get("text")
        if not isinstance(text, str):
            raise TypeError("kotoba translation.text must be a string")
        return cls(
            language=_contract_required_string(value.get("lang"), "kotoba translation.lang"),
            text=text,
        )


@dataclass(frozen=True)
class ContractKotobaTranslationEntry:
    """One stable message id and its localized Kotodama texts."""

    message_id: str
    translations: Tuple[ContractKotobaTranslation, ...]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractKotobaTranslationEntry":
        value = _contract_object(payload, "kotoba translation entry")
        _contract_exact_fields(
            value,
            ("msg_id", "translations"),
            "kotoba translation entry",
        )
        translations = tuple(
            ContractKotobaTranslation.from_payload(item)
            for item in _contract_array(
                value.get("translations"), "kotoba translation entry.translations"
            )
        )
        return cls(
            message_id=_contract_required_string(
                value.get("msg_id"), "kotoba translation entry.msg_id"
            ),
            translations=translations,
        )


@dataclass(frozen=True)
class ContractErrorMessage:
    """Authenticated static presentation text for one nominal error variant."""

    error_type: str
    code: int
    message: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractErrorMessage":
        obj = _contract_object(payload, "error message")
        _contract_exact_fields(obj, ("error_type", "code", "message"), "error message")
        identity = _contract_required_string(obj.get("error_type"), "error message.error_type")
        code = obj.get("code")
        message = obj.get("message")
        if isinstance(code, bool) or not isinstance(code, int) or not 1 <= code <= 0xFFFFFFFF:
            raise TypeError("error message.code must be a nonzero u32")
        if not isinstance(message, str) or not message.strip("\t\n\v\f\r \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"):
            raise TypeError("error message.message must contain 1..4096 UTF-8 bytes of nonblank text")
        try:
            message_bytes = message.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise TypeError("error message.message must contain valid Unicode scalar values") from exc
        if len(message_bytes) > 4096:
            raise TypeError("error message.message must contain 1..4096 UTF-8 bytes of nonblank text")
        return cls(identity, code, message)


@dataclass(frozen=True)
class ContractManifest:
    """On-chain contract manifest metadata with its exact V1 public interface."""

    seiyaku_name: Optional[str]
    code_hash: Optional[str]
    abi_hash: Optional[str]
    compiler_fingerprint: Optional[str]
    features_bitmap: Optional[int]
    access_set_hints: Optional[ContractAccessSetHints]
    entrypoints: Optional[Tuple[ContractEntrypointDescriptor, ...]]
    states: Optional[Tuple[ContractStateDescriptor, ...]]
    error_types: Optional[Tuple[ContractErrorTypeDescriptor, ...]]
    error_messages: Optional[Tuple[ContractErrorMessage, ...]]
    kotoba: Optional[Tuple[ContractKotobaTranslationEntry, ...]]
    provenance: Optional[Mapping[str, Any]]

    @property
    def declared_triggers(self) -> Tuple[ContractTriggerDescriptor, ...]:
        """Return every manifest trigger in entrypoint declaration order."""

        if self.entrypoints is None:
            return ()
        return tuple(trigger for entrypoint in self.entrypoints for trigger in entrypoint.triggers)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractManifest":
        if not isinstance(payload, Mapping):
            raise TypeError("manifest payload must be an object")
        allowed_fields = {
            "seiyaku_name",
            "code_hash",
            "abi_hash",
            "compiler_fingerprint",
            "features_bitmap",
            "access_set_hints",
            "entrypoints",
            "states",
            "error_types",
            "error_messages",
            "kotoba",
            "provenance",
        }
        unknown_fields = sorted(set(payload) - allowed_fields)
        if unknown_fields:
            raise TypeError(
                "manifest payload contains unsupported fields: " + ", ".join(unknown_fields)
            )
        seiyaku_name = payload.get("seiyaku_name")
        if seiyaku_name is not None and (not isinstance(seiyaku_name, str) or not seiyaku_name):
            raise TypeError("manifest `seiyaku_name` must be a non-empty string when provided")
        if seiyaku_name is not None and not _canonical_kotodama_identifier(
            seiyaku_name, type_declaration=True
        ):
            raise TypeError("manifest `seiyaku_name` must be a canonical Kotodama identifier")
        code_hash = _contract_canonical_hash_hex(payload.get("code_hash"), "manifest `code_hash`")
        abi_hash = _contract_canonical_hash_hex(payload.get("abi_hash"), "manifest `abi_hash`")
        compiler_fingerprint = payload.get("compiler_fingerprint")
        if compiler_fingerprint is not None and (
            not isinstance(compiler_fingerprint, str)
            or not compiler_fingerprint.strip()
            or compiler_fingerprint.strip() != compiler_fingerprint
        ):
            raise TypeError(
                "manifest `compiler_fingerprint` must be a non-empty string when provided"
            )
        features_raw = payload.get("features_bitmap")
        if features_raw is None:
            features_bitmap: Optional[int] = None
        elif isinstance(features_raw, bool) or not isinstance(features_raw, int):
            raise TypeError("manifest `features_bitmap` must be an unsigned integer")
        elif not 0 <= features_raw <= 0xFFFFFFFFFFFFFFFF:
            raise TypeError("manifest `features_bitmap` must be a u64")
        elif features_raw > 3:
            raise TypeError(
                "manifest `features_bitmap` contains unsupported Kotodama V1 feature bits"
            )
        else:
            features_bitmap = features_raw

        access_set_hints_raw = payload.get("access_set_hints")
        access_set_hints = (
            None
            if access_set_hints_raw is None
            else ContractAccessSetHints.from_payload(access_set_hints_raw)
        )

        def optional_descriptors(
            name: str, parser: Callable[[Mapping[str, Any]], Any]
        ) -> Optional[Tuple[Any, ...]]:
            raw = payload.get(name)
            if raw is None:
                return None
            return tuple(
                parser(_contract_object(item, f"manifest.{name}[{index}]"))
                for index, item in enumerate(_contract_array(raw, f"manifest.{name}"))
            )

        provenance_raw = payload.get("provenance")
        if provenance_raw is None:
            provenance = None
        else:
            provenance_object = _contract_object(provenance_raw, "manifest.provenance")
            _contract_exact_fields(
                provenance_object,
                ("signer", "signature"),
                "manifest.provenance",
            )
            provenance = {
                "signer": _contract_required_string(
                    provenance_object.get("signer"), "manifest.provenance.signer"
                ),
                "signature": _contract_required_string(
                    provenance_object.get("signature"), "manifest.provenance.signature"
                ),
            }

        entrypoints = optional_descriptors("entrypoints", ContractEntrypointDescriptor.from_payload)
        states = optional_descriptors("states", ContractStateDescriptor.from_payload)
        error_types = optional_descriptors("error_types", ContractErrorTypeDescriptor.from_payload)
        error_messages = optional_descriptors("error_messages", ContractErrorMessage.from_payload)
        kotoba = optional_descriptors("kotoba", ContractKotobaTranslationEntry.from_payload)

        if entrypoints is not None:
            entrypoint_names = [entrypoint.name for entrypoint in entrypoints]
            lifecycle_kinds = [
                entrypoint.kind
                for entrypoint in entrypoints
                if entrypoint.kind
                in {ContractEntrypointKind.HAJIMARI, ContractEntrypointKind.KAIZEN}
            ]
            if len(set(entrypoint_names)) != len(entrypoint_names) or len(
                set(lifecycle_kinds)
            ) != len(lifecycle_kinds):
                raise TypeError("manifest contains duplicate entrypoint declarations")
            entrypoint_kinds = {entrypoint.name: entrypoint.kind for entrypoint in entrypoints}
            trigger_ids = set()
            for entrypoint in entrypoints:
                for trigger in entrypoint.triggers:
                    trigger_id = trigger.id
                    if trigger_id in trigger_ids:
                        raise TypeError("manifest contains duplicate trigger ids")
                    trigger_ids.add(trigger_id)
                    callback = trigger.callback
                    if callback.namespace is None:
                        target_kind = entrypoint_kinds.get(callback.entrypoint)
                        if target_kind is None:
                            raise TypeError(
                                "manifest trigger targets an undeclared local entrypoint"
                            )
                        if target_kind is not ContractEntrypointKind.KOTOAGE:
                            raise TypeError(
                                "manifest local trigger callback must target kotoage/言挙げ"
                            )

        if states is not None and len({state.name for state in states}) != len(states):
            raise TypeError("manifest contains duplicate state descriptors")
        _validate_contract_dynamic_access_hint_state_maps(access_set_hints, states)
        catalog = {error.identity: error for error in error_types or ()}
        if len(catalog) != len(error_types or ()) or len(catalog) > 256:
            raise TypeError("manifest error_types must contain at most 256 unique identities")
        previous_message = None
        for entry in error_messages or ():
            key = (entry.error_type.encode("utf-8"), entry.code)
            error = catalog.get(entry.error_type)
            if error is None or not any(variant.code == entry.code for variant in error.variants):
                raise TypeError("error message must reference a declared nominal error variant")
            if previous_message is not None and previous_message >= key:
                raise TypeError("error messages must be sorted and unique by identity and code")
            previous_message = key
        for state in states or ():
            if not _canonical_kotodama_state_type_name(state.type_name, set(catalog)):
                raise TypeError("state nominal error identity is not declared in the error_types catalog")
        for entrypoint in entrypoints or ():
            schemas = [field.type for field in entrypoint.argument_schema.fields] if entrypoint.argument_schema else []
            if entrypoint.return_schema is not None:
                schemas.append(entrypoint.return_schema)
            for schema in schemas:
                for node in schema.nodes:
                    if node.kind is EntrypointValueTypeNodeKindV1.ERROR and catalog.get(node.value.identity) != node.value:
                        raise TypeError("boundary error schema does not match the error_types catalog")
        if kotoba is not None:
            message_ids = [entry.message_id for entry in kotoba]
            if len(set(message_ids)) != len(message_ids):
                raise TypeError("manifest contains duplicate kotoba message ids")
            for entry in kotoba:
                languages = [translation.language for translation in entry.translations]
                if len(set(languages)) != len(languages):
                    raise TypeError("manifest contains duplicate kotoba languages")

        return cls(
            seiyaku_name=seiyaku_name,
            code_hash=code_hash,
            abi_hash=abi_hash,
            compiler_fingerprint=compiler_fingerprint,
            features_bitmap=features_bitmap,
            access_set_hints=access_set_hints,
            entrypoints=entrypoints,
            states=states,
            error_types=error_types,
            error_messages=error_messages,
            kotoba=kotoba,
            provenance=provenance,
        )


@dataclass(frozen=True)
class ContractArtifactId:
    """Exact dataspace and complete contract artifact hash within one network."""

    dataspace_id: int
    code_hash: str

    def __post_init__(self) -> None:
        _require_u64(self.dataspace_id, "artifact_id.dataspace_id")
        if _contract_hash_convenience_hex(self.code_hash, "artifact_id.code_hash") is None:
            raise TypeError("artifact_id.code_hash is required")

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractArtifactId":
        if not isinstance(payload, Mapping):
            raise TypeError("artifact_id must be an object")
        _require_wire_fields(payload, required=("dataspace_id", "code_hash"), context="artifact_id")
        code_hash = _contract_canonical_hash_hex(payload["code_hash"], "artifact_id.code_hash")
        if code_hash is None:
            raise TypeError("artifact_id.code_hash is required")
        return cls(payload["dataspace_id"], code_hash)

    def to_payload(self) -> Mapping[str, Any]:
        """Return the exact Norito JSON representation."""
        body = self.code_hash.upper()
        return {"dataspace_id": self.dataspace_id,
                "code_hash": f"hash:{body}#{_contract_hash_crc16(body):04X}"}

    @property
    def path(self) -> str:
        """The canonical artifact resource path, without an origin."""
        return f"/v1/contracts/artifacts/{self.dataspace_id}/{self.code_hash}"


def _decode_contract_artifact_bytes(encoded: Any, artifact_id: ContractArtifactId) -> bytes:
    """Validate bounded canonical base64 against the complete scoped artifact digest."""
    if not isinstance(encoded, str):
        raise TypeError("contract bytes must be a base64 string")
    if len(encoded) > 4 * ((16 * 1024 * 1024 + 2) // 3):
        raise ValueError("contract bytes exceed the artifact limit")
    try:
        code = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("contract bytes must be canonical base64") from error
    if base64.b64encode(code).decode("ascii") != encoded or len(code) > 16 * 1024 * 1024:
        raise ValueError("contract bytes are noncanonical or exceed the artifact limit")
    digest = bytearray(hashlib.blake2b(b"iroha:ivm:contract-artifact:v1\0" + code, digest_size=32).digest())
    digest[-1] |= 1
    if digest.hex() != artifact_id.code_hash:
        raise RuntimeError("contract bytes digest differs from the requested artifact")
    return code


@dataclass(frozen=True)
class ContractManifestRecord:
    """Contract manifest bound to one exact network and dataspace artifact."""

    network_id: str
    artifact_id: ContractArtifactId
    manifest: ContractManifest
    code_hash: Optional[str]
    abi_hash: Optional[str]
    code_bytes: Optional[bytes] = None

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContractManifestRecord":
        if not isinstance(payload, Mapping):
            raise TypeError("manifest response must be an object")
        _contract_exact_fields(
            payload,
            ("network_id", "artifact_id", "manifest", "code_hash", "abi_hash", "code_bytes"),
            "manifest response",
        )
        manifest_payload = payload.get("manifest")
        if not isinstance(manifest_payload, Mapping):
            raise TypeError("manifest response missing object `manifest` field")
        manifest = ContractManifest.from_payload(manifest_payload)
        code_hash = _contract_hash_convenience_hex(
            payload.get("code_hash"), "manifest response `code_hash`"
        )
        abi_hash = _contract_hash_convenience_hex(
            payload.get("abi_hash"), "manifest response `abi_hash`"
        )
        if code_hash != manifest.code_hash or abi_hash != manifest.abi_hash:
            raise TypeError(
                "top-level contract hash conveniences must exactly match "
                "the canonical manifest hashes"
            )
        network_id = payload.get("network_id")
        if _contract_canonical_hash_hex(network_id, "manifest response.network_id") is None:
            raise TypeError("manifest response.network_id is required")
        artifact_id = ContractArtifactId.from_payload(payload.get("artifact_id"))
        if artifact_id.code_hash != manifest.code_hash:
            raise TypeError("artifact_id.code_hash differs from the manifest hash")
        encoded = payload.get("code_bytes")
        code_bytes = None if encoded is None else _decode_contract_artifact_bytes(encoded, artifact_id)
        return cls(network_id=network_id, artifact_id=artifact_id,
                   manifest=manifest, code_hash=code_hash, abi_hash=abi_hash, code_bytes=code_bytes)


@dataclass(frozen=True)
class PeerInfo:
    """Metadata describing an online peer returned by `GET /v1/peers`."""

    address: str
    public_key_hex: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PeerInfo":
        if not isinstance(payload, Mapping):
            raise TypeError("peer payload must be a mapping")
        address = payload.get("address")
        if not isinstance(address, str):
            raise TypeError("peer payload missing string `address` field")
        id_section = payload.get("id")
        if not isinstance(id_section, Mapping):
            raise TypeError("peer payload missing `id` object")
        public_key = id_section.get("public_key")
        if not isinstance(public_key, str):
            raise TypeError("peer id missing string `public_key` field")
        return cls(address=address, public_key_hex=public_key)


@dataclass(frozen=True)
class PeerTelemetryConfig:
    """Configuration snapshot returned by `/v1/telemetry/peers-info`."""

    public_key_hex: str
    queue_capacity: Optional[int]
    network_block_gossip_size: Optional[int]
    network_block_gossip_period_ms: Optional[int]
    network_tx_gossip_size: Optional[int]
    network_tx_gossip_period_ms: Optional[int]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PeerTelemetryConfig":
        if not isinstance(payload, Mapping):
            raise TypeError("telemetry peer config must be an object")
        public_key = payload.get("public_key")
        if not isinstance(public_key, str) or not public_key:
            raise TypeError("telemetry peer config missing string `public_key` field")
        queue_capacity = _coerce_int(
            payload.get("queue_capacity"),
            "telemetry peer config queue_capacity",
            allow_zero=True,
        )
        block_size = _coerce_int(
            payload.get("network_block_gossip_size"),
            "telemetry peer config network_block_gossip_size",
            allow_zero=True,
        )
        tx_size = _coerce_int(
            payload.get("network_tx_gossip_size"),
            "telemetry peer config network_tx_gossip_size",
            allow_zero=True,
        )
        block_period = _parse_optional_duration_ms_field(
            payload.get("network_block_gossip_period"),
            "telemetry peer config network_block_gossip_period",
        )
        tx_period = _parse_optional_duration_ms_field(
            payload.get("network_tx_gossip_period"),
            "telemetry peer config network_tx_gossip_period",
        )
        return cls(
            public_key_hex=public_key,
            queue_capacity=queue_capacity,
            network_block_gossip_size=block_size,
            network_block_gossip_period_ms=block_period,
            network_tx_gossip_size=tx_size,
            network_tx_gossip_period_ms=tx_period,
        )


@dataclass(frozen=True)
class PeerTelemetryLocation:
    """Geolocation metadata for `/v1/telemetry/peers-info` entries."""

    lat: float
    lon: float
    country: str
    city: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PeerTelemetryLocation":
        if not isinstance(payload, Mapping):
            raise TypeError("telemetry peer location must be an object")
        lat = _coerce_finite_float(payload.get("lat"), "telemetry peer location lat")
        lon = _coerce_finite_float(payload.get("lon"), "telemetry peer location lon")
        country = payload.get("country")
        city = payload.get("city")
        if not isinstance(country, str) or not country:
            raise TypeError("telemetry peer location missing string `country` field")
        if not isinstance(city, str) or not city:
            raise TypeError("telemetry peer location missing string `city` field")
        return cls(lat=lat, lon=lon, country=country, city=city)


@dataclass(frozen=True)
class PeerTelemetryInfo:
    """Entry returned by `GET /v1/telemetry/peers-info`."""

    url: str
    connected: bool
    telemetry_unsupported: bool
    config: Optional[PeerTelemetryConfig]
    location: Optional[PeerTelemetryLocation]
    connected_peers: Optional[List[str]]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PeerTelemetryInfo":
        if not isinstance(payload, Mapping):
            raise TypeError("telemetry peer payload must be an object")
        url = payload.get("url")
        if not isinstance(url, str) or not url:
            raise TypeError("telemetry peer payload missing string `url` field")
        connected = _coerce_bool_flag(payload.get("connected"), "telemetry peer connected")
        telemetry_flag = payload.get("telemetry_unsupported")
        telemetry_unsupported = _coerce_bool_flag(
            telemetry_flag if telemetry_flag is not None else False,
            "telemetry peer telemetry_unsupported",
        )
        config_payload = payload.get("config")
        if config_payload is not None and not isinstance(config_payload, Mapping):
            raise TypeError("telemetry peer config must be an object when provided")
        location_payload = payload.get("location")
        if location_payload is not None and not isinstance(location_payload, Mapping):
            raise TypeError("telemetry peer location must be an object when provided")
        peers_value = payload.get("connected_peers")
        connected_peers = None
        if peers_value is not None:
            if not isinstance(peers_value, list):
                raise TypeError("telemetry peer `connected_peers` must be a list when provided")
            peer_list: List[str] = []
            for index, peer in enumerate(peers_value):
                if not isinstance(peer, str) or not peer:
                    raise TypeError(
                        f"telemetry peer connected_peers[{index}] must be a non-empty string"
                    )
                peer_list.append(peer)
            connected_peers = peer_list
        return cls(
            url=url,
            connected=connected,
            telemetry_unsupported=telemetry_unsupported,
            config=PeerTelemetryConfig.from_payload(config_payload) if config_payload else None,
            location=PeerTelemetryLocation.from_payload(location_payload)
            if location_payload
            else None,
            connected_peers=connected_peers,
        )


@dataclass(frozen=True)
class NodeSmAcceleration:
    """Acceleration advert nested within :class:`NodeCapabilities`."""

    scalar: bool
    neon_sm3: bool
    neon_sm4: bool
    policy: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "NodeSmAcceleration":
        if not isinstance(payload, Mapping):
            raise TypeError("node capabilities acceleration payload must be an object")
        try:
            scalar = bool(payload.get("scalar", False))
            neon_sm3 = bool(payload.get("neon_sm3", False))
            neon_sm4 = bool(payload.get("neon_sm4", False))
        except (TypeError, ValueError) as exc:
            raise TypeError("node capabilities acceleration booleans must be bool") from exc
        policy_value = payload.get("policy", "unknown")
        if policy_value is None:
            policy = "unknown"
        else:
            policy = str(policy_value)
        return cls(scalar=scalar, neon_sm3=neon_sm3, neon_sm4=neon_sm4, policy=policy)


@dataclass(frozen=True)
class NodeSmCapabilities:
    """SM manifest nested within :class:`NodeCapabilities`."""

    enabled: bool
    default_hash: str
    allowed_signing: List[str]
    sm2_distid_default: str
    openssl_preview: bool
    acceleration: NodeSmAcceleration

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "NodeSmCapabilities":
        if not isinstance(payload, Mapping):
            raise TypeError("node capabilities `crypto.sm` payload must be an object")
        enabled = bool(payload.get("enabled", False))
        default_hash_value = payload.get("default_hash", "")
        default_hash = str(default_hash_value)
        allowed_payload = payload.get("allowed_signing", [])
        if not isinstance(allowed_payload, list):
            raise TypeError("node capabilities `allowed_signing` must be a list")
        allowed_signing = [str(item) for item in allowed_payload]
        sm2_distid_default = str(payload.get("sm2_distid_default", ""))
        openssl_preview = bool(payload.get("openssl_preview", False))
        accel_payload = payload.get("acceleration", {})
        acceleration = NodeSmAcceleration.from_payload(accel_payload)
        return cls(
            enabled=enabled,
            default_hash=default_hash,
            allowed_signing=allowed_signing,
            sm2_distid_default=sm2_distid_default,
            openssl_preview=openssl_preview,
            acceleration=acceleration,
        )


@dataclass(frozen=True)
class NodeCurveCapabilities:
    """Curve manifest nested within :class:`NodeCapabilities`."""

    registry_version: int
    allowed_curve_ids: List[int]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "NodeCurveCapabilities":
        if not isinstance(payload, Mapping):
            raise TypeError("node capabilities `crypto.curves` payload must be an object")
        raw_version = payload.get("registry_version", 1)
        try:
            registry_version = int(raw_version)
        except (TypeError, ValueError) as exc:
            raise TypeError("node curve capability `registry_version` must be numeric") from exc
        if registry_version <= 0:
            raise TypeError("node curve capability `registry_version` must be positive")
        allowed_payload = payload.get("allowed_curve_ids", [])
        if not isinstance(allowed_payload, list):
            raise TypeError("node curve capability `allowed_curve_ids` must be a list")
        allowed_curve_ids: List[int] = []
        for entry in allowed_payload:
            try:
                allowed_curve_ids.append(int(entry))
            except (TypeError, ValueError) as exc:
                raise TypeError(
                    "node curve capability `allowed_curve_ids` entries must be numeric"
                ) from exc
        return cls(registry_version=registry_version, allowed_curve_ids=allowed_curve_ids)


@dataclass(frozen=True)
class NodeCryptoCapabilities:
    """Crypto manifest nested within :class:`NodeCapabilities`."""

    sm: NodeSmCapabilities
    curves: NodeCurveCapabilities

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "NodeCryptoCapabilities":
        if not isinstance(payload, Mapping):
            raise TypeError("node capabilities `crypto` payload must be an object")
        sm_payload = payload.get("sm")
        if not isinstance(sm_payload, Mapping):
            raise TypeError("node capabilities `crypto.sm` payload must be an object")
        sm_caps = NodeSmCapabilities.from_payload(sm_payload)
        curves_payload = payload.get("curves", {})
        if not isinstance(curves_payload, Mapping):
            raise TypeError(
                "node capabilities `crypto.curves` payload must be an object when present"
            )
        curves_caps = NodeCurveCapabilities.from_payload(curves_payload)
        return cls(sm=sm_caps, curves=curves_caps)


@dataclass(frozen=True)
class NodeCapabilities:
    """Typed advert covering `/v1/node/capabilities`."""

    abi_version: int
    data_model_version: int
    crypto: Optional[NodeCryptoCapabilities]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "NodeCapabilities":
        if not isinstance(payload, Mapping):
            raise TypeError("node capabilities payload must be an object")
        try:
            abi_version = int(payload["abi_version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TypeError("node capabilities missing numeric `abi_version` field") from exc
        if abi_version <= 0:
            raise TypeError("node capabilities `abi_version` must be positive")
        try:
            data_model_version = int(payload["data_model_version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TypeError("node capabilities missing numeric `data_model_version` field") from exc
        if data_model_version <= 0:
            raise TypeError("node capabilities `data_model_version` must be positive")
        crypto_payload = payload.get("crypto")
        crypto_caps: Optional[NodeCryptoCapabilities]
        if crypto_payload is None:
            crypto_caps = None
        else:
            if not isinstance(crypto_payload, Mapping):
                raise TypeError("node capabilities `crypto` field must be an object when present")
            crypto_caps = NodeCryptoCapabilities.from_payload(crypto_payload)
        return cls(
            abi_version=abi_version,
            data_model_version=data_model_version,
            crypto=crypto_caps,
        )


@dataclass(frozen=True)
class NodeAdminSnapshot:
    """Aggregated evidence captured from `/v1/configuration`, `/v1/peers`, `/v1/time/*`, `/v1/telemetry/peers-info`, and `/v1/node/capabilities`."""

    configuration: ConfigurationSnapshot
    peers: List[PeerInfo]
    time_now: NetworkTimeSnapshot
    time_status: NetworkTimeStatus
    node_capabilities: NodeCapabilities
    telemetry_peers: Optional[List[PeerTelemetryInfo]] = None


@dataclass(frozen=True)
class PipelineDagSnapshot:
    """Deterministic DAG fingerprint snapshot in pipeline recovery payloads."""

    fingerprint_hex: str
    key_count: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PipelineDagSnapshot":
        if not isinstance(payload, Mapping):
            raise TypeError("pipeline DAG snapshot must be an object")
        fingerprint = payload.get("fingerprint")
        if not isinstance(fingerprint, str):
            raise TypeError("pipeline DAG snapshot missing string `fingerprint`")
        try:
            key_count = int(payload.get("key_count", 0))
        except (TypeError, ValueError) as exc:
            raise TypeError("pipeline DAG snapshot `key_count` must be numeric") from exc
        return cls(fingerprint_hex=fingerprint, key_count=key_count)


@dataclass(frozen=True)
class PipelineTxSnapshot:
    """Access summary for a transaction in a pipeline recovery sidecar."""

    hash_hex: str
    reads: List[str]
    writes: List[str]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PipelineTxSnapshot":
        if not isinstance(payload, Mapping):
            raise TypeError("pipeline transaction snapshot must be an object")
        hash_hex = payload.get("hash")
        if not isinstance(hash_hex, str):
            raise TypeError("pipeline transaction snapshot missing string `hash`")
        reads_value = payload.get("reads", [])
        writes_value = payload.get("writes", [])
        if not isinstance(reads_value, list) or not all(
            isinstance(item, str) for item in reads_value
        ):
            raise TypeError("pipeline transaction snapshot `reads` must be a list of strings")
        if not isinstance(writes_value, list) or not all(
            isinstance(item, str) for item in writes_value
        ):
            raise TypeError("pipeline transaction snapshot `writes` must be a list of strings")
        return cls(hash_hex=hash_hex, reads=list(reads_value), writes=list(writes_value))


@dataclass(frozen=True)
class PipelineRecoverySidecar:
    """Typed representation of `/v1/pipeline/recovery/{height}` responses."""

    format: str
    height: int
    dag: PipelineDagSnapshot
    txs: List[PipelineTxSnapshot]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PipelineRecoverySidecar":
        if not isinstance(payload, Mapping):
            raise TypeError("pipeline recovery payload must be an object")
        format_label = payload.get("format")
        if not isinstance(format_label, str):
            raise TypeError("pipeline recovery payload missing string `format`")
        try:
            height = int(payload.get("height", 0))
        except (TypeError, ValueError) as exc:
            raise TypeError("pipeline recovery `height` must be numeric") from exc
        dag_payload = payload.get("dag")
        if not isinstance(dag_payload, Mapping):
            raise TypeError("pipeline recovery payload missing object `dag`")
        txs_payload = payload.get("txs", [])
        if not isinstance(txs_payload, list):
            raise TypeError("pipeline recovery payload `txs` must be a list")
        dag = PipelineDagSnapshot.from_payload(dag_payload)
        txs = [PipelineTxSnapshot.from_payload(item) for item in txs_payload]
        return cls(format=format_label, height=height, dag=dag, txs=txs)


@dataclass(frozen=True)
class VerifiedCommittedTransaction:
    """A selected full output authenticated by a rooted consensus finality chain.

    Contract rejection schema hashes are canonical 64-character uppercase
    Norito hexadecimal strings.
    """

    proof_kind: str
    transaction_hash: str
    block_hash: str
    block_height: int
    output_hash: str
    network_id: str
    context_id: str
    promoted_checkpoint: bytes
    execution_commitment: Mapping[str, Any]
    executed_block_wire_hash: str
    executed_block_wire_len: int
    entrypoint_kind: str
    authority: Optional[str]
    signer_public_key_hex: Optional[str]
    metadata: Optional[Mapping[str, Any]]
    executable: Optional[Mapping[str, Any]]
    result_ok: bool
    rejection_code: Optional[str]
    rejection_message: Optional[str]
    contract_rejection: Optional[Mapping[str, Any]]
    batch_outcomes: Tuple[Mapping[str, Any], ...]
    committed_transaction: Mapping[str, Any]

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
    ) -> "VerifiedCommittedTransaction":
        if not isinstance(payload, Mapping):
            raise TypeError("verified committed transaction payload must be an object")
        required_fields = {
            "proof_kind",
            "transaction_hash",
            "block_hash",
            "block_height",
            "output_hash",
            "network_id",
            "context_id",
            "promoted_checkpoint",
            "execution_commitment",
            "executed_block_wire_hash",
            "executed_block_wire_len",
            "entrypoint_kind",
            "authority",
            "signer_public_key_hex",
            "metadata",
            "executable",
            "result_ok",
            "rejection_code",
            "rejection_message",
            "contract_rejection",
            "batch_outcomes",
            "committed_transaction",
        }
        if set(payload) != required_fields:
            raise ValueError(
                "verified committed transaction payload must contain exactly "
                + ", ".join(sorted(required_fields))
            )
        transaction_hash = _normalize_hash_hex(
            payload.get("transaction_hash"),
            "verified transaction hash",
        )
        block_hash = _normalize_hash_hex(
            payload.get("block_hash"),
            "verified carrier block hash",
        )
        output_hash = _normalize_hash_hex(
            payload.get("output_hash"),
            "verified transaction output hash",
        )
        block_height = _normalize_positive_int(
            payload.get("block_height"),
            "verified carrier block height",
            allow_zero=False,
        )
        network_id = _require_exact_non_empty_string(
            payload["network_id"], "verified network id"
        )
        context_id = _require_exact_non_empty_string(
            payload["context_id"], "verified native context id"
        )
        promoted_checkpoint = payload["promoted_checkpoint"]
        if type(promoted_checkpoint) is not bytes:
            raise TypeError("verified promoted_checkpoint must be exact immutable bytes")
        if not promoted_checkpoint or len(promoted_checkpoint) > 68 * 1024 * 1024:
            raise ValueError("verified promoted_checkpoint must contain 1..68 MiB")
        if payload["proof_kind"] != "selective-v1":
            raise ValueError("current selective proof_kind required")
        execution_commitment = payload["execution_commitment"]
        if not isinstance(execution_commitment, Mapping):
            raise TypeError("verified execution_commitment must be an object")
        executed_block_wire_hash = _normalize_hash_hex(
            payload["executed_block_wire_hash"], "verified executed wire hash"
        )
        executed_block_wire_len = _normalize_positive_int(
            payload["executed_block_wire_len"], "verified executed wire length", allow_zero=False
        )
        entrypoint_kind = payload.get("entrypoint_kind")
        if entrypoint_kind not in {
            "External",
            "SealedCommitment",
            "SealedReveal",
        }:
            raise ValueError("verified transaction entrypoint_kind is not recognized")
        authority_value = payload.get("authority")
        authority = (
            None
            if authority_value is None
            else _require_exact_non_empty_string(
                authority_value,
                "verified transaction authority",
            )
        )
        signer_value = payload.get("signer_public_key_hex")
        signer_public_key_hex = (
            None
            if signer_value is None
            else _normalize_hex_string(
                signer_value,
                "verified transaction signer public key",
            )
        )
        metadata_value = payload.get("metadata")
        if metadata_value is not None and not isinstance(metadata_value, Mapping):
            raise TypeError("verified transaction metadata must be an object or null")
        executable_value = payload.get("executable")
        if executable_value is not None and not isinstance(executable_value, Mapping):
            raise TypeError("verified transaction executable must be an object or null")
        result_ok = payload.get("result_ok")
        if not isinstance(result_ok, bool):
            raise TypeError("verified transaction result_ok must be a bool")
        rejection_code_value = payload.get("rejection_code")
        rejection_message_value = payload.get("rejection_message")
        if result_ok:
            if rejection_code_value is not None or rejection_message_value is not None:
                raise ValueError("successful verified transaction must omit rejection detail")
            rejection_code = None
            rejection_message = None
        else:
            rejection_code = _require_exact_non_empty_string(
                rejection_code_value,
                "verified transaction rejection code",
            )
            rejection_message = _require_exact_non_empty_string(
                rejection_message_value,
                "verified transaction rejection message",
            )
        if "contract_rejection" not in payload:
            raise ValueError("verified transaction contract_rejection field is required")
        contract_rejection_value = payload["contract_rejection"]
        if contract_rejection_value is None:
            contract_rejection: Optional[Mapping[str, Any]] = None
        else:
            if result_ok:
                raise ValueError(
                    "successful verified transaction must omit contract rejection detail"
                )
            if not isinstance(contract_rejection_value, Mapping):
                raise TypeError(
                    "verified transaction contract_rejection must be an object or null"
                )
            required_contract_fields = {"contract", "error_type", "schema_hash", "name", "code", "message"}
            if set(contract_rejection_value) != required_contract_fields:
                raise ValueError(
                    "verified transaction contract_rejection must contain exactly "
                    + ", ".join(sorted(required_contract_fields))
                )
            contract_name = _require_exact_non_empty_string(
                contract_rejection_value["contract"],
                "verified transaction contract rejection contract",
            )
            contract_error_type = _require_exact_non_empty_string(
                contract_rejection_value["error_type"],
                "verified transaction contract rejection error_type",
            )
            if not _canonical_contract_error_identity(contract_error_type):
                raise ValueError("verified transaction contract rejection error_type is not canonical")
            contract_schema_hash = contract_rejection_value["schema_hash"]
            if (
                not isinstance(contract_schema_hash, str)
                or re.fullmatch(r"[0-9A-F]{64}", contract_schema_hash) is None
                or int(contract_schema_hash[-2:], 16) & 1 != 1
            ):
                raise ValueError(
                    "verified transaction contract rejection schema_hash must be "
                    "exactly 32 canonical hash bytes encoded as uppercase hexadecimal"
                )
            contract_error_name = _require_exact_non_empty_string(
                contract_rejection_value["name"],
                "verified transaction contract rejection name",
            )
            if not _canonical_contract_error_variant(contract_error_name):
                raise ValueError("verified transaction contract rejection name is not canonical")
            contract_error_code_value = contract_rejection_value["code"]
            if isinstance(contract_error_code_value, bool) or not isinstance(
                contract_error_code_value, int
            ):
                raise TypeError(
                    "verified transaction contract rejection code must be an integer"
                )
            if not 0 < contract_error_code_value <= 0xFFFF_FFFF:
                raise ValueError(
                    "verified transaction contract rejection code must be a non-zero u32"
                )
            contract_error_code = contract_error_code_value
            contract_error_message = contract_rejection_value["message"]
            if contract_error_message is not None:
                try:
                    contract_error_message = ContractErrorMessage.from_payload({
                        "error_type": contract_error_type,
                        "code": contract_error_code,
                        "message": contract_error_message,
                    }).message
                except (TypeError, ValueError) as error:
                    raise TypeError(f"verified transaction contract rejection message: {error}") from error
            if rejection_code != contract_error_name:
                raise ValueError(
                    "verified transaction rejection_code must equal the "
                    "manifest-authenticated contract error name"
                )
            contract_rejection = {
                "contract": contract_name,
                "error_type": contract_error_type,
                "schema_hash": contract_schema_hash,
                "name": contract_error_name,
                "code": contract_error_code,
                "message": contract_error_message,
            }
        raw_batch_outcomes = payload.get("batch_outcomes")
        if not isinstance(raw_batch_outcomes, list):
            raise TypeError("verified transaction batch_outcomes must be an array")
        batch_outcomes: List[Mapping[str, Any]] = []
        for index, raw_outcome in enumerate(raw_batch_outcomes):
            if not isinstance(raw_outcome, Mapping):
                raise TypeError(f"verified batch outcome {index} must be an object")
            required_fields = {
            "proof_kind",
                "leg_index",
                "leg_id",
                "asset",
                "destination",
                "amount",
                "status",
                "rejection_code",
                "rejection_message",
            }
            if set(raw_outcome) != required_fields:
                raise ValueError(
                    f"verified batch outcome {index} must contain exactly "
                    + ", ".join(sorted(required_fields))
                )
            leg_index = _normalize_positive_int(
                raw_outcome["leg_index"],
                f"verified batch outcome {index} leg_index",
                allow_zero=True,
            )
            leg_id = _require_exact_non_empty_string(
                raw_outcome["leg_id"],
                f"verified batch outcome {index} leg_id",
            )
            asset = _require_exact_non_empty_string(
                raw_outcome["asset"],
                f"verified batch outcome {index} asset",
            )
            destination = _require_exact_non_empty_string(
                raw_outcome["destination"],
                f"verified batch outcome {index} destination",
            )
            amount = _require_exact_non_empty_string(
                raw_outcome["amount"],
                f"verified batch outcome {index} amount",
            )
            status = raw_outcome["status"]
            outcome_code = raw_outcome["rejection_code"]
            outcome_message = raw_outcome["rejection_message"]
            if status == "Applied":
                if outcome_code is not None or outcome_message is not None:
                    raise ValueError(
                        f"applied verified batch outcome {index} must omit rejection detail"
                    )
            elif status == "Rejected":
                outcome_code = _require_exact_non_empty_string(
                    outcome_code,
                    f"verified batch outcome {index} rejection_code",
                )
                outcome_message = _require_exact_non_empty_string(
                    outcome_message,
                    f"verified batch outcome {index} rejection_message",
                )
            else:
                raise ValueError(
                    f"verified batch outcome {index} status must be Applied or Rejected"
                )
            batch_outcomes.append(
                {
                    "leg_index": leg_index,
                    "leg_id": leg_id,
                    "asset": asset,
                    "destination": destination,
                    "amount": amount,
                    "status": status,
                    "rejection_code": outcome_code,
                    "rejection_message": outcome_message,
                }
            )
        committed = payload.get("committed_transaction")
        if not isinstance(committed, Mapping):
            raise TypeError("verified committed transaction record must be an object")
        return cls(
            proof_kind="selective-v1",
            transaction_hash=transaction_hash,
            block_hash=block_hash,
            block_height=block_height,
            output_hash=output_hash,
            network_id=network_id,
            context_id=context_id,
            promoted_checkpoint=promoted_checkpoint,
            execution_commitment=dict(execution_commitment),
            executed_block_wire_hash=executed_block_wire_hash,
            executed_block_wire_len=executed_block_wire_len,
            entrypoint_kind=entrypoint_kind,
            authority=authority,
            signer_public_key_hex=signer_public_key_hex,
            metadata=dict(metadata_value) if metadata_value is not None else None,
            executable=dict(executable_value) if executable_value is not None else None,
            result_ok=result_ok,
            rejection_code=rejection_code,
            rejection_message=rejection_message,
            contract_rejection=contract_rejection,
            batch_outcomes=tuple(batch_outcomes),
            committed_transaction=dict(committed),
        )


@dataclass(frozen=True)
class AccountPermissionRecord:
    """Account permission entry returned by `GET /v1/accounts/{account_id}/permissions`."""

    name: str
    payload: Any
    raw: Dict[str, Any]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "AccountPermissionRecord":
        if not isinstance(payload, Mapping):
            raise TypeError("account permission record must be an object")
        name = payload.get("name")
        if not isinstance(name, str):
            raise TypeError("account permission record missing string `name` field")
        permission_payload = _json_safe_value(payload.get("payload"))
        return cls(name=name, payload=permission_payload, raw=dict(payload))


# ---------------------------------------------------------------------------
# UAID portfolio & Space Directory helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UaidPortfolioAsset:
    asset_id: str
    asset_definition_id: str
    quantity: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "UaidPortfolioAsset":
        if not isinstance(payload, Mapping):
            raise TypeError("portfolio asset must be an object")
        _require_wire_fields(
            payload,
            required={"asset_id", "asset_definition_id", "quantity"},
            context="portfolio asset",
        )
        asset_id = _require_exact_non_empty_string(
            payload["asset_id"],
            "portfolio asset.asset_id",
        )
        definition_id = _require_exact_non_empty_string(
            payload["asset_definition_id"],
            "portfolio asset.asset_definition_id",
        )
        canonical_quantity = _canonical_quantity_text(
            payload["quantity"],
            "portfolio asset quantity",
        )
        return cls(
            asset_id=asset_id,
            asset_definition_id=definition_id,
            quantity=canonical_quantity,
        )


@dataclass(frozen=True)
class UaidPortfolioAccount:
    account_id: str
    label: Optional[str]
    assets: List[UaidPortfolioAsset]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "UaidPortfolioAccount":
        if not isinstance(payload, Mapping):
            raise TypeError("portfolio account must be an object")
        _require_wire_fields(
            payload,
            required={"account_id", "label", "assets"},
            context="portfolio account",
        )
        account_id = _normalize_exact_any_i105_account_id(
            payload["account_id"],
            "portfolio account.account_id",
        )
        label_value = payload["label"]
        label = (
            None
            if label_value is None
            else _require_exact_non_empty_string(label_value, "portfolio account.label")
        )
        assets_payload = payload["assets"]
        if not isinstance(assets_payload, list):
            raise TypeError("portfolio account `assets` must be a list")
        assets = [UaidPortfolioAsset.from_payload(item) for item in assets_payload]
        return cls(account_id=account_id, label=label, assets=assets)


@dataclass(frozen=True)
class UaidPortfolioDataspace:
    dataspace_id: int
    dataspace_alias: Optional[str]
    accounts: List[UaidPortfolioAccount]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "UaidPortfolioDataspace":
        if not isinstance(payload, Mapping):
            raise TypeError("portfolio dataspace must be an object")
        _require_wire_fields(
            payload,
            required={"dataspace_id", "dataspace_alias", "accounts"},
            context="portfolio dataspace",
        )
        dataspace_id = _require_u64(
            payload["dataspace_id"],
            "portfolio dataspace.dataspace_id",
        )
        alias_value = payload["dataspace_alias"]
        alias = (
            None
            if alias_value is None
            else _require_exact_non_empty_string(
                alias_value,
                "portfolio dataspace.dataspace_alias",
            )
        )
        accounts_payload = payload["accounts"]
        if not isinstance(accounts_payload, list):
            raise TypeError("portfolio dataspace `accounts` must be a list")
        accounts = [UaidPortfolioAccount.from_payload(item) for item in accounts_payload]
        return cls(dataspace_id=dataspace_id, dataspace_alias=alias, accounts=accounts)


@dataclass(frozen=True)
class UaidPortfolioSnapshot:
    uaid: str
    total_accounts: int
    total_positions: int
    dataspaces: List[UaidPortfolioDataspace]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "UaidPortfolioSnapshot":
        if not isinstance(payload, Mapping):
            raise TypeError("portfolio payload must be an object")
        _require_wire_fields(
            payload,
            required={"uaid", "totals", "dataspaces"},
            context="portfolio payload",
        )
        uaid = _normalize_uaid_literal(
            payload["uaid"],
            context="portfolio payload.uaid",
        )
        totals = payload["totals"]
        if not isinstance(totals, Mapping):
            raise TypeError("portfolio payload `totals` must be an object")
        _require_wire_fields(
            totals,
            required={"accounts", "positions"},
            context="portfolio payload.totals",
        )
        accounts = _require_u64(totals["accounts"], "portfolio payload.totals.accounts")
        positions = _require_u64(
            totals["positions"],
            "portfolio payload.totals.positions",
        )
        dataspaces_payload = payload["dataspaces"]
        if not isinstance(dataspaces_payload, list):
            raise TypeError("portfolio payload `dataspaces` must be a list")
        dataspaces = [UaidPortfolioDataspace.from_payload(item) for item in dataspaces_payload]
        return cls(
            uaid=uaid,
            total_accounts=accounts,
            total_positions=positions,
            dataspaces=dataspaces,
        )


@dataclass(frozen=True)
class UaidBindingsSlice:
    dataspace_id: int
    dataspace_alias: Optional[str]
    accounts: List[str]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "UaidBindingsSlice":
        if not isinstance(payload, Mapping):
            raise TypeError("bindings slice must be an object")
        _require_wire_fields(
            payload,
            required={"dataspace_id", "dataspace_alias", "accounts"},
            context="bindings slice",
        )
        dataspace_id = _require_u64(
            payload["dataspace_id"],
            "bindings slice.dataspace_id",
        )
        alias_value = payload["dataspace_alias"]
        alias = (
            None
            if alias_value is None
            else _require_exact_non_empty_string(
                alias_value,
                "bindings slice.dataspace_alias",
            )
        )
        accounts_value = payload["accounts"]
        if not isinstance(accounts_value, list):
            raise TypeError("bindings slice `accounts` must be a list")
        accounts: List[str] = []
        for index, literal in enumerate(accounts_value):
            accounts.append(
                _normalize_exact_any_i105_account_id(
                    literal,
                    f"bindings slice.accounts[{index}]",
                )
            )
        return cls(dataspace_id=dataspace_id, dataspace_alias=alias, accounts=accounts)


@dataclass(frozen=True)
class UaidBindingsSnapshot:
    uaid: str
    dataspaces: List[UaidBindingsSlice]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "UaidBindingsSnapshot":
        if not isinstance(payload, Mapping):
            raise TypeError("bindings payload must be an object")
        _require_wire_fields(
            payload,
            required={"uaid", "dataspaces"},
            context="bindings payload",
        )
        uaid = _normalize_uaid_literal(
            payload["uaid"],
            context="bindings payload.uaid",
        )
        dataspaces_payload = payload["dataspaces"]
        if not isinstance(dataspaces_payload, list):
            raise TypeError("bindings payload `dataspaces` must be a list")
        dataspaces = [UaidBindingsSlice.from_payload(item) for item in dataspaces_payload]
        return cls(uaid=uaid, dataspaces=dataspaces)


@dataclass(frozen=True)
class SpaceDirectoryManifestLifecycle:
    activated_epoch: Optional[int]
    expired_epoch: Optional[int]
    revocation_epoch: Optional[int]
    revocation_reason: Optional[str]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SpaceDirectoryManifestLifecycle":
        if not isinstance(payload, Mapping):
            raise TypeError("manifest lifecycle must be an object")
        _require_wire_fields(
            payload,
            required={"activated_epoch", "expired_epoch", "revocation"},
            context="manifest lifecycle",
        )
        activated = (
            None
            if payload["activated_epoch"] is None
            else _require_u64(
                payload["activated_epoch"],
                "lifecycle.activated_epoch",
            )
        )
        expired = (
            None
            if payload["expired_epoch"] is None
            else _require_u64(
                payload["expired_epoch"],
                "lifecycle.expired_epoch",
            )
        )
        revocation = payload["revocation"]
        revocation_epoch: Optional[int] = None
        revocation_reason: Optional[str] = None
        if revocation is not None:
            if not isinstance(revocation, Mapping):
                raise TypeError("lifecycle.revocation must be an object when present")
            _require_wire_fields(
                revocation,
                required={"epoch", "reason"},
                context="lifecycle.revocation",
            )
            revocation_epoch = _require_u64(
                revocation["epoch"],
                "lifecycle.revocation.epoch",
            )
            reason_value = revocation["reason"]
            if reason_value is not None and not isinstance(reason_value, str):
                raise TypeError("lifecycle.revocation.reason must be a string when present")
            revocation_reason = reason_value
        return cls(
            activated_epoch=activated,
            expired_epoch=expired,
            revocation_epoch=revocation_epoch,
            revocation_reason=revocation_reason,
        )


@dataclass(frozen=True)
class SpaceDirectoryManifestRecord:
    dataspace_id: int
    dataspace_alias: Optional[str]
    manifest_hash: str
    status: str
    lifecycle: SpaceDirectoryManifestLifecycle
    accounts: List[str]
    manifest: Mapping[str, Any]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SpaceDirectoryManifestRecord":
        if not isinstance(payload, Mapping):
            raise TypeError("manifest record must be an object")
        _require_wire_fields(
            payload,
            required={
                "dataspace_id",
                "dataspace_alias",
                "manifest_hash",
                "status",
                "lifecycle",
                "accounts",
                "manifest",
            },
            context="manifest record",
        )
        dataspace_id = _require_u64(payload["dataspace_id"], "manifest record.dataspace_id")
        alias_value = payload["dataspace_alias"]
        alias = (
            None
            if alias_value is None
            else _require_exact_non_empty_string(
                alias_value,
                "manifest record.dataspace_alias",
            )
        )
        manifest_hash = _require_exact_non_empty_string(
            payload["manifest_hash"],
            "manifest record.manifest_hash",
        )
        if re.fullmatch(r"[0-9a-f]{64}", manifest_hash) is None:
            raise ValueError("manifest record.manifest_hash must be 64 lowercase hex characters")
        status = _require_exact_non_empty_string(payload["status"], "manifest record.status")
        if status not in {"Pending", "Active", "Expired", "Revoked"}:
            raise ValueError("manifest record.status is not a first-release status")
        lifecycle_payload = payload["lifecycle"]
        lifecycle = SpaceDirectoryManifestLifecycle.from_payload(lifecycle_payload)
        accounts_value = payload["accounts"]
        if not isinstance(accounts_value, list):
            raise TypeError("manifest record `accounts` must be a list")
        accounts: List[str] = []
        for index, literal in enumerate(accounts_value):
            accounts.append(
                _normalize_exact_any_i105_account_id(
                    literal,
                    f"manifest record.accounts[{index}]",
                )
            )
        manifest = _parse_space_directory_manifest(
            payload["manifest"],
            context="manifest record.manifest",
        )
        if manifest["dataspace"] != dataspace_id:
            raise ValueError("manifest record dataspace differs from its manifest")
        return cls(
            dataspace_id=dataspace_id,
            dataspace_alias=alias,
            manifest_hash=manifest_hash,
            status=status,
            lifecycle=lifecycle,
            accounts=accounts,
            manifest=manifest,
        )


@dataclass(frozen=True)
class TriggerRecord:
    """Trigger definition returned by trigger listing/query endpoints."""

    id: str
    action: Dict[str, Any]
    metadata: Dict[str, Any]
    raw: Dict[str, Any]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "TriggerRecord":
        if not isinstance(payload, Mapping):
            raise TypeError("trigger record must be an object")
        trigger_id = payload.get("id")
        if not isinstance(trigger_id, str):
            raise TypeError("trigger record missing string `id` field")
        action_payload = payload.get("action", {})
        if not isinstance(action_payload, Mapping):
            raise TypeError("trigger record `action` must be an object")
        metadata_payload = payload.get("metadata", {})
        if metadata_payload is None:
            metadata: Dict[str, Any] = {}
        elif isinstance(metadata_payload, Mapping):
            metadata = dict(metadata_payload)
        else:
            raise TypeError("trigger record `metadata` must be an object when present")
        return cls(
            id=trigger_id,
            action=dict(action_payload),
            metadata=metadata,
            raw=dict(payload),
        )


@dataclass(frozen=True)
class TriggerListPage:
    """Paginated trigger listing."""

    items: List[TriggerRecord]
    total: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "TriggerListPage":
        if not isinstance(payload, Mapping):
            raise TypeError("trigger list payload must be an object")
        items_payload = payload.get("items", [])
        if items_payload is None:
            items_payload = []
        if not isinstance(items_payload, list):
            raise TypeError("trigger list `items` must be a list")
        try:
            total = int(payload.get("total", len(items_payload)))
        except (TypeError, ValueError) as exc:
            raise TypeError("trigger list `total` must be numeric") from exc
        items = [TriggerRecord.from_payload(entry) for entry in items_payload]
        return cls(items=items, total=total)


@dataclass(frozen=True)
class TriggerMutationResponse:
    """Governance draft emitted when triggers are registered or deleted."""

    ok: bool
    tx_instructions: List[RuntimeInstruction]
    trigger_id: Optional[str]
    proposal_id: Optional[str]
    accepted: Optional[bool]
    message: Optional[str]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "TriggerMutationResponse":
        if not isinstance(payload, Mapping):
            raise TypeError("trigger mutation response must be an object")
        ok_value = payload.get("ok")
        if not isinstance(ok_value, bool):
            raise TypeError("trigger mutation response missing boolean `ok` field")
        trigger_id_field = payload.get("trigger_id")
        if trigger_id_field is None:
            trigger_id: Optional[str] = None
        else:
            trigger_id = _require_non_empty_string(
                trigger_id_field, "trigger mutation response `trigger_id`"
            )
        proposal_field = payload.get("proposal_id")
        if proposal_field is None:
            proposal_id: Optional[str] = None
        else:
            proposal_id = _require_non_empty_string(
                proposal_field, "trigger mutation response `proposal_id`"
            )
        instructions_payload = payload.get("tx_instructions")
        if instructions_payload is None:
            instructions_payload = []
        if not isinstance(instructions_payload, list):
            raise TypeError("trigger mutation response `tx_instructions` must be a list")
        instructions = [RuntimeInstruction.from_payload(entry) for entry in instructions_payload]
        accepted_field = payload.get("accepted")
        accepted = None
        if accepted_field is not None:
            if not isinstance(accepted_field, bool):
                raise TypeError("trigger mutation response `accepted` must be boolean when present")
            accepted = accepted_field
        message_field = payload.get("message")
        if message_field is None:
            message_field = payload.get("error")
        if message_field is None:
            message_field = payload.get("reason")
        message = None
        if message_field is not None:
            message = str(message_field).strip()
            if not message:
                message = None
        return cls(
            ok=ok_value,
            tx_instructions=instructions,
            trigger_id=trigger_id,
            proposal_id=proposal_id,
            accepted=accepted,
            message=message,
        )


@dataclass(frozen=True)
class TriggerCompletionSummary:
    """One trigger execution step attached to a transaction receipt or history row."""

    trigger_id: str
    trigger_execution_hash: str
    step_index: int
    outcome: str
    message: Optional[str]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "TriggerCompletionSummary":
        if not isinstance(payload, Mapping):
            raise TypeError("trigger completion summary must be an object")
        trigger_id = _require_non_empty_string(
            payload.get("trigger_id"),
            "trigger completion `trigger_id`",
        )
        execution_hash = _require_non_empty_string(
            payload.get("trigger_execution_hash"),
            "trigger completion `trigger_execution_hash`",
        )
        step_index = payload.get("step_index")
        if (
            isinstance(step_index, bool)
            or not isinstance(step_index, int)
            or not 0 <= step_index <= 0xFFFFFFFF
        ):
            raise TypeError("trigger completion `step_index` must be a u32")
        outcome = payload.get("outcome")
        if outcome not in {"Success", "Failure"}:
            raise TypeError("trigger completion `outcome` must be Success or Failure")
        message = payload.get("message")
        if message is not None and not isinstance(message, str):
            raise TypeError("trigger completion `message` must be a string when present")
        return cls(
            trigger_id=trigger_id,
            trigger_execution_hash=execution_hash,
            step_index=step_index,
            outcome=outcome,
            message=message,
        )


@dataclass(frozen=True)
class TriggerCompletionRecord:
    """Persisted or reconstructed trigger completion evidence."""

    block_height: int
    entrypoint_index: Optional[int]
    completion: TriggerCompletionSummary
    source: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "TriggerCompletionRecord":
        if not isinstance(payload, Mapping):
            raise TypeError("trigger completion record must be an object")
        block_height = payload.get("block_height")
        if (
            isinstance(block_height, bool)
            or not isinstance(block_height, int)
            or not 0 <= block_height <= 0xFFFFFFFFFFFFFFFF
        ):
            raise TypeError("trigger completion record `block_height` must be a u64")
        entrypoint_index = payload.get("entrypoint_index")
        if entrypoint_index is not None and (
            isinstance(entrypoint_index, bool)
            or not isinstance(entrypoint_index, int)
            or not 0 <= entrypoint_index <= 0xFFFFFFFFFFFFFFFF
        ):
            raise TypeError(
                "trigger completion record `entrypoint_index` must be a u64 when present"
            )
        completion = TriggerCompletionSummary.from_payload(
            payload.get("completion")  # type: ignore[arg-type]
        )
        source = _require_non_empty_string(
            payload.get("source"),
            "trigger completion record `source`",
        )
        if source != "execution_output":
            raise TypeError("trigger completion record `source` must be execution_output")
        return cls(
            block_height=block_height,
            entrypoint_index=entrypoint_index,
            completion=completion,
            source=source,
        )


@dataclass(frozen=True)
class TriggerCompletionList:
    """Typed response from `/v1/triggers/completed`."""

    latest_height: int
    from_height: int
    to_height: int
    scanned_blocks: int
    limit: int
    completions: Tuple[TriggerCompletionRecord, ...]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "TriggerCompletionList":
        if not isinstance(payload, Mapping):
            raise TypeError("trigger completion list must be an object")

        def uint(name: str) -> int:
            value = payload.get(name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= 0xFFFFFFFFFFFFFFFF
            ):
                raise TypeError(f"trigger completion list `{name}` must be a u64")
            return value

        raw_completions = payload.get("completions")
        if not isinstance(raw_completions, list):
            raise TypeError("trigger completion list `completions` must be a list")
        return cls(
            latest_height=uint("latest_height"),
            from_height=uint("from_height"),
            to_height=uint("to_height"),
            scanned_blocks=uint("scanned_blocks"),
            limit=uint("limit"),
            completions=tuple(
                TriggerCompletionRecord.from_payload(item) for item in raw_completions
            ),
        )


@dataclass(frozen=True)
class SumeragiEvidencePenaltyDetails:
    """Canonical block height that applied the consensus penalty."""

    height: int


@dataclass(frozen=True)
class SumeragiEvidencePendingPenaltyStatus:
    """Penalty lifecycle state for evidence awaiting a committed outcome."""

    status: Literal["pending"]
    details: None


@dataclass(frozen=True)
class SumeragiEvidenceAppliedPenaltyStatus:
    """Penalty lifecycle state for evidence applied in a committed block."""

    status: Literal["applied"]
    details: SumeragiEvidencePenaltyDetails


SumeragiEvidencePenaltyStatus = Union[
    SumeragiEvidencePendingPenaltyStatus,
    SumeragiEvidenceAppliedPenaltyStatus,
]


def _parse_sumeragi_evidence_penalty_status(
    payload: Any,
) -> SumeragiEvidencePenaltyStatus:
    context = "sumeragi evidence penalty_status"
    if not isinstance(payload, Mapping):
        raise TypeError(f"{context} must be an object")
    _require_wire_fields(
        payload,
        required=("status", "details"),
        context=context,
    )
    status = payload["status"]
    if not isinstance(status, str):
        raise TypeError(f"{context}.status must be a string")
    if status == "pending":
        if payload["details"] is not None:
            raise TypeError(f"{context}.details must be null when status is pending")
        return SumeragiEvidencePendingPenaltyStatus(status="pending", details=None)
    if status != "applied":
        raise ValueError(f"{context}.status must be pending or applied")
    details = payload["details"]
    if not isinstance(details, Mapping):
        raise TypeError(f"{context}.details must be an object")
    _require_wire_fields(
        details,
        required=("height",),
        context=f"{context}.details",
    )
    typed_details = SumeragiEvidencePenaltyDetails(
        height=_require_u64(details["height"], f"{context}.details.height")
    )
    return SumeragiEvidenceAppliedPenaltyStatus(
        status="applied",
        details=typed_details,
    )


@dataclass(frozen=True)
class SumeragiEvidenceOffender:
    """Original signer index and peer resolved from authenticated historical state."""

    signer: int
    peer_id: str


@dataclass(frozen=True)
class SumeragiEvidenceRecord:
    """Exact native evidence audit projection returned by `/v1/sumeragi/evidence`."""

    kind: Literal["NativeSumeragiEvidence"]
    class_: Literal["proposal", "phase_vote", "timeout_vote", "invalid_proposal", "conflicting_certificates"]
    instance: str
    height: int
    epoch: int
    context_id: str
    authority_generation: str
    offenders: Tuple[SumeragiEvidenceOffender, ...]
    safety_violation: bool
    native_frame_hash: str
    recorded_height: int
    recorded_view: int
    recorded_ms: int
    consensus_admitted_height: int
    penalty_status: SumeragiEvidencePenaltyStatus

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SumeragiEvidenceRecord":
        if not isinstance(payload, Mapping):
            raise TypeError("sumeragi evidence record must be an object")
        context = "sumeragi evidence record"
        _require_wire_fields(payload, required=(
            "kind", "class", "instance", "height", "epoch", "context_id",
            "authority_generation", "offenders", "safety_violation", "native_frame_hash",
            "recorded_height", "recorded_view", "recorded_ms", "consensus_admitted_height", "penalty_status",
        ), context=context)
        if payload["kind"] != "NativeSumeragiEvidence":
            raise ValueError(f"{context}.kind must be NativeSumeragiEvidence")
        evidence_class = payload["class"]
        if not isinstance(evidence_class, str) or evidence_class not in {
            "proposal", "phase_vote", "timeout_vote", "invalid_proposal", "conflicting_certificates",
        }:
            raise ValueError(f"{context}.class must identify a native signed artifact class")

        def hash32(field_name: str) -> str:
            value = payload[field_name]
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ValueError(f"{context}.{field_name} must be exactly 32 lowercase hexadecimal bytes")
            return value

        raw_offenders = payload["offenders"]
        # Different-view CommitQC conflicts do not attribute individual signers.
        permits_unattributed_safety_violation = (
            evidence_class == "conflicting_certificates"
            and payload["safety_violation"] is True
        )
        if (
            not isinstance(raw_offenders, list)
            or len(raw_offenders) > 1024
            or (not raw_offenders and not permits_unattributed_safety_violation)
        ):
            raise ValueError(
                f"{context}.offenders must contain between 1 and 1024 entries, "
                "or be empty for a conflicting-certificate safety violation"
            )
        offenders = []
        peers: set[str] = set()
        previous_signer = -1
        for index, offender in enumerate(raw_offenders):
            offender_context = f"{context}.offenders[{index}]"
            if not isinstance(offender, Mapping):
                raise TypeError(f"{offender_context} must be an object")
            _require_wire_fields(offender, required=("signer", "peer_id"), context=offender_context)
            signer = _require_u64(offender["signer"], f"{offender_context}.signer")
            if signer > 1023 or signer <= previous_signer:
                raise ValueError(f"{offender_context}.signer must increase strictly within 0..1023")
            peer_id = offender["peer_id"]
            # This checks the canonical BLS-normal literal shape, not cryptographic admission.
            if not isinstance(peer_id, str) or re.fullmatch(r"ea0130[0-9A-F]{96}", peer_id) is None:
                raise ValueError(f"{offender_context}.peer_id must be a canonical BLS-normal public key")
            if peer_id in peers:
                raise ValueError(f"{offender_context}.peer_id must be unique")
            peers.add(peer_id)
            previous_signer = signer
            offenders.append(SumeragiEvidenceOffender(signer, peer_id))
        safety_violation = payload["safety_violation"]
        if not isinstance(safety_violation, bool):
            raise TypeError(f"{context}.safety_violation must be a boolean")
        return cls(
            kind="NativeSumeragiEvidence", class_=evidence_class,
            instance=hash32("instance"), height=_require_u64(payload["height"], f"{context}.height"),
            epoch=_require_u64(payload["epoch"], f"{context}.epoch"),
            context_id=hash32("context_id"), authority_generation=hash32("authority_generation"),
            offenders=tuple(offenders), safety_violation=safety_violation, native_frame_hash=hash32("native_frame_hash"),
            recorded_height=_require_u64(payload["recorded_height"], f"{context}.recorded_height"),
            recorded_view=_require_u64(payload["recorded_view"], f"{context}.recorded_view"),
            recorded_ms=_require_u64(payload["recorded_ms"], f"{context}.recorded_ms"),
            consensus_admitted_height=_require_u64(payload["consensus_admitted_height"], f"{context}.consensus_admitted_height"),
            penalty_status=_parse_sumeragi_evidence_penalty_status(payload["penalty_status"]),
        )


@dataclass(frozen=True)
class SumeragiEvidenceListPage:
    """Paginated evidence snapshot from `/v1/sumeragi/evidence`."""

    items: List[SumeragiEvidenceRecord]
    total: int

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> "SumeragiEvidenceListPage":
        if not isinstance(payload, Mapping):
            raise TypeError("sumeragi evidence payload must be an object")
        _require_wire_fields(
            payload,
            required=("total", "items"),
            context="sumeragi evidence payload",
        )
        items_payload = payload["items"]
        if not isinstance(items_payload, list):
            raise TypeError("sumeragi evidence `items` must be a list")
        total = _require_u64(payload["total"], "sumeragi evidence payload.total")
        items = [SumeragiEvidenceRecord.from_payload(entry) for entry in items_payload]
        if len(items) > limit:
            raise ValueError(
                f"sumeragi evidence payload.items must contain at most {limit} records"
            )
        if total < len(items):
            raise ValueError(
                "sumeragi evidence payload.total must cover the returned items"
            )
        if items and total < offset + len(items):
            raise ValueError(
                "sumeragi evidence payload.total must cover offset plus returned items"
            )
        return cls(items=items, total=total)


_MAX_NATIVE_AMX_GROUP_SOURCES = 4096


def _required_field(payload: Mapping[str, Any], field_name: str, context: str) -> Any:
    if field_name not in payload:
        raise TypeError(f"{context} is missing required `{field_name}` field")
    return payload[field_name]


def _strict_exact_fields(payload: Mapping[str, Any], fields: Iterable[str], context: str) -> None:
    expected = set(fields)
    unknown = sorted(set(payload).difference(expected))
    if unknown:
        raise ValueError(f"{context} contains unknown field `{unknown[0]}`")
    missing = sorted(expected.difference(payload))
    if missing:
        raise TypeError(f"{context} is missing required `{missing[0]}` field")


def _strict_uint(payload: Mapping[str, Any], field_name: str, bits: int, context: str) -> int:
    value = _required_field(payload, field_name, context)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{context} `{field_name}` must be an unsigned integer")
    maximum = (1 << bits) - 1
    if value < 0 or value > maximum:
        raise ValueError(f"{context} `{field_name}` must be between 0 and {maximum}")
    return value


def _strict_nonempty_string(payload: Mapping[str, Any], field_name: str, context: str) -> str:
    value = _required_field(payload, field_name, context)
    if not isinstance(value, str) or value.strip() == "":
        raise TypeError(f"{context} `{field_name}` must be a non-empty string")
    return value


def _crc16_ccitt_false(value: bytes) -> int:
    crc = 0xFFFF
    for byte in value:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _strict_hash_literal(payload: Mapping[str, Any], field_name: str, context: str) -> str:
    value = _required_field(payload, field_name, context)
    if not isinstance(value, str):
        raise TypeError(f"{context} `{field_name}` must be a canonical hash literal")
    match = re.fullmatch(r"hash:([0-9A-F]{64})#([0-9A-F]{4})", value)
    if match is None:
        raise ValueError(
            f"{context} `{field_name}` must use canonical `hash:<uppercase hex>#<CRC16>` syntax"
        )
    body, checksum = match.groups()
    expected = _crc16_ccitt_false(f"hash:{body}".encode("ascii"))
    if int(checksum, 16) != expected:
        raise ValueError(f"{context} `{field_name}` hash checksum mismatch")
    if int(body[-2:], 16) & 1 == 0:
        raise ValueError(f"{context} `{field_name}` has an invalid Iroha hash marker bit")
    return value

def _strict_nexus_lane_config(value: Any, context: str) -> Dict[str, Any]:
    return _strict_nexus_lane_config_impl(value, context, _strict_exact_fields, _strict_uint, _strict_nonempty_string)


_SUMERAGI_EVIDENCE_COUNT_JSON_MAX_BYTES = 1 * 1024
_SUMERAGI_EVIDENCE_LIST_JSON_MAX_BYTES = 1 * 1024 * 1024


@dataclass(frozen=True)
class SumeragiParamsSnapshot:
    """On-chain Sumeragi parameter snapshot from `/v1/sumeragi/params`."""

    block_cadence_ms: int
    max_clock_drift_ms: int
    chain_height: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SumeragiParamsSnapshot":
        """Validate exactly the served fields; any other field fails closed."""
        if not isinstance(payload, Mapping):
            raise TypeError("sumeragi params payload must be an object")
        fields = ("block_cadence_ms", "max_clock_drift_ms", "chain_height")
        unknown = sorted(set(payload) - set(fields))
        if unknown:
            raise TypeError(f"sumeragi params contain unsupported fields: {', '.join(unknown)}")
        values = {}
        for name in fields:
            value = payload.get(name)
            if type(value) is not int or not 0 <= value < (1 << 64):
                raise TypeError(f"sumeragi params `{name}` must be an unsigned 64-bit integer")
            values[name] = value
        if values["block_cadence_ms"] == 0:
            raise TypeError("sumeragi params `block_cadence_ms` must be nonzero")
        return cls(**values)


@dataclass(frozen=True)
class SumeragiEvidenceCount:
    """Evidence store size from `/v1/sumeragi/evidence/count`."""

    count: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SumeragiEvidenceCount":
        if not isinstance(payload, Mapping):
            raise TypeError("evidence count payload must be an object")
        _require_wire_fields(
            payload,
            required=("count",),
            context="sumeragi evidence count payload",
        )
        return cls(
            count=_require_u64(payload["count"], "sumeragi evidence count payload.count")
        )


@dataclass(frozen=True)
class RuntimeUpgradeCounters:
    """Lifecycle counters returned by `/v1/runtime/metrics`."""

    proposed: int
    activated: int
    canceled: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeUpgradeCounters":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime upgrade counters payload must be an object")
        try:
            proposed = int(payload.get("proposed", 0))
            activated = int(payload.get("activated", 0))
            canceled = int(payload.get("canceled", 0))
        except (TypeError, ValueError) as exc:
            raise TypeError("runtime upgrade counter values must be numeric") from exc
        return cls(proposed=proposed, activated=activated, canceled=canceled)


@dataclass(frozen=True)
class RuntimeMetrics:
    """Summary metrics for runtime upgrades."""

    abi_version: int
    upgrade_events_total: RuntimeUpgradeCounters

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeMetrics":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime metrics payload must be an object")
        try:
            abi_version = int(payload["abi_version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TypeError("runtime metrics `abi_version` must be numeric") from exc
        counters_payload = payload.get("upgrade_events_total", {})
        counters = RuntimeUpgradeCounters.from_payload(
            counters_payload if isinstance(counters_payload, Mapping) else {}
        )
        return cls(abi_version=abi_version, upgrade_events_total=counters)


@dataclass(frozen=True)
class RuntimeAbiActive:
    """Active ABI version advertised by `/v1/runtime/abi/active`."""

    abi_version: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeAbiActive":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime ABI active payload must be an object")
        try:
            abi_version = int(payload["abi_version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TypeError("runtime ABI active missing numeric `abi_version` field") from exc
        return cls(abi_version=abi_version)


@dataclass(frozen=True)
class RuntimeAbiHash:
    """Canonical ABI hash summary from `/v1/runtime/abi/hash`."""

    policy: str
    abi_hash_hex: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeAbiHash":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime ABI hash payload must be an object")
        policy = payload.get("policy")
        abi_hash_hex = payload.get("abi_hash_hex")
        if not isinstance(policy, str) or not isinstance(abi_hash_hex, str):
            raise TypeError(
                "runtime ABI hash payload missing string `policy`/`abi_hash_hex` fields"
            )
        return cls(policy=policy, abi_hash_hex=abi_hash_hex)


@dataclass(frozen=True)
class RuntimeUpgradeStatus:
    """Lifecycle status for a runtime upgrade record."""

    kind: str
    activated_height: Optional[int] = None

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeUpgradeStatus":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime upgrade status payload must be an object")
        if len(payload) != 1:
            raise TypeError("runtime upgrade status payload must contain exactly one variant")
        variant, value = next(iter(payload.items()))
        if variant == "Proposed":
            return cls(kind="Proposed")
        if variant == "Canceled":
            return cls(kind="Canceled")
        if variant == "ActivatedAt":
            if value is None:
                raise TypeError("runtime upgrade status `ActivatedAt` requires a height value")
            try:
                height = int(value)
            except (TypeError, ValueError) as exc:
                raise TypeError(
                    "runtime upgrade status `ActivatedAt` height must be numeric"
                ) from exc
            if height < 0:
                raise ValueError("runtime upgrade status `ActivatedAt` height must be non-negative")
            return cls(kind="ActivatedAt", activated_height=height)
        raise TypeError(f"unknown runtime upgrade status variant `{variant}`")


def _coerce_int_list(values: Any, label: str) -> List[int]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise TypeError(f"{label} must be a list")
    result: List[int] = []
    for entry in values:
        try:
            number = int(entry)
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{label} entries must be integers") from exc
        if number < 0:
            raise ValueError(f"{label} entries must be non-negative")
        result.append(number)
    return result


def _validate_runtime_upgrade_manifest_fields(
    *,
    abi_version: int,
    added_syscalls: List[int],
    added_pointer_types: List[int],
    start_height: int,
    end_height: int,
) -> None:
    if abi_version != 1:
        raise ValueError("runtime upgrade manifest `abi_version` must be 1 in the first release")
    if added_syscalls:
        raise ValueError(
            "runtime upgrade manifest `added_syscalls` must be empty in the first release"
        )
    if added_pointer_types:
        raise ValueError(
            "runtime upgrade manifest `added_pointer_types` must be empty in the first release"
        )
    if end_height <= start_height:
        raise ValueError(
            "runtime upgrade manifest `end_height` must be greater than `start_height`"
        )


@dataclass(frozen=True)
class RuntimeUpgradeManifest:
    """Runtime upgrade manifest advertised by `/v1/runtime/upgrades`."""

    name: str
    description: str
    abi_version: int
    abi_hash_hex: str
    added_syscalls: List[int]
    added_pointer_types: List[int]
    start_height: int
    end_height: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeUpgradeManifest":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime upgrade manifest payload must be an object")
        name = payload.get("name")
        description = payload.get("description")
        if not isinstance(name, str) or not isinstance(description, str):
            raise TypeError("runtime upgrade manifest requires string `name` and `description`")
        abi_hash_hex = payload.get("abi_hash")
        if not isinstance(abi_hash_hex, str):
            raise TypeError("runtime upgrade manifest missing string `abi_hash` field")
        abi_version_raw = payload.get("abi_version")
        start_height_raw = payload.get("start_height")
        end_height_raw = payload.get("end_height")
        if abi_version_raw is None or start_height_raw is None or end_height_raw is None:
            raise TypeError("runtime upgrade manifest missing numeric fields")
        try:
            abi_version = int(abi_version_raw)
            start_height = int(start_height_raw)
            end_height = int(end_height_raw)
        except (TypeError, ValueError) as exc:
            raise TypeError("runtime upgrade manifest numeric fields must be integers") from exc
        added_syscalls = _coerce_int_list(
            payload.get("added_syscalls", []), "runtime upgrade manifest `added_syscalls`"
        )
        added_pointer_types = _coerce_int_list(
            payload.get("added_pointer_types", []), "runtime upgrade manifest `added_pointer_types`"
        )
        _validate_runtime_upgrade_manifest_fields(
            abi_version=abi_version,
            added_syscalls=added_syscalls,
            added_pointer_types=added_pointer_types,
            start_height=start_height,
            end_height=end_height,
        )
        return cls(
            name=name,
            description=description,
            abi_version=abi_version,
            abi_hash_hex=abi_hash_hex,
            added_syscalls=added_syscalls,
            added_pointer_types=added_pointer_types,
            start_height=start_height,
            end_height=end_height,
        )

    def to_payload(self) -> Dict[str, Any]:
        """Return a JSON-serialisable payload suitable for Torii POST requests."""

        _validate_runtime_upgrade_manifest_fields(
            abi_version=self.abi_version,
            added_syscalls=self.added_syscalls,
            added_pointer_types=self.added_pointer_types,
            start_height=self.start_height,
            end_height=self.end_height,
        )
        return {
            "name": self.name,
            "description": self.description,
            "abi_version": self.abi_version,
            "abi_hash": self.abi_hash_hex,
            "added_syscalls": list(self.added_syscalls),
            "added_pointer_types": list(self.added_pointer_types),
            "start_height": self.start_height,
            "end_height": self.end_height,
        }


@dataclass(frozen=True)
class RuntimeUpgradeRecord:
    """Individual runtime upgrade record maintained by the node."""

    manifest: RuntimeUpgradeManifest
    status: RuntimeUpgradeStatus
    proposer: str
    created_height: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeUpgradeRecord":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime upgrade record payload must be an object")
        manifest_payload = payload.get("manifest")
        status_payload = payload.get("status")
        if not isinstance(manifest_payload, Mapping):
            raise TypeError("runtime upgrade record missing object `manifest` field")
        if not isinstance(status_payload, Mapping):
            raise TypeError("runtime upgrade record missing object `status` field")
        proposer = payload.get("proposer")
        if not isinstance(proposer, str):
            raise TypeError("runtime upgrade record missing string `proposer` field")
        created_height_raw = payload.get("created_height")
        if created_height_raw is None:
            raise TypeError("runtime upgrade record missing numeric `created_height` field")
        try:
            created_height = int(created_height_raw)
        except (TypeError, ValueError) as exc:
            raise TypeError("runtime upgrade record `created_height` must be numeric") from exc
        manifest = RuntimeUpgradeManifest.from_payload(manifest_payload)
        status = RuntimeUpgradeStatus.from_payload(status_payload)
        return cls(
            manifest=manifest, status=status, proposer=proposer, created_height=created_height
        )


@dataclass(frozen=True)
class RuntimeUpgradeListItem:
    """Entry returned from `/v1/runtime/upgrades`."""

    id_hex: str
    record: RuntimeUpgradeRecord

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeUpgradeListItem":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime upgrade list entry must be an object")
        id_hex = payload.get("id_hex")
        if not isinstance(id_hex, str):
            raise TypeError("runtime upgrade list entry missing string `id_hex` field")
        record_payload = payload.get("record")
        if not isinstance(record_payload, Mapping):
            raise TypeError("runtime upgrade list entry missing object `record` field")
        record = RuntimeUpgradeRecord.from_payload(record_payload)
        return cls(id_hex=id_hex, record=record)


@dataclass(frozen=True)
class RuntimeUpgradeListPage:
    """Paginated runtime upgrade listing."""

    items: List[RuntimeUpgradeListItem]
    total: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeUpgradeListPage":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime upgrades response must be an object")
        items_raw = payload.get("items", [])
        if items_raw is None:
            items_raw = []
        if not isinstance(items_raw, list):
            raise TypeError("runtime upgrades response `items` must be a list")
        try:
            total = int(payload.get("total", len(items_raw)))
        except (TypeError, ValueError) as exc:
            raise TypeError("runtime upgrades response `total` must be numeric") from exc
        items = [RuntimeUpgradeListItem.from_payload(entry) for entry in items_raw]
        return cls(items=items, total=total)


@dataclass(frozen=True)
class RuntimeInstruction:
    """Instruction emitted by runtime upgrade helpers."""

    wire_id: str
    payload_hex: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeInstruction":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime instruction payload must be an object")
        wire_id = payload.get("wire_id")
        payload_hex = payload.get("payload_hex")
        if not isinstance(wire_id, str) or not isinstance(payload_hex, str):
            raise TypeError(
                "runtime instruction requires string `wire_id` and `payload_hex` fields"
            )
        return cls(wire_id=wire_id, payload_hex=payload_hex)


@dataclass(frozen=True)
class RuntimeUpgradeActionResponse:
    """Response returned by runtime upgrade proposal/activation helpers."""

    ok: bool
    tx_instructions: List[RuntimeInstruction]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RuntimeUpgradeActionResponse":
        if not isinstance(payload, Mapping):
            raise TypeError("runtime upgrade action response must be an object")
        ok_value = payload.get("ok")
        if not isinstance(ok_value, bool):
            raise TypeError("runtime upgrade action response missing boolean `ok` field")
        instructions_payload = payload.get("tx_instructions", [])
        if instructions_payload is None:
            instructions_payload = []
        if not isinstance(instructions_payload, list):
            raise TypeError("runtime upgrade action response `tx_instructions` must be a list")
        instructions = [RuntimeInstruction.from_payload(entry) for entry in instructions_payload]
        return cls(ok=ok_value, tx_instructions=instructions)


@dataclass(frozen=True)
class ConnectPerIpSessions:
    """Active session count for a single IP address."""

    ip: str
    sessions: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ConnectPerIpSessions":
        if not isinstance(payload, Mapping):
            raise TypeError("per-ip sessions entry must be an object")
        ip = payload.get("ip")
        if not isinstance(ip, str):
            raise TypeError("per-ip sessions entry missing string `ip` field")
        try:
            sessions = int(payload.get("sessions", 0))
        except (TypeError, ValueError) as exc:
            raise TypeError("per-ip sessions entry `sessions` must be numeric") from exc
        return cls(ip=ip, sessions=sessions)


@dataclass(frozen=True)
class ConnectPolicyStatusSnapshot:
    """Policy limits surfaced by operator-only `/v1/connect/status/aggregate`."""

    ws_max_sessions: int
    ws_per_ip_max_sessions: int
    ws_rate_per_ip_per_min: int
    session_ttl_ms: int
    frame_max_bytes: int
    session_buffer_max_bytes: int
    relay_enabled: bool
    relay_strategy: str
    relay_effective_strategy: str
    relay_p2p_attached: bool
    p2p_ttl_hops: int
    heartbeat_interval_ms: int
    heartbeat_miss_tolerance: int
    heartbeat_min_interval_ms: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ConnectPolicyStatusSnapshot":
        if not isinstance(payload, Mapping):
            raise TypeError("connect policy payload must be an object")
        try:
            ws_max_sessions = int(payload.get("ws_max_sessions", 0))
            ws_per_ip_max_sessions = int(payload.get("ws_per_ip_max_sessions", 0))
            ws_rate = int(payload.get("ws_rate_per_ip_per_min", 0))
            session_ttl_ms = int(payload.get("session_ttl_ms", 0))
            frame_max_bytes = int(payload.get("frame_max_bytes", 0))
            session_buffer_max_bytes = int(payload.get("session_buffer_max_bytes", 0))
            relay_enabled = bool(payload.get("relay_enabled", False))
            relay_strategy = str(payload.get("relay_strategy", ""))
            relay_effective_strategy = str(payload.get("relay_effective_strategy", ""))
            relay_p2p_attached = bool(payload.get("relay_p2p_attached", False))
            p2p_ttl_hops = int(payload.get("p2p_ttl_hops", 0))
            heartbeat_interval_ms = int(payload.get("heartbeat_interval_ms", 0))
            heartbeat_miss_tolerance = int(payload.get("heartbeat_miss_tolerance", 0))
            heartbeat_min_interval_ms = int(payload.get("heartbeat_min_interval_ms", 0))
        except (TypeError, ValueError) as exc:
            raise TypeError("connect policy fields have invalid types") from exc
        return cls(
            ws_max_sessions=ws_max_sessions,
            ws_per_ip_max_sessions=ws_per_ip_max_sessions,
            ws_rate_per_ip_per_min=ws_rate,
            session_ttl_ms=session_ttl_ms,
            frame_max_bytes=frame_max_bytes,
            session_buffer_max_bytes=session_buffer_max_bytes,
            relay_enabled=relay_enabled,
            relay_strategy=relay_strategy,
            relay_effective_strategy=relay_effective_strategy,
            relay_p2p_attached=relay_p2p_attached,
            p2p_ttl_hops=p2p_ttl_hops,
            heartbeat_interval_ms=heartbeat_interval_ms,
            heartbeat_miss_tolerance=heartbeat_miss_tolerance,
            heartbeat_min_interval_ms=heartbeat_min_interval_ms,
        )


@dataclass(frozen=True)
class ConnectStatusSnapshot:
    """Runtime snapshot returned by operator-only `/v1/connect/status/aggregate`."""

    enabled: bool
    sessions_total: int
    sessions_active: int
    per_ip_sessions: List[ConnectPerIpSessions]
    buffered_sessions: int
    total_buffer_bytes: int
    dedupe_size: int
    policy: Optional[ConnectPolicyStatusSnapshot]
    frames_in_total: int
    frames_out_total: int
    ciphertext_total: int
    dedupe_drops_total: int
    buffer_drops_total: int
    plaintext_control_drops_total: int
    monotonic_drops_total: int
    sequence_violation_closes_total: int
    role_direction_mismatch_total: int
    ping_miss_total: int
    p2p_rebroadcasts_total: int
    p2p_rebroadcast_skipped_total: int
    p2p_auth_failures_total: int
    p2p_ttl_drops_total: int
    p2p_unknown_session_drops_total: int
    p2p_session_claims_in_total: int
    p2p_session_claims_installed_total: int
    p2p_session_claim_conflicts_total: int
    p2p_role_consumed_total: int
    p2p_session_terminated_total: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ConnectStatusSnapshot":
        if not isinstance(payload, Mapping):
            raise TypeError("connect status payload must be an object")
        enabled = bool(payload.get("enabled", False))

        def _coerce_int_field(name: str, default: int = 0) -> int:
            try:
                return int(payload.get(name, default))
            except (TypeError, ValueError) as exc:
                raise TypeError(f"connect status field `{name}` must be numeric") from exc

        per_ip_raw = payload.get("per_ip_sessions", [])
        if per_ip_raw is None:
            per_ip_raw = []
        if not isinstance(per_ip_raw, list):
            raise TypeError("connect status `per_ip_sessions` must be a list")
        per_ip = [ConnectPerIpSessions.from_payload(item) for item in per_ip_raw]
        policy_payload = payload.get("policy")
        policy = (
            ConnectPolicyStatusSnapshot.from_payload(policy_payload)
            if isinstance(policy_payload, Mapping)
            else None
        )
        return cls(
            enabled=enabled,
            sessions_total=_coerce_int_field("sessions_total"),
            sessions_active=_coerce_int_field("sessions_active"),
            per_ip_sessions=per_ip,
            buffered_sessions=_coerce_int_field("buffered_sessions"),
            total_buffer_bytes=_coerce_int_field("total_buffer_bytes"),
            dedupe_size=_coerce_int_field("dedupe_size"),
            policy=policy,
            frames_in_total=_coerce_int_field("frames_in_total"),
            frames_out_total=_coerce_int_field("frames_out_total"),
            ciphertext_total=_coerce_int_field("ciphertext_total"),
            dedupe_drops_total=_coerce_int_field("dedupe_drops_total"),
            buffer_drops_total=_coerce_int_field("buffer_drops_total"),
            plaintext_control_drops_total=_coerce_int_field("plaintext_control_drops_total"),
            monotonic_drops_total=_coerce_int_field("monotonic_drops_total"),
            sequence_violation_closes_total=_coerce_int_field("sequence_violation_closes_total"),
            role_direction_mismatch_total=_coerce_int_field("role_direction_mismatch_total"),
            ping_miss_total=_coerce_int_field("ping_miss_total"),
            p2p_rebroadcasts_total=_coerce_int_field("p2p_rebroadcasts_total"),
            p2p_rebroadcast_skipped_total=_coerce_int_field("p2p_rebroadcast_skipped_total"),
            p2p_auth_failures_total=_coerce_int_field("p2p_auth_failures_total"),
            p2p_ttl_drops_total=_coerce_int_field("p2p_ttl_drops_total"),
            p2p_unknown_session_drops_total=_coerce_int_field("p2p_unknown_session_drops_total"),
            p2p_session_claims_in_total=_coerce_int_field("p2p_session_claims_in_total"),
            p2p_session_claims_installed_total=_coerce_int_field(
                "p2p_session_claims_installed_total"
            ),
            p2p_session_claim_conflicts_total=_coerce_int_field(
                "p2p_session_claim_conflicts_total"
            ),
            p2p_role_consumed_total=_coerce_int_field("p2p_role_consumed_total"),
            p2p_session_terminated_total=_coerce_int_field("p2p_session_terminated_total"),
        )


@dataclass(frozen=True)
class ToriiStatusMetrics:
    """Derived metrics computed from consecutive `/status` samples."""

    commit_latency_ms: int
    queue_size: int
    queue_queued: int
    queue_inflight: int
    queue_delta: int
    time_since_last_block_ms: int
    time_since_last_non_empty_block_ms: int
    tx_approved_delta: int
    tx_rejected_delta: int
    view_change_delta: int

    @classmethod
    def from_samples(
        cls,
        previous: Optional["ToriiStatusPayload"],
        current: "ToriiStatusPayload",
    ) -> "ToriiStatusMetrics":
        if previous is None:
            return cls(
                commit_latency_ms=current.commit_time_ms,
                queue_size=current.queue_size,
                queue_queued=current.queue_queued,
                queue_inflight=current.queue_inflight,
                queue_delta=0,
                time_since_last_block_ms=current.time_since_last_block_ms,
                time_since_last_non_empty_block_ms=current.time_since_last_non_empty_block_ms,
                tx_approved_delta=0,
                tx_rejected_delta=0,
                view_change_delta=0,
            )
        return cls(
            commit_latency_ms=current.commit_time_ms,
            queue_size=current.queue_size,
            queue_queued=current.queue_queued,
            queue_inflight=current.queue_inflight,
            queue_delta=current.queue_size - previous.queue_size,
            time_since_last_block_ms=current.time_since_last_block_ms,
            time_since_last_non_empty_block_ms=current.time_since_last_non_empty_block_ms,
            tx_approved_delta=max(0, current.txs_approved - previous.txs_approved),
            tx_rejected_delta=max(0, current.txs_rejected - previous.txs_rejected),
            view_change_delta=max(0, current.view_changes - previous.view_changes),
        )

    @property
    def has_activity(self) -> bool:
        """Return ``True`` if the snapshot reflects any queue or transaction movement."""

        return any(
            value
            for value in (
                self.queue_delta,
                self.tx_approved_delta,
                self.tx_rejected_delta,
                self.view_change_delta,
            )
        )


@dataclass(frozen=True)
class GovernanceProposalSnapshot:
    proposed: int
    rejected: int
    enacted: int
    superseded: int
    execution_failed: int


@dataclass(frozen=True)
class GovernanceProtectedNamespaceSnapshot:
    total_checks: int
    allowed: int
    rejected: int


@dataclass(frozen=True)
class GovernanceManifestAdmissionSnapshot:
    total_checks: int
    allowed: int
    missing_manifest: int
    non_validator_authority: int
    quorum_rejected: int
    protected_namespace_rejected: int
    runtime_hook_rejected: int


@dataclass(frozen=True)
class GovernanceManifestQuorumSnapshot:
    total_checks: int
    satisfied: int
    rejected: int


@dataclass(frozen=True)
class GovernanceManifestActivationSnapshot:
    contract_address: str
    code_hash_hex: str
    abi_hash_hex: Optional[str]
    height: int
    activated_at_ms: int


@dataclass(frozen=True)
class GovernanceStatusSnapshot:
    proposals: GovernanceProposalSnapshot
    protected_namespace: GovernanceProtectedNamespaceSnapshot
    manifest_admission: GovernanceManifestAdmissionSnapshot
    manifest_quorum: GovernanceManifestQuorumSnapshot
    recent_manifest_activations: List[GovernanceManifestActivationSnapshot]


@dataclass(frozen=True)
class ToriiLaneRuntimeUpgradeHookSnapshot:
    allow: bool
    require_metadata: bool
    metadata_key: Optional[str]
    allowed_ids: List[str]


@dataclass(frozen=True)
class ToriiLaneMerkleCommitmentSnapshot:
    root: str
    max_depth: int


@dataclass(frozen=True)
class ToriiLanePrivacyCommitmentSnapshot:
    id: int
    scheme: Literal["merkle"]
    merkle: ToriiLaneMerkleCommitmentSnapshot


@dataclass(frozen=True)
class ToriiLaneGovernanceSnapshot:
    lane_id: int
    alias: str
    dataspace_id: int
    visibility: str
    storage_profile: str
    governance: Optional[str]
    manifest_required: bool
    manifest_ready: bool
    manifest_path: Optional[str]
    validator_ids: List[str]
    quorum: Optional[int]
    protected_namespaces: List[str]
    runtime_upgrade: Optional[ToriiLaneRuntimeUpgradeHookSnapshot]
    privacy_commitments: List[ToriiLanePrivacyCommitmentSnapshot]


@dataclass(frozen=True)
class ToriiStatusPayload:
    """Decoded `/status` payload with convenient integer accessors and lane summaries."""

    observed_at_ms: int
    peers: int
    queue_size: int
    queue_queued: int
    queue_inflight: int
    last_block_committed_at_ms: int
    last_non_empty_block_committed_at_ms: int
    time_since_last_block_ms: int
    time_since_last_non_empty_block_ms: int
    commit_time_ms: int
    txs_approved: int
    txs_rejected: int
    view_changes: int
    governance: Optional[GovernanceStatusSnapshot]
    lane_governance: List[ToriiLaneGovernanceSnapshot]
    lane_governance_sealed_total: int
    lane_governance_sealed_aliases: List[str]
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ToriiStatusPayload":
        if not isinstance(payload, Mapping):
            raise TypeError("status payload must be an object")
        for field_name in ("lane_commitments", "dataspace_commitments", "pipeline_execution"):
            if field_name in payload:
                raise ValueError(f"status payload contains retired field `{field_name}`")

        def _coerce_int(name: str) -> int:
            value = payload.get(name, 0)
            try:
                return int(value)
            except (TypeError, ValueError) as exc:
                raise TypeError(f"status payload field `{name}` must be numeric") from exc

        def _coerce_nested_int(mapping: Mapping[str, Any], key: str, context: str) -> int:
            value = mapping.get(key, 0)
            try:
                return int(value)
            except (TypeError, ValueError) as exc:
                raise TypeError(f"{context} `{key}` must be numeric") from exc

        def _coerce_string(value: Any, context: str) -> str:
            if isinstance(value, str):
                return value
            raise TypeError(f"{context} must be a string")

        def _coerce_optional_string(value: Any, context: str) -> Optional[str]:
            if value is None:
                return None
            if isinstance(value, str):
                return value
            raise TypeError(f"{context} must be a string when present")

        def _coerce_string_list(value: Any, context: str) -> List[str]:
            if value is None:
                return []
            if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
                raise TypeError(f"{context} must be an array of strings")
            result: List[str] = []
            for idx, item in enumerate(value):
                if not isinstance(item, str):
                    raise TypeError(f"{context}[{idx}] must be a string")
                result.append(item)
            return result

        def _parse_privacy_commitments(
            value: Any, context: str
        ) -> List[ToriiLanePrivacyCommitmentSnapshot]:
            if value is None:
                return []
            if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
                raise TypeError(f"{context} must be an array")
            commitments: List[ToriiLanePrivacyCommitmentSnapshot] = []
            for idx, item in enumerate(value):
                if not isinstance(item, Mapping):
                    raise TypeError(f"{context}[{idx}] must be an object")
                entry_context = f"{context}[{idx}]"
                commitment_id = _coerce_nested_int(item, "id", entry_context)
                scheme = _coerce_string(item.get("scheme"), f"{entry_context}.scheme")
                if scheme != "merkle":
                    raise ValueError(f"{entry_context}.scheme must be 'merkle'")
                merkle_payload = item.get("merkle")
                if not isinstance(merkle_payload, Mapping):
                    raise TypeError(f"{entry_context}.merkle must be an object")
                merkle = ToriiLaneMerkleCommitmentSnapshot(
                    root=_coerce_string(
                        merkle_payload.get("root"),
                        f"{entry_context}.merkle.root",
                    ),
                    max_depth=_coerce_nested_int(
                        merkle_payload,
                        "max_depth",
                        f"{entry_context}.merkle",
                    ),
                )
                commitments.append(
                    ToriiLanePrivacyCommitmentSnapshot(
                        id=commitment_id,
                        scheme="merkle",
                        merkle=merkle,
                    )
                )
            return commitments

        def _coerce_bool(value: Any, context: str) -> bool:
            if isinstance(value, bool):
                return value
            raise TypeError(f"{context} must be a boolean")

        def _coerce_optional_int(value: Any, context: str) -> Optional[int]:
            if value is None:
                return None
            try:
                return int(value)
            except (TypeError, ValueError) as exc:
                raise TypeError(f"{context} must be numeric when present") from exc

        governance_snapshot: Optional[GovernanceStatusSnapshot] = None
        governance_payload = payload.get("governance")
        if isinstance(governance_payload, Mapping):
            proposals_payload = governance_payload.get("proposals")
            protected_payload = governance_payload.get("protected_namespace")
            admission_payload = governance_payload.get("manifest_admission")
            quorum_payload = governance_payload.get("manifest_quorum")
            activations_payload = governance_payload.get("recent_manifest_activations")

            if not isinstance(proposals_payload, Mapping):
                raise TypeError("governance payload missing object `proposals` field")
            if not isinstance(protected_payload, Mapping):
                raise TypeError("governance payload missing object `protected_namespace` field")
            if not isinstance(admission_payload, Mapping):
                raise TypeError("governance payload missing object `manifest_admission` field")
            if not isinstance(quorum_payload, Mapping):
                raise TypeError("governance payload missing object `manifest_quorum` field")
            if activations_payload is None:
                activations_payload = []
            if not isinstance(activations_payload, Sequence):
                raise TypeError("governance payload `recent_manifest_activations` must be an array")

            proposals = GovernanceProposalSnapshot(
                proposed=_coerce_nested_int(proposals_payload, "proposed", "governance.proposals"),
                rejected=_coerce_nested_int(proposals_payload, "rejected", "governance.proposals"),
                enacted=_coerce_nested_int(proposals_payload, "enacted", "governance.proposals"),
                superseded=_coerce_nested_int(
                    proposals_payload, "superseded", "governance.proposals"
                ),
                execution_failed=_coerce_nested_int(
                    proposals_payload, "execution_failed", "governance.proposals"
                ),
            )
            protected = GovernanceProtectedNamespaceSnapshot(
                total_checks=_coerce_nested_int(
                    protected_payload, "total_checks", "governance.protected_namespace"
                ),
                allowed=_coerce_nested_int(
                    protected_payload, "allowed", "governance.protected_namespace"
                ),
                rejected=_coerce_nested_int(
                    protected_payload, "rejected", "governance.protected_namespace"
                ),
            )
            admission = GovernanceManifestAdmissionSnapshot(
                total_checks=_coerce_nested_int(
                    admission_payload, "total_checks", "governance.manifest_admission"
                ),
                allowed=_coerce_nested_int(
                    admission_payload, "allowed", "governance.manifest_admission"
                ),
                missing_manifest=_coerce_nested_int(
                    admission_payload, "missing_manifest", "governance.manifest_admission"
                ),
                non_validator_authority=_coerce_nested_int(
                    admission_payload,
                    "non_validator_authority",
                    "governance.manifest_admission",
                ),
                quorum_rejected=_coerce_nested_int(
                    admission_payload, "quorum_rejected", "governance.manifest_admission"
                ),
                protected_namespace_rejected=_coerce_nested_int(
                    admission_payload,
                    "protected_namespace_rejected",
                    "governance.manifest_admission",
                ),
                runtime_hook_rejected=_coerce_nested_int(
                    admission_payload, "runtime_hook_rejected", "governance.manifest_admission"
                ),
            )
            quorum = GovernanceManifestQuorumSnapshot(
                total_checks=_coerce_nested_int(
                    quorum_payload, "total_checks", "governance.manifest_quorum"
                ),
                satisfied=_coerce_nested_int(
                    quorum_payload, "satisfied", "governance.manifest_quorum"
                ),
                rejected=_coerce_nested_int(
                    quorum_payload, "rejected", "governance.manifest_quorum"
                ),
            )

            recent_activations: List[GovernanceManifestActivationSnapshot] = []
            for idx, item in enumerate(activations_payload):
                if not isinstance(item, Mapping):
                    raise TypeError(
                        f"governance manifest activation at index {idx} must be an object"
                    )
                contract_address = item.get("contract_address", "")
                code_hash = item.get("code_hash_hex", "")
                abi_hash = item.get("abi_hash_hex")
                try:
                    height = int(item.get("height", 0))
                    activated_at_ms = int(item.get("activated_at_ms", 0))
                except (TypeError, ValueError) as exc:
                    raise TypeError(
                        "governance manifest activation height/activated_at_ms must be numeric"
                    ) from exc
                recent_activations.append(
                    GovernanceManifestActivationSnapshot(
                        contract_address=str(contract_address),
                        code_hash_hex=str(code_hash),
                        abi_hash_hex=str(abi_hash) if abi_hash is not None else None,
                        height=height,
                        activated_at_ms=activated_at_ms,
                    )
                )

            governance_snapshot = GovernanceStatusSnapshot(
                proposals=proposals,
                protected_namespace=protected,
                manifest_admission=admission,
                manifest_quorum=quorum,
                recent_manifest_activations=recent_activations,
            )

        lane_governance_payload = payload.get("lane_governance")
        lane_governance: List[ToriiLaneGovernanceSnapshot] = []
        if lane_governance_payload:
            if not isinstance(lane_governance_payload, Sequence):
                raise TypeError("lane_governance must be an array")
            for idx, item in enumerate(lane_governance_payload):
                if not isinstance(item, Mapping):
                    raise TypeError(f"lane_governance[{idx}] must be an object")
                validator_ids = _coerce_string_list(
                    item.get("validator_ids"),
                    f"lane_governance[{idx}].validator_ids",
                )
                namespaces = _coerce_string_list(
                    item.get("protected_namespaces"),
                    f"lane_governance[{idx}].protected_namespaces",
                )
                runtime_payload = item.get("runtime_upgrade")
                runtime_upgrade = None
                if runtime_payload is not None:
                    if not isinstance(runtime_payload, Mapping):
                        raise TypeError(f"lane_governance[{idx}].runtime_upgrade must be an object")
                    runtime_upgrade = ToriiLaneRuntimeUpgradeHookSnapshot(
                        allow=_coerce_bool(
                            runtime_payload.get("allow"),
                            f"lane_governance[{idx}].runtime_upgrade.allow",
                        ),
                        require_metadata=_coerce_bool(
                            runtime_payload.get("require_metadata"),
                            f"lane_governance[{idx}].runtime_upgrade.require_metadata",
                        ),
                        metadata_key=_coerce_optional_string(
                            runtime_payload.get("metadata_key"),
                            f"lane_governance[{idx}].runtime_upgrade.metadata_key",
                        ),
                        allowed_ids=_coerce_string_list(
                            runtime_payload.get("allowed_ids"),
                            f"lane_governance[{idx}].runtime_upgrade.allowed_ids",
                        ),
                    )
                privacy_commitments = _parse_privacy_commitments(
                    item.get("privacy_commitments"),
                    f"lane_governance[{idx}].privacy_commitments",
                )
                lane_governance.append(
                    ToriiLaneGovernanceSnapshot(
                        lane_id=_coerce_nested_int(item, "lane_id", f"lane_governance[{idx}]"),
                        alias=_coerce_string(item.get("alias"), f"lane_governance[{idx}].alias"),
                        dataspace_id=_coerce_nested_int(
                            item,
                            "dataspace_id",
                            f"lane_governance[{idx}]",
                        ),
                        visibility=_coerce_string(
                            item.get("visibility"),
                            f"lane_governance[{idx}].visibility",
                        ),
                        storage_profile=_coerce_string(
                            item.get("storage_profile"),
                            f"lane_governance[{idx}].storage_profile",
                        ),
                        governance=_coerce_optional_string(
                            item.get("governance"),
                            f"lane_governance[{idx}].governance",
                        ),
                        manifest_required=_coerce_bool(
                            item.get("manifest_required"),
                            f"lane_governance[{idx}].manifest_required",
                        ),
                        manifest_ready=_coerce_bool(
                            item.get("manifest_ready"),
                            f"lane_governance[{idx}].manifest_ready",
                        ),
                        manifest_path=_coerce_optional_string(
                            item.get("manifest_path"),
                            f"lane_governance[{idx}].manifest_path",
                        ),
                        validator_ids=validator_ids,
                        quorum=_coerce_optional_int(
                            item.get("quorum"),
                            f"lane_governance[{idx}].quorum",
                        ),
                        protected_namespaces=namespaces,
                        runtime_upgrade=runtime_upgrade,
                        privacy_commitments=privacy_commitments,
                    )
                )

        lane_governance_sealed_total = _coerce_int("lane_governance_sealed_total")
        lane_governance_sealed_aliases = _coerce_string_list(
            payload.get("lane_governance_sealed_aliases"),
            "lane_governance_sealed_aliases",
        )

        return cls(
            observed_at_ms=_coerce_int("observed_at_ms"),
            peers=_coerce_int("peers"),
            queue_size=_coerce_int("queue_size"),
            queue_queued=_coerce_int("queue_queued"),
            queue_inflight=_coerce_int("queue_inflight"),
            last_block_committed_at_ms=_coerce_int("last_block_committed_at_ms"),
            last_non_empty_block_committed_at_ms=_coerce_int(
                "last_non_empty_block_committed_at_ms"
            ),
            time_since_last_block_ms=_coerce_int("time_since_last_block_ms"),
            time_since_last_non_empty_block_ms=_coerce_int("time_since_last_non_empty_block_ms"),
            commit_time_ms=_coerce_int("commit_time_ms"),
            txs_approved=_coerce_int("txs_approved"),
            txs_rejected=_coerce_int("txs_rejected"),
            view_changes=_coerce_int("view_changes"),
            governance=governance_snapshot,
            lane_governance=lane_governance,
            lane_governance_sealed_total=lane_governance_sealed_total,
            lane_governance_sealed_aliases=lane_governance_sealed_aliases,
            raw=dict(payload),
        )

    @property
    def liveness_elapsed_ms(self) -> int:
        """Return elapsed block time used for queue-aware stall checks."""

        if self.time_since_last_non_empty_block_ms > 0:
            return self.time_since_last_non_empty_block_ms
        return self.time_since_last_block_ms

    def is_queue_stalled(self, stall_threshold_ms: int) -> bool:
        """Classify stalls only when queued work exists and elapsed block time exceeds the threshold."""

        return self.queue_size > 0 and self.liveness_elapsed_ms > int(stall_threshold_ms)


@dataclass(frozen=True)
class ToriiStatusSnapshot:
    """Snapshot captured from `/status` together with derived metrics."""

    timestamp: float
    status: ToriiStatusPayload
    metrics: ToriiStatusMetrics

    @property
    def has_activity(self) -> bool:
        """Return ``True`` when the underlying metrics observed any movement."""

        return self.metrics.has_activity


PIPELINE_STALL_BLOCK_CADENCES = 20
"""Target block cadences a peer with queued work may go without committing a non-empty block.

`GET /v1/pipeline/preflight` serves one consensus timing value, `sumeragi.block_cadence_ms`
(the signed-genesis target block time), so `ToriiPipelinePreflight.stall_threshold_ms` is
``PIPELINE_STALL_BLOCK_CADENCES * block_cadence_ms``. With work queued a healthy chain commits
about once per cadence. At the Sumeragi defaults (1 s block time, 5 s payload retry, 2-3 s base
view timer) one crashed leader delays the next commit by roughly 11-14 s plus execution
(`specs/sumeragi.md` §8.2 P4, §9.3); twenty cadences keep such a single view change from being
reported as a stall. Callers that know their deployment's local timers pass their own
threshold to `ToriiStatusPayload.is_queue_stalled`.
"""

_PIPELINE_PREFLIGHT_ROOT_FIELDS: Tuple[str, ...] = (
    "schema_version",
    "chain_height",
    "sumeragi",
    "admission",
    "block",
    "pipeline",
    "queue",
    "fees",
)
# Exact served field set of every `PipelinePreflightResponse` object, in Torii's order.
_PIPELINE_PREFLIGHT_SECTION_FIELDS: Dict[str, Tuple[str, ...]] = {
    "sumeragi": ("block_cadence_ms",),
    "admission": (
        "max_signatures",
        "max_instructions",
        "max_tx_bytes",
        "max_decompressed_bytes",
        "max_metadata_depth",
    ),
    "block": ("max_transactions",),
    "pipeline": (
        "signature_batch_max_ed25519",
        "signature_batch_max_secp256k1",
        "signature_batch_max_pqc",
        "signature_batch_max_bls",
        "overlay_max_instructions",
        "ivm_max_cycles_upper_bound",
        "ivm_admission_cycle_limit",
        "ivm_max_decoded_instructions",
    ),
    "queue": ("size", "queued", "inflight"),
    "fees": (
        "fee_asset_id",
        "fee_sink_account_id",
        "base_fee",
        "per_byte_fee",
        "per_instruction_fee",
        "per_gas_unit_fee",
        "sponsor_vault_custody_account_id",
        "settlement_mode",
        "successful_claim_fee_exempt_authorities",
    ),
}
_PIPELINE_PREFLIGHT_UNSIGNED_SECTIONS = ("sumeragi", "admission", "block", "pipeline", "queue")
_PIPELINE_PREFLIGHT_POSITIVE_FIELDS = frozenset(
    {
        ("sumeragi", "block_cadence_ms"),
        ("pipeline", "ivm_max_cycles_upper_bound"),
        ("pipeline", "ivm_admission_cycle_limit"),
    }
)
_PIPELINE_PREFLIGHT_FEE_STRINGS = (
    "fee_asset_id",
    "base_fee",
    "per_byte_fee",
    "per_instruction_fee",
    "per_gas_unit_fee",
    "settlement_mode",
)
_PIPELINE_PREFLIGHT_SETTLEMENT_MODES = ("direct", "lane_relay_burn")


def _require_pipeline_preflight_fields(
    record: Mapping[str, Any],
    expected: Sequence[str],
    context: str,
) -> None:
    """Reject a preflight object that lacks a served field or carries an unserved one."""

    missing = sorted(name for name in expected if name not in record)
    unexpected = sorted(str(name) for name in record if name not in expected)
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unsupported " + ", ".join(unexpected))
        raise ValueError(f"{context} fields are not canonical: " + "; ".join(details))


@dataclass(frozen=True)
class ToriiPipelinePreflight:
    """Typed response from `GET /v1/pipeline/preflight`.

    `from_payload` requires exactly the fields Torii serves in every object. Torii serves no
    stall threshold: `stall_threshold_ms` is derived from ``sumeragi["block_cadence_ms"]``.
    """

    schema_version: int
    chain_height: int
    sumeragi: Mapping[str, Any]
    admission: Mapping[str, Any]
    block: Mapping[str, Any]
    pipeline: Mapping[str, Any]
    queue: Mapping[str, Any]
    fees: Mapping[str, Any]
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def block_cadence_ms(self) -> int:
        """Signed-genesis target block time served as ``sumeragi.block_cadence_ms``."""

        return int(self.sumeragi["block_cadence_ms"])

    @property
    def stall_threshold_ms(self) -> int:
        """SDK-derived stall threshold: `PIPELINE_STALL_BLOCK_CADENCES` served block cadences."""

        return PIPELINE_STALL_BLOCK_CADENCES * self.block_cadence_ms

    def is_status_stalled(self, status: ToriiStatusPayload) -> bool:
        """Report queued work with no non-empty block committed for over `stall_threshold_ms`."""

        return status.is_queue_stalled(self.stall_threshold_ms)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ToriiPipelinePreflight":
        """Parse the exact preflight body; a missing or unserved field is protocol drift."""

        if not isinstance(payload, Mapping):
            raise TypeError("pipeline preflight response must be a JSON object")
        _require_pipeline_preflight_fields(
            payload, _PIPELINE_PREFLIGHT_ROOT_FIELDS, "pipeline preflight"
        )

        def _unsigned(value: Any, context: str, *, positive: bool = False) -> int:
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{context} must be an integer")
            minimum = 1 if positive else 0
            if value < minimum:
                qualifier = "positive" if positive else "non-negative"
                raise ValueError(f"{context} must be {qualifier}")
            return value

        sections: Dict[str, Dict[str, Any]] = {}
        for name, expected in _PIPELINE_PREFLIGHT_SECTION_FIELDS.items():
            value = payload.get(name)
            if not isinstance(value, Mapping):
                raise TypeError(f"pipeline preflight `{name}` must be a JSON object")
            section = dict(value)
            _require_pipeline_preflight_fields(section, expected, f"pipeline preflight `{name}`")
            sections[name] = section
        for name in _PIPELINE_PREFLIGHT_UNSIGNED_SECTIONS:
            section = sections[name]
            for field_name in _PIPELINE_PREFLIGHT_SECTION_FIELDS[name]:
                section[field_name] = _unsigned(
                    section[field_name],
                    f"pipeline preflight {name}.{field_name}",
                    positive=(name, field_name) in _PIPELINE_PREFLIGHT_POSITIVE_FIELDS,
                )

        fees = sections["fees"]
        for field_name in _PIPELINE_PREFLIGHT_FEE_STRINGS:
            value = fees[field_name]
            if not isinstance(value, str) or not value:
                raise TypeError(f"pipeline preflight fees.{field_name} must be a non-empty string")
        if fees["settlement_mode"] not in _PIPELINE_PREFLIGHT_SETTLEMENT_MODES:
            raise ValueError(
                "pipeline preflight fees.settlement_mode must be one of: "
                + ", ".join(_PIPELINE_PREFLIGHT_SETTLEMENT_MODES)
            )
        fees["fee_sink_account_id"] = _normalize_exact_any_i105_account_id(
            fees["fee_sink_account_id"],
            "pipeline preflight fees.fee_sink_account_id",
        )
        fees["sponsor_vault_custody_account_id"] = _normalize_exact_any_i105_account_id(
            fees["sponsor_vault_custody_account_id"],
            "pipeline preflight fees.sponsor_vault_custody_account_id",
        )
        authorities = fees["successful_claim_fee_exempt_authorities"]
        if not isinstance(authorities, list):
            raise TypeError(
                "pipeline preflight fees.successful_claim_fee_exempt_authorities must be an array"
            )
        fees["successful_claim_fee_exempt_authorities"] = [
            _normalize_exact_any_i105_account_id(
                authority,
                "pipeline preflight "
                f"fees.successful_claim_fee_exempt_authorities[{index}]",
            )
            for index, authority in enumerate(authorities)
        ]

        return cls(
            schema_version=_unsigned(
                payload.get("schema_version"),
                "pipeline preflight schema_version",
                positive=True,
            ),
            chain_height=_unsigned(
                payload.get("chain_height"),
                "pipeline preflight chain_height",
            ),
            sumeragi=sections["sumeragi"],
            admission=sections["admission"],
            block=sections["block"],
            pipeline=sections["pipeline"],
            queue=sections["queue"],
            fees=fees,
            raw=dict(payload),
        )


class _ToriiStatusState:
    """Internal helper tracking the previous status sample per client."""

    def __init__(self) -> None:
        self._previous: Optional[ToriiStatusPayload] = None

    def record(self, payload: ToriiStatusPayload) -> ToriiStatusMetrics:
        metrics = ToriiStatusMetrics.from_samples(self._previous, payload)
        self._previous = payload
        return metrics


_TORII_ENV_KEYS = {
    "timeout_ms": "IROHA_TORII_TIMEOUT_MS",
    "max_retries": "IROHA_TORII_MAX_RETRIES",
    "backoff_initial_ms": "IROHA_TORII_BACKOFF_INITIAL_MS",
    "backoff_multiplier": "IROHA_TORII_BACKOFF_MULTIPLIER",
    "max_backoff_ms": "IROHA_TORII_MAX_BACKOFF_MS",
    "retry_statuses": "IROHA_TORII_RETRY_STATUSES",
    "retry_methods": "IROHA_TORII_RETRY_METHODS",
    "api_token": "IROHA_TORII_API_TOKEN",
    "auth_token": "IROHA_TORII_AUTH_TOKEN",
}


def _coerce_sorafs_policy_value(value: Any, context: str) -> SorafsAliasPolicy:
    if isinstance(value, SorafsAliasPolicy):
        return value
    if isinstance(value, Mapping):
        return SorafsAliasPolicy.from_mapping(value)
    raise TypeError(f"{context} must be provided as a mapping or SorafsAliasPolicy instance")


def _normalize_sorafs_policy_config(
    policy: Optional[Union[SorafsAliasPolicy, Mapping[str, Any]]],
) -> SorafsAliasPolicy:
    if policy is None:
        return SorafsAliasPolicy.defaults()
    return _coerce_sorafs_policy_value(policy, "sorafs_alias_policy")


def resolve_torii_client_config(
    *,
    config: Optional[Mapping[str, Any]] = None,
    env: Optional[Mapping[str, str]] = None,
    overrides: Optional[Mapping[str, Any]] = None,
) -> ResolvedToriiClientConfig:
    """Merge Torii client settings from config files, environment variables, and overrides."""

    for source_name, source in (
        ("config", config),
        ("env", env),
        ("overrides", overrides),
    ):
        if source is not None and not isinstance(source, Mapping):
            raise TypeError(f"{source_name} must be a mapping")

    state: Dict[str, Any] = {
        "timeout": _DEFAULT_RESOLVED_CONFIG.timeout,
        "max_retries": _DEFAULT_RESOLVED_CONFIG.max_retries,
        "backoff_initial": _DEFAULT_RESOLVED_CONFIG.backoff_initial,
        "backoff_multiplier": _DEFAULT_RESOLVED_CONFIG.backoff_multiplier,
        "max_backoff": _DEFAULT_RESOLVED_CONFIG.max_backoff,
        "retry_statuses": set(_DEFAULT_RESOLVED_CONFIG.retry_statuses),
        "retry_methods": set(_DEFAULT_RESOLVED_CONFIG.retry_methods),
        "default_headers": dict(_DEFAULT_RESOLVED_CONFIG.default_headers),
        "auth_token": _DEFAULT_RESOLVED_CONFIG.auth_token,
        "api_token": _DEFAULT_RESOLVED_CONFIG.api_token,
        "sorafs_alias_policy": None,
    }

    def apply_source(source: Optional[Mapping[str, Any]]) -> None:
        if not source:
            return
        _reject_alias_keys(
            source,
            {
                "timeoutMs": "timeout_ms",
                "timeoutSeconds": "timeout",
                "maxRetries": "max_retries",
                "backoffInitialMs": "backoff_initial_ms",
                "backoffInitial": "backoff_initial",
                "backoffMultiplier": "backoff_multiplier",
                "maxBackoffMs": "max_backoff_ms",
                "maxBackoff": "max_backoff",
                "retryStatuses": "retry_statuses",
                "retryMethods": "retry_methods",
                "defaultHeaders": "default_headers",
                "authToken": "auth_token",
                "apiToken": "api_token",
                "sorafsAliasPolicy": "sorafs_alias_policy",
            },
            context="torii_client config",
        )
        for milliseconds_key, seconds_key in (
            ("timeout_ms", "timeout"),
            ("backoff_initial_ms", "backoff_initial"),
            ("max_backoff_ms", "max_backoff"),
        ):
            if source.get(milliseconds_key) is not None and source.get(seconds_key) is not None:
                raise TypeError(
                    f"torii_client config cannot contain both {milliseconds_key} "
                    f"and {seconds_key}"
                )
        timeout = _coerce_timeout_seconds(
            source.get("timeout_ms"),
            default_value=source.get("timeout"),
        )
        if timeout is not None:
            state["timeout"] = timeout
        max_retries = _coerce_int(
            source.get("max_retries"),
            "max_retries",
            allow_zero=True,
        )
        if max_retries is not None:
            state["max_retries"] = max_retries
        backoff_initial = _coerce_duration_seconds(
            source.get("backoff_initial_ms"),
            default_value=source.get("backoff_initial"),
        )
        if backoff_initial is not None:
            state["backoff_initial"] = backoff_initial
        backoff_multiplier = _coerce_float(
            source.get("backoff_multiplier"),
            "backoff_multiplier",
            allow_zero=False,
        )
        if backoff_multiplier is not None:
            if backoff_multiplier < 1.0:
                raise ValueError("backoff_multiplier must be at least 1")
            state["backoff_multiplier"] = backoff_multiplier
        max_backoff = _coerce_duration_seconds(
            source.get("max_backoff_ms"),
            default_value=source.get("max_backoff"),
        )
        if max_backoff is not None:
            state["max_backoff"] = max_backoff
        statuses = _parse_retry_statuses(source.get("retry_statuses"))
        if statuses is not None:
            state["retry_statuses"] = statuses
        methods = _parse_retry_methods(source.get("retry_methods"))
        if methods is not None:
            state["retry_methods"] = methods
        headers = _copy_http_headers(
            _normalize_headers(source.get("default_headers")),
            "default_headers",
        )
        for name, value in headers.items():
            _set_exact_header(state["default_headers"], name, value)
        auth_token = source.get("auth_token")
        if auth_token is not None:
            state["auth_token"] = _require_route_token(auth_token, "auth_token")
        api_token = source.get("api_token")
        if api_token is not None:
            state["api_token"] = _require_route_token(api_token, "api_token")
        policy_override = source.get("sorafs_alias_policy")
        if policy_override is not None:
            state["sorafs_alias_policy"] = _coerce_sorafs_policy_value(
                policy_override, "sorafs_alias_policy"
            )

    apply_source(_extract_torii_client_section(config))

    if isinstance(config, Mapping):
        if "toriiConfig" in config:
            raise TypeError("toriiConfig is not supported; use torii")
        torii_section = config.get("torii")
        if "torii" in config and not isinstance(torii_section, Mapping):
            raise TypeError("config['torii'] must be a mapping")
        token = _pick_api_token(torii_section)
        if token and not state["api_token"]:
            state["api_token"] = token

    if env is not None:
        apply_source(
            {
                "timeout_ms": env.get(_TORII_ENV_KEYS["timeout_ms"]),
                "max_retries": env.get(_TORII_ENV_KEYS["max_retries"]),
                "backoff_initial_ms": env.get(_TORII_ENV_KEYS["backoff_initial_ms"]),
                "backoff_multiplier": env.get(_TORII_ENV_KEYS["backoff_multiplier"]),
                "max_backoff_ms": env.get(_TORII_ENV_KEYS["max_backoff_ms"]),
                "retry_statuses": env.get(_TORII_ENV_KEYS["retry_statuses"]),
                "retry_methods": env.get(_TORII_ENV_KEYS["retry_methods"]),
                "api_token": env.get(_TORII_ENV_KEYS["api_token"]),
                "auth_token": env.get(_TORII_ENV_KEYS["auth_token"]),
            }
        )

    apply_source(overrides)

    headers = dict(state["default_headers"])
    if not any(key.lower() == "accept" for key in headers):
        headers["Accept"] = "application/json"
    _reject_reserved_default_headers(headers, "default_headers")

    return ResolvedToriiClientConfig(
        timeout=state["timeout"],
        max_retries=state["max_retries"],
        backoff_initial=state["backoff_initial"],
        backoff_multiplier=state["backoff_multiplier"],
        max_backoff=state["max_backoff"],
        retry_statuses=frozenset(state["retry_statuses"]),
        retry_methods=frozenset(state["retry_methods"]),
        default_headers=headers,
        auth_token=state["auth_token"],
        api_token=state["api_token"],
        sorafs_alias_policy=_normalize_sorafs_policy_config(state["sorafs_alias_policy"]),
    )


def _extract_torii_client_section(config: Optional[Mapping[str, Any]]) -> Mapping[str, Any]:
    if not config:
        return {}
    if not isinstance(config, Mapping):
        raise TypeError("config must be a mapping")
    if "toriiClient" in config:
        raise TypeError("toriiClient is not supported; use torii_client")
    if "torii_client" in config:
        nested = config["torii_client"]
        if not isinstance(nested, Mapping):
            raise TypeError("config['torii_client'] must be a mapping")
        return nested
    return config


def _normalize_public_pipeline_status(payload: Any, expected_hash: str) -> Dict[str, Any]:
    """Validate and copy the metadata-only public pipeline response."""

    context = "transaction status response"
    if not isinstance(payload, Mapping):
        raise TypeError(f"{context} must be an object")
    expected_fields = {"hash", "status", "scope", "resolved_from"}
    actual_fields = set(payload)
    if actual_fields != expected_fields:
        extras = sorted(actual_fields - expected_fields)
        missing = sorted(expected_fields - actual_fields)
        if extras:
            raise ValueError(
                f"{context} contains retired or unsupported fields: {', '.join(extras)}"
            )
        raise ValueError(f"{context} is missing required fields: {', '.join(missing)}")

    observed_hash = _require_exact_pipeline_transaction_hash(
        payload.get("hash"),
        f"{context}.hash",
    )
    if not hmac.compare_digest(observed_hash, expected_hash):
        raise ValueError(f"{context}.hash does not match the requested transaction")

    status_value = payload.get("status")
    if not isinstance(status_value, Mapping):
        raise TypeError(f"{context}.status must be an object")
    allowed_status_fields = {"kind", "block_height"}
    extra_status_fields = sorted(set(status_value) - allowed_status_fields)
    if extra_status_fields:
        raise ValueError(
            f"{context}.status contains retired or unsupported fields: "
            f"{', '.join(extra_status_fields)}"
        )
    kind = _require_exact_non_empty_string(
        status_value.get("kind"),
        f"{context}.status.kind",
    )
    if kind not in _PIPELINE_STATUS_KINDS:
        raise ValueError(f"{context}.status.kind is unsupported")
    status: Dict[str, Any] = {"kind": kind}
    if "block_height" in status_value:
        block_height = status_value["block_height"]
        if isinstance(block_height, bool) or not isinstance(block_height, int) or block_height <= 0:
            raise ValueError(f"{context}.status.block_height must be a positive integer")
        status["block_height"] = block_height

    scope = _require_exact_non_empty_string(payload.get("scope"), f"{context}.scope")
    if scope not in {"local", "global"}:
        raise ValueError(f"{context}.scope is unsupported")
    resolved_from = _require_exact_non_empty_string(
        payload.get("resolved_from"),
        f"{context}.resolved_from",
    )
    if resolved_from not in {"cache", "queue", "state"}:
        raise ValueError(f"{context}.resolved_from is unsupported")
    return {
        "hash": observed_hash,
        "status": status,
        "scope": scope,
        "resolved_from": resolved_from,
    }


def _normalize_contract_call_metadata(
    value: Optional[Mapping[str, Any]],
    *,
    context: str,
) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be a mapping")
    normalized: Dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str):
            raise TypeError(f"{context} keys must be strings")
        if (
            not raw_key
            or raw_key != raw_key.strip()
            or any(character.isspace() for character in raw_key)
            or any(character in "@#$" for character in raw_key)
        ):
            raise ValueError(f"{context} contains an invalid metadata key")
        if raw_key in _CONTRACT_CALL_RESERVED_METADATA_KEYS or raw_key.startswith(
            _CONTRACT_CALL_RESERVED_METADATA_PREFIXES
        ):
            raise ValueError(f"{context} key {raw_key!r} is reserved")
        try:
            normalized[raw_key] = json.loads(json.dumps(raw_value, allow_nan=False))
        except (TypeError, ValueError) as error:
            raise TypeError(f"{context}[{raw_key!r}] must be strict JSON") from error
    return normalized


def _pick_api_token(torii_section: Optional[Mapping[str, Any]]) -> Optional[str]:
    if not isinstance(torii_section, Mapping):
        return None
    if "apiTokens" in torii_section:
        raise TypeError("apiTokens is not supported; use api_tokens")
    tokens = torii_section.get("api_tokens")
    if isinstance(tokens, (list, tuple)):
        normalized = [
            _require_route_token(token, f"torii.api_tokens[{index}]")
            for index, token in enumerate(tokens)
        ]
        return normalized[0] if normalized else None
    if isinstance(tokens, str):
        return _require_route_token(tokens, "torii.api_tokens")
    if tokens is not None and not isinstance(tokens, (list, tuple)):
        raise TypeError("torii.api_tokens must be a string or sequence of strings")
    return None


def _require_crypto() -> ModuleType:
    """Return the compiled crypto bindings, raising a helpful error when missing."""

    global _CRYPTO_MODULE
    if _CRYPTO_MODULE is not None:
        return _CRYPTO_MODULE
    try:
        from . import crypto as _crypto
    except RuntimeError as exc:  # pragma: no cover - optional runtime dependency
        raise RuntimeError(
            "iroha_native._crypto extension module is required for transaction helpers. "
            "Run `maturin develop --release` inside `python/iroha_python` (or install the wheel) "
            "before using these APIs."
        ) from exc
    _CRYPTO_MODULE = _crypto
    return _crypto


def signed_transaction_envelope_from_json(envelope_json: str) -> "SignedTransactionEnvelope":
    """Parse a signed transaction envelope from a JSON payload."""

    return _require_crypto().signed_transaction_envelope_from_json(envelope_json)


@dataclass(frozen=True, init=False)
class ContractCallIntent:
    """One manifest-resolved call requested for an ordered atomic batch."""

    entrypoint: str
    contract_address: Optional[str] = None
    contract_alias: Optional[str] = None
    payload: Any = None
    expected_contract_address: Optional[str] = None
    expected_code_hash_hex: Optional[str] = None
    expected_abi_hash_hex: Optional[str] = None

    def __init__(
        self,
        entrypoint: str,
        *,
        contract_address: Optional[str] = None,
        contract_alias: Optional[str] = None,
        payload: Any = None,
        expected_contract_address: Optional[str] = None,
        expected_code_hash_hex: Optional[str] = None,
        expected_abi_hash_hex: Optional[str] = None,
    ) -> None:
        object.__setattr__(self, "entrypoint", entrypoint)
        object.__setattr__(self, "contract_address", contract_address)
        object.__setattr__(self, "contract_alias", contract_alias)
        object.__setattr__(self, "payload", payload)
        object.__setattr__(
            self,
            "expected_contract_address",
            expected_contract_address,
        )
        object.__setattr__(self, "expected_code_hash_hex", expected_code_hash_hex)
        object.__setattr__(self, "expected_abi_hash_hex", expected_abi_hash_hex)
        self.__post_init__()

    def __post_init__(self) -> None:
        _require_exact_non_empty_string(
            self.entrypoint,
            "ContractCallIntent.entrypoint",
        )
        if (self.contract_address is None) == (self.contract_alias is None):
            raise ValueError(
                "ContractCallIntent requires exactly one of "
                "contract_address or contract_alias"
            )
        for value, field_name in (
            (self.contract_address, "contract_address"),
            (self.contract_alias, "contract_alias"),
            (self.expected_contract_address, "expected_contract_address"),
        ):
            if value is not None:
                _require_exact_non_empty_string(
                    value,
                    f"ContractCallIntent.{field_name}",
                )
        for value, field_name in (
            (self.expected_code_hash_hex, "expected_code_hash_hex"),
            (self.expected_abi_hash_hex, "expected_abi_hash_hex"),
        ):
            if value is None:
                continue
            if not isinstance(value, str):
                raise TypeError(f"ContractCallIntent.{field_name} must be a string")
            if re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ValueError(
                    f"ContractCallIntent.{field_name} must be exactly "
                    "32 lowercase hexadecimal bytes"
                )

    def to_payload(self) -> Dict[str, Any]:
        """Return the strict Torii preparation intent."""

        payload: Dict[str, Any] = {"entrypoint": self.entrypoint}
        if self.contract_address is not None:
            payload["contract_address"] = self.contract_address
        if self.contract_alias is not None:
            payload["contract_alias"] = self.contract_alias
        if self.payload is not None:
            try:
                payload["payload"] = json.loads(
                    json.dumps(self.payload, allow_nan=False)
                )
            except (TypeError, ValueError) as error:
                raise TypeError(
                    "ContractCallIntent.payload must be strict JSON"
                ) from error
        if self.expected_contract_address is not None:
            payload["expected_contract_address"] = self.expected_contract_address
        if self.expected_code_hash_hex is not None:
            payload["expected_code_hash_hex"] = self.expected_code_hash_hex
        if self.expected_abi_hash_hex is not None:
            payload["expected_abi_hash_hex"] = self.expected_abi_hash_hex
        return payload


@dataclass(frozen=True)
class _PreparedContractCallBatchItem:
    index: int
    kind: str
    contract_address: Optional[str] = None
    code_hash_hex: Optional[str] = None
    abi_hash_hex: Optional[str] = None
    entrypoint: Optional[str] = None
    arguments: Optional[bytes] = None
    wire_id: Optional[str] = None
    instruction: Optional[bytes] = None


@dataclass(frozen=True)
class _ContractCallBatchPlan:
    binding: Dict[str, Any]
    binding_digest_hex: str
    prepared_entries: Tuple[_PreparedContractCallBatchItem, ...]


__all__ = [
    "ContractArtifactId",
    "ToriiClient",
    "OperatorSigningContext",
    "SorafsOrderbookSubmissionAmbiguousError",
    "SorafsOrderbookSubmissionIdentity",
    "SorafsOrderbookSubmissionReceipt",
    "SorafsOrderbookSubmissionReceiptPayload",
    "ContractCallIntent",
    "create_torii_client",
    "TransactionStatusError",
    "DataModelMismatchError",
    "signed_transaction_envelope_from_json",
    "resolve_torii_client_config",
    "ResolvedToriiClientConfig",
    "SseEvent",
    "SseStreamError",
    "EventCursor",
    "NetworkTimeSnapshot",
    "NetworkTimeStatus",
    "NetworkTimeSample",
    "NetworkTimeRttBucket",
    "NodeCapabilities",
    "NodeAdminSnapshot",
    "TransportConfig",
    "TransportNoritoRpcConfig",
    "SorafsPorSubmissionResponse",
    "SorafsPorVerdictResponse",
    "SorafsPinRegisterResponse",
    "SorafsPorIngestionProviderStatus",
    "SorafsPorIngestionStatus",
    "ExplorerMetricsSnapshot",
    "ExplorerAccountQrSnapshot",
    "IsoSubmissionRecord",
    "IsoStatusHistoryRecord",
    "IsoMessageTimeoutError",
    "VerifiedCommittedTransaction",
    "AccountPermissionRecord",
    "SubscriptionPlanCreateResult",
    "SubscriptionCreateResult",
    "SubscriptionGetResponse",
    "SubscriptionActionResult",
    "SumeragiEvidencePenaltyDetails",
    "SumeragiEvidencePendingPenaltyStatus",
    "SumeragiEvidenceAppliedPenaltyStatus",
    "SumeragiEvidencePenaltyStatus",
    "SumeragiEvidenceRecord",
    "SumeragiEvidenceListPage",
    "SumeragiStatus",
    "SumeragiFootprint",
    "SumeragiBeaconHorizon",
    "SumeragiHaltReason",
    "SumeragiLaneStatus",
    "SumeragiLaneRecord",
    "SumeragiLaneMember",
    "SumeragiLaneFrontier",
    "SumeragiParameters",
    "SumeragiParamsSnapshot",
    "SumeragiEvidenceCount",
    "TriggerRecord",
    "TriggerListPage",
    "PipelineDagSnapshot",
    "PipelineTxSnapshot",
    "PipelineRecoverySidecar",
    "RuntimeUpgradeCounters",
    "RuntimeMetrics",
    "RuntimeAbiActive",
    "RuntimeAbiHash",
    "RuntimeUpgradeStatus",
    "RuntimeUpgradeManifest",
    "RuntimeUpgradeRecord",
    "RuntimeUpgradeListItem",
    "RuntimeUpgradeListPage",
    "RuntimeInstruction",
    "RuntimeUpgradeActionResponse",
    "GovernanceCanonicalObject",
    "GovernanceContractEmergencyHoldRecord",
    "GovernanceContractLifecycleRecord",
    "GovernanceContractRecord",
    "GovernanceContractLifecycleAction",
    "GovernanceContractLifecycleActionKind",
    "GovernanceContractLifecycleActionPayload",
    "GovernanceContractLifecycleActivate",
    "GovernanceContractLifecycleDeactivate",
    "GovernanceContractLifecycleEmergencyHoldRetrospective",
    "GovernanceContractLifecycleOfferOwnership",
    "GovernanceGlobalDataTriggerPermissionAction",
    "GovernanceManifestProvenance",
    "GovernanceMusubiActionKind",
    "GovernanceProposalDeployContract",
    "GovernanceProposalContractEmergencyHold",
    "GovernanceProposalContractLifecycleGovernance",
    "GovernanceProposalGlobalDataTriggerPermissionGovernance",
    "GovernanceProposalKind",
    "GovernanceProposalKindTag",
    "GovernanceProposalMusubiRegistryGovernance",
    "GovernanceProposalRecord",
    "GovernanceProposalResult",
    "GovernanceProposalRuntimeUpgrade",
    "GovernanceProposalSccpRouteGovernance",
    "GovernanceProposalSorafsProviderGovernance",
    "GovernanceProposalLifecycleStatus",
    "GovernanceProposalValidationFeePayoutLifecycle",
    "GovernanceProposalValidationFeePolicy",
    "GovernanceRuntimeUpgradeManifest",
    "GovernanceSorafsProviderAction",
    "GovernanceSorafsProviderActionKind",
    "GovernanceValidationFeeChargingMode",
    "GovernanceValidationFeePayoutBinding",
    "GovernanceValidationFeeRewardCustody",
    "GovernanceValidationFeePolicy",
    "ToriiCanonicalRequestAuth",
    "canonical_query_string",
    "canonical_request_message",
    "canonical_network_request_signature_message",
    "build_canonical_request_headers",
    "VpnQuoteCreateRequest",
    "VpnSessionCreateRequest",
    "VpnReceiptSubmitRequest",
    "VpnProfile",
    "VpnQuote",
    "VpnSession",
    "VpnReceipt",
    "VpnReceiptListResponse",
    "ConnectAppRecord",
    "ConnectAppRegistryPage",
    "ConnectAdmissionManifestEntry",
    "ConnectAdmissionManifest",
    "ConnectAppPolicyControls",
]


_PIPELINE_STATUS_KINDS = frozenset(
    {"Queued", "Approved", "Committed", "Applied", "Rejected", "Expired"}
)
_DEFAULT_RETRY_STATUSES = frozenset({429, 502, 503, 504})
_DEFAULT_RETRY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_HTTP_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})
_ZK_X509_PRIVACY_PROTOCOL_ID_V1 = "iroha-zk-x509-stark-p256-v1"
_CONTRACT_CALL_BATCH_BINDING_DOMAIN_V1 = b"iroha:contract-call-batch-binding:v1\0"
_CONTRACT_CALL_BATCH_ARGUMENTS_DOMAIN_V1 = b"iroha:contract-call-batch-arguments:v1\0"
_CONTRACT_CALL_BATCH_INSTRUCTION_DOMAIN_V1 = (
    b"iroha:contract-call-batch-instruction:v1\0"
)
_CONTRACT_CALL_BATCH_MAX_ITEMS = 256
_CONTRACT_CALL_RESERVED_METADATA_PREFIXES = ("contract_", "validation_fee_")
_CONTRACT_CALL_RESERVED_METADATA_KEYS = frozenset(
    {"fee_sponsor", "fee_sponsor_account", "gas_asset_id", "gas_limit"}
)


def _normalize_torii_base_url(value: Any) -> str:
    """Return an origin-only HTTP(S) URL suitable for Torii requests."""

    if not isinstance(value, str):
        raise TypeError("base_url must be a string")
    if not value or value != value.strip():
        raise ValueError("base_url must be a non-empty URL without surrounding whitespace")
    if "\\" in value or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("base_url must not contain backslashes, spaces, or control characters")
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("base_url must use http or https")
    if not parsed.netloc or parsed.hostname is None:
        raise ValueError("base_url must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must not include credentials")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("base_url must contain only an origin, without a path, query, or fragment")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("base_url contains an invalid port") from exc
    return urlunparse((parsed.scheme.lower(), parsed.netloc, "", "", "", ""))


def _normalize_request_path(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("path must be a string")
    if not value.startswith("/") or value.startswith("//"):
        raise ValueError("path must be an origin-relative path beginning with one slash")
    if "\\" in value or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("path must not contain backslashes, spaces, or control characters")
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise ValueError("path must not contain an origin or fragment")
    return value


def _normalize_http_method(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise TypeError("method must be a non-empty HTTP method string")
    normalized = value.upper()
    if normalized not in _HTTP_METHODS:
        raise ValueError(f"unsupported HTTP method {value!r}")
    return normalized


def _require_positive_finite_float(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{context} must be a finite positive number")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized <= 0.0:
        raise ValueError(f"{context} must be a finite positive number")
    return normalized


def _require_non_negative_finite_float(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{context} must be a finite non-negative number")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0.0:
        raise ValueError(f"{context} must be a finite non-negative number")
    return normalized


def _require_retry_count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("max_retries must be a non-negative integer")
    if value < 0:
        raise ValueError("max_retries must be a non-negative integer")
    return value


def _normalize_retry_statuses(value: Optional[Iterable[Any]]) -> frozenset[int]:
    if value is None:
        return _DEFAULT_RETRY_STATUSES
    if isinstance(value, (str, bytes, bytearray)):
        raise TypeError("retry_on_status must be an iterable of HTTP status integers")
    result: set[int] = set()
    for status in value:
        if isinstance(status, bool) or not isinstance(status, int):
            raise TypeError("retry_on_status entries must be HTTP status integers")
        if not 400 <= status <= 599:
            raise ValueError("retry_on_status entries must be HTTP error statuses (400..599)")
        result.add(status)
    return frozenset(result)


def _normalize_retry_methods(value: Optional[Iterable[Any]]) -> frozenset[str]:
    if value is None:
        return _DEFAULT_RETRY_METHODS
    if isinstance(value, (str, bytes, bytearray)):
        raise TypeError("retry_on_methods must be an iterable of HTTP method strings")
    result: set[str] = set()
    for method in value:
        if not isinstance(method, str) or not method or method != method.strip():
            raise TypeError("retry_on_methods entries must be non-empty HTTP method strings")
        normalized = method.upper()
        if normalized not in _HTTP_METHODS:
            raise ValueError(f"retry_on_methods contains unsupported HTTP method {method!r}")
        result.add(normalized)
    return frozenset(result)


def _transaction_wait_seconds(value: Any, *, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{context} must be a finite non-negative number")
    seconds = float(value)
    if not math.isfinite(seconds) or seconds < 0.0:
        raise ValueError(f"{context} must be a finite non-negative number")
    return seconds


def _transaction_wait_max_attempts(value: Any, *, context: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{context} must be a positive integer")
    if value <= 0:
        raise ValueError(f"{context} must be a positive integer")
    return value


try:  # pragma: no cover - optional dependency
    import websocket
except ImportError:  # pragma: no cover - optional dependency
    websocket = None

class TransactionStatusError(RuntimeError):
    """Raised when a transaction reaches a terminal failure status."""

    def __init__(self, hash_hex: str, status: Optional[str], payload: Any) -> None:
        self.hash_hex = hash_hex
        self.status = status
        self.payload = payload
        status_repr = repr(status) if status is not None else "unknown"
        super().__init__(f"transaction {hash_hex} reported failure status {status_repr}")


class DataModelMismatchError(RuntimeError):
    """Raised when the node data model version does not match the SDK."""

    def __init__(self, expected: int, actual: Optional[int]) -> None:
        actual_label = "missing" if actual is None else str(actual)
        super().__init__(
            f"Torii data model version mismatch (expected {expected}, got {actual_label})"
        )
        self.expected = expected
        self.actual = actual

_ToriiClientStreamingQueryMixin: type[Any] = create_torii_client_streaming_query_mixin(
    require_crypto=_require_crypto,
    expect_sorafs_reputation_status=expect_status_without_body,
)

_ToriiClientGovernanceBallotMixin: type[Any] = create_torii_client_governance_ballot_mixin(
    network_id_type=NetworkId,
    canonical_auth_type=ToriiCanonicalRequestAuth,
    normalize_network_id=_normalize_network_id,
    require_exact_non_empty_string=_require_exact_non_empty_string,
    normalize_canonical_auth=_normalize_sorafs_reputation_canonical_auth,
    normalize_plain_ballot=_normalize_governance_plain_ballot_payload,
    normalize_zk_ballot_v1=_normalize_governance_zk_ballot_v1_payload,
    normalize_zk_ballot_proof_v1=_normalize_governance_zk_ballot_proof_payload,
)
_ToriiClientSpaceDirectoryMixin: type[Any] = create_torii_client_space_directory_mixin(
    canonical_auth_type=ToriiCanonicalRequestAuth,
    normalize_publish_request=_normalize_publish_space_directory_manifest_request,
    normalize_revoke_request=_normalize_revoke_space_directory_manifest_request,
    normalize_transaction_draft=_normalize_app_api_transaction_draft,
)

_ToriiClientRuntimeAuthMixin: type[Any] = create_torii_client_runtime_auth_mixin(
    node_capabilities_type=NodeCapabilities,
    node_admin_snapshot_type=NodeAdminSnapshot,
    runtime_metrics_type=RuntimeMetrics,
    runtime_abi_active_type=RuntimeAbiActive,
)


def _fetch_authenticated_privacy_capabilities_archive_v1(
    client: "ToriiClient", canonical_auth: ToriiCanonicalRequestAuth
) -> bytes:
    """Fixed transport entry used by native admission; never accepts archived bytes."""
    if type(client) is not ToriiClient:
        raise TypeError("Exact12 admission requires the configured SDK ToriiClient")
    context = "Exact12 privacy capability manifest"
    expected_network = client._require_local_signing_context(context).network_id
    if urlparse(client._base_url).scheme != "https":
        raise ValueError("Exact12 privacy capabilities require an HTTPS Torii endpoint")
    if (
        not isinstance(canonical_auth, ToriiCanonicalRequestAuth)
        or canonical_auth.network_id != expected_network.literal
    ):
        raise ValueError("Exact12 canonical authentication belongs to a different network")
    response = client._account_request(
        "GET", "/v1/privacy/capabilities",
        canonical_auth=canonical_auth,
        headers={
            "Accept": "application/x-norito",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-store",
        },
        stream=True,
        context=context,
    )
    try:
        if response.url != f"{client._base_url}/v1/privacy/capabilities" or response.history:
            raise ValueError("Exact12 capability response must come from the exact signed URL without redirects")
        if response.headers.get("Content-Type") != "application/x-norito":
            raise ValueError("privacy capabilities response must use exact application/x-norito")
        if response.headers.get("Content-Encoding") not in (None, "identity"):
            raise ValueError("Exact12 capability response Content-Encoding must be identity")
        if response.status_code != 200:
            raise ValueError("Exact12 capability response status must be 200")
        body = _read_bounded_response_body(response, 256 * 1024, context)
        declared_length = response.headers.get("Content-Length")
        if not body or (declared_length is not None and int(declared_length) != len(body)):
            raise ValueError("Exact12 capability response must have an exact nonempty body length")
        return body
    finally:
        response.close()


class _AccountCollections(AccountsCollection):
    """Facade account scope with its configured identity and strict permission decoder."""

    def permissions(self, account_id: str) -> Collection[Dict[str, Any]]:
        canonical = self._transport._normalize_canonical_account_id(account_id, "account_id")
        return Collection(
            self._transport,
            f"/v1/accounts/{quote(canonical, safe='')}/permissions",
            lambda payload: AccountPermissionRecord.from_payload(payload).raw,
            "account permissions",
        )


class ToriiClient(
    _ToriiClientSpaceDirectoryMixin,
    ToriiClientIsoOperatorContextMixin,
    _ToriiClientRuntimeAuthMixin,
    _ToriiClientGovernanceBallotMixin,
    _ToriiClientStreamingQueryMixin,
    _BaseToriiClient,
):
    """Typed, fail-closed HTTP client for Torii's first-release API."""

    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        *,
        local_signing_context: Optional[LocalSigningContext] = None,
        operator_signing_context: Optional[OperatorSigningContext] = None,
        canonical_request_auth: Optional[ToriiCanonicalRequestAuth] = None,
        auth_token: Optional[str] = None,
        api_token: Optional[str] = None,
        default_headers: Optional[Mapping[str, str]] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_initial: float = 0.5,
        backoff_max: float = 5.0,
        backoff_multiplier: float = 2.0,
        retry_on_status: Optional[Sequence[int]] = None,
        retry_on_methods: Optional[Sequence[str]] = None,
        chain_discriminant: Optional[int] = None,
        sorafs_alias_policy: Optional[Union[SorafsAliasPolicy, Mapping[str, Any]]] = None,
        sorafs_alias_warning: Optional[Callable[[SorafsAliasWarning], None]] = None,
        sorafs_alias_logger: Optional[logging.Logger] = None,
    ) -> None:
        if session is not None and not isinstance(session, requests.Session):
            raise TypeError("session must be a requests.Session")
        if (
            local_signing_context is not None
            and not isinstance(local_signing_context, LocalSigningContext)
        ):
            raise TypeError("local_signing_context must be a LocalSigningContext")
        base_local_signing_context = (
            None
            if local_signing_context is None
            else _BaseLocalSigningContext(
                network_id=local_signing_context.network_id.literal,
            )
        )
        normalized_base_url = _normalize_torii_base_url(base_url)
        if operator_signing_context is not None and not isinstance(
            operator_signing_context,
            OperatorSigningContext,
        ):
            raise TypeError(
                "operator_signing_context must be an OperatorSigningContext"
            )
        if canonical_request_auth is not None:
            if not isinstance(canonical_request_auth, ToriiCanonicalRequestAuth):
                raise TypeError(
                    "canonical_request_auth must be a ToriiCanonicalRequestAuth"
                )
            _BaseToriiClient._require_exact_i105_account_id(
                canonical_request_auth.account_id,
                "canonical_request_auth.account_id",
            )
        normalized_chain_discriminant = normalize_i105_discriminant(
            DEFAULT_I105_DISCRIMINANT if chain_discriminant is None else chain_discriminant,
            "chain_discriminant",
        )
        normalized_timeout = _require_positive_finite_float(timeout, "timeout")
        normalized_max_retries = _require_retry_count(max_retries)
        normalized_retry_statuses = _normalize_retry_statuses(retry_on_status)
        normalized_retry_methods = _normalize_retry_methods(retry_on_methods)
        normalized_headers: Dict[str, str] = {"Accept": "application/json"}
        if default_headers is not None:
            copied_headers = _copy_http_headers(default_headers, "default_headers")
            _reject_reserved_default_headers(copied_headers, "default_headers")
            for name, value in copied_headers.items():
                _set_exact_header(normalized_headers, name, value)
        normalized_auth_token = (
            None
            if auth_token is None
            else _require_route_token(auth_token, "auth_token")
        )
        normalized_api_token = (
            None
            if api_token is None
            else _require_route_token(api_token, "api_token")
        )
        normalized_backoff_initial = _require_non_negative_finite_float(
            backoff_initial,
            "backoff_initial",
        )
        normalized_backoff_max = _require_non_negative_finite_float(
            backoff_max,
            "backoff_max",
        )
        normalized_backoff_multiplier = _require_positive_finite_float(
            backoff_multiplier,
            "backoff_multiplier",
        )
        if normalized_backoff_multiplier < 1.0:
            raise ValueError("backoff_multiplier must be at least 1")
        if normalized_backoff_max < normalized_backoff_initial:
            raise ValueError("backoff_max must be greater than or equal to backoff_initial")
        normalized_sorafs_alias_policy = _normalize_sorafs_policy_config(
            sorafs_alias_policy
        )

        super().__init__(
            normalized_base_url,
            session=session,
            local_signing_context=base_local_signing_context,
            canonical_request_auth=canonical_request_auth,
            timeout=normalized_timeout,
        )
        try:
            _reject_session_route_secrets(self._session)
        except BaseException:
            self.close()
            raise
        self.__local_signing_context = local_signing_context
        self._install_operator_signing_context(operator_signing_context)
        self._chain_discriminant = normalized_chain_discriminant
        self._max_retries = normalized_max_retries
        self._retry_statuses = normalized_retry_statuses
        self._retry_methods = normalized_retry_methods
        self._default_headers = normalized_headers
        self._auth_token = normalized_auth_token
        self._api_token = normalized_api_token
        self._status_state = _ToriiStatusState()
        if normalized_auth_token is not None:
            self._default_headers["Authorization"] = f"Bearer {normalized_auth_token}"
        if normalized_api_token is not None:
            self._default_headers["X-API-Token"] = normalized_api_token
        self._backoff_initial = normalized_backoff_initial
        self._backoff_cap = normalized_backoff_max
        self._backoff_multiplier = normalized_backoff_multiplier
        self._sorafs_alias_policy = normalized_sorafs_alias_policy
        self._sorafs_alias_warning_hook = sorafs_alias_warning
        self._sorafs_alias_logger = sorafs_alias_logger or logging.getLogger(
            "iroha_python.sorafs.client"
        )
        self._sorafs_alias_metrics: Dict[str, int] = {}
        self._last_sorafs_alias_evaluation: Optional[SorafsAliasEvaluation] = None
        self._data_model_validation = "unknown"
        self._data_model_actual: Optional[int] = None

    @property
    def accounts(self) -> AccountsCollection:
        """Accounts and their scoped collections, with configured account identity validation."""

        return _AccountCollections(self, "/v1/accounts", Account.from_json, "accounts")

    @property
    def explorer_rwas(self) -> HistoryCollection[ExplorerRwaRecord]:
        """Bounded Explorer RWA rows with shared queries and strict quantity decoding."""

        return HistoryCollection(
            self, "/v1/explorer/rwas", ExplorerRwaRecord.from_payload, "Explorer RWAs", "explorer_rwas"
        )

    @property
    def repo_agreements(self) -> Collection[RepoAgreementRecord]:
        """``/v1/repo/agreements``, decoded as :class:`~iroha_python.repo.RepoAgreementRecord`."""

        return Collection(
            self,
            "/v1/repo/agreements",
            RepoAgreementRecord.from_payload,
            "repo agreements",
        )

    @property
    def local_signing_context(self) -> Optional[LocalSigningContext]:
        """Immutable context used by APIs that return local-signing drafts."""

        return self.__local_signing_context

    def _require_local_signing_context(self, context: str) -> LocalSigningContext:
        signing_context = self.__local_signing_context
        if signing_context is None:
            raise ValueError(
                f"{context} requires immutable ToriiClient local_signing_context"
            )
        return signing_context

    def _normalize_canonical_account_id(self, value: Any, context: str) -> str:
        return _normalize_canonical_account_id(
            value,
            context,
            expected_discriminant=self._chain_discriminant,
        )

    def _native_transaction_account_id(self, value: Any, context: str) -> str:
        literal = _require_non_empty_string(value, context)
        if "@" in literal:
            return literal
        candidate_discriminants = [DEFAULT_I105_DISCRIMINANT]
        if self._chain_discriminant != DEFAULT_I105_DISCRIMINANT:
            candidate_discriminants.append(self._chain_discriminant)
        for discriminant in candidate_discriminants:
            try:
                address = AccountAddress.parse_encoded(
                    literal,
                    expected_discriminant=discriminant,
                )
            except AccountAddressError:
                continue
            return address.to_i105(DEFAULT_I105_DISCRIMINANT)
        return literal

    def _exact_account_identity_pin(self, value: Any, context: str) -> str:
        """Validate an exact I105 literal while treating its discriminator as presentation."""

        return _normalize_exact_any_i105_account_id(value, context)

    def _native_transaction_asset_id(self, value: Any, context: str) -> str:
        literal = _require_non_empty_string(value, context)
        parts = literal.split("#")
        if len(parts) not in {2, 3} or not all(parts):
            return literal
        definition, account_id = parts[0], parts[1]
        scope = parts[2] if len(parts) == 3 else None
        native_account_id = self._native_transaction_account_id(
            account_id,
            f"{context}.account_id",
        )
        if native_account_id == account_id:
            return literal
        result = f"{definition}#{native_account_id}"
        if scope is not None:
            result = f"{result}#{scope}"
        return result

    def privacy_capabilities_v1(
        self, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> "PrivacyExact12CapabilityManifestV1":
        """Fetch native-validated committed state for this exact HTTPS Torii network.

        The native boundary owns the immutable origin seal used by transaction
        construction. Public archive decoding remains inspection-only.
        """
        return _require_crypto()._fetch_privacy_exact12_capability_manifest_v1(
            self, canonical_auth
        )

    def submit_signed_privacy_zk_x509_identity_presentation_action_v1(
        self,
        signed_transaction_versioned: bytes | bytearray | memoryview,
        *,
        canonical_auth: ToriiCanonicalRequestAuth,
        network_id: "NetworkId",
        wait: bool = True,
        interval: float = 1.0,
        timeout: Optional[float] = 30.0,
        max_attempts: Optional[int] = None,
        on_status: Optional[Callable[[Optional[str], Any, int], None]] = None,
    ) -> tuple["SignedTransactionEnvelope", Any]:
        """Authenticate, live-gate, and submit one exact ZK-X509 action.

        The signed wire is inspected locally against the exact ``network_id``
        before any network operation.  A fresh authoritative capability
        snapshot must then expose the unique ZK-X509 row with an available
        compiled profile and an active governed lifecycle.  No submission is
        attempted when either check fails.
        """

        signing_context = self._require_local_signing_context(
            "submit_signed_privacy_zk_x509_identity_presentation_action_v1"
        )
        network_id = _normalize_network_id(network_id, "network_id")
        if network_id != signing_context.network_id:
            raise ValueError(
                "network_id does not match ToriiClient local_signing_context"
            )
        crypto = _require_crypto()
        inspection = (
            crypto.inspect_signed_privacy_zk_x509_identity_presentation_action_v1(
                signed_transaction_versioned,
                network_id,
            )
        )
        if not isinstance(inspection, Mapping) or inspection.get(
            "protocol_id"
        ) != _ZK_X509_PRIVACY_PROTOCOL_ID_V1:
            raise RuntimeError(
                "native ZK-X509 inspector returned a mismatched privacy protocol"
            )
        wire = bytes(signed_transaction_versioned)
        manifest = self.privacy_capabilities_v1(canonical_auth=canonical_auth)
        capability = manifest.require_network_capability(
            _ZK_X509_PRIVACY_PROTOCOL_ID_V1
        )
        if not isinstance(capability, Mapping) or capability.get(
            "protocol_id"
        ) != _ZK_X509_PRIVACY_PROTOCOL_ID_V1:
            raise RuntimeError(
                "native Exact12 capability gate returned a mismatched privacy protocol"
            )
        envelope = crypto.signed_transaction_envelope_from_versioned_v1(
            wire,
            signing_context.network_id,
        )
        authenticated_wire = getattr(envelope, "signed_transaction_versioned", None)
        if not isinstance(authenticated_wire, (bytes, bytearray, memoryview)) or bytes(
            authenticated_wire
        ) != wire:
            raise RuntimeError(
                "authenticated ZK-X509 transaction envelope changed the submitted wire"
            )

        if wait:
            result = self.submit_transaction_envelope_and_wait(
                envelope,
                interval=interval,
                timeout=timeout,
                max_attempts=max_attempts,
                on_status=on_status,
            )
        else:
            result = self.submit_transaction_envelope(envelope)
        return envelope, result

    @property
    def sorafs_alias_policy(self) -> SorafsAliasPolicy:
        """Return the resolved SoraFS alias cache policy."""

        return self._sorafs_alias_policy

    def set_sorafs_alias_policy(
        self,
        policy: Optional[Union[SorafsAliasPolicy, Mapping[str, Any]]],
    ) -> None:
        """Override the SoraFS alias cache policy used for validation."""

        self._sorafs_alias_policy = _normalize_sorafs_policy_config(policy)
        self._sorafs_alias_metrics.clear()
        self._last_sorafs_alias_evaluation = None

    def set_sorafs_alias_warning(
        self, callback: Optional[Callable[[SorafsAliasWarning], None]]
    ) -> None:
        """Install a callback invoked when proofs enter the refresh window or require rotation."""

        self._sorafs_alias_warning_hook = callback

    def get_sorafs_alias_metrics(self) -> Dict[str, int]:
        """Return aggregate counters for alias proof evaluations."""

        return dict(self._sorafs_alias_metrics)

    def get_last_sorafs_alias_evaluation(self) -> Optional[SorafsAliasEvaluation]:
        """Return the most recent alias proof evaluation observed by the client, if any."""

        return self._last_sorafs_alias_evaluation

    def _ensure_data_model_validation(self) -> None:
        _validate_client_data_model(
            self,
            canonical_auth=self._canonical_request_auth,
            expected_version=DATA_MODEL_VERSION,
            mismatch_error_type=DataModelMismatchError,
        )

    def submit_transaction(self, payload: bytes) -> Optional[Any]:
        """Submit a Norito-encoded transaction payload to `/v1/pipeline/transactions`.

        Raises :class:`DataModelMismatchError` when the node data model version mismatches.
        """

        self._ensure_data_model_validation()
        response = self._request(
            "POST",
            "/v1/pipeline/transactions",
            data=payload,
            headers={
                "Content-Type": "application/x-norito",
                "Accept": "application/x-norito, application/json",
            },
        )
        self._expect_status(response, {200, 201, 202, 204})
        receipt = type(self)._maybe_transaction_receipt(response)
        if receipt is not None:
            return receipt
        return type(self)._maybe_json(response)

    @staticmethod
    def _native_query_signing_key(
        *,
        private_key: Optional[bytes],
        private_key_hex: Optional[str],
    ) -> bytes:
        if (private_key is None) == (private_key_hex is None):
            raise ValueError("provide exactly one of private_key or private_key_hex")
        if private_key_hex is not None:
            if (
                type(private_key_hex) is not str
                or re.fullmatch(r"[0-9a-f]{64}", private_key_hex) is None
            ):
                raise ValueError(
                    "private_key_hex must contain exactly 64 lowercase hexadecimal characters"
                )
            return bytes.fromhex(private_key_hex)
        if type(private_key) is not bytes:
            raise TypeError("private_key must be exact immutable bytes")
        if len(private_key) != 32:
            raise ValueError("private_key must contain exactly 32 bytes")
        return private_key

    @staticmethod
    def _native_query_response_bytes(
        response: requests.Response,
        context: str,
    ) -> bytes:
        content_type = response.headers.get("Content-Type", "")
        if "application/x-norito" not in content_type.lower():
            raise RuntimeError(f"{context} did not return canonical Norito")
        content = response.content
        if not isinstance(content, (bytes, bytearray, memoryview)) or not content:
            raise RuntimeError(f"{context} returned an empty response")
        return bytes(content)

    def get_verified_committed_transaction(
        self,
        *,
        transaction_hash: str,
        authority: str,
        network_id: "NetworkId",
        native_finality_proof_chain_json: str,
        expected_chain: str,
        trusted_checkpoint: bytes,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
    ) -> VerifiedCommittedTransaction:
        """Fetch and authenticate a selective row from an independent native checkpoint.

        The native proof page must begin at the selected checkpoint and extend
        consecutively to the carrier. Network, chain and checkpoint are caller
        trust inputs. Check ``result_ok`` before treating execution as successful,
        and retain ``promoted_checkpoint`` atomically with the accepted result.
        """

        from .crypto import (
            build_find_committed_transaction_query,
            verify_committed_transaction_inclusion,
        )

        normalized_hash = _require_exact_pipeline_transaction_hash(
            transaction_hash,
            "transaction_hash",
        )
        canonical_authority = self._native_transaction_account_id(authority, "authority")
        signing_key = self._native_query_signing_key(
            private_key=private_key,
            private_key_hex=private_key_hex,
        )
        network_id = _normalize_network_id(network_id, "network_id")
        if type(trusted_checkpoint) is not bytes:
            raise TypeError("trusted_checkpoint must be exact immutable bytes")
        if not trusted_checkpoint or len(trusted_checkpoint) > 68 * 1024 * 1024:
            raise ValueError("trusted_checkpoint must contain 1..68 MiB")
        if type(expected_chain) is not str:
            raise TypeError("expected_chain must be a string")
        if not expected_chain or len(expected_chain.encode("utf-8")) > 1024:
            raise ValueError("expected_chain must contain 1..1024 UTF-8 bytes")
        if type(native_finality_proof_chain_json) is not str:
            raise TypeError("native_finality_proof_chain_json must be a string")
        if not native_finality_proof_chain_json or len(native_finality_proof_chain_json.encode("utf-8")) > 16 * 1024 * 1024:
            raise ValueError("native_finality_proof_chain_json must contain 1..16 MiB")
        transaction_request = build_find_committed_transaction_query(
            canonical_authority,
            signing_key,
            network_id,
            normalized_hash,
        )
        transaction_response = self._request(
            "POST",
            "/v1/query",
            data=transaction_request,
            headers={
                "Content-Type": "application/x-norito",
                "Accept": "application/x-norito",
            },
        )
        self._expect_status(transaction_response, {200})
        transaction_response_bytes = self._native_query_response_bytes(
            transaction_response,
            "committed transaction query",
        )

        verified = verify_committed_transaction_inclusion(
            normalized_hash,
            transaction_response_bytes,
            native_finality_proof_chain_json=native_finality_proof_chain_json,
            expected_network_id=network_id,
            expected_chain=expected_chain,
            trusted_checkpoint=trusted_checkpoint,
        )
        result = VerifiedCommittedTransaction.from_payload(verified)
        if result.transaction_hash != normalized_hash:
            raise RuntimeError(
                "native verifier returned a different committed transaction hash"
            )
        return result

    def get_asset_escrow(
        self,
        *,
        escrow_id: str,
        authority: str,
        network_id: "NetworkId",
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
    ) -> Mapping[str, Any]:
        """Execute ``FindAssetEscrowById`` and return its complete native record."""

        from .crypto import build_find_asset_escrow_query

        request = build_find_asset_escrow_query(
            self._native_transaction_account_id(authority, "authority"),
            self._native_query_signing_key(
                private_key=private_key,
                private_key_hex=private_key_hex,
            ),
            _normalize_network_id(network_id, "network_id"),
            _require_exact_non_empty_string(escrow_id, "escrow_id"),
        )
        response = self._request(
            "POST",
            "/v1/query",
            data=request,
            headers={
                "Content-Type": "application/x-norito",
                "Accept": "application/json",
            },
        )
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, Mapping):
            raise RuntimeError("unexpected native escrow query response")
        records = self._asset_escrow_records_from_query_payload(payload)
        if len(records) != 1:
            raise RuntimeError(
                "native escrow query did not return exactly one asset escrow record"
            )
        return records[0]

    @staticmethod
    def _asset_escrow_records_from_query_payload(
        payload: Mapping[str, Any],
    ) -> List[Mapping[str, Any]]:
        records: List[Mapping[str, Any]] = []

        def visit(value: Any) -> None:
            if isinstance(value, Mapping):
                if value.get("kind") == "AssetEscrowRecord":
                    content = value.get("content")
                    if isinstance(content, Mapping):
                        records.append(dict(content))
                    elif isinstance(content, Sequence) and not isinstance(
                        content,
                        (str, bytes, bytearray, memoryview),
                    ):
                        for item in content:
                            if not isinstance(item, Mapping):
                                raise RuntimeError(
                                    "native escrow query returned a malformed record"
                                )
                            records.append(dict(item))
                    else:
                        raise RuntimeError(
                            "native escrow query returned malformed record content"
                        )
                    return
                for child in value.values():
                    visit(child)
            elif isinstance(value, Sequence) and not isinstance(
                value,
                (str, bytes, bytearray, memoryview),
            ):
                for child in value:
                    visit(child)

        visit(payload)
        return records

    @staticmethod
    def _asset_escrow_status(record: Mapping[str, Any]) -> Optional[str]:
        status = record.get("status")
        if isinstance(status, Mapping):
            for key in ("status", "kind"):
                value = status.get(key)
                if value is not None:
                    return str(value)
        if status is not None:
            return str(status)
        return None

    def _list_asset_escrows_by_party(
        self,
        *,
        account_id: str,
        authority: str,
        network_id: "NetworkId",
        private_key: Optional[bytes],
        private_key_hex: Optional[str],
        party: str,
        status: Optional[str],
        escrow_id: Optional[str],
    ) -> Sequence[Mapping[str, Any]]:
        from .crypto import (
            build_find_asset_escrows_by_buyer_query,
            build_find_asset_escrows_by_seller_query,
        )

        signing_key = self._native_query_signing_key(
            private_key=private_key,
            private_key_hex=private_key_hex,
        )
        canonical_authority = self._native_transaction_account_id(
            authority,
            "authority",
        )
        canonical_account = self._native_transaction_account_id(
            account_id,
            party,
        )
        network_id = _normalize_network_id(network_id, "network_id")
        if party == "seller":
            request = build_find_asset_escrows_by_seller_query(
                canonical_authority,
                signing_key,
                network_id,
                canonical_account,
            )
        elif party == "buyer":
            request = build_find_asset_escrows_by_buyer_query(
                canonical_authority,
                signing_key,
                network_id,
                canonical_account,
            )
        else:  # pragma: no cover - private invariant
            raise AssertionError(f"unsupported escrow party {party!r}")

        response = self._request(
            "POST",
            "/v1/query",
            data=request,
            headers={
                "Content-Type": "application/x-norito",
                "Accept": "application/json",
            },
        )
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, Mapping):
            raise RuntimeError("unexpected native escrow query response")
        records = self._asset_escrow_records_from_query_payload(payload)
        if escrow_id is not None:
            expected_id = _require_exact_non_empty_string(escrow_id, "escrow_id")
            records = [
                record
                for record in records
                if str(record.get("id", record.get("escrow_id"))) == expected_id
            ]
        if status is not None:
            expected_status = _require_exact_non_empty_string(status, "status")
            records = [
                record
                for record in records
                if self._asset_escrow_status(record) == expected_status
            ]
        return records

    def list_asset_escrows_by_seller(
        self,
        *,
        seller: str,
        authority: str,
        network_id: "NetworkId",
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        status: Optional[str] = None,
        escrow_id: Optional[str] = None,
    ) -> Sequence[Mapping[str, Any]]:
        """Return native escrow records funded by ``seller``."""

        return self._list_asset_escrows_by_party(
            account_id=seller,
            authority=authority,
            network_id=network_id,
            private_key=private_key,
            private_key_hex=private_key_hex,
            party="seller",
            status=status,
            escrow_id=escrow_id,
        )

    def list_asset_escrows_by_buyer(
        self,
        *,
        buyer: str,
        authority: str,
        network_id: "NetworkId",
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        status: Optional[str] = None,
        escrow_id: Optional[str] = None,
    ) -> Sequence[Mapping[str, Any]]:
        """Return native escrow records benefiting ``buyer``."""

        return self._list_asset_escrows_by_party(
            account_id=buyer,
            authority=authority,
            network_id=network_id,
            private_key=private_key,
            private_key_hex=private_key_hex,
            party="buyer",
            status=status,
            escrow_id=escrow_id,
        )

    def submit_transaction_envelope(self, envelope: "SignedTransactionEnvelope") -> Optional[Any]:
        """Submit a transaction using a :class:`SignedTransactionEnvelope`."""

        payload = envelope.signed_transaction_versioned
        return self.submit_transaction(bytes(payload))

    def submit_transaction_draft(
        self,
        draft: "TransactionDraft",
        *,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
    ) -> tuple["SignedTransactionEnvelope", Optional[Any]]:
        """Sign a :class:`TransactionDraft` and submit it to Torii.

        Exactly one of ``private_key`` or ``private_key_hex`` must be provided.
        The signed payload is exactly the immutable config and staged entries on
        ``draft``; submission-time transaction overrides are not accepted.
        """

        if (private_key is None) and (private_key_hex is None):
            raise ValueError("provide either `private_key` or `private_key_hex`")
        if private_key is not None and private_key_hex is not None:
            raise ValueError("provide only one of `private_key` or `private_key_hex`")

        envelope = self._sign_transaction_draft(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
        )
        status = self.submit_transaction_envelope(envelope)
        return envelope, status

    def submit_transaction_json(self, envelope_json: str) -> Optional[Any]:
        """Submit a transaction described by the JSON produced via `to_json`."""

        envelope = signed_transaction_envelope_from_json(envelope_json)
        return self.submit_transaction_envelope(envelope)

    def submit_transaction_draft_and_wait(
        self,
        draft: "TransactionDraft",
        *,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        interval: float = 1.0,
        timeout: Optional[float] = 30.0,
        max_attempts: Optional[int] = None,
        on_status: Optional[Callable[[Optional[str], Any, int], None]] = None,
    ) -> Any:
        """Sign a draft, submit it, and wait for the transaction to reach a terminal status."""

        envelope = self._sign_transaction_draft(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
        )
        return self.submit_transaction_envelope_and_wait(
            envelope,
            interval=interval,
            timeout=timeout,
            max_attempts=max_attempts,
            on_status=on_status,
        )

    @staticmethod
    def _sign_transaction_draft(
        draft: "TransactionDraft",
        *,
        private_key: Optional[bytes],
        private_key_hex: Optional[str],
    ) -> "SignedTransactionEnvelope":
        if private_key is None and private_key_hex is None:
            raise ValueError("provide either `private_key` or `private_key_hex`")
        if private_key is not None and private_key_hex is not None:
            raise ValueError("provide only one of `private_key` or `private_key_hex`")

        if private_key_hex is not None:
            return draft.sign_hex_private_key(private_key_hex)
        assert private_key is not None
        return draft.sign(private_key)

    def submit_transaction_json_and_wait(
        self,
        envelope_json: str,
        *,
        interval: float = 1.0,
        timeout: Optional[float] = 30.0,
        max_attempts: Optional[int] = None,
        on_status: Optional[Callable[[Optional[str], Any, int], None]] = None,
    ) -> Any:
        """Submit a transaction JSON blob and wait for final status."""

        envelope = signed_transaction_envelope_from_json(envelope_json)
        return self.submit_transaction_envelope_and_wait(
            envelope,
            interval=interval,
            timeout=timeout,
            max_attempts=max_attempts,
            on_status=on_status,
        )

    def submit_transaction_envelope_and_wait(
        self,
        envelope: "SignedTransactionEnvelope",
        *,
        interval: float = 1.0,
        timeout: Optional[float] = 30.0,
        max_attempts: Optional[int] = None,
        on_status: Optional[Callable[[Optional[str], Any, int], None]] = None,
    ) -> Any:
        """Submit a signed transaction and wait for its terminal status."""

        hash_hex = self._envelope_hash_hex(envelope)
        self.submit_transaction_envelope(envelope)

        return self.wait_for_transaction_status(
            hash_hex,
            interval=interval,
            timeout=timeout,
            max_attempts=max_attempts,
            on_status=on_status,
        )

    # ------------------------------------------------------------------
    # HTTP helper utilities
    # ------------------------------------------------------------------
    def set_auth_token(self, token: Optional[str]) -> None:
        """Configure (or clear) the Authorization bearer token."""

        if token is None:
            self._auth_token = None
            self._default_headers.pop("Authorization", None)
            return
        normalized = _require_route_token(token, "auth_token")
        self._auth_token = normalized
        self._default_headers["Authorization"] = f"Bearer {normalized}"

    def set_api_token(self, token: Optional[str]) -> None:
        """Configure (or clear) the Torii `X-API-Token` header."""

        if token is None:
            self._api_token = None
            self._default_headers.pop("X-API-Token", None)
            return
        normalized = _require_route_token(token, "api_token")
        self._api_token = normalized
        self._default_headers["X-API-Token"] = normalized

    def update_default_headers(self, headers: Mapping[str, str]) -> None:
        """Merge `headers` into the default header set applied to every request."""

        copied_headers = _copy_http_headers(headers, "headers")
        _reject_reserved_default_headers(copied_headers, "headers")
        for name, value in copied_headers.items():
            _set_exact_header(self._default_headers, name, value)

    def request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        data: Optional[bytes] = None,
        expected_status: Sequence[int] = (200,),
        timeout: Optional[float] = None,
        allow_retry: bool = True,
    ) -> Optional[Any]:
        """Issue an HTTP request and decode the JSON payload when present."""

        response = self._request(
            method,
            path,
            params=params,
            headers=headers,
            json_body=json_body,
            data=data,
            timeout=timeout,
            allow_retry=allow_retry,
        )
        self._expect_status(response, expected_status)
        return self._maybe_json(response)

    @staticmethod
    def _operator_key_pair(
        *,
        key_pair: Optional[Any] = None,
        private_key: Optional[Union[str, bytes, bytearray, memoryview]] = None,
        private_key_hex: Optional[str] = None,
    ) -> Any:
        provided = sum(value is not None for value in (key_pair, private_key, private_key_hex))
        if provided != 1:
            raise ValueError("provide exactly one of key_pair, private_key, or private_key_hex")
        if key_pair is not None:
            signer = getattr(key_pair, "sign", None)
            public_key = getattr(key_pair, "public_key_multihash", None)
            if not callable(signer) or public_key is None:
                raise TypeError("key_pair must expose sign(message) and public_key_multihash")
            return key_pair

        from .crypto import CryptoKeyPair, Ed25519KeyPair

        if private_key_hex is not None:
            raw_hex = ToriiClient._require_non_empty_string(private_key_hex, "private_key_hex")
            return Ed25519KeyPair.from_private_key_hex(raw_hex)

        assert private_key is not None
        if isinstance(private_key, (bytes, bytearray, memoryview)):
            return Ed25519KeyPair.from_private_key(bytes(private_key))
        secret = ToriiClient._require_non_empty_string(private_key, "private_key")
        try:
            return CryptoKeyPair.from_private_key_multihash(secret)
        except Exception as multihash_error:
            try:
                raw = bytes.fromhex(secret)
            except ValueError as exc:
                raise ValueError(
                    "private_key must be a private-key multihash or raw Ed25519 hex"
                ) from exc
            if len(raw) != 32:
                raise ValueError("raw Ed25519 private_key must be 32 bytes") from multihash_error
            return Ed25519KeyPair.from_private_key(raw)

    @staticmethod
    def build_operator_signature_headers(
        *,
        network_id: "NetworkId",
        method: str,
        path: str,
        body: Optional[Union[str, bytes, bytearray, memoryview]] = None,
        key_pair: Optional[Any] = None,
        private_key: Optional[Union[str, bytes, bytearray, memoryview]] = None,
        private_key_hex: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        nonce: Optional[str] = None,
    ) -> Dict[str, str]:
        """Build exact-network `x-iroha-operator-*` headers for Torii operator endpoints."""

        network_id = _normalize_network_id(network_id, "network_id")
        key = ToriiClient._operator_key_pair(
            key_pair=key_pair,
            private_key=private_key,
            private_key_hex=private_key_hex,
        )
        public_key = getattr(key, "public_key_multihash", None)
        if not isinstance(public_key, str):
            raise TypeError("operator key pair must expose a public_key_multihash string")
        public_key_text = public_key
        if (
            not public_key_text
            or public_key_text.strip() != public_key_text
            or not public_key_text.isascii()
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in public_key_text
            )
        ):
            raise ValueError("operator public key must be exact non-empty printable ASCII")
        effective_timestamp = int(timestamp_ms if timestamp_ms is not None else time.time() * 1000)
        effective_nonce = nonce if nonce is not None else secrets.token_urlsafe(12)
        if effective_timestamp < 0:
            raise ValueError("timestamp_ms must be non-negative")
        if (
            not isinstance(effective_nonce, str)
            or not effective_nonce
            or len(effective_nonce) > 256
            or any(character.isspace() for character in effective_nonce)
            or not effective_nonce.isascii()
        ):
            raise ValueError(
                "nonce must be non-empty ASCII without whitespace and at most 256 bytes"
            )
        canonical_request = canonical_request_message(method, path, body)
        message = b"".join(
            (
                b"iroha.operator.http-request.network.v1\0",
                bytes(network_id.to_bytes()),
                canonical_request,
                b"\n",
                str(effective_timestamp).encode("ascii"),
                b"\n",
                effective_nonce.encode("ascii"),
            )
        )
        signature = key.sign(message)
        if not isinstance(signature, (bytes, bytearray, memoryview)):
            raise TypeError("operator signer must return bytes")
        return {
            "x-iroha-operator-public-key": public_key_text,
            "x-iroha-operator-timestamp-ms": str(effective_timestamp),
            "x-iroha-operator-nonce": effective_nonce,
            "x-iroha-operator-signature": base64.b64encode(bytes(signature)).decode("ascii"),
        }

    # -------------------------
    # Explorer APIs
    # -------------------------

    def _get_dataspace_visible_response(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
    ) -> requests.Response:
        """Issue one optionally account-signed dataspace-visible GET.

        A configured canonical signer is bound after Requests prepares the final
        path and query. Without one, public dataspaces remain available through
        the ordinary anonymous request path.
        """

        canonical_auth = self._canonical_request_auth
        headers = self._canonical_request_headers(
            "GET",
            path,
            b"",
            canonical_auth=canonical_auth,
            headers={"Accept": "application/json"},
            has_body=False,
        )
        return self._request(
            "GET",
            path,
            params=params,
            headers=headers,
            allow_retry=canonical_auth is None,
            allow_redirects=False,
        )

    def _get_explorer_response(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
    ) -> requests.Response:
        """Issue one optionally account-signed Explorer GET.

        A configured canonical signer is bound after Requests prepares the final
        path and query. Without one, Explorer's public projection remains an
        ordinary anonymous request.
        """

        return self._get_dataspace_visible_response(path, params=params)

    def get_explorer_metrics(self) -> Optional[Any]:
        """Fetch `/v1/explorer/metrics`. Returns `None` when telemetry is gated."""

        response = self._get_explorer_response("/v1/explorer/metrics")
        if response.status_code in {403, 404, 503}:
            return None
        self._expect_status(response, (200,))
        return self._maybe_json(response)

    def get_explorer_metrics_typed(self) -> Optional[ExplorerMetricsSnapshot]:
        """Typed wrapper for :meth:`get_explorer_metrics`."""

        payload = self.get_explorer_metrics()
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise RuntimeError("explorer metrics endpoint returned non-object payload")
        return ExplorerMetricsSnapshot.from_payload(payload)

    def get_explorer_account_qr(
        self,
        account_id: str,
    ) -> Mapping[str, Any]:
        """Fetch explorer QR metadata via `GET /v1/explorer/accounts/{account_id}/qr`."""

        canonical_account_id = self._normalize_canonical_account_id(account_id, "account_id")
        response = self._get_explorer_response(
            f"/v1/explorer/accounts/{quote(canonical_account_id, safe='')}/qr"
        )
        self._expect_status(response, (200,))
        payload = self._maybe_json(response)
        if payload is None:
            raise RuntimeError("explorer account qr endpoint returned no payload")
        if not isinstance(payload, Mapping):
            raise TypeError("explorer account qr response must be a JSON object")
        return payload

    def get_explorer_account_qr_typed(
        self,
        account_id: str,
    ) -> ExplorerAccountQrSnapshot:
        """Typed QR wrapper for :meth:`get_explorer_account_qr`."""

        payload = self.get_explorer_account_qr(account_id)
        return ExplorerAccountQrSnapshot.from_payload(payload)

    def get_explorer_rwa_detail(self, rwa_id: str) -> Mapping[str, Any]:
        """Fetch a single explorer RWA detail via `GET /v1/explorer/rwas/{rwa_id}`."""

        rwa_id_value = _normalize_optional_string(rwa_id, "get_explorer_rwa_detail.rwa_id")
        if rwa_id_value is None:
            raise ValueError("get_explorer_rwa_detail.rwa_id must be a non-empty string")
        response = self._get_explorer_response(
            f"/v1/explorer/rwas/{quote(rwa_id_value, safe='')}"
        )
        self._expect_status(response, (200,))
        payload = self._maybe_json(response)
        if payload is None:
            raise RuntimeError("explorer RWA detail endpoint returned no payload")
        if not isinstance(payload, Mapping):
            raise RuntimeError("explorer RWA detail endpoint returned malformed payload")
        return payload

    def get_explorer_rwa_detail_typed(self, rwa_id: str) -> ExplorerRwaRecord:
        """Typed wrapper for :meth:`get_explorer_rwa_detail`."""

        payload = self.get_explorer_rwa_detail(rwa_id)
        return ExplorerRwaRecord.from_payload(payload)

    # -------------------------
    # ISO 20022 bridge APIs
    # -------------------------

    def submit_iso_pacs008(
        self,
        message: Union[str, bytes, bytearray, memoryview],
        *,
        content_type: Optional[str] = None,
        profile: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """Submit a pacs.008 payload (`POST /v1/iso20022/pacs008`)."""

        return self._submit_iso_message(
            "/v1/iso20022/pacs008",
            message,
            content_type=content_type,
            profile=profile,
            timeout=timeout,
            context="submit_iso_pacs008",
        )

    def submit_iso_pacs008_typed(
        self,
        message: Union[str, bytes, bytearray, memoryview],
        *,
        content_type: Optional[str] = None,
        profile: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Optional[IsoSubmissionRecord]:
        """Typed wrapper for :meth:`submit_iso_pacs008`."""

        payload = self.submit_iso_pacs008(
            message,
            content_type=content_type,
            profile=profile,
            timeout=timeout,
        )
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise RuntimeError("ISO pacs.008 submission returned a non-object payload")
        return IsoSubmissionRecord.from_payload(payload, context="iso pacs.008 submission")

    def submit_iso_pacs009(
        self,
        message: Union[str, bytes, bytearray, memoryview],
        *,
        content_type: Optional[str] = None,
        profile: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """Submit a pacs.009 payload (`POST /v1/iso20022/pacs009`)."""

        return self._submit_iso_message(
            "/v1/iso20022/pacs009",
            message,
            content_type=content_type,
            profile=profile,
            timeout=timeout,
            context="submit_iso_pacs009",
        )

    def submit_iso_pacs009_typed(
        self,
        message: Union[str, bytes, bytearray, memoryview],
        *,
        content_type: Optional[str] = None,
        profile: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Optional[IsoSubmissionRecord]:
        """Typed wrapper for :meth:`submit_iso_pacs009`."""

        payload = self.submit_iso_pacs009(
            message,
            content_type=content_type,
            profile=profile,
            timeout=timeout,
        )
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise RuntimeError("ISO pacs.009 submission returned a non-object payload")
        return IsoSubmissionRecord.from_payload(payload, context="iso pacs.009 submission")

    def get_iso_message_status(
        self,
        message_id: str,
        *,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """Fetch ISO bridge status via `GET /v1/iso20022/messages/{message_id}`."""

        normalized_id = _require_non_empty_string(message_id, "message_id")
        encoded_id = quote(normalized_id, safe="")
        return _get_iso_message_status(
            self,
            f"/v1/iso20022/messages/{encoded_id}",
            timeout=timeout,
            context="get_iso_message_status",
        )

    def get_iso_message_status_typed(
        self,
        message_id: str,
        *,
        timeout: Optional[float] = None,
    ) -> Optional[IsoSubmissionRecord]:
        """Typed wrapper for :meth:`get_iso_message_status`."""

        payload = self.get_iso_message_status(message_id, timeout=timeout)
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise RuntimeError("ISO status endpoint returned a non-object payload")
        return IsoSubmissionRecord.from_payload(payload, context="iso status response")

    def wait_for_iso_message_status(
        self,
        message_id: str,
        *,
        poll_interval: float = _DEFAULT_ISO_POLL_INTERVAL_SECONDS,
        max_attempts: int = _DEFAULT_ISO_WAIT_ATTEMPTS,
        resolve_on_accepted: bool = False,
        timeout: Optional[float] = None,
        on_poll: Optional[Callable[[Optional[IsoSubmissionRecord], int], None]] = None,
    ) -> IsoSubmissionRecord:
        """Poll the ISO bridge until the message reaches a terminal state."""

        normalized_id = _require_non_empty_string(message_id, "message_id")
        if poll_interval < 0.0:
            raise ValueError("poll_interval must be non-negative")
        if 0.0 < poll_interval < _MIN_ISO_POLL_INTERVAL_SECONDS:
            poll_interval = _MIN_ISO_POLL_INTERVAL_SECONDS
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if on_poll is not None and not callable(on_poll):
            raise TypeError("wait.on_poll must be callable when provided")

        attempts = 0
        last_status: Optional[IsoSubmissionRecord] = None
        while True:
            attempts += 1
            status_payload = self.get_iso_message_status_typed(normalized_id, timeout=timeout)
            last_status = status_payload
            if on_poll is not None:
                on_poll(status_payload, attempts)
            if status_payload and _is_iso_status_terminal(status_payload, resolve_on_accepted):
                return status_payload
            if attempts >= max_attempts:
                raise IsoMessageTimeoutError(normalized_id, attempts, last_status)
            if poll_interval > 0.0:
                time.sleep(poll_interval)

    def submit_iso_pacs008_and_wait(
        self,
        message: Union[str, bytes, bytearray, memoryview],
        *,
        content_type: Optional[str] = None,
        profile: Optional[str] = None,
        timeout: Optional[float] = None,
        wait: Optional[Mapping[str, Any]] = None,
    ) -> IsoSubmissionRecord:
        """Submit a pacs.008 payload and wait for a terminal status."""

        submission = self.submit_iso_pacs008_typed(
            message,
            content_type=content_type,
            profile=profile,
            timeout=timeout,
        )
        if submission is None:
            raise RuntimeError("ISO pacs.008 submission did not return a message_id")
        wait_kwargs = _normalize_iso_wait_kwargs(wait, context="submit_iso_pacs008_and_wait.wait")
        return self.wait_for_iso_message_status(submission.message_id, **wait_kwargs)

    def submit_iso_pacs009_and_wait(
        self,
        message: Union[str, bytes, bytearray, memoryview],
        *,
        content_type: Optional[str] = None,
        profile: Optional[str] = None,
        timeout: Optional[float] = None,
        wait: Optional[Mapping[str, Any]] = None,
    ) -> IsoSubmissionRecord:
        """Submit a pacs.009 payload and wait for a terminal status."""

        submission = self.submit_iso_pacs009_typed(
            message,
            content_type=content_type,
            profile=profile,
            timeout=timeout,
        )
        if submission is None:
            raise RuntimeError("ISO pacs.009 submission did not return a message_id")
        wait_kwargs = _normalize_iso_wait_kwargs(wait, context="submit_iso_pacs009_and_wait.wait")
        return self.wait_for_iso_message_status(submission.message_id, **wait_kwargs)

    # ------------------------------------------------------------------
    # Repo agreements
    # ------------------------------------------------------------------

    def get_sorafs_pin_manifest(
        self,
        digest_hex: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Optional[Any]:
        """Fetch a SoraFS pin manifest (`GET /v1/sorafs/pin/{digest}`) enforcing alias policy."""

        if not isinstance(digest_hex, str) or not digest_hex.strip():
            raise ValueError("digest_hex must be a non-empty string")
        response = self._request(
            "GET",
            f"/v1/sorafs/pin/{digest_hex}",
            headers=headers,
        )
        self._expect_status(response, (200,))
        return type(self)._maybe_json(response)

    def register_sorafs_pin_manifest(
        self,
        transaction: "SignedTransactionEnvelope",
        *,
        timeout: Optional[float] = None,
    ) -> SorafsPinRegisterResponse:
        """Submit one already-signed native pin-registration transaction."""

        payload = bytes(transaction.signed_transaction_versioned)
        if not payload:
            raise ValueError("transaction must contain non-empty versioned signed bytes")
        response = self._request(
            "POST",
            "/v1/sorafs/pin/register",
            data=payload,
            headers={
                "Content-Type": "application/x-norito",
                "Accept": "application/json",
            },
            timeout=timeout,
        )
        self._expect_status(response, (202,))
        body = type(self)._maybe_json(response)
        if not isinstance(body, Mapping):
            raise RuntimeError("sorafs pin register endpoint returned malformed payload")
        return SorafsPinRegisterResponse.from_payload(body, "sorafs_pin_register")

    def get_sorafs_orderbook(
        self,
        *,
        expected_finalized_height: Optional[Any] = None,
        expected_finalized_block_hash_hex: Optional[Any] = None,
        after_id_hex: Optional[Any] = None,
        limit: Optional[Any] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Fetch one finalized native order page and authoritative ledger status."""

        response = self._request(
            "GET",
            "/v1/sorafs/orderbook/book",
            params=type(self)._sorafs_orderbook_read_params(
                expected_finalized_height=expected_finalized_height,
                expected_finalized_block_hash_hex=expected_finalized_block_hash_hex,
                after_id_hex=after_id_hex,
                limit=limit,
                context="get_sorafs_orderbook",
            ),
            headers=type(self)._sorafs_orderbook_headers(
                headers=headers,
                context="get_sorafs_orderbook",
            ),
            timeout=timeout,
        )
        self._expect_status(response, (200,))
        payload = type(self)._maybe_json(response)
        if payload is None:
            raise RuntimeError("sorafs orderbook book endpoint returned no payload")
        return type(self)._parse_sorafs_orderbook_book(
            payload,
            context="sorafs orderbook book response",
        )

    def list_sorafs_orderbook_trades(
        self,
        *,
        expected_finalized_height: Optional[Any] = None,
        expected_finalized_block_hash_hex: Optional[Any] = None,
        after_id_hex: Optional[Any] = None,
        limit: Optional[Any] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """List finalized native SoraFS orderbook trades."""

        response = self._request(
            "GET",
            "/v1/sorafs/orderbook/trades",
            params=type(self)._sorafs_orderbook_read_params(
                expected_finalized_height=expected_finalized_height,
                expected_finalized_block_hash_hex=expected_finalized_block_hash_hex,
                after_id_hex=after_id_hex,
                limit=limit,
                context="list_sorafs_orderbook_trades",
            ),
            headers=type(self)._sorafs_orderbook_headers(
                headers=headers,
                context="list_sorafs_orderbook_trades",
            ),
            timeout=timeout,
        )
        self._expect_status(response, (200,))
        payload = type(self)._maybe_json(response)
        if payload is None:
            raise RuntimeError("sorafs orderbook trades endpoint returned no payload")
        return type(self)._parse_sorafs_orderbook_trade_page_response(
            payload,
            context="sorafs orderbook trades response",
        )

    def list_sorafs_orderbook_channels(
        self,
        *,
        expected_finalized_height: Optional[Any] = None,
        expected_finalized_block_hash_hex: Optional[Any] = None,
        after_id_hex: Optional[Any] = None,
        limit: Optional[Any] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """List finalized native SoraFS settlement channels."""

        response = self._request(
            "GET",
            "/v1/sorafs/orderbook/channels",
            params=type(self)._sorafs_orderbook_read_params(
                expected_finalized_height=expected_finalized_height,
                expected_finalized_block_hash_hex=expected_finalized_block_hash_hex,
                after_id_hex=after_id_hex,
                limit=limit,
                context="list_sorafs_orderbook_channels",
            ),
            headers=type(self)._sorafs_orderbook_headers(
                headers=headers,
                context="list_sorafs_orderbook_channels",
            ),
            timeout=timeout,
        )
        self._expect_status(response, (200,))
        payload = type(self)._maybe_json(response)
        if payload is None:
            raise RuntimeError("sorafs orderbook channels endpoint returned no payload")
        return type(self)._parse_sorafs_orderbook_channel_page_response(
            payload,
            context="sorafs orderbook channels response",
        )

    def list_sorafs_orderbook_receipts(
        self,
        *,
        expected_finalized_height: Optional[Any] = None,
        expected_finalized_block_hash_hex: Optional[Any] = None,
        after_id_hex: Optional[Any] = None,
        limit: Optional[Any] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """List finalized native SoraFS settlement receipts."""

        response = self._request(
            "GET",
            "/v1/sorafs/orderbook/receipts",
            params=type(self)._sorafs_orderbook_read_params(
                expected_finalized_height=expected_finalized_height,
                expected_finalized_block_hash_hex=expected_finalized_block_hash_hex,
                after_id_hex=after_id_hex,
                limit=limit,
                context="list_sorafs_orderbook_receipts",
            ),
            headers=type(self)._sorafs_orderbook_headers(
                headers=headers,
                context="list_sorafs_orderbook_receipts",
            ),
            timeout=timeout,
        )
        self._expect_status(response, (200,))
        payload = type(self)._maybe_json(response)
        if payload is None:
            raise RuntimeError("sorafs orderbook receipts endpoint returned no payload")
        return type(self)._parse_sorafs_orderbook_receipt_page_response(
            payload,
            context="sorafs orderbook receipts response",
        )

    def _sorafs_orderbook_native_verifier(self) -> ModuleType:
        return _require_crypto()

    def _private_settlement_native_verifier(self) -> ModuleType:
        """Return the pinned Rust verifier for restricted settlement responses."""

        return _require_crypto()

    def _sorafs_orderbook_expected_network_id(self, value: Any, context: str) -> NetworkId:
        if value is not None:
            raise ValueError(
                f"{context} derives network identity from local_signing_context"
            )
        return self._require_local_signing_context(context).network_id

    def _sorafs_orderbook_expected_chain_discriminant(self, context: str) -> int:
        del context
        return self._chain_discriminant

    def list_sorafs_orderbook_events(
        self,
        *,
        expected_finalized_height: Optional[Any] = None,
        expected_finalized_block_hash_hex: Optional[Any] = None,
        after_sequence: Optional[Any] = None,
        after_block_height: Optional[Any] = None,
        after_block_hash_hex: Optional[Any] = None,
        after_event_index: Optional[Any] = None,
        limit: Optional[Any] = None,
        if_none_match: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """List replayable finalized native SoraFS orderbook events."""

        response = self._request(
            "GET",
            "/v1/sorafs/orderbook/events",
            params=type(self)._sorafs_orderbook_event_params(
                expected_finalized_height=expected_finalized_height,
                expected_finalized_block_hash_hex=expected_finalized_block_hash_hex,
                after_sequence=after_sequence,
                after_block_height=after_block_height,
                after_block_hash_hex=after_block_hash_hex,
                after_event_index=after_event_index,
                limit=limit,
                context="list_sorafs_orderbook_events",
            ),
            headers=type(self)._sorafs_orderbook_headers(
                if_none_match=if_none_match,
                headers=headers,
                context="list_sorafs_orderbook_events",
                cache=True,
            ),
            timeout=timeout,
        )
        self._expect_status(response, (200, 304))
        if response.status_code == 304:
            return None
        payload = type(self)._maybe_json(response)
        if payload is None:
            raise RuntimeError("sorafs orderbook events endpoint returned no payload")
        return type(self)._parse_sorafs_orderbook_event_page_response(
            payload,
            context="sorafs orderbook events response",
        )

    def stream_sorafs_orderbook_events(
        self,
        *,
        expected_finalized_height: Optional[Any] = None,
        expected_finalized_block_hash_hex: Optional[Any] = None,
        after_sequence: Optional[Any] = None,
        after_block_height: Optional[Any] = None,
        after_block_hash_hex: Optional[Any] = None,
        after_event_index: Optional[Any] = None,
        limit: Optional[Any] = None,
        timeout: Optional[float] = None,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        last_event_id: Optional[str] = None,
        resume: bool = False,
        on_event: Optional[Callable[..., None]] = None,
        cursor: Optional[EventCursor] = None,
        with_metadata: bool = False,
        decode_json: bool = True,
    ):
        """Stream finalized orderbook events from the native ledger journal."""

        params = type(self)._sorafs_orderbook_event_params(
            expected_finalized_height=expected_finalized_height,
            expected_finalized_block_hash_hex=expected_finalized_block_hash_hex,
            after_sequence=after_sequence,
            after_block_height=after_block_height,
            after_block_hash_hex=after_block_hash_hex,
            after_event_index=after_event_index,
            limit=limit,
            context="stream_sorafs_orderbook_events",
        )
        initial_event_id = (
            last_event_id
            if last_event_id is not None
            else (cursor.last_event_id if cursor is not None else None)
        )
        should_resume = resume or cursor is not None or last_event_id is not None

        def _normalize_event(event: SseEvent) -> SseEvent:
            if event.event == "lagged" or not isinstance(event.data, Mapping):
                return event
            return SseEvent(
                event=event.event,
                data=type(self)._parse_sorafs_orderbook_finalized_event(
                    event.data,
                    context=f"sorafs orderbook stream event {event.id or ''}".strip(),
                ),
                id=event.id,
                retry=event.retry,
                raw=event.raw,
            )

        def _handle(event: SseEvent) -> None:
            if on_event is None:
                return
            normalized = _normalize_event(event)
            if with_metadata:
                on_event(normalized)
            else:
                on_event(normalized.data, normalized.id)

        iterator = self._stream_sse(
            "/v1/sorafs/orderbook/events/stream",
            params=params,
            timeout=timeout,
            max_retries=max_retries,
            backoff_base=backoff_base,
            last_event_id=initial_event_id,
            resume=should_resume,
            decode_json=decode_json,
            cursor=cursor,
            allow_resume=True,
            on_event=_handle if on_event is not None else None,
        )

        def _events():
            for event in iterator:
                normalized = _normalize_event(event)
                yield normalized if with_metadata else normalized.data

        return _events()

    def build_sorafs_orderbook_events_websocket_url(
        self,
        *,
        expected_finalized_height: Optional[Any] = None,
        expected_finalized_block_hash_hex: Optional[Any] = None,
        after_sequence: Optional[Any] = None,
        after_block_height: Optional[Any] = None,
        after_block_hash_hex: Optional[Any] = None,
        after_event_index: Optional[Any] = None,
        limit: Optional[Any] = None,
        endpoint_path: str = "/v1/sorafs/orderbook/events/ws",
    ) -> str:
        """Build the finalized native orderbook event WebSocket URL."""

        return _sorafs_orderbook_events_websocket_url(
            self._base_url,
            params=type(self)._sorafs_orderbook_event_params(
                expected_finalized_height=expected_finalized_height,
                expected_finalized_block_hash_hex=expected_finalized_block_hash_hex,
                after_sequence=after_sequence,
                after_block_height=after_block_height,
                after_block_hash_hex=after_block_hash_hex,
                after_event_index=after_event_index,
                limit=limit,
                context="build_sorafs_orderbook_events_websocket_url",
            ),
            endpoint_path=endpoint_path,
            context="build_sorafs_orderbook_events_websocket_url",
        )

    def connect_sorafs_orderbook_events_websocket(
        self,
        *,
        expected_finalized_height: Optional[Any] = None,
        expected_finalized_block_hash_hex: Optional[Any] = None,
        after_sequence: Optional[Any] = None,
        after_block_height: Optional[Any] = None,
        after_block_hash_hex: Optional[Any] = None,
        after_event_index: Optional[Any] = None,
        limit: Optional[Any] = None,
        endpoint_path: str = "/v1/sorafs/orderbook/events/ws",
        timeout: Optional[float] = None,
        headers: Optional[Mapping[str, str]] = None,
        subprotocols: Optional[Sequence[str]] = None,
        websocket_factory: Optional[Callable[..., Any]] = None,
    ) -> Any:
        """Open the finalized native SoraFS orderbook event WebSocket."""

        factory = websocket_factory
        if factory is None:
            if websocket is None:  # pragma: no cover - dependency optional
                raise RuntimeError(
                    "websocket-client is not installed. Install iroha-python with the `ws` extra "
                    "(`pip install iroha-python[ws]`) or add `websocket-client` to your environment."
                )
            factory = websocket.create_connection
        ws_url = self.build_sorafs_orderbook_events_websocket_url(
            expected_finalized_height=expected_finalized_height,
            expected_finalized_block_hash_hex=expected_finalized_block_hash_hex,
            after_sequence=after_sequence,
            after_block_height=after_block_height,
            after_block_hash_hex=after_block_hash_hex,
            after_event_index=after_event_index,
            limit=limit,
            endpoint_path=endpoint_path,
        )

        header_list: List[str] = []
        combined_headers: Dict[str, str] = dict(self._default_headers)
        combined_headers.pop("Accept", None)
        if headers:
            combined_headers.update(headers)
        for key, value in combined_headers.items():
            header_list.append(f"{key}: {value}")

        return factory(
            ws_url,
            timeout=timeout,
            header=header_list or None,
            subprotocols=list(subprotocols) if subprotocols else None,
        )

    def stream_sorafs_orderbook_events_websocket(
        self,
        *,
        expected_finalized_height: Optional[Any] = None,
        expected_finalized_block_hash_hex: Optional[Any] = None,
        after_sequence: Optional[Any] = None,
        after_block_height: Optional[Any] = None,
        after_block_hash_hex: Optional[Any] = None,
        after_event_index: Optional[Any] = None,
        limit: Optional[Any] = None,
        endpoint_path: str = "/v1/sorafs/orderbook/events/ws",
        timeout: Optional[float] = None,
        headers: Optional[Mapping[str, str]] = None,
        subprotocols: Optional[Sequence[str]] = None,
        websocket_factory: Optional[Callable[..., Any]] = None,
        on_event: Optional[Callable[..., None]] = None,
        with_metadata: bool = False,
        close_on_return: bool = True,
    ):
        """Stream finalized native orderbook events from WebSocket JSON frames."""

        socket = self.connect_sorafs_orderbook_events_websocket(
            expected_finalized_height=expected_finalized_height,
            expected_finalized_block_hash_hex=expected_finalized_block_hash_hex,
            after_sequence=after_sequence,
            after_block_height=after_block_height,
            after_block_hash_hex=after_block_hash_hex,
            after_event_index=after_event_index,
            limit=limit,
            endpoint_path=endpoint_path,
            timeout=timeout,
            headers=headers,
            subprotocols=subprotocols,
            websocket_factory=websocket_factory,
        )

        def _normalize_event(event: WebSocketEvent) -> WebSocketEvent:
            if event.event == "lagged" or not isinstance(event.data, Mapping):
                return event
            return WebSocketEvent(
                event=event.event,
                data=type(self)._parse_sorafs_orderbook_finalized_event(
                    event.data,
                    context=(f"sorafs orderbook websocket event {event.event or ''}".strip()),
                ),
                raw=event.raw,
            )

        def _events():
            try:
                while True:
                    event = _normalize_event(
                        _parse_websocket_json_event(
                            socket.recv(),
                            "stream_sorafs_orderbook_events_websocket",
                        )
                    )
                    if on_event is not None:
                        if with_metadata:
                            on_event(event)
                        else:
                            on_event(event.data)
                    yield event if with_metadata else event.data
            finally:
                if close_on_return and hasattr(socket, "close"):
                    socket.close()

        return _events()

    def _sorafs_reputation_request_target(
        self,
        path: str,
        params: Optional[Mapping[str, str]],
    ) -> str:
        parsed = urlparse(f"{self._base_url}{path}")
        query = urlencode(params or {})
        return parsed.path if not query else f"{parsed.path}?{query}"

    def _sorafs_reputation_authenticated_headers(
        self,
        *,
        path: str,
        params: Optional[Mapping[str, str]],
        canonical_auth: Optional[ToriiCanonicalRequestAuth],
        headers: Dict[str, Any],
        context: str,
    ) -> Dict[str, str]:
        final_headers, signer_auth = _sorafs_reputation_request_auth(
            canonical_auth=canonical_auth,
            headers=headers,
            default_headers=self._default_headers,
            context=context,
            expected_discriminant=self._chain_discriminant,
        )
        if signer_auth is None:
            return final_headers
        signed_headers = build_canonical_request_headers(
            network_id=signer_auth.network_id,
            account_id=signer_auth.account_id,
            signer=signer_auth.signer,
            method="GET",
            path=self._sorafs_reputation_request_target(path, params),
            body=b"",
            timestamp_ms=signer_auth.timestamp_ms,
            nonce=signer_auth.nonce,
        )
        for name, value in signed_headers.items():
            _set_exact_header(final_headers, name, value)
        return final_headers

    def _get_sorafs_reputation(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, str]] = None,
        canonical_auth: Optional[ToriiCanonicalRequestAuth],
        if_none_match: Optional[str],
        headers: Optional[Mapping[str, str]],
        timeout: Optional[float],
        context: str,
    ) -> requests.Response:
        _require_one_shot_transport(
            self._session,
            f"{self._base_url}{path}",
            context,
        )
        final_headers = self._sorafs_reputation_authenticated_headers(
            path=path,
            params=params,
            canonical_auth=canonical_auth,
            headers=_sorafs_reputation_headers(
                if_none_match=if_none_match,
                headers=headers,
                context=context,
            ),
            context=context,
        )
        return self._request(
            "GET",
            path,
            params=params,
            headers=final_headers,
            timeout=timeout,
            allow_retry=False,
            allow_redirects=False,
            stream=True,
        )

    def get_sorafs_reputation_latest(
        self,
        *,
        canonical_auth: Optional[ToriiCanonicalRequestAuth] = None,
        if_none_match: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """Fetch the authenticated latest SoraFS reputation snapshot summary."""

        response = self._get_sorafs_reputation(
            "/v1/sorafs/reputation/latest",
            canonical_auth=canonical_auth,
            if_none_match=if_none_match,
            headers=headers,
            timeout=timeout,
            context="get_sorafs_reputation_latest",
        )
        expect_status_without_body(
            response,
            (200, 304, 404),
            "SoraFS reputation latest endpoint",
        )
        if response.status_code in {304, 404}:
            response.close()
            return None
        return _parse_and_validate_sorafs_reputation_response(
            response,
            _validate_sorafs_reputation_snapshot,
            "SoraFS reputation latest response",
        )

    def get_sorafs_reputation_provider(
        self,
        provider_id: str,
        *,
        canonical_auth: Optional[ToriiCanonicalRequestAuth] = None,
        if_none_match: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """Fetch a provider reputation record and Merkle proof from the latest snapshot."""

        normalized_provider = _normalize_sorafs_reputation_provider_id(
            provider_id,
            "get_sorafs_reputation_provider.provider_id",
        )
        path = f"/v1/sorafs/reputation/providers/{quote(normalized_provider, safe=':')}"
        response = self._get_sorafs_reputation(
            path,
            canonical_auth=canonical_auth,
            if_none_match=if_none_match,
            headers=headers,
            timeout=timeout,
            context="get_sorafs_reputation_provider",
        )
        expect_status_without_body(
            response,
            (200, 304, 404),
            "SoraFS reputation provider endpoint",
        )
        if response.status_code in {304, 404}:
            response.close()
            return None
        payload = _parse_and_validate_sorafs_reputation_response(
            response,
            _validate_sorafs_reputation_provider_response,
            "SoraFS reputation provider response",
        )
        if payload["provider"]["provider_id"] != normalized_provider:
            raise ValueError(
                "SoraFS reputation provider response does not match the requested provider"
            )
        return payload

    def get_sorafs_reputation_snapshot(
        self,
        snapshot_id_hex: str,
        *,
        canonical_auth: Optional[ToriiCanonicalRequestAuth] = None,
        if_none_match: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """Fetch a historical SoraFS reputation snapshot by its 16-byte id."""

        normalized_snapshot_id = _normalize_sorafs_reputation_snapshot_id_hex(
            snapshot_id_hex,
            "get_sorafs_reputation_snapshot.snapshot_id_hex",
        )
        response = self._get_sorafs_reputation(
            f"/v1/sorafs/reputation/snapshots/{normalized_snapshot_id}",
            canonical_auth=canonical_auth,
            if_none_match=if_none_match,
            headers=headers,
            timeout=timeout,
            context="get_sorafs_reputation_snapshot",
        )
        expect_status_without_body(
            response,
            (200, 304, 404),
            "SoraFS reputation snapshot endpoint",
        )
        if response.status_code in {304, 404}:
            response.close()
            return None
        payload = _parse_and_validate_sorafs_reputation_response(
            response,
            _validate_sorafs_reputation_snapshot,
            "SoraFS reputation snapshot response",
        )
        if payload["snapshot_id_hex"] != normalized_snapshot_id:
            raise ValueError(
                "SoraFS reputation snapshot response does not match the requested snapshot"
            )
        return payload

    def get_sorafs_reputation_weights(
        self,
        *,
        canonical_auth: Optional[ToriiCanonicalRequestAuth] = None,
        if_none_match: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """Fetch active SoraFS reputation scoring weights."""

        response = self._get_sorafs_reputation(
            "/v1/sorafs/reputation/weights",
            canonical_auth=canonical_auth,
            if_none_match=if_none_match,
            headers=headers,
            timeout=timeout,
            context="get_sorafs_reputation_weights",
        )
        expect_status_without_body(
            response,
            (200, 304, 404),
            "SoraFS reputation weights endpoint",
        )
        if response.status_code in {304, 404}:
            response.close()
            return None
        return _parse_and_validate_sorafs_reputation_response(
            response,
            _validate_sorafs_reputation_weights_response,
            "SoraFS reputation weights response",
        )

    def list_sorafs_reputation_events(
        self,
        *,
        since: Optional[Any] = None,
        limit: Optional[Any] = None,
        canonical_auth: Optional[ToriiCanonicalRequestAuth] = None,
        if_none_match: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """List SoraFS reputation snapshot events."""

        params = _sorafs_reputation_event_params(
            since=since,
            limit=limit,
            context="list_sorafs_reputation_events",
        )
        response = self._get_sorafs_reputation(
            "/v1/sorafs/reputation/events",
            params=params,
            canonical_auth=canonical_auth,
            if_none_match=if_none_match,
            headers=headers,
            timeout=timeout,
            context="list_sorafs_reputation_events",
        )
        expect_status_without_body(
            response,
            (200, 304),
            "SoraFS reputation events endpoint",
        )
        if response.status_code == 304:
            response.close()
            return None
        payload = _parse_and_validate_sorafs_reputation_response(
            response,
            _validate_sorafs_reputation_event_page,
            "SoraFS reputation events response",
        )
        expected_since = (
            int(params["since"])
            if params is not None and "since" in params
            else None
        )
        if payload["since"] != expected_since:
            raise ValueError(
                "SoraFS reputation events response since does not match the request"
            )
        if params is not None and "limit" in params and payload["limit"] != int(params["limit"]):
            raise ValueError(
                "SoraFS reputation events response limit does not match the request"
            )
        return payload

    def stream_sorafs_reputation_events(
        self,
        *,
        since: Optional[Any] = None,
        limit: Optional[Any] = None,
        canonical_auth: Optional[ToriiCanonicalRequestAuth] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        on_event: Optional[Callable[..., None]] = None,
        with_metadata: bool = False,
        decode_json: bool = True,
    ):
        """Stream one strictly validated authenticated reputation request."""

        params = _sorafs_reputation_event_params(
            since=since,
            limit=limit,
            context="stream_sorafs_reputation_events",
        )
        if decode_json is not True:
            raise ValueError(
                "stream_sorafs_reputation_events requires strict JSON decoding"
            )
        _require_one_shot_transport(
            self._session,
            f"{self._base_url}/v1/sorafs/reputation/events/stream",
            "stream_sorafs_reputation_events",
        )
        base_headers, signer_auth = _sorafs_reputation_request_auth(
            canonical_auth=canonical_auth,
            headers=_sorafs_reputation_headers(
                headers=headers,
                context="stream_sorafs_reputation_events",
                accept="text/event-stream",
            ),
            default_headers=self._default_headers,
            context="stream_sorafs_reputation_events",
            expected_discriminant=self._chain_discriminant,
        )
        if any(
            str(name).lower() == "last-event-id"
            for source in (base_headers, self._default_headers)
            for name in source
        ):
            raise ValueError(
                "stream_sorafs_reputation_events does not accept Last-Event-ID; "
                "use the finalized since cursor"
            )
        path = "/v1/sorafs/reputation/events/stream"

        def _auth_headers_for_attempt() -> Mapping[str, str]:
            if signer_auth is None:
                return dict(base_headers)
            return self._sorafs_reputation_authenticated_headers(
                path=path,
                params=params,
                canonical_auth=signer_auth,
                headers=dict(base_headers),
                context="stream_sorafs_reputation_events",
            )

        iterator = self._stream_sse(
            path,
            params=params,
            headers_factory=_auth_headers_for_attempt,
            timeout=timeout,
            max_retries=0,
            decode_json=True,
            allow_resume=False,
            maximum_event_bytes=_SORAFS_REPUTATION_SSE_MAX_EVENT_BYTES,
            json_loader=_decode_sorafs_reputation_sse_json,
            expected_content_type="text/event-stream",
            require_identity_encoding=True,
            payload_free_errors=True,
        )

        def _events():
            for event in iterator:
                validated = _validate_sorafs_reputation_sse_event(event)
                if on_event is not None:
                    if with_metadata:
                        on_event(validated)
                    else:
                        on_event(validated.data, validated.id)
                yield validated if with_metadata else validated.data

        return _events()

    def _sorafs_hedging_billing_authenticated_headers(
        self,
        *,
        method: str,
        path: str,
        params: Optional[Mapping[str, str]],
        body: bytes,
        canonical_auth: ToriiCanonicalRequestAuth,
        accept: str,
        context: str,
    ) -> Dict[str, str]:
        final_headers, signer_auth = _sorafs_reputation_request_auth(
            canonical_auth=canonical_auth,
            headers={"Accept": accept, "Accept-Encoding": "identity"},
            default_headers=self._default_headers,
            context=context,
            expected_discriminant=self._chain_discriminant,
        )
        if signer_auth is None:
            raise ValueError(f"{context} requires canonical_auth")
        signed_headers = build_canonical_request_headers(
            network_id=signer_auth.network_id,
            account_id=signer_auth.account_id,
            signer=signer_auth.signer,
            method=method,
            path=self._sorafs_reputation_request_target(path, params),
            body=body,
            timestamp_ms=signer_auth.timestamp_ms,
            nonce=signer_auth.nonce,
        )
        for name, value in signed_headers.items():
            _set_exact_header(final_headers, name, value)
        return final_headers

    def _get_sorafs_hedging_billing_response(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, str]],
        canonical_auth: ToriiCanonicalRequestAuth,
        accept: str,
        timeout: Optional[float],
        context: str,
    ) -> requests.Response:
        _require_one_shot_transport(
            self._session,
            f"{self._base_url}{path}",
            context,
        )
        final_headers = self._sorafs_hedging_billing_authenticated_headers(
            method="GET",
            path=path,
            params=params,
            body=b"",
            canonical_auth=canonical_auth,
            accept=accept,
            context=context,
        )
        return self._request(
            "GET",
            path,
            params=params,
            headers=final_headers,
            timeout=timeout,
            allow_retry=False,
            allow_redirects=False,
            stream=True,
        )

    def _get_sorafs_hedging_billing_json(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, str]],
        canonical_auth: ToriiCanonicalRequestAuth,
        timeout: Optional[float],
        context: str,
    ) -> Dict[str, Any]:
        response = self._get_sorafs_hedging_billing_response(
            path,
            params=params,
            canonical_auth=canonical_auth,
            accept="application/json",
            timeout=timeout,
            context=context,
        )
        expect_status_without_body(response, (200,), context)
        return self._parse_sorafs_hedging_billing_json_response(
            response,
            context,
        )

    @staticmethod
    def _parse_sorafs_hedging_billing_json_response(
        response: requests.Response,
        context: str,
    ) -> Dict[str, Any]:
        payload = decode_exact_json_bytes(
            read_bounded_identity_response(
                response,
                _SORAFS_HEDGING_BILLING_JSON_RESPONSE_MAX_BYTES,
                context,
                expected_content_type="application/json",
            ),
            context,
            maximum_bytes=_SORAFS_HEDGING_BILLING_JSON_RESPONSE_MAX_BYTES,
        )
        if type(payload) is not dict:
            raise ValueError(f"{context} must return a JSON object")
        return payload

    def get_sorafs_billing_status(
        self,
        *,
        canonical_auth: ToriiCanonicalRequestAuth,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Fetch the authenticated supervised SoraFS billing-projector status."""

        return self._get_sorafs_hedging_billing_json(
            "/v1/sorafs/billing/status",
            params=None,
            canonical_auth=canonical_auth,
            timeout=timeout,
            context="SoraFS billing status endpoint",
        )

    def list_sorafs_billing_statements(
        self,
        *,
        expected_checkpoint_fingerprint_hex: str,
        limit: int,
        canonical_auth: ToriiCanonicalRequestAuth,
        after_statement_id_hex: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """List one exact-checkpoint page of statements owned by the caller."""

        params = {
            "expected_checkpoint_fingerprint": (
                _normalize_sorafs_hedging_billing_digest(
                    expected_checkpoint_fingerprint_hex,
                    "list_sorafs_billing_statements.expected_checkpoint_fingerprint_hex",
                )
            )
        }
        if after_statement_id_hex is not None:
            params["after_statement_id"] = _normalize_sorafs_hedging_billing_digest(
                after_statement_id_hex,
                "list_sorafs_billing_statements.after_statement_id_hex",
            )
        params["limit"] = str(
            _normalize_sorafs_hedging_billing_limit(
                limit,
                "list_sorafs_billing_statements.limit",
            )
        )
        return self._get_sorafs_hedging_billing_json(
            "/v1/sorafs/billing/statements",
            params=params,
            canonical_auth=canonical_auth,
            timeout=timeout,
            context="SoraFS billing statements endpoint",
        )

    def get_sorafs_billing_statement(
        self,
        statement_id_hex: str,
        expected_checkpoint_fingerprint_hex: str,
        *,
        canonical_auth: ToriiCanonicalRequestAuth,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Fetch one exact owned published billing statement as Norito bytes."""

        statement_id = _normalize_sorafs_hedging_billing_digest(
            statement_id_hex,
            "get_sorafs_billing_statement.statement_id_hex",
        )
        checkpoint = _normalize_sorafs_hedging_billing_digest(
            expected_checkpoint_fingerprint_hex,
            "get_sorafs_billing_statement.expected_checkpoint_fingerprint_hex",
        )
        context = "SoraFS billing statement endpoint"
        response = self._get_sorafs_hedging_billing_response(
            f"/v1/sorafs/billing/statements/{statement_id}",
            params={"expected_checkpoint_fingerprint": checkpoint},
            canonical_auth=canonical_auth,
            accept="application/x-norito",
            timeout=timeout,
            context=context,
        )
        expect_status_without_body(response, (200,), context)
        if response.headers.get("Content-Type") != "application/x-norito":
            response.close()
            raise ValueError(f"{context} Content-Type must be exactly application/x-norito")
        return read_bounded_identity_response(
            response,
            _SORAFS_BILLING_STATEMENT_RESPONSE_MAX_BYTES,
            context,
            expected_content_type="application/x-norito",
        )

    def acknowledge_sorafs_billing_statement(
        self,
        statement_id_hex: str,
        expected_checkpoint_fingerprint_hex: str,
        *,
        request_nonce_hex: str,
        authentication_proof: bytes,
        canonical_auth: ToriiCanonicalRequestAuth,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Submit one canonical owner acknowledgement for a published statement."""

        statement_id = _normalize_sorafs_hedging_billing_digest(
            statement_id_hex,
            "acknowledge_sorafs_billing_statement.statement_id_hex",
        )
        checkpoint = _normalize_sorafs_hedging_billing_digest(
            expected_checkpoint_fingerprint_hex,
            "acknowledge_sorafs_billing_statement.expected_checkpoint_fingerprint_hex",
        )
        body = encode_sorafs_billing_acknowledgement_proof_v1(
            request_nonce_hex,
            authentication_proof,
        )
        path = f"/v1/sorafs/billing/statements/{statement_id}/acknowledgements"
        params = {"expected_checkpoint_fingerprint": checkpoint}
        context = "SoraFS billing acknowledgement endpoint"
        _require_one_shot_transport(
            self._session,
            f"{self._base_url}{path}",
            context,
        )
        final_headers = self._sorafs_hedging_billing_authenticated_headers(
            method="POST",
            path=path,
            params=params,
            body=body,
            canonical_auth=canonical_auth,
            accept="application/json",
            context=context,
        )
        _set_exact_header(final_headers, "Content-Type", "application/x-norito")
        response = self._request(
            "POST",
            path,
            params=params,
            headers=final_headers,
            data=body,
            timeout=timeout,
            allow_retry=False,
            allow_redirects=False,
            stream=True,
        )
        expect_status_without_body(response, (200,), context)
        return self._parse_sorafs_hedging_billing_json_response(
            response,
            context,
        )

    def get_sorafs_billing_reconciliation(
        self,
        *,
        canonical_auth: ToriiCanonicalRequestAuth,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Fetch payload-free billing delivery reconciliation status."""

        return self._get_sorafs_hedging_billing_json(
            "/v1/sorafs/billing/reconciliation",
            params=None,
            canonical_auth=canonical_auth,
            timeout=timeout,
            context="SoraFS billing reconciliation endpoint",
        )

    def _get_sorafs_hedging_projection(
        self,
        path: str,
        *,
        expected_checkpoint_fingerprint_hex: str,
        limit: int,
        canonical_auth: ToriiCanonicalRequestAuth,
        after_hex: Optional[str],
        timeout: Optional[float],
        context: str,
    ) -> Dict[str, Any]:
        params = {
            "expected_checkpoint_fingerprint": (
                _normalize_sorafs_hedging_billing_digest(
                    expected_checkpoint_fingerprint_hex,
                    f"{context}.expected_checkpoint_fingerprint_hex",
                )
            )
        }
        if after_hex is not None:
            params["after"] = _normalize_sorafs_hedging_billing_digest(
                after_hex,
                f"{context}.after_hex",
            )
        params["limit"] = str(
            _normalize_sorafs_hedging_billing_limit(
                limit,
                f"{context}.limit",
            )
        )
        return self._get_sorafs_hedging_billing_json(
            path,
            params=params,
            canonical_auth=canonical_auth,
            timeout=timeout,
            context=context,
        )

    def get_sorafs_hedging_exposure(
        self,
        *,
        expected_checkpoint_fingerprint_hex: str,
        limit: int,
        canonical_auth: ToriiCanonicalRequestAuth,
        after_hex: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Fetch one exact-checkpoint page of finalized hedging exposure."""

        return self._get_sorafs_hedging_projection(
            "/v1/sorafs/hedging/exposure",
            expected_checkpoint_fingerprint_hex=expected_checkpoint_fingerprint_hex,
            limit=limit,
            canonical_auth=canonical_auth,
            after_hex=after_hex,
            timeout=timeout,
            context="SoraFS hedging exposure endpoint",
        )

    def get_sorafs_hedging_intents(
        self,
        *,
        expected_checkpoint_fingerprint_hex: str,
        limit: int,
        canonical_auth: ToriiCanonicalRequestAuth,
        after_hex: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Fetch one exact-checkpoint page of governed hedge intents."""

        return self._get_sorafs_hedging_projection(
            "/v1/sorafs/hedging/intents",
            expected_checkpoint_fingerprint_hex=expected_checkpoint_fingerprint_hex,
            limit=limit,
            canonical_auth=canonical_auth,
            after_hex=after_hex,
            timeout=timeout,
            context="SoraFS hedging intents endpoint",
        )

    # -------------------------
    # SoraFS Proof-of-Retrievability APIs
    # -------------------------

    def record_sorafs_por_proof(
        self,
        *,
        proof: Optional[Union[bytes, bytearray, memoryview]] = None,
        proof_b64: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> SorafsPorSubmissionResponse:
        """Submit a `PorProofV1` record for a provider."""

        payload = {
            "proof_b64": _normalize_base64_payload(
                proof_b64, proof, "record_sorafs_por_proof.proof"
            )
        }
        response = self._request(
            "POST",
            "/v1/sorafs/capacity/por-proof",
            json_body=payload,
            headers={"Accept": "application/json"},
            timeout=timeout,
        )
        self._expect_status(response, (200,))
        body = self._maybe_json(response)
        if body is None:
            raise RuntimeError("por-proof endpoint returned an empty payload")
        return SorafsPorSubmissionResponse.from_payload(body, "sorafs_por_proof")

    def record_sorafs_por_verdict(
        self,
        *,
        verdict: Optional[Union[bytes, bytearray, memoryview]] = None,
        verdict_b64: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> SorafsPorVerdictResponse:
        """Submit an audit verdict for a PoR challenge."""

        payload = {
            "verdict_b64": _normalize_base64_payload(
                verdict_b64, verdict, "record_sorafs_por_verdict.verdict"
            )
        }
        response = self._request(
            "POST",
            "/v1/sorafs/capacity/por-verdict",
            json_body=payload,
            headers={"Accept": "application/json"},
            timeout=timeout,
        )
        self._expect_status(response, (200,))
        body = self._maybe_json(response)
        if body is None:
            raise RuntimeError("por-verdict endpoint returned an empty payload")
        return SorafsPorVerdictResponse.from_payload(body, "sorafs_por_verdict")

    def get_sorafs_por_status(
        self,
        *,
        manifest_hex: Optional[str] = None,
        provider_hex: Optional[str] = None,
        epoch: Optional[int] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        max_bytes: Optional[int] = None,
        cursor: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Return Norito-encoded `PorChallengeStatusV1` records for the given filters."""

        params = _build_sorafs_por_status_params(
            manifest_hex, provider_hex, epoch, status, limit, max_bytes, cursor
        )
        response = self._request(
            "GET",
            "/v1/sorafs/por/status",
            params=params,
            headers={"Accept": "application/x-norito"},
            timeout=timeout,
        )
        self._expect_status(response, (200,))
        return response.content

    def export_sorafs_por_status(
        self,
        *,
        start_epoch: Optional[int] = None,
        end_epoch: Optional[int] = None,
        limit: Optional[int] = None,
        max_bytes: Optional[int] = None,
        cursor: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Return a Norito-exported history for the supplied epoch range."""

        params = _build_sorafs_por_export_params(
            start_epoch, end_epoch, limit, max_bytes, cursor
        )
        response = self._request(
            "GET",
            "/v1/sorafs/por/export",
            params=params,
            headers={"Accept": "application/x-norito"},
            timeout=timeout,
        )
        self._expect_status(response, (200,))
        return response.content

    def get_sorafs_por_weekly_report(
        self,
        iso_week: Union[str, Tuple[int, int]],
        *,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Fetch the Norito-encoded weekly PoR report for the provided ISO week."""

        label = _normalize_iso_week_label(iso_week, "get_sorafs_por_weekly_report.iso_week")
        response = self._request(
            "GET",
            f"/v1/sorafs/por/report/{label}",
            headers={"Accept": "application/x-norito"},
            timeout=timeout,
        )
        self._expect_status(response, (200,))
        return response.content

    def get_sorafs_por_ingestion_status(
        self,
        manifest_hex: str,
        *,
        timeout: Optional[float] = None,
    ) -> SorafsPorIngestionStatus:
        """Return the JSON PoR ingestion snapshot for the provided manifest digest."""

        digest = _normalize_hex_string(
            manifest_hex,
            "get_sorafs_por_ingestion_status.manifest_hex",
            expected_length=64,
        )
        response = self._request(
            "GET",
            f"/v1/sorafs/por/ingestion/{digest}",
            headers={"Accept": "application/json"},
            timeout=timeout,
        )
        self._expect_status(response, (200,))
        payload = self._maybe_json(response)
        if payload is None or not isinstance(payload, Mapping):
            raise RuntimeError("por ingestion endpoint returned an invalid payload")
        return SorafsPorIngestionStatus.from_payload(payload)

    def get_status(self) -> Optional[Any]:
        """Return Torii node status from the canonical ``GET /status`` route."""

        headers = {"Accept": "application/json"}
        response = self._request("GET", "/status", headers=headers)
        self._expect_status(response, (200,))
        return self._maybe_json(response)

    @staticmethod
    def _status_mapping(status: Optional[Any]) -> Mapping[str, Any]:
        if status is None:
            return {}
        raw = getattr(status, "raw", None)
        if isinstance(raw, Mapping):
            return raw
        nested_status = getattr(status, "status", None)
        nested_raw = getattr(nested_status, "raw", None)
        if isinstance(nested_raw, Mapping):
            return nested_raw
        if isinstance(status, Mapping):
            return status
        if is_dataclass(status) and not isinstance(status, type):
            return asdict(status)
        raise TypeError("status must be a mapping or typed Torii status object")

    @staticmethod
    def _dataspace_entry_from_lane(entry: Mapping[str, Any]) -> Dict[str, Any]:
        alias = str(
            entry.get("dataspace_alias") or entry.get("dataspace") or entry.get("alias") or ""
        ).strip()
        dataspace_id = entry.get("dataspace_id", entry.get("id"))
        result: Dict[str, Any] = dict(entry)
        if alias:
            result.setdefault("alias", alias)
            result.setdefault("dataspace_alias", alias)
        if dataspace_id is not None:
            try:
                result["id"] = int(dataspace_id)
                result["dataspace_id"] = int(dataspace_id)
            except (TypeError, ValueError):
                pass
        return result

    def list_dataspaces(self, status: Optional[Any] = None) -> List[Mapping[str, Any]]:
        """Return dataspace catalog entries from Torii status.

        Nodes expose dataspace information through slightly different status
        shapes across releases. This helper accepts all supported shapes and
        normalizes entries enough for readiness checks.
        """

        payload = self._status_mapping(self.get_status() if status is None else status)
        indexed: Dict[Tuple[Optional[str], Optional[int]], Dict[str, Any]] = {}
        for catalog_key in (
            "teu_dataspace_backlog",
            "dataspaces",
            "dataspace_catalog",
            "teu_lane_commit",
        ):
            entries = payload.get(catalog_key)
            if not isinstance(entries, list):
                continue
            for item in entries:
                if not isinstance(item, Mapping):
                    continue
                entry = self._dataspace_entry_from_lane(item)
                alias = str(entry.get("alias") or entry.get("dataspace_alias") or "").strip()
                dataspace_id = entry.get("id", entry.get("dataspace_id"))
                try:
                    normalized_id: Optional[int] = (
                        int(dataspace_id) if dataspace_id is not None else None
                    )
                except (TypeError, ValueError):
                    normalized_id = None
                index_key = (alias or None, normalized_id)
                existing = indexed.get(index_key, {})
                indexed[index_key] = {**existing, **entry}

        lane_entries = payload.get("lane_governance")
        if isinstance(lane_entries, list):
            sealed_aliases = {
                str(alias)
                for alias in payload.get("lane_governance_sealed_aliases", [])
                if isinstance(alias, str)
            }
            for item in lane_entries:
                if not isinstance(item, Mapping):
                    continue
                entry = self._dataspace_entry_from_lane(item)
                alias = str(entry.get("alias") or entry.get("dataspace_alias") or "").strip()
                if alias:
                    entry["sealed"] = bool(entry.get("sealed", alias in sealed_aliases))
                dataspace_id = entry.get("id", entry.get("dataspace_id"))
                try:
                    normalized_id = int(dataspace_id) if dataspace_id is not None else None
                except (TypeError, ValueError):
                    normalized_id = None
                index_key = (alias or None, normalized_id)
                existing = indexed.get(index_key, {})
                indexed[index_key] = {**existing, **entry}

        return list(indexed.values())

    def get_dataspace(
        self,
        alias_or_id: Union[str, int],
        status: Optional[Any] = None,
    ) -> Optional[Mapping[str, Any]]:
        """Return a dataspace by alias or numeric id, if present in Torii status."""

        needle = str(alias_or_id).strip()
        if not needle:
            raise ValueError("alias_or_id must be non-empty")
        numeric_needle: Optional[int]
        try:
            numeric_needle = int(needle)
        except ValueError:
            numeric_needle = None
        for entry in self.list_dataspaces(status=status):
            aliases = {
                str(entry.get("alias") or "").strip(),
                str(entry.get("dataspace_alias") or "").strip(),
                str(entry.get("dataspace") or "").strip(),
            }
            if needle in aliases:
                return entry
            if numeric_needle is not None:
                raw_id = entry.get("id", entry.get("dataspace_id"))
                try:
                    if int(raw_id) == numeric_needle:
                        return entry
                except (TypeError, ValueError):
                    pass
        return None

    def require_dataspace(
        self,
        alias_or_id: Union[str, int],
        status: Optional[Any] = None,
    ) -> Mapping[str, Any]:
        """Return a dataspace or raise ``KeyError`` with an actionable message."""

        entry = self.get_dataspace(alias_or_id, status=status)
        if entry is None:
            raise KeyError(f"dataspace {alias_or_id!r} is not present in Torii status")
        return entry

    def dataspace_status(
        self,
        alias_or_id: Union[str, int],
        status: Optional[Any] = None,
    ) -> DataspaceStatus:
        """Return a compact readiness status for a dataspace."""

        entry = self.get_dataspace(alias_or_id, status=status)
        if entry is None:
            return DataspaceStatus(
                alias=str(alias_or_id),
                dataspace_id=0,
                lane_id=0,
                found=False,
                ready=False,
                manifest_required=False,
                manifest_ready=False,
                sealed=False,
            )
        alias = str(
            entry.get("dataspace_alias")
            or entry.get("dataspace")
            or entry.get("alias")
            or alias_or_id
        )
        try:
            dataspace_id = int(entry.get("dataspace_id", entry.get("id", 0)))
        except (TypeError, ValueError):
            dataspace_id = 0
        try:
            lane_id = int(entry.get("lane_id", entry.get("index", 0)))
        except (TypeError, ValueError):
            lane_id = 0
        manifest_required = bool(entry.get("manifest_required", False))
        manifest_ready = bool(entry.get("manifest_ready", not manifest_required))
        sealed = bool(entry.get("sealed", False))
        return DataspaceStatus(
            alias=alias,
            dataspace_id=dataspace_id,
            lane_id=lane_id,
            found=True,
            ready=(not sealed and (not manifest_required or manifest_ready)),
            manifest_required=manifest_required,
            manifest_ready=manifest_ready,
            sealed=sealed,
            lane=dict(entry),
        )

    def dataspace_ready(
        self,
        alias_or_id: Union[str, int],
        status: Optional[Any] = None,
    ) -> bool:
        """Return ``True`` when a dataspace exists and is ready for routing."""

        return self.dataspace_status(alias_or_id, status=status).ready

    def smoke_dataspace(
        self,
        alias_or_id: Union[str, int],
        *,
        expected_lane_count: Optional[int] = None,
        expected_dataspace_id: Optional[int] = None,
        status: Optional[Any] = None,
    ) -> DataspaceStatus:
        """Validate dataspace readiness and optionally the configured lane count."""

        payload = self._status_mapping(self.get_status() if status is None else status)
        if expected_lane_count is not None:
            lane_count = payload.get("lane_count")
            if lane_count is None:
                lane_entries = payload.get("lane_governance")
                if not lane_entries:
                    lane_entries = payload.get("dataspace_catalog")
                lane_count = len(lane_entries or [])
            if int(lane_count) < int(expected_lane_count):
                raise AssertionError(
                    f"Torii reports lane_count={lane_count}, expected at least {expected_lane_count}"
                )
        result = self.dataspace_status(alias_or_id, status=payload)
        if not result.found:
            raise AssertionError(f"dataspace {alias_or_id!r} is not present in Torii status")
        if expected_dataspace_id is not None and result.dataspace_id != int(expected_dataspace_id):
            raise AssertionError(
                f"dataspace {alias_or_id!r} has id {result.dataspace_id}, "
                f"expected {int(expected_dataspace_id)}"
            )
        if not result.ready:
            raise AssertionError(
                f"dataspace {alias_or_id!r} is not ready "
                f"(sealed={result.sealed}, manifest_required={result.manifest_required}, "
                f"manifest_ready={result.manifest_ready})"
            )
        return result

    def plan_dataspace(self, spec: DataspaceSpec) -> DataspacePlan:
        """Build manifest/config artifacts for a dataspace without writing files."""

        return _plan_dataspace(spec)

    def write_dataspace_plan(
        self,
        plan: DataspacePlan,
        output_dir: Union[str, Path],
        *,
        force: bool = False,
    ) -> Dict[str, Path]:
        """Write a dataspace plan to ``output_dir``."""

        return _write_dataspace_plan(plan, output_dir, force=force)

    def nexus_lane_lifecycle_status(
        self,
        *,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Fetch the exact current lane catalog and optimistic lifecycle hashes.

        ``runtime_catalog_hash`` is explicitly null before the first committed
        runtime catalog transition; otherwise it is a canonical nonempty hash.
        """

        response = self._request(
            "GET",
            "/v1/nexus/lifecycle",
            headers={"Accept": "application/json"},
            timeout=timeout,
        )
        self._expect_status(response, {200})
        status_context = "Nexus lane lifecycle status"

        def exact_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
            decoded: Dict[str, Any] = {}
            for key, value in pairs:
                if key in decoded:
                    raise ValueError(f"{status_context} contains duplicate field `{key}`")
                decoded[key] = value
            return decoded

        payload = response.json(object_pairs_hook=exact_object)
        if not isinstance(payload, Mapping):
            raise TypeError("Nexus lane lifecycle status must be a JSON object")
        status = dict(payload)
        _strict_exact_fields(
            status,
            (
                "version",
                "lane_count",
                "lanes",
                "catalog_hash",
                "runtime_catalog_hash",
                "incarnations",
                "incarnation_root",
            ),
            status_context,
        )
        if _strict_uint(status, "version", 8, status_context) != 1:
            raise ValueError("Nexus lane lifecycle status version must be 1")
        lane_count = _strict_uint(status, "lane_count", 32, status_context)
        if lane_count == 0:
            raise ValueError("Nexus lane lifecycle status `lane_count` must be in 1..=4294967295")
        lanes = status["lanes"]
        if not isinstance(lanes, list) or not lanes:
            raise TypeError("Nexus lane lifecycle status `lanes` must be a non-empty list")
        if len(lanes) > 1024:
            raise ValueError("Nexus lane lifecycle status contains more than 1024 lanes")
        lane_ids: list[int] = []
        lane_aliases: set[str] = set()
        normalized_lanes: List[Dict[str, Any]] = []
        for index, lane in enumerate(lanes):
            lane_context = f"Nexus lane lifecycle status lanes[{index}]"
            normalized_lane = _strict_nexus_lane_config(lane, lane_context)
            lane_id = normalized_lane["id"]
            if lane_id >= lane_count:
                raise ValueError(f"Nexus lane lifecycle status lanes[{index}].id is invalid")
            alias = normalized_lane["alias"]
            if alias in lane_aliases:
                raise ValueError(
                    f"Nexus lane lifecycle status lanes[{index}].alias duplicates `{alias}`"
                )
            lane_ids.append(lane_id)
            lane_aliases.add(alias)
            normalized_lanes.append(normalized_lane)
        if lane_ids != sorted(set(lane_ids)):
            raise ValueError("Nexus lane lifecycle status lane ids must be unique and sorted")
        status["lanes"] = normalized_lanes
        _strict_hash_literal(status, "catalog_hash", status_context)
        if status["runtime_catalog_hash"] is not None:
            runtime_catalog_hash = _strict_hash_literal(
                status, "runtime_catalog_hash", status_context
            )
            if runtime_catalog_hash[5:69] == "0" * 63 + "1":
                raise ValueError(
                    f"{status_context} `runtime_catalog_hash` must not be the empty Iroha hash"
                )
        incarnation_entries = status["incarnations"]
        if not isinstance(incarnation_entries, list):
            raise TypeError("Nexus lane lifecycle status `incarnations` must be a list")
        incarnation_ids: list[int] = []
        incarnation_values: set[str] = set()
        normalized_incarnations: List[Dict[str, Any]] = []
        for index, entry in enumerate(incarnation_entries):
            if not isinstance(entry, Mapping):
                raise TypeError(
                    f"Nexus lane lifecycle status incarnations[{index}] must be an object"
                )
            incarnation_context = f"Nexus lane lifecycle status incarnations[{index}]"
            _strict_exact_fields(entry, ("lane_id", "incarnation"), incarnation_context)
            lane_id = _strict_uint(entry, "lane_id", 32, incarnation_context)
            incarnation = _strict_hash_literal(entry, "incarnation", incarnation_context)
            if incarnation in incarnation_values:
                raise ValueError("Nexus lane lifecycle status incarnations must be unique")
            incarnation_ids.append(lane_id)
            incarnation_values.add(incarnation)
            normalized_incarnations.append(dict(entry))
        if incarnation_ids != lane_ids:
            raise ValueError(
                "Nexus lane lifecycle status incarnation lane ids must exactly match the catalog"
            )
        status["incarnations"] = normalized_incarnations
        _strict_hash_literal(status, "incarnation_root", status_context)
        return status

    def nexus_lane_lifecycle(
        self,
        additions: Sequence[Mapping[str, Any]],
        *,
        fee_payment: Mapping[str, Any],
        network_id: "NetworkId",
        authority: str,
        private_key: Union[bytes, bytearray, memoryview],
        retire: Optional[Sequence[int]] = None,
        wait: bool = True,
        interval: float = 1.0,
        timeout: Optional[float] = None,
        max_attempts: Optional[int] = None,
    ) -> tuple["SignedTransactionEnvelope", Optional[Any]]:
        """Submit a signed consensus-replayed Nexus lane lifecycle transaction.

        Callers must provide the exact nominal ``network_id``, ``authority``, and
        raw private-key bytes for an account holding ``CanSetParameters``. The
        status commitment is fetched once and is never silently refreshed after
        a stale or concurrent rejection.
        """

        network_id = _normalize_network_id(network_id, "network_id")
        if authority is None or not isinstance(authority, str) or not authority.strip():
            raise ValueError("authority is required for signed Nexus lane lifecycle submission")
        if not isinstance(private_key, (bytes, bytearray, memoryview)):
            raise ValueError(
                "private_key bytes are required for signed Nexus lane lifecycle submission"
            )
        private_key_bytes = bytes(private_key)
        if not private_key_bytes:
            raise ValueError("private_key must not be empty")

        if isinstance(additions, (str, bytes, bytearray, memoryview)) or not isinstance(
            additions, Sequence
        ):
            raise TypeError("additions must be a sequence of lane config mappings")
        if len(additions) > 1024:
            raise ValueError("additions must contain at most 1024 lane configs")
        normalized_additions: List[Dict[str, Any]] = []
        addition_ids: set[int] = set()
        addition_aliases: set[str] = set()
        for index, addition in enumerate(additions):
            normalized = _strict_nexus_lane_config(addition, f"additions[{index}]")
            lane_id = normalized["id"]
            if lane_id in addition_ids:
                raise ValueError(f"additions[{index}].id duplicates lane {lane_id}")
            addition_ids.add(lane_id)
            alias = normalized["alias"]
            if alias in addition_aliases:
                raise ValueError(f"additions[{index}].alias duplicates `{alias}`")
            addition_aliases.add(alias)
            normalized_additions.append(normalized)

        if retire is None:
            retire_items: Sequence[int] = ()
        elif isinstance(retire, (str, bytes, bytearray, memoryview)) or not isinstance(
            retire, Sequence
        ):
            raise TypeError("retire must be a sequence of lane ids")
        else:
            retire_items = retire
        if len(retire_items) > 1024:
            raise ValueError("retire must contain at most 1024 lane ids")

        normalized_retire: List[int] = []
        retired_ids: set[int] = set()
        for index, lane_id in enumerate(retire_items):
            if (
                isinstance(lane_id, bool)
                or not isinstance(lane_id, int)
                or lane_id < 0
                or lane_id > 0xFFFFFFFF
            ):
                raise ValueError(f"retire[{index}] must be a u32 integer lane id")
            if lane_id in retired_ids:
                raise ValueError(f"retire[{index}] duplicates lane {lane_id}")
            retired_ids.add(lane_id)
            normalized_retire.append(lane_id)
        if not normalized_additions and not normalized_retire:
            raise ValueError("lane lifecycle plan must add or retire at least one lane")

        status = self.nexus_lane_lifecycle_status(timeout=timeout)
        plan = _json_safe_value({"additions": normalized_additions, "retire": normalized_retire})
        instruction = _require_crypto().Instruction.nexus_lane_lifecycle(
            json.dumps(_json_safe_value(status), sort_keys=True, separators=(",", ":")),
            json.dumps(plan, sort_keys=True, separators=(",", ":")),
        )
        return self.build_and_submit_transaction(
            network_id,
            authority.strip(),
            private_key_bytes,
            fee_payment=fee_payment,
            instructions=[instruction],
            wait=wait,
            interval=interval,
            timeout=timeout,
            max_attempts=max_attempts,
            expect_json=True,
        )

    def publish_dataspace_manifest(
        self,
        *,
        authority: str,
        uaid: str,
        dataspace: int,
        manifest: Mapping[str, Any],
        reason: Optional[str] = None,
    ) -> AppApiTransactionDraft:
        """Prepare a Space Directory publication draft using dataspace keywords."""

        request: Dict[str, Any] = {
            "authority": authority,
            "manifest": {
                "uaid": uaid,
                "dataspace": dataspace,
                **dict(manifest),
            },
        }
        if reason:
            request["reason"] = reason
        return self.publish_space_directory_manifest(request)

    def revoke_dataspace_manifest(
        self,
        *,
        authority: str,
        uaid: str,
        dataspace: int,
        revoked_epoch: int,
        reason: Optional[str] = None,
    ) -> AppApiTransactionDraft:
        """Prepare a Space Directory revocation draft using dataspace keywords."""

        request: Dict[str, Any] = {
            "authority": authority,
            "uaid": uaid,
            "dataspace": dataspace,
            "revoked_epoch": revoked_epoch,
        }
        if reason:
            request["reason"] = reason
        return self.revoke_space_directory_manifest(request)

    def get_status_snapshot_typed(self) -> ToriiStatusSnapshot:
        """Return a typed status snapshot together with derived metrics."""

        payload = self.request_json("GET", "/status", expected_status=(200,))
        if payload is None:
            raise TypeError("status response body was empty")
        if not isinstance(payload, Mapping):
            raise TypeError("status response must be a JSON object")
        status_payload = ToriiStatusPayload.from_payload(payload)
        metrics = self._status_state.record(status_payload)
        return ToriiStatusSnapshot(
            timestamp=time.monotonic(),
            status=status_payload,
            metrics=metrics,
        )

    def get_pipeline_preflight(self) -> ToriiPipelinePreflight:
        """Return operator-authenticated pipeline preflight diagnostics."""

        response = self._operator_get(
            "/v1/pipeline/preflight",
            headers={"Accept": "application/json"},
            context="get_pipeline_preflight",
        )
        self._expect_status(response, (200,))
        payload = self._maybe_json(response)
        if payload is None:
            raise TypeError("pipeline preflight response body was empty")
        if not isinstance(payload, Mapping):
            raise TypeError("pipeline preflight response must be a JSON object")
        return ToriiPipelinePreflight.from_payload(payload)

    def get_health(self) -> Optional[Any]:
        """Return Torii health information (`GET /v1/health`)."""

        return self.request_json("GET", "/v1/health", expected_status=(200,))

    def get_configuration(self) -> ConfigurationSnapshot:
        """Return the validated operator-authenticated node configuration."""

        response = self._operator_get(
            "/v1/configuration",
            headers={"Accept": "application/json"},
            context="get_configuration",
        )
        self._expect_status(response, (200,))
        payload = self._maybe_json(response)
        if not isinstance(payload, Mapping):
            raise TypeError("configuration response must be a JSON object")
        return ConfigurationSnapshot.from_payload(payload)

    def get_confidential_gas_schedule(self) -> Optional[ConfidentialGasSchedule]:
        """Return the validated confidential verification gas schedule, when available."""

        snapshot = self.get_configuration()
        return snapshot.confidential_gas

    def get_metrics(self, *, as_text: bool = False) -> Optional[Any]:
        """Fetch Torii metrics (`GET /v1/metrics`)."""

        if as_text:
            response = self._request(
                "GET",
                "/v1/metrics",
                headers={"Accept": "text/plain"},
                allow_retry=False,
            )
            self._expect_status(response, {200})
            return response.text
        return self.request_json("GET", "/v1/metrics", expected_status=(200,))

    def get_block(self, height: int) -> Optional[Any]:
        """Fetch a block by height (`GET /v1/blocks/{height}`)."""

        return self.request_json("GET", f"/v1/blocks/{height}", expected_status=(200, 404))

    def get_pipeline_recovery(self, height: int) -> Optional[Any]:
        """Fetch an operator-authenticated pipeline recovery sidecar for `height`."""

        response = self._operator_get(
            f"/v1/pipeline/recovery/{int(height)}",
            headers={"Accept": "application/json"},
            context="get_pipeline_recovery",
        )
        self._expect_status(response, {200, 404})
        return self._maybe_json(response)

    def get_pipeline_recovery_typed(self, height: int) -> Optional[PipelineRecoverySidecar]:
        """Typed wrapper for :meth:`get_pipeline_recovery`."""

        payload = self.get_pipeline_recovery(height)
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise TypeError("pipeline recovery response must be a JSON object")
        return PipelineRecoverySidecar.from_payload(payload)

    def list_peers(self) -> Optional[Any]:
        """List the operator-authenticated node-local online peer snapshot."""

        response = self._operator_get(
            "/v1/peers",
            headers={"Accept": "application/json"},
            context="list_peers",
        )
        self._expect_status(response, (200,))
        return self._maybe_json(response)

    def list_peers_typed(self) -> List[PeerInfo]:
        """Return the online peer set as `PeerInfo` structures (`GET /v1/peers`)."""

        payload = self.list_peers()
        if payload is None:
            return []
        if not isinstance(payload, list):
            raise TypeError("expected list payload from /v1/peers")
        peers: List[PeerInfo] = []
        for entry in payload:
            peers.append(PeerInfo.from_payload(entry))
        return peers

    def list_telemetry_peers_info(self) -> Optional[Any]:
        """Return telemetry metadata from `GET /v1/telemetry/peers-info`."""

        return self.request_json(
            "GET",
            "/v1/telemetry/peers-info",
            expected_status=(200,),
        )

    def list_telemetry_peers_info_typed(self) -> List[PeerTelemetryInfo]:
        """Typed wrapper for :meth:`list_telemetry_peers_info`."""

        payload = self.list_telemetry_peers_info()
        if payload is None:
            return []
        if not isinstance(payload, list):
            raise TypeError("/v1/telemetry/peers-info response must be a list")
        entries: List[PeerTelemetryInfo] = []
        for index, entry in enumerate(payload):
            if not isinstance(entry, Mapping):
                raise TypeError(f"telemetry peers[{index}] must be an object")
            entries.append(PeerTelemetryInfo.from_payload(entry))
        return entries

    def list_kaigi_relays(self) -> Optional[Any]:
        """List registered Kaigi relays with exact-network operator authentication."""

        return self._get_kaigi_relay_json_object(
            "/v1/kaigi/relays",
            context="list_kaigi_relays",
        )

    def list_kaigi_relays_typed(self) -> KaigiRelaySummaryList:
        """Typed wrapper for :meth:`list_kaigi_relays`."""

        payload = self.list_kaigi_relays()
        if payload is None:
            raise RuntimeError("kaigi relays endpoint returned no payload")
        if not isinstance(payload, Mapping):
            raise TypeError("kaigi relays response must be a JSON object")
        return KaigiRelaySummaryList.from_payload(payload)

    def get_kaigi_relay(self, relay_id: str) -> Optional[Any]:
        """Fetch one relay diagnostic with exact-network operator authentication."""

        relay_literal = self._normalize_canonical_account_id(relay_id, "relay_id")
        return self._get_kaigi_relay_json_object(
            f"/v1/kaigi/relays/{quote(relay_literal, safe='')}",
            context="get_kaigi_relay",
            allow_not_found=True,
        )

    def get_kaigi_relay_typed(self, relay_id: str) -> Optional[KaigiRelayDetail]:
        """Typed wrapper for :meth:`get_kaigi_relay`."""

        payload = self.get_kaigi_relay(relay_id)
        if payload is None:
            return None
        return KaigiRelayDetail.from_payload(payload)

    def get_kaigi_relays_health(self) -> Optional[Any]:
        """Fetch aggregate relay health with exact-network operator authentication."""

        return self._get_kaigi_relay_json_object(
            "/v1/kaigi/relays/health",
            context="get_kaigi_relays_health",
        )

    def get_kaigi_relays_health_typed(self) -> KaigiRelayHealthSnapshot:
        """Typed wrapper for :meth:`get_kaigi_relays_health`."""

        payload = self.get_kaigi_relays_health()
        if payload is None:
            raise RuntimeError("kaigi relays health endpoint returned no payload")
        if not isinstance(payload, Mapping):
            raise TypeError("kaigi relays health response must be an object")
        return KaigiRelayHealthSnapshot.from_payload(payload)

    def get_time_now(self) -> NetworkTimeSnapshot:
        """Return the validated Network Time Service snapshot."""

        return super().get_time_now()

    def get_time_status(self) -> NetworkTimeStatus:
        """Return validated operator-authenticated Network Time Service diagnostics."""

        response = self._operator_get(
            "/v1/time/status",
            headers={"Accept": "application/json"},
            context="get_time_status",
        )
        self._expect_status(response, (200,))
        payload = self._maybe_json(response)
        if not isinstance(payload, Mapping):
            raise TypeError("network time status response must be a JSON object")
        return NetworkTimeStatus.from_payload(payload)

    # ------------------------------------------------------------------
    # Runtime & admission helpers
    # ------------------------------------------------------------------
    def get_runtime_abi_hash(self) -> Optional[Any]:
        """Fetch the canonical ABI hash for the node's active policy (`GET /v1/runtime/abi/hash`)."""

        return self.request_json(
            "GET",
            "/v1/runtime/abi/hash",
            expected_status=(200,),
        )

    def get_runtime_abi_hash_typed(self) -> RuntimeAbiHash:
        """Typed wrapper for :meth:`get_runtime_abi_hash`."""

        payload = self.get_runtime_abi_hash()
        if payload is None:
            raise RuntimeError("runtime ABI hash endpoint returned no payload")
        return RuntimeAbiHash.from_payload(payload)

    def list_runtime_upgrades(self) -> Optional[Any]:
        """List runtime upgrade records (`GET /v1/runtime/upgrades`)."""

        return self.request_json(
            "GET",
            "/v1/runtime/upgrades",
            expected_status=(200,),
        )

    def list_runtime_upgrades_typed(self) -> RuntimeUpgradeListPage:
        """Typed wrapper for :meth:`list_runtime_upgrades`."""

        payload = self.list_runtime_upgrades()
        if payload is None:
            return RuntimeUpgradeListPage(items=[], total=0)
        return RuntimeUpgradeListPage.from_payload(payload)

    def propose_runtime_upgrade(self, manifest: Mapping[str, Any]) -> Dict[str, Any]:
        """Wrap a runtime upgrade manifest into instructions (`POST /v1/runtime/upgrades/propose`)."""

        response = self._request(
            "POST",
            "/v1/runtime/upgrades/propose",
            json_body=dict(manifest),
        )
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, dict):
            raise RuntimeError("unexpected runtime upgrade proposal response")
        return payload

    def propose_runtime_upgrade_typed(
        self, manifest: Union[RuntimeUpgradeManifest, Mapping[str, Any]]
    ) -> RuntimeUpgradeActionResponse:
        """Typed wrapper for :meth:`propose_runtime_upgrade`."""

        manifest_payload: Mapping[str, Any]
        if isinstance(manifest, RuntimeUpgradeManifest):
            manifest_payload = manifest.to_payload()
        else:
            manifest_payload = manifest
        payload = self.propose_runtime_upgrade(manifest_payload)
        return RuntimeUpgradeActionResponse.from_payload(payload)

    def activate_runtime_upgrade(self, upgrade_id_hex: str) -> Dict[str, Any]:
        """Generate activation instructions for a runtime upgrade (`POST /v1/runtime/upgrades/activate/{id}`)."""

        path = f"/v1/runtime/upgrades/activate/{upgrade_id_hex.strip()}"
        response = self._request(
            "POST",
            path,
            headers={"Content-Type": "application/json"},
            data=b"",
        )
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, dict):
            raise RuntimeError("unexpected runtime upgrade activation response")
        return payload

    def activate_runtime_upgrade_typed(self, upgrade_id_hex: str) -> RuntimeUpgradeActionResponse:
        """Typed wrapper for :meth:`activate_runtime_upgrade`."""

        payload = self.activate_runtime_upgrade(upgrade_id_hex)
        return RuntimeUpgradeActionResponse.from_payload(payload)

    def cancel_runtime_upgrade(self, upgrade_id_hex: str) -> Dict[str, Any]:
        """Generate cancellation instructions for a runtime upgrade (`POST /v1/runtime/upgrades/cancel/{id}`)."""

        path = f"/v1/runtime/upgrades/cancel/{upgrade_id_hex.strip()}"
        response = self._request(
            "POST",
            path,
            headers={"Content-Type": "application/json"},
            data=b"",
        )
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, dict):
            raise RuntimeError("unexpected runtime upgrade cancellation response")
        return payload

    def cancel_runtime_upgrade_typed(self, upgrade_id_hex: str) -> RuntimeUpgradeActionResponse:
        """Typed wrapper for :meth:`cancel_runtime_upgrade`."""

        payload = self.cancel_runtime_upgrade(upgrade_id_hex)
        return RuntimeUpgradeActionResponse.from_payload(payload)

    # ------------------------------------------------------------------
    # UAID portfolio & Space Directory surfaces
    # ------------------------------------------------------------------

    def get_uaid_portfolio(
        self,
        uaid: str,
        *,
        asset_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch the aggregated UAID portfolio (`GET /v1/accounts/{uaid}/portfolio`).

        Use ``asset_id`` to filter the response to a specific asset identifier.
        """

        literal = _normalize_uaid_literal(uaid)
        params: Dict[str, Any] = {}
        asset_id_value = (
            None
            if asset_id is None
            else _require_exact_non_empty_string(
                asset_id,
                "get_uaid_portfolio.asset_id",
            )
        )
        if asset_id_value is not None:
            params["asset_id"] = asset_id_value
        response = self._request(
            "GET",
            f"/v1/accounts/{literal}/portfolio",
            params=self._clean_params(params),
        )
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, dict):
            raise RuntimeError("unexpected UAID portfolio response")
        return payload

    def get_uaid_portfolio_typed(
        self,
        uaid: str,
        *,
        asset_id: Optional[str] = None,
    ) -> UaidPortfolioSnapshot:
        """Typed wrapper for :meth:`get_uaid_portfolio`."""

        payload = self.get_uaid_portfolio(uaid, asset_id=asset_id)
        return UaidPortfolioSnapshot.from_payload(payload)

    def get_uaid_bindings(
        self,
        uaid: str,
    ) -> Dict[str, Any]:
        """Fetch UAID dataspace bindings (`GET /v1/space-directory/uaids/{uaid}`)."""

        literal = _normalize_uaid_literal(uaid)
        response = self._request(
            "GET",
            f"/v1/space-directory/uaids/{literal}",
        )
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, dict):
            raise RuntimeError("unexpected UAID bindings response")
        return payload

    def get_uaid_bindings_typed(
        self,
        uaid: str,
    ) -> UaidBindingsSnapshot:
        """Typed wrapper for :meth:`get_uaid_bindings`."""

        payload = self.get_uaid_bindings(uaid)
        return UaidBindingsSnapshot.from_payload(payload)

    def uaid_manifests(self, uaid: str) -> Collection[SpaceDirectoryManifestRecord]:
        """Manifest records for one UAID, with shared filters and cursor pages."""

        canonical = _normalize_uaid_literal(uaid)

        def parse(row: Any) -> SpaceDirectoryManifestRecord:
            record = SpaceDirectoryManifestRecord.from_payload(row)
            if record.manifest["uaid"] != canonical:
                raise ValueError("manifest record UAID differs from the requested UAID")
            return record

        return Collection(
            self,
            f"/v1/space-directory/uaids/{quote(canonical, safe='')}/manifests",
            parse,
            "uaid manifests",
        )

    def _handle_sorafs_alias_warning(self, warning: SorafsAliasWarning) -> None:
        """Internal hook for alias-proof warnings."""

        self._sorafs_alias_metrics["warnings"] = self._sorafs_alias_metrics.get("warnings", 0) + 1
        if self._sorafs_alias_warning_hook:
            self._sorafs_alias_warning_hook(warning)

    def _enforce_sorafs_alias_policy(
        self,
        response: requests.Response,
    ) -> Optional[SorafsAliasEvaluation]:
        """Validate SoraFS alias proofs stapled on HTTP responses."""

        try:
            evaluation = enforce_sorafs_alias_policy(
                response,
                policy=self._sorafs_alias_policy,
                warning_hook=self._handle_sorafs_alias_warning,
                logger=self._sorafs_alias_logger,
            )
        except Exception as exc:
            response.close()
            if isinstance(exc, SorafsAliasError):
                raise RuntimeError(f"failed to validate SoraFS alias proof: {exc}") from exc
            raise
        if evaluation is None:
            self._last_sorafs_alias_evaluation = None
            return None
        self._last_sorafs_alias_evaluation = evaluation
        self._sorafs_alias_metrics["total"] = self._sorafs_alias_metrics.get("total", 0) + 1
        label = evaluation.status_label or evaluation.state
        self._sorafs_alias_metrics[label] = self._sorafs_alias_metrics.get(label, 0) + 1
        return evaluation

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        data: Optional[bytes] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        allow_retry: bool = True,
        allow_redirects: bool = False,
        stream: bool = False,
        _headers_are_final: bool = False,
        _operation_deadline_ns: Optional[int] = None,
        _maximum_body_bytes: Optional[int] = None,
        _response_media_type: Optional[str] = None,
    ) -> requests.Response:
        bounded = any(value is not None for value in (
            _operation_deadline_ns, _maximum_body_bytes, _response_media_type,
        ))
        if bounded:
            from .requests_deadline import check_bounded_client, check_bounded_request
            bounded_client = check_bounded_client(self)
            headers = check_bounded_request(method, path, headers, data, json_body, params, timeout,
                (_headers_are_final, stream, allow_retry, allow_redirects),
                _operation_deadline_ns, _maximum_body_bytes, _response_media_type)
        if _headers_are_final and (not stream or headers is None):
            raise ValueError("final SSE headers require a streaming request with headers")
        if json_body is not None and data is not None:
            raise ValueError("provide either `json_body` or `data`, not both")
        if params is not None and not isinstance(params, Mapping):
            raise TypeError("params must be a mapping")
        if json_body is not None and not isinstance(json_body, Mapping):
            raise TypeError("json_body must be a mapping")
        if data is not None and type(data) is not bytes:
            raise TypeError("data must be exact immutable bytes")

        normalized_path = _normalize_request_path(path)

        final_headers: Dict[str, str] = (
            {} if _headers_are_final else dict(
                bounded_client["headers"] if bounded else self._default_headers
            )
        )
        if headers is not None:
            for name, value in _copy_http_headers(headers, "headers").items():
                _set_exact_header(final_headers, name, value)

        payload: Optional[bytes]
        if json_body is not None:
            payload = json.dumps(
                json_body,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            final_headers.setdefault("Content-Type", "application/json")
        else:
            payload = data

        method_upper = _normalize_http_method(method)
        request_timeout = (
            (bounded_client["timeout"] if bounded else self._timeout)
            if timeout is None
            else _require_positive_finite_float(timeout, "timeout")
        )
        if isinstance(headers, _CanonicalRequestHeaderPlan):
            signed_headers: Mapping[str, str] = _CanonicalRequestHeaderPlan(
                final_headers,
                headers.canonical_auth,
                reject_ambient_auth=headers.reject_ambient_auth,
            )
        elif isinstance(headers, _OperatorRequestHeaderPlan):
            signed_headers = _OperatorRequestHeaderPlan(final_headers, headers.context)
        else:
            signed_headers = final_headers
        if bounded:
            if (type(_operation_deadline_ns) is not int
                    or type(_maximum_body_bytes) is not int
                    or type(_response_media_type) is not str
                    or params is not None or not stream or allow_retry or allow_redirects
                    or isinstance(signed_headers, (_CanonicalRequestHeaderPlan, _OperatorRequestHeaderPlan))):
                raise ValueError("bounded observation requires one unsigned, nonredirecting dispatch")
            from .requests_deadline import check_alias_state, send_bounded_request
            if type(self) is not ToriiClient:
                raise TypeError("bounded staking preparation requires the canonical ToriiClient")
            check_alias_state(self._sorafs_alias_metrics, self._last_sorafs_alias_evaluation)
            response = send_bounded_request(
                session=self._session, method=method_upper,
                url=f"{bounded_client['base_url']}{normalized_path}", headers=signed_headers,
                body=payload, timeout=request_timeout, deadline_ns=_operation_deadline_ns,
                max_body=_maximum_body_bytes, media_type=_response_media_type,
                alias_policy=self._sorafs_alias_policy,
                alias_warning_hook=self._sorafs_alias_warning_hook,
                alias_logger=self._sorafs_alias_logger,
            )
            # The worker already ran the canonical proof policy and emitted each
            # admitted warning once. Only closed in-memory data is touched here.
            check_alias_state(self._sorafs_alias_metrics, self._last_sorafs_alias_evaluation)
            evaluation = response._iroha_alias_evaluation
            self._last_sorafs_alias_evaluation = evaluation
            if evaluation is not None:
                metrics = self._sorafs_alias_metrics
                metrics["total"] = metrics.get("total", 0) + 1
                label = evaluation.status_label or evaluation.state
                metrics[label] = metrics.get(label, 0) + 1
                if evaluation.state == "refresh_window" or evaluation.rotation_due:
                    metrics["warnings"] = metrics.get("warnings", 0) + 1
            return response

        if isinstance(
            signed_headers,
            (_CanonicalRequestHeaderPlan, _OperatorRequestHeaderPlan),
        ):
            response = _BaseToriiClient._request(
                self,
                method_upper,
                normalized_path,
                params=params,
                headers=signed_headers,
                data=payload,
                timeout=request_timeout,
                allow_retry=allow_retry,
                allow_redirects=allow_redirects,
                stream=stream,
            )
            self._enforce_sorafs_alias_policy(response)
            return response

        retry_enabled = allow_retry and method_upper in self._retry_methods
        max_attempts = 1 + (self._max_retries if retry_enabled else 0)
        url = f"{self._base_url}{normalized_path}"
        _require_zero_retry_adapter(self._session, url)

        delay = self._backoff_initial
        for attempt in range(max_attempts):
            try:
                response = self._session.request(
                    method_upper,
                    url,
                    params=params,
                    headers=signed_headers or None,
                    data=payload,
                    timeout=request_timeout,
                    allow_redirects=allow_redirects,
                    stream=stream,
                )
            except requests.RequestException:
                if attempt == max_attempts - 1:
                    raise
                delay = self._apply_backoff(delay)
                continue

            if (
                retry_enabled
                and response.status_code in self._retry_statuses
                and attempt < max_attempts - 1
            ):
                response.close()
                delay = self._apply_backoff(delay)
                continue

            self._enforce_sorafs_alias_policy(response)
            return response

        raise RuntimeError("exhausted retries without receiving a response")

    def prepare_public_lane_plan(self, request, xor_asset_definition_id: str):
        """Read exact staking signing inputs under immutable network and explicit XOR pins.

        No transaction is signed or submitted. The observation carries no state
        proof; execution rechecks every effect and expiry. Transport dispatches
        once, rejects redirects, byte-bounds success/error streams, and closes
        after completion or failure. A private Requests worker owns blocking
        I/O under the original absolute deadline on POSIX. Unsupported custom
        Sessions/adapters are rejected before dispatch; there is no fallback.
        """
        started_ns = time.monotonic_ns()
        from .requests_deadline import _remaining, check_preparation_inputs
        original_timeout, network, request = check_preparation_inputs(self, request, xor_asset_definition_id)
        if original_timeout > (((1 << 64) - 1 - started_ns) // 1_000_000_000):
            raise ValueError("staking preparation timeout exceeds the absolute deadline range")
        deadline_ns = started_ns + int(original_timeout * 1_000_000_000)
        from .validator_staking import (
            StakingPreparationRequestV1, StakingPreparationV1,
            encode_staking_preparation_frame_v1, decode_staking_preparation_frame_v1,
            validate_staking_preparation_v1,
        )
        from .address import asset_definition_id_to_bytes
        asset_definition_id_to_bytes(xor_asset_definition_id)
        if type(request) is not StakingPreparationRequestV1:
            raise TypeError("staking preparation requires an exact typed request")
        body = encode_staking_preparation_frame_v1(request)
        response = ToriiClient._request(self, "POST", "/v1/nexus/staking/prepare",
            headers={"Content-Type": "application/x-norito", "Accept": "application/x-norito"},
            data=body, stream=True, allow_retry=False, allow_redirects=False,
            _operation_deadline_ns=deadline_ns, _maximum_body_bytes=256 * 1024,
            _response_media_type="application/x-norito")
        try:
            if response.status_code == 200 and response.headers.get("Content-Type", "").strip().lower() != "application/x-norito":
                raise ValueError("staking preparation requires application/x-norito")
            raw = _read_bounded_response_body(response, 256 * 1024, "staking preparation")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) != len(raw):
                raise ValueError("staking preparation response length mismatch")
            if response.status_code != 200:
                error = requests.HTTPError(f"staking preparation HTTP {response.status_code}", response=response)
                error.staking_preparation_body = raw
                raise error
            prepared = decode_staking_preparation_frame_v1(StakingPreparationV1, raw)
            validated = validate_staking_preparation_v1(prepared, request, network, xor_asset_definition_id)
            _remaining(deadline_ns)
            return validated
        finally:
            response.close()

    def _apply_backoff(self, current_delay: float) -> float:
        delay = current_delay
        if delay <= 0.0 and self._backoff_initial > 0.0:
            delay = self._backoff_initial
        if delay > 0.0:
            time.sleep(delay)
        if delay <= 0.0:
            return 0.0
        next_delay = delay * self._backoff_multiplier
        return min(self._backoff_cap, next_delay)

    def build_and_submit_transaction(
        self,
        network_id: "NetworkId",
        authority: str,
        private_key: bytes,
        *,
        fee_payment: Mapping[str, Any],
        instructions: Iterable["Instruction"] = (),
        creation_time_ms: Optional[int] = None,
        ttl_ms: Optional[int] = None,
        nonce: Optional[int] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        interval: float = 1.0,
        timeout: Optional[float] = 30.0,
        max_attempts: Optional[int] = None,
        on_status: Optional[Callable[[Optional[str], Any, int], None]] = None,
        expect_json: bool = True,
        envelope_format: str = "object",
    ) -> tuple["SignedTransactionEnvelope", Optional[Any]]:
        """Build, submit, and optionally wait for a transaction to finalize.

        When `expect_json` is true, an empty or non-dict response from the
        submission endpoint is normalised to `{}` so callers can assume a mapping.
        ``network_id`` must be the exact typed genesis-derived transaction
        domain; labels and bare hash bytes are rejected.
        """

        crypto = _require_crypto()
        envelope = crypto.build_signed_transaction(
            network_id,
            authority,
            private_key,
            fee_payment=fee_payment,
            instructions=instructions,
            creation_time_ms=creation_time_ms,
            ttl_ms=ttl_ms,
            nonce=nonce,
            metadata=metadata,
        )
        if envelope_format == "object":
            envelope_out: Union[SignedTransactionEnvelope, Dict[str, Any], str] = envelope
        elif envelope_format == "dict":
            envelope_out = envelope.as_dict()
        elif envelope_format == "json":
            envelope_out = envelope.to_json()
        else:
            raise ValueError("envelope_format must be one of {'object', 'dict', 'json'}")
        if wait:
            result = self.submit_transaction_envelope_and_wait(
                envelope,
                interval=interval,
                timeout=timeout,
                max_attempts=max_attempts,
                on_status=on_status,
            )
            return envelope_out, result
        response = self.submit_transaction_envelope(envelope)
        if expect_json and response is None:
            response = {}
        return envelope_out, response

    def get_transaction_status(
        self,
        hash_hex: str,
        *,
        scope: str = "global",
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """Fetch only non-sensitive public pipeline metadata for one transaction."""

        normalized_hash = _require_exact_pipeline_transaction_hash(
            hash_hex,
            "get_transaction_status.hash_hex",
        )
        scope = _normalize_transaction_status_scope(scope, "get_transaction_status.scope")
        response = self._request(
            "GET",
            "/v1/pipeline/transactions/status",
            params={"hash": normalized_hash, "scope": scope},
            timeout=timeout,
        )
        if response.status_code == 404:
            return None
        self._expect_status(response, {200})
        return _normalize_public_pipeline_status(
            self._maybe_json(response),
            normalized_hash,
        )

    def get_pipeline_transaction_details(
        self,
        transaction_hash: str,
        *,
        authority: str,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Fetch authorized committed-transaction details with one signed query.

        The native ``FindTransactions`` builder binds the query to the exact
        NetworkId derived from this client's immutable canonical genesis hash.
        Torii admits only an involved account or an operator and validates the
        signature, freshness, nonce, and exact entrypoint hash. The nonce-bearing
        request is sent once with redirects and retries disabled.
        """

        signing_context = self._require_local_signing_context(
            "get_pipeline_transaction_details"
        )
        normalized_hash = _require_exact_pipeline_transaction_hash(
            transaction_hash,
            "get_pipeline_transaction_details.transaction_hash",
        )
        canonical_authority = self._native_transaction_account_id(
            authority,
            "get_pipeline_transaction_details.authority",
        )
        signing_key = self._native_query_signing_key(
            private_key=private_key,
            private_key_hex=private_key_hex,
        )
        from .crypto import build_find_committed_transaction_query

        request = build_find_committed_transaction_query(
            canonical_authority,
            signing_key,
            signing_context.network_id,
            normalized_hash,
        )
        response = self._request(
            "POST",
            "/v1/pipeline/transactions/details",
            data=request,
            headers={
                "Content-Type": "application/x-norito",
                "Accept": "application/json",
            },
            timeout=timeout,
            allow_retry=False,
            allow_redirects=False,
        )
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, Mapping):
            raise TypeError("transaction details response must be an object")
        expected_fields = {"hash", "transaction", "trigger_completions"}
        actual_fields = set(payload)
        if actual_fields != expected_fields:
            extras = sorted(actual_fields - expected_fields)
            missing = sorted(expected_fields - actual_fields)
            if extras:
                raise ValueError(
                    "transaction details response contains unsupported fields: "
                    + ", ".join(extras)
                )
            raise ValueError(
                "transaction details response is missing required fields: "
                + ", ".join(missing)
            )
        observed_hash = _require_exact_pipeline_transaction_hash(
            payload.get("hash"),
            "transaction details response.hash",
        )
        if not hmac.compare_digest(observed_hash, normalized_hash):
            raise ValueError(
                "transaction details response.hash does not match the requested transaction"
            )
        transaction = payload.get("transaction")
        if not isinstance(transaction, Mapping):
            raise TypeError("transaction details response.transaction must be an object")
        trigger_completions = payload.get("trigger_completions")
        if not isinstance(trigger_completions, list):
            raise TypeError(
                "transaction details response.trigger_completions must be an array"
            )
        return {
            "hash": observed_hash,
            "transaction": dict(transaction),
            "trigger_completions": list(trigger_completions),
        }

    def wait_for_transaction_status(
        self,
        hash_hex: str,
        *,
        interval: float = 1.0,
        timeout: Optional[float] = 30.0,
        max_attempts: Optional[int] = None,
        on_status: Optional[Callable[[Optional[str], Any, int], None]] = None,
    ) -> Any:
        """Poll global status until exact state-resolved ``Applied`` finality.

        State-resolved ``Rejected`` and ``Expired`` are the only failures.
        Queue/cache observations and every other status remain progress only.
        """

        normalized_hash = _require_exact_pipeline_transaction_hash(
            hash_hex,
            "wait_for_transaction_status.hash_hex",
        )
        interval_seconds = _transaction_wait_seconds(
            interval,
            context="wait_for_transaction_status.interval",
        )
        timeout_seconds = (
            None
            if timeout is None
            else _transaction_wait_seconds(
                timeout,
                context="wait_for_transaction_status.timeout",
            )
        )
        maximum_attempts = _transaction_wait_max_attempts(
            max_attempts,
            context="wait_for_transaction_status.max_attempts",
        )
        if on_status is not None and not callable(on_status):
            raise TypeError("wait_for_transaction_status.on_status must be callable")

        attempts = 0
        deadline = (
            None if timeout_seconds is None else time.monotonic() + timeout_seconds
        )

        while True:
            request_timeout = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    raise TimeoutError(
                        f"transaction {normalized_hash} did not reach a terminal status "
                        f"within {timeout_seconds} seconds"
                    )
                request_timeout = (
                    remaining if self._timeout is None else min(self._timeout, remaining)
                )
            attempts += 1
            payload = self.get_transaction_status(
                normalized_hash,
                scope="global",
                timeout=request_timeout,
            )
            status = _extract_pipeline_status_kind(payload)

            if on_status is not None:
                on_status(status, payload, attempts)

            if payload is not None:
                if payload["scope"] != "global":
                    raise ValueError(
                        "transaction status response.scope must be exactly global while waiting"
                    )
                authoritative_status = (
                    status if payload["resolved_from"] == "state" else None
                )
                if authoritative_status == "Applied":
                    return payload
                if authoritative_status in {"Rejected", "Expired"}:
                    raise TransactionStatusError(
                        normalized_hash,
                        authoritative_status,
                        payload,
                    )

            if maximum_attempts is not None and attempts >= maximum_attempts:
                raise TimeoutError(
                    f"transaction {normalized_hash} did not reach a terminal status "
                    f"after {attempts} attempts"
                )

            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(
                    f"transaction {normalized_hash} did not reach a terminal status "
                    f"within {timeout_seconds} seconds"
                )

            if interval_seconds > 0.0:
                if deadline is None:
                    time.sleep(interval_seconds)
                else:
                    sleep_for = min(
                        interval_seconds,
                        max(deadline - time.monotonic(), 0.0),
                    )
                    if sleep_for > 0.0:
                        time.sleep(sleep_for)

    # ------------------------------------------------------------------
    # Transaction construction convenience helpers
    # ------------------------------------------------------------------

    @staticmethod
    def compose_asset_id(
        asset_definition_id: str,
        account_id: str,
        *,
        scope: Optional[str] = None,
    ) -> str:
        """Build a canonical asset balance bucket literal."""

        definition = _require_non_empty_string(
            asset_definition_id,
            "compose_asset_id.asset_definition_id",
        )
        account = _require_non_empty_string(account_id, "compose_asset_id.account_id")
        literal = f"{definition}#{account}"
        if scope:
            scope_text = _require_non_empty_string(scope, "compose_asset_id.scope")
            if scope_text.isdigit():
                scope_text = f"dataspace:{scope_text}"
            literal = f"{literal}#{scope_text}"
        return literal

    @staticmethod
    def _envelope_hash_hex(envelope: "SignedTransactionEnvelope") -> str:
        hash_field = getattr(envelope, "hash", None)
        if hash_field is None:
            raise ValueError("SignedTransactionEnvelope.hash is required to poll status")
        if isinstance(hash_field, memoryview):
            hash_field = hash_field.tobytes()
        if isinstance(hash_field, (bytes, bytearray)):
            hash_field = bytes(hash_field).hex()
        elif not isinstance(hash_field, str):
            raise TypeError(
                "SignedTransactionEnvelope.hash must be bytes or hex string, "
                f"got {type(hash_field)!r}"
            )
        return _require_exact_pipeline_transaction_hash(
            hash_field,
            "SignedTransactionEnvelope.hash",
        )

    def _transaction_draft(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        creation_time_ms: Optional[int] = None,
        ttl_ms: Optional[int] = 900_000,
        nonce: Optional[int] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "TransactionDraft":
        from .tx import TransactionConfig, TransactionDraft, authority_fee_payment

        effective_authority = self._native_transaction_account_id(
            _require_exact_non_empty_string(authority, "authority"),
            "authority",
        )
        signing_context = self._require_local_signing_context(
            "local transaction construction"
        )
        return TransactionDraft(
            TransactionConfig(
                network_id=signing_context.network_id,
                authority=effective_authority,
                fee_payment=(
                    fee_payment
                    if fee_payment is not None
                    else authority_fee_payment(charge_limits=[])
                ),
                creation_time_ms=creation_time_ms,
                ttl_ms=ttl_ms,
                nonce=nonce,
                metadata=metadata,
            )
        )

    def _submit_transaction_draft_result(
        self,
        draft: "TransactionDraft",
        *,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        wait: bool = True,
        interval: float = 1.0,
        timeout: Optional[float] = 30.0,
        max_attempts: Optional[int] = None,
        on_status: Optional[Callable[[Optional[str], Any, int], None]] = None,
    ) -> Mapping[str, Any]:
        envelope = self._sign_transaction_draft(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
        )
        hash_hex = self._envelope_hash_hex(envelope)
        try:
            status = self.submit_transaction_envelope(envelope)
        except (requests.RequestException, TimeoutError) as exc:
            if wait:
                raise
            status = {
                "ok": False,
                "status": "submission_timeout_pending_status",
                "error": str(exc),
            }
        result: Dict[str, Any] = {
            "envelope": envelope,
            "hash": hash_hex,
            "submission": status,
        }
        if wait:
            result["terminal"] = self.wait_for_transaction_status(
                hash_hex,
                interval=interval,
                timeout=timeout,
                max_attempts=max_attempts,
                on_status=on_status,
            )
        return result

    def submit_instructions_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        instructions: Iterable["Instruction"],
        wait: bool = True,
        ttl_ms: Optional[int] = 900_000,
        nonce: Optional[int] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        interval: float = 1.0,
        timeout: Optional[float] = 30.0,
        max_attempts: Optional[int] = None,
    ) -> Mapping[str, Any]:
        """Submit arbitrary instructions in one signed transaction."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            ttl_ms=ttl_ms,
            nonce=nonce,
            metadata=metadata,
        )
        draft.extend_instructions(instructions)
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            interval=interval,
            timeout=timeout,
            max_attempts=max_attempts,
        )

    def register_domain_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        domain_id: str,
        domain_metadata: Optional[Mapping[str, Any]] = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Register a domain and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.register_domain(domain_id, metadata=domain_metadata)
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def register_account_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        account_id: str,
        account_metadata: Optional[Mapping[str, Any]] = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Register an account and optionally wait for commit."""

        return self.register_accounts_and_wait(
            authority=authority,
            fee_payment=fee_payment,
            private_key=private_key,
            private_key_hex=private_key_hex,
            accounts=[account_id],
            account_metadata={account_id: account_metadata or {}},
            transaction_metadata=transaction_metadata,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def register_accounts_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        accounts: Iterable[str],
        account_metadata: Optional[Mapping[str, Mapping[str, Any]]] = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Register multiple accounts in one transaction."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        metadata_by_account = dict(account_metadata or {})
        registered = 0
        for account_id in accounts:
            native_account_id = self._native_transaction_account_id(
                account_id,
                f"accounts[{registered}]",
            )
            draft.register_account(
                native_account_id,
                metadata=(
                    metadata_by_account.get(account_id)
                    or metadata_by_account.get(native_account_id)
                ),
            )
            registered += 1
        if registered == 0:
            raise ValueError("accounts must contain at least one account id")
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def grant_account_permission_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        account_id: str,
        permission_name: str,
        permission_payload: Any = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Grant one account permission and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.grant_account_permission(
            self._native_transaction_account_id(account_id, "account_id"),
            permission_name,
            payload=permission_payload,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def revoke_account_permission_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        account_id: str,
        permission_name: str,
        permission_payload: Any = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Revoke one account permission and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.revoke_account_permission(
            self._native_transaction_account_id(account_id, "account_id"),
            permission_name,
            payload=permission_payload,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def register_asset_definition_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        definition_id: str,
        owning_domain: Optional[str],
        balance_scope_policy: str,
        name: str,
        description: Optional[str] = None,
        alias: Optional[str] = None,
        scale: Optional[Union[int, str]] = None,
        mintable: Optional[str] = "Infinitely",
        asset_metadata: Optional[Mapping[str, Any]] = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Register an asset owned by ``authority`` and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.register_asset_definition(
            definition_id,
            owning_domain=owning_domain,
            name=name,
            description=description,
            alias=alias,
            scale=scale,
            mintable=mintable,
            balance_scope_policy=balance_scope_policy,
            metadata=asset_metadata,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def mint_asset_quantity_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        asset_id: str,
        quantity: QuantityLike,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Mint an exact nominal asset quantity and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.mint_asset_quantity(
            self._native_transaction_asset_id(asset_id, "asset_id"),
            quantity,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def mint_assets_quantity_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        mints: Iterable[Mapping[str, Any]],
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Mint multiple exact nominal asset quantities in one transaction."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        count = 0
        for index, record in enumerate(mints):
            if not isinstance(record, Mapping):
                raise TypeError(f"mints[{index}] must be a mapping")
            asset_id = _require_non_empty_string(
                record.get("asset_id"),
                f"mints[{index}].asset_id",
            )
            if "quantity" not in record:
                raise TypeError(f"mints[{index}].quantity is required")
            draft.mint_asset_quantity(
                self._native_transaction_asset_id(
                    asset_id,
                    f"mints[{index}].asset_id",
                ),
                record["quantity"],
            )
            count += 1
        if count == 0:
            raise ValueError("mints must contain at least one mint record")
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def burn_asset_quantity_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        asset_id: str,
        quantity: QuantityLike,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Burn an exact nominal asset quantity and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.burn_asset_quantity(
            self._native_transaction_asset_id(asset_id, "asset_id"),
            quantity,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def transfer_asset_quantity_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        asset_id: str,
        quantity: QuantityLike,
        destination: str,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Transfer an exact nominal asset quantity and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.transfer_asset_quantity(
            self._native_transaction_asset_id(asset_id, "asset_id"),
            quantity,
            self._native_transaction_account_id(destination, "destination"),
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def transfer_asset_batch_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        asset_definition_id: str,
        source_account: str,
        payments: Sequence[Any],
        mode: Any = "Independent",
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Submit one native transfer batch with ordered, durable leg outcomes."""

        if isinstance(payments, (str, bytes, bytearray, memoryview)) or not isinstance(
            payments,
            Sequence,
        ):
            raise TypeError("payments must be a sequence")
        normalized_payments: List[Dict[str, Any]] = []
        for index, payment in enumerate(payments):
            if isinstance(payment, Mapping):
                payload = dict(payment)
            else:
                to_payload = getattr(payment, "to_payload", None)
                if not callable(to_payload):
                    raise TypeError(
                        f"payments[{index}] must be a mapping or expose to_payload()"
                    )
                payload = dict(to_payload())
            if "to" in payload:
                payload["to"] = self._native_transaction_account_id(
                    payload["to"],
                    f"payments[{index}].to",
                )
            normalized_payments.append(payload)

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.transfer_asset_batch(
            self._native_transaction_account_id(source_account, "source_account"),
            _require_exact_non_empty_string(
                asset_definition_id,
                "asset_definition_id",
            ),
            normalized_payments,
            mode=mode,
        )
        result = dict(
            self._submit_transaction_draft_result(
                draft,
                private_key=private_key,
                private_key_hex=private_key_hex,
                wait=wait,
                timeout=timeout,
                interval=interval,
            )
        )
        terminal = result.get("terminal")
        receipt = (
            terminal.get("batch_receipt")
            if isinstance(terminal, Mapping)
            else None
        )
        if isinstance(receipt, Mapping):
            result["batch_receipt"] = dict(receipt)
        return result

    def set_asset_transfer_availability_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        account_id: str,
        asset_definition_id: str,
        expected_revision: int,
        incoming: Union["AssetTransferAvailability", str],
        outgoing: Union["AssetTransferAvailability", str],
        reason: Optional[str] = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Update directional transfer availability and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.set_asset_transfer_availability(
            self._native_transaction_account_id(account_id, "account_id"),
            _require_non_empty_string(asset_definition_id, "asset_definition_id"),
            expected_revision,
            incoming,
            outgoing,
            reason=reason,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def set_asset_transfer_blacklist_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        account_id: str,
        asset_definition_id: str,
        blacklisted: bool,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Blacklist or restore outbound transfers and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.set_asset_transfer_blacklist(
            self._native_transaction_account_id(account_id, "account_id"),
            _require_non_empty_string(asset_definition_id, "asset_definition_id"),
            blacklisted,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def set_asset_transfer_control_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        account_id: str,
        asset_definition_id: str,
        limits: Sequence[Mapping[str, Any]],
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Replace outbound DAY/WEEK/MONTH caps and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.set_asset_transfer_control(
            self._native_transaction_account_id(account_id, "account_id"),
            _require_non_empty_string(asset_definition_id, "asset_definition_id"),
            limits,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def set_asset_holding_limit_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        account_id: str,
        asset_definition_id: str,
        holding_limit: Optional[QuantityLike],
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Set or clear one account holding limit and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.set_asset_holding_limit(
            self._native_transaction_account_id(account_id, "account_id"),
            _require_non_empty_string(asset_definition_id, "asset_definition_id"),
            holding_limit,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def open_asset_lock_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        escrow_id: str,
        asset_definition_id: str,
        destination: str,
        amount: QuantityLike,
        release_authority: Optional[str] = None,
        expires_at_ms: Optional[int] = None,
        evidence_hashes: Optional[Sequence[Any]] = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Open a native asset lock and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.open_asset_lock(
            escrow_id,
            asset_definition_id,
            self._native_transaction_account_id(destination, "destination"),
            amount,
            release_authority=(
                self._native_transaction_account_id(
                    release_authority,
                    "release_authority",
                )
                if release_authority is not None
                else None
            ),
            expires_at_ms=expires_at_ms,
            evidence_hashes=evidence_hashes,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def open_conditional_escrow_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        escrow_id: str,
        asset_definition_id: str,
        amount: QuantityLike,
        beneficiary: str,
        conditions: Sequence[Any],
        release_policy: Any = "AllConditions",
        expires_at_ms: int,
        evidence_digests: Optional[Sequence[Any]] = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Open an ordered, queryable native conditional escrow."""

        policy = getattr(release_policy, "value", release_policy)
        if policy != "AllConditions":
            raise ValueError(
                "release_policy must be 'AllConditions'; native conditional escrows "
                "release only after every ordered predicate passes"
            )
        if isinstance(conditions, (str, bytes, bytearray, memoryview)) or not isinstance(
            conditions,
            Sequence,
        ):
            raise TypeError("conditions must be a sequence")
        normalized_conditions: List[Dict[str, Any]] = []
        for index, condition in enumerate(conditions):
            if isinstance(condition, Mapping):
                payload = dict(condition)
            else:
                to_payload = getattr(condition, "to_payload", None)
                if not callable(to_payload):
                    raise TypeError(
                        f"conditions[{index}] must be a mapping or expose to_payload()"
                    )
                payload = dict(to_payload())
            if payload.get("kind") == "Oracle":
                oracle = payload.get("value")
                if not isinstance(oracle, Mapping):
                    raise TypeError(f"conditions[{index}].value must be a mapping")
                normalized_oracle = dict(oracle)
                if "attestor" in normalized_oracle:
                    normalized_oracle["attestor"] = self._native_transaction_account_id(
                        normalized_oracle["attestor"],
                        f"conditions[{index}].value.attestor",
                    )
                payload["value"] = normalized_oracle
            normalized_conditions.append(payload)

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.open_conditional_escrow(
            escrow_id,
            _require_exact_non_empty_string(
                asset_definition_id,
                "asset_definition_id",
            ),
            self._native_transaction_account_id(beneficiary, "beneficiary"),
            amount,
            normalized_conditions,
            expires_at_ms,
            evidence_digests=evidence_digests,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def attest_escrow_condition_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        escrow_id: str,
        claim: str,
        value: Any,
        evidence_digest: Optional[Any] = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Attest one condition; the final passing claim releases custody."""

        from .settlement import EscrowValue

        if isinstance(value, Mapping) or callable(getattr(value, "to_payload", None)):
            typed_value = value
        elif isinstance(value, bool):
            typed_value = EscrowValue.boolean(value)
        elif isinstance(value, str):
            typed_value = EscrowValue.text(value)
        elif isinstance(value, (int, float, Decimal)):
            typed_value = EscrowValue.quantity(value)
        else:
            raise TypeError(
                "value must be an EscrowValue, mapping, bool, string, or quantity"
            )

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.attest_escrow_condition(
            escrow_id,
            claim,
            typed_value,
            evidence_digest=evidence_digest,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def expire_conditional_escrow_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        escrow_id: str,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Expire a conditional escrow and atomically refund its opener."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.expire_conditional_escrow(escrow_id)
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def drawdown_asset_lock_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        escrow_id: str,
        amount: QuantityLike,
        expected_remaining_amount: Optional[QuantityLike] = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Draw down a lock while retaining native optimistic concurrency.

        When the caller omits ``expected_remaining_amount``, the SDK obtains the
        current signed escrow record and binds that exact value into the native
        instruction.
        """

        if expected_remaining_amount is None:
            signing_context = self._require_local_signing_context(
                "drawdown_asset_lock_and_wait"
            )
            escrow = self.get_asset_escrow(
                escrow_id=escrow_id,
                authority=authority,
                network_id=signing_context.network_id,
                private_key=private_key,
                private_key_hex=private_key_hex,
            )
            expected_remaining_amount = escrow.get("remaining_amount")
            if expected_remaining_amount is None:
                raise RuntimeError(
                    "native escrow record omitted remaining_amount"
                )
        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.drawdown_asset_lock(escrow_id, amount, expected_remaining_amount)
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def cancel_asset_lock_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        escrow_id: str,
        expected_remaining_amount: QuantityLike,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Cancel a lock with the caller's exact remaining-amount precondition."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.cancel_asset_lock(escrow_id, expected_remaining_amount)
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def expire_asset_lock_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        escrow_id: str,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Expire a native asset lock and optionally wait for commit."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.expire_asset_lock(escrow_id)
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def transfer_assets_quantity_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        transfers: Iterable[Mapping[str, Any]],
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Transfer multiple exact nominal asset quantities in one transaction."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        count = 0
        for index, record in enumerate(transfers):
            if not isinstance(record, Mapping):
                raise TypeError(f"transfers[{index}] must be a mapping")
            asset_id = _require_non_empty_string(
                record.get("asset_id"),
                f"transfers[{index}].asset_id",
            )
            destination = _require_non_empty_string(
                record.get("destination"),
                f"transfers[{index}].destination",
            )
            if "quantity" not in record:
                raise TypeError(f"transfers[{index}].quantity is required")
            draft.transfer_asset_quantity(
                self._native_transaction_asset_id(
                    asset_id,
                    f"transfers[{index}].asset_id",
                ),
                record["quantity"],
                self._native_transaction_account_id(
                    destination,
                    f"transfers[{index}].destination",
                ),
            )
            count += 1
        if count == 0:
            raise ValueError("transfers must contain at least one transfer record")
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def register_zk_asset_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        asset_definition_id: str,
        vk_unshield: Optional[Union[str, Mapping[str, Any]]] = None,
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Register ZK policy metadata for an asset definition."""

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.register_zk_asset(
            asset_definition_id,
            vk_unshield=vk_unshield,
        )
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def verify_proof_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Mapping[str, Any],
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        proof: Mapping[str, Any],
        transaction_metadata: Optional[Mapping[str, Any]] = None,
        wait: bool = True,
        timeout: Optional[float] = 30.0,
        interval: float = 1.0,
    ) -> Mapping[str, Any]:
        """Submit a generic `zk::VerifyProof` instruction."""

        if not isinstance(proof, Mapping):
            raise TypeError("proof must be a mapping")
        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            metadata=transaction_metadata,
        )
        draft.verify_proof(dict(proof))
        return self._submit_transaction_draft_result(
            draft,
            private_key=private_key,
            private_key_hex=private_key_hex,
            wait=wait,
            timeout=timeout,
            interval=interval,
        )

    def find_account(
        self,
        account_id: str,
    ) -> Optional[Mapping[str, Any]]:
        """Fetch an account by exact id, returning ``None`` when it is absent."""

        literal = _require_non_empty_string(account_id, "account_id")
        response = self._get_dataspace_visible_response(
            f"/v1/accounts/{quote(literal, safe='')}",
        )
        if response.status_code == 404:
            return None
        if response.status_code == 200:
            payload = self._maybe_json(response)
            if not isinstance(payload, Mapping):
                raise RuntimeError("account endpoint returned non-object payload")
            return payload
        self._expect_status(response, {200, 404})
        return None

    def account_exists(
        self,
        account_id: str,
    ) -> bool:
        """Return whether Torii can see the account."""

        return self.find_account(account_id) is not None

    def asset_balance(
        self,
        account_id: str,
        asset_definition_id: str,
        *,
        scope: Optional[str] = None,
    ) -> Decimal:
        """Exact balance of one asset definition held by ``account_id``.

        ``asset_definition_id`` is a Base58 definition id or an on-chain alias
        (``name#domain.dataspace``; aliases always contain ``#``, Base58 ids never
        do). The quantities of every balance bucket (global and per-dataspace
        scopes) are summed across all pages; pass ``scope`` (``"global"`` or
        ``"dataspace:<id>"``) to read a single bucket. An account holding none
        returns ``Decimal(0)``; an unknown account raises ``ToriiNotFoundError``.
        """

        definition = _require_non_empty_string(
            asset_definition_id,
            "asset_definition_id",
        )
        by_alias = "#" in definition
        condition: Filter = F["asset_alias" if by_alias else "asset"] == definition
        if scope is not None:
            scope = _require_non_empty_string(scope, "scope")
            condition = condition & (F.scope == scope)
        total = Decimal(0)
        for bucket in self.accounts.assets(account_id).iter(filter=condition):
            selector = bucket.asset_alias if by_alias else bucket.asset
            if selector == definition and (scope is None or bucket.scope == scope):
                total += bucket.quantity
        return total

    def get_asset_definition(
        self,
        asset_definition_id: str,
    ) -> Optional[Mapping[str, Any]]:
        """Fetch an asset definition by id, returning ``None`` for 404."""

        definition = _require_non_empty_string(
            asset_definition_id,
            "asset_definition_id",
        )
        response = self._request(
            "GET",
            f"/v1/assets/definitions/{quote(definition, safe='')}",
        )
        if response.status_code == 404:
            return None
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, Mapping):
            raise RuntimeError("asset definition endpoint returned non-object payload")
        return payload

    def asset_definition_exists(self, asset_definition_id: str) -> bool:
        """Return whether Torii can resolve the asset definition."""

        return self.get_asset_definition(asset_definition_id) is not None

    def get_account_faucet_puzzle(self) -> Mapping[str, Any]:
        """Return the account-faucet proof-of-work puzzle."""

        payload = self.request_json(
            "GET",
            "/v1/accounts/faucet/puzzle",
            expected_status=(200,),
        )
        if not isinstance(payload, Mapping):
            raise RuntimeError("account faucet puzzle endpoint returned non-object payload")
        return payload

    @staticmethod
    def solve_account_faucet_pow(
        account_id: str,
        puzzle: Mapping[str, Any],
        *,
        max_nonce: int = 1_000_000,
    ) -> Tuple[int, str]:
        """Solve a Torii account-faucet proof-of-work puzzle."""

        from .crypto import NetworkId as ExactNetworkId

        if not isinstance(puzzle, Mapping):
            raise TypeError("account faucet puzzle must be an object")
        if set(puzzle) != ACCOUNT_FAUCET_PUZZLE_FIELDS_V1:
            raise TypeError("account faucet puzzle must contain exactly the V1 fields")
        if (
            isinstance(max_nonce, bool)
            or not isinstance(max_nonce, int)
            or not 0 < max_nonce <= 1 << 64
        ):
            raise ValueError("max_nonce must be a positive integer no greater than 2^64")
        algorithm = puzzle.get("algorithm")
        if algorithm != ACCOUNT_FAUCET_POW_ALGORITHM:
            raise ValueError(
                "account faucet puzzle algorithm must be "
                f"{ACCOUNT_FAUCET_POW_ALGORITHM}"
            )
        network_id_literal = puzzle.get("network_id")
        if not isinstance(network_id_literal, str):
            raise TypeError("account faucet puzzle network_id must be a string")
        network_id = ExactNetworkId.parse(network_id_literal)
        raw_chain_discriminant = puzzle.get("chain_discriminant")
        if isinstance(raw_chain_discriminant, bool) or not isinstance(
            raw_chain_discriminant, int
        ):
            raise AccountAddressError(
                "account faucet puzzle chain_discriminant must be an integer between "
                f"0 and {I105_DISCRIMINANT_MAX}"
            )
        chain_discriminant = normalize_i105_discriminant(
            raw_chain_discriminant,
            "account faucet puzzle chain_discriminant",
        )
        account = _normalize_exact_i105_account_id(
            account_id,
            "account_id",
            expected_discriminant=chain_discriminant,
        )
        difficulty_bits = puzzle.get("difficulty_bits")
        if isinstance(difficulty_bits, bool) or not isinstance(difficulty_bits, int):
            raise TypeError("account faucet puzzle difficulty_bits must be a JSON integer")
        if difficulty_bits <= 0:
            raise ValueError(
                "account faucet puzzle difficulty_bits must be greater than zero"
            )
        if difficulty_bits > 255:
            raise ValueError("account faucet puzzle difficulty_bits must fit an unsigned byte")
        anchor_height = puzzle.get("anchor_height")
        if isinstance(anchor_height, bool) or not isinstance(anchor_height, int):
            raise TypeError("account faucet puzzle anchor_height must be a JSON integer")
        if not 0 < anchor_height < 1 << 64:
            raise ValueError("account faucet puzzle anchor_height must be a positive u64")
        max_anchor_age = puzzle.get("max_anchor_age_blocks")
        if isinstance(max_anchor_age, bool) or not isinstance(max_anchor_age, int):
            raise TypeError(
                "account faucet puzzle max_anchor_age_blocks must be a JSON integer"
            )
        if not 0 < max_anchor_age < 1 << 64:
            raise ValueError(
                "account faucet puzzle max_anchor_age_blocks must be a positive u64"
            )
        anchor_hash_hex = puzzle.get("anchor_block_hash_hex")
        if not isinstance(anchor_hash_hex, str) or re.fullmatch(
            r"[0-9a-f]{64}", anchor_hash_hex
        ) is None:
            raise ValueError(
                "account faucet puzzle anchor_block_hash_hex must be exact lowercase 32-byte hex"
            )
        anchor_hash = bytes.fromhex(anchor_hash_hex)
        challenge_salt_hex = puzzle.get("challenge_salt_hex")
        if challenge_salt_hex is not None and (
            not isinstance(challenge_salt_hex, str)
            or re.fullmatch(r"[0-9a-f]{64}", challenge_salt_hex) is None
        ):
            raise ValueError(
                "account faucet puzzle challenge_salt_hex must be null or exact lowercase 32-byte hex"
            )
        challenge_salt = (
            bytes.fromhex(challenge_salt_hex) if challenge_salt_hex is not None else None
        )
        scrypt_values = {
            name: puzzle.get(name) for name in ("scrypt_log_n", "scrypt_r", "scrypt_p")
        }
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in scrypt_values.values()
        ):
            raise TypeError("account faucet scrypt parameters must be JSON integers")
        scrypt_log_n = scrypt_values["scrypt_log_n"]
        scrypt_r = scrypt_values["scrypt_r"]
        scrypt_p = scrypt_values["scrypt_p"]
        assert isinstance(scrypt_log_n, int)
        assert isinstance(scrypt_r, int)
        assert isinstance(scrypt_p, int)
        if not 1 <= scrypt_log_n <= 31 or not 1 <= scrypt_r < 1 << 32:
            raise ValueError("account faucet scrypt N and r parameters are out of range")
        if not 1 <= scrypt_p <= ACCOUNT_FAUCET_MAX_SCRYPT_PARALLELIZATION:
            raise ValueError("account faucet scrypt p parameter is out of range")
        scrypt_n = 1 << scrypt_log_n
        if 128 * scrypt_r * scrypt_n > ACCOUNT_FAUCET_MAX_SCRYPT_ROMIX_BYTES:
            raise ValueError("account faucet scrypt parameters exceed the 64 MiB ROMix bound")
        challenge = hashlib.sha256(
            b"".join(
                (
                    ACCOUNT_FAUCET_POW_DOMAIN_SEPARATOR,
                    network_id.to_bytes(),
                    account.encode("utf-8"),
                    anchor_height.to_bytes(8, "big"),
                    anchor_hash,
                    challenge_salt or b"",
                )
            )
        ).digest()
        for nonce in range(max_nonce):
            nonce_bytes = nonce.to_bytes(8, "big")
            digest = hashlib.scrypt(
                nonce_bytes,
                salt=challenge,
                n=scrypt_n,
                r=scrypt_r,
                p=scrypt_p,
                dklen=32,
            )
            if _leading_zero_bits(digest) >= difficulty_bits:
                return anchor_height, nonce_bytes.hex()
        raise RuntimeError(
            f"could not solve account faucet proof-of-work after {max_nonce} attempts"
        )

    def prepare_account_faucet_registration(
        self,
        account_id: str,
        *,
        binding: Mapping[str, Any],
        fee_payment: Mapping[str, Any],
        expected_asset_definition_id: str,
        expected_amount: str,
        expected_authority: str,
        network_id: "NetworkId",
        puzzle: Optional[Mapping[str, Any]] = None,
        max_nonce: int = 1_000_000,
    ) -> requests.Response:
        """Solve and prepare one faucet transaction under an independent exact policy."""

        exact_asset_definition_id, exact_amount = _copy_expected_faucet_policy_v1(
            expected_asset_definition_id,
            expected_amount,
            "prepare_account_faucet_registration.expected_policy",
        )
        expected_network_id = _normalize_network_id(
            network_id, "prepare_account_faucet_registration.network_id"
        )
        puzzle_payload = (
            self.get_account_faucet_puzzle() if puzzle is None else puzzle
        )
        if not isinstance(puzzle_payload, Mapping):
            raise TypeError("account faucet puzzle must be an object")
        if set(puzzle_payload) != ACCOUNT_FAUCET_PUZZLE_FIELDS_V1:
            raise TypeError("account faucet puzzle must contain exactly the V1 fields")
        if puzzle_payload.get("network_id") != expected_network_id.literal:
            raise ValueError(
                "prepare_account_faucet_registration puzzle network differs from the trust pin"
            )
        anchor_height, nonce_hex = self.solve_account_faucet_pow(
            account_id,
            puzzle_payload,
            max_nonce=max_nonce,
        )
        return self.prepare_account_faucet(
            account_id,
            binding=binding,
            fee_payment=fee_payment,
            expected_asset_definition_id=exact_asset_definition_id,
            expected_amount=exact_amount,
            expected_authority=expected_authority,
            network_id=expected_network_id,
            pow_anchor_height=anchor_height,
            pow_nonce_hex=nonce_hex,
        )

    def prepare_account_faucet(
        self,
        account_id: str,
        *,
        binding: Mapping[str, Any],
        fee_payment: Mapping[str, Any],
        expected_asset_definition_id: str,
        expected_amount: str,
        expected_authority: str,
        network_id: "NetworkId",
        pow_anchor_height: int,
        pow_nonce_hex: str,
    ) -> requests.Response:
        """Return one authenticated transaction matching an independent exact faucet policy."""

        exact_asset_definition_id, exact_amount = _copy_expected_faucet_policy_v1(
            expected_asset_definition_id,
            expected_amount,
            "prepare_account_faucet.expected_policy",
        )
        exact_binding = _copy_prepared_operation_binding(
            binding,
            expected_kind="faucet",
            context="prepare_account_faucet.binding",
            require_active=True,
        )
        exact_fee_payment = _copy_fee_payment_intent_v1(
            fee_payment,
            "prepare_account_faucet.fee_payment",
        )
        canonical_account_id = _normalize_exact_i105_account_id(
            account_id,
            "prepare_account_faucet.account_id",
            expected_discriminant=self._chain_discriminant,
        )
        canonical_authority = self._exact_account_identity_pin(
            expected_authority,
            "prepare_account_faucet.expected_authority",
        )
        expected_network_id = _normalize_network_id(network_id, "prepare_account_faucet.network_id")
        if (
            isinstance(pow_anchor_height, bool)
            or not isinstance(pow_anchor_height, int)
            or not 0 < pow_anchor_height < 1 << 64
        ):
            raise ValueError("pow_anchor_height must be a positive u64")
        if (
            not isinstance(pow_nonce_hex, str)
            or re.fullmatch(r"[0-9a-f]+", pow_nonce_hex) is None
            or len(pow_nonce_hex) % 2 != 0
            or not 2 <= len(pow_nonce_hex) <= 64
        ):
            raise ValueError("pow_nonce_hex must be 1..32 bytes of lowercase hex")
        claim = {
            "account_id": canonical_account_id,
            "pow_anchor_height": pow_anchor_height,
            "pow_nonce_hex": pow_nonce_hex,
        }
        response = self._request(
            "POST",
            "/v1/accounts/faucet/prepare",
            json_body={
                "schema": ACCOUNT_FAUCET_PREPARE_SCHEMA,
                "binding": exact_binding,
                "claim": claim,
                "fee_payment": exact_fee_payment,
            },
            allow_redirects=False,
        )
        if response.status_code == 200:
            try:
                payload = response.json()
            except ValueError as error:
                raise RuntimeError("prepare_account_faucet returned invalid JSON") from error
            prepared = _copy_prepared_transaction(
                payload,
                expected_operation="faucet",
                context="prepare_account_faucet.response",
            )
            if prepared["binding"] != exact_binding or prepared["claim"] != claim:
                raise ValueError("prepare_account_faucet response differs from the exact request")
            _require_same_fee_payer_and_gas_bound_v1(
                exact_fee_payment,
                prepared["fee_payment"],
                "prepare_account_faucet.response",
            )
            if prepared["account_id"] != canonical_account_id:
                raise ValueError(
                    "prepare_account_faucet response account differs from the exact claim"
                )
            _require_prepared_faucet_policy_v1(
                prepared,
                expected_asset_definition_id=exact_asset_definition_id,
                expected_amount=exact_amount,
                context="prepare_account_faucet.response",
            )
            _verify_prepared_transaction_authentication_v1(
                prepared,
                expected_authority=canonical_authority,
                network_id=expected_network_id,
                context="prepare_account_faucet.response",
            )
        return response

    def submit_prepared_account_faucet(
        self,
        prepared: Mapping[str, Any],
        *,
        expected_fee_payment: Mapping[str, Any],
        expected_asset_definition_id: str,
        expected_amount: str,
        expected_authority: str,
        network_id: "NetworkId",
    ) -> requests.Response:
        """Submit one authenticated transaction matching an independent exact faucet policy."""

        exact_asset_definition_id, exact_amount = _copy_expected_faucet_policy_v1(
            expected_asset_definition_id,
            expected_amount,
            "submit_prepared_account_faucet.expected_policy",
        )
        exact_prepared = _copy_prepared_transaction(
            prepared,
            expected_operation="faucet",
            context="submit_prepared_account_faucet.prepared",
        )
        _require_same_fee_payer_and_gas_bound_v1(
            expected_fee_payment,
            exact_prepared["fee_payment"],
            "submit_prepared_account_faucet.prepared",
        )
        _copy_prepared_operation_binding(
            exact_prepared["binding"],
            expected_kind="faucet",
            context="submit_prepared_account_faucet.prepared.binding",
            require_active=True,
        )
        _normalize_exact_i105_account_id(
            exact_prepared["account_id"],
            "submit_prepared_account_faucet.prepared.account_id",
            expected_discriminant=self._chain_discriminant,
        )
        _require_prepared_faucet_policy_v1(
            exact_prepared,
            expected_asset_definition_id=exact_asset_definition_id,
            expected_amount=exact_amount,
            context="submit_prepared_account_faucet.prepared",
        )
        canonical_authority = self._exact_account_identity_pin(
            expected_authority,
            "submit_prepared_account_faucet.expected_authority",
        )
        expected_network_id = _normalize_network_id(
            network_id, "submit_prepared_account_faucet.network_id"
        )
        _verify_prepared_transaction_authentication_v1(
            exact_prepared,
            expected_authority=canonical_authority,
            network_id=expected_network_id,
            context="submit_prepared_account_faucet.prepared",
        )
        response = self._request(
            "POST",
            "/v1/accounts/faucet",
            json_body=exact_prepared,
            allow_redirects=False,
        )
        _validate_prepared_submit_response_v1(
            response,
            expected_prepared=exact_prepared,
            context="submit_prepared_account_faucet.response",
        )
        return response

    def plan_account_onboarding(
        self,
        *,
        onboarding_token: str,
        alias: str,
        account_id: str,
        expected_authority: str,
        network_id: "NetworkId",
        permissions: Optional[Sequence[str]] = None,
    ) -> requests.Response:
        """Create one secret-free, signed semantic onboarding receipt."""

        exact_onboarding_token = _require_account_onboarding_token(onboarding_token)
        canonical_account_id = self._normalize_canonical_account_id(
            account_id,
            "plan_account_onboarding.account_id",
        )
        if "@" in canonical_account_id:
            raise ValueError(
                "plan_account_onboarding.account_id must be a canonical domainless I105 account id"
            )
        canonical_authority = self._exact_account_identity_pin(
            expected_authority,
            "plan_account_onboarding.expected_authority",
        )
        expected_network_id = _normalize_network_id(
            network_id, "plan_account_onboarding.network_id"
        )
        exact_alias = _require_exact_non_empty_string(alias, "plan_account_onboarding.alias")
        payload: Dict[str, Any] = {
            "version": 1,
            "alias": exact_alias,
            "account_id": canonical_account_id,
            "permissions": [],
        }
        if permissions is not None:
            if isinstance(permissions, (str, bytes, bytearray)):
                raise TypeError("plan_account_onboarding.permissions must be a sequence of strings")
            normalized_permissions: List[str] = []
            for index, permission in enumerate(permissions):
                normalized = _require_exact_non_empty_string(
                    permission,
                    f"plan_account_onboarding.permissions[{index}]",
                )
                if normalized not in normalized_permissions:
                    normalized_permissions.append(normalized)
            payload["permissions"] = sorted(normalized_permissions)
        payload = _copy_account_onboarding_request_v1(
            payload,
            "plan_account_onboarding.request",
        )
        response = self._request(
            "POST",
            "/v1/accounts/onboard/plan",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                ACCOUNT_ONBOARDING_TOKEN_HEADER: exact_onboarding_token,
            },
            json_body=payload,
            allow_retry=False,
            allow_redirects=False,
        )
        if response.status_code == 200:
            try:
                receipt = response.json()
            except ValueError as error:
                raise RuntimeError("plan_account_onboarding returned invalid JSON") from error
            _copy_account_onboarding_receipt_v1(
                receipt,
                expected_authority=canonical_authority,
                network_id=expected_network_id,
                expected_request=payload,
                context="plan_account_onboarding.response",
            )
        return response

    def prepare_account_onboarding(
        self,
        *,
        onboarding_token: str,
        binding: Mapping[str, Any],
        fee_payment: Mapping[str, Any],
        receipt: Mapping[str, Any],
        expected_request: Mapping[str, Any],
        expected_authority: str,
        network_id: "NetworkId",
    ) -> requests.Response:
        """Prepare an exact sponsored transaction from one signed semantic receipt."""

        exact_onboarding_token = _require_account_onboarding_token(onboarding_token)
        exact_binding = _copy_prepared_operation_binding(
            binding,
            expected_kind="onboarding",
            context="prepare_account_onboarding.binding",
            require_active=True,
        )
        exact_fee_payment = _copy_fee_payment_intent_v1(
            fee_payment,
            "prepare_account_onboarding.fee_payment",
        )
        canonical_authority = self._exact_account_identity_pin(
            expected_authority,
            "prepare_account_onboarding.expected_authority",
        )
        expected_network_id = _normalize_network_id(
            network_id, "prepare_account_onboarding.network_id"
        )
        exact_expected_request = _copy_account_onboarding_request_v1(
            expected_request,
            "prepare_account_onboarding.expected_request",
        )
        exact_receipt = _copy_account_onboarding_receipt_v1(
            receipt,
            expected_authority=canonical_authority,
            network_id=expected_network_id,
            expected_request=exact_expected_request,
            context="prepare_account_onboarding.receipt",
        )
        _require_onboarding_binding_receipt(exact_binding, exact_receipt, "prepare_account_onboarding")
        response = self._request(
            "POST",
            "/v1/accounts/onboard/prepare",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                ACCOUNT_ONBOARDING_TOKEN_HEADER: exact_onboarding_token,
            },
            json_body={
                "schema": ACCOUNT_ONBOARDING_PREPARE_SCHEMA,
                "binding": exact_binding,
                "receipt": exact_receipt,
                "fee_payment": exact_fee_payment,
            },
            allow_retry=False,
            allow_redirects=False,
        )
        if response.status_code == 200:
            try:
                payload = response.json()
            except ValueError as error:
                raise RuntimeError("prepare_account_onboarding returned invalid JSON") from error
            schema = payload.get("schema") if isinstance(payload, Mapping) else None
            if schema == PREPARED_TRANSACTION_SCHEMA:
                prepared = _copy_prepared_transaction(
                    payload,
                    expected_operation="onboarding",
                    context="prepare_account_onboarding.response",
                )
                if prepared["binding"] != exact_binding or prepared["receipt"] != exact_receipt:
                    raise ValueError(
                        "prepare_account_onboarding response differs from the exact request"
                    )
                _require_same_fee_payer_and_gas_bound_v1(
                    exact_fee_payment,
                    prepared["fee_payment"],
                    "prepare_account_onboarding.response",
                )
                body = _require_mapping(
                    exact_receipt["body"], "prepare_account_onboarding.receipt.body"
                )
                request = _require_mapping(
                    body["request"], "prepare_account_onboarding.receipt.body.request"
                )
                if (
                    prepared["semantic_hash_hex"]
                    != _canonical_receipt_plan_hash_hex(
                        exact_receipt, "prepare_account_onboarding.receipt"
                    )
                    or prepared["account_id"] != request["account_id"]
                    or prepared["alias"] != request["alias"]
                ):
                    raise ValueError(
                        "prepare_account_onboarding response differs from the receipt intent"
                    )
                resource = _require_mapping(
                    body["resource"], "prepare_account_onboarding.receipt.body.resource"
                )
                planned_disposition = _prepared_disposition_text(
                    resource.get("disposition"),
                    "prepare_account_onboarding.receipt.body.resource.disposition",
                )
                prepared_disposition = _prepared_disposition_text(
                    prepared["disposition"],
                    "prepare_account_onboarding.response.disposition",
                )
                allowed_transitions = {
                    "create": {"create", "repair", "no_op"},
                    "repair": {"repair", "no_op"},
                    "no_op": {"no_op"},
                }
                if prepared_disposition not in allowed_transitions.get(planned_disposition, set()):
                    raise ValueError(
                        "prepare_account_onboarding disposition is not a valid live transition"
                    )
                _verify_prepared_transaction_authentication_v1(
                    prepared,
                    expected_authority=canonical_authority,
                    network_id=expected_network_id,
                    context="prepare_account_onboarding.response",
                )
            elif schema == ACCOUNT_ONBOARDING_PROOF_REQUIRED_SCHEMA:
                _copy_account_onboarding_proof_required_v1(
                    payload,
                    expected_binding=exact_binding,
                    expected_receipt=exact_receipt,
                    expected_authority=canonical_authority,
                    context="prepare_account_onboarding.response",
                )
            else:
                raise ValueError(
                    "prepare_account_onboarding response schema is not a closed V1 result"
                )
        return response

    def prove_account_onboarding_current_state(
        self,
        *,
        proof_required: Mapping[str, Any],
        binding: Mapping[str, Any],
        receipt: Mapping[str, Any],
        expected_request: Mapping[str, Any],
        expected_authority: str,
        network_id: "NetworkId",
        canonical_auth: ToriiCanonicalRequestAuth,
    ) -> AccountOnboardingCurrentStateV1:
        """Classify one atomic snapshot for a nonterminal ProofRequired result.

        This method always performs exactly one Torii POST. Its result is
        deliberately not a persistable terminal receipt; a caller resuming
        from durable state must invoke it again.
        """

        exact_binding = _copy_prepared_operation_binding(
            binding,
            expected_kind="onboarding",
            context="prove_account_onboarding_current_state.binding",
            require_active=False,
        )
        canonical_authority = self._exact_account_identity_pin(
            expected_authority,
            "prove_account_onboarding_current_state.expected_authority",
        )
        expected_network_id = _normalize_network_id(
            network_id,
            "prove_account_onboarding_current_state.network_id",
        )
        exact_canonical_auth = self._require_canonical_auth(
            canonical_auth,
            "prove_account_onboarding_current_state",
        )
        self._require_exact_i105_account_id(
            exact_canonical_auth.account_id,
            "prove_account_onboarding_current_state.canonical_auth.account_id",
        )
        if not hmac.compare_digest(
            exact_canonical_auth.network_id,
            expected_network_id.literal,
        ):
            raise ValueError(
                "prove_account_onboarding_current_state.canonical_auth.network_id "
                "must match network_id"
            )
        exact_expected_request = _copy_account_onboarding_request_v1(
            expected_request,
            "prove_account_onboarding_current_state.expected_request",
        )
        exact_receipt = _copy_account_onboarding_receipt_v1(
            receipt,
            expected_authority=canonical_authority,
            network_id=expected_network_id,
            expected_request=exact_expected_request,
            context="prove_account_onboarding_current_state.receipt",
        )
        _require_onboarding_binding_receipt(exact_binding, exact_receipt, "prove_account_onboarding_current_state")
        exact_proof_required = _copy_account_onboarding_proof_required_v1(
            proof_required,
            expected_binding=exact_binding,
            expected_receipt=exact_receipt,
            expected_authority=canonical_authority,
            context="prove_account_onboarding_current_state.proof_required",
        )
        expected_account_id = str(exact_proof_required["account_id"])
        expected_alias = str(exact_proof_required["alias"])
        current_state_path = "/v1/accounts/onboarding/current-state"
        _require_one_shot_transport(
            self._session,
            f"{self._base_url}{current_state_path}",
            "prove_account_onboarding_current_state",
        )
        current_state_body = self._encode_json_body(
            {
                "version": 1,
                "account_id": expected_account_id,
                "alias": expected_alias,
            }
        )
        current_state_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Cache-Control": "no-cache",
            **build_canonical_request_headers(
                network_id=exact_canonical_auth.network_id,
                account_id=exact_canonical_auth.account_id,
                signer=exact_canonical_auth.signer,
                method="POST",
                path=current_state_path,
                body=current_state_body,
                timestamp_ms=exact_canonical_auth.timestamp_ms,
                nonce=exact_canonical_auth.nonce,
            ),
        }

        response = self._request(
            "POST",
            current_state_path,
            headers=current_state_headers,
            data=current_state_body,
            allow_retry=False,
            allow_redirects=False,
        )
        self._expect_status(response, {200})
        response_context = "prove_account_onboarding_current_state.response"
        payload = _require_mapping(
            decode_exact_json_bytes(
                response.content,
                response_context,
                maximum_bytes=ACCOUNT_ONBOARDING_CURRENT_STATE_RESPONSE_MAX_BYTES,
            ),
            response_context,
        )
        if set(payload) != {
            "version",
            "network_id",
            "account_id",
            "alias",
            "account_exists",
            "alias_target_account_id",
            "observed_block_height",
            "observed_block_hash",
        }:
            raise TypeError(f"{response_context} must contain exactly the V1 fields")
        version = payload.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version != 1:
            raise ValueError(f"{response_context}.version must be exactly 1")
        if payload.get("network_id") != expected_network_id.literal:
            raise ValueError(f"{response_context}.network_id differs from the trust pin")
        if payload.get("account_id") != expected_account_id:
            raise ValueError(f"{response_context}.account_id differs from the exact request")
        if payload.get("alias") != expected_alias:
            raise ValueError(f"{response_context}.alias differs from the exact request")
        if payload.get("account_exists") is not True:
            raise ValueError(f"{response_context} reports the expected account absent")
        observed_block_height = payload.get("observed_block_height")
        if (
            isinstance(observed_block_height, bool)
            or not isinstance(observed_block_height, int)
            or not 0 < observed_block_height < 1 << 64
        ):
            raise ValueError(f"{response_context}.observed_block_height must be a positive u64")
        observed_block_hash = _strict_hash_literal(
            payload,
            "observed_block_hash",
            response_context,
        )
        target_value = payload.get("alias_target_account_id")
        if target_value is None:
            kind: Literal["Applied", "AliasAbsent", "AliasConflict"] = "AliasAbsent"
            return AccountOnboardingCurrentStateV1(
                kind=kind,
                block_height=observed_block_height,
                block_hash=observed_block_hash,
            )
        target_context = f"{response_context}.alias_target_account_id"
        resolved_account_id = _require_exact_non_empty_string(target_value, target_context)
        if "@" in resolved_account_id:
            raise ValueError(f"{target_context} must be an exact canonical I105 account id")
        try:
            resolved_address = AccountAddress.parse_encoded(resolved_account_id)
            expected_address = AccountAddress.parse_encoded(expected_account_id)
        except AccountAddressError as exc:
            raise ValueError(
                f"{target_context} must be an exact canonical I105 account id"
            ) from exc
        kind = (
            "Applied"
            if resolved_address.canonical_bytes() == expected_address.canonical_bytes()
            else "AliasConflict"
        )
        return AccountOnboardingCurrentStateV1(
            kind=kind,
            block_height=observed_block_height,
            block_hash=observed_block_hash,
        )

    def submit_prepared_account_onboarding(
        self,
        *,
        onboarding_token: str,
        prepared: Mapping[str, Any],
        expected_fee_payment: Mapping[str, Any],
        expected_request: Mapping[str, Any],
        expected_authority: str,
        network_id: "NetworkId",
    ) -> requests.Response:
        """Submit only one server-authenticated exact onboarding transaction."""

        exact_onboarding_token = _require_account_onboarding_token(onboarding_token)
        exact_prepared = _copy_prepared_transaction(
            prepared,
            expected_operation="onboarding",
            context="submit_prepared_account_onboarding.prepared",
        )
        _require_same_fee_payer_and_gas_bound_v1(
            expected_fee_payment,
            exact_prepared["fee_payment"],
            "submit_prepared_account_onboarding.prepared",
        )
        _copy_prepared_operation_binding(
            exact_prepared["binding"],
            expected_kind="onboarding",
            context="submit_prepared_account_onboarding.prepared.binding",
            require_active=True,
        )
        _normalize_exact_i105_account_id(
            exact_prepared["account_id"],
            "submit_prepared_account_onboarding.prepared.account_id",
            expected_discriminant=self._chain_discriminant,
        )
        canonical_authority = self._exact_account_identity_pin(
            expected_authority,
            "submit_prepared_account_onboarding.expected_authority",
        )
        expected_network_id = _normalize_network_id(
            network_id, "submit_prepared_account_onboarding.network_id"
        )
        exact_expected_request = _copy_account_onboarding_request_v1(
            expected_request,
            "submit_prepared_account_onboarding.expected_request",
        )
        exact_receipt = _copy_account_onboarding_receipt_v1(
            exact_prepared["receipt"],
            expected_authority=canonical_authority,
            network_id=expected_network_id,
            expected_request=exact_expected_request,
            context="submit_prepared_account_onboarding.prepared.receipt",
        )
        if exact_receipt != exact_prepared["receipt"]:
            raise ValueError("submit_prepared_account_onboarding receipt is not exact")
        if exact_prepared["semantic_hash_hex"] != _canonical_receipt_plan_hash_hex(
            exact_receipt,
            "submit_prepared_account_onboarding.prepared.receipt",
        ):
            raise ValueError(
                "submit_prepared_account_onboarding semantic hash differs from the receipt"
            )
        if (
            exact_expected_request["account_id"] != exact_prepared["account_id"]
            or exact_expected_request["alias"] != exact_prepared["alias"]
        ):
            raise ValueError(
                "submit_prepared_account_onboarding intent differs from the receipt"
            )
        _verify_prepared_transaction_authentication_v1(
            exact_prepared,
            expected_authority=canonical_authority,
            network_id=expected_network_id,
            context="submit_prepared_account_onboarding.prepared",
        )
        response = self._request(
            "POST",
            "/v1/accounts/onboard",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                ACCOUNT_ONBOARDING_TOKEN_HEADER: exact_onboarding_token,
            },
            json_body=exact_prepared,
            allow_retry=False,
            allow_redirects=False,
        )
        _validate_prepared_submit_response_v1(
            response,
            expected_prepared=exact_prepared,
            context="submit_prepared_account_onboarding.response",
        )
        return response

    def find_domain(self, domain_id: str) -> Optional[Domain]:
        """The domain with exactly this id, or ``None`` (one ``domains`` query)."""

        resolved_domain_id = _require_non_empty_string(domain_id, "domain_id")
        page = self.domains.list(filter=F.id == resolved_domain_id, limit=1)
        return page.items[0] if page.items else None

    def domain_exists(self, domain_id: str) -> bool:
        """Return whether Torii can resolve a domain."""

        return self.find_domain(domain_id) is not None

    def request_sns_name(self, namespace: str, literal: str) -> requests.Response:
        """Fetch an SNS name registration and return the raw response."""

        return self._request(
            "GET",
            "/v1/sns/names/"
            f"{quote(_require_non_empty_string(namespace, 'namespace'), safe='')}/"
            f"{quote(_require_non_empty_string(literal, 'literal'), safe='')}",
        )

    def get_sns_name(self, namespace: str, literal: str) -> Optional[Mapping[str, Any]]:
        """Fetch an SNS name registration, returning ``None`` on 404."""

        response = self.request_sns_name(namespace, literal)
        if response.status_code == 404:
            return None
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, Mapping):
            raise RuntimeError("SNS name endpoint returned non-object payload")
        return payload

    def get_sns_policy(self, suffix_id: int) -> Mapping[str, Any]:
        """Fetch the SNS suffix policy."""

        payload = self.request_json(
            "GET",
            f"/v1/sns/policies/{int(suffix_id)}",
            expected_status=(200,),
        )
        if not isinstance(payload, Mapping):
            raise RuntimeError("SNS policy endpoint returned non-object payload")
        return payload

    def request_zk_verifying_key(self, backend: str, name: str) -> requests.Response:
        """Fetch a ZK verifying-key registry entry and return the raw response."""

        return self._request(
            "GET",
            "/v1/zk/vk/"
            f"{quote(_require_production_verify_backend_label(backend, 'backend'), safe='')}/"
            f"{quote(_require_exact_non_empty_string(name, 'name'), safe='')}",
        )

    def get_zk_verifying_key(self, backend: str, name: str) -> Optional[Mapping[str, Any]]:
        """Fetch a ZK verifying-key registry entry, returning ``None`` on 404."""

        response = self.request_zk_verifying_key(backend, name)
        if response.status_code == 404:
            return None
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, Mapping):
            raise RuntimeError("ZK verifying-key endpoint returned non-object payload")
        return payload

    def zk_verifying_key_active(self, backend: str, name: str) -> bool:
        """Return whether a ZK verifying key exists and is active."""

        payload = self.get_zk_verifying_key(backend, name)
        if payload is None:
            return False
        record = payload.get("record") if isinstance(payload, Mapping) else None
        return isinstance(record, Mapping) and record.get("status") == "Active"

    def submit_zk_verifying_key_registration(
        self,
        payload: Mapping[str, Any],
    ) -> requests.Response:
        """Send the low-level unsigned registration-draft request."""

        request = _normalize_zk_verifying_key_registration_payload(payload)
        self._require_local_signing_context("submit_zk_verifying_key_registration")
        return self._request(
            "POST",
            "/v1/zk/vk/register",
            json_body=request,
            timeout=60.0,
        )

    def register_zk_verifying_key(
        self,
        payload: Mapping[str, Any],
    ) -> ZkVerifyingKeyTransactionDraft:
        """Prepare a ZK verifying-key registration transaction for local signing."""

        request = _normalize_zk_verifying_key_registration_payload(payload)
        request["authority"] = _normalize_exact_i105_account_id(
            request["authority"],
            "register_zk_verifying_key.authority",
            expected_discriminant=self._chain_discriminant,
        )
        signing_context = self._require_local_signing_context("register_zk_verifying_key")
        response = self._request(
            "POST",
            "/v1/zk/vk/register",
            json_body=request,
            timeout=60.0,
        )
        self._expect_status(response, {200})
        return _normalize_zk_verifying_key_transaction_draft(
            self._maybe_json(response),
            "register_zk_verifying_key response",
            network_id=signing_context.network_id,
            operation="register",
            request=request,
        )

    def submit_zk_verifying_key_update(
        self,
        payload: Mapping[str, Any],
    ) -> requests.Response:
        """Send the low-level unsigned update-draft request."""

        request = _normalize_zk_verifying_key_update_payload(payload)
        self._require_local_signing_context("submit_zk_verifying_key_update")
        return self._request(
            "POST",
            "/v1/zk/vk/update",
            json_body=request,
            timeout=60.0,
        )

    def update_zk_verifying_key(
        self,
        payload: Mapping[str, Any],
    ) -> ZkVerifyingKeyTransactionDraft:
        """Prepare a ZK verifying-key update transaction for local signing."""

        request = _normalize_zk_verifying_key_update_payload(payload)
        request["authority"] = _normalize_exact_i105_account_id(
            request["authority"],
            "update_zk_verifying_key.authority",
            expected_discriminant=self._chain_discriminant,
        )
        signing_context = self._require_local_signing_context("update_zk_verifying_key")
        response = self._request(
            "POST",
            "/v1/zk/vk/update",
            json_body=request,
            timeout=60.0,
        )
        self._expect_status(response, {200})
        return _normalize_zk_verifying_key_transaction_draft(
            self._maybe_json(response),
            "update_zk_verifying_key response",
            network_id=signing_context.network_id,
            operation="update",
            request=request,
        )

    def account_has_permission(
        self,
        account_id: str,
        permission_name: str,
        *,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Find an effective direct or role-granted permission, following every page."""

        expected_payload_value = (
            _json_safe_value(dict(expected_payload)) if expected_payload is not None else None
        )
        permissions = self.accounts.permissions(account_id).iter(filter=F.name == permission_name)
        for row in permissions:
            permission = AccountPermissionRecord.from_payload(row)
            if permission.name != permission_name:
                continue
            if expected_payload is None or permission.payload == expected_payload_value:
                return True
        return False

    # ------------------------------------------------------------------
    # Asset transfer controls and account permissions
    # (collection reads live on ``client.<collection>``; see collection.py)
    # ------------------------------------------------------------------
    def get_asset_transfer_control(
        self,
        account_id: str,
        asset_definition_id: str,
    ) -> Dict[str, Any]:
        """Read native transfer-control state for one account and asset definition."""

        body = {
            "account_id": self._normalize_canonical_account_id(
                account_id,
                "account_id",
            ),
            "asset_definition_id": _require_non_empty_string(
                asset_definition_id,
                "asset_definition_id",
            ),
        }
        response = self._request(
            "POST",
            "/v1/controls/asset-transfer/query",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self._expect_status(response, {200})
        payload = self._maybe_json(response)
        if not isinstance(payload, dict):
            raise RuntimeError("unexpected asset transfer control response")
        return payload

    # ------------------------------------------------------------------
    # Contracts API
    # ------------------------------------------------------------------
    @staticmethod
    def _contract_response_payload(response: Any) -> Any:
        if is_dataclass(response) and not isinstance(response, type):
            return asdict(response)
        return _json_safe_value(response)

    @staticmethod
    def _contract_response_tx_hashes(response: Any) -> List[str]:
        payload = ToriiClient._contract_response_payload(response)
        hashes: List[str] = []

        def visit(value: Any) -> None:
            if isinstance(value, Mapping):
                if "tx_hash_hex" in value and value["tx_hash_hex"] is not None:
                    candidate = _require_exact_pipeline_transaction_hash(
                        value["tx_hash_hex"],
                        "contract response.tx_hash_hex",
                    )
                    if hashes and candidate != hashes[0]:
                        raise ValueError(
                            "contract response contains conflicting transaction hashes"
                        )
                    hashes.append(candidate)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(payload)
        return list(dict.fromkeys(hashes))

    @staticmethod
    def _contract_response_pipeline_statuses(response: Any) -> List[Mapping[str, Any]]:
        payload = ToriiClient._contract_response_payload(response)
        statuses: List[Mapping[str, Any]] = []

        def visit(value: Any) -> None:
            if isinstance(value, Mapping):
                if "pipeline_status" in value and value["pipeline_status"] is not None:
                    candidate = value["pipeline_status"]
                    if not isinstance(candidate, Mapping):
                        raise TypeError(
                            "contract response.pipeline_status must be an object"
                        )
                    if candidate not in statuses:
                        statuses.append(candidate)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(payload)
        return statuses

    def _wait_for_contract_response(
        self,
        response: Any,
        *,
        timeout_ms: Optional[int],
        interval: float,
    ) -> Dict[str, Any]:
        submit_payload = self._contract_response_payload(response)
        tx_hashes = self._contract_response_tx_hashes(response)
        if not tx_hashes:
            raise ValueError(
                "contract response must contain an exact canonical tx_hash_hex"
            )
        embedded_statuses = self._contract_response_pipeline_statuses(response)
        embedded_by_hash: Dict[str, Mapping[str, Any]] = {}
        for status_payload in embedded_statuses:
            status_hash = _require_exact_pipeline_transaction_hash(
                status_payload.get("hash"),
                "contract response.pipeline_status.hash",
            )
            if status_hash not in tx_hashes:
                raise ValueError(
                    "contract response pipeline status hash does not match tx_hash_hex"
                )
            if status_hash in embedded_by_hash:
                raise ValueError(
                    "contract response contains duplicate pipeline status bindings"
                )
            embedded_by_hash[status_hash] = status_payload
        final_payloads: List[Any] = []
        for tx_hash in tx_hashes:
            embedded_status = embedded_by_hash.get(tx_hash)
            if embedded_status is not None:
                normalized_status = _normalize_public_pipeline_status(
                    embedded_status,
                    tx_hash,
                )
                embedded_kind = _extract_pipeline_status_kind(normalized_status)
                authoritative_kind = (
                    embedded_kind
                    if normalized_status["scope"] == "global"
                    and normalized_status["resolved_from"] == "state"
                    else None
                )
                if authoritative_kind == "Applied":
                    final_payloads.append(normalized_status)
                    continue
                if authoritative_kind in {"Rejected", "Expired"}:
                    raise TransactionStatusError(
                        tx_hash,
                        authoritative_kind,
                        normalized_status,
                    )
            final_payloads.append(
                self.wait_for_transaction_status(
                    tx_hash,
                    interval=interval,
                    timeout=None if timeout_ms is None else timeout_ms / 1000.0,
                )
            )
        final_payload: Any
        if not final_payloads:
            final_payload = None
        elif len(final_payloads) == 1:
            final_payload = final_payloads[0]
        else:
            final_payload = {"items": final_payloads}
        return {
            "submit": submit_payload,
            "tx_hashes": tx_hashes,
            "terminal_kind": _extract_pipeline_status_kind(final_payload),
            "r#final": final_payload,
        }

    @staticmethod
    def _canonical_contract_batch_base64(value: Any, context: str) -> bytes:
        if not isinstance(value, str) or not value:
            raise TypeError(f"{context} must be a non-empty base64 string")
        try:
            encoded = value.encode("ascii")
            decoded = base64.b64decode(encoded, validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as error:
            raise ValueError(f"{context} must be canonical padded base64") from error
        if base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError(f"{context} must be canonical padded base64")
        return decoded

    def prepare_contract_call_batch(
        self,
        entries: Sequence[Any],
    ) -> _ContractCallBatchPlan:
        """Resolve and ABI-bind an exact ordered executable batch."""

        if isinstance(entries, (str, bytes, bytearray, memoryview)) or not isinstance(
            entries,
            Sequence,
        ):
            raise TypeError("entries must be a sequence")
        if not entries:
            raise ValueError("entries must not be empty")
        if len(entries) > _CONTRACT_CALL_BATCH_MAX_ITEMS:
            raise ValueError("entries must contain at most 256 items")

        from .crypto import Instruction

        normalized: List[Dict[str, Any]] = []
        for index, entry in enumerate(entries):
            if isinstance(entry, ContractCallIntent):
                normalized.append({"contract_call": entry.to_payload()})
            elif isinstance(entry, Instruction):
                instruction = bytes(entry.to_norito_bytes())
                normalized.append(
                    {
                        "instruction_b64": base64.b64encode(instruction).decode(
                            "ascii"
                        )
                    }
                )
            elif isinstance(entry, Mapping) and set(entry) == {"contract_call"}:
                intent = entry["contract_call"]
                if not isinstance(intent, Mapping):
                    raise TypeError(
                        f"entries[{index}].contract_call must be a mapping"
                    )
                normalized.append({"contract_call": dict(intent)})
            elif isinstance(entry, Mapping) and set(entry) == {"instruction_b64"}:
                encoded = entry["instruction_b64"]
                self._canonical_contract_batch_base64(
                    encoded,
                    f"entries[{index}].instruction_b64",
                )
                normalized.append({"instruction_b64": encoded})
            else:
                raise TypeError(
                    f"entries[{index}] must be a ContractCallIntent, "
                    "Instruction, or strict preparation item"
                )

        response = self._request(
            "POST",
            "/v1/contracts/call/batch/prepare",
            data=json.dumps(
                {"entries": normalized},
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        self._expect_status(response, {200})
        body = self._maybe_json(response)
        if not isinstance(body, Mapping) or body.get("ok") is not True:
            raise RuntimeError("contract batch preparation returned an invalid plan")
        if set(body) != {
            "ok",
            "binding",
            "binding_digest_hex",
            "prepared_entries",
        }:
            raise RuntimeError("contract batch plan contains unsupported fields")

        binding_payload = body.get("binding")
        prepared_payload = body.get("prepared_entries")
        if not isinstance(binding_payload, Mapping):
            raise RuntimeError("contract batch plan binding must be an object")
        binding = dict(binding_payload)
        if set(binding) != {"version", "items"} or binding.get("version") != 1:
            raise RuntimeError("contract batch plan binding must use version 1")
        binding_items = binding.get("items")
        if not isinstance(binding_items, list) or not isinstance(
            prepared_payload,
            list,
        ):
            raise RuntimeError("contract batch plan entries must be arrays")
        if (
            len(binding_items) != len(normalized)
            or len(prepared_payload) != len(normalized)
        ):
            raise RuntimeError("contract batch plan changed the entry count")

        binding_digest_hex = body.get("binding_digest_hex")
        if (
            not isinstance(binding_digest_hex, str)
            or re.fullmatch(r"[0-9a-f]{64}", binding_digest_hex) is None
        ):
            raise RuntimeError("contract batch binding digest is not canonical")
        canonical_binding = json.dumps(
            binding,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        expected_binding_digest = blake3(
            _CONTRACT_CALL_BATCH_BINDING_DOMAIN_V1 + canonical_binding
        ).hexdigest()
        if binding_digest_hex != expected_binding_digest:
            raise RuntimeError("contract batch binding digest does not match its plan")

        prepared_entries: List[_PreparedContractCallBatchItem] = []
        for index, (binding_item, prepared_item, requested) in enumerate(
            zip(binding_items, prepared_payload, normalized, strict=True)
        ):
            if not isinstance(binding_item, Mapping) or not isinstance(
                prepared_item,
                Mapping,
            ):
                raise RuntimeError(f"contract batch item {index} must be an object")
            if (
                binding_item.get("index") != index
                or prepared_item.get("index") != index
                or binding_item.get("kind") != prepared_item.get("kind")
            ):
                raise RuntimeError(f"contract batch item {index} changed order or kind")
            kind = binding_item.get("kind")
            if kind == "contract_call":
                requested_call = requested.get("contract_call")
                if not isinstance(requested_call, Mapping):
                    raise RuntimeError(f"contract batch item {index} changed kind")
                address = binding_item.get("contract_address")
                code_hash = binding_item.get("code_hash_hex")
                abi_hash = binding_item.get("abi_hash_hex")
                entrypoint = binding_item.get("entrypoint")
                for value, name in (
                    (address, "contract_address"),
                    (entrypoint, "entrypoint"),
                ):
                    if not isinstance(value, str) or not value:
                        raise RuntimeError(
                            f"contract batch item {index} omitted {name}"
                        )
                for value, name in (
                    (code_hash, "code_hash_hex"),
                    (abi_hash, "abi_hash_hex"),
                ):
                    if (
                        not isinstance(value, str)
                        or re.fullmatch(r"[0-9a-f]{64}", value) is None
                    ):
                        raise RuntimeError(
                            f"contract batch item {index} has invalid {name}"
                        )
                if prepared_item.get("contract_address") != address:
                    raise RuntimeError(f"contract batch item {index} changed address")
                if (
                    prepared_item.get("code_hash_hex") != code_hash
                    or prepared_item.get("abi_hash_hex") != abi_hash
                    or prepared_item.get("entrypoint") != entrypoint
                ):
                    raise RuntimeError(f"contract batch item {index} changed call identity")
                if requested_call.get("entrypoint") != entrypoint:
                    raise RuntimeError(f"contract batch item {index} changed entrypoint")
                requested_address = requested_call.get("contract_address")
                expected_address = requested_call.get("expected_contract_address")
                if requested_address is not None and requested_address != address:
                    raise RuntimeError(f"contract batch item {index} changed address")
                if expected_address is not None and expected_address != address:
                    raise RuntimeError(
                        f"contract batch item {index} violated address pin"
                    )
                if binding_item.get("contract_alias") != requested_call.get(
                    "contract_alias"
                ):
                    raise RuntimeError(f"contract batch item {index} changed alias")
                for requested_field, actual in (
                    ("expected_code_hash_hex", code_hash),
                    ("expected_abi_hash_hex", abi_hash),
                ):
                    pin = requested_call.get(requested_field)
                    if pin is not None and pin != actual:
                        raise RuntimeError(
                            f"contract batch item {index} violated {requested_field}"
                        )
                arguments_b64 = prepared_item.get("arguments_b64")
                if arguments_b64 is None:
                    arguments = None
                    arguments_digest = blake3(
                        _CONTRACT_CALL_BATCH_ARGUMENTS_DOMAIN_V1 + b"\x00"
                    ).hexdigest()
                else:
                    arguments = self._canonical_contract_batch_base64(
                        arguments_b64,
                        f"prepared_entries[{index}].arguments_b64",
                    )
                    arguments_digest = blake3(
                        _CONTRACT_CALL_BATCH_ARGUMENTS_DOMAIN_V1
                        + b"\x01"
                        + arguments
                    ).hexdigest()
                if binding_item.get("arguments_digest_hex") != arguments_digest:
                    raise RuntimeError(
                        f"contract batch item {index} arguments digest mismatch"
                    )
                prepared_entries.append(
                    _PreparedContractCallBatchItem(
                        index=index,
                        kind="contract_call",
                        contract_address=address,
                        code_hash_hex=code_hash,
                        abi_hash_hex=abi_hash,
                        entrypoint=entrypoint,
                        arguments=arguments,
                    )
                )
            elif kind == "instruction":
                requested_b64 = requested.get("instruction_b64")
                prepared_b64 = prepared_item.get("instruction_b64")
                if requested_b64 != prepared_b64:
                    raise RuntimeError(
                        f"contract batch item {index} changed instruction bytes"
                    )
                instruction = self._canonical_contract_batch_base64(
                    prepared_b64,
                    f"prepared_entries[{index}].instruction_b64",
                )
                wire_id = binding_item.get("wire_id")
                if (
                    not isinstance(wire_id, str)
                    or not wire_id
                    or prepared_item.get("wire_id") != wire_id
                ):
                    raise RuntimeError(
                        f"contract batch item {index} changed instruction identity"
                    )
                instruction_digest = blake3(
                    _CONTRACT_CALL_BATCH_INSTRUCTION_DOMAIN_V1 + instruction
                ).hexdigest()
                if binding_item.get("instruction_digest_hex") != instruction_digest:
                    raise RuntimeError(
                        f"contract batch item {index} instruction digest mismatch"
                    )
                prepared_entries.append(
                    _PreparedContractCallBatchItem(
                        index=index,
                        kind="instruction",
                        wire_id=wire_id,
                        instruction=instruction,
                    )
                )
            else:
                raise RuntimeError(f"contract batch item {index} has unknown kind")

        return _ContractCallBatchPlan(
            binding=binding,
            binding_digest_hex=binding_digest_hex,
            prepared_entries=tuple(prepared_entries),
        )

    def call_contract_batch_and_wait(
        self,
        *,
        authority: str,
        entries: Sequence[Any],
        fee_payment: Optional[Mapping[str, Any]] = None,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        creation_time_ms: Optional[int] = None,
        ttl_ms: Optional[int] = 900_000,
        wait: bool = True,
        interval: float = 1.0,
        timeout: Optional[float] = 120.0,
    ) -> Mapping[str, Any]:
        """Prepare, locally sign, and submit one ordered atomic batch.

        The draft fixes ``creation_time_ms`` before signing, using the local
        clock once when omitted.
        """

        if (private_key is None) == (private_key_hex is None):
            raise ValueError("provide exactly one of private_key or private_key_hex")
        plan = self.prepare_contract_call_batch(entries)
        signed_metadata = _normalize_contract_call_metadata(
            metadata,
            context="metadata",
        )
        signed_metadata["contract_batch_binding_v1"] = {
            "binding": plan.binding,
            "binding_digest_hex": plan.binding_digest_hex,
        }

        from .crypto import Instruction

        draft = self._transaction_draft(
            authority=authority,
            fee_payment=fee_payment,
            creation_time_ms=creation_time_ms,
            ttl_ms=ttl_ms,
            metadata=signed_metadata,
        ).use_executable_batch()
        original_instructions: Dict[int, Any] = {
            index: entry
            for index, entry in enumerate(entries)
            if isinstance(entry, Instruction)
        }
        for index, prepared in enumerate(plan.prepared_entries):
            if prepared.kind == "contract_call":
                if (
                    prepared.contract_address is None
                    or prepared.code_hash_hex is None
                    or prepared.entrypoint is None
                ):
                    raise RuntimeError(f"prepared contract call {index} is incomplete")
                draft.add_contract_call(
                    prepared.contract_address,
                    prepared.code_hash_hex,
                    prepared.entrypoint,
                    prepared.arguments,
                )
            elif prepared.kind == "instruction":
                instruction = original_instructions.get(index)
                if instruction is None:
                    raise RuntimeError(
                        f"prepared native instruction {index} has no local source"
                    )
                if (
                    bytes(instruction.to_norito_bytes()) != prepared.instruction
                    or instruction.wire_id() != prepared.wire_id
                ):
                    raise RuntimeError(
                        f"prepared native instruction {index} changed identity"
                    )
                draft.add_instruction(instruction)
            else:  # pragma: no cover - plan parser invariant
                raise RuntimeError(f"prepared batch item {index} has unknown kind")

        result = dict(
            self._submit_transaction_draft_result(
                draft,
                private_key=private_key,
                private_key_hex=private_key_hex,
                wait=wait,
                interval=interval,
                timeout=timeout,
            )
        )
        result["plan"] = {
            "binding": plan.binding,
            "binding_digest_hex": plan.binding_digest_hex,
        }
        result["tx_hash_hex"] = result["hash"]
        if "terminal" in result:
            result["terminal_kind"] = _extract_pipeline_status_kind(
                result["terminal"]
            )
            result["r#final"] = result["terminal"]
        return result

    def call_contract_and_wait(
        self,
        *,
        authority: str,
        fee_payment: Optional[Mapping[str, Any]] = None,
        entrypoint: str,
        private_key: Optional[bytes] = None,
        private_key_hex: Optional[str] = None,
        contract_address: Optional[str] = None,
        contract_alias: Optional[str] = None,
        payload: Any = None,
        expected_contract_address: Optional[str] = None,
        expected_code_hash_hex: Optional[str] = None,
        expected_abi_hash_hex: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        creation_time_ms: Optional[int] = None,
        ttl_ms: Optional[int] = 900_000,
        wait: bool = True,
        timeout_ms: Optional[int] = 120_000,
        interval: float = 1.0,
    ) -> Any:
        """Prepare one contract call, sign it locally, and submit it.

        This is the single-call convenience form of
        :meth:`call_contract_batch_and_wait`; it therefore shares the same
        manifest, ABI, address, code-hash, metadata, and local-signing checks.
        """

        intent = ContractCallIntent(
            entrypoint,
            contract_address=contract_address,
            contract_alias=contract_alias,
            payload=payload,
            expected_contract_address=expected_contract_address,
            expected_code_hash_hex=expected_code_hash_hex,
            expected_abi_hash_hex=expected_abi_hash_hex,
        )
        result = dict(
            self.call_contract_batch_and_wait(
                authority=authority,
                fee_payment=fee_payment,
                entries=[intent],
                private_key=private_key,
                private_key_hex=private_key_hex,
                metadata=metadata,
                creation_time_ms=creation_time_ms,
                ttl_ms=ttl_ms,
                wait=wait,
                timeout=None if timeout_ms is None else timeout_ms / 1000.0,
                interval=interval,
            )
        )
        result["submit"] = result.get("submission")
        result["tx_hashes"] = [result["hash"]]
        return result

    def get_contract_manifest(
        self, artifact_id: ContractArtifactId, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> Optional[Mapping[str, Any]]:
        """Read one exact artifact with one-shot canonical account authentication."""
        if not isinstance(artifact_id, ContractArtifactId):
            raise TypeError("artifact_id must be a ContractArtifactId")
        expected_network = self._require_local_signing_context("contract manifest").network_id.literal
        response = self._account_request(
            "GET", artifact_id.path, canonical_auth=canonical_auth,
            headers={"Accept": "application/json"}, stream=True, context="contract manifest",
        )
        self._expect_status(response, {200, 404})
        if response.status_code == 404:
            response.close()
            return None
        payload = self._bounded_strict_json_object_response(response, 16 * 1024 * 1024, "contract manifest")
        record = ContractManifestRecord.from_payload(payload)
        if record.network_id != expected_network or record.artifact_id != artifact_id:
            raise RuntimeError("contract manifest response substitutes network or artifact identity")
        return payload

    def get_contract_manifest_typed(
        self, artifact_id: ContractArtifactId, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> ContractManifestRecord:
        """Typed wrapper for :meth:`get_contract_manifest`."""
        payload = self.get_contract_manifest(artifact_id, canonical_auth=canonical_auth)
        if payload is None:
            raise RuntimeError("contract manifest endpoint returned no payload")
        return ContractManifestRecord.from_payload(payload)

    def get_contract_code_bytes(
        self, artifact_id: ContractArtifactId, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> Optional[Mapping[str, Any]]:
        """Read and authenticate the complete domain-separated artifact bytes."""
        if not isinstance(artifact_id, ContractArtifactId):
            raise TypeError("artifact_id must be a ContractArtifactId")
        expected_network = self._require_local_signing_context("contract bytes").network_id.literal
        response = self._account_request(
            "GET", artifact_id.path + "/bytes", canonical_auth=canonical_auth,
            headers={"Accept": "application/json"}, stream=True, context="contract bytes",
        )
        self._expect_status(response, {200, 404})
        if response.status_code == 404:
            response.close()
            return None
        payload = self._bounded_strict_json_object_response(response, 23 * 1024 * 1024, "contract bytes")
        if not isinstance(payload, Mapping):
            raise RuntimeError("contract bytes response is missing")
        _require_wire_fields(payload, required=("network_id", "artifact_id", "code_b64"), context="contract bytes")
        returned_artifact = ContractArtifactId.from_payload(payload["artifact_id"])
        if payload["network_id"] != expected_network or returned_artifact != artifact_id:
            raise RuntimeError("contract bytes response substitutes network or artifact identity")
        _decode_contract_artifact_bytes(payload["code_b64"], artifact_id)
        return payload

    # ------------------------------------------------------------------
    # Connect API
    # ------------------------------------------------------------------
    def create_connect_session(
        self,
        payload: Mapping[str, Any],
    ) -> Optional[Any]:
        """POST `/v1/connect/session` and return the session payload."""

        body = _normalize_connect_session_request(payload)
        return self.request_json(
            "POST",
            "/v1/connect/session",
            json_body=body,
            expected_status=(200, 201),
        )

    def create_connect_session_info(
        self,
        payload: Mapping[str, Any],
    ) -> ConnectSessionInfo:
        """Create a session and parse the exact response into `ConnectSessionInfo`.

        Session creation does not read the operator-only aggregate status endpoint.
        The first-release response does not advertise an expiry timestamp, so
        ``expires_at`` remains ``None``.
        """

        request_body = _normalize_connect_session_request(payload)
        response = self.create_connect_session(request_body)
        return _connect_session_info_from_response(response, request_body, None)

    def send_connect_control(
        self,
        sid: str,
        *,
        kind: str,
        payload: Mapping[str, Any],
    ) -> Optional[Any]:
        """Convenience helper for posting Connect control frames via `/v1/connect/control/{kind}`."""

        return self.request_json(
            "POST",
            f"/v1/connect/control/{kind}",
            params={"sid": sid},
            json_body=dict(payload),
            expected_status=(200, 202),
        )

    def send_connect_control_frame(
        self,
        sid: str,
        control: "ConnectControlBase",
    ) -> Optional[Any]:
        """Send a typed Connect control by inferring the REST endpoint from the variant."""

        payload = _json_safe_value(control.to_dict())
        return self.send_connect_control(
            sid,
            kind=control.endpoint_kind,
            payload=payload,
        )

    def delete_connect_session(self, sid: str, token_management: str) -> bool:
        """DELETE `/v1/connect/session/{sid}` and return True when the session existed."""

        if not isinstance(sid, str) or not sid:
            raise TypeError("sid must be a non-empty string")
        if not isinstance(token_management, str) or not token_management:
            raise TypeError("token_management must be a non-empty string")
        response = self._request(
            "DELETE",
            f"/v1/connect/session/{sid}",
            headers={"Authorization": f"Bearer {token_management}"},
        )
        self._expect_status(response, (204, 404))
        return response.status_code == 204

    def connect_websocket(
        self,
        sid: str,
        role: str,
        token: str,
        *,
        timeout: Optional[float] = None,
        headers: Optional[Mapping[str, str]] = None,
        subprotocols: Optional[Sequence[str]] = None,
    ):
        """Open a Connect WebSocket (`/v1/connect/ws`). Requires `websocket-client`."""

        if websocket is None:  # pragma: no cover - dependency optional
            raise RuntimeError(
                "websocket-client is not installed. Install iroha-python with the `ws` extra "
                "(`pip install iroha-python[ws]`) or add `websocket-client` to your environment."
            )

        ws_url, header_list, prepared_subprotocols = prepare_connect_websocket_request(
            self._base_url,
            sid,
            role,
            token,
            headers=headers,
            subprotocols=subprotocols,
        )

        return websocket.create_connection(
            ws_url,
            timeout=timeout,
            header=header_list or None,
            subprotocols=prepared_subprotocols,
        )

    def get_connect_status(self) -> Optional[Any]:
        """Fetch operator-authenticated Connect aggregate runtime status."""

        response = self._operator_get(
            "/v1/connect/status/aggregate",
            headers={"Accept": "application/json"},
            context="Connect aggregate status",
        )
        if response.status_code == 404:
            return None
        self._expect_status(response, (200,))
        return self._maybe_json(response)

    def get_connect_status_typed(self) -> Optional[ConnectStatusSnapshot]:
        """Typed wrapper for :meth:`get_connect_status`. Returns `None` when Connect is disabled."""

        payload = self.get_connect_status()
        if payload is None:
            return None
        return ConnectStatusSnapshot.from_payload(payload)

    def list_connect_apps(
        self,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> "ConnectAppRegistryPage":
        """List registered Connect applications (`GET /v1/connect/app/apps`)."""

        params: Dict[str, Any] = {}
        if limit is not None:
            params["limit"] = int(limit)
        if cursor is not None:
            if not isinstance(cursor, str):
                raise TypeError("connect app cursor must be a string")
            params["cursor"] = cursor
        payload = self.request_json(
            "GET",
            "/v1/connect/app/apps",
            params=params or None,
            expected_status=(200,),
        )
        if not isinstance(payload, Mapping):
            raise TypeError("connect app registry response must be a JSON object")
        return ConnectAppRegistryPage.from_payload(payload)

    def iter_connect_apps(
        self,
        *,
        page_size: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> Iterator["ConnectAppRecord"]:
        """Iterate over all Connect applications by following pagination cursors.

        Args:
            page_size: Optional limit applied to each request. Must be positive when set.
            cursor: Optional starting cursor returned by a previous listing.

        Yields:
            :class:`ConnectAppRecord` entries for every registry item.
        """

        if page_size is not None:
            page_limit = int(page_size)
            if page_limit <= 0:
                raise ValueError("page_size must be positive when provided")
        else:
            page_limit = None

        if cursor is not None and not isinstance(cursor, str):
            raise TypeError("cursor must be a string when provided")

        seen_cursors: set[str] = set()
        next_cursor = cursor
        if next_cursor is not None:
            seen_cursors.add(next_cursor)

        while True:
            page = self.list_connect_apps(limit=page_limit, cursor=next_cursor)
            for record in page.items:
                yield record
            next_cursor = page.next_cursor
            if next_cursor is None:
                break
            if next_cursor in seen_cursors:
                raise RuntimeError(
                    f"connect app registry returned duplicate cursor {next_cursor!r}"
                )
            seen_cursors.add(next_cursor)

    def get_connect_app(self, app_id: str) -> "ConnectAppRecord":
        """Fetch a single Connect application (`GET /v1/connect/app/apps/{app_id}`)."""

        if not isinstance(app_id, str) or not app_id:
            raise TypeError("app_id must be a non-empty string")
        payload = self.request_json(
            "GET",
            f"/v1/connect/app/apps/{app_id}",
            expected_status=(200,),
        )
        if not isinstance(payload, Mapping):
            raise TypeError("connect app response must be a JSON object")
        return ConnectAppRecord.from_payload(payload)

    def register_connect_app(
        self,
        registration: Union["ConnectAppRecord", Mapping[str, Any]],
    ) -> Optional[Any]:
        """Register or update a Connect application (`POST /v1/connect/app/apps`)."""

        if isinstance(registration, ConnectAppRecord):
            body = registration.to_payload()
        else:
            body = dict(registration)
        payload = self.request_json(
            "POST",
            "/v1/connect/app/apps",
            json_body=_json_safe_value(body),
            expected_status=(200, 201, 202),
        )
        if isinstance(payload, Mapping):
            try:
                return ConnectAppRecord.from_payload(payload)
            except TypeError:
                return payload
        return payload

    def delete_connect_app(self, app_id: str) -> Optional[Any]:
        """Delete a Connect application (`DELETE /v1/connect/app/apps/{app_id}`)."""

        if not isinstance(app_id, str) or not app_id:
            raise TypeError("app_id must be a non-empty string")
        response = self._request("DELETE", f"/v1/connect/app/apps/{app_id}")
        self._expect_status(response, {200, 202, 204, 404})
        return self._maybe_json(response)

    def get_connect_app_policy_controls(self) -> "ConnectAppPolicyControls":
        """Fetch mutable Connect policy toggles (`GET /v1/connect/app/policy`)."""

        payload = self.request_json(
            "GET",
            "/v1/connect/app/policy",
            expected_status=(200,),
        )
        if not isinstance(payload, Mapping):
            raise TypeError("connect app policy response must be a JSON object")
        policy_payload = payload.get("policy")
        if isinstance(policy_payload, Mapping):
            return ConnectAppPolicyControls.from_payload(policy_payload)
        return ConnectAppPolicyControls.from_payload(payload)

    def update_connect_app_policy_controls(
        self,
        updates: Union["ConnectAppPolicyControls", Mapping[str, Any]],
    ) -> "ConnectAppPolicyControls":
        """Update Connect policy toggles (`POST /v1/connect/app/policy`)."""

        if isinstance(updates, ConnectAppPolicyControls):
            body = updates.to_payload()
        else:
            body = dict(updates)
        payload = self.request_json(
            "POST",
            "/v1/connect/app/policy",
            json_body=_json_safe_value(body),
            expected_status=(200, 202),
        )
        if not isinstance(payload, Mapping):
            raise TypeError("connect app policy response must be a JSON object")
        policy_payload = payload.get("policy")
        if isinstance(policy_payload, Mapping):
            return ConnectAppPolicyControls.from_payload(policy_payload)
        return ConnectAppPolicyControls.from_payload(payload)

    def get_connect_admission_manifest(self) -> "ConnectAdmissionManifest":
        """Fetch the Connect admission manifest (`GET /v1/connect/app/manifest`)."""

        payload = self.request_json(
            "GET",
            "/v1/connect/app/manifest",
            expected_status=(200,),
        )
        if not isinstance(payload, Mapping):
            raise TypeError("connect admission manifest response must be a JSON object")
        return ConnectAdmissionManifest.from_payload(payload)

    def set_connect_admission_manifest(
        self,
        manifest: Union["ConnectAdmissionManifest", Mapping[str, Any]],
    ) -> "ConnectAdmissionManifest":
        """Replace the Connect admission manifest (`PUT /v1/connect/app/manifest`)."""

        if isinstance(manifest, ConnectAdmissionManifest):
            body = manifest.to_payload()
        else:
            body = dict(manifest)
        payload = self.request_json(
            "PUT",
            "/v1/connect/app/manifest",
            json_body=_json_safe_value(body),
            expected_status=(200, 202),
        )
        if not isinstance(payload, Mapping):
            raise TypeError("connect admission manifest response must be a JSON object")
        return ConnectAdmissionManifest.from_payload(payload)

    # Telemetry & Sumeragi helpers
    # ------------------------------------------------------------------
    def _sumeragi_operator_json(self, path: str, *, context: str) -> Optional[Any]:
        """Fetch one exact Sumeragi operator JSON resource exactly once."""

        response = self._operator_get(
            path,
            headers={"Accept": "application/json"},
            context=context,
        )
        self._expect_status(response, (200,))
        return self._maybe_json(response)

    def get_sumeragi_status(self) -> Optional[Any]:
        """Fetch the raw native protocol-1 observation JSON."""
        return self._sumeragi_operator_json(
            "/v1/sumeragi/status",
            context="sumeragi status",
        )

    def get_sumeragi_status_typed(self) -> SumeragiStatus:
        """Read the canonical native observation through the original authenticated client."""
        return super().get_sumeragi_status()

    def get_sumeragi_evidence_count(self) -> SumeragiEvidenceCount:
        """Return the exact committed evidence count."""

        payload = self._get_sumeragi_operator_json_object(
            "/v1/sumeragi/evidence/count",
            context="sumeragi evidence count",
            maximum_body_bytes=_SUMERAGI_EVIDENCE_COUNT_JSON_MAX_BYTES,
            parser=parse_sumeragi_json_object,
        )
        return SumeragiEvidenceCount.from_payload(payload)

    def list_sumeragi_evidence(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        kind: Optional[str] = None,
    ) -> SumeragiEvidenceListPage:
        """List the exact first-release evidence records."""

        params: Dict[str, Any] = {}
        page_limit = 50
        page_offset = 0
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int):
                raise TypeError("sumeragi evidence limit must be an integer")
            if not 1 <= limit <= 1_000:
                raise ValueError("sumeragi evidence limit must be in 1..=1000")
            params["limit"] = limit
            page_limit = limit
        if offset is not None:
            if isinstance(offset, bool) or not isinstance(offset, int):
                raise TypeError("sumeragi evidence offset must be an integer")
            if not 0 <= offset <= 10_000:
                raise ValueError("sumeragi evidence offset must be in 0..=10000")
            params["offset"] = offset
            page_offset = offset
        if kind is not None:
            if kind != "NativeSumeragiEvidence":
                raise ValueError(
                    "sumeragi evidence kind must be NativeSumeragiEvidence"
                )
            params["kind"] = kind
        payload = self._get_sumeragi_operator_json_object(
            "/v1/sumeragi/evidence",
            context="sumeragi evidence list",
            params=params or None,
            maximum_body_bytes=_SUMERAGI_EVIDENCE_LIST_JSON_MAX_BYTES,
            parser=parse_sumeragi_json_object,
        )
        return SumeragiEvidenceListPage.from_payload(
            payload,
            limit=page_limit,
            offset=page_offset,
        )

    def get_sumeragi_params(self) -> Optional[Any]:
        """Fetch operator-authenticated on-chain Sumeragi parameters."""

        return self._sumeragi_operator_json(
            "/v1/sumeragi/params",
            context="sumeragi parameters",
        )

    def get_sumeragi_params_typed(self) -> SumeragiParamsSnapshot:
        """Typed wrapper for :meth:`get_sumeragi_params`."""

        payload = self.get_sumeragi_params()
        if not isinstance(payload, Mapping):
            raise TypeError("sumeragi params response must be a JSON object")
        return SumeragiParamsSnapshot.from_payload(payload)

    # ------------------------------------------------------------------
    # Governance API
    # ------------------------------------------------------------------
    def set_protected_namespaces(self, namespaces: Sequence[str]) -> Optional[Any]:
        """Apply the `gov_protected_namespaces` parameter via `POST /v1/gov/protected-namespaces`."""

        if isinstance(namespaces, str):
            raw_values: Sequence[Any] = [namespaces]
        else:
            raw_values = namespaces
        values = []
        for index, value in enumerate(raw_values):
            namespace = _require_exact_token_string(value, f"namespaces[{index}]")
            if not namespace.isascii():
                raise ValueError(f"namespaces[{index}] must contain only ASCII characters")
            values.append(namespace)
        return self.request_json(
            "POST",
            "/v1/gov/protected-namespaces",
            json_body={"namespaces": values},
            expected_status=(200,),
        )

    def get_protected_namespaces(
        self, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> Optional[Any]:
        """Fetch the current `gov_protected_namespaces` setting (`GET /v1/gov/protected-namespaces`)."""

        return self._account_request_json(
            "GET",
            "/v1/gov/protected-namespaces",
            canonical_auth=canonical_auth,
            context="protected namespaces",
            expected_status=(200,),
        )

    def get_governance_contract(
        self,
        contract_address: str,
        *,
        canonical_auth: ToriiCanonicalRequestAuth,
    ) -> Optional[Any]:
        """Fetch one governance-managed contract binding (`GET /v1/gov/contracts/{contract_address}`)."""

        return self._account_request_json(
            "GET",
            f"/v1/gov/contracts/{contract_address}",
            canonical_auth=canonical_auth,
            context="governance contract",
            expected_status=(200,),
        )

    def get_governance_contract_typed(
        self,
        contract_address: str,
        *,
        canonical_auth: ToriiCanonicalRequestAuth,
    ) -> GovernanceContractRecord:
        """Typed wrapper for :meth:`get_governance_contract`."""

        payload = self.get_governance_contract(
            contract_address, canonical_auth=canonical_auth
        )
        if payload is None:
            raise RuntimeError("governance contract endpoint returned no payload")
        if not isinstance(payload, Mapping):
            raise RuntimeError("governance contract endpoint returned non-object payload")
        return GovernanceContractRecord.from_payload(payload)

    def governance_deploy_contract_proposal(
        self, payload: Mapping[str, Any], *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> GovernanceProposalDraft:
        """Draft one strict V1 deploy proposal with optional public provenance.

        The retired opaque ``limits`` field and private-key material are rejected
        before dispatch. The response is accepted only when it contains the exact
        proposal id and one canonical ``ProposeDeployContract`` instruction.
        """

        normalized = _normalize_governance_deploy_contract_payload(
            payload,
            context="governance deploy-contract proposal",
        )
        return self.propose_contract_deploy(
            canonical_auth=canonical_auth,
            contract_address=normalized.get("contract_address"),
            contract_alias=normalized.get("contract_alias"),
            abi_version=normalized["abi_version"],
            code_hash=normalized["code_hash"],
            abi_hash=normalized["abi_hash"],
            manifest_provenance=normalized.get("manifest_provenance"),
        )

    def get_governance_proposal(
        self, proposal_id: str, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> Optional[Any]:
        """GET `/v1/gov/proposals/{proposal_id}`."""

        exact_proposal_id = _require_governance_proposal_id(
            proposal_id,
            "proposal_id",
        )

        return self._account_request_json(
            "GET",
            f"/v1/gov/proposals/{quote(exact_proposal_id, safe='')}",
            canonical_auth=canonical_auth,
            context="governance proposal",
            expected_status=(200, 404),
        )

    def get_governance_proposal_typed(
        self, proposal_id: str, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> GovernanceProposalResult:
        """Typed wrapper for :meth:`get_governance_proposal`."""

        payload = self.get_governance_proposal(
            proposal_id, canonical_auth=canonical_auth
        )
        if payload is None:
            return GovernanceProposalResult(found=False, proposal=None)
        return GovernanceProposalResult.from_payload(payload)

    def get_governance_referendum(
        self, referendum_id: str, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> Optional[Any]:
        """GET `/v1/gov/referenda/{referendum_id}`."""

        exact_referendum_id = _require_governance_selector_string(
            referendum_id,
            "referendum_id",
        )

        return self._account_request_json(
            "GET",
            f"/v1/gov/referenda/{quote(exact_referendum_id, safe='')}",
            canonical_auth=canonical_auth,
            context="governance referendum",
            expected_status=(200, 404),
        )

    def get_governance_referendum_typed(
        self,
        referendum_id: str,
        *,
        canonical_auth: ToriiCanonicalRequestAuth,
    ) -> GovernanceReferendumResult:
        """Typed wrapper for :meth:`get_governance_referendum`."""

        payload = self.get_governance_referendum(
            referendum_id, canonical_auth=canonical_auth
        )
        if payload is None:
            return GovernanceReferendumResult(found=False, referendum=None)
        return GovernanceReferendumResult.from_payload(payload)

    def get_governance_tally(
        self, referendum_id: str, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> Optional[Mapping[str, Any]]:
        """Return the exact tally response, or ``None`` for an unknown referendum."""

        exact_referendum_id = _require_governance_selector_string(
            referendum_id, "referendum_id"
        )
        return self._governance_tally_payload(
            exact_referendum_id, canonical_auth=canonical_auth
        )

    def get_governance_tally_typed(
        self, referendum_id: str, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> Optional[GovernanceTally]:
        """Return an exact typed tally, or ``None`` for an unknown referendum."""

        payload = self.get_governance_tally(
            referendum_id, canonical_auth=canonical_auth
        )
        if payload is None:
            return None
        return GovernanceTally.from_payload(payload)

    def get_governance_locks(
        self, referendum_id: str, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> Optional[Any]:
        """GET `/v1/gov/locks/{referendum_id}`."""

        exact_referendum_id = _require_governance_selector_string(
            referendum_id,
            "referendum_id",
        )

        return self._account_request_json(
            "GET",
            f"/v1/gov/locks/{quote(exact_referendum_id, safe='')}",
            canonical_auth=canonical_auth,
            context="governance locks",
            expected_status=(200, 404),
        )

    def get_governance_locks_typed(
        self, referendum_id: str, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> GovernanceLocksResult:
        """Typed wrapper for :meth:`get_governance_locks`."""

        payload = self.get_governance_locks(
            referendum_id, canonical_auth=canonical_auth
        )
        if payload is None:
            return GovernanceLocksResult(found=False, referendum_id=referendum_id, locks={})
        return GovernanceLocksResult.from_payload(payload)

    def get_governance_unlock_stats(
        self, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> Optional[Any]:
        """GET `/v1/gov/unlocks/stats`."""

        return self._account_request_json(
            "GET",
            "/v1/gov/unlocks/stats",
            canonical_auth=canonical_auth,
            context="governance unlock stats",
            expected_status=(200,),
        )

    def get_governance_unlock_stats_typed(
        self, *, canonical_auth: ToriiCanonicalRequestAuth
    ) -> GovernanceUnlockStats:
        """Typed wrapper for :meth:`get_governance_unlock_stats`."""

        payload = self.get_governance_unlock_stats(canonical_auth=canonical_auth)
        if payload is None:
            raise RuntimeError("governance unlock stats endpoint returned no payload")
        return GovernanceUnlockStats.from_payload(payload)

    def stream_events(
        self,
        *,
        filter: Optional[FilterLike] = None,
        timeout: Optional[float] = None,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        on_event: Optional[Callable[..., None]] = None,
        with_metadata: bool = False,
        decode_json: bool = True,
    ) -> Iterator[Any]:
        """Stream live ledger events from ``/v1/events/sse`` as typed records.

        Each event decodes to a :data:`~iroha_python.stream_events.ToriiEvent`:
        :class:`TransactionEvent`, :class:`BlockEvent`,
        :class:`PipelineWarningEvent`, :class:`WitnessEvent`, the proof events,
        or :class:`GenericEvent` for every other kind (data events such as
        ``Asset``, the ``Other`` category and kinds newer than this SDK, which
        therefore never break the stream). A payload that is not such a JSON
        object raises :class:`ValueError`. ``with_metadata=True`` yields
        :class:`SseEvent` frames whose ``data`` is the typed event;
        ``decode_json=False`` yields the raw ``data`` text instead.

        ``filter`` uses the collection-query text grammar, restricted to what
        event subscriptions can match: ``=`` and ``in [...]`` over
        ``tx_status``, ``tx_hash``, ``tx_block_height``, ``tx_lane_id``,
        ``tx_dataspace_id``, ``block_status``, ``block_height``,
        ``proof_backend``, ``proof_call_hash`` and ``proof_envelope_hash``,
        combined with ``and``/``or``; ``not`` only over ``tx_status = ...`` or
        ``block_status = ...``; and ``tx_block_height is null``::

            client.stream_events(filter=(F.tx_hash == tx_hash) & F.tx_status.in_("Approved", "Rejected"))

        A :class:`~iroha_torii_client.list_query.Filter` is sent in canonical
        text form (object and array literals raise ``FilterError`` before any
        request); a text filter is sent unchanged. Torii rejects any other
        filter with ``invalid_filter``, raised as ``ToriiQueryError`` when the
        stream opens.

        Torii does not retain a replay log for this route. A reconnect starts a
        new live subscription and can have a gap; use the committed block
        stream when complete ledger history is required.
        """

        params = None if filter is None else {"filter": filter_text(filter)}
        path = "/v1/events/sse"
        event_headers = self._canonical_request_headers(
            "GET",
            path,
            b"",
            canonical_auth=self._canonical_request_auth,
            headers={"Accept": "text/event-stream"},
            has_body=False,
        )
        frames = self._stream_sse(
            path,
            params=params,
            headers=event_headers,
            timeout=timeout,
            max_retries=max_retries,
            backoff_base=backoff_base,
            decode_json=False,
        )

        def events() -> Iterator[Any]:
            try:
                for frame in frames:
                    if frame.data is None:
                        continue  # SSE dispatches no event without data lines
                    if decode_json:
                        frame = replace(frame, data=decode_event(frame.data))
                    if on_event is not None:
                        if with_metadata:
                            on_event(frame)
                        else:
                            on_event(frame.data, frame.id)
                    yield frame if with_metadata else frame.data
            finally:
                close = getattr(frames, "close", None)
                if close is not None:
                    close()  # closing this iterator releases the HTTP stream

        return events()

    def stream_sumeragi_status(
        self,
        *,
        timeout: Optional[float] = None,
        max_retries: int = 0,
        backoff_base: float = 0.5,
        on_event: Optional[Callable[..., None]] = None,
        with_metadata: bool = False,
        decode_json: bool = True,
    ):
        """Stream one operator-authenticated Sumeragi status subscription.

        Operator request authentication is one-shot, so redirects and
        automatic reconnects are forbidden. Call this method again to create a
        fresh signed subscription after a disconnect.
        """

        if max_retries != 0:
            raise ValueError("stream_sumeragi_status max_retries must be zero")
        operator_context = self.operator_signing_context
        if operator_context is None:
            raise ValueError(
                "stream_sumeragi_status requires immutable operator_signing_context"
            )

        def _handle(event: SseEvent) -> None:
            if on_event is None:
                return
            if with_metadata:
                on_event(event)
            else:
                on_event(event.data, event.id)

        iterator = self._stream_sse(
            "/v1/sumeragi/status/sse",
            headers=_OperatorRequestHeaderPlan(
                {"Accept": "text/event-stream"},
                _BaseToriiOperatorSigningContext(
                    network_id=operator_context.network_id.literal,
                    public_key=operator_context.key_pair.public_key_multihash,
                    signer=operator_context.key_pair.sign,
                ),
            ),
            timeout=timeout,
            max_retries=0,
            backoff_base=backoff_base,
            decode_json=decode_json,
            on_event=_handle if on_event is not None else None,
        )
        if with_metadata:
            return iterator
        return (event.data for event in iterator)

    # ------------------------------------------------------------------
    # Triggers API
    # ------------------------------------------------------------------
    def list_trigger_completions(
        self,
        *,
        trigger_id: Optional[str] = None,
        entrypoint_hash: Optional[str] = None,
        outcome: Optional[str] = None,
        from_height: Optional[int] = None,
        to_height: Optional[int] = None,
        limit: Optional[int] = None,
        scan_limit_blocks: Optional[int] = None,
    ) -> TriggerCompletionList:
        """Read typed, step-indexed trigger completion evidence."""

        params: Dict[str, Any] = {}
        trigger_id_value = _normalize_optional_string(
            trigger_id,
            "list_trigger_completions.trigger_id",
        )
        if trigger_id_value is not None:
            params["id"] = trigger_id_value
        entrypoint_hash_value = _normalize_optional_string(
            entrypoint_hash,
            "list_trigger_completions.entrypoint_hash",
        )
        if entrypoint_hash_value is not None:
            params["entrypoint_hash"] = entrypoint_hash_value
        if outcome is not None:
            if not isinstance(outcome, str):
                raise TypeError("list_trigger_completions.outcome must be a string")
            outcome_value = outcome.strip().lower()
            if outcome_value not in {"all", "success", "failure"}:
                raise ValueError(
                    "list_trigger_completions.outcome must be all, success, or failure"
                )
            params["outcome"] = outcome_value
        for name, value, allow_zero in (
            ("from_height", from_height, True),
            ("to_height", to_height, True),
            ("limit", limit, False),
            ("scan_limit_blocks", scan_limit_blocks, False),
        ):
            if isinstance(value, bool):
                raise TypeError(f"list_trigger_completions.{name} must be an integer")
            normalized = _coerce_int(
                value,
                f"list_trigger_completions.{name}",
                allow_zero=allow_zero,
            )
            if normalized is not None:
                if normalized > 0xFFFFFFFFFFFFFFFF:
                    raise ValueError(f"list_trigger_completions.{name} must fit in a u64")
                params[name] = normalized

        payload = self.request_json(
            "GET",
            "/v1/triggers/completed",
            params=params or None,
            expected_status=(200,),
        )
        if not isinstance(payload, Mapping):
            raise RuntimeError("trigger completion endpoint returned malformed payload")
        return TriggerCompletionList.from_payload(payload)

    def list_triggers(
        self,
        *,
        namespace: Optional[str] = None,
        authority: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Optional[Any]:
        """GET `/v1/triggers` with optional filtering."""

        params: Dict[str, Any] = {}
        namespace_value = _normalize_optional_string(namespace, "list_triggers.namespace")
        if namespace_value is not None:
            params["namespace"] = namespace_value
        authority_value = _normalize_optional_string(authority, "list_triggers.authority")
        if authority_value is not None:
            params["authority"] = authority_value
        limit_value = _coerce_int(limit, "list_triggers.limit") if limit is not None else None
        if limit_value is not None:
            params["limit"] = limit_value
        offset_value = (
            _coerce_int(offset, "list_triggers.offset", allow_zero=True)
            if offset is not None
            else None
        )
        if offset_value is not None:
            params["offset"] = offset_value
        return self.request_json(
            "GET",
            "/v1/triggers",
            params=params or None,
            expected_status=(200,),
        )

    def list_triggers_typed(
        self,
        *,
        namespace: Optional[str] = None,
        authority: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> TriggerListPage:
        """Typed wrapper for :meth:`list_triggers`."""

        payload = self.list_triggers(
            namespace=namespace,
            authority=authority,
            limit=limit,
            offset=offset,
        )
        if payload is None:
            return TriggerListPage(items=[], total=0)
        return TriggerListPage.from_payload(payload)

    def get_trigger(self, trigger_id: str) -> Optional[Any]:
        """GET `/v1/triggers/{trigger_id}` and return the stored trigger or `None` when missing."""

        normalized_id = _require_non_empty_string(trigger_id, "trigger_id")
        return self.request_json(
            "GET",
            f"/v1/triggers/{normalized_id}",
            expected_status=(200, 404),
        )

    def get_trigger_typed(self, trigger_id: str) -> Optional[TriggerRecord]:
        """Typed wrapper for :meth:`get_trigger`."""

        payload = self.get_trigger(trigger_id)
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise RuntimeError("trigger endpoint returned non-object payload")
        return TriggerRecord.from_payload(payload)

    def register_trigger(self, trigger: Mapping[str, Any]) -> Optional[Any]:
        """POST `/v1/triggers` with a trigger registration payload."""

        if not isinstance(trigger, Mapping):
            raise TypeError("trigger must be a mapping")
        return self.request_json(
            "POST",
            "/v1/triggers",
            json_body=dict(trigger),
            expected_status=(200, 201, 202),
        )

    def register_trigger_typed(
        self, trigger: Mapping[str, Any]
    ) -> Optional[TriggerMutationResponse]:
        """Typed wrapper for :meth:`register_trigger`."""

        payload = self.register_trigger(trigger)
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise RuntimeError("trigger registration returned malformed payload")
        return TriggerMutationResponse.from_payload(payload)

    def delete_trigger(self, trigger_id: str) -> Optional[Any]:
        """DELETE `/v1/triggers/{trigger_id}`."""

        response = self._request("DELETE", f"/v1/triggers/{trigger_id}")
        self._expect_status(response, {200, 202, 204, 404})
        return self._maybe_json(response)

    def delete_trigger_typed(self, trigger_id: str) -> Optional[TriggerMutationResponse]:
        """Typed wrapper for :meth:`delete_trigger`."""

        payload = self.delete_trigger(trigger_id)
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise RuntimeError("trigger deletion returned malformed payload")
        return TriggerMutationResponse.from_payload(payload)

def create_torii_client(
    base_url: str,
    *,
    session: Optional[requests.Session] = None,
    local_signing_context: Optional[LocalSigningContext] = None,
    operator_signing_context: Optional[OperatorSigningContext] = None,
    canonical_request_auth: Optional[ToriiCanonicalRequestAuth] = None,
    auth_token: Optional[str] = None,
    api_token: Optional[str] = None,
    default_headers: Optional[Mapping[str, str]] = None,
    timeout: Optional[float] = None,
    max_retries: Optional[int] = None,
    backoff_initial: Optional[float] = None,
    backoff_max: Optional[float] = None,
    backoff_multiplier: Optional[float] = None,
    retry_on_status: Optional[Sequence[int]] = None,
    retry_on_methods: Optional[Sequence[str]] = None,
    config: Optional[Mapping[str, Any]] = None,
    env: Optional[Mapping[str, str]] = None,
    overrides: Optional[Mapping[str, Any]] = None,
    resolved_config: Optional[ResolvedToriiClientConfig] = None,
    chain_discriminant: Optional[int] = None,
    sorafs_alias_policy: Optional[Union[SorafsAliasPolicy, Mapping[str, Any]]] = None,
    sorafs_alias_warning: Optional[Callable[[SorafsAliasWarning], None]] = None,
    sorafs_alias_logger: Optional[logging.Logger] = None,
) -> ToriiClient:
    """Create a client with deterministic config, then explicit keyword overrides."""

    if resolved_config is not None and not isinstance(
        resolved_config, ResolvedToriiClientConfig
    ):
        raise TypeError("resolved_config must be a ResolvedToriiClientConfig")
    if resolved_config is not None and any(
        source is not None for source in (config, env, overrides)
    ):
        raise ValueError(
            "resolved_config cannot be combined with config, env, or overrides"
        )
    resolved = resolved_config
    if resolved is None and (config is not None or overrides is not None or env is not None):
        resolved = resolve_torii_client_config(config=config, env=env, overrides=overrides)

    header_merge: Dict[str, str] = (
        dict(resolved.default_headers) if resolved is not None else {"Accept": "application/json"}
    )
    if default_headers is not None:
        for name, value in _copy_http_headers(
            default_headers,
            "default_headers",
        ).items():
            _set_exact_header(header_merge, name, value)

    auth_value = (
        auth_token if auth_token is not None else (resolved.auth_token if resolved else None)
    )
    api_value = api_token if api_token is not None else (resolved.api_token if resolved else None)
    timeout_value = timeout if timeout is not None else (resolved.timeout if resolved else 30.0)
    max_retries_value = (
        max_retries if max_retries is not None else (resolved.max_retries if resolved else 3)
    )
    backoff_initial_value = (
        backoff_initial
        if backoff_initial is not None
        else (resolved.backoff_initial if resolved else 0.5)
    )
    backoff_max_value = (
        backoff_max
        if backoff_max is not None
        else (resolved.max_backoff if resolved else 5.0)
    )
    backoff_multiplier_value = (
        backoff_multiplier
        if backoff_multiplier is not None
        else (resolved.backoff_multiplier if resolved else 2.0)
    )
    retry_statuses = (
        retry_on_status
        if retry_on_status is not None
        else (list(resolved.retry_statuses) if resolved else None)
    )
    retry_methods = (
        retry_on_methods
        if retry_on_methods is not None
        else (list(resolved.retry_methods) if resolved else None)
    )
    policy_value: Optional[Union[SorafsAliasPolicy, Mapping[str, Any]]] = sorafs_alias_policy
    if policy_value is None and resolved is not None:
        policy_value = resolved.sorafs_alias_policy

    return ToriiClient(
        base_url,
        session=session,
        local_signing_context=local_signing_context,
        operator_signing_context=operator_signing_context,
        canonical_request_auth=canonical_request_auth,
        auth_token=auth_value,
        api_token=api_value,
        default_headers=header_merge,
        timeout=timeout_value,
        max_retries=max_retries_value,
        backoff_initial=backoff_initial_value,
        backoff_max=backoff_max_value,
        backoff_multiplier=backoff_multiplier_value,
        retry_on_status=retry_statuses,
        retry_on_methods=retry_methods,
        chain_discriminant=chain_discriminant,
        sorafs_alias_policy=policy_value,
        sorafs_alias_warning=sorafs_alias_warning,
        sorafs_alias_logger=sorafs_alias_logger,
    )
