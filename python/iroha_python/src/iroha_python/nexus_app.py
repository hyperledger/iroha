"""High-level SORA Nexus app facade.

The facade is additive: it composes existing Connect, transaction-codec, Torii,
and pipeline-status clients while keeping those lower-level APIs available for
advanced callers.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Callable, Mapping, Optional, Protocol, Union

from .address import (
    AccountAddress,
    AccountAddressError,
    i105_discriminant_from_sentinel,
    normalize_i105_discriminant,
)
from .address import (
    require_canonical_asset_definition_id as _strict_exact_asset_definition_id,
)
from .crypto import NetworkId, _require_network_id, hash_blake2b_32
from .numeric_v1 import NumericV1Codec

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .tx import QuantityLike
else:  # pragma: no cover - postponed annotations only
    QuantityLike = Any

BytesLike = Union[bytes, bytearray, memoryview, str]

_NEXUS_LANE_CONFIG_FIELDS = (
    "id",
    "shard_id",
    "dataspace_id",
    "alias",
    "description",
    "visibility",
    "lane_type",
    "governance",
    "settlement",
    "storage",
    "proof_scheme",
    "manifest_policy",
    "confidential_compute",
    "scheduler",
    "settlement_buffer",
    "metadata",
)
_NEXUS_LANE_VISIBILITIES = frozenset(("public", "restricted"))
_NEXUS_LANE_STORAGE_PROFILES = frozenset(
    ("full_replica", "commitment_only", "split_replica")
)
_NEXUS_LANE_PROOF_SCHEMES_V1 = frozenset(("merkle_sha256",))
_NEXUS_DA_MANIFEST_POLICIES = frozenset(("strict", "audit"))
_NEXUS_CONFIDENTIAL_MECHANISMS = frozenset(("encryption", "secret_sharing"))
_NEXUS_CONFIDENTIAL_COMPUTE_FIELDS = (
    "mechanism",
    "key_version",
    "allowed_audiences",
)
_NEXUS_LANE_SCHEDULER_FIELDS = (
    "teu_capacity",
    "starvation_bound_slots",
)
_NEXUS_LANE_SETTLEMENT_BUFFER_FIELDS = (
    "account_id",
    "asset_definition_id",
    "capacity",
)
_NEXUS_RETIRED_FUNCTIONAL_METADATA_KEYS = frozenset(
    (
        "da_manifest_policy",
        "confidential_compute",
        "confidential_mechanism",
        "confidential_key_version",
        "confidential_access",
        "scheduler.teu_capacity",
        "scheduler.starvation_bound_slots",
        "settlement.buffer_account",
        "settlement.buffer_asset",
        "settlement.buffer_capacity",
    )
)


def _strict_exact_i105_account_id(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or "@" in value:
        raise ValueError(f"{context} must be an exact canonical I105 account id")
    try:
        discriminant = i105_discriminant_from_sentinel(value)
        if discriminant is None:
            raise AccountAddressError("missing canonical I105 sentinel")
        address = AccountAddress.parse_encoded(value, expected_discriminant=discriminant)
        if address.to_i105(discriminant) != value:
            raise AccountAddressError("noncanonical I105 spelling")
    except AccountAddressError as error:
        raise ValueError(
            f"{context} must be an exact canonical I105 account id"
        ) from error
    return value


def _strict_nexus_lane_config(
    value: Any,
    context: str,
    strict_exact_fields: Callable[..., None],
    strict_uint: Callable[..., int],
    strict_nonempty_string: Callable[..., str],
) -> dict[str, Any]:
    """Validate and copy one canonical V1 ``LaneConfig`` JSON object."""

    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be a mapping")
    if any(not isinstance(field, str) for field in value):
        raise TypeError(f"{context} field names must be strings")
    strict_exact_fields(value, _NEXUS_LANE_CONFIG_FIELDS, context)
    lane = dict(value)

    strict_uint(lane, "id", 32, context)
    shard_id = lane["shard_id"]
    if shard_id is not None:
        strict_uint(lane, "shard_id", 32, context)
    strict_uint(lane, "dataspace_id", 64, context)
    strict_nonempty_string(lane, "alias", context)

    for field_name in ("description", "lane_type", "governance", "settlement"):
        field_value = lane[field_name]
        if field_value is not None and not isinstance(field_value, str):
            raise TypeError(f"{context} `{field_name}` must be a string or null")

    visibility = lane["visibility"]
    if not isinstance(visibility, str):
        raise TypeError(f"{context} `visibility` must be a string")
    if visibility not in _NEXUS_LANE_VISIBILITIES:
        raise ValueError(f"{context} `visibility` must be `public` or `restricted`")

    storage = lane["storage"]
    if not isinstance(storage, str):
        raise TypeError(f"{context} `storage` must be a string")
    if storage not in _NEXUS_LANE_STORAGE_PROFILES:
        raise ValueError(
            f"{context} `storage` must be `full_replica`, `commitment_only`, "
            "or `split_replica`"
        )

    proof_scheme = lane["proof_scheme"]
    if not isinstance(proof_scheme, str):
        raise TypeError(f"{context} `proof_scheme` must be a string")
    if proof_scheme not in _NEXUS_LANE_PROOF_SCHEMES_V1:
        raise ValueError(f"{context} `proof_scheme` must be `merkle_sha256` in V1")

    manifest_policy = lane["manifest_policy"]
    if not isinstance(manifest_policy, str):
        raise TypeError(f"{context} `manifest_policy` must be a string")
    if manifest_policy not in _NEXUS_DA_MANIFEST_POLICIES:
        raise ValueError(f"{context} `manifest_policy` must be `strict` or `audit`")

    confidential_compute = lane["confidential_compute"]
    if confidential_compute is not None:
        confidential_context = f"{context} `confidential_compute`"
        if not isinstance(confidential_compute, Mapping):
            raise TypeError(f"{confidential_context} must be an object or null")
        strict_exact_fields(
            confidential_compute,
            _NEXUS_CONFIDENTIAL_COMPUTE_FIELDS,
            confidential_context,
        )
        confidential = dict(confidential_compute)
        mechanism = confidential["mechanism"]
        if not isinstance(mechanism, str):
            raise TypeError(f"{confidential_context} `mechanism` must be a string")
        if mechanism not in _NEXUS_CONFIDENTIAL_MECHANISMS:
            raise ValueError(
                f"{confidential_context} `mechanism` must be `encryption` or "
                "`secret_sharing`"
            )
        key_version = confidential["key_version"]
        if type(key_version) is not int or not 0 < key_version <= 0xFFFFFFFF:
            raise ValueError(
                f"{confidential_context} `key_version` must be a positive u32"
            )
        audiences = confidential["allowed_audiences"]
        if not isinstance(audiences, list):
            raise TypeError(
                f"{confidential_context} `allowed_audiences` must be an array"
            )
        normalized_audiences: set[str] = set()
        for audience in audiences:
            if not isinstance(audience, str):
                raise TypeError(
                    f"{confidential_context} `allowed_audiences` entries must be strings"
                )
            if not audience or audience.strip() != audience:
                raise ValueError(
                    f"{confidential_context} `allowed_audiences` entries must be "
                    "non-empty and must not contain surrounding whitespace"
                )
            normalized_audiences.add(audience)
        confidential["allowed_audiences"] = sorted(normalized_audiences)
        lane["confidential_compute"] = confidential
        if storage == "full_replica":
            raise ValueError(
                f"{context} confidential compute requires `commitment_only` or "
                "`split_replica` storage"
            )

    scheduler = lane["scheduler"]
    if scheduler is not None:
        scheduler_context = f"{context} `scheduler`"
        if not isinstance(scheduler, Mapping):
            raise TypeError(f"{scheduler_context} must be an object or null")
        strict_exact_fields(scheduler, _NEXUS_LANE_SCHEDULER_FIELDS, scheduler_context)
        normalized_scheduler = dict(scheduler)
        if all(normalized_scheduler[field] is None for field in _NEXUS_LANE_SCHEDULER_FIELDS):
            raise ValueError(f"{scheduler_context} must define at least one override")
        for field_name in _NEXUS_LANE_SCHEDULER_FIELDS:
            field_value = normalized_scheduler[field_name]
            if field_value is not None and (
                type(field_value) is not int or not 0 < field_value <= 0xFFFFFFFFFFFFFFFF
            ):
                raise ValueError(
                    f"{scheduler_context} `{field_name}` must be a positive u64 or null"
                )
        lane["scheduler"] = normalized_scheduler

    settlement_buffer = lane["settlement_buffer"]
    if settlement_buffer is not None:
        settlement_context = f"{context} `settlement_buffer`"
        if not isinstance(settlement_buffer, Mapping):
            raise TypeError(f"{settlement_context} must be an object or null")
        strict_exact_fields(
            settlement_buffer,
            _NEXUS_LANE_SETTLEMENT_BUFFER_FIELDS,
            settlement_context,
        )
        normalized_settlement = dict(settlement_buffer)
        normalized_settlement["account_id"] = _strict_exact_i105_account_id(
            normalized_settlement["account_id"],
            f"{settlement_context} `account_id`",
        )
        normalized_settlement["asset_definition_id"] = (
            _strict_exact_asset_definition_id(
                normalized_settlement["asset_definition_id"],
                f"{settlement_context} `asset_definition_id`",
            )
        )
        capacity = normalized_settlement["capacity"]
        try:
            exact_capacity = NumericV1Codec.decode_quantity_json(capacity)
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"{settlement_context} `capacity` must be a canonical positive XOR quantity"
            ) from error
        if exact_capacity.mantissa <= 0 or exact_capacity.scale > 9:
            raise ValueError(
                f"{settlement_context} `capacity` must be a canonical positive XOR quantity "
                "with at most nine fractional digits"
            )
        normalized_settlement["capacity"] = str(exact_capacity)
        lane["settlement_buffer"] = normalized_settlement

    metadata = lane["metadata"]
    if not isinstance(metadata, Mapping):
        raise TypeError(f"{context} `metadata` must be an object of string values")
    normalized_metadata: dict[str, str] = {}
    for key, metadata_value in metadata.items():
        if not isinstance(key, str):
            raise TypeError(f"{context} `metadata` keys must be strings")
        if not isinstance(metadata_value, str):
            raise TypeError(f"{context} `metadata.{key}` must be a string")
        if key == "da_shard_id":
            raise ValueError(
                f"{context} `metadata.da_shard_id` is retired; use the typed `shard_id` field"
            )
        if (
            key in _NEXUS_RETIRED_FUNCTIONAL_METADATA_KEYS
            or key.startswith("confidential_")
            or key.startswith("scheduler.")
            or key.startswith("settlement.buffer_")
        ):
            raise ValueError(
                f"{context} `metadata.{key}` is retired; use the typed lane policy fields"
            )
        normalized_metadata[key] = metadata_value
    lane["metadata"] = normalized_metadata
    return lane


class NexusAppError(RuntimeError):
    """Typed error raised by :class:`NexusAppClient`."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class NexusAppConfig:
    """Static configuration for a Nexus app facade instance."""

    network_id: NetworkId
    account_chain_discriminant: int
    authority: Optional[str] = None
    base_url: Optional[str] = None
    node: Optional[str] = None
    signing_public_key: Optional[bytes] = None
    app_metadata: Optional[Mapping[str, Any]] = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "network_id",
            _require_network_id(self.network_id, "NexusAppConfig.network_id"),
        )
        object.__setattr__(
            self,
            "account_chain_discriminant",
            normalize_i105_discriminant(
                self.account_chain_discriminant,
                "NexusAppConfig.account_chain_discriminant",
            ),
        )


@dataclass(frozen=True)
class NexusConnectOptions:
    """Options used to create a Connect app session."""

    node: Optional[str] = None


@dataclass(frozen=True)
class NexusConnectSession:
    """Registered Connect session and wallet launch metadata."""

    sid: str
    network_id: NetworkId
    app_public_key: bytes
    nonce: bytes
    wallet_launch_uri: str
    app_launch_uri: Optional[str] = None
    token_app: Optional[str] = None
    token_wallet: Optional[str] = None
    token_management: Optional[str] = None
    token_relay: Optional[str] = None
    approved_account: Optional[str] = None
    signing_public_key: Optional[bytes] = None
    app_session: Any = None

    def __post_init__(self) -> None:
        network_id = _require_network_id(
            self.network_id, "NexusConnectSession.network_id"
        )
        app_public_key = _bytes(
            self.app_public_key, "NexusConnectSession.app_public_key"
        )
        nonce = _bytes(self.nonce, "NexusConnectSession.nonce")
        if len(app_public_key) != 32 or not any(app_public_key):
            raise ValueError("NexusConnectSession.app_public_key must be 32 nonzero bytes")
        if len(nonce) != 16 or not any(nonce):
            raise ValueError("NexusConnectSession.nonce must be 16 nonzero bytes")
        if not isinstance(self.sid, str) or not self.sid or self.sid != self.sid.strip():
            raise ValueError("NexusConnectSession.sid must be a non-empty exact string")
        from .connect import generate_connect_sid, parse_connect_uri

        expected = generate_connect_sid(
            network_id=network_id,
            app_public_key=app_public_key,
            nonce=nonce,
        )
        if self.sid != expected.sid_base64url:
            raise ValueError(
                "NexusConnectSession.sid does not match network_id, app_public_key, and nonce"
            )
        wallet_uri = parse_connect_uri(self.wallet_launch_uri)
        if (
            wallet_uri.sid != self.sid
            or wallet_uri.network_id != network_id
            or wallet_uri.app_public_key != app_public_key
            or wallet_uri.nonce != nonce
        ):
            raise ValueError("NexusConnectSession wallet URI substituted session identity")
        object.__setattr__(self, "network_id", network_id)
        object.__setattr__(self, "app_public_key", app_public_key)
        object.__setattr__(self, "nonce", nonce)


@dataclass(frozen=True)
class NexusApprovedAccount:
    """Wallet-approved account plus the updated approved Connect session."""

    account_id: str
    signing_public_key: bytes
    session: NexusConnectSession


@dataclass(frozen=True)
class NexusTransferInput:
    """V1 nominal-quantity asset transfer input."""

    source_asset_id: str
    quantity: QuantityLike
    destination_account_id: str
    fee_payment: Mapping[str, Any]
    authority: Optional[str] = None
    metadata: Optional[Mapping[str, Any]] = None
    creation_time_ms: Optional[int] = None
    ttl_ms: Optional[int] = None
    nonce: Optional[int] = None


@dataclass(frozen=True)
class NexusSignableTransaction:
    """Canonical transaction payload to sign with a wallet."""

    payload_bytes: bytes
    payload_hash_hex: str
    authority: str
    signing_public_key: Optional[bytes] = None
    signature_algorithm: str = "ed25519"
    native: Any = None


@dataclass(frozen=True)
class NexusTransferDraft:
    """Transfer draft with canonical signable payload."""

    input: NexusTransferInput
    signable: NexusSignableTransaction


@dataclass(frozen=True)
class NexusWalletSignature:
    """Wallet signature response."""

    signature: bytes
    algorithm: str = "ed25519"


@dataclass(frozen=True)
class NexusTransferReceipt:
    """Result returned after transaction finalization/submission."""

    signed_transaction: bytes
    signed_transaction_hash_hex: str
    submission: Any = None
    status: Any = None


class NexusConnectTransport(Protocol):
    """Connect dependency used by :class:`NexusAppClient`."""

    def start_connect(
        self,
        options: NexusConnectOptions,
        config: NexusAppConfig,
    ) -> NexusConnectSession: ...

    def await_approval(
        self,
        session: NexusConnectSession,
        config: NexusAppConfig,
    ) -> Mapping[str, Any]: ...

    def request_signature(
        self,
        session: NexusConnectSession,
        signable: NexusSignableTransaction,
        config: NexusAppConfig,
    ) -> Union[NexusWalletSignature, Mapping[str, Any], BytesLike]: ...


@dataclass
class _DefaultConnectState:
    preview: Any
    torii_client: Any
    ws: Any = None
    connect_session: Any = None
    approved_account: Optional[str] = None
    signing_public_key: Optional[bytes] = None
    approval_started: bool = False


def _bytes(value: BytesLike, field: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        raw = value[2:] if value.startswith("0x") else value
        if len(raw) % 2 == 0:
            try:
                return bytes.fromhex(raw)
            except ValueError:
                pass
    raise TypeError(f"{field} must be bytes or a hex string")


def _payload_hash_hex(payload_bytes: bytes) -> str:
    return hash_blake2b_32(payload_bytes).hex()


def _exact_hash_hex(value: Any, field: str, error_code: str) -> str:
    if not isinstance(value, str):
        raise NexusAppError(
            error_code,
            f"{field} must be exactly 64 lowercase hexadecimal characters",
        )
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise NexusAppError(
            error_code,
            f"{field} must be exactly 64 lowercase hexadecimal characters",
        )
    return value


def _exact_transaction_hash_hex(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
        or value[-1] not in "13579bdf"
    ):
        raise NexusAppError(
            "invalid_transaction_hash",
            f"{field} must match [0-9a-f]{{63}}[13579bdf] with the canonical Iroha HashOf marker",
        )
    return value


_TRANSACTION_WAIT_OPTION_FIELDS = frozenset(
    {
        "interval",
        "timeout",
        "max_attempts",
        "on_status",
    }
)


def _transaction_wait_options(value: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise NexusAppError("invalid_wait_options", "wait_options must be a mapping")
    unsupported = [key for key in value if key not in _TRANSACTION_WAIT_OPTION_FIELDS]
    if unsupported:
        raise NexusAppError(
            "invalid_wait_options",
            "wait_options contains unsupported fields: "
            + ", ".join(sorted(repr(key) for key in unsupported)),
        )
    return dict(value)


def _exact_account_id_for_chain(
    account_id: Any,
    expected_chain_discriminant: int,
    context: str,
) -> str:
    if (
        not isinstance(account_id, str)
        or not account_id
        or account_id.strip() != account_id
        or "@" in account_id
    ):
        raise NexusAppError(
            "invalid_account_id",
            f"{context} must be an exact canonical I105 account for chain discriminant "
            f"{expected_chain_discriminant}",
        )
    try:
        address = AccountAddress.from_i105(
            account_id,
            expected_discriminant=expected_chain_discriminant,
        )
        if address.to_i105(expected_chain_discriminant) != account_id:
            raise AccountAddressError("noncanonical I105 spelling")
    except AccountAddressError as exc:
        raise NexusAppError(
            "invalid_account_id",
            f"{context} must be an exact canonical I105 account for chain discriminant "
            f"{expected_chain_discriminant}",
        ) from exc
    return account_id


def _source_asset_owner(source_asset_id: Any) -> str:
    if not isinstance(source_asset_id, str):
        raise NexusAppError(
            "invalid_account_id",
            "transfer source asset must contain one canonical owner account",
        )
    parts = source_asset_id.split("#")
    if len(parts) not in (2, 3) or not parts[1]:
        raise NexusAppError(
            "invalid_account_id",
            "transfer source asset must contain one canonical owner account",
        )
    if len(parts) == 3:
        prefix = "dataspace:"
        scope = parts[2]
        digits = scope[len(prefix) :] if scope.startswith(prefix) else ""
        if (
            not digits
            or not digits.isascii()
            or not digits.isdecimal()
            or (len(digits) > 1 and digits[0] == "0")
            or int(digits) > (1 << 64) - 1
        ):
            raise NexusAppError(
                "invalid_account_id",
                "transfer source asset scope must be a canonical dataspace:<u64> suffix",
            )
    return parts[1]


def _account_ed25519_public_key(
    account_id: str,
    expected_chain_discriminant: int,
) -> bytes:
    from .address import AccountAddress, ControllerPayload, CurveId

    try:
        exact = _exact_account_id_for_chain(
            account_id,
            expected_chain_discriminant,
            "account",
        )
        address = AccountAddress.from_i105(
            exact,
            expected_discriminant=expected_chain_discriminant,
        )
    except Exception as exc:
        raise NexusAppError(
            "missing_signing_public_key",
            "approved account must be a canonical single-key Ed25519 I105 account",
        ) from exc
    controller = address.controller
    if (
        not isinstance(controller, ControllerPayload)
        or controller.tag != ControllerPayload.CONTROLLER_SINGLE_KEY_TAG
        or controller.curve != CurveId.ED25519
    ):
        raise NexusAppError(
            "missing_signing_public_key",
            "approved account must be a canonical single-key Ed25519 I105 account",
        )
    public_key = bytes(controller.public_key)
    return _validate_ed25519_public_key(public_key, "approved Ed25519 public key")


def _validate_ed25519_public_key(value: BytesLike, field: str) -> bytes:
    public_key = _bytes(value, field)
    if len(public_key) != 32:
        raise NexusAppError("invalid_signing_public_key", f"{field} must be 32 bytes")
    return public_key


def _resolve_signing_public_key(
    authority: str,
    explicit: Optional[BytesLike],
    expected_chain_discriminant: int,
) -> bytes:
    return _require_account_signing_key(
        authority,
        expected_chain_discriminant,
        ("signing_public_key", explicit),
    )


def _require_account_signing_key(
    authority: str,
    expected_chain_discriminant: int,
    *sources: tuple[str, Optional[BytesLike]],
) -> bytes:
    account_public_key = _account_ed25519_public_key(
        authority,
        expected_chain_discriminant,
    )
    for field, value in sources:
        if value is None:
            continue
        supplied = _validate_ed25519_public_key(value, field)
        if supplied != account_public_key:
            raise NexusAppError(
                "approval_account_mismatch",
                f"{field} does not control the approved/authority account",
            )
    return account_public_key


def _normalize_algorithm(algorithm: Any) -> str:
    if algorithm is None:
        return "ed25519"
    if not isinstance(algorithm, str):
        raise NexusAppError(
            "unsupported_signature_algorithm",
            f"unsupported signature algorithm {algorithm}",
        )
    if not algorithm or any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in algorithm):
        raise NexusAppError(
            "unsupported_signature_algorithm",
            f"unsupported signature algorithm {algorithm}",
        )
    if algorithm != algorithm.strip():
        raise NexusAppError(
            "unsupported_signature_algorithm",
            f"unsupported signature algorithm {algorithm}",
        )
    if algorithm != "ed25519":
        raise NexusAppError(
            "unsupported_signature_algorithm",
            f"unsupported signature algorithm {algorithm}",
        )
    return "ed25519"


_RETIRED_SUBMISSION_HASH_FIELDS = frozenset(
    {
        "hash_hex",
        "hashHex",
        "transaction_hash_hex",
        "transactionHashHex",
        "entrypoint_hash_hex",
        "entrypointHashHex",
        "transaction_hash",
        "transactionHash",
        "signed_transaction_hash_hex",
        "signedTransactionHashHex",
        "signedTransactionHash",
        "entrypointHash",
        "hash",
        "tx_hash",
        "txHash",
    }
)


def _submission_hash_hex(submission: Any) -> Optional[str]:
    if submission is None:
        return None
    if not isinstance(submission, Mapping):
        raise NexusAppError(
            "invalid_transaction_hash",
            "Torii submission response must be an exact mapping",
        )
    retired_root = sorted(
        set(submission)
        & (
            _RETIRED_SUBMISSION_HASH_FIELDS
            | {
                "entrypoint_hash",
                "signed_transaction_hash",
                "signedTransactionHash",
            }
        )
    )
    if retired_root:
        raise NexusAppError(
            "invalid_transaction_hash",
            f"Torii submission response contains noncanonical root hash field {retired_root[0]}",
        )
    payload = submission.get("payload")
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise NexusAppError(
            "invalid_transaction_hash",
            "Torii submission response.payload must be an exact mapping",
        )
    retired_payload = sorted(set(payload) & _RETIRED_SUBMISSION_HASH_FIELDS)
    if retired_payload:
        raise NexusAppError(
            "invalid_transaction_hash",
            f"Torii submission response.payload contains retired hash field {retired_payload[0]}",
        )
    signed_transaction_hash = payload.get("signed_transaction_hash")
    if signed_transaction_hash is not None:
        _exact_transaction_hash_hex(
            signed_transaction_hash,
            "submission.payload.signed_transaction_hash",
        )
    entrypoint_hash = payload.get("entrypoint_hash")
    if entrypoint_hash is None:
        return None
    return _exact_transaction_hash_hex(
        entrypoint_hash,
        "submission.payload.entrypoint_hash",
    )


def _normalize_signature(value: Union[NexusWalletSignature, Mapping[str, Any], BytesLike]) -> NexusWalletSignature:
    if isinstance(value, NexusWalletSignature):
        signature = value
    elif isinstance(value, Mapping):
        algorithm = _normalize_algorithm(value.get("algorithm", "ed25519"))
        payload = value.get("signature", value.get("bytes", value.get("payload")))
        signature = NexusWalletSignature(_bytes(payload, "signature"), algorithm)
    else:
        signature = NexusWalletSignature(_bytes(value, "signature"), "ed25519")
    _normalize_algorithm(signature.algorithm)
    if len(signature.signature) != 64:
        raise NexusAppError(
            "invalid_signature",
            f"Ed25519 signature must be 64 bytes, got {len(signature.signature)}",
        )
    return NexusWalletSignature(signature.signature, "ed25519")


def _validate_ed25519_signature_for_payload(
    public_key: bytes,
    payload_bytes: bytes,
    signature: bytes,
) -> None:
    from .crypto import verify_ed25519

    try:
        verified = verify_ed25519(public_key, hash_blake2b_32(payload_bytes), signature)
    except Exception as exc:
        raise NexusAppError(
            "invalid_signature",
            "Ed25519 signature does not verify for the signable payload",
        ) from exc
    if not verified:
        raise NexusAppError(
            "invalid_signature",
            "Ed25519 signature does not verify for the signable payload",
        )


class DefaultNexusTransactionCodec:
    """Default transaction codec backed by the Python SDK's native Norito builder."""

    def build_transfer_payload(self, payload_input: Mapping[str, Any]) -> Mapping[str, Any]:
        from .tx import TransactionConfig, TransactionDraft

        chain_discriminant = normalize_i105_discriminant(
            payload_input["account_chain_discriminant"],
            "payload_input.account_chain_discriminant",
        )
        authority = _exact_account_id_for_chain(
            payload_input["authority"],
            chain_discriminant,
            "transfer authority",
        )
        destination = _exact_account_id_for_chain(
            payload_input.get(
                "destination_account_id",
                payload_input.get("destinationAccountId"),
            ),
            chain_discriminant,
            "transfer destination account",
        )
        source_asset_id = str(
            payload_input.get("source_asset_id", payload_input.get("sourceAssetId"))
        )
        _exact_account_id_for_chain(
            _source_asset_owner(source_asset_id),
            chain_discriminant,
            "transfer source asset owner",
        )
        draft = TransactionDraft(
            TransactionConfig(
                network_id=_require_network_id(payload_input["network_id"]),
                authority=authority,
                chain_discriminant=chain_discriminant,
                fee_payment=payload_input["fee_payment"],
                creation_time_ms=payload_input.get("creation_time_ms"),
                ttl_ms=payload_input.get("ttl_ms"),
                nonce=payload_input.get("nonce"),
                metadata=payload_input.get("metadata"),
            )
        )
        draft.transfer_asset_quantity(
            source_asset_id,
            payload_input["quantity"],
            destination,
        )
        builder = draft.to_builder()
        return {
            "payload_bytes": bytes(builder.encode_payload()),
            "payload_hash_hex": builder.payload_hash_hex(),
            "native": builder,
        }

    def payload_hash_hex(self, payload_bytes: BytesLike) -> str:
        return _payload_hash_hex(_bytes(payload_bytes, "payload_bytes"))

    def finalize_signed_transaction(
        self,
        signable: NexusSignableTransaction,
        signature: NexusWalletSignature,
        signing_public_key: bytes,
    ) -> Mapping[str, Any]:
        _ = signing_public_key
        builder = signable.native
        if builder is None or not hasattr(builder, "build_with_signature"):
            raise NexusAppError(
                "transaction_codec_unavailable",
                "native transaction builder is required to finalize a wallet-signed transaction",
            )
        try:
            envelope = builder.build_with_signature(signature.signature)
        except Exception as exc:  # pragma: no cover - native error formatting
            raise NexusAppError("invalid_signature", str(exc)) from exc
        return {
            "signed_transaction": bytes(envelope.signed_transaction_versioned),
            "hash_hex": envelope.hash_hex(),
            "envelope": envelope,
        }


class DefaultNexusConnectTransport:
    """Default app-role Connect transport using `ToriiClient` and Connect frame helpers."""

    def start_connect(
        self,
        options: NexusConnectOptions,
        config: NexusAppConfig,
    ) -> NexusConnectSession:
        if not config.base_url:
            raise NexusAppError("connect_transport_unavailable", "config.base_url is required for Connect")
        from .client import ToriiClient
        from .connect import bootstrap_connect_preview_session

        torii_client = ToriiClient(config.base_url)
        bootstrap = bootstrap_connect_preview_session(
            torii_client,
            network_id=config.network_id,
            node=options.node or config.node,
            register=True,
        )
        if bootstrap.tokens is None:
            raise NexusAppError("connect_transport_unavailable", "Connect session registration failed")
        state = _DefaultConnectState(preview=bootstrap.preview, torii_client=torii_client)
        return NexusConnectSession(
            sid=bootstrap.preview.sid_base64url,
            network_id=bootstrap.preview.network_id,
            app_public_key=bootstrap.preview.app_key_pair.public_key,
            nonce=bootstrap.preview.nonce,
            wallet_launch_uri=bootstrap.preview.wallet_uri,
            app_launch_uri=bootstrap.preview.app_uri,
            token_app=bootstrap.tokens.app,
            token_wallet=bootstrap.tokens.wallet,
            token_management=bootstrap.tokens.management,
            token_relay=bootstrap.tokens.relay,
            app_session=state,
        )

    def await_approval(
        self,
        session: NexusConnectSession,
        config: NexusAppConfig,
    ) -> Mapping[str, Any]:
        state = self._state(session)
        from .connect import (
            ConnectControlApprove,
            ConnectControlOpen,
            ConnectDirection,
            ConnectFrame,
            ConnectPermissions,
            ConnectSession,
            ConnectSessionKeys,
            generate_connect_sid,
            verify_connect_approval_signature,
        )

        if state.approval_started or state.connect_session is not None:
            raise NexusAppError(
                "connect_approval_replayed",
                "Connect approval can be requested only once for a session",
            )
        if config.network_id != state.preview.network_id:
            raise NexusAppError(
                "connect_identity_substituted",
                "Connect Open network_id differs from the registered exact session",
            )
        expected_sid = generate_connect_sid(
            network_id=state.preview.network_id,
            app_public_key=state.preview.app_key_pair.public_key,
            nonce=state.preview.nonce,
        )
        if (
            session.sid != state.preview.sid_base64url
            or expected_sid.sid_bytes != state.preview.sid_bytes
        ):
            raise NexusAppError(
                "connect_identity_substituted",
                "Connect session identity was substituted before Open",
            )
        state.approval_started = True

        ws = self._websocket(session, state)
        permissions = ConnectPermissions(methods=["SIGN_REQUEST_TX"], events=[])
        metadata = self._metadata(config)
        open_frame = ConnectFrame(
            sid=state.preview.sid_bytes,
            direction=ConnectDirection.APP_TO_WALLET,
            sequence=1,
            control=ConnectControlOpen(
                app_public_key=state.preview.app_key_pair.public_key,
                network_id=config.network_id,
                permissions=permissions,
                metadata=metadata,
            ),
        )
        self._send_binary(ws, open_frame.to_bytes())

        while True:
            frame = ConnectFrame.from_bytes(self._recv_bytes(ws))
            if (
                frame.sid != state.preview.sid_bytes
                or frame.direction != ConnectDirection.WALLET_TO_APP
                or frame.sequence != 1
            ):
                raise NexusAppError(
                    "connect_approval_replayed",
                    "Connect approval must be the first wallet frame for this exact session",
                )
            if not isinstance(frame.control, ConnectControlApprove):
                raise NexusAppError(
                    "connect_approval_invalid",
                    "The first wallet frame must be exactly one approval",
                )
            approval = frame.control
            try:
                _normalize_algorithm(approval.algorithm)
            except NexusAppError as exc:
                raise NexusAppError(
                    "unsupported_signature_algorithm",
                    f"unsupported Connect approval signature algorithm {approval.algorithm}",
                ) from exc
            account_public_key = _account_ed25519_public_key(
                approval.account_id,
                config.account_chain_discriminant,
            )
            if config.signing_public_key is not None:
                configured_public_key = _validate_ed25519_public_key(
                    config.signing_public_key,
                    "config.signing_public_key",
                )
                if configured_public_key != account_public_key:
                    raise NexusAppError(
                        "approval_account_mismatch",
                        "configured signing key does not control the approved account",
                    )
            signing_public_key = account_public_key
            if not session.token_relay:
                raise NexusAppError(
                    "connect_approval_invalid",
                    "Connect approval requires the session relay binding",
                )
            try:
                verified = verify_connect_approval_signature(
                    network_id=config.network_id,
                    sid=state.preview.sid_bytes,
                    app_public_key=state.preview.app_key_pair.public_key,
                    nonce=state.preview.nonce,
                    wallet_public_key=approval.wallet_public_key,
                    account_id=approval.account_id,
                    permissions=approval.permissions,
                    proof=approval.proof,
                    relay_token=session.token_relay,
                    algorithm=approval.algorithm,
                    signature=approval.signature,
                )
            except Exception as exc:
                raise NexusAppError(
                    "connect_approval_invalid",
                    "Connect approval verification inputs are invalid",
                ) from exc
            if not verified:
                raise NexusAppError(
                    "connect_approval_invalid",
                    "Connect approval signature verification failed",
                )
            keys = ConnectSessionKeys.derive(
                local_private_key=state.preview.app_key_pair.private_key,
                peer_public_key=approval.wallet_public_key,
                sid=state.preview.sid_bytes,
            )
            state.connect_session = ConnectSession(sid=state.preview.sid_bytes, keys=keys)
            state.approved_account = approval.account_id
            state.signing_public_key = bytes(signing_public_key)
            return {
                "account_id": approval.account_id,
                "signing_public_key": bytes(signing_public_key),
            }

    def request_signature(
        self,
        session: NexusConnectSession,
        signable: NexusSignableTransaction,
        config: NexusAppConfig,
    ) -> NexusWalletSignature:
        _ = config
        state = self._state(session)
        if state.connect_session is None:
            raise NexusAppError(
                "connect_approval_required",
                "await_approval must complete before requesting a wallet signature",
            )
        from .connect import (
            ConnectSignRequestTxPayload,
            ConnectSignResultErrPayload,
            ConnectSignResultOkPayload,
        )

        ws = self._websocket(session, state)
        request = state.connect_session.encrypt_app_to_wallet(
            ConnectSignRequestTxPayload(tx_bytes=signable.payload_bytes)
        )
        self._send_binary(ws, request.to_bytes())

        while True:
            envelope = state.connect_session.decrypt(self._recv_bytes(ws))
            if isinstance(envelope.payload, ConnectSignResultOkPayload):
                return NexusWalletSignature(
                    signature=bytes(envelope.payload.signature),
                    algorithm=envelope.payload.algorithm,
                )
            if isinstance(envelope.payload, ConnectSignResultErrPayload):
                raise NexusAppError("connect_signature_rejected", envelope.payload.message)

    @staticmethod
    def _state(session: NexusConnectSession) -> _DefaultConnectState:
        if not isinstance(session.app_session, _DefaultConnectState):
            raise NexusAppError(
                "connect_transport_unavailable",
                "session was not created by DefaultNexusConnectTransport",
            )
        return session.app_session

    @staticmethod
    def _metadata(config: NexusAppConfig) -> Any:
        if not config.app_metadata:
            return None
        from .connect import ConnectAppMetadata

        return ConnectAppMetadata.from_dict(dict(config.app_metadata))

    @staticmethod
    def _websocket(session: NexusConnectSession, state: _DefaultConnectState) -> Any:
        if state.ws is None:
            if not session.token_app:
                raise NexusAppError("connect_transport_unavailable", "session token_app is missing")
            state.ws = state.torii_client.connect_websocket(session.sid, "app", session.token_app)
        return state.ws

    @staticmethod
    def _send_binary(ws: Any, payload: bytes) -> None:
        if hasattr(ws, "send_binary"):
            ws.send_binary(payload)
        else:
            ws.send(payload)

    @staticmethod
    def _recv_bytes(ws: Any) -> bytes:
        message = ws.recv()
        if isinstance(message, bytes):
            return message
        if isinstance(message, bytearray):
            return bytes(message)
        if isinstance(message, memoryview):
            return message.tobytes()
        if isinstance(message, str):
            return bytes.fromhex(message)
        raise TypeError(f"unsupported Connect WebSocket message type {type(message)!r}")


class NexusAppClient:
    """App-developer-friendly facade over Connect, transaction signing, and Torii."""

    def __init__(
        self,
        config: NexusAppConfig,
        *,
        connect_transport: Optional[NexusConnectTransport] = None,
        transaction_codec: Any = None,
        torii_client: Any = None,
    ) -> None:
        self.config = config
        self.connect_transport = connect_transport or (
            DefaultNexusConnectTransport() if config.base_url else None
        )
        self.transaction_codec = transaction_codec or DefaultNexusTransactionCodec()
        if torii_client is None and config.base_url:
            from .client import ToriiClient

            torii_client = ToriiClient(config.base_url)
        self.torii_client = torii_client

    def start_connect(self, options: Optional[NexusConnectOptions] = None) -> NexusConnectSession:
        """Create a Connect app session and return wallet launch metadata."""

        if self.connect_transport is None:
            raise NexusAppError("connect_transport_unavailable", "Connect transport is required")
        session = self.connect_transport.start_connect(
            options or NexusConnectOptions(), self.config
        )
        if not isinstance(session, NexusConnectSession):
            raise NexusAppError(
                "connect_identity_substituted",
                "Connect transport returned an invalid session",
            )
        if session.network_id != self.config.network_id:
            raise NexusAppError(
                "connect_identity_substituted",
                "Connect transport substituted the configured exact NetworkId",
            )
        return session

    def await_approval(self, session: NexusConnectSession) -> NexusApprovedAccount:
        """Wait for wallet approval and return the approved account plus updated session."""

        if self.connect_transport is None:
            raise NexusAppError("connect_transport_unavailable", "Connect transport is required")
        if not isinstance(session, NexusConnectSession) or session.network_id != self.config.network_id:
            raise NexusAppError(
                "connect_identity_substituted",
                "Connect approval session does not match the configured exact NetworkId",
            )
        approved = self.connect_transport.await_approval(session, self.config)
        if "session" in approved:
            raise NexusAppError(
                "approval_session_mismatch",
                "wallet approval must not replace the caller's Connect session",
            )
        account = approved.get("account_id")
        if not isinstance(account, str) or not account or account != account.strip():
            raise NexusAppError("approval_missing_account", "wallet approval did not include an account")
        account = _exact_account_id_for_chain(
            account,
            self.config.account_chain_discriminant,
            "wallet approval account",
        )
        for context, asserted_account in (
            ("configured authority", self.config.authority),
            ("Connect session approved account", session.approved_account),
        ):
            if asserted_account is None:
                continue
            asserted_account = _exact_account_id_for_chain(
                asserted_account,
                self.config.account_chain_discriminant,
                context,
            )
            if asserted_account != account:
                raise NexusAppError(
                    "approval_account_mismatch",
                    f"{context} does not match the wallet approval account",
                )
        signing_public_key = approved.get("signing_public_key")
        account_public_key = _require_account_signing_key(
            account,
            self.config.account_chain_discriminant,
            ("wallet approval signing_public_key", signing_public_key),
            ("Connect session signing_public_key", session.signing_public_key),
            ("config.signing_public_key", self.config.signing_public_key),
        )
        signing_public_key_bytes = account_public_key
        updated = replace(
            session,
            approved_account=account,
            signing_public_key=bytes(signing_public_key_bytes),
        )
        return NexusApprovedAccount(account, bytes(signing_public_key_bytes), updated)

    def build_transfer_draft(self, input: NexusTransferInput) -> NexusTransferDraft:
        """Build a canonical signable transfer payload."""

        from .tx import _normalize_quantity

        if self.config.authority is not None:
            _exact_account_id_for_chain(
                self.config.authority,
                self.config.account_chain_discriminant,
                "configured authority",
            )
        authority = input.authority or self.config.authority
        if not authority:
            raise NexusAppError("missing_authority", "transfer authority is required")
        authority = _exact_account_id_for_chain(
            authority,
            self.config.account_chain_discriminant,
            "transfer authority",
        )
        destination = _exact_account_id_for_chain(
            input.destination_account_id,
            self.config.account_chain_discriminant,
            "transfer destination account",
        )
        _exact_account_id_for_chain(
            _source_asset_owner(input.source_asset_id),
            self.config.account_chain_discriminant,
            "transfer source asset owner",
        )
        if self.transaction_codec is None or not hasattr(self.transaction_codec, "build_transfer_payload"):
            raise NexusAppError(
                "transaction_codec_unavailable",
                "transaction codec with build_transfer_payload is required",
            )
        try:
            quantity = _normalize_quantity(input.quantity)
        except (TypeError, ValueError) as exc:
            raise NexusAppError("invalid_quantity", str(exc)) from exc
        payload_input = {
            "network_id": self.config.network_id,
            "account_chain_discriminant": self.config.account_chain_discriminant,
            "authority": authority,
            "source_asset_id": input.source_asset_id,
            "quantity": quantity,
            "destination_account_id": destination,
            "fee_payment": input.fee_payment,
            "metadata": input.metadata,
            "creation_time_ms": input.creation_time_ms,
            "ttl_ms": input.ttl_ms,
            "nonce": input.nonce,
        }
        signing_public_key = _resolve_signing_public_key(
            authority,
            self.config.signing_public_key,
            self.config.account_chain_discriminant,
        )
        payload_result = self.transaction_codec.build_transfer_payload(payload_input)
        if isinstance(payload_result, Mapping):
            payload_bytes = _bytes(
                payload_result.get("payload_bytes", payload_result.get("payloadBytes")),
                "payload_bytes",
            )
            computed_payload_hash_hex = _payload_hash_hex(payload_bytes)
            snake_hash = payload_result.get("payload_hash_hex")
            camel_hash = payload_result.get("payloadHashHex")
            if snake_hash is not None and camel_hash is not None and snake_hash != camel_hash:
                raise NexusAppError(
                    "invalid_payload_hash",
                    "transaction codec returned conflicting payload_hash_hex and payloadHashHex values",
                )
            supplied_hash = snake_hash if snake_hash is not None else camel_hash
            payload_hash_hex = (
                computed_payload_hash_hex
                if supplied_hash is None
                else _exact_hash_hex(
                    supplied_hash,
                    "transaction codec payload_hash_hex",
                    "invalid_payload_hash",
                )
            )
            if payload_hash_hex != computed_payload_hash_hex:
                raise NexusAppError(
                    "payload_hash_mismatch",
                    "transaction codec payload_hash_hex does not match payload_bytes",
                )
            native = payload_result.get("native")
        else:
            payload_bytes = _bytes(payload_result, "payload_bytes")
            payload_hash_hex = _payload_hash_hex(payload_bytes)
            native = getattr(payload_result, "native", None)
        signable = NexusSignableTransaction(
            payload_bytes=payload_bytes,
            payload_hash_hex=payload_hash_hex,
            authority=authority,
            signing_public_key=signing_public_key,
            native=native,
        )
        return NexusTransferDraft(
            replace(input, authority=authority, quantity=quantity),
            signable,
        )

    def request_signature(
        self,
        session: NexusConnectSession,
        signable: NexusSignableTransaction,
    ) -> NexusWalletSignature:
        """Request a wallet signature for the canonical transaction payload."""

        if self.connect_transport is None:
            raise NexusAppError("connect_transport_unavailable", "Connect transport is required")
        _exact_account_id_for_chain(
            signable.authority,
            self.config.account_chain_discriminant,
            "signable authority",
        )
        if self.config.authority is not None:
            _exact_account_id_for_chain(
                self.config.authority,
                self.config.account_chain_discriminant,
                "configured authority",
            )
        if session.approved_account is not None:
            _exact_account_id_for_chain(
                session.approved_account,
                self.config.account_chain_discriminant,
                "Connect session approved account",
            )
        for context, asserted_account in (
            ("configured authority", self.config.authority),
            ("Connect session approved account", session.approved_account),
        ):
            if asserted_account is not None and asserted_account != signable.authority:
                raise NexusAppError(
                    "approval_account_mismatch",
                    f"{context} does not match the signable authority",
                )
        _require_account_signing_key(
            signable.authority,
            self.config.account_chain_discriminant,
            ("signable.signing_public_key", signable.signing_public_key),
            ("Connect session signing_public_key", session.signing_public_key),
            ("config.signing_public_key", self.config.signing_public_key),
        )
        _normalize_algorithm(signable.signature_algorithm)
        response = self.connect_transport.request_signature(session, signable, self.config)
        return _normalize_signature(response)

    def finalize_and_submit(
        self,
        signable: NexusSignableTransaction,
        signature: Union[NexusWalletSignature, Mapping[str, Any], BytesLike],
        *,
        wait: bool = True,
        wait_options: Optional[Mapping[str, Any]] = None,
    ) -> NexusTransferReceipt:
        """Finalize, submit, and optionally wait for status.

        Custom codecs must return a mapping containing the signed transaction and its exact
        canonical 32-byte transaction hash matching ``[0-9a-f]{63}[13579bdf]``; the final odd
        nibble is the Iroha ``HashOf`` marker. The SDK cannot infer the hash domain from opaque bare
        or versioned signed bytes and therefore fails closed when the hash is absent.
        """

        options = _transaction_wait_options(wait_options)
        _normalize_algorithm(signable.signature_algorithm)
        normalized = _normalize_signature(signature)
        if self.transaction_codec is None or not hasattr(self.transaction_codec, "finalize_signed_transaction"):
            raise NexusAppError(
                "transaction_codec_unavailable",
                "transaction codec with finalize_signed_transaction is required",
            )
        signing_public_key = _require_account_signing_key(
            signable.authority,
            self.config.account_chain_discriminant,
            ("signable.signing_public_key", signable.signing_public_key),
            ("config.signing_public_key", self.config.signing_public_key),
        )
        _validate_ed25519_signature_for_payload(
            signing_public_key,
            signable.payload_bytes,
            normalized.signature,
        )
        finalized = self.transaction_codec.finalize_signed_transaction(
            signable,
            normalized,
            signing_public_key,
        )
        if not isinstance(finalized, Mapping):
            raise NexusAppError(
                "invalid_transaction_hash",
                "transaction finalizer must return a mapping with signed_transaction and hash_hex",
            )
        required_finalized_fields = {"signed_transaction", "hash_hex"}
        unknown_finalized_fields = set(finalized) - (required_finalized_fields | {"envelope"})
        if not required_finalized_fields.issubset(finalized) or unknown_finalized_fields:
            raise NexusAppError(
                "invalid_transaction_hash",
                "transaction finalizer must return only signed_transaction, hash_hex, and optional envelope",
            )
        signed_transaction = _bytes(finalized["signed_transaction"], "signed_transaction")
        hash_hex = _exact_transaction_hash_hex(
            finalized["hash_hex"],
            "transaction finalizer hash_hex",
        )

        submission = None
        status = None
        if self.torii_client is not None:
            try:
                submission = self.torii_client.submit_transaction(signed_transaction)
            except Exception as exc:  # pragma: no cover - transport dependent
                raise NexusAppError("submit_failed", str(exc)) from exc
            submitted_hash_hex = _submission_hash_hex(submission)
            if submitted_hash_hex and submitted_hash_hex != hash_hex:
                raise NexusAppError(
                    "transaction_hash_mismatch",
                    f"Torii returned transaction hash {submitted_hash_hex} but local hash is {hash_hex}",
                )
            if wait and hasattr(self.torii_client, "wait_for_transaction_status"):
                try:
                    status = self.torii_client.wait_for_transaction_status(hash_hex, **options)
                except Exception as exc:  # pragma: no cover - transport dependent
                    raise NexusAppError("status_wait_failed", str(exc)) from exc
        else:
            raise NexusAppError(
                "torii_client_unavailable",
                "Torii client is required to submit the signed transaction",
            )

        return NexusTransferReceipt(
            signed_transaction=signed_transaction,
            signed_transaction_hash_hex=hash_hex,
            submission=submission,
            status=status,
        )

    def transfer_with_wallet(
        self,
        session: NexusConnectSession,
        input: NexusTransferInput,
        *,
        wait: bool = True,
        wait_options: Optional[Mapping[str, Any]] = None,
    ) -> NexusTransferReceipt:
        """One-call transfer wrapper over draft, signature, finalization, submit, and wait."""

        for context, account in (
            ("Connect session approved account", session.approved_account),
            ("transfer authority", input.authority),
            ("configured authority", self.config.authority),
        ):
            if account is not None:
                _exact_account_id_for_chain(
                    account,
                    self.config.account_chain_discriminant,
                    context,
                )
        authority = input.authority or session.approved_account or self.config.authority
        if not authority:
            raise NexusAppError("missing_authority", "transfer authority is required")
        if session.approved_account and input.authority and session.approved_account != input.authority:
            raise NexusAppError(
                "approval_account_mismatch",
                "transfer authority does not match the approved wallet account",
            )
        draft = self.build_transfer_draft(replace(input, authority=authority))
        signable = replace(
            draft.signable,
            signing_public_key=session.signing_public_key or draft.signable.signing_public_key,
        )
        signature = self.request_signature(session, signable)
        return self.finalize_and_submit(
            signable,
            signature,
            wait=wait,
            wait_options=wait_options,
        )

__all__ = [
    "NexusAppClient",
    "NexusAppConfig",
    "NexusAppError",
    "NexusConnectOptions",
    "NexusConnectSession",
    "NexusApprovedAccount",
    "DefaultNexusConnectTransport",
    "DefaultNexusTransactionCodec",
    "NexusSignableTransaction",
    "NexusTransferDraft",
    "NexusTransferInput",
    "NexusTransferReceipt",
    "NexusWalletSignature",
]
