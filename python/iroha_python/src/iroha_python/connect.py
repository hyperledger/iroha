"""Connect helpers: URI builders plus frame encode/decode utilities."""

from __future__ import annotations

import base64
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Type, Union
from urllib.parse import ParseResult, parse_qs, urlencode, urlparse

from iroha_native import load_crypto_extension

from .crypto import NetworkId, _require_network_id

__all__ = [
    "ConnectUri",
    "build_connect_uri",
    "parse_connect_uri",
    "ConnectDirection",
    "ConnectRole",
    "ConnectKeyPair",
    "ConnectSid",
    "ConnectSessionInfo",
    "ConnectPermissions",
    "ConnectAppMetadata",
    "ConnectSignInProof",
    "ConnectCiphertext",
    "ConnectControlOpen",
    "ConnectControlApprove",
    "ConnectControlReject",
    "ConnectControlClose",
    "ConnectControlPing",
    "ConnectControlPong",
    "ConnectFrame",
    "ConnectSignRequestRawPayload",
    "ConnectSignRequestTxPayload",
    "ConnectSignResultOkPayload",
    "ConnectSignResultErrPayload",
    "ConnectDisplayRequestPayload",
    "ConnectEnvelope",
    "ConnectSessionKeys",
    "ConnectSessionState",
    "ConnectSession",
    "encode_connect_frame",
    "decode_connect_frame",
    "derive_connect_direction_keys",
    "build_connect_approve_preimage",
    "verify_connect_approval_signature",
    "generate_connect_keypair",
    "generate_connect_sid",
    "ConnectSessionPreview",
    "ConnectPreviewTokens",
    "ConnectPreviewBootstrapResult",
    "create_connect_session_preview",
    "bootstrap_connect_preview_session",
    "connect_public_key_from_private",
    "seal_connect_payload",
    "open_connect_payload",
]

_SID_LENGTH = 32
_NONCE_LENGTH = 16
_U16_MAX = (1 << 16) - 1
_U64_MAX = (1 << 64) - 1
_CONNECT_URI_VERSION = "1"
_CONNECT_SESSION_RESPONSE_FIELDS = frozenset(
    {
        "sid",
        "network_id",
        "app_pk",
        "nonce",
        "wallet_uri",
        "app_uri",
        "token_app",
        "token_wallet",
        "token_management",
        "token_relay",
    }
)
_CONNECT_SESSION_URI_FIELDS = frozenset(
    {"sid", "network_id", "app_pk", "nonce", "node", "v", "role", "token", "relay"}
)


def _normalize_connect_wallet_signature_algorithm(algorithm: str) -> str:
    if not isinstance(algorithm, str):
        raise TypeError("wallet signature algorithm must be a string")
    if not algorithm or any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in algorithm):
        raise ValueError("unsupported wallet signature algorithm")
    if algorithm != algorithm.strip():
        raise ValueError("unsupported wallet signature algorithm")
    normalized = algorithm.lower()
    if normalized != "ed25519":
        raise ValueError("unsupported wallet signature algorithm")
    return "ed25519"


def _require_uint(
    value: Any,
    field: str,
    *,
    maximum: int,
    positive: bool = False,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    minimum = 1 if positive else 0
    if value < minimum or value > maximum:
        qualifier = "positive " if positive else ""
        raise ValueError(f"{field} must be a {qualifier}integer no greater than {maximum}")
    return value


@dataclass(frozen=True, slots=True)
class ConnectUri:
    """Structured representation of an `iroha://connect` URI."""

    sid: str
    network_id: NetworkId
    app_public_key: bytes
    nonce: bytes
    node: Optional[str] = None
    version: int = 1


def build_connect_uri(data: ConnectUri) -> str:
    """Return a canonical `iroha://connect?...` URI."""

    if not isinstance(data, ConnectUri):
        raise TypeError("data must be a ConnectUri")
    network_id = _require_network_id(data.network_id, "network_id")
    app_public_key = _ensure_bytes(data.app_public_key, size=32, field="app_public_key")
    nonce = _ensure_bytes(data.nonce, size=16, field="nonce")
    _validate_connect_identity(
        network_id=network_id,
        sid=data.sid,
        app_public_key=app_public_key,
        nonce=nonce,
    )
    if isinstance(data.version, bool) or not isinstance(data.version, int):
        raise TypeError("version must be the integer 1")
    if data.version != 1:
        raise ValueError("Connect URI version must be exactly 1")
    query_items = {
        "sid": data.sid,
        "network_id": network_id.literal,
        "app_pk": _to_base64url(app_public_key),
        "nonce": _to_base64url(nonce),
        "v": str(data.version),
    }
    if data.node:
        query_items["node"] = data.node
    query = urlencode(query_items)
    base = "iroha://connect"
    if query:
        return f"{base}?{query}"
    return base


def parse_connect_uri(uri: str) -> ConnectUri:
    """Parse an `iroha://connect?...` URI into a :class:`ConnectUri`."""

    if not isinstance(uri, str):
        raise TypeError("uri must be a string")
    parsed: ParseResult = urlparse(uri)
    if parsed.scheme != "iroha":
        raise ValueError("URI scheme must be 'iroha'")
    path_is_connect = parsed.path in {"/connect"}
    host_is_connect = parsed.netloc == "connect" and parsed.path in {"", "/"}
    if not (path_is_connect or host_is_connect):
        raise ValueError("URI path must be '/connect'")
    if parsed.params or parsed.fragment:
        raise ValueError("Connect URI must not contain parameters or a fragment")
    params = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    retired = {"chain", "chain_id", "chainId", "genesis_hash", "genesisHash"}.intersection(
        params
    )
    if retired:
        raise ValueError("chain identity aliases are retired; provide exact network_id")
    allowed = {"sid", "network_id", "app_pk", "nonce", "node", "v"}
    unsupported = set(params).difference(allowed)
    if unsupported:
        raise ValueError(f"unsupported Connect URI parameters: {sorted(unsupported)}")
    sid = _require(_get_single(params, "sid"), "sid")
    network_id = NetworkId.parse(_require(_get_single(params, "network_id"), "network_id"))
    app_public_key = _decode_canonical_base64url(
        _require(_get_single(params, "app_pk"), "app_pk"), 32, "app_pk"
    )
    nonce = _decode_canonical_base64url(
        _require(_get_single(params, "nonce"), "nonce"), 16, "nonce"
    )
    _validate_connect_identity(
        network_id=network_id,
        sid=sid,
        app_public_key=app_public_key,
        nonce=nonce,
    )
    version_str = _require(_get_single(params, "v", default="1"), "v")
    if version_str != _CONNECT_URI_VERSION:
        raise ValueError("Connect URI version must be exactly 1")
    version = 1
    node = _get_single(params, "node", default=None)
    return ConnectUri(
        sid=sid,
        network_id=network_id,
        app_public_key=app_public_key,
        nonce=nonce,
        node=node,
        version=version,
    )


_MISSING = object()


def _get_single(
    mapping: dict[str, List[str]],
    key: str,
    default: object = _MISSING,
) -> Optional[str]:
    if key not in mapping:
        if default is _MISSING:
            raise ValueError(f"missing '{key}' query parameter")
        return default  # type: ignore[return-value]
    values = mapping[key]
    if len(values) != 1:
        raise ValueError(f"parameter '{key}' must appear exactly once")
    if not values[0]:
        raise ValueError(f"parameter '{key}' must not be empty")
    return values[0]


def _require(value: Optional[str], name: str) -> str:
    if value is None:
        raise ValueError(f"{name} must be provided")
    return value


_BytesLike = Union[bytes, bytearray, memoryview]
_CodecModule = Optional[Any]
_CODEC_MODULE: _CodecModule = None


def _require_codec_module() -> Any:
    global _CODEC_MODULE
    if _CODEC_MODULE is not None:
        return _CODEC_MODULE
    try:
        _CODEC_MODULE = load_crypto_extension()
    except Exception as exc:  # pragma: no cover - defensive
        raise RuntimeError(
            "native Connect codec unavailable; install the extension before using Connect"
        ) from exc
    return _CODEC_MODULE


def _ensure_bytes(payload: _BytesLike, *, size: Optional[int], field: str) -> bytes:
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError(f"{field} must be bytes-like")
    data = bytes(payload)
    if size is not None and len(data) != size:
        raise ValueError(f"{field} must be {size} bytes, got {len(data)}")
    return data


class ConnectDirection(str, Enum):
    """Direction of a Connect frame."""

    APP_TO_WALLET = "AppToWallet"
    WALLET_TO_APP = "WalletToApp"

    @classmethod
    def normalize(cls, value: Union["ConnectDirection", str]) -> "ConnectDirection":
        if isinstance(value, ConnectDirection):
            return value
        try:
            return ConnectDirection(value)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"invalid connect direction {value!r}") from exc


class ConnectRole(str, Enum):
    """Role responsible for a Connect control message."""

    APP = "App"
    WALLET = "Wallet"

    @classmethod
    def normalize(cls, value: Union["ConnectRole", str]) -> "ConnectRole":
        if isinstance(value, ConnectRole):
            return value
        try:
            return ConnectRole(value)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"invalid connect role {value!r}") from exc


@dataclass(frozen=True, slots=True, repr=False)
class ConnectKeyPair:
    """Ephemeral X25519 key pair used for Connect sessions."""

    private_key: bytes = dataclass_field(repr=False, compare=False)
    public_key: bytes = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "private_key",
            _ensure_bytes(self.private_key, size=32, field="private_key"),
        )
        object.__setattr__(
            self,
            "public_key",
            _ensure_bytes(self.public_key, size=32, field="public_key"),
        )
        if not any(self.private_key) or not any(self.public_key):
            raise ValueError("Connect key material must not be all zero")
        if connect_public_key_from_private(self.private_key) != self.public_key:
            raise ValueError("Connect public key does not match its private key")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(public_key_hex={self.public_key.hex()!r})"

    @classmethod
    def _from_native_result(
        cls,
        private_key: Any,
        public_key: Any,
    ) -> "ConnectKeyPair":
        """Build from one already-validated native key-generation result."""

        instance = object.__new__(cls)
        object.__setattr__(
            instance,
            "private_key",
            _ensure_bytes(private_key, size=32, field="private_key"),
        )
        object.__setattr__(
            instance,
            "public_key",
            _ensure_bytes(public_key, size=32, field="public_key"),
        )
        if not any(instance.private_key) or not any(instance.public_key):
            raise RuntimeError("native Connect key generation returned all-zero material")
        return instance


@dataclass(frozen=True, slots=True)
class ConnectSid:
    """Deterministic Connect session identifier plus helper encodings."""

    sid_bytes: bytes
    sid_base64url: str
    nonce: bytes


@dataclass(frozen=True, slots=True, repr=False)
class ConnectSessionPreview:
    """Pre-registration preview bundle used by dashboards and wallets."""

    network_id: NetworkId
    node: Optional[str]
    sid_bytes: bytes
    sid_base64url: str
    nonce: bytes
    app_key_pair: ConnectKeyPair
    wallet_uri: str
    app_uri: str

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(network_id={self.network_id!r}, "
            f"sid_base64url={self.sid_base64url!r}, node={self.node!r})"
        )


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ConnectPreviewTokens:
    """Convenience container for Torii-issued Connect session tokens."""

    wallet: str = dataclass_field(repr=False)
    app: str = dataclass_field(repr=False)
    management: str = dataclass_field(repr=False)
    relay: str = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        for name in ("wallet", "app", "management", "relay"):
            object.__setattr__(
                self,
                name,
                _canonical_connect_token(getattr(self, name), name),
            )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"


@dataclass(frozen=True, slots=True)
class ConnectPreviewBootstrapResult:
    """Return value for :func:`bootstrap_connect_preview_session`."""

    preview: ConnectSessionPreview
    session: Optional["ConnectSessionInfo"]
    tokens: Optional[ConnectPreviewTokens]


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ConnectSessionInfo:
    """Response payload returned by `ToriiClient.create_connect_session`."""

    sid: str
    network_id: NetworkId
    app_public_key: bytes
    nonce: bytes
    wallet_uri: str = dataclass_field(repr=False, compare=False)
    app_uri: str = dataclass_field(repr=False, compare=False)
    app_token: str = dataclass_field(repr=False, compare=False)
    wallet_token: str = dataclass_field(repr=False, compare=False)
    management_token: str = dataclass_field(repr=False, compare=False)
    relay_token: str = dataclass_field(repr=False, compare=False)
    expires_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        network_id = _require_network_id(self.network_id, "network_id")
        app_public_key = _ensure_bytes(
            self.app_public_key, size=32, field="app_public_key"
        )
        nonce = _ensure_bytes(self.nonce, size=16, field="nonce")
        _validate_connect_identity(
            network_id=network_id,
            sid=self.sid,
            app_public_key=app_public_key,
            nonce=nonce,
        )
        wallet_uri = _require_exact_non_empty_string(self.wallet_uri, "wallet_uri")
        app_uri = _require_exact_non_empty_string(self.app_uri, "app_uri")
        app_token = _canonical_connect_token(self.app_token, "app_token")
        wallet_token = _canonical_connect_token(self.wallet_token, "wallet_token")
        management_token = _canonical_connect_token(
            self.management_token, "management_token"
        )
        relay_token = _canonical_connect_token(self.relay_token, "relay_token")
        wallet_node = _validate_connect_session_role_uri(
            wallet_uri,
            context="wallet_uri",
            sid=self.sid,
            network_id=network_id,
            app_public_key=app_public_key,
            nonce=nonce,
            role="wallet",
            token=wallet_token,
            relay_token=relay_token,
        )
        app_node = _validate_connect_session_role_uri(
            app_uri,
            context="app_uri",
            sid=self.sid,
            network_id=network_id,
            app_public_key=app_public_key,
            nonce=nonce,
            role="app",
            token=app_token,
            relay_token=relay_token,
        )
        if wallet_node != app_node:
            raise ValueError("Connect session response URIs disagree on node")
        object.__setattr__(self, "network_id", network_id)
        object.__setattr__(self, "app_public_key", app_public_key)
        object.__setattr__(self, "nonce", nonce)
        object.__setattr__(self, "wallet_uri", wallet_uri)
        object.__setattr__(self, "app_uri", app_uri)
        object.__setattr__(self, "app_token", app_token)
        object.__setattr__(self, "wallet_token", wallet_token)
        object.__setattr__(self, "management_token", management_token)
        object.__setattr__(self, "relay_token", relay_token)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(sid={self.sid!r}, network_id={self.network_id!r}, "
            f"app_public_key_hex={self.app_public_key.hex()!r}, "
            f"expires_at={self.expires_at!r})"
        )

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any],
        *,
        session_ttl_ms: Optional[int] = None,
    ) -> "ConnectSessionInfo":
        try:
            if set(payload) != _CONNECT_SESSION_RESPONSE_FIELDS:
                missing = sorted(_CONNECT_SESSION_RESPONSE_FIELDS.difference(payload))
                unsupported = sorted(set(payload).difference(_CONNECT_SESSION_RESPONSE_FIELDS))
                raise ValueError(
                    "connect session response has an inexact field set; "
                    f"missing={missing}, unsupported={unsupported}"
                )

            def required_string(key: str) -> str:
                return _require_exact_non_empty_string(payload[key], key)

            expires_at = None
            if session_ttl_ms is not None and session_ttl_ms > 0:
                expires_at = datetime.utcnow() + timedelta(milliseconds=session_ttl_ms)
            return cls(
                sid=required_string("sid"),
                network_id=NetworkId.parse(required_string("network_id")),
                app_public_key=_decode_canonical_base64url(
                    required_string("app_pk"), 32, "app_pk"
                ),
                nonce=_decode_canonical_base64url(required_string("nonce"), 16, "nonce"),
                wallet_uri=required_string("wallet_uri"),
                app_uri=required_string("app_uri"),
                app_token=required_string("token_app"),
                wallet_token=required_string("token_wallet"),
                management_token=required_string("token_management"),
                relay_token=required_string("token_relay"),
                expires_at=expires_at,
            )
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError("connect session response is missing required fields") from exc

    def as_dict(self) -> Dict[str, str]:
        """Return the exact Torii response fields as a JSON-friendly dict."""

        return {
            "sid": self.sid,
            "network_id": self.network_id.literal,
            "app_pk": _to_base64url(self.app_public_key),
            "nonce": _to_base64url(self.nonce),
            "wallet_uri": self.wallet_uri,
            "app_uri": self.app_uri,
            "token_app": self.app_token,
            "token_wallet": self.wallet_token,
            "token_management": self.management_token,
            "token_relay": self.relay_token,
        }


def _normalize_connect_session_request(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate and normalize the exact `/v1/connect/session` request body."""

    if not isinstance(payload, Mapping):
        raise TypeError("Connect session request must be a mapping")
    body = dict(payload)
    retired = {"chain", "chain_id", "chainId", "genesis_hash", "genesisHash"}.intersection(
        body
    )
    if retired:
        raise ValueError("chain identity aliases are retired; provide exact network_id")
    required = {"sid", "network_id", "app_pk", "nonce"}
    missing = required.difference(body)
    if missing:
        raise ValueError(f"Connect session request missing required fields: {sorted(missing)}")
    unsupported = set(body).difference(required | {"node"})
    if unsupported:
        raise ValueError(f"Connect session request has unsupported fields: {sorted(unsupported)}")
    sid = _require_exact_non_empty_string(body["sid"], "sid")
    network_literal = _require_exact_non_empty_string(body["network_id"], "network_id")
    network_id = NetworkId.parse(network_literal)
    app_public_key = _decode_canonical_base64url(
        _require_exact_non_empty_string(body["app_pk"], "app_pk"), 32, "app_pk"
    )
    nonce = _decode_canonical_base64url(
        _require_exact_non_empty_string(body["nonce"], "nonce"), 16, "nonce"
    )
    _validate_connect_identity(
        network_id=network_id,
        sid=sid,
        app_public_key=app_public_key,
        nonce=nonce,
    )
    normalized: Dict[str, Any] = {
        "sid": sid,
        "network_id": network_literal,
        "app_pk": _to_base64url(app_public_key),
        "nonce": _to_base64url(nonce),
    }
    if "node" in body:
        normalized["node"] = _require_exact_non_empty_string(body["node"], "node")
    return normalized


def _ensure_connect_session_matches_request(
    session: ConnectSessionInfo,
    request: Mapping[str, Any],
) -> None:
    """Reject a Torii response that substitutes the requested session identity."""

    body = _normalize_connect_session_request(request)
    if (
        session.sid != body["sid"]
        or session.network_id.literal != body["network_id"]
        or _to_base64url(session.app_public_key) != body["app_pk"]
        or _to_base64url(session.nonce) != body["nonce"]
    ):
        raise ValueError("Torii Connect session response substituted request identity")
    expected_node = body.get("node", "")
    if _connect_session_uri_node(session.wallet_uri) != expected_node:
        raise ValueError("Torii Connect session response substituted request node")


def _canonical_connect_token(value: Any, field: str) -> str:
    token = _require_exact_non_empty_string(value, field)
    _decode_canonical_base64url(token, 32, field)
    return token


def _connect_session_uri_node(uri: str) -> str:
    params = parse_qs(urlparse(uri).query, keep_blank_values=True, strict_parsing=True)
    values = params.get("node")
    if values is None or len(values) != 1:
        raise ValueError("Connect session URI node must appear exactly once")
    return values[0]


def _validate_connect_session_role_uri(
    uri: str,
    *,
    context: str,
    sid: str,
    network_id: NetworkId,
    app_public_key: bytes,
    nonce: bytes,
    role: str,
    token: str,
    relay_token: str,
) -> str:
    parsed = urlparse(uri)
    if (
        parsed.scheme != "iroha"
        or parsed.netloc != "connect"
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.fragment
    ):
        raise ValueError(f"{context} must be an iroha://connect URI")
    params = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    if set(params) != _CONNECT_SESSION_URI_FIELDS:
        missing = sorted(_CONNECT_SESSION_URI_FIELDS.difference(params))
        unsupported = sorted(set(params).difference(_CONNECT_SESSION_URI_FIELDS))
        raise ValueError(
            f"{context} has an inexact parameter set; "
            f"missing={missing}, unsupported={unsupported}"
        )
    expected = {
        "sid": sid,
        "network_id": network_id.literal,
        "app_pk": _to_base64url(app_public_key),
        "nonce": _to_base64url(nonce),
        "v": _CONNECT_URI_VERSION,
        "role": role,
        "token": token,
        "relay": relay_token,
    }
    for field, expected_value in expected.items():
        if _get_single(params, field) != expected_value:
            raise ValueError(f"{context} substituted Connect session identity or authorization")
    return _connect_session_uri_node(uri)


def _connect_session_info_from_response(
    response: Any,
    request: Mapping[str, Any],
    session_ttl_ms: Optional[int],
) -> ConnectSessionInfo:
    """Parse a session response and retain its exact request identity binding."""

    if not isinstance(response, Mapping):
        raise ValueError("connect session response is missing or malformed")
    info = ConnectSessionInfo.from_mapping(response, session_ttl_ms=session_ttl_ms)
    _ensure_connect_session_matches_request(info, request)
    return info


@dataclass
class ConnectPermissions:
    """Requested methods/events/resources for a Connect session."""

    methods: Sequence[str]
    events: Sequence[str]
    resources: Optional[Sequence[str]] = None

    def __post_init__(self) -> None:
        self.methods = list(self.methods)
        self.events = list(self.events)
        if self.resources is not None:
            self.resources = list(self.resources)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "methods": list(self.methods),
            "events": list(self.events),
            "resources": list(self.resources) if self.resources is not None else None,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectPermissions":
        return cls(
            methods=payload.get("methods", ()),
            events=payload.get("events", ()),
            resources=payload.get("resources"),
        )


@dataclass
class ConnectAppMetadata:
    """Display metadata for applications."""

    name: str
    url: Optional[str] = None
    icon_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "url": self.url, "icon_hash": self.icon_hash}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectAppMetadata":
        return cls(
            name=payload["name"],
            url=payload.get("url"),
            icon_hash=payload.get("icon_hash"),
        )


@dataclass
class ConnectSignInProof:
    """Sign-in proof carried alongside approvals."""

    domain: str
    uri: str
    statement: str
    issued_at: str
    nonce: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "domain": self.domain,
            "uri": self.uri,
            "statement": self.statement,
            "issued_at": self.issued_at,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectSignInProof":
        return cls(
            domain=payload["domain"],
            uri=payload["uri"],
            statement=payload["statement"],
            issued_at=payload["issued_at"],
            nonce=payload["nonce"],
        )


@dataclass
class ConnectCiphertext:
    """Encrypted payload delivered after session approval."""

    direction: ConnectDirection
    aead: bytes

    def __post_init__(self) -> None:
        self.direction = ConnectDirection.normalize(self.direction)
        self.aead = bytes(self.aead)

    def to_dict(self) -> Dict[str, Any]:
        return {"direction": self.direction.value, "aead": self.aead}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectCiphertext":
        return cls(
            direction=ConnectDirection.normalize(payload["direction"]),
            aead=_ensure_bytes(payload["aead"], size=None, field="ciphertext.aead"),
        )


@dataclass
class _ConnectControlBase(ABC):
    variant: str

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Return the Connect control payload fields for this variant."""

    @property
    def endpoint_kind(self) -> str:
        """Return the lowercase variant name suitable for Torii REST endpoints."""

        return self.variant.lower()


@dataclass
class ConnectControlOpen(_ConnectControlBase):
    app_public_key: bytes
    network_id: NetworkId
    permissions: Optional[ConnectPermissions] = None
    metadata: Optional[ConnectAppMetadata] = None

    def __init__(
        self,
        *,
        app_public_key: _BytesLike,
        network_id: NetworkId,
        permissions: Optional[ConnectPermissions] = None,
        metadata: Optional[ConnectAppMetadata] = None,
    ) -> None:
        super().__init__(variant="Open")
        self.app_public_key = _ensure_bytes(app_public_key, size=32, field="app_public_key")
        if not any(self.app_public_key):
            raise ValueError("app_public_key must not be all zero")
        self.network_id = _require_network_id(network_id, "network_id")
        self.permissions = permissions
        self.metadata = metadata

    def to_dict(self) -> Dict[str, Any]:
        return {
            "app_public_key": self.app_public_key,
            "network_id": self.network_id,
            "permissions": self.permissions.to_dict() if self.permissions else None,
            "metadata": self.metadata.to_dict() if self.metadata else None,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectControlOpen":
        permissions = (
            ConnectPermissions.from_dict(payload["permissions"])
            if payload.get("permissions")
            else None
        )
        metadata = (
            ConnectAppMetadata.from_dict(payload["metadata"])
            if payload.get("metadata")
            else None
        )
        return cls(
            app_public_key=payload["app_public_key"],
            network_id=payload["network_id"],
            permissions=permissions,
            metadata=metadata,
        )


@dataclass
class ConnectControlApprove(_ConnectControlBase):
    wallet_public_key: bytes
    account_id: str
    signature: bytes
    algorithm: str = "ed25519"
    permissions: Optional[ConnectPermissions] = None
    proof: Optional[ConnectSignInProof] = None

    def __init__(
        self,
        *,
        wallet_public_key: _BytesLike,
        account_id: str,
        signature: _BytesLike,
        algorithm: str = "ed25519",
        permissions: Optional[ConnectPermissions] = None,
        proof: Optional[ConnectSignInProof] = None,
    ) -> None:
        super().__init__(variant="Approve")
        self.wallet_public_key = _ensure_bytes(
            wallet_public_key, size=32, field="wallet_public_key"
        )
        if not any(self.wallet_public_key):
            raise ValueError("wallet_public_key must not be all zero")
        self.account_id = account_id
        self.signature = _ensure_bytes(signature, size=64, field="signature")
        self.algorithm = _normalize_connect_wallet_signature_algorithm(algorithm)
        self.permissions = permissions
        self.proof = proof

    def to_dict(self) -> Dict[str, Any]:
        return {
            "wallet_public_key": self.wallet_public_key,
            "account_id": self.account_id,
            "signature": self.signature,
            "algorithm": self.algorithm,
            "permissions": self.permissions.to_dict() if self.permissions else None,
            "proof": self.proof.to_dict() if self.proof else None,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectControlApprove":
        permissions = (
            ConnectPermissions.from_dict(payload["permissions"])
            if payload.get("permissions")
            else None
        )
        proof = (
            ConnectSignInProof.from_dict(payload["proof"])
            if payload.get("proof")
            else None
        )
        return cls(
            wallet_public_key=payload["wallet_public_key"],
            account_id=payload["account_id"],
            signature=payload["signature"],
            algorithm=payload.get("algorithm", "Ed25519"),
            permissions=permissions,
            proof=proof,
        )


@dataclass
class ConnectControlReject(_ConnectControlBase):
    code: int
    code_id: str
    reason: str

    def __init__(self, *, code: int, code_id: str, reason: str) -> None:
        super().__init__(variant="Reject")
        self.code = _require_uint(code, "Reject code", maximum=_U16_MAX)
        self.code_id = _require_exact_non_empty_string(code_id, "Reject code_id")
        if not isinstance(reason, str):
            raise TypeError("Reject reason must be a string")
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "code_id": self.code_id, "reason": self.reason}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectControlReject":
        return cls(code=payload["code"], code_id=payload["code_id"], reason=payload["reason"])


@dataclass
class ConnectControlClose(_ConnectControlBase):
    role: ConnectRole
    code: int
    reason: str
    retryable: bool

    def __init__(
        self, *, role: Union[ConnectRole, str], code: int, reason: str, retryable: bool
    ) -> None:
        super().__init__(variant="Close")
        self.role = ConnectRole.normalize(role)
        self.code = _require_uint(code, "Close code", maximum=_U16_MAX)
        if not isinstance(reason, str):
            raise TypeError("Close reason must be a string")
        self.reason = reason
        if not isinstance(retryable, bool):
            raise TypeError("Close retryable must be a boolean")
        self.retryable = retryable

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role.value,
            "code": self.code,
            "reason": self.reason,
            "retryable": self.retryable,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectControlClose":
        return cls(
            role=payload["role"],
            code=payload["code"],
            reason=payload["reason"],
            retryable=payload["retryable"],
        )


@dataclass
class ConnectControlPing(_ConnectControlBase):
    nonce: int

    def __init__(self, *, nonce: int) -> None:
        super().__init__(variant="Ping")
        self.nonce = _require_uint(
            nonce,
            "Ping nonce",
            maximum=_U64_MAX,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {"nonce": self.nonce}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectControlPing":
        return cls(nonce=payload["nonce"])


@dataclass
class ConnectControlPong(_ConnectControlBase):
    nonce: int

    def __init__(self, *, nonce: int) -> None:
        super().__init__(variant="Pong")
        self.nonce = _require_uint(
            nonce,
            "Pong nonce",
            maximum=_U64_MAX,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {"nonce": self.nonce}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectControlPong":
        return cls(nonce=payload["nonce"])


ControlVariant = Union[
    ConnectControlOpen,
    ConnectControlApprove,
    ConnectControlReject,
    ConnectControlClose,
    ConnectControlPing,
    ConnectControlPong,
]

_CONTROL_CLASS_MAP: Dict[str, Type[ControlVariant]] = {
    "Open": ConnectControlOpen,
    "Approve": ConnectControlApprove,
    "Reject": ConnectControlReject,
    "Close": ConnectControlClose,
    "Ping": ConnectControlPing,
    "Pong": ConnectControlPong,
}


@dataclass
class ConnectFrame:
    """Structured representation of a Connect frame."""

    sid: bytes
    direction: ConnectDirection
    sequence: int
    control: Optional[ControlVariant] = None
    ciphertext: Optional[ConnectCiphertext] = None

    def __post_init__(self) -> None:
        self.sid = _ensure_bytes(self.sid, size=32, field="sid")
        self.direction = ConnectDirection.normalize(self.direction)
        self.sequence = _require_uint(
            self.sequence,
            "Connect frame sequence",
            maximum=_U64_MAX,
            positive=True,
        )
        if (self.control is None) == (self.ciphertext is None):
            raise ValueError("provide exactly one of `control` or `ciphertext` for a frame")
        if self.ciphertext is not None and self.ciphertext.direction != self.direction:
            raise ValueError("ciphertext direction must match frame direction")

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "sid": self.sid,
            "direction": self.direction.value,
            "sequence": self.sequence,
        }
        if self.control is not None:
            payload["kind"] = {
                "type": "Control",
                "control_type": self.control.variant,
                "fields": self.control.to_dict(),
            }
        else:
            payload["kind"] = {"type": "Ciphertext", "fields": self.ciphertext.to_dict()}  # type: ignore[union-attr]
        return payload

    def to_bytes(self) -> bytes:
        """Return Norito-encoded bytes for the frame."""

        codec = _require_codec_module()
        return bytes(codec.encode_connect_frame(self.to_dict()))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectFrame":
        kind = payload["kind"]
        sid = payload["sid"]
        direction = payload["direction"]
        sequence = payload["sequence"]
        if kind["type"] == "Control":
            variant = kind["control_type"]
            fields = kind["fields"]
            control_cls = _CONTROL_CLASS_MAP.get(variant)
            if control_cls is None:
                raise ValueError(f"unsupported control variant {variant!r}")
            control = control_cls.from_dict(fields)
            return cls(sid=sid, direction=direction, sequence=sequence, control=control)
        if kind["type"] == "Ciphertext":
            return cls(
                sid=sid,
                direction=direction,
                sequence=sequence,
                ciphertext=ConnectCiphertext.from_dict(kind["fields"]),
            )
        raise ValueError(f"unsupported frame kind {kind['type']!r}")

    @classmethod
    def from_bytes(cls, payload: _BytesLike) -> "ConnectFrame":
        """Decode Norito-encoded frame bytes."""

        codec = _require_codec_module()
        decoded = codec.decode_connect_frame(
            _ensure_bytes(payload, size=None, field="payload")
        )
        return cls.from_dict(decoded)



ConnectCiphertextPayload = Union[
    "ConnectControlClose",
    "ConnectControlReject",
    "ConnectSignRequestRawPayload",
    "ConnectSignRequestTxPayload",
    "ConnectSignResultOkPayload",
    "ConnectSignResultErrPayload",
    "ConnectDisplayRequestPayload",
]


@dataclass
class ConnectSignRequestRawPayload:
    domain_tag: str
    payload: bytes

    def __init__(self, *, domain_tag: str, payload: _BytesLike) -> None:
        self.domain_tag = domain_tag
        self.payload = _ensure_bytes(payload, size=None, field="payload")

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "type": "SignRequestRaw",
            "domain_tag": self.domain_tag,
            "bytes": self.payload,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectSignRequestRawPayload":
        return cls(
            domain_tag=str(payload["domain_tag"]),
            payload=_ensure_bytes(payload["bytes"], size=None, field="bytes"),
        )


@dataclass
class ConnectSignRequestTxPayload:
    tx_bytes: bytes

    def __init__(self, *, tx_bytes: _BytesLike) -> None:
        self.tx_bytes = _ensure_bytes(tx_bytes, size=None, field="tx_bytes")

    def to_wire_dict(self) -> Dict[str, Any]:
        return {"type": "SignRequestTx", "tx_bytes": self.tx_bytes}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectSignRequestTxPayload":
        return cls(tx_bytes=_ensure_bytes(payload["tx_bytes"], size=None, field="tx_bytes"))


@dataclass
class ConnectSignResultOkPayload:
    signature: bytes
    algorithm: str = "Ed25519"

    def __init__(self, *, signature: _BytesLike, algorithm: str = "Ed25519") -> None:
        self.signature = _ensure_bytes(signature, size=None, field="signature")
        self.algorithm = _normalize_connect_wallet_signature_algorithm(algorithm)

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "type": "SignResultOk",
            "signature": {
                "algorithm": self.algorithm,
                "signature": self.signature,
            },
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectSignResultOkPayload":
        signature_payload = payload["signature"]
        if not isinstance(signature_payload, Mapping):
            raise TypeError("signature payload must be a mapping")
        return cls(
            signature=_ensure_bytes(
                signature_payload["signature"], size=None, field="signature"
            ),
            algorithm=signature_payload.get("algorithm", "Ed25519"),
        )


@dataclass
class ConnectSignResultErrPayload:
    code: str
    message: str

    def to_wire_dict(self) -> Dict[str, Any]:
        return {"type": "SignResultErr", "code": self.code, "message": self.message}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectSignResultErrPayload":
        return cls(code=str(payload["code"]), message=str(payload["message"]))


@dataclass
class ConnectDisplayRequestPayload:
    title: str
    body: str

    def to_wire_dict(self) -> Dict[str, Any]:
        return {"type": "DisplayRequest", "title": self.title, "body": self.body}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectDisplayRequestPayload":
        return cls(title=str(payload["title"]), body=str(payload["body"]))


@dataclass
class ConnectEnvelope:
    sequence: int
    payload: ConnectCiphertextPayload

    def __post_init__(self) -> None:
        self.sequence = _require_uint(
            self.sequence,
            "Connect envelope sequence",
            maximum=_U64_MAX,
            positive=True,
        )
        _payload_to_dict(self.payload)

    def to_dict(self) -> Dict[str, Any]:
        return {"seq": self.sequence, "payload": _payload_to_dict(self.payload)}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectEnvelope":
        seq = _require_uint(
            payload["seq"],
            "Connect envelope sequence",
            maximum=_U64_MAX,
            positive=True,
        )
        payload_obj = payload["payload"]
        if not isinstance(payload_obj, Mapping):
            raise TypeError("connect payload must be a mapping")
        parsed = _payload_from_dict(payload_obj)
        return cls(sequence=seq, payload=parsed)


def _payload_to_dict(payload: ConnectCiphertextPayload) -> Dict[str, Any]:
    if isinstance(payload, ConnectControlClose):
        return {"type": "Control", "variant": "Close", "fields": payload.to_dict()}
    if isinstance(payload, ConnectControlReject):
        return {"type": "Control", "variant": "Reject", "fields": payload.to_dict()}
    if isinstance(payload, ConnectSignRequestRawPayload):
        return payload.to_wire_dict()
    if isinstance(payload, ConnectSignRequestTxPayload):
        return payload.to_wire_dict()
    if isinstance(payload, ConnectSignResultOkPayload):
        return payload.to_wire_dict()
    if isinstance(payload, ConnectSignResultErrPayload):
        return payload.to_wire_dict()
    if isinstance(payload, ConnectDisplayRequestPayload):
        return payload.to_wire_dict()
    raise TypeError(f"unsupported connect payload type {type(payload)!r}")


def _payload_from_dict(payload: Mapping[str, Any]) -> ConnectCiphertextPayload:
    kind = payload.get("type")
    if kind == "Control":
        variant = payload.get("variant")
        fields = payload.get("fields")
        if not isinstance(fields, Mapping):
            raise TypeError("control payload `fields` must be a mapping")
        if variant == "Close":
            return ConnectControlClose.from_dict(fields)
        if variant == "Reject":
            return ConnectControlReject.from_dict(fields)
        raise ValueError(f"unsupported control variant {variant!r}")
    if kind == "SignRequestRaw":
        return ConnectSignRequestRawPayload.from_dict(payload)
    if kind == "SignRequestTx":
        return ConnectSignRequestTxPayload.from_dict(payload)
    if kind == "SignResultOk":
        return ConnectSignResultOkPayload.from_dict(payload)
    if kind == "SignResultErr":
        return ConnectSignResultErrPayload.from_dict(payload)
    if kind == "DisplayRequest":
        return ConnectDisplayRequestPayload.from_dict(payload)
    raise ValueError(f"unsupported connect payload type {kind!r}")

def encode_connect_frame(frame: Union[ConnectFrame, Mapping[str, Any]]) -> bytes:
    """Encode a Connect frame to Norito bytes."""

    if isinstance(frame, ConnectFrame):
        payload = frame.to_dict()
    else:
        payload = dict(frame)
    codec = _require_codec_module()
    return bytes(codec.encode_connect_frame(payload))


def decode_connect_frame(payload: _BytesLike) -> ConnectFrame:
    """Decode Norito-encoded Connect frame bytes into a :class:`ConnectFrame`."""

    codec = _require_codec_module()
    decoded = codec.decode_connect_frame(
        _ensure_bytes(payload, size=None, field="payload")
    )
    return ConnectFrame.from_dict(decoded)


def generate_connect_keypair() -> ConnectKeyPair:
    """Return a freshly generated Connect X25519 key pair."""

    codec = _require_codec_module()
    private_key, public_key = codec.generate_connect_keypair()
    return ConnectKeyPair._from_native_result(private_key, public_key)


def connect_public_key_from_private(private_key: _BytesLike) -> bytes:
    """Derive the Connect X25519 public key corresponding to `private_key`."""

    codec = _require_codec_module()
    result = codec.connect_public_key_from_private(
        _ensure_bytes(private_key, size=32, field="private_key")
    )
    return bytes(result)


def derive_connect_direction_keys(
    local_private_key: _BytesLike,
    peer_public_key: _BytesLike,
    sid: _BytesLike,
) -> tuple[bytes, bytes]:
    """Derive the App→Wallet and Wallet→App symmetric keys for a session."""

    codec = _require_codec_module()
    app_key, wallet_key = codec.derive_connect_direction_keys(
        _ensure_bytes(local_private_key, size=32, field="local_private_key"),
        _ensure_bytes(peer_public_key, size=32, field="peer_public_key"),
        _ensure_bytes(sid, size=32, field="sid"),
    )
    return bytes(app_key), bytes(wallet_key)


def build_connect_approve_preimage(
    *,
    network_id: NetworkId,
    sid: _BytesLike,
    app_public_key: _BytesLike,
    nonce: _BytesLike,
    wallet_public_key: _BytesLike,
    account_id: str,
    permissions: Optional[ConnectPermissions] = None,
    proof: Optional[ConnectSignInProof] = None,
    relay_token: str,
) -> bytes:
    """Return the canonical byte preimage wallets must sign for approval frames."""

    codec = _require_codec_module()
    network_id = _require_network_id(network_id, "network_id")
    relay_token = _require_non_empty_string(relay_token, "relay_token")
    sid_bytes = _ensure_bytes(sid, size=32, field="sid")
    app_public_key_bytes = _ensure_bytes(
        app_public_key, size=32, field="app_public_key"
    )
    nonce_bytes = _ensure_bytes(nonce, size=16, field="nonce")
    _validate_connect_identity(
        network_id=network_id,
        sid=_to_base64url(sid_bytes),
        app_public_key=app_public_key_bytes,
        nonce=nonce_bytes,
    )
    relay_auth = bytes(codec.connect_relay_auth_hash(sid_bytes, relay_token))
    payload = codec.build_connect_approve_preimage(
        network_id,
        sid_bytes,
        app_public_key_bytes,
        nonce_bytes,
        _ensure_bytes(wallet_public_key, size=32, field="wallet_public_key"),
        account_id,
        permissions.to_dict() if permissions else None,
        proof.to_dict() if proof else None,
        relay_auth,
    )
    return bytes(payload)


def verify_connect_approval_signature(
    *,
    network_id: NetworkId,
    sid: _BytesLike,
    app_public_key: _BytesLike,
    nonce: _BytesLike,
    wallet_public_key: _BytesLike,
    account_id: str,
    permissions: Optional[ConnectPermissions],
    proof: Optional[ConnectSignInProof],
    relay_token: str,
    algorithm: str,
    signature: _BytesLike,
) -> bool:
    """Verify an approval against its exact session, account, and relay binding."""

    normalized_algorithm = _normalize_connect_wallet_signature_algorithm(algorithm)
    return bool(
        _require_codec_module().verify_connect_approval_signature(
            _require_network_id(network_id, "network_id"),
            _ensure_bytes(sid, size=32, field="sid"),
            _ensure_bytes(app_public_key, size=32, field="app_public_key"),
            _ensure_bytes(nonce, size=16, field="nonce"),
            _ensure_bytes(wallet_public_key, size=32, field="wallet_public_key"),
            _require_exact_non_empty_string(account_id, "account_id"),
            permissions.to_dict() if permissions else None,
            proof.to_dict() if proof else None,
            _require_exact_non_empty_string(relay_token, "relay_token"),
            normalized_algorithm,
            _ensure_bytes(signature, size=64, field="signature"),
        )
    )

def seal_connect_payload(
    key: _BytesLike,
    sid: _BytesLike,
    *,
    direction: Union[ConnectDirection, str],
    sequence: int,
    payload: ConnectCiphertextPayload,
) -> ConnectFrame:
    """Encrypt a Connect payload and return the resulting ciphertext frame."""

    direction_obj = ConnectDirection.normalize(direction)
    normalized_sequence = _require_uint(
        sequence,
        "Connect payload sequence",
        maximum=_U64_MAX,
        positive=True,
    )
    payload_dict = _payload_to_dict(payload)
    frame_bytes = _require_codec_module().seal_connect_payload(
        _ensure_bytes(key, size=32, field="key"),
        _ensure_bytes(sid, size=32, field="sid"),
        direction_obj.value,
        normalized_sequence,
        payload_dict,
    )
    return ConnectFrame.from_bytes(frame_bytes)


def open_connect_payload(
    key: _BytesLike,
    frame: Union[ConnectFrame, _BytesLike],
) -> ConnectEnvelope:
    """Decrypt a Connect ciphertext frame using the provided direction key."""

    if isinstance(frame, ConnectFrame):
        frame_bytes = frame.to_bytes()
    else:
        frame_bytes = _ensure_bytes(frame, size=None, field="frame")
    envelope_dict = _require_codec_module().open_connect_payload(
        _ensure_bytes(key, size=32, field="key"),
        frame_bytes,
    )
    if not isinstance(envelope_dict, Mapping):
        raise TypeError("connect payload decoder returned unexpected response")
    return ConnectEnvelope.from_dict(envelope_dict)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ConnectSessionKeys:
    """Container for per-direction symmetric keys used after Connect approval."""

    app_to_wallet: bytes = dataclass_field(repr=False)
    wallet_to_app: bytes = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "app_to_wallet",
            _ensure_bytes(self.app_to_wallet, size=32, field="app_to_wallet"),
        )
        object.__setattr__(
            self,
            "wallet_to_app",
            _ensure_bytes(self.wallet_to_app, size=32, field="wallet_to_app"),
        )
        if not any(self.app_to_wallet) or not any(self.wallet_to_app):
            raise ValueError("Connect session keys must not be all zero")
        if self.app_to_wallet == self.wallet_to_app:
            raise ValueError("Connect direction keys must be distinct")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"

    @classmethod
    def derive(
        cls,
        *,
        local_private_key: _BytesLike,
        peer_public_key: _BytesLike,
        sid: _BytesLike,
    ) -> "ConnectSessionKeys":
        """Derive session keys via X25519 using the provided local key and peer public key."""

        app_key, wallet_key = derive_connect_direction_keys(local_private_key, peer_public_key, sid)
        return cls(app_to_wallet=app_key, wallet_to_app=wallet_key)


@dataclass(frozen=True)
class ConnectSessionState:
    """Serializable snapshot of Connect session counters and replay guards."""

    sid: bytes
    next_sequence_app_to_wallet: int = 1
    next_sequence_wallet_to_app: int = 1
    last_received_app_to_wallet: Optional[int] = None
    last_received_wallet_to_app: Optional[int] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "sid", _ensure_bytes(self.sid, size=32, field="sid"))
        for field in (
            "next_sequence_app_to_wallet",
            "next_sequence_wallet_to_app",
        ):
            object.__setattr__(
                self,
                field,
                _require_uint(
                    getattr(self, field),
                    f"ConnectSessionState {field}",
                    maximum=_U64_MAX,
                    positive=True,
                ),
            )
        for field in (
            "last_received_app_to_wallet",
            "last_received_wallet_to_app",
        ):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(
                    self,
                    field,
                    _require_uint(
                        value,
                        f"ConnectSessionState {field}",
                        maximum=_U64_MAX,
                        positive=True,
                    ),
                )

    def to_dict(self) -> Dict[str, Any]:
        """Convert the state into a JSON-friendly dictionary."""

        return {
            "sid_base64url": _to_base64url(self.sid),
            "next_sequence": {
                "app_to_wallet": self.next_sequence_app_to_wallet,
                "wallet_to_app": self.next_sequence_wallet_to_app,
            },
            "last_received": {
                "app_to_wallet": self.last_received_app_to_wallet,
                "wallet_to_app": self.last_received_wallet_to_app,
            },
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ConnectSessionState":
        """Restore a state snapshot from :meth:`to_dict` output."""

        if not isinstance(payload, Mapping):
            raise TypeError("ConnectSessionState payload must be a mapping")
        sid_base64url = payload.get("sid_base64url")
        if not isinstance(sid_base64url, str) or not sid_base64url:
            raise TypeError("ConnectSessionState payload must include string sid_base64url")
        try:
            sid = _from_base64url(sid_base64url)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(
                "ConnectSessionState sid_base64url must be valid base64url"
            ) from exc
        if len(sid) != _SID_LENGTH:
            raise ValueError("ConnectSessionState sid_base64url must decode to 32 bytes")

        next_sequence = payload.get("next_sequence", {})
        if not isinstance(next_sequence, Mapping):
            raise TypeError("ConnectSessionState next_sequence must be a mapping")
        last_received = payload.get("last_received", {})
        if not isinstance(last_received, Mapping):
            raise TypeError("ConnectSessionState last_received must be a mapping")

        def _read_int(
            holder: Mapping[str, Any],
            key: str,
            *,
            default: int,
        ) -> int:
            return _require_uint(
                holder.get(key, default),
                f"ConnectSessionState field `{key}`",
                maximum=_U64_MAX,
                positive=True,
            )

        def _read_optional_int(holder: Mapping[str, Any], key: str) -> Optional[int]:
            value = holder.get(key, None)
            if value is None:
                return None
            return _require_uint(
                value,
                f"ConnectSessionState field `{key}`",
                maximum=_U64_MAX,
                positive=True,
            )

        return cls(
            sid=sid,
            next_sequence_app_to_wallet=_read_int(
                next_sequence,
                "app_to_wallet",
                default=1,
            ),
            next_sequence_wallet_to_app=_read_int(
                next_sequence,
                "wallet_to_app",
                default=1,
            ),
            last_received_app_to_wallet=_read_optional_int(last_received, "app_to_wallet"),
            last_received_wallet_to_app=_read_optional_int(last_received, "wallet_to_app"),
        )


class ConnectSession:
    """Manage Connect ciphertext sealing/decryption with monotonic counters."""

    def __init__(
        self,
        *,
        sid: _BytesLike,
        keys: ConnectSessionKeys,
        app_initial_sequence: int = 1,
        wallet_initial_sequence: int = 1,
    ) -> None:
        self._sid = _ensure_bytes(sid, size=32, field="sid")
        if not isinstance(keys, ConnectSessionKeys):
            raise TypeError("keys must be ConnectSessionKeys")
        self._keys = keys
        self._next_sequence: Dict[ConnectDirection, int] = {
            ConnectDirection.APP_TO_WALLET: _require_uint(
                app_initial_sequence,
                "app_initial_sequence",
                maximum=_U64_MAX,
                positive=True,
            ),
            ConnectDirection.WALLET_TO_APP: _require_uint(
                wallet_initial_sequence,
                "wallet_initial_sequence",
                maximum=_U64_MAX,
                positive=True,
            ),
        }
        self._last_received: Dict[ConnectDirection, Optional[int]] = {
            ConnectDirection.APP_TO_WALLET: None,
            ConnectDirection.WALLET_TO_APP: None,
        }

    @property
    def sid(self) -> bytes:
        """Return the session identifier."""

        return self._sid

    def _seal(
        self,
        direction: ConnectDirection,
        payload: ConnectCiphertextPayload,
    ) -> ConnectFrame:
        seq = self._next_sequence[direction]
        frame = seal_connect_payload(
            self._key_for(direction),
            self._sid,
            direction=direction,
            sequence=seq,
            payload=payload,
        )
        self._next_sequence[direction] += 1
        return frame

    def encrypt_app_to_wallet(self, payload: ConnectCiphertextPayload) -> ConnectFrame:
        """Seal a payload with the App→Wallet key, incrementing the sequence counter."""

        return self._seal(ConnectDirection.APP_TO_WALLET, payload)

    def encrypt_wallet_to_app(self, payload: ConnectCiphertextPayload) -> ConnectFrame:
        """Seal a payload with the Wallet→App key, incrementing the sequence counter."""

        return self._seal(ConnectDirection.WALLET_TO_APP, payload)

    def decrypt(self, frame: Union[ConnectFrame, _BytesLike]) -> ConnectEnvelope:
        """Decrypt a ciphertext frame, enforcing monotonic sequence progression."""

        frame_obj = frame if isinstance(frame, ConnectFrame) else ConnectFrame.from_bytes(frame)
        if frame_obj.control is not None:
            raise ValueError("expected ciphertext frame")
        if frame_obj.sid != self._sid:
            raise ValueError("Connect frame sid does not match this exact session")
        key = self._key_for(frame_obj.direction)
        last_seq = self._last_received[frame_obj.direction]
        expected_seq = 1 if last_seq is None else last_seq + 1
        if frame_obj.sequence != expected_seq:
            raise ValueError(
                f"Connect frame sequence must be exactly {expected_seq} for this direction"
            )
        envelope = open_connect_payload(key, frame_obj)
        if envelope.sequence != frame_obj.sequence:
            raise ValueError("Connect envelope sequence does not match its frame")
        self._last_received[frame_obj.direction] = envelope.sequence
        return envelope

    def _key_for(self, direction: ConnectDirection) -> bytes:
        if direction == ConnectDirection.APP_TO_WALLET:
            return self._keys.app_to_wallet
        if direction == ConnectDirection.WALLET_TO_APP:
            return self._keys.wallet_to_app
        raise ValueError(f"unsupported direction {direction!r}")

    def snapshot_state(self) -> ConnectSessionState:
        """Capture the current replay guard and sequence counters.

        Use :meth:`from_state` with the same session keys to resume encryption
        after persisting the snapshot.
        """

        return ConnectSessionState(
            sid=self._sid,
            next_sequence_app_to_wallet=self._next_sequence[ConnectDirection.APP_TO_WALLET],
            next_sequence_wallet_to_app=self._next_sequence[ConnectDirection.WALLET_TO_APP],
            last_received_app_to_wallet=self._last_received[ConnectDirection.APP_TO_WALLET],
            last_received_wallet_to_app=self._last_received[ConnectDirection.WALLET_TO_APP],
        )

    @classmethod
    def from_state(
        cls,
        *,
        keys: ConnectSessionKeys,
        state: ConnectSessionState,
    ) -> "ConnectSession":
        """Recreate a session from a :class:`ConnectSessionState` snapshot."""

        session = cls(
            sid=state.sid,
            keys=keys,
            app_initial_sequence=state.next_sequence_app_to_wallet,
            wallet_initial_sequence=state.next_sequence_wallet_to_app,
        )
        session._last_received[ConnectDirection.APP_TO_WALLET] = state.last_received_app_to_wallet
        session._last_received[ConnectDirection.WALLET_TO_APP] = state.last_received_wallet_to_app
        return session


# ---------------------------------------------------------------------------
# Connect session preview helpers
# ---------------------------------------------------------------------------

def generate_connect_sid(
    *,
    network_id: NetworkId,
    app_public_key: _BytesLike,
    nonce: Optional[_BytesLike] = None,
) -> ConnectSid:
    """Derive a deterministic Connect session identifier."""

    network_id = _require_network_id(network_id, "network_id")
    public_key = _ensure_bytes(app_public_key, size=32, field="app_public_key")
    if not any(public_key):
        raise ValueError("app_public_key must not be all zero")
    if nonce is None:
        nonce_bytes = os.urandom(_NONCE_LENGTH)
    else:
        nonce_bytes = _ensure_bytes(nonce, size=_NONCE_LENGTH, field="nonce")
    if not any(nonce_bytes):
        raise ValueError("nonce must not be all zero")
    digest = bytes(
        _require_codec_module().derive_connect_sid(network_id, public_key, nonce_bytes)
    )
    sid_base64url = _to_base64url(digest)
    return ConnectSid(
        sid_bytes=bytes(digest),
        sid_base64url=sid_base64url,
        nonce=nonce_bytes,
    )


def create_connect_session_preview(
    *,
    network_id: NetworkId,
    node: Optional[str] = None,
    nonce: Optional[_BytesLike] = None,
    app_key_pair: Optional[ConnectKeyPair] = None,
) -> ConnectSessionPreview:
    """Generate deterministic URIs, SID material, and keypairs for Connect previews."""

    network_id = _require_network_id(network_id, "network_id")
    normalized_node = _normalize_optional_string(node, "node")
    if app_key_pair is not None and not isinstance(app_key_pair, ConnectKeyPair):
        raise TypeError("app_key_pair must be a ConnectKeyPair")
    key_pair = app_key_pair or generate_connect_keypair()
    sid = generate_connect_sid(
        network_id=network_id,
        app_public_key=key_pair.public_key,
        nonce=nonce,
    )
    wallet_uri = _build_preview_uri(
        "connect", sid.sid_base64url, network_id, key_pair.public_key, sid.nonce, normalized_node
    )
    app_uri = _build_preview_uri(
        "connect/app", sid.sid_base64url, network_id, key_pair.public_key, sid.nonce, normalized_node
    )
    return ConnectSessionPreview(
        network_id=network_id,
        node=normalized_node,
        sid_bytes=sid.sid_bytes,
        sid_base64url=sid.sid_base64url,
        nonce=sid.nonce,
        app_key_pair=key_pair,
        wallet_uri=wallet_uri,
        app_uri=app_uri,
    )


def bootstrap_connect_preview_session(
    torii_client: Any,
    *,
    network_id: NetworkId,
    node: Optional[str] = None,
    nonce: Optional[_BytesLike] = None,
    app_key_pair: Optional[ConnectKeyPair] = None,
    register: bool = True,
    session_options: Optional[Mapping[str, Any]] = None,
) -> ConnectPreviewBootstrapResult:
    """Bundle Connect preview generation with optional Torii registration."""

    if not hasattr(torii_client, "create_connect_session"):
        raise TypeError("torii_client must expose create_connect_session()")
    preview = create_connect_session_preview(
        network_id=network_id,
        node=node,
        nonce=nonce,
        app_key_pair=app_key_pair,
    )
    if not register:
        return ConnectPreviewBootstrapResult(preview=preview, session=None, tokens=None)
    payload: Dict[str, Any] = {
        "sid": preview.sid_base64url,
        "network_id": preview.network_id.literal,
        "app_pk": _to_base64url(preview.app_key_pair.public_key),
        "nonce": _to_base64url(preview.nonce),
    }
    if session_options is not None:
        if not isinstance(session_options, Mapping):
            raise TypeError("session_options must be a mapping when provided")
        for key, value in session_options.items():
            if key == "node":
                if value is None:
                    continue
                payload["node"] = _require_non_empty_string(str(value), "sessionOptions.node")
            else:
                raise ValueError(f"unsupported session option {key!r}")
    if "node" not in payload and preview.node:
        payload["node"] = preview.node
    response = torii_client.create_connect_session(payload)
    if isinstance(response, ConnectSessionInfo):
        session = response
    elif isinstance(response, Mapping):
        session = ConnectSessionInfo.from_mapping(response)
    else:
        raise ValueError("Torii Connect session response is missing or malformed")
    _ensure_connect_session_matches_request(session, payload)
    wallet_token = _read_session_token(session, "wallet_token")
    app_token = _read_session_token(session, "app_token")
    management_token = _read_session_token(session, "management_token")
    relay_token = _read_session_token(session, "relay_token")
    tokens = ConnectPreviewTokens(
        wallet=wallet_token,
        app=app_token,
        management=management_token,
        relay=relay_token,
    )
    return ConnectPreviewBootstrapResult(preview=preview, session=session, tokens=tokens)


def _build_preview_uri(
    suffix: str,
    sid_base64url: str,
    network_id: NetworkId,
    app_public_key: bytes,
    nonce: bytes,
    node: Optional[str],
) -> str:
    params = {
        "sid": sid_base64url,
        "network_id": network_id.literal,
        "app_pk": _to_base64url(app_public_key),
        "nonce": _to_base64url(nonce),
        "v": _CONNECT_URI_VERSION,
    }
    if node:
        params["node"] = node
    return f"iroha://{suffix}?{urlencode(params)}"


def _require_non_empty_string(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field} must not be empty")
    return normalized


def _require_exact_non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    if not value or value != value.strip():
        raise ValueError(f"{field} must be a non-empty exact string")
    return value


def _normalize_optional_string(value: Optional[str], field: str) -> Optional[str]:
    if value is None:
        return None
    return _require_non_empty_string(value, field)


def _to_base64url(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(data)
    return encoded.rstrip(b"=").decode("ascii")

def _from_base64url(value: str) -> bytes:
    normalized = _require_non_empty_string(value, "sid_base64url")
    if "=" in normalized:
        raise ValueError("sid_base64url must not include padding")
    remainder = len(normalized) % 4
    if remainder == 1:
        raise ValueError("sid_base64url has invalid length")
    if remainder:
        normalized = normalized + "=" * (4 - remainder)
    return base64.urlsafe_b64decode(normalized.encode("ascii"))


def _decode_canonical_base64url(value: str, size: int, field: str) -> bytes:
    decoded = _from_base64url(value)
    if len(decoded) != size or _to_base64url(decoded) != value:
        raise ValueError(f"{field} must be canonical base64url for exactly {size} bytes")
    return decoded


def _validate_connect_identity(
    *,
    network_id: NetworkId,
    sid: str,
    app_public_key: bytes,
    nonce: bytes,
) -> None:
    sid_literal = _require_exact_non_empty_string(sid, "sid")
    sid_bytes = _decode_canonical_base64url(sid_literal, _SID_LENGTH, "sid")
    app_public_key = _ensure_bytes(
        app_public_key, size=32, field="app_public_key"
    )
    nonce = _ensure_bytes(nonce, size=_NONCE_LENGTH, field="nonce")
    if not any(app_public_key):
        raise ValueError("app_public_key must not be all zero")
    if not any(nonce):
        raise ValueError("nonce must not be all zero")
    expected = generate_connect_sid(
        network_id=_require_network_id(network_id, "network_id"),
        app_public_key=app_public_key,
        nonce=nonce,
    ).sid_bytes
    if sid_bytes != expected:
        raise ValueError("sid does not match exact network_id, app_pk, and nonce")


def _read_session_token(obj: Any, primary: str) -> str:
    if hasattr(obj, primary):
        token = getattr(obj, primary)
    elif isinstance(obj, Mapping):
        token = obj.get(primary)
    else:  # pragma: no cover - defensive
        token = None
    if not isinstance(token, str) or not token:
        raise ValueError(f"session response missing token field {primary!r}")
    return token
