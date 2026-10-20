"""Typed first-release Kaigi instruction builders and canonical Norito wire codec.

The native :class:`iroha_python.crypto.Instruction` JSON constructor accepts a
base64-encoded canonical ``InstructionBox``.  It does not accept the convenient
argument dictionaries used by some SDKs.  This module therefore constructs the
registered ``(wire_id, framed_payload)`` pair directly and wraps it in the exact
``InstructionBox`` archive before asking the native bridge to decode it again.

Identity fields use the required native Rust validators and canonical Norito
frames. This preserves full single-key and multisig controllers, the pinned
Unicode NFC profile for Names, and the pinned UTS-46 profile for domains.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, Mapping, Sequence

from iroha_native import load_crypto_extension
from norito.crc64 import crc64 as _crc64

if TYPE_CHECKING:
    from .crypto import Instruction

CREATE_KAIGI_WIRE_ID_V1: Final[str] = "iroha.instruction.v1::kaigi::CreateKaigi"
JOIN_KAIGI_WIRE_ID_V1: Final[str] = "iroha.instruction.v1::kaigi::JoinKaigi"
LEAVE_KAIGI_WIRE_ID_V1: Final[str] = "iroha.instruction.v1::kaigi::LeaveKaigi"
END_KAIGI_WIRE_ID_V1: Final[str] = "iroha.instruction.v1::kaigi::EndKaigi"
RECORD_KAIGI_USAGE_WIRE_ID_V1: Final[str] = "iroha.instruction.v1::kaigi::RecordKaigiUsage"
SET_KAIGI_RELAY_MANIFEST_WIRE_ID_V1: Final[str] = (
    "iroha.instruction.v1::kaigi::SetKaigiRelayManifest"
)
REGISTER_KAIGI_RELAY_WIRE_ID_V1: Final[str] = "iroha.instruction.v1::kaigi::RegisterKaigiRelay"
UNREGISTER_KAIGI_RELAY_WIRE_ID_V1: Final[str] = (
    "iroha.instruction.v1::kaigi::UnregisterKaigiRelay"
)
REPORT_KAIGI_RELAY_HEALTH_WIRE_ID_V1: Final[str] = (
    "iroha.instruction.v1::kaigi::ReportKaigiRelayHealth"
)
# Maximum concurrent participants excluding the host in a Kaigi V1 call.
KAIGI_MAX_PARTICIPANTS_V1: Final[int] = 4_096
KAIGI_RELAY_MANIFEST_MAX_HOPS_V1: Final[int] = 8
KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1: Final[int] = 4_096

KAIGI_INSTRUCTION_WIRE_IDS_V1: Final[tuple[str, ...]] = (
    CREATE_KAIGI_WIRE_ID_V1,
    JOIN_KAIGI_WIRE_ID_V1,
    LEAVE_KAIGI_WIRE_ID_V1,
    END_KAIGI_WIRE_ID_V1,
    RECORD_KAIGI_USAGE_WIRE_ID_V1,
    SET_KAIGI_RELAY_MANIFEST_WIRE_ID_V1,
    REGISTER_KAIGI_RELAY_WIRE_ID_V1,
    UNREGISTER_KAIGI_RELAY_WIRE_ID_V1,
    REPORT_KAIGI_RELAY_HEALTH_WIRE_ID_V1,
)

_INNER_TYPE_NAME_BY_WIRE_ID: Final[Mapping[str, str]] = MappingProxyType(
    {
        CREATE_KAIGI_WIRE_ID_V1: "iroha_data_model::isi::kaigi::CreateKaigi",
        JOIN_KAIGI_WIRE_ID_V1: "iroha_data_model::isi::kaigi::JoinKaigi",
        LEAVE_KAIGI_WIRE_ID_V1: "iroha_data_model::isi::kaigi::LeaveKaigi",
        END_KAIGI_WIRE_ID_V1: "iroha_data_model::isi::kaigi::EndKaigi",
        RECORD_KAIGI_USAGE_WIRE_ID_V1: "iroha_data_model::isi::kaigi::RecordKaigiUsage",
        SET_KAIGI_RELAY_MANIFEST_WIRE_ID_V1: (
            "iroha_data_model::isi::kaigi::SetKaigiRelayManifest"
        ),
        REGISTER_KAIGI_RELAY_WIRE_ID_V1: ("iroha_data_model::isi::kaigi::RegisterKaigiRelay"),
        UNREGISTER_KAIGI_RELAY_WIRE_ID_V1: (
            "iroha_data_model::isi::kaigi::UnregisterKaigiRelay"
        ),
        REPORT_KAIGI_RELAY_HEALTH_WIRE_ID_V1: (
            "iroha_data_model::isi::kaigi::ReportKaigiRelayHealth"
        ),
    }
)

_NORITO_MAGIC: Final[bytes] = b"NRT0\x00\x00"
_NORITO_HEADER_BYTES: Final[int] = 40
_COMPACT_LENGTH_FLAG: Final[int] = 0x02
# ``InstructionBox`` overrides its schema with the concrete archived pair.
# This is Rust's exact ``type_name::<(String, Vec<u8>)>()`` spelling.
_INSTRUCTION_BOX_TYPE_NAME: Final[str] = "(alloc::string::String, alloc::vec::Vec<u8>)"
_INSTRUCTION_BOX_SCHEMA_HASH: Final[bytes] = bytes.fromhex("862a7d77075d4d23ff6c1261db027811")
_MAX_ARCHIVE_BYTES: Final[int] = 64 * 1024 * 1024
_MAX_JSON_BYTES: Final[int] = 1_048_576
_MAX_JSON_DEPTH: Final[int] = 128
_U64_MAX: Final[int] = (1 << 64) - 1
_U32_MAX: Final[int] = (1 << 32) - 1
# ``kaigi_zk::Scalar`` is Pasta Fp; its canonical representation is little-endian.
_PASTA_FP_MODULUS: Final[int] = int(
    "40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16
)
_HASH_LITERAL_RE: Final[re.Pattern[str]] = re.compile(
    r"hash:([0-9A-F]{64})#([0-9A-F]{4})\Z", re.ASCII
)


def _schema_hash(type_name: str) -> bytes:
    return hashlib.sha256(b"norito:v1:type-name\0" + type_name.encode("ascii")).digest()[:16]


if _schema_hash(_INSTRUCTION_BOX_TYPE_NAME) != _INSTRUCTION_BOX_SCHEMA_HASH:
    raise RuntimeError("pinned InstructionBox schema hash no longer matches its archived type name")


def _crc16(payload: bytes) -> int:
    crc = 0xFFFF
    for byte in payload:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _compact_length(value: int) -> bytes:
    if type(value) is not int or value < 0 or value > _U64_MAX:
        raise ValueError("Norito compact length must fit an unsigned 64-bit integer")
    result = bytearray()
    remaining = value
    while True:
        byte = remaining & 0x7F
        remaining >>= 7
        result.append(byte | (0x80 if remaining else 0))
        if not remaining:
            return bytes(result)


def _field(payload: bytes) -> bytes:
    return _compact_length(len(payload)) + payload


def _struct(*payloads: bytes) -> bytes:
    return b"".join(_field(payload) for payload in payloads)


def _frame(payload: bytes, schema_hash: bytes) -> bytes:
    if len(schema_hash) != 16:
        raise ValueError("Norito schema hash must contain exactly 16 bytes")
    frame = (
        _NORITO_MAGIC
        + schema_hash
        + b"\x00"
        + struct.pack("<Q", len(payload))
        + struct.pack("<Q", _crc64(payload))
        + bytes([_COMPACT_LENGTH_FLAG])
        + payload
    )
    if len(frame) > _MAX_ARCHIVE_BYTES:
        raise ValueError(f"Kaigi Norito frame exceeds the {_MAX_ARCHIVE_BYTES}-byte limit")
    return frame


def _u64(value: Any, context: str, *, positive: bool = False) -> bytes:
    if type(value) is not int:
        raise TypeError(f"{context} must be an unsigned 64-bit integer")
    if value < (1 if positive else 0) or value > _U64_MAX:
        qualifier = "positive " if positive else ""
        raise ValueError(f"{context} must be a {qualifier}unsigned 64-bit integer")
    return struct.pack("<Q", value)


def _u32(value: Any, context: str, *, positive: bool = False) -> bytes:
    if type(value) is not int:
        raise TypeError(f"{context} must be an unsigned 32-bit integer")
    if value < (1 if positive else 0) or value > _U32_MAX:
        qualifier = "positive " if positive else ""
        raise ValueError(f"{context} must be a {qualifier}unsigned 32-bit integer")
    return struct.pack("<I", value)


def _max_participants(value: Any, context: str) -> bytes:
    payload = _u32(value, context, positive=True)
    if value > KAIGI_MAX_PARTICIPANTS_V1:
        raise ValueError(
            f"{context} must be between 1 and {KAIGI_MAX_PARTICIPANTS_V1}"
        )
    return payload


def _u8(value: Any, context: str, *, positive: bool = False) -> bytes:
    if type(value) is not int:
        raise TypeError(f"{context} must be an unsigned 8-bit integer")
    if value < (1 if positive else 0) or value > 0xFF:
        qualifier = "positive " if positive else ""
        raise ValueError(f"{context} must be a {qualifier}unsigned 8-bit integer")
    return bytes([value])


def _text(value: Any, context: str, *, allow_empty: bool = True) -> str:
    if type(value) is not str:
        raise TypeError(f"{context} must be a string")
    if not allow_empty and not value:
        raise ValueError(f"{context} must be non-empty")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{context} must be valid Unicode text") from error
    return value


def _string(value: str) -> bytes:
    return _field(value.encode("utf-8"))


def _canonical_identity(
    value: Any, context: str, kind: str
) -> tuple[str, bytes]:
    literal = _text(value, context, allow_empty=False)
    native = load_crypto_extension()
    encoder = getattr(native, f"_encode_{kind}_v1", None)
    if encoder is None:
        raise RuntimeError(
            f"iroha_native._crypto is missing the canonical {kind} encoder; rebuild the extension"
        )
    try:
        canonical, frame = encoder(literal)
    except ValueError as error:
        raise ValueError(f"{context}: {error}") from error
    expected_type = {
        "account_id": "iroha_data_model::account::model::AccountId",
        "domain_id": "iroha_data_model::domain::model::DomainId",
        "name": "iroha_data_model::name::model::Name",
    }[kind]
    if type(canonical) is not str or type(frame) is not bytes:
        raise RuntimeError(f"native {kind} encoder returned invalid result types")
    if len(frame) < _NORITO_HEADER_BYTES or len(frame) > _MAX_ARCHIVE_BYTES:
        raise RuntimeError(f"native {kind} encoder returned an invalid frame length")
    payload = frame[_NORITO_HEADER_BYTES:]
    if frame != _frame(payload, _schema_hash(expected_type)):
        raise RuntimeError(f"native {kind} encoder returned a noncanonical frame")
    return canonical, payload


def _name(value: Any, context: str) -> tuple[str, bytes]:
    return _canonical_identity(value, context, "name")


def _domain_id(value: Any, context: str) -> tuple[str, bytes]:
    return _canonical_identity(value, context, "domain_id")


def _kaigi_id(value: "KaigiIdV1", context: str) -> bytes:
    if not isinstance(value, KaigiIdV1):
        raise TypeError(f"{context} must be a KaigiIdV1")
    _, domain = _domain_id(value.domain_id, f"{context}.domain_id")
    _, call_name = _name(value.call_name, f"{context}.call_name")
    return _struct(domain, call_name)


def _account_id(value: Any, context: str) -> tuple[str, bytes]:
    return _canonical_identity(value, context, "account_id")


def _vec_u8(value: Any, *, context: str = "bytes", const_items: bool = False) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        payload = bytes(value)
    else:
        raise TypeError(f"{context} must be bytes-like")
    if len(payload) > _MAX_ARCHIVE_BYTES:
        raise ValueError(f"{context} exceeds the {_MAX_ARCHIVE_BYTES}-byte limit")
    if const_items:
        return struct.pack("<Q", len(payload)) + b"".join(_field(bytes([byte])) for byte in payload)
    return struct.pack("<Q", len(payload)) + payload


def _required_bytes(value: Any, context: str) -> bytes:
    payload = bytes(value) if isinstance(value, (bytes, bytearray, memoryview)) else None
    if payload is None:
        raise TypeError(f"{context} must be bytes-like")
    if not payload:
        raise ValueError(f"{context} must be non-empty")
    if len(payload) > _MAX_ARCHIVE_BYTES:
        raise ValueError(f"{context} exceeds the {_MAX_ARCHIVE_BYTES}-byte limit")
    return payload


def _hpke_public_key(value: Any, context: str) -> bytes:
    payload = _required_bytes(value, context)
    if len(payload) > KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1:
        raise ValueError(
            f"{context} exceeds the {KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1}-byte V1 limit"
        )
    return payload


def _proof(value: Any, context: str) -> bytes:
    return _vec_u8(_required_bytes(value, context), context=context)


def _require_all_or_none(context: str, **artifacts: Any) -> None:
    present = [name for name, value in artifacts.items() if value is not None]
    if present and len(present) != len(artifacts):
        missing = [name for name, value in artifacts.items() if value is None]
        raise ValueError(
            f"{context} privacy artifacts must be all present or all omitted; "
            f"missing {', '.join(missing)}"
        )


def _pasta_scalar_bytes(value: Any, context: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{context} must be a raw bytes-like Pasta Fp scalar")
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError(f"{context} must contain exactly 32 bytes")
    if int.from_bytes(raw, "little") >= _PASTA_FP_MODULUS:
        raise ValueError(f"{context} must be a canonical Pasta Fp scalar below the modulus")
    return raw


def _hash_bytes(value: Any, context: str) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) != 32:
            raise ValueError(f"{context} must contain exactly 32 bytes")
        if raw[-1] & 1 == 0:
            raise ValueError(f"{context} must already use the Iroha hash marker bit")
        return raw
    literal = _text(value, context, allow_empty=False)
    matched = _HASH_LITERAL_RE.fullmatch(literal)
    if matched is None:
        raise ValueError(f"{context} must be one canonical uppercase Hash literal")
    body, checksum = matched.groups()
    expected = f"{_crc16(f'hash:{body}'.encode('ascii')):04X}"
    if checksum != expected:
        raise ValueError(f"{context} has an invalid checksum; expected {expected}")
    raw = bytes.fromhex(body)
    if raw[-1] & 1 == 0:
        raise ValueError(f"{context} must use an Iroha hash marker bit")
    return raw


def _option(value: Any, encode: Any) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + _field(encode(value))


def _vec(values: Sequence[Any], encode: Any) -> bytes:
    entries = [encode(value, index) for index, value in enumerate(values)]
    return struct.pack("<Q", len(entries)) + b"".join(_field(entry) for entry in entries)


def _validate_json_value(value: Any, context: str, depth: int = 0) -> Any:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError(f"{context} exceeds the {_MAX_JSON_DEPTH}-level JSON depth limit")
    if value is None or type(value) in (bool, str):
        if type(value) is str:
            _text(value, context)
        return value
    if type(value) is int:
        if value < -(1 << 63) or value > _U64_MAX:
            raise ValueError(f"{context} integer must fit Norito JSON's i64/u64 domain")
        return value
    if isinstance(value, (float, complex)):
        raise TypeError(f"{context} must not use floating-point JSON values")
    if isinstance(value, (list, tuple)):
        return [
            _validate_json_value(entry, f"{context}[{index}]", depth + 1)
            for index, entry in enumerate(value)
        ]
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, entry in value.items():
            if type(key) is not str:
                raise TypeError(f"{context} object keys must be strings")
            _text(key, f"{context} key", allow_empty=False)
            normalized[key] = _validate_json_value(entry, f"{context}.{key}", depth + 1)
        return normalized
    raise TypeError(f"{context} is not a supported JSON value")


def _json_value(value: Any, context: str) -> bytes:
    normalized = _validate_json_value(value, context)
    rendered = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(rendered.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError(f"{context} exceeds the {_MAX_JSON_BYTES}-byte JSON limit")
    return _struct(_string(rendered))


def _metadata(value: Mapping[str, Any] | None, context: str) -> bytes:
    if value is None:
        entries: list[tuple[str, Any]] = []
    elif isinstance(value, Mapping):
        entries = list(value.items())
    else:
        raise TypeError(f"{context} must be a mapping")
    normalized = []
    for key, entry in entries:
        canonical_key, encoded_key = _name(key, f"{context} key")
        normalized.append((canonical_key, encoded_key, _json_value(entry, f"{context}.{key}")))
    normalized.sort(key=lambda item: item[0])
    if len({item[0] for item in normalized}) != len(normalized):
        raise ValueError(f"{context} contains duplicate canonical keys")
    return _vec(
        normalized,
        lambda item, _index: _struct(item[1], item[2]),
    )


@dataclass(frozen=True)
class KaigiIdV1:
    """A canonical ``domain.dataspace:call`` identity."""

    domain_id: str
    call_name: str

    def __post_init__(self) -> None:
        domain_id, _ = _domain_id(self.domain_id, "KaigiIdV1.domain_id")
        call_name, _ = _name(self.call_name, "KaigiIdV1.call_name")
        object.__setattr__(self, "domain_id", domain_id)
        object.__setattr__(self, "call_name", call_name)

    @classmethod
    def parse(cls, value: str) -> "KaigiIdV1":
        """Parse one exact ``domain.dataspace:call`` literal."""

        literal = _text(value, "KaigiIdV1", allow_empty=False)
        if literal.count(":") != 1:
            raise ValueError("KaigiIdV1 must use exact domain.dataspace:call form")
        domain_id, call_name = literal.split(":", 1)
        return cls(domain_id, call_name)

    def __str__(self) -> str:
        return f"{self.domain_id}:{self.call_name}"


@dataclass(frozen=True)
class KaigiParticipantCommitmentV1:
    """A raw canonical Pasta Fp participant commitment with no alias tag."""

    commitment: bytes

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "commitment",
            _pasta_scalar_bytes(self.commitment, "KaigiParticipantCommitmentV1.commitment"),
        )


@dataclass(frozen=True)
class KaigiParticipantNullifierV1:
    """A raw canonical Pasta Fp nullifier with no clear-text timing field."""

    digest: bytes

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _pasta_scalar_bytes(self.digest, "KaigiParticipantNullifierV1.digest"),
        )


@dataclass(frozen=True)
class KaigiRelayHopV1:
    """One non-zero-weight relay hop."""

    relay_id: str
    hpke_public_key: bytes
    weight: int = 1

    def __post_init__(self) -> None:
        relay_id, _ = _account_id(self.relay_id, "KaigiRelayHopV1.relay_id")
        public_key = _hpke_public_key(self.hpke_public_key, "KaigiRelayHopV1.hpke_public_key")
        _u8(self.weight, "KaigiRelayHopV1.weight", positive=True)
        object.__setattr__(self, "relay_id", relay_id)
        object.__setattr__(self, "hpke_public_key", public_key)


@dataclass(frozen=True)
class KaigiRelayManifestV1:
    """A three-to-eight-hop relay manifest with distinct relay accounts."""

    hops: Sequence[KaigiRelayHopV1]
    expiry_ms: int

    def __post_init__(self) -> None:
        if isinstance(self.hops, (str, bytes, bytearray, memoryview)):
            raise TypeError("KaigiRelayManifestV1.hops must be a sequence of relay hops")
        hops = tuple(self.hops)
        if len(hops) < 3:
            raise ValueError("KaigiRelayManifestV1.hops must contain at least three relays")
        if len(hops) > KAIGI_RELAY_MANIFEST_MAX_HOPS_V1:
            raise ValueError(
                "KaigiRelayManifestV1.hops must not contain more than "
                f"{KAIGI_RELAY_MANIFEST_MAX_HOPS_V1} relays"
            )
        if any(not isinstance(hop, KaigiRelayHopV1) for hop in hops):
            raise TypeError("KaigiRelayManifestV1.hops entries must be KaigiRelayHopV1")
        relay_ids = [_account_id(hop.relay_id, "relay identity")[1] for hop in hops]
        if len(set(relay_ids)) != len(relay_ids):
            raise ValueError("KaigiRelayManifestV1.hops must not contain duplicate relays")
        _u64(self.expiry_ms, "KaigiRelayManifestV1.expiry_ms")
        object.__setattr__(self, "hops", hops)


@dataclass(frozen=True)
class KaigiInstructionWireV1:
    """One canonical registered Kaigi ``WirePayload`` and ``InstructionBox`` archive."""

    wire_id: str
    payload_norito: bytes

    def __post_init__(self) -> None:
        if type(self.wire_id) is not str:
            raise TypeError("wire_id must be a string")
        if self.wire_id not in _INNER_TYPE_NAME_BY_WIRE_ID:
            raise ValueError("wire_id is not a first-release Kaigi instruction identifier")
        payload = _required_bytes(self.payload_norito, "payload_norito")
        expected_hash = _schema_hash(_INNER_TYPE_NAME_BY_WIRE_ID[self.wire_id])
        if (
            len(payload) < _NORITO_HEADER_BYTES
            or payload[:6] != _NORITO_MAGIC
            or payload[6:22] != expected_hash
            or payload[22] != 0
            or payload[39] != _COMPACT_LENGTH_FLAG
            or int.from_bytes(payload[23:31], "little") != len(payload) - _NORITO_HEADER_BYTES
            or int.from_bytes(payload[31:39], "little") != _crc64(payload[_NORITO_HEADER_BYTES:])
        ):
            raise ValueError("payload_norito is not the exact canonical Kaigi instruction frame")
        object.__setattr__(self, "payload_norito", payload)

    def wire_payload(self) -> tuple[str, bytes]:
        """Return the stable registry ID and exact framed concrete payload."""

        return self.wire_id, self.payload_norito

    def to_norito_bytes(self) -> bytes:
        """Return the canonical framed ``InstructionBox`` accepted by transaction builders."""

        wire = _field(self.wire_id.encode("utf-8"))
        inner_frame_field = struct.pack("<Q", len(self.payload_norito)) + self.payload_norito
        outer_payload = _struct(wire, inner_frame_field)
        archive = _frame(outer_payload, _INSTRUCTION_BOX_SCHEMA_HASH)
        if len(archive) > _MAX_ARCHIVE_BYTES:
            raise ValueError(f"Kaigi InstructionBox exceeds the {_MAX_ARCHIVE_BYTES}-byte limit")
        return archive

    def to_json(self) -> str:
        """Return the exact native ``Instruction.from_json`` base64 literal."""

        encoded = base64.b64encode(self.to_norito_bytes()).decode("ascii")
        return json.dumps(encoded, separators=(",", ":"))

    def to_instruction(self) -> "Instruction":
        """Decode this archive through the Rust-backed native instruction boundary."""

        from .crypto import Instruction

        instruction = Instruction.from_norito_bytes(self.to_norito_bytes())
        if instruction.wire_id() != self.wire_id:
            raise RuntimeError("native Kaigi instruction decoder changed the canonical wire ID")
        if bytes(instruction.to_norito_bytes()) != self.to_norito_bytes():
            raise RuntimeError("native Kaigi instruction decoder changed canonical Norito bytes")
        return instruction


def _participant_commitment(value: KaigiParticipantCommitmentV1) -> bytes:
    if not isinstance(value, KaigiParticipantCommitmentV1):
        raise TypeError("commitment must be a KaigiParticipantCommitmentV1")
    return _struct(bytes(value.commitment))


def _participant_nullifier(value: KaigiParticipantNullifierV1) -> bytes:
    if not isinstance(value, KaigiParticipantNullifierV1):
        raise TypeError("nullifier must be a KaigiParticipantNullifierV1")
    return _struct(bytes(value.digest))


def _relay_hop(value: KaigiRelayHopV1) -> bytes:
    _, relay = _account_id(value.relay_id, "relay hop account")
    return _struct(
        relay,
        _vec_u8(value.hpke_public_key, context="relay hop HPKE key"),
        _u8(value.weight, "relay hop weight", positive=True),
    )


def _relay_manifest(value: KaigiRelayManifestV1) -> bytes:
    if not isinstance(value, KaigiRelayManifestV1):
        raise TypeError("relay_manifest must be a KaigiRelayManifestV1")
    return _struct(
        _vec(value.hops, lambda hop, _index: _relay_hop(hop)),
        _u64(value.expiry_ms, "relay manifest expiry_ms"),
    )


def _instruction_wire(wire_id: str, payload: bytes) -> KaigiInstructionWireV1:
    return KaigiInstructionWireV1(
        wire_id,
        _frame(payload, _schema_hash(_INNER_TYPE_NAME_BY_WIRE_ID[wire_id])),
    )


def encode_create_kaigi_instruction_v1(
    *,
    call_id: KaigiIdV1,
    host: str,
    title: str | None = None,
    description: str | None = None,
    max_participants: int | None = None,
    gas_rate_per_minute: int = 0,
    metadata: Mapping[str, Any] | None = None,
    scheduled_start_ms: int | None = None,
    billing_account: str | None = None,
    privacy_mode: str = "Transparent",
    room_policy: str = "Authenticated",
    relay_manifest: KaigiRelayManifestV1 | None = None,
    commitment: KaigiParticipantCommitmentV1 | None = None,
    nullifier: KaigiParticipantNullifierV1 | None = None,
    roster_root: bytes | str | None = None,
    proof: bytes | None = None,
) -> KaigiInstructionWireV1:
    """Encode one typed ``CreateKaigi`` as its canonical registered wire payload.

    An explicit ``max_participants`` (excluding the host) must be between one
    and 4096. ``None`` preserves the absent wire field and uses that maximum.
    """

    _, host_payload = _account_id(host, "CreateKaigi.host")
    if title is not None:
        title = _text(title, "CreateKaigi.title")
    if description is not None:
        description = _text(description, "CreateKaigi.description")
    if max_participants is not None:
        _max_participants(max_participants, "CreateKaigi.max_participants")
    if scheduled_start_ms is not None:
        _u64(scheduled_start_ms, "CreateKaigi.scheduled_start_ms")
    billing_payload = None
    if billing_account is not None:
        _, billing_payload = _account_id(
            billing_account, "CreateKaigi.billing_account"
        )
        if billing_payload != host_payload:
            raise ValueError("CreateKaigi.billing_account must equal the signed host in V1")
    privacy_tags = {"Transparent": 0, "ZkRosterV1": 1}
    room_tags = {"Public": 0, "Authenticated": 1}
    privacy_mode = _text(privacy_mode, "CreateKaigi.privacy_mode", allow_empty=False)
    room_policy = _text(room_policy, "CreateKaigi.room_policy", allow_empty=False)
    if privacy_mode not in privacy_tags:
        raise ValueError("CreateKaigi.privacy_mode must be Transparent or ZkRosterV1")
    if room_policy not in room_tags:
        raise ValueError("CreateKaigi.room_policy must be Public or Authenticated")
    privacy_artifacts = {
        "commitment": commitment,
        "nullifier": nullifier,
        "roster_root": roster_root,
        "proof": proof,
    }
    if privacy_mode == "Transparent":
        if any(value is not None for value in privacy_artifacts.values()):
            raise ValueError("transparent CreateKaigi must omit every privacy artifact")
    else:
        _require_all_or_none("CreateKaigi", **privacy_artifacts)
        if commitment is None:
            raise ValueError(
                "private CreateKaigi requires the host commitment, nullifier, roster_root, and proof"
            )
    call = _struct(
        _kaigi_id(call_id, "CreateKaigi.call_id"),
        host_payload,
        _option(title, _string),
        _option(description, _string),
        _option(
            max_participants,
            lambda value: _max_participants(value, "CreateKaigi.max_participants"),
        ),
        _u64(gas_rate_per_minute, "CreateKaigi.gas_rate_per_minute"),
        _metadata(metadata, "CreateKaigi.metadata"),
        _option(
            scheduled_start_ms,
            lambda value: _u64(value, "CreateKaigi.scheduled_start_ms"),
        ),
        _option(billing_payload, lambda value: value),
        struct.pack("<I", privacy_tags[privacy_mode]),
        struct.pack("<I", room_tags[room_policy]),
        _option(relay_manifest, _relay_manifest),
    )
    payload = _struct(
        call,
        _option(commitment, _participant_commitment),
        _option(nullifier, _participant_nullifier),
        _option(roster_root, lambda value: _hash_bytes(value, "CreateKaigi.roster_root")),
        _option(proof, lambda value: _proof(value, "CreateKaigi.proof")),
    )
    return _instruction_wire(CREATE_KAIGI_WIRE_ID_V1, payload)


def _encode_join_or_leave_kaigi_instruction_v1(
    wire_id: str,
    *,
    call_id: KaigiIdV1,
    participant: str,
    commitment: KaigiParticipantCommitmentV1 | None,
    nullifier: KaigiParticipantNullifierV1 | None,
    roster_root: bytes | str | None,
    proof: bytes | None,
) -> KaigiInstructionWireV1:
    _require_all_or_none(
        "JoinKaigi" if wire_id == JOIN_KAIGI_WIRE_ID_V1 else "LeaveKaigi",
        commitment=commitment,
        nullifier=nullifier,
        roster_root=roster_root,
        proof=proof,
    )
    _, participant_payload = _account_id(participant, "Kaigi participant")
    payload = _struct(
        _kaigi_id(call_id, "Kaigi.call_id"),
        participant_payload,
        _option(commitment, _participant_commitment),
        _option(nullifier, _participant_nullifier),
        _option(roster_root, lambda value: _hash_bytes(value, "Kaigi.roster_root")),
        _option(proof, lambda value: _proof(value, "Kaigi.proof")),
    )
    return _instruction_wire(wire_id, payload)


def encode_join_kaigi_instruction_v1(
    *,
    call_id: KaigiIdV1,
    participant: str,
    commitment: KaigiParticipantCommitmentV1 | None = None,
    nullifier: KaigiParticipantNullifierV1 | None = None,
    roster_root: bytes | str | None = None,
    proof: bytes | None = None,
) -> KaigiInstructionWireV1:
    """Encode one typed ``JoinKaigi`` canonical wire payload."""

    return _encode_join_or_leave_kaigi_instruction_v1(
        JOIN_KAIGI_WIRE_ID_V1,
        call_id=call_id,
        participant=participant,
        commitment=commitment,
        nullifier=nullifier,
        roster_root=roster_root,
        proof=proof,
    )


def encode_leave_kaigi_instruction_v1(
    *,
    call_id: KaigiIdV1,
    participant: str,
    commitment: KaigiParticipantCommitmentV1 | None = None,
    nullifier: KaigiParticipantNullifierV1 | None = None,
    roster_root: bytes | str | None = None,
    proof: bytes | None = None,
) -> KaigiInstructionWireV1:
    """Encode a leave, including the complete authorization quartet for a private call.

    The transparent form omits all four artifacts. Core checks the call mode,
    participation sequence, ownership, and proof against committed state.
    """

    return _encode_join_or_leave_kaigi_instruction_v1(
        LEAVE_KAIGI_WIRE_ID_V1,
        call_id=call_id,
        participant=participant,
        commitment=commitment,
        nullifier=nullifier,
        roster_root=roster_root,
        proof=proof,
    )


def encode_end_kaigi_instruction_v1(
    *,
    call_id: KaigiIdV1,
    ended_at_ms: int | None = None,
    commitment: KaigiParticipantCommitmentV1 | None = None,
    nullifier: KaigiParticipantNullifierV1 | None = None,
    roster_root: bytes | str | None = None,
    proof: bytes | None = None,
) -> KaigiInstructionWireV1:
    """Encode one typed ``EndKaigi`` canonical wire payload."""

    _require_all_or_none(
        "EndKaigi",
        commitment=commitment,
        nullifier=nullifier,
        roster_root=roster_root,
        proof=proof,
    )
    payload = _struct(
        _kaigi_id(call_id, "EndKaigi.call_id"),
        _option(ended_at_ms, lambda value: _u64(value, "EndKaigi.ended_at_ms")),
        _option(commitment, _participant_commitment),
        _option(nullifier, _participant_nullifier),
        _option(roster_root, lambda value: _hash_bytes(value, "EndKaigi.roster_root")),
        _option(proof, lambda value: _proof(value, "EndKaigi.proof")),
    )
    return _instruction_wire(END_KAIGI_WIRE_ID_V1, payload)


def encode_record_kaigi_usage_instruction_v1(
    *,
    call_id: KaigiIdV1,
    duration_ms: int,
    billed_gas: int = 0,
    usage_commitment: bytes | None = None,
    proof: bytes | None = None,
) -> KaigiInstructionWireV1:
    """Encode one typed ``RecordKaigiUsage`` canonical wire payload."""

    _require_all_or_none(
        "RecordKaigiUsage",
        usage_commitment=usage_commitment,
        proof=proof,
    )
    payload = _struct(
        _kaigi_id(call_id, "RecordKaigiUsage.call_id"),
        _u64(duration_ms, "RecordKaigiUsage.duration_ms", positive=True),
        _u64(billed_gas, "RecordKaigiUsage.billed_gas"),
        _option(
            usage_commitment,
            lambda value: _pasta_scalar_bytes(value, "RecordKaigiUsage.usage_commitment"),
        ),
        _option(proof, lambda value: _proof(value, "RecordKaigiUsage.proof")),
    )
    return _instruction_wire(RECORD_KAIGI_USAGE_WIRE_ID_V1, payload)


def encode_set_kaigi_relay_manifest_instruction_v1(
    *, call_id: KaigiIdV1, relay_manifest: KaigiRelayManifestV1 | None
) -> KaigiInstructionWireV1:
    """Encode one typed relay-manifest replacement or clearing instruction."""

    payload = _struct(
        _kaigi_id(call_id, "SetKaigiRelayManifest.call_id"),
        _option(relay_manifest, _relay_manifest),
    )
    return _instruction_wire(SET_KAIGI_RELAY_MANIFEST_WIRE_ID_V1, payload)


def encode_register_kaigi_relay_instruction_v1(
    *, relay_id: str, hpke_public_key: bytes, bandwidth_class: int
) -> KaigiInstructionWireV1:
    """Encode one typed non-zero-capacity Kaigi relay registration."""

    _, relay_payload = _account_id(relay_id, "RegisterKaigiRelay.relay_id")
    public_key = _hpke_public_key(hpke_public_key, "RegisterKaigiRelay.hpke_public_key")
    relay = _struct(
        relay_payload,
        _vec_u8(public_key, context="RegisterKaigiRelay.hpke_public_key"),
        _u8(bandwidth_class, "RegisterKaigiRelay.bandwidth_class", positive=True),
    )
    return _instruction_wire(REGISTER_KAIGI_RELAY_WIRE_ID_V1, _struct(relay))


def encode_unregister_kaigi_relay_instruction_v1(*, relay_id: str) -> KaigiInstructionWireV1:
    """Encode one typed Kaigi relay retirement instruction."""

    _, relay_payload = _account_id(relay_id, "UnregisterKaigiRelay.relay_id")
    return _instruction_wire(UNREGISTER_KAIGI_RELAY_WIRE_ID_V1, _struct(relay_payload))


def encode_report_kaigi_relay_health_instruction_v1(
    *,
    call_id: KaigiIdV1,
    relay_id: str,
    status: str,
    reported_at_ms: int,
    notes: str | None = None,
) -> KaigiInstructionWireV1:
    """Encode one typed monotonic Kaigi relay-health observation."""

    status_tags = {"Healthy": 0, "Degraded": 1, "Unavailable": 2}
    status = _text(status, "ReportKaigiRelayHealth.status", allow_empty=False)
    if status not in status_tags:
        raise ValueError("status must be exactly Healthy, Degraded, or Unavailable")
    _, relay_payload = _account_id(relay_id, "ReportKaigiRelayHealth.relay_id")
    if notes is not None:
        notes = _text(notes, "ReportKaigiRelayHealth.notes")
        if len(notes) > 512:
            raise ValueError("ReportKaigiRelayHealth.notes must not exceed 512 Unicode scalars")
    payload = _struct(
        _kaigi_id(call_id, "ReportKaigiRelayHealth.call_id"),
        relay_payload,
        struct.pack("<I", status_tags[status]),
        _u64(reported_at_ms, "ReportKaigiRelayHealth.reported_at_ms"),
        _option(notes, _string),
    )
    return _instruction_wire(REPORT_KAIGI_RELAY_HEALTH_WIRE_ID_V1, payload)


def build_create_kaigi_instruction(
    *,
    call_id: KaigiIdV1,
    host: str,
    title: str | None = None,
    description: str | None = None,
    max_participants: int | None = None,
    gas_rate_per_minute: int = 0,
    metadata: Mapping[str, Any] | None = None,
    scheduled_start_ms: int | None = None,
    billing_account: str | None = None,
    privacy_mode: str = "Transparent",
    room_policy: str = "Authenticated",
    relay_manifest: KaigiRelayManifestV1 | None = None,
    commitment: KaigiParticipantCommitmentV1 | None = None,
    nullifier: KaigiParticipantNullifierV1 | None = None,
    roster_root: bytes | str | None = None,
    proof: bytes | None = None,
) -> "Instruction":
    """Build a native ``CreateKaigi`` instruction from typed keyword arguments."""

    return encode_create_kaigi_instruction_v1(
        call_id=call_id,
        host=host,
        title=title,
        description=description,
        max_participants=max_participants,
        gas_rate_per_minute=gas_rate_per_minute,
        metadata=metadata,
        scheduled_start_ms=scheduled_start_ms,
        billing_account=billing_account,
        privacy_mode=privacy_mode,
        room_policy=room_policy,
        relay_manifest=relay_manifest,
        commitment=commitment,
        nullifier=nullifier,
        roster_root=roster_root,
        proof=proof,
    ).to_instruction()


def build_join_kaigi_instruction(
    *,
    call_id: KaigiIdV1,
    participant: str,
    commitment: KaigiParticipantCommitmentV1 | None = None,
    nullifier: KaigiParticipantNullifierV1 | None = None,
    roster_root: bytes | str | None = None,
    proof: bytes | None = None,
) -> "Instruction":
    """Build a native ``JoinKaigi`` instruction from typed keyword arguments."""

    return encode_join_kaigi_instruction_v1(
        call_id=call_id,
        participant=participant,
        commitment=commitment,
        nullifier=nullifier,
        roster_root=roster_root,
        proof=proof,
    ).to_instruction()


def build_leave_kaigi_instruction(
    *,
    call_id: KaigiIdV1,
    participant: str,
    commitment: KaigiParticipantCommitmentV1 | None = None,
    nullifier: KaigiParticipantNullifierV1 | None = None,
    roster_root: bytes | str | None = None,
    proof: bytes | None = None,
) -> "Instruction":
    """Build a native ``LeaveKaigi`` instruction from typed keyword arguments."""

    return encode_leave_kaigi_instruction_v1(
        call_id=call_id,
        participant=participant,
        commitment=commitment,
        nullifier=nullifier,
        roster_root=roster_root,
        proof=proof,
    ).to_instruction()


def build_end_kaigi_instruction(
    *,
    call_id: KaigiIdV1,
    ended_at_ms: int | None = None,
    commitment: KaigiParticipantCommitmentV1 | None = None,
    nullifier: KaigiParticipantNullifierV1 | None = None,
    roster_root: bytes | str | None = None,
    proof: bytes | None = None,
) -> "Instruction":
    """Build a native ``EndKaigi`` instruction from typed keyword arguments."""

    return encode_end_kaigi_instruction_v1(
        call_id=call_id,
        ended_at_ms=ended_at_ms,
        commitment=commitment,
        nullifier=nullifier,
        roster_root=roster_root,
        proof=proof,
    ).to_instruction()


def build_record_kaigi_usage_instruction(
    *,
    call_id: KaigiIdV1,
    duration_ms: int,
    billed_gas: int = 0,
    usage_commitment: bytes | None = None,
    proof: bytes | None = None,
) -> "Instruction":
    """Build a native ``RecordKaigiUsage`` instruction from typed keyword arguments."""

    return encode_record_kaigi_usage_instruction_v1(
        call_id=call_id,
        duration_ms=duration_ms,
        billed_gas=billed_gas,
        usage_commitment=usage_commitment,
        proof=proof,
    ).to_instruction()


def build_set_kaigi_relay_manifest_instruction(
    *, call_id: KaigiIdV1, relay_manifest: KaigiRelayManifestV1 | None
) -> "Instruction":
    """Build a native ``SetKaigiRelayManifest`` instruction from typed keyword arguments."""

    return encode_set_kaigi_relay_manifest_instruction_v1(
        call_id=call_id,
        relay_manifest=relay_manifest,
    ).to_instruction()


def build_register_kaigi_relay_instruction(
    *, relay_id: str, hpke_public_key: bytes, bandwidth_class: int
) -> "Instruction":
    """Build a native ``RegisterKaigiRelay`` instruction from typed keyword arguments."""

    return encode_register_kaigi_relay_instruction_v1(
        relay_id=relay_id,
        hpke_public_key=hpke_public_key,
        bandwidth_class=bandwidth_class,
    ).to_instruction()


def build_unregister_kaigi_relay_instruction(*, relay_id: str) -> "Instruction":
    """Build a native ``UnregisterKaigiRelay`` instruction."""

    return encode_unregister_kaigi_relay_instruction_v1(relay_id=relay_id).to_instruction()


def build_report_kaigi_relay_health_instruction(
    *,
    call_id: KaigiIdV1,
    relay_id: str,
    status: str,
    reported_at_ms: int,
    notes: str | None = None,
) -> "Instruction":
    """Build a native ``ReportKaigiRelayHealth`` instruction from typed keyword arguments."""

    return encode_report_kaigi_relay_health_instruction_v1(
        call_id=call_id,
        relay_id=relay_id,
        status=status,
        reported_at_ms=reported_at_ms,
        notes=notes,
    ).to_instruction()


__all__ = [
    "CREATE_KAIGI_WIRE_ID_V1",
    "END_KAIGI_WIRE_ID_V1",
    "JOIN_KAIGI_WIRE_ID_V1",
    "KAIGI_MAX_PARTICIPANTS_V1",
    "KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1",
    "KAIGI_INSTRUCTION_WIRE_IDS_V1",
    "KAIGI_RELAY_MANIFEST_MAX_HOPS_V1",
    "LEAVE_KAIGI_WIRE_ID_V1",
    "RECORD_KAIGI_USAGE_WIRE_ID_V1",
    "REGISTER_KAIGI_RELAY_WIRE_ID_V1",
    "UNREGISTER_KAIGI_RELAY_WIRE_ID_V1",
    "REPORT_KAIGI_RELAY_HEALTH_WIRE_ID_V1",
    "SET_KAIGI_RELAY_MANIFEST_WIRE_ID_V1",
    "KaigiIdV1",
    "KaigiInstructionWireV1",
    "KaigiParticipantCommitmentV1",
    "KaigiParticipantNullifierV1",
    "KaigiRelayHopV1",
    "KaigiRelayManifestV1",
    "build_create_kaigi_instruction",
    "build_end_kaigi_instruction",
    "build_join_kaigi_instruction",
    "build_leave_kaigi_instruction",
    "build_record_kaigi_usage_instruction",
    "build_register_kaigi_relay_instruction",
    "build_unregister_kaigi_relay_instruction",
    "build_report_kaigi_relay_health_instruction",
    "build_set_kaigi_relay_manifest_instruction",
    "encode_create_kaigi_instruction_v1",
    "encode_end_kaigi_instruction_v1",
    "encode_join_kaigi_instruction_v1",
    "encode_leave_kaigi_instruction_v1",
    "encode_record_kaigi_usage_instruction_v1",
    "encode_register_kaigi_relay_instruction_v1",
    "encode_unregister_kaigi_relay_instruction_v1",
    "encode_report_kaigi_relay_health_instruction_v1",
    "encode_set_kaigi_relay_manifest_instruction_v1",
]
