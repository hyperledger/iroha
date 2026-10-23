"""Strict native-independent codec for the first-release Exact12 fixture bundle."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import struct
import sys
from dataclasses import dataclass
from typing import Final, Sequence, cast

from blake3 import blake3
from norito.crc64 import crc64 as _crc64_ecma_v1

from .privacy_catalog import PRIVACY_PROTOCOL_IDS_V1, PrivacyProtocolIdV1

PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1: Final = (
    "iroha.privacy.exact12-typed-fixture-bundle.v1"
)
PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1: Final = "iroha.privacy.submit_proof.v1"
PRIVACY_EXACT12_FIXTURE_BUNDLE_VERSION_V1: Final = 1
PRIVACY_EXACT12_FIXTURE_BUNDLE_ROW_COUNT_V1: Final = 12
PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1: Final = 2 * 1024 * 1024
PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_AGGREGATE_NESTED_BYTES_V1: Final = 2 * 1024 * 1024
PRIVACY_EXACT12_MAX_STATEMENT_BYTES_V1: Final = 256 * 1024
PRIVACY_EXACT12_MAX_ENVELOPE_BYTES_V1: Final = 512 * 1024
PRIVACY_EXACT12_MAX_INSTRUCTION_BYTES_V1: Final = 512 * 1024
PRIVACY_EXACT12_MAX_INTENT_PROJECTION_BYTES_V1: Final = 512 * 1024
PRIVACY_EXACT12_MAX_UNSIGNED_TRANSACTION_BYTES_V1: Final = 768 * 1024
PRIVACY_EXACT12_MAX_SIGNED_TRANSACTION_BYTES_V1: Final = 1024 * 1024
PRIVACY_EXACT12_PROTOCOL_IDS_V1: Final = PRIVACY_PROTOCOL_IDS_V1

_HASH_BYTES_V1: Final = 32
_MAX_WIRE_ID_BYTES_V1: Final = 128
_NRT_HEADER_BYTES_V1: Final = 40
_NRT_COMPACT_LENGTH_FLAG_V1: Final = 0x02
_NRT_OUTER_PADDING_V1: Final = 0
_NRT_TYPED_PRIVACY_PADDING_V1: Final = 8
_NRT_TRANSACTION_PADDING_V1: Final = 0
_NRT_MAGIC_V1: Final = b"NRT0"
_SCHEMA_HASH_DOMAIN_V1: Final = b"norito:v1:type-name\0"
_STATEMENT_SCHEMA_NAME_V1: Final = "iroha.privacy.statement.v1"
_ENVELOPE_SCHEMA_NAME_V1: Final = "iroha.privacy.proof-envelope.v1"
_SUBMIT_PROOF_SCHEMA_NAME_V1: Final = "iroha_data_model::isi::privacy::SubmitPrivacyProofV1"
_TRANSACTION_PAYLOAD_SCHEMA_NAME_V1: Final = (
    "iroha_data_model::transaction::signed::model::TransactionPayload"
)
_STATEMENT_DIGEST_DOMAIN_V1: Final = b"iroha:privacy:statement:v1"
_INTENT_DIGEST_DOMAIN_V1: Final = b"iroha.privacy.transaction-intent-digest.v1"
_PROOF_WIRE_MAGIC_V1: Final = b"IRHZK1\xa5\x5a"
_CATALOG_COMMITMENT_V1: Final = bytes.fromhex(
    "5bcf366fb18d2e4361486c015da5b41a3fb00edf05611042ccc452120d176eb0"
)
_BASE64_RE_V1: Final = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# Proof-system and engine enums intentionally share these closed V1 ordinals.
_PROOF_SYSTEM_AND_ENGINE_TAGS_V1: Final = (0, 2, 3, 1, 4, 0, 5, 8, 6, 7, 0, 0)
# The protocol enum variants carry closed structs, so accepting an arbitrary
# number of compact fields would silently create a second schema in Python.
_STATEMENT_FIELD_COUNTS_V1: Final = (11, 10, 6, 9, 15, 20, 4, 8, 9, 8, 13, 13)
# These statement fields are additionally zeroed by Rust intent projection.
# Field zero is the shared statement context and is handled separately.
_PROJECTION_DERIVED_STATEMENT_FIELD_V1: Final = {0: 10, 4: 10, 10: 5}
# Reserve-backed statements carry the exact typed transparent balance scope at
# these protocol-specific field indexes.
_PUBLIC_BALANCE_SCOPE_STATEMENT_FIELD_V1: Final = {0: 7, 8: 2, 10: 2}

_ROW_BYTE_FIELDS_V1: Final = (
    "statement_norito",
    "envelope_norito",
    "submit_proof_instruction_norito",
    "transaction_intent_projection_norito",
    "transaction_intent_digest",
    "unsigned_transaction_payload_norito",
    "signed_transaction_versioned_norito",
    "signed_transaction_hash",
)


class PrivacyExact12FixtureErrorV1(ValueError):
    """An Exact12 archive or typed model violated the closed V1 contract."""


def _snapshot_bytes_v1(value: object, maximum: int, context: str) -> bytes:
    if type(value) is bytes:
        size = len(value)
        if size > maximum:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} exceeds the {maximum}-byte first-release limit"
            )
        return cast(bytes, value)
    if type(value) is bytearray:
        size = len(cast(bytearray, value))
        if size > maximum:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} exceeds the {maximum}-byte first-release limit"
            )
        return bytes(cast(bytearray, value))
    if type(value) is memoryview:
        view = cast(memoryview, value)
        if view.ndim != 1 or not view.contiguous:
            raise TypeError(f"{context} must be one contiguous byte view")
        if view.nbytes > maximum:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} exceeds the {maximum}-byte first-release limit"
            )
        return view.tobytes()
    raise TypeError(f"{context} must be bytes, bytearray, or memoryview")


def _require_non_empty_v1(value: bytes, context: str) -> None:
    if not value:
        raise PrivacyExact12FixtureErrorV1(f"{context} must not be empty")


def _require_hash_v1(value: bytes, context: str) -> None:
    if len(value) != _HASH_BYTES_V1:
        raise PrivacyExact12FixtureErrorV1(f"{context} must contain exactly 32 bytes")
    if not any(value):
        raise PrivacyExact12FixtureErrorV1(f"{context} must be non-zero")


@dataclass(frozen=True, slots=True)
class PrivacyExact12TypedFixtureRowV1:
    """One immutable byte-complete row in the canonical Exact12 protocol order."""

    protocol_id: PrivacyProtocolIdV1
    statement_norito: bytes
    envelope_norito: bytes
    submit_proof_wire_id: str
    submit_proof_instruction_norito: bytes
    transaction_intent_projection_norito: bytes
    transaction_intent_digest: bytes
    unsigned_transaction_payload_norito: bytes
    signed_transaction_versioned_norito: bytes
    signed_transaction_hash: bytes

    def __post_init__(self) -> None:
        if type(self.protocol_id) is not str or self.protocol_id not in PRIVACY_PROTOCOL_IDS_V1:
            raise PrivacyExact12FixtureErrorV1("protocol_id is not in the closed Exact12 registry")
        if type(self.submit_proof_wire_id) is not str:
            raise TypeError("submit_proof_wire_id must be a string")
        if self.submit_proof_wire_id != PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1:
            raise PrivacyExact12FixtureErrorV1(
                "submit_proof_wire_id must use the sole first-release wire identifier"
            )
        limits = {
            "statement_norito": PRIVACY_EXACT12_MAX_STATEMENT_BYTES_V1,
            "envelope_norito": PRIVACY_EXACT12_MAX_ENVELOPE_BYTES_V1,
            "submit_proof_instruction_norito": PRIVACY_EXACT12_MAX_INSTRUCTION_BYTES_V1,
            "transaction_intent_projection_norito": (
                PRIVACY_EXACT12_MAX_INTENT_PROJECTION_BYTES_V1
            ),
            "transaction_intent_digest": _HASH_BYTES_V1,
            "unsigned_transaction_payload_norito": (
                PRIVACY_EXACT12_MAX_UNSIGNED_TRANSACTION_BYTES_V1
            ),
            "signed_transaction_versioned_norito": (
                PRIVACY_EXACT12_MAX_SIGNED_TRANSACTION_BYTES_V1
            ),
            "signed_transaction_hash": _HASH_BYTES_V1,
        }
        for field_name in _ROW_BYTE_FIELDS_V1:
            snapshot = _snapshot_bytes_v1(getattr(self, field_name), limits[field_name], field_name)
            object.__setattr__(self, field_name, snapshot)
        for field_name in (
            "statement_norito",
            "envelope_norito",
            "submit_proof_instruction_norito",
            "transaction_intent_projection_norito",
            "unsigned_transaction_payload_norito",
            "signed_transaction_versioned_norito",
        ):
            _require_non_empty_v1(getattr(self, field_name), field_name)
        _require_hash_v1(self.transaction_intent_digest, "transaction_intent_digest")
        _require_hash_v1(self.signed_transaction_hash, "signed_transaction_hash")


@dataclass(frozen=True, slots=True)
class PrivacyExact12FixtureBundleV1:
    """Immutable typed bundle containing exactly the twelve first-release rows."""

    version: int
    rows: tuple[PrivacyExact12TypedFixtureRowV1, ...]

    def __post_init__(self) -> None:
        if (
            type(self.version) is not int
            or self.version != PRIVACY_EXACT12_FIXTURE_BUNDLE_VERSION_V1
        ):
            raise PrivacyExact12FixtureErrorV1("Exact12 bundle version must be exactly 1")
        if type(self.rows) not in (tuple, list):
            raise TypeError("Exact12 bundle rows must be a list or tuple")
        rows = tuple(self.rows)
        if len(rows) != PRIVACY_EXACT12_FIXTURE_BUNDLE_ROW_COUNT_V1:
            raise PrivacyExact12FixtureErrorV1("Exact12 bundle must contain exactly 12 rows")
        aggregate = 0
        for index, row in enumerate(rows):
            if type(row) is not PrivacyExact12TypedFixtureRowV1:
                raise TypeError(f"Exact12 row {index} has the wrong typed model")
            if row.protocol_id != PRIVACY_PROTOCOL_IDS_V1[index]:
                raise PrivacyExact12FixtureErrorV1(
                    f"Exact12 row {index} is duplicated, substituted, or out of order"
                )
            aggregate += len(row.submit_proof_wire_id.encode("utf-8"))
            aggregate += sum(len(getattr(row, field)) for field in _ROW_BYTE_FIELDS_V1)
            if aggregate > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_AGGREGATE_NESTED_BYTES_V1:
                raise PrivacyExact12FixtureErrorV1(
                    "Exact12 bundle exceeds the aggregate nested-byte limit"
                )
        object.__setattr__(self, "rows", rows)
        for index, row in enumerate(rows):
            _validate_row_bindings_v1(row, index)


class _ReaderV1:
    __slots__ = ("_bytes", "_context", "_offset")

    def __init__(self, payload: bytes, context: str) -> None:
        self._bytes = payload
        self._context = context
        self._offset = 0

    @property
    def remaining(self) -> int:
        return len(self._bytes) - self._offset

    def read_bytes(self, count: int, label: str) -> bytes:
        if count < 0 or count > self.remaining:
            raise PrivacyExact12FixtureErrorV1(
                f"{self._context}.{label} is truncated or overruns its parent"
            )
        start = self._offset
        self._offset += count
        return self._bytes[start : start + count]

    def read_u32(self, label: str) -> int:
        return struct.unpack("<I", self.read_bytes(4, label))[0]

    def read_u64(self, label: str) -> int:
        return struct.unpack("<Q", self.read_bytes(8, label))[0]

    def read_compact_length(self, label: str) -> int:
        value = 0
        for index in range(10):
            current = self.read_bytes(1, label)[0]
            chunk = current & 0x7F
            if index == 9 and chunk > 1:
                raise PrivacyExact12FixtureErrorV1(
                    f"{self._context}.{label} exceeds an unsigned 64-bit length"
                )
            value |= chunk << (index * 7)
            if current & 0x80 == 0:
                if index > 0 and chunk == 0:
                    raise PrivacyExact12FixtureErrorV1(
                        f"{self._context}.{label} is not minimally compact-encoded"
                    )
                return value
        raise PrivacyExact12FixtureErrorV1(
            f"{self._context}.{label} exceeds the ten-byte compact-length limit"
        )

    def read_field(
        self,
        label: str,
        *,
        maximum: int,
        minimum: int = 0,
    ) -> bytes:
        length = self.read_compact_length(f"{label}.length")
        if length < minimum or length > maximum or length > self.remaining:
            raise PrivacyExact12FixtureErrorV1(
                f"{self._context}.{label} declares an invalid or oversized length"
            )
        return self.read_bytes(length, f"{label}.payload")

    def require_end(self) -> None:
        if self.remaining:
            raise PrivacyExact12FixtureErrorV1(
                f"{self._context} contains {self.remaining} trailing or unknown bytes"
            )


class _DecodeBudgetV1:
    __slots__ = ("_maximum", "_used")

    def __init__(self, maximum: int) -> None:
        self._maximum = maximum
        self._used = 0

    def claim(self, count: int, context: str) -> None:
        self._used += count
        if self._used > self._maximum:
            raise PrivacyExact12FixtureErrorV1(
                f"Exact12 aggregate nested-byte limit exceeded at {context}"
            )


def _encode_compact_length_v1(value: int) -> bytes:
    if type(value) is not int or value < 0 or value > 0xFFFF_FFFF_FFFF_FFFF:
        raise PrivacyExact12FixtureErrorV1("Norito compact length must fit an unsigned u64")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _encode_field_v1(payload: bytes) -> bytes:
    return _encode_compact_length_v1(len(payload)) + payload


def _encode_fields_v1(fields: Sequence[bytes]) -> bytes:
    return b"".join(_encode_field_v1(field) for field in fields)


def _decode_fields_v1(payload: bytes, count: int, context: str, maximum: int) -> tuple[bytes, ...]:
    reader = _ReaderV1(payload, context)
    fields = tuple(reader.read_field(f"field[{index}]", maximum=maximum) for index in range(count))
    reader.require_end()
    if _encode_fields_v1(fields) != payload:
        raise PrivacyExact12FixtureErrorV1(f"{context} has a non-canonical field layout")
    return fields


def _decode_network_id_v1(payload: bytes, context: str) -> bytes:
    """Decode one transparent exact NetworkId and reject unmarked hash bytes."""

    if len(payload) != _HASH_BYTES_V1 or payload[-1] & 1 == 0:
        raise PrivacyExact12FixtureErrorV1(
            f"{context} must contain exactly 32 marked Iroha hash bytes"
        )
    return payload


def _decode_network_transaction_domain_v1(payload: bytes, context: str) -> bytes:
    """Require the first-release ordinary TransactionDomain::Network wire."""

    reader = _ReaderV1(payload, context)
    variant = reader.read_u32("variant")
    if variant != 0:
        raise PrivacyExact12FixtureErrorV1(
            f"{context} must use TransactionDomain::Network; genesis is not client-signable"
        )
    network_id = reader.read_field("network_id", maximum=_HASH_BYTES_V1)
    reader.require_end()
    _decode_network_id_v1(network_id, f"{context}.network_id")
    if struct.pack("<I", 0) + _encode_field_v1(network_id) != payload:
        raise PrivacyExact12FixtureErrorV1(f"{context} is not canonical")
    return network_id


def _schema_hash_v1(type_name: str) -> bytes:
    return hashlib.sha256(_SCHEMA_HASH_DOMAIN_V1 + type_name.encode("utf-8")).digest()[:16]


def _encode_frame_v1(payload: bytes, schema_name: str, padding: int) -> bytes:
    header = b"".join(
        (
            _NRT_MAGIC_V1,
            b"\x00\x00",
            _schema_hash_v1(schema_name),
            b"\x00",
            struct.pack("<Q", len(payload)),
            struct.pack("<Q", _crc64_ecma_v1(payload)),
            bytes((_NRT_COMPACT_LENGTH_FLAG_V1,)),
        )
    )
    return header + bytes(padding) + payload


def _decode_frame_v1(
    archive: bytes,
    *,
    schema_name: str,
    expected_padding: int,
    maximum: int,
    context: str,
) -> bytes:
    if not archive:
        raise PrivacyExact12FixtureErrorV1(f"{context} must not be empty")
    if len(archive) > maximum:
        raise PrivacyExact12FixtureErrorV1(f"{context} exceeds its {maximum}-byte limit")
    if len(archive) < _NRT_HEADER_BYTES_V1:
        raise PrivacyExact12FixtureErrorV1(f"{context} is truncated before the Norito header")
    if archive[:4] != _NRT_MAGIC_V1 or archive[4:6] != b"\x00\x00":
        raise PrivacyExact12FixtureErrorV1(f"{context} has an unsupported Norito header")
    if not hmac.compare_digest(archive[6:22], _schema_hash_v1(schema_name)):
        raise PrivacyExact12FixtureErrorV1(f"{context} has the wrong Norito schema hash")
    if archive[22] != 0:
        raise PrivacyExact12FixtureErrorV1(f"{context} must use uncompressed Norito")
    if archive[39] != _NRT_COMPACT_LENGTH_FLAG_V1:
        raise PrivacyExact12FixtureErrorV1(
            f"{context} must use only the canonical compact-length flag"
        )
    payload_length = struct.unpack_from("<Q", archive, 23)[0]
    maximum_payload = maximum - _NRT_HEADER_BYTES_V1 - expected_padding
    if payload_length == 0 or payload_length > maximum_payload:
        raise PrivacyExact12FixtureErrorV1(f"{context} declares an invalid payload length")
    expected_length = _NRT_HEADER_BYTES_V1 + expected_padding + payload_length
    if expected_length != len(archive):
        raise PrivacyExact12FixtureErrorV1(
            f"{context} payload length does not cover exactly one complete frame"
        )
    padding = archive[_NRT_HEADER_BYTES_V1 : _NRT_HEADER_BYTES_V1 + expected_padding]
    if any(padding):
        raise PrivacyExact12FixtureErrorV1(f"{context} contains non-zero alignment padding")
    payload = archive[_NRT_HEADER_BYTES_V1 + expected_padding :]
    expected_crc = struct.unpack_from("<Q", archive, 31)[0]
    if _crc64_ecma_v1(payload) != expected_crc:
        raise PrivacyExact12FixtureErrorV1(f"{context} CRC64 checksum does not match")
    if _encode_frame_v1(payload, schema_name, expected_padding) != archive:
        raise PrivacyExact12FixtureErrorV1(f"{context} is not byte-canonical Norito")
    return payload


def _decode_tagged_v1(payload: bytes, expected_tag: int, context: str) -> bytes:
    reader = _ReaderV1(payload, context)
    tag = reader.read_u32("tag")
    content = reader.read_field(
        "content", maximum=PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1, minimum=1
    )
    reader.require_end()
    if tag != expected_tag:
        raise PrivacyExact12FixtureErrorV1(f"{context} carries a substituted protocol tag")
    if struct.pack("<I", tag) + _encode_field_v1(content) != payload:
        raise PrivacyExact12FixtureErrorV1(f"{context} is not a canonical tagged payload")
    return content


def _decode_digest_wrapper_v1(payload: bytes, context: str, *, allow_zero: bool) -> bytes:
    if len(payload) != 33 or payload[0] != 32:
        raise PrivacyExact12FixtureErrorV1(f"{context} has a non-canonical digest wrapper")
    digest = payload[1:]
    if not allow_zero and not any(digest):
        raise PrivacyExact12FixtureErrorV1(f"{context} must be non-zero")
    return digest


def _decode_goldilocks_digest384_v1(payload: bytes, context: str, *, allow_zero: bool) -> bytes:
    """Require six raw canonical little-endian Goldilocks limbs without a wrapper."""

    if len(payload) != 48 or any(
        lane >= 0xFFFF_FFFF_0000_0001 for lane in struct.unpack("<6Q", payload)
    ):
        raise PrivacyExact12FixtureErrorV1(f"{context} is not a canonical six-lane Goldilocks digest")
    if not allow_zero and not any(payload):
        raise PrivacyExact12FixtureErrorV1(f"{context} must be non-zero")
    return payload


def _validate_public_balance_scope_v1(payload: bytes, context: str) -> None:
    """Require the sole canonical Norito shape of a usable balance scope."""

    if payload == struct.pack("<I", 0):
        return
    if len(payload) == 14 and payload[:6] == b"\x01\x00\x00\x00\x09\x08":
        dataspace = struct.unpack_from("<Q", payload, 6)[0]
        if dataspace != 0:
            return
    raise PrivacyExact12FixtureErrorV1(
        f"{context} has an invalid or universal public balance scope"
    )


def _decode_statement_context_v1(
    statement_payload: bytes,
    expected_tag: int,
    row_intent_digest: bytes,
    *,
    normalized: bool,
    context: str,
) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
    variant = _decode_tagged_v1(statement_payload, expected_tag, context)
    statement_fields = _decode_fields_v1(
        variant,
        _STATEMENT_FIELD_COUNTS_V1[expected_tag],
        f"{context}.variant",
        PRIVACY_EXACT12_MAX_STATEMENT_BYTES_V1,
    )
    if expected_tag == 0:
        _decode_goldilocks_digest384_v1(
            statement_fields[1], f"{context}.identity_commitment", allow_zero=False
        )
        _decode_goldilocks_digest384_v1(
            statement_fields[10], f"{context}.replay_nullifier", allow_zero=normalized
        )
    scope_index = _PUBLIC_BALANCE_SCOPE_STATEMENT_FIELD_V1.get(expected_tag)
    if scope_index is not None:
        _validate_public_balance_scope_v1(
            statement_fields[scope_index],
            f"{context}.public_balance_scope",
        )
    context_fields = _decode_fields_v1(
        statement_fields[0],
        8,
        f"{context}.context",
        PRIVACY_EXACT12_MAX_STATEMENT_BYTES_V1,
    )
    _decode_network_id_v1(context_fields[0], f"{context}.context.network_id")
    if len(context_fields[1]) != 4 or struct.unpack("<I", context_fields[1])[0] != 0:
        raise PrivacyExact12FixtureErrorV1(f"{context} carries a substituted action index")
    intent = _decode_digest_wrapper_v1(
        context_fields[2], f"{context}.transaction_intent_digest", allow_zero=normalized
    )
    expected_intent = bytes(32) if normalized else row_intent_digest
    if not hmac.compare_digest(intent, expected_intent):
        raise PrivacyExact12FixtureErrorV1(
            f"{context} does not bind the row transaction-intent digest"
        )
    for index, name in enumerate(
        (
            "parameter_id",
            "parameter_digest",
            "verifier_digest",
            "statement_schema_digest",
            "engine_manifest_digest",
        ),
        start=3,
    ):
        _decode_digest_wrapper_v1(context_fields[index], f"{context}.{name}", allow_zero=False)
    return statement_fields, context_fields


def _decode_proof_bytes_v1(
    payload: bytes,
    expected_tag: int,
    *,
    normalized: bool,
    expected_zk_ams_action_tag: int | None,
    context: str,
) -> bytes:
    proof_value = _decode_tagged_v1(payload, expected_tag, context)
    if expected_tag == 3:
        if expected_zk_ams_action_tag is None:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} lacks the ZK-AMS action-to-proof binding"
            )
        proof_value = _decode_tagged_v1(
            proof_value,
            expected_zk_ams_action_tag,
            f"{context}.zk_ams_action",
        )
    proof_fields = _decode_fields_v1(
        proof_value,
        1,
        f"{context}.proof_bytes",
        PRIVACY_EXACT12_MAX_ENVELOPE_BYTES_V1,
    )
    raw_reader = _ReaderV1(proof_fields[0], f"{context}.proof_bytes.bytes")
    count = raw_reader.read_u64("length")
    if count > PRIVACY_EXACT12_MAX_ENVELOPE_BYTES_V1 or count != raw_reader.remaining:
        raise PrivacyExact12FixtureErrorV1(
            f"{context} carries a malformed or oversized proof byte vector"
        )
    proof_bytes = raw_reader.read_bytes(count, "payload")
    raw_reader.require_end()
    if normalized:
        if proof_bytes:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} normalized projection must remove all proof bytes"
            )
    elif not proof_bytes or not any(proof_bytes):
        raise PrivacyExact12FixtureErrorV1(
            f"{context} final proof bytes must be present and non-zero"
        )
    return proof_bytes


def _validate_envelope_payload_v1(
    payload: bytes,
    *,
    expected_tag: int,
    row_intent_digest: bytes,
    normalized: bool,
    expected_statement_payload: bytes | None,
    expected_statement_archive: bytes | None,
    context: str,
) -> tuple[tuple[bytes, ...], tuple[bytes, ...], tuple[bytes, ...]]:
    fields = _decode_fields_v1(payload, 13, context, PRIVACY_EXACT12_MAX_ENVELOPE_BYTES_V1)
    if fields[0] != _PROOF_WIRE_MAGIC_V1:
        raise PrivacyExact12FixtureErrorV1(f"{context} has an invalid final V1 wire marker")
    if fields[1] != _CATALOG_COMMITMENT_V1:
        raise PrivacyExact12FixtureErrorV1(f"{context} has a substituted Exact12 catalog commitment")
    if len(fields[2]) != 4 or struct.unpack("<I", fields[2])[0] != expected_tag:
        raise PrivacyExact12FixtureErrorV1(f"{context} carries a substituted protocol")
    expected_engine = _PROOF_SYSTEM_AND_ENGINE_TAGS_V1[expected_tag]
    for index, label in ((3, "proof-system"), (4, "engine")):
        if len(fields[index]) != 4 or struct.unpack("<I", fields[index])[0] != expected_engine:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} carries the wrong {label} tag for its protocol"
            )
    statement_fields, statement_context = _decode_statement_context_v1(
        fields[11],
        expected_tag,
        row_intent_digest,
        normalized=normalized,
        context=f"{context}.statement",
    )
    for envelope_index, statement_index in zip(range(5, 10), range(3, 8), strict=True):
        _decode_digest_wrapper_v1(
            fields[envelope_index],
            f"{context}.binding_digest[{envelope_index}]",
            allow_zero=False,
        )
        if fields[envelope_index] != statement_context[statement_index]:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} governed digest does not match its statement context"
            )
    statement_digest = _decode_digest_wrapper_v1(
        fields[10], f"{context}.statement_digest", allow_zero=normalized
    )
    if normalized:
        if any(statement_digest):
            raise PrivacyExact12FixtureErrorV1(
                f"{context} normalized statement digest must be zero"
            )
    else:
        if expected_statement_archive is None:
            raise PrivacyExact12FixtureErrorV1(f"{context} lacks its statement archive")
        expected_digest = blake3(
            _STATEMENT_DIGEST_DOMAIN_V1
            + struct.pack("<Q", len(expected_statement_archive))
            + expected_statement_archive
        ).digest()
        if not hmac.compare_digest(statement_digest, expected_digest):
            raise PrivacyExact12FixtureErrorV1(
                f"{context} statement digest does not match statement_norito"
            )
    if expected_statement_payload is not None and fields[11] != expected_statement_payload:
        raise PrivacyExact12FixtureErrorV1(
            f"{context} does not contain the byte-complete statement payload"
        )
    zk_ams_action_tag = None
    if expected_tag == 3:
        if len(statement_fields[8]) < 5:
            raise PrivacyExact12FixtureErrorV1(f"{context} carries a truncated ZK-AMS action")
        zk_ams_action_tag = struct.unpack_from("<I", statement_fields[8])[0]
        zk_ams_action = _decode_tagged_v1(
            statement_fields[8],
            zk_ams_action_tag,
            f"{context}.statement.zk_ams_action",
        )
        # The decoder above establishes the canonical action layout; only the
        # closed BatchAdmission/ProvisionAccount tags are admitted in V1.
        if zk_ams_action_tag not in (0, 1) or not zk_ams_action:
            raise PrivacyExact12FixtureErrorV1(f"{context} carries an unsupported ZK-AMS action")
    _decode_proof_bytes_v1(
        fields[12],
        expected_tag,
        normalized=normalized,
        expected_zk_ams_action_tag=zk_ams_action_tag,
        context=f"{context}.proof",
    )
    return fields, statement_fields, statement_context


def _decode_option_v1(payload: bytes, width: int, context: str) -> int | None:
    if payload == b"\x00":
        return None
    if not payload or payload[0] != 1:
        raise PrivacyExact12FixtureErrorV1(f"{context} has an invalid option tag")
    reader = _ReaderV1(payload[1:], f"{context}.some")
    inner = reader.read_field("value", maximum=width, minimum=width)
    reader.require_end()
    if width == 4:
        return struct.unpack("<I", inner)[0]
    if width == 8:
        return struct.unpack("<Q", inner)[0]
    raise AssertionError("unsupported fixed option width")


def _decode_single_submit_instruction_v1(
    executable: bytes,
    *,
    expected_tag: int,
    row_intent_digest: bytes,
    normalized: bool,
    expected_instruction_archive: bytes | None,
    expected_statement_payload: bytes | None,
    expected_statement_archive: bytes | None,
    context: str,
) -> tuple[tuple[bytes, ...], tuple[bytes, ...], tuple[bytes, ...]]:
    executable_reader = _ReaderV1(executable, context)
    if executable_reader.read_u32("variant") != 0:
        raise PrivacyExact12FixtureErrorV1(f"{context} must use direct instructions")
    sequence = executable_reader.read_field(
        "instructions", maximum=PRIVACY_EXACT12_MAX_UNSIGNED_TRANSACTION_BYTES_V1, minimum=9
    )
    executable_reader.require_end()
    sequence_reader = _ReaderV1(sequence, f"{context}.instructions")
    if sequence_reader.read_u64("count") != 1:
        raise PrivacyExact12FixtureErrorV1(f"{context} must contain exactly one instruction")
    instruction_box = sequence_reader.read_field(
        "instruction[0]", maximum=PRIVACY_EXACT12_MAX_INSTRUCTION_BYTES_V1, minimum=1
    )
    sequence_reader.require_end()
    box_reader = _ReaderV1(instruction_box, f"{context}.instruction_box")
    wire_field = box_reader.read_field("wire_id", maximum=_MAX_WIRE_ID_BYTES_V1 + 2, minimum=2)
    wire_reader = _ReaderV1(wire_field, f"{context}.wire_id")
    wire_length = wire_reader.read_compact_length("utf8_length")
    if (
        wire_length == 0
        or wire_length > _MAX_WIRE_ID_BYTES_V1
        or wire_length > wire_reader.remaining
    ):
        raise PrivacyExact12FixtureErrorV1(f"{context} has an invalid wire identifier length")
    wire_bytes = wire_reader.read_bytes(wire_length, "utf8")
    wire_reader.require_end()
    try:
        wire_id = wire_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise PrivacyExact12FixtureErrorV1(f"{context} wire identifier is not UTF-8") from error
    if wire_id != PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1:
        raise PrivacyExact12FixtureErrorV1(f"{context} uses a retired instruction wire id")
    instruction_field = box_reader.read_field(
        "instruction_archive",
        maximum=PRIVACY_EXACT12_MAX_INSTRUCTION_BYTES_V1 + 8,
        minimum=9,
    )
    instruction_reader = _ReaderV1(instruction_field, f"{context}.instruction_archive")
    instruction_length = instruction_reader.read_u64("length")
    if (
        instruction_length == 0
        or instruction_length > PRIVACY_EXACT12_MAX_INSTRUCTION_BYTES_V1
        or instruction_length != instruction_reader.remaining
    ):
        raise PrivacyExact12FixtureErrorV1(f"{context} has an invalid instruction archive")
    instruction_archive = instruction_reader.read_bytes(instruction_length, "bytes")
    instruction_reader.require_end()
    box_reader.require_end()
    if expected_instruction_archive is not None and not hmac.compare_digest(
        instruction_archive, expected_instruction_archive
    ):
        raise PrivacyExact12FixtureErrorV1(
            f"{context} does not contain submit_proof_instruction_norito"
        )
    instruction_payload = _decode_frame_v1(
        instruction_archive,
        schema_name=_SUBMIT_PROOF_SCHEMA_NAME_V1,
        expected_padding=_NRT_TYPED_PRIVACY_PADDING_V1,
        maximum=PRIVACY_EXACT12_MAX_INSTRUCTION_BYTES_V1,
        context=f"{context}.submit_proof_instruction",
    )
    instruction_fields = _decode_fields_v1(
        instruction_payload,
        1,
        f"{context}.submit_proof_instruction.payload",
        PRIVACY_EXACT12_MAX_ENVELOPE_BYTES_V1,
    )
    return _validate_envelope_payload_v1(
        instruction_fields[0],
        expected_tag=expected_tag,
        row_intent_digest=row_intent_digest,
        normalized=normalized,
        expected_statement_payload=expected_statement_payload,
        expected_statement_archive=expected_statement_archive,
        context=f"{context}.submitted_envelope",
    )


def _decode_transaction_payload_v1(
    payload: bytes,
    *,
    expected_tag: int,
    row_intent_digest: bytes,
    normalized: bool,
    expected_instruction_archive: bytes | None,
    expected_statement_payload: bytes | None,
    expected_statement_archive: bytes | None,
    row_index: int,
    context: str,
) -> tuple[
    tuple[bytes, ...],
    tuple[bytes, ...],
    tuple[bytes, ...],
    tuple[bytes, ...],
]:
    fields = _decode_fields_v1(
        payload, 9, context, PRIVACY_EXACT12_MAX_UNSIGNED_TRANSACTION_BYTES_V1
    )
    envelope_fields, statement_fields, statement_context = _decode_single_submit_instruction_v1(
        fields[3],
        expected_tag=expected_tag,
        row_intent_digest=row_intent_digest,
        normalized=normalized,
        expected_instruction_archive=expected_instruction_archive,
        expected_statement_payload=expected_statement_payload,
        expected_statement_archive=expected_statement_archive,
        context=f"{context}.executable",
    )
    transaction_network_id = _decode_network_transaction_domain_v1(fields[0], f"{context}.domain")
    if transaction_network_id != statement_context[0]:
        raise PrivacyExact12FixtureErrorV1(
            f"{context} NetworkId does not match the privacy statement context"
        )
    expected_creation_time = 1_700_000_000_000 + row_index
    if len(fields[2]) != 8 or struct.unpack("<Q", fields[2])[0] != expected_creation_time:
        raise PrivacyExact12FixtureErrorV1(f"{context} carries a substituted creation time")
    if _decode_option_v1(fields[4], 8, f"{context}.time_to_live_ms") != 60_000:
        raise PrivacyExact12FixtureErrorV1(f"{context} must use the fixture TTL")
    if _decode_option_v1(fields[5], 4, f"{context}.nonce") != row_index + 1:
        raise PrivacyExact12FixtureErrorV1(f"{context} carries a substituted nonce")
    if fields[8] != b"\x00":
        raise PrivacyExact12FixtureErrorV1(f"{context} must not carry attachments")
    return fields, envelope_fields, statement_fields, statement_context


def _validate_signed_transaction_v1(signed: bytes, unsigned: bytes, context: str) -> None:
    if not signed or signed[0] != 1:
        raise PrivacyExact12FixtureErrorV1(f"{context} must use signed transaction version 1")
    fields = _decode_fields_v1(
        signed[1:], 3, f"{context}.payload", PRIVACY_EXACT12_MAX_SIGNED_TRANSACTION_BYTES_V1
    )
    if not fields[0]:
        raise PrivacyExact12FixtureErrorV1(f"{context} must contain a signature")
    if not hmac.compare_digest(fields[1], unsigned):
        raise PrivacyExact12FixtureErrorV1(f"{context} does not contain the unsigned payload")
    if fields[2] != b"\x00":
        raise PrivacyExact12FixtureErrorV1(f"{context} must not carry multisig signatures")


def _validate_row_bindings_v1(row: PrivacyExact12TypedFixtureRowV1, row_index: int) -> None:
    context = f"PrivacyExact12FixtureBundleV1.rows[{row_index}]"
    statement_payload = _decode_frame_v1(
        row.statement_norito,
        schema_name=_STATEMENT_SCHEMA_NAME_V1,
        expected_padding=_NRT_TYPED_PRIVACY_PADDING_V1,
        maximum=PRIVACY_EXACT12_MAX_STATEMENT_BYTES_V1,
        context=f"{context}.statement_norito",
    )
    statement_fields, statement_context = _decode_statement_context_v1(
        statement_payload,
        row_index,
        row.transaction_intent_digest,
        normalized=False,
        context=f"{context}.statement_norito.payload",
    )
    envelope_payload = _decode_frame_v1(
        row.envelope_norito,
        schema_name=_ENVELOPE_SCHEMA_NAME_V1,
        expected_padding=_NRT_TYPED_PRIVACY_PADDING_V1,
        maximum=PRIVACY_EXACT12_MAX_ENVELOPE_BYTES_V1,
        context=f"{context}.envelope_norito",
    )
    envelope_fields, envelope_statement_fields, envelope_statement_context = (
        _validate_envelope_payload_v1(
            envelope_payload,
            expected_tag=row_index,
            row_intent_digest=row.transaction_intent_digest,
            normalized=False,
            expected_statement_payload=statement_payload,
            expected_statement_archive=row.statement_norito,
            context=f"{context}.envelope_norito.payload",
        )
    )
    if (
        envelope_statement_fields != statement_fields
        or envelope_statement_context != statement_context
    ):
        raise PrivacyExact12FixtureErrorV1(
            f"{context}.envelope_norito changed the decoded statement"
        )
    instruction_payload = _decode_frame_v1(
        row.submit_proof_instruction_norito,
        schema_name=_SUBMIT_PROOF_SCHEMA_NAME_V1,
        expected_padding=_NRT_TYPED_PRIVACY_PADDING_V1,
        maximum=PRIVACY_EXACT12_MAX_INSTRUCTION_BYTES_V1,
        context=f"{context}.submit_proof_instruction_norito",
    )
    instruction_fields = _decode_fields_v1(
        instruction_payload,
        1,
        f"{context}.submit_proof_instruction_norito.payload",
        PRIVACY_EXACT12_MAX_ENVELOPE_BYTES_V1,
    )
    if not hmac.compare_digest(instruction_fields[0], envelope_payload):
        raise PrivacyExact12FixtureErrorV1(
            f"{context}.submit_proof_instruction_norito does not contain envelope_norito"
        )
    (
        unsigned_fields,
        unsigned_envelope_fields,
        unsigned_statement_fields,
        unsigned_statement_context,
    ) = _decode_transaction_payload_v1(
        row.unsigned_transaction_payload_norito,
        expected_tag=row_index,
        row_intent_digest=row.transaction_intent_digest,
        normalized=False,
        expected_instruction_archive=row.submit_proof_instruction_norito,
        expected_statement_payload=statement_payload,
        expected_statement_archive=row.statement_norito,
        row_index=row_index,
        context=f"{context}.unsigned_transaction_payload_norito",
    )
    if (
        unsigned_envelope_fields != envelope_fields
        or unsigned_statement_fields != statement_fields
        or unsigned_statement_context != statement_context
    ):
        raise PrivacyExact12FixtureErrorV1(
            f"{context}.unsigned_transaction_payload_norito changed the submitted envelope"
        )
    projection_payload = _decode_frame_v1(
        row.transaction_intent_projection_norito,
        schema_name=_TRANSACTION_PAYLOAD_SCHEMA_NAME_V1,
        expected_padding=_NRT_TRANSACTION_PADDING_V1,
        maximum=PRIVACY_EXACT12_MAX_INTENT_PROJECTION_BYTES_V1,
        context=f"{context}.transaction_intent_projection_norito",
    )
    (
        projection_fields,
        projection_envelope_fields,
        projection_statement_fields,
        projection_statement_context,
    ) = _decode_transaction_payload_v1(
        projection_payload,
        expected_tag=row_index,
        row_intent_digest=row.transaction_intent_digest,
        normalized=True,
        expected_instruction_archive=None,
        expected_statement_payload=None,
        expected_statement_archive=None,
        row_index=row_index,
        context=f"{context}.transaction_intent_projection_norito.payload",
    )
    for index, (unsigned_field, projection_field) in enumerate(
        zip(unsigned_fields, projection_fields, strict=True)
    ):
        if index != 3 and unsigned_field != projection_field:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} transaction-intent projection changed independent field {index}"
            )
    if row.unsigned_transaction_payload_norito == projection_payload:
        raise PrivacyExact12FixtureErrorV1(
            f"{context} transaction-intent projection was not normalized"
        )
    for index in (0, 1, 3, 4, 5, 6, 7):
        if projection_statement_context[index] != statement_context[index]:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} transaction-intent projection changed statement context field {index}"
            )
    for index, (final_field, projected_field) in enumerate(
        zip(statement_fields, projection_statement_fields, strict=True)
    ):
        if index == 0:
            continue
        derived_index = _PROJECTION_DERIVED_STATEMENT_FIELD_V1.get(row_index)
        if index == derived_index:
            decode_digest = (
                _decode_goldilocks_digest384_v1 if row_index == 0 else _decode_digest_wrapper_v1
            )
            final_digest = decode_digest(
                final_field,
                f"{context}.statement_norito.derived_field[{index}]",
                allow_zero=False,
            )
            projected_digest = decode_digest(
                projected_field,
                f"{context}.transaction_intent_projection_norito.derived_field[{index}]",
                allow_zero=True,
            )
            if not any(final_digest) or any(projected_digest):
                raise PrivacyExact12FixtureErrorV1(
                    f"{context} transaction-intent projection did not zero derived field {index}"
                )
        elif projected_field != final_field:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} transaction-intent projection changed independent statement field {index}"
            )
    for index in range(10):
        if projection_envelope_fields[index] != envelope_fields[index]:
            raise PrivacyExact12FixtureErrorV1(
                f"{context} transaction-intent projection changed envelope field {index}"
            )
    expected_intent = blake3(
        _INTENT_DIGEST_DOMAIN_V1
        + struct.pack("<Q", len(row.transaction_intent_projection_norito))
        + row.transaction_intent_projection_norito
    ).digest()
    if not hmac.compare_digest(expected_intent, row.transaction_intent_digest):
        raise PrivacyExact12FixtureErrorV1(
            f"{context}.transaction_intent_digest does not match its projection"
        )
    _validate_signed_transaction_v1(
        row.signed_transaction_versioned_norito,
        row.unsigned_transaction_payload_norito,
        f"{context}.signed_transaction_versioned_norito",
    )
    transaction_hash_preimage = struct.pack("<I", 0) + _encode_field_v1(
        row.unsigned_transaction_payload_norito
    )
    expected_transaction_hash = bytearray(
        hashlib.blake2b(transaction_hash_preimage, digest_size=32).digest()
    )
    expected_transaction_hash[-1] |= 1
    if not hmac.compare_digest(expected_transaction_hash, row.signed_transaction_hash):
        raise PrivacyExact12FixtureErrorV1(
            f"{context}.signed_transaction_hash does not match the unsigned transaction"
        )


def _read_raw_vector_field_v1(
    reader: _ReaderV1,
    *,
    maximum: int,
    budget: _DecodeBudgetV1,
    context: str,
) -> bytes:
    field = reader.read_field(context, maximum=maximum + 8, minimum=9)
    child = _ReaderV1(field, context)
    count = child.read_u64("length")
    if count == 0 or count > maximum or count != child.remaining:
        raise PrivacyExact12FixtureErrorV1(f"{context} declares an invalid byte-vector length")
    budget.claim(count, context)
    value = child.read_bytes(count, "bytes")
    child.require_end()
    return value


def _read_string_field_v1(reader: _ReaderV1, *, budget: _DecodeBudgetV1, context: str) -> str:
    field = reader.read_field(context, maximum=_MAX_WIRE_ID_BYTES_V1 + 2, minimum=2)
    child = _ReaderV1(field, context)
    count = child.read_compact_length("utf8_length")
    if count == 0 or count > _MAX_WIRE_ID_BYTES_V1 or count != child.remaining:
        raise PrivacyExact12FixtureErrorV1(f"{context} declares an invalid UTF-8 length")
    encoded = child.read_bytes(count, "utf8")
    child.require_end()
    try:
        value = encoded.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise PrivacyExact12FixtureErrorV1(f"{context} is not valid UTF-8") from error
    if value.encode("utf-8") != encoded:
        raise PrivacyExact12FixtureErrorV1(f"{context} is not canonical UTF-8")
    budget.claim(count, context)
    return value


def _decode_row_v1(
    payload: bytes, row_index: int, budget: _DecodeBudgetV1
) -> PrivacyExact12TypedFixtureRowV1:
    context = f"PrivacyExact12FixtureBundleV1.rows[{row_index}]"
    reader = _ReaderV1(payload, context)
    protocol = reader.read_field("protocol_id", maximum=4, minimum=4)
    protocol_tag = struct.unpack("<I", protocol)[0]
    if protocol_tag != row_index:
        if protocol_tag < len(PRIVACY_PROTOCOL_IDS_V1):
            detail = "duplicate, substituted, or reordered"
        else:
            detail = "unknown"
        raise PrivacyExact12FixtureErrorV1(f"{context}.protocol_id is {detail}")
    statement = _read_raw_vector_field_v1(
        reader,
        maximum=PRIVACY_EXACT12_MAX_STATEMENT_BYTES_V1,
        budget=budget,
        context=f"{context}.statement_norito",
    )
    envelope = _read_raw_vector_field_v1(
        reader,
        maximum=PRIVACY_EXACT12_MAX_ENVELOPE_BYTES_V1,
        budget=budget,
        context=f"{context}.envelope_norito",
    )
    wire_id = _read_string_field_v1(
        reader, budget=budget, context=f"{context}.submit_proof_wire_id"
    )
    if wire_id != PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1:
        raise PrivacyExact12FixtureErrorV1(f"{context} uses a retired submit-proof wire id")
    instruction = _read_raw_vector_field_v1(
        reader,
        maximum=PRIVACY_EXACT12_MAX_INSTRUCTION_BYTES_V1,
        budget=budget,
        context=f"{context}.submit_proof_instruction_norito",
    )
    projection = _read_raw_vector_field_v1(
        reader,
        maximum=PRIVACY_EXACT12_MAX_INTENT_PROJECTION_BYTES_V1,
        budget=budget,
        context=f"{context}.transaction_intent_projection_norito",
    )
    intent_digest = reader.read_field("transaction_intent_digest", maximum=32, minimum=32)
    budget.claim(32, f"{context}.transaction_intent_digest")
    unsigned = _read_raw_vector_field_v1(
        reader,
        maximum=PRIVACY_EXACT12_MAX_UNSIGNED_TRANSACTION_BYTES_V1,
        budget=budget,
        context=f"{context}.unsigned_transaction_payload_norito",
    )
    signed = _read_raw_vector_field_v1(
        reader,
        maximum=PRIVACY_EXACT12_MAX_SIGNED_TRANSACTION_BYTES_V1,
        budget=budget,
        context=f"{context}.signed_transaction_versioned_norito",
    )
    transaction_hash = reader.read_field("signed_transaction_hash", maximum=32, minimum=32)
    budget.claim(32, f"{context}.signed_transaction_hash")
    reader.require_end()
    return PrivacyExact12TypedFixtureRowV1(
        protocol_id=cast(PrivacyProtocolIdV1, PRIVACY_PROTOCOL_IDS_V1[row_index]),
        statement_norito=statement,
        envelope_norito=envelope,
        submit_proof_wire_id=wire_id,
        submit_proof_instruction_norito=instruction,
        transaction_intent_projection_norito=projection,
        transaction_intent_digest=intent_digest,
        unsigned_transaction_payload_norito=unsigned,
        signed_transaction_versioned_norito=signed,
        signed_transaction_hash=transaction_hash,
    )


def _raw_vector_v1(value: bytes) -> bytes:
    return struct.pack("<Q", len(value)) + value


def _string_value_v1(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _encode_field_v1(encoded)


def _encode_row_v1(row: PrivacyExact12TypedFixtureRowV1, row_index: int) -> bytes:
    return _encode_fields_v1(
        (
            struct.pack("<I", row_index),
            _raw_vector_v1(row.statement_norito),
            _raw_vector_v1(row.envelope_norito),
            _string_value_v1(row.submit_proof_wire_id),
            _raw_vector_v1(row.submit_proof_instruction_norito),
            _raw_vector_v1(row.transaction_intent_projection_norito),
            row.transaction_intent_digest,
            _raw_vector_v1(row.unsigned_transaction_payload_norito),
            _raw_vector_v1(row.signed_transaction_versioned_norito),
            row.signed_transaction_hash,
        )
    )


def _snapshot_row_v1(row: PrivacyExact12TypedFixtureRowV1) -> PrivacyExact12TypedFixtureRowV1:
    return PrivacyExact12TypedFixtureRowV1(
        protocol_id=row.protocol_id,
        statement_norito=row.statement_norito,
        envelope_norito=row.envelope_norito,
        submit_proof_wire_id=row.submit_proof_wire_id,
        submit_proof_instruction_norito=row.submit_proof_instruction_norito,
        transaction_intent_projection_norito=row.transaction_intent_projection_norito,
        transaction_intent_digest=row.transaction_intent_digest,
        unsigned_transaction_payload_norito=row.unsigned_transaction_payload_norito,
        signed_transaction_versioned_norito=row.signed_transaction_versioned_norito,
        signed_transaction_hash=row.signed_transaction_hash,
    )


def _validated_bundle_snapshot_v1(bundle: object) -> PrivacyExact12FixtureBundleV1:
    if type(bundle) is not PrivacyExact12FixtureBundleV1:
        raise TypeError("bundle must be a PrivacyExact12FixtureBundleV1")
    typed = cast(PrivacyExact12FixtureBundleV1, bundle)
    return PrivacyExact12FixtureBundleV1(
        version=typed.version,
        rows=tuple(_snapshot_row_v1(row) for row in typed.rows),
    )


def _encode_bundle_v1(bundle: PrivacyExact12FixtureBundleV1) -> bytes:
    rows = struct.pack("<Q", len(bundle.rows)) + b"".join(
        _encode_field_v1(_encode_row_v1(row, index)) for index, row in enumerate(bundle.rows)
    )
    payload = _encode_fields_v1((struct.pack("<I", bundle.version), rows))
    archive = _encode_frame_v1(
        payload,
        PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1,
        _NRT_OUTER_PADDING_V1,
    )
    if len(archive) > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1:
        raise PrivacyExact12FixtureErrorV1("Exact12 canonical archive exceeds 2 MiB")
    return archive


def _decode_bundle_snapshot_v1(archive: bytes) -> PrivacyExact12FixtureBundleV1:
    payload = _decode_frame_v1(
        archive,
        schema_name=PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1,
        expected_padding=_NRT_OUTER_PADDING_V1,
        maximum=PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1,
        context="PrivacyExact12FixtureBundleV1",
    )
    reader = _ReaderV1(payload, "PrivacyExact12FixtureBundleV1.payload")
    version_field = reader.read_field("version", maximum=4, minimum=4)
    version = struct.unpack("<I", version_field)[0]
    if version != PRIVACY_EXACT12_FIXTURE_BUNDLE_VERSION_V1:
        raise PrivacyExact12FixtureErrorV1("Exact12 bundle version must be exactly 1")
    rows_field = reader.read_field(
        "rows", maximum=PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1, minimum=8
    )
    reader.require_end()
    rows_reader = _ReaderV1(rows_field, "PrivacyExact12FixtureBundleV1.rows")
    count = rows_reader.read_u64("count")
    if count != PRIVACY_EXACT12_FIXTURE_BUNDLE_ROW_COUNT_V1:
        raise PrivacyExact12FixtureErrorV1("Exact12 bundle must declare exactly 12 rows")
    budget = _DecodeBudgetV1(PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_AGGREGATE_NESTED_BYTES_V1)
    rows = tuple(
        _decode_row_v1(
            rows_reader.read_field(
                f"row[{index}]",
                maximum=PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1,
                minimum=1,
            ),
            index,
            budget,
        )
        for index in range(PRIVACY_EXACT12_FIXTURE_BUNDLE_ROW_COUNT_V1)
    )
    rows_reader.require_end()
    bundle = PrivacyExact12FixtureBundleV1(version=version, rows=rows)
    if not hmac.compare_digest(_encode_bundle_v1(bundle), archive):
        raise PrivacyExact12FixtureErrorV1(
            "Exact12 archive is non-canonical or contains unknown/trailing data"
        )
    return bundle


def decode_privacy_exact12_fixture_bundle_v1(archive: object) -> PrivacyExact12FixtureBundleV1:
    """Decode one bounded canonical archive from an immutable input snapshot."""

    snapshot = _snapshot_bytes_v1(
        archive,
        PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1,
        "Exact12 fixture archive",
    )
    return _decode_bundle_snapshot_v1(snapshot)


def encode_privacy_exact12_fixture_bundle_v1(bundle: object) -> bytes:
    """Encode one deeply validated typed bundle as canonical Norito bytes."""

    return _encode_bundle_v1(_validated_bundle_snapshot_v1(bundle))


def privacy_exact12_canonical_base64_encoded_length_v1(decoded_byte_count: int) -> int:
    """Return the exact padded standard-Base64 length without allocating it."""

    if type(decoded_byte_count) is not int or decoded_byte_count < 0:
        raise TypeError("decoded_byte_count must be a non-negative integer")
    if decoded_byte_count > sys.maxsize - 2:
        raise PrivacyExact12FixtureErrorV1("canonical Base64 length exceeds platform bounds")
    return ((decoded_byte_count + 2) // 3) * 4


def decode_privacy_exact12_fixture_bundle_base64_v1(
    encoded: str,
) -> PrivacyExact12FixtureBundleV1:
    """Decode exact padded STANDARD Base64 without whitespace or aliases."""

    if type(encoded) is not str or not encoded:
        raise TypeError("Exact12 fixture Base64 must be a non-empty string")
    maximum = privacy_exact12_canonical_base64_encoded_length_v1(
        PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1
    )
    if len(encoded) > maximum:
        raise PrivacyExact12FixtureErrorV1("Exact12 fixture Base64 exceeds the archive limit")
    if len(encoded) % 4 or _BASE64_RE_V1.fullmatch(encoded) is None:
        raise PrivacyExact12FixtureErrorV1(
            "Exact12 fixture must use canonical padded standard Base64"
        )
    padding = len(encoded) - len(encoded.rstrip("="))
    decoded_length = len(encoded) // 4 * 3 - padding
    if decoded_length <= 0 or decoded_length > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1:
        raise PrivacyExact12FixtureErrorV1("Exact12 Base64 declares an invalid archive size")
    try:
        archive = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise PrivacyExact12FixtureErrorV1(
            "Exact12 fixture must use canonical padded standard Base64"
        ) from error
    if base64.b64encode(archive).decode("ascii") != encoded:
        raise PrivacyExact12FixtureErrorV1("Exact12 fixture Base64 is not canonical")
    return _decode_bundle_snapshot_v1(archive)


def decode_privacy_exact12_fixture_bundle_base64_file_v1(
    contents: str,
) -> PrivacyExact12FixtureBundleV1:
    """Decode the checked fixture-file form: one line followed by exactly one LF."""

    if type(contents) is not str:
        raise TypeError("Exact12 fixture file contents must be a string")
    if not contents.endswith("\n") or contents.endswith("\n\n"):
        raise PrivacyExact12FixtureErrorV1("Exact12 fixture file must end with exactly one LF")
    encoded = contents[:-1]
    if "\n" in encoded or "\r" in encoded:
        raise PrivacyExact12FixtureErrorV1(
            "Exact12 fixture Base64 must be one unwrapped LF-terminated line"
        )
    return decode_privacy_exact12_fixture_bundle_base64_v1(encoded)


def encode_privacy_exact12_fixture_bundle_base64_v1(bundle: object) -> str:
    """Encode one validated typed bundle as canonical padded standard Base64."""

    return base64.b64encode(encode_privacy_exact12_fixture_bundle_v1(bundle)).decode("ascii")


def require_trusted_privacy_exact12_fixture_bundle_v1(
    candidate: object,
    trusted_canonical_archive: object,
) -> PrivacyExact12FixtureBundleV1:
    """Validate two snapshots and require candidate identity with the trusted Rust archive.

    Structural validation intentionally cannot authenticate a substituted but
    well-formed Ed25519 signature or opaque proof body. Byte identity with an
    independently supplied Rust-derived archive closes those final bindings.
    """

    candidate_snapshot = _snapshot_bytes_v1(
        candidate,
        PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1,
        "candidate Exact12 fixture archive",
    )
    trusted_snapshot = _snapshot_bytes_v1(
        trusted_canonical_archive,
        PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1,
        "trusted Exact12 fixture archive",
    )
    _decode_bundle_snapshot_v1(trusted_snapshot)
    decoded = _decode_bundle_snapshot_v1(candidate_snapshot)
    if not hmac.compare_digest(candidate_snapshot, trusted_snapshot):
        raise PrivacyExact12FixtureErrorV1(
            "Exact12 fixture differs from the independently trusted canonical archive"
        )
    return decoded


class PrivacyExact12FixtureCodecV1:
    """Static facade matching the other first-release SDK Exact12 codecs."""

    decode_canonical = staticmethod(decode_privacy_exact12_fixture_bundle_v1)
    encode_canonical = staticmethod(encode_privacy_exact12_fixture_bundle_v1)
    decode_canonical_base64 = staticmethod(decode_privacy_exact12_fixture_bundle_base64_v1)
    decode_canonical_base64_file = staticmethod(
        decode_privacy_exact12_fixture_bundle_base64_file_v1
    )
    encode_canonical_base64 = staticmethod(encode_privacy_exact12_fixture_bundle_base64_v1)
    require_trusted_canonical = staticmethod(require_trusted_privacy_exact12_fixture_bundle_v1)
    canonical_base64_encoded_length = staticmethod(
        privacy_exact12_canonical_base64_encoded_length_v1
    )


__all__ = [
    "PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1",
    "PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1",
    "PRIVACY_EXACT12_FIXTURE_BUNDLE_VERSION_V1",
    "PRIVACY_EXACT12_FIXTURE_BUNDLE_ROW_COUNT_V1",
    "PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1",
    "PRIVACY_EXACT12_PROTOCOL_IDS_V1",
    "PrivacyExact12FixtureErrorV1",
    "PrivacyExact12TypedFixtureRowV1",
    "PrivacyExact12FixtureBundleV1",
    "PrivacyExact12FixtureCodecV1",
    "decode_privacy_exact12_fixture_bundle_v1",
    "encode_privacy_exact12_fixture_bundle_v1",
    "decode_privacy_exact12_fixture_bundle_base64_v1",
    "decode_privacy_exact12_fixture_bundle_base64_file_v1",
    "encode_privacy_exact12_fixture_bundle_base64_v1",
    "require_trusted_privacy_exact12_fixture_bundle_v1",
    "privacy_exact12_canonical_base64_encoded_length_v1",
]
