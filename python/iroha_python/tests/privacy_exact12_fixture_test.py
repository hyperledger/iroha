"""Strict native-independent Exact12 typed fixture bundle conformance tests."""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any, Callable, cast

import pytest

import iroha_python
import iroha_python.privacy_exact12 as exact12_module
from iroha_python.privacy_catalog import PRIVACY_PROTOCOL_IDS_V1
from iroha_python.privacy_exact12 import (
    PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1,
    PRIVACY_EXACT12_FIXTURE_BUNDLE_ROW_COUNT_V1,
    PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1,
    PRIVACY_EXACT12_PROTOCOL_IDS_V1,
    PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1,
    PrivacyExact12FixtureBundleV1,
    PrivacyExact12FixtureCodecV1,
    PrivacyExact12FixtureErrorV1,
    PrivacyExact12TypedFixtureRowV1,
    decode_privacy_exact12_fixture_bundle_base64_file_v1,
    decode_privacy_exact12_fixture_bundle_base64_v1,
    decode_privacy_exact12_fixture_bundle_v1,
    encode_privacy_exact12_fixture_bundle_base64_v1,
    encode_privacy_exact12_fixture_bundle_v1,
    privacy_exact12_canonical_base64_encoded_length_v1,
    require_trusted_privacy_exact12_fixture_bundle_v1,
)

ROOT = Path(__file__).resolve().parents[3]
FIXTURE_PATH = ROOT / "fixtures" / "privacy" / "exact12_typed_fixture_bundle_v1.norito.b64"
MATRIX_PATH = ROOT / "fixtures" / "privacy" / "exact12_v1.tsv"
FIXTURE_FILE = FIXTURE_PATH.read_text(encoding="ascii")
FIXTURE_BASE64 = FIXTURE_FILE[:-1]
FIXTURE_BYTES = base64.b64decode(FIXTURE_BASE64, validate=True)

STATEMENT_SCHEMA = "iroha.privacy.statement.v1"
ENVELOPE_SCHEMA = "iroha.privacy.proof-envelope.v1"
INSTRUCTION_SCHEMA = "iroha_data_model::isi::privacy::SubmitPrivacyProofV1"
TRANSACTION_SCHEMA = "iroha_data_model::transaction::signed::model::TransactionPayload"
CRC64_POLYNOMIAL = 0xC96C_5795_D787_0F42
CRC64_MASK = 0xFFFF_FFFF_FFFF_FFFF
PROOF_ENGINE_TAGS = (0, 2, 3, 1, 4, 0, 5, 8, 6, 7, 0, 0)


def _compact(value: int) -> bytes:
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def test_exact12_transaction_domain_requires_one_marked_network_id() -> None:
    network_id = bytes.fromhex("a4" * 31 + "a5")
    archive = struct.pack("<I", 0) + _compact(len(network_id)) + network_id
    assert (
        exact12_module._decode_network_transaction_domain_v1(archive, "transaction.domain")
        == network_id
    )

    for retired_or_malformed in (
        struct.pack("<I", 1),
        struct.pack("<I", 0) + _compact(4) + b"test",
        struct.pack("<I", 0) + _compact(32) + bytes(32),
        struct.pack("<I", 0) + b"\xa0\x00" + network_id,
    ):
        with pytest.raises(PrivacyExact12FixtureErrorV1):
            exact12_module._decode_network_transaction_domain_v1(
                retired_or_malformed, "transaction.domain"
            )


def test_goldilocks_digest_requires_six_raw_canonical_limbs() -> None:
    canonical = struct.pack("<6Q", 1, 2, 3, 4, 5, 6)
    assert exact12_module._decode_goldilocks_digest384_v1(
        canonical, "digest", allow_zero=False
    ) == canonical
    assert exact12_module._decode_goldilocks_digest384_v1(
        bytes(48), "digest", allow_zero=True
    ) == bytes(48)
    hostile = [bytes(32), b"\x30" + canonical, canonical[:-1], bytes(48)]
    for index in range(6):
        limbs = [1] * 6
        limbs[index] = 0xFFFF_FFFF_0000_0001
        hostile.append(struct.pack("<6Q", *limbs))
    for payload in hostile:
        with pytest.raises(PrivacyExact12FixtureErrorV1):
            exact12_module._decode_goldilocks_digest384_v1(payload, "digest", allow_zero=False)


def test_envelope_requires_final_marker_and_exact_catalog_commitment() -> None:
    bundle = _bundle()
    row = bundle.rows[0]
    original = _fields(_frame_payload(row.envelope_norito, 8), 13)
    assert original[0] == b"IRHZK1\xa5\x5a"
    assert original[1] == bytes.fromhex("5bcf366fb18d2e4361486c015da5b41a3fb00edf05611042ccc452120d176eb0")
    assert len(original[1]) == 32
    for index, offsets, match in ((0, (0, 7), "wire marker"), (1, range(32), "catalog commitment")):
        for offset in offsets:
            fields = list(original)
            changed = bytearray(fields[index])
            changed[offset] ^= 1
            fields[index] = bytes(changed)
            envelope = _frame(_encode_fields(fields), ENVELOPE_SCHEMA, 8)
            _assert_row_rejected(bundle, 0, replace(row, envelope_norito=envelope), match)
    for hostile in (
        original[1][:-1], original[1] + b"\x00", original[1] + bytes(16),
        bytes.fromhex("e037f13904a0307c00db15d85cfb406bd79772d20144a949def0f3fda78e342e747f65787cbfbffac94f11c369e2bbff"),
    ):
        fields = list(original)
        fields[1] = hostile
        envelope = _frame(_encode_fields(fields), ENVELOPE_SCHEMA, 8)
        _assert_row_rejected(bundle, 0, replace(row, envelope_norito=envelope), "catalog commitment")
    retired = _frame(_encode_fields(original[2:]), ENVELOPE_SCHEMA, 8)
    _assert_row_rejected(bundle, 0, replace(row, envelope_norito=retired))


def _read_compact(payload: bytes | bytearray, offset: int) -> tuple[int, int]:
    value = 0
    for used in range(10):
        current = payload[offset + used]
        value |= (current & 0x7F) << (7 * used)
        if current & 0x80 == 0:
            return value, used + 1
    raise AssertionError("test fixture contains an invalid compact length")


def _read_field(payload: bytes | bytearray, offset: int) -> tuple[bytes, int, int]:
    length, prefix = _read_compact(payload, offset)
    start = offset + prefix
    end = start + length
    assert end <= len(payload)
    return bytes(payload[start:end]), start, end


def _fields(payload: bytes, count: int) -> list[bytes]:
    output: list[bytes] = []
    offset = 0
    for _ in range(count):
        field, _, offset = _read_field(payload, offset)
        output.append(field)
    assert offset == len(payload)
    return output


def _encode_fields(fields: list[bytes] | tuple[bytes, ...]) -> bytes:
    return b"".join(_compact(len(field)) + field for field in fields)


def _crc64(payload: bytes) -> int:
    crc = CRC64_MASK
    for byte in payload:
        entry = (crc ^ byte) & 0xFF
        for _ in range(8):
            entry = entry >> 1 if entry & 1 == 0 else (entry >> 1) ^ CRC64_POLYNOMIAL
        crc = entry ^ (crc >> 8)
    return (crc ^ CRC64_MASK) & CRC64_MASK


def _schema_hash(schema: str) -> bytes:
    return hashlib.sha256(b"norito:v1:type-name\0" + schema.encode()).digest()[:16]


def _frame(payload: bytes, schema: str, padding: int) -> bytes:
    return b"".join(
        (
            b"NRT0\x00\x00",
            _schema_hash(schema),
            b"\x00",
            struct.pack("<Q", len(payload)),
            struct.pack("<Q", _crc64(payload)),
            b"\x02",
            bytes(padding),
            payload,
        )
    )


def _frame_payload(archive: bytes, padding: int) -> bytes:
    length = struct.unpack_from("<Q", archive, 23)[0]
    assert len(archive) == 40 + padding + length
    return archive[40 + padding :]


def _rewrite_outer_crc(archive: bytearray) -> None:
    length = struct.unpack_from("<Q", archive, 23)[0]
    payload = bytes(archive[-length:])
    struct.pack_into("<Q", archive, 31, _crc64(payload))


def _bundle() -> PrivacyExact12FixtureBundleV1:
    return decode_privacy_exact12_fixture_bundle_base64_file_v1(FIXTURE_FILE)


def _replace_bundle_row(
    bundle: PrivacyExact12FixtureBundleV1,
    index: int,
    row: PrivacyExact12TypedFixtureRowV1,
) -> PrivacyExact12FixtureBundleV1:
    rows = list(bundle.rows)
    rows[index] = row
    return PrivacyExact12FixtureBundleV1(version=1, rows=tuple(rows))


def _assert_row_rejected(
    bundle: PrivacyExact12FixtureBundleV1,
    index: int,
    row: PrivacyExact12TypedFixtureRowV1,
    match: str | None = None,
) -> None:
    with pytest.raises(PrivacyExact12FixtureErrorV1, match=match):
        _replace_bundle_row(bundle, index, row)


def _mutate_frame_field(
    archive: bytes,
    *,
    schema: str,
    padding: int,
    field_count: int,
    field_index: int,
    replacement: bytes,
) -> bytes:
    fields = _fields(_frame_payload(archive, padding), field_count)
    fields[field_index] = replacement
    return _frame(_encode_fields(fields), schema, padding)


def _extract_instruction_archive(executable: bytes) -> tuple[list[bytes], list[bytes], bytes]:
    assert struct.unpack_from("<I", executable)[0] == 0
    sequence, _, end = _read_field(executable, 4)
    assert end == len(executable) and struct.unpack_from("<Q", sequence)[0] == 1
    instruction_box, _, sequence_end = _read_field(sequence, 8)
    assert sequence_end == len(sequence)
    box_fields = _fields(instruction_box, 2)
    raw_instruction = box_fields[1]
    length = struct.unpack_from("<Q", raw_instruction)[0]
    assert length == len(raw_instruction) - 8
    return box_fields, [sequence[:8]], raw_instruction[8:]


def _replace_executable_instruction(executable: bytes, instruction: bytes) -> bytes:
    box_fields, sequence_prefix, _ = _extract_instruction_archive(executable)
    box_fields[1] = struct.pack("<Q", len(instruction)) + instruction
    instruction_box = _encode_fields(box_fields)
    sequence = sequence_prefix[0] + _compact(len(instruction_box)) + instruction_box
    return struct.pack("<I", 0) + _compact(len(sequence)) + sequence


def _projection_with_envelope(
    row: PrivacyExact12TypedFixtureRowV1,
    mutate: Callable[[list[bytes]], None],
) -> bytes:
    transaction_fields = _fields(_frame_payload(row.transaction_intent_projection_norito, 0), 9)
    _, _, instruction = _extract_instruction_archive(transaction_fields[3])
    instruction_fields = _fields(_frame_payload(instruction, 8), 1)
    envelope_fields = _fields(instruction_fields[0], 13)
    mutate(envelope_fields)
    instruction_fields[0] = _encode_fields(envelope_fields)
    rebuilt_instruction = _frame(_encode_fields(instruction_fields), INSTRUCTION_SCHEMA, 8)
    transaction_fields[3] = _replace_executable_instruction(
        transaction_fields[3], rebuilt_instruction
    )
    return _frame(_encode_fields(transaction_fields), TRANSACTION_SCHEMA, 0)


def _replace_projected_statement(
    row: PrivacyExact12TypedFixtureRowV1,
    mutate: Callable[[list[bytes]], None],
) -> bytes:
    def mutate_envelope(envelope_fields: list[bytes]) -> None:
        tagged = envelope_fields[11]
        statement_tag = tagged[:4]
        statement_variant, _, end = _read_field(tagged, 4)
        assert end == len(tagged)
        statement_fields = _fields(
            statement_variant,
            (11, 10, 6, 9, 15, 20, 4, 8, 9, 8, 13, 13)[struct.unpack("<I", statement_tag)[0]],
        )
        mutate(statement_fields)
        variant = _encode_fields(statement_fields)
        envelope_fields[11] = statement_tag + _compact(len(variant)) + variant

    return _projection_with_envelope(row, mutate_envelope)


def _transaction_hash(unsigned: bytes) -> bytes:
    digest = bytearray(
        hashlib.blake2b(
            struct.pack("<I", 0) + _compact(len(unsigned)) + unsigned, digest_size=32
        ).digest()
    )
    digest[-1] |= 1
    return bytes(digest)


def test_checked_fixture_decodes_all_rows_and_reencodes_byte_identically() -> None:
    assert FIXTURE_FILE.endswith("\n") and not FIXTURE_FILE.endswith("\n\n")
    assert "\n" not in FIXTURE_BASE64 and "\r" not in FIXTURE_FILE
    assert base64.b64encode(FIXTURE_BYTES).decode() == FIXTURE_BASE64
    assert len(FIXTURE_BYTES) <= PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1

    bundle = _bundle()
    matrix_ids = tuple(
        line.split("\t")[2]
        for line in MATRIX_PATH.read_text(encoding="utf-8").splitlines()
        if line.startswith("protocol\t")
    )
    assert bundle.version == 1
    assert len(bundle.rows) == PRIVACY_EXACT12_FIXTURE_BUNDLE_ROW_COUNT_V1
    assert tuple(row.protocol_id for row in bundle.rows) == PRIVACY_PROTOCOL_IDS_V1
    assert PRIVACY_EXACT12_PROTOCOL_IDS_V1 == PRIVACY_PROTOCOL_IDS_V1 == matrix_ids
    assert all(
        row.submit_proof_wire_id == PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1 for row in bundle.rows
    )
    assert encode_privacy_exact12_fixture_bundle_v1(bundle) == FIXTURE_BYTES
    assert encode_privacy_exact12_fixture_bundle_base64_v1(bundle) == FIXTURE_BASE64
    assert decode_privacy_exact12_fixture_bundle_v1(FIXTURE_BYTES) == bundle
    assert PrivacyExact12FixtureCodecV1.decode_canonical(FIXTURE_BYTES) == bundle
    assert PrivacyExact12FixtureCodecV1.encode_canonical(bundle) == FIXTURE_BYTES
    assert iroha_python.PrivacyExact12FixtureCodecV1 is PrivacyExact12FixtureCodecV1
    assert (
        iroha_python.decode_privacy_exact12_fixture_bundle_v1
        is decode_privacy_exact12_fixture_bundle_v1
    )


@pytest.mark.parametrize(
    "scope",
    (
        struct.pack("<I", 0),
        b"\x01\x00\x00\x00\x09\x08" + struct.pack("<Q", 1),
        b"\x01\x00\x00\x00\x09\x08" + struct.pack("<Q", 0xFFFF_FFFF_FFFF_FFFF),
    ),
)
def test_exact12_public_balance_scope_wire_accepts_only_canonical_usable_values(
    scope: bytes,
) -> None:
    exact12_module._validate_public_balance_scope_v1(scope, "scope")


@pytest.mark.parametrize(
    "scope",
    (
        b"",
        struct.pack("<I", 0) + b"\x00",
        struct.pack("<I", 2),
        struct.pack("<I", 1),
        b"\x01\x00\x00\x00\x08\x08" + struct.pack("<Q", 1),
        b"\x01\x00\x00\x00\x09\x08" + struct.pack("<Q", 0),
        b"\x01\x00\x00\x00\x09\x08" + bytes(7),
        b"\x01\x00\x00\x00\x09\x08" + bytes(9),
        b"\x01\x00\x00\x00\x89\x00\x08" + struct.pack("<Q", 1),
    ),
)
def test_exact12_public_balance_scope_wire_rejects_unknown_universal_and_alias_shapes(
    scope: bytes,
) -> None:
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="public balance scope"):
        exact12_module._validate_public_balance_scope_v1(scope, "scope")


def test_models_snapshot_mutable_inputs_and_are_immutable() -> None:
    canonical = _bundle()
    source_statement = bytearray(canonical.rows[0].statement_norito)
    row = PrivacyExact12TypedFixtureRowV1(
        protocol_id=canonical.rows[0].protocol_id,
        statement_norito=cast(bytes, source_statement),
        envelope_norito=cast(bytes, bytearray(canonical.rows[0].envelope_norito)),
        submit_proof_wire_id=canonical.rows[0].submit_proof_wire_id,
        submit_proof_instruction_norito=cast(
            bytes, memoryview(canonical.rows[0].submit_proof_instruction_norito)
        ),
        transaction_intent_projection_norito=canonical.rows[0].transaction_intent_projection_norito,
        transaction_intent_digest=canonical.rows[0].transaction_intent_digest,
        unsigned_transaction_payload_norito=canonical.rows[0].unsigned_transaction_payload_norito,
        signed_transaction_versioned_norito=canonical.rows[0].signed_transaction_versioned_norito,
        signed_transaction_hash=canonical.rows[0].signed_transaction_hash,
    )
    source_statement[-1] ^= 0xFF
    assert row.statement_norito == canonical.rows[0].statement_norito
    assert type(row.statement_norito) is bytes

    mutable_rows = [row, *canonical.rows[1:]]
    copied = PrivacyExact12FixtureBundleV1(version=1, rows=cast(Any, mutable_rows))
    mutable_rows.reverse()
    assert copied.rows == canonical.rows
    assert type(copied.rows) is tuple
    with pytest.raises(FrozenInstanceError):
        copied.version = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        copied.rows[0].protocol_id = copied.rows[1].protocol_id  # type: ignore[misc]
    with pytest.raises(TypeError, match="contiguous"):
        replace(row, statement_norito=cast(bytes, memoryview(bytearray(100))[::2]))


def test_decode_snapshots_bytearray_and_memoryview_before_validation() -> None:
    mutable = bytearray(FIXTURE_BYTES)
    decoded = decode_privacy_exact12_fixture_bundle_v1(mutable)
    mutable[-1] ^= 0xFF
    assert encode_privacy_exact12_fixture_bundle_v1(decoded) == FIXTURE_BYTES

    backing = bytearray(FIXTURE_BYTES)
    decoded_view = decode_privacy_exact12_fixture_bundle_v1(memoryview(backing))
    backing[0] = 0
    assert encode_privacy_exact12_fixture_bundle_v1(decoded_view) == FIXTURE_BYTES


def test_typed_models_reject_wrong_types_versions_counts_order_and_zero_hashes() -> None:
    bundle = _bundle()
    with pytest.raises(TypeError, match="PrivacyExact12FixtureBundleV1"):
        encode_privacy_exact12_fixture_bundle_v1({"version": 1, "rows": bundle.rows})
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="version"):
        PrivacyExact12FixtureBundleV1(version=2, rows=bundle.rows)
    for rows in (bundle.rows[:-1], bundle.rows + (bundle.rows[-1],)):
        with pytest.raises(PrivacyExact12FixtureErrorV1, match="exactly 12"):
            PrivacyExact12FixtureBundleV1(version=1, rows=rows)
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="out of order"):
        PrivacyExact12FixtureBundleV1(
            version=1,
            rows=(bundle.rows[1], bundle.rows[0], *bundle.rows[2:]),
        )
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="closed Exact12 registry"):
        replace(bundle.rows[0], protocol_id=cast(Any, "legacy-zk-ace"))
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="non-zero"):
        replace(bundle.rows[0], transaction_intent_digest=bytes(32))
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="non-zero"):
        replace(bundle.rows[0], signed_transaction_hash=bytes(32))
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="must not be empty"):
        replace(bundle.rows[0], statement_norito=b"")
    with pytest.raises(TypeError, match="bytes, bytearray, or memoryview"):
        replace(bundle.rows[0], envelope_norito=cast(Any, [1, 2, 3]))


@pytest.mark.parametrize(
    "alternate",
    (
        FIXTURE_BASE64 + "\n",
        " " + FIXTURE_BASE64,
        FIXTURE_BASE64 + " ",
        FIXTURE_BASE64[:-1],
        FIXTURE_BASE64.replace("+", "-", 1),
        FIXTURE_BASE64.replace("/", "_", 1),
    ),
)
def test_base64_rejects_whitespace_unpadded_and_urlsafe_aliases(alternate: str) -> None:
    with pytest.raises((TypeError, PrivacyExact12FixtureErrorV1)):
        decode_privacy_exact12_fixture_bundle_base64_v1(alternate)


def test_base64_file_and_pad_bits_are_exact() -> None:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    final_index = alphabet.index(FIXTURE_BASE64[-2])
    assert final_index & 0x03 == 0
    noncanonical = FIXTURE_BASE64[:-2] + alphabet[final_index | 1] + "="
    assert base64.b64decode(noncanonical) == FIXTURE_BYTES
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="canonical"):
        decode_privacy_exact12_fixture_bundle_base64_v1(noncanonical)
    for contents in (FIXTURE_BASE64, FIXTURE_BASE64 + "\r\n", FIXTURE_FILE + "\n", "\n"):
        with pytest.raises((TypeError, PrivacyExact12FixtureErrorV1)):
            decode_privacy_exact12_fixture_bundle_base64_file_v1(contents)
    maximum = privacy_exact12_canonical_base64_encoded_length_v1(
        PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1
    )
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="archive limit"):
        decode_privacy_exact12_fixture_bundle_base64_v1("A" * (maximum + 1))
    with pytest.raises(TypeError):
        privacy_exact12_canonical_base64_encoded_length_v1(True)


@pytest.mark.parametrize("cut", (0, 1, 4, 21, 39, 40, len(FIXTURE_BYTES) - 1))
def test_outer_frame_rejects_hostile_truncation(cut: int) -> None:
    with pytest.raises(PrivacyExact12FixtureErrorV1):
        decode_privacy_exact12_fixture_bundle_v1(FIXTURE_BYTES[:cut])


@pytest.mark.parametrize(
    ("offset", "value"),
    (
        (0, 0),
        (4, 1),
        (6, 0),
        (22, 1),
        (23, 0),
        (31, 0),
        (39, 0),
    ),
)
def test_outer_frame_rejects_header_schema_length_crc_and_flags(offset: int, value: int) -> None:
    mutated = bytearray(FIXTURE_BYTES)
    mutated[offset] = value if mutated[offset] != value else value ^ 0x80
    with pytest.raises(PrivacyExact12FixtureErrorV1):
        decode_privacy_exact12_fixture_bundle_v1(mutated)
    with pytest.raises(PrivacyExact12FixtureErrorV1):
        decode_privacy_exact12_fixture_bundle_v1(FIXTURE_BYTES + b"\x00")
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="exceeds"):
        decode_privacy_exact12_fixture_bundle_v1(
            bytes(PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 + 1)
        )


def test_decoder_rejects_nonminimal_compact_prefixes_counts_lengths_and_unknown_fields() -> None:
    payload = _frame_payload(FIXTURE_BYTES, 0)
    version, _, version_end = _read_field(payload, 0)
    rows, _, rows_end = _read_field(payload, version_end)
    assert rows_end == len(payload)

    nonminimal_payload = b"\x84\x00" + payload[1:]
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="minimally"):
        decode_privacy_exact12_fixture_bundle_v1(
            _frame(nonminimal_payload, PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1, 0)
        )

    wrong_count = struct.pack("<Q", 13) + rows[8:]
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="exactly 12"):
        decode_privacy_exact12_fixture_bundle_v1(
            _frame(
                _encode_fields([version, wrong_count]),
                PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1,
                0,
            )
        )

    huge_first_row = struct.pack("<Q", 12) + _compact(
        PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 + 1
    )
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="length"):
        decode_privacy_exact12_fixture_bundle_v1(
            _frame(
                _encode_fields([version, huge_first_row]),
                PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1,
                0,
            )
        )

    first_row, _, first_end = _read_field(rows, 8)
    row_fields = _fields(first_row, 10)
    statement_raw = bytearray(row_fields[1])
    struct.pack_into("<Q", statement_raw, 0, 256 * 1024 + 1)
    row_fields[1] = bytes(statement_raw)
    malformed_row = _encode_fields(row_fields)
    rebuilt_rows = (
        struct.pack("<Q", 12) + _compact(len(malformed_row)) + malformed_row + rows[first_end:]
    )
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="byte-vector length"):
        decode_privacy_exact12_fixture_bundle_v1(
            _frame(
                _encode_fields([version, rebuilt_rows]),
                PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1,
                0,
            )
        )

    row_with_unknown_tail = first_row + b"\x00"
    rebuilt_rows = (
        struct.pack("<Q", 12)
        + _compact(len(row_with_unknown_tail))
        + row_with_unknown_tail
        + rows[first_end:]
    )
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="trailing|unknown"):
        decode_privacy_exact12_fixture_bundle_v1(
            _frame(
                _encode_fields([version, rebuilt_rows]),
                PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1,
                0,
            )
        )


def test_raw_archive_rejects_reordered_duplicate_and_unknown_protocol_rows() -> None:
    payload = _frame_payload(FIXTURE_BYTES, 0)
    version, _, version_end = _read_field(payload, 0)
    rows, _, _ = _read_field(payload, version_end)
    first, first_start, first_end = _read_field(rows, 8)
    second, _, second_end = _read_field(rows, first_end)
    first_wire = rows[8:first_end]
    second_wire = rows[first_end:second_end]
    reordered_rows = rows[:8] + second_wire + first_wire + rows[second_end:]
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="reordered|substituted"):
        decode_privacy_exact12_fixture_bundle_v1(
            _frame(
                _encode_fields([version, reordered_rows]),
                PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1,
                0,
            )
        )

    for tag, match in ((0, "duplicate|substituted"), (12, "unknown")):
        second_fields = _fields(second, 10)
        second_fields[0] = struct.pack("<I", tag)
        changed = _encode_fields(second_fields)
        changed_rows = rows[:first_end] + _compact(len(changed)) + changed + rows[second_end:]
        with pytest.raises(PrivacyExact12FixtureErrorV1, match=match):
            decode_privacy_exact12_fixture_bundle_v1(
                _frame(
                    _encode_fields([version, changed_rows]),
                    PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1,
                    0,
                )
            )
    assert first_start > 8 and first


@pytest.mark.parametrize("field_index", (3, 4))
def test_every_protocol_rejects_wrong_proof_system_and_engine_tags(field_index: int) -> None:
    bundle = _bundle()
    for index, row in enumerate(bundle.rows):
        wrong_tag = (PROOF_ENGINE_TAGS[index] + 1) % 9
        envelope = _mutate_frame_field(
            row.envelope_norito,
            schema=ENVELOPE_SCHEMA,
            padding=8,
            field_count=13,
            field_index=field_index,
            replacement=struct.pack("<I", wrong_tag),
        )
        _assert_row_rejected(bundle, index, replace(row, envelope_norito=envelope), "wrong")


def test_every_protocol_rejects_statement_envelope_and_proof_tag_substitution() -> None:
    bundle = _bundle()
    for index, row in enumerate(bundle.rows):
        wrong = (index + 1) % 12
        statement_payload = bytearray(_frame_payload(row.statement_norito, 8))
        struct.pack_into("<I", statement_payload, 0, wrong)
        statement = _frame(bytes(statement_payload), STATEMENT_SCHEMA, 8)
        _assert_row_rejected(bundle, index, replace(row, statement_norito=statement), "protocol")

        envelope_payload = _frame_payload(row.envelope_norito, 8)
        envelope_fields = _fields(envelope_payload, 13)
        envelope_fields[2] = struct.pack("<I", wrong)
        envelope = _frame(_encode_fields(envelope_fields), ENVELOPE_SCHEMA, 8)
        _assert_row_rejected(bundle, index, replace(row, envelope_norito=envelope), "protocol")

        envelope_fields = _fields(envelope_payload, 13)
        proof = bytearray(envelope_fields[12])
        struct.pack_into("<I", proof, 0, wrong)
        envelope_fields[12] = bytes(proof)
        envelope = _frame(_encode_fields(envelope_fields), ENVELOPE_SCHEMA, 8)
        _assert_row_rejected(bundle, index, replace(row, envelope_norito=envelope), "protocol")


def test_zk_ams_proof_action_tag_must_match_the_statement_action() -> None:
    bundle = _bundle()
    row = bundle.rows[3]
    envelope_fields = _fields(_frame_payload(row.envelope_norito, 8), 13)
    proof = bytearray(envelope_fields[12])
    outer_value, outer_start, _ = _read_field(proof, 4)
    assert struct.unpack_from("<I", outer_value)[0] == 0
    struct.pack_into("<I", proof, outer_start, 1)
    envelope_fields[12] = bytes(proof)
    envelope = _frame(_encode_fields(envelope_fields), ENVELOPE_SCHEMA, 8)
    _assert_row_rejected(bundle, 3, replace(row, envelope_norito=envelope), "protocol tag")


def test_byte_complete_fields_and_cross_row_substitutions_fail_closed() -> None:
    bundle = _bundle()
    byte_fields = (
        "statement_norito",
        "envelope_norito",
        "submit_proof_instruction_norito",
        "transaction_intent_projection_norito",
        "transaction_intent_digest",
        "unsigned_transaction_payload_norito",
        "signed_transaction_versioned_norito",
        "signed_transaction_hash",
    )
    for field in byte_fields:
        value = bytearray(getattr(bundle.rows[0], field))
        value[-1] ^= 0x80
        _assert_row_rejected(
            bundle,
            0,
            replace(bundle.rows[0], **cast(Any, {field: value})),
        )
        _assert_row_rejected(
            bundle,
            0,
            replace(bundle.rows[0], **{field: getattr(bundle.rows[1], field)}),
        )
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="wire identifier"):
        replace(bundle.rows[0], submit_proof_wire_id="iroha.privacy.submit-proof.legacy")


def test_governed_digest_statement_digest_and_instruction_envelope_bindings() -> None:
    bundle = _bundle()
    row = bundle.rows[0]
    envelope_fields = _fields(_frame_payload(row.envelope_norito, 8), 13)

    changed_digest = bytearray(envelope_fields[5])
    changed_digest[-1] ^= 1
    envelope_fields[5] = bytes(changed_digest)
    envelope = _frame(_encode_fields(envelope_fields), ENVELOPE_SCHEMA, 8)
    _assert_row_rejected(bundle, 0, replace(row, envelope_norito=envelope), "digest")

    envelope_fields = _fields(_frame_payload(row.envelope_norito, 8), 13)
    changed_digest = bytearray(envelope_fields[10])
    changed_digest[-1] ^= 1
    envelope_fields[10] = bytes(changed_digest)
    envelope = _frame(_encode_fields(envelope_fields), ENVELOPE_SCHEMA, 8)
    _assert_row_rejected(bundle, 0, replace(row, envelope_norito=envelope), "statement digest")

    instruction_fields = _fields(_frame_payload(row.submit_proof_instruction_norito, 8), 1)
    instruction_fields[0] = _frame_payload(bundle.rows[1].envelope_norito, 8)
    instruction = _frame(_encode_fields(instruction_fields), INSTRUCTION_SCHEMA, 8)
    _assert_row_rejected(
        bundle,
        0,
        replace(row, submit_proof_instruction_norito=instruction),
        "envelope",
    )

    for proof_bytes, match in ((b"", "present"), (bytes(3), "non-zero")):
        envelope_fields = _fields(_frame_payload(row.envelope_norito, 8), 13)
        proof_value = _encode_fields([struct.pack("<Q", len(proof_bytes)) + proof_bytes])
        envelope_fields[12] = struct.pack("<I", 0) + _compact(len(proof_value)) + proof_value
        envelope = _frame(_encode_fields(envelope_fields), ENVELOPE_SCHEMA, 8)
        _assert_row_rejected(bundle, 0, replace(row, envelope_norito=envelope), match)


@pytest.mark.parametrize("offset", (4, 6, 22, 31, 39, 40))
def test_nested_frames_reject_version_schema_compression_crc_flags_and_padding(
    offset: int,
) -> None:
    bundle = _bundle()
    row = bundle.rows[0]
    statement = bytearray(row.statement_norito)
    statement[offset] ^= 0x80
    _assert_row_rejected(
        bundle,
        0,
        replace(row, statement_norito=bytes(statement)),
    )


def test_closed_statement_schema_rejects_an_extra_compact_field() -> None:
    bundle = _bundle()
    row = bundle.rows[0]
    payload = _frame_payload(row.statement_norito, 8)
    variant, _, end = _read_field(payload, 4)
    assert end == len(payload)
    expanded_variant = variant + b"\x00"
    expanded = payload[:4] + _compact(len(expanded_variant)) + expanded_variant
    _assert_row_rejected(
        bundle,
        0,
        replace(row, statement_norito=_frame(expanded, STATEMENT_SCHEMA, 8)),
        "trailing|unknown",
    )


@pytest.mark.parametrize("field_index", (0, 1, 2, 4, 5, 6, 7, 8))
def test_unsigned_transaction_rejects_all_independent_field_mutations(field_index: int) -> None:
    bundle = _bundle()
    row = bundle.rows[0]
    fields = _fields(row.unsigned_transaction_payload_norito, 9)
    replacement = bytearray(fields[field_index])
    replacement[-1] ^= 1
    fields[field_index] = bytes(replacement)
    _assert_row_rejected(
        bundle,
        0,
        replace(row, unsigned_transaction_payload_norito=_encode_fields(fields)),
    )


def test_transaction_rejects_executable_count_wire_id_ttl_nonce_and_attachments() -> None:
    bundle = _bundle()
    row = bundle.rows[0]
    fields = _fields(row.unsigned_transaction_payload_norito, 9)

    executable = bytearray(fields[3])
    sequence, sequence_start, _ = _read_field(executable, 4)
    assert struct.unpack_from("<Q", sequence)[0] == 1
    struct.pack_into("<Q", executable, sequence_start, 2)
    changed = list(fields)
    changed[3] = bytes(executable)
    _assert_row_rejected(
        bundle,
        0,
        replace(row, unsigned_transaction_payload_norito=_encode_fields(changed)),
        "exactly one",
    )

    box_fields, _, instruction = _extract_instruction_archive(fields[3])
    wire = bytearray(box_fields[0])
    wire[-1] ^= 1
    box_fields[0] = bytes(wire)
    instruction_box = _encode_fields(box_fields)
    sequence = struct.pack("<Q", 1) + _compact(len(instruction_box)) + instruction_box
    changed[3] = struct.pack("<I", 0) + _compact(len(sequence)) + sequence
    _assert_row_rejected(
        bundle, 0, replace(row, unsigned_transaction_payload_norito=_encode_fields(changed)), "wire"
    )
    assert instruction

    for index, replacement, match in (
        (4, b"\x00", "TTL"),
        (5, b"\x00", "nonce"),
        (8, b"\x01\x00", "attachments"),
    ):
        changed = list(fields)
        changed[index] = replacement
        _assert_row_rejected(
            bundle,
            0,
            replace(row, unsigned_transaction_payload_norito=_encode_fields(changed)),
            match,
        )


@pytest.mark.parametrize("insertion_index", (7, 9))
def test_transaction_rejects_retired_admission_and_unknown_fields(insertion_index: int) -> None:
    bundle = _bundle()
    row = bundle.rows[0]
    fields = _fields(row.unsigned_transaction_payload_norito, 9)
    fields.insert(insertion_index, struct.pack("<I", 0))
    _assert_row_rejected(
        bundle,
        0,
        replace(row, unsigned_transaction_payload_norito=_encode_fields(fields)),
        "trailing|unknown",
    )


def test_projection_rejects_nonempty_proof_nonzero_digests_and_independent_changes() -> None:
    bundle = _bundle()
    row = bundle.rows[0]
    full_envelope = _fields(_frame_payload(row.envelope_norito, 8), 13)

    projection = _projection_with_envelope(
        row, lambda fields: fields.__setitem__(12, full_envelope[12])
    )
    _assert_row_rejected(
        bundle,
        0,
        replace(row, transaction_intent_projection_norito=projection),
        "remove all proof bytes",
    )

    projection = _projection_with_envelope(
        row, lambda fields: fields.__setitem__(10, full_envelope[10])
    )
    _assert_row_rejected(
        bundle,
        0,
        replace(row, transaction_intent_projection_norito=projection),
        "statement digest",
    )

    def restore_final_intent(statement_fields: list[bytes]) -> None:
        context_fields = _fields(statement_fields[0], 8)
        final_statement = _frame_payload(row.statement_norito, 8)
        final_variant, _, _ = _read_field(final_statement, 4)
        final_context = _fields(_fields(final_variant, 11)[0], 8)
        context_fields[2] = final_context[2]
        statement_fields[0] = _encode_fields(context_fields)

    projection = _replace_projected_statement(row, restore_final_intent)
    _assert_row_rejected(
        bundle,
        0,
        replace(row, transaction_intent_projection_norito=projection),
        "transaction-intent digest",
    )

    projection = _replace_projected_statement(
        row,
        lambda fields: fields.__setitem__(1, bytes([fields[1][0] ^ 1]) + fields[1][1:]),
    )
    _assert_row_rejected(
        bundle,
        0,
        replace(row, transaction_intent_projection_norito=projection),
        "independent statement field",
    )

    def change_governed_parameter_in_both_places(envelope_fields: list[bytes]) -> None:
        statement_payload = envelope_fields[11]
        statement_variant, _, end = _read_field(statement_payload, 4)
        assert end == len(statement_payload)
        statement_fields = _fields(statement_variant, 11)
        context_fields = _fields(statement_fields[0], 8)
        changed = bytearray(context_fields[3])
        changed[-1] ^= 1
        context_fields[3] = bytes(changed)
        statement_fields[0] = _encode_fields(context_fields)
        variant = _encode_fields(statement_fields)
        envelope_fields[11] = statement_payload[:4] + _compact(len(variant)) + variant
        envelope_fields[5] = bytes(changed)

    projection = _projection_with_envelope(row, change_governed_parameter_in_both_places)
    _assert_row_rejected(
        bundle,
        0,
        replace(row, transaction_intent_projection_norito=projection),
        "statement context field 3",
    )

    projection = _replace_projected_statement(
        row,
        lambda fields: fields.__setitem__(
            10, _fields(_read_field(_frame_payload(row.statement_norito, 8), 4)[0], 11)[10]
        ),
    )
    _assert_row_rejected(
        bundle,
        0,
        replace(row, transaction_intent_projection_norito=projection),
        "zero derived field",
    )


@pytest.mark.parametrize(
    ("row_index", "derived_index", "field_count"),
    ((0, 10, 11), (4, 10, 15), (10, 5, 13)),
)
def test_projection_zeroes_every_protocol_specific_derived_statement_field(
    row_index: int,
    derived_index: int,
    field_count: int,
) -> None:
    bundle = _bundle()
    row = bundle.rows[row_index]
    statement_payload = _frame_payload(row.statement_norito, 8)
    final_variant, _, end = _read_field(statement_payload, 4)
    assert end == len(statement_payload)
    final_derived = _fields(final_variant, field_count)[derived_index]
    projection = _replace_projected_statement(
        row,
        lambda fields: fields.__setitem__(derived_index, final_derived),
    )
    _assert_row_rejected(
        bundle,
        row_index,
        replace(row, transaction_intent_projection_norito=projection),
        "zero derived field",
    )


def test_signed_transaction_version_payload_multisig_and_pipeline_hash_are_bound() -> None:
    bundle = _bundle()
    row = bundle.rows[0]
    signed_fields = _fields(row.signed_transaction_versioned_norito[1:], 3)
    for signed, match in (
        (b"\x00" + row.signed_transaction_versioned_norito[1:], "version 1"),
        (b"\x01" + _encode_fields([b"", signed_fields[1], signed_fields[2]]), "signature"),
        (
            b"\x01"
            + _encode_fields(
                [
                    signed_fields[0],
                    bundle.rows[1].unsigned_transaction_payload_norito,
                    signed_fields[2],
                ]
            ),
            "unsigned payload",
        ),
        (b"\x01" + _encode_fields([signed_fields[0], signed_fields[1], b"\x01\x00"]), "multisig"),
    ):
        _assert_row_rejected(
            bundle,
            0,
            replace(row, signed_transaction_versioned_norito=signed),
            match,
        )
    changed_hash = bytearray(row.signed_transaction_hash)
    changed_hash[0] ^= 1
    _assert_row_rejected(
        bundle,
        0,
        replace(row, signed_transaction_hash=bytes(changed_hash)),
        "hash",
    )


def test_resource_bounds_are_checked_before_deep_decode() -> None:
    bundle = _bundle()
    row = bundle.rows[0]
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="262144-byte"):
        replace(row, statement_norito=bytes(256 * 1024 + 1))
    oversized_row = replace(
        row,
        statement_norito=b"x" * (256 * 1024),
        envelope_norito=b"x" * (512 * 1024),
        submit_proof_instruction_norito=b"x" * (512 * 1024),
        transaction_intent_projection_norito=b"x" * (512 * 1024),
        unsigned_transaction_payload_norito=b"x" * (768 * 1024),
        signed_transaction_versioned_norito=b"x" * (1024 * 1024),
    )
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="aggregate"):
        _replace_bundle_row(bundle, 0, oversized_row)


def test_trusted_archive_identity_closes_signature_and_opaque_proof_substitution() -> None:
    canonical = _bundle()
    assert (
        require_trusted_privacy_exact12_fixture_bundle_v1(
            bytearray(FIXTURE_BYTES), memoryview(FIXTURE_BYTES)
        )
        == canonical
    )
    with pytest.raises(PrivacyExact12FixtureErrorV1):
        require_trusted_privacy_exact12_fixture_bundle_v1(FIXTURE_BYTES[:-1], FIXTURE_BYTES)
    with pytest.raises(PrivacyExact12FixtureErrorV1):
        require_trusted_privacy_exact12_fixture_bundle_v1(FIXTURE_BYTES, FIXTURE_BYTES[:-1])

    row = canonical.rows[0]
    signed_fields = _fields(row.signed_transaction_versioned_norito[1:], 3)
    signature = bytearray(signed_fields[0])
    signature[-1] ^= 1
    signed_fields[0] = bytes(signature)
    signature_row = replace(
        row,
        signed_transaction_versioned_norito=b"\x01" + _encode_fields(signed_fields),
    )
    signature_bundle = _replace_bundle_row(canonical, 0, signature_row)
    signature_archive = encode_privacy_exact12_fixture_bundle_v1(signature_bundle)
    assert decode_privacy_exact12_fixture_bundle_v1(signature_archive) == signature_bundle
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="trusted canonical"):
        require_trusted_privacy_exact12_fixture_bundle_v1(signature_archive, FIXTURE_BYTES)

    envelope_fields = _fields(_frame_payload(row.envelope_norito, 8), 13)
    proof = bytearray(envelope_fields[12])
    proof[-1] ^= 1
    envelope_fields[12] = bytes(proof)
    envelope_payload = _encode_fields(envelope_fields)
    envelope = _frame(envelope_payload, ENVELOPE_SCHEMA, 8)
    instruction = _frame(_encode_fields([envelope_payload]), INSTRUCTION_SCHEMA, 8)
    assert row.unsigned_transaction_payload_norito.count(row.submit_proof_instruction_norito) == 1
    unsigned = row.unsigned_transaction_payload_norito.replace(
        row.submit_proof_instruction_norito, instruction, 1
    )
    signed_fields = _fields(row.signed_transaction_versioned_norito[1:], 3)
    signed_fields[1] = unsigned
    proof_row = replace(
        row,
        envelope_norito=envelope,
        submit_proof_instruction_norito=instruction,
        unsigned_transaction_payload_norito=unsigned,
        signed_transaction_versioned_norito=b"\x01" + _encode_fields(signed_fields),
        signed_transaction_hash=_transaction_hash(unsigned),
    )
    proof_bundle = _replace_bundle_row(canonical, 0, proof_row)
    proof_archive = encode_privacy_exact12_fixture_bundle_v1(proof_bundle)
    assert decode_privacy_exact12_fixture_bundle_v1(proof_archive) == proof_bundle
    with pytest.raises(PrivacyExact12FixtureErrorV1, match="trusted canonical"):
        require_trusted_privacy_exact12_fixture_bundle_v1(proof_archive, FIXTURE_BYTES)
