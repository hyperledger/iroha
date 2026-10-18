"""Canonical Python Kaigi instruction wire vectors and validation tests."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from iroha_python.address import AccountAddress
from iroha_python.kaigi import (
    KAIGI_INSTRUCTION_WIRE_IDS_V1,
    KAIGI_MAX_PARTICIPANTS_V1,
    KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1,
    KAIGI_RELAY_MANIFEST_MAX_HOPS_V1,
    REGISTER_KAIGI_RELAY_WIRE_ID_V1,
    UNREGISTER_KAIGI_RELAY_WIRE_ID_V1,
    KaigiIdV1,
    KaigiInstructionWireV1,
    KaigiParticipantCommitmentV1,
    KaigiParticipantNullifierV1,
    KaigiRelayHopV1,
    KaigiRelayManifestV1,
    build_leave_kaigi_instruction,
    encode_create_kaigi_instruction_v1,
    encode_end_kaigi_instruction_v1,
    encode_join_kaigi_instruction_v1,
    encode_leave_kaigi_instruction_v1,
    encode_record_kaigi_usage_instruction_v1,
    encode_register_kaigi_relay_instruction_v1,
    encode_report_kaigi_relay_health_instruction_v1,
    encode_set_kaigi_relay_manifest_instruction_v1,
    encode_unregister_kaigi_relay_instruction_v1,
)

_FIXTURE_PATH = Path(__file__).with_name("fixtures") / "kaigi_instruction_wire_v1.json"
_FIXTURE = json.loads(_FIXTURE_PATH.read_text("utf-8"))
_CRC64_POLY = 0xC96C_5795_D787_0F42
_U64_MASK = (1 << 64) - 1
_PASTA_FP_MODULUS = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
_RELAY_PUBLIC_KEYS_HEX = (
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
    "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
    "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
    "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c",
    "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1",
    "8a875fff1eb38451577acd5afee405456568dd7c89e090863a0557bc7af49f17",
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca",
)


def _crc64(payload: bytes) -> int:
    crc = _U64_MASK
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ _CRC64_POLY if crc & 1 else crc >> 1
    return (crc ^ _U64_MASK) & _U64_MASK


def _read_compact_length(payload: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        byte = payload[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    raise AssertionError("overlong compact length in golden frame")


def _read_field(payload: bytes, offset: int) -> tuple[bytes, int]:
    length, body_offset = _read_compact_length(payload, offset)
    end = body_offset + length
    assert end <= len(payload)
    return payload[body_offset:end], end


def _frame_payload(frame: bytes, expected_schema_hex: str) -> bytes:
    assert frame[:6] == b"NRT0\x00\x00"
    assert frame[6:22].hex() == expected_schema_hex
    assert frame[22] == 0
    assert frame[39] == 0x02
    length = int.from_bytes(frame[23:31], "little")
    checksum = int.from_bytes(frame[31:39], "little")
    payload = frame[40:]
    assert length == len(payload)
    assert checksum == _crc64(payload)
    return payload


def _decode_instruction_box(archive: bytes) -> tuple[str, bytes]:
    outer = _frame_payload(archive, _FIXTURE["outer_schema_hash_hex"])
    wire_container, offset = _read_field(outer, 0)
    wire_bytes, wire_end = _read_field(wire_container, 0)
    assert wire_end == len(wire_container)
    inner_container, offset = _read_field(outer, offset)
    assert offset == len(outer)
    inner_length = int.from_bytes(inner_container[:8], "little")
    inner_frame = inner_container[8:]
    assert inner_length == len(inner_frame)
    return wire_bytes.decode("ascii"), inner_frame


def _minimal_wires() -> dict[str, KaigiInstructionWireV1]:
    account = _FIXTURE["accounts"][0]
    call_id = KaigiIdV1(**_FIXTURE["call_id"])
    return {
        "CreateKaigi": encode_create_kaigi_instruction_v1(call_id=call_id, host=account),
        "JoinKaigi": encode_join_kaigi_instruction_v1(call_id=call_id, participant=account),
        "LeaveKaigi": encode_leave_kaigi_instruction_v1(call_id=call_id, participant=account),
        "EndKaigi": encode_end_kaigi_instruction_v1(call_id=call_id),
        "RecordKaigiUsage": encode_record_kaigi_usage_instruction_v1(
            call_id=call_id, duration_ms=1, billed_gas=2
        ),
        "SetKaigiRelayManifest": encode_set_kaigi_relay_manifest_instruction_v1(
            call_id=call_id, relay_manifest=None
        ),
        "RegisterKaigiRelay": encode_register_kaigi_relay_instruction_v1(
            relay_id=account, hpke_public_key=b"key", bandwidth_class=1
        ),
        "UnregisterKaigiRelay": encode_unregister_kaigi_relay_instruction_v1(
            relay_id=account
        ),
        "ReportKaigiRelayHealth": encode_report_kaigi_relay_health_instruction_v1(
            call_id=call_id,
            relay_id=account,
            status="Healthy",
            reported_at_ms=3,
        ),
    }


def _complex_create() -> KaigiInstructionWireV1:
    first, second, third = _FIXTURE["accounts"]
    manifest = KaigiRelayManifestV1(
        (
            KaigiRelayHopV1(first, b"\x10\x20", 1),
            KaigiRelayHopV1(second, b"\x30", 2),
            KaigiRelayHopV1(third, b"\x40\x50\x60", 255),
        ),
        1 << 63,
    )
    return encode_create_kaigi_instruction_v1(
        call_id=KaigiIdV1(**_FIXTURE["call_id"]),
        host=first,
        title="Roadmap 🛰",
        description="exact",
        max_participants=7,
        gas_rate_per_minute=9_007_199_254_740_993,
        metadata={"z": [True, None, 7], "a": {"nested": "value"}},
        scheduled_start_ms=1_234_567_890_123,
        billing_account=first,
        privacy_mode="ZkRosterV1",
        room_policy="Public",
        relay_manifest=manifest,
        commitment=KaigiParticipantCommitmentV1(bytes([0x44]) * 31 + b"\x04"),
        nullifier=KaigiParticipantNullifierV1(bytes([0x55]) * 31 + b"\x05"),
        roster_root=bytes([0x66]) * 31 + b"\x67",
        proof=b"\x01\x02\x03",
    )


def test_all_nine_builders_match_complete_instruction_box_golden_frames() -> None:
    wires = _minimal_wires()
    vectors = {entry["name"]: entry for entry in _FIXTURE["vectors"]}
    assert tuple(wire.wire_id for wire in wires.values()) == KAIGI_INSTRUCTION_WIRE_IDS_V1
    assert set(wires) == set(vectors)

    for name, wire in wires.items():
        vector = vectors[name]
        archive = wire.to_norito_bytes()
        assert base64.b64encode(archive).decode("ascii") == vector["instruction_box_base64"]
        assert json.loads(wire.to_json()) == vector["instruction_box_base64"]
        assert wire.wire_payload() == (wire.wire_id, wire.payload_norito)

        decoded_wire_id, inner_frame = _decode_instruction_box(archive)
        assert decoded_wire_id == vector["wire_id"] == wire.wire_id
        assert inner_frame == wire.payload_norito
        _frame_payload(inner_frame, vector["inner_schema_hash_hex"])

        derived_schema = hashlib.sha256(
            b"norito:v1:type-name\0" + vector["inner_type_name"].encode("ascii")
        ).digest()[:16]
        assert derived_schema.hex() == vector["inner_schema_hash_hex"]

    outer_schema = hashlib.sha256(
        b"norito:v1:type-name\0" + _FIXTURE["outer_type_name"].encode("ascii")
    ).digest()[:16]
    assert outer_schema.hex() == _FIXTURE["outer_schema_hash_hex"]


def test_complex_create_matches_final_v1_reference_without_losing_u64_precision() -> None:
    archive = _complex_create().to_norito_bytes()
    expected = _FIXTURE["complex_create"]
    assert len(archive) == 872
    assert hashlib.sha256(archive).hexdigest() == expected["sha256_hex"]
    assert base64.b64encode(archive).decode("ascii") == expected["instruction_box_base64"]


def test_native_instruction_round_trip_uses_current_extension() -> None:
    from iroha_python.crypto import Instruction as NativeInstruction

    wires = _minimal_wires()
    assert NativeInstruction is not None
    instructions = [wire.to_instruction() for wire in wires.values()]
    assert [instruction.wire_id() for instruction in instructions] == [
        wire.wire_id for wire in wires.values()
    ]
    assert [bytes(instruction.to_norito_bytes()) for instruction in instructions] == [
        wire.to_norito_bytes() for wire in wires.values()
    ]


def test_scalar_bytes_are_preserved_while_roster_roots_still_require_hash_markers() -> None:
    raw = bytearray(bytes([0x22]) * 32)
    snapshot = bytes(raw)
    commitment = KaigiParticipantCommitmentV1(raw)
    assert bytes(raw) == snapshot
    assert commitment.commitment == snapshot
    raw[0] ^= 1
    assert commitment.commitment == snapshot
    assert KaigiParticipantNullifierV1(memoryview(snapshot)).digest == snapshot

    with pytest.raises(ValueError, match="marker bit"):
        encode_join_kaigi_instruction_v1(
            call_id=KaigiIdV1(**_FIXTURE["call_id"]),
            participant=_FIXTURE["accounts"][0],
            commitment=commitment,
            nullifier=KaigiParticipantNullifierV1(bytes([0x33]) * 32),
            roster_root=bytes([0x44]) * 32,
            proof=b"proof",
        )


@pytest.mark.parametrize("scalar", [0, 1, (1 << 248), _PASTA_FP_MODULUS - 1])
def test_commitments_and_nullifiers_accept_exact_canonical_pasta_boundaries(scalar: int) -> None:
    raw = scalar.to_bytes(32, "little")
    assert KaigiParticipantCommitmentV1(raw).commitment == raw
    assert KaigiParticipantNullifierV1(raw).digest == raw


@pytest.mark.parametrize("scalar", [_PASTA_FP_MODULUS, _PASTA_FP_MODULUS + 1, (1 << 255), (1 << 256) - 1])
def test_scalar_outputs_reject_out_of_field_values_without_reduction(scalar: int) -> None:
    raw = bytearray(scalar.to_bytes(32, "little"))
    original = bytes(raw)
    for constructor in (KaigiParticipantCommitmentV1, KaigiParticipantNullifierV1):
        with pytest.raises(ValueError, match="below the modulus"):
            constructor(raw)
        assert bytes(raw) == original
    with pytest.raises(ValueError, match="below the modulus"):
        encode_record_kaigi_usage_instruction_v1(
            call_id=KaigiIdV1(**_FIXTURE["call_id"]), duration_ms=1,
            usage_commitment=raw, proof=b"proof",
        )
    assert bytes(raw) == original


@pytest.mark.parametrize("raw", [b"", bytes(31), bytes(33)])
def test_scalar_outputs_reject_noncanonical_lengths(raw: bytes) -> None:
    for constructor in (KaigiParticipantCommitmentV1, KaigiParticipantNullifierV1):
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            constructor(raw)


@pytest.mark.parametrize("value", [False, 0, "00" * 32, "hash:" + "11" * 32 + "#0000"])
def test_scalar_outputs_reject_hash_literals_and_nonbyte_inputs(value: Any) -> None:
    for constructor in (KaigiParticipantCommitmentV1, KaigiParticipantNullifierV1):
        with pytest.raises(TypeError, match="raw bytes-like Pasta Fp scalar"):
            constructor(value)


@pytest.mark.parametrize("mask", range(16))
def test_private_create_requires_all_fields_and_other_actions_reject_partial_quartets(mask: int) -> None:
    call_id = KaigiIdV1(**_FIXTURE["call_id"])
    account = _FIXTURE["accounts"][0]
    fields = {
        "commitment": KaigiParticipantCommitmentV1(bytes(32)),
        "nullifier": KaigiParticipantNullifierV1((_PASTA_FP_MODULUS - 1).to_bytes(32, "little")),
        "roster_root": bytes([0x55]) * 32,
        "proof": b"proof",
    }
    selected = {name: value for index, (name, value) in enumerate(fields.items()) if mask & (1 << index)}
    if mask == 15:
        encode_create_kaigi_instruction_v1(call_id=call_id, host=account, privacy_mode="ZkRosterV1", **selected)
    else:
        with pytest.raises(ValueError, match="requires the host|all present or all omitted"):
            encode_create_kaigi_instruction_v1(call_id=call_id, host=account, privacy_mode="ZkRosterV1", **selected)
    if mask:
        with pytest.raises(ValueError, match="transparent.*omit"):
            encode_create_kaigi_instruction_v1(call_id=call_id, host=account, **selected)
    for encode, identity in (
        (encode_join_kaigi_instruction_v1, {"participant": account}),
        (encode_leave_kaigi_instruction_v1, {"participant": account}),
        (encode_end_kaigi_instruction_v1, {}),
    ):
        if mask in (0, 15):
            encode(call_id=call_id, **identity, **selected)
        else:
            with pytest.raises(ValueError, match="all present or all omitted"):
                encode(call_id=call_id, **identity, **selected)


def test_usage_scalar_preserves_raw_pasta_bytes_without_hash_marker_conversion() -> None:
    raw = (_PASTA_FP_MODULUS - 1).to_bytes(32, "little")
    wire = encode_record_kaigi_usage_instruction_v1(
        call_id=KaigiIdV1(**_FIXTURE["call_id"]), duration_ms=1,
        usage_commitment=raw, proof=b"proof",
    )
    payload = wire.payload_norito[40:]
    offset = 0
    fields = []
    while offset < len(payload):
        field, offset = _read_field(payload, offset)
        fields.append(field)
    assert fields[3][0] == 1
    scalar, end = _read_field(fields[3], 1)
    assert end == len(fields[3])
    assert scalar == raw


def test_private_leave_builder_preserves_the_complete_wire_quartet(monkeypatch: pytest.MonkeyPatch) -> None:
    artifacts = {
        "call_id": KaigiIdV1(**_FIXTURE["call_id"]),
        "participant": _FIXTURE["accounts"][0],
        "commitment": KaigiParticipantCommitmentV1(bytes(32)),
        "nullifier": KaigiParticipantNullifierV1(bytes([0x22]) * 32),
        "roster_root": bytes([0x55]) * 32,
        "proof": b"proof",
    }
    expected = encode_leave_kaigi_instruction_v1(**artifacts)
    # Check the wrapper hands the complete wire to the native boundary; native
    # proof acceptance remains the Core verifier's responsibility.
    monkeypatch.setattr(KaigiInstructionWireV1, "to_instruction", lambda wire: wire)
    assert build_leave_kaigi_instruction(**artifacts) == expected


def test_privacy_artifacts_are_complete_nonempty_and_mode_safe() -> None:
    call_id = KaigiIdV1(**_FIXTURE["call_id"])
    account = _FIXTURE["accounts"][0]
    commitment = KaigiParticipantCommitmentV1(bytes([0x11]) * 32)
    nullifier = KaigiParticipantNullifierV1(bytes([0x33]) * 32)
    roster_root = bytes([0x55]) * 32

    with pytest.raises(ValueError, match="all present or all omitted"):
        encode_join_kaigi_instruction_v1(
            call_id=call_id,
            participant=account,
            commitment=commitment,
        )
    with pytest.raises(ValueError, match="transparent.*omit"):
        encode_create_kaigi_instruction_v1(
            call_id=call_id,
            host=account,
            commitment=commitment,
            nullifier=nullifier,
            roster_root=roster_root,
            proof=b"proof",
        )
    with pytest.raises(ValueError, match="non-empty"):
        encode_end_kaigi_instruction_v1(
            call_id=call_id,
            commitment=commitment,
            nullifier=nullifier,
            roster_root=roster_root,
            proof=b"",
        )
    with pytest.raises(ValueError, match="all present or all omitted"):
        encode_record_kaigi_usage_instruction_v1(
            call_id=call_id,
            duration_ms=1,
            usage_commitment=bytes([0x77]) * 32,
        )


def test_static_native_admission_limits_are_enforced() -> None:
    call_id = KaigiIdV1(**_FIXTURE["call_id"])
    first, second, third = _FIXTURE["accounts"]
    assert KaigiIdV1("Wonderland.SORA", "weekly-sync") == call_id
    assert KAIGI_MAX_PARTICIPANTS_V1 == 4_096

    encode_create_kaigi_instruction_v1(
        call_id=call_id,
        host=first,
        max_participants=KAIGI_MAX_PARTICIPANTS_V1,
    )
    with pytest.raises(ValueError, match="between 1 and 4096"):
        encode_create_kaigi_instruction_v1(
            call_id=call_id,
            host=first,
            max_participants=KAIGI_MAX_PARTICIPANTS_V1 + 1,
        )

    with pytest.raises(ValueError, match="billing_account must equal"):
        encode_create_kaigi_instruction_v1(
            call_id=call_id,
            host=first,
            billing_account=second,
        )
    with pytest.raises((TypeError, ValueError), match="unsigned 64-bit"):
        encode_record_kaigi_usage_instruction_v1(call_id=call_id, duration_ms=True)
    with pytest.raises(ValueError, match="unsigned 64-bit"):
        encode_record_kaigi_usage_instruction_v1(call_id=call_id, duration_ms=1 << 64)
    encode_record_kaigi_usage_instruction_v1(
        call_id=call_id, duration_ms=(1 << 64) - 1, billed_gas=(1 << 64) - 1
    )
    with pytest.raises(ValueError, match="512 Unicode"):
        encode_report_kaigi_relay_health_instruction_v1(
            call_id=call_id,
            relay_id=first,
            status="Healthy",
            reported_at_ms=0,
            notes="界" * 513,
        )
    with pytest.raises(ValueError, match="at least three"):
        KaigiRelayManifestV1(
            (KaigiRelayHopV1(first, b"key"), KaigiRelayHopV1(second, b"key")),
            1,
        )
    with pytest.raises(ValueError, match="duplicate"):
        KaigiRelayManifestV1(
            (
                KaigiRelayHopV1(first, b"one"),
                KaigiRelayHopV1(second, b"two"),
                KaigiRelayHopV1(first, b"three"),
            ),
            1,
        )
    manifest = KaigiRelayManifestV1(
        (
            KaigiRelayHopV1(first, b"one"),
            KaigiRelayHopV1(second, b"two"),
            KaigiRelayHopV1(third, b"three"),
        ),
        1,
    )
    assert isinstance(manifest.hops, tuple)


def test_relay_manifest_and_hpke_key_v1_boundaries() -> None:
    assert KAIGI_RELAY_MANIFEST_MAX_HOPS_V1 == 8
    assert KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1 == 4_096
    accounts = tuple(
        AccountAddress.from_account(public_key=bytes.fromhex(public_key)).to_i105()
        for public_key in _RELAY_PUBLIC_KEYS_HEX
    )
    hops = tuple(
        KaigiRelayHopV1(
            relay_id,
            b"\xa5" * (KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1 if index == 0 else 1),
        )
        for index, relay_id in enumerate(accounts)
    )
    manifest = KaigiRelayManifestV1(hops, expiry_ms=1)
    assert len(manifest.hops) == 8
    assert len(manifest.hops[0].hpke_public_key) == 4_096

    with pytest.raises(ValueError, match="more than 8 relays"):
        KaigiRelayManifestV1(hops + (hops[0],), expiry_ms=1)
    with pytest.raises(ValueError, match="4096-byte V1 limit"):
        KaigiRelayHopV1(accounts[0], b"\xa5" * 4_097)

    registration = encode_register_kaigi_relay_instruction_v1(
        relay_id=accounts[0],
        hpke_public_key=b"\xa5" * 4_096,
        bandwidth_class=1,
    )
    assert registration.wire_id == REGISTER_KAIGI_RELAY_WIRE_ID_V1
    unregistration = encode_unregister_kaigi_relay_instruction_v1(relay_id=accounts[0])
    assert unregistration.wire_id == UNREGISTER_KAIGI_RELAY_WIRE_ID_V1
    with pytest.raises(ValueError, match="4096-byte V1 limit"):
        encode_register_kaigi_relay_instruction_v1(
            relay_id=accounts[0],
            hpke_public_key=b"\xa5" * 4_097,
            bandwidth_class=1,
        )


def test_identity_codec_preserves_every_rust_controller_fixture() -> None:
    from iroha_python.kaigi import _account_id

    fixture_path = Path(__file__).resolve().parents[3] / "fixtures/account/multisig_wire_v1.json"
    fixture = json.loads(fixture_path.read_text("utf-8"))
    assert len(fixture["positive"]) == 16
    for case in fixture["positive"]:
        literal, payload = _account_id(case["i105"], case["name"])
        assert literal == case["i105"]
        assert payload.hex() == case["account_id_payload_hex"]
        wire = encode_create_kaigi_instruction_v1(
            call_id=KaigiIdV1(**_FIXTURE["call_id"]), host=literal
        )
        assert wire.to_instruction().to_norito_bytes() == wire.to_norito_bytes()


def test_identity_codec_rejects_degenerate_ed25519() -> None:
    with pytest.raises(ValueError, match="invalid public key payload"):
        AccountAddress.from_account(
            public_key=b"\x01" + bytes(31), algorithm="ed25519"
        )


def test_identity_unicode_uses_the_rust_nfc_and_uts46_profiles() -> None:
    call = KaigiIdV1("例え.SORA", "éclair")
    assert call.domain_id == "xn--r8jz45g.sora"
    assert call.call_name == "éclair"
    assert call == KaigiIdV1("xn--r8jz45g.sora", "éclair")
    with pytest.raises(ValueError, match="NFC"):
        KaigiIdV1("wonderland.sora", "e\u0301clair")
    with pytest.raises(ValueError):
        KaigiIdV1("xn--.sora", "call")


def test_identity_comparison_uses_controllers_across_display_prefixes() -> None:
    from iroha_python.kaigi import _account_id

    account = AccountAddress.from_i105(_FIXTURE["accounts"][0])
    first = account.to_i105(753)
    second = account.to_i105(42)
    assert first != second
    assert _account_id(first, "first")[1] == _account_id(second, "second")[1]
    wire = encode_create_kaigi_instruction_v1(
        call_id=KaigiIdV1(**_FIXTURE["call_id"]), host=first, billing_account=second
    )
    assert wire.to_instruction().to_norito_bytes() == wire.to_norito_bytes()
    with pytest.raises(ValueError, match="duplicate relays"):
        KaigiRelayManifestV1(
            [
                KaigiRelayHopV1(first, b"key1"),
                KaigiRelayHopV1(second, b"key2"),
                KaigiRelayHopV1(_FIXTURE["accounts"][1], b"key3"),
            ],
            1000,
        )


def test_wire_value_rejects_forged_or_corrupted_inner_frames() -> None:
    wire = next(iter(_minimal_wires().values()))
    corrupted = bytearray(wire.payload_norito)
    corrupted[-1] ^= 1
    with pytest.raises(ValueError, match="canonical Kaigi instruction frame"):
        KaigiInstructionWireV1(wire.wire_id, corrupted)
    with pytest.raises(TypeError, match="bytes-like"):
        KaigiInstructionWireV1(wire.wire_id, 40)  # type: ignore[arg-type]


def test_metadata_rejects_floats_and_noncanonical_unicode_identity_keys() -> None:
    call_id = KaigiIdV1(**_FIXTURE["call_id"])
    account = _FIXTURE["accounts"][0]
    with pytest.raises(TypeError, match="floating-point"):
        encode_create_kaigi_instruction_v1(call_id=call_id, host=account, metadata={"rate": 1.5})
    with pytest.raises(ValueError, match="NFC"):
        encode_create_kaigi_instruction_v1(call_id=call_id, host=account, metadata={"e\u0301": 1})


@pytest.mark.parametrize("issued_at_ms", [False, 0, 1, 0.0, "0", None])
def test_nullifier_timing_hint_is_not_a_final_v1_field(issued_at_ms: Any) -> None:
    with pytest.raises(TypeError, match="unexpected keyword argument 'issued_at_ms'"):
        KaigiParticipantNullifierV1(bytes(32), issued_at_ms=issued_at_ms)


def test_participant_scalar_wrappers_have_only_their_single_raw_field() -> None:
    from dataclasses import fields

    assert [field.name for field in fields(KaigiParticipantCommitmentV1)] == ["commitment"]
    assert [field.name for field in fields(KaigiParticipantNullifierV1)] == ["digest"]
    with pytest.raises(TypeError, match="unexpected keyword argument 'alias_tag'"):
        KaigiParticipantCommitmentV1(bytes(32), alias_tag=None)
