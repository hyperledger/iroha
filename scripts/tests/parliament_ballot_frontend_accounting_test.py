"""Independent byte traces, fixture encoding and failure-prefix charge checks."""

from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "parliament_ballot_frontend_accounting.py"
SPEC = importlib.util.spec_from_file_location("ballot_frontend_accounting", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ROOT = SCRIPT.parent.parent


def serialized_frame(tag, fields):
    """Independent byte encoder using struct, retaining each actual sink write."""
    chunks = [struct.pack("<H", len(tag)), tag, struct.pack("<H", len(fields))]
    for field in fields:
        chunks.append(struct.pack("<I", len(field)))
        chunks.append(field)
    return b"".join(chunks), chunks


def read_frame(data):
    """Walk actual bytes and recover fields without the charge implementation."""
    tag_length = struct.unpack_from("<H", data)[0]
    tag = data[2:2 + tag_length]
    position = 2 + tag_length
    count = struct.unpack_from("<H", data, position)[0]
    position += 2
    fields = []
    for _ in range(count):
        length = struct.unpack_from("<I", data, position)[0]
        position += 4
        fields.append(data[position:position + length])
        position += length
    assert position == len(data)
    return tag, fields


def fixture(stem):
    """Read the existing independent Python reference intermediate file."""
    path = ROOT / f"crates/iroha_parliament_ballot_proof/tests/fixtures/{stem}.txt"
    return {key: bytes.fromhex(value) for line in path.read_text().splitlines()
            if " = " in line and not line.startswith("#") for key, value in [line.split(" = ")]}


def parser_trace(record, role):
    """Independent cursor parser; charge only named successful byte operations.

    Deliberately uses offsets/memoryviews rather than calling model helpers.
    A ValueError stops the trace, like an ordinary decoder rejection.
    """
    trace = Counter()

    class Cursor:
        def __init__(self, data):
            self.data = memoryview(data)
            self.position = 0

        def take(self, length):
            trace["take_slice_bounds_checks"] += 1
            if self.position + length > len(self.data):
                raise ValueError("truncated")
            result = self.data[self.position:self.position + length]
            self.position += length
            return result

        def u32(self):
            result = self.take(4)
            trace["u32_length_decodes"] += 1
            trace["u32_prefix_copy_bytes"] += 4
            trace["u32_prefix_zero_init_bytes"] += 4
            return int.from_bytes(result, "little")

        def u16(self):
            result = self.take(2)
            trace["u16_length_or_count_decodes"] += 1
            return int.from_bytes(result, "little")

    try:
        outer = Cursor(record)
        statement = outer.take(outer.u32())
        proof_len = outer.u32()
        if proof_len != MODULE.PROOF_BYTES["candidate", role]:
            raise ValueError("proof length")
        outer.take(proof_len)
        if outer.position != len(record):
            raise ValueError("trailing record")
        reader = Cursor(statement)
        tag = b"PARL/TEST/REG/v1" if role == "registration" else b"PARL/TEST/VOTE/v1"
        if reader.u16() != len(tag):
            raise ValueError("tag length")
        received_tag = reader.take(len(tag))
        trace["tag_bytes_compared_upper_bound"] += len(tag)
        if received_tag != tag:
            raise ValueError("tag")
        n = 11 if role == "registration" else 10
        if reader.u16() != n:
            raise ValueError("count")
        fields = []
        for _ in range(n):
            fields.append(reader.take(reader.u32()))
            trace["field_slice_pushes"] += 1
        if reader.position != len(statement):
            raise ValueError("trailing statement")
        if len(fields[0]) != 64:
            raise ValueError("descriptor size")
        trace["descriptor_bytes_compared_upper_bound"] += 64
        if role == "registration":
            for value, bound in zip(fields[1:8], [4096, 256, 256, 256, 256, 256, 256], strict=True):
                if len(value) > bound:
                    raise ValueError("oversized opaque")
                trace["opaque_payload_copy_bytes_upper_bound"] += len(value)
            for index, size in [(9, 128), (10, 64), (8, 64)]:
                if len(fields[index]) != size:
                    raise ValueError("fixed size")
                trace["fixed_array_copy_bytes"] += size
            trace["body_digest_bytes_compared_upper_bound"] += 64
        else:
            if len(fields[4]) != 2 or len(fields[8]) != 1:
                raise ValueError("scalar size")
            if len(fields[5]) % 128 or not 3 <= len(fields[5]) // 128 <= 1000:
                raise ValueError("list size")
            for index, size in [(1, 64), (2, 64), (3, 64)]:
                if len(fields[index]) != size:
                    raise ValueError("fixed size")
                trace["fixed_array_copy_bytes"] += size
            trace["u16_length_or_count_decodes"] += 1
            trace["list_entry_zero_init_bytes"] += len(fields[5])
            trace["list_entry_copy_bytes"] += len(fields[5])
            for index, size in [(6, 128), (7, 64), (9, 64)]:
                if len(fields[index]) != size:
                    raise ValueError("late fixed size after list allocation")
                trace["fixed_array_copy_bytes"] += size
            if int.from_bytes(fields[4], "little") != len(fields[5]) // 128:
                raise ValueError("declared list size mismatch after allocation")
    except ValueError:
        return trace, False
    return trace, True


def record(role, fields):
    """Build a test record independently; no public-cryptography validity claim."""
    tag = b"PARL/TEST/REG/v1" if role == "registration" else b"PARL/TEST/VOTE/v1"
    statement, _ = serialized_frame(tag, fields)
    proof = bytes(MODULE.PROOF_BYTES["candidate", role])
    return struct.pack("<I", len(statement)) + statement + struct.pack("<I", len(proof)) + proof


def maximum_fields(role, seats=1000):
    """Literal source-schema field order, separately from the accounting model."""
    if role == "registration":
        return [bytes(n) for n in [64, 4096, 256, 256, 256, 256, 256, 256, 64, 128, 64]]
    fields = [bytes(n) for n in [64, 64, 64, 64, 2, 128 * seats, 128, 64, 1, 64]]
    fields[4] = struct.pack("<H", seats)
    return fields


def test_frame_charges_follow_actual_sink_chunks_and_independent_fixtures():
    for stem, key in [("reg_fast", "F_REG"), ("vote_S3_i1_fast", "F_VOTE")]:
        original = fixture(stem)[key]
        tag, fields = read_frame(original)
        encoded, chunks = serialized_frame(tag, fields)
        assert encoded == original
        charge = MODULE.frame_charge(tag, tuple(map(len, fields)), "vec")
        assert charge["sink_absorb_calls"] == len(chunks)
        assert charge["sink_input_bytes"] == sum(map(len, chunks)) == len(original)
        assert charge["vec_append_bytes"] == len(original)
        assert charge["length_le_encode_bytes"] == sum(len(c) for i, c in enumerate(chunks) if i in (0, 2) or (i >= 3 and i % 2 == 1))
    for fields in [(), (b"",), (b"", bytes(256), b"a")]:
        data, chunks = serialized_frame(b"tag", fields)
        assert MODULE.frame_charge(b"tag", tuple(map(len, fields)), "hash")["hash_input_bytes"] == len(data)
        assert len(chunks) >= 3


def test_profile_word_encoding_matches_independent_reference_digest():
    for row, suffix, tau, grind, gates in [("candidate", "f", 33, 8, 704), ("comparator", "s", 22, 6, 696)]:
        source = (ROOT / f"crates/iroha_zkp_vole/src/crt/generated/faest_256{suffix}_tables.rs").read_text()
        words = [int.from_bytes(b"FAESTCRT", "little"), 256, tau, grind, gates]
        for name in ["TREE_MODULI", "M_TREE", "F", "G", "W_TREE", "W_GATE", "W_CRT"]:
            body = re.search(rf"pub static {name}: \[u(?:16|64); \d+\] = \[(.*?)\];", source, re.S)[1]
            words.extend(int(token.strip().replace("_", ""), 0) for token in body.split(",") if token.strip())
        encoded = b"".join(struct.pack("<Q", word) for word in words)
        expected = fixture("reg_fast" if row == "candidate" else "reg_comparator")
        assert hashlib.shake_256(encoded).digest(64) == expected["T_crt"]
        charge = MODULE.profile_charge(row, 1)
        assert charge["canonical_u64_words"] == len(words)
        assert charge["crt_u64_le_encode_bytes"] == charge["crt_byte_collect_bytes"] == len(encoded)
        doubled = MODULE.profile_charge(row, 2)
        assert all(doubled[k] == 2 * value for k, value in charge.items())


@pytest.mark.parametrize("role", ["registration", "vote"])
def test_maximum_decoder_trace_reaches_named_copy_and_parser_bounds(role):
    data = record(role, maximum_fields(role))
    trace, success = parser_trace(data, role)
    assert success
    bounds = MODULE.decoder_charge(role, 1000)
    for key, actual in trace.items():
        assert actual == bounds[key], key
    case = MODULE.case_charge("candidate", role, 1000, True)
    assert len(data) == case["canonical_record_bytes_max"]


@pytest.mark.parametrize("role", ["registration", "vote"])
def test_truncation_and_oversized_declared_fields_do_not_add_scans_or_copies(role):
    fields = maximum_fields(role)
    data = record(role, fields)
    bounds = MODULE.decoder_charge(role, 1000)
    candidates = [b"", b"\xff" * 4, data[:3], data[:100], data[:-1], data + b"x"]
    # A huge field count does not drive the loop. A huge first-field length
    # fails its slice bound before body/list allocation even with a valid count.
    tag = b"PARL/TEST/REG/v1" if role == "registration" else b"PARL/TEST/VOTE/v1"
    count_at = 4 + 2 + len(tag)
    for at, replacement in [(count_at, b"\xff\xff"), (count_at + 2, b"\xff" * 4)]:
        mutated = bytearray(data)
        mutated[at:at + len(replacement)] = replacement
        candidates.append(bytes(mutated))
    # Well-framed oversize values pass the slice parser but fail before copying
    # that payload; earlier bounded copies may already have happened.
    limits = [(1, 4097), (7, 257), (9, 129)] if role == "registration" else [(5, 128 * 1001), (5, 127999), (6, 129)]
    for index, length in limits:
        changed = fields.copy()
        changed[index] = bytes(length)
        candidates.append(record(role, changed))
    for candidate in candidates:
        trace, success = parser_trace(candidate, role)
        assert not success
        assert all(value <= bounds[key] for key, value in trace.items())


def test_vote_list_concat_and_validation_are_separate_source_call_sites():
    for seats in (3, 500, 1000):
        cold = MODULE.case_charge("candidate", "vote", seats, True)
        warm = MODULE.case_charge("candidate", "vote", seats, False)
        # Named call-site inventory: decoder validate, verifier validate,
        # authorization digest, relation public input and MU construction.
        chunks = [bytes(128) for _ in range(seats)]
        one_list = b"".join(chunks)
        assert cold["public_preparation"]["list_concat_copy_bytes"] == sum(len(one_list) for _ in range(5))
        assert warm["public_preparation"]["list_concat_copy_bytes"] == sum(len(one_list) for _ in range(4))
        assert cold["public_preparation"]["list_order_pair_comparisons"] == 2 * len(list(zip(chunks, chunks[1:])))
        assert cold["frame_totals"]["sink_absorb_calls"] == 126
        assert warm["frame_totals"]["sink_absorb_calls"] == 86


def test_rejection_bound_uses_actual_list_length_not_untrusted_declared_size():
    fields = maximum_fields("vote", 1000)
    fields[4] = struct.pack("<H", 3)
    fields[5] = b"".join(bytes(126) + struct.pack(">H", index) for index in range(1000))
    trace, success = parser_trace(record("vote", fields), "vote")
    assert not success
    assert trace["list_entry_copy_bytes"] == 128000
    assert trace["list_entry_copy_bytes"] > MODULE.decoder_charge("vote", 3)["list_entry_copy_bytes"]
    unconditional = MODULE.decoder_charge("vote", 1000)
    assert all(value <= unconditional[key] for key, value in trace.items())


def test_late_fixed_field_rejection_retains_the_already_copied_list():
    bounds = MODULE.decoder_charge("vote", 1000)
    for index, bad_length in [(6, 129), (7, 63), (9, 63)]:
        fields = maximum_fields("vote", 1000)
        fields[index] = bytes(bad_length)
        trace, success = parser_trace(record("vote", fields), "vote")
        assert not success
        assert trace["list_entry_copy_bytes"] == 128000
        assert trace["list_entry_zero_init_bytes"] == 128000
        assert all(value <= bounds[key] for key, value in trace.items())


def test_bound_inputs_and_charge_modes_are_validated():
    for call in [lambda: MODULE.frame_charge(b"\xff", (), "vec"),
                 lambda: MODULE.frame_charge(b"x", (1 << 32,), "vec"),
                 lambda: MODULE.frame_charge(b"x", (-1,), "hash"),
                 lambda: MODULE.frame_charge(b"x", (), "invalid"),
                 lambda: MODULE.frames("vote", 1001, True),
                 lambda: MODULE.decoder_charge("other", 3),
                 lambda: MODULE.profile_charge("candidate", 3),
                 lambda: MODULE.case_charge("unknown", "vote", 3, False)]:
        with pytest.raises(ValueError):
            call()


def test_source_drift_and_missing_inputs_fail_closed(monkeypatch, tmp_path):
    assert len(MODULE.source_inventory(ROOT)["files"]) == 81
    with pytest.raises(ValueError, match="missing"):
        MODULE.source_inventory(tmp_path)
    monkeypatch.setattr(MODULE, "REVIEWED_SOURCE_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="changed"):
        MODULE.source_inventory(ROOT)


def test_receipt_keeps_incomplete_status_and_explicit_rejection_scope(tmp_path):
    output = tmp_path / "receipt.json"
    assert MODULE.main(["--output", str(output), "--require-complete"]) == 1
    result = json.loads(output.read_text())
    assert len(result["cases"]) == 16
    assert not result["complete_work_certificate"]
    assert not result["process_memory_certificate"]
    assert not result["profile_qualified"]
    assert not result["input_scope"]["ingress_cap_enforced_by_test_codec"]
    assert "S=1000" in result["input_scope"]["case_bounds"]
    assert len(result["remaining_terms"]) == 5
