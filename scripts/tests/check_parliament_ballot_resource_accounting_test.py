"""Independent boundary, fixture and loop checks for B6 resource accounting."""

import importlib.util
import json
from pathlib import Path
import struct

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "check_parliament_ballot_resource_accounting.py"
SPEC = importlib.util.spec_from_file_location("ballot_resource_accounting", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_frame_lengths_match_independent_serialized_bytes():
    tag = b"test"
    fields = (b"", bytes(16), bytes(256))
    encoded = struct.pack("<H", len(tag)) + tag + struct.pack("<H", len(fields))
    encoded += b"".join(struct.pack("<I", len(part)) + part for part in fields)
    assert MODULE.frame_size(tag, tuple(map(len, fields))) == len(encoded)
    for invalid in ((-1,), (1 << 32,)):
        with pytest.raises(ValueError):
            MODULE.frame_size(tag, invalid)
    with pytest.raises(ValueError):
        MODULE.frame_size(b"\xff", ())


def test_all_four_proof_lengths_and_actual_independent_fixtures():
    expected = [160148, 233012, 109498, 158074]
    actual = [sum(MODULE.proof_layout(row, role).values()) for row in MODULE.ROWS for role in MODULE.ROLES]
    assert actual == expected
    result = MODULE.report()
    assert [case["proof_bytes"] for case in result["cases"]] == expected
    assert result["combined_input_cap"] == 425984
    assert result["cases"][1]["envelope_budget_after_fixed_crypto_fields"] == 28665


def test_exact_maximum_frame_inventory_is_not_a_production_envelope():
    data = MODULE.encoding_inventory(1000)
    assert data["registration_mu_frame_max"] == 5946
    assert data["registration_test_statement_max"] == 6016
    assert data["vote_mu_frame"] == 128506
    assert data["vote_test_statement"] == 128576
    assert data["list_digest_frame"] == 128114
    assert data["list_frame_sha3_permutations"] == 1780
    assert data["vote_authorization_digest_sha3_permutations"] == 1786
    for invalid in (0, 2, 1001):
        with pytest.raises(ValueError):
            MODULE.encoding_inventory(invalid)


def test_fold_xor_formula_counts_actual_binary_merge_schedule():
    for depth in range(2, 9):
        count = 0
        for leaf in range(1 << depth):
            level = 0
            while (leaf >> level) & 1:
                count += 2
                level += 1
        assert count == 2 * ((1 << depth) - 1)
    vote = MODULE.work_components("candidate", "vote")
    assert vote["conversion_fold_byte_xors"] == 85292332
    assert vote["conversion_scratch_payload_max"] == 60282
    assert vote["aes_blocks_conservative"] == 2750672
    assert vote["backend_shake_calls_including_mu"] == 744
    small = MODULE.work_components("comparator", "vote")
    assert small["leaf_slots"] == 61440
    assert small["small_vole_max_depth"] == 12


def test_completeness_request_fails_closed(capsys):
    assert MODULE.main(["--require-complete"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert not data["complete_certificate"]
    assert not data["profile_qualified"]
    assert len(data["production_terms_remaining"]) == 5
    assert MODULE.main([]) == 0


def test_sponge_boundaries_follow_absorb_pad_and_delayed_squeeze():
    # Independently walk the byte interfaces: absorption permutes on filling a
    # block, finalization always permutes, squeezing waits for another byte.
    for rate in (72, 136):
        for size in (0, rate - 1, rate, rate + 1, 2 * rate):
            for output in (0, 1, rate, rate + 1, 2 * rate):
                position = calls = 0
                for _ in range(size):
                    position += 1
                    if position == rate:
                        calls += 1
                        position = 0
                calls += 1
                position = 0
                for _ in range(output):
                    if position == rate:
                        calls += 1
                        position = 0
                    position += 1
                assert MODULE.sponge_permutations(size, output, rate) == calls
    with pytest.raises(ValueError):
        MODULE.sponge_permutations(0, 0, 0)


def test_matrix_weight_counts_actual_selected_byte_xors_and_rejects_padding():
    # Three rows and 70 columns cross a word boundary; compare every output
    # byte against a direct bit-list matrix multiplication.
    matrix = [[(r + c) % 3 == 0 for c in range(70)] for r in range(3)]
    words = [sum(int(bit) << i for i, bit in enumerate(row[start:start + 64]))
             for row in matrix for start in (0, 64)]
    width = 5
    columns = [bytes((c + i) % 256 for i in range(width)) for c in range(70)]
    xor_count = 0
    for row in matrix:
        out = bytearray(width)
        for select, column in zip(row, columns):
            if select:
                for index, value in enumerate(column):
                    out[index] ^= value
                    xor_count += 1
    assert MODULE.matrix_weight(words, 3, 70) * width == xor_count
    assert xor_count <= 3 * 70 * width
    bad = words.copy()
    bad[-1] |= 1 << 6
    with pytest.raises(ValueError, match="padding"):
        MODULE.matrix_weight(bad, 3, 70)
    with pytest.raises(ValueError, match="shape"):
        MODULE.matrix_weight(words[:-1], 3, 70)
    assert MODULE.parse_rust_array("pub static T: [u64; 2] = [0x01, 0x2_0,];", "T") == [1, 32]
    for malformed in ("", "pub static T: [u64; 2] = [0x01];", "pub static T: [u64; 1] = [evil()];"):
        with pytest.raises(ValueError):
            MODULE.parse_rust_array(malformed, "T")


def test_pinned_frame_capacity_schedules_and_conservative_reallocation_bound():
    reg = (4096,) + (256,) * 6 + (64, 128, 64)
    assert MODULE.frame_allocation(b"PARL/MU/REG/v1", reg)["capacity_bytes"] == 8236
    for seats, capacity in ((3, 1392), (500, 128466), (1000, 256466)):
        fields = (64, 64, 64, 2, 128 * seats, 128, 64, 1, 64)
        allocation = MODULE.frame_allocation(b"PARL/MU/VOTE/v1", fields)
        assert allocation["capacity_bytes"] == capacity
        assert allocation["with_realloc_overlap_bytes"] <= MODULE.growing_vec_bound(
            allocation["length_bytes"], reallocating=True)
    # Exhaust every ordered composition of up to eight elements; this also
    # covers exact-fill, one-element growth and large single appends.
    for length in range(1, 9):
        for cuts in range(1 << (length - 1)):
            parts, current = [], 1
            for index in range(length - 1):
                if cuts & (1 << index):
                    parts.append(current)
                    current = 1
                else:
                    current += 1
            parts.append(current)
            for element in (1, 8, 128):
                allocation = MODULE.vec_append_schedule(tuple(parts), element)
                assert allocation["capacity_bytes"] <= MODULE.growing_vec_bound(length, element)
                assert allocation["with_realloc_overlap_bytes"] <= MODULE.growing_vec_bound(length, element, True)
    assert MODULE.growing_vec_bound(0) == 0
    with pytest.raises(ValueError):
        MODULE.vec_append_schedule((-1,))


def test_full_field_counts_keep_leaf_product_scalar_and_alignment_separate():
    tables = MODULE.table_inventory(MODULE.ROOT, "candidate")
    schedule = MODULE.backend_schedule("candidate", "registration", 3, tables)
    arithmetic = schedule["arithmetic"]
    relation = MODULE.relation_operations("registration")
    ell, constraints, revealed = 35840, 72576, 6400 - 33
    relation_full = 75136 + 192044 + 36736
    assert relation_full == 303916
    assert relation["constraints"] + ell == constraints
    # Explicit distinct contributions: affine leaves, VOLE hash, D_tilde,
    # powers, Booleanity, relation, constraint lifting, ZK hash, final masks.
    expected = (revealed + 4 * (ell + 6) + 4 + 4 + 7 + ell
                + 75136 + 192044 + constraints + constraints + 2 + 6 + 6)
    assert arithmetic["gf256_full_multiply_upper_bound"] == expected
    assert arithmetic["gf256_mul_u64"] == ell + 6 + constraints
    assert arithmetic["gf256_mul_bit"] == ell + 35968 + 79276
    assert arithmetic["gf256_times_gf768"] == revealed
    assert arithmetic["clmul64_calls_upper_bound"] == 16 * expected + 4 * (ell + 6 + constraints) + 48 * revealed
    assert schedule["sponges"]["H5"]["keccak_f1600"] == 2 * 704
    assert schedule["prg"]["aes256_box_allocations_upper_bound"] == 6399 + 2 * revealed


def test_all_eight_shapes_lifetimes_and_fail_closed_source_binding(tmp_path):
    model = MODULE.standalone_inventory(MODULE.ROOT)
    assert len(model["cases"]) == 8
    assert not model["complete_production_certificate"]
    for case in model["cases"]:
        phases = case["allocation"]["phases"]
        assert max(p["provider_boxes"] for p in phases.values()) == 1
        assert "columns" not in phases["transpose_rows"]["buffers"]
        assert "seeds" not in phases["lift_columns"]["buffers"]
        assert "heads" not in phases["mask_tags"]["buffers"]
        for phase in phases.values():
            assert phase["requested_bytes_excluding_provider"] == sum(phase["buffers"].values())
        assert case["cold_keccak_f1600_total"] > case["ordinary_keccak_f1600_total"]
        loops = case["backend"]["bounded_loops"]
        assert loops["matrix_column_byte_xors_fixed_tables"] <= loops["matrix_column_byte_xors_all_bits_bound"]
    # A partial/different checkout must not silently reuse frozen formulas.
    with pytest.raises(ValueError, match="source changed"):
        MODULE.reviewed_source_inventory(tmp_path)


def test_provider_layout_receipt_checks_source_identity_and_target_uniqueness(tmp_path):
    import hashlib

    evidence = tmp_path / "docs/validation/parliament_ballot_b6"
    evidence.mkdir(parents=True)
    source = tmp_path / "provider.rs"
    source.write_text("reviewed provider")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    ir = evidence / "probe.ll.txt"
    ir.write_text("@B6_SOFT_SIZE = constant [960 x i8] zeroinitializer\n@B6_AUTO_SIZE = constant [960 x i8] zeroinitializer\n")
    target = {"target": "aarch64-apple-darwin", "mode": "portable",
              "bytes": {"SOFT_SIZE": 960, "AUTO_SIZE": 960}, "llvm_ir_file": ir.name,
              "llvm_ir_sha256": hashlib.sha256(ir.read_bytes()).hexdigest()}
    receipt = {"source_sha256": {source.name: digest}, "targets": [target, target],
               "maximum_simultaneous_verifier_provider_boxes": 1}
    path = evidence / "provider-layout.json"
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="duplicate"):
        MODULE.provider_layout_inventory(tmp_path)
    source.write_text("changed provider")
    with pytest.raises(ValueError, match="source changed"):
        MODULE.provider_layout_inventory(tmp_path)
