#!/usr/bin/env python3
"""Recompute frozen standalone ballot sizes and bounded work components.

Requires Python 3.11+ and the repository fixtures, without environment variables
or third-party packages. This read-only diagnostic is not a production envelope
schema or a full allocation/work certificate. Missing production terms are
explicit; --require-complete fails while any remain. Run --help for options.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
ROWS = {"candidate": (33, 8, 229, 704), "comparator": (22, 6, 225, 696)}
ROLES = {"registration": (35840, 72576), "vote": (53504, 108931)}
OPEN_TERMS = (
    "Production Norito envelope header/layout/flags and canonical field mappings",
    "Chain binding, validity-window representation and admission work-stamp encoding",
    "Registration transaction/signature framing and authenticated seal/list-context encoding",
    "Complete verifier operation schedule, including framing, CRT and relation arithmetic",
    "Complete allocation lifetimes, provider scratch, stack and allocator overhead",
)

RUST_REVISION = "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf"
# Updating this pin requires reviewing the symbolic schedules against the new
# implementation, not merely accepting changed hashes.
REVIEWED_RUST_SOURCE_SHA256 = "85637106cc477d878f5935f559db568dd7450fac3f8edcc3dde04d44b9f30741"
# Reviewed Rust 1.93.1 alloc sources; requested Layout sizes, not malloc sizes.
ALLOC_SOURCE_SHA256 = {
    "raw_vec/mod.rs": "7f94665b803a970d83f99d3a451a92af6b210baaa8c9685b1f50d265c836f38b",
    "vec/mod.rs": "98ed44ed3e17e41c6048b2057cdf44443ddb5f7462fbf9c48e7e62fc7ace286e",
    "vec/spec_extend.rs": "5673f04327502716ba5774e2067f9c1a179290e0cde92fe72ddfc5475ab34396",
    "vec/spec_from_iter.rs": "584c9018149f930b5cd56ca3ba7a7d70f48583b2dfc32b243926a6ae4cb10566",
    "vec/spec_from_iter_nested.rs": "f3c1a06f43734a65e102b6a107e2fd5adadd7d94d9a226d6ffe1610d1e7e1466",
    "alloc.rs": "cd8a5946b4c44338c451d1bb4c47e3109ea08ae7e3c58397e0879e4fe099572b",
}


def sponge_permutations(input_bytes: int, output_bytes: int, rate: int = 136) -> int:
    """Count this implementation's absorb, pad and squeeze permutations."""
    if input_bytes < 0 or output_bytes < 0 or rate <= 0:
        raise ValueError("invalid sponge dimensions")
    return input_bytes // rate + 1 + max(0, (output_bytes - 1) // rate)


def growing_vec_bound(length: int, element_bytes: int = 1, reallocating: bool = False) -> int:
    """Bound a grow-only Vec from empty under the pinned RawVec algorithm.

    Every reserve's requested length must be at most the final length. The
    extra old allocation during realloc is included when requested. This is
    not a bound on allocations made internally by the system allocator.
    """
    if length < 0 or element_bytes <= 0:
        raise ValueError("invalid vector dimensions")
    if length == 0:
        return 0
    minimum = 8 if element_bytes == 1 else 4 if element_bytes <= 1024 else 1
    capacity = max(minimum, 2 * length)
    return (capacity + (capacity // 2 if reallocating else 0)) * element_bytes


def vec_append_schedule(parts: tuple[int, ...], element_bytes: int = 1, initial: int = 0) -> dict[str, int]:
    """Model pinned RawVec reserve calls for a known sequence of appends."""
    if initial < 0 or element_bytes <= 0 or any(part < 0 for part in parts):
        raise ValueError("invalid append schedule")
    length = capacity = initial
    peak = initial
    requests = initial
    count = int(initial > 0)
    minimum = 8 if element_bytes == 1 else 4 if element_bytes <= 1024 else 1
    for part in parts:
        length += part
        if length > capacity:
            new = max(minimum, 2 * capacity, length)
            peak = max(peak, capacity + new)
            capacity = new
            requests += capacity
            count += 1
    return {"length_bytes": length * element_bytes, "capacity_bytes": capacity * element_bytes,
            "with_realloc_overlap_bytes": peak * element_bytes,
            "sum_requested_bytes": requests * element_bytes, "allocation_or_reallocation_calls": count}


def frame_allocation(tag: bytes, fields: tuple[int, ...]) -> dict[str, int]:
    """Capacity/overlap for frame_bytes' separate prefix and field appends."""
    frame_size(tag, fields)
    parts = (2, len(tag), 2) + tuple(part for length in fields for part in (4, length))
    return vec_append_schedule(parts)


def parse_rust_array(source: str, name: str, element: str = "u64") -> list[int]:
    """Read only a generated integer array, rejecting missing/ambiguous syntax."""
    matches = re.findall(rf"pub static {re.escape(name)}: \[{element}; (\d+)\] = \[(.*?)\];", source, re.S)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {name} array")
    count, body = matches[0]
    tokens = [token.strip().replace("_", "") for token in body.split(",") if token.strip()]
    if len(tokens) != int(count) or any(not re.fullmatch(r"0x[0-9a-fA-F]+|[0-9]+", token) for token in tokens):
        raise ValueError(f"malformed {name} array")
    values = [int(token, 0) for token in tokens]
    if any(value >= 1 << int(element[1:]) for value in values):
        raise ValueError(f"overflow in {name}")
    return values


def matrix_weight(words: list[int], rows: int, columns: int) -> int:
    """Count actual fixed public matrix entries, checking shape and padding."""
    stride = (columns + 63) // 64
    if rows <= 0 or columns <= 0 or len(words) != rows * stride:
        raise ValueError("invalid matrix shape")
    for row in range(rows):
        if columns % 64 and words[(row + 1) * stride - 1] >> (columns % 64):
            raise ValueError("nonzero matrix padding")
    return sum(word.bit_count() for word in words)


def table_inventory(repo: Path, row: str) -> dict:
    """Derive the CRT byte count and weights from the frozen embedded tables."""
    suffix = "f" if row == "candidate" else "s"
    path = Path(f"crates/iroha_zkp_vole/src/crt/generated/faest_256{suffix}_tables.rs")
    source = (repo / path).read_text()
    tau, grind, _, gates = ROWS[row]
    delta = 256 - grind
    arrays = {name: parse_rust_array(source, name, "u16" if name == "TREE_MODULI" else "u64")
              for name in ("TREE_MODULI", "M_TREE", "F", "G", "W_TREE", "W_GATE", "W_CRT")}
    if len(arrays["TREE_MODULI"]) != tau:
        raise ValueError("wrong CRT row")
    dimensions = {"G": (gates, delta), "W_TREE": (256, delta),
                  "W_GATE": (256, gates), "W_CRT": (256, delta)}
    matrices = {}
    for name, (height, width) in dimensions.items():
        matrices[name] = {"rows": height, "columns": width,
                          "set_bits": matrix_weight(arrays[name], height, width),
                          "all_bits_upper_bound": height * width}
    return {"source": str(path), "sha256": hashlib.sha256((repo / path).read_bytes()).hexdigest(),
            "canonical_words": 5 + sum(map(len, arrays.values())), "matrices": matrices}


def relation_operations(role: str, seats: int = 3) -> dict[str, int]:
    """Bound the actual evaluator schedule, including degree alignment.

    P is the list's bit weight and Z its nonempty bit columns. We use safe
    P<=1024*S and Z<=1024; these maxima need not be jointly realizable by a
    valid sorted distinct list. Constraint lifting/hash is counted separately.
    """
    if not 3 <= seats <= 1000:
        raise ValueError("seats must be in 3..=1000")
    if role == "registration":
        return {"constraint_system_additions": 340780, "multiplications": 75136,
                "degree_alignment_multiplications": 192044, "witness_fetches": 35968,
                "constraints": 36736, "public_list_bit_tests": 0,
                "public_bit_constructions": 2 * 1216 + 75136 + 2 * 86 + 1536}
    if role != "vote":
        raise ValueError("invalid role")
    return {"constraint_system_additions": 512005 + seats + 1024 * seats,
            "multiplications": 113024 + seats, "degree_alignment_multiplications": 288840 + 1024,
            "witness_fetches": 54016 + 2 * seats, "constraints": 55427,
            "public_list_bit_tests": 1024 * seats,
            "public_bit_constructions": 3 * 1216 + 112960 + 3 * 86 + 1536 + 3}


def backend_schedule(row: str, role: str, seats: int, tables: dict) -> dict:
    """Separate arithmetic, PRG, sponge and loop units without cycle prices."""
    tau, grind, opening, gates = ROWS[row]
    ell, constraints = ROLES[role]
    delta = 256 - grind
    short, long_count = divmod(delta, tau)
    depths = [short + 1] * long_count + [short] * (tau - long_count)
    leaves = sum(1 << depth for depth in depths)
    revealed = leaves - tau
    width = (ell + 10 * max(depths) + 7) // 8
    relation = relation_operations(role, seats)
    # Every internal GGM node is an upper bound; hidden paths are skipped.
    internal = leaves - 1
    matrix = tables["matrices"]
    full = (revealed + 4 * (ell + 6) + 8 + 7 + 2 * ell + constraints + 14
            + relation["multiplications"] + relation["degree_alignment_multiplications"]
            + relation["constraints"])
    additions = (5 * (ell + 6) + 12 + 2 * ell + 2 * constraints + 14
                 + relation["constraint_system_additions"] + relation["witness_fetches"])
    # Input lengths include the 77-byte prefix and one domain byte. H5 is
    # two permutations here, despite squeezing only two bytes.
    hashes = {
        "H0": [(77 + 16 + 1, 128)],
        "H1_vectors": [(77 + (1 << depth) * 112 + 1, 64) for depth in depths],
        "H1_outer": [(77 + 64 * tau + 1, 64)],
        "H4": [(77 + 16 + 64 + 1, 16)],
        "challenge_1": [(77 + 64 + 64 + (tau - 1) * (ell // 8) + 10 * ((gates + 7) // 8) + 16 + 32 + 1, 264)],
        "challenge_2": [(77 + 264 + 128 + 128 + ell // 8 + 1, 104)],
        "challenge_3": [(77 + 104 + 224 + 4 + 1, 32)],
        "H5": [(77 + 16 + 32 + 4 + 32 + 1, 2)] * gates,
    }
    sponge = {name: {"calls": len(parts), "absorbed_bytes": sum(x for x, _ in parts),
                     "squeezed_bytes": sum(y for _, y in parts),
                     "keccak_f1600": sum(sponge_permutations(x, y) for x, y in parts)}
              for name, parts in hashes.items()}
    return {
        "arithmetic": {"gf256_full_multiply_upper_bound": full,
                       "gf256_mul_u64": ell + 6 + constraints,
                       "gf256_mul_bit": ell + relation["witness_fetches"] + relation["public_bit_constructions"],
                       "gf256_add_upper_bound": additions,
                       "gf256_times_gf768": revealed, "gf768_add": revealed,
                       "affine_check_byte_xors": 16 * revealed,
                       "clmul64_calls_upper_bound": 16 * full + 4 * (ell + 6 + constraints) + 48 * revealed},
        "prg": {"aes256_provider_constructions_upper_bound": internal + 2 * revealed,
                "aes256_box_allocations_upper_bound": internal + 2 * revealed,
                "aes256_input_blocks_upper_bound": 4 * internal + revealed * (9 + (width + 15) // 16),
                "encrypt_slice_calls_upper_bound": internal + revealed * (2 + (width + 127) // 128),
                "expanded_output_bytes_upper_bound": 64 * internal + revealed * (144 + width),
                "simultaneously_live_provider_boxes": 1},
        "sponges": sponge,
        "relation": relation,
        "bounded_loops": {
            "decode_challenge_bit_tests": 2 * 256,
            "mark_hidden_parent_visits": 2 * (leaves - 1),
            "revealed_node_parent_visits": leaves - 1,
            "internal_node_tests": leaves - 1,
            "leaf_hash_slots": leaves,
            "opening_padding_byte_tests_upper_bound": 2 * opening * 32,
            "conversion_leaf_visits": leaves,
            "conversion_fold_byte_xors": 2 * revealed * width,
            "conversion_stack_copy_bytes": revealed * width,
            "correction_byte_xors_upper_bound": (delta - depths[0]) * (ell // 8),
            "fold_mask_read_windows": 10 * delta,
            "fold_mask_read_window_byte_tests": 30 * delta,
            "fold_mask_modular_reduction_steps": 10 * sum(depth - 1 for depth in depths),
            "fold_mask_or_windows": 10 * tau,
            "gate_spread_bit_updates": 10 * gates,
            "gate_correction_word_and_xors": 10 * ((gates + 63) // 64),
            "matrix_column_tests": gates * delta + 256 * delta,
            "matrix_column_byte_xors_fixed_tables": 32 * matrix["G"]["set_bits"] + width * matrix["W_CRT"]["set_bits"],
            "matrix_column_byte_xors_all_bits_bound": 32 * gates * delta + width * 256 * delta,
            "matrix_vector_word_and_xors": 256 * 4 + gates * 4 + 10 * (256 * 4 + 256 * ((gates + 63) // 64)),
            "matrix_vector_word_parities": 256 + gates + 10 * (256 + 256),
            "matrix_vector_output_bit_updates": 256 + gates + 10 * (256 + 256),
            "mask_tag_word_xors": 10 * 4,
            "transpose_bit_updates": ell * 256,
            "final_challenge_byte_comparisons_upper_bound": 32,
        },
    }


def statement_schedule(role: str, seats: int, tables: dict, cold: bool) -> dict:
    """Hash schedule before the backend for ordinary or cold test-record verify."""
    if not 3 <= seats <= 1000:
        raise ValueError("seats must be in 3..=1000")
    profiles = 2 if cold else 1
    crt = tables["canonical_words"] * 8
    calls = {
        "profile_crt_shake256": (profiles, crt, 64, 136),
        "profile_descriptor_sha3_512": (profiles, 286, 64, 72),
        "profile_namespace_reg_sha3_512": (profiles, 89, 64, 72),
        "profile_namespace_vote_sha3_512": (profiles, 90, 64, 72),
    }
    if role == "registration":
        calls["body_digest_sha3_512"] = (int(cold), 4136, 64, 72)
        calls["registration_authorization_sha3_512"] = (1, 5975, 64, 72)
        calls["message_shake256"] = (1, 6024, 64, 136)
        comparisons = 0
    elif role == "vote":
        calls["list_sha3_512"] = (2 if cold else 1, 128 * seats + 114, 64, 72)
        calls["vote_authorization_sha3_512"] = (1, 128 * seats + 536, 64, 72)
        calls["message_shake256"] = (1, 128 * seats + 584, 64, 136)
        comparisons = (2 if cold else 1) * (seats - 1) * 128
    else:
        raise ValueError("invalid role")
    return {"hashes": {name: {"calls": count, "absorbed_bytes": count * size,
                              "squeezed_bytes": count * output,
                              "keccak_f1600": count * sponge_permutations(size, output, rate)}
                       for name, (count, size, output, rate) in calls.items()},
            "list_order_byte_comparisons_upper_bound": comparisons,
            "test_decoder_field_slices": (11 if role == "registration" else 10) if cold else 0,
            "test_decoder_fixed_digest_comparisons_upper_bound": (128 if role == "registration" else 64) if cold else 0}


def allocation_schedule(row: str, role: str, seats: int, tables: dict) -> dict:
    """Conservative live requested allocations for cold standalone decoding.

    Assumes 64-bit usize, Key<Gf256> size 40 and Tree size at most 24. Provider
    Box storage remains an explicit additive symbol: no repr(Rust)/provider
    layout, allocator-internal memory, stack or process bound is inferred.
    """
    tau, grind, _, gates = ROWS[row]
    ell, _ = ROLES[role]
    delta = 256 - grind
    short, long_count = divmod(delta, tau)
    depth = short + 1
    leaves = long_count * 2**depth + (tau - long_count) * 2**short
    nodes = 2 * leaves - 1
    width = (ell + 10 * depth + 7) // 8
    list_bytes = 0 if role == "registration" else 128 * seats
    typed = 5632 if role == "registration" else list_bytes
    public = list_bytes
    reg_fields = (4096,) + (256,) * 6 + (64, 128, 64)
    vote_fields = (64, 64, 64, 2, list_bytes, 128, 64, 1, 64)
    frame = frame_allocation(b"PARL/MU/REG/v1" if role == "registration" else b"PARL/MU/VOTE/v1",
                             reg_fields if role == "registration" else vote_fields)
    # encode_words grows; serialization collects. The 3*n bound allows one
    # old buffer during reallocation. The two serializations coexist.
    crt_bytes = tables["canonical_words"] * 8
    crt_peak = growing_vec_bound(tables["canonical_words"], 8) + growing_vec_bound(crt_bytes, reallocating=True)
    descriptor_allocation = frame_allocation(b"PARL/DESC/v1", (16, 9, 12, 64, 16, 129))
    descriptor_peak = 12 + 16 + descriptor_allocation["with_realloc_overlap_bytes"]
    profile_peak = max(crt_peak, descriptor_peak)
    tree_metadata = 24 * tau
    hidden = 2 * tau
    bavc_return_metadata = 8 * (tau + 1) + hidden
    reconstructed = 32 * ell + 320 + hidden + 32 + 64
    persistent_vole = tree_metadata + hidden + 32 + 320 + 64 + 32 + 32 + gates * 32 + 880 + 88 + 88
    base = typed + public
    phases = {
        "profile_before_decode": {"buffers": {"profile_compilation_peak": profile_peak}},
        "decode_statement": {"buffers": {"field_slices": (11 if role == "registration" else 10) * 16,
                                         "typed_statement": typed, "list_digest_concat": list_bytes}},
        "profile_inside_verify": {"buffers": {"typed_statement": typed, "profile_compilation_peak": profile_peak}},
        "statement_authorization": {"buffers": {"typed_statement": typed, "digest_concat": list_bytes}},
        "statement_frame_and_mu": {"buffers": {"typed_statement": typed, "public_list": public,
                                              "frame_input_concat": list_bytes,
                                              "frame_with_realloc": frame["with_realloc_overlap_bytes"], "mu": 64}},
        "raw_proof_decode": {"buffers": {"retained_statement_and_public": base, "hidden": hidden, "marks": nodes}},
        "bavc_reconstruct": {"buffers": {"retained_statement_and_public": base, "tree_metadata": tree_metadata,
                                         "hidden": hidden, "marks": nodes, "keys": nodes * 32,
                                         "seeds": leaves * 32, "commitment": 64, "return_metadata": bavc_return_metadata},
                             "provider_boxes": 1},
        "vole_conversion": {"buffers": {"retained_statement_and_public": base, "tree_metadata": tree_metadata,
                                        "hidden": hidden, "bavc_return_metadata": bavc_return_metadata,
                                        "seeds": leaves * 32, "commitment_and_copy": 128, "selector": 32,
                                        "columns": delta * width, "shares": 320, "fold_scratch": (depth + 1) * width},
                            "provider_boxes": 1},
        "gate_labels": {"buffers": {"retained_statement_and_public": base, "tree_metadata": tree_metadata,
                                     "hidden": hidden, "selector": 32, "shares": 320, "commitment": 64,
                                     "delta_words_and_bytes": 64, "columns": delta * width,
                                     "heads": delta * 32, "labels": gates * 32}},
        "mask_tags": {"buffers": {"retained_statement_and_public": base, "persistent_vole": persistent_vole,
                                   "columns": delta * width, "mask_tags": 320, "two_mask_products": 64}},
        "lift_columns": {"buffers": {"retained_statement_and_public": base, "persistent_vole": persistent_vole,
                                      "mask_tags": 320, "columns": delta * width, "lifted": 256 * width}},
        "transpose_rows": {"buffers": {"retained_statement_and_public": base, "persistent_vole": persistent_vole,
                                       "mask_tags": 320, "lifted": 256 * width, "rows": 32 * ell}},
        "transcript_and_relation": {"buffers": {"retained_statement_and_public": base, "reconstruction": reconstructed,
                                                "challenge_1_and_2": 264 + 104, "decoded_masks": 320,
                                                "relation_scratch": 3840 * 40 + 1600 * 8,
                                                "selector_products": 40 * seats if role == "vote" else 0,
                                                "serialized_d_tilde": 128, "coefficients_with_realloc": 256}},
    }
    for phase in phases.values():
        phase["requested_bytes_excluding_provider"] = sum(phase["buffers"].values())
        phase.setdefault("provider_boxes", 0)
    # Counting some disjoint small temporaries together makes this an upper
    # bound, not a claim that all buffers in a phase reach their maxima at once.
    maximum = max(phase["requested_bytes_excluding_provider"] for phase in phases.values())
    record_bytes = 8 + sum(proof_layout(row, role).values()) + (
        encoding_inventory(seats)["registration_test_statement_max"] if role == "registration"
        else encoding_inventory(seats)["vote_test_statement"])
    return {"phases": phases, "frame_allocation": frame,
            "profile_disjoint_subphases": {"crt_and_serialization_with_realloc": crt_peak,
                                           "descriptor_parameters_dimensions_and_frame": descriptor_peak},
            "verifier_requested_bytes_upper_bound_excluding_provider": maximum,
            "provider_bytes_additive_symbol": "size_of::<selected AES256 provider>() (at most one live Box)",
            "canonical_exact_capacity_record_bytes_optional": record_bytes,
            "with_exact_capacity_record_excluding_provider": maximum + record_bytes,
            "process_or_stack_bound": False}


def provider_layout_inventory(repo: Path) -> dict:
    """Check the separate compile-only provider-size receipt and retained IR."""
    path = Path("docs/validation/parliament_ballot_b6/provider-layout.json")
    data = json.loads((repo / path).read_text())
    for name, digest in data["source_sha256"].items():
        if hashlib.sha256((repo / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"provider layout source changed: {name}")
    seen = set()
    for target in data["targets"]:
        key = (target["target"], target["mode"])
        if key in seen:
            raise ValueError("duplicate provider target")
        seen.add(key)
        ir = (repo / path.parent / target["llvm_ir_file"]).read_bytes()
        if hashlib.sha256(ir).hexdigest() != target["llvm_ir_sha256"]:
            raise ValueError("provider IR changed")
        for name in ("SOFT_SIZE", "AUTO_SIZE"):
            match = re.search(rf"@B6_{name} = [^\n]*constant \[(\d+) x i8\]", ir.decode())
            if match is None or int(match[1]) != target["bytes"][name] or int(match[1]) != 960:
                raise ValueError("provider size does not match reviewed layout")
    expected = {(target, mode) for target in ("aarch64-apple-darwin", "aarch64-apple-ios", "aarch64-linux-android", "x86_64-unknown-linux-musl") for mode in ("portable", "accel")}
    if seen != expected or data["maximum_simultaneous_verifier_provider_boxes"] != 1:
        raise ValueError("incomplete provider receipt")
    return {"receipt": str(path), "sha256": hashlib.sha256((repo / path).read_bytes()).hexdigest(),
            "bytes_per_box": 960, "targets_and_modes": sorted(seen), "compile_only": True}


def standalone_case(repo: Path, row: str, role: str, seats: int, tables: dict) -> dict:
    """Compose phase schedules for a bounded cold test-record verification."""
    backend = backend_schedule(row, role, seats, tables)
    cold = statement_schedule(role, seats, tables, True)
    warm = statement_schedule(role, seats, tables, False)
    return {"row": row, "role": role, "seats": seats if role == "vote" else None,
            "registration_fields": "maximum permitted" if role == "registration" else None,
            "backend": backend, "cold_statement": cold, "ordinary_statement": warm,
            "cold_keccak_f1600_total": sum(v["keccak_f1600"] for v in backend["sponges"].values()) + sum(v["keccak_f1600"] for v in cold["hashes"].values()),
            "ordinary_keccak_f1600_total": sum(v["keccak_f1600"] for v in backend["sponges"].values()) + sum(v["keccak_f1600"] for v in warm["hashes"].values()),
            "allocation": allocation_schedule(row, role, seats, tables)}


def reviewed_source_inventory(repo: Path) -> dict:
    """Fail closed if a source underlying the schedules changed since review."""
    paths = sorted(path.relative_to(repo).as_posix()
                   for directory in ("crates/iroha_zkp_vole/src", "crates/iroha_parliament_ballot_proof/src", "vendor/aes/src")
                   for path in (repo / directory).rglob("*.rs"))
    paths += ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "vendor/aes/Cargo.toml",
              "crates/iroha_zkp_vole/Cargo.toml", "crates/iroha_parliament_ballot_proof/Cargo.toml"]
    if any(not (repo / path).is_file() for path in paths):
        raise ValueError("standalone resource model source changed or missing")
    hashes = {path: hashlib.sha256((repo / path).read_bytes()).hexdigest() for path in sorted(paths)}
    digest = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != REVIEWED_RUST_SOURCE_SHA256:
        raise ValueError("standalone resource model source changed; review formulas before updating the pin")
    return {"aggregate_sha256": digest, "files": hashes}


def standalone_inventory(repo: Path) -> dict:
    """Publish bounds only for the explicit standalone model and source set."""
    sources = reviewed_source_inventory(repo)
    provider = provider_layout_inventory(repo)
    tables = {row: table_inventory(repo, row) for row in ROWS}
    cases = [standalone_case(repo, row, role, seats, tables[row])
             for row in ROWS for role in ROLES for seats in ((3,) if role == "registration" else (3, 500, 1000))]
    for case in cases:
        allocation = case["allocation"]
        maximum = max(phase["requested_bytes_excluding_provider"] + 960 * phase["provider_boxes"]
                      for phase in allocation["phases"].values())
        allocation["provider_specialized_requested_bytes_upper_bound"] = maximum
        allocation["provider_specialized_with_exact_capacity_record"] = maximum + allocation["canonical_exact_capacity_record_bytes_optional"]
    return {
        "scope": "cold bounded TEST_RECORD decode followed by ordinary standalone verify; ordinary prelude also reported",
        "complete_production_certificate": False,
        "instruction_cycle_or_deadline_bound": False,
        "assumptions": [
            "Frozen reviewed Rust sources and Rust 1.93.1 Global/Vec allocation policy",
            "Source/manifests/lock pin identifies the reviewed checkout, not a compiled binary; dependency source integrity follows Cargo package checksums",
            "Both fixed extended rows, registration fields at caps, vote S in 3..=1000",
            "64-bit usize; Key<Gf256> size 40 and Tree size at most 24 are explicit layout assumptions",
            "Input slices already exist; arbitrary caller spare capacity is excluded",
            "Optional owned record total assumes an allocation with exactly the canonical record length",
            "Requested allocation sizes only; one AES256 provider Box is an additional symbolic term",
            "Allocator metadata/rounding/internal temporary storage, stack, compiler spills, globals, code and concurrency excluded",
            "Abstract source operations remain separate; AES provider internal batching/key schedule costs are not equal to block counts",
            "Primitive arithmetic/hash/loop counts do not include compiler instructions or price allocator/system calls",
        ],
        "rust_alloc": {"revision": RUST_REVISION, "source_sha256": ALLOC_SOURCE_SHA256,
                       "url_prefix": f"https://github.com/rust-lang/rust/blob/{RUST_REVISION}/library/alloc/src/"},
        "sources": sources, "provider_layout": provider, "tables": tables, "cases": cases,
    }


def frame_size(tag: bytes, fields: tuple[int, ...]) -> int:
    """Count the exact standalone Frame bytes after validating length words."""
    if not tag.isascii() or len(tag) > 0xFFFF or len(fields) > 0xFFFF:
        raise ValueError("invalid Frame tag or count")
    if any(size < 0 or size > 0xFFFFFFFF for size in fields):
        raise ValueError("invalid Frame field length")
    return 2 + len(tag) + 2 + 4 * len(fields) + sum(fields)


def proof_layout(row: str, role: str) -> dict[str, int]:
    """Return the independent byte inventory for the frozen extended proof."""
    tau, _, opening, multiplications = ROWS[row]
    witness, _ = ROLES[role]
    return {
        "corrections": (tau - 1) * (witness // 8),
        "multiplication_corrections": 10 * ((multiplications + 7) // 8),
        "u_tilde": 128,
        "masked_witness": witness // 8,
        "coefficients": 6 * 32,
        "challenge": 32,
        "opening": tau * 112 + opening * 32,
        "iv_pre": 16,
        "salt": 32,
        "counter": 4,
    }


def encoding_inventory(seats: int) -> dict[str, int]:
    """Count maximal registration and exact vote/list frames at a valid size."""
    if not 3 <= seats <= 1000:
        raise ValueError("seats must be in 3..=1000")
    registration = (4096,) + (256,) * 6 + (64, 128, 64)
    vote = (64, 64, 64, 2, 128 * seats, 128, 64, 1, 64)
    list_frame = frame_size(b"PARL/LIST/v1", (16, 64, 2, 128 * seats))
    return {
        "registration_mu_frame_max": frame_size(b"PARL/MU/REG/v1", registration),
        "registration_test_statement_max": frame_size(b"PARL/TEST/REG/v1", (64,) + registration),
        "vote_mu_frame": frame_size(b"PARL/MU/VOTE/v1", vote),
        "vote_test_statement": frame_size(b"PARL/TEST/VOTE/v1", (64,) + vote),
        "raw_list": 128 * seats,
        "list_digest_frame": list_frame,
        "list_frame_sha3_permutations": list_frame // 72 + 1,
        "vote_authorization_digest_frame": 128 * seats + 536,
        "vote_authorization_digest_sha3_permutations": (128 * seats + 536) // 72 + 1,
        "ballot_fixed_cryptographic_fields_including_profile": 467,
        "remaining_list_cap_after_digest_frame": 163840 - list_frame,
    }


def work_components(row: str, role: str) -> dict[str, int]:
    """Bound selected source loops; these components are not a total charge."""
    tau, grind, _, multiplications = ROWS[row]
    witness, constraints = ROLES[role]
    delta = 256 - grind
    short, long_count = divmod(delta, tau)
    depth = short + 1
    leaves = long_count * 2**depth + (tau - long_count) * 2**short
    width = (witness + 10 * depth + 7) // 8
    return {
        "leaf_slots": leaves,
        "reconstructed_leaves": leaves - tau,
        "ggm_nodes": 2 * leaves - 1,
        "small_vole_max_depth": depth,
        "column_bytes": width,
        # fold() performs two width-byte XORs for each binary-tree merge,
        # including the zero hidden slot. Sum_i (N_i - 1) = leaves - tau.
        "conversion_fold_byte_xors": 2 * (leaves - tau) * width,
        "conversion_scratch_payload_max": (depth + 1) * width,
        "aes_blocks_conservative": 4 * (leaves - 1) + (leaves - tau) * (9 + (witness + 10 * depth + 127) // 128),
        # These mix full GF(2^256) products and scalar mul_u64 operations;
        # neither counter is a count of equally costly full-field products.
        "volehash_mixed_field_products": 5 * (witness + 6) + 4,
        "zkhash_mixed_field_products": 2 * constraints + 2,
        "backend_shake_calls_including_mu": multiplications + tau + 7,
        "raw_column_payload": delta * width,
        "lifted_column_payload": 256 * width,
        "lifted_row_payload": 32 * witness,
    }


def report(repo: Path = ROOT) -> dict:
    """Cross-check all raw proof fixtures and retain unknown terms explicitly."""
    fixtures = repo / "crates/iroha_parliament_ballot_proof/tests/fixtures"
    cases = []
    for row in ROWS:
        suffix = "fast" if row == "candidate" else "comparator"
        for role in ROLES:
            layout = proof_layout(row, role)
            proof_bytes = sum(layout.values())
            names = [f"reg_{suffix}.proof"] if role == "registration" else [
                f"vote_S{seats}_i{index}_{suffix}.proof" for seats, index in ((3, 1), (500, 250), (1000, 500))
            ]
            for name in names:
                actual = (fixtures / name).stat().st_size
                if actual != proof_bytes:
                    raise ValueError(f"{name}: expected {proof_bytes} proof bytes, got {actual}")
            case = {"row": row, "role": role, "proof_fields": layout, "proof_bytes": proof_bytes,
                    "envelope_budget_after_proof": 262144 - proof_bytes,
                    "work_components": work_components(row, role)}
            if role == "vote":
                case["envelope_budget_after_fixed_crypto_fields"] = 262144 - proof_bytes - 467
                case["test_records"] = {
                    str(seats): 8 + encoding_inventory(seats)["vote_test_statement"] + proof_bytes
                    for seats in (3, 500, 1000)
                }
            else:
                case["test_record_max"] = 8 + encoding_inventory(3)["registration_test_statement_max"] + proof_bytes
            cases.append(case)
    return {"schema": "parliament-ballot-b6-resource-accounting-v1", "profile_qualified": False,
            "complete_certificate": False, "production_terms_remaining": list(OPEN_TERMS),
            "combined_input_cap": 262144 + 163840,
            "encoding_inventory": {str(n): encoding_inventory(n) for n in (3, 500, 1000)}, "cases": cases,
            "standalone_symbolic_bounds": standalone_inventory(repo)}


def main(argv: list[str] | None = None) -> int:
    """Print the diagnostic and optionally require the currently missing certificate."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-complete", action="store_true", help="fail until every full-certificate term is established")
    args = parser.parse_args(argv)
    result = report()
    print(json.dumps(result, indent=2, sort_keys=True))
    return int(args.require_complete and not result["complete_certificate"])


if __name__ == "__main__":
    raise SystemExit(main())
