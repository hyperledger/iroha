#!/usr/bin/env python3
"""Source-pinned logical byte/control charges for standalone ballot front ends.

Python 3.11+, standard library only, no environment variables. Read-only by
default; --output writes a diagnostic JSON receipt. This covers named source
operations, not machine instructions, complete B_work, or production encoding.
No provider/backend, allocator, relocation, compiler-copy or stack charge is
inferred. --require-complete always refuses the incomplete certificate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVIEWED_SOURCE_SHA256 = "85637106cc477d878f5935f559db568dd7450fac3f8edcc3dde04d44b9f30741"
ROWS = {"candidate": (33, 10538), "comparator": (22, 10463)}
PROOF_BYTES = {("candidate", "registration"): 160148, ("candidate", "vote"): 233012,
               ("comparator", "registration"): 109498, ("comparator", "vote"): 158074}


def source_inventory(repo: Path) -> dict:
    """Refuse drift in the same 81 source/build files as the reviewed model."""
    paths = [p.relative_to(repo).as_posix()
             for directory in ("crates/iroha_zkp_vole/src", "crates/iroha_parliament_ballot_proof/src", "vendor/aes/src")
             for p in (repo / directory).rglob("*.rs")]
    paths += ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "vendor/aes/Cargo.toml",
              "crates/iroha_zkp_vole/Cargo.toml", "crates/iroha_parliament_ballot_proof/Cargo.toml"]
    try:
        hashes = {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in sorted(paths)}
    except OSError as error:
        raise ValueError("reviewed front-end source missing") from error
    aggregate = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if aggregate != REVIEWED_SOURCE_SHA256:
        raise ValueError("front-end sources changed; review charges before updating the pin")
    return {"aggregate_sha256": aggregate, "files": hashes}


def frame_charge(tag: bytes, fields: tuple[int, ...], sink: str) -> dict:
    """Count Frame's explicit interfaces for whole-field writes.

    framing.rs:145-259: begin emits three chunks; field calls begin_field then
    write, emitting two chunks per field. Length encodings create 4+4N bytes.
    Every field performs three fallible integer conversions (u64/u32/u64),
    two checked subtractions and one explicit incomplete-field check. Begin
    performs two fallible conversions, finish two explicit checks. Iterator
    bookkeeping, assignments, implicit slice bounds and sink internals are
    excluded. The ASCII bound is logical bytes inspected, not CPU comparisons.
    """
    if sink not in ("vec", "hash"):
        raise ValueError("unknown sink")
    if len(tag) > 65535 or not tag.isascii() or len(fields) > 65535:
        raise ValueError("invalid frame header")
    if any(not 0 <= n < 1 << 32 for n in fields):
        raise ValueError("invalid frame field")
    n = len(fields)
    length = 4 + len(tag) + 4 * n + sum(fields)
    return {"tag": tag.decode("ascii"), "fields": list(fields), "sink": sink,
            "frame_bytes": length, "sink_absorb_calls": 3 + 2 * n,
            "sink_input_bytes": length, "vec_append_bytes": length if sink == "vec" else 0,
            "hash_input_bytes": length if sink == "hash" else 0,
            "length_le_encode_bytes": 4 + 4 * n, "tag_ascii_bytes_upper_bound": len(tag),
            "fallible_integer_conversions": 2 + 3 * n,
            "checked_subtractions": 2 * n, "explicit_incomplete_or_missing_checks": n + 2,
            "field_iterations": n}


def frames(role: str, seats: int, cold: bool) -> list[dict]:
    """Whole-field frame calls on the maximum bounded front-end success path.

    Profile::new uses DESC and both NS frames. Cold decoding adds the body
    digest or a list validation. Ordinary verify adds authorization and MU;
    vote also validates its list. concat(L) is materialized, not streamed.
    No test encoder runs during cold verification.
    """
    if role not in ("registration", "vote") or not 3 <= seats <= 1000:
        raise ValueError("invalid relation or list size")
    specifications = []
    for _ in range(2 if cold else 1):
        specifications += [(b"PARL/DESC/v1", (16, 9, 12, 64, 16, 129), "vec"),
                           (b"PARL/NS/v1", (64, 3), "hash"),
                           (b"PARL/NS/v1", (64, 4), "hash")]
    if role == "registration":
        if cold:
            specifications.append((b"PARL/BODY/v1", (16, 4096), "hash"))
        specifications += [(b"PARL/REG-AUTH/v1", (16, 3, 64, 4096, *([256] * 6), 64, 128), "hash"),
                           (b"PARL/MU/REG/v1", (4096, *([256] * 6), 64, 128, 64), "vec")]
    else:
        specifications += [(b"PARL/LIST/v1", (16, 64, 2, 128 * seats), "hash")] * (2 if cold else 1)
        specifications += [(b"PARL/VOTE-AUTH/v1", (16, 4, 64, 64, 64, 64, 2, 128 * seats, 128, 1, 64), "hash"),
                           (b"PARL/MU/VOTE/v1", (64, 64, 64, 2, 128 * seats, 128, 64, 1, 64), "vec")]
    return [frame_charge(*spec) for spec in specifications]


def decoder_charge(role: str, seats: int) -> dict:
    """Logical maxima for decode_record plus the bounded statement decoder.

    seats bounds the ACTUAL list payload length, never the untrusted declared
    S. Use 1000 for unconditional rejected-input bounds: a statement declaring
    S=3 can still copy/compare 1000 entries before its size mismatch rejects.

    test_codec.rs:159-364: record takes two u32 prefixes and two borrowed
    payloads. parse_frame takes tag length/tag/count and two slices per field;
    each take_len zero-initializes and copies four bytes before decoding.
    The parser never scans skipped payloads. Field-count mismatch stops before
    allocation/iteration. Body/opaque constructors bound before copying, fixed
    arrays require exact lengths, and list length is bounded before split.
    sealed_list.rs:92-108 explicitly initializes/copies each 128-byte entry.
    List hashing/comparison after decode is charged elsewhere.
    """
    if role not in ("registration", "vote") or not 3 <= seats <= 1000:
        raise ValueError("invalid relation or list size")
    n = 11 if role == "registration" else 10
    tag_len = len(b"PARL/TEST/REG/v1" if role == "registration" else b"PARL/TEST/VOTE/v1")
    prefixes = n + 2
    registration = role == "registration"
    return {"take_slice_bounds_checks": 4 + 3 + 2 * n,
            "u32_length_decodes": prefixes, "u16_length_or_count_decodes": 2 + int(not registration),
            "u32_prefix_zero_init_bytes": 4 * prefixes,
            "u32_prefix_copy_bytes": 4 * prefixes,
            "u32_prefix_usize_conversions": prefixes,
            "tag_bytes_compared_upper_bound": tag_len,
            "descriptor_bytes_compared_upper_bound": 64,
            "body_digest_bytes_compared_upper_bound": 64 if registration else 0,
            "field_slice_pushes": n, "record_payload_copy_bytes": 0,
            "opaque_payload_copy_bytes_upper_bound": 4096 + 6 * 256 if registration else 0,
            "fixed_array_copy_bytes": 128 + 2 * 64 if registration else 5 * 64 + 128,
            "list_entry_zero_init_bytes": 0 if registration else 128 * seats,
            "list_entry_copy_bytes": 0 if registration else 128 * seats,
            "fixed_array_length_checks": 3 if registration else 6,
            "opaque_bound_checks": 7 if registration else 0,
            "early_list_divisibility_checks": 0 if registration else 2,
            "early_list_count_range_tests": 0 if registration else 1,
            "notes": "seats bounds actual list entries, not declared S. Use 1000 for unconditional rejection bounds. Within that actual-length bound, success maxima bound the named rejection-prefix operations. Oversized fields are borrowed/skipped and refused before their payload is copied."}


def profile_charge(row: str, copies: int) -> dict:
    """Named profile construction operations, excluding hash and Vec internals.

    crt/codec.rs:41-63 initializes five u64 values, widens tau u16 values,
    then copies six fixed word arrays. profile.rs:253-269 converts every word
    to eight LE bytes and collects those bytes. profile.rs:282-357 encodes
    six u16 parameters/four u32 dimensions, concatenates their bytes, copies
    the descriptor, initializes digest/namespace/prefix arrays and copies the
    two prefixes. Unspecified moves/return copies are deliberately excluded.
    """
    if row not in ROWS or copies not in (1, 2):
        raise ValueError("invalid profile or multiplicity")
    tau, words = ROWS[row]
    units = {"canonical_u64_words": words, "header_u64_initializations": 5,
             "header_u32_to_u64_conversions": 4, "modulus_u16_to_u64_conversions": tau,
             "array_to_word_vec_copy_bytes": 8 * (words - 5 - tau),
             "modulus_word_push_bytes": 8 * tau,
             "crt_u64_le_encode_bytes": 8 * words, "crt_byte_collect_bytes": 8 * words,
             "descriptor_parameter_le_encode_bytes": 28, "descriptor_parameter_concat_copy_bytes": 28,
             "descriptor_array_copy_bytes": 286,
             "explicit_public_zero_init_bytes": 64 + 2 * 64 + 2 * 77,
             "prefix_copy_bytes": 2 * 77,
             "parameter_fallible_conversions": 10}
    return {"profile_compilations": copies, **{key: value * copies for key, value in units.items()}}


def case_charge(row: str, role: str, seats: int, cold: bool) -> dict:
    """Keep disjoint operation categories separate; no total instruction score."""
    if row not in ROWS:
        raise ValueError("invalid row")
    calls = frames(role, seats, cold)
    numeric = [key for key, value in calls[0].items() if isinstance(value, int)]
    totals = {key: sum(call[key] for call in calls) for key in numeric}
    validations = (2 if cold else 1) if role == "vote" else 0
    blocks = 2 if role == "registration" else 3
    # sealed_list::concat in each validation, authorization_digest,
    # instance_unvalidated's public input, and MU frame construction.
    concatenations = validations + 3 if role == "vote" else 0
    # public_block: zero 200 bytes, copy 4+16+64, and set two pad bytes.
    public = {"public_block_zero_init_bytes": 200 * blocks,
              "public_block_copy_bytes": 84 * blocks, "public_block_padding_byte_writes": 2 * blocks,
              "message_output_zero_init_bytes": 64,
              "list_concat_calls": concatenations, "list_concat_copy_bytes": 128 * seats * concatenations,
              "list_concat_entry_iterations": seats * concatenations,
              "list_count_range_tests": validations,
              "list_order_pair_comparisons": (seats - 1) * validations,
              "list_order_bytes_compared_upper_bound": 128 * (seats - 1) * validations,
              "list_digest_bytes_compared_upper_bound": 64 * validations,
              "list_size_equality_checks": validations, "vote_value_checks": validations,
              "list_size_u16_encode_bytes": 2 * (validations + 2) if role == "vote" else 0}
    statement_bytes = 6016 if role == "registration" else 128 * seats + 576
    return {"row": row, "role": role, "seats": seats if role == "vote" else None,
            "path": "cold_test_record" if cold else "ordinary_typed",
            "canonical_record_bytes_max": 8 + statement_bytes + PROOF_BYTES[row, role],
            "profile": profile_charge(row, 2 if cold else 1), "frames": calls,
            "frame_totals": totals, "decoder": decoder_charge(role, seats) if cold else None,
            "public_preparation": public}


def report(repo: Path = ROOT) -> dict:
    """Publish the bounded subset with its exact source identity and exclusions."""
    return {"schema": "parliament-ballot-frontend-logical-charges-v1",
            "complete_work_certificate": False, "process_memory_certificate": False,
            "profile_qualified": False, "source": source_inventory(repo),
            "accounting_artifact_sha256": {
                path: hashlib.sha256((repo / path).read_bytes()).hexdigest()
                for path in ("scripts/parliament_ballot_frontend_accounting.py",
                             "scripts/tests/parliament_ballot_frontend_accounting_test.py")},
            "charge_semantics": "Logical source-interface units; categories are separate, not machine instructions or measured byte traffic. Hash input bytes overlap the existing sponge inventory and must not be added as another permutation count.",
            "input_scope": {"ingress_cap_enforced_by_test_codec": False,
                            "rejected_declared_lengths": "At most 11 statement fields are traversed. take skips by slicing; prefixes/tags/fixed comparisons are bounded. No oversized body/opaque/list field is copied. Existing caller input capacity and transport parsing are excluded.",
                            "case_bounds": "Each S case bounds accepted-length inputs and rejection prefixes with list length <= S. Use the S=1000 case for arbitrary vote inputs, including mismatched declared S; registration uses all maximum opaque lengths."},
            "remaining_terms": ["Backend byte initialization/copy/drop-zeroization and scalar control",
                                "Hash/AES/provider internals and CRT/runtime-context checks beyond named encoding operations",
                                "Iterator bookkeeping, implicit bounds, assignments, moves, compiler spills/copies and optimization",
                                "Vec relocation, allocation/deallocation, allocator internals, failure, concurrency and stack",
                                "Production Norito ingress/envelope, authenticated context and admission stamps"],
            "zeroization_scope": "This public preprocessing has no explicit Zeroize call. Backend/provider drops remain excluded; zero initialization here is not an erasure guarantee.",
            "cases": [case_charge(row, role, seats, cold) for row in ROWS for role in ("registration", "vote")
                      for seats in ((3,) if role == "registration" else (3, 500, 1000)) for cold in (False, True)]}


def main(argv: list[str] | None = None) -> int:
    """Print or save the subset; never issue a complete certificate."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args(argv)
    data = json.dumps(report(), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(data, encoding="utf-8")
    else:
        print(data, end="")
    return 1 if args.require_complete else 0


if __name__ == "__main__":
    raise SystemExit(main())
