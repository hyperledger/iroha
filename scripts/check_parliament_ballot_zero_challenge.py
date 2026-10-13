#!/usr/bin/env python3
"""Check the fixed zero fallback against both reviewed Parliament row geometries.

Requires Python 3.11+ and the pinned repository sources. No environment, network,
build or cryptographic execution is used. The default only emits JSON; --output
writes report.json in a NEW directory. This source-bound combinatorial check
closes only membership of zero in the proposed admissible challenge set. It
does not prove the H5 lemma, a simulator distribution or production security.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

import check_parliament_ballot_security_ledger as ledger

ROOT = Path(__file__).resolve().parents[1]
PINNED = {
    "crates/iroha_parliament_ballot_proof/src/profile.rs": "9cc79a448f4199b748923b8b3e6a552fb9f0aa7980a1cb6d1d89746e8b79323d",
    "crates/iroha_zkp_vole/src/params.rs": "41d18d1bf137496db8bd858bc291e48684c11122c03834828d54d3b6ae8cabba",
    "crates/iroha_zkp_vole/src/bavc.rs": "481b4c7027b46520e848a67d94a6dc7cdda312838e1769a93b9079260b8d4269",
    "crates/iroha_zkp_vole/src/proof.rs": "f87a7282a56dd75e774edd7082aad132b7267ca075132003c597123d310cf1cc",
    "crates/iroha_zkp_vole/src/vole.rs": "5fcfe9c24e0e4a7319a0e4ed8ab99e7fbc83cd07c89f997864e393fbc9d09f31",
    "crates/iroha_zkp_vole/src/variant.rs": "50d8c414309f5ccc315181abefbdabe79ed092f0644dc72e04596c93c58059b9",
    "scripts/check_parliament_ballot_security_ledger.py": "910e958898c465e70cda88e52cf8f61af05ba8cd343a82812fa1ba103600a359",
    "specs/parliament_ballot_b6_hybrid_driver.md": "a95739b192f2a431cbf2a95c6964817137a6c5e0856121b20d4465a036f5835a",
}
REFERENCES = [
    ("crates/iroha_parliament_ballot_proof/src/profile.rs", 90, 108, "both roles"),
    ("crates/iroha_parliament_ballot_proof/src/profile.rs", 173, 184, "row geometry"),
    ("crates/iroha_parliament_ballot_proof/src/profile.rs", 397, 402, "role-independent extended context geometry"),
    ("crates/iroha_zkp_vole/src/params.rs", 169, 219, "validated parameter limits"),
    ("crates/iroha_zkp_vole/src/params.rs", 267, 317, "depths and leaf counts"),
    ("crates/iroha_zkp_vole/src/params.rs", 580, 590, "three-block AES leaf scheme"),
    ("crates/iroha_zkp_vole/src/params.rs", 641, 685, "actual standard row constants"),
    ("crates/iroha_zkp_vole/src/bavc.rs", 107, 109, "maximum tree tweak"),
    ("crates/iroha_zkp_vole/src/bavc.rs", 362, 427, "shape and position rules"),
    ("crates/iroha_zkp_vole/src/bavc.rs", 700, 749, "hidden marks and revealed boundary"),
    ("crates/iroha_zkp_vole/src/bavc.rs", 927, 960, "opening threshold is inclusive"),
    ("crates/iroha_zkp_vole/src/bavc.rs", 1125, 1149, "length, grinding suffix and low-bit-first decode"),
    ("crates/iroha_zkp_vole/src/proof.rs", 301, 313, "extended context checks"),
    ("crates/iroha_zkp_vole/src/proof.rs", 617, 634, "retry predicate and bounded counter"),
    ("crates/iroha_zkp_vole/src/vole.rs", 662, 674, "VOLE delegates opening to BAVC"),
    ("crates/iroha_zkp_vole/src/variant.rs", 49, 54, "actual counter ceiling"),
    ("crates/iroha_zkp_vole/src/variant.rs", 146, 180, "extended construction eligibility"),
    ("scripts/check_parliament_ballot_security_ledger.py", 94, 98, "reused independent interleaved leaf listing"),
    ("specs/parliament_ballot_b6_hybrid_driver.md", 62, 93, "fixed fallback obligation"),
]


def digest(path: Path) -> str:
    """Identify exact reviewed bytes, not their authenticity."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_sources(root: Path) -> dict[str, str]:
    """Refuse changed source semantics instead of silently repinning a model."""
    ledger_name = "scripts/check_parliament_ballot_security_ledger.py"
    if digest(Path(ledger.__file__).resolve()) != PINNED[ledger_name]:
        raise ValueError("loaded independent leaf-listing source changed")
    observed = {name: digest(root / name) for name in PINNED}
    if observed != PINNED:
        raise ValueError("reviewed source changed: " + ", ".join(name for name in PINNED if observed[name] != PINNED[name]))
    return observed


def geometry(bits: int, tau: int, grind: int, limit: int) -> dict:
    """Derive the source heap geometry; tiny byte-sized rows support model tests.

    The checker is intentionally capped at the largest actual row's leaf count.
    Toy levels are combinatorial controls, never declared backend profiles.
    """
    if any(type(value) is not int for value in (bits, tau, grind, limit)):
        raise ValueError("integer geometry required")
    if not (8 <= bits <= 256 and bits % 8 == 0 and 0 <= grind < bits
            and 2 <= tau <= bits - grind and 1 <= limit <= 65536):
        raise ValueError("invalid geometry")
    short, long_count = divmod(bits - grind, tau)
    if not 2 <= short + 1 <= 16:
        raise ValueError("unsupported vector depth")
    depths = [short + (index < long_count) for index in range(tau)]
    sizes = [1 << depth for depth in depths]
    leaves = sum(sizes)
    if leaves > 61440:
        raise ValueError("checker leaf bound exceeded")
    return {"lambda_bits": bits, "tau": tau, "w_grind": grind, "t_open": limit,
            "n_delta": bits - grind, "tau1": long_count, "k": short + 1,
            "depths": depths, "vector_sizes": sizes, "leaves": leaves, "nodes": 2 * leaves - 1}


def decode_challenge(shape: dict, challenge: bytes) -> list[int]:
    """Decode exactly one fixed-length challenge, refusing every grinding bit."""
    if not isinstance(challenge, bytes) or len(challenge) != shape["lambda_bits"] // 8:
        raise ValueError("challenge length")
    value = int.from_bytes(challenge, "little")
    if value >> shape["n_delta"]:
        raise ValueError("grinding bits set")
    hidden, low = [], 0
    for depth in shape["depths"]:
        hidden.append((value >> low) & ((1 << depth) - 1))
        low += depth
    if low != shape["n_delta"]:
        raise ValueError("invalid decoded depth sum")
    return hidden


def check_indices(shape: dict, hidden: list[int]) -> None:
    """Require exactly one in-range leaf index for each vector."""
    if len(hidden) != shape["tau"] or any(type(index) is not int or not 0 <= index < size
                                         for index, size in zip(hidden, shape["vector_sizes"])):
        raise ValueError("hidden index count or range")


def heap_boundary(shape: dict, hidden: list[int]) -> dict:
    """Apply source PosInTree and bottom-up marking, retaining actual boundary."""
    check_indices(shape, hidden)
    leaves, tau, tau1, half = shape["leaves"], shape["tau"], shape["tau1"], 1 << (shape["k"] - 1)
    selected = [leaves - 1 + (tau * index + vector if index < half
                else tau * half + tau1 * (index - half) + vector) for vector, index in enumerate(hidden)]
    marks = [False] * shape["nodes"]
    for node in selected:
        marks[node] = True
    for parent in range(leaves - 2, -1, -1):
        marks[parent] = marks[2 * parent + 1] or marks[2 * parent + 2]
    boundary = [2 * parent + 1 + int(marks[2 * parent + 1])
                for parent in range(leaves - 2, -1, -1)
                if marks[2 * parent + 1] != marks[2 * parent + 2]]
    return {"selected_leaves": sorted(selected), "marked_nodes": sum(marks), "revealed_nodes": boundary}


def ancestor_boundary(shape: dict, hidden: list[int]) -> dict:
    """Independently list interleaved leaves and union their parent paths.

    Reuses the ledger's exact vector listing, without its expected-opening
    probability calculation. No source position formula or bottom-up marks are
    reused. An unselected sibling of a selected ancestor is a revealed node.
    """
    check_indices(shape, hidden)
    seen, selected = [0] * shape["tau"], []
    for offset, vector in enumerate(ledger.leaf_vectors(tuple(shape["vector_sizes"]))):
        if seen[vector] == hidden[vector]:
            selected.append(shape["leaves"] - 1 + offset)
        seen[vector] += 1
    marked = set()
    for node in selected:
        while node:
            marked.add(node)
            node = (node - 1) // 2
        marked.add(0)
    boundary = {node + 1 if node % 2 else node - 1 for node in marked if node}
    boundary.difference_update(marked)
    return {"selected_leaves": sorted(selected), "marked_nodes": len(marked),
            "revealed_nodes": sorted(boundary, reverse=True)}


def admissible(shape: dict, challenge: bytes) -> bool:
    """Check only the proposal's grinding/decode/opening-size predicate."""
    hidden = decode_challenge(shape, challenge)
    return len(heap_boundary(shape, hidden)["revealed_nodes"]) <= shape["t_open"]


def certificate(root: Path = ROOT) -> dict:
    """Bind exact actual rows and both roles to the finite zero-opening check."""
    before = verify_sources(root)
    params = (root / "crates/iroha_zkp_vole/src/params.rs").read_text()
    rows = {}
    for label, suffix, expected in (("candidate", "F", (33, 8, 229, 704, 6400, 11)),
                                    ("comparator", "S", (22, 6, 225, 696, 61440, 12))):
        pattern = rf'pub const FAEST_256{suffix}: FaestParams = standard\("FAEST-256{suffix.lower()}", Aes, L256, (\d+), (\d+), (\d+), (\d+), 48, \d+\);'
        matches = re.findall(pattern, params)
        if len(matches) != 1:
            raise ValueError("actual profile constant missing or ambiguous")
        tau, grind, limit, gates = map(int, matches[0])
        shape = geometry(256, tau, grind, limit)
        zero = bytes(32)
        hidden = decode_challenge(shape, zero)
        direct, independent = heap_boundary(shape, hidden), ancestor_boundary(shape, hidden)
        count = len(direct["revealed_nodes"])
        if ((tau, grind, limit, gates, shape["leaves"], count) != expected
                or hidden != [0] * tau or direct != independent or not admissible(shape, zero)):
            raise ValueError("zero fallback cross-check failed")
        shape_guards = {"leaves_plus_tau": shape["leaves"] + tau, "tweak_limit": 1 << 31,
                        "largest_checked_node_key_buffer_bytes": 2 * shape["leaves"] * 32}
        if (shape_guards["leaves_plus_tau"] > shape_guards["tweak_limit"]
                or shape_guards["largest_checked_node_key_buffer_bytes"] >= 1 << 32):
            raise ValueError("source shape bounds failed")
        rows[label] = {**shape, "n_mult": gates, "n_leafcom": 3, "d_zk": 7,
                       "challenge_hex": zero.hex(), "decoded_indices": hidden, **direct,
                       "revealed_count": count, "opening_slack_nodes": limit - count,
                       "grinding_bit_positions": list(range(shape["n_delta"], 256)),
                       "admissible": True, "independent_boundary_agrees": True,
                       "source_shape_guards": shape_guards,
                       "role_results": {role: {"construction": "Extended", "same_row_geometry": True,
                                                "admissible": True} for role in ("registration", "vote")},
                       "source_admissibility_work": {
                           "challenge_bit_reads": 256, "hidden_index_range_checks": tau,
                           "mark_initializations": 2 * shape["leaves"] - 1,
                           "selected_leaf_marks": tau, "parent_iterations": shape["leaves"] - 1,
                           "marked_child_reads": 2 * (shape["leaves"] - 1),
                           "scope": "decode_challenge plus mark_hidden loop counts; excludes allocation, cryptographic opening material, checker cross-validation and complete simulator resources"}}
    references = []
    for name, start, end, meaning in REFERENCES:
        lines = (root / name).read_bytes().splitlines(keepends=True)
        references.append({"path": name, "start_line": start, "end_line": end, "meaning": meaning,
                           "excerpt_sha256": hashlib.sha256(b"".join(lines[start - 1:end])).hexdigest()})
    after = verify_sources(root)
    return {"schema": "parliament-zero-challenge-admissibility-v1", "fallback_admissible_both_rows_and_roles": True,
            "source_sha256": before, "source_changes": {name: [before[name], after[name]] for name in before if before[name] != after[name]},
            "checker_sha256": digest(Path(__file__)), "rows": rows, "source_references": references,
            "loaded_leaf_listing_source": {"path": str(Path(ledger.__file__).resolve()),
                                           "sha256": digest(Path(ledger.__file__).resolve())},
            "scope": "Membership of 0^256 in each actual row's grinding/decode/opening admissibility set; source correspondence is a reviewed mathematical model, not a compiled-code proof",
            "counter_preimage_or_valid_proof_claim": False, "uniform_H5_lemma_proved": False,
            "simulator_distribution_proved": False, "complete_simulator_resource_bound": False,
            "independent_cryptographic_review": False, "profile_qualified": False}


def main() -> int:
    """Emit the narrow certificate; only an explicit new directory is written."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = certificate(args.root.resolve())
        if args.output:
            args.output.mkdir(parents=True, exist_ok=False)
            (args.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError) as error:
        print(json.dumps({"failure": str(error), "profile_qualified": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
