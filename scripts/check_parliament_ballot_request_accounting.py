#!/usr/bin/env python3
"""Check candidate ballot request stages against the nominal primitive ledger.

Python 3.11+ and the repository sources are required; no packages, environment
variables, builds or network access are needed. This read-only calculation
counts logical AES input blocks and Keccak permutations, not cycles or gates.
It validates only the request component of the conditional security ledger.
Source drift or failed arithmetic returns nonzero. --require-qualified always
fails: this check cannot supply missing primitive/reduction/resource premises.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = Path("scripts/check_parliament_ballot_resource_accounting.py")
INTERCEPT = 4096
SLOPE = Fraction(2_750_672 + 65_536, 740)
# A pin records a source review, not a proof automatically extracted from Rust.
REVIEWED_SOURCE_SHA256 = "24d191a973854c05337f9fe8ccfa571cc8cebda1d3de984630c12594f0f8d9a3"


def source_inventory(root: Path) -> dict[str, str]:
    """Hash the reviewed protocol/provider sources and imported count formulas."""
    paths = {MODEL_PATH.as_posix()}
    for directory in ("crates/iroha_parliament_ballot_proof/src",
                      "crates/iroha_zkp_vole/src", "vendor/aes/src"):
        paths.update(path.relative_to(root).as_posix()
                     for path in (root / directory).rglob("*.rs"))
    paths.add("crates/iroha_parliament_ballot_proof/examples/resource_contract/budget.rs")
    return {path: hashlib.sha256((root / path).read_bytes()).hexdigest()
            for path in sorted(paths)}


def inventory_digest(inventory: dict[str, str]) -> str:
    """Give the ordered source scope a deterministic identity."""
    return hashlib.sha256(json.dumps(inventory, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def load_model(root: Path):
    """Load only the already reviewed pure count functions, without its CLI."""
    spec = importlib.util.spec_from_file_location("request_count_model", root / MODEL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rational(value: Fraction | int) -> dict[str, int]:
    """Serialize an exact rational; no floating-point decision is used."""
    value = Fraction(value)
    return {"numerator": value.numerator, "denominator": value.denominator}


def stage(name: str, work: int, queries: int) -> dict:
    """Evaluate the coupled request inequality at a source-derived stage bound."""
    if work < 0 or queries < 0:
        raise ValueError("negative resource count")
    allowance = INTERCEPT + SLOPE * queries
    return {"stage": name, "logical_primitive_upper_bound": work,
            "charged_backend_queries": queries, "allowance": rational(allowance),
            "margin": rational(allowance - work), "inequality_holds": work <= allowance}


def request_case(model, row: str, role: str, seats: int, tables: dict) -> dict:
    """Bound normal-return branches; fixed invariant failures are outside scope.

    In the reviewed cold entry, statement rejection occurs before H_mu. Once
    bounded statement validation succeeds, remaining preparation cannot reject
    its fields. The strict backend codec rejects before reconstruction. For
    codec-valid bytes, fixed row/length/table/relation invariants leave only the
    final challenge comparison as a normal adversarial-data-dependent refusal.
    This control-flow claim is source-reviewed, not inferred by this function.
    """
    cold = model.statement_schedule(role, seats, tables, True)
    ordinary = model.statement_schedule(role, seats, tables, False)
    hashes = cold["hashes"]
    cold_cost = sum(item["keccak_f1600"] for item in hashes.values())
    ordinary_cost = sum(item["keccak_f1600"] for item in ordinary["hashes"].values())
    one_profile = sum(item["keccak_f1600"] for key, item in hashes.items()
                      if key.startswith("profile_")) // 2
    rejection_hash = "body_digest_sha3_512" if role == "registration" else "list_sha3_512"
    # Decode constructs/hashes one body or one list before checking its digest.
    rejection_cost = one_profile + (hashes[rejection_hash]["keccak_f1600"]
                                   // hashes[rejection_hash]["calls"])
    backend = model.backend_schedule(row, role, seats, tables)
    aes = backend["prg"]["aes256_input_blocks_upper_bound"]
    backend_keccak = sum(item["keccak_f1600"] for item in backend["sponges"].values())
    # The backend model lists H0/H1/H4/challenges/H5. H_mu is in preparation.
    full_queries = 1 + sum(item["calls"] for item in backend["sponges"].values())
    stages = [stage("input_or_statement_rejection", rejection_cost, 0),
              stage("strict_proof_codec_rejection", cold_cost, 1),
              stage("codec_valid_completed_verification", aes + cold_cost + backend_keccak,
                    full_queries)]
    return {"row": row, "role": role, "seats": seats if role == "vote" else None,
            "cold_preparation_keccak": cold_cost,
            "ordinary_preparation_keccak": ordinary_cost,
            "cold_preparation_excluding_H_mu": cold_cost - hashes["message_shake256"]["keccak_f1600"],
            "ordinary_preparation_excluding_H_mu": ordinary_cost - ordinary["hashes"]["message_shake256"]["keccak_f1600"],
            "logical_aes_input_blocks_upper_bound": aes,
            "backend_keccak": backend_keccak,
            "stages": stages}


def report(root: Path = ROOT) -> dict:
    """Recompute both-role candidate bounds and a comparator scope countercheck."""
    sources = source_inventory(root)
    actual = inventory_digest(sources)
    base = {"schema": "parliament-request-primitive-accounting-v1",
            "source_sha256": sources, "source_manifest_sha256": actual,
            "accounting_artifact_sha256": {
                path: hashlib.sha256((root / path).read_bytes()).hexdigest()
                for path in ("scripts/check_parliament_ballot_request_accounting.py",
                             "scripts/tests/parliament_ballot_request_accounting_test.py")},
            "reviewed_source_manifest_sha256": REVIEWED_SOURCE_SHA256,
            "source_matched": actual == REVIEWED_SOURCE_SHA256,
            "candidate_request_component_checked": False,
            "complete_primitive_resource_bound": False,
            "complete_gate_or_memory_bound": False, "profile_qualified": False}
    if actual != REVIEWED_SOURCE_SHA256:
        return {**base, "failure": "reviewed request sources changed; re-review before repinning"}
    model = load_model(root)
    candidate_tables = model.table_inventory(root, "candidate")
    cases = [request_case(model, "candidate", "registration", 3, candidate_tables)]
    # Check every admitted roster size, not only the measurement sizes.
    votes = [request_case(model, "candidate", "vote", seats, candidate_tables)
             for seats in range(3, 1001)]
    cases += [votes[index - 3] for index in (3, 500, 1000)]
    checked = all(item["inequality_holds"] for case in cases[:1] + votes
                  for item in case["stages"])
    monotone = all(a["cold_preparation_keccak"] <= b["cold_preparation_keccak"]
                   for a, b in zip(votes, votes[1:]))
    comparator = request_case(model, "comparator", "vote", 1000,
                              model.table_inventory(root, "comparator"))
    comparator_covered = all(item["inequality_holds"] for item in comparator["stages"])
    return {**base, "candidate_request_component_checked": checked and monotone,
            "failure": None if checked and monotone else "candidate stage inequality failed",
            "request_intercept": INTERCEPT, "per_backend_query_slope": rational(SLOPE),
            "candidate_cases": cases, "candidate_vote_sizes_checked": len(votes),
            "candidate_vote_preparation_monotone": monotone,
            "pointwise_4096_preparation_bound_valid": False,
            "comparator_scope_countercheck": comparator,
            "candidate_coefficient_covers_comparator": comparator_covered,
            "interpretation": "W_request <= 4096 + C*q_backend; additive logical primitive units only",
            "excluded": ["runtime abort, cancellation and resource failures",
                         "provider key schedules, unused SIMD lanes and elementary-gate conversion",
                         "credential generation, simulator/final-comparison work and quantum reduction resources",
                         "production envelopes/ingress, preprocessing/advice and memory/coherent-access costs"]}


def main() -> int:
    """Print exact evidence; distinguish component success from qualification."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit deterministic JSON evidence")
    parser.add_argument("--require-qualified", action="store_true", help="fail closed on missing qualification")
    args = parser.parse_args()
    result = report()
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else
          f"Candidate request component: {result['candidate_request_component_checked']}; qualification: False")
    if not result["candidate_request_component_checked"]:
        return 1
    return 2 if args.require_qualified else 0


if __name__ == "__main__":
    raise SystemExit(main())
