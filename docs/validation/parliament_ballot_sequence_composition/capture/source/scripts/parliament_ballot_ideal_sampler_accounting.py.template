#!/usr/bin/env python3
"""Account for the bounded IdealFrontierSim mathematical algorithm.

Python 3.11+, standard library only. This does not run a prover or a quantum
simulator. It checks a reviewed classical logical operation model, including
programming records and lifetime totals. Changed inputs refuse before loading
the existing reviewed arithmetic helper. --require-qualified always refuses.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import types

MODEL = "scripts/check_parliament_ballot_resource_accounting.py"
INPUT_DIGEST = "cb689c24e83fb9703a848c9ac83df66e5828b57a8efa5591bfb392d62267d7f8"
MODEL_DIGEST = "18a6fdd3f808f1b73d3e2e6c9903a0a069f1866c0af04783eb03b0c21e7841f1"
MAX_TRIALS = 1 << 20
MAX_REQUESTS = 1 << 64
ROWS = {"candidate": (33, 8, 229, 704), "comparator": (22, 6, 225, 696)}
ROLES = {"registration": 35840, "vote": 53504}
FIXED_INPUTS = (MODEL, "specs/parliament_ballot_b6_ideal_public_sampler.md",
                "specs/parliament_ballot_b6_hidden_assignment_deletion.md",
                "specs/parliament_ballot_b6_hybrid_driver.md",
                "docs/validation/parliament_ballot_ideal_public_sampler/receipt.json")


def bounded(value: int, lower: int, upper: int, name: str) -> int:
    """Require a genuine bounded integer, refusing bool and float coercion."""
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"{name} must be an integer in [{lower}, {upper}]")
    return value


def digest(data: bytes) -> str:
    """Identify exact bytes without implying independent review."""
    return hashlib.sha256(data).hexdigest()


def inventory(root: Path) -> dict[str, str]:
    """Bind both source modules recursively and the frozen endpoint documents."""
    names = set(FIXED_INPUTS)
    for directory in ("crates/iroha_zkp_vole/src", "crates/iroha_parliament_ballot_proof/src"):
        names.update(path.relative_to(root).as_posix() for path in (root / directory).rglob("*.rs"))
    return {name: digest((root / name).read_bytes()) for name in sorted(names)}


def verify_sources(root: Path) -> dict[str, str]:
    """Fail closed on missing, added or changed reviewed source inputs."""
    observed = inventory(root)
    aggregate = digest(json.dumps(observed, sort_keys=True, separators=(",", ":")).encode())
    if aggregate != INPUT_DIGEST or observed.get(MODEL) != MODEL_DIGEST:
        raise ValueError("reviewed source inventory changed; do not automatically repin")
    return observed


def load_model(root: Path) -> types.ModuleType:
    """Hash helper bytes before executing those exact bytes; avoid import caches."""
    source = (root / MODEL).read_bytes()
    if digest(source) != MODEL_DIGEST:
        raise ValueError("reviewed formula helper changed before loading")
    module = types.ModuleType("ideal_sampler_reviewed_resource_model")
    module.__file__ = str(root / MODEL)
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def geometry(row: str) -> dict:
    """Derive actual interleaved full-tree dimensions from the reviewed row."""
    if row not in ROWS:
        raise ValueError("unsupported row")
    tau, grind, limit, gates = ROWS[row]
    short, long_count = divmod(256 - grind, tau)
    depths = [short + int(i < long_count) for i in range(tau)]
    sizes = [1 << depth for depth in depths]
    return {"row": row, "tau": tau, "grind": grind, "limit": limit, "gates": gates,
            "delta": 256 - grind, "depths": depths, "sizes": sizes,
            "long_count": long_count, "half": 1 << short, "leaves": sum(sizes)}


def selected_opening(shape: dict, challenge: bytes) -> dict:
    """Decode/mark an admissible opening and independently count unmarked work."""
    if shape != geometry(shape.get("row", "")):
        raise ValueError("geometry facts were modified")
    if type(challenge) is not bytes or len(challenge) != 32:
        raise ValueError("challenge must be exactly 32 bytes")
    value = int.from_bytes(challenge, "little")
    if value >> shape["delta"]:
        raise ValueError("nonzero grinding bits")
    hidden, offset = [], 0
    for depth in shape["depths"]:
        hidden.append((value >> offset) & ((1 << depth) - 1))
        offset += depth
    leaves, tau, half = shape["leaves"], shape["tau"], shape["half"]
    selected = [leaves - 1 + (tau * index + vector if index < half else
                tau * half + shape["long_count"] * (index - half) + vector)
                for vector, index in enumerate(hidden)]
    marked = set()
    for node in selected:
        while node:
            marked.add(node)
            node = (node - 1) // 2
        marked.add(0)
    frontier = [2 * node + 1 + int(2 * node + 1 in marked)
                for node in range(leaves - 2, -1, -1)
                if (2 * node + 1 in marked) != (2 * node + 2 in marked)]
    r = len(frontier)
    if not 1 <= r <= shape["limit"]:
        raise ValueError("selected opening exceeds canonical frontier threshold")
    unmarked = sum(node not in marked for node in range(leaves - 1))
    if unmarked != leaves - tau - r or len(marked) != r + 2 * tau - 1:
        raise ValueError("independent marked-tree identity failed")
    return {"challenge_hex": challenge.hex(), "hidden": hidden,
            "frontier_nodes": frontier, "r": r, "unmarked_internal": unmarked}


def schedule(primary: int, auxiliary: int, outcome: str) -> dict:
    """Validate a conditional run-count contract, not an observed random tape.

    The caller assumes previous trials rejected and the chosen trial succeeded.
    At most M auxiliary draws are used; fallback requires all M to reject.
    """
    bounded(primary, 1, MAX_TRIALS, "primary trials")
    bounded(auxiliary, 0, MAX_TRIALS, "auxiliary trials")
    if outcome == "success":
        valid = auxiliary == 0
    elif outcome == "exhausted_aux_success":
        valid = primary == MAX_TRIALS and auxiliary >= 1
    elif outcome == "exhausted_fallback":
        valid = primary == MAX_TRIALS and auxiliary == MAX_TRIALS
    else:
        valid = False
    if not valid:
        raise ValueError("inconsistent bounded schedule outcome/counts")
    return {"primary": primary, "auxiliary": auxiliary, "outcome": outcome,
            "trials": primary + auxiliary, "programmed_counter_writes": primary,
            "ordinary_counter_hash_reads": 0, "auxiliary_writes": 0,
            "returns_proof": outcome == "success", "observed_execution": False}


def byte_vector(parts: dict[str, int]) -> dict:
    """Keep named logical payloads and their sum, not an allocation claim."""
    if any(type(value) is not int or value < 0 for value in parts.values()):
        raise ValueError("invalid payload count")
    return {"parts": parts, "total": sum(parts.values())}


def scan_log(entries: list[tuple[bytes, bytes]], query: bytes) -> dict:
    """Model a classical newest-match scan; never price it as a quantum circuit.

    This finite control preserves old higher counter records when a later
    request overwrites only a shorter prefix of the same counter family.
    """
    if type(query) is not bytes or any(type(key) is not bytes or type(value) is not bytes
                                      for key, value in entries):
        raise ValueError("logical log keys and values must be bytes")
    inspections, comparisons = 0, 0
    for key, value in reversed(entries):
        inspections += 1
        if len(key) != len(query):
            continue
        equal = True
        for left, right in zip(key, query):
            comparisons += 1
            if left != right:
                equal = False
                break
        if equal:
            return {"value": value, "record_inspections": inspections, "key_byte_comparisons": comparisons}
    return {"value": None, "record_inspections": inspections, "key_byte_comparisons": comparisons}


def run_vector(model: types.ModuleType, root: Path, row: str, role: str,
               seats: int, selected: dict, plan: dict) -> dict:
    """Compose one valid request's arithmetic, query, programming and payload work."""
    if role not in ROLES:
        raise ValueError("unsupported role")
    bounded(seats, 3, 1000, "seats")
    shape = geometry(row)
    checked = selected_opening(shape, bytes.fromhex(selected["challenge_hex"]))
    if checked != selected:
        raise ValueError("opening facts were modified")
    validated_plan = schedule(plan["primary"], plan["auxiliary"], plan["outcome"])
    if validated_plan != plan:
        raise ValueError("schedule facts were modified")
    if plan["outcome"] == "exhausted_fallback" and selected["challenge_hex"] != "00" * 32:
        raise ValueError("the bounded fallback is the frozen all-zero challenge")
    ell, tau, gates = ROLES[role], shape["tau"], shape["gates"]
    e, r, n, u = ell // 8, selected["r"], shape["leaves"] - tau, selected["unmarked_internal"]
    width = (ell + 10 * max(shape["depths"]) + 7) // 8
    tables = model.table_inventory(root, row)
    old = model.backend_schedule(row, role, seats, tables)
    front = model.statement_schedule(role, seats, tables, False)
    ordinary = {name: value for name, value in old["sponges"].items() if not name.startswith("challenge_")}
    # Concrete frontend hashes have their own cost; only H_mu is a backend oracle.
    concrete_front = {name: value for name, value in front["hashes"].items() if name != "message_shake256"}
    ordinary["H_mu"] = front["hashes"]["message_shake256"]
    key1 = 254 + (tau - 1) * e + 10 * ((gates + 7) // 8)
    key2 = 598 + e
    a, b = plan["primary"], plan["auxiliary"]
    records = byte_vector({"challenge_1_key_and_value": key1 + 264,
                           "challenge_2_key_and_value": key2 + 104,
                           "primary_counter_keys_and_values": a * (410 + 32)})
    random = byte_vector({"schedule_values": 32 * (a + b), "frontier_keys": 32 * r,
                          "selected_commitments": 112 * tau, "corrections_and_d": tau * e,
                          "gate_corrections": 10 * ((gates + 7) // 8),
                          "iv_pre_salt_challenges_responses": 736})
    primitive = {"AES256_key_constructions": u + 2 * n,
                 "AES256_blocks": 4 * u + (9 + (width + 15) // 16) * n,
                 "PRG_output_bytes": 64 * u + (144 + width) * n,
                 "PRG_encrypt_batch_calls": u + (2 + (width + 127) // 128) * n}
    if primitive["AES256_blocks"] > old["prg"]["aes256_input_blocks_upper_bound"]:
        raise ValueError("source verifier PRG upper-bound crosscheck failed")
    loops = dict(old["bounded_loops"])
    # No raw-proof decoder or final challenge comparison runs in this simulator.
    loops.pop("final_challenge_byte_comparisons_upper_bound")
    loops.update({"decode_challenge_bit_tests": 2 * 256,
                  "mark_hidden_parent_visits": 2 * (shape["leaves"] - 1),
                  "revealed_node_parent_visits": 2 * (shape["leaves"] - 1),
                  "opening_padding_byte_tests_upper_bound": 32 * (shape["limit"] - r),
                  "correction_byte_xors_upper_bound": e * sum(index.bit_count() for index in selected["hidden"][1:]),
                  "selected_pattern_flag_initializations": 2 * (2 * shape["leaves"] - 1),
                  "selected_pattern_range_checks": 2 * tau,
                  "selected_pattern_leaf_marks": 2 * tau,
                  "opening_padding_byte_writes": 32 * (shape["limit"] - r)})
    trials = a + b
    trial_work = {"random_bytes": 32 * trials, "decode_bit_tests_upper_bound": 256 * trials,
                  "flag_initializations_upper_bound": (2 * shape["leaves"] - 1) * trials,
                  "hidden_range_checks_upper_bound": tau * trials,
                  "selected_leaf_marks_upper_bound": tau * trials,
                  "parent_visits_upper_bound": (shape["leaves"] - 1) * trials}
    proof_bytes = sum(model.proof_layout(row, role).values())
    # Named mathematical storage slots. Sum is an intentionally conservative
    # all-live payload envelope; metadata, object layout and allocator are absent.
    payload = byte_vector({"primary_values": 32 * a, "auxiliary_current_and_selected": 64,
        "canonical_opening": 112 * tau + 32 * shape["limit"],
        "corrections_and_d": tau * e, "gate_corrections": 10 * ((gates + 7) // 8),
        "public_seed_challenge_response_fields": 736 + 64 + 16 + 32 + 128 + 32,
        "two_hidden_index_arrays_u16": 4 * tau,
        "two_mark_bitflags_as_bytes": 2 * (2 * shape["leaves"] - 1),
        "BAVC_node_keys": (2 * shape["leaves"] - 1) * 32,
        "revealed_seed_slots": 32 * shape["leaves"],
        "columns": shape["delta"] * width,
        "fold_scratch": (max(shape["depths"]) + 1) * width,
        "gate_heads_and_labels": (shape["delta"] + gates) * 32,
        "selector_shares_delta_gates_scratch": 32 + 320 + 64 + 10 * ((gates + 63) // 64) * 8 + 2 * ((gates + 63) // 64) * 8,
        "q_masks_and_tag_scratch": 320 + 64,
        "lifted_columns": 256 * width, "Q_rows": ell * 32,
        "returned_proof": proof_bytes if plan["returns_proof"] else 0})
    fields = dict(old["arithmetic"])
    return {"row": row, "role": role, "seats": seats, "selected_opening": selected,
            "schedule": plan, "ell_hat_bits": ell + 10 * max(shape["depths"]),
            "random_draw_bytes": random, "primitive_work": primitive,
            "ordinary_backend_oracle_reads": ordinary,
            "ordinary_backend_read_count": sum(item["calls"] for item in ordinary.values()),
            "concrete_public_preparation_hashes": concrete_front,
            "concrete_public_preparation_keccak": sum(item["keccak_f1600"] for item in concrete_front.values()),
            "oracle_keccak_equivalent_not_added_to_ideal_query_cost": sum(item["keccak_f1600"] for item in ordinary.values()),
            "programming": {"write_count": a + 2, "record_payload_bytes": records,
                            "log_key_bytes": key1 + key2 + a * 410,
                            "log_value_bytes": 264 + 104 + a * 32,
                            "challenge_1_key_bytes": key1, "challenge_2_key_bytes": key2,
                            "counter_key_bytes": 410, "ordinary_challenge_reads": 0,
                            "auxiliary_writes": 0, "append_log_allows_repeated_addresses": True},
            "source_arithmetic_upper_bounds": fields, "relation_operation_upper_bounds": old["relation"],
            "reconstruction_loop_work": loops, "search_loop_upper_bounds": trial_work,
            "named_request_payload_envelope_bytes": payload,
            "additional_logical_relation_storage": {"verifier_key_values": 3840 + (seats if role == "vote" else 0),
                                                    "relation_usize_indices": 1600,
                                                    "other_fixed_field_scratch": "excluded from named byte payload"},
            "proof_serialization": {"proof_bytes": proof_bytes if plan["returns_proof"] else 0,
                                    "field_length_checks": 9 if plan["returns_proof"] else 0},
            "table_inventory": tables}


def lifetime(cases: list[dict], requests: int, external_queries: int) -> dict:
    """Bound any sequential mixture, without inferring request count from Q."""
    bounded(requests, 0, MAX_REQUESTS, "request cap")
    bounded(external_queries, 0, 1 << 64, "external query cap")
    if not cases:
        raise ValueError("at least one reviewed case is required")
    def maximum(path: tuple[str, ...]) -> int:
        values = []
        for case in cases:
            value = case
            for key in path:
                value = value[key]
            values.append(value)
        return max(values)
    parts = {"AES256_blocks": maximum(("primitive_work", "AES256_blocks")),
             "AES256_key_constructions": maximum(("primitive_work", "AES256_key_constructions")),
             "random_draw_bytes": maximum(("random_draw_bytes", "total")),
             "ordinary_backend_reads": maximum(("ordinary_backend_read_count",)),
             "programming_writes": maximum(("programming", "write_count")),
             "persistent_programming_key_bytes": maximum(("programming", "log_key_bytes")),
             "persistent_programming_record_payload_bytes": maximum(("programming", "record_payload_bytes", "total")),
             "search_parent_visits": maximum(("search_loop_upper_bounds", "parent_visits_upper_bound"))}
    return {"request_cap": requests, "external_query_cap": external_queries,
            "scope": "componentwise envelope of listed cases; not all admissible openings",
            "sequential_requests": True, "per_request_maxima": parts,
            "totals": {name: requests * value for name, value in parts.items()},
            "combined_backend_query_upper_bound": external_queries + requests * parts["ordinary_backend_reads"],
            "programming_log_record_inspections_per_classical_external_query_upper_bound": requests * parts["programming_writes"],
            "classical_external_log_record_inspections_upper_bound": external_queries * requests * parts["programming_writes"],
            "classical_external_log_key_byte_comparisons_upper_bound": external_queries * requests * parts["persistent_programming_key_bytes"],
            "source_arithmetic_totals_upper_bound": {
                name: requests * maximum(("source_arithmetic_upper_bounds", name))
                for name in cases[0]["source_arithmetic_upper_bounds"]},
            "reconstruction_loop_totals_upper_bound": {
                name: requests * maximum(("reconstruction_loop_work", name))
                for name in cases[0]["reconstruction_loop_work"]},
            "search_loop_totals_upper_bound": {
                name: requests * maximum(("search_loop_upper_bounds", name))
                for name in cases[0]["search_loop_upper_bounds"]},
            "concrete_public_preparation_keccak_upper_bound": requests * maximum(("concrete_public_preparation_keccak",)),
            "request_payload_bytes_not_multiplied_by_lifetime": maximum(("named_request_payload_envelope_bytes", "total")) if requests else 0,
            "base_oracle_adversary_state_and_log_metadata_bytes": None,
            "programming_log_starts_empty": True,
            "quantum_lookup_gate_cost": None}


def report(root: Path, requests: int = 1, external_queries: int = 0) -> dict:
    """Produce checked cases and an all-opening envelope with no security adoption."""
    bounded(requests, 0, MAX_REQUESTS, "request cap")
    bounded(external_queries, 0, 1 << 64, "external query cap")
    before = verify_sources(root)
    model = load_model(root)
    cases = []
    plans = [schedule(1, 0, "success"), schedule(MAX_TRIALS, 0, "success"),
             schedule(MAX_TRIALS, 1, "exhausted_aux_success"),
             schedule(MAX_TRIALS, MAX_TRIALS, "exhausted_aux_success"),
             schedule(MAX_TRIALS, MAX_TRIALS, "exhausted_fallback")]
    for row in ROWS:
        shape = geometry(row)
        selected = selected_opening(shape, bytes(32))
        for role in ROLES:
            for plan in plans:
                cases.append(run_vector(model, root, row, role, 1000, selected, plan))
    all_openings = []
    for row in ROWS:
        shape = geometry(row)
        for role in ROLES:
            # Any admissible opening has 1 <= r <= T_open. Use separate extrema:
            # they need not occur together, but bound each resource monotonically.
            case = next(item for item in cases if item["row"] == row and item["role"] == role
                        and item["schedule"]["outcome"] == "exhausted_fallback")
            clone = json.loads(json.dumps(case))
            r = case["selected_opening"]["r"]
            clone["primitive_work"]["AES256_blocks"] += 4 * (r - 1)
            clone["primitive_work"]["AES256_key_constructions"] += r - 1
            clone["random_draw_bytes"]["total"] += 32 * (shape["limit"] - r)
            clone["reconstruction_loop_work"]["correction_byte_xors_upper_bound"] = (
                shape["delta"] - shape["depths"][0]) * (ROLES[role] // 8)
            clone["reconstruction_loop_work"]["opening_padding_byte_tests_upper_bound"] = 32 * (shape["limit"] - 1)
            clone["reconstruction_loop_work"]["opening_padding_byte_writes"] = 32 * (shape["limit"] - 1)
            clone["named_request_payload_envelope_bytes"]["total"] += sum(model.proof_layout(row, role).values())
            all_openings.append(clone)
    total = lifetime(all_openings, requests, external_queries)
    total["scope"] = "all supported valid requests, both roles/rows, S<=1000, any admissible opening and bounded schedule; independent componentwise extrema"
    total["request_payload_bytes_not_multiplied_by_lifetime"] = (max(
        case["named_request_payload_envelope_bytes"]["total"] for case in all_openings) if requests else 0)
    after = verify_sources(root)
    if after != before:
        raise ValueError("source changed during accounting")
    return {"schema": "parliament-ideal-frontier-simulator-accounting-v1",
            "source_sha256_before": before, "source_sha256_after": after,
            "source_manifest_sha256": INPUT_DIGEST, "loaded_model_sha256": MODEL_DIGEST,
            "source_unchanged": True, "checked_logical_accounting": True,
            "cases": cases, "all_opening_lifetime_envelope": total,
            "actual_simulator_execution": False, "complete_resource_vector": False,
            "compiled_memory_or_allocator_bound": False, "quantum_gate_bound": False,
            "primitive_advantage_assumed": False, "actual_input_collision_bridge": False,
            "independent_cryptographic_review": False, "profile_qualified": False,
            "production_gate_changed": False,
            "exclusions": ["Entry/reduction adversaries, final comparison and all hybrid multiplicities",
                "Quantum oracle programming/coherent lookup and adversary/base-oracle state",
                "Actual-input collisions and primitive advantage hypotheses",
                "Full byte-copy/zeroization/validation, RNG implementation, key-setup and elementary-gate pricing",
                "Other fixed field scratch and logical metadata are outside the named byte-payload inventory",
                "Compiled layout, allocator, stack, process peak, concurrency and OS faults",
                "Unbounded optional public preimages, application witness generation and live deployment"]}


def main(argv: list[str] | None = None) -> int:
    """Emit new evidence only; refuse source drift and every qualification request."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--requests", type=int, default=1)
    parser.add_argument("--external-queries", type=int, default=0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = report(args.root.resolve(), args.requests, args.external_queries)
    except (ValueError, OSError) as error:
        print(json.dumps({"checked_logical_accounting": False, "profile_qualified": False,
                          "failure": str(error)}, sort_keys=True))
        return 1
    content = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
        (args.output / "report.json").write_text(content)
    else:
        print(content, end="")
    return 2 if args.require_qualified else 0


if __name__ == "__main__":
    raise SystemExit(main())
