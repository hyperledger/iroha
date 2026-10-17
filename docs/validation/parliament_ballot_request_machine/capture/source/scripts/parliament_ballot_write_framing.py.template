#!/usr/bin/env python3
"""Price reversible packing of supplied IdealFrontierSim challenge records.

This source-bound component prepares the existing oracle-log staging register,
then unprepares it after append. It does not generate transcript fields, supply
an actual runtime quantum API, or complete any security/resource qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import types

CIRCUIT = "scripts/parliament_ballot_oracle_log_circuit.py"
ACCOUNTING = "docs/validation/parliament_ballot_ideal_sampler_accounting/report.json"
RECEIPT = "docs/validation/parliament_ballot_oracle_log_circuit/receipt.json"
PINS = {
    CIRCUIT: "d045f66581f7a50bcb4e696b0346a192724f5d0858a21c23343bb35478d5c558",
    ACCOUNTING: "32f13e842ac39f7f3c3d08ae2135a8ebdffd442acc776002e2229c36610ad043",
    RECEIPT: "216843ae4c5c60d9aeca12f23fc7ec48e84b87dff35c0a68e354dedc5fc129c4",
    "docs/validation/parliament_ballot_oracle_log_circuit/report.json": "dad7ce8147caa2de70adcfabfb03911e396fd21b76828fa2dce0ab6e9b2b735b",
    "specs/parliament_ballot_b6_oracle_log_circuit.md": "de33b603bfc281238b348f082a2316a645f1d236894e7837ee95078ddbc1d673",
}
PREFIX = b"PARL/FAEST/v1"
MAX_TRIALS = 1 << 20
MAX_KEY_BYTES = 215150
VALUE_BYTES = 264
ROWS = {"candidate": (33, 704), "comparator": (22, 696)}
ROLES = {"registration": 4480, "vote": 6688}


def integer(value: int, minimum: int, maximum: int, name: str) -> int:
    """Refuse coercions and out-of-contract dimensions."""
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def sha(data: bytes) -> str:
    """Identify exact reviewed bytes."""
    return hashlib.sha256(data).hexdigest()


def sources(root: Path) -> tuple[dict[str, str], dict]:
    """Check frozen identities before parsing metadata and all retained sources."""
    blobs = {name: (root / name).read_bytes() for name in PINS}
    if {name: sha(data) for name, data in blobs.items()} != PINS:
        raise ValueError("frozen inputs changed; do not repin automatically")
    receipt = json.loads(blobs[RECEIPT])
    prior = receipt["source_sha256_at_freeze"]
    if (len(prior) != 65 or prior != receipt["source_sha256_before"]
            or prior != receipt["source_sha256_after"]):
        raise ValueError("inconsistent prior source custody")
    merged = dict(prior)
    for name, value in PINS.items():
        if name in merged and merged[name] != value:
            raise ValueError("conflicting source identity")
        merged[name] = value
    for prefix in ("crates/iroha_zkp_vole/src/", "crates/iroha_parliament_ballot_proof/src/"):
        actual = {path.relative_to(root).as_posix() for path in (root / prefix).rglob("*.rs")}
        if actual != {name for name in merged if name.startswith(prefix)}:
            raise ValueError("reviewed Rust source membership changed")
    current = {name: sha((root / name).read_bytes()) for name in sorted(merged)}
    if current != merged:
        raise ValueError("reviewed framing source changed")
    return current, json.loads(blobs[ACCOUNTING])


def load_circuit(root: Path) -> types.ModuleType:
    """Load exact pinned append implementation bytes, never an import cache."""
    data = (root / CIRCUIT).read_bytes()
    if sha(data) != PINS[CIRCUIT]:
        raise ValueError("append circuit helper changed")
    module = types.ModuleType("reviewed_oracle_log_circuit")
    module.__file__ = str(root / CIRCUIT)
    exec(compile(data, module.__file__, "exec"), module.__dict__)
    return module


def shape(row: str, role: str, challenge: int) -> dict:
    """Define actual source transcript order from already available field bytes.

    Namespace hashing and generation of every supplied field are outside this
    interface. The counter input's 32 wires denote its unsigned value; byte
    encoding is little-endian by the explicit low-bit-first wire convention.
    """
    if row not in ROWS or role not in ROLES:
        raise ValueError("unsupported row or role")
    integer(challenge, 1, 3, "challenge")
    tau, gates = ROWS[row]
    e = ROLES[role]
    fields = [("namespace_digest", 64)]
    if challenge == 1:
        fields += [("mu", 64), ("commitment", 64), ("corrections", (tau-1)*e),
                   ("mult_corrections", 10*((gates+7)//8)), ("iv_pre", 16), ("salt", 32)]
        value_bytes = 264
    elif challenge == 2:
        fields += [("challenge_1", 264), ("u_tilde", 128), ("d_tilde", 128), ("masked_witness", e)]
        value_bytes = 104
    else:
        fields += [("challenge_2", 104), ("a0", 32), ("coefficients", 192), ("counter_u32_le", 4)]
        value_bytes = 32
    return {"row": row, "role": role, "challenge": challenge,
            "fields": fields, "prefix": PREFIX, "domain": challenge+8,
            "key_bytes": len(PREFIX)+sum(size for _, size in fields)+1,
            "value_bytes": value_bytes}


def encode_record(plan: dict, fields: dict[str, bytes], value: bytes) -> tuple[bytes, bytes]:
    """Encode independent supplied byte registers; refuse missing/extra fields."""
    expected = dict(plan["fields"])
    if set(fields) != set(expected):
        raise ValueError("wrong field inventory")
    if any(type(fields[name]) is not bytes or len(fields[name]) != size for name, size in expected.items()):
        raise ValueError("wrong field encoding length")
    if type(value) is not bytes or len(value) != plan["value_bytes"]:
        raise ValueError("wrong programmed value length")
    return plan["prefix"] + b"".join(fields[name] for name, _ in plan["fields"]) + bytes([plan["domain"]]), value


def layout(plan: dict, length_bits: int, *, key_capacity: int = MAX_KEY_BYTES,
           value_capacity: int = VALUE_BYTES, source_offset: int = 0,
           staging_offset: int | None = None) -> dict:
    """Allocate explicit disjoint source wires and the existing padded staging.

    All bytes have low bit first; the leading length register is low bit first.
    No scratch is allocated. Source wire ownership is an interface premise.
    """
    integer(length_bits, 1, 4096, "length bits")
    integer(key_capacity, 1, MAX_KEY_BYTES, "key capacity bytes")
    integer(value_capacity, 1, VALUE_BYTES, "value capacity bytes")
    integer(source_offset, 0, 1 << 48, "source offset")
    if not 0 <= plan["domain"] <= 255 or type(plan["domain"]) is not int:
        raise ValueError("invalid domain byte")
    if type(plan["prefix"]) is not bytes:
        raise ValueError("invalid constant prefix")
    names = [name for name, _ in plan["fields"]]
    if len(set(names)) != len(names) or "value" in names:
        raise ValueError("duplicate source field")
    for name, size in plan["fields"]:
        if not isinstance(name, str) or not name:
            raise ValueError("invalid source field name")
        integer(size, 1, MAX_KEY_BYTES, "field byte length")
    computed_key = len(plan["prefix"])+sum(size for _, size in plan["fields"])+1
    if plan["key_bytes"] != computed_key or not computed_key <= key_capacity:
        raise ValueError("key geometry mismatch")
    integer(plan["value_bytes"], 1, value_capacity, "value byte length")
    if plan["key_bytes"] >= 1 << length_bits:
        raise ValueError("length register cannot represent full key length")
    inputs = {}
    cursor = source_offset
    for name, size in plan["fields"] + [("value", plan["value_bytes"])]:
        inputs[name] = (cursor, 8*size)
        cursor += 8*size
    source_end = cursor
    if staging_offset is None:
        staging_offset = cursor
    integer(staging_offset, 0, 1 << 48, "staging offset")
    stage_width = length_bits+8*(key_capacity+value_capacity)
    if not (staging_offset+stage_width <= source_offset or source_end <= staging_offset):
        raise ValueError("source/staging wire alias")
    return {"plan": plan, "length_bits": length_bits, "key_capacity": key_capacity,
            "value_capacity": value_capacity, "inputs": inputs,
            "source_start": source_offset, "source_end": source_end,
            "staging_start": staging_offset, "staging_end": staging_offset+stage_width,
            "staging_wires_reused": stage_width, "additional_clean_work_wires": 0}


def require_disjoint_append(p: dict, append: dict) -> None:
    """Check a finite append wiring before composing the two reviewed circuits.

    Source fields are separate from log slots, the append position counter and
    its work bits. The supplied transcript trial counter is a different register.
    This validates public wire indices, never the secret values on those wires.
    """
    incoming = list(range(p["staging_start"], p["staging_end"]))
    if append["incoming"] != incoming:
        raise ValueError("append incoming wires must be exactly the shared staging")
    other = list(append["counter"])+[append["append_flag"]]+list(append["append_ladder"])
    key_width = p["length_bits"]+8*p["key_capacity"]
    for active, key, value in append["slots"]:
        if len(key) != key_width or len(value) != 8*p["value_capacity"]:
            raise ValueError("append record shape differs from padded staging")
        other += [active]+list(key)+list(value)
    all_append = incoming+other
    if (any(type(wire) is not int or wire < 0 for wire in all_append)
            or len(set(all_append)) != len(all_append)):
        raise ValueError("aliased or invalid append wire")
    if any(p["source_start"] <= wire < p["source_end"] for wire in all_append):
        raise ValueError("source wire aliases append log/counter/work")


def scatter(p: dict, *, inverse: bool = False):
    """Emit exact X/CNOT preparation, or its inverse, without runtime addressing.

    Targets are distinct staging bits, source controls are disjoint and never
    modified. The gates commute, so the inverse is exactly the same gate stream.
    Padding wires have no gates and remain zero when initially zero.
    """
    if type(inverse) is not bool:
        raise ValueError("inverse must be bool")
    plan, start, b = p["plan"], p["staging_start"], p["length_bits"]
    for bit in range(b):
        if plan["key_bytes"] >> bit & 1:
            yield ("x", start+bit)
    cursor = start+b
    for byte in plan["prefix"]:
        for bit in range(8):
            if byte >> bit & 1:
                yield ("x", cursor+bit)
        cursor += 8
    for name, _ in plan["fields"]:
        source, width = p["inputs"][name]
        for bit in range(width):
            yield ("cx", source+bit, cursor+bit)
        cursor += width
    for bit in range(8):
        if plan["domain"] >> bit & 1:
            yield ("x", cursor+bit)
    source, width = p["inputs"]["value"]
    target = start+b+8*p["key_capacity"]
    for bit in range(width):
        yield ("cx", source+bit, target+bit)


def framing_counts(plan: dict, length_bits: int) -> dict:
    """Count both scatter and inverse exactly, independently of field values."""
    p = layout(plan, length_bits)
    x = 2*(plan["key_bytes"].bit_count()+sum(byte.bit_count() for byte in plan["prefix"])+plan["domain"].bit_count())
    cx = 16*(sum(size for _, size in plan["fields"])+plan["value_bytes"])
    upper = 2*(length_bits+8*(plan["key_bytes"]+plan["value_bytes"]))
    assert x+cx <= upper
    return {"x_exact": x, "cnot_exact": cx, "toffoli_exact": 0,
            "additional_base_oracle_calls": 0, "elementary_gates_exact": x+cx,
            "elementary_gates_simple_upper_bound": upper,
            "existing_staging_wires_reused": p["staging_wires_reused"],
            "additional_clean_work_wires": 0,
            "supplied_source_wires": p["source_end"]-p["source_start"]}


def schedule_counts(row: str, role: str, primary: int, auxiliary: int,
                    outcome: str, length_bits: int) -> dict:
    """Count every primary write, including exhaustion; auxiliary draws write none."""
    integer(primary, 1, MAX_TRIALS, "primary trials")
    integer(auxiliary, 0, MAX_TRIALS, "auxiliary trials")
    valid = ((outcome == "success" and auxiliary == 0)
             or (outcome == "exhausted_aux_success" and primary == MAX_TRIALS and auxiliary >= 1)
             or (outcome == "exhausted_fallback" and primary == MAX_TRIALS and auxiliary == MAX_TRIALS))
    if not valid:
        raise ValueError("invalid conditional schedule")
    counts = [framing_counts(shape(row, role, i), length_bits) for i in (1, 2, 3)]
    return {"row": row, "role": role, "primary": primary, "auxiliary": auxiliary,
            "outcome": outcome, "append_operations": primary+2, "auxiliary_writes": 0,
            "x_exact": counts[0]["x_exact"]+counts[1]["x_exact"]+primary*counts[2]["x_exact"],
            "cnot_exact": counts[0]["cnot_exact"]+counts[1]["cnot_exact"]+primary*counts[2]["cnot_exact"],
            "elementary_gates_exact": sum(c["elementary_gates_exact"] for c in counts[:2])+primary*counts[2]["elementary_gates_exact"],
            "observed_execution": False, "previous_trial_outcomes_assumed": True}


def report(root: Path, requests: int, length_bits: int) -> dict:
    """Bind framing costs to frozen source/schedule counts; keep missing totals open."""
    integer(requests, 0, 1 << 64, "request cap")
    before, accounting = sources(root)
    cases = accounting["cases"]
    frames, schedules = [], []
    for row in ROWS:
        for role in ROLES:
            original = [case for case in cases if case["row"] == row and case["role"] == role]
            if len(original) != 5:
                raise ValueError("frozen case inventory changed")
            for challenge, key_name in ((1, "challenge_1_key_bytes"), (2, "challenge_2_key_bytes"), (3, "counter_key_bytes")):
                plan = shape(row, role, challenge)
                if any(case["programming"][key_name] != plan["key_bytes"] for case in original):
                    raise ValueError("frame/source key dimension mismatch")
                frames.append({"row": row, "role": role, "challenge": challenge,
                               "key_bytes": plan["key_bytes"], "value_bytes": plan["value_bytes"],
                               "ordered_fields": plan["fields"], "constant_prefix_hex": PREFIX.hex(),
                               "trailing_domain_byte": plan["domain"], "counts": framing_counts(plan, length_bits)})
            for case in original:
                s = case["schedule"]
                schedules.append(schedule_counts(row, role, s["primary"], s["auxiliary"], s["outcome"], length_bits))
    max_gates = max(s["elementary_gates_exact"] for s in schedules)
    honest_read_envelope = max(item["absorbed_bytes"] for case in cases
                               for item in case["ordinary_backend_oracle_reads"].values())
    max_payload = max(c["programming"]["record_payload_bytes"]["total"] for c in cases)
    simple_upper = 2*requests*((MAX_TRIALS+2)*length_bits+8*max_payload)
    exact_envelope = requests*max_gates
    if max_payload != 463693396 or exact_envelope > simple_upper:
        raise ValueError("framing envelope inconsistent")
    after, _ = sources(root)
    if before != after:
        raise ValueError("input drift during accounting")
    return {"schema": "parliament-write-framing-v1", "request_cap": requests, "length_bits": length_bits,
            "frames": frames, "schedules": schedules,
            "lifetime": {"framing_elementary_gates_upper_bound": exact_envelope,
                         "per_request_max_exact_framing_gates": max_gates,
                         "simple_payload_derived_upper_bound": simple_upper,
                         "additional_base_oracle_calls": 0, "additional_clean_work_wires": 0,
                         "existing_staging_wires_reused": length_bits+8*(MAX_KEY_BYTES+VALUE_BYTES) if requests else 0,
                         "append_operations_upper_bound": requests*(MAX_TRIALS+2)},
            "source_sha256_before": before, "source_sha256_after": after,
            "explicit_supplied_canonical_field_register_boundary": True,
            "prior_combined_interface_honest_read_envelope_bytes": honest_read_envelope,
            "shared_length_width_satisfies_prior_honest_envelope": (1 << length_bits) > honest_read_envelope,
            "scope": "Scatter and inverse around the separately priced unchanged append circuit. Already generated classical transcript/value fields are supplied in registers disjoint from staging, log, append counter and scratch. Their computational-basis labels are preserved; coherent inputs may become entangled with the log, so unchanged reduced source state is not claimed. This is a proposed reversible interface, not execution of the Rust runtime as a unitary.",
            "exclusions": ["source field generation, validation and namespace digest computation", "source field selection/addressing, counter generation and schedule controller", "append/lookup gates already priced by the separate log circuit", "supplied source-register storage already belonging to the surrounding sampler", "adversary/full query/base-oracle storage and all other simulator/reduction work", "physical memory, routing/error correction and primitive advantages"],
            "full_resource_vector": False, "actual_input_collision_bridge": False, "primitive_advantage_assumed": False,
            "independent_cryptographic_review": False, "profile_qualified": False,
            "physical_verification_workspace_certificate": False, "production_gate_changed": False}


def main(argv: list[str] | None = None) -> int:
    """Emit separate deterministic evidence and always refuse qualification."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--request-cap", type=int, required=True)
    parser.add_argument("--length-bits", type=int, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args(argv)
    try:
        value = report(args.root.resolve(), args.request_cap, args.length_bits)
        encoded = json.dumps(value, indent=2, sort_keys=True)+"\n"
        if args.output:
            with args.output.open("x") as stream:
                stream.write(encoded)
        else:
            print(encoded, end="")
    except (ValueError, OSError) as error:
        parser.error(str(error))
    return 2 if args.require_qualified else 0


if __name__ == "__main__":
    raise SystemExit(main())
