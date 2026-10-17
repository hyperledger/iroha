#!/usr/bin/env python3
"""Model an exact reversible chronological oracle overlay, without QRAM.

This is a new circuit proposal, not the deployed backend or a full reduction.
The small-circuit interpreter validates basis permutations; real-size resources
are symbolic integers. No earlier frozen artifact is imported or modified.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

RECEIPT = "docs/validation/parliament_ballot_ideal_sampler_accounting/receipt.json"
REPORT = "docs/validation/parliament_ballot_ideal_sampler_accounting/report.json"
PINS = {
    RECEIPT: "65281fa88da41ce17e63265d0d6c04ad763427e9c8f79d1b74a9829f54bd74d1",
    REPORT: "32f13e842ac39f7f3c3d08ae2135a8ebdffd442acc776002e2229c36610ad043",
    "scripts/parliament_ballot_ideal_sampler_accounting.py": "b375d40189b1440404f48e124e7655fa54792c1f75289baad9978760f4c759d0",
    "specs/parliament_ballot_b6_ideal_sampler_accounting.md": "c022d1f76360dfe4bdd6934fe352d5d87e7b9f63df3828608230f759cb1e22c5",
    "specs/parliament_ballot_b6_ideal_public_sampler.md": "eeea377a3686fcd31c1c77b8ea576d6f72895789389ed4c2d99d9107a5f0ab74",
}
MAX_TRIALS = 1 << 20


def integer(value: int, low: int, high: int, name: str) -> int:
    """Refuse bool/coercions and out-of-contract integer inputs."""
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in [{low}, {high}]")
    return value


def sha(data: bytes) -> str:
    """Identify exact input bytes."""
    return hashlib.sha256(data).hexdigest()


def sources(root: Path) -> tuple[dict, dict]:
    """Verify frozen provenance before parsing it, then every retained source."""
    blobs = {p: (root / p).read_bytes() for p in PINS}
    if {p: sha(b) for p, b in blobs.items()} != PINS:
        raise ValueError("frozen sampler/accounting inputs changed; do not repin automatically")
    receipt = json.loads(blobs[RECEIPT])
    pinned = receipt["source_sha256_at_freeze"]
    if (len(pinned) != 61 or pinned != receipt["source_sha256_before"]
            or pinned != receipt["source_sha256_after"]):
        raise ValueError("inconsistent prior source custody")
    for prefix in ("crates/iroha_zkp_vole/src/", "crates/iroha_parliament_ballot_proof/src/"):
        actual = {p.relative_to(root).as_posix() for p in (root / prefix).rglob("*.rs")}
        if actual != {p for p in pinned if p.startswith(prefix)}:
            raise ValueError("reviewed Rust source membership changed")
    merged = dict(pinned)
    merged.update(PINS)
    current = {p: sha((root / p).read_bytes()) for p in sorted(merged)}
    if current != merged:
        raise ValueError("reviewed sampler source changed")
    return current, json.loads(blobs[REPORT])


def gate_counts(gates: list[tuple]) -> dict[str, int]:
    """Count the explicit instruction list; base XOR calls remain separate."""
    c = Counter(g[0] for g in gates)
    return {name: c[name] for name in ("x", "cx", "ccx", "oracle")}


def and_xor(controls: list[int], target: int, scratch: list[int]) -> list[tuple]:
    """XOR an AND into target with a clean ladder and restored scratch."""
    if len(set(controls + [target] + scratch)) != len(controls) + 1 + len(scratch):
        raise ValueError("gate wires alias")
    if not controls:
        return [("x", target)]
    if len(controls) == 1:
        return [("cx", controls[0], target)]
    if len(scratch) < len(controls) - 2:
        raise ValueError("insufficient clean AND scratch")
    if len(controls) == 2:
        return [("ccx", *controls, target)]
    forward = [("ccx", controls[0], controls[1], scratch[0])]
    for i in range(2, len(controls) - 1):
        forward.append(("ccx", scratch[i - 2], controls[i], scratch[i - 1]))
    return forward + [("ccx", scratch[len(controls) - 3], controls[-1], target)] + forward[::-1]


class Wires:
    """Allocate named finite toy wires; symbolic production bounds do not use it."""

    def __init__(self) -> None:
        self.size = 0

    def take(self, n: int) -> list[int]:
        """Reserve n distinct zero-initialized wire positions."""
        result = list(range(self.size, self.size + n))
        self.size += n
        return result


def toy_layout(capacity: int, key_bits: int, value_bits: int, extra_tail_bits: int = 0) -> dict:
    """Allocate only small test circuits; refuse accidentally enormous builds."""
    integer(capacity, 1, 8, "toy capacity")
    integer(key_bits, 1, 16, "toy key bits")
    integer(value_bits, 1, 8, "toy value bits")
    integer(extra_tail_bits, 0, 16, "toy full-query tail bits")
    w = Wires()
    slots = [(w.take(1)[0], w.take(key_bits), w.take(value_bits)) for _ in range(capacity)]
    query, tail = w.take(key_bits), w.take(extra_tail_bits)
    enable, output = w.take(1)[0], w.take(value_bits)
    counter_width = max(2, capacity.bit_length())
    counter, incoming = w.take(counter_width), w.take(key_bits + value_bits)
    persistent_end = w.size
    matches, prefixes = w.take(capacity), w.take(capacity + 1)
    hit, ladder, base = w.take(1)[0], w.take(key_bits), w.take(value_bits)
    lookup_work = list(range(persistent_end, w.size))
    append_flag, append_ladder = w.take(1)[0], w.take(counter_width - 2)
    return dict(capacity=capacity, k=key_bits, v=value_bits, slots=slots, query=query,
                full_query=query + tail, query_tail=tail,
                enable=enable, output=output, counter=counter, incoming=incoming,
                matches=matches, prefixes=prefixes, hit=hit, ladder=ladder, base=base,
                lookup_work=lookup_work, append_flag=append_flag,
                append_ladder=append_ladder, size=w.size)


def lookup_circuit(p: dict) -> list[tuple]:
    """Emit a fixed-address coherent newest-match scan, with complete uncompute."""
    equality = []
    for i, (active, key, _) in enumerate(p["slots"]):
        compare = [("cx", q, z) for q, z in zip(p["query"], key)]
        negate = [("x", z) for z in key]
        equality += compare + negate + and_xor(
            [p["enable"], active] + key, p["matches"][i], p["ladder"]
        ) + negate[::-1] + compare[::-1]
    prefixes = [("x", p["prefixes"][-1])]
    for i in reversed(range(p["capacity"])):
        e = p["matches"][i]
        prefixes += [("x", e), ("ccx", p["prefixes"][i + 1], e, p["prefixes"][i]), ("x", e)]
    route = []
    for i, (_, _, value) in enumerate(p["slots"]):
        hit = ("ccx", p["matches"][i], p["prefixes"][i + 1], p["hit"])
        route += [hit] + [("ccx", p["hit"], z, y) for z, y in zip(value, p["output"])] + [hit]
    base_call = ("oracle", tuple(p["full_query"]), tuple(p["base"]))
    miss = ("ccx", p["enable"], p["prefixes"][0], p["hit"])
    route += [base_call, miss] + [("ccx", p["hit"], z, y) for z, y in zip(p["base"], p["output"])] + [miss, base_call]
    return equality + prefixes + route + prefixes[::-1] + equality[::-1]


def append_circuit(p: dict) -> list[tuple]:
    """Emit scan-based append into a blank next slot, then increment its counter."""
    gates = []
    counter, flag, scratch = p["counter"], p["append_flag"], p["append_ladder"]
    for i, (active, key, value) in enumerate(p["slots"]):
        negate = [("x", wire) for j, wire in enumerate(counter) if not (i >> j) & 1]
        eq = negate + and_xor(counter, flag, scratch) + negate[::-1]
        gates += eq + [("ccx", flag, source, dest) for source, dest in zip(p["incoming"], key + value)]
        gates += [("cx", flag, active)] + eq[::-1]
    for j in reversed(range(1, len(counter))):
        gates += and_xor(counter[:j], counter[j], scratch[:max(0, j - 2)])
    return gates + [("x", counter[0])]


def simulate(gates: list[tuple], state: list[int], base) -> list[int]:
    """Evaluate basis permutations, including a fixed response-XOR base oracle."""
    if any(type(b) is not int or b not in (0, 1) for b in state):
        raise ValueError("basis state must contain exact bits")
    bits = state.copy()
    for gate in gates:
        op, *w = gate
        if op == "x":
            bits[w[0]] ^= 1
        elif op == "cx":
            bits[w[1]] ^= bits[w[0]]
        elif op == "ccx":
            bits[w[2]] ^= bits[w[0]] & bits[w[1]]
        elif op == "oracle":
            query, output = w
            answer = base(sum(bits[wire] << i for i, wire in enumerate(query)))
            integer(answer, 0, (1 << len(output)) - 1, "base response")
            for i, wire in enumerate(output):
                bits[wire] ^= (answer >> i) & 1
        else:
            raise ValueError("unknown circuit instruction")
    return bits


def resource_vector(capacity: int, key_bits: int, value_bits: int) -> dict:
    """Give derived gate/wire bounds for fixed-capacity lookup and append."""
    integer(capacity, 0, (1 << 64) * (MAX_TRIALS + 2), "capacity")
    integer(key_bits, 1, 1 << 32, "key bits")
    integer(value_bits, 1, 1 << 16, "value bits")
    n, k, v = capacity, key_bits, value_bits
    if n == 0:
        return {"capacity": 0, "lookup": {"x": 0, "cx": 0, "ccx": v, "oracle": 2,
                "elementary_one_two_qubit_gates": 5*v}, "append": None,
                "persistent_log_wires": 0, "append_counter_wires": 0,
                "lookup_clean_work_wires": v, "append_clean_work_wires": 0}
    d = max(2, n.bit_length())
    lookup = dict(x=4*k*n + 4*n + 2, cx=4*k*n, ccx=n*(4*k + 6 + v) + v + 2, oracle=2)
    append = dict(x_upper_bound=4*d*n + 1, cx=n + 1,
                  ccx=n*(4*d - 6 + k + v) + (d - 2)**2, oracle=0)
    lookup["elementary_one_two_qubit_gates"] = lookup["x"] + lookup["cx"] + 5*lookup["ccx"]
    append["elementary_one_two_qubit_gates_upper_bound"] = append["x_upper_bound"] + append["cx"] + 5*append["ccx"]
    return dict(capacity=n, key_bits=k, value_bits=v, lookup=lookup, append=append,
                persistent_log_wires=n*(1 + k + v), append_counter_wires=d,
                lookup_clean_work_wires=2*n + k + v + 2, append_clean_work_wires=d - 1,
                incoming_record_staging_wires=k + v)


def report(root: Path, requests: int, external_queries: int, length_bits: int) -> dict:
    """Bind the standalone overlay circuit envelope to the frozen sampler counts."""
    integer(requests, 0, 1 << 64, "request cap")
    integer(external_queries, 0, 1 << 64, "external-query cap")
    integer(length_bits, 1, 4096, "finite byte-length register width")
    before, accounting = sources(root)
    cases = accounting["cases"]
    key_bytes = max(c["programming"][name] for c in cases for name in
                    ("challenge_1_key_bytes", "challenge_2_key_bytes", "counter_key_bytes"))
    # Aggregated bytes conservatively bound every individual honest read.
    honest_length_bound = max(item["absorbed_bytes"] for c in cases
                              for item in c["ordinary_backend_oracle_reads"].values())
    if (1 << length_bits) <= max(key_bytes, honest_length_bound):
        raise ValueError("finite length register cannot cover the retained honest input envelope")
    if key_bytes != 215150 or len(cases) != 20:
        raise ValueError("frozen source-derived geometry changed")
    value_bits = 8*264
    capacity = requests*(MAX_TRIALS + 2)
    r = resource_vector(capacity, 8*key_bytes + length_bits, value_bits)
    queries = external_queries + requests*max(c["ordinary_backend_read_count"] for c in cases)
    writes = capacity
    lookup_gates = queries*r["lookup"]["elementary_one_two_qubit_gates"]
    append_gates = 0 if not writes else writes*r["append"]["elementary_one_two_qubit_gates_upper_bound"]
    after, _ = sources(root)
    if before != after:
        raise ValueError("source drift during circuit accounting")
    return dict(schema="parliament-oracle-log-circuit-draft-v1", request_cap=requests,
        external_query_cap=external_queries, length_bits=length_bits,
        finite_address_domain_premise=True, programmed_key_max_bytes=key_bytes,
        honest_read_length_envelope_bytes=honest_length_bound, circuit=r,
        lifetime=dict(overlay_lookups=queries, append_operations=writes,
            base_xor_oracle_calls=queries*r["lookup"]["oracle"],
            lookup_elementary_gates=lookup_gates, append_elementary_gates_upper_bound=append_gates,
            overlay_elementary_gates_upper_bound=lookup_gates + append_gates),
        source_sha256_before=before, source_sha256_after=after,
        exact_overlay_circuit_proposal=True, full_resource_vector=False,
        concrete_backend_gate_bound=False, actual_input_collision_bridge=False,
        primitive_advantage_assumed=False, independent_cryptographic_review=False,
        physical_verification_workspace_certificate=False, profile_qualified=False,
        production_gate_changed=False,
        exclusions=["base oracle implementation and its retained state", "all other simulator/reduction computation",
                    "actual-input primitive bridge and quantitative primitive advantages", "gate routing/error correction and physical memory",
                    "preparation of the supplied canonical framed write input", "initialization cost of zero wires is reported as wire inventory, not gates"])


def main() -> int:
    """Emit a reviewable conditional report; always refuse qualification."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--request-cap", type=int, required=True)
    p.add_argument("--external-query-cap", type=int, required=True)
    p.add_argument("--length-bits", type=int, required=True)
    p.add_argument("--output", type=Path)
    p.add_argument("--require-qualified", action="store_true")
    args = p.parse_args()
    try:
        r = report(args.root.resolve(), args.request_cap, args.external_query_cap, args.length_bits)
        rendered = json.dumps(r, sort_keys=True, indent=2) + "\n"
        if args.output:
            with args.output.open("x") as out:
                out.write(rendered)
        print(rendered, end="")
        return 2 if args.require_qualified else 0
    except (OSError, ValueError, KeyError) as error:
        p.exit(2, str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
