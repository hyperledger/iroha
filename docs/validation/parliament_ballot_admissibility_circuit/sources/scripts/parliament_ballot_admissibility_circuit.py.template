#!/usr/bin/env python3
"""Price a clean reversible circuit for the ballot challenge predicate.

This implements the fixed-row grinding and opening-size predicate on supplied
challenge wires. It neither samples challenges nor implements the surrounding
bounded search, cryptographic reduction, or production ballot verification.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

MAX_TRIALS = 1 << 20
PINS = {
    "crates/iroha_zkp_vole/src/bavc.rs": "481b4c7027b46520e848a67d94a6dc7cdda312838e1769a93b9079260b8d4269",
    "crates/iroha_zkp_vole/src/params.rs": "41d18d1bf137496db8bd858bc291e48684c11122c03834828d54d3b6ae8cabba",
    "crates/iroha_zkp_vole/src/variant.rs": "50d8c414309f5ccc315181abefbdabe79ed092f0644dc72e04596c93c58059b9",
    "crates/iroha_parliament_ballot_proof/src/profile.rs": "9cc79a448f4199b748923b8b3e6a552fb9f0aa7980a1cb6d1d89746e8b79323d",
    "specs/parliament_ballot_b6_ideal_public_sampler.md": "eeea377a3686fcd31c1c77b8ea576d6f72895789389ed4c2d99d9107a5f0ab74",
}


def integer(value: int, low: int, high: int, name: str) -> int:
    """Reject implicit numeric coercions and out-of-contract dimensions."""
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in [{low}, {high}]")
    return value


@dataclass(frozen=True)
class Geometry:
    """Fixed public heap shape; smaller shapes exist only for circuit tests."""

    tau: int
    k: int
    tau1: int
    grinding_bits: int
    opening_limit: int

    def __post_init__(self) -> None:
        """Keep the emitter finite and every AND ladder at least two-wide."""
        integer(self.tau, 2, 64, "vectors")
        integer(self.k, 3, 12, "long depth")
        integer(self.tau1, 0, self.tau, "long vectors")
        integer(self.grinding_bits, 0, 256, "grinding bits")
        integer(self.leaves, 4, 61440, "leaves")
        integer(self.challenge_bits, 1, 256, "challenge bits")
        integer(self.opening_limit, 0, self.leaves - 1, "opening limit")

    @property
    def depths(self) -> tuple[int, ...]:
        """Source-ordered low-bit-first hidden-index widths."""
        return (self.k,) * self.tau1 + (self.k - 1,) * (self.tau - self.tau1)

    @property
    def leaves(self) -> int:
        """Total leaf count in the single interleaved heap."""
        return (self.tau + self.tau1) * (1 << (self.k - 1))

    @property
    def challenge_bits(self) -> int:
        """Index bits followed by the source's high grinding bits."""
        return sum(self.depths) + self.grinding_bits


def row(name: str) -> Geometry:
    """Return the two source-pinned rows, common to registration and vote."""
    if name == "candidate":
        return Geometry(33, 8, 17, 8, 229)
    if name == "comparator":
        return Geometry(22, 12, 8, 6, 225)
    raise ValueError("unsupported row")


def position(g: Geometry, vector: int, index: int) -> int:
    """Implement Shape::position, including the interleaved short half."""
    integer(vector, 0, g.tau - 1, "vector")
    integer(index, 0, (1 << g.depths[vector]) - 1, "index")
    half = 1 << (g.k - 1)
    if index < half:
        return g.leaves - 1 + g.tau * index + vector
    return g.leaves - 1 + g.tau * half + g.tau1 * (index - half) + vector


def layout(g: Geometry) -> dict:
    """Allocate explicit input/output and disjoint zero-initialized work wires."""
    if not isinstance(g, Geometry):
        raise ValueError("expected validated Geometry")
    d = (g.leaves - 1).bit_length()
    cursor = 0

    def take(n: int) -> list[int]:
        nonlocal cursor
        result = list(range(cursor, cursor + n))
        cursor += n
        return result

    challenge = take(g.challenge_bits)
    target = take(1)[0]
    start = cursor
    marks, counter = take(2 * g.leaves - 1), take(d)
    flag, scratch = take(1)[0], take(d + g.grinding_bits - 2)
    return dict(geometry=g, challenge=challenge, target=target, marks=marks,
                count=counter, flag=flag, scratch=scratch, size=cursor,
                clean_work_wires=cursor - start)


def and_xor(controls: list[int], target: int, scratch: list[int]) -> list[tuple]:
    """XOR a conjunction using a clean AND ladder, with no relative phases."""
    all_wires = controls + [target] + scratch
    if (any(type(w) is not int or w < 0 for w in all_wires)
            or len(set(all_wires)) != len(all_wires)):
        raise ValueError("invalid or aliased AND wires")
    if len(scratch) < max(0, len(controls) - 2):
        raise ValueError("insufficient clean AND scratch")
    if not controls:
        return [("x", target)]
    if len(controls) == 1:
        return [("cx", controls[0], target)]
    if len(controls) == 2:
        return [("ccx", *controls, target)]
    prefix = [("ccx", controls[0], controls[1], scratch[0])]
    for i in range(2, len(controls) - 1):
        prefix.append(("ccx", scratch[i - 2], controls[i], scratch[i - 1]))
    return prefix + [("ccx", scratch[len(controls) - 3], controls[-1], target)] + prefix[::-1]


def controlled_increment(counter: list[int], flag: int, scratch: list[int]) -> list[tuple]:
    """Increment a little-endian counter modulo its width iff flag is one."""
    if not counter:
        raise ValueError("empty counter")
    gates = []
    for j in reversed(range(len(counter))):
        gates += and_xor([flag] + counter[:j], counter[j], scratch)
    return gates


def compute_gates(p: dict, *, inverse: bool = False):
    """Compute or uncompute node marks and the exact frontier count.

    Only small local gate blocks are materialized, even for the comparator.
    The inverse reverses both the block order and every gate inside each block.
    """
    if type(inverse) is not bool:
        raise ValueError("inverse must be bool")
    g = p["geometry"]
    offsets = [sum(g.depths[:i]) for i in range(g.tau)]

    def leaves():
        vectors = reversed(range(g.tau)) if inverse else range(g.tau)
        for i in vectors:
            depth = g.depths[i]
            controls = p["challenge"][offsets[i]:offsets[i] + depth]
            indices = reversed(range(1 << depth)) if inverse else range(1 << depth)
            for j in indices:
                negate = [("x", w) for b, w in enumerate(controls) if not (j >> b) & 1]
                block = negate + and_xor(controls, p["marks"][position(g, i, j)], p["scratch"]) + negate[::-1]
                yield from reversed(block) if inverse else block

    def parents():
        order = range(g.leaves - 1) if inverse else reversed(range(g.leaves - 1))
        for parent in order:
            left, right = p["marks"][2 * parent + 1:2 * parent + 3]
            mark, flag = p["marks"][parent], p["flag"]
            block = [("cx", left, mark), ("cx", right, mark), ("ccx", left, right, mark),
                     ("cx", left, flag), ("cx", right, flag)]
            block += controlled_increment(p["count"], flag, p["scratch"])
            block += [("cx", right, flag), ("cx", left, flag)]
            yield from reversed(block) if inverse else block

    if inverse:
        yield from parents()
        yield from leaves()
    else:
        yield from leaves()
        yield from parents()


def predicate_gates(p: dict):
    """Emit |y,z,0> -> |y,z XOR admissible(y),0> on the fixed public row.

    It scans every leaf and parent, including for grinding rejection. There is
    no data-dependent circuit wiring, table access, or early stopping.
    """
    expected = layout(p["geometry"])
    if p != expected:
        raise ValueError("predicate requires its exact disjoint wire layout")
    yield from compute_gates(p)
    g = p["geometry"]
    controls = p["count"] + p["challenge"][sum(g.depths):]
    for value in range(g.opening_limit + 1):
        negate = [("x", w) for bit, w in enumerate(controls) if not (value >> bit) & 1]
        yield from negate
        yield from and_xor(controls, p["target"], p["scratch"])
        yield from reversed(negate)
    yield from compute_gates(p, inverse=True)


def counts(g: Geometry) -> dict:
    """Derive exact emitted counts; one Toffoli is five elementary gates."""
    if not isinstance(g, Geometry):
        raise ValueError("expected validated Geometry")
    n, c = g.leaves, g.opening_limit
    d = (n - 1).bit_length()
    s = d + g.grinding_bits
    leaf_and = sum((1 << depth) * (2 * depth - 3) for depth in g.depths)
    leaf_x = sum((1 << depth) * depth for depth in g.depths)
    ccx = 2 * leaf_and + 2 * (n - 1) * (1 + (d - 1)**2) + (c + 1) * (2 * s - 3)
    cx = 14 * (n - 1)
    x = 2 * leaf_x + 2 * sum(s - value.bit_count() for value in range(c + 1))
    return dict(x=x, cx=cx, ccx=ccx, elementary_gates=x + cx + 5 * ccx,
                clean_work_wires=2 * n + 2 * d + g.grinding_bits - 2,
                input_wires=g.challenge_bits, output_wires=1,
                base_oracle_calls=0, counter_bits=d,
                gate_count_is_exact_for_emitter=True)


def sources(root: Path) -> dict[str, str]:
    """Check only the five named correspondence inputs; no closure is implied."""
    current = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in PINS}
    if current != PINS:
        raise ValueError("reviewed predicate inputs changed; do not repin automatically")
    return current


def report(root: Path, requests: int) -> dict:
    """Bound calls to this component while retaining every omitted operation."""
    integer(requests, 0, 1 << 64, "request cap")
    before = sources(root)
    rows = {}
    for name in ("candidate", "comparator"):
        g = row(name)
        per_trial = counts(g)
        rows[name] = dict(tau=g.tau, depths=list(g.depths), grinding_bits=g.grinding_bits,
                          leaves=g.leaves, opening_limit=g.opening_limit,
                          per_trial=per_trial,
                          per_request_gate_upper_bound=2 * MAX_TRIALS * per_trial["elementary_gates"],
                          lifetime_gate_upper_bound=requests * 2 * MAX_TRIALS * per_trial["elementary_gates"])
    after = sources(root)
    if before != after:
        raise ValueError("predicate inputs changed during accounting")
    return dict(schema="parliament-admissibility-circuit-v1", requests=requests,
                max_primary_trials=MAX_TRIALS, max_auxiliary_trials=MAX_TRIALS,
                max_predicate_calls_per_request=2 * MAX_TRIALS,
                source_before=before, source_after=after, rows=rows,
                role_independent=True, full_resource_vector=False,
                actual_input_collision_bridge=False, independent_cryptographic_review=False,
                physical_verification_workspace_certificate=False,
                production_gate_changed=False, profile_qualified=False,
                scope="Exact clean predicate circuit on supplied fixed-width challenge wires; lifetime totals price this component only. Randomness preparation, bounded-search controller, first-success selection, input/public validation, remaining sampler/reduction work and physical execution are excluded. No prior ledger or oracle-log cost is replaced.")


def main(argv: list[str] | None = None) -> int:
    """Emit a source-bound report; every qualification request is refused."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--requests", type=int, default=1 << 44)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = report(args.root, args.requests)
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.out is not None:
            with args.out.open("x") as output:
                output.write(encoded)
        else:
            print(encoded, end="")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 2 if args.require_qualified else 0


if __name__ == "__main__":
    raise SystemExit(main())
