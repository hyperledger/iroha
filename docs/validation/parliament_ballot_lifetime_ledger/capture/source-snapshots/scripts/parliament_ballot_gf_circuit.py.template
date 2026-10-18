#!/usr/bin/env python3
"""Emit clean polynomial-product XOR circuits for three reviewed field APIs.

This analytical circuit is not Rust code, a runtime implementation, a complete
simulator, or a whole-program reversible resource bound. Its source registers
and output/work registers are disjoint, and work begins zero. No oracle or RAM
access is hidden in a gate. The CLI only accounts; it executes no Rust binary.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re


FIELD = "crates/iroha_zkp_vole/src/field.rs"
ACCOUNTING = "docs/validation/parliament_ballot_ideal_sampler_accounting/report.json"
PINS = {
    FIELD: "df65fd59ae7970752ec71c18212e3aee09fc8f498068dff29e3ac23da9d5e3a8",
    ACCOUNTING: "32f13e842ac39f7f3c3d08ae2135a8ebdffd442acc776002e2229c36610ad043",
    "specs/parliament_ballot_b6_ideal_sampler_accounting.md": "c022d1f76360dfe4bdd6934fe352d5d87e7b9f63df3828608230f759cb1e22c5",
    "specs/parliament_ballot_b6_oracle_log_circuit.md": "de33b603bfc281238b348f082a2316a645f1d236894e7837ee95078ddbc1d673",
}
FALSE_FLAGS = {
    "actual_simulator_execution": False,
    "complete_resource_vector": False,
    "whole_program_quantum_gate_bound": False,
    "compiled_memory_or_allocator_bound": False,
    "physical_workspace_qualified": False,
    "actual_input_collision_bridge": False,
    "primitive_advantage_assumed": False,
    "independent_cryptographic_review": False,
    "profile_qualified": False,
    "production_gate_changed": False,
}


def require(condition, message):
    """Fail closed without relying on removable Python assertions."""
    if not condition:
        raise ValueError(message)


def bounded(value, lower, upper, name):
    """Reject noninteger and out-of-scope geometry or wire labels."""
    require(type(value) is int and lower <= value <= upper, "invalid " + name)
    return value


@dataclass(frozen=True)
class Geometry:
    """Public operand widths and a monic binary reduction polynomial.

    Toy quotient rings need not be fields: the product/remainder circuit proof
    needs no irreducibility premise. The production rows use source field taps.
    """

    p: int
    q: int
    n: int
    taps: tuple[int, ...]

    def __post_init__(self):
        bounded(self.n, 2, 768, "modulus degree")
        bounded(self.p, 1, self.n, "first operand width")
        bounded(self.q, 1, self.n, "second operand width")
        require(type(self.taps) is tuple and self.taps, "taps must be a nonempty tuple")
        for tap in self.taps:
            bounded(tap, 0, self.n - 1, "polynomial tap")
        require(len(set(self.taps)) == len(self.taps) and 0 in self.taps, "duplicate taps or no constant term")

    @property
    def work(self):
        """Number of polynomial convolution coefficients."""
        return self.p + self.q - 1

    @property
    def modulus(self):
        """Monic polynomial as a little-endian coefficient bit vector."""
        return (1 << self.n) | sum(1 << tap for tap in self.taps)


KERNELS = {
    "gf256_mul": Geometry(256, 256, 256, (10, 5, 2, 0)),
    "gf256_mul_u64": Geometry(256, 64, 256, (10, 5, 2, 0)),
    "gf256_mul_tripled": Geometry(256, 768, 768, (19, 17, 4, 0)),
}


def geometry(name):
    """Select one of the three source API geometries."""
    require(type(name) is str and name in KERNELS, "unknown kernel")
    return KERNELS[name]


def layout(g):
    """Allocate a conventional contiguous disjoint mathematical wire layout."""
    require(type(g) is Geometry, "invalid geometry")
    cursor, wires = 0, {}
    for name, width in (("a", g.p), ("b", g.q), ("z", g.n), ("work", g.work)):
        wires[name] = tuple(range(cursor, cursor + width))
        cursor += width
    return wires


def validate_wires(g, wires):
    """Reject aliasing, including an aliased source used as both operands."""
    require(type(g) is Geometry and type(wires) is dict, "invalid circuit interface")
    require(set(wires) == {"a", "b", "z", "work"}, "wrong wire regions")
    all_wires = []
    for name, width in (("a", g.p), ("b", g.q), ("z", g.n), ("work", g.work)):
        require(type(wires[name]) in (tuple, list) and len(wires[name]) == width, "wrong wire width: " + name)
        for wire in wires[name]:
            bounded(wire, 0, (1 << 63) - 1, "wire index")
            all_wires.append(wire)
    require(len(set(all_wires)) == len(all_wires), "wire regions overlap")


def reduction_columns(g):
    """Derive x^d modulo the public monic polynomial for every product degree."""
    require(type(g) is Geometry, "invalid geometry")
    value, columns = 1, []
    for _ in range(g.work):
        columns.append(value)
        value <<= 1
        if value & (1 << g.n):
            value ^= g.modulus
    return tuple(columns)


def _convolution(g, wires, reverse=False):
    """XOR each bilinear coefficient into its fixed convolution wire."""
    first = range(g.p - 1, -1, -1) if reverse else range(g.p)
    second = range(g.q - 1, -1, -1) if reverse else range(g.q)
    for i in first:
        for j in second:
            yield ("CCX", wires["a"][i], wires["b"][j], wires["work"][i + j])


def emit(g, wires=None):
    """Stream compute, reduced-output XOR and reverse compute gates.

    Returned gates are tuples ("CX", control, target) or
    ("CCX", first_control, second_control, target). Addresses are entirely public.
    Validation runs before the generator emits its first gate. The source and
    destination labels are never modified except for the stated z XOR update.
    """
    wires = layout(g) if wires is None else wires
    validate_wires(g, wires)
    # Fix the validated public layout for the lifetime of this streamed circuit.
    # A caller mutating its lists after the first yield cannot change later gates.
    wires = {name: tuple(region) for name, region in wires.items()}
    yield from _convolution(g, wires)
    for degree, column in enumerate(reduction_columns(g)):
        while column:
            low = column & -column
            yield ("CX", wires["work"][degree], wires["z"][low.bit_length() - 1])
            column ^= low
    yield from _convolution(g, wires, reverse=True)


def resources(g):
    """Count this exact emitter, never a whole-program compiled implementation."""
    require(type(g) is Geometry, "invalid geometry")
    toffoli = 2 * g.p * g.q
    cnot = sum(column.bit_count() for column in reduction_columns(g))
    return {
        "operand_bits": [g.p, g.q],
        "output_bits": g.n,
        "modulus_taps": list(g.taps),
        "X": 0,
        "CNOT": cnot,
        "Toffoli": toffoli,
        "elementary_one_two_qubit_gates": cnot + 5 * toffoli,
        "base_oracle_calls": 0,
        "clean_work_bits": g.work,
        "source_and_output_bits": g.p + g.q + g.n,
        "total_interface_bits": g.p + g.q + g.n + g.work,
        "sequential_elementary_depth_upper_bound": cnot + 5 * toffoli,
        "scope": "One disjoint product-XOR kernel; zero work is supplied and returned. No routing, alias adaptation or whole-program cleanup is included.",
    }


def digest(path):
    """Hash exact source/evidence bytes."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_sources(root):
    """Check only the explicit selected inventory; do not adopt changed pins."""
    root = Path(root).resolve()
    observed = {name: digest(root / name) for name in PINS}
    require(observed == PINS, "selected source/evidence changed")
    return observed


def source_geometry(source):
    """Check the pinned macro choices and LambdaField widening association."""
    found = {}
    for name, limbs, taps in re.findall(r"\b(Gf256|Gf768), limbs = (\d+), taps = \[([0-9, ]+)\]", source):
        require(name not in found, "duplicate source field geometry")
        found[name] = (64 * int(limbs), tuple(int(t.strip()) for t in taps.split(",")))
    require(found == {"Gf256": (256, (10, 5, 2, 0)), "Gf768": (768, (19, 17, 4, 0))}, "source field geometry differs")
    require(re.search(r"lambda_field!\(\s*Gf256,\s*Gf768,\s*SecurityLevel::L256,\s*limbs = 4,", source) is not None,
            "source tripled association differs")
    return found


def report(root):
    """Bind four selected inputs, then report the exact three kernel resources."""
    root = Path(root).resolve()
    before = verify_sources(root)
    fields = source_geometry((root / FIELD).read_text())
    previous = json.loads((root / ACCOUNTING).read_text())
    require(previous["source_sha256_before"][FIELD] == before[FIELD]
            and previous["source_sha256_after"][FIELD] == before[FIELD], "historical field source differs")
    require(previous["checked_logical_accounting"] is True and previous["profile_qualified"] is False
            and previous["complete_resource_vector"] is False, "unexpected prior accounting scope")
    entries = {name: resources(g) for name, g in KERNELS.items()}
    after = verify_sources(root)
    require(before == after, "source/evidence changed during accounting")
    return {
        "schema": "parliament-gf-circuit-v1",
        "verdict": "PASS_UNDER_STATED_PREMISES",
        "checked_component_construction": True,
        "source_sha256_before": before,
        "source_sha256_after": after,
        "selected_source_count": len(before),
        "source_field_geometry": fields,
        "kernels": entries,
        "exclusions": [
            "This four-input inventory is not a complete compiler/dependency or historical-accounting closure.",
            "Inputs, output and work must be disjoint wire regions; equal operand values are allowed, aliased registers are not.",
            "Source basis labels are preserved jointly; their reduced state may change through entanglement with z.",
            "Zero initialization, sampling, addressing, source-field creation and whole-program history/cleanup are not priced.",
            "No source operation-count multiplication is claimed to give a whole-simulator quantum or memory bound.",
            "Primitive interfaces, entry bridges, adversary resources, full reductions and qualification remain open.",
        ],
        **FALSE_FLAGS,
    }


def main(argv=None):
    """Write a new report; refuse changed inputs and every qualification request."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args(argv)
    if args.out.exists():
        parser.error("output already exists")
    try:
        value = report(args.root)
        code = 2 if args.require_qualified else 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        value = {"schema": "parliament-gf-circuit-v1", "verdict": "UNKNOWN", "error": str(error),
                 "checked_component_construction": False, **FALSE_FLAGS}
        code = 1
    with args.out.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
