#!/usr/bin/env python3
"""Emit fixed-slot reversible oracle writes and their exact resource metadata.

Requires Python 3.11 and the two pinned repository helpers below; no environment
variables or third-party packages are needed. The CLI emits metadata, never a
production-sized gate list, and refuses to replace an output file. This is a
separate mathematical component, not an integrated reduction or qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import types

MAX_TRIALS = 1 << 20
MAX_REQUESTS = 1 << 64
KEY_BYTES = 215150
VALUE_BITS = 2112
FRAMING = "scripts/parliament_ballot_write_framing.py"
LOOKUP = "scripts/parliament_ballot_oracle_log_circuit.py"
PINS = {
    FRAMING: "ad5230fdcd01b52588b40d29a2e766625050ef530dfba4cb529350f993a21617",
    LOOKUP: "d045f66581f7a50bcb4e696b0346a192724f5d0858a21c23343bb35478d5c558",
}


def integer(value: int, low: int, high: int, name: str) -> int:
    """Refuse booleans, coercions and dimensions outside the finite interface."""
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in [{low}, {high}]")
    return value


def load_reviewed(root: Path, relative: str) -> types.ModuleType:
    """Execute only one explicitly pinned helper, with a second custody check."""
    if relative not in PINS:
        raise ValueError("unrecognized helper")
    path = root / relative
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != PINS[relative]:
        raise ValueError("reviewed helper changed; do not repin automatically")
    module = types.ModuleType("static_overlay_reviewed_" + path.stem)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    if path.read_bytes() != data:
        raise ValueError("reviewed helper changed during loading")
    return module


def population_sum(count: int) -> int:
    """Sum popcount(0..count-1) using bounded public integer arithmetic."""
    integer(count, 0, MAX_TRIALS, "trial count")
    total = 0
    for bit in range(count.bit_length()):
        half = 1 << bit
        total += (count // (2 * half)) * half
        total += max(0, count % (2 * half) - half)
    return total


def counts(x: int = 0, cx: int = 0, ccx: int = 0) -> dict:
    """Keep exact reversible gates separate from the supplied base oracle."""
    return dict(x=x, cx=cx, ccx=ccx, base_xor_oracle_calls=0,
                elementary_one_two_qubit_gates=x + cx + 5 * ccx)


class StaticSlotWrite:
    """Controlled XOR into one public fixed slot; no counter or routing scan.

    On a blank slot this installs active=enable and record=enable*incoming.
    Every target may instead be arbitrary: the same circuit remains an exact
    involution, but is not then an append. A caller must establish vacancy and
    use each assigned slot at most once. No quantum input is measured.
    """

    def __init__(self, capacity: int, key_bits: int, value_bits: int, slot: int):
        self.capacity = integer(capacity, 1, MAX_REQUESTS * (MAX_TRIALS + 2), "capacity")
        self.key_bits = integer(key_bits, 1, 1 << 32, "key bits")
        self.value_bits = integer(value_bits, 1, 1 << 16, "value bits")
        self.slot = integer(slot, 0, capacity - 1, "slot")

    @property
    def record_bits(self) -> int:
        """Width of length/key/value data, excluding its active flag."""
        return self.key_bits + self.value_bits

    def layout(self) -> dict:
        """Describe large wire intervals without allocating or enumerating them."""
        log_bits = self.capacity * (1 + self.record_bits)
        return dict(log=0, log_bits=log_bits, enable=log_bits,
                    incoming=log_bits + 1, size=log_bits + 1 + self.record_bits,
                    target=self.slot * (1 + self.record_bits))

    def emit(self, *, inverse: bool = False):
        """Lazily emit only gates touching the selected slot and source wires."""
        if type(inverse) is not bool:
            raise ValueError("inverse must be bool")
        p = self.layout()
        flag = ("cx", p["enable"], p["target"])
        if not inverse:
            yield flag
        bits = range(self.record_bits - 1, -1, -1) if inverse else range(self.record_bits)
        for bit in bits:
            yield ("ccx", p["enable"], p["incoming"] + bit, p["target"] + 1 + bit)
        if inverse:
            yield flag

    def resources(self) -> dict:
        """Count emitted gates; storage and preparation remain explicit."""
        return dict(gates=counts(cx=1, ccx=self.record_bits),
                    persistent_log_bits=self.layout()["log_bits"],
                    supplied_record_bits=self.record_bits, supplied_enable_bits=1,
                    clean_work_bits=0, counter_bits=0, fixed_slot=self.slot,
                    append_semantics_require_vacant_slot=True)


class StaticProgrammedWrites:
    """W0's supplied fields and flags, with a fixed segment for invocation j.

    Offsets 0,1,2+c mean domain09, domain0a, domain0b/counter c. This is the
    captured post-entry W0 logical order, not a new commutation argument for
    earlier programming hybrids. The invocation ordinal is classical public
    controller metadata; selection/authentication of that ordinal is external.
    The caller supplies valid and primary-prefix flags and generated fields.
    Small trial caps are synthetic wiring tests, never protocol bounds.
    """

    def __init__(self, framing: types.ModuleType, row: str, role: str,
                 requests: int, request_index: int, length_bits: int = 64,
                 *, trials: int = MAX_TRIALS, key_bytes: int = KEY_BYTES):
        self.requests = integer(requests, 1, MAX_REQUESTS, "request cap")
        self.request_index = integer(request_index, 0, requests - 1, "request index")
        self.length_bits = integer(length_bits, 1, 4096, "length bits")
        self.trials = integer(trials, 1, MAX_TRIALS, "primary cap")
        self.key_bytes = integer(key_bytes, 1, KEY_BYTES, "key capacity bytes")
        self.row, self.role, self.framing = row, role, framing
        self.plans = tuple(framing.shape(row, role, c) for c in (1, 2, 3))
        if any(p["key_bytes"] >= 1 << length_bits or p["key_bytes"] > key_bytes for p in self.plans):
            raise ValueError("length register cannot represent every full key")
        self.capacity = requests * (trials + 2)
        self.key_bits = length_bits + 8 * key_bytes
        self.record_bits = self.key_bits + VALUE_BITS

    def field_inventory(self) -> tuple:
        """Share equal-named immutable transcript fields, including challenge1/2."""
        fields = {}
        for plan in self.plans:
            for name, width in plan["fields"]:
                if name == "counter_u32_le":
                    continue
                if name in fields and fields[name] != width:
                    raise ValueError("inconsistent shared transcript field")
                fields[name] = width
        for index in (0, 1):
            name, width = "challenge_" + str(index + 1), self.plans[index]["value_bytes"]
            if name in fields and fields[name] != width:
                raise ValueError("inconsistent challenge width")
            fields[name] = width
        return tuple(fields.items())

    def layout(self) -> dict:
        """Retain inputs/log separately from the reused zero staging and controls."""
        fields, cursor = {}, 0
        for name, width in self.field_inventory():
            fields[name] = (cursor, 8 * width)
            cursor += 8 * width
        primary = cursor
        flags = primary + self.trials * 256
        valid = flags + self.trials
        inputs = valid + 1
        log_bits = self.capacity * (1 + self.record_bits)
        enable = inputs + log_bits
        staging = enable + 1
        trial = staging + self.record_bits
        return dict(fields=fields, primary=primary, flags=flags, valid=valid,
                    input_bits=inputs, log=inputs, log_bits=log_bits, enable=enable,
                    staging=staging, trial=trial, size=trial + 32)

    def slot(self, challenge: int, index: int = 0) -> int:
        """Map only legal logical writes to disjoint increasing slot ordinals."""
        integer(challenge, 1, 3, "challenge")
        integer(index, 0, self.trials - 1 if challenge == 3 else 0, "trial index")
        return self.request_index * (self.trials + 2) + (challenge - 1 if challenge < 3 else 2 + index)

    def scatter_layout(self, challenge: int, index: int = 0) -> dict:
        """Bind the pinned framing emitter to the exact retained field registers."""
        self.slot(challenge, index)
        p, plan = self.layout(), self.plans[challenge - 1]
        inputs = {name: ((p["trial"], 32) if name == "counter_u32_le" else p["fields"][name])
                  for name, _ in plan["fields"]}
        inputs["value"] = ((p["primary"] + index * 256, 256) if challenge == 3
                           else p["fields"]["challenge_" + str(challenge)])
        return dict(plan=plan, length_bits=self.length_bits, key_capacity=self.key_bytes,
                    value_capacity=264, inputs=inputs, staging_start=p["staging"])

    def emit_record(self, challenge: int, index: int = 0, *, inverse: bool = False):
        """Prepare one frame, write its fixed vacant slot, and clear all work."""
        slot = self.slot(challenge, index)
        if type(inverse) is not bool:
            raise ValueError("inverse must be bool")
        p = self.layout()

        def controls():
            if challenge == 3:
                for bit in range(32):
                    if (index >> bit) & 1:
                        yield ("x", p["trial"] + bit)
                yield ("ccx", p["valid"], p["flags"] + index, p["enable"])
            else:
                yield ("cx", p["valid"], p["enable"])

        writer = StaticSlotWrite(self.capacity, self.key_bits, VALUE_BITS, slot)
        w = writer.layout()

        def mapped(wire):
            if wire < w["log_bits"]:
                return p["log"] + wire
            if wire == w["enable"]:
                return p["enable"]
            return p["staging"] + wire - w["incoming"]

        yield from controls()
        yield from self.framing.scatter(self.scatter_layout(challenge, index))
        for gate in writer.emit(inverse=inverse):
            yield (gate[0], *(mapped(wire) for wire in gate[1:]))
        yield from self.framing.scatter(self.scatter_layout(challenge, index), inverse=True)
        yield from controls()

    def emit(self, *, inverse: bool = False):
        """Emit all M+2 record circuits, including disabled primary attempts."""
        if type(inverse) is not bool:
            raise ValueError("inverse must be bool")
        if inverse:
            for index in range(self.trials - 1, -1, -1):
                yield from self.emit_record(3, index, inverse=True)
            for challenge in (2, 1):
                yield from self.emit_record(challenge, inverse=True)
        else:
            for challenge in (1, 2):
                yield from self.emit_record(challenge)
            for index in range(self.trials):
                yield from self.emit_record(3, index)

    def resources(self) -> dict:
        """Count the actual emitter without expanding its production gate list."""
        p = self.layout()
        f = [self.framing.framing_counts(plan, self.length_bits) for plan in self.plans]
        x = f[0]["x_exact"] + f[1]["x_exact"] + self.trials * f[2]["x_exact"]
        cx = f[0]["cnot_exact"] + f[1]["cnot_exact"] + self.trials * f[2]["cnot_exact"]
        x += 2 * population_sum(self.trials)
        cx += self.trials + 2 + 4
        ccx = (self.trials + 2) * self.record_bits + 2 * self.trials
        return dict(gates=counts(x, cx, ccx), supplied_input_bits=p["input_bits"],
                    persistent_log_bits=p["log_bits"], counter_bits=0,
                    trial_constant_work_bits=32,
                    clean_work_bits=1 + self.record_bits + 32, total_logical_bits=p["size"],
                    fixed_write_circuits=self.trials + 2, auxiliary_writes=0,
                    first_slot=self.slot(1), last_slot=self.slot(3, self.trials - 1),
                    disabled_write_gates_charged=True, vacancy_and_schedule_are_premises=True,
                    key_capacity_bytes=self.key_bytes,
                    synthetic_reduced_trials=self.trials != MAX_TRIALS)


def report(root: Path, requests: int, request_index: int, row: str, role: str,
           length_bits: int) -> dict:
    """Report this component and unchanged scan lookup, with narrow source pins."""
    framing = load_reviewed(root, FRAMING)
    lookup = load_reviewed(root, LOOKUP)
    writer = StaticProgrammedWrites(framing, row, role, requests, request_index, length_bits)
    value = writer.resources()
    scan = lookup.resource_vector(writer.capacity, writer.key_bits, VALUE_BITS)
    after = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in PINS}
    if after != PINS:
        raise ValueError("reviewed helper changed during accounting")
    return dict(schema="parliament-static-overlay-v1", request_cap=requests,
                request_index=request_index, row=row, role=role, trials=MAX_TRIALS,
                length_bits=length_bits, capacity=writer.capacity, writer=value,
                inherited_lookup=scan["lookup"],
                inherited_lookup_clean_work_bits=scan["lookup_clean_work_wires"],
                frames=[dict(challenge=p["challenge"], key_bytes=p["key_bytes"],
                             value_bytes=p["value_bytes"], domain=p["domain"],
                             fields=p["fields"]) for p in writer.plans],
                source_sha256_before=dict(PINS), source_sha256_after=after,
                source_pin_scope="Two helper files only; not complete Rust/source/dependency custody.",
                scope="Fixed-slot W0 writer with supplied transcript fields/flags; unchanged coherent scan lookup priced separately.",
                premises=["Each assigned slot is initially zero and used once in chronological invocation order.",
                          "The controller supplies/authenticates a classical valid-invocation ordinal.",
                          "Generated fields, validity, and primary-prefix flags are supplied; auxiliary trials never write.",
                          "Scratch/staging start zero; original fields and coins remain retained.",
                          "Lookup requires complete canonical addresses and the same supplied base XOR oracle.",
                          "The chosen length width covers every allowed full query, not merely programmed keys."],
                exclusions=["Source field/schedule generation and prior programming-game commutations.",
                            "Full adaptive dispatcher, controller, allocation/preparation and family-wide resource maxima.",
                            "Base oracle construction, external queries, primitive advantages and physical routing."],
                full_root_driver_integrated=False, full_resource_vector=False,
                independent_cryptographic_review=False, profile_qualified=False,
                physical_verification_workspace_certificate=False, production_gate_changed=False)


def main(argv: list[str] | None = None) -> int:
    """Print metadata or create a fresh file; qualification always fails closed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--request-cap", type=int, required=True)
    parser.add_argument("--request-index", type=int, default=0)
    parser.add_argument("--row", choices=("candidate", "comparator"), default="candidate")
    parser.add_argument("--role", choices=("registration", "vote"), default="vote")
    parser.add_argument("--length-bits", type=int, default=64)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args(argv)
    try:
        value = report(args.root.resolve(), args.request_cap, args.request_index,
                       args.row, args.role, args.length_bits)
        encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
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
