"""Independently check the reversible challenge-admissibility construction.

These are basis-state and source-accounting checks, not native performance,
physical workspace, quantum security, or production qualification evidence.
"""
from __future__ import annotations

from collections import Counter
import contextlib
from dataclasses import FrozenInstanceError
from functools import lru_cache
import importlib.util
import io
import itertools
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "admissibility_under_test", ROOT / "scripts/parliament_ballot_admissibility_circuit.py"
)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)


@lru_cache(maxsize=32)
def reference_leaves(geometry):
    """Enumerate the source's interleaved leaf labels, without its position formula."""
    widths = [geometry.k if vector < geometry.tau1 else geometry.k - 1
              for vector in range(geometry.tau)]
    labels = [(vector, index) for index in range(2**geometry.k)
              for vector, width in enumerate(widths) if index < 2**width]
    return {label: len(labels) - 1 + offset for offset, label in enumerate(labels)}


def reference_frontier(geometry, selected):
    """Count missing children adjacent to the union of selected root paths."""
    leaves = reference_leaves(geometry)
    marked = set()
    for vector, index in enumerate(selected):
        node = leaves[vector, index]
        while True:
            marked.add(node)
            if node == 0:
                break
            node = (node - 1) // 2
    frontier = {child for parent in marked if parent < len(leaves) - 1
                for child in (2*parent + 1, 2*parent + 2) if child not in marked}
    return len(frontier), marked


def reference_decode(geometry, challenge):
    """Consecutive source bits decode each index least-significant bit first."""
    indices = []
    offset = 0
    for vector in range(geometry.tau):
        width = geometry.k if vector < geometry.tau1 else geometry.k - 1
        indices.append(sum(challenge[offset + bit] * 2**bit for bit in range(width)))
        offset += width
    return indices, not any(challenge[offset:])


def reference_predicate(geometry, challenge):
    selected, grind_clear = reference_decode(geometry, challenge)
    return int(grind_clear and reference_frontier(geometry, selected)[0] <= geometry.opening_limit)


def interpret(gates, state, lane_mask=1):
    """Independent reversible Boolean interpreter, optionally with packed basis states."""
    seen = Counter()
    for gate in gates:
        op = gate[0]
        seen[op] += 1
        if op == "x":
            if len(gate) != 2:
                raise AssertionError(gate)
            state[gate[1]] ^= lane_mask
        elif op == "cx":
            _, control, target = gate
            if control == target:
                raise AssertionError("aliased CNOT")
            state[target] ^= state[control]
        elif op == "ccx":
            _, first, second, target = gate
            if first == second or first == target or second == target:
                raise AssertionError("aliased Toffoli")
            state[target] ^= state[first] & state[second]
        else:
            raise AssertionError(gate)
    return seen


def packed_state(plan, cases):
    state = [0] * plan["size"]
    for lane, (challenge, target) in enumerate(cases):
        for wire, bit in zip(plan["challenge"], challenge, strict=True):
            state[wire] |= bit << lane
        state[plan["target"]] |= target << lane
    return state


class AdmissibilityTest(unittest.TestCase):
    def assert_basis_cases(self, geometry, cases, *, inverse=False):
        plan = M.layout(geometry)
        state = packed_state(plan, cases)
        original = list(state)
        expected = list(state)
        for lane, (challenge, _) in enumerate(cases):
            expected[plan["target"]] ^= reference_predicate(geometry, challenge) << lane
        gates = M.predicate_gates(plan)
        if inverse:
            gates = list(gates)
        seen = interpret(gates, state, (1 << len(cases)) - 1)
        self.assertEqual(state, expected, "challenge/target mismatch or dirty work wires")
        if inverse:
            interpret(reversed(gates), state, (1 << len(cases)) - 1)
            self.assertEqual(state, original)
        return seen

    def test_source_leaf_order_and_complete_bijection(self):
        for geometry in (M.Geometry(2, 3, 0, 2, 3), M.Geometry(2, 3, 1, 2, 3),
                         M.row("candidate"), M.row("comparator")):
            labels = reference_leaves(geometry)
            self.assertEqual(geometry.leaves, len(labels))
            self.assertEqual(set(labels.values()), set(range(len(labels)-1, 2*len(labels)-1)))
            for (vector, index), expected in labels.items():
                self.assertEqual(M.position(geometry, vector, index), expected)

    def test_small_uniform_and_mixed_all_inputs_targets_thresholds_and_inverse(self):
        for tau1 in (0, 1, 2):
            initial = M.Geometry(2, 3, tau1, 2, 3)
            all_challenges = list(itertools.product((0, 1), repeat=initial.challenge_bits))
            frontiers = {reference_frontier(initial, reference_decode(initial, c)[0])[0]
                         for c in all_challenges}
            self.assertGreater(len(frontiers), 1)
            # Every threshold that can distinguish the independent path unions,
            # with both target values and every grinding-bit combination.
            for limit in sorted(set(range(max(frontiers) + 2)) | {initial.leaves - 1}):
                geometry = M.Geometry(2, 3, tau1, 2, limit)
                cases = [(challenge, target) for challenge in all_challenges for target in (0, 1)]
                seen = self.assert_basis_cases(geometry, cases, inverse=True)
                report = M.counts(geometry)
                self.assertEqual(dict(seen), {name: report[name] for name in ("x", "cx", "ccx")})
                self.assertEqual(seen["x"] + seen["cx"] + 5*seen["ccx"], report["elementary_gates"])

    def test_frontier_identity_carries_and_threshold_equality(self):
        geometry = M.Geometry(3, 3, 1, 1, 3)
        indices = itertools.product(*(range(2**width) for width in geometry.depths))
        examples = {}
        for selected in indices:
            frontier, marked = reference_frontier(geometry, selected)
            self.assertEqual(frontier, len(marked) - 2*geometry.tau + 1)
            examples.setdefault(frontier, selected)
        self.assertTrue(any((value & (value-1)) == 0 for value in examples))
        for frontier, selected in examples.items():
            challenge = [index >> bit & 1 for index, width in zip(selected, geometry.depths)
                         for bit in range(width)] + [0]
            for limit in (frontier-1, frontier, frontier+1):
                if limit >= 0:
                    changed = M.Geometry(3, 3, 1, 1, limit)
                    self.assert_basis_cases(changed, [(challenge, 0), (challenge, 1)])

    def test_actual_rows_streamed_with_all_grinding_positions_and_gate_counts(self):
        random_source = random.Random(0xB6A11)
        for name in ("candidate", "comparator"):
            geometry = M.row(name)
            self.assertEqual(geometry.challenge_bits, 256)
            selected = {}
            # Fixed bytes expose source byte/bit ordering without helper decoding.
            patterned = bytes((19*index + 0xA3) % 256 for index in range(32))
            initial = [byte >> bit & 1 for byte in patterned for bit in range(8)]
            initial[-geometry.grinding_bits:] = [0] * geometry.grinding_bits
            challenges = [[0]*256, initial]
            for _ in range(2048):
                candidate = [random_source.randrange(2) for _ in range(256-geometry.grinding_bits)]
                candidate += [0]*geometry.grinding_bits
                selected.setdefault(reference_predicate(geometry, candidate), candidate)
                if len(selected) == 2:
                    break
            self.assertEqual(set(selected), {0, 1})
            challenges.extend(selected.values())
            for bit in range(256-geometry.grinding_bits, 256):
                changed = list(selected[1])
                changed[bit] = 1
                self.assertEqual(reference_predicate(geometry, changed), 0)
                challenges.append(changed)
            cases = [(challenge, target) for challenge in challenges for target in (0, 1)]
            seen = self.assert_basis_cases(geometry, cases)
            counted = M.counts(geometry)
            self.assertEqual({key: seen[key] for key in ("x", "cx", "ccx")},
                             {key: counted[key] for key in ("x", "cx", "ccx")})
            self.assertEqual(seen["x"] + seen["cx"] + 5*seen["ccx"], counted["elementary_gates"])
            self.assertEqual(counted["base_oracle_calls"], 0)

    def test_computed_marks_and_counter_equal_independent_frontier_then_clean(self):
        for tau1, grinding in itertools.product((0, 1, 2), (0, 2)):
            geometry = M.Geometry(2, 3, tau1, grinding, 3)
            plan = M.layout(geometry)
            cases = [(challenge, 1) for challenge in itertools.product((0, 1), repeat=geometry.challenge_bits)]
            state = packed_state(plan, cases)
            original = list(state)
            mask = (1 << len(cases)) - 1
            forward = list(M.compute_gates(plan))
            backward = list(M.compute_gates(plan, inverse=True))
            self.assertEqual(backward, list(reversed(forward)))
            interpret(forward, state, mask)
            for lane, (challenge, _) in enumerate(cases):
                selected, _ = reference_decode(geometry, challenge)
                frontier, marked = reference_frontier(geometry, selected)
                observed = {node for node, wire in enumerate(plan["marks"]) if state[wire] >> lane & 1}
                self.assertEqual(observed, marked)
                self.assertEqual(sum((state[wire] >> lane & 1) * 2**bit
                                     for bit, wire in enumerate(plan["count"])), frontier)
            self.assertFalse(any(state[wire] for wire in plan["scratch"] + [plan["flag"]]))
            self.assertEqual([state[wire] for wire in plan["challenge"] + [plan["target"]]],
                             [original[wire] for wire in plan["challenge"] + [plan["target"]]])
            interpret(backward, state, mask)
            self.assertEqual(state, original)

    def test_controlled_increment_all_values_carries_wrap_and_inverse(self):
        for width in (*range(1, 8), 13, 16):
            counter = list(range(width))
            flag = width
            scratch = list(range(width+1, 2*width))
            values = (range(2**width) if width <= 7 else
                      sorted({0, 2**width-1} | {2**bit-1 for bit in range(width)} |
                             {2**bit for bit in range(width)}))
            cases = [(value, active) for value in values for active in (0, 1)]
            state = [0] * (2*width)
            expected = [0] * len(state)
            for lane, (value, active) in enumerate(cases):
                state[flag] |= active << lane
                expected[flag] |= active << lane
                for bit, wire in enumerate(counter):
                    state[wire] |= (value >> bit & 1) << lane
                    expected[wire] |= (((value+active) % 2**width) >> bit & 1) << lane
            initial = list(state)
            gates = M.controlled_increment(counter, flag, scratch)
            interpret(gates, state, (1 << len(cases)) - 1)
            self.assertEqual(state, expected)
            interpret(reversed(gates), state, (1 << len(cases)) - 1)
            self.assertEqual(state, initial)

    def test_and_ladder_all_inputs_arbitrary_targets_and_clean_scratch(self):
        for width in range(9):
            controls, target = list(range(width)), width
            scratch = list(range(width+1, width+1+max(0, width-2)))
            state = [0] * (width+1+len(scratch))
            expected = list(state)
            cases = [(inputs, target_value) for inputs in itertools.product((0, 1), repeat=width)
                     for target_value in (0, 1)]
            for lane, (inputs, target_value) in enumerate(cases):
                for wire, value in zip(controls, inputs):
                    state[wire] |= value << lane
                state[target] |= target_value << lane
                expected[target] |= (target_value ^ int(all(inputs))) << lane
            expected[:width] = state[:width]
            interpret(M.and_xor(controls, target, scratch), state, (1 << len(cases)) - 1)
            self.assertEqual(state, expected)

    def test_layout_geometry_and_work_count_match_disjoint_wire_inventory(self):
        for geometry in (M.Geometry(2, 3, 0, 0, 0), M.Geometry(2, 3, 2, 2, 15),
                         M.row("candidate"), M.row("comparator")):
            plan = M.layout(geometry)
            work = plan["marks"] + plan["count"] + [plan["flag"]] + plan["scratch"]
            inventory = plan["challenge"] + [plan["target"]] + work
            self.assertEqual(inventory, list(range(plan["size"])))
            self.assertEqual(len(work), plan["clean_work_wires"])
            self.assertEqual(len(work), M.counts(geometry)["clean_work_wires"])
            self.assertEqual(len(plan["marks"]), 2*geometry.leaves-1)
            self.assertGreater(2**len(plan["count"]), geometry.leaves-1)
            self.assertEqual(geometry.depths, tuple(geometry.k if i < geometry.tau1 else geometry.k-1
                                                   for i in range(geometry.tau)))
        self.assertEqual(M.row("candidate"), M.Geometry(33, 8, 17, 8, 229))
        self.assertEqual(M.row("comparator"), M.Geometry(22, 12, 8, 6, 225))
        with self.assertRaises(FrozenInstanceError):
            M.row("candidate").opening_limit = 1

    def test_invalid_numeric_geometry_positions_and_layout_refuse(self):
        valid = dict(tau=2, k=3, tau1=1, grinding_bits=2, opening_limit=3)
        for field in valid:
            for bad in (True, False, 1.5, "2", None, -1, float("inf"), float("nan")):
                with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                    M.Geometry(**dict(valid, **{field: bad}))
        for changed in (dict(tau=1), dict(tau=65), dict(k=2), dict(k=13), dict(tau1=3),
                        dict(grinding_bits=257), dict(opening_limit=12),
                        dict(tau=64, k=12), dict(tau=64, k=4, tau1=64, grinding_bits=1)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                M.Geometry(**dict(valid, **changed))
        geometry = M.Geometry(**valid)
        for name in ("other", "Candidate", None, True):
            with self.assertRaises(ValueError):
                M.row(name)
        for vector, index in ((-1, 0), (2, 0), (True, 0), (0, -1), (0, 8),
                              (1, 4), (0, True), (0, 1.5)):
            with self.assertRaises(ValueError):
                M.position(geometry, vector, index)
        for value in (None, {}, (2, 3, 1, 2, 3)):
            with self.assertRaises(ValueError):
                M.layout(value)
            with self.assertRaises(ValueError):
                M.counts(value)
        plan = M.layout(geometry)
        for key in ("challenge", "marks", "count", "scratch"):
            changed = dict(plan, **{key: list(plan[key])})
            changed[key][0] = plan["target"]
            with self.assertRaises(ValueError):
                list(M.predicate_gates(changed))
        for inverse in (0, 1, None, "false"):
            with self.assertRaises(ValueError):
                list(M.compute_gates(plan, inverse=inverse))
        for controls, target, scratch in (([0, 0], 1, []), ([0], 0, []),
                                         ([0, 1, 2], 3, []), ([0], 1, [0]),
                                         ([True], 1, []), ([-1], 1, [])):
            with self.assertRaises(ValueError):
                M.and_xor(controls, target, scratch)
        with self.assertRaises(ValueError):
            M.controlled_increment([], 0, [])

    def test_all_selected_source_pins_and_mid_report_drift_refuse(self):
        self.assertEqual(len(M.PINS), 5)
        self.assertEqual(M.sources(ROOT), M.PINS)
        original = Path.read_bytes
        for source in M.PINS:
            target = ROOT / source
            def changed(path, target=target):
                data = original(path)
                return data+b"\n" if path == target else data
            with patch.object(Path, "read_bytes", changed), self.assertRaises(ValueError):
                M.sources(ROOT)
        target = ROOT / next(iter(M.PINS))
        reads = 0
        def late_changed(path):
            nonlocal reads
            data = original(path)
            if path == target:
                reads += 1
                if reads == 2:
                    return data+b"\n"
            return data
        with patch.object(Path, "read_bytes", late_changed), self.assertRaises(ValueError):
            M.report(ROOT, 1)
        self.assertEqual(reads, 2)

    def test_report_bounded_primary_auxiliary_zero_requests_and_qualification_flags(self):
        result = M.report(ROOT, 3)
        self.assertEqual(result["source_before"], result["source_after"])
        self.assertEqual(result["source_before"], M.PINS)
        self.assertEqual(result["max_primary_trials"], 2**20)
        self.assertEqual(result["max_auxiliary_trials"], 2**20)
        self.assertEqual(result["max_predicate_calls_per_request"], 2**21)
        self.assertEqual(set(result["rows"]), {"candidate", "comparator"})
        for name, row in result["rows"].items():
            per_trial = M.counts(M.row(name))
            self.assertEqual(row["per_trial"], per_trial)
            self.assertEqual(row["per_request_gate_upper_bound"], 2**21 * per_trial["elementary_gates"])
            self.assertEqual(row["lifetime_gate_upper_bound"], 3 * row["per_request_gate_upper_bound"])
        zero = M.report(ROOT, 0)
        self.assertTrue(all(row["lifetime_gate_upper_bound"] == 0 for row in zero["rows"].values()))
        maximum = M.report(ROOT, 2**64)
        self.assertTrue(all(row["lifetime_gate_upper_bound"] == 2**64 * row["per_request_gate_upper_bound"]
                            for row in maximum["rows"].values()))
        for flag in ("full_resource_vector", "actual_input_collision_bridge", "independent_cryptographic_review",
                     "physical_verification_workspace_certificate", "production_gate_changed", "profile_qualified"):
            self.assertIs(result[flag], False)
        self.assertIs(result["role_independent"], True)
        for bad in (True, False, -1, 1.1, "1", None, 2**64+1):
            with self.assertRaises(ValueError):
                M.report(ROOT, bad)

    def test_cli_refuses_qualification_malformed_numbers_and_overwrite(self):
        arguments = ["--root", str(ROOT), "--requests", "1"]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(M.main(arguments + ["--require-qualified"]), 2)
        self.assertFalse(json.loads(output.getvalue())["profile_qualified"])
        for bad in ("1.5", "nan", "true", "-1", str(2**64+1)):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                M.main(["--root", str(ROOT), "--requests", bad])
            self.assertEqual(error.exception.code, 2)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            self.assertEqual(M.main(arguments + ["--out", str(path), "--require-qualified"]), 2)
            original = path.read_bytes()
            self.assertFalse(json.loads(original)["production_gate_changed"])
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                M.main(arguments + ["--out", str(path)])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(path.read_bytes(), original)

    def test_omitting_uncompute_is_detected_even_when_output_is_right(self):
        geometry = M.Geometry(2, 3, 1, 2, 5)
        plan = M.layout(geometry)
        gates = list(M.predicate_gates(plan))
        challenge = [0]*geometry.challenge_bits
        original = packed_state(plan, [(challenge, 0)])
        output_gates = [index for index, gate in enumerate(gates) if gate[-1] == plan["target"]]
        self.assertTrue(output_gates)
        dirty = list(original)
        interpret(gates[:max(output_gates)+1], dirty)
        self.assertEqual(dirty[plan["target"]], reference_predicate(geometry, challenge))
        work = set(range(plan["size"])) - set(plan["challenge"]) - {plan["target"]}
        self.assertTrue(any(dirty[wire] for wire in work), "mutation must leave observable garbage")
        clean = list(original)
        interpret(gates, clean)
        self.assertFalse(any(clean[wire] for wire in work))


if __name__ == "__main__":
    unittest.main()
