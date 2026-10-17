"""Finite reversible-circuit and source-custody controls for the new proposal."""
from __future__ import annotations

import importlib.util
import itertools
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/parliament_ballot_oracle_log_circuit.py"
SPEC = importlib.util.spec_from_file_location("oracle_log_circuit", SCRIPT)
MODEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODEL)


def put(bits, wires, value):
    for i, wire in enumerate(wires):
        bits[wire] = (value >> i) & 1


def get(bits, wires):
    return sum(bits[wire] << i for i, wire in enumerate(wires))


class CircuitTests(unittest.TestCase):
    def test_and_ladder_all_inputs_targets_and_clean_work(self):
        for n in range(7):
            controls = list(range(n))
            scratch = list(range(n + 1, n + 1 + max(0, n - 2)))
            gates = MODEL.and_xor(controls, n, scratch)
            for value in range(1 << n):
                for target in (0, 1):
                    before = [(value >> i) & 1 for i in controls] + [target] + [0]*len(scratch)
                    after = MODEL.simulate(gates, before, lambda _: 0)
                    expected = before.copy()
                    expected[n] ^= int(value == (1 << n) - 1)
                    self.assertEqual(after, expected)
            if n >= 2:
                self.assertEqual(MODEL.gate_counts(gates)["ccx"], 2*n - 3)

    def test_and_refuses_alias_and_missing_scratch(self):
        with self.assertRaises(ValueError):
            MODEL.and_xor([0, 1], 1, [])
        with self.assertRaises(ValueError):
            MODEL.and_xor([0, 1, 2], 3, [])

    def test_all_three_slot_histories_queries_outputs_enables(self):
        p = MODEL.toy_layout(3, 1, 1)
        circuit = MODEL.lookup_circuit(p)
        # Include holes and nonzero inactive contents; selection only uses active.
        for entries in itertools.product(itertools.product(range(2), repeat=3), repeat=3):
            for query, output, enabled in itertools.product(range(2), repeat=3):
                before = [0]*p["size"]
                for (active, key, value), (a, k, v) in zip(p["slots"], entries):
                    before[active] = a
                    put(before, key, k)
                    put(before, value, v)
                put(before, p["query"], query)
                put(before, p["output"], output)
                before[p["enable"]] = enabled
                answer = query ^ 1
                for a, k, v in entries:
                    if a and k == query:
                        answer = v
                expected = before.copy()
                put(expected, p["output"], output ^ (answer if enabled else 0))
                after = MODEL.simulate(circuit, before, lambda x: x ^ 1)
                self.assertEqual(after, expected)
                self.assertEqual(MODEL.simulate(circuit, after, lambda x: x ^ 1), before)

    def test_lookup_instruction_counts_and_all_work_cleanup(self):
        for n, k, v in itertools.product((1, 2, 4, 8), (1, 2, 7), (1, 3)):
            p = MODEL.toy_layout(n, k, v)
            observed = MODEL.gate_counts(MODEL.lookup_circuit(p))
            expected = MODEL.resource_vector(n, k, v)
            self.assertEqual(observed, {q: expected["lookup"][q] for q in observed})
            self.assertEqual(len(p["lookup_work"]), expected["lookup_clean_work_wires"])

    def test_multibit_overwrite_and_old_higher_counter_survives(self):
        p = MODEL.toy_layout(4, 3, 2)
        before = [0]*p["size"]
        # Two counters in one family, then overwrite only counter zero.
        entries = [(0b100, 1), (0b101, 2), (0b100, 3)]
        for (active, key, value), (k, v) in zip(p["slots"], entries):
            before[active] = 1
            put(before, key, k)
            put(before, value, v)
        before[p["enable"]] = 1
        circuit = MODEL.lookup_circuit(p)
        for query in range(8):
            put(before, p["query"], query)
            after = MODEL.simulate(circuit, before, lambda q: q % 4)
            self.assertEqual(get(after, p["output"]), {4: 3, 5: 2}.get(query, query % 4))

    def test_query_length_bits_and_zero_padded_value_are_part_of_key(self):
        p = MODEL.toy_layout(2, 4, 3)
        before = [0]*p["size"]
        # Bits 2/3 act as length tags; same payload is a different address.
        for (active, key, value), (k, v) in zip(p["slots"], ((0b0101, 1), (0b1001, 2))):
            before[active] = 1
            put(before, key, k)
            put(before, value, v)
        before[p["enable"]] = 1
        for query, answer in ((0b0101, 1), (0b1001, 2), (0b0001, 7)):
            put(before, p["query"], query)
            self.assertEqual(get(MODEL.simulate(MODEL.lookup_circuit(p), before, lambda _: 7), p["output"]), answer)

    def test_long_message_tail_reaches_base_and_never_short_key_overlay(self):
        p = MODEL.toy_layout(2, 4, 2, extra_tail_bits=2)
        before = [0]*p["size"]
        active, key, value = p["slots"][0]
        before[active] = before[p["enable"]] = 1
        # Low two head bits are payload, high two are the length tag.
        # A short (length 1) stored address shares its payload prefix with
        # both length-3 queries. Their extra actual message bits differ.
        put(before, key, 0b0101)
        put(before, value, 3)
        put(before, p["query"], 0b1101)
        circuit = MODEL.lookup_circuit(p)
        self.assertEqual(len(p["lookup_work"]), MODEL.resource_vector(2, 4, 2)["lookup_clean_work_wires"])
        for tail in (0, 1):
            put(before, p["query_tail"], tail)
            expected = before.copy()
            put(expected, p["output"], tail + 1)
            after = MODEL.simulate(circuit, before, lambda full: (full >> 4) + 1)
            self.assertEqual(after, expected)
            self.assertEqual(MODEL.simulate(circuit, after, lambda full: (full >> 4) + 1), before)

    def test_no_implicit_xor_of_duplicate_values(self):
        p = MODEL.toy_layout(2, 1, 1)
        before = [0]*p["size"]
        before[p["enable"]] = 1
        for active, _, value in p["slots"]:
            before[active] = 1
            put(before, value, 1)
        self.assertEqual(get(MODEL.simulate(MODEL.lookup_circuit(p), before, lambda _: 0), p["output"]), 1)

    def test_append_all_values_each_slot_and_inverse(self):
        for n in (1, 2, 3, 4, 8):
            p = MODEL.toy_layout(n, 2, 2)
            circuit = MODEL.append_circuit(p)
            for next_slot in range(n):
                for incoming in range(16):
                    before = [0]*p["size"]
                    # Old records are retained exactly, including duplicate keys.
                    for i in range(next_slot):
                        active, key, value = p["slots"][i]
                        before[active] = 1
                        put(before, key, i % 4)
                        put(before, value, (i + 1) % 4)
                    put(before, p["counter"], next_slot)
                    put(before, p["incoming"], incoming)
                    expected = before.copy()
                    active, key, value = p["slots"][next_slot]
                    expected[active] = 1
                    put(expected, key + value, incoming)
                    put(expected, p["counter"], next_slot + 1)
                    after = MODEL.simulate(circuit, before, lambda _: 0)
                    self.assertEqual(after, expected)
                    self.assertEqual(MODEL.simulate(circuit[::-1], after, lambda _: 0), before)

    def test_append_instruction_counts(self):
        for n, k, v in itertools.product((1, 2, 3, 4, 8), (1, 3, 7), (1, 3)):
            p = MODEL.toy_layout(n, k, v)
            observed = MODEL.gate_counts(MODEL.append_circuit(p))
            expected = MODEL.resource_vector(n, k, v)["append"]
            for name in ("cx", "ccx", "oracle"):
                self.assertEqual(observed[name], expected[name])
            self.assertLessEqual(observed["x"], expected["x_upper_bound"])

    def test_append_then_lookup_joint_chronology(self):
        p = MODEL.toy_layout(4, 2, 2)
        state = [0]*p["size"]
        history = []
        for key, value in ((1, 2), (2, 3), (1, 0), (1, 3)):
            put(state, p["incoming"], key + (value << 2))
            state = MODEL.simulate(MODEL.append_circuit(p), state, lambda _: 0)
            history.append((key, value))
            for query in range(4):
                put(state, p["query"], query)
                state[p["enable"]] = 1
                expected = dict(history).get(query, query)
                self.assertEqual(get(MODEL.simulate(MODEL.lookup_circuit(p), state, lambda x: x), p["output"]), expected)

    def test_missing_uncompute_negative_control(self):
        p = MODEL.toy_layout(2, 1, 1)
        initial = [0]*p["size"]
        initial[p["enable"]] = 1
        gates = MODEL.lookup_circuit(p)
        mutant = gates.copy()
        oracle_indices = [i for i, g in enumerate(gates) if g[0] == "oracle"]
        del mutant[oracle_indices[-1]]
        after = MODEL.simulate(mutant, initial, lambda _: 1)
        self.assertTrue(any(after[i] for i in p["lookup_work"]))

    def test_empty_log_enabled_base_circuit_and_count(self):
        query, output, work, enable = (0, 1), (2, 3), (4, 5), 6
        call = ("oracle", query, work)
        gates = [call] + [("ccx", enable, z, y) for z, y in zip(work, output)] + [call]
        cost = MODEL.resource_vector(0, 2, 2)["lookup"]
        self.assertEqual(MODEL.gate_counts(gates), {name: cost[name] for name in ("x", "cx", "ccx", "oracle")})
        for q, y, e in itertools.product(range(4), range(4), range(2)):
            before = [0]*7
            put(before, query, q)
            put(before, output, y)
            before[enable] = e
            expected = before.copy()
            put(expected, output, y ^ ((3-q) if e else 0))
            self.assertEqual(MODEL.simulate(gates, before, lambda x: 3-x), expected)

    def test_five_two_qubit_toffoli_decomposition_has_no_relative_phase(self):
        # V^2=X, and V is applied with exponent b-(a xor b)+a=2ab.
        v = (((1+1j)/2, (1-1j)/2), ((1-1j)/2, (1+1j)/2))
        vd = tuple(tuple(v[j][i].conjugate() for j in range(2)) for i in range(2))
        def apply(matrix, state):
            return [sum(matrix[i][j]*state[j] for j in range(2)) for i in range(2)]
        for a, b, t in itertools.product(range(2), repeat=3):
            state = [int(t == 0), int(t == 1)]
            if b:
                state = apply(v, state)
            bp = a ^ b
            if bp:
                state = apply(vd, state)
            bp ^= a
            if a:
                state = apply(v, state)
            self.assertEqual(bp, b)
            self.assertEqual(state, [int((t ^ (a & b)) == 0), int((t ^ (a & b)) == 1)])


class AccountingTests(unittest.TestCase):
    def test_real_source_provenance_and_lifetime_arithmetic(self):
        r = MODEL.report(ROOT, 3, 5, 64)
        self.assertEqual(r["programmed_key_max_bytes"], 215150)
        self.assertEqual(r["circuit"]["capacity"], 3*((1 << 20) + 2))
        self.assertEqual(r["lifetime"]["overlay_lookups"], 5 + 3*741)
        self.assertEqual(r["lifetime"]["base_xor_oracle_calls"], 2*(5 + 3*741))
        self.assertEqual(r["source_sha256_before"], r["source_sha256_after"])
        for name in ("profile_qualified", "full_resource_vector", "actual_input_collision_bridge", "physical_verification_workspace_certificate"):
            self.assertIs(r[name], False)

    def test_zero_requests_still_charges_enabled_base_query_dispatch(self):
        r = MODEL.report(ROOT, 0, 7, 64)
        self.assertEqual(r["lifetime"]["base_xor_oracle_calls"], 14)
        self.assertEqual(r["lifetime"]["append_operations"], 0)
        self.assertEqual(r["lifetime"]["overlay_elementary_gates_upper_bound"], 7*5*2112)

    def test_invalid_bounds_and_toy_size_refuse(self):
        for value in (True, 1.0, -1, 1 << 65):
            with self.assertRaises(ValueError):
                MODEL.report(ROOT, value, 0, 64)
        with self.assertRaises(ValueError):
            MODEL.report(ROOT, 1, 1, 18)
        with self.assertRaises(ValueError):
            MODEL.toy_layout(1 << 20, 4, 4)

    def test_frozen_receipt_tamper_refuses_before_parsing(self):
        original = Path.read_bytes
        def read(path):
            return b"not json" if path == ROOT/MODEL.RECEIPT else original(path)
        with patch.object(Path, "read_bytes", read):
            with self.assertRaisesRegex(ValueError, "frozen sampler"):
                MODEL.sources(ROOT)

    def test_pinned_rust_source_drift_refuses(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data + b"\n" if str(path).endswith("crates/iroha_zkp_vole/src/vole.rs") else data
        with patch.object(Path, "read_bytes", read):
            with self.assertRaisesRegex(ValueError, "reviewed sampler source"):
                MODEL.sources(ROOT)

    def test_sources_rechecked_after_accounting(self):
        real = MODEL.sources
        calls = 0
        def changed(root):
            nonlocal calls
            calls += 1
            pins, prior = real(root)
            if calls == 2:
                pins = {**pins, "changed": "yes"}
            return pins, prior
        with patch.object(MODEL, "sources", changed):
            with self.assertRaisesRegex(ValueError, "source drift"):
                MODEL.report(ROOT, 1, 1, 64)

    def test_cli_qualification_and_existing_output_refuse(self):
        args = [sys.executable, str(SCRIPT), "--root", str(ROOT), "--request-cap", "1",
                "--external-query-cap", "1", "--length-bits", "64", "--require-qualified"]
        run = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn('"profile_qualified": false', run.stdout)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/"occupied.json"
            output.write_text("keep")
            run = subprocess.run(args[:-1] + ["--output", str(output)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(output.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
