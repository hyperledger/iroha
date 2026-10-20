"""Finite state, framing and custody tests for the separate fixed-slot writer."""
from __future__ import annotations

from collections import Counter
import importlib.util
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/parliament_ballot_static_overlay.py"
SPEC = importlib.util.spec_from_file_location("static_overlay", SCRIPT)
MODEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODEL)
FRAMING = MODEL.load_reviewed(ROOT, MODEL.FRAMING)
LOOKUP = MODEL.load_reviewed(ROOT, MODEL.LOOKUP)


def put(bits, start, width, value):
    """Set a low-bit-first register in a finite test state."""
    for bit in range(width):
        bits[start + bit] = (value >> bit) & 1


def get(bits, start, width):
    """Read a low-bit-first register without changing it."""
    return sum(bits[start + bit] << bit for bit in range(width))


def tiny_shape(row, role, challenge):
    """Synthetic small frames; keep all three distinct domains and u32 counter."""
    del row, role
    fields = [("namespace_digest", 1)]
    if challenge == 2:
        fields += [("challenge_1", 1)]
    if challenge == 3:
        fields += [("challenge_2", 1), ("counter_u32_le", 4)]
    return dict(challenge=challenge, fields=fields, prefix=b"P", domain=challenge + 8,
                key_bytes=2 + sum(size for _, size in fields),
                value_bytes=32 if challenge == 3 else 1)


TINY = types.SimpleNamespace(shape=tiny_shape, scatter=FRAMING.scatter,
                             framing_counts=FRAMING.framing_counts)


def tiny_writer(request_index=0, trials=2, requests=2):
    """Use explicit synthetic caps only inside finite circuit tests."""
    return MODEL.StaticProgrammedWrites(TINY, "synthetic", "synthetic", requests,
                                        request_index, 4, trials=trials, key_bytes=8)


def remap_to_lookup(writer, lookup):
    """Join independent fixed-slot writer wires to the pinned lookup toy layout."""
    p = writer.layout()

    def mapped(wire):
        if wire < p["log_bits"]:
            return wire
        if wire == p["enable"]:
            return lookup["enable"]
        return lookup["incoming"][wire - p["incoming"]]

    return [(gate[0], *(mapped(wire) for wire in gate[1:])) for gate in writer.emit()]


class StaticOverlayTests(unittest.TestCase):
    """Check the emitted permutation, not only the accounting formulas."""

    def test_fixed_slot_all_values_disabled_nonzero_targets_and_inverse(self):
        for n, k, v in itertools.product((1, 3, 5), (1, 3), (1, 2)):
            for slot in range(n):
                writer = MODEL.StaticSlotWrite(n, k, v, slot)
                p, q = writer.layout(), k + v
                gates = list(writer.emit())
                self.assertEqual(list(writer.emit(inverse=True)), gates[::-1])
                observed = Counter(g[0] for g in gates)
                self.assertEqual((observed["x"], observed["cx"], observed["ccx"]), (0, 1, q))
                self.assertEqual(writer.resources()["gates"], MODEL.counts(cx=1, ccx=q))
                for enabled, incoming, target in itertools.product(
                        (0, 1), range(1 << q), (0, 1, (1 << (q + 1)) - 1)):
                    before = [0] * p["size"]
                    # Non-target old records need not be blank or unique.
                    for bit in range(p["log_bits"]):
                        before[bit] = bit % 2
                    put(before, p["target"], q + 1, target)
                    put(before, p["incoming"], q, incoming)
                    before[p["enable"]] = enabled
                    expected = before.copy()
                    put(expected, p["target"], q + 1, target ^ (enabled * (1 + 2 * incoming)))
                    after = LOOKUP.simulate(gates, before, lambda _: 0)
                    self.assertEqual(after, expected)
                    self.assertEqual(LOOKUP.simulate(gates[::-1], after, lambda _: 0), before)

    def test_disjoint_request_slots_and_exact_full_w0_counts(self):
        for trials in (1, 2, 3, 4):
            writer = tiny_writer(1, trials, 3)
            self.assertEqual([writer.slot(1), writer.slot(2)]
                             + [writer.slot(3, i) for i in range(trials)],
                             list(range(trials + 2, 2 * (trials + 2))))
            observed = Counter(g[0] for g in writer.emit())
            r = writer.resources()
            self.assertEqual({name: observed[name] for name in ("x", "cx", "ccx")},
                             {name: r["gates"][name] for name in ("x", "cx", "ccx")})
            self.assertEqual(r["clean_work_bits"], writer.record_bits + 33)
            self.assertEqual(r["counter_bits"], 0)
            self.assertEqual(r["auxiliary_writes"], 0)

    def test_w0_supplied_frames_validity_prefix_padding_and_cleanup(self):
        writer = tiny_writer()
        p = writer.layout()
        for valid, flags in itertools.product((0, 1), ((0, 0), (1, 0), (1, 1))):
            before = [0] * p["size"]
            for name, (start, width) in p["fields"].items():
                put(before, start, width, {"namespace_digest": 0x87, "challenge_1": 0x39,
                                          "challenge_2": 0xDA}[name])
            values = ((1 << 255) + 19, (1 << 256) - 7)
            for index, value in enumerate(values):
                put(before, p["primary"] + index * 256, 256, value)
                before[p["flags"] + index] = flags[index]
            before[p["valid"]] = valid
            after = LOOKUP.simulate(writer.emit(), before, lambda _: 0)
            expected = before.copy()
            for challenge, index in ((1, 0), (2, 0), (3, 0), (3, 1)):
                if not valid or (challenge == 3 and not flags[index]):
                    continue
                plan = writer.plans[challenge - 1]
                fields = {}
                for name, width in plan["fields"]:
                    value = index if name == "counter_u32_le" else get(before, *p["fields"][name])
                    fields[name] = value.to_bytes(width, "little")
                value = (values[index].to_bytes(32, "little") if challenge == 3 else
                         get(before, *p["fields"]["challenge_" + str(challenge)]).to_bytes(1, "little"))
                key, value = FRAMING.encode_record(plan, fields, value)
                base = p["log"] + writer.slot(challenge, index) * (1 + writer.record_bits)
                expected[base] = 1
                record = len(key) | (int.from_bytes(key, "little") << writer.length_bits)
                record |= int.from_bytes(value, "little") << writer.key_bits
                put(expected, base + 1, writer.record_bits, record)
            self.assertEqual(after, expected)  # includes all input and scratch preservation
            self.assertEqual(LOOKUP.simulate(writer.emit(inverse=True), after, lambda _: 0), before)

    def test_shorter_later_prefix_preserves_old_high_counter(self):
        p = LOOKUP.toy_layout(8, 3, 2)
        state = [0] * p["size"]
        # Two invocations, M=2: c0/c1 use slots2/3 then slots6/7. The last
        # invocation disables c1; it must not erase old slot3's c1 response.
        history = [(2, 4, 1, 1), (3, 5, 2, 1), (6, 4, 3, 1), (7, 5, 0, 0)]
        for slot, key, value, enabled in history:
            put(state, p["incoming"][0], 5, key | (value << 3))
            state[p["enable"]] = enabled
            gates = remap_to_lookup(MODEL.StaticSlotWrite(8, 3, 2, slot), p)
            state = LOOKUP.simulate(gates, state, lambda _: 0)
        state[p["enable"]] = 1
        for query in range(8):
            put(state, p["query"][0], 3, query)
            for old in range(4):
                put(state, p["output"][0], 2, old)
                expected = state.copy()
                put(expected, p["output"][0], 2, old ^ {4: 3, 5: 2}.get(query, query % 4))
                self.assertEqual(LOOKUP.simulate(LOOKUP.lookup_circuit(p), state, lambda q: q % 4), expected)

    def test_correlated_superposition_write_then_lookup_has_no_phase_or_residue(self):
        p = LOOKUP.toy_layout(3, 1, 1)
        gates = remap_to_lookup(MODEL.StaticSlotWrite(3, 1, 1, 2), p)
        gates += LOOKUP.lookup_circuit(p)
        # Sparse exact amplitudes; include a reference bit entangled with the
        # input record and query. Compare the entire joint state, including work.
        amplitudes, expected = {}, {}
        for reference, incoming, query, enabled, output in itertools.product(
                range(2), range(4), range(2), range(2), range(2)):
            before = [0] * (p["size"] + 1)
            before[-1] = reference
            before[p["enable"]] = enabled
            before[p["slots"][0][0]] = 1
            put(before, p["slots"][0][1][0], 1, reference)
            put(before, p["slots"][0][2][0], 1, 1)
            put(before, p["incoming"][0], 2, incoming)
            put(before, p["query"][0], 1, query)
            before[p["output"][0]] = output
            amplitude = (1 if incoming & 1 else -1) * (1j if reference else 1) / 8
            amplitudes[tuple(before)] = amplitude
            after = before.copy()
            active, key, value = p["slots"][2]
            after[active] = enabled
            after[key[0]], after[value[0]] = enabled * (incoming & 1), enabled * (incoming >> 1)
            answer = 1 if query == reference else query ^ 1
            if enabled and query == (incoming & 1):
                answer = incoming >> 1
            after[p["output"][0]] ^= enabled * answer
            expected[tuple(after)] = amplitude
        actual = {tuple(LOOKUP.simulate(gates, list(basis), lambda q: q ^ 1)): amplitude
                  for basis, amplitude in amplitudes.items()}
        self.assertEqual(actual, expected)
        self.assertEqual(sum(abs(a) ** 2 for a in actual.values()), 1)

    def test_actual_source_shapes_and_production_metadata_without_gate_expansion(self):
        for row, tau, gates in (("candidate", 33, 704), ("comparator", 22, 696)):
            for role, e in (("registration", 4480), ("vote", 6688)):
                report = MODEL.report(ROOT, 1 << 44, (1 << 44) - 1, row, role, 64)
                self.assertEqual([p["key_bytes"] for p in report["frames"]],
                                 [254 + (tau - 1) * e + 10 * ((gates + 7) // 8), 598 + e, 410])
                self.assertEqual([p["value_bytes"] for p in report["frames"]], [264, 104, 32])
                self.assertEqual([p["domain"] for p in report["frames"]], [9, 10, 11])
                self.assertEqual(report["writer"]["last_slot"], report["capacity"] - 1)
                self.assertFalse(report["writer"]["synthetic_reduced_trials"])
                self.assertEqual(report["inherited_lookup"]["oracle"], 2)
                self.assertEqual(report["source_sha256_before"], report["source_sha256_after"])
                for flag in ("full_root_driver_integrated", "full_resource_vector", "profile_qualified",
                             "physical_verification_workspace_certificate", "production_gate_changed"):
                    self.assertIs(report[flag], False)

    def test_refuses_malformed_dimensions_indices_and_non_bool_inverse(self):
        for args in ((True, 1, 1, 0), (0, 1, 1, 0), (1, 0, 1, 0), (1, 1, 0, 0),
                     (1, 1, 1, -1), (1, 1, 1, 1)):
            with self.assertRaises(ValueError):
                MODEL.StaticSlotWrite(*args)
        for trials in (0, True, MODEL.MAX_TRIALS + 1):
            with self.assertRaises(ValueError):
                tiny_writer(trials=trials)
        for requests, index in ((0, 0), (1, 1), (1, -1), (True, 0)):
            with self.assertRaises(ValueError):
                MODEL.StaticProgrammedWrites(FRAMING, "candidate", "vote", requests, index)
        for row, role, bits in (("bad", "vote", 64), ("candidate", "bad", 64), ("candidate", "vote", 8)):
            with self.assertRaises(ValueError):
                MODEL.StaticProgrammedWrites(FRAMING, row, role, 1, 0, bits)
        writer = tiny_writer()
        for challenge, index in ((0, 0), (4, 0), (1, 1), (3, 2), (3, True)):
            with self.assertRaises(ValueError):
                writer.slot(challenge, index)
        for emitter in (writer.emit, MODEL.StaticSlotWrite(1, 1, 1, 0).emit):
            with self.assertRaises(ValueError):
                next(emitter(inverse=1))
        for n in (0, 1, 2, 3, 31, MODEL.MAX_TRIALS):
            expected = (sum(i.bit_count() for i in range(n)) if n < 100 else 20 * (1 << 19))
            self.assertEqual(MODEL.population_sum(n), expected)
        with self.assertRaises(ValueError):
            MODEL.population_sum(True)

    def test_helper_custody_refuses_changed_or_unknown_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / MODEL.FRAMING
            path.parent.mkdir()
            path.write_text("raise RuntimeError('must not execute')\n")
            with self.assertRaisesRegex(ValueError, "reviewed helper changed"):
                MODEL.load_reviewed(root, MODEL.FRAMING)
        with self.assertRaisesRegex(ValueError, "unrecognized helper"):
            MODEL.load_reviewed(ROOT, "scripts/untrusted.py")

    def test_cli_help_fresh_output_and_qualification_refusal(self):
        command = [sys.executable, "-B", str(SCRIPT)]
        result = subprocess.run(command + ["--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--request-index", result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            args = ["--root", str(ROOT), "--request-cap", "1", "--output", str(path)]
            result = subprocess.run(command + args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            original = path.read_bytes()
            self.assertFalse(json.loads(original)["profile_qualified"])
            result = subprocess.run(command + args, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_bytes(), original)
        result = subprocess.run(command + ["--request-cap", "1", "--require-qualified"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)["profile_qualified"])


if __name__ == "__main__":
    unittest.main()
