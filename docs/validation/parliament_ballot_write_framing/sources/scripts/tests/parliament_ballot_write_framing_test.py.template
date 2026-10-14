"""Check source-bound framing bytes and composed reversible staging behavior."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import itertools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("write_framing", ROOT / "scripts/parliament_ballot_write_framing.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def fields_for(plan):
    """Give every field distinct reproducible byte patterns, including endian probes."""
    result = {name: bytes((17*i+3*j+1) & 255 for j in range(size))
              for i, (name, size) in enumerate(plan["fields"])}
    if "counter_u32_le" in result:
        result["counter_u32_le"] = (0x01020304).to_bytes(4, "little")
    return result


def bits(data):
    return [byte >> bit & 1 for byte in data for bit in range(8)]


def run(gates, state):
    """Small independent classical basis interpreter; no shared simulator import."""
    for gate in gates:
        op, *wires = gate
        if len(wires) != len(set(wires)):
            raise AssertionError("aliased gate")
        if op == "x":
            state[wires[0]] ^= 1
        elif op == "cx":
            state[wires[1]] ^= state[wires[0]]
        elif op == "ccx":
            state[wires[2]] ^= state[wires[0]] & state[wires[1]]
        else:
            raise AssertionError(op)
    return state


def set_sources(p, fields, value, state):
    for name, data in dict(fields, value=value).items():
        start, width = p["inputs"][name]
        assert width == len(data)*8
        state[start:start+width] = bits(data)


def expected_staging(plan, fields, value, b, capacity, value_capacity):
    """Independent encoding, with explicit actual field order per source transcript."""
    if plan["challenge"] == 1:
        body = fields["mu"]+fields["commitment"]+fields["corrections"]+fields["mult_corrections"]+fields["iv_pre"]+fields["salt"]
    elif plan["challenge"] == 2:
        body = fields["challenge_1"]+fields["u_tilde"]+fields["d_tilde"]+fields["masked_witness"]
    else:
        body = fields["challenge_2"]+fields["a0"]+fields["coefficients"]+fields["counter_u32_le"]
    key = b"PARL/FAEST/v1"+fields["namespace_digest"]+body+bytes([8+plan["challenge"]])
    return [len(key) >> i & 1 for i in range(b)] + bits(key+bytes(capacity-len(key))) + bits(value+bytes(value_capacity-len(value)))


class FramingTest(unittest.TestCase):
    def test_actual_shape_bytes_and_domain_last_all_rows_roles(self):
        lengths = {("candidate", "registration"): (144494, 5078),
                   ("candidate", "vote"): (215150, 7286),
                   ("comparator", "registration"): (95204, 5078),
                   ("comparator", "vote"): (141572, 7286)}
        for (row, role), (k1, k2) in lengths.items():
            for challenge, key_length, value_length in ((1, k1, 264), (2, k2, 104), (3, 410, 32)):
                plan = M.shape(row, role, challenge)
                fields = fields_for(plan)
                value = bytes([0xa5])*value_length
                key, output = M.encode_record(plan, fields, value)
                expected = expected_staging(plan, fields, value, 20, key_length, value_length)
                self.assertEqual(bits(key)+bits(output), expected[20:])
                self.assertEqual((len(key), len(output)), (key_length, value_length))
                self.assertEqual(key[-1], challenge+8)
                if challenge == 3:
                    self.assertEqual(key[-5:-1], b"\x04\x03\x02\x01")
                    self.assertEqual(key[181:213], fields["a0"])

    def test_scatter_actual_largest_frame_then_inverse_restores_input(self):
        plan = M.shape("candidate", "vote", 1)
        p = M.layout(plan, 64)
        fields = fields_for(plan)
        value = bytes(range(256))+bytes(range(8))
        state = bytearray(p["staging_end"])
        set_sources(p, fields, value, state)
        initial = bytes(state)
        run(M.scatter(p), state)
        self.assertEqual(state[:p["source_end"]], initial[:p["source_end"]])
        self.assertEqual(list(state[p["staging_start"]:]), expected_staging(plan, fields, value, 64, 215150, 264))
        run(M.scatter(p, inverse=True), state)
        self.assertEqual(bytes(state), initial)

    def test_actual_padded_challenge_two_and_three(self):
        for role, challenge in itertools.product(M.ROLES, (2, 3)):
            plan = M.shape("comparator", role, challenge)
            p = M.layout(plan, 32)
            fields = fields_for(plan)
            value = bytes([0x5d])*plan["value_bytes"]
            state = bytearray(p["staging_end"])
            set_sources(p, fields, value, state)
            run(M.scatter(p), state)
            self.assertEqual(list(state[p["staging_start"]:]), expected_staging(plan, fields, value, 32, 215150, 264))
            run(M.scatter(p, inverse=True), state)
            self.assertFalse(any(state[p["staging_start"]:]))

    def test_counts_match_emitted_gates_and_exact_value_independence(self):
        for row, role, challenge in itertools.product(M.ROWS, M.ROLES, (1, 2, 3)):
            plan = M.shape(row, role, challenge)
            p = M.layout(plan, 64)
            actual = {"x": 0, "cx": 0}
            for gate in M.scatter(p):
                actual[gate[0]] += 2
            counted = M.framing_counts(plan, 64)
            self.assertEqual((actual["x"], actual["cx"]), (counted["x_exact"], counted["cnot_exact"]))
            self.assertEqual(counted["elementary_gates_exact"], sum(actual.values()))
            self.assertLessEqual(sum(actual.values()), counted["elementary_gates_simple_upper_bound"])
            self.assertEqual(counted["additional_base_oracle_calls"], 0)
            self.assertEqual(counted["additional_clean_work_wires"], 0)

    def test_schedule_success_and_both_exhaustion_branches(self):
        for row, role in itertools.product(M.ROWS, M.ROLES):
            first = M.schedule_counts(row, role, 1, 0, "success", 64)
            last = M.schedule_counts(row, role, M.MAX_TRIALS, 0, "success", 64)
            aux_first = M.schedule_counts(row, role, M.MAX_TRIALS, 1, "exhausted_aux_success", 64)
            aux_last = M.schedule_counts(row, role, M.MAX_TRIALS, M.MAX_TRIALS, "exhausted_aux_success", 64)
            fallback = M.schedule_counts(row, role, M.MAX_TRIALS, M.MAX_TRIALS, "exhausted_fallback", 64)
            increment = M.framing_counts(M.shape(row, role, 3), 64)["elementary_gates_exact"]
            self.assertEqual(last["elementary_gates_exact"]-first["elementary_gates_exact"], (M.MAX_TRIALS-1)*increment)
            for s in (last, aux_first, aux_last, fallback):
                self.assertEqual(s["append_operations"], M.MAX_TRIALS+2)
                self.assertEqual(s["auxiliary_writes"], 0)
                self.assertEqual(s["elementary_gates_exact"], last["elementary_gates_exact"])

    def test_composed_append_collision_history_preserves_sources_and_cleans_staging(self):
        circuit = M.load_circuit(ROOT)
        # Small exact same affine packing construction: constant prefix/domain,
        # two variable bytes (namespace and counter), and one value byte.
        plan = {"prefix": b"P", "domain": 11, "fields": [("namespace", 1), ("counter", 1)],
                "key_bytes": 4, "value_bytes": 1}
        # Explicit disjoint wire assignment for the already-reviewed general
        # append emitter; the older convenience toy_layout caps keys at16 bits.
        cursor = 0
        def take(n):
            nonlocal cursor
            result = list(range(cursor, cursor+n))
            cursor += n
            return result
        log = {"slots": [(take(1)[0], take(48), take(16)) for _ in range(3)],
               "counter": take(2), "incoming": take(64), "append_flag": take(1)[0],
               "append_ladder": []}
        log["size"] = cursor
        incoming = log["incoming"]
        self.assertEqual(incoming, list(range(incoming[0], incoming[0]+64)))
        p = M.layout(plan, 8, key_capacity=5, value_capacity=2,
                     source_offset=log["size"], staging_offset=incoming[0])
        M.require_disjoint_append(p, log)
        for location in ("counter", "append_ladder"):
            changed = dict(log, **{location: [p["source_start"]]})
            with self.assertRaises(ValueError): M.require_disjoint_append(p, changed)
        with self.assertRaises(ValueError):
            M.require_disjoint_append(p, dict(log, append_flag=p["source_start"]))
        with self.assertRaises(ValueError):
            M.require_disjoint_append(p, dict(log, incoming=list(reversed(incoming))))
        bad_slot = (log["slots"][0][0], log["slots"][0][1][1:], log["slots"][0][2])
        with self.assertRaises(ValueError):
            M.require_disjoint_append(p, dict(log, slots=[bad_slot]+log["slots"][1:]))
        # Newest overwrite followed by a different counter leaves both addresses.
        state = [0]*max(log["size"], p["source_end"])
        append = circuit.append_circuit(log)
        frames = [(b"A", b"\x01", b"\x05"), (b"A", b"\x01", b"\x07"), (b"A", b"\x02", b"\x09")]
        expected_records = []
        for index, (namespace, counter, value) in enumerate(frames):
            fields = {"namespace": namespace, "counter": counter}
            set_sources(p, fields, value, state)
            before_sources = state[p["source_start"]:p["source_end"]]
            before_all = list(state)
            prepare = list(M.scatter(p))
            run(prepare, state)
            key = b"P"+namespace+counter+b"\x0b"
            expected = bits(b"\x04"+key+b"\0"+value+b"\0")
            self.assertEqual([state[i] for i in incoming], expected)
            run(append, state)
            self.assertEqual([state[i] for i in incoming], expected)
            run(M.scatter(p, inverse=True), state)
            self.assertEqual(state[p["source_start"]:p["source_end"]], before_sources)
            self.assertFalse(any(state[i] for i in incoming+log["append_ladder"]+[log["append_flag"]]))
            expected_records.append(expected)
            for slot_index, (active, keys, values) in enumerate(log["slots"]):
                self.assertEqual(state[active], int(slot_index <= index))
                self.assertEqual([state[i] for i in keys+values], expected_records[slot_index] if slot_index <= index else [0]*64)
            # Inverse of the entire composition recovers the previous log as well.
            restored = list(state)
            run(prepare+list(reversed(append))+list(reversed(prepare)), restored)
            self.assertEqual(restored, before_all)
        # Independent overwrite model checks collision policy, including retained older records.
        newest = {b"P"+n+c+b"\x0b": v for n, c, v in frames}
        self.assertEqual(newest[b"PA\x01\x0b"], b"\x07")
        self.assertEqual(newest[b"PA\x02\x0b"], b"\x09")

    def test_mutations_expose_dirty_staging_wrong_domain_endian_and_padding(self):
        plan = M.shape("candidate", "registration", 3)
        p = M.layout(plan, 16, key_capacity=410, value_capacity=32)
        fields, value = fields_for(plan), bytes([3])*32
        state = [0]*p["staging_end"]
        set_sources(p, fields, value, state)
        expected = expected_staging(plan, fields, value, 16, 410, 32)
        gates = list(M.scatter(p))
        run(gates, state)
        self.assertEqual(state[p["staging_start"]:], expected)
        omitted_cleanup = list(state)
        run(gates[1:], omitted_cleanup)
        self.assertTrue(any(omitted_cleanup[p["staging_start"]:]))
        wrong_endian = dict(fields, counter_u32_le=fields["counter_u32_le"][::-1])
        self.assertNotEqual(expected_staging(plan, wrong_endian, value, 16, 410, 32), expected)
        changed_domain = dict(plan, domain=9)
        different = M.layout(changed_domain, 16, key_capacity=410, value_capacity=32)
        other = [0]*different["staging_end"]
        set_sources(different, fields, value, other)
        run(M.scatter(different), other)
        self.assertNotEqual(other[different["staging_start"]:], expected)
        padded = M.layout(plan, 16, key_capacity=411, value_capacity=33)
        dirty = [0]*padded["staging_end"]
        set_sources(padded, fields, value, dirty)
        dirty[-1] = 1
        run(M.scatter(padded), dirty)
        run(M.scatter(padded, inverse=True), dirty)
        self.assertEqual(dirty[-1], 1)  # Clean staging is a premise, never manufactured for free.

    def test_invalid_geometry_inputs_and_aliases_refuse(self):
        plan = M.shape("candidate", "registration", 3)
        for b in (True, 1.5, 0, 8, 4097):
            with self.assertRaises(ValueError): M.layout(plan, b)
        for invalid in (True, -1, 1.5, 4):
            with self.assertRaises(ValueError): M.shape("candidate", "vote", invalid)
        with self.assertRaises(ValueError): M.shape("unsupported", "vote", 1)
        with self.assertRaises(ValueError): M.layout(plan, 64, staging_offset=1)
        with self.assertRaises(ValueError): M.layout(dict(plan, key_bytes=411), 64)
        with self.assertRaises(ValueError): M.layout(dict(plan, fields=[("same", 1), ("same", 1)]), 64)
        with self.assertRaises(ValueError): M.layout(dict(plan, domain=True), 64)
        with self.assertRaises(ValueError): M.layout(plan, 64, value_capacity=31)
        with self.assertRaises(ValueError): list(M.scatter(M.layout(plan, 64), inverse=1))
        fields = fields_for(plan)
        for invalid in ({}, dict(fields, extra=b"x"), dict(fields, counter_u32_le=b"\0")):
            with self.assertRaises(ValueError): M.encode_record(plan, invalid, bytes(32))
        with self.assertRaises(ValueError): M.encode_record(plan, fields, bytes(31))
        for args in ((0, 0, "success"), (1, 1, "success"), (1, 0, "exhausted_fallback"), (M.MAX_TRIALS, 0, "exhausted_aux_success")):
            with self.assertRaises(ValueError): M.schedule_counts("candidate", "vote", *args, 64)

    def test_provenance_and_receipt_drift_refuse_before_report(self):
        original = Path.read_bytes
        for name in (M.RECEIPT, M.CIRCUIT, "crates/iroha_zkp_vole/src/transcript.rs", "crates/iroha_parliament_ballot_proof/src/profile.rs"):
            target = ROOT/name
            def changed(path, target=target):
                data = original(path)
                return data+b"\n" if path == target else data
            with patch.object(Path, "read_bytes", changed), self.assertRaises(ValueError):
                M.sources(ROOT)
        with patch.object(Path, "read_bytes", lambda path: b"changed"), self.assertRaises(ValueError):
            M.load_circuit(ROOT)
        walk = Path.rglob
        def extra(path, pattern):
            found = list(walk(path, pattern))
            if str(path).endswith("iroha_zkp_vole/src"):
                found.append(path/"unreviewed.rs")
            return iter(found)
        with patch.object(Path, "rglob", extra), self.assertRaises(ValueError): M.sources(ROOT)

    def test_report_exact_upper_units_zero_and_false_flags(self):
        r = M.report(ROOT, 3, 64)
        self.assertEqual(len(r["frames"]), 12)
        self.assertEqual(len(r["schedules"]), 20)
        self.assertEqual(r["source_sha256_before"], r["source_sha256_after"])
        total = r["lifetime"]
        self.assertEqual(total["framing_elementary_gates_upper_bound"], 3*max(s["elementary_gates_exact"] for s in r["schedules"]))
        self.assertEqual(total["simple_payload_derived_upper_bound"], 6*((2**20+2)*64+8*463693396))
        self.assertLessEqual(total["framing_elementary_gates_upper_bound"], total["simple_payload_derived_upper_bound"])
        for flag in ("full_resource_vector", "actual_input_collision_bridge", "independent_cryptographic_review", "profile_qualified", "physical_verification_workspace_certificate", "production_gate_changed"):
            self.assertIs(r[flag], False)
        self.assertTrue(r["shared_length_width_satisfies_prior_honest_envelope"])
        narrow = M.report(ROOT, 1, 18)
        self.assertFalse(narrow["shared_length_width_satisfies_prior_honest_envelope"])
        self.assertEqual(narrow["prior_combined_interface_honest_read_envelope_bytes"], 6882996)
        zero = M.report(ROOT, 0, 64)
        self.assertEqual(zero["lifetime"]["framing_elementary_gates_upper_bound"], 0)
        self.assertEqual(zero["lifetime"]["existing_staging_wires_reused"], 0)
        for value in (True, -1, 1.1, 2**64+1):
            with self.assertRaises(ValueError): M.report(ROOT, value, 64)

    def test_cli_refuses_qualification_and_overwrite(self):
        arguments = ["--root", str(ROOT), "--request-cap", "1", "--length-bits", "64"]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(M.main(arguments+["--require-qualified"]), 2)
        self.assertFalse(json.loads(output.getvalue())["full_resource_vector"])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"report.json"
            self.assertEqual(M.main(arguments+["--output", str(path)]), 0)
            before = path.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                M.main(arguments+["--output", str(path)])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
