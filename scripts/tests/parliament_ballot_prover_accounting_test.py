"""Independent boundary and fail-closed checks for real-prover hash accounting."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "parliament_ballot_prover_accounting.py"
SPEC = importlib.util.spec_from_file_location("prover_accounting", SCRIPT)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class ByteSponge:
    """Byte-at-a-time state counter, independent of division/ceiling formulas."""

    def __init__(self, rate):
        self.rate = rate
        self.position = 0
        self.permutations = 0

    def absorb(self, size):
        for _ in range(size):
            self.position += 1
            if self.position == self.rate:
                self.permutations += 1
                self.position = 0

    def finalize_and_squeeze(self, size):
        # The padding is XORed into the partially filled rate block, even empty.
        self.permutations += 1
        self.position = 0
        for _ in range(size):
            if self.position == self.rate:
                self.permutations += 1
                self.position = 0
            self.position += 1


class SpongeTests(unittest.TestCase):
    def test_byte_walk_rate_padding_and_squeeze_boundaries(self):
        for rate in (72, 136):
            for length in (0, 1, rate - 1, rate, rate + 1, 2 * rate - 1, 2 * rate, 405):
                for output in (0, 1, 64, rate - 1, rate, rate + 1, 2 * rate, 2 * rate + 1):
                    with self.subTest(rate=rate, length=length, output=output):
                        state = ByteSponge(rate)
                        state.absorb(length // 3)
                        state.absorb(length - length // 3)
                        state.finalize_and_squeeze(output)
                        self.assertEqual(M.sponge(length, output, rate), state.permutations)

    def test_invalid_dimensions_and_negative_calls(self):
        for args in ((-1, 64, 136), (1, -1, 136), (1, 64, 168)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                M.sponge(*args)
        with self.assertRaises(ValueError):
            M.schedule([(-1, 1, 64, 136)])

    def test_schedule_tracks_work_and_bytes_separately(self):
        result = M.schedule([(3, 136, 137, 136), (1, 72, 64, 72)])
        self.assertEqual(result["calls"], 4)
        self.assertEqual(result["absorbed_bytes"], 480)
        self.assertEqual(result["squeezed_bytes"], 475)
        self.assertEqual(result["keccak_f1600"], 11)
        self.assertEqual(M.total({"one": result, "empty": M.schedule([])}), 11)


class CounterTests(unittest.TestCase):
    def test_cloned_prefix_executed_once_including_failed_attempts(self):
        for attempts in range(1, 41):
            prefix = ByteSponge(136)
            for size in (77, 104, 224):
                prefix.absorb(size)
            self.assertEqual((prefix.permutations, prefix.position), (2, 133))
            completed = prefix.permutations
            for _ in range(attempts):
                trial = ByteSponge(136)
                trial.position = prefix.position
                # Every attempt hashes before deciding grinding/opening success.
                trial.absorb(4)
                trial.absorb(1)
                trial.finalize_and_squeeze(32)
                completed += trial.permutations
            with self.subTest(attempts=attempts):
                result = M.counter_work(attempts)
                self.assertEqual(result["keccak_f1600"], completed)
                self.assertLessEqual(completed, result["ledger_upper_bound"])

    def test_zero_cap_and_rejected_counts(self):
        self.assertEqual(M.counter_work(0)["keccak_f1600"], 0)
        cap = M.counter_work(1 << 20)
        self.assertEqual(cap["keccak_f1600"], 2_097_154)
        self.assertEqual(cap["ledger_upper_bound"], 4_194_304)
        for value in (-1, (1 << 20) + 1, 1.5, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                M.counter_work(value)


class ProverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model, cls.helper_hash = M.load_model(M.ROOT)
        cls.tables = {row: cls.model.table_inventory(M.ROOT, row) for row in M.ROWS}

    def test_profile_serialization_and_actual_table_word_counts(self):
        self.assertEqual(self.tables["candidate"]["canonical_words"], 10538)
        self.assertEqual(self.tables["comparator"]["canonical_words"], 10463)
        for row, expected in (("candidate", 628), ("comparator", 624)):
            counts = M.profile_schedule(self.tables[row]["canonical_words"])
            self.assertEqual(M.total(counts), expected)
            self.assertEqual(counts["profile_descriptor_sha3_512"]["keccak_f1600"], 4)

    def test_literal_maxima_from_source_phase_walk(self):
        # Independent fixed expected values catch changes in either composed model.
        expected = {
            ("candidate", "registration"): (756, 9238, 2, 9996, 771, 10767),
            ("candidate", "vote"): (5140, 9773, 3, 14916, 4196, 19112),
            ("comparator", "registration"): (752, 54162, 2, 54916, 767, 55683),
            ("comparator", "vote"): (5136, 54518, 3, 59657, 4192, 63849),
        }
        for (row, role), wanted in expected.items():
            result = M.case(self.model, row, role, 1000, self.tables[row])
            actual = (M.total(result["ordinary_public_preparation"]),
                      M.total(result["backend_non_counter"]), result["witness_lane_evaluations"],
                      result["ordinary_prove_non_counter_keccak"], M.total(result["optional_for_secret_setup"]),
                      result["for_secret_then_prove_non_counter_keccak"])
            with self.subTest(row=row, role=role):
                self.assertEqual(actual, wanted)
                self.assertTrue(result["within_allowance"])
                self.assertTrue(result["verifier_schedule_crosscheck"])

    def test_both_gate_labels_and_no_h3_or_counter_in_backend(self):
        for row, gates, tau in (("candidate", 704, 33), ("comparator", 696, 22)):
            result = M.case(self.model, row, "vote", 3, self.tables[row])
            backend = result["backend_non_counter"]
            self.assertEqual(backend["H5"]["calls"], 2 * gates)
            self.assertEqual(backend["H5"]["keccak_f1600"], 4 * gates)
            self.assertEqual(backend["H1_vectors"]["calls"], tau)
            self.assertNotIn("H3", backend)
            self.assertNotIn("challenge_3", backend)
            self.assertEqual(result["successful_opening_extra_aes_blocks"], 9 * tau)
            self.assertEqual(result["failed_opening_extra_aes_blocks"], 0)

    def test_setup_has_one_credential_and_one_authorization_output(self):
        for role in M.WITNESS_BITS:
            result = M.setup_schedule(role, 3, 10538)["credential_lane_evaluations"]
            self.assertEqual(result["calls"], 2)
            self.assertEqual(result["absorbed_bytes"], 264)
            self.assertEqual(result["squeezed_bytes"], 192)
            self.assertEqual(result["keccak_f1600"], 2)

    def test_all_vote_sizes_are_monotone_and_within_maximum(self):
        for row, maximum in (("candidate", 19112), ("comparator", 63849)):
            last = 0
            for seats in range(3, 1001):
                value = M.case(self.model, row, "vote", seats, self.tables[row])
                current = value["for_secret_then_prove_non_counter_keccak"]
                self.assertLessEqual(last, current)
                self.assertLessEqual(current, maximum)
                self.assertTrue(value["verifier_schedule_crosscheck"])
                last = current
            self.assertEqual(last, maximum)

    def test_shape_rejection(self):
        for role, seats in (("other", 3), ("vote", 2), ("vote", 1001)):
            with self.subTest(role=role, seats=seats):
                for function in (M.frontend_schedule, M.setup_schedule):
                    with self.assertRaises(ValueError):
                        function(role, seats, 10538)
        for row, role in (("other", "vote"), ("candidate", "other")):
            with self.assertRaises(ValueError):
                M.backend_schedule(row, role)

    def test_unbounded_context_setup_is_explicitly_excluded(self):
        result = M.preimage_counterexample()
        length = (1 << 32) - 1
        # Literal Frame headers: u16 tag length, tag, u16 fields, u32 per field.
        self.assertEqual(result["policy"]["frame_bytes"], length + 42)
        self.assertEqual(result["proposal"]["frame_bytes"], length + 24)
        for item in result.values():
            self.assertGreater(item["keccak_f1600"], M.ALLOWANCE)
            self.assertFalse(item["fits_65536"])


class EvidenceTests(unittest.TestCase):
    def test_inventory_hash_is_order_independent(self):
        self.assertEqual(M.inventory_digest({"b": "2", "a": "1"}),
                         M.inventory_digest({"a": "1", "b": "2"}))
        self.assertNotEqual(M.inventory_digest({"b": "2"}), M.inventory_digest({"b": "3"}))

    def test_exact_helper_bytes_loaded_even_after_same_length_edit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / M.MODEL
            source.parent.mkdir()
            for payload, expected in ((b"value = 1\n", 1), (b"value = 2\n", 2)):
                source.write_bytes(payload)
                module, digest = M.load_model(root)
                self.assertEqual(module.value, expected)
                self.assertEqual(digest, hashlib.sha256(payload).hexdigest())

    def test_source_drift_refuses_before_executing_helper(self):
        with mock.patch.object(M, "source_inventory", return_value={"changed.rs": "bad"}), \
             mock.patch.object(M, "load_model") as loader:
            result = M.report()
        self.assertFalse(result["source_real_prover_component_checked"])
        self.assertFalse(result["source_matched"])
        loader.assert_not_called()

    def test_helper_drift_during_load_refuses(self):
        sources = M.source_inventory(M.ROOT)
        with mock.patch.object(M, "REVIEWED_SOURCE_SHA256", M.inventory_digest(sources)), \
             mock.patch.object(M, "load_model", return_value=(None, "changed")):
            result = M.report()
        self.assertFalse(result["source_real_prover_component_checked"])
        self.assertIn("during loading", result["failure"])

    def test_report_checks_all_shapes_and_does_not_qualify(self):
        result = M.report()
        self.assertTrue(result["source_real_prover_component_checked"], result.get("failure"))
        self.assertTrue(result["source_stable"])
        self.assertEqual(len(result["selected_cases"]), 8)
        for value in result["maxima"].values():
            self.assertEqual(value["vote_sizes_checked"], 998)
            self.assertTrue(value["vote_cost_monotone"])
        for key in ("profile_qualified", "complete_honest_oracle_or_simulator_bound",
                    "complete_primitive_resource_bound", "complete_gate_or_memory_bound"):
            self.assertFalse(result[key])

    def test_midrun_source_drift_does_not_publish_component_success(self):
        sources = M.source_inventory(M.ROOT)
        changed = {**sources, "drift": "changed"}
        with mock.patch.object(M, "REVIEWED_SOURCE_SHA256", M.inventory_digest(sources)), \
             mock.patch.object(M, "source_inventory", side_effect=[sources, changed]):
            result = M.report()
        self.assertFalse(result["source_real_prover_component_checked"])
        self.assertFalse(result["source_stable"])

    def test_cli_refuses_qualification_and_failed_component(self):
        for checked, arguments, expected in ((True, [], 0), (True, ["--require-qualified"], 2),
                                              (False, ["--json"], 1)):
            result = {"source_real_prover_component_checked": checked, "profile_qualified": False}
            with mock.patch.object(M, "report", return_value=result), \
                 mock.patch("sys.argv", [str(SCRIPT), *arguments]), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(M.main(), expected)
            if "--json" in arguments:
                self.assertFalse(json.loads(output.getvalue())["profile_qualified"])


if __name__ == "__main__":
    unittest.main()
