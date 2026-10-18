"""Boundary, independent traversal and refusal tests for the ideal sampler model."""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "parliament_ballot_ideal_sampler_accounting.py"
SPEC = importlib.util.spec_from_file_location("ideal_sampler_accounting", SCRIPT)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
ROOT = SCRIPT.parents[1]


class GeometryTests(unittest.TestCase):
    def test_actual_zero_frontiers_and_primitive_counts(self):
        for row, leaves, frontier, unmarked in (("candidate", 6400, 11, 6356),
                                                ("comparator", 61440, 12, 61406)):
            shape = M.geometry(row)
            opening = M.selected_opening(shape, bytes(32))
            self.assertEqual((shape["leaves"], opening["r"], opening["unmarked_internal"]),
                             (leaves, frontier, unmarked))
            self.assertEqual(opening["hidden"], [0] * shape["tau"])

    def test_frontier_descendants_partition_nonhidden_leaves(self):
        # Walk only descendants of sampled frontier roots, independently of the
        # ancestor-union implementation in the checker. Include nonzero selectors.
        for row in M.ROWS:
            shape = M.geometry(row)
            for value in (0, 1, 7, 257, 65535, 1 << (shape["delta"] - 1)):
                opening = M.selected_opening(shape, value.to_bytes(32, "little"))
                seen, internal, terminal = set(), 0, 0
                pending = list(opening["frontier_nodes"])
                while pending:
                    node = pending.pop()
                    self.assertNotIn(node, seen)
                    seen.add(node)
                    if node < shape["leaves"] - 1:
                        internal += 1
                        pending += [2 * node + 1, 2 * node + 2]
                    else:
                        terminal += 1
                self.assertEqual(internal, opening["unmarked_internal"])
                self.assertEqual(terminal, shape["leaves"] - shape["tau"])

    def test_lengths_and_all_grinding_bits_refuse(self):
        for row in M.ROWS:
            shape = M.geometry(row)
            for challenge in (b"", bytes(31), bytes(33), bytearray(32), "00" * 32):
                with self.assertRaises(ValueError):
                    M.selected_opening(shape, challenge)
            for bit in range(shape["delta"], 256):
                with self.assertRaisesRegex(ValueError, "grinding"):
                    M.selected_opening(shape, (1 << bit).to_bytes(32, "little"))

    def test_mutated_geometry_and_unknown_rows_refuse(self):
        with self.assertRaises(ValueError):
            M.geometry("legacy")
        shape = M.geometry("candidate")
        shape["limit"] = 1000
        with self.assertRaisesRegex(ValueError, "modified"):
            M.selected_opening(shape, bytes(32))

    def test_real_nonadmissible_challenge_refuses(self):
        # Deterministic search creates a negative input, not a cryptographic claim.
        import hashlib
        shape = M.geometry("candidate")
        found = False
        for counter in range(100):
            value = int.from_bytes(hashlib.sha256(counter.to_bytes(4, "little")).digest(), "little")
            value &= (1 << shape["delta"]) - 1
            try:
                M.selected_opening(shape, value.to_bytes(32, "little"))
            except ValueError as error:
                self.assertIn("threshold", str(error))
                found = True
                break
        self.assertTrue(found)


class ScheduleTests(unittest.TestCase):
    def test_all_branch_extremes_keep_primary_writes(self):
        cap = M.MAX_TRIALS
        for args in ((1, 0, "success"), (cap, 0, "success"),
                     (cap, 1, "exhausted_aux_success"),
                     (cap, cap, "exhausted_aux_success"),
                     (cap, cap, "exhausted_fallback")):
            value = M.schedule(*args)
            self.assertEqual(value["programmed_counter_writes"], args[0])
            self.assertEqual(value["trials"], sum(args[:2]))
            self.assertEqual(value["auxiliary_writes"], 0)
            self.assertEqual(value["ordinary_counter_hash_reads"], 0)
            self.assertFalse(value["observed_execution"])

    def test_inconsistent_counts_refuse(self):
        cap = M.MAX_TRIALS
        for args in ((1, 1, "success"), (cap - 1, 1, "exhausted_aux_success"),
                     (cap, 0, "exhausted_aux_success"), (cap, cap - 1, "exhausted_fallback"),
                     (cap, cap, "unknown"), (0, 0, "success"),
                     (cap + 1, 0, "success"), (cap, cap + 1, "exhausted_fallback")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                M.schedule(*args)

    def test_type_coercions_and_caps_refuse(self):
        for bad in (True, False, 1.0, "1", None, -1):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                M.schedule(bad, 0, "success")
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                M.schedule(1, bad, "success")
        self.assertEqual(M.bounded(1 << 64, 0, 1 << 64, "q"), 1 << 64)
        with self.assertRaises(ValueError):
            M.bounded((1 << 64) + 1, 0, 1 << 64, "q")


class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        M.verify_sources(ROOT)
        cls.model = M.load_model(ROOT)

    def case(self, row="candidate", role="vote", a=1, b=0, outcome="success", value=0):
        opening = M.selected_opening(M.geometry(row), value.to_bytes(32, "little"))
        return M.run_vector(self.model, ROOT, row, role, 1000, opening, M.schedule(a, b, outcome))

    def test_four_exact_aes_counts_independent_block_walk(self):
        expected = {("candidate", "registration"): 1871854,
                    ("candidate", "vote"): 2750500,
                    ("comparator", "registration"): 18056844,
                    ("comparator", "vote"): 26532528}
        for (row, role), wanted in expected.items():
            case = self.case(row, role)
            shape = M.geometry(row)
            width = (case["ell_hat_bits"] + 7) // 8
            # Count chunks directly instead of ceil formulas used by the model.
            row_blocks = len(list(range(0, width, 16)))
            u = case["selected_opening"]["unmarked_internal"]
            n = shape["leaves"] - shape["tau"]
            self.assertEqual(4 * u + n * (9 + row_blocks), wanted)
            self.assertEqual(case["primitive_work"]["AES256_blocks"], wanted)
            self.assertEqual(case["primitive_work"]["AES256_key_constructions"], u + 2 * n)

    def test_programmed_transcript_is_not_hashed(self):
        case = self.case(a=M.MAX_TRIALS)
        self.assertFalse(any(name.startswith("challenge_") for name in case["ordinary_backend_oracle_reads"]))
        self.assertEqual(case["programming"]["write_count"], M.MAX_TRIALS + 2)
        self.assertEqual(case["programming"]["ordinary_challenge_reads"], 0)
        self.assertEqual(case["ordinary_backend_read_count"], 704 + 33 + 4)
        self.assertEqual(case["ordinary_backend_oracle_reads"]["H5"]["calls"], 704)
        self.assertIn("H_mu", case["ordinary_backend_oracle_reads"])
        self.assertNotIn("message_shake256", case["concrete_public_preparation_hashes"])

    def test_random_draws_from_independent_serialized_field_list(self):
        for row in M.ROWS:
            for role in M.ROLES:
                case = self.case(row, role, 3)
                shape, ell = M.geometry(row), M.ROLES[role]
                sizes = [32] * 3 + [32] * case["selected_opening"]["r"]
                sizes += [112] * shape["tau"]
                sizes += [ell // 8] * shape["tau"]
                sizes += [(shape["gates"] + 7) // 8] * 10
                sizes += [16, 32, 264, 104, 128, 192]
                self.assertEqual(case["random_draw_bytes"]["total"], sum(sizes))

    def test_auxiliary_work_adds_randomness_and_search_not_writes(self):
        first = self.case(a=M.MAX_TRIALS, b=1, outcome="exhausted_aux_success")
        last = self.case(a=M.MAX_TRIALS, b=M.MAX_TRIALS, outcome="exhausted_fallback")
        self.assertEqual(first["programming"], last["programming"])
        self.assertEqual(first["ordinary_backend_read_count"], last["ordinary_backend_read_count"])
        self.assertEqual(last["random_draw_bytes"]["total"] - first["random_draw_bytes"]["total"],
                         32 * (M.MAX_TRIALS - 1))
        self.assertEqual(last["search_loop_upper_bounds"]["parent_visits_upper_bound"], 2 * M.MAX_TRIALS * 6399)

    def test_program_record_lengths_and_overwrite_storage(self):
        case = self.case(a=7)
        p = case["programming"]
        # Concatenation lengths from actual transcript fields, independent totals.
        k1 = sum((77, 64, 64, 32 * 6688, 880, 16, 32, 1))
        k2 = sum((77, 264, 128, 128, 6688, 1))
        self.assertEqual((p["challenge_1_key_bytes"], p["challenge_2_key_bytes"]), (k1, k2))
        self.assertEqual(p["counter_key_bytes"], sum((77, 104, 224, 4, 1)))
        self.assertEqual(p["record_payload_bytes"]["total"], k1 + 264 + k2 + 104 + 7 * 442)
        self.assertEqual(p["record_payload_bytes"]["total"], p["log_key_bytes"] + p["log_value_bytes"])
        self.assertTrue(p["append_log_allows_repeated_addresses"])

    def test_two_selected_admission_passes_and_one_padding_check(self):
        case = self.case()
        loops = case["reconstruction_loop_work"]
        self.assertEqual(loops["decode_challenge_bit_tests"], 512)
        self.assertEqual(loops["mark_hidden_parent_visits"], 2 * 6399)
        self.assertEqual(loops["revealed_node_parent_visits"], 2 * 6399)
        self.assertEqual(loops["opening_padding_byte_tests_upper_bound"], (229 - 11) * 32)
        self.assertNotIn("final_challenge_byte_comparisons_upper_bound", loops)

    def test_fold_merge_count_matches_binary_stack_walk(self):
        for row in M.ROWS:
            shape = M.geometry(row)
            merges, copies = 0, 0
            for depth, size in zip(shape["depths"], shape["sizes"]):
                for leaf in range(size):
                    level = 0
                    while (leaf >> level) & 1:
                        merges += 1
                        level += 1
                    copies += level < depth
            n = shape["leaves"] - shape["tau"]
            self.assertEqual(merges, n)
            self.assertEqual(copies, n)
            case = self.case(row)
            width = (case["ell_hat_bits"] + 7) // 8
            self.assertEqual(case["reconstruction_loop_work"]["conversion_fold_byte_xors"], 2 * merges * width)
            self.assertEqual(case["reconstruction_loop_work"]["conversion_stack_copy_bytes"], copies * width)

    def test_success_output_overlaps_fields_exhaustion_has_none(self):
        success = self.case(a=M.MAX_TRIALS)
        exhausted = self.case(a=M.MAX_TRIALS, b=1, outcome="exhausted_aux_success")
        proof = sum(self.model.proof_layout("candidate", "vote").values())
        self.assertEqual(success["named_request_payload_envelope_bytes"]["parts"]["returned_proof"], proof)
        self.assertEqual(exhausted["named_request_payload_envelope_bytes"]["parts"]["returned_proof"], 0)
        self.assertEqual(success["proof_serialization"]["field_length_checks"], 9)
        self.assertEqual(exhausted["proof_serialization"]["field_length_checks"], 0)

    def test_nonzero_fallback_and_tampered_facts_refuse(self):
        shape = M.geometry("candidate")
        zero = M.selected_opening(shape, bytes(32))
        plan = M.schedule(1, 0, "success")
        tampered = copy.deepcopy(zero)
        tampered["r"] += 1
        with self.assertRaisesRegex(ValueError, "opening facts"):
            M.run_vector(self.model, ROOT, "candidate", "vote", 3, tampered, plan)
        plan["trials"] += 1
        with self.assertRaisesRegex(ValueError, "schedule facts"):
            M.run_vector(self.model, ROOT, "candidate", "vote", 3, zero, plan)
        with self.assertRaisesRegex(ValueError, "fallback"):
            self.case(a=M.MAX_TRIALS, b=M.MAX_TRIALS, outcome="exhausted_fallback", value=1)

    def test_bad_role_seats_and_payload_counts_refuse(self):
        for bad in (2, 1001, True, 3.0):
            with self.assertRaises(ValueError):
                M.run_vector(self.model, ROOT, "candidate", "vote", bad,
                             M.selected_opening(M.geometry("candidate"), bytes(32)), M.schedule(1, 0, "success"))
        with self.assertRaises(ValueError):
            self.case(role="legacy")
        for value in (-1, True, 1.0):
            with self.assertRaises(ValueError):
                M.byte_vector({"bad": value})

    def test_lifetime_counts_q_and_requests_independently(self):
        case = self.case()
        result = M.lifetime([case], 7, 0)
        self.assertEqual(result["combined_backend_query_upper_bound"], 7 * 741)
        self.assertEqual(result["totals"]["programming_writes"], 21)
        self.assertEqual(result["request_payload_bytes_not_multiplied_by_lifetime"], case["named_request_payload_envelope_bytes"]["total"])
        large = M.lifetime([case], 7, 13)
        self.assertEqual(large["classical_external_log_record_inspections_upper_bound"], 13 * 21)
        self.assertEqual(large["classical_external_log_key_byte_comparisons_upper_bound"], 13 * 7 * case["programming"]["log_key_bytes"])
        self.assertIsNone(large["quantum_lookup_gate_cost"])
        for requests, queries in ((-1, 0), (True, 0), (1, -1), (1, 1 << 65)):
            with self.assertRaises(ValueError):
                M.lifetime([case], requests, queries)
        with self.assertRaises(ValueError):
            M.lifetime([], 1, 0)

    def test_empty_lifetime_has_no_simulator_work(self):
        value = M.report(ROOT, requests=0, external_queries=17)["all_opening_lifetime_envelope"]
        self.assertEqual(value["combined_backend_query_upper_bound"], 17)
        self.assertEqual(value["request_payload_bytes_not_multiplied_by_lifetime"], 0)
        self.assertTrue(all(count == 0 for count in value["totals"].values()))

    def test_all_opening_envelope_dominates_nonzero_patterns(self):
        report = M.report(ROOT)
        bound = report["all_opening_lifetime_envelope"]
        self.assertEqual(len(report["cases"]), 20)
        for row in M.ROWS:
            for role in M.ROLES:
                case = self.case(row, role, a=M.MAX_TRIALS, value=257)
                self.assertLessEqual(case["primitive_work"]["AES256_blocks"], bound["totals"]["AES256_blocks"])
                self.assertLessEqual(case["random_draw_bytes"]["total"], bound["totals"]["random_draw_bytes"])
                self.assertLessEqual(case["reconstruction_loop_work"]["correction_byte_xors_upper_bound"],
                                     bound["reconstruction_loop_totals_upper_bound"]["correction_byte_xors_upper_bound"])
        self.assertTrue(report["checked_logical_accounting"])
        for name in ("actual_simulator_execution", "complete_resource_vector", "compiled_memory_or_allocator_bound",
                     "quantum_gate_bound", "primitive_advantage_assumed", "actual_input_collision_bridge",
                     "independent_cryptographic_review", "profile_qualified", "production_gate_changed"):
            self.assertIs(report[name], False)


class RefusalTests(unittest.TestCase):
    def test_source_drift_refuses_before_helper_load(self):
        with mock.patch.object(M, "inventory", return_value={}), mock.patch.object(M, "load_model") as loader:
            with self.assertRaisesRegex(ValueError, "inventory changed"):
                M.report(ROOT)
            loader.assert_not_called()

    def test_changed_helper_bytes_are_never_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / M.MODEL
            path.parent.mkdir()
            path.write_text("raise RuntimeError('untrusted helper executed')\n")
            with self.assertRaisesRegex(ValueError, "helper changed"):
                M.load_model(root)

    def test_midrun_source_change_refuses(self):
        sources = M.verify_sources(ROOT)
        with mock.patch.object(M, "verify_sources", side_effect=[sources, {**sources, "changed": "bad"}]):
            with self.assertRaisesRegex(ValueError, "during accounting"):
                M.report(ROOT)

    def test_cli_source_failure_is_nonzero_and_false(self):
        out = io.StringIO()
        with mock.patch.object(M, "report", side_effect=ValueError("source changed")), contextlib.redirect_stdout(out):
            self.assertEqual(M.main(["--root", str(ROOT)]), 1)
        result = json.loads(out.getvalue())
        self.assertFalse(result["checked_logical_accounting"])
        self.assertFalse(result["profile_qualified"])

    def test_qualification_always_refuses_even_after_valid_accounting(self):
        with mock.patch.object(M, "report", return_value={"profile_qualified": False}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(M.main(["--root", str(ROOT), "--require-qualified"]), 2)

    def test_output_does_not_overwrite_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence"
            path.mkdir()
            target = path / "report.json"
            target.write_text("retain\n")
            with mock.patch.object(M, "report", return_value={"profile_qualified": False}):
                with self.assertRaises(FileExistsError):
                    M.main(["--root", str(ROOT), "--output", str(path)])
            self.assertEqual(target.read_text(), "retain\n")


class ChronologicalLogTests(unittest.TestCase):
    def test_exhaustive_small_overwrites_match_persistent_table(self):
        from itertools import product
        for keys in product((b"A", b"B", b"AB"), repeat=4):
            entries, table = [], {}
            for counter, key in enumerate(keys):
                value = bytes([counter])
                entries.append((key, value))
                table[key] = value
                for query in (b"A", b"B", b"AB", b"C", b""):
                    result = M.scan_log(entries, query)
                    self.assertEqual(result["value"], table.get(query))
                    self.assertLessEqual(result["record_inspections"], len(entries))
                    self.assertLessEqual(result["key_byte_comparisons"], sum(len(k) for k, _ in entries))

    def test_shorter_counter_family_does_not_delete_old_high_entries(self):
        prefix = b"same-prefix"
        entries = [(prefix + index.to_bytes(4, "little"), b"old" + bytes([index])) for index in range(5)]
        entries += [(prefix + index.to_bytes(4, "little"), b"new" + bytes([index])) for index in range(2)]
        for index in range(5):
            result = M.scan_log(entries, prefix + index.to_bytes(4, "little"))
            self.assertEqual(result["value"], (b"new" if index < 2 else b"old") + bytes([index]))

    def test_empty_and_bad_log_inputs(self):
        self.assertEqual(M.scan_log([], b"address"), {"value": None, "record_inspections": 0, "key_byte_comparisons": 0})
        for entries, query in (([("bad", b"value")], b"key"), ([(b"key", "bad")], b"key"), ([], "bad")):
            with self.assertRaises(ValueError):
                M.scan_log(entries, query)


if __name__ == "__main__":
    unittest.main()
