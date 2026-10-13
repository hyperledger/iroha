"""Exact request-stage bounds, source refusal and qualification separation."""

from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "check_parliament_ballot_request_accounting.py"
SPEC = importlib.util.spec_from_file_location("request_accounting", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RequestAccountingTests(unittest.TestCase):
    """Check the accounting boundary without accepting cryptographic premises."""

    @classmethod
    def setUpClass(cls):
        cls.result = MODULE.report()

    def test_source_inventory_and_imported_count_code_match_review(self):
        inventory = MODULE.source_inventory(MODULE.ROOT)
        self.assertEqual(MODULE.inventory_digest(inventory), MODULE.REVIEWED_SOURCE_SHA256)
        self.assertIn(MODULE.MODEL_PATH.as_posix(), inventory)
        self.assertIn("crates/iroha_zkp_vole/src/codec.rs", inventory)
        self.assertIn("crates/iroha_parliament_ballot_proof/examples/resource_contract/budget.rs", inventory)
        self.assertTrue(self.result["source_matched"])

    def test_source_drift_refuses_before_loading_count_code(self):
        with patch.object(MODULE, "source_inventory", return_value={"changed": "bad"}), \
             patch.object(MODULE, "load_model", side_effect=AssertionError("must not run")):
            result = MODULE.report()
        self.assertFalse(result["candidate_request_component_checked"])
        self.assertFalse(result["source_matched"])
        self.assertIn("changed", result["failure"])

    def test_candidate_maximum_stages_and_exact_margins(self):
        vote = self.result["candidate_cases"][-1]
        self.assertEqual(vote["cold_preparation_keccak"], 7548)
        self.assertEqual(vote["ordinary_preparation_keccak"], 5140)
        self.assertEqual(vote["cold_preparation_excluding_H_mu"], 6602)
        self.assertEqual(vote["ordinary_preparation_excluding_H_mu"], 4194)
        stages = vote["stages"]
        self.assertEqual([s["logical_primitive_upper_bound"] for s in stages], [2408, 7548, 2766589])
        self.assertEqual([s["charged_backend_queries"] for s in stages], [0, 1, 744])
        self.assertEqual([Fraction(**s["margin"]) for s in stages],
                         [Fraction(1688), Fraction(65432, 185), Fraction(12753483, 185)])

    def test_all_admitted_sizes_and_registration_are_checked(self):
        self.assertTrue(self.result["candidate_request_component_checked"])
        self.assertEqual(self.result["candidate_vote_sizes_checked"], 998)
        self.assertTrue(self.result["candidate_vote_preparation_monotone"])
        registration = self.result["candidate_cases"][0]
        self.assertEqual(registration["cold_preparation_keccak"], 1442)
        self.assertEqual(registration["stages"][0]["logical_primitive_upper_bound"], 686)
        self.assertTrue(all(stage["inequality_holds"] for stage in registration["stages"]))

    def test_pointwise_and_cross_row_inferences_are_rejected(self):
        self.assertFalse(self.result["pointwise_4096_preparation_bound_valid"])
        self.assertFalse(self.result["candidate_coefficient_covers_comparator"])
        comparator = self.result["comparator_scope_countercheck"]
        self.assertFalse(comparator["stages"][-1]["inequality_holds"])
        self.assertEqual(comparator["stages"][-1]["charged_backend_queries"], 725)
        self.assertFalse(MODULE.stage("bad", 4097, 0)["inequality_holds"])
        with self.assertRaises(ValueError):
            MODULE.stage("invalid", -1, 0)

    def test_qualification_stays_false_and_cli_is_discoverable(self):
        for field in ("complete_primitive_resource_bound", "complete_gate_or_memory_bound", "profile_qualified"):
            self.assertIs(self.result[field], False)
        help_result = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("--require-qualified", help_result.stdout)
        result = subprocess.run([sys.executable, str(SCRIPT), "--require-qualified", "--json"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout), self.result)


if __name__ == "__main__":
    unittest.main()
