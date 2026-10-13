"""Independent arithmetic and fail-closed checks for the B6 ledger (stdlib only)."""

from contextlib import redirect_stdout
from decimal import Decimal, localcontext
from fractions import Fraction
import importlib.util
import io
from itertools import product
import json
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check_parliament_ballot_security_ledger.py"
SPEC = importlib.util.spec_from_file_location("ballot_security_ledger", SCRIPT)
LEDGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEDGER)


def exhaustive_opening_average(sizes: tuple[int, ...]) -> Fraction:
    """Enumerate all selections and count sibling disclosures, without the A(v) formula."""
    labels = LEDGER.leaf_vectors(sizes)
    first_leaf = len(labels) - 1
    positions = [[first_leaf + i for i, label in enumerate(labels) if label == vector]
                 for vector in range(len(sizes))]
    total, selections = 0, 0
    for selected in product(*positions):
        marked = set(selected)
        for leaf in selected:
            node = leaf
            while node:
                node = (node - 1) // 2
                marked.add(node)
        total += sum(1 for parent in range(first_leaf) if parent in marked
                     for child in (2 * parent + 1, 2 * parent + 2) if child not in marked)
        selections += 1
    return Fraction(total, selections)


class LedgerTests(unittest.TestCase):
    """Exercise exact arithmetic separately from high-precision diagnostics."""

    @classmethod
    def setUpClass(cls):
        cls.report = LEDGER.build_report()

    def test_heap_formula_matches_independent_enumeration(self):
        for sizes in ((1,), (2,), (2, 2), (3, 2), (4, 2, 1), (4, 4, 2)):
            with self.subTest(sizes=sizes):
                self.assertEqual(LEDGER.expected_opening_seeds(sizes), exhaustive_opening_average(sizes))

    def test_final_heap_exact_numerator_and_markov_bound(self):
        actual = LEDGER.expected_opening_seeds((256,) * 17 + (128,) * 16)
        self.assertEqual(actual * 2**248, LEDGER.EXPECTED_SEED_NUMERATOR)
        self.assertLess(actual, 222)
        self.assertGreater((1 - actual / 230) / 256, Fraction(1, 7360))

    def test_budget_includes_counter_ceiling_and_certificate(self):
        self.assertEqual(LEDGER.oracle_budget(), 36918944040625374208)
        self.assertEqual(LEDGER.oracle_budget(0), 1447 * 2**44 + 2**64 + 1024)
        with self.assertRaises(ValueError):
            LEDGER.oracle_budget(-1)

    def test_every_exact_threshold_has_the_claimed_adjacent_values(self):
        for name, row in self.report["soundness_conditional_exact_thresholds"].items():
            cutoff = row["largest_q_strictly_below"]
            target = Fraction(1, 2) if name.endswith("half") else Fraction(1, 2**64)
            self.assertLess(LEDGER.soundness(cutoff, name.startswith("batch")), target)
            self.assertGreaterEqual(LEDGER.soundness(cutoff + 1, name.startswith("batch")), target)
        self.assertIsNone(LEDGER.last_integer_below(lambda q: Fraction(q + 1), Fraction(1)))

    def test_batch_does_not_multiply_global_leaf_failure(self):
        leaf = 33 * (1 - Fraction(1, 2**256)) / 2**256
        self.assertEqual(LEDGER.soundness(batch=True) - leaf, 1001 * (LEDGER.soundness() - leaf))

    def test_p1_at_zero_is_already_six_times_2pow_minus64(self):
        with localcontext() as context:
            context.prec = LEDGER.PRECISION
            computed = LEDGER.known_terms(0)["epsilon_P1"]
            self.assertEqual(computed, LEDGER.dec(Fraction(6, 2**64)))
        self.assertIsNone(self.report["written_Z_2pow_minus64_query_cutoff_at_fixed_T"])

    def test_decimal_diagnostics_stable_at_higher_precision(self):
        def evaluate(precision):
            with localcontext() as context:
                context.prec = precision
                return {name: format(LEDGER.dec(value), ".24E")
                        for name, value in LEDGER.known_terms().items()}
        self.assertEqual(evaluate(160), evaluate(220))

    def test_main_numeric_terms_match_recorded_ledger(self):
        recorded = {"epsilon_P1": "3.3306706621e-16", "K_sim": "2.16986018285e-19",
                    "D_sw": "1.49586152902e-19", "epsilon_initial": "7.6702489205e-33"}
        for name, expected in recorded.items():
            actual = Decimal(self.report["known_terms"][name]["decimal"])
            self.assertLess(abs(actual / Decimal(expected) - 1), Decimal("2e-11"))

    def test_interactive_coefficients_match_independently_recorded_values(self):
        rows = self.report["interactive_components_not_added_to_adaptive_soundness"]
        recorded = {"candidate_registration": "8.00003187801758", "candidate_vote": "8.00023624506764",
                    "comparator_registration": "8.00204017513642", "comparator_vote": "8.01511964380443"}
        for name, expected in recorded.items():
            actual = Decimal(rows[name]["coefficient"]["decimal"])
            self.assertLess(abs(actual - Decimal(expected)), Decimal("5e-15"))

    def test_statistical_budget_checks_the_sum_and_switching(self):
        checks = self.report["checks"]
        self.assertTrue(checks["listed_statistical_union_excluding_switching_below_budget"])
        self.assertTrue(checks["direct_switching_exceeds_statistical_budget"])
        terms = self.report["known_terms"]
        self.assertGreater(Decimal(terms["listed_statistical_union_with_direct_switching"]["decimal"]), Decimal(2) ** -128)

    def test_frame_bound_charges_output_blocks_and_xor_conversion(self):
        row = LEDGER.frame_collision_diagnostic(5, 72)
        self.assertEqual(row["output_message_blocks_total"], 4)
        self.assertEqual(row["swap_queries_plus_twice_output_blocks"], 18)
        self.assertIsNone(row["concrete_frame_bound"])
        self.assertIsNone(LEDGER.frame_collision_diagnostic(2**800)["collision_upper_bound"])

    def test_inventory_does_not_certify_omitted_costs(self):
        inventory = self.report["resource_inventory"]
        self.assertEqual(inventory["commitment_aes_blocks"], 2764797)
        self.assertEqual(inventory["simulator_max_total_uniform_256bit_draws"], 2**65)
        self.assertEqual(inventory["simulator_max_bits_for_those_draws"], 2**73)
        self.assertIsNone(inventory["total_primitive_bound"])
        self.assertIsNone(inventory["total_runtime_gate_memory_resource_vector"])
        self.assertIsNone(inventory["final_comparison_allowance"])

    def test_nominal_table_never_populates_missing_bounds(self):
        self.assertTrue(self.report["arithmetic_checks_pass"])
        self.assertFalse(self.report["qualified"])
        self.assertFalse(self.report["production_approved"])
        self.assertTrue(all(value is None for value in self.report["unknown_required_bounds_or_evidence"].values()))
        self.assertTrue(all(value is None for value in self.report["certified_complete_query_thresholds"].values()))
        nominal = self.report["nominal_substitution_not_qualification"]
        self.assertLess(Decimal(nominal["anonymity_and_unlinkability"]["decimal"]), Decimal("0.5"))
        self.assertGreater(Decimal(nominal["joint_zero_knowledge"]["decimal"]), Decimal(2) ** -64)

    def test_cli_qualification_fails_closed_and_json_is_deterministic(self):
        first, second = io.StringIO(), io.StringIO()
        with redirect_stdout(first):
            self.assertEqual(LEDGER.main(["--json"]), 0)
        with redirect_stdout(second):
            self.assertEqual(LEDGER.main(["--json", "--require-qualified"]), 2)
        self.assertEqual(first.getvalue(), second.getvalue())
        self.assertFalse(json.loads(first.getvalue())["qualified"])

    def test_invalid_inputs_are_rejected(self):
        for sizes in ((), (0,), (-1, 2)):
            with self.assertRaises(ValueError):
                LEDGER.expected_opening_seeds(sizes)
        with self.assertRaises(ValueError):
            LEDGER.known_terms(-1)
        with self.assertRaises(ValueError):
            LEDGER.frame_collision_diagnostic(-1)


if __name__ == "__main__":
    unittest.main()
