"""Exact arithmetic, interval and fail-closed tests for the conditional calculator."""

import argparse
from decimal import Decimal, ROUND_DOWN, localcontext
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "parliament_ballot_conditional_composition.py"
SPEC = importlib.util.spec_from_file_location("conditional_composition", SCRIPT)
CALCULATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CALCULATOR)


class ConditionalCompositionTests(unittest.TestCase):
    """Check the stated formulas without asserting adversary advantage bounds."""

    def test_counts_reject_nonintegers_booleans_and_negative_values(self):
        for invalid in (True, False, -1, 1.0, "1", None, Fraction(1), Decimal("1")):
            with self.subTest(value=invalid):
                with self.assertRaises(ValueError):
                    CALCULATOR.calculate_terms(invalid, 0)
                with self.assertRaises(ValueError):
                    CALCULATOR.calculate_terms(0, invalid)

    def test_zero_formula_does_not_qualify(self):
        terms = CALCULATOR.calculate_terms(0, 0)
        for name, value in terms.items():
            with self.subTest(name=name):
                self.assertEqual(value, (Fraction(0), Fraction(0)) if isinstance(value, tuple) else 0)
        self.assertFalse(CALCULATOR.build_report(0, 0)["qualified"])

    def test_exact_components_and_once_only_sum(self):
        # 2Q + 2T = 16 gives an independently known exact rational square root.
        terms = CALCULATOR.calculate_terms(3, 5)
        material = Fraction(3 * (10 + 260 * 6 + 33 * (36 + 419 * 418 // 2)), 2**128)
        own_label = Fraction(3, 2**256)
        deletion = Fraction(2 * (5 + 704 * 3), 2**128) + Fraction(3, 2**256)
        exact_h5 = 704 * 3 * (Fraction(4, 2**256) + Fraction(16, 2**513))
        self.assertEqual(terms["material_switching"], material)
        self.assertEqual(terms["own_label"], own_label)
        self.assertEqual(terms["deletion_unclipped"], deletion)
        self.assertEqual(terms["deletion"], deletion)
        h5_lower, h5_upper = terms["h5_reprogramming"]
        self.assertLessEqual(h5_lower, exact_h5)
        self.assertLessEqual(exact_h5, h5_upper)
        for total, h5 in zip(terms["known_unclipped"], terms["h5_reprogramming"]):
            self.assertEqual(total, material + h5 + own_label + deletion)
        self.assertEqual(terms["known_clipped_at_one"], terms["known_unclipped"])

    def test_square_root_grid_exact_squares(self):
        for value, expected in ((Fraction(0), Fraction(0)), (Fraction(9, 4), Fraction(3, 2)),
                                (Fraction(4), Fraction(2)), (Fraction(1, 100), Fraction(1, 10))):
            with self.subTest(value=value):
                self.assertEqual(CALCULATOR.sqrt_enclosure(value), (expected, expected))

    def test_square_root_enclosures_use_integer_rational_certificates(self):
        # Include a rational square whose root does not fit the fixed decimal grid.
        for value in (Fraction(2, 3), Fraction(2), Fraction(1, 9),
                      Fraction(1, 2**512), Fraction(10**300, 7)):
            with self.subTest(value=value):
                lower, upper = CALCULATOR.sqrt_enclosure(value)
                self.assertLessEqual(lower**2, value)
                self.assertLess(value, upper**2)
                self.assertEqual(upper - lower, Fraction(1, 10**120))
        for invalid in (-1, Fraction(-1), True, 2.0, Decimal("2")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                CALCULATOR.sqrt_enclosure(invalid)

    def test_exact_formulas_at_default_ceiling(self):
        t, q = 2**44, 2**64
        terms = CALCULATOR.calculate_terms()
        self.assertEqual(terms["material_switching"], Fraction(2_892_601, 2**84))
        self.assertEqual(terms["own_label"], Fraction(1, 2**212))
        self.assertEqual(terms["deletion_unclipped"],
                         Fraction(q + 704 * t, 2**127) + Fraction(t * (t - 1), 2**257))

    def test_monotonic_in_each_input_including_clipped_region(self):
        values = (0, 1, 2, 10, 2**44, 2**64, 2**128)
        for fixed in (0, 1, 2**64):
            for vary_invocations in (True, False):
                previous = CALCULATOR.calculate_terms(0, fixed) if vary_invocations else CALCULATOR.calculate_terms(fixed, 0)
                for value in values:
                    current = CALCULATOR.calculate_terms(value, fixed) if vary_invocations else CALCULATOR.calculate_terms(fixed, value)
                    for name in current:
                        older, newer = previous[name], current[name]
                        if isinstance(older, tuple):
                            for old_endpoint, new_endpoint in zip(older, newer):
                                self.assertLessEqual(old_endpoint, new_endpoint)
                        else:
                            self.assertLessEqual(older, newer)
                    previous = current

    def test_deletion_is_clipped_at_one_before_known_sum(self):
        for queries, unclipped in ((2**127 - 1, Fraction(2**127 - 1, 2**127)),
                                   (2**127, Fraction(1)), (2**128, Fraction(2))):
            terms = CALCULATOR.calculate_terms(0, queries)
            self.assertEqual(terms["deletion_unclipped"], unclipped)
            self.assertEqual(terms["deletion"], min(Fraction(1), unclipped))
            self.assertEqual(terms["known_unclipped"], (terms["deletion"],) * 2)
        terms = CALCULATOR.calculate_terms(2**128, 2**128)
        self.assertGreater(terms["deletion_unclipped"], 1)
        self.assertEqual(terms["deletion"], 1)
        self.assertGreater(terms["known_unclipped"][0], 1)
        self.assertEqual(terms["known_clipped_at_one"], (Fraction(1), Fraction(1)))
        self.assertEqual(terms["known_unclipped"][0], terms["material_switching"]
                         + terms["h5_reprogramming"][0] + terms["own_label"] + 1)

    def test_fraction_records_preserve_exact_values(self):
        for value in (Fraction(0), Fraction(2, 3), Fraction(2**512 + 1, 2**256)):
            record = CALCULATOR.fraction_record(value)
            self.assertEqual(Fraction(int(record["numerator"]), int(record["denominator"])), value)
            self.assertIsInstance(record["approximate_decimal"], str)
        report = CALCULATOR.build_report()
        self.assertEqual(report["inputs"], {"T": str(2**44), "Q_all": str(2**64)})

    def test_unknowns_and_scope_remain_explicit_at_every_size(self):
        for t, q in ((0, 0), (2**44, 2**64), (2**256, 2**256)):
            report = CALCULATOR.build_report(t, q)
            for name in ("initial_programming_bound", "aes_advantage_sum", "full_driver_resources"):
                self.assertIsNone(report[name])
            self.assertIs(report["qualified"], False)
            self.assertNotIn("security_total", report)
            self.assertIn("not adversary advantage", report["known_contribution"]["interval_target"])
            self.assertIn("not a security lower bound", report["known_contribution"]["interval_target"])
            self.assertIn("invalid-request", report["input_scope"]["Q_all"])

    def test_report_is_independent_of_ambient_decimal_precision(self):
        expected = json.dumps(CALCULATOR.build_report(), sort_keys=True, allow_nan=False)
        with localcontext() as context:
            context.prec = 3
            context.rounding = ROUND_DOWN
            actual = json.dumps(CALCULATOR.build_report(), sort_keys=True, allow_nan=False)
        self.assertEqual(actual, expected)

    def test_cli_decimal_parser_is_strict(self):
        self.assertEqual(CALCULATOR.decimal_count("0"), 0)
        self.assertEqual(CALCULATOR.decimal_count(str(2**128)), 2**128)
        for invalid in ("", "-1", "+1", "1.0", "1e2", "true", " 1", "１"):
            with self.subTest(value=invalid), self.assertRaises(argparse.ArgumentTypeError):
                CALCULATOR.decimal_count(invalid)

    def test_cli_defaults_are_deterministic_json(self):
        first = subprocess.run([sys.executable, str(SCRIPT), "--json"], text=True, capture_output=True, check=True)
        second = subprocess.run([sys.executable, str(SCRIPT)], text=True, capture_output=True, check=True)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stderr, "")
        self.assertEqual(json.loads(first.stdout), CALCULATOR.build_report())

    def test_cli_require_qualified_always_fails_with_report(self):
        for extra in ([], ["--invocations", "0", "--queries", "0"],
                      ["--invocations", str(2**256), "--queries", str(2**256)]):
            result = subprocess.run([sys.executable, str(SCRIPT), "--require-qualified", *extra], text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIs(json.loads(result.stdout)["qualified"], False)
            self.assertIn("Not qualified", result.stderr)

    def test_cli_invalid_inputs_fail_before_report(self):
        for option, value in (("--invocations", "-1"), ("--queries", "true"), ("--queries", "1.5")):
            result = subprocess.run([sys.executable, str(SCRIPT), option, value], text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("nonnegative decimal integer", result.stderr)


if __name__ == "__main__":
    unittest.main()
