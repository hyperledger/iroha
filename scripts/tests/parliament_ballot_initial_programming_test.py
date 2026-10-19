"""Exact certificates and fail-closed tests for conditional initial programming."""

from decimal import Decimal, ROUND_DOWN, localcontext
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "parliament_ballot_initial_programming.py"
SPEC = importlib.util.spec_from_file_location("initial_programming", SCRIPT)
CALCULATOR = importlib.util.module_from_spec(SPEC)
# Match direct CLI execution's sibling-module lookup without retaining a path edit.
sys.path.insert(0, str(SCRIPT.parent))
try:
    SPEC.loader.exec_module(CALCULATOR)
finally:
    sys.path.pop(0)


class InitialProgrammingTests(unittest.TestCase):
    """Check formula values, never assert actual adversary advantage bounds."""

    def assert_sqrt_certificate(self, value):
        lower, upper = CALCULATOR.relative_sqrt_enclosure(value)
        self.assertGreaterEqual(lower, 0)
        self.assertLessEqual(lower**2, value)
        self.assertLessEqual(value, upper**2)
        # Square the relative-error inequality so this check is rational too.
        self.assertLessEqual((upper - lower)**2 * 2**800, value)
        return lower, upper

    def test_exact_dyadic_squares_and_zero_collapse(self):
        cases = ((Fraction(0), Fraction(0)), (Fraction(9, 4), Fraction(3, 2)),
                 (Fraction(1, 2**2112), Fraction(1, 2**1056)),
                 (Fraction(2**1200), Fraction(2**600)))
        for value, root in cases:
            with self.subTest(value=value):
                self.assertEqual(self.assert_sqrt_certificate(value), (root, root))

    def test_non_grid_rational_square_has_two_certified_endpoints(self):
        lower, upper = self.assert_sqrt_certificate(Fraction(1, 9))
        self.assertLess(lower, Fraction(1, 3))
        self.assertLess(Fraction(1, 3), upper)
        self.assertEqual(upper - lower, Fraction(1, 2**402))

    def test_tiny_irrational_roots_retain_relative_precision(self):
        for value in (Fraction(3, 2**2112), Fraction(1, 3 * 2**2112),
                      Fraction(2 * 2**64 + 2**44, 2**2112)):
            with self.subTest(value=value):
                lower, upper = self.assert_sqrt_certificate(value)
                self.assertGreater(lower, 0)
                self.assertGreater(upper, lower)
                self.assertLess((upper - lower) * 2**399, lower)

    def test_exponent_boundaries_and_large_roots_are_certified(self):
        for exponent in (-2113, -2112, -1, 0, 1, 799, 800, 801, 1201):
            power = Fraction(2**exponent) if exponent >= 0 else Fraction(1, 2**-exponent)
            for factor in (Fraction(3, 4), Fraction(1), Fraction(5, 4), Fraction(2)):
                with self.subTest(exponent=exponent, factor=factor):
                    self.assert_sqrt_certificate(power * factor)

    def test_square_root_rejects_non_fraction_and_negative_inputs(self):
        for invalid in (Fraction(-1), -1, 1, True, 1.0, Decimal("1"), "1"):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                CALCULATOR.relative_sqrt_enclosure(invalid)

    def test_entry_counts_and_coefficients_are_charged_once(self):
        terms = CALCULATOR.calculate_terms(3, 5)
        self.assertEqual(terms["qhat"], 13)
        self.assertEqual(CALCULATOR.MAX_TRIALS, 2**20)
        for name, entropy, repeats in (("challenge_1", 256, 3),
                                        ("challenge_2", 2112, 3),
                                        ("challenge_3", 832, 3 * 2**20)):
            product = Fraction(13, 2**entropy)
            lower, upper = terms["components"][name]
            # Remove the independently specified multiplier/linear term, then
            # certify the remaining square root, rather than call it again.
            root_lower = lower / repeats - product / 2
            root_upper = upper / repeats - product / 2
            self.assertLessEqual(root_lower**2, product)
            self.assertLessEqual(product, root_upper**2)
            self.assertLessEqual((root_upper - root_lower)**2 * 2**800, product)
        for index in (0, 1):
            self.assertEqual(terms["entry_unclipped"][index],
                             sum(value[index] for value in terms["components"].values()))

    def test_entry_exact_power_case_matches_independent_closed_form(self):
        # qhat=16 makes all three roots exact dyadic values on the chosen grid.
        terms = CALCULATOR.calculate_terms(2, 7)
        expected = {
            "challenge_1": 2 * (Fraction(4, 2**128) + Fraction(8, 2**256)),
            "challenge_2": 2 * (Fraction(4, 2**1056) + Fraction(8, 2**2112)),
            "challenge_3": 2 * 2**20 * (Fraction(4, 2**416) + Fraction(8, 2**832)),
        }
        self.assertEqual(terms["components"], {name: (value, value) for name, value in expected.items()})
        self.assertEqual(terms["entry_unclipped"], (sum(expected.values()),) * 2)

    def test_defaults_and_tiny_component_are_not_rounded_to_zero(self):
        terms = CALCULATOR.calculate_terms()
        self.assertEqual(terms["qhat"], 2**65 + 2**44)
        lower, upper = terms["components"]["challenge_2"]
        self.assertGreater(lower, 0)
        self.assertLess(upper, Fraction(1, 2**979))
        self.assertLess(upper - lower, lower / 2**399)

    def test_monotonic_entry_and_combination_across_grid_changes(self):
        values = (0, 1, 2, 3, 4, 7, 8, 15, 16, 2**44, 2**64, 2**128)
        for fixed in (0, 1, 2**64):
            for vary_t in (True, False):
                previous = None
                for count in values:
                    current = CALCULATOR.calculate_terms(count, fixed) if vary_t else CALCULATOR.calculate_terms(fixed, count)
                    if previous is not None:
                        intervals = list(current["components"].items()) + [
                            (name, current[name]) for name in (
                                "entry_unclipped", "entry_clipped_at_one", "combined_known_unclipped",
                                "combined_known_clipped_at_one",
                            )
                        ]
                        for name, interval in intervals:
                            prior = previous["components"][name] if name in previous["components"] else previous[name]
                            for old, new in zip(prior, interval):
                                self.assertLessEqual(old, new)
                    previous = current

    def test_combination_clips_entry_but_keeps_post_entry_K_unclipped(self):
        for t, q in ((0, 0), (3, 5), (2**44, 2**64), (2**128, 2**128)):
            terms = CALCULATOR.calculate_terms(t, q)
            sibling = CALCULATOR.composition.calculate_terms(t, q)
            self.assertEqual(terms["post_entry_K"], sibling["known_unclipped"])
            for index in (0, 1):
                clipped_entry = min(Fraction(1), terms["entry_unclipped"][index])
                self.assertEqual(terms["entry_clipped_at_one"][index], clipped_entry)
                self.assertEqual(terms["combined_known_unclipped"][index],
                                 clipped_entry + sibling["known_unclipped"][index])
                self.assertEqual(terms["combined_known_clipped_at_one"][index],
                                 min(Fraction(1), terms["combined_known_unclipped"][index]))
        self.assertGreater(terms["entry_unclipped"][0], 1)
        self.assertGreater(terms["post_entry_K"][0], 1)
        self.assertGreater(terms["combined_known_unclipped"][0], 2)
        self.assertEqual(terms["combined_known_clipped_at_one"], (Fraction(1), Fraction(1)))

    def test_input_validation_is_shared_and_rejects_coercions(self):
        for invalid in (True, False, -1, 1.0, "1", None, Fraction(1), Decimal("1")):
            with self.subTest(value=invalid):
                with self.assertRaises(ValueError):
                    CALCULATOR.calculate_terms(invalid, 0)
                with self.assertRaises(ValueError):
                    CALCULATOR.calculate_terms(0, invalid)

    def test_report_unknowns_scope_and_exact_records(self):
        for t, q in ((0, 0), (2**44, 2**64), (2**128, 2**128)):
            report = CALCULATOR.build_report(t, q)
            self.assertIs(report["qualified"], False)
            self.assertIsNone(report["aes_advantage_sum"])
            self.assertIsNone(report["full_driver_resources"])
            self.assertNotIn("security_total", report)
            self.assertIn("not adversary advantage", report["combined_known_contribution"]["interval_target"])
            self.assertIn("not a security lower bound", report["combined_known_contribution"]["interval_target"])
            self.assertIn("conditional initial-programming", report["scope"])
            self.assertEqual(report["inputs"], {"T": str(t), "Q_all": str(q)})
            terms = CALCULATOR.calculate_terms(t, q)
            for index, side in enumerate(("lower", "upper")):
                record = report["conditional_initial_programming"]["unclipped"][side]
                exact = Fraction(int(record["numerator"]), int(record["denominator"]))
                self.assertEqual(exact, terms["entry_unclipped"][index])

    def test_report_ignores_ambient_decimal_precision(self):
        expected = json.dumps(CALCULATOR.build_report(), sort_keys=True, allow_nan=False)
        with localcontext() as context:
            context.prec = 3
            context.rounding = ROUND_DOWN
            actual = json.dumps(CALCULATOR.build_report(), sort_keys=True, allow_nan=False)
        self.assertEqual(actual, expected)

    def test_cli_deterministic_default_and_explicit_json(self):
        first = subprocess.run([sys.executable, str(SCRIPT)], text=True, capture_output=True, check=True)
        second = subprocess.run([sys.executable, str(SCRIPT), "--json"], text=True, capture_output=True, check=True)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stderr, "")
        self.assertEqual(json.loads(first.stdout), CALCULATOR.build_report())

    def test_cli_require_qualified_fails_including_zero_inputs(self):
        for extra in ([], ["--invocations", "0", "--queries", "0"],
                      ["--invocations", str(2**128), "--queries", str(2**128)]):
            result = subprocess.run([sys.executable, str(SCRIPT), "--require-qualified", *extra], text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIs(json.loads(result.stdout)["qualified"], False)
            self.assertIn("Not qualified", result.stderr)

    def test_cli_invalid_counts_fail_without_a_report(self):
        for option, value in (("--invocations", "-1"), ("--queries", "true"), ("--queries", "1.5")):
            result = subprocess.run([sys.executable, str(SCRIPT), option, value], text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("nonnegative decimal integer", result.stderr)


if __name__ == "__main__":
    unittest.main()
