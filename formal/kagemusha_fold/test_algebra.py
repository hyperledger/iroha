"""Independent coefficient, degree, finite-field and essential-hypothesis controls."""

import hashlib
from itertools import product
import json
from pathlib import Path
import unittest

from algebra import Ring, abort_coefficient, recurrence


class FoldAlgebra(unittest.TestCase):
    def test_laurent_operations_and_denominator_refusal(self):
        ring = Ring(2, 101)
        x, inv_x, y = ring.variable(0), ring.variable(0, -1), ring.variable(1)
        self.assertEqual(ring.multiply(x, inv_x), ring.constant(1))
        self.assertEqual(ring.multiply(ring.add(x, y), ring.add(x, ring.multiply(ring.constant(-1), y))),
                         ring.add(ring.variable(0, 2), ring.multiply(ring.constant(-1), ring.variable(1, 2))))
        self.assertEqual(ring.evaluate(ring.multiply(inv_x, y), [2, 3]), 52)
        self.assertEqual(ring.constant(101), {})
        with self.assertRaises(ValueError):
            ring.degree(inv_x)
        with self.assertRaises(ValueError):
            ring.inner([x], [])
        with self.assertRaises(ValueError):
            ring.evaluate(inv_x, [0, 3])
        with self.assertRaises(ValueError):
            ring.evaluate(x, [1])

    def test_exact_leading_coefficients_and_degrees(self):
        for k in range(1, 5):
            n = 1 << k
            for sources in ([[2] * k], [[], [2] * k], [[-1] * k, [3] * k, [2]]):
                with self.subTest(k=k, sources=sources):
                    ring, original, rounds, generator = recurrence(k, sources, [1] * n)
                    self.assertTrue(original[-1])
                    d = len(sources) - 1
                    for j, row in enumerate(rounds):
                        h, denominator = row["half"], row["denominator"]
                        left_degree, right_degree = n - h - 1, 2 * n - h - 1
                        self.assertEqual(max(e[1] for e in row["left_aux"]), left_degree)
                        self.assertEqual(max(e[1] for e in row["right_aux"]), right_degree)
                        self.assertEqual(ring.coefficient(row["left_aux"], 1, left_degree),
                                         ring.multiply(denominator, row["last_a"]))
                        self.assertEqual(ring.coefficient(row["right_aux"], 1, right_degree),
                                         ring.multiply(ring.constant(-1), denominator, denominator, original[-1]))
                        # Set all earlier u variables to zero only after clearing.
                        constant_u = {e: c for e, c in row["last_a"].items() if not any(e[3:])}
                        self.assertEqual(constant_u, original[-1])
                        self.assertLessEqual(ring.degree(row["left"]), d + 2 * j + n - h)
                        self.assertLessEqual(ring.degree(row["right"]), d + 2 * j + 2 * n - h)
                    self.assertLessEqual(ring.degree(generator), k)
                    self.assertEqual(generator.get((0,) * (k + 3)), 1)

    def test_known_dependent_logs_cannot_erase_auxiliary_polynomial(self):
        k, n = 3, 8
        for modulus in (5, 101):
            for logs in ([1] * n, [1, -1] * 4, list(range(1, 5)) * 2):
                for auxiliary in (1, -1):
                    with self.subTest(modulus=modulus, logs=logs, auxiliary=auxiliary):
                        ring, _, rounds, _ = recurrence(k, [[1, -1, 2], [2]], logs, auxiliary, modulus)
                        for row in rounds:
                            for side in ("left", "right"):
                                coefficient = ring.coefficient(row[side], 2, 1)
                                self.assertTrue(coefficient)
                                self.assertEqual(coefficient, ring.multiply(ring.constant(auxiliary), row[side + "_aux"]))

    def test_symbolic_rounds_match_scalar_recurrence(self):
        # Concrete challenge zero is legal for alpha/z/zeta; only round u is inverted.
        modulus, k = 101, 3
        sources, logs = [[2, 3, 4], [5]], list(range(1, 9))
        ring, original, rounds, final = recurrence(k, sources, logs, 7, modulus)
        for values in ([0, 0, 0, 1, 2, 3], [1, 1, 1, 2, 3, 4], [3, 4, 5, 6, 7, 8]):
            _, z, zeta, *challenges = values
            a = [ring.evaluate(poly, values) for poly in original]
            b, g = [pow(z, i, modulus) for i in range(8)], logs.copy()
            a[0] = (a[0] - sum(x * y for x, y in zip(a, b))) % modulus
            denominator = 1
            for row, u in zip(rounds, challenges):
                h = len(a) // 2
                left = sum(a[i + h] * (g[i] + 7 * zeta * b[i]) for i in range(h)) % modulus
                right = sum(a[i] * (g[i + h] + 7 * zeta * b[i + h]) for i in range(h)) % modulus
                self.assertEqual(ring.evaluate(row["left"], values), denominator * left % modulus)
                self.assertEqual(ring.evaluate(row["right"], values), denominator * right % modulus)
                a = [(a[i] + pow(u, -1, modulus) * a[i + h]) % modulus for i in range(h)]
                b = [(b[i] + u * b[i + h]) % modulus for i in range(h)]
                g = [(g[i] + u * g[i + h]) % modulus for i in range(h)]
                denominator = denominator * u % modulus
            self.assertEqual(ring.evaluate(final, values), g[0])

    def test_full_length_hypothesis_has_a_short_only_counterexample(self):
        for k in range(1, 5):
            _, original, rounds, _ = recurrence(k, [[2] * (k - 1)], [1] * (1 << k))
            self.assertEqual(original[-1], {})
            self.assertEqual(rounds[0]["left"], {})

    def test_missing_shift_changes_the_right_leading_coefficient(self):
        ring, original, rounds, _ = recurrence(3, [[2, 3, 4]], [1] * 8)
        self.assertNotEqual(ring.coefficient(rounds[0]["right_aux"], 1, 11), {})
        # Without a_0 -= H(z), the first R auxiliary has degree at most n-1.
        unshifted = ring.inner(original[:4], [ring.variable(1, i) for i in range(4, 8)])
        self.assertEqual(ring.coefficient(unshifted, 1, 11), {})

    def test_union_bound_sums_all_rounds_at_native_depth(self):
        for k in (1, 2, 4, 16):
            for inputs in (1, 2, 4, 17):
                n, d = 1 << k, inputs - 1
                explicit = sum((d + 2 * j + n - (n >> (j + 1))) +
                               (d + 2 * j + 2 * n - (n >> (j + 1))) for j in range(k)) + 2 * k
                self.assertEqual(abort_coefficient(k, inputs), explicit)
        self.assertEqual(abort_coefficient(16, 1), 3_015_170)
        self.assertEqual(abort_coefficient(16, 4), 3_015_266)

    def test_exhaustive_small_field_exception_union(self):
        # With m=1 alpha drops out. Enumerate every remaining challenge tape,
        # including zero and all tapes following an earlier exceptional message.
        modulus = 17
        for logs in ([1, 1], [1, -1], [3, 5]):
            ring, _, rounds, generator = recurrence(1, [[2]], logs, 1, modulus)
            failures = 0
            for z, zeta, u in product(range(modulus), repeat=3):
                values = [0, z, zeta, u]
                failures += (u == 0 or ring.evaluate(rounds[0]["left"], values) == 0 or
                             ring.evaluate(rounds[0]["right"], values) == 0 or
                             ring.evaluate(generator, values) == 0)
            self.assertGreater(failures, 0)
            self.assertLessEqual(failures, abort_coefficient(1, 1) * modulus ** 2)

    def test_invalid_and_unbounded_control_inputs_refuse(self):
        for k, sources, logs, auxiliary, modulus in (
                (5, [[1] * 5], [1] * 32, 1, None), (1, [], [1, 1], 1, None),
                (1, [[1, 1]], [1, 1], 1, None), (1, [[0]], [1, 1], 1, None),
                (1, [[1]], [1], 1, None), (1, [[1]], [0, 1], 1, None),
                (1, [[1]], [1, 1], 0, None), (1, [[5]], [1, 1], 1, 5),
                (1, [[1]], [1, 5], 1, 5), (1, [[1]], [1, 1], 5, 5)):
            with self.subTest(k=k, sources=sources, logs=logs):
                with self.assertRaises(ValueError):
                    recurrence(k, sources, logs, auxiliary, modulus)
        for k, inputs in ((0, 1), (17, 1), (True, 1), (16, 0), (16, False)):
            with self.assertRaises(ValueError):
                abort_coefficient(k, inputs)

    def test_exact_reviewed_sources_and_controls(self):
        here = Path(__file__).resolve().parent
        root = here.parents[1]
        manifest = json.loads((here / "source_manifest.json").read_text())
        self.assertEqual(set(manifest), {"schema", "sources", "files"})
        self.assertEqual(manifest["schema"], "kagemusha.fold.polynomial-controls.v1")
        self.assertEqual(set(manifest["sources"]), {
            "crates/iroha_plonk_recursion/src/accumulation.rs",
            "crates/iroha_plonk_recursion/src/claim.rs", "crates/iroha_plonk/src/pcs/ipa/mod.rs"})
        self.assertEqual(set(manifest["files"]), {"algebra.py", "test_algebra.py", "README.md"})
        for base, files in ((root, manifest["sources"]), (here, manifest["files"])):
            for name, digest in files.items():
                self.assertEqual(hashlib.sha256((base / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
